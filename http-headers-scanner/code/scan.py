"""http-headers-scanner: which security headers one response carries.

One HEAD request; each missing header is a finding, and one INFO record
keeps the inventory of what was present. HSTS is only judged over HTTPS,
where browsers honour it. A Server or X-Powered-By header that names a
version, and cookies set without Secure (over HTTPS), HttpOnly or SameSite,
are findings too. Cookie values are never recorded, only their names.
"""

import os
import re

import samma_finding
from samma_finding import config, netutil

SCANNER = "http-headers-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

MISSING_CHECKS = {
    "content-security-policy": "SAMMA-HEADERS-CSP-MISSING",
    "x-content-type-options": "SAMMA-HEADERS-X-CONTENT-TYPE-OPTIONS-MISSING",
    "x-frame-options": "SAMMA-HEADERS-X-FRAME-OPTIONS-MISSING",
    "referrer-policy": "SAMMA-HEADERS-REFERRER-POLICY-MISSING",
    "permissions-policy": "SAMMA-HEADERS-PERMISSIONS-POLICY-MISSING",
}

VALUE_PREVIEW = 120

# Headers that advertise the software; a digit after a letter or slash in the
# value (nginx/1.27.5, PHP/8.2.1, Apache/2.4) is a version.
BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
VERSION_RE = re.compile(r"[A-Za-z/ ]\d+(\.\d+)+|^\d+(\.\d+)+")


def settings(environ=None, cfg=None):
    """Environment > config.yaml > defaults. The port follows the scheme:
    HTTPS=True without PORT means 443, never the port config.yaml lists for
    plain HTTP (samma_finding.config.endpoint)."""
    env = os.environ if environ is None else environ
    section = config.section("http-headers-scanner", CONFIG_PATH, cfg)
    https, port = config.endpoint(env, section, default_https=False)
    return {
        "https": https,
        "port": port,
        "timeout": float(config.setting(env, section, "timeout", 5)),
    }


def fetch(target, opts):
    """``(status_code, {header: value})`` for ``HEAD /``; errors propagate."""
    if opts["https"]:
        conn = netutil.HTTPSConnection(target, opts["port"], timeout=opts["timeout"])
    else:
        conn = netutil.HTTPConnection(target, opts["port"], timeout=opts["timeout"])
    try:
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        # A dict keeps one Set-Cookie; every cookie is judged.
        cookies = resp.msg.get_all("Set-Cookie") or []
        if cookies:
            headers["set-cookie"] = list(cookies)
        return resp.status, headers
    finally:
        conn.close()


def _preview(value):
    value = " ".join(str(value).split())
    return value if len(value) <= VALUE_PREVIEW else value[:VALUE_PREVIEW] + "..."


def cookie_issues(set_cookie, https):
    """``[(name, [missing attribute, ...])]`` for each Set-Cookie value.

    Secure only counts over HTTPS, where the cookie could be sent in clear
    otherwise. The cookie value is not returned.
    """
    if set_cookie is None:
        return []
    values = set_cookie if isinstance(set_cookie, (list, tuple)) else [set_cookie]
    issues = []
    for value in values:
        parts = [p.strip() for p in str(value).split(";")]
        name = parts[0].split("=", 1)[0].strip() or "(unnamed)"
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:] if p}
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            issues.append((name[:64], missing))
    return issues


def version_banners(headers):
    """``[(header, value)]`` for software headers that name a version."""
    out = []
    for header in BANNER_HEADERS:
        value = headers.get(header)
        if value and VERSION_RE.search(str(value)):
            out.append((header, _preview(value)))
    return out


def classify(headers, https, status_code=None):
    """``[(check_id, evidence, header)]``; ``header`` is ``None`` for the summary."""
    findings = []
    where = "response status %s" % status_code if status_code is not None else "response"
    if https and "strict-transport-security" not in headers:
        findings.append(("SAMMA-HEADERS-HSTS-MISSING",
                         "strict-transport-security not present (%s)" % where,
                         "strict-transport-security"))
    csp = headers.get("content-security-policy") or ""
    for header, check_id in MISSING_CHECKS.items():
        if header in headers:
            continue
        if header == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue  # CSP frame-ancestors supersedes X-Frame-Options
        findings.append((check_id, "%s not present (%s)" % (header, where), header))
    xss = headers.get("x-xss-protection")
    if xss is not None and str(xss).strip().startswith("1"):
        findings.append(("SAMMA-HEADERS-X-XSS-PROTECTION-ENABLED",
                         "x-xss-protection: %s" % _preview(xss), "x-xss-protection"))
    banners = version_banners(headers)
    if banners:
        findings.append(("SAMMA-HEADERS-SERVER-VERSION",
                         "; ".join("%s: %s" % b for b in banners), banners[0][0]))
    issues = cookie_issues(headers.get("set-cookie"), https)
    if issues:
        findings.append(("SAMMA-HEADERS-COOKIE-FLAGS-MISSING",
                         "; ".join("cookie %s without %s" % (n, ", ".join(m)) for n, m in issues),
                         "set-cookie"))
    present = [h for h in SECURITY_HEADERS if h in headers]
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    summary = "%s; present: %s; missing: %s" % (
        where,
        ", ".join("%s=%s" % (h, _preview(headers[h])) for h in present) or "none",
        ", ".join(missing) or "none",
    )
    findings.append(("SAMMA-HEADERS-OBSERVED", summary, None))
    return findings


def scan(run, opts=None, fetch_=None):
    opts = opts or settings()
    status_code, headers = (fetch_ or fetch)(run.target, opts)
    scheme = "https" if opts["https"] else "http"
    endpoint = run.endpoint(port=opts["port"], scheme=scheme)
    base = {"host": run.target, "port": opts["port"], "https": opts["https"],
            "status_code": status_code, "type": "HTTPHeaders"}
    for check_id, evidence, header in classify(headers, opts["https"], status_code):
        raw = dict(base)
        if header is None:
            raw["headers"] = {h: headers.get(h) for h in SECURITY_HEADERS}
        elif header == "set-cookie":
            # Names and missing attributes only: a cookie value can be a session token.
            raw.update({"header": header, "present": True,
                        "cookies": [{"name": n, "missing": m}
                                    for n, m in cookie_issues(headers.get("set-cookie"), opts["https"])]})
        else:
            raw.update({"header": header, "present": header in headers,
                        "value": headers.get(header)})
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
