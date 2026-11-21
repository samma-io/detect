"""tls-scanner: one TLS handshake with the target and what it tells us.

The certificate, the negotiated protocol and cipher become findings; the
verification error, when there is one, is classified too. A connection that
cannot be made at all ends the run as failed.

The default handshake negotiates the highest version both sides support, so a
server that still accepts TLS 1.0 next to TLS 1.3 looks like a 1.3-only one.
Unless ``probe_protocols`` is off, the scanner therefore also tries one
handshake pinned to each deprecated version (TLS 1.0 and 1.1) and reports the
ones the server accepts.
"""

import os
import ssl
from datetime import datetime, timezone

import samma_finding
from samma_finding import config, netutil
from samma_finding.catalog import tls_scanner as checks

SCANNER = "tls-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

# OpenSSL reasons that mean the server only speaks TLS versions below the
# client's minimum (TLS 1.2), so the handshake fails instead of negotiating.
PROTOCOL_TOO_OLD_REASONS = ("UNSUPPORTED_PROTOCOL", "TLSV1_ALERT_PROTOCOL_VERSION")

# Deprecated versions probed with a pinned handshake: (label, ssl.TLSVersion name).
PROBED_PROTOCOLS = (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"))


def settings(environ=None, cfg=None):
    """Environment > config.yaml > defaults. Always TLS, so there is no
    scheme for the port to follow: PORT, then config.yaml, then 443."""
    env = os.environ if environ is None else environ
    tls = config.section("tls-scanner", CONFIG_PATH, cfg)
    return {
        "port": int(config.setting(env, tls, "port", 443)),
        "timeout": float(config.setting(env, tls, "timeout", 5)),
        "verify_cert": config.truthy(config.setting(env, tls, "verify_cert", True)),
        "probe_protocols": config.truthy(config.setting(env, tls, "probe_protocols", True)),
    }


def parse_certificate(cert, now=None):
    """Expiry and names from ``getpeercert()``'s dictionary."""
    now = now or datetime.now(timezone.utc)
    info = {"expires": None, "days_remaining": None, "expired": None,
            "subject_cn": None, "issuer": None}
    not_after_str = cert.get("notAfter")
    if not_after_str:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        info["days_remaining"] = (not_after - now).days
        info["expired"] = info["days_remaining"] < 0
        info["expires"] = not_after.strftime("%Y-%m-%d")
    for field in cert.get("subject", ()):
        for key, value in field:
            if key == "commonName":
                info["subject_cn"] = value
    for field in cert.get("issuer", ()):
        for key, value in field:
            if key == "organizationName":
                info["issuer"] = value
    return info


def is_weak_cipher(name):
    if not name:
        return False
    tokens = name.upper().replace("_", "-").split("-")
    return any(token in checks.WEAK_CIPHER_TOKENS for token in tokens)


def classify(observation):
    """``[(check_id, evidence)]`` for one handshake observation.

    ``observation`` has ``protocol``, ``cipher``, ``cert`` (the dict from
    :func:`parse_certificate` or ``None``), ``verify_error`` and
    ``protocol_error`` (strings or ``None``), and optionally ``accepted``: the
    deprecated versions the server accepted in pinned handshakes.
    """
    findings = []
    verify_error = observation.get("verify_error")
    if verify_error:
        if "expired" in verify_error.lower():
            findings.append(("SAMMA-TLS-CERT-EXPIRED",
                             "certificate verification failed: %s" % verify_error))
        else:
            findings.append(("SAMMA-TLS-CERT-INVALID",
                             "certificate verification failed: %s" % verify_error))
    protocol_error = observation.get("protocol_error")
    if protocol_error:
        findings.append(("SAMMA-TLS-PROTOCOL-DEPRECATED",
                         "handshake failed with %s: the server offers no TLS version "
                         "of 1.2 or newer" % protocol_error))
    protocol = observation.get("protocol")
    accepted = [p for p in observation.get("accepted") or () if p != protocol]
    if protocol in checks.DEPRECATED_PROTOCOLS:
        evidence = "negotiated %s" % protocol
        if accepted:
            evidence += "; also accepts %s" % ", ".join(accepted)
        findings.append(("SAMMA-TLS-PROTOCOL-DEPRECATED", evidence))
    elif accepted and not protocol_error:
        findings.append(("SAMMA-TLS-PROTOCOL-DEPRECATED",
                         "accepts %s in a pinned handshake (negotiates %s by default)"
                         % (", ".join(accepted), protocol or "nothing newer")))
    cipher = observation.get("cipher")
    if is_weak_cipher(cipher):
        findings.append(("SAMMA-TLS-CIPHER-WEAK", "negotiated cipher %s" % cipher))
    cert = observation.get("cert")
    if cert:
        days = cert.get("days_remaining")
        if cert.get("expired"):
            findings.append(("SAMMA-TLS-CERT-EXPIRED",
                             "certificate expired on %s (%d days ago)" % (cert["expires"], -days)))
        elif days is not None and days <= checks.EXPIRY_WARNING_DAYS:
            findings.append(("SAMMA-TLS-CERT-EXPIRING",
                             "certificate expires on %s (%d days left)" % (cert["expires"], days)))
    if protocol:
        summary = "protocol=%s cipher=%s" % (protocol, cipher)
        if cert:
            summary += " subject=%s issuer=%s expires=%s days_remaining=%s" % (
                cert.get("subject_cn"), cert.get("issuer"), cert.get("expires"),
                cert.get("days_remaining"))
        findings.append(("SAMMA-TLS-CERTIFICATE", summary))
    return findings


def handshake(target, opts, connect=netutil.connect_any):
    """Connect, shake hands and return ``(observation, raw)``."""
    if opts["verify_cert"]:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()
    sock, used = connect(target, opts["port"], opts["timeout"])  # OSError -> failed run
    observation = {"protocol": None, "cipher": None, "cert": None,
                   "verify_error": None, "protocol_error": None}
    raw = {
        "host": target, "port": opts["port"], "valid": False, "expired": None,
        "days_remaining": None, "expires": None, "subject_cn": None,
        "issuer": None, "protocol": None, "cipher": None, "type": "TLSScan",
        "address": used.describe(),
    }
    try:
        with sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = parse_certificate(ssock.getpeercert() or {})
                cipher_info = ssock.cipher()
                observation.update({
                    "protocol": ssock.version(),
                    "cipher": cipher_info[0] if cipher_info else None,
                    "cert": cert,
                })
    except ssl.SSLCertVerificationError as exc:
        observation["verify_error"] = getattr(exc, "verify_message", None) or str(exc)
        raw["error"] = observation["verify_error"]
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", None) or ""
        if reason not in PROTOCOL_TOO_OLD_REASONS:
            raise
        observation["protocol_error"] = reason
        raw["error"] = reason
    if observation["cert"]:
        raw.update(observation["cert"])
        raw["valid"] = True
    raw["protocol"] = observation["protocol"]
    raw["cipher"] = observation["cipher"]
    return observation, raw


def probe_protocol(target, opts, version, connect=netutil.connect_any):
    """Whether the server completes a handshake pinned to ``version`` alone.

    The certificate is not checked: the question is whether the version is
    offered. ``@SECLEVEL=0`` lets the client offer the old versions at all.
    Any failure, including a client that cannot pin the version, counts as not
    accepted.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        context.minimum_version = version
        context.maximum_version = version
    except (ValueError, ssl.SSLError):
        return False
    try:
        sock, _ = connect(target, opts["port"], opts["timeout"])
        with sock:
            with context.wrap_socket(sock, server_hostname=target):
                return True
    except (OSError, ssl.SSLError):
        return False


def probe_deprecated(target, opts, connect=netutil.connect_any, probe=probe_protocol):
    """Labels of the deprecated versions the server accepts."""
    accepted = []
    for label, name in PROBED_PROTOCOLS:
        version = getattr(ssl.TLSVersion, name, None)
        if version is not None and probe(target, opts, version, connect):
            accepted.append(label)
    return accepted


def scan(run, opts=None, connect=netutil.connect_any, probe=probe_protocol):
    opts = opts or settings()
    observation, raw = handshake(run.target, opts, connect)
    if opts.get("probe_protocols"):
        observation["accepted"] = probe_deprecated(run.target, opts, connect, probe)
    endpoint = run.endpoint(port=opts["port"], scheme="https")
    for check_id, evidence in classify(observation):
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
