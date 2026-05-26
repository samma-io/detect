import os
import http.client
import urllib.parse
import yaml
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

waf_config = config.get('waf-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

https_env = os.getenv('HTTPS', str(waf_config.get('https', True)))
https = https_env.lower() not in ('false', '0', 'no')
default_port = 443 if https else 80
port = int(os.getenv('PORT', waf_config.get('port', default_port)))
timeout = float(os.getenv('TIMEOUT', waf_config.get('timeout', 5)))
user_agent = os.getenv('USER_AGENT', waf_config.get('user_agent', 'samma-io-waf-scanner/1.0'))

# Vendor signature table. Each rule:
#   source: 'header' | 'cookie' | 'body'
#   name:   header/cookie name (case-insensitive), ignored for body
#   match:  None (presence only), or a regex/substring to match (case-insensitive)
#   strength: 'strong' for vendor-specific, 'weak' for generic
WAF_SIGNATURES = [
    ('Cloudflare', [
        {'source': 'header', 'name': 'cf-ray',     'match': None,         'strength': 'strong'},
        {'source': 'header', 'name': 'cf-cache-status', 'match': None,    'strength': 'strong'},
        {'source': 'header', 'name': 'server',     'match': 'cloudflare', 'strength': 'strong'},
        {'source': 'cookie', 'name': '__cf_bm',    'match': None,         'strength': 'strong'},
        {'source': 'cookie', 'name': '__cfduid',   'match': None,         'strength': 'strong'},
    ]),
    ('Sucuri', [
        {'source': 'header', 'name': 'x-sucuri-id',    'match': None, 'strength': 'strong'},
        {'source': 'header', 'name': 'x-sucuri-cache', 'match': None, 'strength': 'strong'},
    ]),
    ('Akamai', [
        {'source': 'header', 'name': 'server',                'match': 'akamaighost', 'strength': 'strong'},
        {'source': 'header', 'name': 'x-akamai-transformed',  'match': None,          'strength': 'strong'},
        {'source': 'cookie', 'name': 'ak_bmsc',               'match': None,          'strength': 'strong'},
    ]),
    ('AWS CloudFront', [
        {'source': 'header', 'name': 'x-amz-cf-id',  'match': None,       'strength': 'strong'},
        {'source': 'header', 'name': 'server',       'match': 'cloudfront', 'strength': 'strong'},
        {'source': 'header', 'name': 'via',          'match': 'cloudfront', 'strength': 'strong'},
    ]),
    ('F5 BIG-IP ASM', [
        {'source': 'header', 'name': 'server',   'match': 'bigip',         'strength': 'strong'},
        {'source': 'cookie', 'name': 'ts0',      'match': None,            'strength': 'weak'},
        {'source': 'cookie', 'name': 'bigipserver', 'match': None,         'strength': 'strong'},
    ]),
    ('Imperva Incapsula', [
        {'source': 'header', 'name': 'x-iinfo',         'match': None, 'strength': 'strong'},
        {'source': 'cookie', 'name': 'incap_ses_',      'match': None, 'strength': 'strong'},
        {'source': 'cookie', 'name': 'visid_incap_',    'match': None, 'strength': 'strong'},
    ]),
    ('Barracuda', [
        {'source': 'cookie', 'name': 'barra_counter_session', 'match': None, 'strength': 'strong'},
    ]),
    ('Fastly', [
        {'source': 'header', 'name': 'server',              'match': 'fastly', 'strength': 'strong'},
        {'source': 'header', 'name': 'x-fastly-request-id', 'match': None,     'strength': 'strong'},
    ]),
    ('Azure Front Door', [
        {'source': 'header', 'name': 'x-azure-ref', 'match': None, 'strength': 'strong'},
    ]),
    ('ModSecurity', [
        {'source': 'header', 'name': 'server', 'match': 'mod_security', 'strength': 'strong'},
        {'source': 'header', 'name': 'server', 'match': 'noyb',         'strength': 'strong'},
    ]),
    ('Wallarm', [
        {'source': 'header', 'name': 'nginx-wallarm', 'match': None, 'strength': 'strong'},
    ]),
    ('Generic WAF', [
        {'source': 'header', 'name': 'server',           'match': 'firewall', 'strength': 'weak'},
        {'source': 'header', 'name': 'x-waf-status',     'match': None,       'strength': 'weak'},
        {'source': 'header', 'name': 'x-firewall',       'match': None,       'strength': 'weak'},
    ]),
]

# Active probes — sent as URL-encoded query strings on GET /
ACTIVE_PROBES = [
    ('sqli',      "id=1' OR '1'='1--"),
    ('xss',       "q=<script>alert(1)</script>"),
    ('traversal', "file=../../../../etc/passwd"),
]

BLOCKED_STATUSES = {403, 406, 419, 429, 451, 501, 503}
BLOCKED_BODY_MARKERS = [
    'blocked', 'firewall', 'security', 'forbidden',
    'incident id', 'ray id', 'attack', 'denied',
]


def _new_conn():
    if https:
        return http.client.HTTPSConnection(target, port, timeout=timeout)
    return http.client.HTTPConnection(target, port, timeout=timeout)


def _fetch(path):
    conn = _new_conn()
    try:
        conn.request('GET', path, headers={'User-Agent': user_agent, 'Accept': '*/*'})
        resp = conn.getresponse()
        status = resp.status
        raw_headers = resp.getheaders()
        body = resp.read(4096)
        try:
            body_text = body.decode('utf-8', errors='replace')
        except Exception:
            body_text = ''
        return status, raw_headers, body_text
    finally:
        conn.close()


def _collect_cookies(raw_headers):
    cookies = []
    for k, v in raw_headers:
        if k.lower() == 'set-cookie':
            cookies.append(v)
    return cookies


def _match_indicator(rule, headers_lower, cookies, body_lower):
    name = rule['name']
    match = rule['match']
    src = rule['source']

    if src == 'header':
        if name not in headers_lower:
            return None
        value = headers_lower[name]
        if match is None or match.lower() in value.lower():
            return {'source': 'header', 'name': name, 'value': value}
        return None

    if src == 'cookie':
        for c in cookies:
            cookie_name = c.split('=', 1)[0].strip().lower()
            if name.lower() in cookie_name:
                return {'source': 'cookie', 'name': name, 'value': c.split(';', 1)[0]}
        return None

    if src == 'body':
        if match and match.lower() in body_lower:
            return {'source': 'body', 'name': name, 'value': match}
        return None

    return None


def _probe_blocked(status, body_lower, baseline_status):
    if status in BLOCKED_STATUSES and 200 <= baseline_status < 300:
        return True
    if status != baseline_status and status >= 400 and 200 <= baseline_status < 300:
        return True
    for marker in BLOCKED_BODY_MARKERS:
        if marker in body_lower:
            return True
    return False


finding = {
    'host': target,
    'port': port,
    'https': https,
    'type': 'WAFDetection',
}

try:
    baseline_status, baseline_headers, baseline_body = _fetch('/')
    headers_lower = {k.lower(): v for k, v in baseline_headers}
    cookies = _collect_cookies(baseline_headers)
    body_lower = baseline_body.lower()

    # Passive fingerprinting — collect every match per vendor
    vendor_matches = []
    for vendor, rules in WAF_SIGNATURES:
        matched = []
        has_strong = False
        for rule in rules:
            ind = _match_indicator(rule, headers_lower, cookies, body_lower)
            if ind:
                ind['vendor'] = vendor
                matched.append(ind)
                if rule['strength'] == 'strong':
                    has_strong = True
        if matched:
            vendor_matches.append((vendor, matched, has_strong))

    passive_indicators = []
    waf_name = None
    has_strong_match = False
    if vendor_matches:
        # Pick vendor with most matches; ties resolve by table order (first wins)
        vendor_matches.sort(key=lambda x: -len(x[1]))
        best_vendor, best_matches, best_strong = vendor_matches[0]
        if best_vendor != 'Generic WAF':
            waf_name = best_vendor
        has_strong_match = best_strong
        for _, matches, _ in vendor_matches:
            for m in matches:
                passive_indicators.append(m)

    # Active probes
    active_probes = []
    any_probe_blocked = False
    for probe_name, query in ACTIVE_PROBES:
        path = '/?' + urllib.parse.quote(query, safe='=&')
        try:
            p_status, _p_headers, p_body = _fetch(path)
            p_body_lower = p_body.lower()
            blocked = _probe_blocked(p_status, p_body_lower, baseline_status)
        except Exception as e:
            active_probes.append({
                'payload': probe_name,
                'error': str(e),
                'blocked': False,
            })
            continue
        if blocked:
            any_probe_blocked = True
        active_probes.append({
            'payload': probe_name,
            'status_code': p_status,
            'blocked': blocked,
        })

    # Confidence resolution
    if any_probe_blocked:
        confidence = 'confirmed'
        waf_detected = True
    elif has_strong_match:
        confidence = 'high'
        waf_detected = True
    elif len(passive_indicators) >= 2:
        confidence = 'medium'
        waf_detected = True
    elif len(passive_indicators) == 1:
        confidence = 'low'
        waf_detected = True
    else:
        confidence = 'none'
        waf_detected = False

    finding.update({
        'waf_detected': waf_detected,
        'waf_name': waf_name,
        'waf_confidence': confidence,
        'passive_indicators': passive_indicators,
        'active_probes': active_probes,
        'baseline_status': baseline_status,
    })

except Exception as e:
    finding['error'] = str(e)

sammaParser.logger(finding)
sammaParser.endThis()
