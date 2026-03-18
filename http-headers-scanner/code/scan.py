import os
import http.client
import yaml
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

hh_config = config.get('http-headers-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

https_env = os.getenv('HTTPS', str(hh_config.get('https', False)))
https = https_env.lower() not in ('false', '0', 'no')
default_port = 443 if https else 80
port = int(os.getenv('PORT', hh_config.get('port', default_port)))
timeout = float(os.getenv('TIMEOUT', hh_config.get('timeout', 5)))

SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'x-xss-protection',
]

status_code = None
error = None

try:
    if https:
        conn = http.client.HTTPSConnection(target, port, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(target, port, timeout=timeout)

    conn.request('HEAD', '/')
    resp = conn.getresponse()
    status_code = resp.status
    headers_lower = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()

    for h in SECURITY_HEADERS:
        finding = {
            'host': target,
            'port': port,
            'https': https,
            'status_code': status_code,
            'header': h,
            'present': h in headers_lower,
            'value': headers_lower.get(h),
            'type': 'HTTPHeaders'
        }
        sammaParser.logger(finding)

except Exception as e:
    finding = {
        'host': target,
        'port': port,
        'https': https,
        'error': str(e),
        'type': 'HTTPHeaders'
    }
    sammaParser.logger(finding)

sammaParser.endThis()
