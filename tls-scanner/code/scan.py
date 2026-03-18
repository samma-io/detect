import os
import socket
import ssl
import datetime
import yaml
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

tls_config = config.get('tls-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

port = int(os.getenv('PORT', tls_config.get('port', 443)))
timeout = float(os.getenv('TIMEOUT', tls_config.get('timeout', 5)))
verify_cert_env = os.getenv('VERIFY_CERT', str(tls_config.get('verify_cert', True)))
verify_cert = verify_cert_env.lower() not in ('false', '0', 'no')

context = ssl.create_default_context() if verify_cert else ssl._create_unverified_context()

finding = {
    'host': target,
    'port': port,
    'valid': False,
    'expired': None,
    'days_remaining': None,
    'expires': None,
    'subject_cn': None,
    'issuer': None,
    'protocol': None,
    'cipher': None,
    'type': 'TLSScan'
}

try:
    with socket.create_connection((target, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            cert = ssock.getpeercert()
            cipher_info = ssock.cipher()
            protocol = ssock.version()

            # Parse expiry
            not_after_str = cert.get('notAfter', '')
            not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            now = datetime.datetime.utcnow()
            days_remaining = (not_after - now).days
            expired = days_remaining < 0

            # Subject CN
            subject_cn = None
            for field in cert.get('subject', []):
                for key, value in field:
                    if key == 'commonName':
                        subject_cn = value

            # Issuer organisation
            issuer = None
            for field in cert.get('issuer', []):
                for key, value in field:
                    if key == 'organizationName':
                        issuer = value

            finding['valid'] = True
            finding['expired'] = expired
            finding['days_remaining'] = days_remaining
            finding['expires'] = not_after.strftime('%Y-%m-%d')
            finding['subject_cn'] = subject_cn
            finding['issuer'] = issuer
            finding['protocol'] = protocol
            finding['cipher'] = cipher_info[0] if cipher_info else None

except ssl.SSLCertVerificationError as e:
    finding['valid'] = False
    finding['error'] = str(e)
except Exception as e:
    finding['error'] = str(e)

sammaParser.logger(finding)
sammaParser.endThis()
