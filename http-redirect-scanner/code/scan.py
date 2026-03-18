import os
import urllib.request
import urllib.error
import yaml
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

hr_config = config.get('http-redirect-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

timeout = float(os.getenv('TIMEOUT', hr_config.get('timeout', 5)))
max_redirects = int(os.getenv('MAX_REDIRECTS', hr_config.get('max_redirects', 10)))

# Ensure URL has scheme
current_url = target if target.startswith('http') else 'http://' + target

# Opener that does NOT auto-follow redirects
class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirectHandler())

hop = 0
while hop < max_redirects:
    try:
        resp = opener.open(current_url, timeout=timeout)
        finding = {
            'host': target,
            'hop': hop,
            'url': current_url,
            'status_code': resp.status,
            'redirect_to': None,
            'final': True,
            'type': 'HTTPRedirect'
        }
        sammaParser.logger(finding)
        break
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            location = e.headers.get('Location', '')
            finding = {
                'host': target,
                'hop': hop,
                'url': current_url,
                'status_code': e.code,
                'redirect_to': location,
                'final': False,
                'type': 'HTTPRedirect'
            }
            sammaParser.logger(finding)
            current_url = location
            hop += 1
        else:
            finding = {
                'host': target,
                'hop': hop,
                'url': current_url,
                'status_code': e.code,
                'redirect_to': None,
                'final': True,
                'type': 'HTTPRedirect'
            }
            sammaParser.logger(finding)
            break
    except Exception as e:
        finding = {
            'host': target,
            'hop': hop,
            'url': current_url,
            'error': str(e),
            'final': True,
            'type': 'HTTPRedirect'
        }
        sammaParser.logger(finding)
        break

sammaParser.endThis()
