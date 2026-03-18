import os
import yaml
import whois
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

def first_or_str(v):
    if v is None:
        return None
    if isinstance(v, list):
        return str(v[0]) if v else None
    return str(v)

finding = {
    'host': target,
    'registrar': None,
    'creation_date': None,
    'expiration_date': None,
    'name_servers': [],
    'type': 'WHOISScan'
}

try:
    w = whois.whois(target)
    finding['registrar'] = first_or_str(w.registrar)
    finding['creation_date'] = first_or_str(w.creation_date)
    finding['expiration_date'] = first_or_str(w.expiration_date)
    ns = w.name_servers
    if isinstance(ns, list):
        finding['name_servers'] = [str(n).lower() for n in ns if n]
    elif ns:
        finding['name_servers'] = [str(ns).lower()]
except Exception as e:
    finding['error'] = str(e)

sammaParser.logger(finding)
sammaParser.endThis()
