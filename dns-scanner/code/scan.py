import os
import yaml
import dns.resolver
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

dns_config = config.get('dns-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

record_types_env = os.getenv('RECORD_TYPES', '')
if record_types_env:
    record_types = [r.strip().upper() for r in record_types_env.split(',') if r.strip()]
else:
    record_types = dns_config.get('record_types', ['A', 'AAAA', 'MX', 'TXT'])

for rtype in record_types:
    try:
        answers = dns.resolver.resolve(target, rtype)
        for rdata in answers:
            finding = {
                'host': target,
                'record_type': rtype,
                'value': rdata.to_text(),
                'type': 'DNSScan'
            }
            sammaParser.logger(finding)
    except dns.resolver.NoAnswer:
        finding = {
            'host': target,
            'record_type': rtype,
            'value': None,
            'error': 'no answer',
            'type': 'DNSScan'
        }
        sammaParser.logger(finding)
    except dns.resolver.NXDOMAIN:
        finding = {
            'host': target,
            'record_type': rtype,
            'value': None,
            'error': 'NXDOMAIN',
            'type': 'DNSScan'
        }
        sammaParser.logger(finding)
    except Exception as e:
        finding = {
            'host': target,
            'record_type': rtype,
            'value': None,
            'error': str(e),
            'type': 'DNSScan'
        }
        sammaParser.logger(finding)

sammaParser.endThis()
