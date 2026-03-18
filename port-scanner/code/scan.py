import os
import socket
import yaml
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {'defaults': {'ports': [80, 443, 8080, 8443], 'timeout': 3}}

defaults = config.get('defaults', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

# Determine ports: PORT (single) > PORTS (comma-separated) > config defaults
if os.getenv('PORT'):
    ports = [int(os.getenv('PORT'))]
elif os.getenv('PORTS'):
    ports = [int(p.strip()) for p in os.getenv('PORTS').split(',') if p.strip()]
else:
    ports = defaults.get('ports', [80, 443, 8080, 8443])

# Timeout
timeout = float(os.getenv('TIMEOUT', defaults.get('timeout', 3)))

# Scan each port
for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()

    status = 'open' if result == 0 else 'closed'
    finding = {
        'host': target,
        'port': port,
        'status': status,
        'type': 'PortScan'
    }
    sammaParser.logger(finding)

sammaParser.endThis()
