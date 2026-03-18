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
    config = {}

ssh_config = config.get('ssh-banner-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

port = int(os.getenv('PORT', ssh_config.get('port', 22)))
timeout = float(os.getenv('TIMEOUT', ssh_config.get('timeout', 5)))

finding = {
    'host': target,
    'port': port,
    'banner': None,
    'software': None,
    'type': 'SSHBanner'
}

try:
    with socket.create_connection((target, port), timeout=timeout) as sock:
        raw = sock.recv(256).decode('utf-8', errors='replace').strip()
        finding['banner'] = raw
        # SSH banner format: SSH-<protoversion>-<softwareversion> [comment]
        # e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        if raw.startswith('SSH-'):
            parts = raw.split('-', 2)
            if len(parts) >= 3:
                finding['software'] = parts[2].split()[0]
except Exception as e:
    finding['error'] = str(e)

sammaParser.logger(finding)
sammaParser.endThis()
