import os
import re
import subprocess
import yaml
import sammaParser

# Load base config
config_path = os.path.join(os.path.dirname(__file__), '../../config.yaml')
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}

tr_config = config.get('traceroute-scanner', {})

# Read target (required)
target = os.getenv('TARGET', '')
if not target:
    print('ERROR: TARGET environment variable is required')
    exit(1)

max_hops = int(os.getenv('MAX_HOPS', tr_config.get('max_hops', 30)))
timeout = int(os.getenv('TIMEOUT', tr_config.get('timeout', 2)))

# Run traceroute
cmd = ['traceroute', '-n', '-q', '1', '-w', str(timeout), '-m', str(max_hops), target]
result = subprocess.run(cmd, capture_output=True, text=True)

# Parse each hop line: "  1  1.2.3.4  12.345 ms" or "  1  *"
hop_pattern = re.compile(r'^\s*(\d+)\s+(\S+)\s+(\d+\.\d+)\s+ms')
star_pattern = re.compile(r'^\s*(\d+)\s+\*')

for line in result.stdout.splitlines():
    hop_match = hop_pattern.match(line)
    star_match = star_pattern.match(line)

    if hop_match:
        hop = int(hop_match.group(1))
        ip = hop_match.group(2)
        rtt_ms = float(hop_match.group(3))
        finding = {
            'host': target,
            'hop': hop,
            'ip': ip,
            'rtt_ms': rtt_ms,
            'type': 'Traceroute'
        }
        sammaParser.logger(finding)
    elif star_match:
        hop = int(star_match.group(1))
        finding = {
            'host': target,
            'hop': hop,
            'ip': None,
            'rtt_ms': None,
            'type': 'Traceroute'
        }
        sammaParser.logger(finding)

sammaParser.endThis()
