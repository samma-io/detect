# detect: the Samma detect scanners

Eight small, open-source security scanners. Each one checks one thing about a host, reports one
record per finding, and exits. They are the light, always-on layer of
[Samma](https://github.com/samma-io/guide): the Samma operator runs them in your Kubernetes cluster
against every Ingress you annotate, and the findings end up in Grafana in that same cluster.

Images are published to `ghcr.io/samma-io/detect-<tool-name>:latest` on every push to `main`.

---

## The scanners and what they are for

| Scanner | What it checks | Use it for |
|---|---|---|
| `tls-scanner` | Certificate validity, expiry and days left, issuer, protocol, cipher | Catching expiring or invalid certificates and old TLS versions |
| `http-headers-scanner` | Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection | OWASP secure-headers hygiene on every web endpoint |
| `http-redirect-scanner` | Full redirect chain, hop by hop | Making sure HTTP goes to HTTPS and nothing redirects somewhere unexpected |
| `port-scanner` | Open TCP ports (default 80, 443, 8080, 8443) | Spotting services that should not be exposed |
| `ssh-banner-scanner` | SSH banner and software version | Finding outdated SSH servers |
| `dns-scanner` | A, AAAA, MX and TXT records | Tracking DNS changes and dangling records |
| `whois-scanner` | Registrar, creation and expiry dates, name servers | Domain expiry and ownership changes |
| `traceroute-scanner` | Network path, hop by hop | Seeing how a target is reached, and when that changes |

None of them sends attack-like traffic, so they are safe to run often. For deeper checks, the
operator also runs the classic scanners: [nmap](https://github.com/samma-io/nmap),
[nikto](https://github.com/samma-io/nikto) and [tsunami](https://github.com/samma-io/tsunami).
With a [samma.io](https://samma.io) connection you also get external scanners and validated vendor
scanners, such as PCI DSS ASV, for tagged Ingresses. The
[guide](https://github.com/samma-io/guide/blob/main/1a-the-scanners/README.md) covers the whole
picture.

---

## How it works

Every tool follows the same pattern:

1. Read configuration from environment variables (or fall back to `config.yaml` defaults).
2. Run the detection and emit one record per finding through `sammaParser.py`. It is printed to
   stdout and, when `NATS_ENABLED=true`, published to NATS as JSON.
3. Optionally write the results to `/out/<tool-name>.json` when `WRITE_TO_FILE=true`.
4. Write `/out/die` when finished, so a sidecar (if any) knows the scan is done.

Under the Samma operator, findings go **scanner → NATS (`samma-io.scan`) → bridge → TimescaleDB →
Grafana**. You don't run anything else.

---

## Quick start

All `docker compose` commands use the repo root as build context, so always run them from the **repo root**.

### Pull and run a pre-built image

```bash
TARGET=example.com docker compose -f tls-scanner/docker-compose.yaml up
```

### Build and run locally

```bash
# Port scan
TARGET=scanme.nmap.org docker compose -f port-scanner/docker-compose.yaml up --build

# Traceroute
TARGET=scanme.nmap.org docker compose -f traceroute-scanner/docker-compose.yaml up --build

# TLS certificate check
TARGET=example.com docker compose -f tls-scanner/docker-compose.yaml up --build

# HTTP security headers
TARGET=example.com docker compose -f http-headers-scanner/docker-compose.yaml up --build

# DNS records
TARGET=example.com docker compose -f dns-scanner/docker-compose.yaml up --build

# SSH banner
TARGET=scanme.nmap.org docker compose -f ssh-banner-scanner/docker-compose.yaml up --build

# WHOIS
TARGET=example.com docker compose -f whois-scanner/docker-compose.yaml up --build

# HTTP redirect chain
TARGET=http://example.com docker compose -f http-redirect-scanner/docker-compose.yaml up --build
```

### Read the output

Each tool writes results to `<tool-name>/out/<tool-name>.json`:

```bash
cat port-scanner/out/port-scanner.json
cat tls-scanner/out/tls-scanner.json
# etc.
```

Completion is signalled by the `die` file:

```bash
ls port-scanner/out/die   # exists when the scan is done
```

---

## Environment variables

Every tool accepts a common set of variables plus tool-specific ones.

### Common variables (all tools)

| Variable | Default | Description |
|---|---|---|
| `TARGET` | **required** | Host or IP to scan |
| `WRITE_TO_FILE` | `False` | Set to `true` to write JSON to `/out/` |
| `PARSER` | `<tool-name>` | Output filename (without `.json`) |
| `SAMMA_IO_SCANNER` | `<tool-name>` | Tool label added to every record |
| `SAMMA_IO_ID` | `1234` | Deployment ID added to every record |
| `SAMMA_IO_TAGS` | `['scanner']` | Tags added to every record |
| `SAMMA_IO_JSON` | `{}` | Extra arbitrary JSON added to every record |
| `TARGET_ID` | — | samma.io target id, so results show on that target in the dashboard |
| `NATS_ENABLED` | `False` | Set to `true` to publish every finding to NATS |
| `NATS_URL` | `nats://localhost:4222` | NATS server |
| `NATS_SUBJECT` | `scans` | Subject to publish on (the operator uses `samma-io.scan`) |

### port-scanner

| Variable | Default | Description |
|---|---|---|
| `PORT` | — | Scan a single port |
| `PORTS` | `80,443,8080,8443` | Comma-separated list of ports |
| `TIMEOUT` | `3` | Connection timeout (seconds) |

```bash
TARGET=scanme.nmap.org PORTS=22,80,443 docker compose -f port-scanner/docker-compose.yaml up
```

### traceroute-scanner

| Variable | Default | Description |
|---|---|---|
| `MAX_HOPS` | `30` | Maximum TTL / hop count |
| `TIMEOUT` | `2` | Per-probe wait time (seconds) |

```bash
TARGET=8.8.8.8 MAX_HOPS=15 docker compose -f traceroute-scanner/docker-compose.yaml up
```

### tls-scanner

| Variable | Default | Description |
|---|---|---|
| `PORT` | `443` | TLS port |
| `TIMEOUT` | `5` | Connection timeout (seconds) |
| `VERIFY_CERT` | `True` | Validate certificate chain |

```bash
TARGET=example.com VERIFY_CERT=False docker compose -f tls-scanner/docker-compose.yaml up
```

### http-headers-scanner

| Variable | Default | Description |
|---|---|---|
| `HTTPS` | `False` | Use HTTPS instead of HTTP |
| `PORT` | `80` | Port to connect to |
| `TIMEOUT` | `5` | Connection timeout (seconds) |

```bash
TARGET=example.com HTTPS=True PORT=443 docker compose -f http-headers-scanner/docker-compose.yaml up
```

Checked headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`.

### dns-scanner

| Variable | Default | Description |
|---|---|---|
| `RECORD_TYPES` | `A,AAAA,MX,TXT` | Comma-separated record types to query |

```bash
TARGET=example.com RECORD_TYPES=A,MX,TXT docker compose -f dns-scanner/docker-compose.yaml up
```

### ssh-banner-scanner

| Variable | Default | Description |
|---|---|---|
| `PORT` | `22` | SSH port |
| `TIMEOUT` | `5` | Connection timeout (seconds) |

```bash
TARGET=scanme.nmap.org PORT=2222 docker compose -f ssh-banner-scanner/docker-compose.yaml up
```

### whois-scanner

| Variable | Default | Description |
|---|---|---|
| *(none beyond common)* | | |

```bash
TARGET=example.com docker compose -f whois-scanner/docker-compose.yaml up
```

### http-redirect-scanner

| Variable | Default | Description |
|---|---|---|
| `TIMEOUT` | `5` | Per-request timeout (seconds) |
| `MAX_REDIRECTS` | `10` | Maximum hops to follow |

```bash
TARGET=http://example.com MAX_REDIRECTS=5 docker compose -f http-redirect-scanner/docker-compose.yaml up
```

---

## Output format

Every JSON record includes a `samma-io` metadata block alongside the tool-specific fields:

```json
{
  "host": "example.com",
  "port": 443,
  "status": "open",
  "type": "PortScan",
  "samma-io": {
    "scanner": "port-scanner",
    "id": "1234",
    "tags": "['scanner']",
    "json": "{}"
  }
}
```

### Output shapes per tool

**port-scanner**
```json
{"host": "example.com", "port": 443, "status": "open", "type": "PortScan"}
```

**traceroute-scanner**
```json
{"host": "example.com", "hop": 3, "ip": "1.2.3.4", "rtt_ms": 12.4, "type": "Traceroute"}
{"host": "example.com", "hop": 5, "ip": null, "rtt_ms": null, "type": "Traceroute"}
```

**tls-scanner**
```json
{
  "host": "example.com", "port": 443,
  "valid": true, "expired": false, "days_remaining": 42,
  "expires": "2026-05-01", "subject_cn": "example.com",
  "issuer": "Let's Encrypt", "protocol": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384", "type": "TLSScan"
}
```

**http-headers-scanner**
```json
{"host": "example.com", "port": 80, "https": false, "status_code": 200, "header": "strict-transport-security", "present": true, "value": "max-age=31536000", "type": "HTTPHeaders"}
{"host": "example.com", "port": 80, "https": false, "status_code": 200, "header": "content-security-policy", "present": false, "value": null, "type": "HTTPHeaders"}
```

**dns-scanner**
```json
{"host": "example.com", "record_type": "A", "value": "93.184.216.34", "type": "DNSScan"}
{"host": "example.com", "record_type": "MX", "value": "0 .", "type": "DNSScan"}
```

**ssh-banner-scanner**
```json
{"host": "scanme.nmap.org", "port": 22, "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13", "software": "OpenSSH_6.6.1p1", "type": "SSHBanner"}
```

**whois-scanner**
```json
{
  "host": "example.com",
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "creation_date": "1995-08-14 04:00:00",
  "expiration_date": "2025-08-13 04:00:00",
  "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
  "type": "WHOISScan"
}
```

**http-redirect-scanner**
```json
{"host": "http://example.com", "hop": 0, "url": "http://example.com", "status_code": 301, "redirect_to": "https://example.com/", "final": false, "type": "HTTPRedirect"}
{"host": "http://example.com", "hop": 1, "url": "https://example.com/", "status_code": 200, "redirect_to": null, "final": true, "type": "HTTPRedirect"}
```

---

## Configuration file

`config.yaml` at the repo root holds default values for all tools. Environment variables always take precedence.

```yaml
defaults:
  ports: [80, 443, 8080, 8443]
  timeout: 3

traceroute-scanner:
  max_hops: 30
  timeout: 2

tls-scanner:
  port: 443
  timeout: 5
  verify_cert: true

http-headers-scanner:
  port: 80
  https: false
  timeout: 5

dns-scanner:
  record_types: [A, AAAA, MX, TXT]

ssh-banner-scanner:
  port: 22
  timeout: 5

http-redirect-scanner:
  timeout: 5
  max_redirects: 10
```

---

## CI/CD

Every push to `main` triggers `.github/workflows/docker-build.yml`, which builds all tool images in parallel and pushes them to the GitHub Container Registry:

```
ghcr.io/samma-io/detect-port-scanner:latest
ghcr.io/samma-io/detect-traceroute-scanner:latest
ghcr.io/samma-io/detect-tls-scanner:latest
ghcr.io/samma-io/detect-http-headers-scanner:latest
ghcr.io/samma-io/detect-dns-scanner:latest
ghcr.io/samma-io/detect-ssh-banner-scanner:latest
ghcr.io/samma-io/detect-whois-scanner:latest
ghcr.io/samma-io/detect-http-redirect-scanner:latest
```

Each image is also tagged with the short git SHA (`sha-<7chars>`).

---

## Kubernetes

The normal way to run these in Kubernetes is the
[Samma operator](https://github.com/samma-io/operator). It creates the Jobs and CronJobs for you,
from an annotated Ingress, the API or a `Scanner` resource, and wires up NATS. For a few fixed
targets without the operator, use the Helm chart in `helm/`.

The standalone manifests below are the older way. Each tool ships `manifest/job.yaml` (one-off run) and `manifest/cron.yaml` (scheduled run). Both include the tool container and a Filebeat sidecar that ships results to Elasticsearch.

```bash
# Apply ConfigMaps + run a one-off job
kubectl apply -f port-scanner/manifest/job.yaml

# Apply ConfigMaps + schedule a recurring job
kubectl apply -f port-scanner/manifest/cron.yaml
```

The Filebeat sidecar watches for `/out/die` via a liveness probe and kills itself (and the pod) once the detection is complete.

To point tools at a different Elasticsearch cluster, set `ELASTICSEARCH_HOSTS` in the manifest:

```yaml
- name: ELASTICSEARCH_HOSTS
  value: http://my-elastic-cluster:9200
```

---

## Repo structure

```
detect/
├── config.yaml
├── .github/workflows/docker-build.yml
├── port-scanner/
├── traceroute-scanner/
├── tls-scanner/
├── http-headers-scanner/
├── dns-scanner/
├── ssh-banner-scanner/
├── whois-scanner/
└── http-redirect-scanner/

Each tool directory:
├── code/
│   ├── scan.py
│   ├── sammaParser.py
│   └── requirements.txt
├── Dockerfile
├── docker-compose.yaml
├── filebeat/
│   └── filebeat.yml
└── manifest/
    ├── job.yaml
    └── cron.yaml
```
