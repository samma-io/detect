# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and run

All `docker compose` commands use the **repo root as the build context** — always run them from the repo root.

```bash
# Build and run any tool (replace <tool> with the directory name)
TARGET=example.com docker compose -f <tool>/docker-compose.yaml up --build

# Run without rebuilding (uses image from GHCR)
TARGET=example.com docker compose -f <tool>/docker-compose.yaml up

# Check output
cat <tool>/out/<tool>.json

# Confirm detection finished
ls <tool>/out/die
```

There are no automated tests. Verification is manual: run the container, inspect the JSON output in `<tool>/out/`.

## CI/CD

`.github/workflows/docker-build.yml` runs on every push to `main`. It uses a matrix strategy to build all 8 tool images in parallel and pushes them to GHCR as `ghcr.io/samma-io/detect-<tool-name>:latest` and `ghcr.io/samma-io/detect-<tool-name>:sha-<short-sha>`.

The workflow authenticates to GHCR using the automatic `GITHUB_TOKEN` — no secrets need to be configured.

## Architecture

### Tool lifecycle

Each tool is a self-contained Docker image that:
1. Reads config from env vars, falling back to `config.yaml` for defaults
2. Performs the detection and calls `sammaParser.logger(finding_dict)` for each result
3. Calls `sammaParser.endThis()` at the end, which writes `{"scan":"done"}` then creates `/out/die`

The `/out/die` file is the shutdown signal — the Filebeat sidecar's liveness probe watches for it and kills the pod.

### Two-module pattern

Every tool has exactly two Python files:

- **`scan.py`** — detection logic only; imports `sammaParser` and calls `logger()` / `endThis()`
- **`sammaParser.py`** — handles output: appends `samma-io` metadata to every record, writes to `/out/<PARSER>.json` if `WRITE_TO_FILE != "False"`, and prints to stdout

`sammaParser.py` is duplicated per tool (not shared) so each image is fully self-contained. The only difference between copies is the default value of `PARSER` and `SAMMA_IO_SCANNER`.

### Config precedence

Environment variable → `config.yaml` section for that tool → hardcoded fallback in `scan.py`.

`config.yaml` lives at the repo root and is copied into every image at `/config.yaml`. `scan.py` loads it with a relative path (`../../config.yaml` from `/code/`).

### Build context

Dockerfiles `COPY` from paths relative to the repo root (e.g. `COPY port-scanner/code /code`), which is why the build context must be `..` in every `docker-compose.yaml` and `.` (repo root) in the GitHub Actions workflow.

### Kubernetes manifests

Each tool's `manifest/` directory contains two files with identical structure:
- `job.yaml` — one-off `batch/v1 Job`
- `cron.yaml` — `batch/v1 CronJob`

Both embed the Filebeat config and liveness script as ConfigMaps in the same file (multi-doc YAML). ConfigMap names are suffixed per tool (`-ps`, `-tr`, `-tls`, `-hh`, `-dns`, `-ssh`, `-whois`, `-hr`) to avoid collisions in the `samma-io` namespace.

## Adding a new tool

1. Create `<name>/code/scan.py`, `sammaParser.py` (copy from any existing tool, change `PARSER` default), `requirements.txt`
2. Create `Dockerfile` — copy pattern from an existing tool; add apt/pip deps if needed
3. Create `docker-compose.yaml` with `context: ..` and tool-specific env vars; set `image: ghcr.io/samma-io/detect-<name>:latest`
4. Copy `filebeat/filebeat.yml` verbatim from any existing tool
5. Create `manifest/job.yaml` and `manifest/cron.yaml` using a new ConfigMap suffix
6. Add a defaults section to `config.yaml`
7. Add the new tool name to the `scanner` matrix in `.github/workflows/docker-build.yml`
