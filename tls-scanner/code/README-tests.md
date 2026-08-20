# Testing scanner checks

`protocols.py` / `test_protocols.py` are the reference pattern for adding a
check that can be tested without touching a live host.

## Run

```sh
docker run --rm -v "$(pwd):/app" -w /app python:3.12-slim \
  sh -c 'pip install -q pytest && python -m pytest tls-scanner/code -q'
```

(Python is not assumed on the host; these scanners target 3.12 in-image.)

## The pattern

Split every check into three pieces, so only the thinnest one touches the
network:

| Piece | Example | Tested how |
|---|---|---|
| Pure finding builder | `finding_for()` | Directly. Asserts shape, severity hints, and that keys stay inside the bridge's redaction allowlist. |
| Network probe | `probe_protocol()` | Not unit-tested. One socket call, no branching worth faking. |
| Orchestrator | `enumerate_protocols(prober=...)` | Prober injected. Covers legacy hosts, modern hosts, total refusal, and untestable-client cases with no network. |

## Two rules worth keeping

**Assert the redaction allowlist.** The bridge drops any `details` key not
listed for the scanner in `samma-panther/schema/redact.yaml`. A finding with a
new field name is silently stripped before Panther, and nothing fails loudly.
`test_finding_only_uses_redaction_allowlisted_keys` catches that at test time
instead of in production.

**Assert the finding `type` the bridge switches on.** `internal/transform/
legacy.go` is a closed switch ending in `default: unknown legacy type` — an
unrecognised `type` is routed to poison and, under the webhook sink, discarded
without archival. A new finding type needs a matching case added there first.
