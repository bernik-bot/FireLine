# Blackbirch Cyber Platform

Managed cyber defense & posture-monitoring platform. **Assess once. Monitor continuously. Remediate through Blackbirch.**

This repo is being built **spine-first**: one working vertical slice end-to-end, then expand module by module against the component map in [`ROADMAP.md`](ROADMAP.md). Empty stubs for 40 services were deliberately *not* created — they rot and mislead. Everything checked in runs.

## What works today (slice 1 — the spine)

```
collector / decoy  ──POST /ingest──▶  normalize  ──▶  correlate (rules)  ──▶  alert sinks
                                          │                  │
                                          ▼                  ▼
                                    Event (stored)   Finding + Alert (stored)
```

- **Core data model** — `Customer · Node · Asset · Event · Finding · Alert` (the slide-10 vocabulary), in `app/models.py`.
- **Ingestion API** — `POST /ingest` accepts raw events from any collector or decoy.
- **Normalize** — maps per-source payloads onto the canonical `Event` (`app/pipeline/normalize.py`).
- **Correlation engine** — the alert catalog as code; representative rules across exposure, identity, endpoint, and deception (`app/pipeline/rules.py`).
- **Alert sinks** — console (always on) + generic webhook, Slack/Teams compatible (`app/pipeline/alerting.py`).
- **Sample collector** — `collectors/network_discovery.py` simulates the node→cloud flow.
- **Tests** — end-to-end pipeline tests, in-memory, no external services.

## Quickstart

```bash
cd services/core-api
pip install -e ".[dev]"           # or: pip install fastapi "uvicorn[standard]" sqlmodel pytest httpx

# run the tests
pytest -q

# run the API
uvicorn app.main:app --reload     # docs at http://127.0.0.1:8000/docs

# in another shell: register a customer, then feed it events
CID=$(curl -s -X POST localhost:8000/customers -H 'Content-Type: application/json' \
      -d '{"name":"Acme Corp"}' | python -c "import sys,json;print(json.load(sys.stdin)['id'])")
python collectors/network_discovery.py "$CID"
curl -s "localhost:8000/alerts?customer_id=$CID"
```

Set `BLACKBIRCH_WEBHOOK_URL` to also fan alerts out to a Slack/Teams incoming webhook.
Set `BLACKBIRCH_DB_URL` (e.g. a Postgres URL) to move off the default SQLite file.

## Control channel — two modes

The agent's control surface is deliberately minimal and opt-in:

- **Normal Mode (default)** — the collector sends output only. The cloud *cannot* task the agent. Any task attempt is refused (`409`) and logged.
- **Investigation Mode** — the customer explicitly enables it for a time-boxed window. Only then may the cloud request jobs, and only jobs that exist in a fixed, read-only catalog. Each job is wrapped in an Ed25519-signed manifest; the agent verifies the signature against the control-plane public key and independently enforces its own local mode. A stolen agent can verify jobs but can never forge one. Everything is written to an append-only audit log.

```bash
# Normal mode: cloud is blocked
curl -s -X POST localhost:8000/nodes/$NID/jobs -d '{"job_key":"ad_enumerate_paths"}' -H 'Content-Type: application/json'
# -> 409 "node is not in Investigation Mode — cloud cannot task it"

# Customer enables investigation (time-boxed), then cloud can request catalogued jobs only
curl -s -X POST localhost:8000/nodes/$NID/mode -H 'Content-Type: application/json' \
  -d '{"mode":"investigation","enabled_by":"ciso@acme","duration_minutes":30}'
curl -s localhost:8000/catalog        # the only jobs the cloud may ever request
curl -s localhost:8000/audit?node_id=$NID   # full control-action trail
```

Active/containment jobs (isolate host, disable account) are intentionally absent from the catalog — they belong behind a separate approval gate, not on this read-only channel.

## Layout

```
services/core-api/
  app/
    models.py            # core data model (the shared vocabulary)
    db.py                # engine/session (sqlite default, postgres-ready)
    schemas.py           # API request/response shapes
    main.py              # FastAPI app: /customers /nodes /ingest /findings /alerts
    pipeline/
      normalize.py       # raw payload -> canonical Event
      rules.py           # alert catalog as code
      correlate.py       # run rules -> Finding -> Alert -> dispatch
      alerting.py        # console + webhook sinks
  collectors/
    network_discovery.py # sample collector (stand-in for node-side agent)
  tests/
    test_pipeline.py     # end-to-end pipeline tests
```

## Where this is going

`ROADMAP.md` maps every component from the architecture manifest onto a build
order. Each new collector, integration, or module plugs into the spine above:
emit events → add rules → route alerts. Next slices: the deception/honeypot
service (well-specified, high-signal) and the control-plane node registry +
job manifests.

> Status: pilot architecture, not a finished product. Built to be extended, not to impress empty.
