"""
Agent runner — what actually runs on the internal node at a client site.

It is outbound-only: it polls the cloud, never listens. Each loop it checks in,
runs any signed jobs the cloud delivered (verifying every manifest against the
control-plane public key first, and only while the local switch is in
investigation mode), and reports results back. In Normal Mode it still ships
routine telemetry but accepts no jobs.

Usage:
  export BLACKBIRCH_CLOUD=https://collector.yourdomain.com
  export BLACKBIRCH_NODE_ID=<node id from registration>
  python collectors/agent_runner.py
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

from app.agent import Agent, AgentRefusal

CLOUD = os.environ.get("BLACKBIRCH_CLOUD", "http://127.0.0.1:8000").rstrip("/")
NODE_ID = os.environ.get("BLACKBIRCH_NODE_ID", "")
POLL_SECONDS = int(os.environ.get("BLACKBIRCH_POLL_SECONDS", "30"))
# The customer flips this locally; it is NOT settable by the cloud.
LOCAL_MODE = os.environ.get("BLACKBIRCH_LOCAL_MODE", "normal")


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"{CLOUD}{path}", timeout=10) as r:
        return json.loads(r.read())


def _post(path: str, body: dict) -> dict:
    req = urllib.request.Request(f"{CLOUD}{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def main() -> None:
    if not NODE_ID:
        raise SystemExit("set BLACKBIRCH_NODE_ID (from node registration)")

    # Fetch the control-plane public key ONCE at enrollment and pin it.
    pubkey = _get("/control-plane/pubkey")["public_key"]
    agent = Agent(NODE_ID, pubkey)
    agent.set_local_mode(LOCAL_MODE)
    print(f"agent up · node={NODE_ID[:8]} · mode={LOCAL_MODE} · cloud={CLOUD}")

    while True:
        try:
            ci = _get(f"/nodes/{NODE_ID}/checkin")
            for handed in ci.get("jobs", []):
                manifest, sig = handed["manifest"], handed["signature"]
                job_id = manifest["job_id"]
                try:
                    accepted = agent.accept(manifest, sig)        # verify or raise
                    result = agent.run_job(accepted)              # read-only execute
                except AgentRefusal as exc:
                    result = {"status": "rejected", "summary": str(exc), "events": []}
                _post(f"/jobs/{job_id}/result", result)
                print(f"  job {job_id[:8]} -> {result['status']}")
        except Exception as exc:        # never die on a transient cloud/network error
            print(f"  loop error (will retry): {exc}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
