"""
Agent-side enforcement (the 'hands').

This is what runs on the internal node. Its job is to be paranoid:
every manifest from the cloud is verified against the control-plane PUBLIC key,
checked against the local catalog, checked for expiry, and — defense in depth —
only run if the agent's OWN local mode flag is set to investigation. The cloud
saying "investigation" is not enough; the agent independently refuses to act in
Normal Mode. The agent can verify but can never forge a job.

`run_job` here is a stub that returns synthetic read-only results. Real
collectors (AD enumeration, EDR pull) slot in behind the same interface.
"""
from __future__ import annotations

from app.jobs import signing
from app.jobs.catalog import CATALOG
from app.models import _now


class AgentRefusal(Exception):
    """Raised when the agent refuses a job. The result is reported as 'rejected'."""


class Agent:
    def __init__(self, node_id: str, control_plane_pubkey: str):
        self.node_id = node_id
        self.pubkey = control_plane_pubkey
        self.local_mode = "normal"   # set to 'investigation' by a local, customer-side switch

    # The customer flips this locally; it is NOT settable by the cloud.
    def set_local_mode(self, mode: str) -> None:
        self.local_mode = mode

    def accept(self, manifest: dict, signature: str) -> dict:
        """Validate a job. Raises AgentRefusal if anything is off; else returns the job."""
        if self.local_mode != "investigation":
            raise AgentRefusal("agent is in Normal Mode; refusing all jobs")
        if manifest.get("node_id") != self.node_id:
            raise AgentRefusal("manifest is for a different node")
        if not signing.verify(manifest, signature, self.pubkey):
            raise AgentRefusal("signature verification failed")
        if manifest.get("job_key") not in CATALOG:
            raise AgentRefusal(f"job '{manifest.get('job_key')}' not in local catalog")
        if not CATALOG[manifest["job_key"]].read_only:
            raise AgentRefusal("refusing non-read-only job")
        expires = manifest.get("expires_at")
        if expires and expires <= _now().isoformat():
            raise AgentRefusal("manifest expired")
        return manifest

    def run_job(self, manifest: dict) -> dict:
        """Execute an accepted read-only job. Stub returns synthetic findings."""
        key = manifest["job_key"]
        if key == "ad_enumerate_paths":
            return {"status": "completed",
                    "summary": "AD attack-path enumeration complete (read-only).",
                    "events": [{"source": "ad_enumerate_paths", "event_type": "attack_path_found",
                                "data": {"path": "user01 -> HelpDesk -> DnsAdmins -> DomainAdmins",
                                         "hops": 3}}]}
        return {"status": "completed", "summary": f"{key} complete (read-only).", "events": []}
