"""
The reasoning layer (the "brain"). Pluggable: a transparent heuristic today,
a Hermes/LLM-backed planner later. Its entire contract is:

    findings in  ->  proposals out

CAPABILITY BOUNDARY — read carefully. This module deliberately imports nothing
that can touch a node: no signing, no Job model, no agent, no HTTP client, no
session. It cannot create, sign, or deliver a job. Its only output is inert
JobProposal data. Swapping the heuristic for an LLM does not change this — an
LLM planner returns proposals too, and proposals are powerless until the
boundary routes them through the signed catalog. (test_reasoning_boundary.py
asserts this module stays import-clean, so a future shortcut fails CI.)

The brain only ever proposes jobs that exist in the catalog; anything else is
dropped here, and would be rejected at the boundary anyway (defense in depth).
"""
from __future__ import annotations

from app.jobs.catalog import CATALOG
from app.reasoning.proposals import JobProposal

# finding rule_id -> follow-up investigation job + why. All targets are
# read-only catalog jobs. This is the "what should I look at next" logic an
# analyst (or an LLM) performs; here it's explicit and auditable.
_FOLLOW_UP: dict[str, tuple[str, str]] = {
    "DEC-011": ("ad_enumerate_paths",
                "Deception asset was touched — map what the attacker could reach from here."),
    "IDN-005": ("identity_mfa_state",
                "Admin MFA disabled — pull full identity posture for blast-radius."),
    "IDN-006": ("identity_mfa_state",
                "Impossible travel — pull identity posture (MFA, sessions, OAuth) to confirm takeover."),
    "EXP-001": ("network_open_services",
                "External RDP exposed — enumerate other listening services on the host."),
    "EDR-009": ("edr_pull_detections",
                "EDR offline — pull recent detections to check what was missed."),
}


class ReasoningLayer:
    def plan(self, findings: list[dict]) -> list[JobProposal]:
        proposals: list[JobProposal] = []
        for f in findings:
            mapping = self._follow_up_for(f)
            if mapping is None:
                continue
            job_key, rationale = mapping
            # Only catalogued jobs can even be proposed.
            if job_key not in CATALOG:
                continue
            proposals.append(JobProposal(
                node_id=f.get("node_id") or "",
                job_key=job_key,
                rationale=rationale,
                confidence=self._confidence(f),
                params={},
            ))
        return proposals

    def _follow_up_for(self, finding: dict) -> tuple[str, str] | None:
        return _FOLLOW_UP.get(finding.get("rule_id", ""))

    def _confidence(self, finding: dict) -> float:
        return {"critical": 0.95, "high": 0.8, "medium": 0.5}.get(
            finding.get("severity", "medium"), 0.4)
