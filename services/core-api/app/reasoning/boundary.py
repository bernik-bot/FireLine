"""
The boundary — the one-way valve between the brain and the edge.

A JobProposal is inert. The ONLY way it becomes something a node will run is
`dispatch`, and `dispatch` does not sign or send anything itself — it hands the
proposal to the single signed-job chokepoint (jobs.issue.issue_job), which
enforces Investigation Mode + the read-only catalog before any manifest is
signed. So the brain's reach to a client host is exactly: propose -> boundary
-> catalog/signing gate -> edge. No catalog entry, no edge action. Full stop.

Consequences that fall out for free, proven by tests:
  • A proposal for a job not in the catalog is refused here.
  • A proposal for a node in Normal Mode is refused here (cloud can't task it).
  • Every dispatch (and every refusal) lands in the audit log.
"""
from __future__ import annotations

from sqlmodel import Session

from app.jobs.issue import CatalogRejected, TaskingBlocked, issue_job
from app.models import Job, Node
from app.reasoning.proposals import JobProposal


class ProposalRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def dispatch(proposal: JobProposal, session: Session, *, requested_by: str = "reasoning-layer",
             ttl_minutes: int = 15) -> Job:
    """Route a single proposal to the edge through the signed catalog, or refuse.

    Note what is NOT here: no signing, no manifest building, no node channel.
    All of that lives behind issue_job, which the HTTP endpoint uses too."""
    node = session.get(Node, proposal.node_id)
    if not node:
        raise ProposalRejected("proposal targets an unknown node")
    try:
        return issue_job(node, proposal.job_key, proposal.params,
                         requested_by=requested_by, ttl_minutes=ttl_minutes, session=session)
    except TaskingBlocked as exc:
        raise ProposalRejected(str(exc))
    except CatalogRejected as exc:
        raise ProposalRejected(str(exc))
