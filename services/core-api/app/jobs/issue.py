"""
The one and only function that can turn an intent into a signed edge job.

EVERY path that reaches a client node — the HTTP endpoint a human/operator hits,
and the reasoning-layer boundary — funnels through `issue_job`. There is no
other code that signs a manifest for the edge. That makes the catalog + the
Investigation-Mode gate a true one-way valve: enforce it here once, and nothing
upstream can bypass it.

The enforced invariants, in order:
  1. node must be in active Investigation Mode (customer opted in, not expired)
  2. job_key must be a read-only entry in the fixed catalog (validate())
  3. only then is a manifest built and Ed25519-signed
  4. the action is written to the append-only audit log
"""
from __future__ import annotations

from datetime import timedelta

from sqlmodel import Session

from app.jobs import audit, signing
from app.jobs.catalog import JobValidationError, validate
from app.models import Job, JobStatus, Node, _now


class TaskingBlocked(Exception):
    """Node not in Investigation Mode — the edge is unreachable."""


class CatalogRejected(Exception):
    """Requested job is not a read-only catalog entry."""


def issue_job(
    node: Node,
    job_key: str,
    params: dict,
    *,
    requested_by: str,
    ttl_minutes: int,
    session: Session,
) -> Job:
    # (1) Investigation-Mode gate — same wall the cloud hits.
    if not node.investigation_active():
        audit.record(session, actor="cloud", action="job.blocked_not_investigation",
                     customer_id=node.customer_id, node_id=node.id,
                     detail={"job_key": job_key, "by": requested_by})
        raise TaskingBlocked("node is not in Investigation Mode — cannot task it")

    # (2) Catalog gate — only read-only, known jobs survive.
    try:
        validate(job_key, params)
    except JobValidationError as exc:
        audit.record(session, actor="cloud", action="job.rejected_catalog",
                     customer_id=node.customer_id, node_id=node.id,
                     detail={"error": str(exc), "by": requested_by})
        raise CatalogRejected(str(exc))

    # (3) Sign.
    expires_at = _now() + timedelta(minutes=ttl_minutes)
    job = Job(
        customer_id=node.customer_id, node_id=node.id, job_key=job_key,
        params=params, requested_by=requested_by,
        status=JobStatus.issued, expires_at=expires_at,
    )
    job.manifest = {
        "job_id": job.id, "node_id": node.id, "job_key": job_key,
        "params": params, "read_only": True,
        "issued_at": job.created_at.isoformat(), "expires_at": expires_at.isoformat(),
    }
    job.signature = signing.sign(job.manifest)

    session.add(job)
    session.commit()
    session.refresh(job)

    # (4) Audit.
    audit.record(session, actor="cloud", action="job.issue",
                 customer_id=node.customer_id, node_id=node.id,
                 detail={"job_id": job.id, "job_key": job_key, "by": requested_by})
    session.refresh(job)
    return job
