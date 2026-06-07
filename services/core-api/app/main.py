"""
Blackbirch Core API — the spine.

Endpoints in this slice:
  POST /customers              register a customer
  POST /nodes                  register a security node (the sensor)
  POST /ingest                 collectors/decoys push raw events  -> normalize -> correlate -> alert
  GET  /findings               list findings (optionally by customer)
  GET  /alerts                 list dispatched alerts
  GET  /healthz                liveness

Run:  uvicorn app.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Session, select

from app.db import get_session, init_db
from app.external.analyzer import ExternalAttackSurfaceAnalyzer
from app.jobs import audit, signing
from app.jobs.issue import CatalogRejected, TaskingBlocked, issue_job
from app.reasoning import boundary
from app.reasoning.brain import ReasoningLayer
from app.reasoning.proposals import JobProposal
from app.local_ai.analyst import LocalAIAnalyst
from app.local_ai.ollama_client import ModelTier
from app.jobs.catalog import CATALOG, JobValidationError, validate
from app.models import (
    Alert,
    AdvisoryNote,
    AuditLog,
    Customer,
    Finding,
    Job,
    JobStatus,
    Node,
    NodeMode,
)
from app.models import _now  # internal tz-aware now()
from app.pipeline.correlate import correlate
from app.pipeline.normalize import normalize
from app.schemas import (
    ActRequest,
    AnalyzeRequest,
    CustomerCreate,
    ExternalScanRequest,
    IngestResult,
    JobRequest,
    JobResult,
    ModeChange,
    NodeRegister,
    PlanRequest,
    RawEvent,
)

app = FastAPI(title="Blackbirch Core API", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/customers", response_model=Customer)
def create_customer(body: CustomerCreate, session: Session = Depends(get_session)) -> Customer:
    customer = Customer(**body.model_dump())
    session.add(customer)
    session.commit()
    session.refresh(customer)
    return customer


@app.post("/nodes", response_model=Node)
def register_node(body: NodeRegister, session: Session = Depends(get_session)) -> Node:
    if not session.get(Customer, body.customer_id):
        raise HTTPException(404, "unknown customer_id")
    node = Node(**body.model_dump())
    session.add(node)
    session.commit()
    session.refresh(node)
    return node


@app.post("/ingest", response_model=IngestResult)
def ingest(body: RawEvent, session: Session = Depends(get_session)) -> IngestResult:
    if not session.get(Customer, body.customer_id):
        raise HTTPException(404, "unknown customer_id")

    event = normalize(
        customer_id=body.customer_id,
        source=body.source,
        event_type=body.event_type,
        data=body.data,
        node_id=body.node_id,
        observed_at=body.observed_at,
    )
    session.add(event)
    session.commit()
    session.refresh(event)

    findings, alerts = correlate(event, session)
    return IngestResult(
        event_id=event.id,
        findings=[f.model_dump(mode="json") for f in findings],
        alerts=[a.model_dump(mode="json") for a in alerts],
    )


@app.get("/findings", response_model=list[Finding])
def list_findings(customer_id: str | None = None, session: Session = Depends(get_session)):
    stmt = select(Finding)
    if customer_id:
        stmt = stmt.where(Finding.customer_id == customer_id)
    return session.exec(stmt.order_by(Finding.created_at.desc())).all()


@app.get("/alerts", response_model=list[Alert])
def list_alerts(customer_id: str | None = None, session: Session = Depends(get_session)):
    stmt = select(Alert)
    if customer_id:
        stmt = stmt.where(Alert.customer_id == customer_id)
    return session.exec(stmt.order_by(Alert.created_at.desc())).all()


# --------------------------------------------------------------------------- #
# Control channel — Normal Mode vs Investigation Mode
# --------------------------------------------------------------------------- #
@app.get("/control-plane/pubkey")
def control_plane_pubkey() -> dict:
    """Agents fetch this once at enrollment to verify every future job manifest."""
    return {"algorithm": "ed25519", "public_key": signing.public_key_b64()}


@app.get("/catalog")
def job_catalog() -> dict:
    """The complete set of jobs the cloud is ever allowed to request."""
    return {
        k: {"description": s.description, "read_only": s.read_only,
            "allowed_params": list(s.allowed_params)}
        for k, s in CATALOG.items()
    }


@app.post("/nodes/{node_id}/mode", response_model=Node)
def set_mode(node_id: str, body: ModeChange, session: Session = Depends(get_session)) -> Node:
    """CUSTOMER action. Investigation Mode is opt-in and time-boxed; it auto-reverts."""
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, "unknown node")
    try:
        mode = NodeMode(body.mode)
    except ValueError:
        raise HTTPException(400, "mode must be 'normal' or 'investigation'")

    if mode == NodeMode.investigation:
        node.mode = NodeMode.investigation
        node.investigation_until = _now() + timedelta(minutes=body.duration_minutes)
        node.investigation_enabled_by = body.enabled_by
        action, detail = "mode.enable_investigation", {
            "enabled_by": body.enabled_by,
            "until": node.investigation_until.isoformat(),
        }
    else:
        node.mode = NodeMode.normal
        node.investigation_until = None
        node.investigation_enabled_by = None
        action, detail = "mode.return_to_normal", {"by": body.enabled_by}

    session.add(node)
    session.commit()
    session.refresh(node)
    audit.record(session, actor="customer", action=action,
                 customer_id=node.customer_id, node_id=node.id, detail=detail)
    session.refresh(node)
    return node


@app.post("/nodes/{node_id}/jobs", response_model=Job)
def request_job(node_id: str, body: JobRequest, session: Session = Depends(get_session)) -> Job:
    """CLOUD action. Allowed only when the node is actively in Investigation Mode,
    and only for read-only jobs that exist in the catalog. The manifest is signed.

    Delegates to the single issue_job chokepoint — the only code that signs edge jobs."""
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, "unknown node")
    try:
        return issue_job(node, body.job_key, body.params,
                         requested_by=body.requested_by, ttl_minutes=body.ttl_minutes,
                         session=session)
    except TaskingBlocked as exc:
        raise HTTPException(409, str(exc))
    except CatalogRejected as exc:
        raise HTTPException(400, str(exc))


@app.get("/nodes/{node_id}/checkin")
def checkin(node_id: str, session: Session = Depends(get_session)) -> dict:
    """AGENT action. Returns current mode and any signed jobs to run.

    In Normal Mode the agent is told mode=normal and receives ZERO jobs — there
    is no control surface at all. Jobs are only ever handed out while Investigation
    Mode is active; expired windows yield nothing."""
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, "unknown node")

    node.last_checkin = _now()
    session.add(node)
    session.commit()

    jobs: list[dict] = []
    if node.investigation_active():
        pending = session.exec(
            select(Job).where(Job.node_id == node.id, Job.status == JobStatus.issued)
        ).all()
        for job in pending:
            if job.expires_at <= _now():
                job.status = JobStatus.expired
            else:
                job.status = JobStatus.delivered
                jobs.append({"manifest": job.manifest, "signature": job.signature})
                audit.record(session, actor="cloud", action="job.deliver",
                             customer_id=node.customer_id, node_id=node.id,
                             detail={"job_id": job.id})
            session.add(job)
        session.commit()

    return {"mode": node.mode.value, "investigation_active": node.investigation_active(),
            "jobs": jobs}


@app.post("/jobs/{job_id}/result", response_model=IngestResult | dict)
def submit_result(job_id: str, body: JobResult, session: Session = Depends(get_session)):
    """AGENT action. Records the outcome and feeds any findings into the pipeline."""
    job = session.get(Job, job_id)
    if not job:
        raise HTTPException(404, "unknown job")

    job.status = JobStatus.completed if body.status == "completed" else JobStatus.rejected
    job.completed_at = _now()
    job.result_summary = body.summary
    session.add(job)
    session.commit()
    audit.record(session, actor="agent", action=f"job.{job.status.value}",
                 customer_id=job.customer_id, node_id=job.node_id,
                 detail={"job_id": job.id, "summary": body.summary})

    all_findings, all_alerts = [], []
    for raw in body.events:
        event = normalize(customer_id=job.customer_id, node_id=job.node_id,
                          source=raw.get("source", job.job_key),
                          event_type=raw.get("event_type", "job_result"),
                          data=raw.get("data", {}))
        session.add(event)
        session.commit()
        session.refresh(event)
        f, a = correlate(event, session)
        all_findings += [x.model_dump(mode="json") for x in f]
        all_alerts += [x.model_dump(mode="json") for x in a]

    return {"job_id": job.id, "status": job.status.value,
            "findings": all_findings, "alerts": all_alerts}


@app.get("/audit", response_model=list[AuditLog])
def list_audit(node_id: str | None = None, session: Session = Depends(get_session)):
    stmt = select(AuditLog)
    if node_id:
        stmt = stmt.where(AuditLog.node_id == node_id)
    return session.exec(stmt.order_by(AuditLog.at.desc())).all()


# --------------------------------------------------------------------------- #
# External attack surface analyzer (cloud-side, outside-in)
# --------------------------------------------------------------------------- #
@app.post("/external/scan", response_model=IngestResult | dict)
def external_scan(body: ExternalScanRequest, session: Session = Depends(get_session)):
    """Run an outside-in perimeter analysis and feed findings into the same
    correlation engine as inside-out data — one unified view of risk."""
    if not session.get(Customer, body.customer_id):
        raise HTTPException(404, "unknown customer_id")

    cert_not_after = None
    if body.cert_days_remaining is not None:
        cert_not_after = _now() + timedelta(days=body.cert_days_remaining)

    raw_events = ExternalAttackSurfaceAnalyzer().analyze(
        body.domain, spf=body.spf, dmarc=body.dmarc,
        cert_not_after=cert_not_after, open_ports=body.open_ports, live=body.live,
    )

    all_findings, all_alerts = [], []
    for raw in raw_events:
        event = normalize(customer_id=body.customer_id, source=raw["source"],
                          event_type=raw["event_type"], data=raw["data"])
        session.add(event)
        session.commit()
        session.refresh(event)
        f, a = correlate(event, session)
        all_findings += [x.model_dump(mode="json") for x in f]
        all_alerts += [x.model_dump(mode="json") for x in a]

    return {"domain": body.domain, "events_observed": len(raw_events),
            "findings": all_findings, "alerts": all_alerts}


# --------------------------------------------------------------------------- #
# Reasoning layer (cloud "brain") — proposes; the boundary disposes
# --------------------------------------------------------------------------- #
@app.post("/reasoning/plan")
def reasoning_plan(body: PlanRequest, session: Session = Depends(get_session)) -> dict:
    """Run the brain over the customer's open findings. Returns PROPOSALS ONLY.

    This endpoint has no edge effect whatsoever — no job is signed, nothing
    reaches a node. Proposals are inert suggestions for a human (or the act
    step) to consider."""
    findings = session.exec(
        select(Finding).where(Finding.customer_id == body.customer_id)
        .order_by(Finding.created_at.desc())
    ).all()
    proposals = ReasoningLayer().plan([f.model_dump(mode="json") for f in findings])
    return {"proposal_count": len(proposals),
            "proposals": [p.__dict__ for p in proposals],
            "note": "Proposals are inert. Nothing has been sent to any node."}


@app.post("/reasoning/act", response_model=Job)
def reasoning_act(body: ActRequest, session: Session = Depends(get_session)) -> Job:
    """Send ONE proposal to the edge via the boundary. This is the *only* way the
    brain's output reaches a node, and it still passes every gate: Investigation
    Mode + read-only catalog + signing + audit. In Normal Mode this returns 409;
    an off-catalog job_key returns 400 — proving the brain cannot bypass the catalog."""
    proposal = JobProposal(node_id=body.node_id, job_key=body.job_key,
                           rationale=body.rationale, params=body.params)
    try:
        return boundary.dispatch(proposal, session)
    except boundary.ProposalRejected as exc:
        # Map the boundary's refusal to the same status codes the HTTP job path uses.
        code = 409 if "Investigation Mode" in exc.reason else (
            404 if "unknown node" in exc.reason else 400)
        raise HTTPException(code, exc.reason)


# --------------------------------------------------------------------------- #
# Local AI analyst (on-appliance) — advisory only, never authoritative
# --------------------------------------------------------------------------- #
@app.post("/local-ai/analyze")
def local_ai_analyze(body: AnalyzeRequest, session: Session = Depends(get_session)) -> dict:
    """Run the LOCAL AI analyst over a customer's findings + telemetry.

    Returns an ADVISORY annotation only. No Finding is created or modified, no
    severity is changed, and nothing is sent to any node. Any jobs the analyst
    suggests are inert nominations (advisory=true, signed=false) — turning one
    into an action requires the human-driven Authorization Broker path (Slice B),
    never this endpoint.
    """
    if not session.get(Customer, body.customer_id):
        raise HTTPException(404, "unknown customer_id")
    try:
        tier = ModelTier(body.tier)
    except ValueError:
        raise HTTPException(400, "tier must be 'continuous' or 'periodic'")

    note = LocalAIAnalyst().annotate(body.customer_id, session, tier=tier)
    audit.record(session, actor="local-ai", action="advisory.annotate",
                 customer_id=body.customer_id,
                 detail={"note_id": note.id, "model": note.model,
                         "nominations": len(note.nominations)})
    return {
        "advisory": True,
        "note_id": note.id,
        "model": note.model,
        "summary": note.summary,
        "suggested_priority": note.suggested_priority,
        "nominations": note.nominations,
        "note": "Advisory only. No finding was created or changed; nothing was sent to any node.",
    }


@app.get("/local-ai/advisories", response_model=list[AdvisoryNote])
def list_advisories(customer_id: str | None = None, session: Session = Depends(get_session)):
    stmt = select(AdvisoryNote)
    if customer_id:
        stmt = stmt.where(AdvisoryNote.customer_id == customer_id)
    return session.exec(stmt.order_by(AdvisoryNote.created_at.desc())).all()
