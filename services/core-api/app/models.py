"""
Core data model — the platform's shared vocabulary.

These objects are the spine everything else plugs into. They map directly to the
"Minimum data objects" on slide 10 of the service overview:

  Customer · Node · Asset · Identity · Exposure · Control ·
  Event · Finding · Alert · RemediationTask · EvidenceObject · Integration

Using SQLModel so the same class is both the ORM table and the API schema base.
SQLite by default (zero setup); swap the DB URL for Postgres in production.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel, Column, JSON


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    # Naive UTC: SQLite returns naive datetimes on read, so storing naive keeps
    # all comparisons (investigation window, job expiry) consistent.
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(str, Enum):
    open = "open"
    triaged = "triaged"
    remediating = "remediating"
    closed = "closed"
    false_positive = "false_positive"


class NodeMode(str, Enum):
    """Agent operating mode. NORMAL is the default and the safe resting state.

    normal        — collector sends output only; the cloud CANNOT task it.
    investigation — cloud may request pre-approved, signed, read-only jobs.
                    Must be explicitly enabled by the customer and is time-boxed.
    """
    normal = "normal"
    investigation = "investigation"


class JobStatus(str, Enum):
    issued = "issued"        # signed and queued for the agent
    delivered = "delivered"  # handed to the agent at check-in
    completed = "completed"  # agent returned a result
    rejected = "rejected"    # agent refused (bad signature / not in catalog / mode off)
    expired = "expired"


# --------------------------------------------------------------------------- #
# Tenancy / topology
# --------------------------------------------------------------------------- #
class Customer(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    name: str
    tier: str = "pilot"               # pilot · monitoring · full
    primary_contact: Optional[str] = None
    created_at: datetime = Field(default_factory=_now)


class Node(SQLModel, table=True):
    """Internal security node — the sensor inside the customer network."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    hostname: str
    deployment: str = "vm"            # mini-pc · vm · hardened-workstation
    healthy: bool = True
    last_checkin: Optional[datetime] = None
    # --- control model ---
    mode: NodeMode = NodeMode.normal              # safe default: no remote control
    investigation_until: Optional[datetime] = None  # time-box; None = not active
    investigation_enabled_by: Optional[str] = None   # who authorized it (audit)
    created_at: datetime = Field(default_factory=_now)

    def investigation_active(self, now: Optional[datetime] = None) -> bool:
        now = now or _now()
        return (
            self.mode == NodeMode.investigation
            and self.investigation_until is not None
            and self.investigation_until > now
        )


# --------------------------------------------------------------------------- #
# Evidence surface
# --------------------------------------------------------------------------- #
class Asset(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    kind: str                         # host · saas · device · identity-asset
    name: str
    attributes: dict = Field(default_factory=dict, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)


# --------------------------------------------------------------------------- #
# Signals -> Findings -> Alerts
# --------------------------------------------------------------------------- #
class Event(SQLModel, table=True):
    """A normalized, time-stamped signal from any collector or decoy."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    node_id: Optional[str] = Field(default=None, foreign_key="node.id")
    source: str                       # collector / decoy that produced it
    category: str                     # network · identity · endpoint · exposure · deception ...
    event_type: str                   # machine key, e.g. external_rdp_exposed
    observed_at: datetime = Field(default_factory=_now)
    data: dict = Field(default_factory=dict, sa_column=Column(JSON))


class Finding(SQLModel, table=True):
    """Correlated, risk-scored conclusion drawn from one or more events."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    rule_id: str
    title: str
    description: str = ""
    severity: Severity = Severity.medium
    status: FindingStatus = FindingStatus.open
    risk_score: int = 0               # 0-100
    evidence_event_ids: list = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)


class Alert(SQLModel, table=True):
    """A finding that crossed the notification threshold and was dispatched."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    finding_id: str = Field(foreign_key="finding.id", index=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    severity: Severity
    title: str
    dispatched: bool = False
    sinks: list = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)


# --------------------------------------------------------------------------- #
# Tasking + audit (the control channel)
# --------------------------------------------------------------------------- #
class Job(SQLModel, table=True):
    """A signed, pre-approved job issued to an agent during Investigation Mode.

    The cloud never sends free-form commands — only a job_id drawn from the
    fixed catalog, with constrained params, wrapped in a signed manifest. The
    agent verifies the signature against the control-plane public key before
    running anything, and runs only read-only catalog jobs.
    """
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    node_id: str = Field(foreign_key="node.id", index=True)
    job_key: str                       # catalog key, e.g. ad_enumerate_paths
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    manifest: dict = Field(default_factory=dict, sa_column=Column(JSON))  # exactly what was signed
    signature: str = ""                # base64 Ed25519 signature over the manifest
    status: JobStatus = JobStatus.issued
    requested_by: str = "cloud"        # operator / reasoning layer that asked
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime = Field(default_factory=_now)
    completed_at: Optional[datetime] = None
    result_summary: Optional[str] = None


class AuditLog(SQLModel, table=True):
    """Append-only record of every control-relevant action.

    'Everything is logged': mode changes, job issuance, delivery, execution,
    rejections. In production this sink is immutable (e.g. versioned S3/Glacier).
    """
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: Optional[str] = Field(default=None, index=True)
    node_id: Optional[str] = Field(default=None, index=True)
    actor: str                         # customer · cloud · agent
    action: str                        # mode.enable · job.issue · job.deliver · job.complete · job.reject ...
    detail: dict = Field(default_factory=dict, sa_column=Column(JSON))
    at: datetime = Field(default_factory=_now)


# --------------------------------------------------------------------------- #
# Local AI analyst surface — strictly advisory (Slice A)
# --------------------------------------------------------------------------- #
class AdvisoryNote(SQLModel, table=True):
    """An annotation produced by the local AI analyst — advisory ONLY.

    Deliberately a separate table from Finding. Deterministic detections
    (correlation rules, impossible-travel) write Finding rows and are ground
    truth. The LLM never writes a Finding; it can only attach an AdvisoryNote
    that *references* existing findings to explain or prioritize them. A
    poisoned model or poisoned log can therefore alter an annotation but can
    never fabricate, suppress, or downgrade an authoritative detection — there
    is no code path from the analyst to the Finding table.

    `advisory=True` is fixed and structural: anything reading these rows knows
    it is looking at model output, not a detection.
    """
    id: str = Field(default_factory=_uuid, primary_key=True)
    customer_id: str = Field(foreign_key="customer.id", index=True)
    # The deterministic findings this note comments on (may be empty for a
    # general observation). Stored as IDs, not a relationship, to keep this
    # surface read-only with respect to the Finding table.
    finding_ids: list = Field(default_factory=list, sa_column=Column(JSON))
    advisory: bool = True              # structural: never an authoritative detection
    model: str = ""                    # which Ollama model/tier produced this
    summary: str = ""                  # human-readable prioritization/explanation
    suggested_priority: Optional[str] = None   # info|low|medium|high|critical (advisory)
    # Inert nominations the analyst suggests a human consider. These are data
    # only — they are NOT JobRequests and carry no signature or channel.
    nominations: list = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)
