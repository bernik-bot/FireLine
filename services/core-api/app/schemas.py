"""Request/response schemas for the API boundary (kept separate from ORM models)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CustomerCreate(BaseModel):
    name: str
    tier: str = "pilot"
    primary_contact: Optional[str] = None


class NodeRegister(BaseModel):
    customer_id: str
    hostname: str
    deployment: str = "vm"


class RawEvent(BaseModel):
    """What a collector or decoy POSTs to /ingest."""
    customer_id: str
    source: str                 # e.g. network_discovery, honeypot
    event_type: str             # e.g. external_rdp_exposed
    data: dict = {}
    node_id: Optional[str] = None
    observed_at: Optional[datetime] = None   # collectors report real event time


class IngestResult(BaseModel):
    event_id: str
    findings: list[dict]
    alerts: list[dict]


class ModeChange(BaseModel):
    """Customer action: enable/disable Investigation Mode (time-boxed)."""
    mode: str                       # "normal" | "investigation"
    enabled_by: str                 # who authorized (recorded in audit)
    duration_minutes: int = 60      # auto-reverts to normal after this window


class JobRequest(BaseModel):
    """Cloud asks the agent to run one pre-approved catalog job."""
    job_key: str
    params: dict = {}
    requested_by: str = "cloud"
    ttl_minutes: int = 15


class JobResult(BaseModel):
    """Agent returns the outcome of a signed job."""
    status: str = "completed"       # completed | rejected
    summary: str = ""
    events: list[dict] = []         # normalized findings to feed the pipeline


class ExternalScanRequest(BaseModel):
    """Cloud-side outside-in scan of a customer's perimeter.

    Data can be injected (offline / pilot) or fetched live when live=true.
    """
    customer_id: str
    domain: str
    live: bool = False
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    cert_days_remaining: Optional[int] = None
    open_ports: list[int] = []


class PlanRequest(BaseModel):
    """Run the reasoning layer over a customer's open findings -> proposals only."""
    customer_id: str


class ActRequest(BaseModel):
    """Send ONE proposal through the boundary to the edge (subject to all gates)."""
    node_id: str
    job_key: str
    params: dict = {}
    rationale: str = ""


class AnalyzeRequest(BaseModel):
    """Run the LOCAL AI analyst over a customer's findings/telemetry.

    Produces an advisory annotation only — no finding is created or changed and
    nothing reaches a node. `tier` selects the local model size.
    """
    customer_id: str
    tier: str = "continuous"        # "continuous" (8B) | "periodic" (70B)
