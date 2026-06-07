"""
Reasoning-boundary tests — prove the brain cannot reach a client host except
through the signed catalog.

Three kinds of proof:
  1. Structural: the brain module imports nothing that can act on a node.
  2. Behavioural: proposals are inert; only the boundary issues jobs, and only
     through the same Investigation-Mode + catalog gates.
  3. Negative: an off-catalog or Normal-Mode proposal is refused at the boundary.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

from app import db, main
from app.reasoning import boundary
from app.reasoning.brain import ReasoningLayer
from app.reasoning.proposals import JobProposal


# --- (1) Structural proof: the brain can't even import a way to act -----------
def test_brain_module_has_no_edge_capability():
    """If someone wires the brain straight to signing/agent/issue/http, fail CI."""
    src = Path(main.__file__).with_name("reasoning") / "brain.py"
    tree = ast.parse(src.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")

    forbidden = {"app.jobs.signing", "app.jobs.issue", "app.agent",
                 "app.reasoning.boundary", "httpx", "requests", "socket", "urllib"}
    leaks = {m for m in imported if any(m == f or m.startswith(f + ".") for f in forbidden)}
    assert not leaks, f"brain must not import edge-reaching modules, found: {leaks}"


def test_proposal_is_inert_data():
    p = JobProposal(node_id="n1", job_key="ad_enumerate_paths", rationale="x")
    # A proposal has no method to sign, send, or execute anything.
    for attr in ("sign", "send", "dispatch", "execute", "run"):
        assert not hasattr(p, attr)


# --- behavioural fixtures ----------------------------------------------------
@pytest.fixture(name="client")
def client_fixture():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)

    def _get_session():
        with Session(engine) as session:
            yield session

    main.app.dependency_overrides[db.get_session] = _get_session
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.clear()


def _setup(client):
    cid = client.post("/customers", json={"name": "Acme"}).json()["id"]
    nid = client.post("/nodes", json={"customer_id": cid, "hostname": "sec-node-01"}).json()["id"]
    # produce a critical deception finding for this node
    client.post("/ingest", json={"customer_id": cid, "node_id": nid, "source": "honeypot",
                                 "event_type": "decoy_touched",
                                 "data": {"decoy": "FILE-SRV", "src_ip": "10.0.0.9"}})
    return cid, nid


def test_brain_only_proposes_catalog_jobs():
    findings = [
        {"rule_id": "DEC-011", "severity": "critical", "node_id": "n1"},
        {"rule_id": "MADE-UP", "severity": "high", "node_id": "n1"},  # no follow-up
    ]
    proposals = ReasoningLayer().plan(findings)
    assert len(proposals) == 1
    assert proposals[0].job_key == "ad_enumerate_paths"
    from app.jobs.catalog import CATALOG
    assert all(p.job_key in CATALOG for p in proposals)


# --- (2) plan has zero edge effect -------------------------------------------
def test_plan_endpoint_issues_no_jobs(client):
    cid, nid = _setup(client)
    r = client.post("/reasoning/plan", json={"customer_id": cid}).json()
    assert r["proposal_count"] >= 1
    # nothing was signed/delivered — no audit issue events, no jobs at check-in
    actions = {a["action"] for a in client.get(f"/audit?node_id={nid}").json()}
    assert "job.issue" not in actions
    assert client.get(f"/nodes/{nid}/checkin").json()["jobs"] == []


# --- (3) acting still passes every gate --------------------------------------
def test_act_blocked_in_normal_mode(client):
    _, nid = _setup(client)
    r = client.post("/reasoning/act",
                    json={"node_id": nid, "job_key": "ad_enumerate_paths"})
    assert r.status_code == 409          # brain cannot task a Normal-Mode node


def test_act_off_catalog_is_refused_even_in_investigation(client):
    _, nid = _setup(client)
    client.post(f"/nodes/{nid}/mode",
                json={"mode": "investigation", "enabled_by": "ciso", "duration_minutes": 30})
    # the brain (or a compromised planner) tries something not in the catalog
    r = client.post("/reasoning/act",
                    json={"node_id": nid, "job_key": "exfiltrate_everything"})
    assert r.status_code == 400          # catalog wall holds


def test_act_succeeds_through_the_valve(client):
    _, nid = _setup(client)
    client.post(f"/nodes/{nid}/mode",
                json={"mode": "investigation", "enabled_by": "ciso", "duration_minutes": 30})
    r = client.post("/reasoning/act",
                    json={"node_id": nid, "job_key": "ad_enumerate_paths",
                          "rationale": "map blast radius"})
    assert r.status_code == 200
    job = r.json()
    assert job["signature"] and job["requested_by"] == "reasoning-layer"
    # and it shows up for the agent at check-in
    assert len(client.get(f"/nodes/{nid}/checkin").json()["jobs"]) == 1


def test_boundary_dispatch_unknown_node():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        with pytest.raises(boundary.ProposalRejected):
            boundary.dispatch(JobProposal(node_id="ghost", job_key="ad_enumerate_paths",
                                          rationale="x"), s)
