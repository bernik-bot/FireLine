"""
Control-channel tests — the two modes must behave exactly as specified.

Mode 1 (Normal): collector sends output only; cloud CANNOT control it.
Mode 2 (Investigation): cloud may request only pre-approved signed jobs;
                        customer must enable it; everything is logged.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

from app import agent as agent_mod
from app import db, main
from app.jobs import signing


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


def _customer_and_node(client) -> tuple[str, str]:
    cid = client.post("/customers", json={"name": "Acme"}).json()["id"]
    nid = client.post("/nodes", json={"customer_id": cid, "hostname": "sec-node-01"}).json()["id"]
    return cid, nid


# --- Mode 1: Normal ---------------------------------------------------------
def test_node_defaults_to_normal(client):
    _, nid = _customer_and_node(client)
    r = client.get(f"/nodes/{nid}/checkin").json()
    assert r["mode"] == "normal"
    assert r["investigation_active"] is False
    assert r["jobs"] == []


def test_cloud_cannot_task_in_normal_mode(client):
    _, nid = _customer_and_node(client)
    r = client.post(f"/nodes/{nid}/jobs", json={"job_key": "ad_enumerate_paths"})
    assert r.status_code == 409          # refused: not in investigation mode
    # ...and the attempt is logged
    actions = [a["action"] for a in client.get(f"/audit?node_id={nid}").json()]
    assert "job.blocked_not_investigation" in actions


# --- Mode 2: Investigation --------------------------------------------------
def _enable_investigation(client, nid):
    return client.post(f"/nodes/{nid}/mode",
                       json={"mode": "investigation", "enabled_by": "ciso@acme", "duration_minutes": 30})


def test_investigation_requires_customer_enable_then_signs_job(client):
    _, nid = _customer_and_node(client)
    assert _enable_investigation(client, nid).status_code == 200

    r = client.post(f"/nodes/{nid}/jobs", json={"job_key": "ad_enumerate_paths", "params": {"max_depth": 5}})
    assert r.status_code == 200
    job = r.json()
    assert job["signature"]
    # signature actually verifies against the control-plane public key
    assert signing.verify(job["manifest"], job["signature"], signing.public_key_b64())

    # agent receives it at check-in
    ci = client.get(f"/nodes/{nid}/checkin").json()
    assert ci["mode"] == "investigation" and len(ci["jobs"]) == 1


def test_uncatalogued_job_is_rejected(client):
    _, nid = _customer_and_node(client)
    _enable_investigation(client, nid)
    r = client.post(f"/nodes/{nid}/jobs", json={"job_key": "rm_minus_rf_everything"})
    assert r.status_code == 400


def test_everything_is_logged(client):
    cid, nid = _customer_and_node(client)
    _enable_investigation(client, nid)
    client.post(f"/nodes/{nid}/jobs", json={"job_key": "edr_pull_detections"})
    client.get(f"/nodes/{nid}/checkin")
    actions = {a["action"] for a in client.get(f"/audit?node_id={nid}").json()}
    assert {"mode.enable_investigation", "job.issue", "job.deliver"} <= actions


# --- Agent-side enforcement -------------------------------------------------
def test_agent_refuses_in_local_normal_mode(client):
    _, nid = _customer_and_node(client)
    _enable_investigation(client, nid)
    job = client.post(f"/nodes/{nid}/jobs", json={"job_key": "ad_enumerate_paths"}).json()

    a = agent_mod.Agent(nid, signing.public_key_b64())
    # cloud issued it, but the agent's own local switch is still 'normal'
    with pytest.raises(agent_mod.AgentRefusal):
        a.accept(job["manifest"], job["signature"])


def test_agent_rejects_forged_or_tampered_manifest(client):
    _, nid = _customer_and_node(client)
    _enable_investigation(client, nid)
    job = client.post(f"/nodes/{nid}/jobs", json={"job_key": "ad_enumerate_paths"}).json()

    a = agent_mod.Agent(nid, signing.public_key_b64())
    a.set_local_mode("investigation")
    tampered = dict(job["manifest"])
    tampered["job_key"] = "network_open_services"   # swap the job after signing
    with pytest.raises(agent_mod.AgentRefusal):
        a.accept(tampered, job["signature"])


def test_agent_runs_valid_job_end_to_end(client):
    _, nid = _customer_and_node(client)
    _enable_investigation(client, nid)
    job = client.post(f"/nodes/{nid}/jobs", json={"job_key": "ad_enumerate_paths"}).json()

    a = agent_mod.Agent(nid, signing.public_key_b64())
    a.set_local_mode("investigation")
    manifest = a.accept(job["manifest"], job["signature"])
    result = a.run_job(manifest)

    r = client.post(f"/jobs/{job['id']}/result", json=result)
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
