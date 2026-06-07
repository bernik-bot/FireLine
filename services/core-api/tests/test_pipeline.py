"""
End-to-end test of the spine: ingest -> normalize -> correlate -> alert.

Uses an in-memory SQLite DB and the console sink so it runs anywhere with no
external services. Verifies that representative events produce the right
findings/alerts and that benign events stay quiet.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

from app import db, main


@pytest.fixture(name="client")
def client_fixture():
    # Isolated in-memory DB shared across the connection pool for the test.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)

    def _get_session():
        with Session(engine) as session:
            yield session

    main.app.dependency_overrides[db.get_session] = _get_session
    main.app.on_event  # startup init_db is a no-op against our pre-made tables
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.clear()


def _customer(client) -> str:
    r = client.post("/customers", json={"name": "Acme"})
    assert r.status_code == 200
    return r.json()["id"]


def test_critical_deception_alert(client):
    cid = _customer(client)
    r = client.post("/ingest", json={
        "customer_id": cid, "source": "honeypot", "event_type": "decoy_touched",
        "data": {"decoy": "FILE-SRV-BACKUP", "src_ip": "10.0.0.42"},
    })
    assert r.status_code == 200
    body = r.json()
    assert len(body["findings"]) == 1
    assert body["findings"][0]["severity"] == "critical"
    assert len(body["alerts"]) == 1            # critical -> dispatched


def test_external_rdp_is_critical(client):
    cid = _customer(client)
    r = client.post("/ingest", json={
        "customer_id": cid, "source": "network_discovery",
        "event_type": "external_rdp_exposed", "data": {"host": "10.0.0.5"},
    })
    body = r.json()
    assert body["findings"][0]["rule_id"] == "EXP-001"
    assert len(body["alerts"]) == 1


def test_cert_with_long_expiry_is_quiet(client):
    cid = _customer(client)
    r = client.post("/ingest", json={
        "customer_id": cid, "source": "external_scan",
        "event_type": "tls_cert_expiring", "data": {"host": "x.com", "days_remaining": 90},
    })
    body = r.json()
    assert body["findings"] == []              # 90 days out -> no finding
    assert body["alerts"] == []


def test_unknown_customer_rejected(client):
    r = client.post("/ingest", json={
        "customer_id": "nope", "source": "honeypot", "event_type": "decoy_touched", "data": {},
    })
    assert r.status_code == 404
