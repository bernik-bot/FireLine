"""Tests for the cloud-side external attack surface analyzer."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

from app import db, main
from app.external import checks
from app.external.analyzer import ExternalAttackSurfaceAnalyzer


# --- pure check logic -------------------------------------------------------
def test_spf_checks():
    assert checks.check_spf(None)["data"]["severity"] == "high"        # missing
    assert checks.check_spf("v=spf1 +all")["data"]["severity"] == "medium"  # permissive
    assert checks.check_spf("v=spf1 include:_spf.google.com -all") is None   # healthy


def test_dmarc_checks():
    assert checks.check_dmarc(None)["data"]["severity"] == "high"      # missing
    assert checks.check_dmarc("v=DMARC1; p=none")["data"]["control"] == "DMARC"  # weak
    assert checks.check_dmarc("v=DMARC1; p=reject") is None            # enforcing


def test_cert_and_ports():
    soon = datetime.utcnow() + timedelta(days=5)
    assert checks.check_tls_cert(soon)["event_type"] == "tls_cert_expiring"
    assert checks.check_tls_cert(datetime.utcnow() + timedelta(days=120)) is None
    ports = checks.check_open_ports([3389, 8080])
    assert ports[0]["event_type"] == "external_rdp_exposed"


def test_analyzer_aggregates():
    events = ExternalAttackSurfaceAnalyzer().analyze(
        "acme.com", spf=None, dmarc="v=DMARC1; p=none",
        cert_not_after=datetime.utcnow() + timedelta(days=3), open_ports=[3389],
    )
    types = {e["event_type"] for e in events}
    assert {"email_security_degraded", "tls_cert_expiring", "external_rdp_exposed"} <= types


# --- end to end through the API + pipeline ----------------------------------
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


def test_external_scan_produces_alerts(client):
    cid = client.post("/customers", json={"name": "Acme"}).json()["id"]
    r = client.post("/external/scan", json={
        "customer_id": cid, "domain": "acme.com",
        "spf": None, "dmarc": "v=DMARC1; p=none",
        "cert_days_remaining": 3, "open_ports": [3389],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["events_observed"] == 4              # spf, dmarc, cert, rdp
    titles = {f["title"] for f in body["findings"]}
    assert "New external RDP exposure" in titles
    # critical RDP + high cert/SPF should have dispatched alerts
    assert len(body["alerts"]) >= 2
