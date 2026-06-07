"""
Impossible-travel detection tests.

Covers the four behaviours that matter:
  1. True positive   — distant logins in a short window -> High finding.
  2. VPN suppression  — same scenario but one leg is VPN -> stays quiet.
  3. Escalation       — impossible travel + new device -> Critical.
  4. Feasible travel  — far apart but enough time -> no finding (no over-firing).
And confirms the reasoning layer proposes the MFA-state follow-up.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool

from app import db, main

# Fixed reference time so tests are deterministic.
T0 = datetime(2026, 6, 1, 12, 0, 0)


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


def _customer(client) -> str:
    return client.post("/customers", json={"name": "Acme"}).json()["id"]


def _signin(client, cid, *, city, lat, lon, when, device="dev-1",
            asn="AS100", network="residential", mfa=True, country="GB"):
    return client.post("/ingest", json={
        "customer_id": cid, "source": "identity_signins", "event_type": "identity_signin",
        "observed_at": when.isoformat(),
        "data": {"user": "alice@acme.com", "city": city, "country": country,
                 "lat": lat, "lon": lon, "device_id": device, "asn": asn,
                 "network_type": network, "mfa_satisfied": mfa},
    }).json()


# London / New York coordinates (~5,570 km apart).
LON = dict(city="London", lat=51.5, lon=-0.12, country="GB")
NYC = dict(city="New York", lat=40.71, lon=-74.0, country="US")


def test_true_positive_impossible_travel_high(client):
    cid = _customer(client)
    _signin(client, cid, when=T0, **LON)                       # baseline
    res = _signin(client, cid, when=T0 + timedelta(minutes=30),  # 5570 km in 0.5h
                  device="dev-1", asn="AS100", **NYC)           # same device+asn, mfa ok
    findings = {f["rule_id"]: f for f in res["findings"]}
    assert "IDN-006" in findings
    assert findings["IDN-006"]["severity"] == "high"           # no corroboration -> High
    assert len(res["alerts"]) == 1


def test_vpn_leg_is_suppressed(client):
    cid = _customer(client)
    _signin(client, cid, when=T0, **LON)
    res = _signin(client, cid, when=T0 + timedelta(minutes=30),
                  network="vpn", **NYC)                          # NY login via VPN
    assert all(f["rule_id"] != "IDN-006" for f in res["findings"])
    assert res["alerts"] == []


def test_new_device_escalates_to_critical(client):
    cid = _customer(client)
    _signin(client, cid, when=T0, device="dev-1", **LON)
    res = _signin(client, cid, when=T0 + timedelta(minutes=30),
                  device="dev-NEW", asn="AS100", **NYC)          # never-seen device
    findings = {f["rule_id"]: f for f in res["findings"]}
    assert findings["IDN-006"]["severity"] == "critical"
    assert len(res["alerts"]) == 1


def test_feasible_travel_stays_quiet(client):
    cid = _customer(client)
    _signin(client, cid, when=T0, **LON)
    # 5570 km over 10 hours ~= 557 km/h: feasible (a real flight). No finding.
    res = _signin(client, cid, when=T0 + timedelta(hours=10), device="dev-1", asn="AS100", **NYC)
    assert all(f["rule_id"] != "IDN-006" for f in res["findings"])


def test_reasoning_proposes_mfa_followup(client):
    cid = _customer(client)
    _signin(client, cid, when=T0, device="dev-1", **LON)
    _signin(client, cid, when=T0 + timedelta(minutes=30), device="dev-NEW", **NYC)
    plan = client.post("/reasoning/plan", json={"customer_id": cid}).json()
    keys = {p["job_key"] for p in plan["proposals"]}
    assert "identity_mfa_state" in keys
