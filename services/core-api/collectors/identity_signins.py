"""
Sample identity sign-in collector.

Stands in for a real puller of Microsoft 365 / Entra ID or Google Workspace
sign-in audit logs. Each sign-in carries geo (lat/lon/city/country), the device
fingerprint, ASN, network type, and whether MFA was satisfied — everything the
impossible-travel rule needs. A real collector would page the provider's audit
API and post each record with its true observed_at.

Run the API first, then:  python collectors/identity_signins.py <customer_id>
"""
from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

API = "http://127.0.0.1:8000/ingest"


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=None).isoformat()


def push(customer_id: str, data: dict, observed_at: datetime) -> dict:
    body = json.dumps({
        "customer_id": customer_id, "source": "identity_signins",
        "event_type": "identity_signin", "data": data, "observed_at": _iso(observed_at),
    }).encode()
    req = urllib.request.Request(API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python collectors/identity_signins.py <customer_id>")
        raise SystemExit(1)
    cid = sys.argv[1]
    now = datetime.now(timezone.utc)
    # London now, then New York 30 minutes later from a new device: impossible.
    sequence = [
        ({"user": "alice@acme.com", "lat": 51.5, "lon": -0.12, "city": "London",
          "country": "GB", "device_id": "dev-laptop-1", "asn": "AS5089",
          "network_type": "residential", "mfa_satisfied": True}, now - timedelta(minutes=30)),
        ({"user": "alice@acme.com", "lat": 40.71, "lon": -74.0, "city": "New York",
          "country": "US", "device_id": "dev-unknown-9", "asn": "AS6939",
          "network_type": "residential", "mfa_satisfied": False}, now),
    ]
    for data, ts in sequence:
        res = push(cid, data, ts)
        print(f"  {data['city']:<9} -> {len(res['findings'])} finding(s), {len(res['alerts'])} alert(s)")
