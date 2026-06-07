"""
Sample collector: network discovery.

Stands in for an approved collector running on the internal security node. It
produces raw events and POSTs them to the Core API /ingest endpoint — exactly
how a real collector (or a honeypot decoy) feeds the pipeline.

Run the API first, then:  python collectors/network_discovery.py <customer_id>
"""
from __future__ import annotations

import json
import sys
import urllib.request

API = "http://127.0.0.1:8000/ingest"

# Simulated scan output. A real collector would derive these from nmap/agent data.
SAMPLE_EVENTS = [
    {"source": "network_discovery", "event_type": "external_rdp_exposed",
     "data": {"host": "10.0.0.5", "port": 3389}},
    {"source": "external_scan", "event_type": "tls_cert_expiring",
     "data": {"host": "vpn.acme.com", "days_remaining": 7}},
    {"source": "identity_m365", "event_type": "mfa_disabled",
     "data": {"user": "admin@acme.com", "is_admin": True}},
    {"source": "honeypot", "event_type": "decoy_touched",
     "data": {"decoy": "FILE-SRV-BACKUP (honeypot)", "src_ip": "10.0.0.42"}},
]


def push(customer_id: str, ev: dict) -> dict:
    body = json.dumps({"customer_id": customer_id, **ev}).encode()
    req = urllib.request.Request(API, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python collectors/network_discovery.py <customer_id>")
        raise SystemExit(1)
    cid = sys.argv[1]
    for ev in SAMPLE_EVENTS:
        result = push(cid, ev)
        n_alerts = len(result["alerts"])
        print(f"  pushed {ev['event_type']:<22} -> {len(result['findings'])} finding(s), {n_alerts} alert(s)")
