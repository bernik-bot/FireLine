"""
Attack-surface checks (passive). Pure evaluation logic that turns a piece of
fetched perimeter data into a raw event dict, or None if the control is healthy.

Kept free of network I/O so it's deterministic and unit-testable; the analyzer
supplies the data (live-fetched or injected). Raw events use the same shape the
agent/collectors post: {"source", "event_type", "data"}.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

_SRC = "external_scan"


def check_spf(record: Optional[str]) -> Optional[dict]:
    """SPF: no record or a permissive 'all' qualifier is a weakness."""
    if not record:
        return {"source": _SRC, "event_type": "email_security_degraded",
                "data": {"control": "SPF", "issue": "no SPF record published", "severity": "high"}}
    r = record.lower()
    if "+all" in r or "?all" in r:
        return {"source": _SRC, "event_type": "email_security_degraded",
                "data": {"control": "SPF", "issue": "permissive policy (+all/?all)", "severity": "medium"}}
    return None  # -all / ~all are acceptable


def check_dmarc(record: Optional[str]) -> Optional[dict]:
    """DMARC: missing is high; p=none is a weak (monitor-only) policy."""
    if not record:
        return {"source": _SRC, "event_type": "email_security_degraded",
                "data": {"control": "DMARC", "issue": "no DMARC record published", "severity": "high"}}
    r = record.lower().replace(" ", "")
    if "p=none" in r:
        return {"source": _SRC, "event_type": "email_security_degraded",
                "data": {"control": "DMARC", "issue": "policy p=none (monitor only)", "severity": "medium"}}
    return None  # quarantine / reject are enforcing


def check_tls_cert(not_after: datetime, now: Optional[datetime] = None) -> Optional[dict]:
    """TLS: flag certs expiring within 14 days (feeds the existing EXP-003 rule)."""
    now = now or datetime.utcnow()
    days = (not_after - now).days
    if days <= 14:
        return {"source": _SRC, "event_type": "tls_cert_expiring",
                "data": {"days_remaining": max(days, 0)}}
    return None


def check_open_ports(open_ports: list[int]) -> list[dict]:
    """Service exposure. 3389 maps to the existing critical RDP rule (EXP-001)."""
    events: list[dict] = []
    for port in open_ports or []:
        if port == 3389:
            events.append({"source": _SRC, "event_type": "external_rdp_exposed",
                           "data": {"port": 3389}})
        else:
            events.append({"source": _SRC, "event_type": "external_service_exposed",
                           "data": {"port": port}})
    return events
