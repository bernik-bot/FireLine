"""
Normalize: turn a raw collector/decoy payload into a canonical Event.

Every collector emits its own shape; this is the single choke point that maps
those shapes onto the common data model so the correlation engine only ever
deals with one structure. Add per-source mappers here as collectors are built.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from app.models import Event


# Minimal source -> category map. Extend as collectors are added.
_CATEGORY_BY_SOURCE = {
    "network_discovery": "network",
    "identity_m365": "identity",
    "identity_signins": "identity",
    "endpoint_posture": "endpoint",
    "external_scan": "exposure",
    "honeypot": "deception",
    "canary_token": "deception",
}


def normalize(
    *,
    customer_id: str,
    source: str,
    event_type: str,
    data: dict,
    node_id: Optional[str] = None,
    observed_at: Optional["datetime"] = None,
) -> Event:
    category = _CATEGORY_BY_SOURCE.get(source, "other")
    kwargs = dict(
        customer_id=customer_id,
        node_id=node_id,
        source=source,
        category=category,
        event_type=event_type,
        data=data or {},
    )
    if observed_at is not None:
        kwargs["observed_at"] = observed_at
    return Event(**kwargs)
