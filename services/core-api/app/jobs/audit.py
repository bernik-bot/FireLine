"""Tiny helper so every control-relevant action lands in the audit log."""
from __future__ import annotations

from typing import Optional

from sqlmodel import Session

from app.models import AuditLog


def record(
    session: Session,
    *,
    actor: str,
    action: str,
    customer_id: Optional[str] = None,
    node_id: Optional[str] = None,
    detail: Optional[dict] = None,
) -> AuditLog:
    entry = AuditLog(
        actor=actor,
        action=action,
        customer_id=customer_id,
        node_id=node_id,
        detail=detail or {},
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry
