"""
Correlate: the heart of the spine.

Given a freshly normalized Event, run every rule. For each rule that fires,
persist a Finding, and if it meets the alert threshold, create + dispatch an
Alert. Returns the findings and alerts produced so the API can echo them back.

Alert threshold is HIGH and above by default — tune per customer later.
"""
from __future__ import annotations

from sqlmodel import Session

from app.models import Alert, Event, Finding, Severity
from app.pipeline import alerting
from app.pipeline.rules import RULES, STATEFUL_RULES

_ALERTABLE = {Severity.high, Severity.critical}


def correlate(event: Event, session: Session) -> tuple[list[Finding], list[Alert]]:
    findings: list[Finding] = []
    alerts: list[Alert] = []

    # Stateless rules see only this event; stateful rules also get the session
    # to look back at recent events (e.g. the user's prior login).
    specs = [r(event) for r in RULES] + [r(event, session) for r in STATEFUL_RULES]

    for spec in specs:
        if spec is None:
            continue

        finding = Finding(
            customer_id=event.customer_id,
            rule_id=spec.rule_id,
            title=spec.title,
            description=spec.description,
            severity=spec.severity,
            risk_score=spec.risk_score,
            evidence_event_ids=[event.id],
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        findings.append(finding)

        if spec.severity in _ALERTABLE:
            alert = Alert(
                finding_id=finding.id,
                customer_id=finding.customer_id,
                severity=finding.severity,
                title=finding.title,
            )
            alert.sinks = alerting.dispatch(alert)
            alert.dispatched = bool(alert.sinks)
            session.add(alert)
            session.commit()
            session.refresh(alert)
            alerts.append(alert)

    # Earlier commits expire prior objects' attributes; reload before returning
    # so callers (e.g. response serialization) see fully-populated rows.
    for obj in (*findings, *alerts):
        session.refresh(obj)

    return findings, alerts
