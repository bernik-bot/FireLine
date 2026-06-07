"""
Correlation rules = the alert catalog (slide 11) expressed as code.

A rule inspects an incoming Event (optionally with recent context) and either
returns a Finding spec or None. Keeping rules as small, declarative callables
makes the catalog easy to grow — advisory-driven rules from banking threat
intel get appended here without touching the engine.

This slice ships a representative subset across posture, identity, exposure,
and deception. The full catalog from the deck slots in the same way.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from sqlmodel import Session, select

from app.models import Event, Severity


@dataclass
class FindingSpec:
    rule_id: str
    title: str
    description: str
    severity: Severity
    risk_score: int


# A stateless rule: given one Event, return a FindingSpec to raise, or None.
Rule = Callable[[Event], Optional[FindingSpec]]

# A stateful rule additionally gets the DB session so it can look back at recent
# events (e.g. the user's prior login) to correlate across time.
StatefulRule = Callable[[Event, Session], Optional[FindingSpec]]


def rule_external_rdp(ev: Event) -> Optional[FindingSpec]:
    """#1 EXTERNAL EXPOSURE — New external RDP exposure (Critical)."""
    if ev.event_type == "external_rdp_exposed":
        host = ev.data.get("host", "unknown")
        return FindingSpec(
            rule_id="EXP-001",
            title="New external RDP exposure",
            description=f"RDP (3389) reachable from the internet on {host}.",
            severity=Severity.critical,
            risk_score=90,
        )
    return None


def rule_cert_expiry(ev: Event) -> Optional[FindingSpec]:
    """#3 EXTERNAL EXPOSURE — Certificate expires within 14 days (High)."""
    if ev.event_type == "tls_cert_expiring":
        days = int(ev.data.get("days_remaining", 99))
        if days <= 14:
            host = ev.data.get("host", "unknown")
            return FindingSpec(
                rule_id="EXP-003",
                title="TLS certificate expiring soon",
                description=f"Certificate on {host} expires in {days} day(s).",
                severity=Severity.high,
                risk_score=60,
            )
    return None


def rule_mfa_disabled_admin(ev: Event) -> Optional[FindingSpec]:
    """#5 IDENTITY — MFA disabled for admin (Critical)."""
    if ev.event_type == "mfa_disabled" and ev.data.get("is_admin"):
        user = ev.data.get("user", "unknown")
        return FindingSpec(
            rule_id="IDN-005",
            title="MFA disabled for admin account",
            description=f"Privileged account {user} has MFA disabled.",
            severity=Severity.critical,
            risk_score=95,
        )
    return None


def rule_edr_disabled(ev: Event) -> Optional[FindingSpec]:
    """#9 ENDPOINT — EDR disabled or missing (High)."""
    if ev.event_type == "edr_disabled":
        host = ev.data.get("host", "unknown")
        return FindingSpec(
            rule_id="EDR-009",
            title="EDR disabled or missing",
            description=f"Endpoint protection not running on {host}.",
            severity=Severity.high,
            risk_score=70,
        )
    return None


def rule_deception_triggered(ev: Event) -> Optional[FindingSpec]:
    """#11 DECEPTION — Honeypot or canary triggered (Critical).

    Anything that touches a decoy is suspicious by definition: no tuning,
    no false positives. Highest-fidelity signal in the catalog.
    """
    if ev.category == "deception":
        decoy = ev.data.get("decoy", "decoy asset")
        src = ev.data.get("src_ip", "unknown source")
        return FindingSpec(
            rule_id="DEC-011",
            title="Deception asset triggered",
            description=f"{decoy} was touched by {src}. Decoys have no legitimate use.",
            severity=Severity.critical,
            risk_score=99,
        )
    return None


def rule_email_security(ev: Event) -> Optional[FindingSpec]:
    """#4 EMAIL SECURITY — SPF / DKIM / DMARC degradation (Medium / High)."""
    if ev.event_type == "email_security_degraded":
        ctrl = ev.data.get("control", "email auth")
        issue = ev.data.get("issue", "weakness detected")
        high = ev.data.get("severity") == "high"
        return FindingSpec(
            rule_id="EML-004",
            title=f"{ctrl} weakness",
            description=f"{ctrl} on {ev.data.get('domain', 'domain')}: {issue}.",
            severity=Severity.high if high else Severity.medium,
            risk_score=55 if high else 35,
        )
    return None


# Registry — append advisory-driven rules here as they're authored.
RULES: list[Rule] = [
    rule_external_rdp,
    rule_cert_expiry,
    rule_mfa_disabled_admin,
    rule_edr_disabled,
    rule_deception_triggered,
    rule_email_security,
]


# --------------------------------------------------------------------------- #
# Stateful rules — correlate across time
# --------------------------------------------------------------------------- #
from datetime import timedelta          # noqa: E402

from app.pipeline.geo import MAX_FEASIBLE_KMH, haversine_km, implied_speed_kmh  # noqa: E402

# Networks whose IP geolocation is unreliable — a user on these can "appear"
# anywhere instantly. The single biggest source of impossible-travel false
# positives, so we suppress when either login sits behind one.
_UNRELIABLE_NETWORKS = {"vpn", "proxy", "tor", "hosting", "datacenter"}
_SIGNIN_LOOKBACK = timedelta(hours=24)


def rule_impossible_travel(event: Event, session: Session) -> Optional[FindingSpec]:
    """#6 IDENTITY — Impossible travel (High; Critical with corroboration).

    Fires when a user authenticates from two locations too far apart to have
    travelled between in the elapsed time. Suppressed when either side is on an
    unreliable network (VPN/proxy/hosting). Escalated to Critical when paired
    with a corroborating signal (new device, new ASN, or MFA not satisfied)."""
    if event.event_type != "identity_signin":
        return None
    d = event.data
    user = d.get("user")
    if not user or d.get("lat") is None or d.get("lon") is None:
        return None

    # Pull this customer's recent sign-ins; filter to the same user in Python
    # (the user lives inside the JSON data column). Fine at pilot scale; a
    # production build indexes user/time into columns for this lookback.
    recent = session.exec(
        select(Event)
        .where(Event.customer_id == event.customer_id,
               Event.event_type == "identity_signin")
        .order_by(Event.observed_at.desc())
    ).all()
    user_signins = [e for e in recent if e.data.get("user") == user and e.id != event.id]

    prior = next(
        (e for e in user_signins
         if e.observed_at <= event.observed_at
         and event.observed_at - e.observed_at <= _SIGNIN_LOOKBACK),
        None,
    )
    if prior is None:
        return None

    # Suppression: unreliable network on either end -> don't alert.
    if (d.get("network_type") in _UNRELIABLE_NETWORKS
            or prior.data.get("network_type") in _UNRELIABLE_NETWORKS):
        return None

    km = haversine_km(prior.data["lat"], prior.data["lon"], d["lat"], d["lon"])
    seconds = (event.observed_at - prior.observed_at).total_seconds()
    speed = implied_speed_kmh(km, seconds)
    if speed <= MAX_FEASIBLE_KMH:
        return None

    # Corroboration -> escalate. "New device" = a device_id never seen before
    # for this user across their sign-in history.
    seen_devices = {e.data.get("device_id") for e in user_signins
                    if e.observed_at < event.observed_at}
    new_device = d.get("device_id") is not None and d.get("device_id") not in seen_devices
    new_asn = bool(d.get("asn")) and d.get("asn") != prior.data.get("asn")
    mfa_gap = d.get("mfa_satisfied") is False
    corroborated = new_device or new_asn or mfa_gap

    why = []
    if new_device:
        why.append("new device")
    if new_asn:
        why.append("new ASN")
    if mfa_gap:
        why.append("MFA not satisfied")
    corro = f" Corroborated by: {', '.join(why)}." if why else ""

    a = f"{prior.data.get('city', 'unknown')} ({prior.data.get('country', '?')})"
    b = f"{d.get('city', 'unknown')} ({d.get('country', '?')})"
    return FindingSpec(
        rule_id="IDN-006",
        title="Impossible travel for user sign-in",
        description=(f"{user}: {a} -> {b} implies {int(speed)} km/h, "
                     f"physically impossible.{corro}"),
        severity=Severity.critical if corroborated else Severity.high,
        risk_score=92 if corroborated else 70,
    )


# Stateful rules run after the stateless ones, with DB access.
STATEFUL_RULES: list[StatefulRule] = [
    rule_impossible_travel,
]
