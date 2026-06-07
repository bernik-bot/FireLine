"""
Alert sinks — where dispatched alerts go.

The deck routes alerts to Slack / MS Teams / email / SOAR / ticketing. This
slice ships a console sink (always on) and a generic webhook sink (Slack/Teams
incoming-webhook compatible). Real connectors implement the same `send()`
contract and get appended to ACTIVE_SINKS.
"""
from __future__ import annotations

import json
import os
from typing import Protocol

from app.models import Alert


class Sink(Protocol):
    name: str

    def send(self, alert: Alert) -> bool: ...


class ConsoleSink:
    name = "console"

    def send(self, alert: Alert) -> bool:
        print(f"[ALERT::{alert.severity.value.upper()}] {alert.title}  ({alert.id})")
        return True


class WebhookSink:
    """POSTs a minimal payload to an incoming webhook (Slack/Teams style)."""
    name = "webhook"

    def __init__(self, url: str):
        self.url = url

    def send(self, alert: Alert) -> bool:
        try:
            import urllib.request

            payload = json.dumps(
                {"text": f"[{alert.severity.value.upper()}] {alert.title}"}
            ).encode()
            req = urllib.request.Request(
                self.url, data=payload, headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5)
            return True
        except Exception as exc:  # never let a sink failure break the pipeline
            print(f"[sink:webhook] dispatch failed: {exc}")
            return False


def _build_sinks() -> list[Sink]:
    sinks: list[Sink] = [ConsoleSink()]
    if url := os.environ.get("BLACKBIRCH_WEBHOOK_URL"):
        sinks.append(WebhookSink(url))
    return sinks


ACTIVE_SINKS: list[Sink] = _build_sinks()


def dispatch(alert: Alert) -> list[str]:
    """Send an alert to all active sinks; return the names that accepted it."""
    delivered = []
    for sink in ACTIVE_SINKS:
        if sink.send(alert):
            delivered.append(sink.name)
    return delivered
