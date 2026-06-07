"""
External attack surface analyzer (cloud-side, outside-in).

Orchestrates the passive checks for a target domain and returns raw events to
feed the correlation engine. Data can be injected (offline / tests) or fetched
live. Heavier active tools (subfinder, naabu, nuclei, sslyze) plug in behind the
adapter methods — each just needs to return raw event dicts.

Authorization note: active scanning runs only inside an authorized scope and
rate-limited. Passive sources (DNS, cert transparency, Shodan/Censys) don't
touch the target and are the safe default.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from app.external import checks


class ExternalAttackSurfaceAnalyzer:
    def analyze(
        self,
        domain: str,
        *,
        spf: Optional[str] = None,
        dmarc: Optional[str] = None,
        cert_not_after: Optional[datetime] = None,
        open_ports: Optional[list[int]] = None,
        live: bool = False,
    ) -> list[dict]:
        """Run all checks. If live=True, fetch missing data; else use what's passed."""
        if live:
            spf = spf if spf is not None else self._fetch_txt(domain, "v=spf1")
            dmarc = dmarc if dmarc is not None else self._fetch_txt(f"_dmarc.{domain}", "v=DMARC1")
            if cert_not_after is None:
                cert_not_after = self._fetch_cert_expiry(domain)

        events: list[dict] = []
        for ev in (checks.check_spf(spf), checks.check_dmarc(dmarc)):
            if ev:
                ev["data"]["domain"] = domain
                events.append(ev)
        if cert_not_after is not None:
            ev = checks.check_tls_cert(cert_not_after)
            if ev:
                ev["data"]["host"] = domain
                events.append(ev)
        for ev in checks.check_open_ports(open_ports or []):
            ev["data"]["host"] = domain
            events.append(ev)
        return events

    # --- live fetchers (best-effort; degrade gracefully if deps/network absent) ---
    def _fetch_txt(self, name: str, startswith: str) -> Optional[str]:
        try:
            import dns.resolver  # dnspython, optional
            for rdata in dns.resolver.resolve(name, "TXT"):
                txt = b"".join(rdata.strings).decode(errors="ignore")
                if txt.lower().startswith(startswith.lower()):
                    return txt
        except Exception:
            return None
        return None

    def _fetch_cert_expiry(self, host: str, port: int = 443) -> Optional[datetime]:
        try:
            import socket
            import ssl
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    not_after = ssock.getpeercert()["notAfter"]
            return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            return None

    # --- active tool adapters (stubs — shell out to the real tools here) ---
    def enumerate_subdomains(self, domain: str) -> list[str]:
        """Wire to subfinder/amass or crt.sh. Returns discovered subdomains."""
        return []

    def scan_ports(self, host: str) -> list[int]:
        """Wire to naabu/nmap (authorized + rate-limited) or Shodan (passive)."""
        return []
