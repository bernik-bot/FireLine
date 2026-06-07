# Roadmap — from spine to full platform

The component manifest is the **target backlog**, not a thing to stub all at once.
Each item below plugs into the spine (`ingest → normalize → correlate → alert`)
via the same contract: produce events, add rules, route alerts. Build in slices;
keep `main` runnable at every step.

Legend: ✅ done · 🔨 next · ⬜ backlog

## Slice 1 — Spine (done)
- ✅ Core data model (Customer, Node, Asset, Event, Finding, Alert)
- ✅ Ingestion API + normalize
- ✅ Correlation engine + representative alert catalog
- ✅ Alert sinks (console, webhook)
- ✅ Sample collector + end-to-end tests

## Slice 2 — Control channel (Normal / Investigation modes) (done)
- ✅ Node mode model — `normal` (default) vs `investigation` (opt-in, time-boxed)
- ✅ Normal Mode: collector output only; cloud cannot task (enforced + audited)
- ✅ Investigation Mode: customer-enabled; cloud may request only catalogued, read-only jobs
- ✅ Ed25519-signed job manifests (cloud signs, agent verifies; stolen agent can't forge)
- ✅ Fixed read-only job catalog; agent-side verification + local-mode enforcement
- ✅ Append-only audit log of every control action

## Slice 2b — Reasoning layer + capability boundary (done)
- ✅ Single signed-job chokepoint (`jobs/issue.py`) — only code that can mint an edge job
- ✅ Brain (`reasoning/brain.py`): correlated findings → inert `JobProposal`s; Hermes/LLM-pluggable
- ✅ Boundary (`reasoning/boundary.py`): proposals reach the edge *only* via the signed catalog
- ✅ `/reasoning/plan` (no edge effect) and `/reasoning/act` (passes every gate)
- ✅ Structural test asserts the brain imports no edge-reaching capability (CI-enforced)

## Slice 3 — Deception / Honeypot service 🔨
*Highest signal-to-effort: fully specified, reuses the spine verbatim.*
- 🔨 Decoy registry + provisioning (internal services, honeyfiles, honeytokens)
- 🔨 M365 decoy identities & canary mailboxes
- 🔨 External honey-domains + canary tokens
- 🔨 Deception event source → already routes through `category=="deception"` rule

## Slice 4 — Control plane core ⬜
- ⬜ Node enrollment with per-node identity / mTLS client certs
- ⬜ Job scheduler + recurring manifests
- ⬜ Tenant isolation + RBAC; move audit sink to immutable storage

## Slice 4 — Collectors (inside-out) ⬜
Each is just an event producer feeding `/ingest`:
- ⬜ Network discovery (real nmap/agent) ⬜ Endpoint/server posture (EDR, patch, encryption)
- ⬜ Identity & M365 (MFA, admin roles, OAuth, forwarding) ⬜ Backup posture ⬜ Edge & remote access
  - ✅ Impossible-travel detection (IDN-006): stateful geo-velocity rule + VPN/proxy suppression + corroboration escalation (new device/ASN/MFA) → reasoning proposes identity_mfa_state follow-up; sign-in collector (`identity_signins`)

## Slice 5 — External testing engine (outside-in) ⬜
- ⬜ Domain/subdomain discovery ⬜ DNS/MX/SPF/DKIM/DMARC/CAA ⬜ Port/service exposure ⬜ TLS health

## Slice 6 — Cyber service modules ⬜
Map directly to manifest §4. All consume the spine's data model:
- ⬜ SIEM log ingest at scale (Elastic) ⬜ EDR/XDR driver layer (CrowdStrike, SentinelOne, Defender, Elastic)
- ⬜ Threat-intel service (OTX, MISP feeds → IOC enrichment) ⬜ Vulnerability mgmt (Nessus/OpenVAS → risk scoring)
- ⬜ IAM drift ⬜ SOAR playbook engine (YAML/Python) + autonomous responses ⬜ Attack-surface monitoring ⬜ Compliance engine

## Slice 7 — Frontend ⬜
- ⬜ Next.js dashboard: real-time alerts, asset inventory, case management, compliance views
- ⬜ SSO (Okta/Auth0/Azure AD) + RBAC ⬜ Embedded Grafana/Kibana

## Slice 8 — Integrations ⬜
- ⬜ Ticketing (Jira, ServiceNow, Zendesk) ⬜ Messaging (Slack, Teams, Twilio) ⬜ Cloud (GuardDuty, Defender, SCC)

## Slice 9 — Platform / infra ⬜
- ⬜ Dockerfiles per service ⬜ Helm charts ⬜ Terraform (EKS/AKS) ⬜ ArgoCD ⬜ Ingress (Traefik/Kong) ⬜ Prometheus/Loki

## Cross-cutting (introduce as services land)
- ⬜ Vault secrets + rotation ⬜ S3/MinIO evidence store ⬜ SonarQube/Snyk in CI ⬜ DR backup/restore jobs

## Guardrails (from the deck — enforce from day one)
- Read-only by default · outbound-only node · explicitly authorized scope.
- No exploitation, password spraying, destructive/DoS testing, or production changes without separate written approval.
