"""
The job catalog — the complete, fixed set of things the cloud can ask an agent
to do. If it isn't in here, the agent refuses it. Everything in this slice is
READ-ONLY: collection and analysis, never action.

Active/containment jobs (isolate host, disable account) are deliberately NOT in
this catalog. They belong behind a separate, explicit approval gate and are out
of scope for the read-only investigation channel.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class JobSpec:
    key: str
    description: str
    read_only: bool
    allowed_params: tuple[str, ...] = field(default_factory=tuple)


CATALOG: dict[str, JobSpec] = {
    "ad_enumerate_paths": JobSpec(
        key="ad_enumerate_paths",
        description="Read-only AD enumeration: objects, ACLs, group nesting, "
        "session/admin data, to compute attack-path reachability (BloodHound-style).",
        read_only=True,
        allowed_params=("domain", "max_depth"),
    ),
    "edr_pull_detections": JobSpec(
        key="edr_pull_detections",
        description="Pull recent detections from the configured EDR via its API.",
        read_only=True,
        allowed_params=("since", "severity_min"),
    ),
    "identity_mfa_state": JobSpec(
        key="identity_mfa_state",
        description="Read M365/AD identity posture: MFA state, admin roles, OAuth grants.",
        read_only=True,
        allowed_params=("tenant",),
    ),
    "network_open_services": JobSpec(
        key="network_open_services",
        description="Safe-active local discovery of listening services on in-scope hosts.",
        read_only=True,
        allowed_params=("subnet",),
    ),
}


class JobValidationError(ValueError):
    pass


def validate(job_key: str, params: dict) -> JobSpec:
    spec = CATALOG.get(job_key)
    if spec is None:
        raise JobValidationError(f"job '{job_key}' is not in the catalog")
    if not spec.read_only:
        # Belt and suspenders: this channel only carries read-only jobs.
        raise JobValidationError(f"job '{job_key}' is not read-only")
    unknown = set(params or {}) - set(spec.allowed_params)
    if unknown:
        raise JobValidationError(f"unsupported params for '{job_key}': {sorted(unknown)}")
    return spec
