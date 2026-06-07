"""
A JobProposal is the brain's *output*: a suggestion, not an action.

It is plain, frozen data. It carries no signature, no authority, and no channel
to a node. The only thing that can turn a proposal into something the edge will
run is the boundary (boundary.py), which routes it through the single signed-job
chokepoint. A proposal sitting in memory does nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class JobProposal:
    node_id: str
    job_key: str                 # what the brain *wants* to run (may be anything)
    rationale: str               # why — for the human reviewing the plan
    confidence: float = 0.5      # 0..1
    params: dict = field(default_factory=dict)
