"""
A JobNomination is the local AI analyst's *suggestion* that a human consider
running a read-only investigation job. It is plain, frozen data.

It is NOT a JobRequest (the cloud->agent API schema), and it is NOT a
JobProposal (the cloud brain's output). It carries no signature, no authority,
no session, and no channel to a node. The analyst can emit nominations all day;
none of them does anything. The only way anything reaches an endpoint is the
existing chokepoint: a human reviews the nomination and, separately, drives the
Authorization Broker -> sign -> verify path (Slice B). There is deliberately no
function here, and no import elsewhere in this package, that turns a nomination
into an action.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class JobNomination:
    node_id: str
    job_key: str                 # what the analyst *suggests* looking at next
    rationale: str               # why — for the human reviewing it
    confidence: float = 0.5      # 0..1, advisory only
    params: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "job_key": self.job_key,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "params": dict(self.params),
            # explicit marker so no downstream consumer mistakes this for an
            # authorized or signed job.
            "advisory": True,
            "signed": False,
        }
