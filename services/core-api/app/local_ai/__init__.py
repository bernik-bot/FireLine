"""
Local AI analyst (Slice A) — a strictly advisory reasoning component that runs
on the local appliance under Ollama.

CAPABILITY BOUNDARY — this package, transitively, imports NOTHING that can act
on an endpoint or sign a job: no `app.jobs.*`, no `app.agent`, no boundary, no
shell (`subprocess`/`os.system`), no socket/HTTP client to a node. Its only
outputs are (1) advisory AdvisoryNote rows that reference deterministic
findings, and (2) inert JobNomination data objects for a human to consider.

`tests/test_local_ai_boundary.py` asserts this package stays import-clean, so a
future shortcut that wires the analyst to an actuator fails CI — the same
discipline as the reasoning-layer brain.
"""
