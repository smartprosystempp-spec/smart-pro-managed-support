# 3.15.2 — Persistent Runtime Source Telemetry Hotfix

- Fixes the live 3.15.1 promotion failure `promotion_target_runtime_start_timeout`.
- `save_persistent_state()` already persisted `runtime_source`, but `load_persistent_state()` did not return it.
- The promotion worker therefore could not observe `status=running` together with `runtime_source=target`, even though the target MeshAgent had actually started.
- Adds `runtime_source` to the sanitized persistent-state reader only.
- Broker 0.42.1 contract, candidate identity, rollback-first commit, exact bound-node verification, old-node retention, and technician authorization remain unchanged.
- No node deletion, permission mutation, service persistence, re-pair, or `/data` reset.
