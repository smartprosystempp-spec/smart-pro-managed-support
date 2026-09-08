# 3.13.1 — Reseed Supervisor Lock & Candidate Quarantine Carry-Forward Hotfix

- Fixes the live QA race where the unattended supervisor could try to restart the shared runtime while the clean identity reseed worker was still active.
- The unattended supervisor now waits while either the legacy group-migration canary or the clean identity reseed worker owns the MeshAgent lifecycle.
- Preserves an existing quarantined candidate across the 3.13.0 -> 3.13.1 version bump in the Ingress status card instead of showing the reseed as not-run.
- Keeps the second-reseed gate locked while candidate quarantine exists.
- No candidate promotion, no permanent source switch, no identity-binding commit, no old-node deletion, no MeshCentral permission mutation, no technician authorization.

# 3.13.1 — Clean Per-Installation Identity Reseed Canary

- Preserves the current stable shared-group identity unchanged as rollback.
- Adds Broker 0.39.0 clean-reseed request/consume/watch/report consumer.
- Executes verified target .msh for <=45s without copying the existing meshagent.db.
- Persists exactly one fresh candidate meshagent.db in a separate 0700/0600 quarantine area.
- Refuses a second reseed while a candidate is already quarantined.
- No permanent runtime-source switch, no active identity-binding commit, no old-node deletion, no technician authorization.
- Retires the 3.12 stable-identity group-move canary button after live proof that identity reuse does not move an existing MeshCentral node.

## 3.12.0 — Controlled Per-Installation Group Migration Canary

- Adds Broker 0.38.0 request/consume/watch/report canary consumer.
- Temporarily stops the shared unattended foreground runtime under an in-process migration lock.
- Re-fetches and verifies target .msh and MeshAgent binary.
- Reuses the exact protected stable meshagent.db without committing the target binding.
- Runs target-group foreground MeshAgent for <=45 seconds, then terminates and deletes the runtime directory.
- Requests rollback to the proven shared unattended runtime.
- No permanent runtime-source switch, no identity-binding commit, no technician access.

# Changelog

## 3.11.1 — Unicode-Safe Target Binding Hotfix
- Fixes the live target .msh verification crash when the exact per-installation group name contains non-ASCII characters (the em dash in `Smart Pro Managed — ID-95948`).
- Uses `secrets.compare_digest()` on exact UTF-8 byte sequences for request/preflight binding checks.
- No runtime-source switch, node move, identity-binding commit, MeshAgent execution or technician permission change.
- Unattended runtime/recovery functions remain unchanged from 3.11.0.


## 3.11.1 — Per-Installation Target Settings Verification Consumer

- Preserves the proven 3.10.0/3.9.0 unattended stable-identity runtime path.
- Adds authenticated one-time target `.msh` request/consume against Broker 0.37.0+.
- Refreshes migration preflight immediately before delivery.
- Verifies target group, MeshID hint, full critical binding hint, WSS host, stable SPMNG label, SHA-256 and byte count entirely in memory.
- Persists metadata only; raw target ticket and raw target `.msh` are never stored.
- No MeshAgent execution, node move, runtime source switch, identity-binding commit or technician actions.
