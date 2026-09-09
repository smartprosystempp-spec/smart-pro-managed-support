# 3.15.0
- Adds permanent promotion of the already verified quarantined candidate.
- Atomically retains the old shared identity as a local rollback backup.
- Promoted continuous runtime uses the verified per-installation target source.
- Broker read-only watch must observe the exact bound candidate online.
- On failed post-commit verification, restores the shared identity and runtime.
- No old MeshCentral node deletion or technician authorization.
