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
