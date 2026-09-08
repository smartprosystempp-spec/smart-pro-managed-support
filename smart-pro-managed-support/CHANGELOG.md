# Changelog

## 3.11.0 — Per-Installation Target Settings Verification Consumer

- Preserves the proven 3.10.0/3.9.0 unattended stable-identity runtime path.
- Adds authenticated one-time target `.msh` request/consume against Broker 0.37.0+.
- Refreshes migration preflight immediately before delivery.
- Verifies target group, MeshID hint, full critical binding hint, WSS host, stable SPMNG label, SHA-256 and byte count entirely in memory.
- Persists metadata only; raw target ticket and raw target `.msh` are never stored.
- No MeshAgent execution, node move, runtime source switch, identity-binding commit or technician actions.
