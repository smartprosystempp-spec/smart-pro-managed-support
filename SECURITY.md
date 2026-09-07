# Security — 3.2.0

- `/share` remains read-only.
- `host_network=false`; no Supervisor/Home Assistant API permission.
- Pairing code is sent only once over HTTPS and is never persisted or logged.
- Persistent identity contains only node ID, node secret, Installation ID and paired timestamp; file mode is 0600 under private `/data`.
- Broker pairing is bound to the local Installation ID.
- Broker authorization is not derived from the local policy; Broker 0.26.0 checks the Portal independently.
- Server authorization has a bounded `valid_until`; network failure can use only the unexpired last lease, then fails closed.
- Node secret and Broker response bodies are not logged.
- No `.msh`, MeshCentral credentials, MeshAgent binary, subprocess execution, shell execution, chmod executable path, service install, or host persistence exists in 3.2.0.


## 3.6.0 settings handling
- One-time settings tickets are memory-only on the HA client.
- Raw `.msh` bytes are verified in memory and are not persisted.
- Only non-secret metadata (fingerprint/SHA hints, size, opaque node label, host) may be persisted for QA state.
- MeshAgent execution and remote access remain disabled.
