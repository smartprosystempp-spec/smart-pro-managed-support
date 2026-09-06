# Changelog

## 3.1.0 — Dual Authorization Foundation
- Keeps Smart Pro Tools Managed Policy Contract v1 as the local, read-only authorization gate.
- Adds one-time Managed identity pairing through the existing Broker identity contract.
- Pairing is bound to the Installation ID from the local policy; a mismatched Broker pairing is rejected server-side before node creation by Broker 0.26.0+.
- Stores only `node_id`, `node_secret`, Installation ID and paired timestamp in `/data/managed-identity.json` with mode 0600. Pairing codes are never persisted.
- Adds authenticated Broker heartbeat every 60 seconds.
- Consumes Managed Server Authorization Contract v1 and requires a valid bounded server lease.
- If a Broker request temporarily fails, the last successful server authorization may remain valid only until its original `valid_until`; after that the client fails closed.
- Overall Managed authorization is `local policy ALLOWED` AND `server authorization ALLOWED`.
- No `.msh`, MeshAgent, MeshCentral node, remote desktop, terminal, files, tunnel, or remote access in 3.1.0.
