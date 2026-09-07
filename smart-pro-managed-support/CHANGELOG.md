# Changelog

## 3.3.0 — Secure Settings Verification Consumer
- Fresh 3.3.0 enrollment authorization before settings delivery.
- Dedicated Managed 3.x `/managed/settings/request` + `/consume` consumer.
- Exact SHA-256 / byte-count / required-field / WSS / opaque node-label verification.
- Raw one-time ticket and raw `.msh` are never persisted or logged.
- MeshAgent, MeshCentral runtime and remote access remain disabled.
- Fixes latent unpaired Ingress rendering fallback for missing identity/source dictionaries.


## 3.2.0 — Enrollment Authorization Consumer
- Preserves the complete 3.1.0 local policy + Broker identity + server-authorization chain.
- Adds a controlled manual enrollment authorization check against Broker 0.27.0+.
- Requires local policy ALLOWED, active Managed identity and a live server authorization lease before requesting enrollment authorization.
- Requests a one-time `SPMB-*` bootstrap/enrollment ticket, validates the response contract, and immediately consumes the same ticket.
- Validates Installation ID, node identity, architecture/client binding, source fingerprint hint continuity and server authorization validity.
- Requires Broker responses to keep `.msh delivery`, Agent delivery, execution and remote access explicitly false.
- The one-time ticket is held only in memory during request/consume; it is never persisted or logged.
- Persists only a non-secret verification record: timestamp, Installation ID, node ID, client/architecture, server-valid-until and 12-character source fingerprint hint.
- No `.msh` is requested or stored.
- No MeshAgent is downloaded, chmodded or executed.
- No MeshCentral node or remote access is created.

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
