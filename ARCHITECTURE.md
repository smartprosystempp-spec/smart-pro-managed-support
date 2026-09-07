# Architecture — Managed 3.x

Portal / Subscription Core → Smart Pro Tools → read-only Managed Policy v1 → Smart Pro Managed Support

Smart Pro Managed Support ↔ Smart Pro Remote Session Broker 0.26.0+ → live Portal Subscription Core

Authorization is deliberately two independent gates:

1. **Local gate**: Smart Pro Tools policy must be fresh and ALLOWED.
2. **Server gate**: authenticated Managed identity must receive an unexpired Server Authorization Contract v1 lease.

Only `local_allowed && server_authorized` produces `authorized_managed=true`.

MeshCentral enrollment/runtime is a later stage and remains absent from 3.2.0.


## 3.5.0 secure-settings boundary

`Local Policy ALLOWED + Server Authorization ALLOWED + fresh 3.5.0 enrollment consume` → one-time secure settings ticket → in-memory `.msh` verification → discard raw payload.

This stage does not execute or persist MeshAgent and does not create a MeshCentral runtime connection.
