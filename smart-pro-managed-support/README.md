# 3.11.1 target settings verification

This release verifies the staged per-installation target `.msh` through a one-time authenticated Broker 0.37.0+ contract while the existing shared unattended runtime may remain online. The raw ticket and `.msh` are memory-only. No MeshAgent execution, node move, runtime-source switch, identity-binding commit or technician access occurs.

> 3.11.1 hotfix: exact request/preflight text bindings are compared as UTF-8 bytes so the non-ASCII em dash in the per-installation group name is handled safely. Runtime behavior is unchanged.
