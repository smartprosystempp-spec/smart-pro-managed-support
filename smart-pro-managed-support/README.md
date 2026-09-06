# Smart Pro Managed Support 3.1.0

Authorization-only Home Assistant add-on for the subscription Managed Remote Support architecture.

## Active in 3.1.0
- Read-only Smart Pro Tools policy from `/share/smart-pro-system/managed-policy.json`.
- One-time pairing with Smart Pro Remote Session Broker 0.26.0+.
- Persistent Managed node identity under the add-on private `/data` directory.
- Authenticated heartbeat every 60 seconds.
- Server Authorization Contract v1 with a bounded lease (server maximum 180 seconds).
- Overall authorization requires both local policy and server authorization.

## Still disabled
- `.msh` delivery
- MeshAgent download or execution
- MeshCentral connection/node creation
- Remote desktop/terminal/files/tunnel
- Any host service installation or persistence
