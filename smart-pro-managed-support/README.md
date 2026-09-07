# Smart Pro Managed Support 3.2.0

Authorization-only Home Assistant add-on for the subscription Managed Remote Support architecture.

## Active in 3.2.0
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


## 3.2.0 Enrollment Authorization Consumer
Η έκδοση 3.2.0 προσθέτει μόνο ελεγχόμενο one-time enrollment authorization request/consume προς Broker 0.27.0+. Δεν ζητά ή αποθηκεύει `.msh`, δεν κατεβάζει/εκτελεί MeshAgent και δεν ενεργοποιεί MeshCentral ή remote access.
