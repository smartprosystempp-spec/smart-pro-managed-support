# Smart Pro Managed Support 3.17.6

First-device target-binding compatibility hotfix for the hard-pinned ID-34973 QA installation.

The verified 3.17.4 first-device identity stores the provisioning MeshCentral mesh-id hint (16 hex), while the older per-installation target-settings path exposes a separate .msh MeshID hint (12 hex). 3.17.6 stops treating those different hint namespaces as the same value for this narrowly identified first-device identity.

Security remains fail-closed: the target source fingerprint must still match, and before any MeshAgent execution the full persisted identity binding SHA-256 over MeshName, MeshType, MeshID, ServerID, MeshServer and agentName must match exactly. No re-pair, reseed, new node, permission mutation, MeshAgent `-install`, service/systemd persistence, or technician Web/Terminal/Files/Desktop authorization is added.
