# Smart Pro Managed Support 3.17.7

First-device target-binding compatibility hotfix for the hard-pinned ID-34973 QA installation.

The verified 3.17.4 first-device identity stores the provisioning MeshCentral mesh-id hint (16 hex), while the older per-installation target-settings path exposes a separate .msh MeshID hint (12 hex). 3.17.7 stops treating those different hint namespaces as the same value for this narrowly identified first-device identity.

Security remains fail-closed: the target source fingerprint must still match, and before any MeshAgent execution the full persisted identity binding SHA-256 over MeshName, MeshType, MeshID, ServerID, MeshServer and agentName must match exactly. No re-pair, reseed, new node, permission mutation, MeshAgent `-install`, service/systemd persistence, or technician Web/Terminal/Files/Desktop authorization is added.


## 3.17.7 live finding / fix
After the first successful 3.17.6 target runtime, the stable identity metadata correctly hydrated the target binding/source hints. A later manual re-enable then stopped at `persistent_target_binding_changed` because the 3.17.6 compatibility classifier incorrectly depended on those hints still being empty. 3.17.7 recognizes the already-proven Portal-bound first-device identity by its durable 16-hex provisioning mesh hint and continues to compare every other target/source hint plus the full persisted `.msh` binding SHA-256. No re-pair, reseed, Arm, or Broker mutation is introduced.
