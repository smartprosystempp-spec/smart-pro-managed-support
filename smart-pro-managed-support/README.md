# Smart Pro Managed Support 3.17.5

Continuous runtime lifecycle verification release for the hard-pinned ID-34973 QA installation.

This release preserves the verified first-device result from 3.17.4 and the persisted stable MeshAgent identity. It unlocks only the already-proven unattended continuous-runtime start/stop path so restart/reconnect continuity can be verified using the same identity.

Safety boundary: no re-pair, no identity reseed, no first-device retry/reset, no MeshAgent `-install`, no service/systemd persistence, and technician Web/Terminal/Files/Desktop actions remain NOT AUTHORIZED.
