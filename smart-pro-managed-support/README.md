# Smart Pro Managed Support 3.17.0

Hard-pinned bounded first-device execution canary for the prepared Portal-bound `ID-34973` / `amd64` target.

This build requires Broker 0.53.0, a fresh 3.17.0 Managed heartbeat, live Portal authorization, and an explicit 5-minute Broker admin arm. It consumes exactly one execution contract, re-verifies the exact prepared `.msh` and approved amd64 MeshAgent, starts only a foreground process for at most 75 seconds, and reports the observed exact-mesh device count.

No `-install`, no service/systemd persistence, no technician Desktop/Terminal/Files authorization, no automatic retry. Raw execution tickets, raw `.msh`, and the MeshAgent binary are not persisted. On a normal bounded completion, only the MeshAgent identity database is retained for later continuity testing.
