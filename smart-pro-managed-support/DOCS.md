# Smart Pro Managed Support 3.17.1

Bounded first-device execution canary for the hard-pinned Portal-bound `ID-34973` / `amd64` target.

Requires Broker 0.53.1, fresh Managed heartbeat/server authorization, and an explicit temporary Broker admin arm. The client consumes one execution contract, verifies exact `.msh` + approved MeshAgent material, requires a fresh zero-device start gate, runs MeshAgent foreground-only for at most 75 seconds, then reports the exact-mesh device count.

No `-install`, no service/systemd persistence, no technician Desktop/Terminal/Files authorization, and no automatic retry.
