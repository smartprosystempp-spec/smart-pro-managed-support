# 3.14.0 — Quarantined Candidate Reconnect Verification Consumer

- Reuses the already quarantined candidate `meshagent.db`; it does not seed a second candidate.
- Requires Broker 0.41.0+ short-lived candidate reconnect authorization.
- Broker read-only `nodes` watch must observe the exact already-bound candidate node online during the <=45s canary.
- Stable shared identity remains untouched and is automatically restored after the canary.
- Candidate quarantine remains unchanged after the test.
- No permanent runtime-source switch, no identity-binding commit, no old-node deletion, no technician authorization.
- Unattended supervisor is locked while the reconnect worker owns the MeshAgent lifecycle.

# 3.13.1 — Reseed Supervisor Lock & Candidate Quarantine Carry-Forward Hotfix

- Prevented unattended supervisor race during clean reseed.
- Preserved an existing quarantined candidate across version update and kept second reseed locked.

# 3.13.0 — Clean Per-Installation Identity Reseed Canary

- Created one quarantined fresh candidate in the verified per-installation group without changing the active stable identity.
