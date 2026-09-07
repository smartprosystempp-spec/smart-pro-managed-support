# Smart Pro Managed Support — 3.7.0 Controlled Identity Continuity QA

## Checkpoint A — Update only

1. Keep Broker 0.31.0 and Smart Pro Tools 2.4.6 unchanged.
2. Keep Legacy Managed 2.5.2 and Guest/Temporary 0.9.6 untouched.
3. Update 3.6.2 → 3.7.0 without uninstall/re-pair.
4. Do **not** start the canary.
5. Confirm startup log says `STABLE MESHAGENT IDENTITY CANARY 3.7.0` and runtime client 3.7.0.
6. Confirm Managed authorization remains ALLOWED.
7. Confirm `MeshCentral stable identity` says that no stable identity has been saved yet.
8. Confirm the existing two offline canary records remain offline and **no new MeshCentral node is created by the update itself**.
9. STOP and review.

## Checkpoint B — First seed run (only after A passes)

The old 3.6.x runtime directories were deleted, so their private MeshAgent identities cannot be recovered. The first 3.7.0 canary is therefore expected to create **one new final candidate node** and persist its `meshagent.db`. After stop: identity mode `seed`, identity DB persisted `Ναι`, generation `1`, continuity runs `1`, elapsed <=45s, runtime cleanup `Ναι`, technician actions NOT AUTHORIZED, agent/service persistence OFF. STOP.

## Checkpoint C — Reuse proof (only after B passes)

Run exactly one more canary. The node created in B must come online again and the total number of MeshCentral records must **not increase**. Expected identity mode `reuse`, generation `1`, continuity runs `2`. Only after this passes is MeshCentral identity continuity considered proven.
