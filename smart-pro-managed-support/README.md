# Smart Pro Managed Support 3.18.0

UI consolidation and documented diagnostic archive built directly on the live-verified 3.17.7 lifecycle baseline.

## What changes
- A compact **Current state / Next action** snapshot is shown first.
- The active **Unattended Managed runtime** card remains visible and operational.
- Historical diagnostics, first-device checkpoints and migration/recovery tooling are preserved in collapsible sections instead of a permanent wall of cards.
- Every archived tool explains its impact, intended use, prerequisites, rerun policy and how to interpret success/failure.
- Historical mutation/test buttons are visibly locked in 3.18.0; the server-side gate also accepts only explicit unattended start/stop.
- The old technical pairing form is retained only as reference when no identity exists, but is locked pending the separate Customer Portal onboarding/activation flow.

## What does not change
The verified 3.17.7 stable identity, target-binding continuity, renewable runtime leases, unattended restart recovery and fail-closed behavior are unchanged. No re-pair, reseed, new node, MeshCentral permission mutation, MeshAgent `-install`, service/systemd persistence, or technician Web/Terminal/Files/Desktop authorization is added.

This release intentionally does **not** add a second diagnostic ZIP exporter. Home Assistant add-on logs remain the primary client-side incident artifact; a lightweight support snapshot can be reconsidered later if real support cases justify it.
