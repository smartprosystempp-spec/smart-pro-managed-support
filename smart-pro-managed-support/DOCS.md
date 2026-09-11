# Smart Pro Managed Support 3.18.0 — UI / Diagnostic Archive

3.18.0 is a presentation and documentation release over the verified 3.17.7 unattended lifecycle.

The everyday view now prioritizes current authorization/runtime health, unattended state, lease/reconnect counters, expected stable node and the next safe action. The active unattended runtime controls remain outside collapsed sections.

All prior diagnostic/checkpoint cards remain available under collapsible groups:
- Diagnostic chain tools — enrollment, secure settings, MeshAgent binary and runtime-lease dry-run.
- Identity/connectivity diagnostics — bounded identity-continuity canary.
- Provisioning / Migration / Recovery — preflight, target settings, migration canary, identity reseed, candidate reconnect and permanent promotion.
- Completed first-device checkpoints — Portal-bound settings and controlled retry/reset + bounded first-device execution.
- Detailed Policy & Authorization — the original low-level status grid.

Archived actions are UI-disabled and also blocked by the 3.18.0 server-side POST safety gate. They are retained as forensic history and future maintenance tooling, not as routine buttons.

The customer-facing Managed onboarding/activation flow is intentionally out of scope for 3.18.0 and will be designed separately around Portal-owned installation activation.
