## 3.18.1 — Presentation & Documentation Polish
- Presentation/documentation-only polish over 3.18.0.
- Rewrites Home Assistant add-on description and documentation as customer/support-facing content instead of release notes.
- Removes the 3.17.7 baseline wording from the everyday Add-on Store presentation.
- Greek-first operational labels and collapsible section names.
- Shows «Αναμονή αυτόματης επανασύνδεσης» during the normal post-restart recovery window when unattended mode is enabled.
- Simplifies the top summary and moves stable-node / lease / identity internals under «Τεχνικά στοιχεία runtime».
- Gives Enable/Pause controls clearer visual hierarchy.
- Removes the permanent UI-only release-note banner from the everyday Ingress screen.
- Historical diagnostics remain documented and locked; customer activation remains out of scope.
- No runtime algorithm, lease/reconnect logic, identity validation, Broker protocol, MeshAgent execution path, permissions, or persistence change.

## 3.18.0 — UI Consolidation & Diagnostic Archive
- UI-only consolidation over the live-verified 3.17.7 ID-34973 lifecycle baseline.
- Adds compact Current State / Next Action operational snapshot.
- Keeps the active unattended runtime card visible and operational.
- Moves historical diagnostics/checkpoints into collapsible sections without deleting state, forms or forensic information.
- Adds per-tool documentation: impact, when to use, prerequisites, rerun policy and result interpretation.
- Visibly locks historical mutation/test buttons; server-side stable gate accepts only explicit unattended start/stop.
- Keeps the old technical pairing UI only as locked reference pending the separate Portal customer onboarding/activation flow.
- No runtime algorithm, stable identity binding, lease/reconnect logic, Broker contract, MeshCentral permissions, service persistence or technician authorization change.

## 3.17.7 — First-Device Target Binding Continuity
- Built directly from live 3.17.6 after successful unattended runtime + restart recovery + pause/restart QA, followed by a manual re-enable failure `persistent_target_binding_changed`.
- Root cause: 3.17.6 detected first-device compatibility only while target binding/source hints were still empty. The first successful target runtime correctly hydrated those fields, so the next start no longer entered the compatibility path even though the durable first-device provenance was unchanged.
- Fix: recognize the Portal-bound first-device target identity from `runtime_source=target`, no promotion state, persisted 16-hex provisioning mesh hint, and current 12-hex target `.msh` MeshID hint. Skip only that incompatible hint-namespace comparison.
- All other target/source hints still compare exactly and `_validate_persisted_mesh_identity()` still requires the full SHA-256 binding over MeshName/MeshType/MeshID/ServerID/MeshServer/agentName.
- No Broker change, no re-pair, no reseed, no MeshAgent install/service persistence, no technician actions.

# Changelog

## 3.17.6 — First-Device Target Binding Compatibility
- Built directly from 3.17.5 after live `persistent_target_binding_changed` on ID-34973.
- Root cause: the first-device provisioning state stores a 16-character hint of the immutable MeshCentral mesh id, while the legacy group-migration target-settings contract exposes a 12-character hint of the `.msh` `MeshID`; these are intentionally different hint namespaces.
- Adds a narrowly-scoped compatibility path only for a TARGET identity seeded by the verified first-device flow (no promotion state, no legacy target-binding hint, no shared-source hint).
- Does not compare those heterogeneous MeshID hints directly.
- Still requires the exact target source fingerprint and, immediately afterwards, the existing full persisted identity binding SHA-256 over `MeshName`, `MeshType`, `MeshID`, `ServerID`, `MeshServer`, and `agentName`.
- No Broker change required; intended counterpart remains Broker 0.56.4.
- No re-pair, reseed, new identity, MeshCentral permission mutation, `-install`, service persistence, or technician authorization.

## 3.17.5 — Continuous Runtime Lifecycle Unlock + Control UI Fix
- Built directly from live-verified 3.17.4 after first-device PASS and restart identity persistence PASS.
- Preserves the 3.17.4 first-device proof and stable MeshAgent identity; no reset/re-arm/reseed.
- Leaves first-device execution ownership frozen at 3.17.4 and moves 3.17.5 into continuous-runtime lifecycle QA.
- Starts the existing unattended supervisor again, but only after explicit admin enablement.
- Fixes the persistent-runtime Start/Pause buttons, which were accidentally rendered with an unconditional HTML `disabled` attribute.
- Adds a 3.17.5 POST safety gate: only unattended start/stop are accepted; historical mutation/test actions remain non-repeatable.
- No MeshAgent -install, no service/systemd persistence, no technician Desktop/Terminal/Files authorization.
- Broker 0.56.1 remains unchanged; generic Managed 3.x runtime contracts are reused.

# Changelog

## 3.17.4 — Controlled Retry Proof Correction
- Corrects the local reset-consume safety guard to require the actual preserved failed 3.17.1 execution proof.
- Keeps Broker reset consume explicit/manual and execution DISARMED.
- Updates UI/runtime labels to 3.17.4 while preserving prior diagnostic history.
- Requires Broker 0.56.1 for exact 3.17.4 protocol compatibility.

## 3.17.3 — Controlled Retry Reset Consumer
- Exact ID-34973/amd64 one-time Broker 0.56 retry reset consume.
- No automatic arm, no MeshAgent execution, no technician actions.
- Local failed 3.17.2 proof is required before consume; only non-secret metadata is retained.
- Later execution remains separately admin-armed and bounded.

# Changelog

## 3.17.2
- Diagnostic/reliability hotfix on top of 3.17.1; no automatic execution retry is introduced.
- Persists only non-secret stage metadata for the first-device canary: diagnostic stage, Broker endpoint, failure class, watch count, process-started flag, and final-report status.
- Adds stage logs around execution request/consume, agent consume, start gate, process launch, watch loop, identity persistence, report, and cleanup.
- Keeps raw tickets, raw .msh, MeshAgent binary and node secrets out of diagnostics.
- Keeps the existing no-retry guard authoritative; a failed/consumed 3.17.1 canary is not re-armed by this update.
- No MeshAgent -install, service/systemd persistence, or technician Desktop/Terminal/Files authorization.

## 3.17.1
- UI continuity hotfix over 3.17.0. Restores all previously built Managed diagnostic/status panels that 3.17.0 accidentally hid at render time.
- Keeps every legacy mutation control visibly disabled during the first-device execution checkpoint; the existing server-side legacy POST block remains authoritative.
- Does not change the bounded first-device execution algorithm, identity files, one-time settings proof, MeshAgent binary verification, runtime limit, persistence rules, technician authorization, or device lifecycle.
- Requires Broker 0.53.1, which pins the execution client to exact Managed Support 3.17.1.

## 3.17.0
- Adds the hard-pinned `ID-34973` / `amd64` bounded first-device execution consumer for Broker 0.53.0.
- Requires explicit server-side admin arm and a fresh 0-device exact-mesh recheck before client start.
- Consumes one-time execution/settings/agent material only in memory or ephemeral `/tmp` runtime.
- Runs MeshAgent foreground only for at most 75 seconds; never uses `-install` or service persistence.
- Persists only the resulting protected `meshagent.db` identity after normal bounded completion for later continuity QA.
- Final local PASS requires Broker report `first_device_verified` and exactly one device.
- No automatic retry; technician actions remain disabled.

## 3.16.0
- Adds verification-only consumer for Broker 0.51.0 Portal-bound first-device settings contract.
- Hard-pinned to ID-34973 / amd64 / exact Managed 3.16.0 identity.
- One-time SPMFD ticket and raw .msh remain memory-only.
- Persists only non-secret verification metadata.
- Does not execute MeshAgent, create/enroll a device, authorize remote access, or enable technician actions.
- Keeps the dedicated api.smart-pro-system.gr Broker endpoint and existing 3.15.3 identity/state.

# Changelog

## 3.15.3
- Switched the default Managed Broker base URL from the public site hostname to the dedicated API gateway: `https://api.smart-pro-system.gr/wp-json/smart-pro-remote/v1`.
- No change to identity files, promoted TARGET runtime, MeshAgent execution logic, lease logic, rollback backup, group binding, technician authorization, or MeshCentral node lifecycle.

# 3.15.2 — Persistent Runtime Source Telemetry Hotfix

- Fixes the live 3.15.1 promotion failure `promotion_target_runtime_start_timeout`.
- `save_persistent_state()` already persisted `runtime_source`, but `load_persistent_state()` did not return it.
- The promotion worker therefore could not observe `status=running` together with `runtime_source=target`, even though the target MeshAgent had actually started.
- Adds `runtime_source` to the sanitized persistent-state reader only.
- Broker 0.42.1 contract, candidate identity, rollback-first commit, exact bound-node verification, old-node retention, and technician authorization remain unchanged.
- No node deletion, permission mutation, service persistence, re-pair, or `/data` reset.
