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
