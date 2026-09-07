# Changelog

## 3.9.0 — Unattended Restart Recovery Consumer
- Adds explicit admin enable/pause state for unattended Managed runtime.
- Update alone remains safe: unattended mode defaults OFF when no prior 3.9 control file exists.
- After explicit enable, add-on restart waits for local policy + Broker server authorization and then automatically recovers the same stable MeshCentral identity.
- Respects Broker 0.32.0 stale-runtime recovery window before a restart recovery attempt.
- Backs off after failed starts and disables unattended mode on identity-integrity failures pending manual review.
- No identity seed, no -install/service persistence, no technician actions.


## 3.8.0 — Continuous Foreground Runtime Consumer
- Requires already-proven stable MeshAgent identity from 3.7.0; seed is forbidden.
- Consumes Broker 0.32.0 persistent-runtime contract.
- Renewable runtime lease + continuous watch + health reporting.
- Bounded controlled reconnect using the same node identity.
- Fail-closed stop on local policy/server authorization/runtime lease loss.
- First live QA remains manual start/stop; update alone does not launch MeshAgent.
- Technician actions remain NOT AUTHORIZED; no `-install` or service persistence.


## 3.7.0 — Stable MeshAgent Identity Canary

- Adds a protected persistent MeshAgent identity store under private `/data`.
- Persists only `meshagent.db` plus non-secret binding/integrity metadata; binary, `.msh`, leases and one-time tokens remain ephemeral.
- First successful canary seeds a stable identity; later canaries must reuse it.
- Runtime hardening adds `skipmaccheck=1` so container MAC changes do not rotate the MeshAgent NodeID.
- Stored identity is bound to Installation ID, Broker Managed node ID, architecture, opaque `SPMNG-*` label and hash of critical verified `.msh` fields.
- Database file is regular-file checked, size-bounded, mode 0600 and SHA-256 verified before reuse.
- Partial, mismatched or tampered persistent state fails closed before MeshAgent launch to avoid silent duplicate-node creation.
- Runtime remains foreground, hard <=45s, no `-install`, no service persistence and technician actions remain NOT AUTHORIZED.
- Broker stays 0.31.0; no re-pairing required.

## 3.6.2 — Strict Canary Runtime Boundary Hotfix

- Διορθώνει live QA εύρημα όπου το τελικό elapsed εμφανίστηκε 48s / 45s.
- Η 3.6.1 έδινε SIGTERM στο όριο και μετά περίμενε έως 3s graceful shutdown πριν μετρήσει το τελικό elapsed.
- Το canary ξεκινά πλέον graceful shutdown 3s πριν από το απόλυτο hard stop και κάνει SIGKILL fallback στο hard stop.
- Το πραγματικό process lifetime δεν επιτρέπεται πλέον να ξεπεράσει το μικρότερο από local max και Broker hard deadline.
- Η τελική ένδειξη Έναρξη διατηρεί πλέον τον πραγματικό process-start χρόνο αντί για την αρχή του preflight worker.
- Δεν αλλάζουν pairing, Broker contract, verified chain, technician authorization ή persistence policy.

## 3.6.1 — Connectivity Canary UI Hotfix

- Διορθώνει μόνο την εμφάνιση της ενότητας `MeshAgent connectivity canary` στο Ingress UI.
- Στην 3.6.0 το canary HTML block βρισκόταν κατά λάθος μέσα στο `else` του unpaired runtime branch, οπότε σε paired εγκατάσταση δεν αποδιδόταν ποτέ.
- Δεν αλλάζει το connectivity-canary worker, Broker contract, execution boundaries, runtime lease, `.msh`, MeshAgent verification ή cleanup logic.
- Δεν απαιτεί re-pairing.

## 3.6.0 — Foreground MeshAgent Connectivity Canary

- Πρώτη πραγματική Managed 3.x foreground εκτέλεση MeshAgent, μόνο μετά από πλήρη fresh verified chain και Broker 0.31.0 execution-canary authorization.
- Hard runtime έως 45s, lease-bounded και server-watch controlled.
- Private ephemeral runtime directory 0700.
- Verified MeshAgent ephemeral copy chmod 0700 μόνο μέσα στο canary runtime.
- Ephemeral meshagent.msh mode 0600 με disableUpdate/noUpdateCoreModule hardening.
- Launch: `setsid ./meshagent` χωρίς args, χωρίς `-install`, χωρίς service persistence.
- stdout/stderr δεν αποθηκεύονται.
- Desktop/Terminal/Files παραμένουν NOT AUTHORIZED.
- Runtime directory διαγράφεται μετά το stop/report.

## 3.5.0 — Runtime Lease Dry-Run Consumer

- Προσθέτει verification-only consumer του Broker 0.30.0 `smart-pro-managed-runtime-lease-v1`.
- Ένα button ανανεώνει αυτόματα enrollment + secure settings + MeshAgent binary verification για την 3.5.0.
- Ζητά ένα βραχύβιο runtime lease και το ανανεώνει ακριβώς μία φορά μετά από ~70s.
- Το raw `SPMRL-*` lease μένει μόνο στη μνήμη του background worker και δεν αποθηκεύεται/εμφανίζεται/logged.
- Μετά την επιτυχή ανανέωση το local raw lease απορρίπτεται και το server lease αφήνεται να λήξει φυσιολογικά.
- Αποθηκεύονται μόνο μη-μυστικά timestamps/status για QA.
- MeshAgent execution, chmod +x, MeshCentral runtime/node και remote access παραμένουν OFF.

## 3.5.0 — Agent Binary Verification Consumer

- Προσθέτει verification-only one-time MeshAgent binary request/consume μέσω Broker 0.29.0.
- Πριν από binary delivery εκτελεί fresh 3.5.0 enrollment + secure settings verification.
- Το binary γράφεται μόνο σε /tmp με mode 0600, ελέγχεται streaming SHA/bytes, ELF64/little-endian/e_machine και ξανά SHA/bytes από disk.
- Διαγράφεται αμέσως μετά τον έλεγχο, και σε failure cleanup path.
- Δεν γίνεται chmod +x, δεν εκτελείται subprocess/MeshAgent και δεν δημιουργείται MeshCentral node.
- Remote access παραμένει OFF.

## 3.3.0 — Secure Settings Verification Consumer
- Fresh 3.3.0 enrollment authorization before settings delivery.
- Dedicated Managed 3.x `/managed/settings/request` + `/consume` consumer.
- Exact SHA-256 / byte-count / required-field / WSS / opaque node-label verification.
- Raw one-time ticket and raw `.msh` are never persisted or logged.
- MeshAgent, MeshCentral runtime and remote access remain disabled.
- Fixes latent unpaired Ingress rendering fallback for missing identity/source dictionaries.


## 3.2.0 — Enrollment Authorization Consumer
- Preserves the complete 3.1.0 local policy + Broker identity + server-authorization chain.
- Adds a controlled manual enrollment authorization check against Broker 0.27.0+.
- Requires local policy ALLOWED, active Managed identity and a live server authorization lease before requesting enrollment authorization.
- Requests a one-time `SPMB-*` bootstrap/enrollment ticket, validates the response contract, and immediately consumes the same ticket.
- Validates Installation ID, node identity, architecture/client binding, source fingerprint hint continuity and server authorization validity.
- Requires Broker responses to keep `.msh delivery`, Agent delivery, execution and remote access explicitly false.
- The one-time ticket is held only in memory during request/consume; it is never persisted or logged.
- Persists only a non-secret verification record: timestamp, Installation ID, node ID, client/architecture, server-valid-until and 12-character source fingerprint hint.
- No `.msh` is requested or stored.
- No MeshAgent is downloaded, chmodded or executed.
- No MeshCentral node or remote access is created.

## 3.1.0 — Dual Authorization Foundation
- Keeps Smart Pro Tools Managed Policy Contract v1 as the local, read-only authorization gate.
- Adds one-time Managed identity pairing through the existing Broker identity contract.
- Pairing is bound to the Installation ID from the local policy; a mismatched Broker pairing is rejected server-side before node creation by Broker 0.26.0+.
- Stores only `node_id`, `node_secret`, Installation ID and paired timestamp in `/data/managed-identity.json` with mode 0600. Pairing codes are never persisted.
- Adds authenticated Broker heartbeat every 60 seconds.
- Consumes Managed Server Authorization Contract v1 and requires a valid bounded server lease.
- If a Broker request temporarily fails, the last successful server authorization may remain valid only until its original `valid_until`; after that the client fails closed.
- Overall Managed authorization is `local policy ALLOWED` AND `server authorization ALLOWED`.
- No `.msh`, MeshAgent, MeshCentral node, remote desktop, terminal, files, tunnel, or remote access in 3.1.0.
