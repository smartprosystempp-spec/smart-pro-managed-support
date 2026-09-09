Smart Pro Managed Support 3.15.2 — Permanent Candidate Promotion Persistent Runtime Source Telemetry Hotfix.

This build fixes one live-only promotion gate defect found in 3.15.1: the persistent runtime state writer stored `runtime_source`, but the sanitized state reader omitted it. As a result, the promotion worker timed out waiting for `RUNNING + target` even when the target runtime had already launched.

3.15.2 keeps Broker 0.42.1, rollback-first safety, the exact bound candidate node, target group, candidate quarantine, old shared identity backup, and technician-access lock unchanged.
