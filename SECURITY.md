# Security boundary

Η 3.0.0 δεν έχει MeshAgent runtime ή server authorization.

- `share` mapped read-only.
- no host network.
- no privileged/full access.
- no Home Assistant/Supervisor API permissions.
- no credentials stored or displayed.
- local `allowed=true` is not sufficient for remote access.
- stale Tools lease fails closed.
- invalid/missing policy fails closed.
