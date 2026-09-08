# 3.13.1 controlled migration canary

First real per-installation group connectivity canary. It reuses the existing protected stable identity, never commits the target binding, and rolls back to the shared unattended runtime after <=45 seconds.
