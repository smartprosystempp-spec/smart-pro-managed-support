# Smart Pro Managed Support 3.5.0

## Agent Binary Verification Consumer

Η 3.5.0 είναι το επόμενο ελεγχόμενο βήμα μετά το verified 3.2.0 enrollment authorization.

Ενεργά:
- Smart Pro Tools Managed Policy Contract v1 (read-only),
- Broker Managed identity + authenticated heartbeat,
- Portal-backed Server Authorization Contract v1,
- fresh one-time enrollment authorization bound to 3.5.0,
- one-time Managed 3.x secure settings request/consume,
- local verification του `.msh`: exact SHA-256, exact byte count, required MeshCentral fields, WSS endpoint και opaque `SPMNG-*` node label.

Security boundary:
- το raw settings ticket δεν αποθηκεύεται ούτε γράφεται σε log,
- το raw `.msh` επαληθεύεται στη μνήμη και δεν αποθηκεύεται,
- αποθηκεύονται μόνο non-secret verification metadata/hints,
- δεν γίνεται MeshAgent download, chmod ή execution,
- δεν δημιουργείται MeshCentral node,
- remote access παραμένει OFF.
