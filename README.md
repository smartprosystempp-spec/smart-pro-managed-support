# Smart Pro Managed Support Repository

Ξεχωριστό Home Assistant repository για το συνδρομητικό **Smart Pro Managed Support** με slug `smart_pro_managed_support`.

## 3.5.0 — Secure Settings Verification Consumer

Η 3.5.0 προσθέτει το πρώτο πραγματικό Managed 3.x secure-settings consume πάνω στην ήδη verified authorization αλυσίδα. Πριν από κάθε settings consume εκτελεί fresh enrollment authorization δεμένο στη συγκεκριμένη έκδοση/αρχιτεκτονική.

Το `.msh` επαληθεύεται μόνο στη μνήμη (SHA-256, bytes, required fields, WSS endpoint, opaque `SPMNG-*` label) και δεν αποθηκεύεται.

Η 3.5.0 **δεν** κατεβάζει/εκτελεί MeshAgent, δεν δημιουργεί MeshCentral node και δεν παρέχει remote access.
