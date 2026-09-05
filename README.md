# Smart Pro Managed Support Repository

Ξεχωριστό Home Assistant repository για το συνδρομητικό **Smart Pro Managed Support**.

Η σειρά 3.x είναι ανεξάρτητη από το Guest/Temporary repository και χρησιμοποιεί νέο slug `smart_pro_managed_support`.

## 3.0.0 Foundation

Η 3.0.0 είναι **policy-consumer foundation μόνο**:

- διαβάζει read-only το `/share/smart-pro-system/managed-policy.json` που παράγει το Smart Pro Tools 2.4.6+,
- ελέγχει contract/version, Installation ID, authorization deadline και Tools liveness lease,
- εμφανίζει την τοπική κατάσταση στο Ingress,
- δεν επικοινωνεί ακόμη με Broker,
- δεν παραλαμβάνει `.msh`,
- δεν κατεβάζει/εκτελεί MeshAgent,
- δεν δημιουργεί MeshCentral node,
- δεν παρέχει remote access.

Το επόμενο στάδιο θα προσθέσει ξεχωριστό server-side Managed authorization contract πριν ενεργοποιηθεί οποιοδήποτε runtime.
