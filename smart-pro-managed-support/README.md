# Smart Pro Managed Support 3.18.1

Το **Smart Pro Managed Support** είναι το πρόσθετο μόνιμης, ελεγχόμενης υποστήριξης του Smart Pro System για Home Assistant.

Η 3.18.1 είναι έκδοση **παρουσίασης και τεκμηρίωσης**. Δεν αλλάζει τη λειτουργία της σταθερής MeshCentral ταυτότητας, τα renewable runtime leases, την αυτόματη επανασύνδεση, το fail-closed behavior ή το πρωτόκολλο του Broker.

## Τι βελτιώνει
- Ελληνική και πιο καθαρή καθημερινή οθόνη.
- Συνοπτική «Σύνοψη λειτουργίας» με τα στοιχεία που χρειάζονται πραγματικά στην καθημερινή χρήση.
- Η κύρια «Μόνιμη Managed σύνδεση» ξεχωρίζει από τα ιστορικά diagnostics.
- Τα τεχνικά runtime στοιχεία μετακινούνται σε αναδιπλούμενη ενότητα.
- Η κατάσταση μετά από restart εμφανίζεται ως «Αναμονή αυτόματης επανασύνδεσης» αντί να μοιάζει σαν να μην έχει ξεκινήσει ποτέ.
- Τα ιστορικά εργαλεία παραμένουν διαθέσιμα, τεκμηριωμένα και κλειδωμένα.
- Η τεκμηρίωση του Home Assistant είναι πλέον customer/support oriented αντί για release-note oriented.

## Τι δεν αλλάζει
- Δεν γίνεται re-pair ή reseed.
- Δεν δημιουργείται νέο MeshCentral node από το update.
- Δεν αλλάζει το target binding.
- Δεν αλλάζει η λογική leases / reconnect / Broker authorization.
- Δεν χρησιμοποιείται MeshAgent `-install`.
- Δεν δημιουργείται service/systemd persistence.
- Web / Terminal / Files / Desktop για τεχνικό παραμένουν **NOT AUTHORIZED**.

Τα Home Assistant logs παραμένουν το βασικό client-side διαγνωστικό αρχείο. Δεν προστίθεται δεύτερο diagnostic ZIP exporter σε αυτή την έκδοση.
