# Smart Pro Managed Support 3.7.0

## Stable MeshAgent Identity Canary

Η 3.7.0 κρατά όλη την ασφαλή verified αλυσίδα της 3.6.2 και προσθέτει **ελεγχόμενη συνέχεια MeshCentral ταυτότητας**.

Το canary παραμένει χειροκίνητο, foreground και έως 45s. Η πρώτη επιτυχής εκτέλεση δημιουργεί και αποθηκεύει ιδιωτικά το `meshagent.db`. Το runtime `.msh` θέτει επίσης `skipmaccheck=1` για να μη γίνεται αλλαγή NodeID λόγω αλλαγής MAC του add-on container. Η επόμενη εκτέλεση πρέπει να επαναχρησιμοποιήσει το ίδιο DB ώστε το ίδιο server-side MeshCentral node να γίνει ξανά online, χωρίς νέο duplicate.

Παραμένουν απενεργοποιημένα:
- `MeshAgent -install`,
- service/systemd persistence,
- unattended 24/7 runtime,
- Desktop / Terminal / Files technician authorization.

Binary, `.msh`, runtime lease και one-time authorization tokens παραμένουν ephemeral.
