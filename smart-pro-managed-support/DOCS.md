# Smart Pro Managed Support — 3.6.0 Controlled Canary QA

1. Broker 0.31.0 πρέπει να είναι ήδη PASS.
2. Update 3.5.0 → 3.6.0 χωρίς uninstall/re-pairing.
3. Επιβεβαίωσε Managed authorization ALLOWED και Remote access = Όχι.
4. Άνοιξε MeshCentral σε δεύτερο tab ΠΡΙΝ το canary.
5. Πάτησε μία φορά «Έναρξη connectivity canary ≤45″».
6. Παρατήρησε μόνο αν εμφανίζεται το expected `SPMNG-*` node. ΜΗΝ ανοίξεις Desktop/Terminal/Files.
7. Μετά από 50–60s κάνε refresh στο Ingress. Αναμενόμενο reported result + runtime cleanup Ναι.
8. Μετά το stop, το node μπορεί να φαίνεται offline.

Δεν κοινοποιούνται pairing/node secrets, .msh, agent tickets, runtime lease ή report token.
