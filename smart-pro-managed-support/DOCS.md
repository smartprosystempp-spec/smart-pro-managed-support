# Smart Pro Managed Support — 3.3.0 QA

1. Update 3.2.0 → 3.3.0 χωρίς uninstall/re-pairing.
2. Επιβεβαίωσε ότι Managed authorization παραμένει ΕΠΙΤΡΕΠΕΤΑΙ και Remote access = Όχι.
3. Το προηγούμενο 3.2.0 enrollment μπορεί να εμφανίζεται ως προηγούμενο VERIFIED· ο secure-settings έλεγχος θα εκτελέσει αυτόματα νέο enrollment δεμένο στη 3.3.0.
4. Πάτησε μία φορά «Έλεγχος secure settings».
5. Αναμενόμενο: VERIFIED, source fingerprint hint, SHA-256 hint, bytes και opaque `SPMNG-*` label.
6. Δεν πρέπει να δημιουργηθεί MeshCentral node και δεν πρέπει να ξεκινήσει MeshAgent.

Το `.msh` και τα one-time tickets δεν πρέπει να κοινοποιούνται ή να εμφανίζονται σε screenshots/logs.
