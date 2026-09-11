# Smart Pro Managed Support Repository

Ξεχωριστό Home Assistant repository για το **Smart Pro Managed Support** του Smart Pro System.

Η τρέχουσα γραμμή είναι η **3.18.1** με σταθερή Managed ταυτότητα, renewable runtime leases, unattended recovery μετά από restart και τεκμηριωμένο diagnostic archive.

## Τι περιέχει το repository

- `smart-pro-managed-support/` — το ενεργό Home Assistant add-on.
- `repository.yaml` — metadata του Home Assistant repository.
- `ARCHITECTURE.md` — συνοπτική τεχνική αρχιτεκτονική.
- `SECURITY.md` — βασικά όρια ασφάλειας και fail-closed συμπεριφορά.
- `UPLOAD-TO-GITHUB.md` — οδηγίες ενημέρωσης του repository.

## Τρέχουσα λειτουργική βάση

Η 3.18.1 πατά πάνω στο επαληθευμένο unattended lifecycle της 3.17.7 και διατηρεί:

- μόνιμη per-installation Managed identity,
- reuse του ίδιου stable MeshCentral node,
- renewable runtime leases,
- αυτόματη επανασύνδεση μετά από add-on restart όταν το unattended mode είναι ενεργό,
- fail-closed διακοπή όταν χαθεί η απαιτούμενη local/server authorization,
- χωρίς MeshAgent `-install`, service/systemd persistence ή αυτόματη εξουσιοδότηση τεχνικού.

Η 3.18.1 είναι presentation/documentation release και δεν αλλάζει τον παραπάνω runtime μηχανισμό.

## Σχέση με άλλα Smart Pro add-ons

Το Temporary / Guest Support βρίσκεται σε ξεχωριστό repository. Η παλιά Managed 2.5.2 γραμμή έχει αποσυρθεί από τα ενεργά repositories και διατηρείται μόνο ως historical archive.

## Σημαντικό

Μην κάνετε uninstall, re-pair, reseed ή διαγραφή `/data` για απλό update. Οι ενημερώσεις της 3.x γραμμής γίνονται in-place ώστε να διατηρείται η σταθερή identity.
