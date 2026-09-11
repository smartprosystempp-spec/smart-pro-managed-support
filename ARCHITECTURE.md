# Architecture — Smart Pro Managed Support 3.18.1

## Ροή εξουσιοδότησης

`Customer Portal / Subscription Core` → `Smart Pro Tools Managed Policy` → `Smart Pro Managed Support` ↔ `Smart Pro Remote Session Broker` → `MeshCentral`

Η Managed σύνδεση απαιτεί δύο ανεξάρτητες πηγές εξουσιοδότησης:

1. **Local policy gate** από το Smart Pro Tools.
2. **Server authorization gate** από τον Broker.

Μόνο όταν και τα δύο είναι έγκυρα επιτρέπεται η Managed runtime λειτουργία.

## Σταθερή ταυτότητα

Η τρέχουσα 3.x γραμμή χρησιμοποιεί per-installation stable MeshAgent identity. Η identity δεσμεύεται στην εγκατάσταση, στην αναμενόμενη αρχιτεκτονική και στο επαληθευμένο MeshCentral target binding.

Το runtime λειτουργεί με **reuse-only** identity μετά την επιτυχημένη δημιουργία/επαλήθευσή της. Αλλαγή ή ασυμφωνία binding αποτυγχάνει fail-closed αντί να δημιουργηθεί αυθαίρετα νέο node.

## Unattended runtime

Όταν το unattended mode είναι ενεργό:

- το MeshAgent εκτελείται foreground,
- χρησιμοποιεί βραχύβια renewable runtime leases,
- παρακολουθεί local policy και Broker authorization,
- μπορεί να επανέλθει αυτόματα μετά από add-on restart με την ίδια stable identity,
- σταματά fail-closed αν χαθεί η απαιτούμενη εξουσιοδότηση ή lease.

Δεν χρησιμοποιείται MeshAgent `-install` και δεν δημιουργείται host/service persistence.

## Diagnostic archive

Τα παλιότερα enrollment, settings, binary, migration/recovery και first-device checkpoints διατηρούνται σε collapsed diagnostic sections για μελλοντικό troubleshooting. Οι ιστορικές mutation/test actions είναι κλειδωμένες στη stable 3.18.x γραμμή.

Τα Home Assistant logs παραμένουν το κύριο client-side diagnostic artifact. Το Broker παρέχει ξεχωριστό per-installation sanitized diagnostic bundle για server-side συσχέτιση.

## Customer activation

Η τελική customer-facing activation/onboarding ροή είναι ξεχωριστό επόμενο στάδιο και θα συνδεθεί με το Customer Portal. Δεν αποτελεί μέρος της 3.18.1.
