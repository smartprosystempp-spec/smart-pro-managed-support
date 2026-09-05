# Smart Pro Managed Support — 3.0.0 Foundation

## Αναμενόμενη πρώτη δοκιμή

Με Smart Pro Tools 2.4.6 ενεργό, ανοίξτε το Ingress του νέου add-on.

Στην τρέχουσα εγκατάσταση, μέχρι να προστεθεί το `managed_remote_support` entitlement στο Portal, αναμένεται:

- σωστό Installation ID,
- σωστή συνδρομή/κατάσταση,
- Managed entitlement = Όχι,
- local policy = denied,
- reason code = `entitlement_missing`,
- Remote access = Όχι.

Αυτό είναι επιτυχές foundation checkpoint.

## Δεν πρέπει να συμβεί

- να δημιουργηθεί νέο MeshCentral node,
- να εκτελεστεί MeshAgent,
- να ζητηθεί κωδικός/session/customer approval,
- να τροποποιηθεί Smart Pro Tools,
- να επηρεαστεί Guest/Temporary 0.9.6 ή legacy Managed 2.5.2.
