# Smart Pro Managed Support — Architecture 3.x

## Σταθερή αλυσίδα

Portal / Subscription Core → Smart Pro Tools → Smart Pro Managed Support → Managed Backend/Broker → MeshCentral

## Αρχές

1. Το Smart Pro Tools είναι η τοπική canonical γέφυρα Installation ID + subscription policy.
2. Το Managed add-on δεν εμπιστεύεται μόνο το τοπικό policy για remote access.
3. Για μελλοντικό runtime απαιτούνται ταυτόχρονα local policy allowance + fresh Tools lease + server-side Managed authorization.
4. Το MeshAgent θα τρέχει foreground μέσα στο add-on container. Δεν προβλέπεται `-install`, systemd ή host service persistence.
5. Guest/Temporary και Managed είναι ξεχωριστά προϊόντα, repositories, slugs και MeshCentral groups.
6. MeshCentral Managed group: `Smart Pro Managed Support`; Managed node prefix: `SPMNG-`.

## Foundation 3.0.0

Μόνο read-only policy consumer. Καμία δυνατότητα απομακρυσμένης πρόσβασης.
