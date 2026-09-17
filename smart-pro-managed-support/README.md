# Smart Pro Managed Support 3.19.0

Το **Smart Pro Managed Support** είναι το πρόσθετο μόνιμης, ελεγχόμενης υποστήριξης του Smart Pro System για Home Assistant.

Η **3.19.0** προσθέτει το production **Router Compatibility** πάνω στο επαληθευμένο multi-architecture Managed lifecycle της 3.18.2, χωρίς αλλαγή της σταθερής MeshAgent ταυτότητας, του unattended reconnect, των renewable leases ή της λογικής Broker authorization.

## Τι αλλάζει

- Προστίθεται Router Compatibility endpoint μόνο στο `127.0.0.1:18080`.
- Το router target προκύπτει μόνο από το read-only contract `smart-pro-managed-network-v1` που παράγει το Smart Pro Tools.
- Γίνεται validation ιδιωτικού IPv4 gateway, freshness/lease και βασικών health flags πριν επιτραπεί οποιοδήποτε request.
- Υποστηρίζονται bounded `GET`, `HEAD` και `POST` requests με όρια request/response size.
- Γίνεται ασφαλές rewriting των `Host`, `Referer`, `Origin` και router-local redirects όπου απαιτείται για MeshCentral WebRelay compatibility.
- Η 3.19.0 συνεχίζει να υποστηρίζει **amd64** και **aarch64**.
- Το stable continuous lifecycle gate μεταφέρεται στην 3.19.0.

## Τι παραμένει ίδιο

- Δεν γίνεται re-pair ή reseed.
- Δεν δημιουργείται νέο MeshCentral node από το update.
- Δεν αλλάζει το per-installation target group.
- Δεν αλλάζει το persisted MeshAgent identity.
- Δεν αλλάζει η λογική renewable leases / reconnect / Broker authorization.
- Δεν χρησιμοποιείται MeshAgent `-install`.
- Δεν δημιουργείται service/systemd persistence μέσα στο Home Assistant host.
- Τα ιστορικά first-device εργαλεία παραμένουν αρχειοθετημένα και κλειδωμένα.
- Τα δικαιώματα Web / Terminal / Files / Desktop παραμένουν **ξεχωριστά ελεγχόμενα από τα MeshCentral permissions** και δεν ενεργοποιούνται απλώς επειδή εγκαταστάθηκε η 3.19.0.

## Router Compatibility

Το Router Compatibility λειτουργεί ως ελεγχόμενη γέφυρα:

**MeshCentral WebRelay → Managed Agent → `127.0.0.1:18080` → validated local gateway**

Ο browser δεν επιλέγει αυθαίρετο target και το component δεν λειτουργεί ως γενικό proxy.

Δεν αποθηκεύονται router usernames ή passwords από το Smart Pro Managed Support. Το login στον router γίνεται από τον browser του εξουσιοδοτημένου τεχνικού.

Στο verified production QA της 3.19.0 επιβεβαιώθηκαν:
- anonymous router page load,
- authenticated login,
- διατήρηση session,
- πλοήγηση σε Wi‑Fi και γενικές ρυθμίσεις,
- restart recovery του Router Compatibility.

Σε ορισμένα router interfaces η πλοήγηση μέσω WebRelay μπορεί να είναι αισθητά πιο αργή από την άμεση LAN πρόσβαση.

## Verified lifecycle

Η 3.19.0 έχει επαληθευτεί για:
- reuse της ίδιας stable MeshAgent identity,
- αυτόματη επανασύνδεση μετά από restart,
- Broker authorization,
- renewable lease,
- Terminal / Files σύμφωνα με τα αντίστοιχα permissions,
- Home Assistant WebRelay,
- σωστή UTF‑8/ελληνική απόδοση,
- Router Compatibility πριν και μετά από restart.

## Update

Η έκδοση προορίζεται για **update-in-place**.

Δεν γίνεται:
- uninstall,
- διαγραφή `/data`,
- νέο pairing,
- χειροκίνητη μετακίνηση ή διαγραφή MeshCentral node.

Σε περίπτωση προβλήματος μετά από update, ελέγχεται πρώτα το Home Assistant add-on log και το αντίστοιχο server-side diagnostic/checkpoint.
