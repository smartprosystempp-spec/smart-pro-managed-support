# Smart Pro Managed Support 3.9.0

## Unattended Restart Recovery Consumer — restart recovery checkpoint

Η 3.9.0 είναι το πρώτο client στάδιο μετά το live PASS της σταθερής MeshCentral identity στην 3.7.0 και απαιτεί Broker 0.32.0+.

- Χρησιμοποιεί μόνο υπάρχουσα VERIFIED σταθερή `meshagent.db` identity. Δεν κάνει seed νέας identity.
- Κάνει fresh enrollment/settings/agent verification πριν από start.
- Ζητά renewable runtime lease και το νέο `smart-pro-managed-persistent-runtime-v1` authorization.
- Εκτελεί μόνο foreground `setsid ./meshagent`, χωρίς `-install` ή service persistence.
- Polls continuous server watch και στέλνει health reports.
- Ανανεώνει το runtime lease όταν ζητηθεί από τον Broker.
- Σε agent exit κάνει bounded controlled reconnect με την ίδια identity.
- Σε local policy/server authorization/runtime lease loss σταματά fail-closed.
- Technician actions παραμένουν NOT AUTHORIZED.
- Raw runtime lease, start ticket και control token μένουν μόνο στη μνήμη.

Για το πρώτο live checkpoint, η continuous λειτουργία ξεκινά χειροκίνητα από Ingress. Το update μόνο του δεν ενεργοποιεί MeshAgent.
