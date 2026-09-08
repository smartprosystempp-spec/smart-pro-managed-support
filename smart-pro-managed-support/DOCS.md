# 3.10.0 migration preflight notes

Η online παρουσία του Managed MeshCentral node και η τεχνική πρόσβαση παραμένουν ξεχωριστές έννοιες. Η 3.10.0 διατηρεί το αποδεδειγμένο unattended runtime της 3.9.0 και προσθέτει μόνο authenticated preflight προς τον Broker 0.36.0+.

Το preflight επαληθεύει ότι η υπάρχουσα stable MeshAgent identity και το Installation ID συμφωνούν με το verified target group `Smart Pro Managed — <Installation ID>`, το dedicated controller binding και την ενεργή Portal-backed authorization. Δεν παραδίδει target `.msh`, δεν μετακινεί MeshCentral node, δεν αλλάζει το runtime source και δεν ενεργοποιεί Web/Terminal/Files/Desktop.

Η σταθερή MeshAgent identity παραμένει ιδιωτικά στο `/data/meshagent-identity/`. Runtime binary, `.msh`, runtime lease και Broker control material παραμένουν ephemeral/memory-only. Το migration-preflight state αποθηκεύει μόνο non-secret hints και timestamps.
