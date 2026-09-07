# Smart Pro Managed Support — 3.2.0 QA

1. Broker 0.26.0 must be active first.
2. Open the add-on after updating 3.0.0 → 3.2.0. Local policy should still show ID-95948 and ALLOWED, but Broker identity should be No.
3. In WordPress → Remote Sessions → Managed Support, issue one one-time pairing for ID-95948.
4. Enter that code once in the 3.2.0 Ingress page.
5. Expected: Broker identity = Yes, Broker server authorization = Yes / `allowed`, server lease present, authorization chain = Yes.
6. Remote access must remain No. No new MeshCentral SPMNG node must appear.
7. Do not use any legacy support-session/60-second runtime controls for this 3.x QA.


## 3.2.0 Enrollment Authorization Consumer
Η έκδοση 3.2.0 προσθέτει μόνο ελεγχόμενο one-time enrollment authorization request/consume προς Broker 0.27.0+. Δεν ζητά ή αποθηκεύει `.msh`, δεν κατεβάζει/εκτελεί MeshAgent και δεν ενεργοποιεί MeshCentral ή remote access.
