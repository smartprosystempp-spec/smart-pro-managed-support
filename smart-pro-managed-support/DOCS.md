# Smart Pro Managed Support — 3.1.0 QA

1. Broker 0.26.0 must be active first.
2. Open the add-on after updating 3.0.0 → 3.1.0. Local policy should still show ID-95948 and ALLOWED, but Broker identity should be No.
3. In WordPress → Remote Sessions → Managed Support, issue one one-time pairing for ID-95948.
4. Enter that code once in the 3.1.0 Ingress page.
5. Expected: Broker identity = Yes, Broker server authorization = Yes / `allowed`, server lease present, authorization chain = Yes.
6. Remote access must remain No. No new MeshCentral SPMNG node must appear.
7. Do not use any legacy support-session/60-second runtime controls for this 3.x QA.
