# Changelog

## 3.0.0

- Νέο ανεξάρτητο `Smart Pro Managed Support` add-on/repository.
- Νέο slug `smart_pro_managed_support` ώστε να μην αναβαθμίζει κατά λάθος το legacy 2.5.2.
- Read-only mapping του Home Assistant `share`.
- Consumer του `smart-pro-managed-policy-v1` από Smart Pro Tools 2.4.6+.
- Fail-closed validation για missing/invalid contract, stale Tools lease και expired local authorization.
- Ingress health/status foundation.
- Κανένα Broker request, `.msh`, MeshAgent, MeshCentral runtime ή remote access.
