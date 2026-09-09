#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.15.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: PER-INSTALLATION PERMANENT CANDIDATE PROMOTION ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + unattended renewable runtime + verified per-installation target + quarantined candidate + rollback-first permanent promotion."
echo "Promotion: candidate -> νέα stable identity με local rollback backup και target per-installation runtime source. Ο παλιός MeshCentral node δεν διαγράφεται πριν ολοκληρωθεί post-promotion QA."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
