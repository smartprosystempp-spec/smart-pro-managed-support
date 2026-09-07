#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.8.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: CONTINUOUS FOREGROUND RUNTIME CONSUMER ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + stable MeshCentral identity reuse + renewable runtime lease + continuous Broker watch/health + controlled foreground reconnect."
echo "Πρώτο live QA: το MeshAgent ΔΕΝ ξεκινά αυτόματα με το update. Η εκκίνηση γίνεται χειροκίνητα από Ingress και μετά μπορεί να παραμένει online όσο οι άδειες ανανεώνονται."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
