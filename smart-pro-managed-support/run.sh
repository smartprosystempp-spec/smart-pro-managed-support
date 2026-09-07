#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.9.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: UNATTENDED RESTART RECOVERY CONSUMER ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + stable MeshCentral identity reuse + renewable runtime lease + continuous Broker watch/health + controlled foreground reconnect."
echo "Unattended mode: παραμένει OFF μετά το update. Μετά από ρητή ενεργοποίηση admin, το ίδιο stable node ανακτάται αυτόματα μετά από add-on restart όταν οι άδειες είναι έγκυρες."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
