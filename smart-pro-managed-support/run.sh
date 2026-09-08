#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.13.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: CLEAN PER-INSTALLATION IDENTITY RESEED CANARY ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + stable shared rollback identity + unattended renewable runtime + verified per-installation target + clean-reseed authorization."
echo "Clean reseed canary: foreground <=45s με verified target .msh ΧΩΡΙΣ το παλιό meshagent.db. Δημιουργεί μόνο quarantined candidate identity, κρατά την παλιά stable identity ανέγγιχτη και κάνει rollback στο shared runtime."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
