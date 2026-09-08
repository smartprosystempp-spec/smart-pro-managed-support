#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.10.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: PER-INSTALLATION GROUP MIGRATION PREFLIGHT CONSUMER ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + stable MeshCentral identity reuse + unattended renewable runtime + authenticated per-installation group migration preflight."
echo "Migration preflight: metadata-only. Δεν παραδίδει target .msh, δεν μετακινεί node και δεν αλλάζει το ενεργό runtime source."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
