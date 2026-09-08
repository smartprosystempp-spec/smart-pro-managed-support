#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.12.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: PER-INSTALLATION GROUP EXECUTION MIGRATION CANARY ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + stable MeshCentral identity reuse + unattended renewable runtime + authenticated per-installation migration preflight + one-time target .msh verification."
echo "Migration canary: foreground <=45s με την ίδια stable identity και verified target .msh. Δεν κάνει permanent binding/source commit και δεν ενεργοποιεί technician access."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
