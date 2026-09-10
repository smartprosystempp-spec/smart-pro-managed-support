#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.16.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: PER-INSTALLATION TARGET RUNTIME + DEDICATED API GATEWAY ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified per-installation target runtime + unattended renewable leases + dedicated Smart Pro API gateway endpoint."
echo "Broker endpoint: https://api.smart-pro-system.gr/wp-json/smart-pro-remote/v1 — machine-to-machine μόνο. Identity/runtime source παραμένουν TARGET."
echo "Ανενεργά: MeshAgent -install, service/systemd persistence, technician web/Terminal/Files/Desktop authorization. Raw lease/tickets/control token δεν αποθηκεύονται."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
