#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.4.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: AGENT BINARY VERIFICATION CONSUMER ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: read-only Managed Policy + Broker identity/heartbeat + Server Authorization + fresh enrollment + secure .msh verification + one-time MeshAgent binary request/consume + SHA/bytes/ELF64/architecture verification."
echo "Ανενεργά: persistent .msh/agent storage, chmod +x, MeshAgent execution, MeshCentral runtime, remote access."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
