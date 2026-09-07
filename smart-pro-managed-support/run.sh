#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.3.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: SECURE SETTINGS VERIFICATION CONSUMER ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: read-only Managed Policy Contract v1 + Broker identity/heartbeat + Server Authorization Contract v1 + fresh enrollment authorization + one-time secure .msh request/consume + local integrity/format verification."
echo "Ανενεργά: persistent .msh storage, MeshAgent download/execution, MeshCentral runtime, remote access."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
