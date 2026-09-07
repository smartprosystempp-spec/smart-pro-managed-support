#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.2.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: ENROLLMENT AUTHORIZATION CONSUMER ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: read-only Managed Policy Contract v1 + Broker identity/heartbeat + Server Authorization Contract v1 + one-time enrollment authorization request/consume."
echo "Ανενεργά: .msh delivery/storage, MeshAgent download/execution, MeshCentral runtime, remote access."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
