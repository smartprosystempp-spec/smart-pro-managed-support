#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.0.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: POLICY CONSUMER FOUNDATION ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: read-only Managed Policy Contract v1 + local health classification."
echo "Ανενεργά: Broker authorization, .msh delivery, MeshAgent, MeshCentral runtime, remote access."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
