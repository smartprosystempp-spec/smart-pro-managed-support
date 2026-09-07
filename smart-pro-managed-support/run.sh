#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.6.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: FOREGROUND CONNECTIVITY CANARY ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + renewable runtime lease + one-time execution-canary authorization + foreground MeshAgent connectivity έως 45s."
echo "Ανενεργά: MeshAgent -install, service persistence, unattended permanent runtime, Desktop/Terminal/Files authorization. Runtime material παραμένει ephemeral."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
