#!/bin/sh
set -eu

VERSION="${SMART_PRO_MANAGED_VERSION:-3.7.0}"
PORT="8098"

umask 077
ulimit -c 0 2>/dev/null || true

echo "===================================================="
echo "  Smart Pro Managed Support"
echo "===================================================="
echo "Κατάσταση: STABLE MESHAGENT IDENTITY CANARY ${VERSION}"
echo "Το Ingress UI ακούει μόνο στο εσωτερικό port ${PORT}."
echo "Ενεργά: verified Managed chain + renewable runtime lease + one-time execution-canary authorization + foreground MeshAgent έως 45s + protected MeshAgent identity continuity."
echo "Ανενεργά: MeshAgent -install, service persistence, unattended permanent runtime, Desktop/Terminal/Files authorization. Binary/.msh/tickets παραμένουν ephemeral· μόνο το meshagent.db identity αποθηκεύεται ιδιωτικά μετά από επιτυχή canary."
echo "===================================================="

exec python3 /opt/smart-pro/app.py
