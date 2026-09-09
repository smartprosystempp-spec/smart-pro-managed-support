#!/usr/bin/env python3
import base64
import binascii
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

VERSION = os.environ.get("SMART_PRO_MANAGED_VERSION", "3.14.0")
ARCH = os.environ.get("SMART_PRO_MANAGED_ARCH", "unknown")
PORT = 8098
BROKER_BASE = os.environ.get(
    "SMART_PRO_BROKER_BASE_URL",
    "https://smart-pro-system.gr/wp-json/smart-pro-remote/v1",
).rstrip("/")
POLICY_FILE = Path("/share/smart-pro-system/managed-policy.json")
DATA_DIR = Path("/data")
IDENTITY_FILE = DATA_DIR / "managed-identity.json"
ENROLLMENT_STATE_FILE = DATA_DIR / "enrollment-authorization.json"
SETTINGS_STATE_FILE = DATA_DIR / "settings-verification.json"
AGENT_STATE_FILE = DATA_DIR / "agent-binary-verification.json"
RUNTIME_STATE_FILE = DATA_DIR / "runtime-lease-dry-run.json"
CANARY_STATE_FILE = DATA_DIR / "identity-continuity-canary.json"
PERSISTENT_STATE_FILE = DATA_DIR / "continuous-runtime-state.json"
UNATTENDED_CONTROL_FILE = DATA_DIR / "unattended-runtime-control.json"
GROUP_MIGRATION_PREFLIGHT_FILE = DATA_DIR / "group-migration-preflight.json"
GROUP_MIGRATION_TARGET_SETTINGS_FILE = DATA_DIR / "group-migration-target-settings.json"
GROUP_MIGRATION_CANARY_FILE = DATA_DIR / "group-migration-canary.json"
GROUP_IDENTITY_RESEED_FILE = DATA_DIR / "group-identity-reseed-canary.json"
CANDIDATE_RECONNECT_FILE = DATA_DIR / "candidate-reconnect-verification.json"
MESH_CANDIDATE_DIR = DATA_DIR / "meshagent-candidate-quarantine"
MESH_CANDIDATE_DB_FILE = MESH_CANDIDATE_DIR / "meshagent.db"
MESH_CANDIDATE_META_FILE = MESH_CANDIDATE_DIR / "candidate-meta.json"
MESH_IDENTITY_DIR = DATA_DIR / "meshagent-identity"
MESH_IDENTITY_DB_FILE = MESH_IDENTITY_DIR / "meshagent.db"
MESH_IDENTITY_META_FILE = MESH_IDENTITY_DIR / "identity-meta.json"
EXPECTED_CONTRACT = "smart-pro-managed-policy-v1"
EXPECTED_POLICY_VERSION = 1
EXPECTED_SERVER_AUTH_VERSION = 1
MAX_POLICY_BYTES = 65536
MAX_RESPONSE_BYTES = 131072
MAX_POST_BYTES = 8192
HEARTBEAT_INTERVAL = 60
HTTP_TIMEOUT = 12
RUNTIME_RENEW_DELAY = 70
CANARY_LOCAL_MAX_RUNTIME = 45
CANARY_SHUTDOWN_GRACE = 3
CANARY_POLL_FALLBACK = 5
MAX_MESH_IDENTITY_DB_BYTES = 16 * 1024 * 1024
MESH_IDENTITY_BINDING_KEYS = ("MeshName", "MeshType", "MeshID", "ServerID", "MeshServer", "agentName")
NODE_ID_RE = re.compile(r"^SPMN-[A-F0-9]{32}$")
NODE_SECRET_RE = re.compile(r"^SPMS-[A-Za-z0-9_-]{43}$")
BOOTSTRAP_TICKET_RE = re.compile(r"^SPMB-[A-Za-z0-9_-]{43}$")
SETTINGS_TICKET_RE = re.compile(r"^SPMD-[A-Za-z0-9_-]{43}$")
TARGET_SETTINGS_TICKET_RE = re.compile(r"^SPGMT-[A-Za-z0-9_-]{43}$")
MIGRATION_CANARY_TICKET_RE = re.compile(r"^SPMGC-[A-Za-z0-9_-]{43}$")
MIGRATION_CANARY_REPORT_RE = re.compile(r"^SPMGR-[A-Za-z0-9_-]{43}$")
IDENTITY_RESEED_TICKET_RE = re.compile(r"^SPMIR-[A-Za-z0-9_-]{43}$")
IDENTITY_RESEED_REPORT_RE = re.compile(r"^SPMIRR-[A-Za-z0-9_-]{43}$")
CANDIDATE_RECONNECT_TICKET_RE = re.compile(r"^SPMCR-[A-Za-z0-9_-]{43}$")
CANDIDATE_RECONNECT_REPORT_RE = re.compile(r"^SPMCRR-[A-Za-z0-9_-]{43}$")
AGENT_TICKET_RE = re.compile(r"^SPMA-[A-Za-z0-9_-]{43}$")
RUNTIME_LEASE_RE = re.compile(r"^SPMRL-[A-Za-z0-9_-]{43}$")
CANARY_TICKET_RE = re.compile(r"^SPMEC-[A-Za-z0-9_-]{43}$")
CANARY_REPORT_RE = re.compile(r"^SPMER-[A-Za-z0-9_-]{43}$")
PERSISTENT_TICKET_RE = re.compile(r"^SPMPR-[A-Za-z0-9_-]{43}$")
PERSISTENT_CONTROL_RE = re.compile(r"^SPMPC-[A-Za-z0-9_-]{43}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
AGENT_LABEL_RE = re.compile(r"^SPMNG-[A-F0-9]{16}$")
FINGERPRINT_HINT_RE = re.compile(r"^[a-f0-9]{12}$")
MIN_AGENT_BYTES = 100000
MAX_AGENT_BYTES = 67108864
ELF_MACHINE = {"aarch64": 183, "amd64": 62}
CSRF_TOKEN = secrets.token_urlsafe(24)
STATE_LOCK = threading.RLock()
RUNTIME_WORKER_LOCK = threading.Lock()
RUNTIME_WORKER_ACTIVE = False
CANARY_WORKER_LOCK = threading.Lock()
CANARY_WORKER_ACTIVE = False
PERSISTENT_WORKER_LOCK = threading.Lock()
PERSISTENT_WORKER_ACTIVE = False
PERSISTENT_STOP_EVENT = threading.Event()
MIGRATION_CANARY_WORKER_LOCK = threading.Lock()
MIGRATION_CANARY_WORKER_ACTIVE = False
IDENTITY_RESEED_WORKER_LOCK = threading.Lock()
IDENTITY_RESEED_WORKER_ACTIVE = False
CANDIDATE_RECONNECT_WORKER_LOCK = threading.Lock()
CANDIDATE_RECONNECT_WORKER_ACTIVE = False
PERSISTENT_RECONNECT_DELAYS = (5, 10, 20, 30, 60)
PERSISTENT_MAX_CONSECUTIVE_EXITS = 5
PERSISTENT_WATCH_FAILURE_GRACE = 45
MIGRATION_CANARY_LOCAL_MAX_RUNTIME = 45
MIGRATION_CANARY_SHARED_STOP_TIMEOUT = 20
IDENTITY_RESEED_LOCAL_MAX_RUNTIME = 45
IDENTITY_RESEED_SHARED_STOP_TIMEOUT = 20
CANDIDATE_RECONNECT_LOCAL_MAX_RUNTIME = 45
CANDIDATE_RECONNECT_SHARED_STOP_TIMEOUT = 20
UNATTENDED_STARTUP_DELAY = 8
UNATTENDED_STALE_RECOVERY_DELAY = 80
UNATTENDED_FAILURE_RETRY_DELAY = 90
SERVER_STATE = {
    "paired": False,
    "state": "unpaired",
    "authorized_server": False,
    "reason_code": "not_paired",
    "reason": "Απαιτείται μία αρχική ενεργοποίηση Managed Support.",
    "valid_until": 0,
    "last_heartbeat_at": 0,
    "last_success_at": 0,
    "node_id": "",
    "installation_id": "",
    "subscription_status": "",
    "portal_paired": False,
    "managed_entitlement": False,
}


def now_ts():
    return int(time.time())


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_str(value, max_len=300):
    value = str(value or "").strip()
    return value[:max_len]


def read_policy():
    """Read and validate the non-secret Tools policy. Fail closed on ambiguity."""
    base = {
        "state": "policy_missing",
        "allowed_local": False,
        "reason": "Δεν βρέθηκε ακόμη το Managed Policy του Smart Pro Tools.",
        "reason_code": "policy_missing",
        "policy": None,
    }
    try:
        stat = POLICY_FILE.stat()
    except FileNotFoundError:
        return base
    except OSError:
        base["state"] = "policy_unreadable"
        base["reason_code"] = "policy_unreadable"
        base["reason"] = "Το Managed Policy υπάρχει αλλά δεν μπορεί να διαβαστεί."
        return base

    if stat.st_size <= 0 or stat.st_size > MAX_POLICY_BYTES:
        base["state"] = "policy_invalid"
        base["reason_code"] = "policy_invalid"
        base["reason"] = "Το Managed Policy έχει μη αποδεκτό μέγεθος."
        return base

    try:
        raw = POLICY_FILE.read_text(encoding="utf-8")
        policy = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        base["state"] = "policy_invalid"
        base["reason_code"] = "policy_invalid"
        base["reason"] = "Το Managed Policy δεν είναι έγκυρο JSON."
        return base

    if not isinstance(policy, dict):
        base["state"] = "policy_invalid"
        base["reason_code"] = "policy_invalid"
        base["reason"] = "Το Managed Policy έχει μη έγκυρη δομή."
        return base
    if policy.get("contract_id") != EXPECTED_CONTRACT:
        base["state"] = "contract_mismatch"
        base["reason_code"] = "contract_mismatch"
        base["reason"] = "Το Managed Policy Contract δεν είναι συμβατό."
        return base
    if _as_int(policy.get("policy_version")) != EXPECTED_POLICY_VERSION:
        base["state"] = "policy_version_mismatch"
        base["reason_code"] = "policy_version_mismatch"
        base["reason"] = "Η έκδοση Managed Policy δεν υποστηρίζεται."
        return base

    installation_id = _safe_str(policy.get("installation_id"), 100).upper()
    if not installation_id:
        base.update({
            "state": "installation_id_missing",
            "reason_code": "installation_id_missing",
            "reason": "Δεν υπάρχει έγκυρο Installation ID στο Managed Policy.",
            "policy": policy,
        })
        return base

    tools = policy.get("tools_liveness") if isinstance(policy.get("tools_liveness"), dict) else {}
    lease_until = _as_int(tools.get("lease_until"))
    if not lease_until or now_ts() > lease_until:
        base.update({
            "state": "tools_stale",
            "reason_code": "tools_stale",
            "reason": "Το Smart Pro Tools δεν έχει ανανεώσει έγκαιρα το Managed Policy.",
            "policy": policy,
        })
        return base

    authorization = policy.get("authorization") if isinstance(policy.get("authorization"), dict) else {}
    valid_until = _as_int(authorization.get("valid_until"))
    if valid_until and now_ts() > valid_until:
        base.update({
            "state": "authorization_expired",
            "reason_code": "authorization_expired",
            "reason": "Η τοπική Managed εξουσιοδότηση έχει λήξει.",
            "policy": policy,
        })
        return base

    if policy.get("allowed") is not True:
        base.update({
            "state": "policy_denied",
            "allowed_local": False,
            "reason_code": _safe_str(policy.get("reason_code") or "policy_denied", 80),
            "reason": _safe_str(policy.get("reason_label") or "Η Managed υποστήριξη δεν επιτρέπεται από την τρέχουσα πολιτική."),
            "policy": policy,
        })
        return base

    base.update({
        "state": "local_policy_allowed",
        "allowed_local": True,
        "reason_code": _safe_str(policy.get("reason_code") or "allowed_verified", 80),
        "reason": "Η τοπική πολιτική επιτρέπει Managed Support.",
        "policy": policy,
    })
    return base


def load_identity():
    try:
        if not IDENTITY_FILE.exists():
            return None
        if IDENTITY_FILE.stat().st_size <= 0 or IDENTITY_FILE.stat().st_size > 16384:
            return None
        data = json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    node_id = _safe_str(data.get("node_id"), 64).upper()
    node_secret = _safe_str(data.get("node_secret"), 80)
    installation_id = _safe_str(data.get("installation_id"), 100).upper()
    if not NODE_ID_RE.fullmatch(node_id) or not NODE_SECRET_RE.fullmatch(node_secret) or not installation_id:
        return None
    return {
        "node_id": node_id,
        "node_secret": node_secret,
        "installation_id": installation_id,
        "paired_at": _as_int(data.get("paired_at")) or 0,
    }


def save_identity(identity):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = IDENTITY_FILE.with_suffix(".tmp")
    payload = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, IDENTITY_FILE)
        os.chmod(IDENTITY_FILE, 0o600)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def broker_post(endpoint, payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    req = Request(
        BROKER_BASE + endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"SmartProManaged/{VERSION}",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise RuntimeError("broker_response_too_large")
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise RuntimeError("broker_response_invalid")
            return data
    except HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        code = f"http_{exc.code}"
        message = f"Ο Broker απέρριψε το αίτημα (HTTP {exc.code})."
        try:
            data = json.loads(raw.decode("utf-8"))
            if isinstance(data, dict):
                code = _safe_str(data.get("code") or code, 100)
                message = _safe_str(data.get("message") or message)
        except (UnicodeError, json.JSONDecodeError):
            pass
        raise RuntimeError(f"{code}|{message}") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("broker_unreachable|Δεν ήταν δυνατή η επικοινωνία με τον Smart Pro Broker.") from exc



def broker_binary_post(endpoint, payload, expected_bytes):
    """POST JSON and stream a verification-only binary to a private 0600 temp file.

    The raw SPMA ticket exists only in the caller's memory. The binary is never
    persisted under /data and this helper never makes it executable.
    """
    expected_bytes = _as_int(expected_bytes) or 0
    if expected_bytes < MIN_AGENT_BYTES or expected_bytes > MAX_AGENT_BYTES:
        raise RuntimeError("agent_expected_size_invalid|Το αναμενόμενο μέγεθος MeshAgent δεν είναι έγκυρο.")

    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    req = Request(
        BROKER_BASE + endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/octet-stream",
            "User-Agent": f"SmartProManaged/{VERSION}",
        },
        method="POST",
    )
    temp_path = None
    success = False
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            content_type = _safe_str(resp.headers.get("Content-Type"), 100).lower()
            contract = _safe_str(resp.headers.get("X-Smart-Pro-Agent-Contract"), 100)
            response_arch = _safe_str(resp.headers.get("X-Smart-Pro-Agent-Architecture"), 30)
            response_sha = _safe_str(resp.headers.get("X-Smart-Pro-Agent-SHA256"), 80).lower()
            execution = _safe_str(resp.headers.get("X-Smart-Pro-Agent-Execution"), 30).lower()
            remote_access = _safe_str(resp.headers.get("X-Smart-Pro-Remote-Access"), 30).lower()
            content_length = _as_int(resp.headers.get("Content-Length")) or 0

            if not content_type.startswith("application/octet-stream"):
                raise RuntimeError("agent_content_type_invalid|Ο Broker δεν επέστρεψε binary MeshAgent payload.")
            if contract != "smart-pro-managed-agent-v1":
                raise RuntimeError("agent_contract_invalid|Το MeshAgent binary contract δεν είναι συμβατό.")
            if response_arch != ARCH:
                raise RuntimeError("agent_arch_header_mismatch|Η αρχιτεκτονική του MeshAgent response δεν συμφωνεί με το add-on.")
            if not SHA256_RE.fullmatch(response_sha):
                raise RuntimeError("agent_sha_header_invalid|Ο Broker δεν επέστρεψε έγκυρο MeshAgent SHA-256.")
            if execution != "disabled" or remote_access != "disabled":
                raise RuntimeError("agent_safety_header_invalid|Το MeshAgent response δεν επιβεβαιώνει verification-only λειτουργία.")
            if content_length and content_length != expected_bytes:
                raise RuntimeError("agent_content_length_mismatch|Το Content-Length του MeshAgent δεν συμφωνεί με το εγκεκριμένο μέγεθος.")

            fd, temp_path = tempfile.mkstemp(prefix="smart-pro-managed-agent-", suffix=".bin", dir="/tmp")
            os.chmod(temp_path, 0o600)
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "wb") as handle:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected_bytes or total > MAX_AGENT_BYTES:
                        raise RuntimeError("agent_stream_too_large|Το MeshAgent payload ξεπέρασε το εγκεκριμένο μέγεθος.")
                    handle.write(chunk)
                    digest.update(chunk)
                handle.flush()
                os.fsync(handle.fileno())

            if total != expected_bytes:
                raise RuntimeError("agent_stream_size_mismatch|Το MeshAgent payload δεν έχει το εγκεκριμένο μέγεθος.")
            success = True
            return {
                "path": temp_path,
                "bytes": total,
                "sha256": digest.hexdigest(),
                "header_sha256": response_sha,
                "architecture": response_arch,
            }
    except HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        code = f"http_{exc.code}"
        message = f"Ο Broker απέρριψε τη λήψη MeshAgent (HTTP {exc.code})."
        try:
            data = json.loads(raw.decode("utf-8"))
            if isinstance(data, dict):
                code = _safe_str(data.get("code") or code, 100)
                message = _safe_str(data.get("message") or message)
        except (UnicodeError, json.JSONDecodeError):
            pass
        raise RuntimeError(f"{code}|{message}") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("broker_unreachable|Δεν ήταν δυνατή η ασφαλής λήψη MeshAgent από τον Smart Pro Broker.") from exc
    except RuntimeError:
        raise
    finally:
        # Failed/abandoned downloads are removed here. On success the caller
        # owns the immediate verify+delete lifecycle.
        if temp_path and not success:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                pass


def set_server_state(**updates):
    with STATE_LOCK:
        SERVER_STATE.update(updates)


def get_server_state():
    identity = load_identity()
    with STATE_LOCK:
        state = dict(SERVER_STATE)
    if identity:
        state["paired"] = True
        state["node_id"] = identity["node_id"]
        state["installation_id"] = identity["installation_id"]
    return state


def validate_server_authorization(auth, identity):
    if not isinstance(auth, dict):
        return False, "server_contract_missing", "Ο Broker δεν επέστρεψε Managed Server Authorization Contract.", 0, {}
    if _as_int(auth.get("schema_version")) != EXPECTED_SERVER_AUTH_VERSION:
        return False, "server_contract_mismatch", "Η έκδοση του Server Authorization Contract δεν υποστηρίζεται.", 0, auth
    installation_id = _safe_str(auth.get("installation_id"), 100).upper()
    if installation_id != identity["installation_id"]:
        return False, "server_installation_mismatch", "Το Server Authorization αφορά διαφορετικό Installation ID.", 0, auth
    valid_until = _as_int(auth.get("valid_until")) or 0
    authorized = auth.get("authorized") is True and valid_until > now_ts()
    reason_code = _safe_str(auth.get("reason_code") or ("allowed" if authorized else "server_denied"), 100)
    reason = _safe_str(auth.get("reason_label") or ("Ο Broker επιτρέπει Managed Support." if authorized else "Ο Broker δεν επιτρέπει Managed Support."))
    return authorized, reason_code, reason, valid_until, auth


def heartbeat_once():
    identity = load_identity()
    if not identity:
        set_server_state(
            paired=False,
            state="unpaired",
            authorized_server=False,
            reason_code="not_paired",
            reason="Απαιτείται μία αρχική ενεργοποίηση Managed Support.",
            valid_until=0,
            node_id="",
            installation_id="",
        )
        return

    policy_snapshot = read_policy()
    policy = policy_snapshot.get("policy") if isinstance(policy_snapshot.get("policy"), dict) else {}
    local_installation = _safe_str(policy.get("installation_id"), 100).upper()
    if local_installation and local_installation != identity["installation_id"]:
        set_server_state(
            paired=True,
            state="identity_mismatch",
            authorized_server=False,
            reason_code="identity_mismatch",
            reason="Η αποθηκευμένη Managed ταυτότητα αντιστοιχεί σε διαφορετικό Installation ID.",
            valid_until=0,
            node_id=identity["node_id"],
            installation_id=identity["installation_id"],
        )
        return

    payload = {
        "node_id": identity["node_id"],
        "node_secret": identity["node_secret"],
        "client_version": VERSION,
        "architecture": ARCH,
    }
    try:
        data = broker_post("/managed/heartbeat", payload)
        if _safe_str(data.get("node_id"), 64).upper() != identity["node_id"]:
            raise RuntimeError("server_node_mismatch|Ο Broker επέστρεψε διαφορετικό Managed node.")
        if _safe_str(data.get("installation_ref"), 100).upper() != identity["installation_id"]:
            raise RuntimeError("server_installation_mismatch|Ο Broker επέστρεψε διαφορετικό Installation ID.")
        authorized, reason_code, reason, valid_until, auth = validate_server_authorization(data.get("server_authorization"), identity)
        set_server_state(
            paired=True,
            state="server_allowed" if authorized else "server_denied",
            authorized_server=authorized,
            reason_code=reason_code,
            reason=reason,
            valid_until=valid_until,
            last_heartbeat_at=now_ts(),
            last_success_at=now_ts(),
            node_id=identity["node_id"],
            installation_id=identity["installation_id"],
            subscription_status=_safe_str(auth.get("subscription_status"), 40),
            portal_paired=auth.get("portal_paired") is True,
            managed_entitlement=auth.get("managed_entitlement") is True,
        )
    except RuntimeError as exc:
        text = str(exc)
        code, _, message = text.partition("|")
        with STATE_LOCK:
            previous = dict(SERVER_STATE)
        cached_ok = previous.get("authorized_server") is True and (_as_int(previous.get("valid_until")) or 0) > now_ts()
        set_server_state(
            paired=True,
            state="server_lease_cached" if cached_ok else "server_unreachable",
            authorized_server=cached_ok,
            reason_code="allowed_cached" if cached_ok else (code or "broker_unreachable"),
            reason="Χρησιμοποιείται το τελευταίο έγκυρο server lease μέχρι τη λήξη του." if cached_ok else (message or "Δεν ήταν δυνατή η επικοινωνία με τον Smart Pro Broker."),
            last_heartbeat_at=now_ts(),
            node_id=identity["node_id"],
            installation_id=identity["installation_id"],
        )


def pair_with_broker(pairing_code):
    snapshot = read_policy()
    policy = snapshot.get("policy") if isinstance(snapshot.get("policy"), dict) else {}
    installation_id = _safe_str(policy.get("installation_id"), 100).upper()
    if not snapshot.get("allowed_local") or not installation_id:
        raise RuntimeError("local_policy_denied|Η αρχική ενεργοποίηση επιτρέπεται μόνο όταν η τοπική Managed πολιτική είναι ενεργή.")
    code = _safe_str(pairing_code, 100).upper()
    if not code.startswith("SPM-"):
        raise RuntimeError("pairing_code_invalid|Ο one-time κωδικός pairing δεν έχει έγκυρη μορφή.")

    data = broker_post("/managed/pair", {
        "pairing_code": code,
        "client": "smart_pro_managed_support",
        "client_version": VERSION,
        "architecture": ARCH,
        "installation_id": installation_id,
    })
    node_id = _safe_str(data.get("node_id"), 64).upper()
    node_secret = _safe_str(data.get("node_secret"), 80)
    server_installation = _safe_str(data.get("installation_ref"), 100).upper()
    if not NODE_ID_RE.fullmatch(node_id) or not NODE_SECRET_RE.fullmatch(node_secret):
        raise RuntimeError("pairing_response_invalid|Ο Broker δεν επέστρεψε έγκυρη Managed ταυτότητα.")
    if server_installation != installation_id:
        raise RuntimeError("pairing_installation_mismatch|Το pairing αντιστοιχεί σε διαφορετικό Installation ID.")

    identity = {
        "node_id": node_id,
        "node_secret": node_secret,
        "installation_id": installation_id,
        "paired_at": now_ts(),
    }
    save_identity(identity)
    set_server_state(
        paired=True,
        state="paired_waiting_heartbeat",
        authorized_server=False,
        reason_code="paired_waiting_heartbeat",
        reason="Η Managed ταυτότητα αποθηκεύτηκε. Γίνεται server-side επαλήθευση.",
        valid_until=0,
        node_id=node_id,
        installation_id=installation_id,
    )
    print(f"[managed] pairing stored for {installation_id}; node secret not logged", flush=True)
    heartbeat_once()



def parse_iso_epoch(value):
    value = _safe_str(value, 80)
    if not value:
        return 0
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except (ValueError, OverflowError, OSError):
        return 0


def load_enrollment_state():
    try:
        if not ENROLLMENT_STATE_FILE.exists():
            return {}
        if ENROLLMENT_STATE_FILE.stat().st_size <= 0 or ENROLLMENT_STATE_FILE.stat().st_size > 16384:
            return {}
        data = json.loads(ENROLLMENT_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    hint = _safe_str(data.get("source_fingerprint_hint"), 20).lower()
    if hint and not FINGERPRINT_HINT_RE.fullmatch(hint):
        return {}
    return {
        "verified": data.get("verified") is True,
        "verified_at": _as_int(data.get("verified_at")) or 0,
        "consumed_at": _as_int(data.get("consumed_at")) or 0,
        "server_valid_until": _as_int(data.get("server_valid_until")) or 0,
        "source_fingerprint_hint": hint,
        "installation_id": _safe_str(data.get("installation_id"), 100).upper(),
        "node_id": _safe_str(data.get("node_id"), 64).upper(),
        "client_version": _safe_str(data.get("client_version"), 30),
        "architecture": _safe_str(data.get("architecture"), 20),
    }


def save_enrollment_state(state):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ENROLLMENT_STATE_FILE.with_suffix(".tmp")
    payload = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, ENROLLMENT_STATE_FILE)
        os.chmod(ENROLLMENT_STATE_FILE, 0o600)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def verify_enrollment_authorization():
    """Request and immediately consume one enrollment authorization ticket.
    The one-time ticket is never persisted or logged.
    """
    snapshot = read_policy()
    identity = load_identity()
    server = get_server_state()

    if identity is None:
        raise RuntimeError("not_paired|Απαιτείται ενεργή Managed identity πριν από τον έλεγχο enrollment.")
    if not snapshot.get("allowed_local"):
        raise RuntimeError("local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει enrollment αυτή τη στιγμή.")

    server_valid_until = _as_int(server.get("valid_until")) or 0
    if server.get("authorized_server") is not True or server_valid_until <= now_ts():
        raise RuntimeError("server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από τον έλεγχο enrollment.")

    policy = snapshot.get("policy") if isinstance(snapshot.get("policy"), dict) else {}
    local_installation = _safe_str(policy.get("installation_id"), 100).upper()
    if local_installation != identity["installation_id"]:
        raise RuntimeError("identity_mismatch|Το Installation ID της Managed identity δεν συμφωνεί με την τοπική πολιτική.")

    common = {
        "node_id": identity["node_id"],
        "node_secret": identity["node_secret"],
        "client_version": VERSION,
        "architecture": ARCH,
    }

    request_data = broker_post("/managed/bootstrap/request", common)
    ticket = _safe_str(request_data.get("bootstrap_ticket"), 80)
    request_hint = _safe_str(request_data.get("source_fingerprint_hint"), 20).lower()
    request_expires = parse_iso_epoch(request_data.get("expires_at"))
    request_server_until = parse_iso_epoch(request_data.get("server_valid_until"))

    request_ok = (
        request_data.get("success") is True
        and request_data.get("mode") == "managed_support"
        and request_data.get("phase") == "bootstrap_authorization_only"
        and request_data.get("enrollment_authorized") is True
        and request_data.get("server_authorization") == "allowed"
        and request_data.get("managed_source_ready") is True
        and request_data.get("msh_delivery") is False
        and request_data.get("agent_delivery") is False
        and request_data.get("execution") is False
        and request_data.get("remote_access") is False
        and BOOTSTRAP_TICKET_RE.fullmatch(ticket) is not None
        and FINGERPRINT_HINT_RE.fullmatch(request_hint) is not None
        and request_expires > now_ts()
        and request_server_until > now_ts()
        and request_expires <= request_server_until
    )
    if not request_ok:
        raise RuntimeError("enrollment_request_contract_invalid|Ο Broker επέστρεψε μη έγκυρο enrollment authorization contract.")

    consume_payload = dict(common)
    consume_payload["bootstrap_ticket"] = ticket
    consume_data = broker_post("/managed/bootstrap/consume", consume_payload)

    consume_hint = _safe_str(consume_data.get("source_fingerprint_hint"), 20).lower()
    consume_server_until = parse_iso_epoch(consume_data.get("server_valid_until"))
    consumed_at = parse_iso_epoch(consume_data.get("consumed_at"))

    consume_ok = (
        consume_data.get("success") is True
        and consume_data.get("authorized") is True
        and consume_data.get("mode") == "managed_support"
        and consume_data.get("phase") == "bootstrap_authorization_only"
        and _safe_str(consume_data.get("node_id"), 64).upper() == identity["node_id"]
        and _safe_str(consume_data.get("installation_ref"), 100).upper() == identity["installation_id"]
        and consume_data.get("enrollment_authorized") is True
        and consume_data.get("server_authorization") == "allowed"
        and consume_data.get("msh_delivery") is False
        and consume_data.get("agent_delivery") is False
        and consume_data.get("execution") is False
        and consume_data.get("remote_access") is False
        and FINGERPRINT_HINT_RE.fullmatch(consume_hint) is not None
        and secrets.compare_digest(request_hint, consume_hint)
        and consume_server_until > now_ts()
        and consumed_at > 0
    )
    if not consume_ok:
        raise RuntimeError("enrollment_consume_contract_invalid|Η κατανάλωση του enrollment authorization δεν επαληθεύτηκε.")

    state = {
        "verified": True,
        "verified_at": now_ts(),
        "consumed_at": consumed_at,
        "server_valid_until": consume_server_until,
        "source_fingerprint_hint": consume_hint,
        "installation_id": identity["installation_id"],
        "node_id": identity["node_id"],
        "client_version": VERSION,
        "architecture": ARCH,
    }
    save_enrollment_state(state)
    print(
        f"[managed] enrollment authorization verified for {identity['installation_id']} "
        f"source_hint={consume_hint}; ticket not stored",
        flush=True,
    )
    return state




def load_settings_state():
    try:
        if not SETTINGS_STATE_FILE.exists():
            return {}
        if SETTINGS_STATE_FILE.stat().st_size <= 0 or SETTINGS_STATE_FILE.stat().st_size > 16384:
            return {}
        data = json.loads(SETTINGS_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    hint = _safe_str(data.get("source_fingerprint_hint"), 20).lower()
    sha_hint = _safe_str(data.get("sha256_hint"), 20).lower()
    agent_label = _safe_str(data.get("agent_label"), 40).upper()
    if hint and not FINGERPRINT_HINT_RE.fullmatch(hint):
        return {}
    if sha_hint and not re.fullmatch(r"^[a-f0-9]{12}$", sha_hint):
        return {}
    if agent_label and not AGENT_LABEL_RE.fullmatch(agent_label):
        return {}
    return {
        "verified": data.get("verified") is True,
        "verified_at": _as_int(data.get("verified_at")) or 0,
        "consumed_at": _as_int(data.get("consumed_at")) or 0,
        "server_valid_until": _as_int(data.get("server_valid_until")) or 0,
        "source_fingerprint_hint": hint,
        "sha256_hint": sha_hint,
        "bytes": _as_int(data.get("bytes")) or 0,
        "agent_label": agent_label,
        "mesh_server_host": _safe_str(data.get("mesh_server_host"), 255).lower(),
        "installation_id": _safe_str(data.get("installation_id"), 100).upper(),
        "node_id": _safe_str(data.get("node_id"), 64).upper(),
        "client_version": _safe_str(data.get("client_version"), 30),
        "architecture": _safe_str(data.get("architecture"), 20),
    }


def save_settings_state(state):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_STATE_FILE.with_suffix(".tmp")
    payload = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, SETTINGS_STATE_FILE)
        os.chmod(SETTINGS_STATE_FILE, 0o600)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def parse_msh_strict(raw_bytes):
    if not isinstance(raw_bytes, (bytes, bytearray)) or len(raw_bytes) < 20 or len(raw_bytes) > 262144:
        raise RuntimeError("settings_payload_size_invalid|Το .msh έχει μη αποδεκτό μέγεθος.")
    if b"\x00" in raw_bytes:
        raise RuntimeError("settings_payload_binary_invalid|Το .msh περιέχει μη αναμενόμενα binary δεδομένα.")
    try:
        text = bytes(raw_bytes).decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError("settings_payload_encoding_invalid|Το .msh δεν είναι έγκυρο UTF-8 κείμενο.") from None
    fields = {}
    for line in re.split(r"\r\n|\r|\n", text):
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
            continue
        if key in fields:
            raise RuntimeError("settings_payload_duplicate_key|Το .msh περιέχει διπλό κρίσιμο πεδίο.")
        fields[key] = value
    for key in ("MeshName", "MeshType", "MeshID", "ServerID", "MeshServer", "agentName"):
        if not fields.get(key):
            raise RuntimeError("settings_payload_required_field_missing|Το .msh δεν περιέχει όλα τα απαιτούμενα πεδία.")
    return fields


def verify_secure_settings():
    """Fresh 3.3.0 enrollment -> one-time settings request/consume -> local verification.
    Raw ticket and raw .msh are never persisted or logged.
    """
    snapshot = read_policy()
    identity = load_identity()
    server = get_server_state()
    if identity is None:
        raise RuntimeError("not_paired|Απαιτείται ενεργή Managed identity πριν από τη λήψη ρυθμίσεων.")
    if not snapshot.get("allowed_local"):
        raise RuntimeError("local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει λήψη ρυθμίσεων αυτή τη στιγμή.")
    server_valid_until = _as_int(server.get("valid_until")) or 0
    if server.get("authorized_server") is not True or server_valid_until <= now_ts():
        raise RuntimeError("server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από τη λήψη ρυθμίσεων.")

    enrollment = verify_enrollment_authorization()
    if enrollment.get("client_version") != VERSION or enrollment.get("architecture") != ARCH:
        raise RuntimeError("enrollment_binding_invalid|Ο νέος enrollment έλεγχος δεν δέθηκε στη σωστή έκδοση/αρχιτεκτονική.")

    common = {
        "node_id": identity["node_id"],
        "node_secret": identity["node_secret"],
        "client_version": VERSION,
        "architecture": ARCH,
    }
    request_data = broker_post("/managed/settings/request", common)
    ticket = _safe_str(request_data.get("settings_ticket"), 80)
    source_hint = _safe_str(request_data.get("source_fingerprint_hint"), 20).lower()
    expected_sha = _safe_str(request_data.get("expected_sha256"), 80).lower()
    expected_bytes = _as_int(request_data.get("expected_bytes")) or 0
    agent_label = _safe_str(request_data.get("agent_label"), 40).upper()
    expires_at = parse_iso_epoch(request_data.get("expires_at"))
    request_server_until = parse_iso_epoch(request_data.get("server_valid_until"))
    request_ok = (
        request_data.get("success") is True
        and request_data.get("mode") == "managed_support"
        and request_data.get("phase") == "managed3_secure_settings_delivery"
        and request_data.get("settings_contract") == "smart-pro-managed-settings-v1"
        and request_data.get("settings_delivery_authorized") is True
        and request_data.get("settings_delivered") is False
        and request_data.get("server_authorization") == "allowed"
        and request_data.get("agent_delivery") is False
        and request_data.get("execution") is False
        and request_data.get("remote_access") is False
        and SETTINGS_TICKET_RE.fullmatch(ticket) is not None
        and FINGERPRINT_HINT_RE.fullmatch(source_hint) is not None
        and secrets.compare_digest(source_hint, enrollment.get("source_fingerprint_hint") or "")
        and SHA256_RE.fullmatch(expected_sha) is not None
        and 20 <= expected_bytes <= 262144
        and AGENT_LABEL_RE.fullmatch(agent_label) is not None
        and expires_at > now_ts()
        and request_server_until > now_ts()
        and expires_at <= request_server_until
    )
    if not request_ok:
        raise RuntimeError("settings_request_contract_invalid|Ο Broker επέστρεψε μη έγκυρο secure settings contract.")

    consume_payload = dict(common)
    consume_payload["settings_ticket"] = ticket
    consume_data = broker_post("/managed/settings/consume", consume_payload)
    settings = consume_data.get("settings") if isinstance(consume_data.get("settings"), dict) else {}
    consume_hint = _safe_str(consume_data.get("source_fingerprint_hint"), 20).lower()
    consumed_at = parse_iso_epoch(consume_data.get("consumed_at"))
    consume_server_until = parse_iso_epoch(consume_data.get("server_valid_until"))
    response_sha = _safe_str(settings.get("sha256"), 80).lower()
    response_bytes = _as_int(settings.get("bytes")) or 0
    response_label = _safe_str(settings.get("agent_label"), 40).upper()
    encoded = settings.get("data")
    consume_ok = (
        consume_data.get("success") is True
        and consume_data.get("mode") == "managed_support"
        and consume_data.get("phase") == "managed3_secure_settings_delivery"
        and consume_data.get("settings_contract") == "smart-pro-managed-settings-v1"
        and _safe_str(consume_data.get("installation_ref"), 100).upper() == identity["installation_id"]
        and consume_data.get("settings_delivery") is True
        and consume_data.get("server_authorization") == "allowed"
        and consume_data.get("agent_delivery") is False
        and consume_data.get("execution") is False
        and consume_data.get("remote_access") is False
        and FINGERPRINT_HINT_RE.fullmatch(consume_hint) is not None
        and secrets.compare_digest(source_hint, consume_hint)
        and settings.get("encoding") == "base64"
        and isinstance(encoded, str)
        and SHA256_RE.fullmatch(response_sha) is not None
        and secrets.compare_digest(expected_sha, response_sha)
        and response_bytes == expected_bytes
        and response_label == agent_label
        and consumed_at > 0
        and consume_server_until > now_ts()
    )
    if not consume_ok:
        raise RuntimeError("settings_consume_contract_invalid|Η κατανάλωση του secure settings ticket δεν επαληθεύτηκε.")

    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise RuntimeError("settings_base64_invalid|Ο Broker επέστρεψε μη έγκυρο base64 .msh payload.") from None
    actual_sha = hashlib.sha256(raw).hexdigest()
    if len(raw) != expected_bytes or not secrets.compare_digest(actual_sha, expected_sha):
        raise RuntimeError("settings_integrity_mismatch|Το .msh απέτυχε στον τοπικό έλεγχο ακεραιότητας.")
    fields = parse_msh_strict(raw)
    if not secrets.compare_digest(_safe_str(fields.get("agentName"), 40).upper(), agent_label):
        raise RuntimeError("settings_agent_label_mismatch|Το .msh δεν περιέχει το αναμενόμενο opaque Managed node label.")
    parsed = urlparse(_safe_str(fields.get("MeshServer"), 2048))
    if parsed.scheme.lower() != "wss" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("settings_meshserver_invalid|Το .msh δεν περιέχει έγκυρο ασφαλές WSS MeshServer endpoint.")

    state = {
        "verified": True,
        "verified_at": now_ts(),
        "consumed_at": consumed_at,
        "server_valid_until": consume_server_until,
        "source_fingerprint_hint": consume_hint,
        "sha256_hint": actual_sha[:12],
        "bytes": len(raw),
        "agent_label": agent_label,
        "mesh_server_host": parsed.hostname.lower(),
        "installation_id": identity["installation_id"],
        "node_id": identity["node_id"],
        "client_version": VERSION,
        "architecture": ARCH,
    }
    save_settings_state(state)
    print(
        f"[managed] secure settings verified for {identity['installation_id']} "
        f"source_hint={consume_hint} sha_hint={actual_sha[:12]} bytes={len(raw)}; raw settings not stored",
        flush=True,
    )
    return state



def load_agent_state():
    try:
        if not AGENT_STATE_FILE.exists():
            return {}
        if AGENT_STATE_FILE.stat().st_size <= 0 or AGENT_STATE_FILE.stat().st_size > 16384:
            return {}
        data = json.loads(AGENT_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    sha_hint = _safe_str(data.get("sha256_hint"), 20).lower()
    if sha_hint and not re.fullmatch(r"^[a-f0-9]{12}$", sha_hint):
        return {}
    architecture = _safe_str(data.get("architecture"), 20)
    if architecture and architecture not in ELF_MACHINE:
        return {}
    return {
        "verified": data.get("verified") is True,
        "verified_at": _as_int(data.get("verified_at")) or 0,
        "sha256_hint": sha_hint,
        "bytes": _as_int(data.get("bytes")) or 0,
        "architecture": architecture,
        "elf_class": _safe_str(data.get("elf_class"), 20),
        "endianness": _safe_str(data.get("endianness"), 20),
        "e_machine": _as_int(data.get("e_machine")) or 0,
        "installation_id": _safe_str(data.get("installation_id"), 100).upper(),
        "node_id": _safe_str(data.get("node_id"), 64).upper(),
        "client_version": _safe_str(data.get("client_version"), 30),
    }


def save_agent_state(state):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = AGENT_STATE_FILE.with_suffix(".tmp")
    payload = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, AGENT_STATE_FILE)
        os.chmod(AGENT_STATE_FILE, 0o600)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def sha256_file(path):
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_AGENT_BYTES:
                raise RuntimeError("agent_disk_size_invalid|Το προσωρινό MeshAgent αρχείο ξεπέρασε το μέγιστο επιτρεπόμενο μέγεθος.")
            digest.update(chunk)
    return digest.hexdigest(), total


def verify_elf64(path, architecture):
    expected_machine = ELF_MACHINE.get(architecture)
    if expected_machine is None:
        raise RuntimeError("agent_arch_unsupported|Η αρχιτεκτονική MeshAgent δεν υποστηρίζεται.")
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        with open(path, "rb") as handle:
            header = handle.read(64)
    except OSError as exc:
        raise RuntimeError("agent_temp_read_failed|Δεν ήταν δυνατός ο δεύτερος τοπικός έλεγχος του MeshAgent.") from exc
    if mode & 0o111:
        raise RuntimeError("agent_executable_bit_forbidden|Το verification-only MeshAgent αρχείο δεν πρέπει να είναι εκτελέσιμο.")
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise RuntimeError("agent_elf_invalid|Το MeshAgent δεν είναι έγκυρο ELF binary.")
    if header[4] != 2:
        raise RuntimeError("agent_elf_class_invalid|Το MeshAgent δεν είναι ELF64.")
    if header[5] != 1:
        raise RuntimeError("agent_elf_endian_invalid|Το MeshAgent δεν είναι little-endian ELF.")
    machine = int.from_bytes(header[18:20], "little")
    if machine != expected_machine:
        raise RuntimeError("agent_elf_machine_mismatch|Το MeshAgent ELF e_machine δεν συμφωνεί με την αρχιτεκτονική του add-on.")
    return machine


def verify_agent_binary():
    """Refresh 3.4.0 settings, receive one MeshAgent binary, verify twice, delete.

    The SPMA ticket is memory-only. The binary exists only as a 0600 /tmp file
    for the duration of the verification and is never chmod +x or executed.
    """
    snapshot = read_policy()
    identity = load_identity()
    server = get_server_state()
    if identity is None:
        raise RuntimeError("not_paired|Απαιτείται ενεργή Managed identity πριν από τον έλεγχο MeshAgent.")
    if not snapshot.get("allowed_local"):
        raise RuntimeError("local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει έλεγχο MeshAgent αυτή τη στιγμή.")
    server_valid_until = _as_int(server.get("valid_until")) or 0
    if server.get("authorized_server") is not True or server_valid_until <= now_ts():
        raise RuntimeError("server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από τον έλεγχο MeshAgent.")

    # The Broker requires a recent settings consume bound to THIS 3.4.0 client.
    settings = verify_secure_settings()
    if settings.get("client_version") != VERSION or settings.get("architecture") != ARCH:
        raise RuntimeError("agent_settings_binding_invalid|Ο νέος secure settings έλεγχος δεν δέθηκε στη σωστή έκδοση/αρχιτεκτονική.")

    common = {
        "node_id": identity["node_id"],
        "node_secret": identity["node_secret"],
        "client_version": VERSION,
        "architecture": ARCH,
    }
    request_data = broker_post("/managed/agent-binary/request", common)
    ticket = _safe_str(request_data.get("agent_ticket"), 80)
    expected_sha = _safe_str(request_data.get("expected_sha256"), 80).lower()
    expected_bytes = _as_int(request_data.get("expected_bytes")) or 0
    expires_at = parse_iso_epoch(request_data.get("expires_at"))
    request_server_until = _as_int(request_data.get("server_valid_until")) or parse_iso_epoch(request_data.get("server_valid_until"))

    request_ok = (
        request_data.get("success") is True
        and request_data.get("mode") == "managed_support"
        and request_data.get("phase") == "managed3_agent_binary_verification"
        and request_data.get("agent_contract") == "smart-pro-managed-agent-v1"
        and request_data.get("server_authorization") == "allowed"
        and request_data.get("agent_delivery_authorized") is True
        and request_data.get("agent_delivered") is False
        and request_data.get("verification_only") is True
        and request_data.get("execution") is False
        and request_data.get("remote_access") is False
        and request_data.get("meshcentral_runtime") is False
        and AGENT_TICKET_RE.fullmatch(ticket) is not None
        and SHA256_RE.fullmatch(expected_sha) is not None
        and MIN_AGENT_BYTES <= expected_bytes <= MAX_AGENT_BYTES
        and expires_at > now_ts()
        and request_server_until > now_ts()
        and expires_at <= request_server_until
    )
    if not request_ok:
        raise RuntimeError("agent_request_contract_invalid|Ο Broker επέστρεψε μη έγκυρο MeshAgent verification contract.")

    consume_payload = dict(common)
    consume_payload["agent_ticket"] = ticket
    temp_path = None
    try:
        result = broker_binary_post("/managed/agent-binary/consume", consume_payload, expected_bytes)
        temp_path = result.get("path")
        stream_sha = _safe_str(result.get("sha256"), 80).lower()
        header_sha = _safe_str(result.get("header_sha256"), 80).lower()
        if not temp_path or not Path(temp_path).is_file():
            raise RuntimeError("agent_temp_missing|Το προσωρινό MeshAgent αρχείο δεν δημιουργήθηκε σωστά.")
        if not secrets.compare_digest(stream_sha, expected_sha) or not secrets.compare_digest(header_sha, expected_sha):
            raise RuntimeError("agent_stream_integrity_mismatch|Το MeshAgent απέτυχε στον πρώτο SHA-256 έλεγχο.")

        machine = verify_elf64(temp_path, ARCH)
        disk_sha, disk_bytes = sha256_file(temp_path)
        if disk_bytes != expected_bytes or not secrets.compare_digest(disk_sha, expected_sha):
            raise RuntimeError("agent_disk_integrity_mismatch|Το MeshAgent απέτυχε στον δεύτερο έλεγχο ακεραιότητας από disk.")

        state = {
            "verified": True,
            "verified_at": now_ts(),
            "sha256_hint": disk_sha[:12],
            "bytes": disk_bytes,
            "architecture": ARCH,
            "elf_class": "ELF64",
            "endianness": "little-endian",
            "e_machine": machine,
            "installation_id": identity["installation_id"],
            "node_id": identity["node_id"],
            "client_version": VERSION,
        }
        save_agent_state(state)
        print(
            f"[managed] MeshAgent binary verified for {identity['installation_id']} "
            f"arch={ARCH} sha_hint={disk_sha[:12]} bytes={disk_bytes} e_machine={machine}; temp binary deleted, not executed",
            flush=True,
        )
        return state
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                pass


def load_runtime_state():
    try:
        if not RUNTIME_STATE_FILE.exists():
            return {}
        if RUNTIME_STATE_FILE.stat().st_size <= 0 or RUNTIME_STATE_FILE.stat().st_size > 16384:
            return {}
        data = json.loads(RUNTIME_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    status = _safe_str(data.get("status"), 40)
    if status not in {"not_run", "refreshing_chain", "lease_issued_waiting_renewal", "verified_renewed_once", "failed"}:
        status = "not_run"
    return {
        "status": status,
        "verified": data.get("verified") is True,
        "started_at": _as_int(data.get("started_at")) or 0,
        "requested_at": _as_int(data.get("requested_at")) or 0,
        "initial_expires_at": _as_int(data.get("initial_expires_at")) or 0,
        "renewed_at": _as_int(data.get("renewed_at")) or 0,
        "renewed_expires_at": _as_int(data.get("renewed_expires_at")) or 0,
        "server_valid_until": _as_int(data.get("server_valid_until")) or 0,
        "error_code": _safe_str(data.get("error_code"), 100),
        "error_message": _safe_str(data.get("error_message"), 300),
        "installation_id": _safe_str(data.get("installation_id"), 100).upper(),
        "node_id": _safe_str(data.get("node_id"), 64).upper(),
        "client_version": _safe_str(data.get("client_version"), 30),
        "architecture": _safe_str(data.get("architecture"), 20),
        "token_persisted": False,
        "execution": False,
        "meshcentral_runtime": False,
        "remote_access": False,
    }


def save_runtime_state(state):
    """Persist only non-secret dry-run metadata; raw runtime lease is forbidden."""
    safe = {
        "status": _safe_str(state.get("status"), 40),
        "verified": state.get("verified") is True,
        "started_at": _as_int(state.get("started_at")) or 0,
        "requested_at": _as_int(state.get("requested_at")) or 0,
        "initial_expires_at": _as_int(state.get("initial_expires_at")) or 0,
        "renewed_at": _as_int(state.get("renewed_at")) or 0,
        "renewed_expires_at": _as_int(state.get("renewed_expires_at")) or 0,
        "server_valid_until": _as_int(state.get("server_valid_until")) or 0,
        "error_code": _safe_str(state.get("error_code"), 100),
        "error_message": _safe_str(state.get("error_message"), 300),
        "installation_id": _safe_str(state.get("installation_id"), 100).upper(),
        "node_id": _safe_str(state.get("node_id"), 64).upper(),
        "client_version": _safe_str(state.get("client_version"), 30),
        "architecture": _safe_str(state.get("architecture"), 20),
        "token_persisted": False,
        "execution": False,
        "meshcentral_runtime": False,
        "remote_access": False,
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = RUNTIME_STATE_FILE.with_suffix(".tmp")
    payload = json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, RUNTIME_STATE_FILE)
        os.chmod(RUNTIME_STATE_FILE, 0o600)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _runtime_dry_run_failure(exc, identity=None, started_at=0):
    text = str(exc)
    code, sep, message = text.partition("|")
    if not sep:
        code = "runtime_dry_run_failed"
        message = "Ο έλεγχος runtime lease απέτυχε."
    state = {
        "status": "failed",
        "verified": False,
        "started_at": started_at or now_ts(),
        "error_code": _safe_str(code, 100),
        "error_message": _safe_str(message, 300),
        "installation_id": (identity or {}).get("installation_id", ""),
        "node_id": (identity or {}).get("node_id", ""),
        "client_version": VERSION,
        "architecture": ARCH,
    }
    save_runtime_state(state)
    print(f"[managed] runtime lease dry-run failed code={state['error_code']}; no lease token logged", flush=True)


def runtime_lease_dry_run_worker():
    """Refresh the full current Managed verification chain, issue one lease and renew it once.

    The raw SPMRL lease exists only in this worker's local memory. It is never
    persisted, rendered or logged. This dry-run never executes MeshAgent.
    """
    global RUNTIME_WORKER_ACTIVE
    started_at = now_ts()
    identity = load_identity()
    lease_token = ""
    try:
        if identity is None:
            raise RuntimeError("not_paired|Απαιτείται ενεργή Managed identity πριν από το runtime lease dry-run.")
        snapshot = read_policy()
        if not snapshot.get("allowed_local"):
            raise RuntimeError("local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει runtime lease αυτή τη στιγμή.")
        server = get_server_state()
        server_valid_until = _as_int(server.get("valid_until")) or 0
        if server.get("authorized_server") is not True or server_valid_until <= now_ts():
            raise RuntimeError("server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από το runtime lease.")

        save_runtime_state({
            "status": "refreshing_chain",
            "verified": False,
            "started_at": started_at,
            "installation_id": identity["installation_id"],
            "node_id": identity["node_id"],
            "client_version": VERSION,
            "architecture": ARCH,
        })

        # This refreshes enrollment + secure settings under the current Managed version, verifies the
        # MeshAgent twice, and deletes the temporary binary before any lease call.
        agent = verify_agent_binary()
        if agent.get("client_version") != VERSION or agent.get("architecture") != ARCH:
            raise RuntimeError("runtime_agent_binding_invalid|Η επαλήθευση MeshAgent δεν δέθηκε στη σωστή έκδοση/αρχιτεκτονική.")

        common = {
            "node_id": identity["node_id"],
            "node_secret": identity["node_secret"],
            "client_version": VERSION,
            "architecture": ARCH,
        }
        issued = broker_post("/managed/runtime-lease/request", common)
        lease_token = _safe_str(issued.get("runtime_lease"), 90)
        initial_expires = parse_iso_epoch(issued.get("expires_at"))
        request_server_until = _as_int(issued.get("server_valid_until")) or parse_iso_epoch(issued.get("server_valid_until"))
        request_ok = (
            issued.get("success") is True
            and issued.get("mode") == "managed_support"
            and issued.get("phase") == "managed3_runtime_lease_dry_run"
            and issued.get("runtime_contract") == "smart-pro-managed-runtime-lease-v1"
            and issued.get("runtime_authorized") is True
            and issued.get("lease_renewable") is True
            and issued.get("execution") is False
            and issued.get("meshcentral_runtime") is False
            and issued.get("remote_access") is False
            and issued.get("state") == "runtime_lease_active_execution_disabled"
            and RUNTIME_LEASE_RE.fullmatch(lease_token) is not None
            and initial_expires > now_ts()
            and request_server_until > now_ts()
            and initial_expires <= request_server_until
        )
        if not request_ok:
            raise RuntimeError("runtime_lease_request_contract_invalid|Ο Broker επέστρεψε μη έγκυρο runtime lease contract.")

        requested_at = now_ts()
        save_runtime_state({
            "status": "lease_issued_waiting_renewal",
            "verified": False,
            "started_at": started_at,
            "requested_at": requested_at,
            "initial_expires_at": initial_expires,
            "server_valid_until": request_server_until,
            "installation_id": identity["installation_id"],
            "node_id": identity["node_id"],
            "client_version": VERSION,
            "architecture": ARCH,
        })
        print(
            f"[managed] runtime lease issued for {identity['installation_id']}; "
            f"waiting {RUNTIME_RENEW_DELAY}s for one renewal; raw lease not persisted/logged",
            flush=True,
        )

        time.sleep(RUNTIME_RENEW_DELAY)

        # Local policy is checked again before the server renewal. The Broker
        # independently re-checks live Portal authorization during renew.
        if not read_policy().get("allowed_local"):
            raise RuntimeError("local_policy_denied|Η τοπική Managed πολιτική έπαψε να επιτρέπει runtime lease πριν από την ανανέωση.")

        renew_payload = dict(common)
        renew_payload["runtime_lease"] = lease_token
        renewed = broker_post("/managed/runtime-lease/renew", renew_payload)
        renewed_expires = parse_iso_epoch(renewed.get("expires_at"))
        renewed_server_until = _as_int(renewed.get("server_valid_until")) or parse_iso_epoch(renewed.get("server_valid_until"))
        renewed_at = now_ts()
        renew_ok = (
            renewed.get("success") is True
            and renewed.get("mode") == "managed_support"
            and renewed.get("phase") == "managed3_runtime_lease_dry_run"
            and renewed.get("runtime_contract") == "smart-pro-managed-runtime-lease-v1"
            and renewed.get("runtime_authorized") is True
            and renewed.get("lease_renewed") is True
            and renewed.get("execution") is False
            and renewed.get("meshcentral_runtime") is False
            and renewed.get("remote_access") is False
            and renewed.get("state") == "runtime_lease_renewed_execution_disabled"
            and renewed_expires > renewed_at
            and renewed_server_until > renewed_at
            and renewed_expires <= renewed_server_until
            and renewed_expires > initial_expires
        )
        if not renew_ok:
            raise RuntimeError("runtime_lease_renew_contract_invalid|Η ανανέωση του runtime lease δεν επαληθεύτηκε.")

        save_runtime_state({
            "status": "verified_renewed_once",
            "verified": True,
            "started_at": started_at,
            "requested_at": requested_at,
            "initial_expires_at": initial_expires,
            "renewed_at": renewed_at,
            "renewed_expires_at": renewed_expires,
            "server_valid_until": renewed_server_until,
            "installation_id": identity["installation_id"],
            "node_id": identity["node_id"],
            "client_version": VERSION,
            "architecture": ARCH,
        })
        print(
            f"[managed] runtime lease dry-run VERIFIED for {identity['installation_id']}; "
            "renewed once; execution=false meshcentral_runtime=false remote_access=false; raw lease discarded",
            flush=True,
        )
    except RuntimeError as exc:
        _runtime_dry_run_failure(exc, identity, started_at)
    finally:
        # Explicitly drop the only in-memory copy. The server-side lease is
        # intentionally allowed to expire on its own after this dry-run.
        lease_token = ""
        with RUNTIME_WORKER_LOCK:
            RUNTIME_WORKER_ACTIVE = False
CANARY_WORKER_LOCK = threading.Lock()
CANARY_WORKER_ACTIVE = False


def start_runtime_lease_dry_run():
    global RUNTIME_WORKER_ACTIVE
    with RUNTIME_WORKER_LOCK:
        if PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError("runtime_dry_run_persistent_active|Δεν εκτελείται runtime lease dry-run όσο είναι ενεργή η continuous Managed λειτουργία.")
        if RUNTIME_WORKER_ACTIVE:
            raise RuntimeError("runtime_dry_run_already_running|Υπάρχει ήδη runtime lease dry-run σε εξέλιξη.")
        RUNTIME_WORKER_ACTIVE = True
    thread = threading.Thread(target=runtime_lease_dry_run_worker, name="managed-runtime-lease-dry-run", daemon=True)
    thread.start()



def save_canary_state(state):
    """Persist non-secret canary metadata only. Raw tickets/settings/agent never enter /data."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    safe = {
        "status": _safe_str(state.get("status"), 40),
        "verified": state.get("verified") is True,
        "started_at": _as_int(state.get("started_at")) or 0,
        "ended_at": _as_int(state.get("ended_at")) or 0,
        "result_code": _safe_str(state.get("result_code"), 80),
        "elapsed_seconds": _as_int(state.get("elapsed_seconds")) or 0,
        "max_runtime_seconds": _as_int(state.get("max_runtime_seconds")) or 0,
        "agent_label": _safe_str(state.get("agent_label"), 40).upper(),
        "installation_id": _safe_str(state.get("installation_id"), 100).upper(),
        "node_id": _safe_str(state.get("node_id"), 64).upper(),
        "client_version": _safe_str(state.get("client_version"), 30),
        "architecture": _safe_str(state.get("architecture"), 20),
        "runtime_directory_deleted": state.get("runtime_directory_deleted") is True,
        "technician_actions_authorized": False,
        "identity_mode": _safe_str(state.get("identity_mode"), 20),
        "identity_db_persisted": state.get("identity_db_persisted") is True,
        "identity_binding_verified": state.get("identity_binding_verified") is True,
        "identity_db_sha256_hint": _safe_str(state.get("identity_db_sha256_hint"), 12).lower(),
        "identity_generation": max(0, _as_int(state.get("identity_generation")) or 0),
        "identity_continuity_runs": max(0, _as_int(state.get("identity_continuity_runs")) or 0),
        "identity_relative_path": _safe_str(state.get("identity_relative_path"), 200),
    }
    tmp = CANARY_STATE_FILE.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(safe, ensure_ascii=False, separators=(',', ':')))
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, CANARY_STATE_FILE)
        os.chmod(CANARY_STATE_FILE, 0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass


def load_canary_state():
    try:
        if not CANARY_STATE_FILE.exists() or CANARY_STATE_FILE.stat().st_size <= 0 or CANARY_STATE_FILE.stat().st_size > 16384:
            return {}
        data = json.loads(CANARY_STATE_FILE.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict): return {}
    status = _safe_str(data.get('status'), 40)
    if status not in {'not_run','preparing','running','reported','failed'}: status = 'not_run'
    return {
        'status': status,
        'verified': data.get('verified') is True,
        'started_at': _as_int(data.get('started_at')) or 0,
        'ended_at': _as_int(data.get('ended_at')) or 0,
        'result_code': _safe_str(data.get('result_code'), 80),
        'elapsed_seconds': _as_int(data.get('elapsed_seconds')) or 0,
        'max_runtime_seconds': _as_int(data.get('max_runtime_seconds')) or 0,
        'agent_label': _safe_str(data.get('agent_label'), 40).upper(),
        'installation_id': _safe_str(data.get('installation_id'), 100).upper(),
        'node_id': _safe_str(data.get('node_id'), 64).upper(),
        'client_version': _safe_str(data.get('client_version'), 30),
        'architecture': _safe_str(data.get('architecture'), 20),
        'runtime_directory_deleted': data.get('runtime_directory_deleted') is True,
        'technician_actions_authorized': False,
        'identity_mode': _safe_str(data.get('identity_mode'), 20),
        'identity_db_persisted': data.get('identity_db_persisted') is True,
        'identity_binding_verified': data.get('identity_binding_verified') is True,
        'identity_db_sha256_hint': _safe_str(data.get('identity_db_sha256_hint'), 12).lower(),
        'identity_generation': max(0, _as_int(data.get('identity_generation')) or 0),
        'identity_continuity_runs': max(0, _as_int(data.get('identity_continuity_runs')) or 0),
        'identity_relative_path': _safe_str(data.get('identity_relative_path'), 200),
    }


def _execution_settings_material(identity):
    """Fresh Managed 3.x enrollment + secure-settings consume, returning raw .msh only in memory."""
    enrollment = verify_enrollment_authorization()
    common = {'node_id': identity['node_id'], 'node_secret': identity['node_secret'], 'client_version': VERSION, 'architecture': ARCH}
    req = broker_post('/managed/settings/request', common)
    ticket = _safe_str(req.get('settings_ticket'), 80)
    source_hint = _safe_str(req.get('source_fingerprint_hint'), 20).lower()
    expected_sha = _safe_str(req.get('expected_sha256'), 80).lower()
    expected_bytes = _as_int(req.get('expected_bytes')) or 0
    agent_label = _safe_str(req.get('agent_label'), 40).upper()
    expires_at = parse_iso_epoch(req.get('expires_at'))
    server_until = parse_iso_epoch(req.get('server_valid_until'))
    ok = (
        req.get('success') is True and req.get('mode') == 'managed_support'
        and req.get('phase') == 'managed3_secure_settings_delivery'
        and req.get('settings_contract') == 'smart-pro-managed-settings-v1'
        and req.get('settings_delivery_authorized') is True and req.get('settings_delivered') is False
        and req.get('server_authorization') == 'allowed' and req.get('agent_delivery') is False
        and req.get('execution') is False and req.get('remote_access') is False
        and SETTINGS_TICKET_RE.fullmatch(ticket) is not None
        and FINGERPRINT_HINT_RE.fullmatch(source_hint) is not None
        and secrets.compare_digest(source_hint, enrollment.get('source_fingerprint_hint') or '')
        and SHA256_RE.fullmatch(expected_sha) is not None and 20 <= expected_bytes <= 262144
        and AGENT_LABEL_RE.fullmatch(agent_label) is not None
        and expires_at > now_ts() and server_until > now_ts() and expires_at <= server_until
    )
    if not ok: raise RuntimeError('canary_settings_request_invalid|Ο Broker επέστρεψε μη έγκυρο secure settings contract για το identity continuity canary.')
    payload = dict(common); payload['settings_ticket'] = ticket
    data = broker_post('/managed/settings/consume', payload)
    settings = data.get('settings') if isinstance(data.get('settings'), dict) else {}
    consume_hint = _safe_str(data.get('source_fingerprint_hint'),20).lower()
    response_sha = _safe_str(settings.get('sha256'),80).lower(); response_bytes = _as_int(settings.get('bytes')) or 0
    response_label = _safe_str(settings.get('agent_label'),40).upper(); encoded = settings.get('data')
    consume_server_until = parse_iso_epoch(data.get('server_valid_until')); consumed_at = parse_iso_epoch(data.get('consumed_at'))
    ok = (
        data.get('success') is True and data.get('phase') == 'managed3_secure_settings_delivery'
        and data.get('settings_contract') == 'smart-pro-managed-settings-v1'
        and _safe_str(data.get('installation_ref'),100).upper() == identity['installation_id']
        and data.get('settings_delivery') is True and data.get('server_authorization') == 'allowed'
        and data.get('agent_delivery') is False and data.get('execution') is False and data.get('remote_access') is False
        and FINGERPRINT_HINT_RE.fullmatch(consume_hint) is not None and secrets.compare_digest(source_hint, consume_hint)
        and settings.get('encoding') == 'base64' and isinstance(encoded,str)
        and SHA256_RE.fullmatch(response_sha) is not None and secrets.compare_digest(expected_sha,response_sha)
        and response_bytes == expected_bytes and response_label == agent_label and consumed_at > 0 and consume_server_until > now_ts()
    )
    if not ok: raise RuntimeError('canary_settings_consume_invalid|Η κατανάλωση secure settings για το identity continuity canary απέτυχε.')
    try: raw = base64.b64decode(encoded.encode('ascii'), validate=True)
    except (UnicodeEncodeError,binascii.Error,ValueError): raise RuntimeError('canary_settings_base64_invalid|Το runtime .msh payload δεν είναι έγκυρο base64.') from None
    sha = hashlib.sha256(raw).hexdigest()
    if len(raw) != expected_bytes or not secrets.compare_digest(sha,expected_sha):
        raise RuntimeError('canary_settings_integrity_mismatch|Το runtime .msh απέτυχε στον έλεγχο ακεραιότητας.')
    fields = parse_msh_strict(raw)
    if not secrets.compare_digest(_safe_str(fields.get('agentName'),40).upper(),agent_label):
        raise RuntimeError('canary_settings_agent_label_mismatch|Το runtime .msh δεν περιέχει το αναμενόμενο SPMNG label.')
    parsed = urlparse(_safe_str(fields.get('MeshServer'),2048))
    if parsed.scheme.lower() != 'wss' or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError('canary_settings_meshserver_invalid|Το runtime .msh δεν περιέχει ασφαλές WSS endpoint.')
    save_settings_state({'verified':True,'verified_at':now_ts(),'consumed_at':consumed_at,'server_valid_until':consume_server_until,
        'source_fingerprint_hint':consume_hint,'sha256_hint':sha[:12],'bytes':len(raw),'agent_label':agent_label,
        'mesh_server_host':parsed.hostname.lower(),'installation_id':identity['installation_id'],'node_id':identity['node_id'],
        'client_version':VERSION,'architecture':ARCH})
    return {'raw':raw,'fields':fields,'agent_label':agent_label,'sha256':sha,'bytes':len(raw)}


def _execution_agent_material(identity, settings_material):
    """Consume one Managed 3.x agent ticket and keep the verified 0600 temp binary until canary cleanup."""
    common = {'node_id': identity['node_id'], 'node_secret': identity['node_secret'], 'client_version': VERSION, 'architecture': ARCH}
    req = broker_post('/managed/agent-binary/request', common)
    ticket = _safe_str(req.get('agent_ticket'),80); expected_sha = _safe_str(req.get('expected_sha256'),80).lower()
    expected_bytes = _as_int(req.get('expected_bytes')) or 0; expires_at = parse_iso_epoch(req.get('expires_at'))
    server_until = _as_int(req.get('server_valid_until')) or parse_iso_epoch(req.get('server_valid_until'))
    ok = (
        req.get('success') is True and req.get('phase') == 'managed3_agent_binary_verification'
        and req.get('agent_contract') == 'smart-pro-managed-agent-v1' and req.get('server_authorization') == 'allowed'
        and req.get('agent_delivery_authorized') is True and req.get('agent_delivered') is False
        and req.get('verification_only') is True and req.get('execution') is False and req.get('remote_access') is False
        and req.get('meshcentral_runtime') is False and AGENT_TICKET_RE.fullmatch(ticket) is not None
        and SHA256_RE.fullmatch(expected_sha) is not None and MIN_AGENT_BYTES <= expected_bytes <= MAX_AGENT_BYTES
        and expires_at > now_ts() and server_until > now_ts() and expires_at <= server_until
    )
    if not ok: raise RuntimeError('canary_agent_request_invalid|Ο Broker επέστρεψε μη έγκυρο MeshAgent contract για το identity continuity canary.')
    payload = dict(common); payload['agent_ticket'] = ticket
    result = broker_binary_post('/managed/agent-binary/consume', payload, expected_bytes)
    path = result.get('path')
    try:
        if not path or not Path(path).is_file(): raise RuntimeError('canary_agent_temp_missing|Δεν δημιουργήθηκε προσωρινό verified MeshAgent binary.')
        stream_sha = _safe_str(result.get('sha256'),80).lower(); header_sha = _safe_str(result.get('header_sha256'),80).lower()
        if not secrets.compare_digest(stream_sha,expected_sha) or not secrets.compare_digest(header_sha,expected_sha):
            raise RuntimeError('canary_agent_stream_integrity|Το MeshAgent απέτυχε στον πρώτο SHA-256 έλεγχο.')
        machine = verify_elf64(path,ARCH); disk_sha,disk_bytes = sha256_file(path)
        if disk_bytes != expected_bytes or not secrets.compare_digest(disk_sha,expected_sha):
            raise RuntimeError('canary_agent_disk_integrity|Το MeshAgent απέτυχε στον δεύτερο disk verification.')
        state={'verified':True,'verified_at':now_ts(),'sha256_hint':disk_sha[:12],'bytes':disk_bytes,'architecture':ARCH,
               'elf_class':'ELF64','endianness':'little-endian','e_machine':machine,'installation_id':identity['installation_id'],
               'node_id':identity['node_id'],'client_version':VERSION}
        save_agent_state(state)
        return {'path':path,'sha256':disk_sha,'bytes':disk_bytes,'e_machine':machine}
    except Exception:
        try:
            if path: Path(path).unlink(missing_ok=True)
        except OSError: pass
        raise


def _harden_runtime_msh(raw, expected_label):
    """Apply only the already-proven no-update hardening to an ephemeral runtime copy."""
    try: text = raw.decode('utf-8')
    except UnicodeDecodeError: raise RuntimeError('canary_msh_encoding_invalid|Το runtime .msh δεν είναι έγκυρο UTF-8.') from None
    original = parse_msh_strict(raw)
    critical = {k: original.get(k) for k in ('MeshName','MeshType','MeshID','ServerID','MeshServer','agentName')}
    drop = {'forceUpdate','fakeUpdate','coreDumpEnabled','disableUpdate','noUpdateCoreModule','skipmaccheck'}
    lines=[]
    for line in text.splitlines():
        key = line.split('=',1)[0].strip() if '=' in line else ''
        if key in drop: continue
        lines.append(line)
    lines += ['disableUpdate=1','noUpdateCoreModule=1','skipmaccheck=1']
    hardened = ('\n'.join(lines).rstrip('\n')+'\n').encode('utf-8')
    parsed = parse_msh_strict(hardened)
    for key,value in critical.items():
        if parsed.get(key) != value: raise RuntimeError('canary_msh_hardening_binding|Το hardening άλλαξε κρίσιμο MeshCentral πεδίο.')
    if _safe_str(parsed.get('agentName'),40).upper() != expected_label:
        raise RuntimeError('canary_msh_hardening_label|Το hardening άλλαξε το SPMNG node label.')
    return hardened


def _terminate_process_group(proc):
    if proc is None or proc.poll() is not None: return
    try: os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try: proc.terminate()
        except OSError: pass
    try: proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try: proc.kill()
            except OSError: pass
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: pass


def _terminate_process_group_before(proc, hard_stop_monotonic):
    """Stop the canary process group before the absolute process-lifetime boundary."""
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try: proc.terminate()
        except OSError: pass
    remaining=max(0.0, hard_stop_monotonic-time.monotonic())
    if remaining>0:
        try:
            proc.wait(timeout=remaining)
            return
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try: proc.kill()
            except OSError: pass
        try: proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired: pass



def _mesh_identity_binding_hash(identity, settings_material):
    fields = settings_material.get('fields') if isinstance(settings_material, dict) else None
    if not isinstance(fields, dict):
        raise RuntimeError('mesh_identity_settings_missing|Λείπουν τα verified MeshCentral settings για τον έλεγχο σταθερής ταυτότητας.')
    payload = {
        'installation_id': _safe_str(identity.get('installation_id'), 100).upper(),
        'broker_node_id': _safe_str(identity.get('node_id'), 64).upper(),
        'architecture': ARCH,
    }
    for key in MESH_IDENTITY_BINDING_KEYS:
        payload[key] = _safe_str(fields.get(key), 2048)
    label = _safe_str(payload.get('agentName'), 40).upper()
    if not AGENT_LABEL_RE.fullmatch(label):
        raise RuntimeError('mesh_identity_label_invalid|Το verified .msh δεν περιέχει έγκυρο Managed node label για identity continuity.')
    payload['agentName'] = label
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _open_regular_nofollow(path, max_bytes):
    path = Path(path)
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        raise RuntimeError('mesh_identity_db_missing|Δεν βρέθηκε το αποθηκευμένο MeshAgent identity database.') from None
    except OSError as exc:
        raise RuntimeError('mesh_identity_db_unreadable|Δεν ήταν δυνατός ο έλεγχος του MeshAgent identity database.') from exc
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise RuntimeError('mesh_identity_db_type_invalid|Το MeshAgent identity database δεν είναι κανονικό αρχείο.')
    if lst.st_size <= 0 or lst.st_size > max_bytes:
        raise RuntimeError('mesh_identity_db_size_invalid|Το MeshAgent identity database έχει μη αποδεκτό μέγεθος.')
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError('mesh_identity_db_open_failed|Δεν ήταν δυνατό να ανοιχτεί με ασφάλεια το MeshAgent identity database.') from exc
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_ino != lst.st_ino or fst.st_dev != lst.st_dev:
            raise RuntimeError('mesh_identity_db_race_detected|Το MeshAgent identity database άλλαξε κατά τον ασφαλή έλεγχο.')
        if stat.S_IMODE(fst.st_mode) & 0o077:
            raise RuntimeError('mesh_identity_db_permissions_invalid|Τα δικαιώματα του MeshAgent identity database δεν είναι αρκετά αυστηρά.')
        return fd, fst.st_size
    except Exception:
        os.close(fd)
        raise


def _sha256_fd(fd, max_bytes):
    digest = hashlib.sha256(); total = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk: break
        total += len(chunk)
        if total > max_bytes:
            raise RuntimeError('mesh_identity_db_size_invalid|Το MeshAgent identity database ξεπέρασε το μέγιστο επιτρεπόμενο μέγεθος.')
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest(), total


def _secure_identity_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if MESH_IDENTITY_DIR.exists() or MESH_IDENTITY_DIR.is_symlink():
            lst = os.lstat(MESH_IDENTITY_DIR)
            if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
                raise RuntimeError('mesh_identity_dir_invalid|Ο χώρος αποθήκευσης MeshAgent identity δεν είναι ασφαλής κατάλογος.')
        else:
            MESH_IDENTITY_DIR.mkdir(mode=0o700)
        os.chmod(MESH_IDENTITY_DIR, 0o700)
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError('mesh_identity_dir_unavailable|Δεν ήταν δυνατή η ασφαλής προετοιμασία του χώρου MeshAgent identity.') from exc


def _read_mesh_identity_meta():
    if not MESH_IDENTITY_META_FILE.exists():
        return None
    try:
        lst = os.lstat(MESH_IDENTITY_META_FILE)
        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode) or lst.st_size <= 0 or lst.st_size > 16384:
            raise RuntimeError('mesh_identity_meta_invalid|Το metadata της σταθερής MeshAgent ταυτότητας δεν είναι έγκυρο.')
        if stat.S_IMODE(lst.st_mode) & 0o077:
            raise RuntimeError('mesh_identity_meta_permissions_invalid|Τα δικαιώματα του identity metadata δεν είναι αρκετά αυστηρά.')
        data = json.loads(MESH_IDENTITY_META_FILE.read_text(encoding='utf-8'))
    except RuntimeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('mesh_identity_meta_unreadable|Δεν ήταν δυνατή η ασφαλής ανάγνωση του MeshAgent identity metadata.') from exc
    if not isinstance(data, dict):
        raise RuntimeError('mesh_identity_meta_invalid|Το MeshAgent identity metadata δεν έχει έγκυρη μορφή.')
    return data


def _validate_persisted_mesh_identity(identity, settings_material=None):
    db_exists = MESH_IDENTITY_DB_FILE.exists() or MESH_IDENTITY_DB_FILE.is_symlink()
    meta_exists = MESH_IDENTITY_META_FILE.exists() or MESH_IDENTITY_META_FILE.is_symlink()
    if not db_exists and not meta_exists:
        return {'state':'not_seeded','generation':0}
    if db_exists != meta_exists:
        raise RuntimeError('mesh_identity_partial_state|Η σταθερή MeshAgent ταυτότητα είναι ελλιπής. Η εκτέλεση μπλοκαρίστηκε για να μη δημιουργηθεί duplicate node.')
    meta = _read_mesh_identity_meta()
    installation_id = _safe_str(meta.get('installation_id'),100).upper()
    node_id = _safe_str(meta.get('broker_node_id'),64).upper()
    architecture = _safe_str(meta.get('architecture'),20)
    agent_label = _safe_str(meta.get('agent_label'),40).upper()
    db_sha = _safe_str(meta.get('db_sha256'),80).lower()
    binding_sha = _safe_str(meta.get('binding_sha256'),80).lower()
    relative_path = _safe_str(meta.get('runtime_relative_path'),200)
    generation = max(1,_as_int(meta.get('generation')) or 1)
    continuity_runs = max(0,_as_int(meta.get('continuity_runs')) or 0)
    if installation_id != identity['installation_id'] or node_id != identity['node_id'] or architecture != ARCH:
        raise RuntimeError('mesh_identity_owner_mismatch|Η αποθηκευμένη MeshAgent ταυτότητα ανήκει σε διαφορετική εγκατάσταση/Managed identity. Η εκτέλεση μπλοκαρίστηκε.')
    if not AGENT_LABEL_RE.fullmatch(agent_label) or not SHA256_RE.fullmatch(db_sha) or not SHA256_RE.fullmatch(binding_sha):
        raise RuntimeError('mesh_identity_meta_binding_invalid|Το MeshAgent identity metadata δεν περιέχει έγκυρα bindings.')
    rel = Path(relative_path)
    if not relative_path or rel.is_absolute() or '..' in rel.parts or rel.name != 'meshagent.db':
        raise RuntimeError('mesh_identity_runtime_path_invalid|Η αποθηκευμένη θέση του MeshAgent identity database δεν είναι έγκυρη.')
    fd,size = _open_regular_nofollow(MESH_IDENTITY_DB_FILE,MAX_MESH_IDENTITY_DB_BYTES)
    try:
        actual_sha,actual_size = _sha256_fd(fd,MAX_MESH_IDENTITY_DB_BYTES)
    finally:
        os.close(fd)
    if actual_size != (_as_int(meta.get('db_bytes')) or 0) or not secrets.compare_digest(actual_sha,db_sha):
        raise RuntimeError('mesh_identity_db_integrity_mismatch|Το αποθηκευμένο MeshAgent identity database απέτυχε στον έλεγχο ακεραιότητας. Η εκτέλεση μπλοκαρίστηκε.')
    if settings_material is not None:
        current_binding = _mesh_identity_binding_hash(identity,settings_material)
        current_label = _safe_str(settings_material.get('agent_label'),40).upper()
        if not secrets.compare_digest(current_binding,binding_sha) or not secrets.compare_digest(current_label,agent_label):
            raise RuntimeError('mesh_identity_msh_binding_mismatch|Τα νέα verified MeshCentral settings δεν ταιριάζουν με την αποθηκευμένη σταθερή ταυτότητα. Η εκτέλεση μπλοκαρίστηκε για αποφυγή duplicate node.')
    return {'state':'ready','generation':generation,'agent_label':agent_label,'db_sha256':actual_sha,'db_bytes':actual_size,
            'binding_sha256':binding_sha,'runtime_relative_path':relative_path,'seeded_at':_as_int(meta.get('seeded_at')) or 0,
            'updated_at':_as_int(meta.get('updated_at')) or 0,'continuity_runs':continuity_runs}


def _copy_persisted_identity_into_runtime(runtime_dir, identity, settings_material):
    state = _validate_persisted_mesh_identity(identity,settings_material)
    if state.get('state') == 'not_seeded':
        return {'mode':'seed','generation':0,'continuity_runs':0,'runtime_relative_path':''}
    rel = Path(state['runtime_relative_path'])
    target = Path(runtime_dir) / rel
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(target.parent,0o700)
    fd,size = _open_regular_nofollow(MESH_IDENTITY_DB_FILE,MAX_MESH_IDENTITY_DB_BYTES)
    tmp = target.with_name(target.name + '.identity-copy.tmp')
    try:
        outfd = os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            total=0; digest=hashlib.sha256()
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                total += len(chunk)
                if total > MAX_MESH_IDENTITY_DB_BYTES:
                    raise RuntimeError('mesh_identity_db_size_invalid|Το MeshAgent identity database ξεπέρασε το επιτρεπόμενο μέγεθος κατά το runtime copy.')
                view=memoryview(chunk)
                while view:
                    written=os.write(outfd,view)
                    if written <= 0:
                        raise RuntimeError('mesh_identity_runtime_copy_write_failed|Απέτυχε η ασφαλής εγγραφή του runtime MeshAgent identity database.')
                    view=view[written:]
                digest.update(chunk)
            os.fsync(outfd)
        finally:
            os.close(outfd)
        if total != size or not secrets.compare_digest(digest.hexdigest(),state['db_sha256']):
            raise RuntimeError('mesh_identity_runtime_copy_mismatch|Το runtime αντίγραφο του MeshAgent identity database απέτυχε στον έλεγχο ακεραιότητας.')
        os.replace(tmp,target); os.chmod(target,0o600)
    finally:
        os.close(fd)
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass
    return {'mode':'reuse','generation':state['generation'],'continuity_runs':state.get('continuity_runs',0),'runtime_relative_path':str(rel),'db_sha256':state['db_sha256']}


def _find_runtime_mesh_identity_db(runtime_dir):
    root = Path(runtime_dir).resolve()
    found=[]
    try:
        for path in Path(runtime_dir).rglob('meshagent.db'):
            try:
                resolved=path.resolve()
                if root not in resolved.parents and resolved != root:
                    continue
                lst=os.lstat(path)
                if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
                    continue
                if 0 < lst.st_size <= MAX_MESH_IDENTITY_DB_BYTES:
                    found.append(path)
            except OSError:
                continue
    except OSError as exc:
        raise RuntimeError('mesh_identity_runtime_scan_failed|Δεν ήταν δυνατός ο έλεγχος του runtime MeshAgent identity database.') from exc
    if len(found) != 1:
        code='mesh_identity_runtime_db_missing' if not found else 'mesh_identity_runtime_db_ambiguous'
        message='Δεν δημιουργήθηκε MeshAgent identity database στο ιδιωτικό runtime.' if not found else 'Βρέθηκαν πολλαπλά MeshAgent identity databases και η συνέχεια ταυτότητας μπλοκαρίστηκε.'
        raise RuntimeError(f'{code}|{message}')
    rel=found[0].resolve().relative_to(root)
    return found[0],str(rel)


def _persist_runtime_mesh_identity(runtime_dir, identity, settings_material, prior):
    db_path,relative_path=_find_runtime_mesh_identity_db(runtime_dir)
    fd,size=_open_regular_nofollow(db_path,MAX_MESH_IDENTITY_DB_BYTES)
    try:
        db_sha,db_bytes=_sha256_fd(fd,MAX_MESH_IDENTITY_DB_BYTES)
        _secure_identity_dir()
        tmp_db=MESH_IDENTITY_DIR / ('.meshagent.db.' + secrets.token_hex(6) + '.tmp')
        outfd=os.open(tmp_db,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            total=0
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                total += len(chunk)
                view=memoryview(chunk)
                while view:
                    written=os.write(outfd,view)
                    if written <= 0:
                        raise RuntimeError('mesh_identity_persist_write_failed|Απέτυχε η ασφαλής αποθήκευση του MeshAgent identity database.')
                    view=view[written:]
            os.fsync(outfd)
        finally:
            os.close(outfd)
        if total != db_bytes:
            raise RuntimeError('mesh_identity_persist_copy_short|Δεν αντιγράφηκε ολόκληρο το MeshAgent identity database.')
        os.replace(tmp_db,MESH_IDENTITY_DB_FILE); os.chmod(MESH_IDENTITY_DB_FILE,0o600)
    finally:
        os.close(fd)
        try:
            if 'tmp_db' in locals() and tmp_db.exists(): tmp_db.unlink()
        except OSError: pass
    previous_meta=None
    try: previous_meta=_read_mesh_identity_meta()
    except RuntimeError: previous_meta=None
    seeded_at=(_as_int((previous_meta or {}).get('seeded_at')) or now_ts())
    generation=max(1,_as_int((previous_meta or {}).get('generation')) or _as_int((prior or {}).get('generation')) or 1)
    continuity_runs=max(0,_as_int((previous_meta or {}).get('continuity_runs')) or _as_int((prior or {}).get('continuity_runs')) or 0)+1
    binding_sha=_mesh_identity_binding_hash(identity,settings_material)
    meta={
        'schema_version':1,'installation_id':identity['installation_id'],'broker_node_id':identity['node_id'],'architecture':ARCH,
        'agent_label':_safe_str(settings_material.get('agent_label'),40).upper(),'binding_sha256':binding_sha,
        'db_sha256':db_sha,'db_bytes':db_bytes,'runtime_relative_path':relative_path,'seeded_at':seeded_at,'updated_at':now_ts(),
        'generation':generation,'continuity_runs':continuity_runs,'service_persistence':False,'technician_actions_authorized':False,
    }
    tmp_meta=MESH_IDENTITY_DIR / ('.identity-meta.' + secrets.token_hex(6) + '.tmp')
    fd_meta=os.open(tmp_meta,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd_meta,'w',encoding='utf-8') as handle:
            handle.write(json.dumps(meta,ensure_ascii=False,separators=(',',':'))); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp_meta,MESH_IDENTITY_META_FILE); os.chmod(MESH_IDENTITY_META_FILE,0o600)
        try:
            dirfd=os.open(MESH_IDENTITY_DIR,os.O_RDONLY)
            try: os.fsync(dirfd)
            finally: os.close(dirfd)
        except OSError: pass
    finally:
        try:
            if tmp_meta.exists(): tmp_meta.unlink()
        except OSError: pass
    check=_validate_persisted_mesh_identity(identity,settings_material)
    return {'generation':check['generation'],'continuity_runs':check.get('continuity_runs',0),'db_sha256':check['db_sha256'],'runtime_relative_path':check['runtime_relative_path'],'seeded_at':check['seeded_at']}


def get_mesh_identity_status(identity):
    if identity is None:
        return {'state':'unpaired','label':'Απαιτείται Managed pairing'}
    try:
        state=_validate_persisted_mesh_identity(identity,None)
        if state.get('state') == 'not_seeded':
            return {'state':'not_seeded','label':'Δεν έχει αποθηκευτεί ακόμη σταθερή MeshCentral ταυτότητα','generation':0}
        return {'state':'ready','label':'READY — υπάρχει αποθηκευμένη σταθερή MeshCentral ταυτότητα','generation':state.get('generation',0),
                'agent_label':state.get('agent_label',''),'db_sha256_hint':state.get('db_sha256','')[:12],
                'updated_at':state.get('updated_at',0),'runtime_relative_path':state.get('runtime_relative_path',''),'continuity_runs':state.get('continuity_runs',0)}
    except RuntimeError as exc:
        code,_,message=str(exc).partition('|')
        return {'state':'blocked','label':'BLOCKED — '+(message or code),'generation':0}


def _report_canary(identity, report_token, result_code, elapsed):
    try:
        data = broker_post('/managed/execution-canary/report', {
            'report_token': report_token, 'node_id': identity['node_id'], 'node_secret': identity['node_secret'],
            'result_code': result_code, 'elapsed_seconds': max(0,min(60,int(elapsed)))})
        return data.get('success') is True and data.get('reported') is True
    except RuntimeError:
        return False


def connectivity_canary_worker():
    global CANARY_WORKER_ACTIVE
    identity = load_identity(); runtime_dir=None; agent_temp=None; proc=None; report_token=''; result='launch_failed'; started=now_ts()
    max_runtime=0; agent_label=''; cleanup_ok=True; identity_mode=''; identity_db_persisted=False; identity_binding_verified=False
    identity_db_sha256_hint=''; identity_generation=0; identity_continuity_runs=0; identity_relative_path=''; settings=None; prior_identity={}
    try:
        if identity is None: raise RuntimeError('not_paired|Απαιτείται ενεργή Managed identity πριν από το identity continuity canary.')
        if not read_policy().get('allowed_local'): raise RuntimeError('local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει identity continuity canary.')
        server=get_server_state(); server_until=_as_int(server.get('valid_until')) or 0
        if server.get('authorized_server') is not True or server_until <= now_ts():
            raise RuntimeError('server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από το identity continuity canary.')
        save_canary_state({'status':'preparing','verified':False,'started_at':started,'installation_id':identity['installation_id'],
            'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH})

        settings = _execution_settings_material(identity); agent_label=settings['agent_label']
        prior_identity=_validate_persisted_mesh_identity(identity,settings)
        identity_mode='seed' if prior_identity.get('state') == 'not_seeded' else 'reuse'
        identity_binding_verified=prior_identity.get('state') == 'ready'
        identity_generation=max(0,_as_int(prior_identity.get('generation')) or 0)
        identity_continuity_runs=max(0,_as_int(prior_identity.get('continuity_runs')) or 0)
        identity_relative_path=_safe_str(prior_identity.get('runtime_relative_path'),200)
        agent = _execution_agent_material(identity, settings); agent_temp=agent['path']
        common={'node_id':identity['node_id'],'node_secret':identity['node_secret'],'client_version':VERSION,'architecture':ARCH}
        lease=broker_post('/managed/runtime-lease/request', common); lease_token=_safe_str(lease.get('runtime_lease'),90)
        lease_exp=parse_iso_epoch(lease.get('expires_at'))
        if not (lease.get('success') is True and lease.get('runtime_contract')=='smart-pro-managed-runtime-lease-v1'
                and lease.get('runtime_authorized') is True and lease.get('execution') is False and RUNTIME_LEASE_RE.fullmatch(lease_token)
                and lease_exp>now_ts()):
            raise RuntimeError('canary_runtime_lease_invalid|Δεν εκδόθηκε έγκυρο runtime lease για το identity continuity canary.')
        can_req=dict(common); can_req['runtime_lease']=lease_token
        auth=broker_post('/managed/execution-canary/request', can_req)
        canary_ticket=_safe_str(auth.get('canary_ticket'),90); report_token=_safe_str(auth.get('report_token'),90)
        max_runtime=min(CANARY_LOCAL_MAX_RUNTIME,_as_int(auth.get('max_runtime_seconds')) or 0)
        if not (auth.get('success') is True and auth.get('canary_contract')=='smart-pro-managed-execution-canary-v1'
                and auth.get('state')=='canary_ticket_issued_runtime_not_started' and auth.get('foreground_only') is True
                and auth.get('install') is False and auth.get('service_persistence') is False
                and auth.get('technician_actions_authorized') is False and CANARY_TICKET_RE.fullmatch(canary_ticket)
                and CANARY_REPORT_RE.fullmatch(report_token) and 1 <= max_runtime <= CANARY_LOCAL_MAX_RUNTIME):
            raise RuntimeError('canary_authorization_invalid|Ο Broker δεν επέστρεψε έγκυρη identity-continuity canary authorization.')
        consume=dict(common); consume['canary_ticket']=canary_ticket
        run=broker_post('/managed/execution-canary/consume',consume)
        hard_deadline=parse_iso_epoch(run.get('hard_deadline')); watch_interval=_as_int(run.get('watch_interval_seconds')) or CANARY_POLL_FALLBACK
        if not (run.get('success') is True and run.get('canary_contract')=='smart-pro-managed-execution-canary-v1'
                and run.get('state')=='canary_execution_authorized_connectivity_only' and run.get('foreground_only') is True
                and run.get('install') is False and run.get('service_persistence') is False
                and run.get('meshcentral_connectivity_canary') is True and run.get('technician_actions_authorized') is False
                and 1 <= (_as_int(run.get('max_runtime_seconds')) or 0) <= CANARY_LOCAL_MAX_RUNTIME and hard_deadline>now_ts()):
            raise RuntimeError('canary_consume_invalid|Η identity-continuity canary authorization δεν καταναλώθηκε σωστά.')
        max_runtime=min(max_runtime,_as_int(run.get('max_runtime_seconds')) or max_runtime)

        runtime_dir=Path(tempfile.mkdtemp(prefix='smart-pro-managed-identity-canary-',dir='/tmp')); os.chmod(runtime_dir,0o700)
        agent_path=runtime_dir/'meshagent'; shutil.move(agent_temp,agent_path); agent_temp=None; os.chmod(agent_path,0o700)
        msh_path=runtime_dir/'meshagent.msh'; hardened=_harden_runtime_msh(settings['raw'],agent_label)
        fd=os.open(msh_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as h: h.write(hardened); h.flush(); os.fsync(h.fileno())
        private=runtime_dir/'private'; private.mkdir(mode=0o700)
        prepared=_copy_persisted_identity_into_runtime(runtime_dir,identity,settings)
        identity_mode=prepared.get('mode') or identity_mode
        identity_generation=max(identity_generation,_as_int(prepared.get('generation')) or 0)
        identity_continuity_runs=max(identity_continuity_runs,_as_int(prepared.get('continuity_runs')) or 0)
        identity_relative_path=_safe_str(prepared.get('runtime_relative_path'),200)
        identity_binding_verified=identity_mode == 'reuse'
        env=os.environ.copy(); env.update({'HOME':str(private),'TMPDIR':str(private),'XDG_CONFIG_HOME':str(private),'XDG_CACHE_HOME':str(private)})
        process_started_at=now_ts()
        save_canary_state({'status':'running','verified':False,'started_at':process_started_at,'max_runtime_seconds':max_runtime,'agent_label':agent_label,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'identity_mode':identity_mode,'identity_db_persisted':False,'identity_binding_verified':identity_binding_verified,
            'identity_generation':identity_generation,'identity_continuity_runs':identity_continuity_runs,'identity_relative_path':identity_relative_path})
        proc=subprocess.Popen(['setsid','./meshagent'],cwd=str(runtime_dir),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              env=env,close_fds=True)
        run_started=time.monotonic(); result='runtime_limit'
        broker_remaining=max(0,hard_deadline-now_ts())
        hard_stop_monotonic=run_started+min(max_runtime,broker_remaining)
        graceful_stop_monotonic=max(run_started,hard_stop_monotonic-CANARY_SHUTDOWN_GRACE)
        while True:
            elapsed=int(time.monotonic()-run_started)
            if proc.poll() is not None:
                result='agent_exit'; break
            if time.monotonic() >= graceful_stop_monotonic or now_ts() >= max(0,hard_deadline-CANARY_SHUTDOWN_GRACE):
                result='runtime_limit'; break
            if not read_policy().get('allowed_local'):
                result='runtime_lease_lost'; break
            watch=broker_post('/managed/execution-canary/watch',{'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
            if watch.get('continue') is not True:
                reason=_safe_str(watch.get('reason'),80)
                result='runtime_limit' if reason=='canary_runtime_limit' else 'runtime_lease_lost'
                break
            remaining=max(0.0,graceful_stop_monotonic-time.monotonic())
            if remaining<=0:
                result='runtime_limit'; break
            time.sleep(min(max(1,min(10,watch_interval)),remaining))
        _terminate_process_group_before(proc,hard_stop_monotonic)
        elapsed=int(time.monotonic()-run_started)
        persisted=_persist_runtime_mesh_identity(runtime_dir,identity,settings,prior_identity)
        identity_db_persisted=True; identity_binding_verified=True
        identity_db_sha256_hint=_safe_str(persisted.get('db_sha256'),80)[:12]
        identity_generation=max(1,_as_int(persisted.get('generation')) or 1)
        identity_continuity_runs=max(1,_as_int(persisted.get('continuity_runs')) or 1)
        identity_relative_path=_safe_str(persisted.get('runtime_relative_path'),200)
        report_ok=_report_canary(identity,report_token,result,elapsed)
        save_canary_state({'status':'reported' if report_ok else 'failed','verified':report_ok,'started_at':process_started_at,'ended_at':now_ts(),
            'result_code':result,'elapsed_seconds':elapsed,'max_runtime_seconds':max_runtime,'agent_label':agent_label,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'runtime_directory_deleted':False,'identity_mode':identity_mode,'identity_db_persisted':identity_db_persisted,
            'identity_binding_verified':identity_binding_verified,'identity_db_sha256_hint':identity_db_sha256_hint,
            'identity_generation':identity_generation,'identity_continuity_runs':identity_continuity_runs,'identity_relative_path':identity_relative_path})
        print(f"[managed] identity continuity canary mode={identity_mode} generation={identity_generation} continuity_runs={identity_continuity_runs} persisted=true db_hint={identity_db_sha256_hint}; technician_actions=false",flush=True)
    except (RuntimeError,OSError,subprocess.SubprocessError) as exc:
        if proc is not None: _terminate_process_group(proc)
        elapsed=max(0,now_ts()-started)
        text=str(exc); code,msg=(text.split('|',1)+[''])[:2] if '|' in text else ('canary_failed',text)
        broker_result='cleanup_failed' if code.startswith('mesh_identity_') and report_token else 'launch_failed'
        if report_token: _report_canary(identity,report_token,broker_result,elapsed)
        save_canary_state({'status':'failed','verified':False,'started_at':started,'ended_at':now_ts(),'result_code':code,'elapsed_seconds':elapsed,
            'max_runtime_seconds':max_runtime,'agent_label':agent_label,'installation_id':(identity or {}).get('installation_id',''),
            'node_id':(identity or {}).get('node_id',''),'client_version':VERSION,'architecture':ARCH,'runtime_directory_deleted':False,
            'identity_mode':identity_mode,'identity_db_persisted':identity_db_persisted,'identity_binding_verified':identity_binding_verified,
            'identity_db_sha256_hint':identity_db_sha256_hint,'identity_generation':identity_generation,'identity_continuity_runs':identity_continuity_runs,'identity_relative_path':identity_relative_path})
        print(f"[managed] identity continuity canary failed code={code}; no raw credentials/tokens logged",flush=True)
    finally:
        if proc is not None: _terminate_process_group(proc)
        if agent_temp:
            try: Path(agent_temp).unlink(missing_ok=True)
            except OSError: cleanup_ok=False
        if runtime_dir:
            try: shutil.rmtree(runtime_dir)
            except OSError: cleanup_ok=False
        state=load_canary_state()
        if state:
            state['runtime_directory_deleted']=cleanup_ok
            save_canary_state(state)
        with CANARY_WORKER_LOCK: CANARY_WORKER_ACTIVE=False

def start_connectivity_canary():
    global CANARY_WORKER_ACTIVE
    with CANARY_WORKER_LOCK:
        if PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('canary_persistent_active|Δεν εκτελείται identity canary όσο είναι ενεργή η continuous Managed λειτουργία.')
        if CANARY_WORKER_ACTIVE: raise RuntimeError('canary_already_running|Υπάρχει ήδη identity continuity canary σε εξέλιξη.')
        CANARY_WORKER_ACTIVE=True
    t=threading.Thread(target=connectivity_canary_worker,name='managed-identity-continuity-canary',daemon=True); t.start()


def load_persistent_state():
    try:
        if not PERSISTENT_STATE_FILE.exists():
            return {}
        if PERSISTENT_STATE_FILE.stat().st_size <= 0 or PERSISTENT_STATE_FILE.stat().st_size > 32768:
            return {}
        data = json.loads(PERSISTENT_STATE_FILE.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        'status': _safe_str(data.get('status'), 40),
        'verified': data.get('verified') is True,
        'started_at': _as_int(data.get('started_at')) or 0,
        'ended_at': _as_int(data.get('ended_at')) or 0,
        'result_code': _safe_str(data.get('result_code'), 80),
        'health_state': _safe_str(data.get('health_state'), 40),
        'last_reason': _safe_str(data.get('last_reason'), 100),
        'last_watch_at': _as_int(data.get('last_watch_at')) or 0,
        'last_health_at': _as_int(data.get('last_health_at')) or 0,
        'runtime_lease_expires_at': _as_int(data.get('runtime_lease_expires_at')) or 0,
        'lease_renewals': max(0, _as_int(data.get('lease_renewals')) or 0),
        'reconnect_count': max(0, _as_int(data.get('reconnect_count')) or 0),
        'agent_label': _safe_str(data.get('agent_label'), 40).upper(),
        'installation_id': _safe_str(data.get('installation_id'), 100).upper(),
        'node_id': _safe_str(data.get('node_id'), 64).upper(),
        'client_version': _safe_str(data.get('client_version'), 30),
        'architecture': _safe_str(data.get('architecture'), 20),
        'identity_mode': _safe_str(data.get('identity_mode'), 20),
        'identity_generation': max(0, _as_int(data.get('identity_generation')) or 0),
        'identity_continuity_runs': max(0, _as_int(data.get('identity_continuity_runs')) or 0),
        'runtime_directory_deleted': data.get('runtime_directory_deleted') is True,
        'technician_actions_authorized': False,
        'service_persistence': False,
        'control_token_persisted': False,
        'runtime_lease_persisted': False,
    }


def save_persistent_state(state):
    """Persist only non-secret continuous-runtime telemetry. Raw lease/ticket/control token are forbidden."""
    safe = {
        'status': _safe_str(state.get('status'), 40),
        'verified': state.get('verified') is True,
        'started_at': _as_int(state.get('started_at')) or 0,
        'ended_at': _as_int(state.get('ended_at')) or 0,
        'result_code': _safe_str(state.get('result_code'), 80),
        'health_state': _safe_str(state.get('health_state'), 40),
        'last_reason': _safe_str(state.get('last_reason'), 100),
        'last_watch_at': _as_int(state.get('last_watch_at')) or 0,
        'last_health_at': _as_int(state.get('last_health_at')) or 0,
        'runtime_lease_expires_at': _as_int(state.get('runtime_lease_expires_at')) or 0,
        'lease_renewals': max(0, _as_int(state.get('lease_renewals')) or 0),
        'reconnect_count': max(0, _as_int(state.get('reconnect_count')) or 0),
        'agent_label': _safe_str(state.get('agent_label'), 40).upper(),
        'installation_id': _safe_str(state.get('installation_id'), 100).upper(),
        'node_id': _safe_str(state.get('node_id'), 64).upper(),
        'client_version': _safe_str(state.get('client_version'), 30),
        'architecture': _safe_str(state.get('architecture'), 20),
        'identity_mode': _safe_str(state.get('identity_mode'), 20),
        'identity_generation': max(0, _as_int(state.get('identity_generation')) or 0),
        'identity_continuity_runs': max(0, _as_int(state.get('identity_continuity_runs')) or 0),
        'runtime_directory_deleted': state.get('runtime_directory_deleted') is True,
        'technician_actions_authorized': False,
        'service_persistence': False,
        'control_token_persisted': False,
        'runtime_lease_persisted': False,
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PERSISTENT_STATE_FILE.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(safe, ensure_ascii=False, separators=(',', ':')))
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, PERSISTENT_STATE_FILE); os.chmod(PERSISTENT_STATE_FILE, 0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass


def _persistent_state_update(base, **changes):
    next_state = dict(base or {})
    next_state.update(changes)
    save_persistent_state(next_state)
    return next_state




def load_unattended_control():
    """Read the non-secret desired unattended-runtime state. Missing file = disabled."""
    try:
        data = json.loads(UNATTENDED_CONTROL_FILE.read_text(encoding='utf-8'))
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return {'enabled': False, 'enabled_at': 0, 'updated_at': 0, 'reason': 'not_enabled'}
    if not isinstance(data, dict):
        return {'enabled': False, 'enabled_at': 0, 'updated_at': 0, 'reason': 'invalid_control'}
    return {
        'enabled': data.get('enabled') is True,
        'enabled_at': _as_int(data.get('enabled_at')) or 0,
        'updated_at': _as_int(data.get('updated_at')) or 0,
        'reason': _safe_str(data.get('reason'), 80),
    }


def save_unattended_control(enabled, reason):
    """Persist only the admin's desired mode; no lease, ticket, token or MeshCentral secret."""
    current = load_unattended_control()
    now = now_ts()
    safe = {
        'enabled': bool(enabled),
        'enabled_at': (current.get('enabled_at') or now) if enabled else 0,
        'updated_at': now,
        'reason': _safe_str(reason, 80),
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = UNATTENDED_CONTROL_FILE.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(json.dumps(safe, ensure_ascii=False, separators=(',', ':')))
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, UNATTENDED_CONTROL_FILE); os.chmod(UNATTENDED_CONTROL_FILE, 0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass
    return safe


def unattended_supervisor():
    """Recover the foreground Managed runtime after add-on restart when explicitly enabled.

    It never seeds a new MeshAgent identity. It waits for local + Broker authorization,
    respects the Broker stale-runtime recovery window, and backs off after failed starts.
    """
    time.sleep(UNATTENDED_STARTUP_DELAY)
    last_log = None
    while True:
        control = load_unattended_control()
        if not control.get('enabled'):
            time.sleep(5); continue
        # Migration/reseed workers own the MeshAgent lifecycle while active.
        # The unattended supervisor must not race them by trying to restart the shared runtime.
        if MIGRATION_CANARY_WORKER_ACTIVE or IDENTITY_RESEED_WORKER_ACTIVE or CANDIDATE_RECONNECT_WORKER_ACTIVE:
            time.sleep(2); continue
        if PERSISTENT_WORKER_ACTIVE:
            time.sleep(5); continue

        identity = load_identity()
        identity_status = get_mesh_identity_status(identity) if identity else {'state':'not_paired'}
        local = read_policy()
        server = get_server_state()
        now = now_ts()

        reason = ''
        if identity is None:
            reason = 'identity_missing'
        elif identity_status.get('state') != 'ready':
            reason = 'identity_not_ready'
        elif not local.get('allowed_local'):
            reason = 'local_policy_denied'
        elif server.get('authorized_server') is not True or (_as_int(server.get('valid_until')) or 0) <= now:
            reason = 'server_authorization_wait'

        if reason:
            if reason != last_log:
                print(f"[managed] unattended supervisor waiting reason={reason}; no MeshAgent start", flush=True)
                last_log = reason
            time.sleep(10); continue

        state = load_persistent_state()
        state_code = _safe_str(state.get('result_code'), 80)
        if state.get('status') == 'failed' and 'identity' in state_code:
            save_unattended_control(False, 'identity_failure_requires_review')
            print('[managed] unattended supervisor disabled after identity failure; manual review required', flush=True)
            last_log = 'identity_failure_requires_review'
            time.sleep(10); continue

        # After an add-on/container restart, the previous server row may still be live.
        # Broker 0.32.0 marks it stale after >75s without watch; wait locally before retry.
        if state.get('status') in {'running','preparing','reconnecting','stopping'}:
            anchor = max(_as_int(state.get('last_watch_at')) or 0, _as_int(state.get('started_at')) or 0)
            if anchor and now < anchor + UNATTENDED_STALE_RECOVERY_DELAY:
                reason = 'waiting_previous_runtime_stale_window'
                if reason != last_log:
                    print('[managed] unattended supervisor waiting for previous runtime stale window before restart recovery', flush=True)
                    last_log = reason
                time.sleep(10); continue

        if state.get('status') == 'failed':
            ended = _as_int(state.get('ended_at')) or 0
            if ended and now < ended + UNATTENDED_FAILURE_RETRY_DELAY:
                reason = 'start_retry_backoff'
                if reason != last_log:
                    print('[managed] unattended supervisor backing off after failed start', flush=True)
                    last_log = reason
                time.sleep(10); continue

        try:
            start_persistent_runtime()
            print('[managed] unattended supervisor started continuous foreground runtime using existing stable identity', flush=True)
            last_log = 'runtime_started'
        except RuntimeError as exc:
            code = str(exc).partition('|')[0] or 'start_failed'
            if code != last_log:
                print(f"[managed] unattended supervisor start deferred code={_safe_str(code,80)}", flush=True)
                last_log = code
        time.sleep(10)


def _persistent_health(identity, control_token, health_state, reason=''):
    try:
        data = broker_post('/managed/persistent-runtime/health', {
            'control_token': control_token,
            'node_id': identity['node_id'],
            'node_secret': identity['node_secret'],
            'health_state': health_state,
            'reason': reason,
        })
        return data if isinstance(data, dict) else {}
    except RuntimeError:
        return {}


def _persistent_report(identity, control_token, result_code):
    if not control_token:
        return False
    try:
        data = broker_post('/managed/persistent-runtime/report', {
            'control_token': control_token,
            'node_id': identity['node_id'],
            'node_secret': identity['node_secret'],
            'result_code': result_code,
        })
        return data.get('success') is True and data.get('reported') is True
    except RuntimeError:
        return False


def _persistent_launch(runtime_dir, env):
    return subprocess.Popen(
        ['setsid', './meshagent'], cwd=str(runtime_dir), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, close_fds=True,
    )


def persistent_runtime_worker():
    """Continuous foreground runtime with explicit unattended enablement.

    In 3.9.0 the admin can enable unattended mode once. After that, add-on restarts
    recover the same stable MeshAgent identity automatically after local and Broker
    authorization are valid. Technician actions remain explicitly unauthorized.
    """
    global PERSISTENT_WORKER_ACTIVE
    identity = load_identity()
    runtime_dir = None
    agent_temp = None
    proc = None
    runtime_lease = ''
    runtime_ticket = ''
    control_token = ''
    settings = None
    prior_identity = None
    base_state = {}
    result_code = 'stopped'
    last_reason = 'manual_stop'
    cleanup_ok = True
    report_ok = False
    started_at = now_ts()
    lease_expires = 0
    lease_renewals = 0
    reconnect_count = 0
    consecutive_exits = 0
    try:
        if identity is None:
            raise RuntimeError('persistent_not_paired|Απαιτείται ενεργή Managed identity πριν από τη συνεχή λειτουργία.')
        snapshot = read_policy()
        if not snapshot.get('allowed_local'):
            raise RuntimeError('persistent_local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει συνεχή λειτουργία.')
        server = get_server_state()
        if server.get('authorized_server') is not True or (_as_int(server.get('valid_until')) or 0) <= now_ts():
            raise RuntimeError('persistent_server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από τη συνεχή λειτουργία.')
        prior_identity = _validate_persisted_mesh_identity(identity, None)
        if prior_identity.get('state') != 'ready':
            raise RuntimeError('persistent_identity_not_ready|Απαιτείται ήδη VERIFIED σταθερή MeshCentral ταυτότητα από το 3.7.0. Η 3.9.0 δεν δημιουργεί νέα identity.')

        base_state = {
            'status': 'preparing', 'verified': False, 'started_at': started_at,
            'health_state': 'starting', 'last_reason': 'refreshing_verified_chain',
            'installation_id': identity['installation_id'], 'node_id': identity['node_id'],
            'client_version': VERSION, 'architecture': ARCH,
            'identity_mode': 'reuse', 'identity_generation': prior_identity.get('generation', 0),
            'identity_continuity_runs': prior_identity.get('continuity_runs', 0),
            'agent_label': prior_identity.get('agent_label', ''), 'runtime_directory_deleted': False,
        }
        save_persistent_state(base_state)

        # Fresh verification chain under 3.9.0. Raw settings and binary remain ephemeral.
        settings = _execution_settings_material(identity)
        verified_identity = _validate_persisted_mesh_identity(identity, settings)
        if verified_identity.get('state') != 'ready':
            raise RuntimeError('persistent_identity_binding_failed|Η σταθερή MeshCentral identity δεν επαληθεύτηκε με τα νέα .msh settings.')
        if not secrets.compare_digest(_safe_str(verified_identity.get('agent_label'),40).upper(), _safe_str(settings.get('agent_label'),40).upper()):
            raise RuntimeError('persistent_identity_label_mismatch|Το verified node label δεν συμφωνεί με τη σταθερή MeshCentral identity.')
        agent = _execution_agent_material(identity, settings)
        agent_temp = agent.get('path')
        if not agent_temp:
            raise RuntimeError('persistent_agent_missing|Δεν προετοιμάστηκε verified MeshAgent binary.')

        common = {'node_id': identity['node_id'], 'node_secret': identity['node_secret'], 'client_version': VERSION, 'architecture': ARCH}
        lease = broker_post('/managed/runtime-lease/request', common)
        runtime_lease = _safe_str(lease.get('runtime_lease'), 90)
        lease_expires = parse_iso_epoch(lease.get('expires_at'))
        server_until = _as_int(lease.get('server_valid_until')) or parse_iso_epoch(lease.get('server_valid_until'))
        if not (
            lease.get('success') is True and lease.get('runtime_contract') == 'smart-pro-managed-runtime-lease-v1'
            and lease.get('runtime_authorized') is True and lease.get('lease_renewable') is True
            and RUNTIME_LEASE_RE.fullmatch(runtime_lease) is not None and lease_expires > now_ts()
            and server_until > now_ts() and lease_expires <= server_until
        ):
            raise RuntimeError('persistent_runtime_lease_invalid|Ο Broker δεν επέστρεψε έγκυρο renewable runtime lease.')

        req = dict(common); req['runtime_lease'] = runtime_lease
        auth = broker_post('/managed/persistent-runtime/request', req)
        runtime_ticket = _safe_str(auth.get('runtime_ticket'), 90)
        control_token = _safe_str(auth.get('control_token'), 90)
        if not (
            auth.get('success') is True and auth.get('runtime_contract') == 'smart-pro-managed-persistent-runtime-v1'
            and auth.get('state') == 'persistent_runtime_ticket_issued_not_started'
            and auth.get('foreground_only') is True and auth.get('service_persistence') is False
            and auth.get('technician_actions_authorized') is False and auth.get('remote_access') is False
            and PERSISTENT_TICKET_RE.fullmatch(runtime_ticket) is not None
            and PERSISTENT_CONTROL_RE.fullmatch(control_token) is not None
            and parse_iso_epoch(auth.get('expires_at')) > now_ts()
        ):
            raise RuntimeError('persistent_authorization_invalid|Ο Broker δεν επέστρεψε έγκυρη continuous-runtime authorization.')

        consume = dict(common); consume['runtime_ticket'] = runtime_ticket
        run = broker_post('/managed/persistent-runtime/consume', consume)
        watch_interval = _as_int(run.get('watch_interval_seconds')) or 15
        health_interval = _as_int(run.get('health_interval_seconds')) or 30
        renew_before = _as_int(run.get('renew_before_seconds')) or 75
        consume_lease_expires = parse_iso_epoch(run.get('runtime_lease_expires_at'))
        if not (
            run.get('success') is True and run.get('runtime_contract') == 'smart-pro-managed-persistent-runtime-v1'
            and run.get('state') == 'persistent_runtime_authorized_connectivity_only'
            and run.get('foreground_only') is True and run.get('service_persistence') is False
            and run.get('meshcentral_runtime_authorized') is True
            and run.get('technician_actions_authorized') is False and run.get('remote_access') is False
            and 5 <= watch_interval <= 60 and 10 <= health_interval <= 120 and 30 <= renew_before <= 120
            and consume_lease_expires > now_ts()
        ):
            raise RuntimeError('persistent_consume_invalid|Η continuous-runtime authorization δεν καταναλώθηκε σωστά.')
        lease_expires = consume_lease_expires

        runtime_dir = Path(tempfile.mkdtemp(prefix='smart-pro-managed-continuous-', dir='/tmp')); os.chmod(runtime_dir, 0o700)
        agent_path = runtime_dir / 'meshagent'; shutil.move(agent_temp, agent_path); agent_temp = None; os.chmod(agent_path, 0o700)
        msh_path = runtime_dir / 'meshagent.msh'; hardened = _harden_runtime_msh(settings['raw'], settings['agent_label'])
        fd = os.open(msh_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(hardened); handle.flush(); os.fsync(handle.fileno())
        private = runtime_dir / 'private'; private.mkdir(mode=0o700)
        os.chmod(private, 0o700)
        prepared = _copy_persisted_identity_into_runtime(runtime_dir, identity, settings)
        if prepared.get('mode') != 'reuse':
            raise RuntimeError('persistent_identity_reuse_required|Η 3.9.0 απαιτεί reuse της ήδη αποθηκευμένης MeshCentral identity και δεν επιτρέπεται seed νέου node.')
        env = os.environ.copy(); env.update({'HOME':str(private),'TMPDIR':str(private),'XDG_CONFIG_HOME':str(private),'XDG_CACHE_HOME':str(private)})

        proc = _persistent_launch(runtime_dir, env)
        launch_mono = time.monotonic()
        last_watch_success = time.monotonic()
        next_watch = 0.0
        next_health = 0.0
        base_state = _persistent_state_update(base_state, status='running', verified=True, started_at=now_ts(),
            health_state='starting', last_reason='persistent_runtime_started', runtime_lease_expires_at=lease_expires,
            agent_label=settings['agent_label'], identity_mode='reuse', runtime_directory_deleted=False)
        _persistent_health(identity, control_token, 'starting', 'persistent_runtime_started')
        print(f"[managed] continuous runtime started for {identity['installation_id']} label={settings['agent_label']} identity=reuse; technician_actions=false", flush=True)

        while True:
            now_mono = time.monotonic()
            if PERSISTENT_STOP_EVENT.is_set():
                result_code='stopped'; last_reason='manual_stop'; break
            if not read_policy().get('allowed_local'):
                result_code='stopped'; last_reason='local_policy_denied'; break

            if proc.poll() is not None:
                if now_mono - launch_mono >= 60:
                    consecutive_exits = 0
                consecutive_exits += 1
                reconnect_count += 1
                if consecutive_exits > PERSISTENT_MAX_CONSECUTIVE_EXITS:
                    result_code='agent_exit'; last_reason='reconnect_limit_reached'; break
                delay = PERSISTENT_RECONNECT_DELAYS[min(consecutive_exits-1, len(PERSISTENT_RECONNECT_DELAYS)-1)]
                base_state = _persistent_state_update(base_state, status='reconnecting', health_state='reconnecting',
                    last_reason='agent_exit_reconnect_wait', reconnect_count=reconnect_count, runtime_lease_expires_at=lease_expires)
                _persistent_health(identity, control_token, 'reconnecting', 'agent_exit_reconnect_wait')
                wait_until = time.monotonic() + delay
                while time.monotonic() < wait_until:
                    if PERSISTENT_STOP_EVENT.is_set(): break
                    if not read_policy().get('allowed_local'): break
                    time.sleep(1)
                if PERSISTENT_STOP_EVENT.is_set():
                    result_code='stopped'; last_reason='manual_stop'; break
                if not read_policy().get('allowed_local'):
                    result_code='stopped'; last_reason='local_policy_denied'; break
                # Server must still explicitly allow continuation immediately before reconnect.
                try:
                    watch = broker_post('/managed/persistent-runtime/watch', {'control_token':control_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
                except RuntimeError:
                    result_code='server_authorization_lost'; last_reason='watch_failed_before_reconnect'; break
                if watch.get('continue') is not True:
                    result_code='server_authorization_lost'; last_reason=_safe_str(watch.get('reason'),100) or 'watch_denied_before_reconnect'; break
                if watch.get('renew_runtime_lease') is True or (lease_expires - now_ts()) <= renew_before:
                    renew = dict(common); renew['runtime_lease'] = runtime_lease
                    try:
                        renewed = broker_post('/managed/runtime-lease/renew', renew)
                    except RuntimeError:
                        result_code='runtime_lease_lost'; last_reason='runtime_lease_renew_failed_before_reconnect'; break
                    renewed_expires = parse_iso_epoch(renewed.get('expires_at'))
                    renewed_server_until = _as_int(renewed.get('server_valid_until')) or parse_iso_epoch(renewed.get('server_valid_until'))
                    if not (renewed.get('success') is True and renewed.get('runtime_contract') == 'smart-pro-managed-runtime-lease-v1'
                            and renewed.get('lease_renewed') is True and renewed_expires > now_ts()
                            and renewed_server_until > now_ts() and renewed_expires <= renewed_server_until):
                        result_code='runtime_lease_lost'; last_reason='runtime_lease_renew_contract_invalid_before_reconnect'; break
                    lease_expires = renewed_expires; lease_renewals += 1
                proc = _persistent_launch(runtime_dir, env); launch_mono = time.monotonic(); last_watch_success = time.monotonic()
                base_state = _persistent_state_update(base_state, status='running', health_state='online',
                    last_reason='controlled_reconnect', last_watch_at=now_ts(), reconnect_count=reconnect_count)
                print(f"[managed] controlled MeshAgent reconnect #{reconnect_count} using same persisted identity", flush=True)
                next_watch = time.monotonic() + max(5, watch_interval)
                next_health = 0.0
                continue

            if now_mono >= next_watch:
                try:
                    watch = broker_post('/managed/persistent-runtime/watch', {'control_token':control_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
                    last_watch_success = time.monotonic()
                except RuntimeError:
                    if time.monotonic() - last_watch_success >= PERSISTENT_WATCH_FAILURE_GRACE or now_ts() >= lease_expires:
                        result_code='server_authorization_lost'; last_reason='watch_unreachable_fail_closed'; break
                    base_state = _persistent_state_update(base_state, health_state='reconnecting', last_reason='watch_temporarily_unreachable')
                    next_watch = time.monotonic() + 5
                    time.sleep(1)
                    continue
                if watch.get('continue') is not True:
                    reason = _safe_str(watch.get('reason'),100) or 'watch_denied'
                    result_code = 'runtime_lease_lost' if reason.startswith('runtime_lease_') else 'server_authorization_lost'
                    last_reason = reason
                    break
                base_state = _persistent_state_update(base_state, status='running', health_state='online',
                    last_reason='persistent_runtime_allowed', last_watch_at=now_ts(), runtime_lease_expires_at=lease_expires)
                if watch.get('renew_runtime_lease') is True or (lease_expires - now_ts()) <= renew_before:
                    renew = dict(common); renew['runtime_lease'] = runtime_lease
                    try:
                        renewed = broker_post('/managed/runtime-lease/renew', renew)
                    except RuntimeError:
                        result_code='runtime_lease_lost'; last_reason='runtime_lease_renew_failed'; break
                    renewed_expires = parse_iso_epoch(renewed.get('expires_at'))
                    renewed_server_until = _as_int(renewed.get('server_valid_until')) or parse_iso_epoch(renewed.get('server_valid_until'))
                    if not (
                        renewed.get('success') is True and renewed.get('runtime_contract') == 'smart-pro-managed-runtime-lease-v1'
                        and renewed.get('lease_renewed') is True and renewed_expires > now_ts()
                        and renewed_server_until > now_ts() and renewed_expires <= renewed_server_until
                    ):
                        result_code='runtime_lease_lost'; last_reason='runtime_lease_renew_contract_invalid'; break
                    lease_expires = renewed_expires; lease_renewals += 1
                    base_state = _persistent_state_update(base_state, runtime_lease_expires_at=lease_expires,
                        lease_renewals=lease_renewals, last_reason='runtime_lease_renewed')
                    print(f"[managed] continuous runtime lease renewed count={lease_renewals}; raw lease remains memory-only", flush=True)
                next_watch = time.monotonic() + max(5, watch_interval)

            if now_mono >= next_health:
                health = _persistent_health(identity, control_token, 'online', 'meshagent_foreground_online')
                if health and health.get('continue') is False:
                    result_code='server_authorization_lost'; last_reason=_safe_str(health.get('reason'),100) or 'health_denied'; break
                base_state = _persistent_state_update(base_state, health_state='online', last_health_at=now_ts(),
                    last_reason='meshagent_foreground_online', reconnect_count=reconnect_count, lease_renewals=lease_renewals,
                    runtime_lease_expires_at=lease_expires)
                next_health = time.monotonic() + max(10, health_interval)

            if now_mono - launch_mono >= 60:
                consecutive_exits = 0
            time.sleep(1)

        base_state = _persistent_state_update(base_state, status='stopping', health_state='stopping', last_reason=last_reason,
            reconnect_count=reconnect_count, lease_renewals=lease_renewals, runtime_lease_expires_at=lease_expires)
        _persistent_health(identity, control_token, 'stopping', last_reason)
        _terminate_process_group(proc); proc = None
        persisted = _persist_runtime_mesh_identity(runtime_dir, identity, settings, prior_identity)
        report_ok = _persistent_report(identity, control_token, result_code)
        base_state = _persistent_state_update(base_state, status='reported' if report_ok else 'stopped', verified=report_ok,
            ended_at=now_ts(), result_code=result_code, health_state='stopped', last_reason=last_reason,
            identity_generation=persisted.get('generation',0), identity_continuity_runs=persisted.get('continuity_runs',0),
            reconnect_count=reconnect_count, lease_renewals=lease_renewals, runtime_lease_expires_at=lease_expires)
        print(f"[managed] continuous runtime stopped result={result_code} reported={str(report_ok).lower()} renewals={lease_renewals} reconnects={reconnect_count}; technician_actions=false", flush=True)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        if proc is not None:
            _terminate_process_group(proc); proc = None
        text = str(exc); code, sep, message = text.partition('|')
        if not sep:
            code='persistent_runtime_failed'; message=text or 'Η συνεχής Managed λειτουργία απέτυχε.'
        result_code = 'identity_invalid' if 'identity' in code else 'launch_failed'
        if control_token and identity:
            _persistent_report(identity, control_token, result_code)
        fail = dict(base_state or {})
        fail.update({'status':'failed','verified':False,'ended_at':now_ts(),'result_code':code,'health_state':'error',
            'last_reason':_safe_str(message,100),'installation_id':(identity or {}).get('installation_id',''),
            'node_id':(identity or {}).get('node_id',''),'client_version':VERSION,'architecture':ARCH,
            'runtime_lease_expires_at':lease_expires,'lease_renewals':lease_renewals,'reconnect_count':reconnect_count,
            'identity_mode':'reuse','runtime_directory_deleted':False})
        save_persistent_state(fail)
        print(f"[managed] continuous runtime failed code={code}; raw lease/ticket/control token not logged or persisted", flush=True)
    finally:
        if proc is not None:
            _terminate_process_group(proc)
        if agent_temp:
            try: Path(agent_temp).unlink(missing_ok=True)
            except OSError: cleanup_ok=False
        if runtime_dir:
            try: shutil.rmtree(runtime_dir)
            except OSError: cleanup_ok=False
        state = load_persistent_state()
        if state:
            state['runtime_directory_deleted'] = cleanup_ok
            save_persistent_state(state)
        runtime_lease = ''; runtime_ticket = ''; control_token = ''
        PERSISTENT_STOP_EVENT.clear()
        with PERSISTENT_WORKER_LOCK:
            PERSISTENT_WORKER_ACTIVE = False


def start_persistent_runtime():
    global PERSISTENT_WORKER_ACTIVE
    with PERSISTENT_WORKER_LOCK:
        if PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('persistent_runtime_already_running|Η συνεχής Managed λειτουργία εκτελείται ήδη.')
        if CANARY_WORKER_ACTIVE:
            raise RuntimeError('persistent_canary_active|Περιμένετε να ολοκληρωθεί το identity canary πριν ξεκινήσει συνεχής λειτουργία.')
        identity = load_identity()
        if identity is None:
            raise RuntimeError('persistent_not_paired|Απαιτείται ενεργή Managed identity.')
        status = get_mesh_identity_status(identity)
        if status.get('state') != 'ready':
            raise RuntimeError('persistent_identity_not_ready|Η σταθερή MeshCentral identity δεν είναι READY. Δεν θα δημιουργηθεί νέο node από την 3.9.0.')
        PERSISTENT_STOP_EVENT.clear()
        PERSISTENT_WORKER_ACTIVE = True
    thread = threading.Thread(target=persistent_runtime_worker, name='managed-continuous-runtime', daemon=True)
    thread.start()


def stop_persistent_runtime():
    with PERSISTENT_WORKER_LOCK:
        if not PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('persistent_runtime_not_running|Δεν υπάρχει ενεργή συνεχής Managed λειτουργία για τερματισμό.')
        PERSISTENT_STOP_EVENT.set()

def load_group_migration_preflight_state():
    base = {
        "status": "not_run",
        "verified": False,
        "checked_at": 0,
        "installation_id": "",
        "node_id": "",
        "client_version": "",
        "architecture": "",
        "target_group_name": "",
        "target_mesh_id_hint": "",
        "target_binding_hint": "",
        "target_source_fingerprint_hint": "",
        "shared_source_fingerprint_hint": "",
        "controller_node_hint": "",
        "expected_agent_label": "",
        "server_valid_until": 0,
        "error_code": "",
        "error_message": "",
    }
    try:
        if not GROUP_MIGRATION_PREFLIGHT_FILE.exists():
            return base
        st = GROUP_MIGRATION_PREFLIGHT_FILE.stat()
        if st.st_size <= 0 or st.st_size > 32768:
            return base
        data = json.loads(GROUP_MIGRATION_PREFLIGHT_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return base
    if not isinstance(data, dict):
        return base
    for key in base:
        if key in data:
            base[key] = data[key]
    return base


def save_group_migration_preflight_state(state):
    """Persist only non-secret migration-preflight metadata. Never persist raw .msh or enrollment identifiers."""
    allowed = {
        "status", "verified", "checked_at", "installation_id", "node_id", "client_version", "architecture",
        "target_group_name", "target_mesh_id_hint", "target_binding_hint", "target_source_fingerprint_hint",
        "shared_source_fingerprint_hint", "controller_node_hint", "expected_agent_label", "server_valid_until",
        "error_code", "error_message",
    }
    payload = {k: state.get(k) for k in allowed if k in state}
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = GROUP_MIGRATION_PREFLIGHT_FILE.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(',', ':'))
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, GROUP_MIGRATION_PREFLIGHT_FILE)
        os.chmod(GROUP_MIGRATION_PREFLIGHT_FILE, 0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError:
            pass


def verify_group_migration_preflight():
    """Consume Broker 0.36 metadata-only preflight. No target settings delivery, MeshAgent execution or group move."""
    identity = load_identity()
    if identity is None:
        raise RuntimeError('group_migration_not_paired|Απαιτείται ενεργή Managed identity πριν από migration preflight.')
    local = read_policy()
    if not local.get('allowed_local'):
        raise RuntimeError('group_migration_local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει migration preflight.')
    server = get_server_state()
    if not server.get('authorized_server') or (_as_int(server.get('valid_until')) or 0) <= now_ts():
        raise RuntimeError('group_migration_server_authorization_denied|Απαιτείται ενεργή Broker Server Authorization πριν από migration preflight.')
    if ARCH not in ELF_MACHINE:
        raise RuntimeError('group_migration_architecture_invalid|Η αρχιτεκτονική του add-on δεν υποστηρίζεται για migration preflight.')

    mesh_identity = get_mesh_identity_status(identity)
    if mesh_identity.get('state') != 'ready':
        raise RuntimeError('group_migration_identity_not_ready|Η σταθερή MeshCentral identity δεν είναι READY.')
    current_agent_label = _safe_str(mesh_identity.get('agent_label'), 80).upper()
    if not AGENT_LABEL_RE.fullmatch(current_agent_label):
        raise RuntimeError('group_migration_agent_label_invalid|Η αποθηκευμένη stable MeshCentral identity δεν έχει έγκυρο opaque label.')

    try:
        result = broker_post('/managed/group-migration/preflight', {
            'node_id': identity['node_id'],
            'node_secret': identity['node_secret'],
            'client_version': VERSION,
            'architecture': ARCH,
        })
        if result.get('success') is not True or result.get('phase') != 'per_installation_group_migration_preflight':
            raise RuntimeError('group_migration_preflight_response_invalid|Ο Broker δεν επέστρεψε έγκυρο migration preflight response.')
        if result.get('contract_id') != 'smart-pro-managed-group-migration-preflight-v1' or _as_int(result.get('schema_version')) != 1:
            raise RuntimeError('group_migration_preflight_contract_invalid|Το migration preflight contract δεν είναι συμβατό.')
        if _safe_str(result.get('installation_ref'), 100).upper() != identity['installation_id']:
            raise RuntimeError('group_migration_installation_mismatch|Το Installation ID του migration preflight δεν συμφωνεί με την Managed identity.')
        expected_group = f"Smart Pro Managed — {identity['installation_id']}"
        if _safe_str(result.get('target_group_name'), 180) != expected_group:
            raise RuntimeError('group_migration_target_group_mismatch|Το target MeshCentral group δεν συμφωνεί με το Installation ID.')
        expected_label = _safe_str(result.get('expected_agent_label'), 80).upper()
        if expected_label != current_agent_label:
            raise RuntimeError('group_migration_agent_label_mismatch|Το Broker migration preflight δεν συμφωνεί με την υπάρχουσα stable MeshAgent identity.')
        target_mesh_hint = _safe_str(result.get('target_mesh_id_hint'), 80).lower()
        target_binding_hint = _safe_str(result.get('target_binding_hint'), 80).lower()
        target_source_hint = _safe_str(result.get('target_source_fingerprint_hint'), 20).lower()
        shared_source_hint = _safe_str(result.get('shared_source_fingerprint_hint'), 20).lower()
        controller_hint = _safe_str(result.get('controller_node_hint'), 20).lower()
        if not FINGERPRINT_HINT_RE.fullmatch(target_mesh_hint) or not FINGERPRINT_HINT_RE.fullmatch(target_binding_hint) or not FINGERPRINT_HINT_RE.fullmatch(target_source_hint) or not FINGERPRINT_HINT_RE.fullmatch(shared_source_hint) or not FINGERPRINT_HINT_RE.fullmatch(controller_hint):
            raise RuntimeError('group_migration_hint_invalid|Ο Broker δεν επέστρεψε έγκυρα non-secret migration binding hints.')
        if secrets.compare_digest(target_source_hint, shared_source_hint):
            raise RuntimeError('group_migration_sources_not_distinct|Το target source δεν είναι διαφορετικό από το ενεργό shared Managed source.')
        if result.get('preflight_ready') is not True:
            raise RuntimeError('group_migration_not_ready|Το server-side migration preflight δεν είναι READY.')
        for safety_flag in ('target_msh_delivered','node_move','runtime_source_switch','identity_binding_commit','meshagent_execution','technician_actions_authorized','remote_access'):
            if result.get(safety_flag) is not False:
                raise RuntimeError('group_migration_safety_boundary_invalid|Το migration preflight response παραβιάζει το preflight-only safety boundary.')
        server_valid_until = _as_int(result.get('server_valid_until')) or 0
        if server_valid_until <= now_ts():
            raise RuntimeError('group_migration_server_lease_invalid|Το migration preflight δεν είναι δεμένο σε ενεργή server authorization lease.')

        state = {
            'status': 'verified', 'verified': True, 'checked_at': now_ts(),
            'installation_id': identity['installation_id'], 'node_id': identity['node_id'],
            'client_version': VERSION, 'architecture': ARCH,
            'target_group_name': expected_group, 'target_mesh_id_hint': target_mesh_hint,
            'target_binding_hint': target_binding_hint, 'target_source_fingerprint_hint': target_source_hint,
            'shared_source_fingerprint_hint': shared_source_hint, 'controller_node_hint': controller_hint,
            'expected_agent_label': expected_label, 'server_valid_until': server_valid_until,
            'error_code': '', 'error_message': '',
        }
        save_group_migration_preflight_state(state)
        print(f"[managed] group migration preflight VERIFIED for {identity['installation_id']} label={expected_label}; runtime_source_switch=false node_move=false technician_actions=false", flush=True)
        return state
    except RuntimeError as exc:
        text = str(exc)
        code, _, message = text.partition('|')
        save_group_migration_preflight_state({
            'status': 'failed', 'verified': False, 'checked_at': now_ts(),
            'installation_id': identity['installation_id'], 'node_id': identity['node_id'],
            'client_version': VERSION, 'architecture': ARCH,
            'error_code': _safe_str(code, 100),
            'error_message': _safe_str(message or 'Το migration preflight απέτυχε.', 300),
        })
        raise



def load_group_migration_target_settings_state():
    base = {
        "status": "not_run", "verified": False, "checked_at": 0,
        "installation_id": "", "node_id": "", "client_version": "", "architecture": "",
        "target_group_name": "", "target_mesh_id_hint": "", "target_binding_hint": "",
        "target_source_fingerprint_hint": "", "shared_source_fingerprint_hint": "",
        "expected_agent_label": "", "mesh_server_host": "", "sha256_hint": "", "bytes": 0,
        "target_msh_memory_only": False, "runtime_source_switch": False, "node_move": False,
        "identity_binding_commit": False, "meshagent_execution": False,
        "technician_actions_authorized": False, "error_code": "", "error_message": "",
    }
    try:
        if not GROUP_MIGRATION_TARGET_SETTINGS_FILE.exists():
            return base
        st = GROUP_MIGRATION_TARGET_SETTINGS_FILE.stat()
        if st.st_size <= 0 or st.st_size > 32768:
            return base
        data = json.loads(GROUP_MIGRATION_TARGET_SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return base
    if not isinstance(data, dict):
        return base
    for key in base:
        if key in data:
            base[key] = data[key]
    return base


def save_group_migration_target_settings_state(state):
    """Persist non-secret target-settings verification metadata only; never persist ticket or raw .msh."""
    allowed = {
        "status", "verified", "checked_at", "installation_id", "node_id", "client_version", "architecture",
        "target_group_name", "target_mesh_id_hint", "target_binding_hint", "target_source_fingerprint_hint",
        "shared_source_fingerprint_hint", "expected_agent_label", "mesh_server_host", "sha256_hint", "bytes",
        "target_msh_memory_only", "runtime_source_switch", "node_move", "identity_binding_commit",
        "meshagent_execution", "technician_actions_authorized", "error_code", "error_message",
    }
    payload = {k: state.get(k) for k in allowed if k in state}
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = GROUP_MIGRATION_TARGET_SETTINGS_FILE.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(',', ':'))
            handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, GROUP_MIGRATION_TARGET_SETTINGS_FILE)
        os.chmod(GROUP_MIGRATION_TARGET_SETTINGS_FILE, 0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError:
            pass


def verify_group_migration_target_settings(return_material=False):
    """One-time Broker 0.37+ target .msh delivery + strict in-memory verification. Raw material is returned only to the controlled 3.12 migration canary when explicitly requested."""
    identity = load_identity()
    if identity is None:
        raise RuntimeError('group_target_not_paired|Απαιτείται ενεργή Managed identity πριν από target .msh verification.')
    local = read_policy()
    if not local.get('allowed_local'):
        raise RuntimeError('group_target_local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει target .msh verification.')
    server = get_server_state()
    if not server.get('authorized_server') or (_as_int(server.get('valid_until')) or 0) <= now_ts():
        raise RuntimeError('group_target_server_authorization_denied|Απαιτείται ενεργή Broker Server Authorization πριν από target .msh verification.')
    if ARCH not in ELF_MACHINE:
        raise RuntimeError('group_target_architecture_invalid|Η αρχιτεκτονική του add-on δεν υποστηρίζεται για target .msh verification.')
    mesh_identity = get_mesh_identity_status(identity)
    if mesh_identity.get('state') != 'ready':
        raise RuntimeError('group_target_identity_not_ready|Η σταθερή MeshCentral identity δεν είναι READY.')

    # Always refresh the authenticated metadata-only preflight immediately before delivery.
    preflight = verify_group_migration_preflight()
    if preflight.get('verified') is not True:
        raise RuntimeError('group_target_preflight_not_ready|Το migration preflight δεν είναι VERIFIED.')
    expected_group = preflight.get('target_group_name') or f"Smart Pro Managed — {identity['installation_id']}"
    expected_label = _safe_str(preflight.get('expected_agent_label'), 80).upper()
    try:
        common = {
            'node_id': identity['node_id'], 'node_secret': identity['node_secret'],
            'client_version': VERSION, 'architecture': ARCH,
        }
        req = broker_post('/managed/group-migration/target-settings/request', common)
        ticket = _safe_str(req.get('target_settings_ticket'), 90)
        if not (
            req.get('success') is True and req.get('phase') == 'per_installation_group_target_settings_request'
            and req.get('contract_id') == 'smart-pro-managed-group-target-settings-v1'
            and _as_int(req.get('schema_version')) == 1
            and TARGET_SETTINGS_TICKET_RE.fullmatch(ticket) is not None
            and (_as_int(req.get('expires_at')) or 0) > now_ts()
        ):
            raise RuntimeError('group_target_request_invalid|Ο Broker δεν επέστρεψε έγκυρο one-time target settings contract.')
        for field, expected in (
            ('installation_ref', identity['installation_id']),
            ('target_group_name', expected_group),
            ('target_mesh_id_hint', preflight.get('target_mesh_id_hint')),
            ('target_binding_hint', preflight.get('target_binding_hint')),
            ('target_source_fingerprint_hint', preflight.get('target_source_fingerprint_hint')),
            ('shared_source_fingerprint_hint', preflight.get('shared_source_fingerprint_hint')),
            ('expected_agent_label', expected_label),
        ):
            actual = _safe_str(req.get(field), 200)
            expected_text = _safe_str(expected, 200)
            # compare_digest(str, str) rejects non-ASCII text. The per-installation
            # group name intentionally contains an em dash, so compare the exact
            # UTF-8 byte sequences instead while retaining constant-time comparison.
            if not secrets.compare_digest(actual.encode('utf-8'), expected_text.encode('utf-8')):
                raise RuntimeError('group_target_request_binding_mismatch|Το target settings request δεν συμφωνεί με το verified migration preflight.')
        for flag in ('target_msh_delivered','meshagent_execution','node_move','runtime_source_switch','identity_binding_commit','technician_actions_authorized','remote_access'):
            if req.get(flag) is not False:
                raise RuntimeError('group_target_request_safety_boundary|Το target settings request παραβιάζει το verification-only safety boundary.')

        consume_payload = dict(common); consume_payload['target_settings_ticket'] = ticket
        res = broker_post('/managed/group-migration/target-settings/consume', consume_payload)
        ticket = ''  # raw one-time ticket deliberately discarded immediately after consume
        if not (
            res.get('success') is True and res.get('phase') == 'per_installation_group_target_settings_consume'
            and res.get('contract_id') == 'smart-pro-managed-group-target-settings-v1'
            and _as_int(res.get('schema_version')) == 1
            and res.get('target_msh_delivered') is True
            and res.get('meshagent_execution') is False and res.get('node_move') is False
            and res.get('runtime_source_switch') is False and res.get('identity_binding_commit') is False
            and res.get('technician_actions_authorized') is False and res.get('remote_access') is False
        ):
            raise RuntimeError('group_target_consume_invalid|Ο Broker δεν επέστρεψε έγκυρο verification-only target .msh consume contract.')
        encoded = _safe_str(res.get('data'), MAX_RESPONSE_BYTES)
        try:
            raw = base64.b64decode(encoded.encode('ascii'), validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError):
            raise RuntimeError('group_target_base64_invalid|Το target .msh payload δεν είναι έγκυρο base64.') from None
        expected_bytes = _as_int(res.get('bytes')) or 0
        expected_sha = _safe_str(res.get('sha256'), 64).lower()
        actual_sha = hashlib.sha256(raw).hexdigest()
        if expected_bytes != len(raw) or not SHA256_RE.fullmatch(expected_sha) or not secrets.compare_digest(expected_sha, actual_sha):
            raw = b''
            raise RuntimeError('group_target_integrity_mismatch|Το target .msh απέτυχε στον τοπικό SHA/bytes έλεγχο ακεραιότητας.')
        fields = parse_msh_strict(raw)
        if _safe_str(fields.get('MeshName'), 200) != expected_group:
            raw = b''
            raise RuntimeError('group_target_group_mismatch|Το target .msh δεν αντιστοιχεί στο verified per-installation group.')
        if _safe_str(fields.get('agentName'), 80).upper() != expected_label:
            raw = b''
            raise RuntimeError('group_target_agent_label_mismatch|Το target .msh δεν διατηρεί το expected stable SPMNG label.')
        mesh_id_hint = hashlib.sha256(_safe_str(fields.get('MeshID'), 4096).encode('utf-8')).hexdigest()[:12]
        binding_material = '\n'.join(_safe_str(fields.get(k), 4096) for k in ('MeshName','MeshType','MeshID','ServerID','MeshServer'))
        binding_hint = hashlib.sha256(binding_material.encode('utf-8')).hexdigest()[:12]
        if not secrets.compare_digest(mesh_id_hint, _safe_str(preflight.get('target_mesh_id_hint'), 12).lower()):
            raw = b''
            raise RuntimeError('group_target_meshid_mismatch|Το target MeshID δεν συμφωνεί με το verified preflight hint.')
        if not secrets.compare_digest(binding_hint, _safe_str(preflight.get('target_binding_hint'), 12).lower()):
            raw = b''
            raise RuntimeError('group_target_binding_mismatch|Το target MeshCentral binding δεν συμφωνεί με το verified preflight hint.')
        parsed = urlparse(_safe_str(fields.get('MeshServer'), 4096))
        if parsed.scheme.lower() != 'wss' or not parsed.hostname:
            raw = b''
            raise RuntimeError('group_target_meshserver_invalid|Το target .msh δεν περιέχει ασφαλές WSS MeshServer endpoint.')
        mesh_server_host = parsed.hostname.lower()
        if _safe_str(res.get('mesh_server_host'), 255).lower() != mesh_server_host:
            raw = b''
            raise RuntimeError('group_target_meshserver_host_mismatch|Το target MeshServer host δεν συμφωνεί με το Broker verification.')
        target_source_hint = _safe_str(res.get('target_source_fingerprint_hint'), 12).lower()
        shared_source_hint = _safe_str(res.get('shared_source_fingerprint_hint'), 12).lower()
        if not FINGERPRINT_HINT_RE.fullmatch(target_source_hint) or not FINGERPRINT_HINT_RE.fullmatch(shared_source_hint):
            raw = b''
            raise RuntimeError('group_target_source_hint_invalid|Ο Broker δεν επέστρεψε έγκυρα target/shared source hints.')
        if not secrets.compare_digest(target_source_hint, _safe_str(preflight.get('target_source_fingerprint_hint'), 12).lower()) or not secrets.compare_digest(shared_source_hint, _safe_str(preflight.get('shared_source_fingerprint_hint'), 12).lower()):
            raw = b''
            raise RuntimeError('group_target_source_hint_mismatch|Τα target/shared source hints άλλαξαν μετά το migration preflight.')
        if secrets.compare_digest(target_source_hint, shared_source_hint):
            raw = b''
            raise RuntimeError('group_target_sources_not_distinct|Το target source δεν είναι διαφορετικό από το shared runtime source.')

        state = {
            'status':'verified', 'verified':True, 'checked_at':now_ts(),
            'installation_id':identity['installation_id'], 'node_id':identity['node_id'],
            'client_version':VERSION, 'architecture':ARCH, 'target_group_name':expected_group,
            'target_mesh_id_hint':mesh_id_hint, 'target_binding_hint':binding_hint,
            'target_source_fingerprint_hint':target_source_hint, 'shared_source_fingerprint_hint':shared_source_hint,
            'expected_agent_label':expected_label, 'mesh_server_host':mesh_server_host,
            'sha256_hint':actual_sha[:12], 'bytes':len(raw), 'target_msh_memory_only':True,
            'runtime_source_switch':False, 'node_move':False, 'identity_binding_commit':False,
            'meshagent_execution':False, 'technician_actions_authorized':False,
            'error_code':'', 'error_message':'',
        }
        save_group_migration_target_settings_state(state)
        material = {
            'raw': raw, 'fields': fields, 'agent_label': expected_label, 'sha256': actual_sha, 'bytes': len(raw),
            'target_group_name': expected_group, 'target_mesh_id_hint': mesh_id_hint, 'target_binding_hint': binding_hint,
            'target_source_fingerprint_hint': target_source_hint, 'shared_source_fingerprint_hint': shared_source_hint,
            'mesh_server_host': mesh_server_host,
        }
        print(f"[managed] target group settings VERIFIED for {identity['installation_id']} label={expected_label} group={expected_group}; target_msh_memory_only=true runtime_source_switch=false node_move=false identity_binding_commit=false meshagent_execution=false technician_actions=false", flush=True)
        if return_material:
            encoded = ''
            return state, material
        raw = b''; encoded = ''
        return state
    except RuntimeError as exc:
        text = str(exc); code, _, message = text.partition('|')
        save_group_migration_target_settings_state({
            'status':'failed','verified':False,'checked_at':now_ts(),
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],
            'client_version':VERSION,'architecture':ARCH,
            'error_code':_safe_str(code,100),'error_message':_safe_str(message or 'Το target .msh verification απέτυχε.',300),
            'target_msh_memory_only':False,'runtime_source_switch':False,'node_move':False,
            'identity_binding_commit':False,'meshagent_execution':False,'technician_actions_authorized':False,
        })
        raise


def load_group_migration_canary_state():
    base = {
        'status':'not_run','verified':False,'started_at':0,'ended_at':0,'result_code':'','elapsed_seconds':0,
        'installation_id':'','node_id':'','client_version':'','architecture':'','target_group_name':'',
        'expected_agent_label':'','target_mesh_id_hint':'','target_binding_hint':'','target_source_fingerprint_hint':'',
        'shared_source_fingerprint_hint':'','shared_runtime_stopped':False,'stable_identity_reused':False,
        'target_meshagent_execution':False,'permanent_runtime_source_switch':False,'identity_binding_commit':False,
        'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
        'technician_actions_authorized':False,'error_code':'','error_message':'',
    }
    try:
        if not GROUP_MIGRATION_CANARY_FILE.exists(): return base
        st=GROUP_MIGRATION_CANARY_FILE.stat()
        if st.st_size<=0 or st.st_size>32768: return base
        data=json.loads(GROUP_MIGRATION_CANARY_FILE.read_text(encoding='utf-8'))
    except (OSError,UnicodeError,json.JSONDecodeError): return base
    if not isinstance(data,dict): return base
    for k in base:
        if k in data: base[k]=data[k]
    return base


def save_group_migration_canary_state(state):
    allowed=set(load_group_migration_canary_state().keys())
    payload={k:state.get(k) for k in allowed if k in state}
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    tmp=GROUP_MIGRATION_CANARY_FILE.with_suffix('.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as h:
            json.dump(payload,h,ensure_ascii=False,separators=(',',':')); h.flush(); os.fsync(h.fileno())
        os.replace(tmp,GROUP_MIGRATION_CANARY_FILE); os.chmod(GROUP_MIGRATION_CANARY_FILE,0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass


def _copy_persisted_identity_for_migration(runtime_dir, identity, target_settings):
    """Copy the exact protected meshagent.db without accepting a new binding.

    This is the single controlled migration exception: ownership + DB integrity +
    stable label are verified against persisted metadata, while the old shared
    binding hash is intentionally NOT replaced by the target binding during canary.
    """
    state=_validate_persisted_mesh_identity(identity,None)
    if state.get('state')!='ready':
        raise RuntimeError('group_canary_identity_not_ready|Η stable MeshAgent identity δεν είναι READY για migration canary.')
    expected=_safe_str(target_settings.get('agent_label'),40).upper()
    if not AGENT_LABEL_RE.fullmatch(expected) or not secrets.compare_digest(expected,state.get('agent_label') or ''):
        raise RuntimeError('group_canary_identity_label_mismatch|Το target .msh δεν συμφωνεί με το persisted stable node label.')
    rel=Path(state['runtime_relative_path'])
    target=Path(runtime_dir)/rel
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(target.parent,0o700)
    fd,size=_open_regular_nofollow(MESH_IDENTITY_DB_FILE,MAX_MESH_IDENTITY_DB_BYTES)
    tmp=target.with_name(target.name+'.migration-copy.tmp')
    try:
        outfd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            total=0; digest=hashlib.sha256()
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                total+=len(chunk)
                if total>MAX_MESH_IDENTITY_DB_BYTES:
                    raise RuntimeError('group_canary_identity_db_size|Το stable identity database ξεπέρασε το ασφαλές όριο.')
                view=memoryview(chunk)
                while view:
                    written=os.write(outfd,view)
                    if written<=0: raise RuntimeError('group_canary_identity_copy_write|Απέτυχε η ασφαλής runtime αντιγραφή της stable identity.')
                    view=view[written:]
                digest.update(chunk)
            os.fsync(outfd)
        finally: os.close(outfd)
        if total!=size or not secrets.compare_digest(digest.hexdigest(),state['db_sha256']):
            raise RuntimeError('group_canary_identity_copy_mismatch|Η runtime αντιγραφή της stable identity απέτυχε στον SHA-256 έλεγχο.')
        os.replace(tmp,target); os.chmod(target,0o600)
    finally:
        os.close(fd)
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass
    return {'generation':state['generation'],'continuity_runs':state.get('continuity_runs',0),'runtime_relative_path':str(rel),'db_sha256':state['db_sha256']}


def _migration_canary_report(identity, report_token, result_code, elapsed):
    try:
        data=broker_post('/managed/group-migration/canary/report',{
            'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret'],
            'result_code':result_code,'elapsed_seconds':max(0,min(60,int(elapsed)))})
        return data.get('success') is True and data.get('reported') is True
    except RuntimeError:
        return False


def group_migration_canary_worker():
    global MIGRATION_CANARY_WORKER_ACTIVE
    identity=load_identity(); runtime_dir=None; agent_temp=None; proc=None; report_token=''; started=now_ts(); cleanup_ok=True
    result='launch_failed'; process_started_at=0; shared_stopped=False; reused=False; target_execution=False
    rollback_requested=False; rollback_started=False; target_state={}; target_material=None
    try:
        if identity is None: raise RuntimeError('group_canary_not_paired|Απαιτείται ενεργή Managed identity πριν από migration canary.')
        if not load_unattended_control().get('enabled'):
            raise RuntimeError('group_canary_unattended_disabled|Το unattended Managed runtime πρέπει να είναι ENABLED πριν από migration canary.')
        if not read_policy().get('allowed_local'):
            raise RuntimeError('group_canary_local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει migration canary.')
        server=get_server_state()
        if server.get('authorized_server') is not True or (_as_int(server.get('valid_until')) or 0)<=now_ts():
            raise RuntimeError('group_canary_server_authorization_denied|Απαιτείται ενεργό Broker Server Authorization πριν από migration canary.')
        stable=_validate_persisted_mesh_identity(identity,None)
        if stable.get('state')!='ready': raise RuntimeError('group_canary_identity_not_ready|Η stable MeshAgent identity δεν είναι READY.')
        save_group_migration_canary_state({'status':'stopping_shared_runtime','verified':False,'started_at':started,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'expected_agent_label':stable.get('agent_label',''),'shared_runtime_stopped':False,'stable_identity_reused':False,
            'target_meshagent_execution':False,'permanent_runtime_source_switch':False,'identity_binding_commit':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
            'technician_actions_authorized':False})
        PERSISTENT_STOP_EVENT.set()
        deadline=time.monotonic()+MIGRATION_CANARY_SHARED_STOP_TIMEOUT
        while PERSISTENT_WORKER_ACTIVE and time.monotonic()<deadline: time.sleep(0.25)
        if PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('group_canary_shared_runtime_stop_failed|Το shared unattended runtime δεν τερματίστηκε μέσα στο ασφαλές χρονικό όριο.')
        shared_stopped=True

        target_state,target_material=verify_group_migration_target_settings(return_material=True)
        expected_group=f"Smart Pro Managed — {identity['installation_id']}"
        if target_state.get('verified') is not True or target_material.get('target_group_name')!=expected_group:
            raise RuntimeError('group_canary_target_not_verified|Το target .msh δεν είναι VERIFIED για το per-installation group.')
        # The generic agent-binary delivery contract is deliberately still tied to
        # a fresh ordinary Managed settings verification. Refresh that chain only
        # to authorize/verify the binary; the runtime below uses TARGET settings.
        shared_material=_execution_settings_material(identity)
        if _safe_str(shared_material.get('agent_label'),40).upper()!=target_material['agent_label']:
            raise RuntimeError('group_canary_shared_target_label_mismatch|Shared και target settings δεν συμφωνούν στο stable node label.')
        agent=_execution_agent_material(identity,shared_material); agent_temp=agent['path']
        shared_material['raw']=b''

        common={'node_id':identity['node_id'],'node_secret':identity['node_secret'],'client_version':VERSION,'architecture':ARCH}
        auth=broker_post('/managed/group-migration/canary/request',common)
        ticket=_safe_str(auth.get('canary_ticket'),90); report_token=_safe_str(auth.get('report_token'),90)
        max_runtime=min(MIGRATION_CANARY_LOCAL_MAX_RUNTIME,_as_int(auth.get('max_runtime_seconds')) or 0)
        if not (auth.get('success') is True and auth.get('phase')=='per_installation_group_migration_canary_request'
                and auth.get('contract_id')=='smart-pro-managed-group-migration-canary-v1' and _as_int(auth.get('schema_version'))==1
                and MIGRATION_CANARY_TICKET_RE.fullmatch(ticket) and MIGRATION_CANARY_REPORT_RE.fullmatch(report_token)
                and auth.get('foreground_only') is True and auth.get('stable_identity_reuse_required') is True
                and auth.get('shared_runtime_stop_required') is True and auth.get('permanent_runtime_source_switch') is False
                and auth.get('identity_binding_commit') is False and auth.get('technician_actions_authorized') is False
                and auth.get('remote_access') is False and 20<=max_runtime<=MIGRATION_CANARY_LOCAL_MAX_RUNTIME
                and _safe_str(auth.get('target_group_name'),200)==expected_group
                and _safe_str(auth.get('expected_agent_label'),80).upper()==target_material['agent_label']):
            raise RuntimeError('group_canary_authorization_invalid|Ο Broker δεν επέστρεψε έγκυρο controlled migration canary contract.')
        consume=dict(common); consume['canary_ticket']=ticket
        run=broker_post('/managed/group-migration/canary/consume',consume); ticket=''
        hard_deadline=_as_int(run.get('hard_deadline')) or 0; watch_interval=_as_int(run.get('watch_interval_seconds')) or 5
        if not (run.get('success') is True and run.get('phase')=='per_installation_group_migration_canary_consume'
                and run.get('contract_id')=='smart-pro-managed-group-migration-canary-v1'
                and run.get('temporary_target_group_connectivity') is True and run.get('foreground_only') is True
                and run.get('stable_identity_reuse_required') is True and run.get('permanent_runtime_source_switch') is False
                and run.get('identity_binding_commit') is False and run.get('technician_actions_authorized') is False
                and run.get('remote_access') is False and hard_deadline>now_ts()):
            raise RuntimeError('group_canary_consume_invalid|Η controlled migration canary authorization δεν καταναλώθηκε σωστά.')
        max_runtime=min(max_runtime,_as_int(run.get('max_runtime_seconds')) or max_runtime)

        runtime_dir=Path(tempfile.mkdtemp(prefix='smart-pro-managed-group-migration-canary-',dir='/tmp')); os.chmod(runtime_dir,0o700)
        agent_path=runtime_dir/'meshagent'; shutil.move(agent_temp,agent_path); agent_temp=None; os.chmod(agent_path,0o700)
        msh_path=runtime_dir/'meshagent.msh'; hardened=_harden_runtime_msh(target_material['raw'],target_material['agent_label'])
        fd=os.open(msh_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as h: h.write(hardened); h.flush(); os.fsync(h.fileno())
        private=runtime_dir/'private'; private.mkdir(mode=0o700)
        prepared=_copy_persisted_identity_for_migration(runtime_dir,identity,target_material); reused=True
        env=os.environ.copy(); env.update({'HOME':str(private),'TMPDIR':str(private),'XDG_CONFIG_HOME':str(private),'XDG_CACHE_HOME':str(private)})
        process_started_at=now_ts()
        save_group_migration_canary_state({'status':'running','verified':False,'started_at':process_started_at,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'target_group_name':expected_group,'expected_agent_label':target_material['agent_label'],
            'target_mesh_id_hint':target_material['target_mesh_id_hint'],'target_binding_hint':target_material['target_binding_hint'],
            'target_source_fingerprint_hint':target_material['target_source_fingerprint_hint'],'shared_source_fingerprint_hint':target_material['shared_source_fingerprint_hint'],
            'shared_runtime_stopped':True,'stable_identity_reused':True,'target_meshagent_execution':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'rollback_shared_runtime_requested':False,
            'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,'technician_actions_authorized':False})
        proc=subprocess.Popen(['setsid','./meshagent'],cwd=str(runtime_dir),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              env=env,close_fds=True); target_execution=True
        run_started=time.monotonic(); result='runtime_limit'
        hard_stop_mono=run_started+min(max_runtime,max(0,hard_deadline-now_ts()))
        graceful=max(run_started,hard_stop_mono-CANARY_SHUTDOWN_GRACE)
        print(f"[managed] migration canary target runtime started for {identity['installation_id']} label={target_material['agent_label']} group={expected_group} identity=reuse; permanent_commit=false technician_actions=false",flush=True)
        while True:
            if proc.poll() is not None: result='agent_exit'; break
            if time.monotonic()>=graceful or now_ts()>=max(0,hard_deadline-CANARY_SHUTDOWN_GRACE): result='runtime_limit'; break
            if not read_policy().get('allowed_local'): result='server_authorization_lost'; break
            watch=broker_post('/managed/group-migration/canary/watch',{'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
            if watch.get('continue') is not True:
                result='runtime_limit' if _safe_str(watch.get('reason'),80)=='canary_runtime_limit' else 'server_authorization_lost'; break
            time.sleep(min(max(1,min(5,watch_interval)),max(0.2,graceful-time.monotonic())))
        _terminate_process_group_before(proc,hard_stop_mono); proc=None
        elapsed=max(0,int(time.monotonic()-run_started))
        report_ok=_migration_canary_report(identity,report_token,result,elapsed); report_token=''
        canary_verified = bool(report_ok and result == 'runtime_limit')
        save_group_migration_canary_state({'status':'reported' if canary_verified else 'failed','verified':canary_verified,'started_at':process_started_at,'ended_at':now_ts(),
            'result_code':result,'elapsed_seconds':elapsed,'installation_id':identity['installation_id'],'node_id':identity['node_id'],
            'client_version':VERSION,'architecture':ARCH,'target_group_name':expected_group,'expected_agent_label':target_material['agent_label'],
            'target_mesh_id_hint':target_material['target_mesh_id_hint'],'target_binding_hint':target_material['target_binding_hint'],
            'target_source_fingerprint_hint':target_material['target_source_fingerprint_hint'],'shared_source_fingerprint_hint':target_material['shared_source_fingerprint_hint'],
            'shared_runtime_stopped':True,'stable_identity_reused':True,'target_meshagent_execution':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'rollback_shared_runtime_requested':False,
            'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,'technician_actions_authorized':False})
        print(f"[managed] migration canary target runtime stopped result={result} reported={str(report_ok).lower()} verified={str(canary_verified).lower()} elapsed={elapsed}s; identity_binding_commit=false permanent_runtime_source_switch=false",flush=True)
    except (RuntimeError,OSError,subprocess.SubprocessError) as exc:
        if proc is not None: _terminate_process_group(proc); proc=None
        elapsed=max(0,now_ts()-started); text=str(exc); code,_,message=text.partition('|')
        if not code: code='group_canary_failed'
        if report_token: _migration_canary_report(identity,report_token,'launch_failed',elapsed); report_token=''
        save_group_migration_canary_state({'status':'failed','verified':False,'started_at':started,'ended_at':now_ts(),'result_code':code,'elapsed_seconds':elapsed,
            'installation_id':(identity or {}).get('installation_id',''),'node_id':(identity or {}).get('node_id',''),'client_version':VERSION,'architecture':ARCH,
            'target_group_name':(target_material or {}).get('target_group_name',''),'expected_agent_label':(target_material or {}).get('agent_label',''),
            'shared_runtime_stopped':shared_stopped,'stable_identity_reused':reused,'target_meshagent_execution':target_execution,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'rollback_shared_runtime_requested':False,
            'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,'technician_actions_authorized':False,
            'error_code':_safe_str(code,100),'error_message':_safe_str(message or text,300)})
        print(f"[managed] migration canary failed code={code}; permanent binding/source unchanged",flush=True)
    finally:
        if proc is not None: _terminate_process_group(proc)
        if agent_temp:
            try: Path(agent_temp).unlink(missing_ok=True)
            except OSError: cleanup_ok=False
        if runtime_dir:
            try: shutil.rmtree(runtime_dir)
            except OSError: cleanup_ok=False
        st=load_group_migration_canary_state(); st['runtime_directory_deleted']=cleanup_ok; save_group_migration_canary_state(st)
        if target_material is not None:
            try: target_material['raw']=b''
            except Exception: pass
        with MIGRATION_CANARY_WORKER_LOCK: MIGRATION_CANARY_WORKER_ACTIVE=False
        # Roll back to the already-proven shared runtime. This does not change the
        # persisted binding; it merely restarts the normal unattended path.
        control=load_unattended_control(); local=read_policy(); server=get_server_state()
        if control.get('enabled') and local.get('allowed_local') and server.get('authorized_server') is True and (_as_int(server.get('valid_until')) or 0)>now_ts():
            rollback_requested=True
            st=load_group_migration_canary_state(); st['rollback_shared_runtime_requested']=True; save_group_migration_canary_state(st)
            try:
                if not PERSISTENT_WORKER_ACTIVE: start_persistent_runtime()
                rollback_started=True
            except RuntimeError:
                rollback_started=bool(PERSISTENT_WORKER_ACTIVE)
            st=load_group_migration_canary_state(); st['rollback_shared_runtime_started']=rollback_started; save_group_migration_canary_state(st)
            print(f"[managed] migration canary rollback to shared unattended runtime requested={str(rollback_requested).lower()} started={str(rollback_started).lower()}",flush=True)


def start_group_migration_canary():
    global MIGRATION_CANARY_WORKER_ACTIVE
    with MIGRATION_CANARY_WORKER_LOCK:
        if MIGRATION_CANARY_WORKER_ACTIVE:
            raise RuntimeError('group_canary_already_running|Υπάρχει ήδη controlled migration canary σε εξέλιξη.')
        if CANARY_WORKER_ACTIVE:
            raise RuntimeError('group_canary_identity_canary_active|Υπάρχει ήδη identity canary σε εξέλιξη.')
        if not PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('group_canary_shared_runtime_not_running|Το shared unattended runtime πρέπει να είναι RUNNING πριν από το migration canary.')
        MIGRATION_CANARY_WORKER_ACTIVE=True
    t=threading.Thread(target=group_migration_canary_worker,name='managed-group-migration-canary',daemon=True); t.start()


def load_group_identity_reseed_state():
    base = {'status':'not_run','verified':False,'candidate_identity_persisted':False,'candidate_db_sha256_hint':'',
            'existing_identity_preserved':True,'permanent_runtime_source_switch':False,'identity_binding_commit':False,
            'old_meshcentral_node_delete':False,'technician_actions_authorized':False,'runtime_directory_deleted':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False}
    try:
        if not GROUP_IDENTITY_RESEED_FILE.exists(): return base
        st=os.lstat(GROUP_IDENTITY_RESEED_FILE)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size<=0 or st.st_size>32768: return base
        data=json.loads(GROUP_IDENTITY_RESEED_FILE.read_text(encoding='utf-8'))
        if not isinstance(data,dict): return base
        base.update(data); return base
    except (OSError,UnicodeError,json.JSONDecodeError): return base


def save_group_identity_reseed_state(state):
    payload=dict(state) if isinstance(state,dict) else {}
    payload['schema_version']=1; payload['updated_at']=now_ts()
    # Never persist raw Broker tokens, .msh or MeshAgent bytes.
    for forbidden in ('reseed_ticket','report_token','node_secret','raw_msh','meshagent_binary'):
        payload.pop(forbidden,None)
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    tmp=GROUP_IDENTITY_RESEED_FILE.with_suffix('.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as h:
            json.dump(payload,h,ensure_ascii=False,separators=(',',':')); h.flush(); os.fsync(h.fileno())
        os.replace(tmp,GROUP_IDENTITY_RESEED_FILE); os.chmod(GROUP_IDENTITY_RESEED_FILE,0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass


def _candidate_quarantine_exists():
    return (MESH_CANDIDATE_DB_FILE.exists() or MESH_CANDIDATE_DB_FILE.is_symlink()
            or MESH_CANDIDATE_META_FILE.exists() or MESH_CANDIDATE_META_FILE.is_symlink())


def _secure_candidate_dir():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    if MESH_CANDIDATE_DIR.exists() or MESH_CANDIDATE_DIR.is_symlink():
        st=os.lstat(MESH_CANDIDATE_DIR)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise RuntimeError('reseed_candidate_dir_invalid|Ο χώρος quarantine της candidate identity δεν είναι ασφαλής κατάλογος.')
    else:
        MESH_CANDIDATE_DIR.mkdir(mode=0o700)
    os.chmod(MESH_CANDIDATE_DIR,0o700)


def _persist_candidate_identity(runtime_dir, identity, target_settings, stable_before):
    """Persist ONE fresh target-group identity separately; never touch the active stable identity."""
    if _candidate_quarantine_exists():
        raise RuntimeError('reseed_candidate_already_exists|Υπάρχει ήδη quarantined candidate identity. Δεν επιτρέπεται νέο reseed πριν αξιολογηθεί η υπάρχουσα candidate.')
    db_path,relative_path=_find_runtime_mesh_identity_db(runtime_dir)
    fd,size=_open_regular_nofollow(db_path,MAX_MESH_IDENTITY_DB_BYTES)
    tmp_db=None; tmp_meta=None
    try:
        db_sha,db_bytes=_sha256_fd(fd,MAX_MESH_IDENTITY_DB_BYTES)
        _secure_candidate_dir()
        tmp_db=MESH_CANDIDATE_DIR / ('.meshagent.db.'+secrets.token_hex(6)+'.tmp')
        outfd=os.open(tmp_db,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            total=0
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                total+=len(chunk)
                if total>MAX_MESH_IDENTITY_DB_BYTES:
                    raise RuntimeError('reseed_candidate_db_size|Η candidate identity database ξεπέρασε το ασφαλές όριο.')
                view=memoryview(chunk)
                while view:
                    written=os.write(outfd,view)
                    if written<=0: raise RuntimeError('reseed_candidate_write_failed|Απέτυχε η ασφαλής αποθήκευση της candidate identity.')
                    view=view[written:]
            os.fsync(outfd)
        finally: os.close(outfd)
        if total!=db_bytes:
            raise RuntimeError('reseed_candidate_copy_short|Δεν αντιγράφηκε ολόκληρη η candidate identity database.')
        # Prove the active identity is still byte-identical before creating candidate metadata.
        stable_after=_validate_persisted_mesh_identity(identity,None)
        if stable_after.get('state')!='ready' or not secrets.compare_digest(stable_after.get('db_sha256',''),stable_before.get('db_sha256','')):
            raise RuntimeError('reseed_active_identity_changed|Η υπάρχουσα stable identity άλλαξε κατά το reseed canary. Η candidate δεν γίνεται αποδεκτή.')
        os.replace(tmp_db,MESH_CANDIDATE_DB_FILE); os.chmod(MESH_CANDIDATE_DB_FILE,0o600); tmp_db=None
        binding_sha=_mesh_identity_binding_hash(identity,target_settings)
        meta={
            'schema_version':1,'status':'quarantined','active':False,'installation_id':identity['installation_id'],
            'broker_node_id':identity['node_id'],'architecture':ARCH,'agent_label':_safe_str(target_settings.get('agent_label'),40).upper(),
            'target_group_name':_safe_str(target_settings.get('target_group_name'),200),
            'target_mesh_id_hint':_safe_str(target_settings.get('target_mesh_id_hint'),20),
            'target_binding_hint':_safe_str(target_settings.get('target_binding_hint'),20),
            'target_source_fingerprint_hint':_safe_str(target_settings.get('target_source_fingerprint_hint'),20),
            'shared_source_fingerprint_hint':_safe_str(target_settings.get('shared_source_fingerprint_hint'),20),
            'binding_sha256':binding_sha,'db_sha256':db_sha,'db_bytes':db_bytes,'runtime_relative_path':relative_path,
            'seeded_at':now_ts(),'candidate_generation':1,'existing_identity_db_sha256':stable_before.get('db_sha256',''),
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
            'service_persistence':False,'technician_actions_authorized':False,
        }
        tmp_meta=MESH_CANDIDATE_DIR / ('.candidate-meta.'+secrets.token_hex(6)+'.tmp')
        mfd=os.open(tmp_meta,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            with os.fdopen(mfd,'w',encoding='utf-8') as h:
                json.dump(meta,h,ensure_ascii=False,separators=(',',':')); h.flush(); os.fsync(h.fileno())
        finally: pass
        os.replace(tmp_meta,MESH_CANDIDATE_META_FILE); os.chmod(MESH_CANDIDATE_META_FILE,0o600); tmp_meta=None
        try:
            dfd=os.open(MESH_CANDIDATE_DIR,os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except OSError: pass
        return {'db_sha256':db_sha,'db_sha256_hint':db_sha[:12],'db_bytes':db_bytes,'runtime_relative_path':relative_path,'binding_sha256':binding_sha}
    finally:
        os.close(fd)
        for p in (tmp_db,tmp_meta):
            if p:
                try: Path(p).unlink(missing_ok=True)
                except OSError: pass


def _identity_reseed_report(identity, report_token, result_code, elapsed, candidate_persisted=False, candidate_hint=''):
    try:
        data=broker_post('/managed/group-migration/reseed/report',{
            'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret'],
            'result_code':result_code,'elapsed_seconds':max(0,min(60,int(elapsed))),
            'candidate_persisted':bool(candidate_persisted),'candidate_db_sha256_hint':_safe_str(candidate_hint,20).lower()})
        return data.get('success') is True and data.get('reported') is True
    except RuntimeError:
        return False


def group_identity_reseed_worker():
    global IDENTITY_RESEED_WORKER_ACTIVE
    identity=load_identity(); runtime_dir=None; agent_temp=None; proc=None; report_token=''; started=now_ts(); cleanup_ok=True
    shared_stopped=False; candidate_execution=False; candidate_persisted=False; candidate_hint=''; rollback_requested=False; rollback_started=False
    target_material=None; result='launch_failed'; process_started_at=0; stable_before=None
    try:
        if identity is None: raise RuntimeError('reseed_not_paired|Απαιτείται ενεργή Managed identity πριν από clean reseed canary.')
        if _candidate_quarantine_exists():
            raise RuntimeError('reseed_candidate_already_exists|Υπάρχει ήδη quarantined candidate identity. Σταματήστε και αξιολογήστε την πριν από νέο reseed.')
        if not load_unattended_control().get('enabled'):
            raise RuntimeError('reseed_unattended_disabled|Το unattended Managed runtime πρέπει να είναι ENABLED πριν από clean reseed canary.')
        if not read_policy().get('allowed_local'):
            raise RuntimeError('reseed_local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει clean reseed canary.')
        server=get_server_state()
        if server.get('authorized_server') is not True or (_as_int(server.get('valid_until')) or 0)<=now_ts():
            raise RuntimeError('reseed_server_authorization_denied|Απαιτείται ενεργό Broker Server Authorization πριν από clean reseed canary.')
        stable_before=_validate_persisted_mesh_identity(identity,None)
        if stable_before.get('state')!='ready': raise RuntimeError('reseed_existing_identity_not_ready|Η υπάρχουσα stable identity δεν είναι READY για ασφαλές rollback.')
        save_group_identity_reseed_state({'status':'stopping_shared_runtime','verified':False,'started_at':started,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'expected_agent_label':stable_before.get('agent_label',''),'shared_runtime_stopped':False,'candidate_meshagent_execution':False,
            'candidate_identity_persisted':False,'candidate_db_sha256_hint':'','existing_identity_preserved':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
            'technician_actions_authorized':False})
        PERSISTENT_STOP_EVENT.set()
        deadline=time.monotonic()+IDENTITY_RESEED_SHARED_STOP_TIMEOUT
        while PERSISTENT_WORKER_ACTIVE and time.monotonic()<deadline: time.sleep(0.25)
        if PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('shared_runtime_stop_failed|Το shared unattended runtime δεν τερματίστηκε μέσα στο ασφαλές χρονικό όριο.')
        shared_stopped=True

        target_state,target_material=verify_group_migration_target_settings(return_material=True)
        expected_group=f"Smart Pro Managed — {identity['installation_id']}"
        if target_state.get('verified') is not True or target_material.get('target_group_name')!=expected_group:
            raise RuntimeError('reseed_target_not_verified|Το target .msh δεν είναι VERIFIED για το per-installation group.')
        if _safe_str(target_material.get('agent_label'),40).upper()!=stable_before.get('agent_label',''):
            raise RuntimeError('reseed_target_label_mismatch|Το target .msh δεν συμφωνεί με το προβλεπόμενο SPMNG label.')
        # Binary delivery remains authorized through the ordinary verified Managed chain; candidate runtime uses TARGET settings.
        shared_material=_execution_settings_material(identity)
        if _safe_str(shared_material.get('agent_label'),40).upper()!=target_material['agent_label']:
            raise RuntimeError('reseed_shared_target_label_mismatch|Shared και target settings δεν συμφωνούν στο Managed label.')
        agent=_execution_agent_material(identity,shared_material); agent_temp=agent['path']; shared_material['raw']=b''

        common={'node_id':identity['node_id'],'node_secret':identity['node_secret'],'client_version':VERSION,'architecture':ARCH}
        auth=broker_post('/managed/group-migration/reseed/request',common)
        ticket=_safe_str(auth.get('reseed_ticket'),90); report_token=_safe_str(auth.get('report_token'),90)
        max_runtime=min(IDENTITY_RESEED_LOCAL_MAX_RUNTIME,_as_int(auth.get('max_runtime_seconds')) or 0)
        if not (auth.get('success') is True and auth.get('phase')=='per_installation_group_identity_reseed_request'
                and auth.get('contract_id')=='smart-pro-managed-group-identity-reseed-canary-v1' and _as_int(auth.get('schema_version'))==1
                and IDENTITY_RESEED_TICKET_RE.fullmatch(ticket) and IDENTITY_RESEED_REPORT_RE.fullmatch(report_token)
                and auth.get('foreground_only') is True and auth.get('shared_runtime_stop_required') is True
                and auth.get('existing_identity_preserved') is True and auth.get('candidate_identity_seed_required') is True
                and auth.get('candidate_identity_quarantine_required') is True and auth.get('rollback_shared_runtime_required') is True
                and auth.get('old_meshcentral_node_delete') is False and auth.get('permanent_runtime_source_switch') is False
                and auth.get('identity_binding_commit') is False and auth.get('technician_actions_authorized') is False
                and auth.get('remote_access') is False and 20<=max_runtime<=IDENTITY_RESEED_LOCAL_MAX_RUNTIME
                and _safe_str(auth.get('target_group_name'),200)==expected_group
                and _safe_str(auth.get('expected_agent_label'),80).upper()==target_material['agent_label']):
            raise RuntimeError('reseed_authorization_invalid|Ο Broker δεν επέστρεψε έγκυρο clean identity reseed contract.')
        consume=dict(common); consume['reseed_ticket']=ticket
        run=broker_post('/managed/group-migration/reseed/consume',consume); ticket=''
        hard_deadline=_as_int(run.get('hard_deadline')) or 0; watch_interval=_as_int(run.get('watch_interval_seconds')) or 5
        if not (run.get('success') is True and run.get('phase')=='per_installation_group_identity_reseed_consume'
                and run.get('contract_id')=='smart-pro-managed-group-identity-reseed-canary-v1'
                and run.get('foreground_only') is True and run.get('shared_runtime_stopped_by_client') is True
                and run.get('existing_identity_preserved') is True and run.get('candidate_identity_seed_required') is True
                and run.get('candidate_identity_quarantine_required') is True and run.get('rollback_shared_runtime_required') is True
                and run.get('old_meshcentral_node_delete') is False and run.get('permanent_runtime_source_switch') is False
                and run.get('identity_binding_commit') is False and run.get('technician_actions_authorized') is False
                and run.get('remote_access') is False and hard_deadline>now_ts()):
            raise RuntimeError('reseed_consume_invalid|Η clean identity reseed authorization δεν καταναλώθηκε σωστά.')
        max_runtime=min(max_runtime,_as_int(run.get('max_runtime_seconds')) or max_runtime)

        runtime_dir=Path(tempfile.mkdtemp(prefix='smart-pro-managed-clean-reseed-canary-',dir='/tmp')); os.chmod(runtime_dir,0o700)
        agent_path=runtime_dir/'meshagent'; shutil.move(agent_temp,agent_path); agent_temp=None; os.chmod(agent_path,0o700)
        msh_path=runtime_dir/'meshagent.msh'; hardened=_harden_runtime_msh(target_material['raw'],target_material['agent_label'])
        fd=os.open(msh_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as h: h.write(hardened); h.flush(); os.fsync(h.fileno())
        private=runtime_dir/'private'; private.mkdir(mode=0o700)
        # CRITICAL: DO NOT copy the active meshagent.db. Candidate must seed fresh against target group.
        env=os.environ.copy(); env.update({'HOME':str(private),'TMPDIR':str(private),'XDG_CONFIG_HOME':str(private),'XDG_CACHE_HOME':str(private)})
        process_started_at=now_ts()
        save_group_identity_reseed_state({'status':'running','verified':False,'started_at':process_started_at,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'target_group_name':expected_group,'expected_agent_label':target_material['agent_label'],
            'target_mesh_id_hint':target_material['target_mesh_id_hint'],'target_binding_hint':target_material['target_binding_hint'],
            'target_source_fingerprint_hint':target_material['target_source_fingerprint_hint'],'shared_source_fingerprint_hint':target_material['shared_source_fingerprint_hint'],
            'shared_runtime_stopped':True,'candidate_meshagent_execution':True,'candidate_identity_persisted':False,
            'candidate_db_sha256_hint':'','existing_identity_preserved':True,'permanent_runtime_source_switch':False,
            'identity_binding_commit':False,'old_meshcentral_node_delete':False,'rollback_shared_runtime_requested':False,
            'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,'technician_actions_authorized':False})
        proc=subprocess.Popen(['setsid','./meshagent'],cwd=str(runtime_dir),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              env=env,close_fds=True); candidate_execution=True
        run_started=time.monotonic(); result='runtime_limit'
        hard_stop_mono=run_started+min(max_runtime,max(0,hard_deadline-now_ts()))
        graceful=max(run_started,hard_stop_mono-CANARY_SHUTDOWN_GRACE)
        print(f"[managed] clean identity reseed candidate runtime started for {identity['installation_id']} label={target_material['agent_label']} group={expected_group} identity=fresh_candidate; existing_identity_preserved=true permanent_commit=false technician_actions=false",flush=True)
        while True:
            if proc.poll() is not None: result='agent_exit'; break
            if time.monotonic()>=graceful or now_ts()>=max(0,hard_deadline-CANARY_SHUTDOWN_GRACE): result='runtime_limit'; break
            if not read_policy().get('allowed_local'): result='server_authorization_lost'; break
            watch=broker_post('/managed/group-migration/reseed/watch',{'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
            if watch.get('continue') is not True:
                result='runtime_limit' if _safe_str(watch.get('reason'),80)=='reseed_runtime_limit' else 'server_authorization_lost'; break
            time.sleep(min(max(1,min(5,watch_interval)),max(0.2,graceful-time.monotonic())))
        _terminate_process_group_before(proc,hard_stop_mono); proc=None
        elapsed=max(0,int(time.monotonic()-run_started))
        if result in ('runtime_limit','agent_exit'):
            try:
                candidate=_persist_candidate_identity(runtime_dir,identity,target_material,stable_before)
                candidate_persisted=True; candidate_hint=candidate['db_sha256_hint']
            except RuntimeError as exc:
                result='candidate_identity_missing' if 'runtime_db_missing' in str(exc) else 'candidate_identity_invalid'
                raise
        report_ok=_identity_reseed_report(identity,report_token,result,elapsed,candidate_persisted,candidate_hint); report_token=''
        verified=bool(report_ok and result=='runtime_limit' and candidate_persisted)
        save_group_identity_reseed_state({'status':'reported' if verified else 'failed','verified':verified,'started_at':process_started_at,'ended_at':now_ts(),
            'result_code':result,'elapsed_seconds':elapsed,'installation_id':identity['installation_id'],'node_id':identity['node_id'],
            'client_version':VERSION,'architecture':ARCH,'target_group_name':expected_group,'expected_agent_label':target_material['agent_label'],
            'target_mesh_id_hint':target_material['target_mesh_id_hint'],'target_binding_hint':target_material['target_binding_hint'],
            'target_source_fingerprint_hint':target_material['target_source_fingerprint_hint'],'shared_source_fingerprint_hint':target_material['shared_source_fingerprint_hint'],
            'shared_runtime_stopped':True,'candidate_meshagent_execution':True,'candidate_identity_persisted':candidate_persisted,
            'candidate_db_sha256_hint':candidate_hint,'existing_identity_preserved':True,'permanent_runtime_source_switch':False,
            'identity_binding_commit':False,'old_meshcentral_node_delete':False,'rollback_shared_runtime_requested':False,
            'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,'technician_actions_authorized':False})
        print(f"[managed] clean identity reseed candidate runtime stopped result={result} reported={str(report_ok).lower()} verified={str(verified).lower()} elapsed={elapsed}s candidate_persisted={str(candidate_persisted).lower()} candidate_db_hint={candidate_hint or '-'}; existing_identity_preserved=true identity_binding_commit=false permanent_runtime_source_switch=false",flush=True)
    except (RuntimeError,OSError,subprocess.SubprocessError) as exc:
        if proc is not None: _terminate_process_group(proc); proc=None
        elapsed=max(0,now_ts()-started); text=str(exc); code,_,message=text.partition('|')
        if not code: code='reseed_failed'
        allowed_result='candidate_identity_missing' if 'candidate_identity_missing' in code or 'runtime_db_missing' in code else 'candidate_identity_invalid' if code.startswith('reseed_candidate') else 'launch_failed'
        if report_token: _identity_reseed_report(identity,report_token,allowed_result,elapsed,candidate_persisted,candidate_hint); report_token=''
        save_group_identity_reseed_state({'status':'failed','verified':False,'started_at':started,'ended_at':now_ts(),'result_code':code,'elapsed_seconds':elapsed,
            'installation_id':(identity or {}).get('installation_id',''),'node_id':(identity or {}).get('node_id',''),'client_version':VERSION,'architecture':ARCH,
            'target_group_name':(target_material or {}).get('target_group_name',''),'expected_agent_label':(target_material or {}).get('agent_label',''),
            'shared_runtime_stopped':shared_stopped,'candidate_meshagent_execution':candidate_execution,'candidate_identity_persisted':candidate_persisted,
            'candidate_db_sha256_hint':candidate_hint,'existing_identity_preserved':True,'permanent_runtime_source_switch':False,
            'identity_binding_commit':False,'old_meshcentral_node_delete':False,'rollback_shared_runtime_requested':False,
            'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,'technician_actions_authorized':False,
            'error_code':_safe_str(code,100),'error_message':_safe_str(message or text,300)})
        print(f"[managed] clean identity reseed canary failed code={code}; existing identity preserved; permanent binding/source unchanged",flush=True)
    finally:
        if proc is not None: _terminate_process_group(proc)
        if agent_temp:
            try: Path(agent_temp).unlink(missing_ok=True)
            except OSError: cleanup_ok=False
        if runtime_dir:
            try: shutil.rmtree(runtime_dir)
            except OSError: cleanup_ok=False
        st=load_group_identity_reseed_state(); st['runtime_directory_deleted']=cleanup_ok; save_group_identity_reseed_state(st)
        if target_material is not None:
            try: target_material['raw']=b''
            except Exception: pass
        with IDENTITY_RESEED_WORKER_LOCK: IDENTITY_RESEED_WORKER_ACTIVE=False
        control=load_unattended_control(); local=read_policy(); server=get_server_state()
        if control.get('enabled') and local.get('allowed_local') and server.get('authorized_server') is True and (_as_int(server.get('valid_until')) or 0)>now_ts():
            rollback_requested=True
            st=load_group_identity_reseed_state(); st['rollback_shared_runtime_requested']=True; save_group_identity_reseed_state(st)
            try:
                if not PERSISTENT_WORKER_ACTIVE: start_persistent_runtime()
                rollback_started=True
            except RuntimeError:
                rollback_started=bool(PERSISTENT_WORKER_ACTIVE)
            st=load_group_identity_reseed_state(); st['rollback_shared_runtime_started']=rollback_started; save_group_identity_reseed_state(st)
            print(f"[managed] clean identity reseed rollback to shared unattended runtime requested={str(rollback_requested).lower()} started={str(rollback_started).lower()}",flush=True)


def start_group_identity_reseed_canary():
    global IDENTITY_RESEED_WORKER_ACTIVE
    with IDENTITY_RESEED_WORKER_LOCK:
        if IDENTITY_RESEED_WORKER_ACTIVE:
            raise RuntimeError('reseed_already_running|Υπάρχει ήδη clean identity reseed canary σε εξέλιξη.')
        if MIGRATION_CANARY_WORKER_ACTIVE or CANARY_WORKER_ACTIVE:
            raise RuntimeError('reseed_other_canary_active|Υπάρχει ήδη άλλο Managed canary σε εξέλιξη.')
        if _candidate_quarantine_exists():
            raise RuntimeError('reseed_candidate_already_exists|Υπάρχει ήδη quarantined candidate identity. Δεν επιτρέπεται δεύτερη candidate.')
        if not PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('reseed_shared_runtime_not_running|Το shared unattended runtime πρέπει να είναι RUNNING πριν από clean reseed canary.')
        IDENTITY_RESEED_WORKER_ACTIVE=True
    t=threading.Thread(target=group_identity_reseed_worker,name='managed-group-identity-reseed-canary',daemon=True); t.start()


def load_candidate_reconnect_state():
    base = {
        'status':'not_run','verified':False,'started_at':0,'ended_at':0,'result_code':'','elapsed_seconds':0,
        'installation_id':'','node_id':'','client_version':'','architecture':'','target_group_name':'',
        'expected_agent_label':'','candidate_db_sha256_hint':'','candidate_node_hint':'','candidate_seen_online':False,
        'shared_runtime_stopped':False,'candidate_meshagent_execution':False,'existing_stable_identity_preserved':True,
        'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
        'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
        'technician_actions_authorized':False,'error_code':'','error_message':'',
    }
    try:
        if not CANDIDATE_RECONNECT_FILE.exists():
            return base
        st = os.lstat(CANDIDATE_RECONNECT_FILE)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > 32768:
            return base
        data = json.loads(CANDIDATE_RECONNECT_FILE.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            base.update(data)
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    return base


def save_candidate_reconnect_state(state):
    allowed=set(load_candidate_reconnect_state().keys())
    payload={k:state.get(k) for k in allowed if k in state}
    payload['schema_version']=1
    payload['updated_at']=now_ts()
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    tmp=CANDIDATE_RECONNECT_FILE.with_suffix('.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as h:
            json.dump(payload,h,ensure_ascii=False,separators=(',',':'))
            h.flush(); os.fsync(h.fileno())
        os.replace(tmp,CANDIDATE_RECONNECT_FILE); os.chmod(CANDIDATE_RECONNECT_FILE,0o600)
    finally:
        try:
            if tmp.exists(): tmp.unlink()
        except OSError:
            pass


def _read_candidate_meta_secure():
    if not MESH_CANDIDATE_META_FILE.exists() or MESH_CANDIDATE_META_FILE.is_symlink():
        raise RuntimeError('candidate_reconnect_meta_missing|Λείπει το quarantined candidate metadata.')
    st=os.lstat(MESH_CANDIDATE_META_FILE)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_size<=0 or st.st_size>32768:
        raise RuntimeError('candidate_reconnect_meta_invalid|Το quarantined candidate metadata δεν έχει ασφαλή μορφή.')
    try:
        data=json.loads(MESH_CANDIDATE_META_FILE.read_text(encoding='utf-8'))
    except (OSError,UnicodeError,json.JSONDecodeError) as exc:
        raise RuntimeError('candidate_reconnect_meta_unreadable|Δεν ήταν δυνατή η ασφαλής ανάγνωση του candidate metadata.') from exc
    if not isinstance(data,dict):
        raise RuntimeError('candidate_reconnect_meta_invalid|Το candidate metadata δεν έχει έγκυρη μορφή.')
    return data


def _validate_candidate_quarantine_for_reconnect(identity,target_material):
    if not _candidate_quarantine_exists():
        raise RuntimeError('candidate_reconnect_quarantine_missing|Δεν υπάρχει quarantined candidate identity.')
    meta=_read_candidate_meta_secure()
    if _safe_str(meta.get('status'),40)!='quarantined' or meta.get('active') is not False:
        raise RuntimeError('candidate_reconnect_quarantine_state|Η candidate δεν βρίσκεται σε ασφαλή quarantined κατάσταση.')
    if (_safe_str(meta.get('installation_id'),100).upper()!=identity['installation_id']
            or _safe_str(meta.get('broker_node_id'),64).upper()!=identity['node_id']
            or _safe_str(meta.get('architecture'),20)!=ARCH):
        raise RuntimeError('candidate_reconnect_owner_mismatch|Η quarantined candidate ανήκει σε διαφορετική εγκατάσταση/Managed identity.')
    expected_group=f"Smart Pro Managed — {identity['installation_id']}"
    if _safe_str(meta.get('target_group_name'),200)!=expected_group or _safe_str(target_material.get('target_group_name'),200)!=expected_group:
        raise RuntimeError('candidate_reconnect_group_mismatch|Η candidate ή το target .msh δεν αντιστοιχούν στο per-installation group.')
    expected_label=_safe_str(target_material.get('agent_label'),40).upper()
    if not AGENT_LABEL_RE.fullmatch(expected_label) or _safe_str(meta.get('agent_label'),40).upper()!=expected_label:
        raise RuntimeError('candidate_reconnect_label_mismatch|Η quarantined candidate δεν συμφωνεί με το verified target label.')
    for mk,tk in (
        ('target_mesh_id_hint','target_mesh_id_hint'),
        ('target_binding_hint','target_binding_hint'),
        ('target_source_fingerprint_hint','target_source_fingerprint_hint'),
        ('shared_source_fingerprint_hint','shared_source_fingerprint_hint'),
    ):
        if not secrets.compare_digest(_safe_str(meta.get(mk),40),_safe_str(target_material.get(tk),40)):
            raise RuntimeError('candidate_reconnect_binding_mismatch|Η quarantined candidate δεν συμφωνεί με το verified target binding.')
    stable=_validate_persisted_mesh_identity(identity,None)
    if stable.get('state')!='ready':
        raise RuntimeError('candidate_reconnect_stable_not_ready|Η υπάρχουσα stable rollback identity δεν είναι READY.')
    existing_sha=_safe_str(meta.get('existing_identity_db_sha256'),80).lower()
    if not SHA256_RE.fullmatch(existing_sha) or not secrets.compare_digest(existing_sha,stable.get('db_sha256','')):
        raise RuntimeError('candidate_reconnect_stable_changed|Η stable rollback identity άλλαξε μετά τη δημιουργία της candidate.')
    db_sha=_safe_str(meta.get('db_sha256'),80).lower()
    rel_text=_safe_str(meta.get('runtime_relative_path'),200)
    rel=Path(rel_text)
    if not SHA256_RE.fullmatch(db_sha) or not rel_text or rel.is_absolute() or '..' in rel.parts or rel.name!='meshagent.db':
        raise RuntimeError('candidate_reconnect_meta_binding_invalid|Το candidate metadata δεν περιέχει έγκυρο DB binding.')
    fd,size=_open_regular_nofollow(MESH_CANDIDATE_DB_FILE,MAX_MESH_IDENTITY_DB_BYTES)
    try:
        actual_sha,actual_size=_sha256_fd(fd,MAX_MESH_IDENTITY_DB_BYTES)
    finally:
        os.close(fd)
    if actual_size!=(_as_int(meta.get('db_bytes')) or 0) or not secrets.compare_digest(actual_sha,db_sha):
        raise RuntimeError('candidate_reconnect_db_integrity|Το quarantined candidate database απέτυχε στον έλεγχο ακεραιότητας.')
    return {
        'meta':meta,'stable':stable,'db_sha256':actual_sha,'db_sha256_hint':actual_sha[:12],
        'db_bytes':actual_size,'runtime_relative_path':rel_text,'target_group_name':expected_group,
        'agent_label':expected_label,
    }


def _copy_candidate_identity_into_runtime(runtime_dir,candidate):
    rel=Path(candidate['runtime_relative_path'])
    target=Path(runtime_dir)/rel
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(target.parent,0o700)
    fd,size=_open_regular_nofollow(MESH_CANDIDATE_DB_FILE,MAX_MESH_IDENTITY_DB_BYTES)
    tmp=target.with_name(target.name+'.candidate-reconnect.tmp')
    try:
        outfd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            total=0; digest=hashlib.sha256()
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                total+=len(chunk)
                if total>MAX_MESH_IDENTITY_DB_BYTES:
                    raise RuntimeError('candidate_reconnect_db_size|Η candidate DB ξεπέρασε το ασφαλές όριο.')
                view=memoryview(chunk)
                while view:
                    written=os.write(outfd,view)
                    if written<=0:
                        raise RuntimeError('candidate_reconnect_copy_write|Απέτυχε η αντιγραφή της candidate DB στο runtime.')
                    view=view[written:]
                digest.update(chunk)
            os.fsync(outfd)
        finally:
            os.close(outfd)
        if total!=size or not secrets.compare_digest(digest.hexdigest(),candidate['db_sha256']):
            raise RuntimeError('candidate_reconnect_copy_mismatch|Το runtime αντίγραφο της candidate DB απέτυχε στον έλεγχο ακεραιότητας.')
        os.replace(tmp,target); os.chmod(target,0o600)
    finally:
        os.close(fd)
        try:
            if tmp.exists(): tmp.unlink()
        except OSError: pass
    return target


def _candidate_reconnect_report(identity,report_token,result_code,elapsed,candidate_hint):
    try:
        data=broker_post('/managed/group-migration/candidate-reconnect/report',{
            'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret'],
            'result_code':result_code,'elapsed_seconds':max(0,min(60,int(elapsed))),
            'candidate_db_sha256_hint':candidate_hint})
        return data
    except RuntimeError:
        return {}


def candidate_reconnect_worker():
    global CANDIDATE_RECONNECT_WORKER_ACTIVE
    identity=load_identity(); runtime_dir=None; agent_temp=None; proc=None; report_token=''; started=now_ts()
    cleanup_ok=True; shared_stopped=False; candidate_execution=False; candidate_seen_online=False
    rollback_requested=False; rollback_started=False; target_material=None; result='launch_failed'; process_started_at=0
    candidate=None
    try:
        if identity is None:
            raise RuntimeError('candidate_reconnect_not_paired|Απαιτείται ενεργή Managed identity.')
        if not load_unattended_control().get('enabled'):
            raise RuntimeError('candidate_reconnect_unattended_disabled|Το unattended Managed runtime πρέπει να είναι ENABLED.')
        if not read_policy().get('allowed_local'):
            raise RuntimeError('candidate_reconnect_local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει candidate reconnect verification.')
        server=get_server_state()
        if server.get('authorized_server') is not True or (_as_int(server.get('valid_until')) or 0)<=now_ts():
            raise RuntimeError('candidate_reconnect_server_authorization_denied|Απαιτείται ενεργό Broker Server Authorization.')

        target_state,target_material=verify_group_migration_target_settings(return_material=True)
        if target_state.get('verified') is not True:
            raise RuntimeError('candidate_reconnect_target_not_verified|Το target .msh δεν είναι VERIFIED.')
        candidate=_validate_candidate_quarantine_for_reconnect(identity,target_material)

        save_candidate_reconnect_state({
            'status':'stopping_shared_runtime','verified':False,'started_at':started,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'target_group_name':candidate['target_group_name'],'expected_agent_label':candidate['agent_label'],
            'candidate_db_sha256_hint':candidate['db_sha256_hint'],'shared_runtime_stopped':False,
            'candidate_meshagent_execution':False,'candidate_seen_online':False,'existing_stable_identity_preserved':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
            'technician_actions_authorized':False})

        # Prepare a verified agent before asking the Broker to arm the reconnect.
        shared_material=_execution_settings_material(identity)
        if _safe_str(shared_material.get('agent_label'),40).upper()!=candidate['agent_label']:
            raise RuntimeError('candidate_reconnect_shared_label_mismatch|Shared και target settings δεν συμφωνούν στο Managed label.')
        agent=_execution_agent_material(identity,shared_material); agent_temp=agent['path']; shared_material['raw']=b''

        common={'node_id':identity['node_id'],'node_secret':identity['node_secret'],'client_version':VERSION,
                'architecture':ARCH,'candidate_db_sha256_hint':candidate['db_sha256_hint']}
        auth=broker_post('/managed/group-migration/candidate-reconnect/request',common)
        ticket=_safe_str(auth.get('candidate_reconnect_ticket'),100)
        report_token=_safe_str(auth.get('report_token'),100)
        max_runtime=min(CANDIDATE_RECONNECT_LOCAL_MAX_RUNTIME,_as_int(auth.get('max_runtime_seconds')) or CANDIDATE_RECONNECT_LOCAL_MAX_RUNTIME)
        if not (
            auth.get('success') is True and auth.get('phase')=='candidate_reconnect_request'
            and auth.get('contract_id')=='smart-pro-managed-candidate-reconnect-v1' and _as_int(auth.get('schema_version'))==1
            and CANDIDATE_RECONNECT_TICKET_RE.fullmatch(ticket) and CANDIDATE_RECONNECT_REPORT_RE.fullmatch(report_token)
            and auth.get('candidate_identity_reuse_required') is True and auth.get('candidate_quarantine_required') is True
            and auth.get('shared_runtime_stop_required') is True and auth.get('permanent_runtime_source_switch') is False
            and auth.get('identity_binding_commit') is False and auth.get('old_meshcentral_node_delete') is False
            and auth.get('technician_actions_authorized') is False and auth.get('remote_access') is False
            and _safe_str(auth.get('target_group_name'),200)==candidate['target_group_name']
            and _safe_str(auth.get('expected_agent_label'),80).upper()==candidate['agent_label']
            and secrets.compare_digest(_safe_str(auth.get('candidate_db_sha256_hint'),20),candidate['db_sha256_hint'])
        ):
            raise RuntimeError('candidate_reconnect_authorization_invalid|Ο Broker δεν επέστρεψε έγκυρο candidate reconnect contract.')

        PERSISTENT_STOP_EVENT.set()
        deadline=time.monotonic()+CANDIDATE_RECONNECT_SHARED_STOP_TIMEOUT
        while PERSISTENT_WORKER_ACTIVE and time.monotonic()<deadline:
            time.sleep(0.25)
        if PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('candidate_reconnect_shared_stop_failed|Το shared unattended runtime δεν τερματίστηκε εγκαίρως.')
        shared_stopped=True

        consume=dict(common); consume['candidate_reconnect_ticket']=ticket
        run=broker_post('/managed/group-migration/candidate-reconnect/consume',consume); ticket=''
        hard_deadline=_as_int(run.get('hard_deadline')) or 0
        watch_interval=_as_int(run.get('watch_interval_seconds')) or 5
        max_runtime=min(CANDIDATE_RECONNECT_LOCAL_MAX_RUNTIME,_as_int(run.get('max_runtime_seconds')) or max_runtime)
        if not (
            run.get('success') is True and run.get('phase')=='candidate_reconnect_consume'
            and run.get('contract_id')=='smart-pro-managed-candidate-reconnect-v1'
            and run.get('candidate_identity_reuse_required') is True and run.get('shared_runtime_stopped_by_client') is True
            and run.get('permanent_runtime_source_switch') is False and run.get('identity_binding_commit') is False
            and run.get('old_meshcentral_node_delete') is False and run.get('technician_actions_authorized') is False
            and run.get('remote_access') is False and hard_deadline>now_ts()
        ):
            raise RuntimeError('candidate_reconnect_consume_invalid|Το candidate reconnect authorization δεν καταναλώθηκε σωστά.')

        runtime_dir=Path(tempfile.mkdtemp(prefix='smart-pro-managed-candidate-reconnect-',dir='/tmp')); os.chmod(runtime_dir,0o700)
        agent_path=runtime_dir/'meshagent'; shutil.move(agent_temp,agent_path); agent_temp=None; os.chmod(agent_path,0o700)
        msh_path=runtime_dir/'meshagent.msh'; hardened=_harden_runtime_msh(target_material['raw'],candidate['agent_label'])
        fd=os.open(msh_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as h:
            h.write(hardened); h.flush(); os.fsync(h.fileno())
        _copy_candidate_identity_into_runtime(runtime_dir,candidate)
        private=runtime_dir/'private'; private.mkdir(mode=0o700)
        env=os.environ.copy(); env.update({'HOME':str(private),'TMPDIR':str(private),'XDG_CONFIG_HOME':str(private),'XDG_CACHE_HOME':str(private)})

        process_started_at=now_ts()
        save_candidate_reconnect_state({
            'status':'running','verified':False,'started_at':process_started_at,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'target_group_name':candidate['target_group_name'],'expected_agent_label':candidate['agent_label'],
            'candidate_db_sha256_hint':candidate['db_sha256_hint'],'shared_runtime_stopped':True,
            'candidate_meshagent_execution':True,'candidate_seen_online':False,'existing_stable_identity_preserved':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
            'technician_actions_authorized':False})

        proc=subprocess.Popen(['setsid','./meshagent'],cwd=str(runtime_dir),stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,close_fds=True)
        candidate_execution=True
        run_started=time.monotonic(); result='runtime_limit'
        hard_stop_mono=run_started+min(max_runtime,max(0,hard_deadline-now_ts()))
        graceful=max(run_started,hard_stop_mono-CANARY_SHUTDOWN_GRACE)
        print(f"[managed] quarantined candidate reconnect runtime started for {identity['installation_id']} label={candidate['agent_label']} group={candidate['target_group_name']} candidate_db_hint={candidate['db_sha256_hint']}; permanent_commit=false technician_actions=false",flush=True)

        while True:
            if proc.poll() is not None:
                result='agent_exit'; break
            if time.monotonic()>=graceful or now_ts()>=max(0,hard_deadline-CANARY_SHUTDOWN_GRACE):
                result='runtime_limit'; break
            if not read_policy().get('allowed_local'):
                result='server_authorization_lost'; break
            watch=broker_post('/managed/group-migration/candidate-reconnect/watch',{
                'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
            if watch.get('candidate_seen_online') is True:
                candidate_seen_online=True
            if watch.get('continue') is not True:
                reason=_safe_str(watch.get('reason'),100)
                result='runtime_limit' if reason=='candidate_reconnect_runtime_limit' else 'server_authorization_lost'
                break
            time.sleep(min(max(1,min(5,watch_interval)),max(0.2,graceful-time.monotonic())))

        _terminate_process_group_before(proc,hard_stop_mono); proc=None
        elapsed=max(0,int(time.monotonic()-run_started))
        report=_candidate_reconnect_report(identity,report_token,result,elapsed,candidate['db_sha256_hint']); report_token=''
        if report.get('candidate_seen_online') is True:
            candidate_seen_online=True
        verified=bool(report.get('success') is True and report.get('reported') is True and report.get('verified') is True
                      and result=='runtime_limit' and candidate_seen_online)

        save_candidate_reconnect_state({
            'status':'reported' if verified else 'failed','verified':verified,'started_at':process_started_at,'ended_at':now_ts(),
            'result_code':result,'elapsed_seconds':elapsed,'installation_id':identity['installation_id'],'node_id':identity['node_id'],
            'client_version':VERSION,'architecture':ARCH,'target_group_name':candidate['target_group_name'],
            'expected_agent_label':candidate['agent_label'],'candidate_db_sha256_hint':candidate['db_sha256_hint'],
            'candidate_node_hint':_safe_str(report.get('candidate_node_hint'),20),'candidate_seen_online':candidate_seen_online,
            'shared_runtime_stopped':True,'candidate_meshagent_execution':candidate_execution,'existing_stable_identity_preserved':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
            'technician_actions_authorized':False})
        print(f"[managed] quarantined candidate reconnect runtime stopped result={result} verified={str(verified).lower()} elapsed={elapsed}s candidate_seen_online={str(candidate_seen_online).lower()} candidate_db_hint={candidate['db_sha256_hint']}; permanent_commit=false",flush=True)

    except (RuntimeError,OSError,subprocess.SubprocessError) as exc:
        if proc is not None:
            _terminate_process_group(proc); proc=None
        elapsed=max(0,now_ts()-started); text=str(exc); code,_,message=text.partition('|')
        if report_token and identity is not None and candidate is not None:
            _candidate_reconnect_report(identity,report_token,'launch_failed',elapsed,candidate.get('db_sha256_hint','')); report_token=''
        save_candidate_reconnect_state({
            'status':'failed','verified':False,'started_at':started,'ended_at':now_ts(),'result_code':code or 'candidate_reconnect_failed',
            'elapsed_seconds':elapsed,'installation_id':(identity or {}).get('installation_id',''),'node_id':(identity or {}).get('node_id',''),
            'client_version':VERSION,'architecture':ARCH,'target_group_name':(candidate or {}).get('target_group_name',''),
            'expected_agent_label':(candidate or {}).get('agent_label',''),'candidate_db_sha256_hint':(candidate or {}).get('db_sha256_hint',''),
            'candidate_seen_online':candidate_seen_online,'shared_runtime_stopped':shared_stopped,
            'candidate_meshagent_execution':candidate_execution,'existing_stable_identity_preserved':True,
            'permanent_runtime_source_switch':False,'identity_binding_commit':False,'old_meshcentral_node_delete':False,
            'rollback_shared_runtime_requested':False,'rollback_shared_runtime_started':False,'runtime_directory_deleted':False,
            'technician_actions_authorized':False,'error_code':_safe_str(code or 'candidate_reconnect_failed',100),
            'error_message':_safe_str(message or text,300)})
        print(f"[managed] candidate reconnect verification failed code={code or 'candidate_reconnect_failed'}; stable identity preserved; permanent commit unchanged",flush=True)

    finally:
        if proc is not None:
            _terminate_process_group(proc)
        if agent_temp:
            try: Path(agent_temp).unlink(missing_ok=True)
            except OSError: cleanup_ok=False
        if runtime_dir:
            try: shutil.rmtree(runtime_dir)
            except OSError: cleanup_ok=False
        st=load_candidate_reconnect_state(); st['runtime_directory_deleted']=cleanup_ok; save_candidate_reconnect_state(st)
        if target_material is not None:
            try: target_material['raw']=b''
            except Exception: pass
        with CANDIDATE_RECONNECT_WORKER_LOCK:
            CANDIDATE_RECONNECT_WORKER_ACTIVE=False
        control=load_unattended_control(); local=read_policy(); server=get_server_state()
        if control.get('enabled') and local.get('allowed_local') and server.get('authorized_server') is True and (_as_int(server.get('valid_until')) or 0)>now_ts():
            rollback_requested=True
            st=load_candidate_reconnect_state(); st['rollback_shared_runtime_requested']=True; save_candidate_reconnect_state(st)
            try:
                if not PERSISTENT_WORKER_ACTIVE:
                    start_persistent_runtime()
                rollback_started=True
            except RuntimeError:
                rollback_started=bool(PERSISTENT_WORKER_ACTIVE)
            st=load_candidate_reconnect_state(); st['rollback_shared_runtime_started']=rollback_started; save_candidate_reconnect_state(st)
            print(f"[managed] candidate reconnect rollback to shared unattended runtime requested={str(rollback_requested).lower()} started={str(rollback_started).lower()}",flush=True)


def start_candidate_reconnect_canary():
    global CANDIDATE_RECONNECT_WORKER_ACTIVE
    with CANDIDATE_RECONNECT_WORKER_LOCK:
        if CANDIDATE_RECONNECT_WORKER_ACTIVE:
            raise RuntimeError('candidate_reconnect_already_running|Υπάρχει ήδη candidate reconnect verification σε εξέλιξη.')
        if IDENTITY_RESEED_WORKER_ACTIVE or MIGRATION_CANARY_WORKER_ACTIVE or CANARY_WORKER_ACTIVE:
            raise RuntimeError('candidate_reconnect_other_canary_active|Υπάρχει ήδη άλλο Managed canary σε εξέλιξη.')
        if not _candidate_quarantine_exists():
            raise RuntimeError('candidate_reconnect_quarantine_missing|Δεν υπάρχει quarantined candidate identity.')
        if not PERSISTENT_WORKER_ACTIVE:
            raise RuntimeError('candidate_reconnect_shared_runtime_not_running|Το shared unattended runtime πρέπει να είναι RUNNING πριν από candidate reconnect verification.')
        CANDIDATE_RECONNECT_WORKER_ACTIVE=True
    t=threading.Thread(target=candidate_reconnect_worker,name='managed-candidate-reconnect-canary',daemon=True)
    t.start()

def heartbeat_worker():
    last_summary = None
    while True:
        heartbeat_once()
        state = get_server_state()
        summary = (state.get("state"), state.get("reason_code"), bool(state.get("authorized_server")))
        if summary != last_summary:
            print(f"[managed] broker state={summary[0]} reason={summary[1]} authorized={str(summary[2]).lower()}", flush=True)
            last_summary = summary
        time.sleep(HEARTBEAT_INTERVAL)


def fmt_epoch(value):
    value = _as_int(value)
    if not value:
        return "—"
    try:
        return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(value))
    except (OverflowError, OSError, ValueError):
        return "—"


def render_page(local_snapshot, notice="", notice_kind="info"):
    policy = local_snapshot.get("policy") if isinstance(local_snapshot.get("policy"), dict) else {}
    subscription = policy.get("subscription") if isinstance(policy.get("subscription"), dict) else {}
    entitlement = policy.get("entitlement") if isinstance(policy.get("entitlement"), dict) else {}
    tools = policy.get("tools_liveness") if isinstance(policy.get("tools_liveness"), dict) else {}
    health = policy.get("health") if isinstance(policy.get("health"), dict) else {}
    server = get_server_state()
    identity = load_identity()
    enrollment = load_enrollment_state()
    settings_state = load_settings_state()
    agent_state = load_agent_state()
    runtime_state = load_runtime_state()
    canary_state = load_canary_state()
    persistent_state = load_persistent_state()
    migration_preflight_state = load_group_migration_preflight_state()
    migration_target_settings_state = load_group_migration_target_settings_state()
    migration_canary_state = load_group_migration_canary_state()
    identity_reseed_state = load_group_identity_reseed_state()
    candidate_reconnect_state = load_candidate_reconnect_state()

    local_allowed = bool(local_snapshot.get("allowed_local"))
    server_allowed = bool(server.get("authorized_server")) and (_as_int(server.get("valid_until")) or 0) > now_ts()
    overall = local_allowed and server_allowed and identity is not None

    if overall:
        badge_class, badge = "ok", "Managed authorization: ΕΠΙΤΡΕΠΕΤΑΙ"
        reason = "Local Policy και Broker Server Authorization συμφωνούν. Η συσκευή μπορεί να χρησιμοποιηθεί για ελεγχόμενη continuous connectivity, ενώ η τεχνική πρόσβαση παραμένει ξεχωριστά κλειδωμένη."
    elif identity is None:
        badge_class, badge = "warn", "Απαιτείται αρχική ενεργοποίηση"
        reason = "Η τοπική πολιτική είναι έτοιμη. Δημιουργήστε έναν one-time pairing code στον Broker και εισάγετέ τον μία φορά εδώ."
    elif not local_allowed:
        badge_class, badge = "bad", "Managed authorization: ΔΕΝ ΕΠΙΤΡΕΠΕΤΑΙ"
        reason = local_snapshot.get("reason") or "Η τοπική πολιτική δεν επιτρέπει Managed Support."
    else:
        badge_class, badge = "bad", "Managed authorization: ΔΕΝ ΕΠΙΤΡΕΠΕΤΑΙ"
        reason = server.get("reason") or "Ο Broker δεν έχει δώσει έγκυρο server authorization."

    def esc(value):
        return html.escape(str(value if value not in (None, "") else "—"))

    entitled = "Ναι" if entitlement.get("managed_remote_support") is True else "Όχι"
    portal_paired_local = "Ναι" if health.get("portal_paired") is True else "Όχι"
    tools_online = "Ναι" if health.get("tools_online") is True else "Όχι"
    broker_paired = "Ναι" if identity else "Όχι"
    server_auth = "Ναι" if server_allowed else "Όχι"
    overall_text = "Ναι — authorization chain complete" if overall else "Όχι"
    node_hint = "—"
    if identity:
        node_hint = "…" + identity["node_id"][-8:]

    notice_html = ""
    if notice:
        klass = "notice-ok" if notice_kind == "ok" else "notice-bad" if notice_kind == "bad" else "notice-info"
        notice_html = f'<div class="notice {klass}">{esc(notice)}</div>'

    pair_html = ""
    if identity is None:
        disabled = "" if local_allowed else " disabled"
        pair_html = f'''
<section class="pairbox">
<h2>Αρχική ενεργοποίηση Managed Support</h2>
<p>Στο WordPress: <strong>Remote Sessions → Managed Support → Δημιουργία pairing</strong>, με Installation reference <code>{esc(policy.get('installation_id'))}</code>. Ο κωδικός χρησιμοποιείται μία φορά και δεν αποθηκεύεται εδώ.</p>
<form method="post" action="pair" autocomplete="off">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<label for="pairing_code">One-time pairing code</label>
<input id="pairing_code" name="pairing_code" type="text" inputmode="text" maxlength="100" placeholder="SPM-XXXX-XXXX-XXXX-XXXX" required autocomplete="off"{disabled}>
<button type="submit"{disabled}>Ενεργοποίηση Managed identity</button>
</form>
</section>'''

    enrollment_html = ""
    settings_html = ""
    agent_html = ""
    canary_html = ""
    persistent_html = ""
    migration_preflight_html = ""
    migration_target_settings_html = ""
    migration_canary_html = ""
    identity_reseed_html = ""
    candidate_reconnect_html = ""
    if identity is not None:
        enrollment_verified = (
            enrollment.get("verified") is True
            and enrollment.get("installation_id") == identity["installation_id"]
            and enrollment.get("node_id") == identity["node_id"]
        )
        enrollment_current = enrollment_verified and enrollment.get("client_version") == VERSION and enrollment.get("architecture") == ARCH
        if enrollment_current:
            enrollment_label = "VERIFIED — τρέχον Managed enrollment consume"
        elif enrollment_verified:
            enrollment_label = f"Προηγούμενο VERIFIED ({enrollment.get('client_version') or 'άγνωστη έκδοση'}) — θα ανανεωθεί αυτόματα"
        else:
            enrollment_label = "Δεν έχει εκτελεστεί ακόμη"
        enrollment_time = fmt_epoch(enrollment.get("verified_at")) if enrollment_verified else "—"
        enrollment_hint = enrollment.get("source_fingerprint_hint") if enrollment_verified else "—"
        disabled = "" if (overall and not PERSISTENT_WORKER_ACTIVE and not CANARY_WORKER_ACTIVE and not MIGRATION_CANARY_WORKER_ACTIVE and not IDENTITY_RESEED_WORKER_ACTIVE and not CANDIDATE_RECONNECT_WORKER_ACTIVE) else " disabled"
        enrollment_html = f"""
<section class="pairbox">
<h2>Enrollment authorization check</h2>
<p>Εκδίδει και καταναλώνει άμεσα ένα one-time enrollment authorization ticket από τον Broker. Το ticket <strong>δεν αποθηκεύεται</strong>, δεν παραδίδεται .msh και δεν ενεργοποιείται MeshAgent ή remote access.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(enrollment_label)}</strong></div>
<div><span>Τελευταίος έλεγχος</span><strong>{esc(enrollment_time)}</strong></div>
<div><span>Source fingerprint hint</span><strong>{esc(enrollment_hint)}</strong></div>
</div>
<form method="post" action="enrollment-check">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{disabled}>Έλεγχος enrollment authorization</button>
</form>
</section>"""

        settings_any_verified = (
            settings_state.get("verified") is True
            and settings_state.get("installation_id") == identity["installation_id"]
            and settings_state.get("node_id") == identity["node_id"]
        )
        settings_verified = settings_any_verified and settings_state.get("client_version") == VERSION and settings_state.get("architecture") == ARCH
        if settings_verified:
            settings_label = f"VERIFIED — τρέχον {VERSION} .msh verification"
        elif settings_any_verified:
            settings_label = f"Προηγούμενο VERIFIED ({settings_state.get('client_version') or 'άγνωστη έκδοση'}) — θα ανανεωθεί αυτόματα"
        else:
            settings_label = "Δεν έχει εκτελεστεί ακόμη"
        settings_time = fmt_epoch(settings_state.get("verified_at")) if settings_any_verified else "—"
        settings_hint = settings_state.get("source_fingerprint_hint") if settings_any_verified else "—"
        settings_sha = settings_state.get("sha256_hint") if settings_any_verified else "—"
        settings_bytes = str(settings_state.get("bytes")) if settings_any_verified else "—"
        settings_agent = settings_state.get("agent_label") if settings_any_verified else "—"
        settings_html = f"""
<section class="pairbox">
<h2>Secure settings verification</h2>
<p>Εκτελεί νέο enrollment authorization για την τρέχουσα Managed έκδοση και μετά ζητά/καταναλώνει ακριβώς ένα one-time secure settings ticket. Το raw ticket και το <strong>.msh δεν αποθηκεύονται</strong>. Ελέγχονται integrity, required fields, ασφαλές WSS endpoint και opaque node label.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(settings_label)}</strong></div>
<div><span>Τελευταίος έλεγχος</span><strong>{esc(settings_time)}</strong></div>
<div><span>Source fingerprint hint</span><strong>{esc(settings_hint)}</strong></div>
<div><span>Settings SHA-256 hint</span><strong>{esc(settings_sha)}</strong></div>
<div><span>Bytes</span><strong>{esc(settings_bytes)}</strong></div>
<div><span>Opaque node label</span><strong>{esc(settings_agent)}</strong></div>
</div>
<form method="post" action="settings-check">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{disabled}>Έλεγχος secure settings</button>
</form>
</section>"""

        agent_verified = (
            agent_state.get("verified") is True
            and agent_state.get("installation_id") == identity["installation_id"]
            and agent_state.get("node_id") == identity["node_id"]
            and agent_state.get("client_version") == VERSION
            and agent_state.get("architecture") == ARCH
        )
        agent_label = "VERIFIED — binary ελέγχθηκε δύο φορές και διαγράφηκε" if agent_verified else "Δεν έχει εκτελεστεί ακόμη"
        agent_time = fmt_epoch(agent_state.get("verified_at")) if agent_verified else "—"
        agent_sha = agent_state.get("sha256_hint") if agent_verified else "—"
        agent_bytes = str(agent_state.get("bytes")) if agent_verified else "—"
        agent_elf = agent_state.get("elf_class") if agent_verified else "—"
        agent_arch = agent_state.get("architecture") if agent_verified else "—"
        agent_machine = str(agent_state.get("e_machine")) if agent_verified else "—"
        agent_html = f"""
<section class="pairbox">
<h2>MeshAgent binary verification</h2>
<p>Ανανεώνει αυτόματα enrollment + secure settings για την τρέχουσα Managed έκδοση και μετά ζητά/καταναλώνει ακριβώς ένα one-time MeshAgent binary ticket. Το binary γράφεται μόνο προσωρινά με mode 0600, ελέγχεται SHA/bytes/ELF64/architecture δεύτερη φορά από disk και <strong>διαγράφεται αμέσως</strong>. Δεν γίνεται chmod +x ή execution.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(agent_label)}</strong></div>
<div><span>Τελευταίος έλεγχος</span><strong>{esc(agent_time)}</strong></div>
<div><span>Agent SHA-256 hint</span><strong>{esc(agent_sha)}</strong></div>
<div><span>Bytes</span><strong>{esc(agent_bytes)}</strong></div>
<div><span>ELF / Arch</span><strong>{esc(agent_elf)} · {esc(agent_arch)}</strong></div>
<div><span>ELF e_machine</span><strong>{esc(agent_machine)}</strong></div>
</div>
<form method="post" action="agent-check">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{disabled}>Έλεγχος MeshAgent binary</button>
</form>
</section>"""


    if identity:
        runtime_same_identity = (
            runtime_state.get("installation_id") == identity["installation_id"]
            and runtime_state.get("node_id") == identity["node_id"]
            and runtime_state.get("client_version") == VERSION
            and runtime_state.get("architecture") == ARCH
        )
        runtime_status = runtime_state.get("status") if runtime_same_identity else "not_run"
        if runtime_status == "refreshing_chain":
            runtime_label = "RUNNING — ανανεώνεται η Managed αλυσίδα"
        elif runtime_status == "lease_issued_waiting_renewal":
            runtime_label = "RUNNING — lease εκδόθηκε, αναμένεται μία ανανέωση"
        elif runtime_status == "verified_renewed_once" and runtime_state.get("verified") is True:
            runtime_label = "VERIFIED — lease εκδόθηκε και ανανεώθηκε μία φορά"
        elif runtime_status == "failed":
            runtime_label = "FAILED — " + (runtime_state.get("error_message") or "Ο έλεγχος απέτυχε")
        else:
            runtime_label = "Δεν έχει εκτελεστεί ακόμη"
        runtime_requested = fmt_epoch(runtime_state.get("requested_at")) if runtime_same_identity else "—"
        runtime_initial_until = fmt_epoch(runtime_state.get("initial_expires_at")) if runtime_same_identity else "—"
        runtime_renewed = fmt_epoch(runtime_state.get("renewed_at")) if runtime_same_identity else "—"
        runtime_renewed_until = fmt_epoch(runtime_state.get("renewed_expires_at")) if runtime_same_identity else "—"
        runtime_button_disabled = " disabled" if (disabled or runtime_status in {"refreshing_chain", "lease_issued_waiting_renewal"}) else ""
        runtime_html = f"""
<section class="pairbox">
<h2>Runtime lease dry-run</h2>
<p>Ανανεώνει αυτόματα enrollment + secure settings + MeshAgent verification για την τρέχουσα Managed έκδοση, ζητά ένα βραχύβιο server-authoritative runtime lease και το ανανεώνει <strong>μία φορά</strong> μετά από περίπου {RUNTIME_RENEW_DELAY} δευτερόλεπτα. Το raw lease μένει μόνο στη μνήμη και απορρίπτεται μετά τον έλεγχο. <strong>Δεν εκτελείται MeshAgent</strong> και δεν ανοίγει MeshCentral/remote access.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(runtime_label)}</strong></div>
<div><span>Lease εκδόθηκε</span><strong>{esc(runtime_requested)}</strong></div>
<div><span>Αρχικό lease έως</span><strong>{esc(runtime_initial_until)}</strong></div>
<div><span>Ανανέωση</span><strong>{esc(runtime_renewed)}</strong></div>
<div><span>Ανανεωμένο lease έως</span><strong>{esc(runtime_renewed_until)}</strong></div>
<div><span>Execution / Remote</span><strong>OFF / OFF</strong></div>
</div>
<form method="post" action="runtime-lease-check">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{runtime_button_disabled}>Έλεγχος runtime lease</button>
</form>
</section>"""
    else:
        runtime_html = ""

    mesh_identity_status = get_mesh_identity_status(identity)
    mesh_identity_label = mesh_identity_status.get('label') or '—'
    mesh_identity_generation = str(mesh_identity_status.get('generation') or 0) if identity is not None else '—'
    mesh_identity_db_hint = mesh_identity_status.get('db_sha256_hint') or '—'
    mesh_identity_runs = str(mesh_identity_status.get('continuity_runs') or 0) if identity is not None else '—'
    mesh_identity_updated = fmt_epoch(mesh_identity_status.get('updated_at')) if mesh_identity_status.get('updated_at') else '—'

    if identity is not None:
        canary_current = (
            canary_state.get('client_version') == VERSION and canary_state.get('architecture') == ARCH
            and canary_state.get('installation_id') == identity['installation_id'] and canary_state.get('node_id') == identity['node_id']
        )
        cstatus = canary_state.get('status') if canary_current else 'not_run'
        if cstatus == 'running': canary_label = 'RUNNING — identity-continuity foreground canary'
        elif cstatus == 'preparing': canary_label = 'PREPARING — ανανεώνεται verified chain / authorization'
        elif cstatus == 'reported' and canary_state.get('verified'): canary_label = 'VERIFIED — canary ολοκληρώθηκε και αναφέρθηκε'
        elif cstatus == 'failed': canary_label = 'FAILED — ελέγξτε το αποτέλεσμα πριν επανάληψη'
        else: canary_label = 'Δεν έχει εκτελεστεί ακόμη'
        cstart = fmt_epoch(canary_state.get('started_at')) if canary_current else '—'
        cend = fmt_epoch(canary_state.get('ended_at')) if canary_current else '—'
        cresult = canary_state.get('result_code') if canary_current else '—'
        celapsed = str(canary_state.get('elapsed_seconds')) if canary_current and canary_state.get('elapsed_seconds') else '—'
        cmax = str(canary_state.get('max_runtime_seconds')) if canary_current and canary_state.get('max_runtime_seconds') else '≤45'
        clabel = canary_state.get('agent_label') if canary_current else '—'
        cclean = 'Ναι' if canary_current and canary_state.get('runtime_directory_deleted') else ('Σε εξέλιξη' if cstatus in {'preparing','running'} else '—')
        cid_mode = canary_state.get('identity_mode') if canary_current else '—'
        cid_persisted = 'Ναι' if canary_current and canary_state.get('identity_db_persisted') else ('Σε εξέλιξη' if cstatus in {'preparing','running'} else '—')
        cid_binding = 'Ναι' if canary_current and canary_state.get('identity_binding_verified') else ('Θα δημιουργηθεί' if canary_current and cid_mode == 'seed' else '—')
        cid_generation = str(canary_state.get('identity_generation') or 0) if canary_current else '—'
        cid_runs = str(canary_state.get('identity_continuity_runs') or 0) if canary_current else '—'
        canary_disabled = ' disabled' if (not overall or CANARY_WORKER_ACTIVE or PERSISTENT_WORKER_ACTIVE) else ''
        canary_html = f"""
<section class="pairbox">
<h2>MeshAgent identity continuity canary</h2>
<p>Διατηρεί διαθέσιμο το ήδη επαληθευμένο 3.7.x identity-continuity canary για διαγνωστικό έλεγχο έως 45″. Στην πρώτη επιτυχή εκτέλεση αποθηκεύει μόνο το προστατευμένο <code>meshagent.db</code> της MeshCentral ταυτότητας. Στις επόμενες εκτελέσεις απαιτεί να ταιριάζει με το ίδιο Installation ID, Broker identity και verified .msh ώστε να επαναχρησιμοποιείται το ίδιο MeshCentral node. Δεν χρησιμοποιείται <code>-install</code>, δεν δημιουργείται service και <strong>δεν εξουσιοδοτούνται Desktop / Terminal / Files</strong>.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(canary_label)}</strong></div>
<div><span>Έναρξη</span><strong>{esc(cstart)}</strong></div>
<div><span>Λήξη</span><strong>{esc(cend)}</strong></div>
<div><span>Αποτέλεσμα</span><strong>{esc(cresult)}</strong></div>
<div><span>Elapsed / Max</span><strong>{esc(celapsed)}s / {esc(cmax)}s</strong></div>
<div><span>Expected node</span><strong>{esc(clabel)}</strong></div>
<div><span>Runtime cleanup</span><strong>{esc(cclean)}</strong></div>
<div><span>Identity mode</span><strong>{esc(cid_mode)}</strong></div>
<div><span>Identity DB persisted</span><strong>{esc(cid_persisted)}</strong></div>
<div><span>Identity binding verified</span><strong>{esc(cid_binding)}</strong></div>
<div><span>Identity generation</span><strong>{esc(cid_generation)}</strong></div>
<div><span>Continuity runs</span><strong>{esc(cid_runs)}</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
<div><span>Agent/service persistence</span><strong>OFF</strong></div>
</div>
<form method="post" action="identity-continuity-canary">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{canary_disabled}>Έναρξη identity continuity canary ≤45″</button>
</form>
</section>"""


    if identity is not None:
        pcurrent = (
            persistent_state.get('client_version') == VERSION and persistent_state.get('architecture') == ARCH
            and persistent_state.get('installation_id') == identity['installation_id'] and persistent_state.get('node_id') == identity['node_id']
        )
        pstatus = persistent_state.get('status') if pcurrent else 'not_run'
        if PERSISTENT_WORKER_ACTIVE and pstatus in {'not_run','reported','stopped','failed'}:
            pstatus = 'starting'
        if pstatus == 'preparing': plabel = 'PREPARING — ανανεώνεται verified chain / authorization'
        elif pstatus == 'starting': plabel = 'STARTING — προετοιμάζεται continuous foreground runtime'
        elif pstatus == 'running': plabel = 'RUNNING — το σταθερό MeshCentral node διατηρείται online'
        elif pstatus == 'reconnecting': plabel = 'RECONNECTING — ελεγχόμενη επανασύνδεση στο ίδιο node'
        elif pstatus == 'stopping': plabel = 'STOPPING — ασφαλής τερματισμός σε εξέλιξη'
        elif pstatus == 'reported': plabel = 'STOPPED — ολοκληρώθηκε και αναφέρθηκε στον Broker'
        elif pstatus == 'stopped': plabel = 'STOPPED — ολοκληρώθηκε, η τελική αναφορά δεν επιβεβαιώθηκε'
        elif pstatus == 'failed': plabel = 'FAILED — ελέγξτε reason/logs πριν από νέα εκκίνηση'
        else: plabel = 'Δεν έχει ξεκινήσει ακόμη'
        pstart = fmt_epoch(persistent_state.get('started_at')) if pcurrent else '—'
        pend = fmt_epoch(persistent_state.get('ended_at')) if pcurrent else '—'
        phealth = persistent_state.get('health_state') if pcurrent else '—'
        preason = persistent_state.get('last_reason') if pcurrent else '—'
        pwatch = fmt_epoch(persistent_state.get('last_watch_at')) if pcurrent else '—'
        phealth_at = fmt_epoch(persistent_state.get('last_health_at')) if pcurrent else '—'
        please = fmt_epoch(persistent_state.get('runtime_lease_expires_at')) if pcurrent else '—'
        prenewals = str(persistent_state.get('lease_renewals') or 0) if pcurrent else '0'
        preconnects = str(persistent_state.get('reconnect_count') or 0) if pcurrent else '0'
        plabel_node = persistent_state.get('agent_label') if pcurrent else (mesh_identity_status.get('agent_label') or '—')
        pclean = 'Ναι' if pcurrent and persistent_state.get('runtime_directory_deleted') else ('Όχι — runtime ενεργό' if PERSISTENT_WORKER_ACTIVE else '—')
        identity_ready = mesh_identity_status.get('state') == 'ready'
        unattended = load_unattended_control()
        unattended_enabled = unattended.get('enabled') is True
        unattended_text = 'ENABLED — επανεκκινεί αυτόματα μετά από add-on restart' if unattended_enabled else 'DISABLED — απαιτείται ρητή ενεργοποίηση'
        pstart_disabled = ' disabled' if (not overall or not identity_ready or unattended_enabled or PERSISTENT_WORKER_ACTIVE or CANARY_WORKER_ACTIVE) else ''
        pstop_disabled = '' if (unattended_enabled or PERSISTENT_WORKER_ACTIVE) else ' disabled'
        persistent_html = f"""
<section class="pairbox">
<h2>Unattended Managed runtime — restart recovery checkpoint</h2>
<p>Χρησιμοποιεί <strong>αποκλειστικά την ήδη σταθερή MeshCentral identity</strong>, ανανεώνει βραχύβια runtime leases, ελέγχει συνεχώς τον Broker και αναφέρει health. Όσο οι άδειες παραμένουν έγκυρες, το ίδιο node μπορεί να μένει online χωρίς χρονικό canary limit. Αν χαθεί local policy, subscription/server authorization ή runtime lease, σταματά fail-closed. Το unattended control που αποδείχθηκε στην 3.9.0 <strong>διατηρείται στην 3.12.0</strong>. Αν ήταν ήδη ENABLED, μετά το add-on restart περιμένει έγκυρη local + server authorization και επαναφέρει αυτόματα την ίδια σταθερή συσκευή. Η παύση απενεργοποιεί αυτή την αυτόματη επαναφορά.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(plabel)}</strong></div>
<div><span>Έναρξη</span><strong>{esc(pstart)}</strong></div>
<div><span>Λήξη</span><strong>{esc(pend)}</strong></div>
<div><span>Health</span><strong>{esc(phealth)}</strong></div>
<div><span>Τελευταίος λόγος</span><strong>{esc(preason)}</strong></div>
<div><span>Expected node</span><strong>{esc(plabel_node)}</strong></div>
<div><span>Τελευταίο server watch</span><strong>{esc(pwatch)}</strong></div>
<div><span>Τελευταίο health report</span><strong>{esc(phealth_at)}</strong></div>
<div><span>Runtime lease έως</span><strong>{esc(please)}</strong></div>
<div><span>Lease renewals</span><strong>{esc(prenewals)}</strong></div>
<div><span>Controlled reconnects</span><strong>{esc(preconnects)}</strong></div>
<div><span>Identity mode</span><strong>reuse only</strong></div>
<div><span>Unattended mode</span><strong>{esc(unattended_text)}</strong></div>
<div><span>Runtime cleanup</span><strong>{esc(pclean)}</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
<div><span>Agent/service persistence</span><strong>OFF</strong></div>
</div>
<form method="post" action="continuous-runtime-start">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{pstart_disabled}>Ενεργοποίηση unattended Managed runtime</button>
</form>
<form method="post" action="continuous-runtime-stop">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{pstop_disabled}>Παύση unattended Managed runtime</button>
</form>
</section>"""

    if identity:
        mcurrent = (
            migration_preflight_state.get('installation_id') == identity['installation_id']
            and migration_preflight_state.get('node_id') == identity['node_id']
            and migration_preflight_state.get('client_version') == VERSION
            and migration_preflight_state.get('architecture') == ARCH
        )
        mstatus = migration_preflight_state.get('status') if mcurrent else 'not_run'
        if mstatus == 'verified' and migration_preflight_state.get('verified') is True:
            mlabel = 'VERIFIED — READY FOR CONTROLLED MIGRATION CANARY'
        elif mstatus == 'failed':
            mlabel = 'FAILED — ' + (migration_preflight_state.get('error_message') or 'ελέγξτε Broker/profile/controller')
        else:
            mlabel = 'Δεν έχει εκτελεστεί ακόμη'
        mtime = fmt_epoch(migration_preflight_state.get('checked_at')) if mcurrent else '—'
        mgroup = migration_preflight_state.get('target_group_name') if mcurrent else f"Smart Pro Managed — {identity['installation_id']}"
        mmesh = migration_preflight_state.get('target_mesh_id_hint') if mcurrent else '—'
        mbinding = migration_preflight_state.get('target_binding_hint') if mcurrent else '—'
        mtarget = migration_preflight_state.get('target_source_fingerprint_hint') if mcurrent else '—'
        mshared = migration_preflight_state.get('shared_source_fingerprint_hint') if mcurrent else '—'
        mcontroller = migration_preflight_state.get('controller_node_hint') if mcurrent else '—'
        mlabel_agent = migration_preflight_state.get('expected_agent_label') if mcurrent else (mesh_identity_status.get('agent_label') or '—')
        mlease = fmt_epoch(migration_preflight_state.get('server_valid_until')) if mcurrent else '—'
        mdisabled = ' disabled' if (not overall or CANARY_WORKER_ACTIVE) else ''
        migration_preflight_html = f"""
<section class="pairbox">
<h2>Per-installation group migration preflight</h2>
<p>Ελέγχει authenticated με τον Broker 0.36.0+ ότι η υπάρχουσα stable identity, το Installation ID, το verified target group <strong>{esc(mgroup)}</strong>, το dedicated controller binding και η Portal-backed authorization συμφωνούν. <strong>Δεν παραδίδει target .msh, δεν μετακινεί node, δεν αλλάζει runtime source και δεν ενεργοποιεί technician actions.</strong> Επιτρέπεται να εκτελεστεί ενώ το stable unattended runtime παραμένει online.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(mlabel)}</strong></div>
<div><span>Τελευταίος έλεγχος</span><strong>{esc(mtime)}</strong></div>
<div><span>Target group</span><strong>{esc(mgroup)}</strong></div>
<div><span>Expected stable node</span><strong>{esc(mlabel_agent)}</strong></div>
<div><span>Target MeshID hint</span><strong>{esc(mmesh)}</strong></div>
<div><span>Target binding hint</span><strong>{esc(mbinding)}</strong></div>
<div><span>Target source hint</span><strong>{esc(mtarget)}</strong></div>
<div><span>Shared source hint</span><strong>{esc(mshared)}</strong></div>
<div><span>Controller node hint</span><strong>{esc(mcontroller)}</strong></div>
<div><span>Server authorization έως</span><strong>{esc(mlease)}</strong></div>
<div><span>Runtime source switch</span><strong>ΟΧΙ</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
</div>
<form method="post" action="group-migration-preflight">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{mdisabled}>Έλεγχος migration preflight</button>
</form>
</section>"""

        tcurrent = (
            migration_target_settings_state.get('installation_id') == identity['installation_id']
            and migration_target_settings_state.get('node_id') == identity['node_id']
            and migration_target_settings_state.get('client_version') == VERSION
            and migration_target_settings_state.get('architecture') == ARCH
        )
        tstatus = migration_target_settings_state.get('status') if tcurrent else 'not_run'
        if tstatus == 'verified' and migration_target_settings_state.get('verified') is True:
            tlabel = 'VERIFIED — TARGET .MSH READY FOR EXECUTION CANARY DESIGN'
        elif tstatus == 'failed':
            tlabel = 'FAILED — ' + (migration_target_settings_state.get('error_message') or 'ελέγξτε target settings contract')
        else:
            tlabel = 'Δεν έχει εκτελεστεί ακόμη'
        ttime = fmt_epoch(migration_target_settings_state.get('checked_at')) if tcurrent else '—'
        tgroup = migration_target_settings_state.get('target_group_name') if tcurrent else f"Smart Pro Managed — {identity['installation_id']}"
        tmesh = migration_target_settings_state.get('target_mesh_id_hint') if tcurrent else '—'
        tbinding = migration_target_settings_state.get('target_binding_hint') if tcurrent else '—'
        ttarget = migration_target_settings_state.get('target_source_fingerprint_hint') if tcurrent else '—'
        tshared = migration_target_settings_state.get('shared_source_fingerprint_hint') if tcurrent else '—'
        tlabel_agent = migration_target_settings_state.get('expected_agent_label') if tcurrent else (mesh_identity_status.get('agent_label') or '—')
        thost = migration_target_settings_state.get('mesh_server_host') if tcurrent else '—'
        tsha = migration_target_settings_state.get('sha256_hint') if tcurrent else '—'
        tbytes = str(migration_target_settings_state.get('bytes') or '—') if tcurrent else '—'
        tdisabled = ' disabled' if (not overall or CANARY_WORKER_ACTIVE or MIGRATION_CANARY_WORKER_ACTIVE or IDENTITY_RESEED_WORKER_ACTIVE or CANDIDATE_RECONNECT_WORKER_ACTIVE) else ''
        migration_target_settings_html = f"""
<section class="pairbox">
<h2>Per-installation target .msh verification</h2>
<p>Ανανεώνει πρώτα το authenticated migration preflight και μετά ζητά/καταναλώνει <strong>ένα one-time target settings ticket</strong> από τον Broker 0.37.0+. Το target .msh επαληθεύεται αυστηρά <strong>μόνο στη μνήμη</strong>: group, MeshID/binding, WSS host, SHA/bytes και το ίδιο stable <code>SPMNG-...</code> label. <strong>Δεν γράφεται σε /data, δεν εκτελείται MeshAgent, δεν μετακινείται node, δεν αλλάζει runtime source και δεν γίνεται identity-binding commit.</strong> Μπορεί να εκτελεστεί ενώ το υπάρχον shared unattended runtime παραμένει online.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(tlabel)}</strong></div>
<div><span>Τελευταίος έλεγχος</span><strong>{esc(ttime)}</strong></div>
<div><span>Target group</span><strong>{esc(tgroup)}</strong></div>
<div><span>Expected stable node</span><strong>{esc(tlabel_agent)}</strong></div>
<div><span>Target MeshID hint</span><strong>{esc(tmesh)}</strong></div>
<div><span>Target binding hint</span><strong>{esc(tbinding)}</strong></div>
<div><span>Target source hint</span><strong>{esc(ttarget)}</strong></div>
<div><span>Shared source hint</span><strong>{esc(tshared)}</strong></div>
<div><span>MeshServer host</span><strong>{esc(thost)}</strong></div>
<div><span>Target runtime SHA-256 hint</span><strong>{esc(tsha)}</strong></div>
<div><span>Bytes</span><strong>{esc(tbytes)}</strong></div>
<div><span>Runtime source / Node move</span><strong>ΟΧΙ / ΟΧΙ</strong></div>
<div><span>Identity binding commit</span><strong>ΟΧΙ</strong></div>
<div><span>MeshAgent execution</span><strong>ΟΧΙ</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
</div>
<form method="post" action="group-migration-target-settings">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{tdisabled}>Έλεγχος target .msh</button>
</form>
</section>"""

        gccurrent = (
            migration_canary_state.get('installation_id') == identity['installation_id']
            and migration_canary_state.get('node_id') == identity['node_id']
            and migration_canary_state.get('client_version') == VERSION
            and migration_canary_state.get('architecture') == ARCH
        )
        gcstatus = migration_canary_state.get('status') if gccurrent else 'not_run'
        if gcstatus == 'running':
            gclabel = 'RUNNING — TARGET GROUP CANARY ≤45″'
        elif gcstatus == 'reported' and migration_canary_state.get('verified') is True:
            gclabel = 'VERIFIED — TARGET CANARY REPORTED / ROLLBACK REQUESTED'
        elif gcstatus == 'failed':
            gclabel = 'FAILED — ' + (migration_canary_state.get('error_message') or migration_canary_state.get('result_code') or 'ελέγξτε logs')
        elif gcstatus == 'stopping_shared_runtime':
            gclabel = 'PREPARING — ασφαλής τερματισμός shared runtime'
        else:
            gclabel = 'Δεν έχει εκτελεστεί ακόμη'
        gcgroup = migration_canary_state.get('target_group_name') if gccurrent else f"Smart Pro Managed — {identity['installation_id']}"
        gcnode = migration_canary_state.get('expected_agent_label') if gccurrent else (mesh_identity_status.get('agent_label') or '—')
        gcresult = migration_canary_state.get('result_code') if gccurrent else '—'
        gcelapsed = str(migration_canary_state.get('elapsed_seconds') or '—') if gccurrent else '—'
        gcsharedstop = 'ΝΑΙ' if gccurrent and migration_canary_state.get('shared_runtime_stopped') else 'ΟΧΙ'
        gcreuse = 'ΝΑΙ' if gccurrent and migration_canary_state.get('stable_identity_reused') else 'ΟΧΙ'
        gcexec = 'ΝΑΙ — CANARY ONLY' if gccurrent and migration_canary_state.get('target_meshagent_execution') else 'ΟΧΙ'
        gcrollback = 'ΝΑΙ' if gccurrent and migration_canary_state.get('rollback_shared_runtime_requested') else 'ΟΧΙ'
        gcrollbackstart = 'ΝΑΙ' if gccurrent and migration_canary_state.get('rollback_shared_runtime_started') else 'ΟΧΙ'
        gccleanup = 'ΝΑΙ' if gccurrent and migration_canary_state.get('runtime_directory_deleted') else 'ΟΧΙ'
        gcdisabled = ' disabled'  # 3.12 stable-identity move canary retired after live proof; do not rerun
        migration_canary_html = f"""
<section class="pairbox">
<h2>Controlled per-installation group migration canary</h2>
<p>Ιστορικό checkpoint 3.12.0. Απέδειξε ασφαλές stop/target execution/rollback, αλλά η υπάρχουσα stable identity δεν μεταφέρθηκε στο νέο group. Το test διατηρείται μόνο για ιστορικό και <strong>δεν επαναλαμβάνεται</strong>. Η 3.14.0 διατηρεί το clean reseed ως ιστορικό και προσθέτει ξεχωριστό reconnect verification της ήδη quarantined candidate.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(gclabel)}</strong></div>
<div><span>Target group</span><strong>{esc(gcgroup)}</strong></div>
<div><span>Expected stable node</span><strong>{esc(gcnode)}</strong></div>
<div><span>Shared runtime stopped</span><strong>{esc(gcsharedstop)}</strong></div>
<div><span>Stable identity reused</span><strong>{esc(gcreuse)}</strong></div>
<div><span>Target MeshAgent execution</span><strong>{esc(gcexec)}</strong></div>
<div><span>Result</span><strong>{esc(gcresult)}</strong></div>
<div><span>Elapsed</span><strong>{esc(gcelapsed)} s</strong></div>
<div><span>Runtime directory deleted</span><strong>{esc(gccleanup)}</strong></div>
<div><span>Permanent source switch</span><strong>ΟΧΙ</strong></div>
<div><span>Identity binding commit</span><strong>ΟΧΙ</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
<div><span>Rollback shared runtime requested</span><strong>{esc(gcrollback)}</strong></div>
<div><span>Rollback shared runtime started</span><strong>{esc(gcrollbackstart)}</strong></div>
</div>
<form method="post" action="group-migration-canary">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{gcdisabled}>Παλιό migration canary — ολοκληρώθηκε / δεν επαναλαμβάνεται</button>
</form>
</section>"""


        candidate_exists = _candidate_quarantine_exists()
        # A quarantined candidate is durable /data state and must remain visible after
        # a hotfix version bump. Do not make it look like the reseed was never run.
        rcurrent = (
            identity_reseed_state.get('installation_id') == identity['installation_id']
            and identity_reseed_state.get('node_id') == identity['node_id']
            and identity_reseed_state.get('architecture') == ARCH
            and (identity_reseed_state.get('client_version') == VERSION or candidate_exists)
        )
        rstatus = identity_reseed_state.get('status') if rcurrent else 'not_run'
        if rstatus == 'running':
            rlabel = 'RUNNING — FRESH TARGET-GROUP CANDIDATE ≤45″'
        elif rstatus == 'reported' and identity_reseed_state.get('verified') is True:
            rlabel = 'VERIFIED — CANDIDATE QUARANTINED / ROLLBACK REQUESTED'
        elif rstatus == 'failed':
            rlabel = 'FAILED — ' + (identity_reseed_state.get('error_message') or identity_reseed_state.get('result_code') or 'ελέγξτε logs')
        elif rstatus == 'stopping_shared_runtime':
            rlabel = 'PREPARING — ασφαλής τερματισμός shared runtime'
        else:
            rlabel = 'Δεν έχει εκτελεστεί ακόμη'
        rgroup = identity_reseed_state.get('target_group_name') if rcurrent else f"Smart Pro Managed — {identity['installation_id']}"
        rlabelnode = identity_reseed_state.get('expected_agent_label') if rcurrent else (mesh_identity_status.get('agent_label') or '—')
        rresult = identity_reseed_state.get('result_code') if rcurrent else '—'
        relapsed = str(identity_reseed_state.get('elapsed_seconds') or '—') if rcurrent else '—'
        rsharedstop = 'ΝΑΙ' if rcurrent and identity_reseed_state.get('shared_runtime_stopped') else 'ΟΧΙ'
        rexecution = 'ΝΑΙ — FRESH CANDIDATE ONLY' if rcurrent and identity_reseed_state.get('candidate_meshagent_execution') else 'ΟΧΙ'
        rpersisted = 'ΝΑΙ — QUARANTINED' if rcurrent and identity_reseed_state.get('candidate_identity_persisted') else 'ΟΧΙ'
        rhint = identity_reseed_state.get('candidate_db_sha256_hint') if rcurrent and identity_reseed_state.get('candidate_db_sha256_hint') else '—'
        rrollback = 'ΝΑΙ' if rcurrent and identity_reseed_state.get('rollback_shared_runtime_requested') else 'ΟΧΙ'
        rrollbackstart = 'ΝΑΙ' if rcurrent and identity_reseed_state.get('rollback_shared_runtime_started') else 'ΟΧΙ'
        rcleanup = 'ΝΑΙ' if rcurrent and identity_reseed_state.get('runtime_directory_deleted') else 'ΟΧΙ'
        rexisting = 'ΝΑΙ' if (not rcurrent or identity_reseed_state.get('existing_identity_preserved') is not False) else 'ΟΧΙ'
        rdisabled = ' disabled' if (not overall or IDENTITY_RESEED_WORKER_ACTIVE or not PERSISTENT_WORKER_ACTIVE or candidate_exists) else ''
        identity_reseed_html = f"""
<section class="pairbox">
<h2>Clean per-installation identity reseed canary</h2>
<p>Νέο production-oriented μοντέλο. Σταματά προσωρινά το shared unattended runtime, διατηρεί <strong>ανέγγιχτη</strong> την υπάρχουσα stable identity ως rollback και εκτελεί το verified target .msh <strong>χωρίς το παλιό meshagent.db</strong>. Έτσι ο MeshAgent πρέπει να δημιουργήσει <strong>μία νέα candidate identity απευθείας στο {esc(rgroup)}</strong>. Η candidate αποθηκεύεται ξεχωριστά σε quarantine και δεν γίνεται ενεργή. Μετά το ≤45″ canary επανέρχεται το παλιό shared runtime. <strong>Δεν διαγράφεται κανένα παλιό node, δεν γίνεται permanent source/binding commit και δεν ενεργοποιείται technician access.</strong></p>
{('<p class="note"><strong>Candidate quarantine: PRESENT — reseed locked.</strong> Η υπάρχουσα candidate διατηρείται για το επόμενο server-side binding verification και δεν επιτρέπεται δεύτερο reseed.</p>' if candidate_exists else '')}
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(rlabel)}</strong></div>
<div><span>Target group</span><strong>{esc(rgroup)}</strong></div>
<div><span>Expected label</span><strong>{esc(rlabelnode)}</strong></div>
<div><span>Shared runtime stopped</span><strong>{esc(rsharedstop)}</strong></div>
<div><span>Fresh candidate execution</span><strong>{esc(rexecution)}</strong></div>
<div><span>Candidate identity</span><strong>{esc(rpersisted)}</strong></div>
<div><span>Candidate DB hint</span><strong>{esc(rhint)}</strong></div>
<div><span>Existing stable identity preserved</span><strong>{esc(rexisting)}</strong></div>
<div><span>Result</span><strong>{esc(rresult)}</strong></div>
<div><span>Elapsed</span><strong>{esc(relapsed)} s</strong></div>
<div><span>Runtime directory deleted</span><strong>{esc(rcleanup)}</strong></div>
<div><span>Permanent source switch</span><strong>ΟΧΙ</strong></div>
<div><span>Identity binding commit</span><strong>ΟΧΙ</strong></div>
<div><span>Old MeshCentral node delete</span><strong>ΟΧΙ</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
<div><span>Rollback requested / started</span><strong>{esc(rrollback)} / {esc(rrollbackstart)}</strong></div>
</div>
<form method="post" action="group-identity-reseed-canary">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{rdisabled}>Έναρξη clean candidate reseed canary ≤45″</button>
</form>
</section>"""

        crcurrent = (
            candidate_reconnect_state.get('installation_id') == identity['installation_id']
            and candidate_reconnect_state.get('node_id') == identity['node_id']
            and candidate_reconnect_state.get('architecture') == ARCH
        )
        crstatus = candidate_reconnect_state.get('status') if crcurrent else 'not_run'
        if crstatus == 'running':
            crlabel = 'RUNNING — QUARANTINED CANDIDATE RECONNECT ≤45″'
        elif crstatus == 'reported' and candidate_reconnect_state.get('verified') is True:
            crlabel = 'VERIFIED — EXACT BOUND CANDIDATE RECONNECTED / ROLLBACK REQUESTED'
        elif crstatus == 'failed':
            crlabel = 'FAILED — ' + (candidate_reconnect_state.get('error_message') or candidate_reconnect_state.get('result_code') or 'ελέγξτε logs')
        elif crstatus == 'stopping_shared_runtime':
            crlabel = 'PREPARING — ασφαλής τερματισμός shared runtime'
        else:
            crlabel = 'Δεν έχει εκτελεστεί ακόμη'
        crgroup = candidate_reconnect_state.get('target_group_name') if crcurrent else f"Smart Pro Managed — {identity['installation_id']}"
        crnode = candidate_reconnect_state.get('expected_agent_label') if crcurrent else (mesh_identity_status.get('agent_label') or '—')
        crdbhint = candidate_reconnect_state.get('candidate_db_sha256_hint') if crcurrent and candidate_reconnect_state.get('candidate_db_sha256_hint') else (rhint if candidate_exists else '—')
        crnodehint = candidate_reconnect_state.get('candidate_node_hint') if crcurrent and candidate_reconnect_state.get('candidate_node_hint') else '—'
        crseen = 'ΝΑΙ' if crcurrent and candidate_reconnect_state.get('candidate_seen_online') else 'ΟΧΙ'
        crshared = 'ΝΑΙ' if crcurrent and candidate_reconnect_state.get('shared_runtime_stopped') else 'ΟΧΙ'
        crexec = 'ΝΑΙ — QUARANTINED DB REUSE ONLY' if crcurrent and candidate_reconnect_state.get('candidate_meshagent_execution') else 'ΟΧΙ'
        crrollback = 'ΝΑΙ' if crcurrent and candidate_reconnect_state.get('rollback_shared_runtime_requested') else 'ΟΧΙ'
        crrollbackstart = 'ΝΑΙ' if crcurrent and candidate_reconnect_state.get('rollback_shared_runtime_started') else 'ΟΧΙ'
        crcleanup = 'ΝΑΙ' if crcurrent and candidate_reconnect_state.get('runtime_directory_deleted') else 'ΟΧΙ'
        crresult = candidate_reconnect_state.get('result_code') if crcurrent else '—'
        crelapsed = str(candidate_reconnect_state.get('elapsed_seconds') or '—') if crcurrent else '—'
        crdisabled = ' disabled' if (not overall or CANDIDATE_RECONNECT_WORKER_ACTIVE or not PERSISTENT_WORKER_ACTIVE or not candidate_exists) else ''
        candidate_reconnect_html = f"""
<section class="pairbox">
<h2>Quarantined candidate reconnect verification</h2>
<p>Επαναχρησιμοποιεί <strong>μόνο</strong> την ήδη quarantined candidate identity και το verified target .msh για ένα ≤45″ foreground proof. Ο Broker 0.41.0+ παρακολουθεί read-only μέσω του dedicated controller ότι γίνεται online το <strong>ίδιο exact bound candidate node</strong>. Μετά το test επανέρχεται το shared stable runtime. <strong>Δεν γίνεται permanent source switch, identity binding commit, old-node delete ή technician authorization.</strong></p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(crlabel)}</strong></div>
<div><span>Target group</span><strong>{esc(crgroup)}</strong></div>
<div><span>Expected label</span><strong>{esc(crnode)}</strong></div>
<div><span>Candidate DB hint</span><strong>{esc(crdbhint)}</strong></div>
<div><span>Bound candidate node hint</span><strong>{esc(crnodehint)}</strong></div>
<div><span>Candidate seen online</span><strong>{esc(crseen)}</strong></div>
<div><span>Shared runtime stopped</span><strong>{esc(crshared)}</strong></div>
<div><span>Candidate execution</span><strong>{esc(crexec)}</strong></div>
<div><span>Result</span><strong>{esc(crresult)}</strong></div>
<div><span>Elapsed</span><strong>{esc(crelapsed)} s</strong></div>
<div><span>Runtime directory deleted</span><strong>{esc(crcleanup)}</strong></div>
<div><span>Existing stable identity preserved</span><strong>ΝΑΙ</strong></div>
<div><span>Permanent source switch</span><strong>ΟΧΙ</strong></div>
<div><span>Identity binding commit</span><strong>ΟΧΙ</strong></div>
<div><span>Old MeshCentral node delete</span><strong>ΟΧΙ</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
<div><span>Rollback requested / started</span><strong>{esc(crrollback)} / {esc(crrollbackstart)}</strong></div>
</div>
<form method="post" action="candidate-reconnect-canary">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{crdisabled}>Έναρξη candidate reconnect verification ≤45″</button>
</form>
</section>"""

    return f"""<!doctype html>
<html lang="el"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart Pro Managed Support</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#10151d;color:#eef5ff;font:14px/1.5 Arial,Helvetica,sans-serif}}main{{max-width:1000px;margin:0 auto;padding:24px}}.hero{{background:#172231;border:1px solid #2c4158;border-radius:16px;padding:22px;margin-bottom:16px}}h1{{margin:0 0 5px;font-size:27px}}h2{{margin:0 0 10px;font-size:18px}}.sub{{color:#aab9ca}}.badge{{display:inline-block;margin-top:14px;padding:8px 12px;border-radius:999px;font-weight:700}}.ok{{background:#173a2a;color:#9ff0bd;border:1px solid #2c7750}}.bad{{background:#442128;color:#ffb5c0;border:1px solid #8c3d4d}}.warn{{background:#43381a;color:#ffe49a;border:1px solid #8b7331}}.note{{margin-top:15px;padding:13px 15px;border-radius:10px;background:#12293a;border:1px solid #245473;color:#cfeeff}}.notice{{margin:0 0 16px;padding:12px 14px;border-radius:10px}}.notice-ok{{background:#173a2a;border:1px solid #2c7750;color:#bdf7d0}}.notice-bad{{background:#442128;border:1px solid #8c3d4d;color:#ffd0d6}}.notice-info{{background:#12293a;border:1px solid #245473;color:#cfeeff}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.card,.pairbox{{background:#171d26;border:1px solid #293646;border-radius:12px;padding:15px}}.k{{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8fa1b5}}.v{{font-size:15px;font-weight:700;margin-top:4px;overflow-wrap:anywhere}}.pairbox{{margin:16px 0}}.pairbox p{{color:#b7c5d5}}label{{display:block;font-weight:700;margin:12px 0 6px}}input{{width:100%;max-width:460px;padding:11px 12px;border-radius:8px;border:1px solid #3b4c60;background:#0f151d;color:#fff;font:inherit}}button{{display:block;margin-top:12px;border:0;border-radius:8px;padding:10px 14px;background:#19aee8;color:#06131b;font-weight:800;cursor:pointer}}button:disabled,input:disabled{{opacity:.5;cursor:not-allowed}}code{{color:#9fdfff}}.mini-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:14px 0}}.mini-grid div{{background:#111821;border:1px solid #28384a;border-radius:9px;padding:10px}}.mini-grid span{{display:block;color:#8fa1b5;font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}}.mini-grid strong{{overflow-wrap:anywhere}}.footer{{margin-top:18px;color:#7f91a6;font-size:12px}}@media(max-width:650px){{main{{padding:14px}}.grid,.mini-grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<section class="hero"><h1>Smart Pro Managed Support</h1><div class="sub">3.14.0 · Quarantined Candidate Reconnect Verification Consumer · {esc(ARCH)}</div><span class="badge {badge_class}">{esc(badge)}</span><div class="note">{esc(reason)}</div></section>
{notice_html}
{pair_html}
{enrollment_html}
{settings_html}
{agent_html}
{runtime_html}
{canary_html}
{persistent_html}
{migration_preflight_html}
{migration_target_settings_html}
{migration_canary_html}
{identity_reseed_html}
{candidate_reconnect_html}
<section class="grid">
<div class="card"><div class="k">Installation ID</div><div class="v">{esc(policy.get('installation_id') or (identity or {}).get('installation_id'))}</div></div>
<div class="card"><div class="k">Smart Pro Tools</div><div class="v">v{esc((policy.get('source') or {}).get('addon_version'))} · Online: {esc(tools_online)}</div></div>
<div class="card"><div class="k">Portal pairing (local policy)</div><div class="v">{esc(portal_paired_local)}</div></div>
<div class="card"><div class="k">Συνδρομή</div><div class="v">{esc(subscription.get('plan'))} · {esc(subscription.get('status'))}</div></div>
<div class="card"><div class="k">Managed entitlement</div><div class="v">{esc(entitled)}</div></div>
<div class="card"><div class="k">Local policy</div><div class="v">{'ALLOWED' if local_allowed else 'DENIED'} · {esc(local_snapshot.get('reason_code'))}</div></div>
<div class="card"><div class="k">Broker identity</div><div class="v">{esc(broker_paired)} · Node {esc(node_hint)}</div></div>
<div class="card"><div class="k">Broker server authorization</div><div class="v">{esc(server_auth)} · {esc(server.get('reason_code'))}</div></div>
<div class="card"><div class="k">Server lease έως</div><div class="v">{esc(fmt_epoch(server.get('valid_until')))}</div></div>
<div class="card"><div class="k">Τελευταίο Broker heartbeat</div><div class="v">{esc(fmt_epoch(server.get('last_heartbeat_at')))}</div></div>
<div class="card"><div class="k">Authorization chain</div><div class="v">{esc(overall_text)}</div></div>
<div class="card"><div class="k">MeshCentral stable identity</div><div class="v">{esc(mesh_identity_label)} · generation {esc(mesh_identity_generation)} · runs {esc(mesh_identity_runs)} · DB {esc(mesh_identity_db_hint)} · {esc(mesh_identity_updated)}</div></div>
<div class="card"><div class="k">Remote access</div><div class="v">Όχι — το node μπορεί να είναι online, αλλά web/Terminal/Files technician actions παραμένουν NOT AUTHORIZED</div></div>
</section>
<div class="footer">3.14.0 candidate reconnect verification. Η υπάρχουσα stable identity και η quarantined candidate παραμένουν ανέγγιχτες. Η candidate DB επαναχρησιμοποιείται μόνο σε ≤45s foreground verification ώστε ο Broker να αποδείξει read-only ότι επανέρχεται το ίδιο exact bound candidate node. Δεν γίνεται permanent source/binding commit, old-node delete ή technician authorization.</div>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartProManaged/3.14.0"

    def _send(self, code, body, content_type):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'self'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        local = read_policy()
        if path in ("/healthz", "/api/health"):
            policy = local.get("policy") if isinstance(local.get("policy"), dict) else {}
            server = get_server_state()
            server_allowed = bool(server.get("authorized_server")) and (_as_int(server.get("valid_until")) or 0) > now_ts()
            overall = bool(local.get("allowed_local")) and server_allowed and load_identity() is not None
            payload = {
                "service": "smart_pro_managed_support",
                "version": VERSION,
                "local_state": local.get("state"),
                "allowed_local": bool(local.get("allowed_local")),
                "broker_paired": load_identity() is not None,
                "server_state": server.get("state"),
                "authorized_server": server_allowed,
                "authorized_managed": overall,
                "server_reason_code": server.get("reason_code"),
                "server_valid_until": _as_int(server.get("valid_until")) or 0,
                "remote_access": False,
                "meshcentral": False,
                "enrollment_authorization_verified_once": bool(load_enrollment_state().get("verified")),
                "enrollment_source_fingerprint_hint": load_enrollment_state().get("source_fingerprint_hint") or "",
                "secure_settings_verified_once": bool(load_settings_state().get("verified")),
                "secure_settings_source_fingerprint_hint": load_settings_state().get("source_fingerprint_hint") or "",
                "secure_settings_sha256_hint": load_settings_state().get("sha256_hint") or "",
                "agent_binary_verified_once": bool(load_agent_state().get("verified")),
                "agent_binary_sha256_hint": load_agent_state().get("sha256_hint") or "",
                "agent_binary_architecture": load_agent_state().get("architecture") or "",
                "runtime_lease_dry_run_status": load_runtime_state().get("status") or "not_run",
                "runtime_lease_renewed_once": bool(load_runtime_state().get("verified")),
                "runtime_execution": bool(PERSISTENT_WORKER_ACTIVE),
                "runtime_meshcentral": bool(PERSISTENT_WORKER_ACTIVE),
                "connectivity_canary_status": load_canary_state().get("status") or "not_run",
                "connectivity_canary_verified": bool(load_canary_state().get("verified")),
                "continuous_runtime_status": load_persistent_state().get("status") or "not_run",
                "continuous_runtime_active": bool(PERSISTENT_WORKER_ACTIVE),
                "continuous_runtime_health": load_persistent_state().get("health_state") or "",
                "continuous_runtime_lease_renewals": load_persistent_state().get("lease_renewals") or 0,
                "continuous_runtime_reconnects": load_persistent_state().get("reconnect_count") or 0,
                "group_migration_preflight_status": load_group_migration_preflight_state().get("status") or "not_run",
                "group_migration_preflight_verified": bool(load_group_migration_preflight_state().get("verified")),
                "group_migration_target_settings_status": load_group_migration_target_settings_state().get("status") or "not_run",
                "group_migration_target_settings_verified": bool(load_group_migration_target_settings_state().get("verified")),
                "group_migration_canary_status": load_group_migration_canary_state().get("status") or "not_run",
                "group_migration_canary_verified": bool(load_group_migration_canary_state().get("verified")),
                "group_migration_canary_active": bool(MIGRATION_CANARY_WORKER_ACTIVE),
                "group_identity_reseed_canary_active": bool(IDENTITY_RESEED_WORKER_ACTIVE),
                "candidate_reconnect_status": load_candidate_reconnect_state().get("status") or "not_run",
                "candidate_reconnect_verified": bool(load_candidate_reconnect_state().get("verified")),
                "candidate_reconnect_active": bool(CANDIDATE_RECONNECT_WORKER_ACTIVE),
                "unattended_runtime_enabled": bool(load_unattended_control().get("enabled")),
                "technician_actions_authorized": False,
                "installation_id": policy.get("installation_id") or server.get("installation_id"),
            }
            self._send(200, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")
            return
        self._send(200, render_page(local), "text/html; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        is_pair = path.endswith("/pair") or path == "pair"
        is_enrollment = path.endswith("/enrollment-check") or path == "enrollment-check"
        is_settings = path.endswith("/settings-check") or path == "settings-check"
        is_agent = path.endswith("/agent-check") or path == "agent-check"
        is_runtime = path.endswith("/runtime-lease-check") or path == "runtime-lease-check"
        is_canary = path.endswith("/identity-continuity-canary") or path == "identity-continuity-canary"
        is_persistent_start = path.endswith("/continuous-runtime-start") or path == "continuous-runtime-start"
        is_persistent_stop = path.endswith("/continuous-runtime-stop") or path == "continuous-runtime-stop"
        is_group_migration_preflight = path.endswith("/group-migration-preflight") or path == "group-migration-preflight"
        is_group_migration_target_settings = path.endswith("/group-migration-target-settings") or path == "group-migration-target-settings"
        is_group_migration_canary = path.endswith("/group-migration-canary") or path == "group-migration-canary"
        is_group_identity_reseed_canary = path.endswith("/group-identity-reseed-canary") or path == "group-identity-reseed-canary"
        is_candidate_reconnect_canary = path.endswith("/candidate-reconnect-canary") or path == "candidate-reconnect-canary"
        if not is_pair and not is_enrollment and not is_settings and not is_agent and not is_runtime and not is_canary and not is_persistent_start and not is_persistent_stop and not is_group_migration_preflight and not is_group_migration_target_settings and not is_group_migration_canary and not is_group_identity_reseed_canary and not is_candidate_reconnect_canary:
            self._send(404, "Not found", "text/plain; charset=utf-8")
            return
        length = _as_int(self.headers.get("Content-Length")) or 0
        if length <= 0 or length > MAX_POST_BYTES:
            self._send(400, render_page(read_policy(), "Μη έγκυρο αίτημα ενεργοποίησης.", "bad"), "text/html; charset=utf-8")
            return
        raw = self.rfile.read(length)
        try:
            form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        except UnicodeError:
            form = {}
        csrf = _safe_str((form.get("csrf") or [""])[0], 100)
        if not secrets.compare_digest(csrf, CSRF_TOKEN):
            self._send(403, render_page(read_policy(), "Η φόρμα ενεργοποίησης έληξε. Ανανεώστε τη σελίδα.", "bad"), "text/html; charset=utf-8")
            return
        if PERSISTENT_WORKER_ACTIVE and not (is_persistent_stop or is_group_migration_preflight or is_group_migration_target_settings or is_group_migration_canary or is_group_identity_reseed_canary or is_candidate_reconnect_canary):
            self._send(409, render_page(read_policy(), "Η continuous Managed λειτουργία είναι ενεργή. Επιτρέπονται μόνο ασφαλής τερματισμός ή οι verification-only migration έλεγχοι.", "bad"), "text/html; charset=utf-8")
            return
        if is_pair:
            if load_identity() is not None:
                self._send(409, render_page(read_policy(), "Υπάρχει ήδη ενεργή Managed identity σε αυτό το add-on.", "bad"), "text/html; charset=utf-8")
                return
            code = (form.get("pairing_code") or [""])[0]
            try:
                pair_with_broker(code)
                self._send(200, render_page(read_policy(), "Η Managed identity ενεργοποιήθηκε και έγινε η πρώτη server-side επαλήθευση.", "ok"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                text = str(exc)
                _, _, message = text.partition("|")
                self._send(400, render_page(read_policy(), message or "Η ενεργοποίηση απέτυχε.", "bad"), "text/html; charset=utf-8")
            return

        if is_enrollment:
            try:
                verify_enrollment_authorization()
                self._send(
                    200,
                    render_page(
                        read_policy(),
                        "Το one-time enrollment authorization εκδόθηκε, καταναλώθηκε και επαληθεύτηκε. Δεν αποθηκεύτηκε ticket και δεν ενεργοποιήθηκε remote access.",
                        "ok",
                    ),
                    "text/html; charset=utf-8",
                )
            except RuntimeError as exc:
                text = str(exc)
                _, _, message = text.partition("|")
                self._send(
                    400,
                    render_page(read_policy(), message or "Ο έλεγχος enrollment authorization απέτυχε.", "bad"),
                    "text/html; charset=utf-8",
                )
            return

        if is_group_migration_preflight:
            try:
                verify_group_migration_preflight()
                self._send(
                    200,
                    render_page(
                        read_policy(),
                        "Το per-installation migration preflight επαληθεύτηκε. Η stable identity, το target group, το controller binding και η server authorization συμφωνούν. Δεν παραδόθηκε target .msh, δεν μετακινήθηκε node και το ενεργό runtime source παραμένει αμετάβλητο.",
                        "ok",
                    ),
                    "text/html; charset=utf-8",
                )
            except RuntimeError as exc:
                text = str(exc)
                _, _, message = text.partition('|')
                self._send(409, render_page(read_policy(), message or "Το migration preflight απέτυχε.", "bad"), "text/html; charset=utf-8")
            return

        if is_settings:
            try:
                verify_secure_settings()
                self._send(
                    200,
                    render_page(
                        read_policy(),
                        "Το secure .msh παραλήφθηκε, επαληθεύτηκε τοπικά και δεν αποθηκεύτηκε. MeshAgent και remote access παραμένουν ανενεργά.",
                        "ok",
                    ),
                    "text/html; charset=utf-8",
                )
            except RuntimeError as exc:
                text = str(exc)
                _, _, message = text.partition("|")
                self._send(
                    400,
                    render_page(read_policy(), message or "Ο έλεγχος secure settings απέτυχε.", "bad"),
                    "text/html; charset=utf-8",
                )
            return

        if is_group_migration_target_settings:
            try:
                verify_group_migration_target_settings()
                self._send(
                    200,
                    render_page(
                        read_policy(),
                        "Το per-installation target .msh παραδόθηκε one-time και επαληθεύτηκε αυστηρά μόνο στη μνήμη. Δεν εκτελέστηκε MeshAgent, δεν μετακινήθηκε node, δεν άλλαξε runtime source και δεν έγινε identity-binding commit.",
                        "ok",
                    ),
                    "text/html; charset=utf-8",
                )
            except RuntimeError as exc:
                message = str(exc).partition('|')[2] or "Το target .msh verification απέτυχε."
                self._send(409, render_page(read_policy(), message, "bad"), "text/html; charset=utf-8")
            return

        if is_group_migration_canary:
            try:
                start_group_migration_canary()
                self._send(202, render_page(read_policy(), "Το controlled migration canary ξεκίνησε. Κρατήστε ανοιχτό το MeshCentral: η ΙΔΙΑ stable συσκευή πρέπει προσωρινά να εμφανιστεί στο Smart Pro Managed — ID-95948 και μετά, όταν λήξει το canary, να επιστρέψει αυτόματα στο shared group. Μην ανοίξετε Desktop/Terminal/Files. Κάντε refresh εδώ μετά από περίπου 55–70 δευτερόλεπτα.", "info"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                message=str(exc).partition('|')[2] or "Δεν ήταν δυνατή η εκκίνηση του controlled migration canary."
                self._send(409,render_page(read_policy(),message,"bad"),"text/html; charset=utf-8")
            return


        if is_group_identity_reseed_canary:
            try:
                start_group_identity_reseed_canary()
                self._send(202, render_page(read_policy(), "Το clean candidate reseed canary ξεκίνησε. Κρατήστε ανοιχτό το MeshCentral. Το παλιό shared node θα πέσει προσωρινά offline και πρέπει να εμφανιστεί ΑΚΡΙΒΩΣ ΜΙΑ νέα candidate συσκευή στο Smart Pro Managed — ID-95948. Μετά από ≤45″ η candidate θα σταματήσει και το παλιό shared runtime θα επανέλθει. Μην ανοίξετε Desktop/Terminal/Files και μην διαγράψετε καμία συσκευή. Κάντε refresh εδώ μετά από περίπου 60–90 δευτερόλεπτα.", "info"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                message=str(exc).partition('|')[2] or "Δεν ήταν δυνατή η εκκίνηση του clean identity reseed canary."
                self._send(409,render_page(read_policy(),message,"bad"),"text/html; charset=utf-8")
            return

        if is_candidate_reconnect_canary:
            try:
                start_candidate_reconnect_canary()
                self._send(202, render_page(read_policy(), "Το quarantined candidate reconnect verification ξεκίνησε. Κρατήστε ανοιχτό το MeshCentral: το shared stable node θα πέσει προσωρινά offline και πρέπει να ξαναγίνει online η ΗΔΗ ΥΠΑΡΧΟΥΣΑ candidate στο Smart Pro Managed — ID-95948, χωρίς να δημιουργηθεί νέα συσκευή. Μετά από ≤45″ η candidate θα σταματήσει και το shared runtime θα επανέλθει. Μην ανοίξετε Desktop/Terminal/Files και μην διαγράψετε/μετακινήσετε καμία συσκευή. Κάντε refresh εδώ μετά από περίπου 60–90 δευτερόλεπτα.", "info"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                message=str(exc).partition('|')[2] or "Δεν ήταν δυνατή η εκκίνηση του candidate reconnect verification."
                self._send(409,render_page(read_policy(),message,"bad"),"text/html; charset=utf-8")
            return

        if is_persistent_start:
            try:
                save_unattended_control(True, 'admin_enabled')
                start_persistent_runtime()
                self._send(202, render_page(read_policy(), "Το unattended Managed runtime ενεργοποιήθηκε και ξεκίνησε με την ΙΔΙΑ σταθερή συσκευή. Από εδώ και πέρα το add-on μπορεί να το επαναφέρει αυτόματα μετά από restart, μόνο όταν local policy και Broker authorization είναι έγκυρα. Technician actions παραμένουν κλειστά.", "info"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                save_unattended_control(False, 'enable_start_failed')
                message = str(exc).partition('|')[2] or "Δεν ήταν δυνατή η ενεργοποίηση του unattended Managed runtime."
                self._send(409, render_page(read_policy(), message, "bad"), "text/html; charset=utf-8")
            return

        if is_persistent_stop:
            save_unattended_control(False, 'admin_paused')
            if PERSISTENT_WORKER_ACTIVE:
                try:
                    stop_persistent_runtime()
                    self._send(202, render_page(read_policy(), "Το unattended mode απενεργοποιήθηκε και ζητήθηκε ασφαλής τερματισμός του ενεργού runtime. Δεν θα επανεκκινήσει αυτόματα μέχρι νέα ρητή ενεργοποίηση.", "info"), "text/html; charset=utf-8")
                except RuntimeError as exc:
                    message = str(exc).partition('|')[2] or "Δεν ήταν δυνατή η παύση του unattended Managed runtime."
                    self._send(409, render_page(read_policy(), message, "bad"), "text/html; charset=utf-8")
            else:
                self._send(200, render_page(read_policy(), "Το unattended mode είναι πλέον απενεργοποιημένο. Δεν υπήρχε ενεργό runtime για τερματισμό.", "ok"), "text/html; charset=utf-8")
            return

        if is_canary:
            try:
                start_connectivity_canary()
                self._send(202, render_page(read_policy(), "Το identity continuity canary ξεκίνησε. Παρατηρήστε μόνο το expected SPMNG node στο MeshCentral. Μην ανοίξετε Desktop/Terminal/Files. Κάντε refresh εδώ μετά από περίπου 50–60 δευτερόλεπτα.", "info"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                message = str(exc).partition('|')[2] or "Δεν ήταν δυνατή η εκκίνηση του identity continuity canary."
                self._send(409, render_page(read_policy(), message, "bad"), "text/html; charset=utf-8")
            return

        if is_runtime:
            try:
                start_runtime_lease_dry_run()
                self._send(
                    202,
                    render_page(
                        read_policy(),
                        f"Το runtime lease dry-run ξεκίνησε. Θα ανανεώσει πρώτα enrollment/settings/agent verification και θα κάνει μία αυτόματη ανανέωση lease μετά από περίπου {RUNTIME_RENEW_DELAY} δευτερόλεπτα. Κάντε refresh σε περίπου 80–90 δευτερόλεπτα.",
                        "info",
                    ),
                    "text/html; charset=utf-8",
                )
            except RuntimeError as exc:
                message = str(exc).partition("|")[2] or "Δεν ήταν δυνατή η εκκίνηση του runtime lease dry-run."
                self._send(
                    409,
                    render_page(read_policy(), message, "bad"),
                    "text/html; charset=utf-8",
                )
            return

        try:
            verify_agent_binary()
            self._send(
                200,
                render_page(
                    read_policy(),
                    "Το MeshAgent binary παραλήφθηκε, επαληθεύτηκε δύο φορές από SHA/bytes/ELF/architecture και διαγράφηκε. Δεν έγινε εκτελέσιμο και δεν εκτελέστηκε.",
                    "ok",
                ),
                "text/html; charset=utf-8",
            )
        except RuntimeError as exc:
            text = str(exc)
            _, _, message = text.partition("|")
            self._send(
                400,
                render_page(read_policy(), message or "Ο έλεγχος MeshAgent binary απέτυχε.", "bad"),
                "text/html; charset=utf-8",
            )

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[managed] Smart Pro Managed Support {VERSION} quarantined candidate reconnect verification consumer listening on {PORT}", flush=True)
    boot_identity = get_mesh_identity_status(load_identity())
    boot_control = load_unattended_control()
    print(f"[managed] mesh identity state={boot_identity.get('state')} generation={boot_identity.get('generation', 0)} continuity_runs={boot_identity.get('continuity_runs', 0)}; unattended_enabled={str(bool(boot_control.get('enabled'))).lower()}", flush=True)
    thread = threading.Thread(target=heartbeat_worker, name="managed-heartbeat", daemon=True)
    thread.start()
    unattended_thread = threading.Thread(target=unattended_supervisor, name="managed-unattended-supervisor", daemon=True)
    unattended_thread.start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
