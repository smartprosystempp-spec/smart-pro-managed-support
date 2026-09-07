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

VERSION = os.environ.get("SMART_PRO_MANAGED_VERSION", "3.6.0")
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
CANARY_STATE_FILE = DATA_DIR / "connectivity-canary.json"
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
CANARY_POLL_FALLBACK = 5
NODE_ID_RE = re.compile(r"^SPMN-[A-F0-9]{32}$")
NODE_SECRET_RE = re.compile(r"^SPMS-[A-Za-z0-9_-]{43}$")
BOOTSTRAP_TICKET_RE = re.compile(r"^SPMB-[A-Za-z0-9_-]{43}$")
SETTINGS_TICKET_RE = re.compile(r"^SPMD-[A-Za-z0-9_-]{43}$")
AGENT_TICKET_RE = re.compile(r"^SPMA-[A-Za-z0-9_-]{43}$")
RUNTIME_LEASE_RE = re.compile(r"^SPMRL-[A-Za-z0-9_-]{43}$")
CANARY_TICKET_RE = re.compile(r"^SPMEC-[A-Za-z0-9_-]{43}$")
CANARY_REPORT_RE = re.compile(r"^SPMER-[A-Za-z0-9_-]{43}$")
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
    """Refresh the full 3.6.0 verification chain, issue one lease and renew it once.

    The raw SPMRL lease exists only in this worker's local memory. It is never
    persisted, rendered or logged. 3.6.0 never executes MeshAgent.
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

        # This refreshes enrollment + secure settings under 3.6.0, verifies the
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
    }


def _execution_settings_material(identity):
    """Fresh 3.6.0 enrollment + secure-settings consume, returning raw .msh only in memory."""
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
    if not ok: raise RuntimeError('canary_settings_request_invalid|Ο Broker επέστρεψε μη έγκυρο secure settings contract για το connectivity canary.')
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
    if not ok: raise RuntimeError('canary_settings_consume_invalid|Η κατανάλωση secure settings για το connectivity canary απέτυχε.')
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
    """Consume one 3.6.0 agent ticket and keep the verified 0600 temp binary until canary cleanup."""
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
    if not ok: raise RuntimeError('canary_agent_request_invalid|Ο Broker επέστρεψε μη έγκυρο MeshAgent contract για το connectivity canary.')
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
    drop = {'forceUpdate','fakeUpdate','coreDumpEnabled','disableUpdate','noUpdateCoreModule'}
    lines=[]
    for line in text.splitlines():
        key = line.split('=',1)[0].strip() if '=' in line else ''
        if key in drop: continue
        lines.append(line)
    lines += ['disableUpdate=1','noUpdateCoreModule=1']
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
    max_runtime=0; agent_label=''; cleanup_ok=True
    try:
        if identity is None: raise RuntimeError('not_paired|Απαιτείται ενεργή Managed identity πριν από το connectivity canary.')
        if not read_policy().get('allowed_local'): raise RuntimeError('local_policy_denied|Η τοπική Managed πολιτική δεν επιτρέπει connectivity canary.')
        server=get_server_state(); server_until=_as_int(server.get('valid_until')) or 0
        if server.get('authorized_server') is not True or server_until <= now_ts():
            raise RuntimeError('server_authorization_required|Απαιτείται ενεργό Broker Server Authorization πριν από το connectivity canary.')
        save_canary_state({'status':'preparing','verified':False,'started_at':started,'installation_id':identity['installation_id'],
            'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH})

        settings = _execution_settings_material(identity); agent_label=settings['agent_label']
        agent = _execution_agent_material(identity, settings); agent_temp=agent['path']
        common={'node_id':identity['node_id'],'node_secret':identity['node_secret'],'client_version':VERSION,'architecture':ARCH}
        lease=broker_post('/managed/runtime-lease/request', common); lease_token=_safe_str(lease.get('runtime_lease'),90)
        lease_exp=parse_iso_epoch(lease.get('expires_at'))
        if not (lease.get('success') is True and lease.get('runtime_contract')=='smart-pro-managed-runtime-lease-v1'
                and lease.get('runtime_authorized') is True and lease.get('execution') is False and RUNTIME_LEASE_RE.fullmatch(lease_token)
                and lease_exp>now_ts()):
            raise RuntimeError('canary_runtime_lease_invalid|Δεν εκδόθηκε έγκυρο runtime lease για το canary.')
        can_req=dict(common); can_req['runtime_lease']=lease_token
        auth=broker_post('/managed/execution-canary/request', can_req)
        canary_ticket=_safe_str(auth.get('canary_ticket'),90); report_token=_safe_str(auth.get('report_token'),90)
        max_runtime=min(CANARY_LOCAL_MAX_RUNTIME,_as_int(auth.get('max_runtime_seconds')) or 0)
        if not (auth.get('success') is True and auth.get('canary_contract')=='smart-pro-managed-execution-canary-v1'
                and auth.get('state')=='canary_ticket_issued_runtime_not_started' and auth.get('foreground_only') is True
                and auth.get('install') is False and auth.get('service_persistence') is False
                and auth.get('technician_actions_authorized') is False and CANARY_TICKET_RE.fullmatch(canary_ticket)
                and CANARY_REPORT_RE.fullmatch(report_token) and 1 <= max_runtime <= CANARY_LOCAL_MAX_RUNTIME):
            raise RuntimeError('canary_authorization_invalid|Ο Broker δεν επέστρεψε έγκυρη connectivity-canary authorization.')
        consume=dict(common); consume['canary_ticket']=canary_ticket
        run=broker_post('/managed/execution-canary/consume',consume)
        hard_deadline=parse_iso_epoch(run.get('hard_deadline')); watch_interval=_as_int(run.get('watch_interval_seconds')) or CANARY_POLL_FALLBACK
        if not (run.get('success') is True and run.get('canary_contract')=='smart-pro-managed-execution-canary-v1'
                and run.get('state')=='canary_execution_authorized_connectivity_only' and run.get('foreground_only') is True
                and run.get('install') is False and run.get('service_persistence') is False
                and run.get('meshcentral_connectivity_canary') is True and run.get('technician_actions_authorized') is False
                and 1 <= (_as_int(run.get('max_runtime_seconds')) or 0) <= CANARY_LOCAL_MAX_RUNTIME and hard_deadline>now_ts()):
            raise RuntimeError('canary_consume_invalid|Η execution-canary authorization δεν καταναλώθηκε σωστά.')
        max_runtime=min(max_runtime,_as_int(run.get('max_runtime_seconds')) or max_runtime)

        runtime_dir=Path(tempfile.mkdtemp(prefix='smart-pro-managed-canary-',dir='/tmp')); os.chmod(runtime_dir,0o700)
        agent_path=runtime_dir/'meshagent'; shutil.move(agent_temp,agent_path); agent_temp=None; os.chmod(agent_path,0o700)
        msh_path=runtime_dir/'meshagent.msh'; hardened=_harden_runtime_msh(settings['raw'],agent_label)
        fd=os.open(msh_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as h: h.write(hardened); h.flush(); os.fsync(h.fileno())
        private=runtime_dir/'private'; private.mkdir(mode=0o700)
        env=os.environ.copy(); env.update({'HOME':str(private),'TMPDIR':str(private),'XDG_CONFIG_HOME':str(private),'XDG_CACHE_HOME':str(private)})
        save_canary_state({'status':'running','verified':False,'started_at':now_ts(),'max_runtime_seconds':max_runtime,'agent_label':agent_label,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH})
        proc=subprocess.Popen(['setsid','./meshagent'],cwd=str(runtime_dir),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              env=env,close_fds=True)
        run_started=time.monotonic(); result='runtime_limit'
        while True:
            elapsed=int(time.monotonic()-run_started)
            if proc.poll() is not None:
                result='agent_exit'; break
            if elapsed >= max_runtime or now_ts() >= hard_deadline:
                result='runtime_limit'; break
            if not read_policy().get('allowed_local'):
                result='runtime_lease_lost'; break
            watch=broker_post('/managed/execution-canary/watch',{'report_token':report_token,'node_id':identity['node_id'],'node_secret':identity['node_secret']})
            if watch.get('continue') is not True:
                reason=_safe_str(watch.get('reason'),80)
                result='runtime_limit' if reason=='canary_runtime_limit' else 'runtime_lease_lost'
                break
            time.sleep(max(1,min(10,watch_interval)))
        _terminate_process_group(proc)
        elapsed=int(time.monotonic()-run_started)
        report_ok=_report_canary(identity,report_token,result,elapsed)
        save_canary_state({'status':'reported' if report_ok else 'failed','verified':report_ok,'started_at':started,'ended_at':now_ts(),
            'result_code':result,'elapsed_seconds':elapsed,'max_runtime_seconds':max_runtime,'agent_label':agent_label,
            'installation_id':identity['installation_id'],'node_id':identity['node_id'],'client_version':VERSION,'architecture':ARCH,
            'runtime_directory_deleted':False})
    except (RuntimeError,OSError,subprocess.SubprocessError) as exc:
        if proc is not None: _terminate_process_group(proc)
        elapsed=max(0,now_ts()-started)
        if report_token: _report_canary(identity,report_token,'launch_failed',elapsed)
        code,msg=(str(exc).split('|',1)+[''])[:2] if '|' in str(exc) else ('canary_failed',str(exc))
        save_canary_state({'status':'failed','verified':False,'started_at':started,'ended_at':now_ts(),'result_code':code,'elapsed_seconds':elapsed,
            'max_runtime_seconds':max_runtime,'agent_label':agent_label,'installation_id':(identity or {}).get('installation_id',''),
            'node_id':(identity or {}).get('node_id',''),'client_version':VERSION,'architecture':ARCH,'runtime_directory_deleted':False})
        print(f"[managed] connectivity canary failed code={code}; no raw credentials/tokens logged",flush=True)
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
        if CANARY_WORKER_ACTIVE: raise RuntimeError('canary_already_running|Υπάρχει ήδη connectivity canary σε εξέλιξη.')
        CANARY_WORKER_ACTIVE=True
    t=threading.Thread(target=connectivity_canary_worker,name='managed-connectivity-canary',daemon=True); t.start()

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

    local_allowed = bool(local_snapshot.get("allowed_local"))
    server_allowed = bool(server.get("authorized_server")) and (_as_int(server.get("valid_until")) or 0) > now_ts()
    overall = local_allowed and server_allowed and identity is not None

    if overall:
        badge_class, badge = "ok", "Managed authorization: ΕΠΙΤΡΕΠΕΤΑΙ"
        reason = "Local Policy και Broker Server Authorization συμφωνούν. Το remote access παραμένει κλειστό μέχρι το επόμενο MeshCentral στάδιο."
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
    if identity is not None:
        enrollment_verified = (
            enrollment.get("verified") is True
            and enrollment.get("installation_id") == identity["installation_id"]
            and enrollment.get("node_id") == identity["node_id"]
        )
        enrollment_current = enrollment_verified and enrollment.get("client_version") == VERSION and enrollment.get("architecture") == ARCH
        if enrollment_current:
            enrollment_label = "VERIFIED — τρέχον 3.6.0 enrollment consume"
        elif enrollment_verified:
            enrollment_label = f"Προηγούμενο VERIFIED ({enrollment.get('client_version') or 'άγνωστη έκδοση'}) — θα ανανεωθεί αυτόματα"
        else:
            enrollment_label = "Δεν έχει εκτελεστεί ακόμη"
        enrollment_time = fmt_epoch(enrollment.get("verified_at")) if enrollment_verified else "—"
        enrollment_hint = enrollment.get("source_fingerprint_hint") if enrollment_verified else "—"
        disabled = "" if overall else " disabled"
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
            settings_label = "VERIFIED — τρέχον 3.6.0 .msh verification"
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
<p>Εκτελεί νέο enrollment authorization για την 3.6.0 και μετά ζητά/καταναλώνει ακριβώς ένα one-time secure settings ticket. Το raw ticket και το <strong>.msh δεν αποθηκεύονται</strong>. Ελέγχονται integrity, required fields, ασφαλές WSS endpoint και opaque node label.</p>
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
<p>Ανανεώνει αυτόματα enrollment + secure settings για την 3.6.0 και μετά ζητά/καταναλώνει ακριβώς ένα one-time MeshAgent binary ticket. Το binary γράφεται μόνο προσωρινά με mode 0600, ελέγχεται SHA/bytes/ELF64/architecture δεύτερη φορά από disk και <strong>διαγράφεται αμέσως</strong>. Δεν γίνεται chmod +x ή execution.</p>
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
            runtime_label = "RUNNING — ανανεώνεται η αλυσίδα 3.6.0"
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
<p>Ανανεώνει αυτόματα enrollment + secure settings + MeshAgent verification για την 3.6.0, ζητά ένα βραχύβιο server-authoritative runtime lease και το ανανεώνει <strong>μία φορά</strong> μετά από περίπου {RUNTIME_RENEW_DELAY} δευτερόλεπτα. Το raw lease μένει μόνο στη μνήμη και απορρίπτεται μετά τον έλεγχο. <strong>Δεν εκτελείται MeshAgent</strong> και δεν ανοίγει MeshCentral/remote access.</p>
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


        canary_current = (
            canary_state.get('client_version') == VERSION and canary_state.get('architecture') == ARCH
            and canary_state.get('installation_id') == identity['installation_id'] and canary_state.get('node_id') == identity['node_id']
        )
        cstatus = canary_state.get('status') if canary_current else 'not_run'
        if cstatus == 'running': canary_label = 'RUNNING — connectivity-only foreground canary'
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
        canary_disabled = ' disabled' if (not overall or CANARY_WORKER_ACTIVE) else ''
        canary_html = f"""
<section class="pairbox">
<h2>MeshAgent connectivity canary</h2>
<p>Εκτελεί την πλήρη verified αλυσίδα της 3.6.0, αποκτά runtime lease + one-time execution canary και ξεκινά <strong>μόνο foreground MeshAgent connectivity</strong> για έως 45″. Δεν χρησιμοποιείται <code>-install</code>, δεν δημιουργείται service και <strong>δεν εξουσιοδοτούνται Desktop / Terminal / Files</strong>. Το private runtime directory διαγράφεται στο τέλος.</p>
<div class="mini-grid">
<div><span>Κατάσταση</span><strong>{esc(canary_label)}</strong></div>
<div><span>Έναρξη</span><strong>{esc(cstart)}</strong></div>
<div><span>Λήξη</span><strong>{esc(cend)}</strong></div>
<div><span>Αποτέλεσμα</span><strong>{esc(cresult)}</strong></div>
<div><span>Elapsed / Max</span><strong>{esc(celapsed)}s / {esc(cmax)}s</strong></div>
<div><span>Expected node</span><strong>{esc(clabel)}</strong></div>
<div><span>Runtime cleanup</span><strong>{esc(cclean)}</strong></div>
<div><span>Technician actions</span><strong>NOT AUTHORIZED</strong></div>
<div><span>Persistence</span><strong>OFF</strong></div>
</div>
<form method="post" action="connectivity-canary">
<input type="hidden" name="csrf" value="{esc(CSRF_TOKEN)}">
<button type="submit"{canary_disabled}>Έναρξη connectivity canary ≤45″</button>
</form>
</section>"""

    return f"""<!doctype html>
<html lang="el"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart Pro Managed Support</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#10151d;color:#eef5ff;font:14px/1.5 Arial,Helvetica,sans-serif}}main{{max-width:1000px;margin:0 auto;padding:24px}}.hero{{background:#172231;border:1px solid #2c4158;border-radius:16px;padding:22px;margin-bottom:16px}}h1{{margin:0 0 5px;font-size:27px}}h2{{margin:0 0 10px;font-size:18px}}.sub{{color:#aab9ca}}.badge{{display:inline-block;margin-top:14px;padding:8px 12px;border-radius:999px;font-weight:700}}.ok{{background:#173a2a;color:#9ff0bd;border:1px solid #2c7750}}.bad{{background:#442128;color:#ffb5c0;border:1px solid #8c3d4d}}.warn{{background:#43381a;color:#ffe49a;border:1px solid #8b7331}}.note{{margin-top:15px;padding:13px 15px;border-radius:10px;background:#12293a;border:1px solid #245473;color:#cfeeff}}.notice{{margin:0 0 16px;padding:12px 14px;border-radius:10px}}.notice-ok{{background:#173a2a;border:1px solid #2c7750;color:#bdf7d0}}.notice-bad{{background:#442128;border:1px solid #8c3d4d;color:#ffd0d6}}.notice-info{{background:#12293a;border:1px solid #245473;color:#cfeeff}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.card,.pairbox{{background:#171d26;border:1px solid #293646;border-radius:12px;padding:15px}}.k{{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8fa1b5}}.v{{font-size:15px;font-weight:700;margin-top:4px;overflow-wrap:anywhere}}.pairbox{{margin:16px 0}}.pairbox p{{color:#b7c5d5}}label{{display:block;font-weight:700;margin:12px 0 6px}}input{{width:100%;max-width:460px;padding:11px 12px;border-radius:8px;border:1px solid #3b4c60;background:#0f151d;color:#fff;font:inherit}}button{{display:block;margin-top:12px;border:0;border-radius:8px;padding:10px 14px;background:#19aee8;color:#06131b;font-weight:800;cursor:pointer}}button:disabled,input:disabled{{opacity:.5;cursor:not-allowed}}code{{color:#9fdfff}}.mini-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:14px 0}}.mini-grid div{{background:#111821;border:1px solid #28384a;border-radius:9px;padding:10px}}.mini-grid span{{display:block;color:#8fa1b5;font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}}.mini-grid strong{{overflow-wrap:anywhere}}.footer{{margin-top:18px;color:#7f91a6;font-size:12px}}@media(max-width:650px){{main{{padding:14px}}.grid,.mini-grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<section class="hero"><h1>Smart Pro Managed Support</h1><div class="sub">3.6.0 · Foreground MeshAgent Connectivity Canary · {esc(ARCH)}</div><span class="badge {badge_class}">{esc(badge)}</span><div class="note">{esc(reason)}</div></section>
{notice_html}
{pair_html}
{enrollment_html}
{settings_html}
{agent_html}
{runtime_html}
{canary_html}
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
<div class="card"><div class="k">Remote access</div><div class="v">Όχι — technician actions δεν είναι εξουσιοδοτημένες (connectivity canary μόνο)</div></div>
</section>
<div class="footer">3.6.0 connectivity-canary client. Η κανονική λειτουργία παραμένει fail-closed. Μόνο το χειροκίνητο canary μπορεί να εκτελέσει foreground MeshAgent έως 45″, χωρίς -install/service persistence και χωρίς authorization για Desktop/Terminal/Files.</div>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartProManaged/3.6.0"

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
                "runtime_execution": False,
                "runtime_meshcentral": False,
                "connectivity_canary_status": load_canary_state().get("status") or "not_run",
                "connectivity_canary_verified": bool(load_canary_state().get("verified")),
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
        is_canary = path.endswith("/connectivity-canary") or path == "connectivity-canary"
        if not is_pair and not is_enrollment and not is_settings and not is_agent and not is_runtime and not is_canary:
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

        if is_canary:
            try:
                start_connectivity_canary()
                self._send(202, render_page(read_policy(), "Το connectivity canary ξεκίνησε. Ανοίξτε αμέσως το MeshCentral και παρατηρήστε μόνο αν εμφανίζεται το expected SPMNG node. Μην ανοίξετε Desktop/Terminal/Files. Κάντε refresh εδώ μετά από περίπου 50–60 δευτερόλεπτα.", "info"), "text/html; charset=utf-8")
            except RuntimeError as exc:
                message = str(exc).partition('|')[2] or "Δεν ήταν δυνατή η εκκίνηση του connectivity canary."
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
    print(f"[managed] Smart Pro Managed Support {VERSION} foreground connectivity canary client listening on {PORT}", flush=True)
    thread = threading.Thread(target=heartbeat_worker, name="managed-heartbeat", daemon=True)
    thread.start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
