#!/usr/bin/env python3
import html
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

VERSION = os.environ.get("SMART_PRO_MANAGED_VERSION", "3.1.0")
ARCH = os.environ.get("SMART_PRO_MANAGED_ARCH", "unknown")
PORT = 8098
BROKER_BASE = os.environ.get(
    "SMART_PRO_BROKER_BASE_URL",
    "https://smart-pro-system.gr/wp-json/smart-pro-remote/v1",
).rstrip("/")
POLICY_FILE = Path("/share/smart-pro-system/managed-policy.json")
DATA_DIR = Path("/data")
IDENTITY_FILE = DATA_DIR / "managed-identity.json"
EXPECTED_CONTRACT = "smart-pro-managed-policy-v1"
EXPECTED_POLICY_VERSION = 1
EXPECTED_SERVER_AUTH_VERSION = 1
MAX_POLICY_BYTES = 65536
MAX_RESPONSE_BYTES = 131072
MAX_POST_BYTES = 8192
HEARTBEAT_INTERVAL = 60
HTTP_TIMEOUT = 12
NODE_ID_RE = re.compile(r"^SPMN-[A-F0-9]{32}$")
NODE_SECRET_RE = re.compile(r"^SPMS-[A-Za-z0-9_-]{43}$")
CSRF_TOKEN = secrets.token_urlsafe(24)
STATE_LOCK = threading.RLock()
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

    return f"""<!doctype html>
<html lang="el"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart Pro Managed Support</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#10151d;color:#eef5ff;font:14px/1.5 Arial,Helvetica,sans-serif}}main{{max-width:1000px;margin:0 auto;padding:24px}}.hero{{background:#172231;border:1px solid #2c4158;border-radius:16px;padding:22px;margin-bottom:16px}}h1{{margin:0 0 5px;font-size:27px}}h2{{margin:0 0 10px;font-size:18px}}.sub{{color:#aab9ca}}.badge{{display:inline-block;margin-top:14px;padding:8px 12px;border-radius:999px;font-weight:700}}.ok{{background:#173a2a;color:#9ff0bd;border:1px solid #2c7750}}.bad{{background:#442128;color:#ffb5c0;border:1px solid #8c3d4d}}.warn{{background:#43381a;color:#ffe49a;border:1px solid #8b7331}}.note{{margin-top:15px;padding:13px 15px;border-radius:10px;background:#12293a;border:1px solid #245473;color:#cfeeff}}.notice{{margin:0 0 16px;padding:12px 14px;border-radius:10px}}.notice-ok{{background:#173a2a;border:1px solid #2c7750;color:#bdf7d0}}.notice-bad{{background:#442128;border:1px solid #8c3d4d;color:#ffd0d6}}.notice-info{{background:#12293a;border:1px solid #245473;color:#cfeeff}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.card,.pairbox{{background:#171d26;border:1px solid #293646;border-radius:12px;padding:15px}}.k{{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8fa1b5}}.v{{font-size:15px;font-weight:700;margin-top:4px;overflow-wrap:anywhere}}.pairbox{{margin:16px 0}}.pairbox p{{color:#b7c5d5}}label{{display:block;font-weight:700;margin:12px 0 6px}}input{{width:100%;max-width:460px;padding:11px 12px;border-radius:8px;border:1px solid #3b4c60;background:#0f151d;color:#fff;font:inherit}}button{{display:block;margin-top:12px;border:0;border-radius:8px;padding:10px 14px;background:#19aee8;color:#06131b;font-weight:800;cursor:pointer}}button:disabled,input:disabled{{opacity:.5;cursor:not-allowed}}code{{color:#9fdfff}}.footer{{margin-top:18px;color:#7f91a6;font-size:12px}}@media(max-width:650px){{main{{padding:14px}}.grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<section class="hero"><h1>Smart Pro Managed Support</h1><div class="sub">3.1.0 · Dual Authorization Foundation · {esc(ARCH)}</div><span class="badge {badge_class}">{esc(badge)}</span><div class="note">{esc(reason)}</div></section>
{notice_html}
{pair_html}
<section class="grid">
<div class="card"><div class="k">Installation ID</div><div class="v">{esc(policy.get('installation_id') or (identity or {{}}).get('installation_id'))}</div></div>
<div class="card"><div class="k">Smart Pro Tools</div><div class="v">v{esc((policy.get('source') or {{}}).get('addon_version'))} · Online: {esc(tools_online)}</div></div>
<div class="card"><div class="k">Portal pairing (local policy)</div><div class="v">{esc(portal_paired_local)}</div></div>
<div class="card"><div class="k">Συνδρομή</div><div class="v">{esc(subscription.get('plan'))} · {esc(subscription.get('status'))}</div></div>
<div class="card"><div class="k">Managed entitlement</div><div class="v">{esc(entitled)}</div></div>
<div class="card"><div class="k">Local policy</div><div class="v">{'ALLOWED' if local_allowed else 'DENIED'} · {esc(local_snapshot.get('reason_code'))}</div></div>
<div class="card"><div class="k">Broker identity</div><div class="v">{esc(broker_paired)} · Node {esc(node_hint)}</div></div>
<div class="card"><div class="k">Broker server authorization</div><div class="v">{esc(server_auth)} · {esc(server.get('reason_code'))}</div></div>
<div class="card"><div class="k">Server lease έως</div><div class="v">{esc(fmt_epoch(server.get('valid_until')))}</div></div>
<div class="card"><div class="k">Τελευταίο Broker heartbeat</div><div class="v">{esc(fmt_epoch(server.get('last_heartbeat_at')))}</div></div>
<div class="card"><div class="k">Authorization chain</div><div class="v">{esc(overall_text)}</div></div>
<div class="card"><div class="k">Remote access</div><div class="v">Όχι — MeshCentral runtime δεν έχει ενεργοποιηθεί</div></div>
</section>
<div class="footer">3.1.0 authorization-only. Δεν παραλαμβάνει .msh, δεν κατεβάζει ή εκτελεί MeshAgent και δεν δημιουργεί MeshCentral node.</div>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartProManaged/3.1.0"

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
                "installation_id": policy.get("installation_id") or server.get("installation_id"),
            }
            self._send(200, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")
            return
        self._send(200, render_page(local), "text/html; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        if not path.endswith("/pair") and path != "pair":
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

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[managed] Smart Pro Managed Support {VERSION} dual authorization foundation listening on {PORT}", flush=True)
    thread = threading.Thread(target=heartbeat_worker, name="managed-heartbeat", daemon=True)
    thread.start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
