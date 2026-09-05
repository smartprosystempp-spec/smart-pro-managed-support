#!/usr/bin/env python3
import html
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

VERSION = os.environ.get("SMART_PRO_MANAGED_VERSION", "3.0.0")
ARCH = os.environ.get("SMART_PRO_MANAGED_ARCH", "unknown")
PORT = 8098
POLICY_FILE = Path("/share/smart-pro-system/managed-policy.json")
EXPECTED_CONTRACT = "smart-pro-managed-policy-v1"
EXPECTED_POLICY_VERSION = 1
MAX_POLICY_BYTES = 65536


def now_ts():
    return int(time.time())


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def read_policy():
    """Read and validate the non-secret Tools policy. Fail closed on any ambiguity."""
    base = {
        "state": "policy_missing",
        "allowed_local": False,
        "remote_access_ready": False,
        "reason": "Δεν βρέθηκε ακόμη το Managed Policy του Smart Pro Tools.",
        "policy": None,
    }
    try:
        stat = POLICY_FILE.stat()
    except FileNotFoundError:
        return base
    except OSError:
        base["state"] = "policy_unreadable"
        base["reason"] = "Το Managed Policy υπάρχει αλλά δεν μπορεί να διαβαστεί."
        return base

    if stat.st_size <= 0 or stat.st_size > MAX_POLICY_BYTES:
        base["state"] = "policy_invalid"
        base["reason"] = "Το Managed Policy έχει μη αποδεκτό μέγεθος."
        return base

    try:
        raw = POLICY_FILE.read_text(encoding="utf-8")
        policy = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        base["state"] = "policy_invalid"
        base["reason"] = "Το Managed Policy δεν είναι έγκυρο JSON."
        return base

    if not isinstance(policy, dict):
        base["state"] = "policy_invalid"
        base["reason"] = "Το Managed Policy έχει μη έγκυρη δομή."
        return base
    if policy.get("contract_id") != EXPECTED_CONTRACT:
        base["state"] = "contract_mismatch"
        base["reason"] = "Το Managed Policy Contract δεν είναι συμβατό."
        return base
    if _as_int(policy.get("policy_version")) != EXPECTED_POLICY_VERSION:
        base["state"] = "policy_version_mismatch"
        base["reason"] = "Η έκδοση Managed Policy δεν υποστηρίζεται."
        return base

    installation_id = str(policy.get("installation_id") or "").strip()
    if not installation_id:
        base["state"] = "installation_id_missing"
        base["reason"] = "Δεν υπάρχει έγκυρο Installation ID στο Managed Policy."
        base["policy"] = policy
        return base

    tools = policy.get("tools_liveness") if isinstance(policy.get("tools_liveness"), dict) else {}
    lease_until = _as_int(tools.get("lease_until"))
    if not lease_until or now_ts() > lease_until:
        base["state"] = "tools_stale"
        base["reason"] = "Το Smart Pro Tools δεν έχει ανανεώσει έγκαιρα το Managed Policy."
        base["policy"] = policy
        return base

    authorization = policy.get("authorization") if isinstance(policy.get("authorization"), dict) else {}
    valid_until = _as_int(authorization.get("valid_until"))
    if valid_until and now_ts() > valid_until:
        base["state"] = "authorization_expired"
        base["reason"] = "Η τοπική Managed εξουσιοδότηση έχει λήξει."
        base["policy"] = policy
        return base

    if policy.get("allowed") is not True:
        reason_code = str(policy.get("reason_code") or "policy_denied")
        reason_label = str(policy.get("reason_label") or "Η Managed υποστήριξη δεν επιτρέπεται από την τρέχουσα πολιτική.")
        base.update({
            "state": "policy_denied",
            "allowed_local": False,
            "reason_code": reason_code,
            "reason": reason_label,
            "policy": policy,
        })
        return base

    # Important: local allowance is only one half of future authorization.
    base.update({
        "state": "local_policy_allowed",
        "allowed_local": True,
        "remote_access_ready": False,
        "reason_code": str(policy.get("reason_code") or "allowed"),
        "reason": "Η τοπική πολιτική επιτρέπει Managed Support. Αναμένεται το server-side authorization στάδιο.",
        "policy": policy,
    })
    return base


def fmt_epoch(value):
    value = _as_int(value)
    if not value:
        return "—"
    try:
        return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(value))
    except (OverflowError, OSError, ValueError):
        return "—"


def render_page(snapshot):
    policy = snapshot.get("policy") if isinstance(snapshot.get("policy"), dict) else {}
    subscription = policy.get("subscription") if isinstance(policy.get("subscription"), dict) else {}
    entitlement = policy.get("entitlement") if isinstance(policy.get("entitlement"), dict) else {}
    auth = policy.get("authorization") if isinstance(policy.get("authorization"), dict) else {}
    tools = policy.get("tools_liveness") if isinstance(policy.get("tools_liveness"), dict) else {}
    health = policy.get("health") if isinstance(policy.get("health"), dict) else {}

    state = snapshot.get("state", "unknown")
    if state == "local_policy_allowed":
        badge_class, badge = "ok", "Τοπική πολιτική: ΕΠΙΤΡΕΠΕΤΑΙ"
    elif state == "policy_denied":
        badge_class, badge = "bad", "Managed Support: ΔΕΝ ΕΠΙΤΡΕΠΕΤΑΙ"
    else:
        badge_class, badge = "warn", "Managed Foundation: ΑΝΑΜΟΝΗ"

    def esc(value):
        return html.escape(str(value if value not in (None, "") else "—"))

    entitled = "Ναι" if entitlement.get("managed_remote_support") is True else "Όχι"
    portal_paired = "Ναι" if health.get("portal_paired") is True else "Όχι"
    tools_online = "Ναι" if health.get("tools_online") is True else "Όχι"
    remote_ready = "Όχι — δεν έχει υλοποιηθεί ακόμη server authorization" if not snapshot.get("remote_access_ready") else "Ναι"

    return f"""<!doctype html>
<html lang=\"el\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Smart Pro Managed Support</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#10151d;color:#eef5ff;font:14px/1.5 Arial,Helvetica,sans-serif}}main{{max-width:980px;margin:0 auto;padding:24px}}.hero{{background:#172231;border:1px solid #2c4158;border-radius:16px;padding:22px;margin-bottom:16px}}h1{{margin:0 0 5px;font-size:27px}}.sub{{color:#aab9ca}}.badge{{display:inline-block;margin-top:14px;padding:8px 12px;border-radius:999px;font-weight:700}}.ok{{background:#173a2a;color:#9ff0bd;border:1px solid #2c7750}}.bad{{background:#442128;color:#ffb5c0;border:1px solid #8c3d4d}}.warn{{background:#43381a;color:#ffe49a;border:1px solid #8b7331}}.note{{margin-top:15px;padding:13px 15px;border-radius:10px;background:#12293a;border:1px solid #245473;color:#cfeeff}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}.card{{background:#171d26;border:1px solid #293646;border-radius:12px;padding:15px}}.k{{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8fa1b5}}.v{{font-size:15px;font-weight:700;margin-top:4px;overflow-wrap:anywhere}}.footer{{margin-top:18px;color:#7f91a6;font-size:12px}}@media(max-width:650px){{main{{padding:14px}}.grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<section class=\"hero\"><h1>Smart Pro Managed Support</h1><div class=\"sub\">Foundation 3.0.0 · Policy Consumer · {esc(ARCH)}</div><span class=\"badge {badge_class}\">{esc(badge)}</span><div class=\"note\">{esc(snapshot.get('reason'))}</div></section>
<section class=\"grid\">
<div class=\"card\"><div class=\"k\">Installation ID</div><div class=\"v\">{esc(policy.get('installation_id'))}</div></div>
<div class=\"card\"><div class=\"k\">Smart Pro Tools</div><div class=\"v\">v{esc((policy.get('source') or {{}}).get('addon_version'))} · Online: {esc(tools_online)}</div></div>
<div class=\"card\"><div class=\"k\">Portal pairing</div><div class=\"v\">{esc(portal_paired)}</div></div>
<div class=\"card\"><div class=\"k\">Συνδρομή</div><div class=\"v\">{esc(subscription.get('plan'))} · {esc(subscription.get('status'))}</div></div>
<div class=\"card\"><div class=\"k\">Managed entitlement</div><div class=\"v\">{esc(entitled)}</div></div>
<div class=\"card\"><div class=\"k\">Reason code</div><div class=\"v\">{esc(policy.get('reason_code') or snapshot.get('state'))}</div></div>
<div class=\"card\"><div class=\"k\">Tools lease έως</div><div class=\"v\">{esc(fmt_epoch(tools.get('lease_until')))}</div></div>
<div class=\"card\"><div class=\"k\">Authorization έως</div><div class=\"v\">{esc(fmt_epoch(auth.get('valid_until')))}</div></div>
<div class=\"card\"><div class=\"k\">Remote access</div><div class=\"v\">{esc(remote_ready)}</div></div>
<div class=\"card\"><div class=\"k\">Policy contract</div><div class=\"v\">{esc(policy.get('contract_id'))} · v{esc(policy.get('policy_version'))}</div></div>
</section>
<div class=\"footer\">Τοπικό foundation μόνο. Δεν εκτελείται MeshAgent και δεν δημιουργείται MeshCentral node στην 3.0.0.</div>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartProManaged/3.0.0"

    def _send(self, code, body, content_type):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        snapshot = read_policy()
        if path in ("/healthz", "/api/health"):
            policy = snapshot.get("policy") if isinstance(snapshot.get("policy"), dict) else {}
            payload = {
                "service": "smart_pro_managed_support",
                "version": VERSION,
                "state": snapshot.get("state"),
                "allowed_local": bool(snapshot.get("allowed_local")),
                "remote_access_ready": False,
                "installation_id": policy.get("installation_id"),
                "reason_code": policy.get("reason_code") or snapshot.get("state"),
            }
            self._send(200, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")
            return
        self._send(200, render_page(snapshot), "text/html; charset=utf-8")

    def log_message(self, fmt, *args):
        # Keep logs compact and free of policy contents/credentials.
        return


if __name__ == "__main__":
    print(f"[managed] Smart Pro Managed Support {VERSION} policy foundation listening on {PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
