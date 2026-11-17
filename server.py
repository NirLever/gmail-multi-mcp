"""
Multi-account Gmail MCP server.

Exposes several Gmail accounts to Claude through one custom connector.
Every tool takes an `account` argument (an email address, or a short alias).

Environment:
  MCP_SECRET          Random string (32+ chars). MCP endpoint lives at /mcp/<MCP_SECRET>.
  GOOGLE_CLIENT_JSON  Contents of the OAuth client JSON downloaded from Google Cloud (Web application).
  ALLOWED_EMAILS      Comma-separated Gmail addresses that may be connected. Anyone else is refused.
  ACCOUNTS_SECRET     Secret Manager secret holding the account tokens, e.g.
                      projects/my-project/secrets/gmail-accounts  (server reads and writes it)
                      If unset, ACCOUNTS_FILE (default accounts.json) is used instead (local runs).
  PORT                Port (Cloud Run sets it). Default 8080.

Connecting an account: open https://<service>/connect and pick an alias. Google sign-in returns
to /oauth/callback, which stores the refresh token and shows the Claude connector URL.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time
from email.message import EmailMessage
from typing import Any

import uvicorn
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse

TOKEN_URI = "https://oauth2.googleapis.com/token"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
MAX_BODY_CHARS = 20000

# ---------------------------------------------------------------- config

SECRET = os.environ.get("MCP_SECRET", "").strip()
if len(SECRET) < 32:
    raise RuntimeError("MCP_SECRET must be set to a random string of at least 32 characters.")

_client_raw = json.loads(os.environ["GOOGLE_CLIENT_JSON"])
CLIENT = _client_raw.get("web") or _client_raw.get("installed")
ALLOWED = {e.strip().lower() for e in os.environ.get("ALLOWED_EMAILS", "").split(",") if e.strip()}
ACCOUNTS_SECRET = os.environ.get("ACCOUNTS_SECRET", "").strip()
ACCOUNTS_FILE = os.environ.get("ACCOUNTS_FILE", "accounts.json")
_store_lock = threading.Lock()


def _sm():
    from google.cloud import secretmanager
    return secretmanager.SecretManagerServiceClient()


def _load_accounts() -> dict:
    try:
        if ACCOUNTS_SECRET:
            r = _sm().access_secret_version(name=f"{ACCOUNTS_SECRET}/versions/latest")
            return json.loads(r.payload.data.decode()).get("accounts", {})
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE, encoding="utf-8") as f:
                return json.load(f).get("accounts", {})
    except Exception as e:  # first run: secret has no version yet
        print("No stored accounts yet:", type(e).__name__, e)
    return {}


def _save_accounts() -> None:
    data = json.dumps({"accounts": CONFIG["accounts"]}).encode()
    if ACCOUNTS_SECRET:
        _sm().add_secret_version(parent=ACCOUNTS_SECRET, payload={"data": data})
    else:
        with open(ACCOUNTS_FILE, "wb") as f:
            f.write(data)


CONFIG = {"client_id": CLIENT["client_id"], "client_secret": CLIENT["client_secret"],
          "accounts": _load_accounts()}
_services: dict[str, Any] = {}


def _resolve(account: str) -> str:
    """Accept a full address or an alias, case-insensitive."""
    a = account.strip().lower()
    for email, info in CONFIG["accounts"].items():
        if a == email.lower() or a == str(info.get("alias", "")).lower():
            return email
    known = ", ".join(f"{e} ({i.get('alias', '')})" for e, i in CONFIG["accounts"].items())
    raise ValueError(f"Unknown account '{account}'. Known: {known or 'none connected yet'}")


def _gmail(account: str):
    email = _resolve(account)
    if email not in _services:
        info = CONFIG["accounts"][email]
        creds = Credentials(
            token=None,
            refresh_token=info["refresh_token"],
            token_uri=TOKEN_URI,
            client_id=CONFIG["client_id"],
            client_secret=CONFIG["client_secret"],
            scopes=SCOPES,
        )
        _services[email] = build("gmail", "v1", credentials=creds, cache_discovery=False)
    return _services[email]


# ---------------------------------------------------------------- helpers

def _headers(payload: dict) -> dict[str, str]:
    return {h["name"].lower(): h["value"] for h in payload.get("headers", [])}


def _decode(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="replace")


def _strip_html(html: str) -> str:
    html = re.sub(r"(?is)<(script|style).*?</\1>", "", html)
    html = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", html)
    text = re.sub(r"<[^>]+>", "", html)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&#39;|&apos;", "'", text)
    text = re.sub(r"&quot;", '"', text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _walk(part: dict, out: dict) -> None:
    mime = part.get("mimeType", "")
    body = part.get("body", {})
    if part.get("filename"):
        out["attachments"].append({
            "filename": part["filename"],
            "mimeType": mime,
            "size": body.get("size", 0),
            "attachmentId": body.get("attachmentId"),
        })
    elif mime == "text/plain" and body.get("data"):
        out["plain"].append(_decode(body["data"]))
    elif mime == "text/html" and body.get("data"):
        out["html"].append(_decode(body["data"]))
    for p in part.get("parts", []) or []:
        _walk(p, out)


def _message_summary(msg: dict, with_body: bool) -> dict:
    payload = msg.get("payload", {})
    h = _headers(payload)
    result = {
        "id": msg["id"],
        "threadId": msg.get("threadId"),
        "from": h.get("from"),
        "to": h.get("to"),
        "cc": h.get("cc"),
        "date": h.get("date"),
        "subject": h.get("subject"),
        "labelIds": msg.get("labelIds", []),
        "snippet": msg.get("snippet"),
    }
    if with_body:
        parts = {"plain": [], "html": [], "attachments": []}
        _walk(payload, parts)
        text = "\n".join(parts["plain"]) or _strip_html("\n".join(parts["html"]))
        if len(text) > MAX_BODY_CHARS:
            text = text[:MAX_BODY_CHARS] + "\n...[truncated]"
        result["body"] = text
        result["attachments"] = parts["attachments"]
        result["messageIdHeader"] = h.get("message-id")
        result["references"] = h.get("references")
    return result


def _label_ids(svc, names: list[str]) -> list[str]:
    """Map label names (or ids, or system names like INBOX) to ids."""
    if not names:
        return []
    labels = svc.users().labels().list(userId="me").execute().get("labels", [])
    by_name = {l["name"].lower(): l["id"] for l in labels}
    by_id = {l["id"]: l["id"] for l in labels}
    ids = []
    for n in names:
        lid = by_id.get(n) or by_name.get(n.lower()) or by_id.get(n.upper())
        if not lid:
            raise ValueError(f"Label not found: {n}")
        ids.append(lid)
    return ids


def _view_url(email: str, thread_id: str) -> str:
    return f"https://mail.google.com/mail/?authuser={email}#all/{thread_id}"


# ---------------------------------------------------------------- MCP

mcp = FastMCP(
    name="gmail-multi",
    instructions=(
        "Access to several of the user's Gmail accounts. Call list_accounts first to see them. "
        "Every tool takes `account` (an email address or alias). When the user doesn't name an "
        "account, search all of them with search_all_accounts. Never send email without the user's "
        "explicit confirmation of recipient and text; prefer create_draft."
    ),
    stateless_http=True,
    json_response=True,
    streamable_http_path=f"/mcp/{SECRET}",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


@mcp.tool()
def list_accounts() -> list[dict]:
    """List the Gmail accounts this connector can access, with their aliases."""
    return [{"email": e, "alias": i.get("alias", "")} for e, i in CONFIG["accounts"].items()]


@mcp.tool()
def search_threads(account: str, query: str = "", max_results: int = 20, page_token: str = "") -> dict:
    """Search threads in one account using Gmail search syntax (from:, to:, subject:, after:YYYY/MM/DD,
    is:unread, label:, has:attachment, in:inbox ...). Returns each thread's latest message summary."""
    email = _resolve(account)
    svc = _gmail(email)
    kw = {"userId": "me", "q": query, "maxResults": max(1, min(max_results, 50))}
    if page_token:
        kw["pageToken"] = page_token
    resp = svc.users().threads().list(**kw).execute()
    threads = []
    for t in resp.get("threads", []):
        full = svc.users().threads().get(
            userId="me", id=t["id"], format="metadata",
            metadataHeaders=["From", "To", "Cc", "Date", "Subject"],
        ).execute()
        msgs = full.get("messages", [])
        last = _message_summary(msgs[-1], with_body=False) if msgs else {}
        last["messageCount"] = len(msgs)
        last["viewUrl"] = _view_url(email, t["id"])
        threads.append(last)
    return {"account": email, "threads": threads, "nextPageToken": resp.get("nextPageToken")}


@mcp.tool()
def search_all_accounts(query: str = "", max_results_per_account: int = 10) -> list[dict]:
    """Run the same Gmail search across every connected account."""
    out = []
    for email in CONFIG["accounts"]:
        try:
            out.append(search_threads(email, query, max_results_per_account))
        except Exception as e:  # keep other accounts working
            out.append({"account": email, "error": str(e)})
    return out


@mcp.tool()
def get_thread(account: str, thread_id: str) -> dict:
    """Read every message in a thread, with plain-text bodies and attachment info."""
    email = _resolve(account)
    t = _gmail(email).users().threads().get(userId="me", id=thread_id, format="full").execute()
    return {
        "account": email,
        "threadId": thread_id,
        "viewUrl": _view_url(email, thread_id),
        "messages": [_message_summary(m, with_body=True) for m in t.get("messages", [])],
    }


@mcp.tool()
def get_message(account: str, message_id: str) -> dict:
    """Read one message with its plain-text body and attachment info."""
    email = _resolve(account)
    m = _gmail(email).users().messages().get(userId="me", id=message_id, format="full").execute()
    return {"account": email, **_message_summary(m, with_body=True)}


@mcp.tool()
def get_attachment_text(account: str, message_id: str, attachment_id: str) -> dict:
    """Fetch an attachment. Text-like files are returned as text; others as base64 (first 1 MB)."""
    email = _resolve(account)
    a = _gmail(email).users().messages().attachments().get(
        userId="me", messageId=message_id, id=attachment_id
    ).execute()
    raw = base64.urlsafe_b64decode(a["data"] + "=" * (-len(a["data"]) % 4))
    try:
        return {"size": len(raw), "text": raw.decode("utf-8")[:MAX_BODY_CHARS]}
    except UnicodeDecodeError:
        return {"size": len(raw), "base64": base64.b64encode(raw[:1_000_000]).decode()}


@mcp.tool()
def list_labels(account: str) -> list[dict]:
    """List labels (system and user) in an account."""
    labels = _gmail(account).users().labels().list(userId="me").execute().get("labels", [])
    return [{"id": l["id"], "name": l["name"], "type": l.get("type")} for l in labels]


@mcp.tool()
def modify_thread(account: str, thread_id: str, add_labels: list[str] | None = None,
                  remove_labels: list[str] | None = None) -> dict:
    """Add/remove labels on a thread by name. Archive = remove INBOX. Mark read = remove UNREAD.
    Star = add STARRED. Trash with trash_thread instead."""
    svc = _gmail(account)
    body = {"addLabelIds": _label_ids(svc, add_labels or []),
            "removeLabelIds": _label_ids(svc, remove_labels or [])}
    r = svc.users().threads().modify(userId="me", id=thread_id, body=body).execute()
    return {"threadId": r["id"], "ok": True}


@mcp.tool()
def trash_thread(account: str, thread_id: str) -> dict:
    """Move a thread to Trash (recoverable for 30 days)."""
    _gmail(account).users().threads().trash(userId="me", id=thread_id).execute()
    return {"threadId": thread_id, "trashed": True}


@mcp.tool()
def create_label(account: str, name: str) -> dict:
    """Create a user label (use '/' for nesting, e.g. 'Business/Orders')."""
    r = _gmail(account).users().labels().create(
        userId="me", body={"name": name, "labelListVisibility": "labelShow",
                           "messageListVisibility": "show"}).execute()
    return {"id": r["id"], "name": r["name"]}


def _build_raw(sender: str, to: str, subject: str, body: str, cc: str = "", bcc: str = "",
               in_reply_to: str = "", references: str = "") -> str:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    if bcc:
        msg["Bcc"] = bcc
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (references + " " + in_reply_to).strip()
    msg.set_content(body)
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


@mcp.tool()
def create_draft(account: str, to: str, subject: str, body: str, cc: str = "", bcc: str = "",
                 reply_to_message_id: str = "") -> dict:
    """Create a plain-text draft in the given account (sent from that account's address).
    To reply in a thread, pass reply_to_message_id (the Gmail message id you're answering);
    subject gets 'Re:' and threading headers are set automatically."""
    email = _resolve(account)
    svc = _gmail(email)
    draft_msg: dict = {}
    in_reply_to = references = ""
    if reply_to_message_id:
        orig = svc.users().messages().get(
            userId="me", id=reply_to_message_id, format="metadata",
            metadataHeaders=["Message-ID", "References", "Subject"]).execute()
        h = _headers(orig["payload"])
        in_reply_to = h.get("message-id", "")
        references = h.get("references", "")
        if not subject:
            subject = h.get("subject", "")
        if subject and not subject.lower().startswith("re:"):
            subject = "Re: " + subject
        draft_msg["threadId"] = orig["threadId"]
    draft_msg["raw"] = _build_raw(email, to, subject, body, cc, bcc, in_reply_to, references)
    d = svc.users().drafts().create(userId="me", body={"message": draft_msg}).execute()
    return {"account": email, "draftId": d["id"], "messageId": d["message"]["id"],
            "threadId": d["message"].get("threadId")}


@mcp.tool()
def list_drafts(account: str, max_results: int = 20) -> list[dict]:
    """List drafts in an account."""
    svc = _gmail(account)
    ds = svc.users().drafts().list(userId="me", maxResults=max_results).execute().get("drafts", [])
    out = []
    for d in ds:
        full = svc.users().drafts().get(userId="me", id=d["id"], format="metadata").execute()
        out.append({"draftId": d["id"], **_message_summary(full["message"], with_body=False)})
    return out


@mcp.tool()
def send_draft(account: str, draft_id: str) -> dict:
    """Send an existing draft. Only call after the user explicitly confirms sending it."""
    r = _gmail(account).users().drafts().send(userId="me", body={"id": draft_id}).execute()
    return {"sent": True, "messageId": r["id"], "threadId": r.get("threadId")}


def _list_message_ids(svc, query: str, limit: int) -> list[str]:
    ids, token = [], None
    while len(ids) < limit:
        kw = {"userId": "me", "q": query, "maxResults": min(500, limit - len(ids))}
        if token:
            kw["pageToken"] = token
        r = svc.users().messages().list(**kw).execute()
        ids += [m["id"] for m in r.get("messages", [])]
        token = r.get("nextPageToken")
        if not token:
            break
    return ids


def _metadata_batch(svc, ids: list[str], headers: list[str]) -> list[dict]:
    out: list[dict] = []
    def cb(_rid, resp, exc):
        if exc is None and resp:
            out.append(resp)
    for i in range(0, len(ids), 50):
        batch = svc.new_batch_http_request(callback=cb)
        for mid in ids[i:i + 50]:
            batch.add(svc.users().messages().get(userId="me", id=mid, format="metadata",
                                                 metadataHeaders=headers))
        batch.execute()
    return out


@mcp.tool()
def mailbox_overview(account: str, query: str = "in:inbox", sample: int = 300, top: int = 25) -> dict:
    """Survey a mailbox: estimated count for the query, plus the top senders (with counts,
    unread counts, newest date and Gmail category) in a sample of the newest matching messages.
    Use before cleanup to decide what to label, archive or trash."""
    email = _resolve(account)
    svc = _gmail(email)
    est = svc.users().messages().list(userId="me", q=query, maxResults=1).execute() \
        .get("resultSizeEstimate", 0)
    ids = _list_message_ids(svc, query, max(1, min(sample, 1000)))
    msgs = _metadata_batch(svc, ids, ["From", "Date", "List-Unsubscribe"])
    senders: dict[str, dict] = {}
    for m in msgs:
        h = _headers(m.get("payload", {}))
        frm = h.get("from", "?")
        addr = (re.search(r"<([^>]+)>", frm) or re.search(r"(\S+@\S+)", frm))
        key = (addr.group(1) if addr else frm).lower()
        s = senders.setdefault(key, {"sender": frm[:80], "count": 0, "unread": 0, "newest": "",
                                     "categories": set(), "newsletter": False})
        s["count"] += 1
        labels = m.get("labelIds", [])
        if "UNREAD" in labels:
            s["unread"] += 1
        s["categories"].update(l.replace("CATEGORY_", "").lower() for l in labels if l.startswith("CATEGORY_"))
        if h.get("list-unsubscribe"):
            s["newsletter"] = True
        if not s["newest"]:
            s["newest"] = h.get("date", "")
    rows = sorted(senders.items(), key=lambda kv: -kv[1]["count"])[:top]
    return {"account": email, "query": query, "estimated_total": est, "sampled": len(msgs),
            "top_senders": [{"address": k, **{**v, "categories": sorted(v["categories"])}} for k, v in rows]}


@mcp.tool()
def bulk_modify(account: str, query: str, add_labels: list[str] | None = None,
                remove_labels: list[str] | None = None, trash: bool = False,
                max_messages: int = 2000, dry_run: bool = True) -> dict:
    """Apply one action to every message matching a Gmail search (up to max_messages, 10000 cap).
    add_labels/remove_labels by name (archive = remove INBOX, mark read = remove UNREAD).
    trash=True moves them to Trash (recoverable 30 days). Missing user labels in add_labels are
    created. dry_run=True (default) only counts; call again with dry_run=False to apply."""
    email = _resolve(account)
    svc = _gmail(email)
    ids = _list_message_ids(svc, query, max(1, min(max_messages, 10000)))
    if dry_run:
        return {"account": email, "query": query, "would_affect": len(ids), "dry_run": True}
    add = list(add_labels or [])
    existing = {l["name"].lower() for l in svc.users().labels().list(userId="me").execute().get("labels", [])}
    for name in add:
        if name.lower() not in existing and name.upper() not in {"INBOX", "UNREAD", "STARRED", "IMPORTANT", "TRASH", "SPAM"}:
            svc.users().labels().create(userId="me", body={"name": name, "labelListVisibility": "labelShow",
                                                           "messageListVisibility": "show"}).execute()
    add_ids = _label_ids(svc, add) + (["TRASH"] if trash else [])
    rem_ids = _label_ids(svc, list(remove_labels or []))
    if trash:
        rem_ids = [r for r in rem_ids if r != "TRASH"] + (["INBOX"] if "INBOX" not in rem_ids else [])
    try:
        for i in range(0, len(ids), 1000):
            svc.users().messages().batchModify(userId="me", body={
                "ids": ids[i:i + 1000], "addLabelIds": add_ids, "removeLabelIds": rem_ids}).execute()
    except Exception:
        if not trash:
            raise
        # Fallback: label first without TRASH, then trash one by one in HTTP batches
        add_ids = [a for a in add_ids if a != "TRASH"]
        if add_ids or rem_ids:
            for i in range(0, len(ids), 1000):
                svc.users().messages().batchModify(userId="me", body={
                    "ids": ids[i:i + 1000], "addLabelIds": add_ids, "removeLabelIds": rem_ids}).execute()
        for i in range(0, len(ids), 50):
            b = svc.new_batch_http_request()
            for mid in ids[i:i + 50]:
                b.add(svc.users().messages().trash(userId="me", id=mid))
            b.execute()
    return {"account": email, "query": query, "affected": len(ids), "added": add_labels or [],
            "removed": remove_labels or [], "trashed": trash}


# ---------------------------------------------------------------- app

app = mcp.streamable_http_app()


async def health(_: Request):
    return PlainTextResponse("ok")

app.add_route("/healthz", health, methods=["GET"])

# ---------------------------------------------------------------- account connect flow

_pending: dict[str, dict] = {}   # state -> {alias, verifier, t}


def _base_url(request: Request) -> str:
    if os.environ.get("PUBLIC_URL"):
        return os.environ["PUBLIC_URL"].rstrip("/")
    host = request.headers.get("host", "")
    local = host.startswith(("localhost", "127.0.0.1"))
    return f"{'http' if local else 'https'}://{host}"


def _flow(request: Request, verifier: str | None = None) -> Flow:
    cfg = {"web": {**CLIENT, "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                   "token_uri": TOKEN_URI}}
    return Flow.from_client_config(cfg, SCOPES, redirect_uri=_base_url(request) + "/oauth/callback",
                                   code_verifier=verifier, autogenerate_code_verifier=verifier is None)


def _page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>{html.escape(title)}</title><body style="font:16px system-ui;max-width:640px;margin:40px auto;padding:0 16px">
<h2>{html.escape(title)}</h2>{body}</body>""")


async def connect(request: Request):
    alias = re.sub(r"[^a-z0-9_-]", "", request.query_params.get("alias", "").lower())[:20]
    if not alias:
        rows = "".join(f"<li><b>{html.escape(i.get('alias') or '(no alias)')}</b></li>"
                       for i in CONFIG["accounts"].values()) or "<li>none yet</li>"
        return _page("Connect a Gmail account", f"""
<p>Connected:</p><ul>{rows}</ul>
<form><label>Short name for the account you'll sign in with:
<input name=alias placeholder="business" required pattern="[a-zA-Z0-9_-]+"></label>
<button>Sign in with Google</button></form>""")
    for k in [k for k, v in _pending.items() if time.time() - v["t"] > 900]:
        _pending.pop(k, None)
    flow = _flow(request)
    state = secrets.token_urlsafe(24)
    url, _ = flow.authorization_url(access_type="offline", prompt="consent select_account", state=state)
    _pending[state] = {"alias": alias, "verifier": flow.code_verifier, "t": time.time()}
    return RedirectResponse(url, status_code=302)


async def callback(request: Request):
    state = request.query_params.get("state", "")
    p = _pending.pop(state, None)
    if not p:
        return _page("Link expired", "<p>Start again from <a href=/connect>/connect</a>.</p>")
    if request.query_params.get("error"):
        return _page("Cancelled", f"<p>{html.escape(request.query_params['error'])}</p>")
    flow = _flow(request, p["verifier"])
    flow.fetch_token(code=request.query_params.get("code", ""))
    creds = flow.credentials
    email = build("gmail", "v1", credentials=creds, cache_discovery=False) \
        .users().getProfile(userId="me").execute()["emailAddress"]
    if ALLOWED and email.lower() not in ALLOWED:
        return _page("Not allowed", f"<p>{html.escape(email)} is not on this server's allow list.</p>")
    if not creds.refresh_token:
        return _page("No refresh token", "<p>Google didn't return a long-lived token. "
                     "Remove the app at myaccount.google.com/permissions and try again.</p>")
    with _store_lock:
        for e, i in CONFIG["accounts"].items():   # alias must be unique
            if e != email and i.get("alias") == p["alias"]:
                i["alias"] = ""
        CONFIG["accounts"][email] = {"refresh_token": creds.refresh_token, "alias": p["alias"]}
        _services.pop(email, None)
        _save_accounts()
    mcp_url = _base_url(request) + f"/mcp/{SECRET}"
    return _page("Connected", f"""
<p><b>{html.escape(email)}</b> is connected as <b>{html.escape(p['alias'])}</b>.</p>
<p><a href=/connect>Connect another account</a></p>
<p>Claude connector URL (Settings → Connectors → Add custom connector). Keep it private:</p>
<p><input readonly style="width:100%;font:13px monospace" value="{html.escape(mcp_url)}" onclick="this.select()"></p>""")


app.add_route("/connect", connect, methods=["GET"])
app.add_route("/oauth/callback", callback, methods=["GET"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
