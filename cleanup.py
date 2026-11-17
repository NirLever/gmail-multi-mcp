"""
One-shot mailbox cleanup across all connected accounts.
Run in Cloud Shell (reads tokens from Secret Manager):
  python3 cleanup.py            # dry run: counts only
  python3 cleanup.py --apply    # apply
Trash = Gmail Trash (recoverable for 30 days). Nothing is permanently deleted.
"""
import json, subprocess, sys
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

APPLY = "--apply" in sys.argv
PROJECT = "gmail-multi-7cabd9"

SOCIAL = ("from:(notification@service.tiktok.com OR no-reply@mail.instagram.com OR "
          "notification@priority.instagram.com)")

# (name, query, action) ; action: "trash" or label name (label + archive)
RULES = [
    ("social notifications", SOCIAL, "trash"),
    ("old promotions (30d+)", "category:promotions older_than:30d -is:starred", "trash"),
    ("old social tab (30d+)", "category:social older_than:30d -is:starred", "trash"),
    ("setup security alerts", 'from:no-reply@accounts.google.com "gmail-multi"', "trash"),
    ("forwarding confirmation", "from:forwarding-noreply@google.com", "trash"),
    ("old login codes (7d+)", 'subject:("login code" OR "verification code" OR "security code" '
                              'OR "sign-in code" OR "one-time code" OR "temporary") older_than:7d -is:starred', "trash"),
    ("receipts / invoices", 'in:inbox -is:starred (subject:(receipt OR invoice OR "חשבונית") OR '
                            'from:(invoice+statements@mail.anthropic.com OR receipts@modal.com OR '
                            'payments-noreply@google.com))', "Receipts"),
    ("ads (Meta, Google Ads)", "in:inbox -is:starred from:(business-updates.facebook.com OR "
                               "business.facebook.com OR ads-account-noreply@google.com)", "Ads"),
    ("dev notifications", "in:inbox -is:starred from:(noreply@github.com OR kaggle-noreply@google.com OR "
                          "microsoft-noreply@microsoft.com)", "Dev"),
    ("account notices", 'in:inbox -is:starred category:updates (subject:("shared some Google Account data") '
                        'OR subject:(welcome))', "Accounts"),
    ("sales (Lemon Squeezy)", 'in:inbox -is:starred from:lemonsqueezy subject:("You made a sale" OR '
                              '"been paid")', "Sales"),
    ("auto-replies", 'in:inbox -is:starred subject:("Automatic reply" OR "Out of Office" OR "Away from" '
                     'OR "I\'m away" OR "Working Remotely" OR "On Sabbatical" OR "Auto-reply")',
     "Outreach/Auto-replies"),
]


def secret(name):
    return subprocess.check_output(["gcloud", "secrets", "versions", "access", "latest",
                                     f"--secret={name}", f"--project={PROJECT}"]).decode()


client = json.loads(secret("oauth-client"))
client = client.get("web") or client.get("installed")
accounts = json.loads(secret("gmail-accounts"))["accounts"]


def svc_for(info):
    c = Credentials(None, refresh_token=info["refresh_token"], token_uri="https://oauth2.googleapis.com/token",
                    client_id=client["client_id"], client_secret=client["client_secret"])
    return build("gmail", "v1", credentials=c, cache_discovery=False)


def ids_for(svc, q, cap=20000):
    out, tok = [], None
    while len(out) < cap:
        r = svc.users().messages().list(userId="me", q=q, maxResults=500, pageToken=tok).execute()
        out += [m["id"] for m in r.get("messages", [])]
        tok = r.get("nextPageToken")
        if not tok:
            break
    return out


def label_id(svc, name):
    for l in svc.users().labels().list(userId="me").execute().get("labels", []):
        if l["name"].lower() == name.lower():
            return l["id"]
    return svc.users().labels().create(userId="me", body={
        "name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}).execute()["id"]


def apply(svc, ids, action):
    if action == "trash":
        for i in range(0, len(ids), 1000):
            try:
                svc.users().messages().batchModify(userId="me", body={
                    "ids": ids[i:i + 1000], "addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX"]}).execute()
            except Exception:
                for j in range(i, min(i + 1000, len(ids)), 50):
                    b = svc.new_batch_http_request()
                    for mid in ids[j:j + 50]:
                        b.add(svc.users().messages().trash(userId="me", id=mid))
                    b.execute()
    else:
        lid = label_id(svc, action)
        for i in range(0, len(ids), 1000):
            svc.users().messages().batchModify(userId="me", body={
                "ids": ids[i:i + 1000], "addLabelIds": [lid], "removeLabelIds": ["INBOX"]}).execute()


print(("APPLYING" if APPLY else "DRY RUN") + " - counts are messages\n")
totals = {}
for email, info in accounts.items():
    alias = info.get("alias") or email
    svc = svc_for(info)
    before = svc.users().labels().get(userId="me", id="INBOX").execute()
    print(f"== {alias} ({email})  inbox now: {before.get('messagesTotal')} msgs, {before.get('messagesUnread')} unread")
    for name, q, action in RULES:
        ids = ids_for(svc, q)
        if not ids:
            continue
        verb = "trash" if action == "trash" else f"-> {action}"
        print(f"   {len(ids):6d}  {name:26s} {verb}")
        totals[verb] = totals.get(verb, 0) + len(ids)
        if APPLY:
            apply(svc, ids, action)
    if APPLY:
        after = svc.users().labels().get(userId="me", id="INBOX").execute()
        print(f"   inbox after: {after.get('messagesTotal')} msgs, {after.get('messagesUnread')} unread")
print("\nTOTALS:", ", ".join(f"{k}: {v}" for k, v in totals.items()))
