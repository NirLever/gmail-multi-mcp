#!/usr/bin/env bash
# Usage (in Cloud Shell, with the OAuth client JSON uploaded to ~):
#   bash deploy.sh <project-id> <allowed-email-1>,<allowed-email-2>
set -euo pipefail
P="$1"; ALLOWED="$2"; REGION="${REGION:-europe-west1}"; SVC=gmail-multi
cd "$(dirname "$0")"
gcloud config set project "$P" >/dev/null
PN=$(gcloud projects describe "$P" --format='value(projectNumber)')
SA="${PN}-compute@developer.gserviceaccount.com"

CLIENT=$(ls -t ~/client_secret*.json 2>/dev/null | head -1 || true)
if [ -z "$CLIENT" ] && ! gcloud secrets describe oauth-client >/dev/null 2>&1; then
  echo "!! Upload the OAuth client JSON (client_secret_....json) to your home folder first"; exit 1; fi

mk() { # name, file
  if gcloud secrets describe "$1" >/dev/null 2>&1; then
    if [ -n "${2:-}" ]; then gcloud secrets versions add "$1" --data-file="$2" >/dev/null; fi
  else
    if [ -n "${2:-}" ]; then gcloud secrets create "$1" --data-file="$2" >/dev/null
    else gcloud secrets create "$1" --replication-policy=automatic >/dev/null; fi
  fi
}
if [ -n "$CLIENT" ]; then mk oauth-client "$CLIENT"; fi
if ! gcloud secrets describe mcp-secret >/dev/null 2>&1; then
  head -c 32 /dev/urandom | base64 | tr -d '/+=\n' > /tmp/ms && mk mcp-secret /tmp/ms && rm /tmp/ms
fi
mk gmail-accounts
if [ -n "$CLIENT" ]; then rm -f "$CLIENT"; fi

for s in oauth-client mcp-secret gmail-accounts; do
  gcloud secrets add-iam-policy-binding "$s" --member="serviceAccount:$SA" \
    --role=roles/secretmanager.secretAccessor >/dev/null
done
gcloud secrets add-iam-policy-binding gmail-accounts --member="serviceAccount:$SA" \
  --role=roles/secretmanager.secretVersionAdder >/dev/null
# Cloud Build (source deploys) runs as the compute SA on new projects
for r in roles/run.builder roles/logging.logWriter roles/storage.admin roles/artifactregistry.writer; do
  gcloud projects add-iam-policy-binding "$P" --member="serviceAccount:$SA" --role="$r" \
    --condition=None >/dev/null 2>&1 || true
done

gcloud run deploy "$SVC" --source . --region "$REGION" --quiet \
  --allow-unauthenticated --max-instances=1 --memory=512Mi \
  --set-env-vars="^|^ALLOWED_EMAILS=${ALLOWED}|ACCOUNTS_SECRET=projects/${PN}/secrets/gmail-accounts|PUBLIC_URL=https://${SVC}-${PN}.${REGION}.run.app" \
  --set-secrets=GOOGLE_CLIENT_JSON=oauth-client:latest,MCP_SECRET=mcp-secret:latest

URL="https://${SVC}-${PN}.${REGION}.run.app"
echo
echo "DEPLOYED: $URL"
echo "CONNECT:  $URL/connect"
