#!/usr/bin/env bash
# Public, authenticated SWG on GCP for a ROAMING LAPTOP FLEET.
# Spec: docs/spec-swg-public-proxy.md.
#
#   Laptop (MDM: device client cert + 2 CAs trusted)
#     | PAC: AI hosts -> HTTPS <public-host>:8443 ; else DIRECT
#     v TLS to the proxy, presenting the device client cert (mTLS)
#   VM external IP :8443  squid (squid.public.conf: require client cert, bump AI only)
#                           \-- docker bridge --> shield-icap :1344 (NEVER public) -> /guardrails/input
#
# This is NOT deploy-mode-a.sh (in-VPC, no external IP) and NOT deploy.sh
# (Mode B, adapter only behind an existing SWG). Use this when the clients are
# managed laptops dialling in over the internet.
#
# Why a public port is acceptable here: every client is authenticated by an
# MDM-issued CLIENT CERTIFICATE (mTLS, no cert = no connection), and the proxy
# carries ONLY AI hosts (squid.public.conf denies every other destination), so
# it is not a relay. The firewall is open on 8443 BY DESIGN -- a roaming fleet
# has no fixed source IP; the client cert is the allow-list.
#
# VERIFY before enforce (spec section 11): `squid -k parse` in the image, a live
# mTLS handshake, and a real deploy. This script is bash -n + structurally
# tested; a running deploy is the operator's acceptance step.
set -euo pipefail

# --- configuration --------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-YOUR_GCP_PROJECT_ID}"
REGION="${REGION:-us-west1}"
ZONE="${ZONE:-${REGION}-a}"
VM_NAME="${VM_NAME:-shield-swg-public}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-standard-2}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"

# The hostname laptops reach the proxy at. Point its DNS at this VM's external
# IP (printed at the end). The proxy's TLS cert is forged for this name.
SHIELD_PROXY_PUBLIC_HOST="${SHIELD_PROXY_PUBLIC_HOST:-YOUR_PROXY_HOSTNAME}"
PROXY_PORT="${PROXY_PORT:-8443}"
PAC_PORT="${PAC_PORT:-8081}"
# SSH is NOT opened to the internet. Default: the GCP IAP range (use
# `gcloud compute ssh --tunnel-through-iap`). Override for a bastion/admin CIDR.
ADMIN_CIDR="${ADMIN_CIDR:-35.235.240.0/20}"

SHIELD_API_BASE="${SHIELD_API_BASE:-https://api.guardrails.votal.ai}"
SHIELD_ICAP_MODE="${SHIELD_ICAP_MODE:-monitor}"            # monitor | enforce
SHIELD_ICAP_SYNC_SCREEN="${SHIELD_ICAP_SYNC_SCREEN:-0}"    # 1 = Tier 2 blocks inline
SHIELD_ICAP_EXPECT_TENANT="${SHIELD_ICAP_EXPECT_TENANT:-}"
CA_SUBJECT="${CA_SUBJECT:-/CN=Votal Shield Inspection CA}"

KEY_SECRET="shield-api-key"
CA_SECRET="swg-ca-pem"               # interception CA (cert+key); generated here if absent
CLIENT_CA_SECRET="swg-client-ca-pem" # MDM issuing CA (cert only); operator provides
SA_NAME="shield-swg-public"
IMG_ICAP="${REGION}-docker.pkg.dev/${PROJECT_ID}/shield/shield-icap:latest"
IMG_SQUID="${REGION}-docker.pkg.dev/${PROJECT_ID}/shield/shield-squid:latest"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SQUID_CONF="$HERE/../squid.public.conf"   # the mTLS config, NOT the in-VPC base

# --- validate -------------------------------------------------------------
[ "$PROJECT_ID" != "YOUR_GCP_PROJECT_ID" ] || { echo "ERROR: set PROJECT_ID"; exit 1; }
[ "$SHIELD_PROXY_PUBLIC_HOST" != "YOUR_PROXY_HOSTNAME" ] || { echo "ERROR: set SHIELD_PROXY_PUBLIC_HOST"; exit 1; }
[ -f "$SQUID_CONF" ] || { echo "ERROR: $SQUID_CONF not found - run from deploy/swg/gcp/"; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl is required"; exit 1; }

gcloud config set project "$PROJECT_ID" >/dev/null
echo "== Public SWG  project=$PROJECT_ID host=$SHIELD_PROXY_PUBLIC_HOST mode=$SHIELD_ICAP_MODE =="

# --- 1. secrets: tenant key, interception CA, MDM issuing CA --------------
# Checked FIRST, before the (slow) image build, so a missing secret fails fast.
echo "==> 1/6 secrets"
ensure_secret() { gcloud secrets describe "$1" >/dev/null 2>&1 || gcloud secrets create "$1" --replication-policy=automatic; }
has_version() { gcloud secrets versions access latest --secret="$1" >/dev/null 2>&1; }

ensure_secret "$KEY_SECRET"
has_version "$KEY_SECRET" || { echo "  !! add your tenant key, then re-run:"; \
  echo "       printf %s 'YOUR_TENANT_KEY' | gcloud secrets versions add $KEY_SECRET --data-file=-"; exit 1; }

ensure_secret "$CA_SECRET"
if ! has_version "$CA_SECRET"; then
  echo "  generating interception CA (5y) -> $CA_SECRET (holds a PRIVATE KEY; restrict it)"
  TMP_CA="$(mktemp)"
  openssl req -new -newkey rsa:4096 -sha256 -days 1825 -nodes -x509 \
    -extensions v3_ca -keyout "$TMP_CA" -out "$TMP_CA" -subj "$CA_SUBJECT" 2>/dev/null
  gcloud secrets versions add "$CA_SECRET" --data-file="$TMP_CA" >/dev/null
  rm -f "$TMP_CA"
fi

ensure_secret "$CLIENT_CA_SECRET"
has_version "$CLIENT_CA_SECRET" || { cat <<EOF
  !! $CLIENT_CA_SECRET has no version. This is the CERTIFICATE (no key) of the
     CA your MDM uses to issue device client certs. Squid verifies each laptop's
     cert against it. Export it from your MDM/SCEP/ACME CA and add it:
       gcloud secrets versions add $CLIENT_CA_SECRET --data-file=mdm-issuing-ca.pem
EOF
  exit 1; }

# --- 2. images (both, one Cloud Build run; cloudbuild.yaml selects the ----
#        Dockerfiles, since `gcloud builds submit --tag` cannot). ----------
echo "==> 2/6 build images (Cloud Build)"
gcloud artifacts repositories describe shield --location="$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create shield --repository-format=docker --location="$REGION"
gcloud builds submit "$REPO_ROOT" \
  --config "$HERE/cloudbuild.yaml" \
  --substitutions=_IMG_ICAP="$IMG_ICAP",_IMG_SQUID="$IMG_SQUID"

# --- 3. service account ---------------------------------------------------
echo "==> 3/6 service account"
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "$SA" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SA_NAME" --display-name="$SA_NAME"
  # IAM is eventually consistent: a just-created SA is not usable in a binding
  # for a few seconds. Wait until it is visible before binding.
  for _ in $(seq 1 20); do
    gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 && break
    sleep 3
  done
fi
# Visibility does not guarantee the binding succeeds yet, so retry each one.
for s in "$KEY_SECRET" "$CA_SECRET" "$CLIENT_CA_SECRET"; do
  for _ in $(seq 1 10); do
    gcloud secrets add-iam-policy-binding "$s" \
      --member="serviceAccount:${SA}" --role=roles/secretmanager.secretAccessor >/dev/null 2>&1 && break
    sleep 3
  done
done
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA}" --role=roles/artifactregistry.reader >/dev/null 2>&1 || true

# --- 4. firewall: 8443 + 8081 OPEN (auth is the client cert); SSH via IAP -
echo "==> 4/6 firewall"
# 8443 is public BY DESIGN: a roaming fleet has no fixed IP, and mTLS + the
# AI-only destination allow-list are the controls, not source IP. 1344 is NEVER
# opened - it is the ICAP oracle and stays on the docker bridge.
gcloud compute firewall-rules describe allow-shield-swg-public >/dev/null 2>&1 || \
  gcloud compute firewall-rules create allow-shield-swg-public \
    --network="$NETWORK" --direction=INGRESS --action=ALLOW \
    --rules="tcp:${PROXY_PORT},tcp:${PAC_PORT}" \
    --source-ranges="0.0.0.0/0" --target-tags=shield-swg-public
gcloud compute firewall-rules describe allow-shield-swg-public-ssh >/dev/null 2>&1 || \
  gcloud compute firewall-rules create allow-shield-swg-public-ssh \
    --network="$NETWORK" --direction=INGRESS --action=ALLOW \
    --rules=tcp:22 --source-ranges="$ADMIN_CIDR" --target-tags=shield-swg-public

# --- 5. VM ----------------------------------------------------------------
echo "==> 5/6 vm"
STARTUP="$(mktemp)"; trap 'rm -f "$STARTUP"' EXIT
cat > "$STARTUP" <<'STARTUP_EOF'
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y docker.io curl
systemctl enable --now docker
M="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
h="Metadata-Flavor: Google"
meta() { curl -s -H "$h" "$M/$1"; }
gcloud auth configure-docker "$(meta region)-docker.pkg.dev" -q

mkdir -p /var/shield/ssl /var/shield/secrets
gcloud secrets versions access latest --secret="$(meta ca-secret)"        > /var/shield/ssl/ca.pem
gcloud secrets versions access latest --secret="$(meta client-ca-secret)" > /var/shield/ssl/client-ca.pem
gcloud secrets versions access latest --secret="$(meta key-secret)"       > /var/shield/secrets/shield_api_key
chmod 600 /var/shield/ssl/ca.pem /var/shield/ssl/client-ca.pem /var/shield/secrets/shield_api_key
meta squid-conf > /var/shield/squid.public.conf

IMG_ICAP="$(meta icap-image)"; IMG_SQUID="$(meta squid-image)"
docker pull "$IMG_ICAP"; docker pull "$IMG_SQUID"
docker network inspect shield-net >/dev/null 2>&1 || docker network create shield-net
docker rm -f shield-icap shield-squid 2>/dev/null || true

# shield-icap serves the PAC (8081, public) and ICAP (1344, bridge-only - NOT
# published). The PAC returns `HTTPS <host>:8443` so the browser->proxy hop is TLS.
docker run -d --restart=always --name shield-icap --network shield-net \
  -v /var/shield/secrets:/run/secrets:ro \
  -p 0.0.0.0:8081:8081 \
  -e SHIELD_API_BASE="$(meta shield-api-base)" \
  -e SHIELD_API_KEY_FILE=/run/secrets/shield_api_key \
  -e SHIELD_ICAP_MODE="$(meta shield-mode)" \
  -e SHIELD_ICAP_SYNC_SCREEN="$(meta shield-sync)" \
  -e SHIELD_ICAP_EXPECT_TENANT="$(meta shield-expect)" \
  -e SHIELD_ICAP_PAC_SCHEME=HTTPS \
  -e SHIELD_ICAP_PAC_PROXY="$(meta proxy-host):$(meta proxy-port)" \
  "$IMG_ICAP"

docker run -d --restart=always --name shield-squid --network shield-net \
  -v /var/shield/squid.public.conf:/etc/squid/squid.conf:ro \
  -v /var/shield/ssl:/etc/squid/ssl:ro \
  -v shield-ssldb:/var/spool/squid \
  -p 0.0.0.0:8443:8443 \
  "$IMG_SQUID"
STARTUP_EOF

META="region=$REGION,icap-image=$IMG_ICAP,squid-image=$IMG_SQUID,ca-secret=$CA_SECRET,client-ca-secret=$CLIENT_CA_SECRET,key-secret=$KEY_SECRET,shield-api-base=$SHIELD_API_BASE,shield-mode=$SHIELD_ICAP_MODE,shield-sync=$SHIELD_ICAP_SYNC_SCREEN,shield-expect=$SHIELD_ICAP_EXPECT_TENANT,proxy-host=$SHIELD_PROXY_PUBLIC_HOST,proxy-port=$PROXY_PORT"
if gcloud compute instances describe "$VM_NAME" --zone="$ZONE" >/dev/null 2>&1; then
  gcloud compute instances add-metadata "$VM_NAME" --zone="$ZONE" \
    --metadata="$META" --metadata-from-file=startup-script="$STARTUP",squid-conf="$SQUID_CONF"
  gcloud compute instances reset "$VM_NAME" --zone="$ZONE"
else
  gcloud compute instances create "$VM_NAME" --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" --network="$NETWORK" --subnet="$SUBNET" \
    --tags=shield-swg-public --image-family=debian-12 --image-project=debian-cloud \
    --boot-disk-size=20GB --boot-disk-type=pd-balanced \
    --service-account="$SA" --scopes=cloud-platform \
    --metadata="$META" --metadata-from-file=startup-script="$STARTUP",squid-conf="$SQUID_CONF"
fi

# --- 6. report ------------------------------------------------------------
echo "==> 6/6 done (first boot pulls images + starts containers; ~1-2 min)"
sleep 10
IP="$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" \
      --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
cat <<EOF

======================================
Public SWG up. External IP: ${IP}
======================================
1. DNS: point ${SHIELD_PROXY_PUBLIC_HOST} at ${IP}.
2. PAC:   http://${SHIELD_PROXY_PUBLIC_HOST}:${PAC_PORT}/proxy.pac
   Proxy: ${SHIELD_PROXY_PUBLIC_HOST}:${PROXY_PORT}  (HTTPS proxy, mTLS)
   Health: curl -s http://${IP}:${PAC_PORT}/healthz

3. Push to every laptop by MDM (deploy/swg/mdm/):
   - the INTERCEPTION CA cert, trusted in the system store:
       gcloud secrets versions access latest --secret=${CA_SECRET} > interception-ca.pem
   - a per-device CLIENT CERT + key from your MDM issuing CA (whose cert is in
     ${CLIENT_CA_SECRET}) - this authenticates the laptop
   - the PAC URL above
   A laptop without its device cert cannot use the proxy at all.

Started in ${SHIELD_ICAP_MODE}. Review /healthz + Telemetry, then re-run with
SHIELD_ICAP_MODE=enforce. Note: 8443 is public and authenticated by client
cert; 1344 (ICAP) is not exposed. VERIFY squid -k parse + an mTLS handshake
before enforce (spec section 11).
EOF
