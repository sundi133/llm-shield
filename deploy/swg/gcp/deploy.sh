#!/usr/bin/env bash
# Deploy shield-icap to GCP, behind an internal TCP load balancer.
#
#   ./deploy.sh <project> <region> <network> <gateway-cidr>
#
# Cloud Run cannot host this. ICAP is its own protocol on its own port, and
# Cloud Run only accepts HTTP. The shape that works is instances behind an
# INTERNAL PASSTHROUGH load balancer: passthrough because an application load
# balancer would try to parse ICAP as HTTP, and internal because port 1344
# answers "is this blocked?" and so is an oracle for the tenant's DLP patterns
# to anyone who can reach it.
#
# Squid is not deployed here. It holds the interception CA's private key and
# belongs wherever the customer's users are, not next to the screening service.
set -euo pipefail

PROJECT="${1:?usage: deploy.sh <project> <region> <network> <gateway-cidr>}"
REGION="${2:?}"
NETWORK="${3:?}"
GATEWAY_CIDR="${4:?}"          # the subnet your SWG egresses from
ZONE="${REGION}-a"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/shield/shield-icap:latest"

gcloud config set project "$PROJECT" >/dev/null

echo "==> 1/6 image"
gcloud artifacts repositories describe shield --location="$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create shield --repository-format=docker --location="$REGION"
gcloud builds submit --tag "$IMAGE" -f Dockerfile.icap ../../..

echo "==> 2/6 tenant key in Secret Manager"
# Not an environment variable and not baked into the image: a key in either
# shows up in `gcloud compute instances describe` and in the image layers.
gcloud secrets describe shield-api-key >/dev/null 2>&1 || \
  gcloud secrets create shield-api-key --replication-policy=automatic
echo "  add a version with:"
echo "    printf %s 'tenant_key' | gcloud secrets versions add shield-api-key --data-file=-"

echo "==> 3/6 service account"
SA="shield-icap@${PROJECT}.iam.gserviceaccount.com"
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 || \
  gcloud iam service-accounts create shield-icap --display-name="shield-icap"
gcloud secrets add-iam-policy-binding shield-api-key \
  --member="serviceAccount:${SA}" --role=roles/secretmanager.secretAccessor >/dev/null

echo "==> 4/6 instance template"
# The startup script pulls the key at boot rather than the image carrying it,
# so rotating the key is a new secret version and a rolling restart.
cat > /tmp/shield-startup.sh <<'STARTUP'
#!/bin/bash
set -euo pipefail
mkdir -p /var/shield
gcloud secrets versions access latest --secret=shield-api-key > /var/shield/api_key
chmod 600 /var/shield/api_key
docker run -d --restart=always --name shield-icap \
  -p 1344:1344 -p 8081:8081 \
  -v /var/shield:/run/secrets:ro \
  -e SHIELD_API_KEY_FILE=/run/secrets/api_key \
  -e SHIELD_ICAP_MODE=monitor \
  -e SHIELD_ICAP_ALLOWED_CLIENTS=GATEWAY_CIDR_PLACEHOLDER \
  IMAGE_PLACEHOLDER
STARTUP
sed -i.bak "s|IMAGE_PLACEHOLDER|${IMAGE}|; s|GATEWAY_CIDR_PLACEHOLDER|${GATEWAY_CIDR}|" \
  /tmp/shield-startup.sh

gcloud compute instance-templates create-with-container shield-icap-tpl \
  --machine-type=e2-medium \
  --network="$NETWORK" --no-address \
  --service-account="$SA" \
  --scopes=cloud-platform \
  --container-image="$IMAGE" \
  --metadata-from-file=startup-script=/tmp/shield-startup.sh \
  --tags=shield-icap || echo "  template exists, skipping"

echo "==> 5/6 managed instance group"
# Two minimum. The gateway is configured bypass=off, so adapter availability
# is AI availability for the whole fleet behind it.
gcloud compute instance-groups managed create shield-icap-mig \
  --template=shield-icap-tpl --size=2 --zone="$ZONE" || echo "  MIG exists, skipping"
gcloud compute health-checks create tcp shield-icap-hc --port=8081 || true

echo "==> 6/6 internal passthrough load balancer + firewall"
gcloud compute backend-services create shield-icap-be \
  --load-balancing-scheme=INTERNAL --protocol=TCP \
  --region="$REGION" --health-checks=shield-icap-hc || echo "  backend exists"
gcloud compute backend-services add-backend shield-icap-be \
  --region="$REGION" --instance-group=shield-icap-mig --instance-group-zone="$ZONE" || true
gcloud compute forwarding-rules create shield-icap-fr \
  --load-balancing-scheme=INTERNAL --network="$NETWORK" \
  --region="$REGION" --ports=1344 --backend-service=shield-icap-be || echo "  rule exists"

# Only the gateway may reach ICAP. Health checks come from Google's own ranges.
gcloud compute firewall-rules create allow-shield-icap \
  --network="$NETWORK" --allow=tcp:1344 \
  --source-ranges="$GATEWAY_CIDR" --target-tags=shield-icap || echo "  fw exists"
gcloud compute firewall-rules create allow-shield-icap-hc \
  --network="$NETWORK" --allow=tcp:8081 \
  --source-ranges=35.191.0.0/16,130.211.0.0/22 --target-tags=shield-icap || echo "  fw exists"

echo
echo "Point the gateway at the forwarding rule's address:"
gcloud compute forwarding-rules describe shield-icap-fr --region="$REGION" \
  --format="value(IPAddress)" 2>/dev/null | sed 's|^|  icap://|; s|$|:1344/screen|'
