#!/usr/bin/env bash
# Votal Edge on GCP: create the VM, install the gateway, prove it came up.
#
#   export VOTAL_TOKEN=...  TS_AUTHKEY=...
#   ./create-edge-vm.sh --project my-proj --zone us-central1-a --tenant acme
#
#   ./create-edge-vm.sh --dry-run  --project p --tenant acme   rehearse
#   ./create-edge-vm.sh --verify   --project p                 report state
#   ./create-edge-vm.sh --delete   --project p                 tear down
#
# What it leaves behind:
#
#   GCP project
#    ├── e2-standard-2 VM, Ubuntu 22.04, tag votal-edge
#    ├── NO external IP, NO inbound rule for 3128  (the data path is Tailscale)
#    ├── one firewall rule: SSH from the IAP range only
#    ├── Cloud NAT, so the box can reach apt, Docker Hub and the policy engine
#    └── the interception CA copied back here, for the MDM to distribute
#
# The tenant token and the Tailscale key travel over the SSH channel and are
# never written to instance metadata: metadata is readable by anything holding
# compute.instances.get on the project, it persists for the life of the VM, and
# it lands in exports. This is the one thing this script does differently from
# every "startup-script" recipe you will find, and it is deliberate.
set -uo pipefail

VERSION="0.1.0"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$HERE/../install-votal-edge.sh"

PROJECT="" ZONE="us-central1-a" NAME="votal-edge"
MACHINE="e2-standard-2" DISK_GB="50"
IMAGE_FAMILY="ubuntu-2204-lts" IMAGE_PROJECT="ubuntu-os-cloud"
NETWORK="default" SUBNET="" ALLOW_LAN=""
TENANT="" TOKEN="${VOTAL_TOKEN:-}" TS_KEY="${TS_AUTHKEY:-}"
ENDPOINT="https://api.guardrails.votal.ai"
MODE="monitor" REF="main" WITH_WS="1" WITH_TAILSCALE="1" PUBLIC_IP="0"
CA_OUT="./votal-edge-ca.pem"
ACTION="create"

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; Z=$'\033[0m'
ok()   { printf '  %sok%s    %s\n' "$G" "$Z" "$1"; }
no()   { printf '  %sFAIL%s  %s\n' "$R" "$Z" "$1"; }
note() { printf '  %s..%s    %s\n' "$Y" "$Z" "$1"; }
die()  { printf '%sERROR:%s %s\n' "$R" "$Z" "$1" >&2; exit 1; }
run()  {
    if [ "$ACTION" = "dry-run" ]; then
        printf '  would:'; printf ' %q' "$@"; printf '\n'
    else
        "$@"
    fi
}

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --project)             PROJECT="${2:?}"; shift 2 ;;
        --zone)                ZONE="${2:?}"; shift 2 ;;
        --name)                NAME="${2:?}"; shift 2 ;;
        --machine-type)        MACHINE="${2:?}"; shift 2 ;;
        --disk-gb)             DISK_GB="${2:?}"; shift 2 ;;
        --network)             NETWORK="${2:?}"; shift 2 ;;
        --subnet)              SUBNET="${2:?}"; shift 2 ;;
        --allow-lan)           ALLOW_LAN="${2:?}"; shift 2 ;;
        --tenant)              TENANT="${2:?}"; shift 2 ;;
        --token)               TOKEN="${2:?}"; shift 2 ;;
        --token-file)          TOKEN="$(cat "${2:?}")"; shift 2 ;;
        --tailscale-authkey)   TS_KEY="${2:?}"; shift 2 ;;
        --guardrail-endpoint)  ENDPOINT="${2:?}"; shift 2 ;;
        --mode)                MODE="${2:?}"; shift 2 ;;
        --ref)                 REF="${2:?}"; shift 2 ;;
        --ca-out)              CA_OUT="${2:?}"; shift 2 ;;
        --no-websocket)        WITH_WS="0"; shift ;;
        --no-tailscale)        WITH_TAILSCALE="0"; shift ;;
        --public-ip)           PUBLIC_IP="1"; shift ;;
        --dry-run)             ACTION="dry-run"; shift ;;
        --verify)              ACTION="verify"; shift ;;
        --delete)              ACTION="delete"; shift ;;
        -h|--help)             usage 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

command -v gcloud >/dev/null 2>&1 || die "gcloud not found: install the Google Cloud CLI first"
[ -n "$PROJECT" ] || PROJECT="$(gcloud config get-value project 2>/dev/null)"
[ -n "$PROJECT" ] && [ "$PROJECT" != "(unset)" ] || die "--project is required (or: gcloud config set project ...)"

REGION="${ZONE%-*}"
GC=(gcloud --project "$PROJECT" --quiet)
SSH=("${GC[@]}" compute ssh "$NAME" --zone "$ZONE" --tunnel-through-iap)

# ── verify: read-only, safe against a live appliance ──────────────────────
if [ "$ACTION" = "verify" ]; then
    echo "${B}Votal Edge on GCP $VERSION${Z}  project=$PROJECT zone=$ZONE name=$NAME"
    "${SSH[@]}" --command "sudo /root/install-votal-edge.sh --verify" 2>/dev/null
    exit $?
fi

# ── delete ────────────────────────────────────────────────────────────────
if [ "$ACTION" = "delete" ]; then
    echo "${B}Deleting $NAME in $ZONE${Z}"
    printf 'This destroys the gateway and its CA. Type the instance name to confirm: '
    read -r confirm
    [ "$confirm" = "$NAME" ] || die "not confirmed"
    run "${GC[@]}" compute instances delete "$NAME" --zone "$ZONE"
    run "${GC[@]}" compute firewall-rules delete "$NAME-iap-ssh"
    [ -n "$ALLOW_LAN" ] && run "${GC[@]}" compute firewall-rules delete "$NAME-lan-proxy"
    # The Cloud NAT is left alone on purpose: other workloads in the region may
    # be relying on it by now, and deleting it silently takes their egress away.
    note "Cloud Router/NAT left in place; remove $NAME-nat yourself if nothing else uses it"
    exit 0
fi

# ── create ────────────────────────────────────────────────────────────────
[ -n "$TENANT" ] || die "--tenant is required"
[ -n "$TOKEN" ] || die "--token is required (or set VOTAL_TOKEN); it never touches metadata"
case "$MODE" in monitor|enforce) ;; *) die "--mode must be monitor or enforce" ;; esac
[ -f "$INSTALLER" ] || die "installer not found at $INSTALLER"

[ "$ACTION" = "dry-run" ] && echo "${B}DRY RUN${Z}: nothing will be created"
echo "${B}Votal Edge on GCP $VERSION${Z}  project=$PROJECT zone=$ZONE name=$NAME mode=$MODE"
echo

echo "==> 1/7 APIs"
for api in compute.googleapis.com iap.googleapis.com oslogin.googleapis.com; do
    if [ "$ACTION" != "dry-run" ] && "${GC[@]}" services list --enabled --filter="config.name=$api" --format='value(config.name)' 2>/dev/null | grep -q .; then
        note "$api already enabled"
    else
        run "${GC[@]}" services enable "$api"
    fi
done

echo "==> 2/7 egress"
# Without an external IP a VM has NO route to the internet, so apt, Docker Hub
# and the policy engine all hang. The instance still comes up green, which is
# why this is checked here rather than discovered during the install.
if [ "$PUBLIC_IP" = "1" ]; then
    note "--public-ip: the box gets an external address (still no inbound rule for it)"
elif [ "$ACTION" != "dry-run" ] && "${GC[@]}" compute routers nats list --router="$NAME-router" --router-region "$REGION" --format='value(name)' 2>/dev/null | grep -q .; then
    note "Cloud NAT already present in $REGION"
else
    run "${GC[@]}" compute routers create "$NAME-router" --network "$NETWORK" --region "$REGION"
    run "${GC[@]}" compute routers nats create "$NAME-nat" --router "$NAME-router" --region "$REGION" \
        --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges
fi

echo "==> 3/7 firewall"
# 35.235.240.0/20 is IAP's TCP-forwarding range and the only way in. There is
# deliberately no rule for 3128 or 8081: clients reach those over Tailscale, so
# the proxy has no internet-facing surface at all.
run "${GC[@]}" compute firewall-rules create "$NAME-iap-ssh" \
    --network "$NETWORK" --direction INGRESS --action allow --rules tcp:22 \
    --source-ranges 35.235.240.0/20 --target-tags votal-edge \
    --description "SSH to the Votal Edge gateway via IAP only"
if [ -n "$ALLOW_LAN" ]; then
    note "--allow-lan $ALLOW_LAN: opening 3128/8081 to that range instead of Tailscale"
    run "${GC[@]}" compute firewall-rules create "$NAME-lan-proxy" \
        --network "$NETWORK" --direction INGRESS --action allow --rules tcp:3128,tcp:8081 \
        --source-ranges "$ALLOW_LAN" --target-tags votal-edge \
        --description "Votal Edge proxy, reachable from the corporate range"
fi
if [ "$ACTION" != "dry-run" ]; then
    exposed="$("${GC[@]}" compute firewall-rules list \
        --filter="network=$NETWORK AND sourceRanges:0.0.0.0/0 AND allowed.ports:3128" \
        --format='value(name)' 2>/dev/null)"
    [ -n "$exposed" ] && no "an existing rule exposes 3128 to the internet: $exposed" \
                      || ok "nothing exposes 3128 to the internet"
fi

echo "==> 4/7 instance"
create=("${GC[@]}" compute instances create "$NAME" --zone "$ZONE"
    --machine-type "$MACHINE" --image-family "$IMAGE_FAMILY" --image-project "$IMAGE_PROJECT"
    --boot-disk-size "${DISK_GB}GB" --boot-disk-type pd-balanced --tags votal-edge
    --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
    # The box terminates TLS for a whole office. A default service account with
    # cloud-platform scope would turn one shell on it into project-wide access,
    # and it needs no GCP API to do its job. Same reasoning for project-wide
    # SSH keys: gcloud adds an instance key, so blocking them costs nothing.
    --no-service-account --no-scopes
    --metadata block-project-ssh-keys=TRUE,enable-oslogin=TRUE)
[ -n "$SUBNET" ] && create+=(--subnet "$SUBNET") || create+=(--network "$NETWORK")
[ "$PUBLIC_IP" = "1" ] || create+=(--no-address)
run "${create[@]}"

echo "==> 5/7 waiting for SSH"
if [ "$ACTION" = "dry-run" ]; then
    echo "  would: poll ${NAME} over IAP until sshd answers"
else
    for i in $(seq 1 30); do
        "${SSH[@]}" --command true >/dev/null 2>&1 && { ok "reachable over IAP after ${i}0s"; break; }
        [ "$i" = "30" ] && die "no SSH after 5 minutes: check IAP permissions (roles/iap.tunnelResourceAccessor)"
        sleep 10
    done
fi

echo "==> 6/7 install"
# Built as a quoted string rather than an array: this is handed to a shell on
# the far side, and an unquoted tenant name with a space in it would silently
# install the wrong tenant's policy.
rargs="$(printf '%q ' --tenant "$TENANT" --mode "$MODE" --ref "$REF" --guardrail-endpoint "$ENDPOINT")"
rargs="$rargs --token \"\$TOKEN\""
[ "$WITH_WS" = "1" ] || rargs="$rargs --no-websocket"
if [ "$WITH_TAILSCALE" = "1" ]; then
    if [ -n "$TS_KEY" ]; then
        rargs="$rargs --tailscale-authkey \"\$TS_KEY\""
    else
        note "no Tailscale key given: run 'tailscale up' on the box before laptops can reach it"
    fi
else
    rargs="$rargs --no-tailscale"
fi

if [ "$ACTION" = "dry-run" ]; then
    echo "  would: scp $INSTALLER to the VM and run it with $rargs"
    echo "  would: pass TOKEN and TS_KEY down stdin, never as metadata, argv or a file"
else
    "${GC[@]}" compute scp "$INSTALLER" "$NAME:/tmp/install-votal-edge.sh" \
        --zone "$ZONE" --tunnel-through-iap || die "scp failed"
    # The secrets live only in this heredoc, which goes down the SSH channel
    # into `sh -s`. Nothing writes them to metadata, to Cloud Logging, to a
    # file on the VM, or to either shell's history. (The installer still takes
    # --token as a flag, so it is briefly visible in ps on the box itself; that
    # box is single-tenant and root-owned, which is the trade we accept.)
    printf 'TOKEN=%q\nTS_KEY=%q\nset -e\n%s\n%s\n%s\n' \
        "$TOKEN" "$TS_KEY" \
        "install -m 0700 /tmp/install-votal-edge.sh /root/install-votal-edge.sh" \
        "rm -f /tmp/install-votal-edge.sh" \
        "/root/install-votal-edge.sh $rargs" \
        | "${SSH[@]}" --command "sudo sh -s" \
        || die "the installer failed on the VM (ssh in and run /root/install-votal-edge.sh --verify)"
fi

echo "==> 7/7 verify"
if [ "$ACTION" = "dry-run" ]; then
    echo "  would: run --verify on the VM and copy the CA to $CA_OUT"
    echo
    echo "${B}DRY RUN complete${Z}: nothing was created."
    exit 0
fi

status="$("${SSH[@]}" --command "sudo /root/install-votal-edge.sh --verify" 2>/dev/null)"
echo "$status" | sed 's/^/  /'

"${GC[@]}" compute scp "$NAME:/opt/votal-edge/deploy/swg/ssl/ca.pem" "$CA_OUT" \
    --zone "$ZONE" --tunnel-through-iap >/dev/null 2>&1 \
    && ok "CA copied to $CA_OUT (this is what the MDM distributes)" \
    || no "could not copy the CA: the install may not have completed"

echo
if echo "$status" | grep -q "service=1 tailscale=1 health=1 firewall=1 ca=1"; then
    echo "${G}${B}Gateway is up.${Z}"
else
    echo "${Y}${B}Gateway is up but incomplete${Z} (see the status line above)."
fi
cat <<EOF

Next, in order:

  1. Push $CA_OUT to the fleet on its own. It changes nothing by itself,
     so a bad CA shows up before any traffic depends on it.
  2. Point endpoints at the PAC:  http://<tailscale-name>:8081/proxy.pac
     deploy/swg/mdm/install-macos.sh does both for a Mac.
  3. Leave it in monitor for two to four weeks and read the decisions.
  4. Switch to enforce in rings:
       gcloud compute ssh $NAME --zone $ZONE --tunnel-through-iap \\
         --command "sudo /root/install-votal-edge.sh --mode enforce --tenant $TENANT --token \\\$TOKEN"
  5. Only then deny outbound 443 to AI hosts from everything except this VM.
     Steps 1-4 make this the default path. Step 5 makes it the only one.
EOF
