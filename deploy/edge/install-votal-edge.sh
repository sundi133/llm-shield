#!/usr/bin/env bash
# Votal Edge: one command turns an Ubuntu VM into a screening gateway.
#
#   sudo ./install-votal-edge.sh --tenant acme --token "$VOTAL_TOKEN" \
#        --tailscale-authkey "$TS_KEY"
#
#   sudo ./install-votal-edge.sh --dry-run --tenant acme --token x   rehearse
#   sudo ./install-votal-edge.sh --verify                            report state
#
# What it leaves behind:
#
#   Ubuntu VM
#    ├── Tailscale          the private path laptops use to reach it
#    ├── Squid              TLS interception for AI hosts only
#    ├── shield-icap        screens REST prompts against the tenant's policy
#    ├── shield-ws          screens WebSocket prompts (Codex and friends)
#    ├── interception CA    generated HERE; the key never leaves this box
#    ├── UFW                3128/8081 reachable on tailscale0 and nowhere else
#    └── systemd            votal-edge.service, restarts with the machine
#
# Deliberately NOT here: enrolling the appliance with a Votal console. That
# needs a provisioning API, an enrollment credential and a heartbeat, none of
# which exist yet, and inventing them in an installer is how they end up
# undesigned. Pass --tenant and --token; the console flow is a later spec.
set -uo pipefail

VERSION="0.1.0"
REPO_URL="${VOTAL_EDGE_REPO:-https://github.com/sundi133/llm-shield.git}"
REPO_REF="${VOTAL_EDGE_REF:-main}"
INSTALL_DIR=/opt/votal-edge
ENV_FILE=/etc/votal-edge.env
CA_DIR="$INSTALL_DIR/deploy/swg/ssl"
UNIT=/etc/systemd/system/votal-edge.service

TENANT="" TOKEN="" TS_AUTHKEY="" HOSTNAME_TS="votal-edge"
GUARDRAIL_ENDPOINT="https://api.guardrails.votal.ai"
MODE="monitor" SYNC="0" FALLBACK="block" WITH_WS="1" WITH_TAILSCALE="1"
ACTION="install"

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

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --tenant)              TENANT="${2:?}"; shift 2 ;;
        --token)               TOKEN="${2:?}"; shift 2 ;;
        --tailscale-authkey)   TS_AUTHKEY="${2:?}"; shift 2 ;;
        --hostname)            HOSTNAME_TS="${2:?}"; shift 2 ;;
        --guardrail-endpoint)  GUARDRAIL_ENDPOINT="${2:?}"; shift 2 ;;
        --mode)                MODE="${2:?}"; shift 2 ;;
        --sync-screen)         SYNC="1"; shift ;;
        --redact-fallback)     FALLBACK="${2:?}"; shift 2 ;;
        --no-websocket)        WITH_WS="0"; shift ;;
        --no-tailscale)        WITH_TAILSCALE="0"; shift ;;
        --ref)                 REPO_REF="${2:?}"; shift 2 ;;
        --dry-run)             ACTION="dry-run"; shift ;;
        --verify)              ACTION="verify"; shift ;;
        -h|--help)             usage 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

# ── verify: read-only, so it is safe on a live appliance ──────────────────
if [ "$ACTION" = "verify" ]; then
    echo "${B}Votal Edge $VERSION status${Z}"
    svc=0 health=0 ts=0 fw=0 ca=0

    systemctl is-active --quiet votal-edge 2>/dev/null && { svc=1; ok "votal-edge.service is running"; } \
        || no "votal-edge.service is not running"

    if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
        ts=1
        ok "tailscale up as $(tailscale status --json 2>/dev/null | grep -o '"DNSName":"[^"]*"' | head -1 | cut -d'"' -f4)"
    else
        no "tailscale is not connected: laptops have no private path to this box"
    fi

    if curl -fsS -m 5 http://127.0.0.1:8081/healthz >/dev/null 2>&1; then
        health=1
        curl -fsS -m 5 http://127.0.0.1:8081/healthz | sed 's/^/        /'
        # rules>0 is not the test; enforcing_anything is. A tenant can load
        # four rules and enforce none of them, and the numbers look healthy.
        curl -fsS -m 5 http://127.0.0.1:8081/healthz | grep -q '"enforcing_anything": *true' \
            && ok "policy loaded AND able to block" \
            || no "policy loaded but nothing can block (check redact fallback)"
    else
        no "the adapter is not answering on 8081"
    fi

    if ufw status 2>/dev/null | grep -q "3128.*tailscale0"; then
        fw=1; ok "3128 reachable on tailscale0 only"
    else
        no "firewall does not restrict 3128 to tailscale0"
    fi

    if [ -f "$CA_DIR/ca.pem" ]; then
        if openssl x509 -in "$CA_DIR/ca.pem" -noout -text 2>/dev/null | grep -q "Certificate Sign"; then
            ca=1
            ok "CA present, fingerprint $(openssl x509 -in "$CA_DIR/ca.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | head -c 24)..."
        else
            no "CA has no keyUsage=keyCertSign: Python, Node and Java will reject it"
        fi
    else
        no "no CA at $CA_DIR/ca.pem"
    fi

    echo
    echo "votal-edge-status service=$svc tailscale=$ts health=$health firewall=$fw ca=$ca"
    [ $((svc * ts * health * fw * ca)) -eq 1 ] && exit 0 || exit 1
fi

# ── install ───────────────────────────────────────────────────────────────
[ "$ACTION" = "dry-run" ] || [ "$(id -u)" -eq 0 ] || die "must run as root"
[ -n "$TENANT" ] || die "--tenant is required"
[ -n "$TOKEN" ] || die "--token is required (the tenant key this edge screens with)"
case "$MODE" in monitor|enforce) ;; *) die "--mode must be monitor or enforce" ;; esac

[ "$ACTION" = "dry-run" ] && echo "${B}DRY RUN${Z}: nothing will be changed"
echo "${B}Votal Edge $VERSION${Z}  tenant=$TENANT mode=$MODE endpoint=$GUARDRAIL_ENDPOINT"
echo

echo "==> 1/9 packages"
run apt-get update -qq
# Squid itself is NOT installed here: it comes from the container image, which
# builds on squid-openssl deliberately (Ubuntu's default squid package has no
# ssl_bump, so an apt-installed proxy would come up and decrypt nothing).
run apt-get install -y -qq ca-certificates curl git openssl ufw

echo "==> 2/9 docker"
if command -v docker >/dev/null 2>&1 && [ "$ACTION" != "dry-run" ]; then
    note "docker already installed"
else
    run install -m 0755 -d /etc/apt/keyrings
    run sh -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc"
    run chmod a+r /etc/apt/keyrings/docker.asc
    run sh -c 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list'
    run apt-get update -qq
    run apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

echo "==> 3/9 tailscale"
if [ "$WITH_TAILSCALE" = "1" ]; then
    command -v tailscale >/dev/null 2>&1 || run sh -c "curl -fsSL https://tailscale.com/install.sh | sh"
    if [ -n "$TS_AUTHKEY" ]; then
        # --ssh is deliberately NOT set: this box terminates TLS for a whole
        # office, and tailscale SSH would widen who can reach that.
        run tailscale up --authkey "$TS_AUTHKEY" --hostname "$HOSTNAME_TS" \
            --advertise-tags=tag:votal-edge --accept-dns=false
    else
        note "no --tailscale-authkey given; run 'tailscale up' yourself before clients connect"
    fi
else
    note "skipping tailscale (--no-tailscale): clients reach this box over the LAN or VPN"
fi

echo "==> 4/9 source at $INSTALL_DIR"
if [ -d "$INSTALL_DIR/.git" ]; then
    run git -C "$INSTALL_DIR" fetch --quiet origin
    run git -C "$INSTALL_DIR" checkout --quiet "$REPO_REF"
    run git -C "$INSTALL_DIR" pull --quiet --ff-only
else
    run git clone --quiet --branch "$REPO_REF" "$REPO_URL" "$INSTALL_DIR"
fi

echo "==> 5/9 interception CA"
# Generated HERE, never shipped: the private key is the customer's, and a CA
# minted by a vendor's build pipeline is a conversation no security review
# survives. keyUsage=keyCertSign is not optional -- without it curl works while
# Python, Node and Java reject the CA, so the fleet looks configured and every
# script fails TLS.
CA_REGENERATED=0
if [ -f "$CA_DIR/ca.pem" ] && openssl x509 -in "$CA_DIR/ca.pem" -noout -text 2>/dev/null | grep -q "Certificate Sign"; then
    note "reusing the existing CA (fingerprint unchanged, clients keep trusting it)"
else
    run mkdir -p "$CA_DIR"
    if [ "$ACTION" != "dry-run" ]; then
        cat > "$CA_DIR/ca.cnf" <<CNF
[req]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no
[dn]
CN = ${TENANT} AI Inspection CA
[v3_ca]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
CNF
        openssl req -new -newkey rsa:4096 -sha256 -days 1825 -nodes -x509 \
            -config "$CA_DIR/ca.cnf" -keyout "$CA_DIR/ca.pem" -out "$CA_DIR/ca.pem" 2>/dev/null
        chmod 600 "$CA_DIR/ca.pem"
    else
        echo "  would: generate a 5-year CA at $CA_DIR/ca.pem with keyUsage=keyCertSign"
    fi
    CA_REGENERATED=1
fi

echo "==> 6/9 configuration"
# Tailscale hands out 100.64.0.0/10 (CGNAT). Squid's shipped localnet covers
# RFC1918 only, so without this every tailnet client is denied by the proxy's
# own ACL and the failure looks like a network problem.
if [ "$ACTION" != "dry-run" ] && ! grep -q "100.64.0.0/10" "$INSTALL_DIR/deploy/swg/squid.conf"; then
    sed -i 's#^acl localnet src 10.0.0.0/8#acl localnet src 100.64.0.0/10 10.0.0.0/8#' \
        "$INSTALL_DIR/deploy/swg/squid.conf"
    ok "added the tailnet range to Squid's client ACL"
elif [ "$ACTION" = "dry-run" ]; then
    echo "  would: add 100.64.0.0/10 to Squid's localnet ACL"
fi

EDGE_ADDR="$HOSTNAME_TS"
if [ "$ACTION" != "dry-run" ] && [ "$WITH_TAILSCALE" = "1" ] && command -v tailscale >/dev/null 2>&1; then
    EDGE_ADDR="$(tailscale status --json 2>/dev/null | grep -o '"DNSName":"[^"]*"' | head -1 | cut -d'"' -f4 | sed 's/\.$//')"
    [ -n "$EDGE_ADDR" ] || EDGE_ADDR="$HOSTNAME_TS"
fi

if [ "$ACTION" != "dry-run" ]; then
    printf %s "$TOKEN" > "$INSTALL_DIR/deploy/swg/shield_api_key.txt"
    chmod 600 "$INSTALL_DIR/deploy/swg/shield_api_key.txt"
    cat > "$ENV_FILE" <<ENV
# Votal Edge, written by install-votal-edge.sh $VERSION
SHIELD_API_BASE=$GUARDRAIL_ENDPOINT
SHIELD_ICAP_MODE=$MODE
# Off for browser traffic on purpose: a web app fires dozens of requests per
# page and each would wait on a remote verdict. Turn it on for API and agent
# paths, where it is one call per prompt.
SHIELD_ICAP_SYNC_SCREEN=$SYNC
SHIELD_ICAP_REDACT_FALLBACK=$FALLBACK
SHIELD_ICAP_FAIL_OPEN=0
# What the PAC tells laptops to use. If this is wrong they proxy to themselves.
SHIELD_ICAP_PAC_PROXY=$EDGE_ADDR:3128
ENV
    chmod 600 "$ENV_FILE"
    # The PAC port must listen where laptops can reach it, not on loopback.
    cat > "$INSTALL_DIR/docker-compose.override.yml" <<OVR
services:
  shield-icap:
    ports:
      - "8081:8081"
OVR
else
    echo "  would: write $ENV_FILE and the compose port override (PAC on 8081)"
fi

echo "==> 7/9 systemd"
if [ "$ACTION" != "dry-run" ]; then
    PROFILE=""
    [ "$WITH_WS" = "1" ] && PROFILE="--profile ws"
    cat > "$UNIT" <<UNITF
[Unit]
Description=Votal Edge (Squid + shield-icap${WITH_WS:+ + shield-ws})
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/docker compose -f docker-compose.swg.yml $PROFILE up -d --build
ExecStop=/usr/bin/docker compose -f docker-compose.swg.yml $PROFILE down
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
UNITF
    systemctl daemon-reload
else
    echo "  would: write $UNIT and reload systemd"
fi

echo "==> 8/9 firewall"
# SSH first, always. A firewall enabled before the admin's own path is allowed
# is how a remote box is lost.
run ufw allow OpenSSH
run ufw default deny incoming
run ufw default allow outgoing
if [ "$WITH_TAILSCALE" = "1" ]; then
    run ufw allow in on tailscale0 to any port 3128 proto tcp
    run ufw allow in on tailscale0 to any port 8081 proto tcp
    [ "$WITH_WS" = "1" ] && run ufw allow in on tailscale0 to any port 3129 proto tcp
else
    note "no tailscale: open 3128/8081 to your client ranges yourself, never to the internet"
fi
run ufw --force enable

echo "==> 9/9 start"
if [ "$ACTION" != "dry-run" ]; then
    # A changed CA leaves Squid serving certificates signed by the old one, and
    # every handshake then fails. Clearing the forged-certificate volume is
    # part of changing the CA, not an optional tidy-up.
    if [ "$CA_REGENERATED" = "1" ]; then
        (cd "$INSTALL_DIR" && docker compose -f docker-compose.swg.yml down -v >/dev/null 2>&1) || true
    fi
    systemctl enable --now votal-edge >/dev/null 2>&1 || die "votal-edge.service failed to start (journalctl -u votal-edge)"
    for _ in $(seq 1 60); do
        curl -fsS -m 3 http://127.0.0.1:8081/healthz >/dev/null 2>&1 && break
        sleep 3
    done
else
    echo "  would: systemctl enable --now votal-edge"
fi

# ── what the operator needs next ──────────────────────────────────────────
echo
echo "${B}Votal Edge is up${Z}"
echo "  proxy         $EDGE_ADDR:3128"
[ "$WITH_WS" = "1" ] && echo "  websockets    $EDGE_ADDR:3129"
echo "  PAC URL       http://$EDGE_ADDR:8081/proxy.pac"
echo "  CA            $CA_DIR/ca.pem  (public cert only goes to MDM)"
if [ "$ACTION" != "dry-run" ]; then
    echo "  fingerprint   $(openssl x509 -in "$CA_DIR/ca.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    echo
    curl -fsS -m 5 http://127.0.0.1:8081/healthz 2>/dev/null | sed 's/^/  /'
fi
cat <<NEXT

Next, on one Mac, rehearse before you push to anyone:
  ./install-macos.sh --dry-run "http://$EDGE_ADDR:8081/proxy.pac" ./ca-cert.pem

Export the CA's PUBLIC certificate for MDM (never the file above, it holds the key):
  openssl x509 -in $CA_DIR/ca.pem -out ca-cert.pem

Mode is "$MODE". In enforce, the PAC has no DIRECT fallback, so if this box is
down the fleet loses AI access rather than quietly going direct. That is the
intended behaviour and it is worth agreeing before you flip it.

This makes the gateway the DEFAULT path. It becomes the ONLY path when the
network denies 443 (TCP and UDP) to AI destinations from everything except
this box.
NEXT
