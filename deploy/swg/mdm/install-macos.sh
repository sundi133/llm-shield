#!/bin/bash
# Configure a managed Mac to send AI traffic through the inspection proxy.
#
# Push with Jamf (Files and Processes / script policy), Kandji (Custom Script),
# or Intune (Shell script, "run as signed-in user" = NO). Runs as root.
#
#   ./install-macos.sh <pac-url> <ca-cert.pem>          configure this Mac
#   ./install-macos.sh --dry-run <pac-url> <ca-cert.pem>  print, change nothing
#   ./install-macos.sh --verify                          report coverage
#
# Idempotent: safe to run on every check-in.
#
# A configuration PROFILE is still the better vehicle for the certificate and
# the proxy, because a profile can be marked non-removable and a script cannot.
# Use this for the pieces a profile does not reach -- Firefox's own trust store,
# Java's own truststore, and the CA bundles Python and Node ship with -- or as
# one artefact to start with.
#
# --verify prints a machine-readable line for fleet reporting:
#
#   shield-coverage ca=1 pac=1 chrome=1 firefox=1 bundles=1 java=1 proxyenv=1
#
# Jamf reads that with an extension attribute, Intune with a custom compliance
# script. Phase 5 of docs/swg-rollout-runbook.md asks for a coverage number you
# can show an auditor; this is where that number comes from.
set -uo pipefail

CA_DEST="/Library/Application Support/Shield/ca-cert.pem"
ENV_FILE="/etc/zshenv"
PROFILE_FILE="/etc/profile"
MARKER="# Managed by Shield"

MODE="install"
case "${1:-}" in
    --verify)  MODE="verify"; shift ;;
    --dry-run) MODE="dry-run"; shift ;;
esac

if [ "$MODE" != "verify" ]; then
    PAC_URL="${1:?usage: install-macos.sh [--dry-run|--verify] <pac-url> <ca-cert.pem>}"
    CA_CERT="${2:?usage: install-macos.sh [--dry-run|--verify] <pac-url> <ca-cert.pem>}"
    # The proxy the CLI uses. curl, Python, Node and Java cannot read a PAC, so
    # they need a fixed host:port; derive it from the PAC URL's host unless the
    # caller overrides it.
    PROXY_HOSTPORT="${SHIELD_PROXY:-$(printf %s "$PAC_URL" | sed -E 's#^https?://([^/:]+).*#\1#'):3128}"
fi

G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
ok()   { printf '  %sok%s    %s\n' "$G" "$Z" "$1"; }
no()   { printf '  %sFAIL%s  %s\n' "$R" "$Z" "$1"; }
note() { printf '  %s..%s    %s\n' "$Y" "$Z" "$1"; }
# Quote what dry-run prints. Network service names contain spaces ("Thunderbolt
# Bridge", "USB 10/100 LAN"), and an operator who copies an unquoted line out of
# a rehearsal gets a command that silently targets the wrong thing.
run() {
    if [ "$MODE" = "dry-run" ]; then
        printf '  would:'; printf ' %q' "$@"; printf '\n'
    else
        "$@"
    fi
}

# Only the install path needs root. --verify reads, and a coverage check that
# demands root is a coverage check the fleet tool will run as root or not at
# all; --dry-run changes nothing by definition.
[ "$MODE" != "install" ] || [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

# ── verify ───────────────────────────────────────────────────────────────
# Read-only. Safe on a production laptop, which matters: a coverage check that
# can change the machine will not be allowed to run fleet-wide.
if [ "$MODE" = "verify" ]; then
    ca=0; pac=0; chrome=0; firefox=0; bundles=0; java=0; proxyenv=0

    security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null \
        | grep -qi "Shield\|Inspection" && ca=1
    [ "$ca" = 1 ] && ok "inspection CA in the System keychain" || no "CA missing"

    svc=$(/usr/sbin/networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | head -1)
    if [ -n "$svc" ] && /usr/sbin/networksetup -getautoproxyurl "$svc" 2>/dev/null | grep -q "Enabled: Yes"; then
        pac=1; ok "PAC enabled on $svc"
    else
        no "PAC not enabled"
    fi

    if [ "$(defaults read /Library/Preferences/com.google.Chrome QuicAllowed 2>/dev/null)" = "0" ]; then
        chrome=1; ok "Chrome policy applied, QUIC disabled"
    else
        no "Chrome policy missing or QUIC still allowed"
    fi

    if [ ! -d /Applications/Firefox.app ]; then
        firefox=1; note "Firefox not installed"
    elif grep -q "AutoConfigURL" /Applications/Firefox.app/Contents/Resources/distribution/policies.json 2>/dev/null; then
        firefox=1; ok "Firefox policy applied"
    else
        no "Firefox installed but unmanaged: its own trust store and proxy are untouched"
    fi

    grep -q "REQUESTS_CA_BUNDLE" "$ENV_FILE" 2>/dev/null && bundles=1
    [ "$bundles" = 1 ] && ok "CA bundles set for Python, Node and curl" || no "CA bundles missing: scripts will fail TLS"

    grep -q "https_proxy" "$ENV_FILE" 2>/dev/null && proxyenv=1
    [ "$proxyenv" = 1 ] && ok "proxy variables set for CLI tools" || no "CLI tools go direct: curl and coding agents are unscreened"

    if ! /usr/libexec/java_home >/dev/null 2>&1; then
        java=1; note "no JDK installed"
    else
        jh=$(/usr/libexec/java_home 2>/dev/null)
        if keytool -list -keystore "$jh/lib/security/cacerts" -storepass changeit -alias votal-swg >/dev/null 2>&1; then
            java=1; ok "CA in the Java truststore"
        else
            no "JDK present but the CA is not in its truststore: Java ignores the keychain"
        fi
    fi

    echo
    echo "shield-coverage ca=$ca pac=$pac chrome=$chrome firefox=$firefox bundles=$bundles java=$java proxyenv=$proxyenv"
    [ $((ca * pac * chrome * firefox * bundles * java * proxyenv)) -eq 1 ] && exit 0 || exit 1
fi

# ── install ──────────────────────────────────────────────────────────────
[ "$MODE" = "dry-run" ] && echo "DRY RUN: nothing will be changed"
[ -f "$CA_CERT" ] || { echo "no CA at $CA_CERT" >&2; exit 1; }

# A CA without keyUsage=keyCertSign is accepted by curl (LibreSSL) and REJECTED
# by OpenSSL 3.x, so Python, Node and Java fail TLS on a fleet that looks
# correctly configured. Catch it here rather than in a support queue.
if ! openssl x509 -in "$CA_CERT" -noout -text 2>/dev/null | grep -q "Certificate Sign"; then
    echo "refusing to install: $CA_CERT has no keyUsage=keyCertSign." >&2
    echo "OpenSSL-based clients (Python, Node, Java) will reject it." >&2
    exit 1
fi

echo "==> 1/6 trusting the inspection CA"
run mkdir -p "$(dirname "$CA_DEST")"
run cp "$CA_CERT" "$CA_DEST"
run chmod 644 "$CA_DEST"
# -d puts it in the admin domain (system-wide), -r trustRoot makes it a root.
run security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "$CA_DEST"

echo "==> 2/6 proxy PAC on every network service"
# Covers Safari, which has no proxy setting of its own, and most native apps.
# Every service, not just Wi-Fi: a laptop on a dock is on Ethernet.
/usr/sbin/networksetup -listallnetworkservices | tail -n +2 | while read -r svc; do
    case "$svc" in \**) continue ;; esac   # a leading * means disabled
    run /usr/sbin/networksetup -setautoproxyurl "$svc" "$PAC_URL"
    run /usr/sbin/networksetup -setautoproxystate "$svc" on
done

echo "==> 3/6 Chrome and Edge policy"
# QuicAllowed=false is not optional: Chrome prefers HTTP/3, which ignores an
# HTTP proxy entirely, and the bypass is silent -- no error, no traffic,
# nothing inspected.
for domain in com.google.Chrome com.microsoft.Edge; do
    run defaults write "/Library/Preferences/$domain" ProxyMode   -string "pac_script"
    run defaults write "/Library/Preferences/$domain" ProxyPacUrl -string "$PAC_URL"
    run defaults write "/Library/Preferences/$domain" QuicAllowed -bool false
done

echo "==> 4/6 Firefox (shares neither the trust store nor the proxy)"
FF_DIST="/Applications/Firefox.app/Contents/Resources/distribution"
if [ -d "/Applications/Firefox.app" ]; then
    run mkdir -p "$FF_DIST"
    if [ "$MODE" = "dry-run" ]; then
        echo "  would: write $FF_DIST/policies.json"
    else
        cat > "$FF_DIST/policies.json" <<JSON
{
  "policies": {
    "Certificates": { "ImportEnterpriseRoots": true },
    "Proxy": {
      "Mode": "autoConfig",
      "AutoConfigURL": "$PAC_URL",
      "Locked": true
    }
  }
}
JSON
    fi
else
    echo "    Firefox not installed, skipping"
fi

echo "==> 5/6 CLI tools: CA bundles AND the proxy"
# Two separate failures live here.
#
# The bundles: Python and Node ship their own trust stores and ignore the
# keychain. Miss them and every script on the fleet starts failing TLS, which
# is the change people notice first.
#
# The proxy: curl, Python, Node and coding agents (Codex, Claude Code) do NOT
# read the macOS proxy setting, only these variables, and they cannot read a
# PAC at all. Without them the browser is screened and the terminal is not,
# which is the gap most likely to be mistaken for coverage. Note this is a
# DEFAULT, not a control: a user can unset it. Only egress control makes the
# gateway mandatory.
if [ "$MODE" = "dry-run" ]; then
    echo "  would: write $ENV_FILE and $PROFILE_FILE (proxy + CA bundle variables)"
else
    for f in "$ENV_FILE" "$PROFILE_FILE"; do
        [ -f "$f" ] && grep -q "$MARKER" "$f" && sed -i '' "/$MARKER/,\$d" "$f"
        cat >> "$f" <<ENVV
$MARKER
export REQUESTS_CA_BUNDLE="$CA_DEST"
export SSL_CERT_FILE="$CA_DEST"
export NODE_EXTRA_CA_CERTS="$CA_DEST"
export CURL_CA_BUNDLE="$CA_DEST"
export https_proxy="http://$PROXY_HOSTPORT"
export http_proxy="http://$PROXY_HOSTPORT"
export no_proxy="localhost,127.0.0.1,::1"
# Node 24+ ignores proxy variables in fetch() unless this is set.
export NODE_USE_ENV_PROXY=1
ENVV
    done
fi

echo "==> 6/6 Java (its own truststore, its own proxy settings)"
# Java reads neither the keychain nor the variables above, so a JDK on the
# fleet is an unscreened path with a confusing TLS error at the end of it.
if /usr/libexec/java_home >/dev/null 2>&1; then
    for jh in $(/usr/libexec/java_home -V 2>&1 | awk '/\/.*Home/ {print $NF}' | sort -u); do
        ks="$jh/lib/security/cacerts"
        [ -f "$ks" ] || continue
        run keytool -delete -alias votal-swg -keystore "$ks" -storepass changeit
        run keytool -importcert -noprompt -alias votal-swg -keystore "$ks" \
            -storepass changeit -file "$CA_DEST"
        echo "    $ks"
    done
    if [ "$MODE" != "dry-run" ]; then
        printf '%s\nexport JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=%s -Dhttps.proxyPort=%s"\n' \
            "$MARKER" "${PROXY_HOSTPORT%%:*}" "${PROXY_HOSTPORT##*:}" >> "$ENV_FILE"
    fi
else
    echo "    no JDK installed, skipping"
fi

echo
echo "Done. Verify on this device:"
echo "  $0 --verify"
echo "  chrome://policy            ProxySettings and QuicAllowed applied"
echo "  about:policies             Proxy and Certificates (Firefox)"
echo
echo "Reminder: this makes the gateway the DEFAULT path. It becomes the ONLY"
echo "path when the network denies 443 (TCP and UDP) to AI destinations from"
echo "everything except the proxy."
