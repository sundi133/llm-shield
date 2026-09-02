#!/bin/bash
# Configure a managed Mac to send AI traffic through the inspection proxy.
#
# Push with Jamf (Files and Processes / script policy), Kandji (Custom Script),
# or Intune (Shell script, "run as signed-in user" = NO). Runs as root.
#
#   ./install-macos.sh <pac-url> <path-to-ca-cert.pem>
#
# Idempotent: safe to run on every check-in.
#
# A configuration PROFILE is the better vehicle for the certificate and the
# proxy, because a profile can be marked non-removable and a script cannot.
# Use this when you want one artefact that covers the pieces a profile does
# not reach -- Firefox's own trust store, and the CA bundles that Python and
# Node ship with -- or when you want the whole thing in one place to start.
set -euo pipefail

PAC_URL="${1:?usage: install-macos.sh <pac-url> <ca-cert.pem>}"
CA_CERT="${2:?usage: install-macos.sh <pac-url> <ca-cert.pem>}"
CA_DEST="/Library/Application Support/Shield/ca-cert.pem"

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
[ -f "$CA_CERT" ] || { echo "no CA at $CA_CERT" >&2; exit 1; }

echo "==> 1/5 trusting the inspection CA"
mkdir -p "$(dirname "$CA_DEST")"
cp "$CA_CERT" "$CA_DEST"
chmod 644 "$CA_DEST"
# -d puts it in the admin domain (system-wide), -r trustRoot makes it a root.
security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "$CA_DEST"

echo "==> 2/5 proxy PAC on every network service"
# Covers Safari, which has no proxy setting of its own, and most native apps.
# Every service, not just Wi-Fi: a laptop on a dock is on Ethernet.
/usr/sbin/networksetup -listallnetworkservices | tail -n +2 | while read -r svc; do
    case "$svc" in \**) continue ;; esac   # a leading * means disabled
    /usr/sbin/networksetup -setautoproxyurl "$svc" "$PAC_URL" || true
    /usr/sbin/networksetup -setautoproxystate "$svc" on || true
done

echo "==> 3/5 Chrome and Edge policy"
# QuicAllowed=false is not optional: Chrome prefers HTTP/3, which ignores an
# HTTP proxy entirely, and the bypass is silent -- no error, no traffic,
# nothing inspected.
for domain in com.google.Chrome com.microsoft.Edge; do
    defaults write "/Library/Preferences/$domain" ProxyMode   -string "pac_script"
    defaults write "/Library/Preferences/$domain" ProxyPacUrl -string "$PAC_URL"
    defaults write "/Library/Preferences/$domain" QuicAllowed -bool false
done

echo "==> 4/5 Firefox (shares neither the trust store nor the proxy)"
FF_DIST="/Applications/Firefox.app/Contents/Resources/distribution"
if [ -d "/Applications/Firefox.app" ]; then
    mkdir -p "$FF_DIST"
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
else
    echo "    Firefox not installed, skipping"
fi

echo "==> 5/5 CA bundles for Python, Node and curl"
# These ship their own trust stores and ignore the system keychain. Miss this
# and every script on the fleet starts failing TLS, which is the change people
# notice first.
cat > /etc/zshenv <<ENVV
# Managed by Shield. AI inspection CA for runtimes with their own trust store.
export REQUESTS_CA_BUNDLE="$CA_DEST"
export SSL_CERT_FILE="$CA_DEST"
export NODE_EXTRA_CA_CERTS="$CA_DEST"
ENVV
cp /etc/zshenv /etc/profile.d_shield_ca 2>/dev/null || true

echo
echo "Done. Verify on this device:"
echo "  chrome://policy            ProxySettings and QuicAllowed applied"
echo "  about:policies             Proxy and Certificates (Firefox)"
echo "  networksetup -getautoproxyurl Wi-Fi"
