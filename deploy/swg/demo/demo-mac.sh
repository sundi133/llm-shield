#!/usr/bin/env bash
# Customer demo: auto-route a REAL browser through the public SWG -- no curl,
# no MDM. Scoped to a throwaway Chrome profile and a scoped DNS override, so the
# rest of this Mac (including any Claude Code / app traffic) is left alone.
# Fully reversible: `teardown` removes everything it added.
#
#   ./demo-mac.sh setup      # trust the inspection CA + import the device cert (one sudo)
#   ./demo-mac.sh launch     # open the demo Chrome, already pointed at the SWG
#   ./demo-mac.sh teardown   # remove CA trust, the device identity, and the profile
#
# This is the MANUAL, single-machine equivalent of what MDM pushes fleet-wide
# (deploy/swg/mdm/install-macos.sh). Use it to show the control working in a
# real browser before standing up MDM.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# Where the deploy's cert material lives. Override CERTS= if you keep it elsewhere.
CERTS="${CERTS:-$HERE/../gcp}"
HOST="${SHIELD_PROXY_PUBLIC_HOST:-swg.votal.ai}"
IP="${SHIELD_PROXY_IP:-35.185.217.75}"
PAC="http://$HOST:8081/proxy.pac"
CN="${DEVICE_CN:-test-laptop-01}"       # the CN you minted device.crt with
CA_CN="${CA_CN:-Votal Shield Inspection CA}"

PROFILE="$HOME/.shield-swg-demo-chrome"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CA_SRC="$CERTS/interception-ca.pem"      # Secret Manager blob: holds cert AND key
CA_CERT_ONLY="$HERE/.demo-ca-cert.pem"   # only the certificate is ever installed
DEV_CRT="$CERTS/device.crt"
DEV_KEY="$CERTS/device.key"
P12="$HERE/.demo-device.p12"
P12_PASS="shielddemo"

case "${1:-}" in
setup)
  for f in "$CA_SRC" "$DEV_CRT" "$DEV_KEY"; do
    [ -f "$f" ] || { echo "missing $f -- run the gate steps in docs/swg-public-proxy-runbook.md first (mint device.crt, pull interception-ca.pem)"; exit 1; }
  done
  # The CA file is the Secret Manager blob (cert + PRIVATE KEY in one file).
  # Extract ONLY the certificate -- the CA key must never land on a device.
  openssl x509 -in "$CA_SRC" -out "$CA_CERT_ONLY" >/dev/null 2>&1
  echo "==> trusting the inspection CA system-wide (sudo; so bumped AI sites validate)"
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CA_CERT_ONLY"
  echo "==> importing the device identity into your login keychain (mTLS to the proxy)"
  openssl pkcs12 -export -inkey "$DEV_KEY" -in "$DEV_CRT" -out "$P12" -passout "pass:$P12_PASS" >/dev/null 2>&1
  security import "$P12" -k "$HOME/Library/Keychains/login.keychain-db" -P "$P12_PASS" -A >/dev/null 2>&1 \
    || security import "$P12" -P "$P12_PASS" -A >/dev/null 2>&1
  echo "setup done.  next:  $0 launch"
  ;;
launch)
  [ -x "$CHROME" ] || { echo "Google Chrome not found at: $CHROME"; exit 1; }
  echo "==> launching the demo browser (AI hosts -> SWG at $HOST:8443, everything else DIRECT)"
  echo "    - scoped to profile $PROFILE and a scoped DNS override; the rest of this Mac is untouched"
  echo "    - a one-time client-cert picker may appear: choose '$CN' (that IS the mTLS device auth)"
  # --proxy-pac-url     : selective routing (AI -> proxy, else DIRECT) from the deployed PAC
  # --host-resolver-rules: resolve the proxy host to the VM IP for THIS Chrome only (no /etc/hosts)
  # --disable-quic      : Chrome prefers HTTP/3, which silently bypasses an HTTP proxy
  "$CHROME" \
    --user-data-dir="$PROFILE" \
    --proxy-pac-url="$PAC" \
    --host-resolver-rules="MAP $HOST $IP" \
    --disable-quic \
    --no-first-run --no-default-browser-check \
    "https://claude.ai" >/dev/null 2>&1 &
  cat <<TXT
demo browser started. Suggested flow:
  1. Sign in to claude.ai (or chatgpt.com) as normal -- it works, it's just inspected.
  2. Send a benign message ("summarise this quarter's goals") -> it goes through.
  3. Send one with protected data (a customer SSN / card / secret) -> blocked;
     the message fails to send and never reaches the model.
  4. Switch to the Shield Telemetry tab (shield.votal.ai) -> the block appears in
     real time with the policy name, while the benign one shows PASS.
TXT
  ;;
teardown)
  echo "==> removing CA trust (sudo), the device identity, and the demo profile"
  sudo security delete-certificate -c "$CA_CN" /Library/Keychains/System.keychain 2>/dev/null || true
  security delete-identity -c "$CN" 2>/dev/null || true
  rm -rf "$PROFILE" "$CA_CERT_ONLY" "$P12"
  echo "teardown done. nothing of the demo remains."
  ;;
*)
  echo "usage: $0 {setup|launch|teardown}"; exit 1 ;;
esac
