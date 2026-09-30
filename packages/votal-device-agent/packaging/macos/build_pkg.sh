#!/bin/bash
# Build the macOS installer: PyInstaller, then pkgbuild; signing and notarization
# only when the release credentials are present (spec §10: "signing in release
# only").
#
#   ./build_pkg.sh                 (version from votal_device_agent/_version.py)
#   VERSION=0.1.1 ./build_pkg.sh   (override)
#
# Optional:
#   OLLAMA_TGZ=/path/ollama-darwin.tgz OLLAMA_SHA256=<hex>   bundle Ollama (release)
#   MAC_APP_IDENTITY="Developer ID Application: ..."           sign the binaries
#   MAC_INSTALLER_IDENTITY="Developer ID Installer: ..."       sign the pkg
#   NOTARY_PROFILE=<keychain profile for notarytool>          notarize and staple
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PKG_ROOT="$(cd "$HERE/../.." && pwd)"            # packages/votal-device-agent
REPO="$(cd "$PKG_ROOT/../.." && pwd)"
# The agent's own version unless the release overrides it.
VERSION="${VERSION:-$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$PKG_ROOT/votal_device_agent/_version.py")}"
OUT="${OUT:-$PKG_ROOT/dist}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 -m PyInstaller --noconfirm --clean --onedir --name votal-device-agent \
  --distpath "$WORK/dist" --workpath "$WORK/build" --specpath "$WORK" \
  --paths "$PKG_ROOT" --paths "$REPO" --paths "$REPO/packages/shield-mavlink" \
  --collect-submodules votal_device_agent --collect-submodules icap \
  --collect-submodules shield_mavlink --collect-all mitmproxy \
  "$HERE/../entry.py"

BASE="$WORK/root/Library/Application Support/Votal/DeviceAgent"
mkdir -p "$BASE" "$WORK/root/Library/LaunchDaemons"
cp -R "$WORK/dist/votal-device-agent" "$BASE/bin"
cp "$HERE/votal-native-host" "$BASE/bin/votal-native-host"
cp "$HERE/ai.votal.device-agent.plist" "$WORK/root/Library/LaunchDaemons/"

if [ -n "${OLLAMA_TGZ:-}" ]; then
  echo "${OLLAMA_SHA256:?OLLAMA_SHA256 is required with OLLAMA_TGZ}  $OLLAMA_TGZ" | shasum -a 256 -c -
  mkdir -p "$BASE/ollama"
  tar -xzf "$OLLAMA_TGZ" -C "$BASE/ollama"
else
  echo "note: no OLLAMA_TGZ; this package does not bundle Ollama (development build)"
fi

if [ -n "${MAC_APP_IDENTITY:-}" ]; then
  find "$BASE" -type f \( -perm -u+x -o -name "*.dylib" -o -name "*.so" \) -print0 |
    xargs -0 codesign --force --options runtime --timestamp --sign "$MAC_APP_IDENTITY"
fi

mkdir -p "$OUT"
PKG="$OUT/votal-device-agent-$VERSION.pkg"
SIGN=()
[ -n "${MAC_INSTALLER_IDENTITY:-}" ] && SIGN=(--sign "$MAC_INSTALLER_IDENTITY")
pkgbuild --root "$WORK/root" --scripts "$HERE/scripts" --identifier ai.votal.device-agent \
  --version "$VERSION" --install-location / ${SIGN[@]+"${SIGN[@]}"} "$PKG"

if [ -n "${NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$PKG"
fi
echo "$PKG"
