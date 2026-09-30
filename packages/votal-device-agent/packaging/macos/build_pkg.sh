#!/bin/bash
# Build the macOS installer: PyInstaller, then pkgbuild; signing and notarization
# only when the release credentials are present (spec §10: "signing in release
# only").
#
#   ./build_pkg.sh                 (version from votal_device_agent/_version.py)
#   VERSION=0.1.1 ./build_pkg.sh   (override)
#
# Optional:
#   OLLAMA_DIR=<dir from fetch_ollama.py macos>              bundle Ollama (release)
#   MAC_APP_IDENTITY="Developer ID Application: ..."           sign the binaries
#   MAC_INSTALLER_IDENTITY="Developer ID Installer: ..."       sign the pkg
#   NOTARY_PROFILE=<keychain profile for notarytool>          notarize and staple
#   NOTARY_KEYCHAIN=<keychain holding that profile>           when not the default one
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

if [ -n "${OLLAMA_DIR:-}" ]; then
  # Already checked against ollama.lock by fetch_ollama.py.
  [ -x "$OLLAMA_DIR/ollama" ] || { echo "OLLAMA_DIR has no ollama binary" >&2; exit 1; }
  cp -R "$OLLAMA_DIR" "$BASE/ollama"
else
  echo "note: no OLLAMA_DIR; this package does not bundle Ollama (development build)"
fi

if [ -n "${MAC_APP_IDENTITY:-}" ]; then
  # Our files only. Ollama arrives signed by its maker (Developer ID, hardened
  # runtime, timestamped), which notarization accepts; re-signing it would
  # replace their identity with ours for code we did not build.
  find "$BASE/bin" -type f \( -perm -u+x -o -name "*.dylib" -o -name "*.so" \) -print0 |
    xargs -0 codesign --force --options runtime --timestamp --sign "$MAC_APP_IDENTITY"
fi

mkdir -p "$OUT"
PKG="$OUT/votal-device-agent-$VERSION.pkg"
SIGN=()
[ -n "${MAC_INSTALLER_IDENTITY:-}" ] && SIGN=(--sign "$MAC_INSTALLER_IDENTITY")
pkgbuild --root "$WORK/root" --scripts "$HERE/scripts" --identifier ai.votal.device-agent \
  --version "$VERSION" --install-location / ${SIGN[@]+"${SIGN[@]}"} "$PKG"

if [ -n "${NOTARY_PROFILE:-}" ]; then
  KC=()
  [ -n "${NOTARY_KEYCHAIN:-}" ] && KC=(--keychain "$NOTARY_KEYCHAIN")
  xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" ${KC[@]+"${KC[@]}"} --wait
  xcrun stapler staple "$PKG"
fi
echo "$PKG"
