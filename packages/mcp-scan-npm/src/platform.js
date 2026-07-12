"use strict";

// Map the host platform/arch to a release asset name produced by
// .github/workflows/build-shield-mcp-binaries.yml. Keep these two in lockstep.
function assetName(platform = process.platform, arch = process.arch) {
  const osName = { linux: "linux", darwin: "macos", win32: "windows" }[platform];
  const archName = { x64: "x64", arm64: "arm64" }[arch];
  if (!osName || !archName) {
    throw new Error(`unsupported platform: ${platform}/${arch}`);
  }
  // v1 ships Windows on x64 only (matches the build matrix).
  if (osName === "windows" && archName !== "x64") {
    throw new Error(`unsupported platform: ${platform}/${arch} (windows is x64 only in v1)`);
  }
  const ext = osName === "windows" ? ".exe" : "";
  return `shield-mcp-${osName}-${archName}${ext}`;
}

module.exports = { assetName };
