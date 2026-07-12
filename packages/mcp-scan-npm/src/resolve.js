"use strict";

const { spawnSync } = require("child_process");
const os = require("os");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const https = require("https");
const { assetName } = require("./platform");

// The scanner release these binaries come from. Pinned so the wrapper downloads
// a known, checksum-verified build. Overridable for tests / staging.
const RELEASE_TAG = process.env.MCP_SCAN_RELEASE_TAG || "shield-mcp-v0.1.0";
const RELEASE_BASE =
  process.env.MCP_SCAN_RELEASE_BASE ||
  `https://github.com/sundi133/llm-shield/releases/download/${RELEASE_TAG}`;

// Fast path: a `shield-mcp` already on PATH (pip/pipx install). `--help` exits 0.
function findLocal(spawnSyncFn = spawnSync) {
  const res = spawnSyncFn("shield-mcp", ["--help"], { stdio: "ignore" });
  if (res.error && res.error.code === "ENOENT") return null;
  if (typeof res.status === "number") return "shield-mcp";
  return null;
}

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function verifyChecksum(filePath, expectedHex) {
  return sha256(filePath).toLowerCase() === String(expectedHex).trim().toLowerCase();
}

function cacheDir() {
  const base =
    process.env.MCP_SCAN_CACHE ||
    path.join(os.homedir() || os.tmpdir(), ".cache", "votal-mcp-scan");
  return path.join(base, RELEASE_TAG);
}

// Minimal GET that follows redirects (GitHub release assets 302 to a CDN).
function httpGet(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "user-agent": "votal-mcp-scan" } }, (res) => {
        const { statusCode, headers } = res;
        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          res.resume();
          if (redirectsLeft <= 0) return reject(new Error("too many redirects"));
          return resolve(httpGet(headers.location, redirectsLeft - 1));
        }
        if (statusCode !== 200) {
          res.resume();
          return reject(new Error(`GET ${url} -> HTTP ${statusCode}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

// Parse a `sha256  filename` line out of a SHA256SUMS body for one asset.
function checksumFor(sumsBody, asset) {
  const line = sumsBody
    .split("\n")
    .find((l) => l.trim().endsWith(" " + asset) || l.trim().endsWith("*" + asset) || l.trim().endsWith(asset));
  if (!line) return null;
  return line.trim().split(/\s+/)[0];
}

// Slow path: download the pinned binary for this OS/arch, verify its checksum,
// cache it executable, and return its path.
async function downloadBinary({ httpGetFn = httpGet } = {}) {
  const asset = assetName();
  const dir = cacheDir();
  const dest = path.join(dir, asset);
  if (fs.existsSync(dest)) return dest;

  fs.mkdirSync(dir, { recursive: true });
  const sumsBody = (await httpGetFn(`${RELEASE_BASE}/SHA256SUMS`)).toString("utf8");
  const expected = checksumFor(sumsBody, asset);
  if (!expected) {
    throw new Error(`no checksum for ${asset} in ${RELEASE_TAG}`);
  }

  const bin = await httpGetFn(`${RELEASE_BASE}/${asset}`);
  const tmp = dest + ".part";
  fs.writeFileSync(tmp, bin);
  if (!verifyChecksum(tmp, expected)) {
    fs.unlinkSync(tmp);
    throw new Error(`checksum mismatch for ${asset} (refusing to run)`);
  }
  fs.chmodSync(tmp, 0o755);
  fs.renameSync(tmp, dest);
  return dest;
}

// Hybrid resolution: local shield-mcp if present, else the verified binary.
async function resolveExecutable(opts = {}) {
  const { spawnSyncFn, allowDownload = true } = opts;
  const local = findLocal(spawnSyncFn);
  if (local) return { command: local, args: [] };
  if (!allowDownload) {
    throw new Error("shield-mcp not found on PATH and downloads are disabled");
  }
  const bin = await downloadBinary(opts);
  return { command: bin, args: [] };
}

module.exports = {
  RELEASE_TAG,
  RELEASE_BASE,
  findLocal,
  sha256,
  verifyChecksum,
  cacheDir,
  checksumFor,
  downloadBinary,
  resolveExecutable,
};
