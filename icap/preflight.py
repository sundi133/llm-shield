"""Pre-flight: decide whether this site already decrypts.

Task 5 of docs/spec-swg-icap-adapter.md.

The most common objection to this product is "we already do TLS inspection at
the SWG, why would I install a second MITM?" It is a fair objection, and the
right answer is usually to integrate rather than duplicate. So the adapter
detects it and says so, rather than letting an operator deploy a redundant
root CA and find out later.

    python -m icap preflight

Two signals, in order of reliability:

1. **The certificate chain.** Open TLS to a well-known host and look at the
   issuer the peer presents. If it is not a public CA, something between here
   and the internet is already terminating TLS. This works from inside a
   container, which is where this usually runs.
2. **Forwarding clients.** Zscaler Client Connector, Netskope's stAgentSvc and
   friends. Only visible with `--pid=host` or when run on the host directly, so
   its absence proves nothing and is reported that way.

This is advisory, not a security control. It exists to stop a bad deployment,
not to detect an adversary.
"""
from __future__ import annotations

import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass, field

# Markers that appear in an intercepting CA's issuer name. Matched against the
# raw certificate bytes, which is crude but dependency-free and good enough to
# tell an operator to go look.
SWG_VENDORS: dict[str, str] = {
    "Zscaler": "Zscaler",
    "Netskope": "Netskope",
    "Palo Alto": "Palo Alto Networks",
    "Blue Coat": "Broadcom/Symantec Blue Coat",
    "Symantec": "Broadcom/Symantec",
    "Forcepoint": "Forcepoint",
    "McAfee": "Skyhigh/McAfee",
    "Fortinet": "Fortinet",
    "FortiGate": "Fortinet",
    "Cisco Umbrella": "Cisco Umbrella",
    "iboss": "iboss",
    "Menlo": "Menlo Security",
}

SWG_PROCESSES: dict[str, str] = {
    "ZscalerClientConnector": "Zscaler",
    "Zscaler": "Zscaler",
    "stAgentSvc": "Netskope",
    "nsdiag": "Netskope",
    "GlobalProtect": "Palo Alto",
    "acumbrellaagent": "Cisco Umbrella",
}

PROBE_HOSTS = ("api.openai.com", "api.anthropic.com")


@dataclass
class Finding:
    probed: str = ""
    issuer_blob: bytes = b""
    vendor: str = ""
    error: str = ""


@dataclass
class Preflight:
    findings: list[Finding] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    process_scan_available: bool = False

    @property
    def vendor(self) -> str:
        for f in self.findings:
            if f.vendor:
                return f.vendor
        return self.processes[0] if self.processes else ""

    @property
    def already_inspecting(self) -> bool:
        return bool(self.vendor)


def probe_chain(host: str, port: int = 443, timeout: float = 5.0) -> Finding:
    """Fetch the peer certificate without validating it.

    Validation is off on purpose: the interesting case is precisely the one
    where the presented chain is NOT publicly trusted.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True) or b""
        return Finding(probed=host, issuer_blob=der, vendor=identify(der))
    except Exception as exc:
        return Finding(probed=host, error=str(exc))


def identify(der: bytes) -> str:
    """Name the intercepting vendor, if the certificate names one."""
    if not der:
        return ""
    for marker, vendor in SWG_VENDORS.items():
        if marker.encode("utf-8") in der or marker.encode("utf-16-be") in der:
            return vendor
    return ""


def scan_processes() -> tuple[list[str], bool]:
    """Look for a forwarding client. Returns (vendors, scan_worked)."""
    try:
        out = subprocess.run(
            ["ps", "-eo", "comm"], capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return [], False
    found = {vendor for name, vendor in SWG_PROCESSES.items() if name.lower() in out.lower()}
    return sorted(found), True


def run(probe=probe_chain, scanner=scan_processes, hosts=PROBE_HOSTS) -> Preflight:
    result = Preflight()
    for host in hosts:
        result.findings.append(probe(host))
    result.processes, result.process_scan_available = scanner()
    return result


def report(result: Preflight) -> str:
    lines: list[str] = ["shield-icap pre-flight", ""]

    for f in result.findings:
        if f.error:
            lines.append(f"  {f.probed:<32} could not probe: {f.error}")
        elif f.vendor:
            lines.append(f"  {f.probed:<32} intercepted by {f.vendor}")
        else:
            lines.append(f"  {f.probed:<32} chain looks publicly issued")

    lines.append("")
    if result.process_scan_available:
        if result.processes:
            lines.append("  forwarding client: " + ", ".join(result.processes))
        else:
            lines.append("  forwarding client: none found")
    else:
        lines.append("  forwarding client: not checked (run on the host or with --pid=host)")

    lines.append("")
    if result.already_inspecting:
        lines += [
            f"Existing inspection detected: {result.vendor}",
            "",
            "  -> Mode B (ICAP only). Point that gateway's ICAP service at",
            "     icap://<this-host>:1344/screen.",
            "  -> Do NOT install a second root CA. A second MITM means two",
            "     forged chains, two bypass lists, and twice the debugging.",
        ]
    else:
        lines += [
            "No existing inspection detected.",
            "",
            "  -> Mode A (bundled Squid): docker compose -f docker-compose.swg.yml up -d",
            "  -> This deploys a root CA to your fleet, which needs security",
            "     sign-off. If you do run an SWG that this probe could not see,",
            "     prefer Mode B and skip the CA entirely.",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    result = run()
    print(report(result))
    # Exit code is advisory too: 0 = no inspection found (Mode A),
    # 10 = existing inspection (Mode B). Lets an installer branch on it.
    return 10 if result.already_inspecting else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
