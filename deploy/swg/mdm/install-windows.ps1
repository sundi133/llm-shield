<#
Configure a managed Windows device to send AI traffic through the inspection
proxy. The Windows counterpart of install-macos.sh, and it closes the same gaps:
the browser is the easy half, the terminal and the JDK are where a fleet ends
up looking covered while coding agents go straight out.

Push with Intune (Devices > Scripts, "Run this script using the logged on
credentials" = No, so it runs as SYSTEM) or as a GPO startup script.

  .\install-windows.ps1 -PacUrl "http://swg.corp.example:8081/proxy.pac" `
                        -CaCertPath "\\share\shield\ca-cert.cer"
  .\install-windows.ps1 -DryRun -PacUrl ... -CaCertPath ...   print, change nothing
  .\install-windows.ps1 -Verify                               report coverage

Idempotent: safe to run on every check-in.

Group Policy is the better vehicle for the Chrome and Edge settings, because
ADMX-backed policy is what users cannot override. Use this when you want one
artefact that also covers Firefox's own trust store, the CA bundles Python and
Node ship with, the proxy variables the terminal reads, and Java's truststore.

-Verify prints a machine-readable line for fleet reporting, the same shape the
macOS script emits so one compliance query covers both platforms:

  shield-coverage ca=1 pac=1 chrome=1 firefox=1 bundles=1 java=1 proxyenv=1

Intune reads it with a custom compliance script; ConfigMgr with a CI.
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory)]
    [Parameter(ParameterSetName = 'DryRun',  Mandatory)]
    [string]$PacUrl,

    [Parameter(ParameterSetName = 'Install', Mandatory)]
    [Parameter(ParameterSetName = 'DryRun',  Mandatory)]
    [string]$CaCertPath,

    # curl, Python, Node and Java cannot read a PAC, so they need a fixed
    # host:port. Derived from the PAC URL's host on :3128 unless overridden.
    [string]$Proxy,

    [Parameter(ParameterSetName = 'DryRun')][switch]$DryRun,
    [Parameter(ParameterSetName = 'Verify')][switch]$Verify
)

$ErrorActionPreference = 'Stop'
$caDest   = "$env:ProgramData\Shield\ca-cert.cer"
$vendors  = @('Google\Chrome', 'Microsoft\Edge')
$cliVars  = 'REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS', 'CURL_CA_BUNDLE'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# host:port the CLI and Java use. From the PAC URL's host on :3128 by default.
function Get-ProxyHostPort {
    param($pac, $override)
    if ($override) { return $override }
    $h = ([Uri]$pac).Host
    return "${h}:3128"
}

$G = 'Green'; $R = 'Red'; $Y = 'Yellow'
function Ok   { param($m) Write-Host "  ok    $m"   -ForegroundColor $G }
function Fail { param($m) Write-Host "  FAIL  $m" -ForegroundColor $R }
function Note { param($m) Write-Host "  ..    $m" -ForegroundColor $Y }

# ── verify ───────────────────────────────────────────────────────────────
# Read-only, needs no admin: a coverage check the fleet tool runs unprivileged,
# or it does not run at all.
if ($Verify) {
    $ca = 0; $pac = 0; $chrome = 0; $firefox = 0; $bundles = 0; $java = 0; $proxyenv = 0

    if (Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -match 'Shield|Inspection' }) { $ca = 1 }
    if ($ca) { Ok "inspection CA in the Machine Root store" } else { Fail "CA missing" }

    $cs = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome" -ErrorAction SilentlyContinue
    if ($cs -and $cs.ProxySettings -match 'pac_script' -and $cs.QuicAllowed -eq 0) {
        $pac = 1; $chrome = 1; Ok "Chrome/Edge PAC applied, QUIC disabled"
    } else {
        Fail "Chrome policy missing, or QUIC still allowed (HTTP/3 bypasses the proxy)"
    }

    $ff = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Proxy" -ErrorAction SilentlyContinue
    if (-not (Get-Command firefox -ErrorAction SilentlyContinue) -and
        -not (Test-Path "$env:ProgramFiles\Mozilla Firefox")) {
        $firefox = 1; Note "Firefox not installed"
    } elseif ($ff -and $ff.AutoConfigURL) {
        $firefox = 1; Ok "Firefox policy applied"
    } else {
        Fail "Firefox installed but unmanaged: its own trust store and proxy are untouched"
    }

    if ([Environment]::GetEnvironmentVariable('REQUESTS_CA_BUNDLE', 'Machine')) { $bundles = 1 }
    if ($bundles) { Ok "CA bundles set for Python, Node and curl" } else { Fail "CA bundles missing: scripts will fail TLS" }

    if ([Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Machine')) { $proxyenv = 1 }
    if ($proxyenv) { Ok "proxy variables set for CLI tools" } else { Fail "CLI tools go direct: curl and coding agents are unscreened" }

    $keytool = Get-Command keytool -ErrorAction SilentlyContinue
    if (-not $keytool) {
        $java = 1; Note "no JDK on PATH"
    } else {
        $jdkHome = Split-Path (Split-Path $keytool.Source)
        $ks = Join-Path $jdkHome 'lib\security\cacerts'
        if ((Test-Path $ks) -and
            (& $keytool.Source -list -keystore $ks -storepass changeit -alias votal-swg 2>$null)) {
            $java = 1; Ok "CA in the Java truststore"
        } else {
            Fail "JDK present but the CA is not in its truststore: Java ignores the Windows store"
        }
    }

    Write-Host ""
    Write-Host "shield-coverage ca=$ca pac=$pac chrome=$chrome firefox=$firefox bundles=$bundles java=$java proxyenv=$proxyenv"
    if ($ca * $pac * $chrome * $firefox * $bundles * $java * $proxyenv -eq 1) { exit 0 } else { exit 1 }
}

# ── install / dry-run ─────────────────────────────────────────────────────
if (-not (Test-Admin)) { throw "must run elevated (SYSTEM or Administrator)" }
if ($DryRun) { Write-Host "DRY RUN: nothing will be changed" -ForegroundColor $Y }

function Do-Step {
    param([string]$Describe, [scriptblock]$Action)
    if ($DryRun) { Write-Host "  would: $Describe" } else { & $Action }
}

if (-not (Test-Path $CaCertPath)) { throw "no CA at $CaCertPath" }

# A CA without keyUsage=KeyCertSign is accepted by some clients and REJECTED by
# OpenSSL 3.x, so Python, Node and Java fail TLS on a fleet that looks correctly
# configured. Refuse it here rather than in a support queue. (Cost us an hour.)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CaCertPath
$ku = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] }
if (-not $ku -or -not ($ku.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign)) {
    throw "refusing to install: $CaCertPath has no keyUsage=KeyCertSign. OpenSSL-based clients (Python, Node, Java) will reject it."
}

$proxyHostPort = Get-ProxyHostPort $PacUrl $Proxy

Write-Host "==> 1/6 trusting the inspection CA"
Do-Step "import $CaCertPath into Machine Root" {
    New-Item -ItemType Directory -Force -Path (Split-Path $caDest) | Out-Null
    Copy-Item $CaCertPath $caDest -Force
    Import-Certificate -FilePath $caDest -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
}

Write-Host "==> 2/6 system proxy (WinINET + WinHTTP, for native apps and services)"
# Chromium-based native apps (Claude, ChatGPT desktop) and Windows services read
# the machine WinINET/WinHTTP proxy, not the per-user browser policy. Point both
# at the PAC so a native app is covered without a per-app launch flag.
Do-Step "set WinINET AutoConfigURL and WinHTTP proxy to the PAC" {
    $inet = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    New-ItemProperty -Path $inet -Name 'AutoConfigURL' -Value $PacUrl -PropertyType String -Force | Out-Null
    netsh winhttp import proxy source=ie | Out-Null
}

Write-Host "==> 3/6 Chrome and Edge policy"
# QuicAllowed=0 is not optional: Chrome prefers HTTP/3, which ignores an HTTP
# proxy entirely, and the bypass is silent -- no error, no traffic, nothing
# inspected.
$proxyJson = (@{ ProxyMode = 'pac_script'; ProxyPacUrl = $PacUrl } | ConvertTo-Json -Compress)
foreach ($vendor in $vendors) {
    Do-Step "set $vendor ProxySettings (PAC) and QuicAllowed=0" {
        $key = "HKLM:\SOFTWARE\Policies\$vendor"
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name 'ProxySettings' -Value $proxyJson -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'QuicAllowed'   -Value 0          -PropertyType DWord  -Force | Out-Null
    }
}

Write-Host "==> 4/6 Firefox (shares neither the trust store nor the proxy)"
Do-Step "set Firefox ImportEnterpriseRoots and the PAC" {
    $ff = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    New-Item -Path "$ff\Certificates" -Force | Out-Null
    New-ItemProperty -Path "$ff\Certificates" -Name 'ImportEnterpriseRoots' -Value 1 -PropertyType DWord -Force | Out-Null
    New-Item -Path "$ff\Proxy" -Force | Out-Null
    New-ItemProperty -Path "$ff\Proxy" -Name 'Mode'          -Value 'autoConfig' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$ff\Proxy" -Name 'AutoConfigURL' -Value $PacUrl       -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$ff\Proxy" -Name 'Locked'        -Value 1             -PropertyType DWord  -Force | Out-Null
}

Write-Host "==> 5/6 CLI tools: CA bundles AND the proxy"
# Two separate failures live here.
#
# The bundles: Python and Node ship their own trust stores and ignore the
# Windows certificate store. Miss them and every script on the fleet starts
# failing TLS, which is the change people notice first.
#
# The proxy: curl, Python, Node and coding agents (Codex, Claude Code) do NOT
# read the WinINET/WinHTTP proxy above, only these variables, and they cannot
# read a PAC at all. Without them the browser is screened and the terminal is
# not, which is the gap most easily mistaken for coverage. A socket-carrying
# agent (Codex) needs a proxy that speaks WebSocket, so an operator screening
# those should point this at shield-ws (:3129), not Squid (:3128); the -Proxy
# override is for exactly that. Note this is a DEFAULT, not a control: a user
# can unset it. Only egress control makes the gateway mandatory.
Do-Step "set machine env: CA bundles, https_proxy/http_proxy/no_proxy, NODE_USE_ENV_PROXY" {
    foreach ($v in $cliVars) { [Environment]::SetEnvironmentVariable($v, $caDest, 'Machine') }
    [Environment]::SetEnvironmentVariable('HTTPS_PROXY', "http://$proxyHostPort", 'Machine')
    [Environment]::SetEnvironmentVariable('HTTP_PROXY',  "http://$proxyHostPort", 'Machine')
    [Environment]::SetEnvironmentVariable('NO_PROXY',    'localhost,127.0.0.1,::1', 'Machine')
    # Node 24+ ignores proxy variables in fetch() unless this is set.
    [Environment]::SetEnvironmentVariable('NODE_USE_ENV_PROXY', '1', 'Machine')
}

Write-Host "==> 6/6 Java (its own truststore, its own proxy settings)"
# Java reads neither the Windows store nor the variables above, so a JDK on the
# fleet is an unscreened path with a confusing TLS error at the end of it.
$keytool = Get-Command keytool -ErrorAction SilentlyContinue
if ($keytool) {
    $javaHome = Split-Path (Split-Path $keytool.Source)
    $ks = Join-Path $javaHome 'lib\security\cacerts'
    if (Test-Path $ks) {
        Do-Step "import the CA into $ks and set JAVA_TOOL_OPTIONS" {
            & $keytool.Source -delete -alias votal-swg -keystore $ks -storepass changeit 2>$null
            & $keytool.Source -importcert -noprompt -alias votal-swg -keystore $ks -storepass changeit -file $caDest
            $jhost, $jport = $proxyHostPort -split ':'
            [Environment]::SetEnvironmentVariable('JAVA_TOOL_OPTIONS',
                "-Dhttps.proxyHost=$jhost -Dhttps.proxyPort=$jport", 'Machine')
        }
        Write-Host "    $ks"
    }
} else {
    Write-Host "    no JDK on PATH, skipping"
}

Write-Host ""
Write-Host "Done. Verify on this device:"
Write-Host "  .\install-windows.ps1 -Verify"
Write-Host "  chrome://policy    ProxySettings and QuicAllowed applied"
Write-Host "  about:policies     Proxy and Certificates (Firefox)"
Write-Host ""
Write-Host "Reminder: this makes the gateway the DEFAULT path. It becomes the ONLY"
Write-Host "path when the network denies 443 (TCP and UDP) to AI destinations from"
Write-Host "everything except the proxy."
