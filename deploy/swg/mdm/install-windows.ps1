<#
Configure a managed Windows device to send AI traffic through the inspection
proxy.

Push with Intune (Devices > Scripts, "Run this script using the logged on
credentials" = No, so it runs as SYSTEM) or as a GPO startup script.

  .\install-windows.ps1 -PacUrl "http://swg.corp.example:8081/proxy.pac" `
                        -CaCertPath "\\share\shield\ca-cert.cer"

Idempotent: safe to run on every check-in.

Group Policy is the better vehicle for the Chrome and Edge settings, because
ADMX-backed policy is what users cannot override. Use this when you want one
artefact that also covers Firefox's own trust store and the CA bundles that
Python and Node ship with.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PacUrl,
    [Parameter(Mandatory)][string]$CaCertPath
)

$ErrorActionPreference = 'Stop'
$caDest = "$env:ProgramData\Shield\ca-cert.cer"

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "must run elevated (SYSTEM or Administrator)"
}

Write-Host "==> 1/5 trusting the inspection CA"
New-Item -ItemType Directory -Force -Path (Split-Path $caDest) | Out-Null
Copy-Item $CaCertPath $caDest -Force
Import-Certificate -FilePath $caDest -CertStoreLocation Cert:\LocalMachine\Root | Out-Null

Write-Host "==> 2/5 system proxy (WinHTTP, for services and native apps)"
# Covers what does not read the per-user browser settings.
netsh winhttp set advproxy settings source=ie | Out-Null

Write-Host "==> 3/5 Chrome and Edge policy"
# QuicAllowed=0 is not optional: Chrome prefers HTTP/3, which ignores an HTTP
# proxy entirely, and the bypass is silent -- no error, no traffic, nothing
# inspected.
$proxyJson = (@{ ProxyMode = 'pac_script'; ProxyPacUrl = $PacUrl } | ConvertTo-Json -Compress)
foreach ($vendor in @('Google\Chrome', 'Microsoft\Edge')) {
    $key = "HKLM:\SOFTWARE\Policies\$vendor"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'ProxySettings' -Value $proxyJson `
        -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $key -Name 'QuicAllowed' -Value 0 `
        -PropertyType DWord -Force | Out-Null
}

Write-Host "==> 4/5 Firefox (shares neither the trust store nor the proxy)"
$ff = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
New-Item -Path "$ff\Certificates" -Force | Out-Null
New-ItemProperty -Path "$ff\Certificates" -Name 'ImportEnterpriseRoots' -Value 1 `
    -PropertyType DWord -Force | Out-Null
New-Item -Path "$ff\Proxy" -Force | Out-Null
New-ItemProperty -Path "$ff\Proxy" -Name 'Mode' -Value 'autoConfig' `
    -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$ff\Proxy" -Name 'AutoConfigURL' -Value $PacUrl `
    -PropertyType String -Force | Out-Null
New-ItemProperty -Path "$ff\Proxy" -Name 'Locked' -Value 1 `
    -PropertyType DWord -Force | Out-Null

Write-Host "==> 5/5 CA bundles for Python, Node and curl"
# These ship their own trust stores and ignore the Windows certificate store.
# Miss this and every script on the fleet starts failing TLS, which is the
# change people notice first.
foreach ($var in 'REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS') {
    [Environment]::SetEnvironmentVariable($var, $caDest, 'Machine')
}

Write-Host ""
Write-Host "Done. Verify on this device:"
Write-Host "  chrome://policy    ProxySettings and QuicAllowed applied"
Write-Host "  about:policies     Proxy and Certificates (Firefox)"
