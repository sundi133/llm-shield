# Build the Windows installer: PyInstaller, then WiX v5. Signing only when the
# release certificate is present (spec §10: "signing in release only").
#
#   ./build_msi.ps1                  (version from votal_device_agent/_version.py)
#   ./build_msi.ps1 -Version 0.1.1   (override)
#   Optional: -OllamaZip ollama-windows-amd64.zip -OllamaSha256 <hex>   (release)
#             $env:SIGN_CERT_THUMBPRINT                                  (release)
param(
  [string]$Version = "",
  [string]$OllamaZip = "",
  [string]$OllamaSha256 = ""
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$PkgRoot = Resolve-Path "$Here\..\.."
$Repo = Resolve-Path "$PkgRoot\..\.."
if (-not $Version) {
  $m = Select-String -Path "$PkgRoot\votal_device_agent\_version.py" -Pattern '^__version__ = "(.*)"$'
  $Version = $m.Matches[0].Groups[1].Value
}
$Work = Join-Path $env:TEMP ("votal-msi-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Work | Out-Null

python -m PyInstaller --noconfirm --clean --onedir --name votal-device-agent `
  --distpath "$Work\dist" --workpath "$Work\build" --specpath "$Work" `
  --paths "$PkgRoot" --paths "$Repo" --paths "$Repo\packages\shield-mavlink" `
  --collect-submodules votal_device_agent --collect-submodules icap `
  --collect-submodules shield_mavlink --collect-all mitmproxy `
  --hidden-import win32timezone "$Here\..\entry.py"
$Dist = "$Work\dist\votal-device-agent"

if ($OllamaZip) {
  $sha = (Get-FileHash -Algorithm SHA256 $OllamaZip).Hash.ToLower()
  if ($sha -ne $OllamaSha256.ToLower()) { throw "Ollama archive checksum mismatch: $sha" }
  Expand-Archive -Path $OllamaZip -DestinationPath "$Dist\ollama"
} else {
  Write-Host "note: no -OllamaZip; this installer does not bundle Ollama (development build)"
}

$Out = "$PkgRoot\dist"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Msi = "$Out\votal-device-agent-$Version.msi"
Push-Location $Here
wix build votal-device-agent.wxs -arch x64 -d Version=$Version -bindpath dist=$Dist -o $Msi
Pop-Location

if ($env:SIGN_CERT_THUMBPRINT) {
  signtool sign /sha1 $env:SIGN_CERT_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Msi
}
Write-Host $Msi
