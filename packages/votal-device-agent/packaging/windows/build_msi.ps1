# Build the Windows installer: PyInstaller, then WiX v5. Signing only when the
# release certificate is present (spec §10: "signing in release only").
#
#   ./build_msi.ps1                  (version from votal_device_agent/_version.py)
#   ./build_msi.ps1 -Version 0.1.1   (override)
#   Optional: -OllamaDir <dir from fetch_ollama.py windows>   (release)
#             $env:SIGN_CERT_THUMBPRINT                         (release: signs the exe and the msi)
param(
  [string]$Version = "",
  [string]$OllamaDir = ""
)

function Find-SignTool {
  $found = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($found) { return $found.Source }
  $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  $tool = Get-ChildItem -Path $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like "*x64*" } | Sort-Object FullName | Select-Object -Last 1
  if (-not $tool) { throw "signtool.exe not found (install the Windows SDK)" }
  return $tool.FullName
}

function Sign-File([string]$Path) {
  & (Find-SignTool) sign /sha1 $env:SIGN_CERT_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Path
  if ($LASTEXITCODE -ne 0) { throw "signing $Path failed" }
}
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

if ($OllamaDir) {
  # Already checked against ollama.lock (and CUDA stripped) by fetch_ollama.py.
  if (-not (Test-Path "$OllamaDir\ollama.exe")) { throw "OllamaDir has no ollama.exe" }
  Copy-Item -Recurse -Path $OllamaDir -Destination "$Dist\ollama"
} else {
  Write-Host "note: no -OllamaDir; this installer does not bundle Ollama (development build)"
}
if ($env:SIGN_CERT_THUMBPRINT) { Sign-File "$Dist\votal-device-agent.exe" }

$Out = "$PkgRoot\dist"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Msi = "$Out\votal-device-agent-$Version.msi"
Push-Location $Here
wix build votal-device-agent.wxs -arch x64 -d Version=$Version -bindpath dist=$Dist -o $Msi
Pop-Location

if ($env:SIGN_CERT_THUMBPRINT) { Sign-File $Msi }
Write-Host $Msi
