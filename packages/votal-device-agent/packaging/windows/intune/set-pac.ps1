# Intune platform script (run as SYSTEM): send only AI services' traffic to the
# Votal device agent, machine-wide. Everything else keeps its current route.
$ErrorActionPreference = "Stop"
$Policy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
New-Item -Path $Policy -Force | Out-Null
# One proxy configuration for the machine, not per user.
Set-ItemProperty -Path $Policy -Name "ProxySettingsPerUser" -Type DWord -Value 0
$Machine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $Machine -Name "AutoConfigURL" -Value "http://127.0.0.1:47823/proxy.pac"
Write-Output "PAC set to http://127.0.0.1:47823/proxy.pac"
