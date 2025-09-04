Set-Location $PSScriptRoot
$serviceName = "AlphaRequestManager"
# Erzwinge Aktualisierung vom Remote

Write-Host "Dienst $serviceName wird gestoppt..."
Stop-Service -Name $serviceName -Force

git fetch origin main
git reset --hard origin/main
git clean -fd

# Dienstname anpassen falls nötig

Write-Host "Dienst $serviceName wird gestartet..."
Start-Service -Name $serviceName