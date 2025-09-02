Set-Location $PSScriptRoot

# Erzwinge Aktualisierung vom Remote
git fetch origin main
git reset --hard origin/main
git clean -fd

# Dienstname anpassen falls nötig
$serviceName = "AlphaRequestManager"

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Dienst $serviceName wird neu gestartet..."
    Restart-Service -Name $serviceName -Force
    Write-Host "Dienst $serviceName wurde erfolgreich neu gestartet."
} else {
    Write-Host "Dienst $serviceName wurde nicht gefunden!"
}
