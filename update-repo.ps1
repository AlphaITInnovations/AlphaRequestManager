# Gehe in das Verzeichnis, in dem das Skript liegt (= dein Repo)
Set-Location $PSScriptRoot

# Ziehe immer den neuesten Stand vom Hauptbranch
git pull origin main


# Dienstname (so wie er in Windows Services registriert ist)
$serviceName = "AlphaRequestManager"

# Prüfe, ob der Dienst existiert
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Dienst $serviceName wird neu gestartet..."
    Restart-Service -Name $serviceName -Force
    Write-Host "Dienst $serviceName wurde erfolgreich neu gestartet."
} else {
    Write-Host "Dienst $serviceName wurde nicht gefunden!"
}