param([string]$Distribution='Ubuntu',[string]$Interface='eth0',[ValidateRange(30,86400)][int]$Seconds=900,[ValidateRange(16,4096)][int]$MaxMiB=256)
$ErrorActionPreference='Stop'
$projectRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$linuxRoot=(& wsl.exe -d $Distribution -- wslpath -a -u $projectRoot | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {throw 'Ubuntu unavailable. Complete setup-suricata-wsl.ps1 first.'}
Write-Host "Capturing only authorized traffic visible on WSL $Interface for at most $Seconds seconds. Ctrl+C stops this session."
& wsl.exe -d $Distribution -u root -- python3 "$linuxRoot/deploy/suricata/run_sensor.py" --interface $Interface --seconds $Seconds --max-mib $MaxMiB --config "$linuxRoot/sensor-data/suricata.yaml" --rules "$linuxRoot/rules/cbb-demo.rules" --output "$linuxRoot/sensor-data"
if ($LASTEXITCODE -ne 0) {throw 'Suricata did not finish successfully. Inspect sensor-data/console.log and sensor-status.json.'}
