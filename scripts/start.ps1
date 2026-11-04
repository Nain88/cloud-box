param([switch]$Install, [string]$Data = 'data', [int]$Port = 8765)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$pythonExe = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) {
    if (Get-Command py -ErrorAction SilentlyContinue) { & py -3.12 -m venv .venv }
    elseif (Get-Command python -ErrorAction SilentlyContinue) { & python -m venv .venv }
    else { throw 'Install Python 3.12 or newer, then run this launcher again.' }
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
    $Install = $true
}
if ($Install) {
    & $pythonExe -m pip install -r requirements.lock
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}
if (-not (Test-Path -LiteralPath 'web\dist\index.html')) {
    throw 'The interface has not been built. Run pnpm --dir web install --frozen-lockfile, then pnpm --dir web build.'
}
$env:CBB_PUBLIC_URL = "http://127.0.0.1:$Port"
# Double-clicking a second time should reopen the existing dashboard. Check
# the saved deployment identity before assuming the listener is our server.
$localDb = Join-Path $Data 'cbb.sqlite3'
if ((Test-Path -LiteralPath $localDb) -and -not $env:CBB_DATABASE_URL) {
    $running = $null
    try { $running = Invoke-RestMethod "$env:CBB_PUBLIC_URL/api/v1/status" -TimeoutSec 4 } catch { }
    if ($running -and $running.deployment_id) {
        $readIdentity = @'
import json, sqlite3, sys
from pathlib import Path
db = sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + '?mode=ro', uri=True)
entry = db.execute('SELECT value FROM configuration WHERE id=?', ('deployment',)).fetchone()
print(json.loads(entry[0])['id'] if entry else '')
'@
        $identity = $readIdentity | & $pythonExe - $localDb
        if ($LASTEXITCODE -eq 0 -and $running.deployment_id -eq $identity) {
            Write-Host "Cyber Black Box is already running. Opening $env:CBB_PUBLIC_URL"
            Start-Process "$env:CBB_PUBLIC_URL/#overview"
            exit 0
        }
        throw "Port $Port is serving a different deployment. Check the data directory and port."
    }
}
& $pythonExe -m cbb.cli --data $Data init
if ($LASTEXITCODE -ne 0) { throw 'Initialization failed.' }
$bootstrapPath = Join-Path $Data 'keys\bootstrap.token'
if (Test-Path -LiteralPath $bootstrapPath) {
    Write-Host 'First-time setup token (paste into the setup screen):' -ForegroundColor Cyan
    Get-Content -LiteralPath $bootstrapPath
}
Write-Host "Open http://127.0.0.1:$Port . Keep this window open; Ctrl+C stops the server."
$sensorProcess=$null
# Only the local default deployment has this explicitly provisioned collector.
if ($Data -eq 'data' -and $Port -eq 8765 -and (Test-Path -LiteralPath 'sensor-agent-data\agent.json')) {
    $sensorConfig=Join-Path $projectRoot 'sensor-agent-data\agent.json'
    $sensorStop=Join-Path (Split-Path $sensorConfig) ('stop-'+[guid]::NewGuid().ToString('N'))
    $sensorProcess=Start-Process -FilePath $pythonExe -WindowStyle Hidden -WorkingDirectory $projectRoot -ArgumentList @('-m','cbb.agent','--config',('"'+$sensorConfig+'"'),'--stop-file',('"'+$sensorStop+'"'),'run') -PassThru
}
try {
    $nativeConfig=Join-Path $projectRoot 'sensor-data\native-capture.json'
    if ($sensorProcess -and (Test-Path -LiteralPath $nativeConfig) -and -not (Test-Path -LiteralPath 'sensor-data\sensor.lock')) {
        $adapter=(Get-Content -Raw -LiteralPath $nativeConfig | ConvertFrom-Json).interface
        if ($adapter -match '^[A-Za-z0-9 ._-]{1,100}$') {
            $captureScript=Join-Path $PSScriptRoot 'start-suricata-windows.ps1'
            Start-Process powershell.exe -WindowStyle Hidden -WorkingDirectory $projectRoot -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$captureScript+'"'),'-InterfaceAlias',('"'+$adapter+'"'),'-Seconds','900')
            Write-Host "Starting a bounded 15-minute Suricata capture on $adapter. Check Live monitor for health."
        }
    }
    & $pythonExe -m cbb.cli --data $Data serve --port $Port
    $serverExit=$LASTEXITCODE
} finally {
    if ($sensorProcess -and -not $sensorProcess.HasExited) {
        Set-Content -LiteralPath $sensorStop -Value 'stop'
        if ($sensorProcess.WaitForExit(30000)) {Remove-Item -LiteralPath $sensorStop}
    }
}
exit $serverExit
