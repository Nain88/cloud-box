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
    $sensorProcess=Start-Process -FilePath $pythonExe -WindowStyle Hidden -WorkingDirectory $projectRoot -ArgumentList @('-m','cbb.agent','--config',('"'+$sensorConfig+'"'),'run') -PassThru
}
try {
    & $pythonExe -m cbb.cli --data $Data serve --port $Port
    $serverExit=$LASTEXITCODE
} finally {
    if ($sensorProcess -and -not $sensorProcess.HasExited) { Stop-Process -Id $sensorProcess.Id -ErrorAction SilentlyContinue }
}
exit $serverExit
