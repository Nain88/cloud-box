$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
& (Join-Path $root '.venv\Scripts\python.exe') -m cbb.agent --config (Join-Path $root 'sensor-agent-data\agent.json') run
exit $LASTEXITCODE
