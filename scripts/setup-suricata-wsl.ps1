param([string]$Distribution='Ubuntu')
$ErrorActionPreference='Stop'
$projectRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$linuxRoot=(& wsl.exe -d $Distribution -- wslpath -a -u $projectRoot | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxRoot.StartsWith('/mnt/')) { throw 'Ubuntu is not ready. Restart Windows, run wsl --install -d Ubuntu, finish its first launch, then retry this script.' }
& wsl.exe -d $Distribution -u root -- bash "$linuxRoot/deploy/suricata/setup.sh" $linuxRoot
if ($LASTEXITCODE -ne 0) {throw 'Suricata setup failed. Read the package/configuration errors above.'}
Write-Host 'Suricata configured. Start a bounded session with scripts/start-suricata-wsl.ps1.'
