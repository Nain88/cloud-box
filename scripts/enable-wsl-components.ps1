$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$output=Join-Path $root 'sensor-data'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$result=@{checked_at=(Get-Date).ToUniversalTime().ToString('o');state='CHECKING';steps=@()}
foreach ($feature in @('Microsoft-Windows-Subsystem-Linux','VirtualMachinePlatform')) {
    $log=Join-Path $output ($feature+'.log')
    & dism.exe /Online /Enable-Feature "/FeatureName:$feature" /All /NoRestart 2>&1 | Out-File -LiteralPath $log -Encoding UTF8
    $code=$LASTEXITCODE
    $result.steps+=@{feature=$feature;exit_code=$code;log=$log}
    if ($code -notin @(0,3010)) {
        $result.state='WINDOWS_REPAIR_REQUIRED'
        $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'wsl-setup.json') -Encoding UTF8
        exit 1
    }
}
$result.state='RESTART_REQUIRED'
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'wsl-setup.json') -Encoding UTF8
