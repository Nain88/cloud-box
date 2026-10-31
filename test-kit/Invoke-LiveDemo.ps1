param(
    [ValidateSet('Prepare','Modify','Marker','OfflineChange','Status')]
    [string]$Step = 'Status',
    [switch]$NewRun
)
$ErrorActionPreference = 'Stop'
# Only this demonstration's own files are created or changed.
$demoRoot = Join-Path $PSScriptRoot 'live-lab'
$watchedRoot = Join-Path $demoRoot 'watched'
$currentPath = Join-Path $demoRoot 'current-run.json'
New-Item -ItemType Directory -Force -Path $watchedRoot | Out-Null
if ($NewRun -and $Step -ne 'Prepare') { throw 'Use -NewRun only with -Step Prepare.' }
if ($Step -eq 'Prepare' -and ($NewRun -or -not (Test-Path -LiteralPath $currentPath))) {
    $runId = 'run-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6)
    @{run_id=$runId; started_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $currentPath -Encoding UTF8
}
if (-not (Test-Path -LiteralPath $currentPath)) { throw 'Run -Step Prepare first.' }
$current = Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
if ($current.run_id -notmatch '^run-[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$') { throw 'Invalid demo run identifier.' }
$runDirectory = Join-Path $watchedRoot $current.run_id
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null
$filePath = Join-Path $runDirectory 'research-notes.txt'
$expectedRoot = [IO.Path]::GetFullPath($watchedRoot).TrimEnd('\') + '\'
if (-not [IO.Path]::GetFullPath($filePath).StartsWith($expectedRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Demo file is outside its allowed folder.' }
$before = if (Test-Path -LiteralPath $filePath) { (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant() } else { '' }
$actionUtc = [DateTime]::UtcNow.ToString('o')
$changed = $false
switch ($Step) {
    'Prepare' {
        if (-not (Test-Path -LiteralPath $filePath)) {
            "Harmless Cyber Black Box live laboratory file.`r`nRun: $($current.run_id)`r`nBaseline created UTC: $actionUtc`r`n" | Set-Content -LiteralPath $filePath -Encoding UTF8
            $changed = $true
        }
    }
    'Modify' {
        if (-not (Test-Path -LiteralPath $filePath)) { throw 'Baseline file is missing; start a new run.' }
        "A real authorized edit was made at UTC $actionUtc" | Add-Content -LiteralPath $filePath -Encoding UTF8
        $changed = $true
    }
    'Marker' {
        if (-not (Test-Path -LiteralPath $filePath)) { throw 'Baseline file is missing.' }
        "CBB_TEST_MARKER - harmless approved rule test at UTC $actionUtc" | Add-Content -LiteralPath $filePath -Encoding UTF8
        $changed = $true
    }
    'OfflineChange' {
        if (-not (Test-Path -LiteralPath $filePath)) { throw 'Baseline file is missing.' }
        "Controlled server-outage experiment: actual local edit UTC $actionUtc" | Add-Content -LiteralPath $filePath -Encoding UTF8
        $changed = $true
    }
}
if (-not (Test-Path -LiteralPath $filePath)) { throw 'Demo file is missing.' }
$after = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
$facts = [ordered]@{
    run_id=$current.run_id; action=$Step; action_utc=$actionUtc; changed=$changed
    file=$filePath; previous_sha256=$before; sha256=$after
    bytes=(Get-Item -LiteralPath $filePath).Length
    dashboard_seen_utc=''; evidence_id=''; result='NOT_YET_CHECKED'
}
if ($changed) {
    $facts | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $demoRoot 'operator-observations.jsonl') -Encoding UTF8
}
Write-Host "`nLIVE DEMO: $Step" -ForegroundColor Cyan
Write-Host "Run: $($current.run_id)"
Write-Host "Watched root: $watchedRoot"
Write-Host "File: $filePath"
Write-Host "Action UTC: $actionUtc"
Write-Host "Previous SHA256: $before"
Write-Host "Current SHA256:  $after"
Write-Host "Changed: $changed"
Write-Host 'This output records your actual file action; it is not a dashboard verification result.'
Write-Host 'Wait for collector delivery, then compare the SHA256 with ORIGINAL BYTES in the FIM evidence.'
