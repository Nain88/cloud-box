param(
    [Parameter(Mandatory=$true)][string]$ProjectDirectory,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$TaskName = 'CyberBlackBoxCollector',
    [switch]$RunElevated,
    [switch]$StartNow
)
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path -LiteralPath $ProjectDirectory).Path
$configuration = (Resolve-Path -LiteralPath $ConfigPath).Path
$python = Join-Path $project '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'Create the project Python environment before installing the collector task.' }
$policy = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
if (-not $policy.collector_id -or -not $policy.token -or -not $policy.server_signing_key) { throw 'Enroll the collector before installing the task.' }
if ($policy.collector_id -like 'REPLACE*') { throw 'An example configuration cannot be installed as a real collector.' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principalCheck = [System.Security.Principal.WindowsPrincipal]::new($identity)
if ($RunElevated -and -not $principalCheck.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an administrator PowerShell window only if you intentionally require elevated collection.'
}
$level = if ($RunElevated) { 'Highest' } else { 'Limited' }
$action = New-ScheduledTaskAction -Execute $python -Argument "-m cbb.agent --config `"$configuration`" run" -WorkingDirectory $project
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel $level
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw "Task '$TaskName' already exists. Inspect or remove it explicitly before reinstalling."
}
Register-ScheduledTask -TaskName $TaskName -Description 'Cyber Black Box authorized collector; starts only when this user signs in.' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
if ($StartNow) { Start-ScheduledTask -TaskName $TaskName }
Write-Output "Installed '$TaskName' for $($identity.Name), run level $level. Local rotating logs are in the configured data directory."
Write-Output 'This interactive task stops when the user signs out. It is not an always-on machine service.'
