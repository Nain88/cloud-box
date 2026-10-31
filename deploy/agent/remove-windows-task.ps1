param([string]$TaskName = 'CyberBlackBoxCollector')
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
Stop-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
Unregister-ScheduledTask -InputObject $task -Confirm:$true
Write-Output 'Task removed. Collector credentials, queue, logs and artifacts were preserved.'
