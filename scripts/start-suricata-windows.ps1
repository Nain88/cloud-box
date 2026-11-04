param([string]$InterfaceAlias,[ValidateRange(30,86400)][int]$Seconds=900,[ValidateRange(16,4096)][int]$MaxMiB=256)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$adapters=@(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
if ($InterfaceAlias) {$adapters=@($adapters | Where-Object Name -eq $InterfaceAlias)}
if ($adapters.Count -ne 1) {throw 'Specify one active physical adapter using -InterfaceAlias, for example Wi-Fi. List available adapters with Get-NetAdapter.'}
$adapter=$adapters[0]
$device='\Device\NPF_'+([guid]$adapter.InterfaceGuid).ToString('B').ToUpperInvariant()
& (Join-Path $root '.venv\Scripts\python.exe') (Join-Path $root 'deploy\suricata\windows_sensor.py') --device $device --label $adapter.Name --seconds $Seconds --max-mib $MaxMiB
exit $LASTEXITCODE
