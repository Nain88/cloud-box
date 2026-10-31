$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$backup = Get-Content -Raw -LiteralPath (Join-Path $root 'sensor-data\firewall-before.json') | ConvertFrom-Json
foreach ($profile in $backup) {
    # Restore only logging settings. Never disable the firewall during rollback.
    Set-NetFirewallProfile -Profile $profile.Name -LogAllowed $profile.LogAllowed -LogBlocked $profile.LogBlocked -LogMaxSizeKilobytes $profile.LogMaxSizeKilobytes -LogFileName $profile.LogFileName
}
