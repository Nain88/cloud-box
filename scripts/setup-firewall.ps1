# Run from an Administrator PowerShell. Does not change allow/block rules.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root 'sensor-data'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$resultFile = Join-Path $output 'firewall-setup.json'
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator PowerShell is required to enable firewall logging.' }
    $backup = Join-Path $output 'firewall-before.json'
    if (-not (Test-Path -LiteralPath $backup)) {
        Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name,Enabled,LogAllowed,LogBlocked,LogMaxSizeKilobytes,LogFileName | ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding UTF8
    }
    # Keep the OS-protected default log path. The collector needs read permission.
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,LogAllowed,LogBlocked,LogMaxSizeKilobytes,LogFileName)
    if (@($profiles | Where-Object { $_.Enabled -ne 1 -or $_.LogAllowed -ne 1 -or $_.LogBlocked -ne 1 }).Count) { throw 'Effective firewall policy did not enable logging for every profile; check Group Policy.' }
    @{state='CONFIGURED';checked_at=(Get-Date).ToUniversalTime().ToString('o');profiles=$profiles;rules_changed=$false} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultFile -Encoding UTF8
} catch {
    @{state='FAILED';checked_at=(Get-Date).ToUniversalTime().ToString('o');error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $resultFile -Encoding UTF8
    throw
}
