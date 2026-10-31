# Safe local enforcement test: packets to a documentation-only IP are blocked
# before transmission. The temporary rule is always removed on normal exit.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$name='CBB-selftest-'+[guid]::NewGuid().ToString('N')
$started=(Get-Date).ToUniversalTime().ToString('o')
try {
    New-NetFirewallRule -Name $name -DisplayName $name -Group 'Cyber Black Box self-test' -Direction Outbound -Action Block -RemoteAddress 192.0.2.123 -Protocol TCP -RemotePort 45101-45106 -Profile Any | Out-Null
    foreach ($port in 45101..45106) {
        $client=[Net.Sockets.TcpClient]::new()
        try { $result=$client.BeginConnect('192.0.2.123',$port,$null,$null); $null=$result.AsyncWaitHandle.WaitOne(500); if ($result.IsCompleted) {try {$client.EndConnect($result)}catch{}} }
        finally {$client.Close()}
    }
} finally {
    Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    @{kind='AUTHORIZED_LOCAL_FIREWALL_TEST';started_at=$started;finished_at=(Get-Date).ToUniversalTime().ToString('o');destination='192.0.2.123';ports='45101-45106';rule=$name;remaining_rules=@(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue).Count;note='Locally generated blocked traffic, not an external attack. Verify DROP logs and alert separately.'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'sensor-data\firewall-test.json') -Encoding UTF8
}
