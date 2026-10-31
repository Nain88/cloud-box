$ErrorActionPreference = 'Stop'
$folder = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $folder
$rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule)
Set-Acl -LiteralPath $folder -AclObject $acl
# Existing firewall files may have inheritance disabled; grant only read.
Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -like 'pfirewall.log*' } | ForEach-Object {
    $fileAcl = Get-Acl -LiteralPath $_.FullName
    $fileAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'Read', 'Allow'))
    Set-Acl -LiteralPath $_.FullName -AclObject $fileAcl
}
