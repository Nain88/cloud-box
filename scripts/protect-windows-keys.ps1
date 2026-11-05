param([string]$Data = 'data')
$ErrorActionPreference = 'Stop'
$keys = Join-Path ([IO.Path]::GetFullPath($Data)) 'keys'
[void][IO.Directory]::CreateDirectory($keys)
$operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')

function Set-KeyAccess([string]$Path, [bool]$Directory) {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $inheritance = if ($Directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
    foreach ($sid in @($operatorSid, $systemSid)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', $inheritance, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Set-KeyAccess $keys $true
foreach ($name in @('signing.pem', 'bootstrap.token')) {
    $path = Join-Path $keys $name
    if (Test-Path -LiteralPath $path -PathType Leaf) { Set-KeyAccess $path $false }
}
