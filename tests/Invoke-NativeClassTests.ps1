[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Host 'SKIP native AD assembly checks: Windows is required.'
    exit 0
}

# Load the shipped CLR types without registering the AD cmdlets/provider. The
# constructors exercised below do not query a domain or create an AD drive.
$assemblyPath = Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
[Reflection.Assembly]::LoadFrom($assemblyPath) > $null
$module = Import-Module (Join-Path $RepositoryRoot 'bin/ADEnvironment.psm1') -Force -PassThru
Write-Host 'PASS full module imports against the shipped Active Directory assembly'

& $module ([scriptblock]::Create(@'
$ErrorActionPreference = 'Stop'
foreach ($name in @('DomainData', 'ObjectData', 'UserData', 'GroupData', 'ComputerData', 'GroupPolicyData')) {
    $model = New-Object -TypeName $name
    if ($model -isnot [Data]) { throw "Invalid Data inheritance: $name" }
}
Write-Host 'PASS all six Data models construct with their inherited contracts'

foreach ($name in @('UserTable', 'GroupTable', 'ComputerTable', 'GroupPolicyTable')) {
    $table = (New-Object -TypeName $name)::SetDefault()
    if ($table -isnot [Table] -or [string]::IsNullOrEmpty($table.Properties.Key)) {
        throw "Invalid table factory: $name"
    }
}
Write-Host 'PASS all four report-table factories initialize metadata'

foreach ($name in @('UserObject', 'GroupObject', 'ComputerObject', 'GroupPolicyObject', 'PasswordPolicyObject')) {
    $record = (New-Object -TypeName $name)::SetDefault()
    if ($record -isnot [System.Collections.Specialized.OrderedDictionary]) {
        throw "Invalid record inheritance: $name"
    }
}
Write-Host 'PASS all five record factories construct ordered records'

$nativeUser = [Microsoft.ActiveDirectory.Management.ADUser]::new()
$nativeUser.SamAccountName = 'fixture-user'
$nativeUser.UserPrincipalName = 'fixture-user@example.invalid'
$nativeUser.Enabled = $true
$normalized = [Format]::ValueCollection($nativeUser, @('nTSecurityDescriptor'))
if ($normalized['samaccountname'] -ne 'fixture-user' -or $normalized['enabled'] -ne $true) {
    throw 'Native ADUser attributes failed normalization'
}
Write-Host 'PASS populated native ADUser attributes normalize without querying a domain'

try {
    $environment = [ADEnvironment]::Initialize('fixture.invalid', [System.Collections.ArrayList]@('User', 'Group', 'Computer', 'GroupPolicy'))
    if ($environment -isnot [ADTarget] -or $environment.Finding -isnot [Finding]) {
        throw 'Invalid environment or findings inheritance'
    }
    if ([ADTarget]::Diagnostic['StopWatch'] -isnot [System.Diagnostics.Stopwatch]) {
        throw 'Missing diagnostic stopwatch'
    }
    Write-Host 'PASS environment graph initializes without querying Active Directory'
}
finally {
    [ADEnvironment]::Close()
}
'@))
