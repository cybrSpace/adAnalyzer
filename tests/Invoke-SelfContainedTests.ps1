[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){Write-Host 'SKIP Windows package bootstrap';exit 0}
if(Get-Module -ListAvailable -Name ActiveDirectory,GroupPolicy){throw 'RSAT modules are installed on this test runner; a clean runner is required'}
$module=Import-Module (Join-Path $RepositoryRoot 'ADEnvironment.psd1') -Force -PassThru -WarningAction SilentlyContinue
$expected=[IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$paths=& $module {
    foreach($name in @('Get-ADDomain','Get-ADRootDSE','Get-ADObject','Get-ADUser','Get-ADGroup','Get-ADComputer','Get-ADTrust','Get-ADDomainController','Get-ADServiceAccount','Get-ADDefaultDomainPasswordPolicy','Get-ADFineGrainedPasswordPolicy','Get-ADUserResultantPasswordPolicy','Set-ADObject','Disable-ADAccount','Enable-ADAccount','Remove-ADObject')){
        $command=Get-Command $name -CommandType Cmdlet -ErrorAction Stop
        $command.Module.Path
    }
}
foreach($path in $paths){if([IO.Path]::GetFullPath($path) -ne $expected){throw "External AD dependency: $path"}}
if(-not (Get-PSProvider ActiveDirectory -ErrorAction Stop)){throw 'Bundled AD provider was not registered'}
$driveCommand=Get-Command New-PSDrive -ArgumentList @('ADAnalyzerMetadataProbe','ActiveDirectory','DC=example,DC=invalid') -ErrorAction Stop
foreach($parameter in @('Server','Credential','Root','Scope')){
    if(-not $driveCommand.Parameters.ContainsKey($parameter)){throw "Bundled AD drive is missing parameter: $parameter"}
}
Write-Host 'PASS bundled AD provider exposes drive server credential root and scope parameters without a live bind'
if(Get-Command Get-ADComputer -ListImported -ErrorAction SilentlyContinue){throw 'Private AD computer command was visible before the local import probe'}
$localPaths=@(& {
    Import-Module -Name $expected -Scope Local -ErrorAction Stop
    foreach($name in @('Get-ADComputer','Get-ADGroup','Get-ADObject')){
        $command=Get-Command $name -CommandType Cmdlet -ListImported -ErrorAction Stop
        foreach($parameter in @('Identity','Properties','Server','Credential')){if(-not $command.Parameters.ContainsKey($parameter)){throw ('Bundled command lacks '+$parameter)}}
        if($name -eq 'Get-ADGroup' -and -not $command.Parameters.ContainsKey('LDAPFilter')){throw 'Bundled group command lacks literal LDAP filtering'}
        $command.Module.Path
    }
})
foreach($localPath in $localPaths){if([IO.Path]::GetFullPath($localPath) -ne $expected){throw 'Scoped AD command came from an external dependency'}}
foreach($name in @('Get-ADComputer','Get-ADGroup','Get-ADObject')){if(Get-Command $name -ListImported -ErrorAction SilentlyContinue){throw 'Local binary import leaked a private AD command'}}
Write-Host 'PASS bundled AD computer metadata is locally scoped without invoking a directory query'
Write-Host 'PASS bundled group and object lookup metadata is locally scoped without a directory query'
Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
$contextType=[System.DirectoryServices.AccountManagement.PrincipalContext]
$machineType=[System.DirectoryServices.AccountManagement.ContextType]
$identityType=[System.DirectoryServices.AccountManagement.IdentityType]
$groupType=[System.DirectoryServices.AccountManagement.GroupPrincipal]
foreach($signature in @(@($machineType,[string]),@($machineType,[string],[string],[string]))){if($null -eq $contextType.GetConstructor([type[]]$signature)){throw 'Missing host principal context constructor'}}
if($null -eq $groupType.GetMethod('FindByIdentity',[type[]]@($contextType,$identityType,[string]))){throw 'Missing host group lookup signature'}
foreach($name in @('Name','SamAccountName','Sid','Description')){if($null -eq $groupType.GetProperty($name)){throw ('Missing principal metadata getter '+$name)}}
if(-not [IDisposable].IsAssignableFrom($contextType) -or -not [IDisposable].IsAssignableFrom($groupType)){throw 'Principal ownership contract is not disposable'}
if(-not [Enum]::IsDefined($machineType,'Machine') -or -not [Enum]::IsDefined($identityType,'SamAccountName')){throw 'Missing machine/SAM lookup enums'}
Write-Host 'PASS host principal framework metadata supports detached snapshots without creating an authentication context'
$principalType=[System.DirectoryServices.AccountManagement.Principal]
$resultType=[System.DirectoryServices.AccountManagement.PrincipalSearchResult[System.DirectoryServices.AccountManagement.Principal]]
$enumeratorType=[Collections.Generic.IEnumerator[System.DirectoryServices.AccountManagement.Principal]]
$members=$groupType.GetMethod('GetMembers',[type[]]@([bool]))
if($null -eq $members -or $members.IsStatic -or $members.ReturnType -ne $resultType){throw 'Missing direct group-member enumeration contract'}
$enumerator=$resultType.GetMethod('GetEnumerator',[type]::EmptyTypes)
if($null -eq $enumerator -or $enumerator.IsStatic -or $enumerator.ReturnType -ne $enumeratorType){throw 'Missing principal enumerator contract'}
if(-not [IDisposable].IsAssignableFrom($resultType) -or -not [IDisposable].IsAssignableFrom($enumeratorType) -or -not [Collections.IEnumerator].IsAssignableFrom($enumeratorType)){throw 'Principal enumeration ownership contract is unavailable'}
foreach($contract in @(@{Owner=$principalType;Name='Context';Value=$contextType},@{Owner=$principalType;Name='SamAccountName';Value=[string]},@{Owner=$contextType;Name='Name';Value=[string]})){
    $property=$contract.Owner.GetProperty($contract.Name)
    if($null -eq $property -or $property.PropertyType -ne $contract.Value -or $null -eq $property.GetGetMethod() -or $property.GetGetMethod().IsStatic){throw ('Missing readable principal property '+$contract.Name)}
}
if(-not [Enum]::IsDefined($identityType,'Sid')){throw 'Missing SID lookup enum'}
Write-Host 'PASS principal member enumeration metadata without authentication'
if(Get-Module -Name GroupPolicy){throw 'Unexpected external GroupPolicy module'}
if($module.ExportedCmdlets.Count -or $module.ExportedVariables.Count){throw 'Internal AD commands or script variables leaked from the public package interface'}
foreach($name in @('Get-ADAnalyzerGpo','Get-ADAnalyzerGpoReport','Read-ADAnalyzerGpo')){
    if(-not $module.ExportedFunctions.ContainsKey($name)){throw "Missing package GPO command: $name"}
}
$reader=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'bin/ADGpo.ps1') -Raw
if($reader -match '(?i)\bGet-GPO(?:Report)?\b|\bNew-Object\s+-ComObject\b|Import-Module\s+GroupPolicy'){throw 'GPO reader depends on GPMC/GroupPolicy'}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('ad-bootstrap-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -Path $temporary -ItemType Directory
try {
    $report=Read-ADAnalyzerGpo -Path $temporary
    if($report.Files.Count -ne 0){throw 'Unexpected empty-policy output'}
} finally {Remove-Item -LiteralPath $temporary -Recurse -Force}
Write-Host 'PASS manifest registers bundled AD commands and provider without installed RSAT'
Write-Host 'PASS package exports its own offline GPO reader without GPMC'
