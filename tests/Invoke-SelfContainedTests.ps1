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
$localPath=& {
    Import-Module -Name $expected -Scope Local -ErrorAction Stop
    $command=Get-Command Get-ADComputer -CommandType Cmdlet -ListImported -ErrorAction Stop
    foreach($name in @('Identity','Properties','Server','Credential')){if(-not $command.Parameters.ContainsKey($name)){throw ('Bundled computer command lacks '+$name)}}
    $command.Module.Path
}
if([IO.Path]::GetFullPath($localPath) -ne $expected){throw 'Scoped computer command came from an external dependency'}
if(Get-Command Get-ADComputer -ListImported -ErrorAction SilentlyContinue){throw 'Local binary import leaked a private AD command'}
Write-Host 'PASS bundled AD computer metadata is locally scoped without invoking a directory query'
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
