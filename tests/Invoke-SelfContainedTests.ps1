[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){Write-Host 'SKIP Windows package bootstrap';exit 0}
if(Get-Module -ListAvailable -Name ActiveDirectory,GroupPolicy){throw 'RSAT modules are installed on this test runner; a clean runner is required'}
$module=Import-Module (Join-Path $RepositoryRoot 'ADEnvironment.psd1') -Force -PassThru -WarningAction SilentlyContinue
$expected=[IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$paths=& $module {
    foreach($name in @('Get-ADDomain','Get-ADObject','Get-ADUser','Get-ADGroup','Get-ADComputer','Set-ADObject','Disable-ADAccount','Remove-ADObject')){
        $command=Get-Command $name -CommandType Cmdlet -ErrorAction Stop
        $command.Module.Path
    }
}
foreach($path in $paths){if([IO.Path]::GetFullPath($path) -ne $expected){throw "External AD dependency: $path"}}
if(-not (Get-PSProvider ActiveDirectory -ErrorAction Stop)){throw 'Bundled AD provider was not registered'}
if(Get-Module -Name GroupPolicy){throw 'Unexpected external GroupPolicy module'}
Write-Host 'PASS manifest registers bundled AD commands and provider without installed RSAT'
