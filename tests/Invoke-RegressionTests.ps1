using namespace System.Management.Automation.Language

[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$script:Passed = 0
$script:Failed = 0

function Assert-Equal($Expected, $Actual) {
    if ($Expected -ne $Actual) {
        throw "Expected [$Expected], received [$Actual]"
    }
}

function Invoke-Test([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name : $_"
    }
}

function Get-SourceAst([string]$Path) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) {
        throw ($parseErrors.Message -join '; ')
    }
    return $ast
}

# Supply only the type names needed by the parser. Never load the AD assemblies
# or import/execute the analyzer module in this domain-independent test suite.
Add-Type -TypeDefinition @'
namespace Microsoft.ActiveDirectory.Management {
    public class ADPropertyValueCollection {}
    public class ADPartition {}
    public class ADEntity {}
}
namespace Microsoft.ActiveDirectory.Management.Provider {
    public class ADDriveInfo {}
}
'@

$moduleAst = Get-SourceAst (Join-Path $RepositoryRoot 'bin/ADEnvironment.psm1')
$helperAst = Get-SourceAst (Join-Path $RepositoryRoot 'bin/Start-ADAnalyzer.ps1')
$setFunction = $moduleAst.Find({
    param($node)
    $node -is [FunctionDefinitionAst] -and $node.Name -eq 'Set-ADEnvironment'
}, $false).Extent.Text
$processClass = $moduleAst.Find({
    param($node)
    $node -is [TypeDefinitionAst] -and $node.Name -eq 'Process'
}, $false).Extent.Text

$setProbeSource = @'
using namespace System.Collections
using namespace System.Management.Automation
class ADEnvironment { static [void] Close() {} }
function Get-ADEnvironment {
    param($Analyze, $Credential, $FQDN)
    $script:AnalysisCalls++
    $environment = [pscustomobject]@{}
    $environment | Add-Member ScriptMethod Remediate { $script:RemediationCalls++ }
    return $environment
}
function Invoke-SetProbe([bool]$Preview) {
    $script:AnalysisCalls = 0
    $script:RemediationCalls = 0
    $null = Set-ADEnvironment -Class @('user') -WhatIf:$Preview -Confirm:$false
    return [pscustomobject]@{
        Analysis = $script:AnalysisCalls
        Remediation = $script:RemediationCalls
    }
}
'@ + "`n" + $processClass + "`n" + $setFunction
$setProbe = New-Module -Name SetProbe -ScriptBlock ([scriptblock]::Create($setProbeSource))

$helperDefinitions = @($helperAst.EndBlock.Statements | Where-Object {
    $_ -is [TypeDefinitionAst] -or $_ -is [FunctionDefinitionAst]
} | ForEach-Object { $_.Extent.Text }) -join "`n"
$pathInitialization = @($helperAst.FindAll({
    param($node)
    $node -is [AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq "[Config]::Parameters['path']"
}, $true) | ForEach-Object { $_.Extent.Text }) -join "`n"
$entryPointArguments = $helperAst.Find({
    param($node)
    $node -is [AssignmentStatementAst] -and
        $node.Left.Extent.Text -eq '$splat' -and
        $node.Right.Extent.Text -match 'Get-Credential'
}, $true).Extent.Text

$helperProbeSource = @'
using namespace System.Collections
using namespace System.Collections.Specialized
using namespace System.Management.Automation
'@ + "`n" + $helperDefinitions + "`n" + @'
function New-FakeEnvironment {
    $finding = [pscustomobject]@{}
    $finding | Add-Member ScriptMethod ExportCSV { param($Path) }
    return [pscustomobject]@{ Finding = $finding }
}
function Set-ADEnvironment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('user', 'computer')][ArrayList]$Remediate,
        $Credential, $FQDN
    )
    $script:SetCalls++
    $script:SelectedFQDN = $FQDN
    $script:SelectedClasses = $Remediate -join ','
    return New-FakeEnvironment
}
function Get-ADEnvironment {
    param($Analyze, $Credential, $FQDN)
    $script:ReportCalls++
    $script:SelectedFQDN = $FQDN
    return New-FakeEnvironment
}
function Test-ComputerSecureChannel {
    param($Server, [switch]$WhatIf, [switch]$Confirm)
    return $true
}
function Invoke-HelperProbe([string]$Operation, [bool]$Preview, [bool]$ExplicitClass, [string]$TargetFQDN) {
    [Config]::Options = [Config]::New()
    [Config]::Options['FQDN'] = 'example.invalid'
    [Config]::Options['path'] = @{ tmp = 'unused' }
    [Config]::Options['whatIf'] = $false
    [Config]::Options['confirm'] = $false
    $script:SetCalls = 0
    $script:ReportCalls = 0
    $script:SelectedClasses = ''
    $script:SelectedFQDN = ''
    $arguments = @{ Operation = $Operation; WhatIf = $Preview; Confirm = $false }
    if ($ExplicitClass) { $arguments['Class'] = @('computer') }
    if ($TargetFQDN) { $arguments['FQDN'] = $TargetFQDN }
    $target = Start-ADAnalyzer @arguments
    $reportedFQDN = ''
    if ($null -ne $target) { $reportedFQDN = $target['FQDN'] }
    return [pscustomobject]@{
        SetCalls = $script:SetCalls
        ReportCalls = $script:ReportCalls
        Classes = $script:SelectedClasses
        RequestedFQDN = $script:SelectedFQDN
        ReportedFQDN = $reportedFQDN
    }
}
function Invoke-HelperPathProbe([string]$Path) {
    $configuration = [Config]::New()
    $configuration.Path($Path)
    return $configuration['path']['tmp']
}
function Invoke-HelperDefaultPathProbe([string]$ScriptDirectory) {
    $PSScriptRoot = $ScriptDirectory
'@ + "`n" + $pathInitialization + "`n" + @'
    return [Config]::Parameters['path']
}
function Get-Credential { return [PSCredential]::Empty }
function Invoke-EntryPointClassesProbe([string]$Operation) {
    [Config]::Options = [Config]::New()
    foreach ($key in [Config]::Parameters.Keys) {
        [Config]::Options[$key] = [Config]::Parameters[$key]
    }
    [Config]::Options['Operation'] = $Operation
'@ + "`n" + $entryPointArguments + "`n" + @'
    return $splat['Class'] -join ','
}
'@
$helperProbe = New-Module -Name HelperProbe -ScriptBlock ([scriptblock]::Create($helperProbeSource))

Invoke-Test 'module and helper parse without syntax errors' {
    Assert-Equal 'Set-ADEnvironment' ($moduleAst.Find({
        param($node)
        $node -is [FunctionDefinitionAst] -and $node.Name -eq 'Set-ADEnvironment'
    }, $false).Name)
    Assert-Equal 'Start-ADAnalyzer' ($helperAst.Find({
        param($node)
        $node -is [FunctionDefinitionAst] -and $node.Name -eq 'Start-ADAnalyzer'
    }, $false).Name)
}

Invoke-Test 'Set-ADEnvironment -WhatIf never reaches analysis or remediation' {
    $result = & $setProbe { Invoke-SetProbe $true }
    Assert-Equal 0 $result.Analysis
    Assert-Equal 0 $result.Remediation
}

Invoke-Test 'Set-ADEnvironment still remediates when approved' {
    $result = & $setProbe { Invoke-SetProbe $false }
    Assert-Equal 1 $result.Analysis
    Assert-Equal 1 $result.Remediation
}

Invoke-Test 'Start-ADAnalyzer -WhatIf never invokes the remediation command' {
    $result = & $helperProbe { Invoke-HelperProbe 'remediate' $true $true }
    Assert-Equal 0 $result.SetCalls
}

Invoke-Test 'helper remediation preserves an explicit class' {
    $result = & $helperProbe { Invoke-HelperProbe 'remediate' $false $true }
    Assert-Equal 1 $result.SetCalls
    Assert-Equal 'computer' $result.Classes
}

Invoke-Test 'helper defaults remediation to supported object classes' {
    $result = & $helperProbe { Invoke-HelperProbe 'remediate' $false $false }
    Assert-Equal 1 $result.SetCalls
    Assert-Equal 'User,Computer' $result.Classes
}

Invoke-Test 'reporting remains available with -WhatIf' {
    $result = & $helperProbe { Invoke-HelperProbe 'report' $true $true }
    Assert-Equal 0 $result.SetCalls
    Assert-Equal 1 $result.ReportCalls
}

Invoke-Test 'helper reports the requested domain without explicit credentials' {
    $result = & $helperProbe { Invoke-HelperProbe 'report' $false $true 'target.example.invalid' }
    Assert-Equal 'target.example.invalid' $result.RequestedFQDN
    Assert-Equal 'target.example.invalid' $result.ReportedFQDN
}

Invoke-Test 'helper remediates the requested domain without explicit credentials' {
    $result = & $helperProbe { Invoke-HelperProbe 'remediate' $false $true 'target.example.invalid' }
    Assert-Equal 'target.example.invalid' $result.RequestedFQDN
    Assert-Equal 'target.example.invalid' $result.ReportedFQDN
}

Invoke-Test 'script entry point uses the configured remediation classes' {
    $actual = & $helperProbe { Invoke-EntryPointClassesProbe 'remediate' }
    Assert-Equal 'User,Computer' $actual
}

Invoke-Test 'script entry point uses the configured report classes' {
    $actual = & $helperProbe { Invoke-EntryPointClassesProbe 'report' }
    Assert-Equal 'User,Group,Computer,GroupPolicy' $actual
}

Invoke-Test 'helper resolves the checkout from its script directory' {
    $actual = & $helperProbe { param($Path) Invoke-HelperDefaultPathProbe $Path } (Join-Path $RepositoryRoot 'bin')
    Assert-Equal $RepositoryRoot $actual
}

Invoke-Test 'manifest points to an existing module' {
    $manifest = Import-PowerShellDataFile (Join-Path $RepositoryRoot 'ADEnvironment.psd1')
    Assert-Equal $true (Test-Path -LiteralPath (Join-Path $RepositoryRoot $manifest.RootModule) -PathType Leaf)
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('ad-analyzer-tests-' + [guid]::NewGuid())
New-Item -Path $temporaryRoot -ItemType Directory > $null
try {
    Invoke-Test 'helper creates a missing report directory' {
        $outputPath = & $helperProbe { param($Path) Invoke-HelperPathProbe $Path } $temporaryRoot
        Assert-Equal (Join-Path $temporaryRoot 'tmp') $outputPath
        Assert-Equal $true (Test-Path -LiteralPath $outputPath -PathType Container)
    }

    Invoke-Test 'helper reuses an existing report directory' {
        New-Item -Path (Join-Path $temporaryRoot 'tmp') -ItemType Directory -Force > $null
        $outputPath = & $helperProbe { param($Path) Invoke-HelperPathProbe $Path } $temporaryRoot
        Assert-Equal (Join-Path $temporaryRoot 'tmp') $outputPath
    }

    Invoke-Test 'manifest generator works from a different current directory' {
        $fixture = Join-Path $temporaryRoot 'fixture'
        $fixtureEtc = Join-Path $fixture 'etc'
        New-Item -Path $fixtureEtc -ItemType Directory -Force > $null
        $fixtureBin = Join-Path $fixture 'bin'
        New-Item -Path $fixtureBin -ItemType Directory > $null
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'bin/ADEnvironment.psm1') -Destination $fixtureBin
        Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'etc/CreateModuleManifest.ps1') -Destination $fixtureEtc
        Push-Location $temporaryRoot
        try { & (Join-Path $fixtureEtc 'CreateModuleManifest.ps1') }
        finally { Pop-Location }
        $manifestPath = Join-Path $fixture 'ADEnvironment.psd1'
        Assert-Equal $true (Test-Path -LiteralPath $manifestPath -PathType Leaf)
        $manifest = Import-PowerShellDataFile $manifestPath
        Assert-Equal 'bin/ADEnvironment.psm1' $manifest.RootModule
        Assert-Equal $true (Test-Path -LiteralPath (Join-Path $fixture $manifest.RootModule) -PathType Leaf)
    }
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -WhatIf:$false -Confirm:$false
}

Write-Host ("{0} passed; {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed) { exit 1 }
