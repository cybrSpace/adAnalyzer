[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [string]$ExpectedVersion,
    [ValidateSet('Regression','Quality','All')][string]$Mode='Regression'
)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent $PSScriptRoot}
$engine=(Get-Process -Id $PID).Path
Write-Host ('Test executable: '+$engine)
$PSVersionTable | Format-List | Out-String | Write-Host
Write-Host ('64-bit process: '+[Environment]::Is64BitProcess)
$runtime=if('System.Runtime.InteropServices.RuntimeInformation' -as [type]){[Runtime.InteropServices.RuntimeInformation]::FrameworkDescription}else{'CLR '+[Environment]::Version}
Write-Host ('Runtime: '+$runtime)
if($ExpectedVersion) {
    if($ExpectedVersion -eq '5.1') {
        if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or $PSVersionTable.PSEdition -ne 'Desktop') {
            throw 'Expected Windows PowerShell 5.1 Desktop'
        }
    } elseif($PSVersionTable.PSVersion.ToString() -ne $ExpectedVersion -or $PSVersionTable.PSEdition -ne 'Core') {
        throw ('Expected PowerShell Core '+$ExpectedVersion)
    }
    if(-not [Environment]::Is64BitProcess){throw 'Expected a 64-bit test process'}
}

if($Mode -in 'Regression','All') {
    # Class/static state must not leak between independent suites.
    $suites=@(
        'Invoke-RegressionTests.ps1'
        'Invoke-ClassContractTests.ps1'
        'Invoke-NativeClassTests.ps1'
        'Invoke-SelfContainedTests.ps1'
        'Invoke-GpoReaderTests.ps1'
        'Invoke-PolicyAnalysisTests.ps1'
        'Invoke-DirectoryAnalysisTests.ps1'
        'Invoke-OperationsTests.ps1'
        'Invoke-AssessmentTests.ps1'
        'Invoke-HostAnalysisTests.ps1'
    )
    foreach($suite in $suites) {
        Write-Host ('Running '+$suite)
        & $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot $suite) -RepositoryRoot $RepositoryRoot
        if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    }
}
if($Mode -eq 'All') {
    # Pester and the module import also start with a fresh process.
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,'-RepositoryRoot',$RepositoryRoot,'-Mode','Quality')
    # Windows PowerShell's native argument binding drops empty strings.
    if($ExpectedVersion){$arguments+=@('-ExpectedVersion',$ExpectedVersion)}
    & $engine @arguments
    exit $LASTEXITCODE
}
if($Mode -eq 'Quality') {
    $dependencies=Import-PowerShellDataFile -LiteralPath (Join-Path $RepositoryRoot 'etc/DevelopmentDependencies.psd1')
    foreach($name in @('Pester','PSScriptAnalyzer')) {
        $manifest=Join-Path $RepositoryRoot ('tools/modules/{0}/{1}/{0}.psd1' -f $name,$dependencies[$name])
        Import-Module $manifest -Force -ErrorAction Stop
    }
    Import-Module (Join-Path $RepositoryRoot 'ADEnvironment.psd1') -ErrorAction Stop -WarningAction SilentlyContinue
    $result=Invoke-Pester -Path (Join-Path $PSScriptRoot 'Quality.Tests.ps1') -PassThru
    if($result.FailedCount -or $result.FailedBlocksCount -or $result.PassedCount -lt 1){exit 1}
    $rules=@('PSAvoidUsingInvokeExpression','PSAvoidUsingPlainTextForPassword','PSUsePSCredentialType','PSAvoidUsingConvertToSecureStringWithPlainText')
    $diagnostics=@(Invoke-ScriptAnalyzer -Path (Join-Path $RepositoryRoot 'bin') -Recurse -IncludeRule $rules)
    $diagnostics | Format-Table -AutoSize
    Write-Host ('Static security diagnostics: '+$diagnostics.Count)
    if($diagnostics.Count){exit 1}
}
