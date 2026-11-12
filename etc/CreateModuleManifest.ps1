$manifest = @{
    Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'ADEnvironment.psd1'
    RootModule = 'bin/ADEnvironment.psm1'
    ModuleVersion = '1.2'
    GUID = 'e383e5d0-4c43-4147-9ca4-2513410e6248'
    Author = 'Allen Lipa'
    CompanyName = 'cybrPro'
    Copyright = '(c) 2023 Allen Lipa. All rights reserved.'
    PowerShellVersion = '5.1'
    RequiredAssemblies = @('lib/Microsoft.ActiveDirectory.Management.dll')
    NestedModules = @('lib/Microsoft.ActiveDirectory.Management.dll')
    FunctionsToExport = @(
        'Get-ADEnvironment', 'Set-ADEnvironment', 'Get-ADAnalyzerGpo', 'Get-ADAnalyzerGpoReport', 'Read-ADAnalyzerGpo',
        'Get-ADAnalyzerDefaultProfile', 'Import-ADAnalyzerProfile', 'Get-ADAnalyzerPrerequisite',
        'Get-ADAnalyzerAssessment', 'Invoke-ADAnalyzerAssessment', 'Import-ADAnalyzerBaseline',
        'Test-ADAnalyzerGpoPolicy', 'Test-ADAnalyzerDirectoryPolicy', 'Resolve-ADAnalyzerRegistryPolicy',
        'Test-ADAnalyzerHostPolicy', 'Get-ADAnalyzerAuditPolicy', 'Get-ADAnalyzerTlsCertificate',
        'Export-ADAnalyzerAssessment', 'Compare-ADAnalyzerAssessment',
        'New-ADAnalyzerRemediationPlan', 'Invoke-ADAnalyzerRemediationPlan', 'Undo-ADAnalyzerRemediation', 'Start-ADAnalyzer'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
New-ModuleManifest @manifest
# New-ModuleManifest comments out an explicitly empty VariablesToExport on
# some PowerShell versions. Keep the generated public surface deterministic.
$text=Get-Content -LiteralPath $manifest.Path -Raw
Set-Content -LiteralPath $manifest.Path -Value ($text.Replace('# VariablesToExport = @()','VariablesToExport = @()')) -Encoding UTF8
