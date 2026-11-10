$manifest = @{
    Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'ADEnvironment.psd1'
    RootModule = 'bin/ADEnvironment.psm1'
    ModuleVersion = '1.1'
    GUID = 'e383e5d0-4c43-4147-9ca4-2513410e6248'
    Author = 'Allen Lipa'
    CompanyName = 'cybrPro'
    Copyright = '(c) 2023 Allen Lipa. All rights reserved.'
    PowerShellVersion = '5.1'
    RequiredAssemblies = @('lib/Microsoft.ActiveDirectory.Management.dll')
    NestedModules = @('lib/Microsoft.ActiveDirectory.Management.dll')
    FunctionsToExport = @('Get-ADEnvironment', 'Set-ADEnvironment', 'Get-ADAnalyzerGpo', 'Get-ADAnalyzerGpoReport', 'Read-ADAnalyzerGpo')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
New-ModuleManifest @manifest
