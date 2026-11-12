[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$Path=(Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/modules'))
$ErrorActionPreference='Stop'
$dependencies=Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'DevelopmentDependencies.psd1')
foreach($name in $dependencies.Keys) {
    $version=$dependencies[$name]
    if(-not $PSCmdlet.ShouldProcess("$name $version",'Save optional development tool from PSGallery')){continue}
    if(-not (Test-Path -LiteralPath $Path -PathType Container)){$null=New-Item -Path $Path -ItemType Directory -Force -WhatIf:$false -Confirm:$false}
    if(Get-Command Save-PSResource -ErrorAction SilentlyContinue) {
        Save-PSResource -Name $name -Version $version -Repository PSGallery -Path $Path -TrustRepository -ErrorAction Stop
    } else {
        Save-Module -Name $name -RequiredVersion $version -Repository PSGallery -Path $Path -Force -ErrorAction Stop
    }
}
# Tools are kept in the repository's ignored tools directory. The application
# does not import them, modify trusted repositories, or require them at runtime.
