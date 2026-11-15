[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [ValidateSet('NullSuccess', 'Missing', 'Denied', 'Unexpected', 'Native')]
    [string]$Mode = 'NullSuccess'
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
. (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-reader-path-' + [guid]::NewGuid().ToString('N'))
$global:ReaderPathProbe = @{
    Mode = $Mode
    MissingPath = ''
    MissingLookups = 0
    MissingEnumerations = 0
    GetItem = Get-Command Microsoft.PowerShell.Management\Get-Item
    GetChildItem = Get-Command Microsoft.PowerShell.Management\Get-ChildItem
}

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function New-PathPolicy([string]$Root, [string]$Side) {
    $path = Join-Path $Root ($Side + '/Microsoft/Windows NT/SecEdit/GptTmpl.inf')
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    [IO.File]::WriteAllText($path, "[System Access]`nMinimumPasswordLength=12", [Text.Encoding]::Unicode)
}

if ($Mode -ne 'Native') {
    function Get-Item {
        [CmdletBinding()]
        param([string]$LiteralPath, [switch]$Force)
        if ($LiteralPath -eq $global:ReaderPathProbe.MissingPath) {
            $global:ReaderPathProbe.MissingLookups++
            Assert-Equal 'Stop' ([string]$PSBoundParameters.ErrorAction)
            switch ($global:ReaderPathProbe.Mode) {
                'NullSuccess' {
                    return
                }
                'Missing' {
                    throw [Management.Automation.ItemNotFoundException]::new('Fixture missing side')
                }
                'Denied' {
                    throw [UnauthorizedAccessException]::new('Fixture denied side')
                }
                'Unexpected' {
                    throw [IO.IOException]::new('Fixture unexpected lookup failure')
                }
            }
        }
        & $global:ReaderPathProbe.GetItem @PSBoundParameters
    }

    function Get-ChildItem {
        [CmdletBinding()]
        param([string]$LiteralPath, [switch]$Recurse, [switch]$File, [switch]$Force)
        if ($LiteralPath -eq $global:ReaderPathProbe.MissingPath) {
            $global:ReaderPathProbe.MissingEnumerations++
            throw 'The reader enumerated an absent policy side.'
        }
        & $global:ReaderPathProbe.GetChildItem @PSBoundParameters
    }
}

try {
    $root = Join-Path $temporary ('policy [literal] ' + [char]0x00E9)
    New-PathPolicy $root 'Machine'
    $global:ReaderPathProbe.MissingPath = Join-Path $root 'User'
    foreach ($preference in @('Continue', 'Stop')) {
        $ErrorActionPreference = $preference
        $rows = [Collections.Generic.List[object]]::new()
        $caught = $null
        try {
            Read-ADAnalyzerGpo -Path $root | ForEach-Object { $rows.Add($_) }
        }
        catch {
            $caught = $_
        }
        if ($Mode -in 'Denied', 'Unexpected') {
            Assert-Equal 0 $rows.Count
            Assert-Equal $false ($null -eq $caught)
            $expectedType = if ($Mode -eq 'Denied') {
                'System.UnauthorizedAccessException'
            }
            else {
                'System.IO.IOException'
            }
            Assert-Equal $expectedType $caught.Exception.GetBaseException().GetType().FullName
        }
        else {
            if ($null -ne $caught) {
                throw $caught
            }
            Assert-Equal 1 $rows.Count
            Assert-Equal 1 $rows[0].SecuritySettings.Count
            Assert-Equal 12 $rows[0].SecuritySettings[0].Value
            Assert-Equal 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf' $rows[0].SecuritySettings[0].Source
        }
    }
    Assert-Equal 0 $global:ReaderPathProbe.MissingEnumerations
    if ($Mode -eq 'Native') {
        $userRoot = Join-Path $temporary ('user [literal] ' + [char]0x00E9)
        New-PathPolicy $userRoot 'User'
        $result = Read-ADAnalyzerGpo -Path $userRoot
        Assert-Equal 1 $result.SecuritySettings.Count
        Assert-Equal 'User' $result.SecuritySettings[0].Scope
        Assert-Equal 'User/Microsoft/Windows NT/SecEdit/GptTmpl.inf' $result.SecuritySettings[0].Source
    }
    else {
        Assert-Equal 2 $global:ReaderPathProbe.MissingLookups
    }
    Write-Output ('PASS reader side path ' + $Mode)
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
