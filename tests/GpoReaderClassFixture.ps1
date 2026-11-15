[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [ValidateSet('Construction', 'Read', 'Parsers', 'Errors', 'Streaming', 'Compatibility', 'Isolation', 'Paths', 'Rights')]
    [string]$Mode = 'Construction'
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
if ($null -eq ('ADAnalyzerGpoReader' -as [type])) {
    throw 'The constructor-based GPO reader is missing.'
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-reader-class-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($temporary)

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function Assert-Fails([scriptblock]$Body) {
    $caught = $null
    $rows = [Collections.Generic.List[object]]::new()
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $caught = $_
    }
    Assert-Equal $false ($null -eq $caught)
    Assert-Equal 0 $rows.Count
}

function Get-Json($Value) {
    ConvertTo-Json -InputObject $Value -Depth 100 -Compress
}

function Write-Policy([string]$Path, [switch]$InvalidTail) {
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream = [IO.File]::Create($Path)
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'))
        $writer.Write([uint32]1)
        foreach ($pair in @(@('Enabled', 0), @('Other', 1))) {
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes('Software\Fixture' + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($pair[0] + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([uint32]4)
            $writer.Write([uint16]59)
            $writer.Write([uint32]4)
            $writer.Write([uint16]59)
            $writer.Write([uint32]$pair[1])
            $writer.Write([uint16]93)
        }
        if ($InvalidTail) {
            $writer.Write([byte]1)
        }
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

try {
    if ($Mode -eq 'Construction') {
        function Get-Item { throw 'Unexpected constructor file lookup' }
        function Get-ChildItem { throw 'Unexpected constructor enumeration' }
        function Import-Module { throw 'Unexpected constructor module import' }
        function Get-ADObject { throw 'Unexpected constructor directory query' }
    }
    $reader = [ADAnalyzerGpoReader]::new()
    $pol = Join-Path $temporary 'Machine/Registry.pol'
    $xml = Join-Path $temporary 'Machine/Preferences/Groups/Groups.xml'
    $ini = Join-Path $temporary 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
    Write-Policy $pol
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($xml))
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ini))
    [IO.File]::WriteAllText($xml, '<Groups><User uid="one"><Properties cpassword="READER_CLASS_SECRET" /></User></Groups>')
    [IO.File]::WriteAllText($ini, "[System Access]`nMinimumPasswordLength=12`nPasswordComplexity=0", [Text.Encoding]::Unicode)
    [IO.File]::WriteAllText((Join-Path $temporary 'GPT.INI'), "[General]`nVersion=1")

    switch ($Mode) {
        'Construction' {
            $second = [ADAnalyzerGpoReader]::new()
            Assert-Equal '{}' (Get-Json $reader)
            Assert-Equal '{}' (Get-Json $second)
            Assert-Equal 0 @($reader.PSObject.Properties).Count
        }
        'Read' {
            $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pol))
            $direct = $reader.Read($temporary)
            $compatibility = Read-ADAnalyzerGpo -Path $temporary
            Assert-Equal (Get-Json $compatibility) (Get-Json $direct)
            Assert-Equal 2 $direct.RegistrySettings.Count
            Assert-Equal 2 $direct.SecuritySettings.Count
            Assert-Equal 1 $direct.XmlFiles.Count
            Assert-Equal 1 $direct.SysvolVersion
            Assert-Equal $false ((Get-Json $direct) -match 'READER_CLASS_SECRET|REDACTED')
            Assert-Equal $before ([Convert]::ToBase64String([IO.File]::ReadAllBytes($pol)))
            Assert-Equal $true ([IO.File]::ReadAllText($xml).Contains('READER_CLASS_SECRET'))
            Assert-Equal $false $direct.SecuritySettings[1].Value
        }
        'Parsers' {
            Assert-Equal (Get-Json (Read-AnalyzerPolicyIni $ini)) (Get-Json $reader.ReadIni($ini))
            Assert-Equal $true ($reader.ReadIni($ini) -is [Collections.Specialized.OrderedDictionary])
            $csv = '1,"a,b""c",0'
            Assert-Equal (Get-Json (Split-AnalyzerPolicyCsv $csv)) (Get-Json $reader.SplitCsv($csv))
            Assert-Equal 1 @(Split-AnalyzerPolicyCsv 'one').Count
            Assert-Equal 1 $reader.SplitCsv('one').Count
            Assert-Equal '' $reader.SplitCsv('')[0]
            Assert-Equal (Read-AnalyzerPolicyXml $xml).OuterXml $reader.ReadXml($xml).OuterXml
            Assert-Equal (Get-Json @(Read-AnalyzerRegistryPolicy $pol Computer)) (Get-Json $reader.ReadRegistryPolicy($pol, 'Computer'))
            Assert-Equal 'System.UInt32' $reader.ReadRegistryPolicy($pol, 'Computer')[0].Value.GetType().FullName
            Assert-Equal 'System.Byte[]' $reader.ReadRegistryPolicy($pol, 'Computer')[0].RawData.GetType().FullName
            Assert-Equal (Get-Json (ConvertFrom-ADAnalyzerInfFlag PasswordComplexity '0')) (Get-Json $reader.ConvertInfFlag('PasswordComplexity', '0'))
            Assert-Equal $null $reader.ConvertInfFlag('Unknown', '1')
            Assert-Equal 2 $reader.ConvertSecurityOption('unknown', @('one', 'two')).Count
        }
        'Rights' {
            $content = "[Privilege Rights]`nSeOnePrivilege=*S-1-5-32-544`nSeManyPrivilege=*S-1-5-32-544,*S-1-5-32-545`nSeEmptyPrivilege="
            [IO.File]::WriteAllText($ini, $content, [Text.Encoding]::Unicode)
            $policy = $reader.Read($temporary)
            $one = @($policy.SecuritySettings | Where-Object Name -eq 'SeOnePrivilege')[0]
            $many = @($policy.SecuritySettings | Where-Object Name -eq 'SeManyPrivilege')[0]
            $empty = @($policy.SecuritySettings | Where-Object Name -eq 'SeEmptyPrivilege')[0]
            Assert-Equal 'System.String[]' $one.Value.GetType().FullName
            Assert-Equal 'System.String[]' $many.Value.GetType().FullName
            Assert-Equal '["*S-1-5-32-544"]' (Get-Json $one.Value)
            Assert-Equal '["*S-1-5-32-544","*S-1-5-32-545"]' (Get-Json $many.Value)
            Assert-Equal $null $empty.Value
        }
        'Errors' {
            Assert-Fails { $reader.Read('') }
            Assert-Fails { $reader.Read((Join-Path $temporary 'missing')) }
            Assert-Fails { $reader.Read($pol) }
            Assert-Fails { $reader.ReadRegistryPolicy($pol, 'InvalidScope') }
            Assert-Fails { $reader.SplitCsv('"unfinished') }
            $invalidPath = $null
            try {
                $null = Read-AnalyzerPolicyXml ''
            }
            catch {
                $invalidPath = $_
            }
            Assert-Equal $false ($null -eq $invalidPath)
            Assert-Equal 'System.ArgumentException' $invalidPath.Exception.GetBaseException().GetType().FullName
            [IO.File]::WriteAllText($xml, '<!DOCTYPE root [<!ENTITY x SYSTEM "file:///never-read">]><root>&x;</root>')
            Assert-Fails { $reader.ReadXml($xml) }
            $held = [IO.File]::Open($xml, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $held.Dispose()
            [IO.File]::WriteAllText($pol, 'invalid')
            Assert-Fails { $reader.ReadRegistryPolicy($pol, 'Computer') }
            $held = [IO.File]::Open($pol, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $held.Dispose()
        }
        'Streaming' {
            Write-Policy $pol -InvalidTail
            $rows = [Collections.Generic.List[object]]::new()
            $caught = $null
            try {
                Read-AnalyzerRegistryPolicy -Path $pol -Scope Computer | ForEach-Object { $rows.Add($_) }
            }
            catch {
                $caught = $_
            }
            Assert-Equal 2 $rows.Count
            Assert-Equal $false ($null -eq $caught)
            Assert-Fails { $reader.ReadRegistryPolicy($pol, 'Computer') }
            $held = [IO.File]::Open($pol, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $held.Dispose()
            Write-Policy $pol
            Assert-Equal 1 @(Read-AnalyzerRegistryPolicy -Path $pol -Scope Computer | Select-Object -First 1).Count
            $held = [IO.File]::Open($pol, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $held.Dispose()
        }
        'Compatibility' {
            Assert-Equal (Get-Json @(Read-AnalyzerRegistryPolicy -Path $pol)) (Get-Json $reader.ReadRegistryPolicy($pol))
            Assert-Equal '' $reader.ReadRegistryPolicy($pol)[0].Scope
            Assert-Equal 'HKCU' $reader.ReadRegistryPolicy($pol)[0].Hive
            $parts = @(Split-AnalyzerPolicyCsv 'a,b')
            Assert-Equal 1 $parts.Count
            Assert-Equal 'a|b' ($parts[0] -join '|')
            Assert-Equal (Get-Json @(ConvertTo-AnalyzerSecurityOption 'unknown' @('one', 'two'))) (Get-Json $reader.ConvertSecurityOption('unknown', @('one', 'two')))
        }
        'Isolation' {
            $second = [ADAnalyzerGpoReader]::new()
            $firstResult = $reader.Read($temporary)
            $firstResult.RegistrySettings[0].Value = 99
            Assert-Equal 0 $reader.Read($temporary).RegistrySettings[0].Value
            Assert-Equal 0 $second.Read($temporary).RegistrySettings[0].Value
            Assert-Equal '{}' (Get-Json $reader)
        }
        'Paths' {
            $other = Join-Path $temporary ('copy [literal] ' + [char]0x00E9)
            $null = [IO.Directory]::CreateDirectory($other)
            Write-Policy (Join-Path $other 'Machine/Registry.pol')
            $result = $reader.Read($other)
            Assert-Equal 1 $result.Files.Count
            Assert-Equal 'Machine/Registry.pol' $result.Files[0].Path
            Assert-Equal 'Machine/Registry.pol' $result.RegistrySettings[0].Source
            Assert-Equal ([IO.Path]::GetFullPath($other)) $result.Path
        }
    }
    Write-Output ('PASS GPO reader class ' + $Mode)
}
finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
