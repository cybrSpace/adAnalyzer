[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Healthy', 'Unreadable', 'Required', 'Dictionary', 'Getters', 'Export', 'Presence')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
. (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
. (Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1')
$script:ExternalCalls = [Collections.Generic.List[string]]::new()
$script:Checks = 0
$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-local-gpo-metadata-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Temporary)

# Every inventory invocation supplies local reports. These fail-closed sentries
# make an accidental transition to a live catalog, provider or mutation visible.
function Import-Module {
    $script:ExternalCalls.Add('Import-Module')
    throw 'Unexpected module import'
}

function Get-ADAnalyzerGpo {
    $script:ExternalCalls.Add('Get-ADAnalyzerGpo')
    throw 'Unexpected catalog query'
}

function Get-ADAnalyzerGpoReport {
    $script:ExternalCalls.Add('Get-ADAnalyzerGpoReport')
    throw 'Unexpected live report'
}

function Get-ADRootDSE {
    $script:ExternalCalls.Add('Get-ADRootDSE')
    throw 'Unexpected directory query'
}

function Get-ADObject {
    $script:ExternalCalls.Add('Get-ADObject')
    throw 'Unexpected directory query'
}

function New-PSDrive {
    $script:ExternalCalls.Add('New-PSDrive')
    throw 'Unexpected provider preparation'
}

function New-ADUser {
    $script:ExternalCalls.Add('New-ADUser')
    throw 'Unexpected account mutation'
}

function Invoke-WebRequest {
    $script:ExternalCalls.Add('Invoke-WebRequest')
    throw 'Unexpected network request'
}

function Invoke-RestMethod {
    $script:ExternalCalls.Add('Invoke-RestMethod')
    throw 'Unexpected network request'
}

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function Assert-True($Value, [string]$Message) {
    if (-not $Value) {
        throw $Message
    }
}

function Get-Json($Value) {
    ConvertTo-Json -InputObject $Value -Depth 100 -Compress
}

function New-Metadata([int]$Index = 1) {
    [pscustomobject]@{
        Id = [guid]('11111111-1111-4111-8111-' + $Index.ToString('D12'))
        DisplayName = 'policy ' + $Index
        Domain = 'example.invalid'
        Server = 'dc.example.invalid'
        Flags = 0
        Version = 1
        Links = @()
        WmiFilter = $null
    }
}

$script:Policy = [pscustomobject]@{
    Path = 'in-memory fixture'
    SysvolVersion = 1
    Files = @()
    UnparsedFiles = @()
    SecuritySettings = @()
    RegistrySettings = @()
    IniSettings = @()
    XmlFiles = @()
}

function New-Packet([string]$Shape = 'Absent', [int]$Index = 1) {
    $report = [ADAnalyzerGpoReportService]::new().BuildReport(@{
        Gpo = New-Metadata $Index
        Policy = $script:Policy
        VersionMismatch = $false
    })
    switch ($Shape) {
        'Null' {
            $report | Add-Member NoteProperty ReadError $null
        }
        'False' {
            $report | Add-Member NoteProperty ReadError $false
        }
        'True' {
            $report | Add-Member NoteProperty ReadError $true
            $report | Add-Member NoteProperty ErrorType 'FixtureException'
        }
        'TruthyString' {
            $report | Add-Member NoteProperty ReadError 'false'
            $report | Add-Member NoteProperty ErrorType 'FixtureException'
        }
        'MissingDiagnostic' {
            $report.Policy = $null
            $report | Add-Member NoteProperty ReadError $true
        }
        'FalseNullPolicy' {
            $report.Policy = $null
            $report | Add-Member NoteProperty ReadError $false
        }
        'NullDiagnostic' {
            $report.Policy = $null
            $report | Add-Member NoteProperty ReadError $true
            $report | Add-Member NoteProperty ErrorType $null
        }
        'FalseDiagnostic' {
            $report.Policy = $null
            $report | Add-Member NoteProperty ReadError $true
            $report | Add-Member NoteProperty ErrorType $false
        }
        'RequiredPolicyMissing' {
            $report.PSObject.Properties.Remove('Policy')
            $report | Add-Member NoteProperty ReadError $false
            $report | Add-Member NoteProperty ErrorType 'FixtureException'
        }
    }
    return $report
}

function Invoke-Entry([object[]]$Reports, [string]$Route, [hashtable]$Options = @{}) {
    $command = if ($Route -eq 'Command') {
        'Get-ADAnalyzerLocalAdminGpo'
    }
    else {
        Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1'
    }
    $arguments = @{
        InputObject = $Reports
        ErrorAction = 'Stop'
        ErrorVariable = '+captured'
    }
    foreach ($key in $Options.Keys) {
        $arguments[$key] = $Options[$key]
    }
    $captured = @()
    $rows = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $command @arguments | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $failure = $_
    }
    return @{
        Rows = $rows.ToArray()
        Failure = $failure
        Diagnostics = $captured.Count
    }
}

function Assert-Healthy([hashtable]$Result) {
    Assert-Equal $null $Result.Failure
    Assert-Equal 0 $Result.Diagnostics
    Assert-Equal 'GPO.Preferences.CPassword,GPO.RestrictedGroups.LocalAdministrators,GPO.Preferences.LocalUsersGroups' ($Result.Rows.RuleId -join ',')
    Assert-Equal 'Pass,NotConfigured,NotConfigured' ($Result.Rows.Status -join ',')
}

function Assert-Unreadable([hashtable]$Result, $Diagnostic) {
    Assert-Equal $null $Result.Failure
    Assert-Equal 0 $Result.Diagnostics
    Assert-Equal 1 $Result.Rows.Count
    Assert-Equal 'GPO.READ' $Result.Rows[0].RuleId
    Assert-Equal 'Unreadable' $Result.Rows[0].Status
    $actual = $Result.Rows[0].Evidence.RuleEvidence.ErrorType
    Assert-Equal $Diagnostic $actual
    if ($null -ne $Diagnostic) {
        Assert-Equal $Diagnostic.GetType().FullName $actual.GetType().FullName
    }
}

function Invoke-MetadataCase([string]$Strict, [string]$Route) {
    if ($Strict -eq 'Off') {
        Set-StrictMode -Off
    }
    else {
        Set-StrictMode -Version $Strict
    }
    switch ($Mode) {
        'Healthy' {
            $reference = $null
            foreach ($shape in 'False', 'Null', 'Absent') {
                $report = New-Packet $shape
                $before = Get-Json $report
                $result = Invoke-Entry @($report) $Route
                Assert-Healthy $result
                $json = Get-Json $result.Rows
                if ($null -eq $reference) {
                    $reference = $json
                }
                Assert-Equal $reference $json
                Assert-Equal $before (Get-Json $report)
                $script:Checks++
            }
        }
        'Unreadable' {
            foreach ($shape in 'True', 'TruthyString', 'NullDiagnostic', 'FalseDiagnostic', 'MissingDiagnostic', 'FalseNullPolicy') {
                $report = New-Packet $shape
                $before = Get-Json $report
                $diagnostic = if ($shape -in 'True', 'TruthyString') {
                    'FixtureException'
                }
                elseif ($shape -eq 'FalseDiagnostic') {
                    $false
                }
                else {
                    $null
                }
                Assert-Unreadable (Invoke-Entry @($report) $Route) $diagnostic
                Assert-Equal $before (Get-Json $report)
                $script:Checks++
            }
        }
        'Required' {
            $result = Invoke-Entry @((New-Packet RequiredPolicyMissing)) $Route
            if ($Strict -eq 'Off') {
                Assert-Unreadable $result 'FixtureException'
            }
            else {
                Assert-True ($null -ne $result.Failure) 'Omitted required Policy was accepted.'
                Assert-True ($result.Failure.Exception.Message -match 'Policy') 'The required-field failure changed.'
                Assert-Equal 0 $result.Rows.Count
            }
            $script:Checks++
        }
        'Dictionary' {
            foreach ($shape in 'True', 'Absent', 'Lowercase') {
                $map = if ($shape -eq 'Lowercase') {
                    [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
                }
                else {
                    @{}
                }
                $map.Add('Gpo', (New-Metadata))
                $map.Add('Policy', $script:Policy)
                if ($shape -eq 'True') {
                    $map.Add('ReadError', $true)
                    $map.Add('ErrorType', 'FixtureException')
                }
                elseif ($shape -eq 'Lowercase') {
                    $map.Add('readerror', $true)
                    $map.Add('errortype', 'FixtureException')
                }
                $before = Get-Json $map
                $result = Invoke-Entry @($map) $Route
                if ($shape -eq 'True') {
                    Assert-Unreadable $result 'FixtureException'
                }
                else {
                    Assert-Healthy $result
                }
                Assert-Equal $before (Get-Json $map)
                $script:Checks++
            }
        }
        'Getters' {
            foreach ($preference in 'Continue', 'Stop') {
                foreach ($shape in 'False', 'True', 'ReadErrorThrow', 'PolicyThrow', 'DiagnosticThrow', 'DiagnosticNull', 'DiagnosticFalse') {
                    $report = [ADAnalyzer.OptionalMetadataFixture.DeclaredReport]::new()
                    $report.Gpo = New-Metadata
                    $report.PolicyData = $script:Policy
                    $report.ReadErrorData = $false
                    $report.ErrorTypeData = 'FixtureException'
                    switch ($shape) {
                        'True' {
                            $report.ReadErrorData = $true
                            $report.ThrowPolicy = $true
                        }
                        'ReadErrorThrow' {
                            $report.ThrowReadError = $true
                        }
                        'PolicyThrow' {
                            $report.ThrowPolicy = $true
                        }
                        'DiagnosticThrow' {
                            $report.ReadErrorData = $true
                            $report.ThrowErrorType = $true
                        }
                        'DiagnosticNull' {
                            $report.ReadErrorData = $true
                            $report.ErrorTypeData = $null
                        }
                        'DiagnosticFalse' {
                            $report.ReadErrorData = $true
                            $report.ErrorTypeData = $false
                        }
                    }
                    [ADAnalyzer.OptionalMetadataFixture.DeclaredReport]::Events.Clear()
                    $result = Invoke-Entry @($report) $Route @{ ErrorAction = $preference }
                    if ($shape -in 'False', 'ReadErrorThrow') {
                        Assert-Healthy $result
                        $events = 'ReadError,Policy,Policy'
                    }
                    else {
                        $diagnostic = if ($shape -eq 'DiagnosticFalse') {
                            $false
                        }
                        elseif ($shape -in 'DiagnosticNull', 'DiagnosticThrow') {
                            $null
                        }
                        else {
                            'FixtureException'
                        }
                        Assert-Unreadable $result $diagnostic
                        $events = if ($shape -eq 'PolicyThrow') {
                            'ReadError,Policy,ErrorType'
                        }
                        else {
                            'ReadError,ErrorType'
                        }
                    }
                    Assert-Equal $events ([ADAnalyzer.OptionalMetadataFixture.DeclaredReport]::Events -join ',')
                    $script:Checks++
                }
            }
        }
        'Export' {
            foreach ($shape in 'True', 'MissingDiagnostic') {
                $reports = @((New-Packet False 1), (New-Packet $shape 2), (New-Packet False 3))
                $before = Get-Json $reports
                $result = Invoke-Entry $reports $Route
                Assert-Equal $null $result.Failure
                Assert-Equal 0 $result.Diagnostics
                Assert-Equal 'Pass,NotConfigured,NotConfigured,Unreadable,Pass,NotConfigured,NotConfigured' ($result.Rows.Status -join ',')
                Assert-Equal '1,1,1,2,3,3,3' (($result.Rows | ForEach-Object { ([guid]$_.GpoId).ToString('D').Substring(35) }) -join ',')
                foreach ($whatIf in $false, $true) {
                    $parent = Join-Path $script:Temporary ([guid]::NewGuid().ToString('N'))
                    $destination = Join-Path $parent 'inventory.csv'
                    $sentinel = [byte[]]@(0, 1, 2, 13, 10, 255)
                    if (-not $whatIf) {
                        $null = [IO.Directory]::CreateDirectory($parent)
                        [IO.File]::WriteAllBytes($destination, $sentinel)
                    }
                    $result = Invoke-Entry $reports $Route @{ OutputPath = $destination; WhatIf = $whatIf }
                    Assert-True ($null -ne $result.Failure) 'Unreadable inventory was exported.'
                    Assert-Equal 'GPO inventory is incomplete; the previous report was preserved.' $result.Failure.Exception.GetBaseException().Message
                    Assert-Equal 0 $result.Rows.Count
                    if ($whatIf) {
                        Assert-Equal $false ([IO.Directory]::Exists($parent))
                    }
                    else {
                        Assert-Equal ([Convert]::ToBase64String($sentinel)) ([Convert]::ToBase64String([IO.File]::ReadAllBytes($destination)))
                    }
                    $script:Checks++
                }
                Assert-Equal $before (Get-Json $reports)
                $script:Checks++
            }
            foreach ($shape in 'False', 'Absent') {
                foreach ($whatIf in $false, $true) {
                    $parent = Join-Path $script:Temporary ([guid]::NewGuid().ToString('N'))
                    $destination = Join-Path $parent 'inventory.csv'
                    if (-not $whatIf) {
                        $null = [IO.Directory]::CreateDirectory($parent)
                        [IO.File]::WriteAllText($destination, 'previous report')
                    }
                    $report = New-Packet $shape
                    $before = Get-Json $report
                    Assert-Healthy (Invoke-Entry @($report) $Route @{ OutputPath = $destination; WhatIf = $whatIf })
                    if ($whatIf) {
                        Assert-Equal $false ([IO.Directory]::Exists($parent))
                    }
                    else {
                        Assert-Equal 3 @(Import-Csv -LiteralPath $destination).Count
                    }
                    Assert-Equal $before (Get-Json $report)
                    $script:Checks++
                }
            }
        }
        'Presence' {
            foreach ($report in $script:PresenceReports) {
                Assert-Equal $null $report.PSObject.Properties['ReadError']
                $before = Get-Json $report
                $result = Invoke-Entry @($report) $Route
                Assert-Equal $null $result.Failure
                Assert-Equal 0 $result.Diagnostics
                Assert-Equal 'GPO.Preferences.CPassword,GPO.StoredSecret' (($result.Rows | Where-Object Category -eq CredentialExposure).RuleId -join ',')
                foreach ($row in @($result.Rows | Where-Object Category -eq CredentialExposure)) {
                    Assert-Equal 'Fail' $row.Status
                    Assert-Equal $true $row.Observed
                    Assert-Equal 'System.Boolean' $row.Observed.GetType().FullName
                    Assert-Equal $true $row.Evidence.RuleEvidence.SecretPresent
                    Assert-Equal 'System.Boolean' $row.Evidence.RuleEvidence.SecretPresent.GetType().FullName
                }
                $resultJson = Get-Json $result.Rows
                Assert-True ($resultJson -notmatch 'OPTIONAL_METADATA_SECRET|REDACTED') 'A secret or masked placeholder escaped.'
                Assert-Equal $false $resultJson.Contains([Convert]::ToBase64String($bytes))
                Assert-True ($resultJson -match 'Machine/Registry.pol' -and $resultJson -match 'DefaultPassword') 'Secret locations were lost.'
                Assert-Equal $before (Get-Json $report)
                $script:Checks++
            }
        }
    }
}

try {
    if ($Mode -eq 'Getters') {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace ADAnalyzer.OptionalMetadataFixture {
    public sealed class DeclaredReport {
        public static readonly List<string> Events = new List<string>();
        public object Gpo { get; set; }
        public object PolicyData, ReadErrorData, ErrorTypeData;
        public bool ThrowPolicy, ThrowReadError, ThrowErrorType;
        public object Policy {
            get {
                Events.Add("Policy");
                if (ThrowPolicy) {
                    throw new InvalidOperationException("fixture Policy getter");
                }
                return PolicyData;
            }
        }
        public object ReadError {
            get {
                Events.Add("ReadError");
                if (ThrowReadError) {
                    throw new InvalidOperationException("fixture ReadError getter");
                }
                return ReadErrorData;
            }
        }
        public object ErrorType {
            get {
                Events.Add("ErrorType");
                if (ThrowErrorType) {
                    throw new InvalidOperationException("fixture ErrorType getter");
                }
                return ErrorTypeData;
            }
        }
    }
}
'@
    }
    if ($Mode -eq 'Presence') {
        $root = Join-Path $script:Temporary 'policy'
        $pol = Join-Path $root 'Machine/Registry.pol'
        $xml = Join-Path $root 'Machine/Preferences/Groups/Groups.xml'
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($xml))
        [IO.File]::WriteAllText((Join-Path $root 'GPT.INI'), "[General]`nVersion=1")
        [IO.File]::WriteAllText($xml, '<Groups><User uid="fixture"><Properties userName="fixture" cpassword="OPTIONAL_METADATA_SECRET" /></User></Groups>')
        $bytes = [Text.Encoding]::ASCII.GetBytes('OPTIONAL_METADATA_SECRET')
        $writer = [IO.BinaryWriter]::new([IO.File]::Create($pol))
        try {
            $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'))
            $writer.Write([uint32]1)
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes('Software\Fixture' + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes('DefaultPassword' + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([uint32]3)
            $writer.Write([uint16]59)
            $writer.Write([uint32]$bytes.Length)
            $writer.Write([uint16]59)
            $writer.Write($bytes)
            $writer.Write([uint16]93)
        }
        finally {
            $writer.Dispose()
        }
        $beforePol = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pol))
        $beforeXml = [Convert]::ToBase64String([IO.File]::ReadAllBytes($xml))
        $native = [ADAnalyzerGpoReportService]::new().BuildReport(@{
            Gpo = New-Metadata
            Policy = [ADAnalyzerGpoReader]::new().Read($root)
            VersionMismatch = $false
        })
        Assert-Equal $true $native.Policy.RegistrySettings[0].SecretPresent
        Assert-Equal $null $native.Policy.RegistrySettings[0].PSObject.Properties['Value']
        $script:PresenceReports = @($native, (Get-Json $native | ConvertFrom-Json))
    }
    foreach ($strict in 'Off', '2.0', 'Latest') {
        foreach ($route in 'Command', 'Standalone') {
            Invoke-MetadataCase $strict $route
        }
    }
    if ($Mode -eq 'Presence') {
        Assert-Equal $beforePol ([Convert]::ToBase64String([IO.File]::ReadAllBytes($pol)))
        Assert-Equal $beforeXml ([Convert]::ToBase64String([IO.File]::ReadAllBytes($xml)))
    }
    Assert-Equal 0 $script:ExternalCalls.Count
    Write-Output ('PASS local-admin GPO optional metadata {0} {1}' -f $Mode, $script:Checks)
}
finally {
    [IO.Directory]::Delete($script:Temporary, $true)
}
