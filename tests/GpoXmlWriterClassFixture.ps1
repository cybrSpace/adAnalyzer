[CmdletBinding()]
param(
    [ValidateSet('Contracts', 'Direct', 'Uncaught')][string]$Case = 'Contracts',
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

# Exact accepted U-103 functions, before the renderer migration.
$script:HelperSource = @'
function Add-AnalyzerGpoXmlNode {
    param(
        [xml]$Document,
        [Xml.XmlNode]$Parent,
        [string]$Name,
        $Value

    )
    $node = $Document.CreateElement($Name)
    if ($null -ne $Value) {
        $node.PSBase.InnerText = [string]$Value
    }
    $null = $Parent.AppendChild($node)
    return $node
}
'@
$script:WriterSource = @'
function ConvertTo-AnalyzerGpoXml {
    param(
        $Gpo,
        $Parsed,
        [hashtable]$SidNames = @{},
        [hashtable]$SidStatus = @{}

    )
    $known = @{
        'S-1-5-32-544' = 'Administrators'
        'S-1-5-32-545' = 'Users'
        'S-1-5-32-546' = 'Guests'
        'S-1-5-32-551' = 'Backup Operators'
        'S-1-1-0' = 'Everyone'
        'S-1-5-11' = 'Authenticated Users'
        'S-1-5-18' = 'SYSTEM'
        'S-1-5-19' = 'LOCAL SERVICE'
        'S-1-5-20' = 'NETWORK SERVICE'
    }
    foreach ($key in ([Collections.IDictionary].GetProperty('Keys')).GetValue($SidNames, $null)) {
        $known[$key] = $SidNames[$key]
    }
    $doc = [xml]::new()
    $doc.XmlResolver = $null
    $g = $doc.CreateElement('GPO')
    $null = $doc.AppendChild($g)
    $null = Add-AnalyzerGpoXmlNode $doc $g 'ReadTime' ([datetime]::UtcNow.ToString('o'))
    $null = Add-AnalyzerGpoXmlNode $doc $g 'DirectoryVersion' $Gpo.Version
    $null = Add-AnalyzerGpoXmlNode $doc $g 'SysvolVersion' $Parsed.SysvolVersion
    $null = Add-AnalyzerGpoXmlNode $doc $g 'VersionMismatch' ([string]($null -ne $Parsed.SysvolVersion -and
            $null -ne $Gpo.Version -and
            $Parsed.SysvolVersion -ne ([long]$Gpo.Version -band [long]4294967295))).ToLowerInvariant()
    foreach ($link in @($Gpo.Links)) {
        $l = Add-AnalyzerGpoXmlNode $doc $g 'LinksTo'
        $null = Add-AnalyzerGpoXmlNode $doc $l 'SOMPath' $link.SOMPath
        $null = Add-AnalyzerGpoXmlNode $doc $l 'Enabled' ([string]$link.Enabled).ToLowerInvariant()
        $null = Add-AnalyzerGpoXmlNode $doc $l 'NoOverride' ([string]$link.Enforced).ToLowerInvariant()
    }
    foreach ($scope in @('Computer', 'User')) {
        $side = Add-AnalyzerGpoXmlNode $doc $g $scope
        $bit = if ($scope -eq 'Computer') {
            2
        }
        else {
            1
        }
        $null = Add-AnalyzerGpoXmlNode $doc $side 'Enabled' ([string](($Gpo.Flags -band $bit) -eq 0)).ToLowerInvariant()
        $settings = @($Parsed.SecuritySettings | Where-Object Scope -eq $scope)
        if ($settings.Count) {
            $ext = Add-AnalyzerGpoXmlNode $doc $side 'ExtensionData'
            $null = Add-AnalyzerGpoXmlNode $doc $ext 'Name' 'Security'
            $body = Add-AnalyzerGpoXmlNode $doc $ext 'Extension'
            foreach ($setting in $settings) {
                # A failed native assignment under Continue can leave an earlier value.
                $node = $null
                $node = Add-AnalyzerGpoXmlNode $doc $body $setting.Kind
                if ($null -eq $node) {
                    continue
                }
                if ($null -ne $setting.PSObject.Properties['ValueValid'] -and $null -ne $setting.ValueValid) {
                    $valid = $setting.ValueValid -is [bool] -and $setting.ValueValid
                    $null = Add-AnalyzerGpoXmlNode $doc $node 'ValueValid' ([string]$valid).ToLowerInvariant()
                }
                if ($null -ne $setting.PSObject.Properties['SecretPresent']) {
                    $null = Add-AnalyzerGpoXmlNode $doc $node 'Name' $setting.Name
                    $null = Add-AnalyzerGpoXmlNode $doc $node 'SecretPresent' ([string]$setting.SecretPresent).ToLowerInvariant()
                    if ($setting.Source) {
                        $null = Add-AnalyzerGpoXmlNode $doc $node 'Source' $setting.Source
                    }
                    continue
                }
                if ($setting.Kind -eq 'SecurityOptions') {
                    $display = Add-AnalyzerGpoXmlNode $doc $node 'Display'
                    $null = Add-AnalyzerGpoXmlNode $doc $display 'Name' $setting.Name
                    if ($setting.Value -is [bool]) {
                        $null = Add-AnalyzerGpoXmlNode $doc $display 'DisplayBoolean' ([string]$setting.Value).ToLowerInvariant()
                    }
                    else {
                        $null = Add-AnalyzerGpoXmlNode $doc $display 'DisplayString' $setting.Value
                    }
                }
                else {
                    $null = Add-AnalyzerGpoXmlNode $doc $node 'Name' $setting.Name
                    if ($setting.Kind -eq 'Account') {
                        if ($setting.Value -is [bool]) {
                            $null = Add-AnalyzerGpoXmlNode $doc $node 'SettingBoolean' ([string]$setting.Value).ToLowerInvariant()
                        }
                        elseif ($setting.Value -is [long]) {
                            $null = Add-AnalyzerGpoXmlNode $doc $node 'SettingNumber' $setting.Value
                        }
                        else {
                            $null = Add-AnalyzerGpoXmlNode $doc $node 'SettingString' $setting.Value
                        }
                    }
                    else {
                        foreach ($entry in @($setting.Value)) {
                            $member = Add-AnalyzerGpoXmlNode $doc $node 'Member'
                            $token = ([string]$entry).TrimStart('*')
                            if ($token -match '^S-\d-') {
                                $null = Add-AnalyzerGpoXmlNode $doc $member 'SID' $token
                                $status = 'NotAttempted'
                                if ($known.ContainsKey($token)) {
                                    $null = Add-AnalyzerGpoXmlNode $doc $member 'Name' $known[$token]
                                    $status = 'Resolved'
                                }
                                elseif ($SidStatus.ContainsKey($token)) {
                                    $status = $SidStatus[$token]
                                }
                                $null = Add-AnalyzerGpoXmlNode $doc $member 'Resolution' $status
                            }
                            else {
                                $null = Add-AnalyzerGpoXmlNode $doc $member 'Name' $token
                            }
                        }
                    }
                }
            }
        }
        foreach ($kind in @('Registry', 'Preferences', 'Xml', 'Ini')) {
            # Wrap the complete conditional: Windows PowerShell 5.1 does not
            # provide Count on a singleton PSCustomObject after pipeline unwrap.
            $rows = @(
                if ($kind -eq 'Registry') {
                    $Parsed.RegistrySettings | Where-Object Scope -eq $scope
                }
                elseif ($kind -eq 'Ini') {
                    $Parsed.IniSettings | Where-Object { $_.Scope -eq $scope -and -not $_.Analyzed }
                }
                else {
                    $Parsed.XmlFiles | Where-Object { $_.Scope -eq $scope -and $_.Kind -eq $kind }
                }
            )
            if (-not $rows.Count) {
                continue
            }
            $ext = Add-AnalyzerGpoXmlNode $doc $side 'ExtensionData'
            $null = Add-AnalyzerGpoXmlNode $doc $ext 'Name' $kind
            $body = Add-AnalyzerGpoXmlNode $doc $ext 'Extension'
            foreach ($row in $rows) {
                # A failed native read must leave this record's field empty.
                $label = $null
                $value = $null
                $record = Add-AnalyzerGpoXmlNode $doc $body 'Record'
                if ($kind -eq 'Registry') {
                    $label = '{0}\{1}\{2}' -f $row.Hive, $row.Key, $row.ValueName
                    $value = if ($null -eq $row.PSObject.Properties['Value'] -and
                        $null -ne $row.PSObject.Properties['SecretPresent']) {
                        $null
                    }
                    elseif ($row.Value -is [byte[]]) {
                        [System.Convert]::ToBase64String($row.Value)
                    }
                    elseif ($row.Value -is [array]) {
                        ConvertTo-Json -InputObject $row.Value -Compress
                    }
                    else {
                        [string]$row.Value
                    }
                    $null = Add-AnalyzerGpoXmlNode $doc $record 'Type' $row.Type
                }
                elseif ($kind -eq 'Ini') {
                    $label = '{0}: [{1}] {2}' -f $row.Source, $row.Section, $row.Name
                    $value = if ($null -eq $row.PSObject.Properties['Value'] -and
                        $null -ne $row.PSObject.Properties['SecretPresent']) {
                        $null
                    }
                    else {
                        $row.Value
                    }
                }
                else {
                    $label = $row.Path
                    $value = $row.Xml
                }
                $null = Add-AnalyzerGpoXmlNode $doc $record 'Name' $label
                if ($null -ne $row.PSObject.Properties['SecretPresent']) {
                    $null = Add-AnalyzerGpoXmlNode $doc $record 'SecretPresent' ([string]$row.SecretPresent).ToLowerInvariant()
                }
                else {
                    $null = Add-AnalyzerGpoXmlNode $doc $record 'Value' $value
                }
            }
        }
    }
    $inventory = Add-AnalyzerGpoXmlNode $doc $g 'FileInventory'
    foreach ($file in $Parsed.Files) {
        $node = Add-AnalyzerGpoXmlNode $doc $inventory 'File'
        $node.SetAttribute('Kind', $file.Kind)
        $node.PSBase.InnerText = $file.Path
    }
    return $doc.PSBase.OuterXml
}
'@
$script:Oracle = $script:HelperSource + [Environment]::NewLine + $script:WriterSource
$script:Frozen = [ordered]@{
    'Add-AnalyzerGpoXmlNode' = @{
        Text = $script:HelperSource
        Hash = '6ae1c314c37aca0cac0ac8a9b0d96504a68add3f9a32e4b53e863af030983dd8'
    }
    'ConvertTo-AnalyzerGpoXml' = @{
        Text = $script:WriterSource
        Hash = '4245dabb593e009b55e79a318a720c15f3e17b6bfa125db9638a16f488179cac'
    }
}
$script:Valid = @('Empty', 'Linked', 'Security', 'Registry', 'IniXml', 'Sid', 'Json', 'Ofs')
$script:Faults = @(
    'Version', 'Flags', 'NullNames', 'NullStatus', 'MissingKind', 'MissingValue',
    'BadScalar', 'InventoryKind', 'BadMemberStrict', 'BadMemberLoose'
)

function Assert-WriterFixture($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-WriterFixtureHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Assert-WriterFixtureBinding {
    foreach ($name in $script:Frozen.Keys) {
        $spec = $script:Frozen[$name]
        Assert-WriterFixture ((Get-WriterFixtureHash $spec.Text) -ieq $spec.Hash) "Frozen $name source changed."
        $tokens = $null
        $errors = $null
        $oracle = [Management.Automation.Language.Parser]::ParseInput($spec.Text, [ref]$tokens, [ref]$errors)
        $command = Get-Command $name -CommandType Function
        $actual = $command.ScriptBlock.Ast
        if ($actual -is [Management.Automation.Language.FunctionDefinitionAst]) {
            $actual = $actual.Body
        }
        Assert-WriterFixture (-not $command.CmdletBinding -and $errors.Count -eq 0 -and
            (Get-WriterFixtureHash $actual.ParamBlock.Extent.Text) -ceq
            (Get-WriterFixtureHash $oracle.EndBlock.Statements[0].Body.ParamBlock.Extent.Text)) "$name parameter binding changed."
    }
}

function Assert-WriterSame($Expected, $Actual, [string]$Context) {
    $before = ConvertTo-Json -InputObject $Expected -Depth 14 -Compress
    $after = ConvertTo-Json -InputObject $Actual -Depth 14 -Compress
    Assert-WriterFixture ($before -ceq $after) "$Context differs from the frozen same-engine writer."
}

function Get-WriterXml([string]$Text) {
    $time = ([xml]$Text).SelectSingleNode('/GPO/ReadTime')
    $parsed = [datetime]::MinValue
    Assert-WriterFixture ($null -ne $time -and
        [datetime]::TryParse($time.InnerText,
            [ref]$parsed)) 'The writer did not emit a valid ReadTime.'
    $Text -replace '(?<=<ReadTime>)[^<]*(?=</ReadTime>)', 'fixture-time'
}

function New-WriterSecurity([string]$Kind, [string]$Name, $Value, [string]$Scope = 'Computer') {
    [pscustomobject]@{
        Scope = $Scope
        Kind = $Kind
        Name = $Name
        Value = $Value
    }
}

function New-WriterRegistry([string]$Name, [int]$Type, $Value) {
    [pscustomobject]@{
        Scope = 'Computer'
        Hive = 'HKLM'
        Key = 'Software\Fixture'
        ValueName = $Name
        Type = $Type
        Value = $Value
    }
}

function New-WriterInput([string]$Name) {
    $gpo = [pscustomobject]@{
        Version = 1
        Flags = 0
        Links = @()
    }
    $policy = [pscustomobject]@{
        SysvolVersion = 1
        SecuritySettings = @()
        RegistrySettings = @()
        IniSettings = @()
        XmlFiles = @()
        Files = @()
    }
    $names = @{}
    $status = @{}
    $explicit = $false
    $linked = $Name -in 'Linked', 'Json'
    $security = $Name -in 'Security', 'Json', 'MissingKind', 'BadScalar'
    $registry = $Name -in 'Registry', 'Json', 'MissingValue'
    $extensions = $Name -in 'IniXml', 'Json'
    if ($linked) {
        $gpo.Flags = 1
        $gpo.Links = @(
            [pscustomobject]@{
                SOMPath = 'OU=One & Two,DC=fixture'
                Enabled = $true
                Enforced = $false
            }
            [pscustomobject]@{
                SOMPath = 'OU=Other,DC=fixture'
                Enabled = $false
                Enforced = $true
            }
        )
        $policy.SysvolVersion = 2
        $policy.Files = @([pscustomobject]@{
                Kind = 'Policy'
                Path = 'Machine/Registry & fixture.pol'
            })
    }
    if ($security) {
        $policy.SecuritySettings = @(
            [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Account'
                Name = 'Boolean'
                Value = $false
                ValueValid = $true
            }
            New-WriterSecurity Account Number 17L
            New-WriterSecurity Account Text '<fixture & text>'
            New-WriterSecurity SecurityOptions Option $true
            [pscustomobject]@{
                Scope = 'User'
                Kind = 'SecurityOptions'
                Name = 'Password'
                SecretPresent = $false
                Source = 'Fixture.inf'
            }
        )
    }
    if ($registry) {
        $policy.RegistrySettings = @(
            New-WriterRegistry Binary 3 ([byte[]]@(19, 42))
            New-WriterRegistry Multi 7 ([string[]]@('a', 'b'))
            New-WriterRegistry ExplicitNull 3 $null
            [pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Password'
                Type = 3
                SecretPresent = $true
            }
        )
    }
    if ($extensions) {
        $policy.IniSettings = @(
            [pscustomobject]@{
                Scope = 'Computer'
                Source = 'fixture.ini'
                Section = 'Fixture'
                Name = 'Option'
                Value = 'plain <&>'
                Analyzed = $false
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Source = 'fixture.ini'
                Section = 'Fixture'
                Name = 'Password'
                SecretPresent = $false
                Analyzed = $false
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Source = 'fixture.ini'
                Section = 'Fixture'
                Name = 'AlreadyAnalyzed'
                Value = 12
                Analyzed = $true
            }
        )
        $policy.XmlFiles = @(
            [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Preferences'
                Path = 'Machine/preferences.xml'
                Xml = '<Fixture preferences="true" />'
            }
            [pscustomobject]@{
                Scope = 'User'
                Kind = 'Xml'
                Path = 'User/ordinary.xml'
                Xml = '<Fixture>ordinary</Fixture>'
            }
        )
    }
    if ($Name -in 'Sid', 'NullNames', 'NullStatus') {
        $policy.SecuritySettings = @(New-WriterSecurity UserRightsAssignment 'Fixture right' @('*S-1-5-32-544',
                '*S-1-5-21-1-2-3-10',
                '*S-1-5-21-1-2-3-11',
                'Fixture user'))
        $names = @{
            'S-1-5-21-1-2-3-10' = 'Fixture resolved'
        }
        $status = @{
            'S-1-5-21-1-2-3-11' = 'Unreadable'
        }
        $explicit = $true
        if ($Name -eq 'NullNames') {
            $names = $null
        }
        if ($Name -eq 'NullStatus') {
            $status = $null
        }
    }
    switch ($Name) {
        'Ofs' {
            $policy.SecuritySettings = @(New-WriterSecurity Account 'Fixture array' @('alpha', 'beta'))
        }
        'Version' {
            $gpo.Version = 'fixture invalid version'
        }
        'Flags' {
            $gpo.Flags = 'fixture invalid flags'
        }
        'MissingKind' {
            $policy.SecuritySettings[1].PSObject.Properties.Remove('Kind')
        }
        'MissingValue' {
            $policy.RegistrySettings[1].PSObject.Properties.Remove('Value')
        }
        'InventoryKind' {
            $policy.Files = @([pscustomobject]@{
                    Path = 'Machine/first'
                }, [pscustomobject]@{
                    Kind = 'File'
                    Path = 'Machine/tail'
                })
        }
        'BadScalar' {
            $policy.SecuritySettings[1].Value = [WriterFixtureBadScalar]::new()
        }
        { $_ -in 'BadMemberStrict', 'BadMemberLoose' } {
            $policy.SecuritySettings += [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'UserRightsAssignment'
                Name = 'First member has no usable text'
                Value = @([WriterFixtureBadScalar]::new(), 'S-1-5-18')
            }
        }
    }
    $result = [pscustomobject]@{
        Gpo = $gpo
        Policy = $policy
        Names = $names
        Status = $status
        Explicit = $explicit
    }
    if ($Name -eq 'Json') {
        return (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $result -Depth 15 -Compress))
    }
    $result
}

function Get-WriterFixtureError([Management.Automation.ErrorRecord]$Item) {
    $cause = $Item.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Invoke-WriterObservation([string]$Name, [string]$Route, [string]$Action, [bool]$Catch, $Service) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:Oracle))
    }
    $data = New-WriterInput $Name
    $before = ConvertTo-Json -InputObject $data -Depth 18 -Compress
    if ($Name -eq 'BadMemberLoose') {
        Set-StrictMode -Off
    }
    else {
        Set-StrictMode -Version Latest
    }
    if ($Name -eq 'BadMemberStrict') {
        $token = 'fixture-caller-token'
    }
    if ($Name -eq 'Ofs') {
        $OFS = '|'
    }
    $ErrorActionPreference = $Action
    $global:Error.Clear()
    $operation = {
        if ($Route -eq 'Direct') {
            if ($data.Explicit) {
                $Service.Render($data.Gpo, $data.Policy, $data.Names, $data.Status)
            }
            else {
                $Service.Render($data.Gpo, $data.Policy)
            }
        }
        elseif ($data.Explicit) {
            ConvertTo-AnalyzerGpoXml $data.Gpo $data.Policy $data.Names $data.Status
        }
        else {
            ConvertTo-AnalyzerGpoXml $data.Gpo $data.Policy
        }
    }
    $output = @()
    $caught = $null
    if ($Catch) {
        try {
            $output = @(& $operation 3>&1 2>&1)
        }
        catch {
            $caught = Get-WriterFixtureError $_
        }
    }
    else {
        $output = @(& $operation 3>&1 2>&1)
    }
    $diagnostics = @($global:Error | ForEach-Object { Get-WriterFixtureError $_ })
    $stream = @(foreach ($item in $output) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                Get-WriterFixtureError $item
            }
            elseif ($item -is [Management.Automation.WarningRecord]) {
                [pscustomobject]@{
                    Warning = $item.Message
                }
            }
            else {
                [pscustomobject]@{
                    Xml = (Get-WriterXml $item)
                }
            }
        })
    [pscustomobject]@{
        Stream = $stream
        Caught = $caught
        Diagnostics = $diagnostics
        Unchanged = $before -ceq (ConvertTo-Json -InputObject $data -Depth 18 -Compress)
    }
}

function Invoke-WriterHelper([bool]$Frozen, [string]$Mode) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:Oracle))
    }
    Set-StrictMode -Version Latest
    $doc = [xml]'<Fixture/>'
    $name = 'Item'
    if ($Mode -ne 'Valid') {
        $name = 'Invalid Kind'
    }
    $output = @()
    $caught = $null
    $ErrorActionPreference = 'Continue'
    if ($Mode -eq 'Stop') {
        $ErrorActionPreference = 'Stop'
        try {
            $output = @(Add-AnalyzerGpoXmlNode $doc $doc.DocumentElement $name '<fixture & text>' 2>&1)
        }
        catch {
            $caught = Get-WriterFixtureError $_
        }
    }
    else {
        $output = @(Add-AnalyzerGpoXmlNode $doc $doc.DocumentElement $name '<fixture & text>' 2>&1)
    }
    [pscustomobject]@{
        Report = $doc.OuterXml
        Caught = $caught
        Items = @(foreach ($item in $output) {
                if ($item -is [Management.Automation.ErrorRecord]) {
                    Get-WriterFixtureError $item
                }
                elseif ($null -eq $item) {
                    [pscustomobject]@{
                        Node = $null
                    }
                }
                else {
                    [pscustomobject]@{
                        Node = $item.PSBase.OuterXml
                    }
                }
            })
    }
}

if ($Case -ne 'Direct') {
    Add-Type @'
public sealed class WriterFixtureBadScalar
{
    public override string ToString()
    {
        throw new System.InvalidOperationException("fixture scalar conversion failure");
    }
}
'@
}

if ($Case -eq 'Uncaught') {
    $route = 'Command'
    if ($Original) {
        $route = 'Original'
    }
    $observations = @(foreach ($name in $script:Faults) {
            Invoke-WriterObservation $name $route Continue $false $null
        })
    $helper = Invoke-WriterHelper ([bool]$Original) Continue
    ConvertTo-Json -InputObject ([pscustomobject]@{
            Observations = $observations
            Helper = $helper
        }) -Depth 14 -Compress
    exit
}

function Invoke-WriterChild([bool]$Frozen) {
    $exe = (Get-Process -Id $PID).Path
    $arguments = @('-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-File',
        $PSCommandPath,
        '-Case',
        'Uncaught',
        '-RepositoryRoot',
        $RepositoryRoot)
    if ($Frozen) {
        $arguments += '-Original'
    }
    $lines = @(& $exe @arguments 2>&1)
    Assert-WriterFixture ($LASTEXITCODE -eq 0 -and $lines.Count -eq 1) 'Uncaught writer child did not produce its boxed result.'
    ConvertFrom-Json -InputObject ([string]$lines[0])
}

Assert-WriterFixtureBinding
$count = 1
$route = 'Command'
$service = $null
if ($Case -eq 'Direct') {

    function ConvertTo-AnalyzerGpoXml {
        throw 'The object renderer called its compatibility writer.'
    }
    $service = & {

        function Read-ADAnalyzerGpo {
            throw 'Writer construction tried to read policy.'
        }
        [ADAnalyzerGpoXmlWriter]::new()
    }
    Assert-WriterFixture ($service.GetType().Name -ceq 'ADAnalyzerGpoXmlWriter') 'Literal writer construction failed.'
    $route = 'Direct'
}
foreach ($name in $script:Valid) {
    $expected = Invoke-WriterObservation $name Original Stop $true $null
    $actual = Invoke-WriterObservation $name $route Stop $true $service
    Assert-WriterFixture ($expected.Stream.Count -eq 1 -and $null -eq $expected.Caught -and
        $expected.Unchanged -and
        $null -ne $expected.Stream[0].PSObject.Properties['Xml']) "Frozen $name did not return one unmodified XML result."
    if ($name -eq 'Ofs') {
        Assert-WriterFixture ($expected.Stream[0].Xml.Contains('alpha|beta')) 'The scalar observation did not exercise OFS.'
    }
    Assert-WriterSame $expected $actual "$Case/$name"
    $count++
}

if ($Case -eq 'Contracts') {
    $oldChild = Invoke-WriterChild $true
    $newChild = Invoke-WriterChild $false
    for ($i = 0; $i -lt $script:Faults.Count; $i++) {
        $name = $script:Faults[$i]
        $expected = $oldChild.Observations[$i]
        $actual = $newChild.Observations[$i]
        Assert-WriterFixture ($expected.Stream.Count -ge 2 -and $null -ne $expected.Stream[0].PSObject.Properties['Id'] -and
            $null -ne $expected.Stream[-1].PSObject.Properties['Xml'] -and
            $expected.Unchanged) "Frozen uncaught $name did not emit a primary error and one XML result."
        if ($name -in 'BadMemberStrict', 'BadMemberLoose') {
            Assert-WriterFixture ($expected.Stream.Count -eq 2 -and
                $expected.Stream[-1].Xml.Contains('<Member><Name /></Member>') -and
                $expected.Stream[-1].Xml.Contains('<SID>S-1-5-18</SID>') -and
                -not $expected.Stream[-1].Xml.Contains('fixture-caller-token')) "Frozen $name did not preserve token isolation."
        }
        Assert-WriterSame $expected $actual "Uncaught $name"
        foreach ($action in @('Continue', 'Stop')) {
            $expected = Invoke-WriterObservation $name Original $action $true $null
            $actual = Invoke-WriterObservation $name Command $action $true $null
            Assert-WriterSame $expected $actual "Caught $name/$action"
            if ($action -eq 'Stop') {
                Assert-WriterFixture ($null -ne $expected.Caught -and $expected.Stream.Count -eq 0) "Frozen $name/Stop produced output."
            }
        }
        $count++
    }
    $expected = Invoke-WriterHelper $true Valid
    $actual = Invoke-WriterHelper $false Valid
    Assert-WriterFixture ($expected.Items.Count -eq 1 -and
        $expected.Report.Contains('&lt;fixture &amp; text&gt;')) 'The frozen helper did not append one escaped DOM element.'
    Assert-WriterSame $expected $actual 'Valid DOM helper'
    $count++
    Assert-WriterSame $oldChild.Helper $newChild.Helper 'Uncaught DOM helper'
    Assert-WriterFixture ($oldChild.Helper.Items.Count -gt 0 -and
        $oldChild.Helper.Items[0].Cause -ceq 'System.Xml.XmlException' -and
        $oldChild.Helper.Report -eq '<Fixture />') 'Frozen DOM helper did not exercise native element failure.'
    Assert-WriterSame (Invoke-WriterHelper $true Stop) (Invoke-WriterHelper $false Stop) 'Stopped DOM helper'
    $count++
}
else {
    foreach ($name in @('Version', 'MissingKind')) {
        $expected = Invoke-WriterObservation $name Original Stop $true $null
        $actual = Invoke-WriterObservation $name Direct Stop $true $service
        Assert-WriterFixture ($null -ne $actual.Caught -and $actual.Caught.Message -ceq $expected.Caught.Message -and
            $actual.Stream.Count -eq 0 -and $actual.Unchanged) "Direct $name did not surface its failure without a partial report."
        $count++
    }
    $data = New-WriterInput Sid
    $names = $data.Names
    $status = $data.Status
    $explicit = Get-WriterXml ($service.Render($data.Gpo, $data.Policy, $names, $status))
    $defaults = Get-WriterXml ($service.Render($data.Gpo, $data.Policy))
    $independent = [ADAnalyzerGpoXmlWriter]::new()
    $fresh = Get-WriterXml ($independent.Render($data.Gpo, $data.Policy))
    Assert-WriterFixture ($explicit.Contains('Fixture resolved') -and -not $defaults.Contains('Fixture resolved') -and
        $defaults.Contains('Administrators') -and $fresh -ceq $defaults) 'A prior SID map changed default or independent rendering.'
    $count++
}
Write-Host "PASS GPO XML writer $Case $count"
