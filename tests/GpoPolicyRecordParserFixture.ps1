[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Records', 'Faults', 'Direct', 'Uncaught')]
    [string]$Case = 'Records',
    [string]$Fault,
    [ValidateSet('Continue', 'Stop')]
    [string]$Preference = 'Continue',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'bin/ADAnalyzer.ps1')

# Verbatim parser definitions from accepted revision 2b256d9.
$script:OriginalGpoParser = @'
function Get-ADAnalyzerPolicyXmlPath {
    param([Xml.XmlNode]$Node)
    $parts = @()
    while ($Node -and $Node.PSBase.NodeType -eq [Xml.XmlNodeType]::Element) {
        $uid = Get-ADAnalyzerXmlAttribute $Node uid
        if ($uid) {
            $parts = @($Node.PSBase.LocalName + '#' + $uid) + $parts
            break
        }
        $position = 1
        $sibling = $Node.PSBase.PreviousSibling
        while ($sibling) {
            if ($sibling.PSBase.NodeType -eq [Xml.XmlNodeType]::Element -and $sibling.PSBase.LocalName -eq $Node.PSBase.LocalName) {
                $position++
            }
            $sibling = $sibling.PSBase.PreviousSibling
        }
        $parts = @($Node.PSBase.LocalName + '[' + $position + ']') + $parts
        $Node = $Node.PSBase.ParentNode
    }
    return $parts -join '/'
}

function Resolve-ADAnalyzerPolicyIdentityCollisions {
    param([string[]]$Targets)
    $counts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    $seen = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($identity in $Targets) {
        if ($counts.ContainsKey($identity)) {
            $counts[$identity]++
        }
        else {
            $counts[$identity] = 1
        }
    }
    foreach ($identity in $Targets) {
        if ($counts[$identity] -eq 1) {
            $identity
            continue
        }
        if ($seen.ContainsKey($identity)) {
            $seen[$identity]++
        }
        else {
            $seen[$identity] = 1
        }
        $identity + '/duplicate/' + $seen[$identity].ToString([Globalization.CultureInfo]::InvariantCulture)
    }
}

function Test-ADAnalyzerSecurityTemplateSource {
    param(
        [string]$Scope,
        [string]$Source

    )
    $relative = ([string]$Source).Replace('\', '/')
    ($Scope -ieq 'Computer' -and $relative -ieq 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf') -or
    ($Scope -ieq 'User' -and $relative -ieq 'User/Microsoft/Windows NT/SecEdit/GptTmpl.inf')
}

function ConvertFrom-ADAnalyzerRestrictedGroups {
    [CmdletBinding()]
    param([object[]]$IniSettings)
    foreach ($setting in @($IniSettings | Where-Object { $_.Section -ieq 'Group Membership' -and
                (Test-ADAnalyzerSecurityTemplateSource `
                    -Scope $_.Scope `
                    -Source $_.Source) })) {
        $match = [regex]::Match([string]$setting.Name,
            '^(?<group>.+)__(?<mode>Members|Memberof)$',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $valid = $match.Success
        $group = $null
        $members = @()
        $errorText = $null
        try {
            if ($valid) {
                $group = ConvertFrom-ADAnalyzerPolicyPrincipal $match.Groups['group'].Value
                $valid = $group.Valid
                if (-not [string]::IsNullOrWhiteSpace([string]$setting.Value)) {
                    $members = @(Split-AnalyzerPolicyCsv ([string]$setting.Value) | ForEach-Object { $_ } | ForEach-Object { ConvertFrom-ADAnalyzerPolicyPrincipal $_ })
                    if (@($members | Where-Object { -not $_.Valid }).Count) {
                        $valid = $false
                    }
                }
            }
        }
        catch {
            $valid = $false
            $errorText = 'Malformed group membership value'
        }
        [pscustomobject]@{
            Scope = $setting.Scope
            Source = $setting.Source
            GroupSid = $group.Sid
            GroupName = $group.Name
            Mode = $match.Groups['mode'].Value
            Members = $members
            Valid = $valid
            Error = $errorText
            SettingName = $setting.Name
        }
    }
}

function Get-ADAnalyzerPolicyXmlRecords {
    param([object[]]$XmlFiles)
    foreach ($file in @($XmlFiles)) {
        try {
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $text = [IO.StringReader]::new([string]$file.Xml)
            $reader = [Xml.XmlReader]::Create($text, $settings)
            try {
                $doc = [xml]::new()
                $doc.XmlResolver = $null
                $doc.Load($reader)
            }
            finally {
                $reader.Dispose()
                $text.Dispose()
            }
            [pscustomobject]@{
                File = $file
                Document = $doc
                Valid = $true
            }
        }
        catch {
            [pscustomobject]@{
                File = $file
                Document = $null
                Valid = $false
            }
        }
    }
}

function ConvertFrom-ADAnalyzerLocalUsersGroups {
    [CmdletBinding()]
    param([object[]]$XmlFiles)
    foreach ($record in @(Get-ADAnalyzerPolicyXmlRecords $XmlFiles)) {
        if (-not $record.Valid) {
            continue
        }
        if ($record.Document.PSBase.DocumentElement.PSBase.LocalName -ine 'Groups') {
            continue
        }
        foreach ($item in @($record.Document.PSBase.DocumentElement.PSBase.ChildNodes | Where-Object { $_.PSBase.NodeType -eq [Xml.XmlNodeType]::Element -and
                    $_.PSBase.LocalName -in 'Group',
                    'User' })) {
            $properties = $item.SelectSingleNode('./*[local-name()="Properties"]')
            $members = @()
            foreach ($member in @($(if ($properties) {
                            $properties.SelectNodes('./*[local-name()="Members"]/*[local-name()="Member"]')
                        }))) {
                $sid = Get-ADAnalyzerXmlAttribute $member sid
                $principal = ConvertFrom-ADAnalyzerPolicyPrincipal $(if ($sid) {
                        $sid
                    }
                    else {
                        Get-ADAnalyzerXmlAttribute $member name
                    })
                if ($sid -and -not (Test-ADAnalyzerPolicySid $sid)) {
                    $principal.Valid = $false
                }
                $members += [pscustomobject]@{
                    Sid = $principal.Sid
                    Name = $principal.Name
                    Valid = $principal.Valid
                    Action = (Get-ADAnalyzerXmlAttribute $member action).ToUpperInvariant()
                }
            }
            $action = (Get-ADAnalyzerXmlAttribute $properties action).ToUpperInvariant()
            $filters = $item.SelectSingleNode('./*[local-name()="Filters"]')
            $disabled = Get-ADAnalyzerXmlAttribute $item disabled '0'
            $targetSid = Get-ADAnalyzerXmlAttribute $properties groupSid
            if ($item.PSBase.LocalName -eq 'User') {
                $targetSid = Get-ADAnalyzerXmlAttribute $properties userSid (Get-ADAnalyzerXmlAttribute $properties sid)
            }
            $targetName = Get-ADAnalyzerXmlAttribute $properties $(if ($item.PSBase.LocalName -eq 'Group') {
                    'groupName'
                }
                else {
                    'userName'
                })
            $sidValid = -not $targetSid -or (Test-ADAnalyzerPolicySid $targetSid)
            [pscustomobject]@{
                Scope = $record.File.Scope
                Source = $record.File.Path
                Kind = $item.PSBase.LocalName
                Uid = (Get-ADAnalyzerXmlAttribute $item uid)
                ItemPath = (Get-ADAnalyzerPolicyXmlPath $item)
                Name = $targetName
                Sid = $targetSid
                Action = $action
                Disabled = ($disabled -in '1', 'true')
                AccountDisabled = (Get-ADAnalyzerXmlAttribute $properties disabled)
                PasswordNeverExpires = (Get-ADAnalyzerXmlAttribute $properties neverExpires)
                Targeted = ($null -ne $filters -and $filters.PSBase.HasChildNodes)
                Filters = (Get-ADAnalyzerPresencePolicyXml $filters)
                DeleteAllUsers = (Get-ADAnalyzerXmlAttribute $properties deleteAllUsers '0') -in '1', 'true'
                DeleteAllGroups = (Get-ADAnalyzerXmlAttribute $properties deleteAllGroups '0') -in '1', 'true'
                RemovePolicy = (Get-ADAnalyzerXmlAttribute $item removePolicy '0') -in '1', 'true'
                Members = $members
                Valid = ($null -ne $properties -and
                    $sidValid -and
                    $disabled -in '0',
                    '1',
                    'true',
                    'false' -and
                    $action -in 'C',
                    'U',
                    'R',
                    'D' -and
                    @($members | Where-Object { -not $_.Valid -or
                            $_.Action -notin 'ADD',
                            'REMOVE' }).Count -eq 0)
            }
        }
    }
}
'@
$script:OriginalParserHashes = @{
    'Get-ADAnalyzerPolicyXmlPath' = '8469208e46354996ce3b52803b0765690fee546de81459a640d517c95d7754e2'
    'Resolve-ADAnalyzerPolicyIdentityCollisions' = '2d232d0cbd18dadbf819cb345e62bb425e782479350799959447256a05c3a7ef'
    'Test-ADAnalyzerSecurityTemplateSource' = 'eaf70119c25afd7ab224ccbae4529c70c6c19595a1ce645d30ebb3e275774da6'
    'ConvertFrom-ADAnalyzerRestrictedGroups' = 'c15a726c80bbd159bde7b1ebaafd44f14026998b92fc76ca192aa3ca781d974d'
    'Get-ADAnalyzerPolicyXmlRecords' = '2d726386cef59bbea3b8df28920c81f38d956410f6f78a4c07ce2f1e55addbc5'
    'ConvertFrom-ADAnalyzerLocalUsersGroups' = '01692aed0bbe7d9b1d79dd8ccac96e76217213010df7f338e5621215fa38f496'
}
$script:ParserCommands = [ordered]@{
    GetXmlPath = 'Get-ADAnalyzerPolicyXmlPath'
    ResolveIdentities = 'Resolve-ADAnalyzerPolicyIdentityCollisions'
    IsSecurityTemplateSource = 'Test-ADAnalyzerSecurityTemplateSource'
    ParseRestrictedGroups = 'ConvertFrom-ADAnalyzerRestrictedGroups'
    ReadXmlRecords = 'Get-ADAnalyzerPolicyXmlRecords'
    ParseLocalUsersGroups = 'ConvertFrom-ADAnalyzerLocalUsersGroups'
}
$script:SyntheticMarker = 'GP_FIXTURE_STATIC_SENTINEL_087'

function Assert-RecordParser($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-RecordParserAsts([string]$Text) {
    $tokens = $null
    $errors = $null
    $parsed = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    Assert-RecordParser ($errors.Count -eq 0) 'Policy parser source did not parse.'
    $parsed.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $script:OriginalParserHashes.ContainsKey($_.Name)
    }
}

function Assert-RecordParserHashes([string]$Text) {
    $definitions = @(Get-RecordParserAsts $Text)
    Assert-RecordParser ($definitions.Count -eq 6) 'Frozen parser is missing functions.'
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($definition in $definitions) {
            $source = $definition.Extent.Text.Replace([string][char]13 + [char]10, [string][char]10)
            $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source))).Replace('-', '')
            Assert-RecordParser ($hash -ieq $script:OriginalParserHashes[$definition.Name]) "Frozen parser hash changed: $($definition.Name)."
        }
    }
    finally {
        $sha.Dispose()
    }
}

Assert-RecordParserHashes $script:OriginalGpoParser

function Get-RecordParserParamText([string]$Name) {
    $ast = (Get-Command -Name $Name -CommandType Function).ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    $original = $ast.ParamBlock.Extent.Text
    $original.Replace([string][char]13 + [char]10, [string][char]10)
}

function Assert-RecordParserParameters {
    $current = @{}
    foreach ($name in $script:ParserCommands.Values) {
        $current[$name] = Get-RecordParserParamText $name
    }
    . ([scriptblock]::Create($script:OriginalGpoParser))
    foreach ($name in $script:ParserCommands.Values) {
        Assert-RecordParser ((Get-RecordParserParamText $name) -ceq $current[$name]) "Parser parameter contract changed for $name."
    }
}

function ConvertTo-RecordParserJson($Value) {
    if ($null -eq $Value) {
        return 'null'
    }
    $json = ConvertTo-Json -InputObject $Value -Compress -Depth 22
    Assert-RecordParser (-not $json.Contains($script:SyntheticMarker)) 'A synthetic XML source marker reached policy output.'
    $json
}

function Assert-RecordParserSame($Expected, $Actual, [string]$Label) {
    $before = ConvertTo-RecordParserJson $Expected
    $after = ConvertTo-RecordParserJson $Actual
    Assert-RecordParser ($before -ceq $after) "$Label differs. Expected $before; actual $after"
}

function Get-RecordParserTyped($Value) {
    if ($null -eq $Value) {
        return [pscustomobject]@{
            Type = '<null>'
            Value = $null
        }
    }
    $type = $Value.GetType().FullName
    if ($type -ceq 'System.Management.Automation.PSCustomObject') {
        return [pscustomobject]@{
            Type = $type
            Fields = @(
                foreach ($property in $Value.PSObject.Properties) {
                    [pscustomobject]@{
                        Name = $property.Name
                        Data = Get-RecordParserTyped $property.Value
                    }
                }
            )
        }
    }
    if ($Value -is [array]) {
        return [pscustomobject]@{
            Type = $type
            Items = @(foreach ($item in $Value) {
                    Get-RecordParserTyped $item
                })
        }
    }
    if ($Value -is [Xml.XmlNode]) {
        return [pscustomobject]@{
            Type = $type
            Value = $Value.PSBase.OuterXml
        }
    }
    if ($Value -is [GpoParserUnstringable]) {
        return [pscustomobject]@{
            Type = $type
            Value = $Value.Observation
        }
    }
    [pscustomobject]@{
        Type = $type
        Value = $Value
    }
}

if ($null -eq ('GpoParserUnstringable' -as [type])) {
    Add-Type -TypeDefinition @'
using System;

public sealed class GpoParserUnstringable
{
    public string Observation { get; private set; }

    public GpoParserUnstringable(string observation)
    {
        Observation = observation;
    }

    public override string ToString()
    {
        throw new InvalidOperationException("synthetic restricted observation " + Observation);
    }
}
'@
}

function New-RecordParserIni($Name,
    $Value,
    [string]$Scope = 'Computer',
    [string]$Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf',
    [string]$Section = 'Group Membership') {
    [pscustomobject][ordered]@{
        Section = $Section
        Name = $Name
        Value = $Value
        Scope = $Scope
        Source = $Source
    }
}

function New-RecordParserFile([string]$Name, [string]$Text, [bool]$Tracked = $false) {
    if (-not $Tracked) {
        return [pscustomobject]@{
            Path = $Name
            Scope = 'Computer'
            Xml = $Text
        }
    }
    $file = [pscustomobject]@{
        FixtureName = $Name
        FixtureXml = $Text
    }
    $file.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Xml', {
                $script:ParserTrace.Add('Read:' + $this.FixtureName)
                $this.FixtureXml
            }))
    $file.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Path', {
                $script:ParserTrace.Add('Path:' + $this.FixtureName)
                $this.FixtureName
            }))
    $file.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Scope', {
                $script:ParserTrace.Add('Scope:' + $this.FixtureName)
                'Computer'
            }))
    $file
}

function New-RecordParserTrackedIni([string]$Tag, [bool]$Ignore) {
    $section = 'Group Membership'
    if ($Ignore) {
        $section = 'Suppressed fixture section'
    }
    $setting = [pscustomobject]@{
        FixtureTag = $Tag
        FixtureSection = $section
        Value = ''
        Scope = 'Computer'
    }
    $setting.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Section', {
                $script:ParserTrace.Add('Section:' + $this.FixtureTag)
                $this.FixtureSection
            }))
    $setting.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Name', {
                $script:ParserTrace.Add('Name:' + $this.FixtureTag)
                'fixture group__Members'
            }))
    $setting.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Source', {
                $script:ParserTrace.Add('Source:' + $this.FixtureTag)
                'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            }))
    $setting
}

$script:ParserBusiness = @(
    'PathNull', 'PathDocument', 'PathText', 'PathRoot', 'PathSibling', 'PathUidAncestor', 'PathUidCurrent', 'PathMetadata',
    'IdentityNull', 'IdentityEmpty', 'IdentityBlank', 'IdentityCasing', 'IdentityUnicode', 'IdentityLiteralSuffix',
    'TemplateComputer',
    'TemplateComputerSlashes',
    'TemplateUser',
    'TemplateMismatch',
    'TemplateScopeAlias',
    'TemplateNull',
    'TemplateOther',
    'RestrictedNull',
    'RestrictedEmpty',
    'RestrictedAuthoritative',
    'RestrictedMalformedName',
    'RestrictedInvalidSids',
    'RestrictedEmptyAssignment',
    'RestrictedTrace',
    'XmlNull', 'XmlEmpty', 'XmlNullItem', 'XmlMixedRecovery', 'XmlReadOrder', 'XmlDuplicateFile',
    'LocalNull', 'LocalEmpty', 'LocalMixedRecovery', 'LocalInvalidProperties', 'LocalNamespace', 'LocalReadOrder'
)
$script:ParserFaults = @('IdentityNullElement', 'RestrictedNameFault', 'RestrictedValueFault')

function New-RecordParserSample([string]$Name) {
    $inf = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
    $groups = '<Groups><Group uid="sample"><Properties action="U" groupName="Fixture" /></Group></Groups>'
    $malformed = '<Groups><Group></Groups>'
    $dtd = '<!DOCTYPE Groups [<!ENTITY sample "fixture">]><Groups>&sample;</Groups>'
    switch -Wildcard ($Name) {
        'Path*' {
            $doc = [xml]'<r xmlns:p="urn:p"><p:Item/><item uid="nearest"><Child>fixture</Child></item><Item><NodeType/><LocalName/><PreviousSibling/></Item></r>'
            $node = switch ($Name) {
                PathDocument {
                    , $doc
                }
                PathText {
                    , $doc.SelectSingleNode('/r/item/Child/text()')
                }
                PathRoot {
                    , $doc.DocumentElement
                }
                PathSibling {
                    , $doc.SelectSingleNode('/r/Item')
                }
                PathUidAncestor {
                    , $doc.SelectSingleNode('/r/item/Child')
                }
                PathUidCurrent {
                    , $doc.SelectSingleNode('/r/item')
                }
                PathMetadata {
                    , $doc.SelectSingleNode('/r/Item/LocalName')
                }
            }
            return @{
                Method = 'GetXmlPath'
                Arguments = @{
                    Node = $node
                }
            }
        }
        'Identity*' {
            $targets = $null
            switch ($Name) {
                IdentityEmpty {
                    $targets = [string[]]@()
                }
                IdentityBlank {
                    $targets = [string[]]@('')
                }
                IdentityCasing {
                    $targets = [string[]]@('a', 'B', 'A', 'b', 'first', 'A')
                }
                IdentityUnicode {
                    $targets = [string[]]@('ø', 'Ø', 'ångström', 'ÅNGSTRÖM')
                }
                IdentityLiteralSuffix {
                    $targets = [string[]]@('a', 'a/duplicate/1', 'A')
                }
                IdentityNullElement {
                    $targets = [string[]]::new(4)
                    $targets.SetValue('before', 0)
                    $targets.SetValue('after', 2)
                    $targets.SetValue('AFTER', 3)
                    Assert-RecordParser ($null -eq $targets[1]) 'The fixture did not contain a CLR null identity.'
                }
            }
            return @{
                Method = 'ResolveIdentities'
                Arguments = @{
                    Targets = $targets
                }
            }
        }
        'Template*' {
            $cases = @{
                TemplateComputer = @('Computer', $inf)
                TemplateComputerSlashes = @('COMPUTER', 'MACHINE\Microsoft\Windows NT\SecEdit\GPTTMPL.INF')
                TemplateUser = @('User', 'USER/Microsoft/Windows NT/SecEdit/GptTmpl.inf')
                TemplateMismatch = @('User', $inf)
                TemplateScopeAlias = @('Machine', $inf)
                TemplateNull = @($null, $null)
                TemplateOther = @('Computer', 'Machine/Microsoft/Windows NT/SecEdit/other.inf')
            }
            $inputs = $cases[$Name]
            return @{
                Method = 'IsSecurityTemplateSource'
                Arguments = @{
                    Scope = $inputs[0]
                    Source = $inputs[1]
                }
            }
        }
        'Restricted*' {
            $settings = $null
            switch ($Name) {
                RestrictedEmpty {
                    $settings = @()
                }
                RestrictedAuthoritative {
                    $settings = @(
                        (New-RecordParserIni '*S-1-5-32-544__Members' '*S-1-5-11,"Team,Red"')
                        (New-RecordParserIni 'fixture__MemberOf' '*S-1-5-32-544' User 'User/Microsoft/Windows NT/SecEdit/GptTmpl.inf')
                        (New-RecordParserIni 'cannot appear__Members' '' 'Machine')
                        (New-RecordParserIni 'cannot appear__Members' '' 'Computer' $inf 'Privileges')
                    )
                }
                RestrictedMalformedName {
                    $settings = @((New-RecordParserIni 'no delimiter' 'member'))
                }
                RestrictedInvalidSids {
                    $settings = @(
                        (New-RecordParserIni '*S-1-5-4294967296__Members' 'member')
                        (New-RecordParserIni 'valid__Members' '*S-1-5-4294967296')
                    )
                }
                RestrictedEmptyAssignment {
                    $settings = @((New-RecordParserIni '*S-1-5-32-544__Members' ''))
                }
                RestrictedTrace {
                    $settings = @(
                        (New-RecordParserTrackedIni 'first' $false)
                        (New-RecordParserTrackedIni 'ignored' $true)
                        (New-RecordParserTrackedIni 'last' $false)
                    )
                }
                RestrictedNameFault {
                    $settings = @(
                        (New-RecordParserIni 'before__Members' 'one')
                        (New-RecordParserIni ([GpoParserUnstringable]::new('Name')) 'two')
                        (New-RecordParserIni 'after__MemberOf' 'three')
                    )
                }
                RestrictedValueFault {
                    $settings = @(
                        (New-RecordParserIni 'before__Members' 'one')
                        (New-RecordParserIni 'middle__Members' ([GpoParserUnstringable]::new('Value')))
                        (New-RecordParserIni 'after__MemberOf' 'three')
                    )
                }
            }
            return @{
                Method = 'ParseRestrictedGroups'
                Arguments = @{
                    IniSettings = $settings
                }
            }
        }
        'Xml*' {
            $files = $null
            switch ($Name) {
                XmlEmpty {
                    $files = @()
                }
                XmlNullItem {
                    $files = [object[]]::new(1)
                }
                XmlMixedRecovery {
                    $files = @(
                        (New-RecordParserFile first.xml $groups)
                        (New-RecordParserFile malformed.xml $malformed)
                        (New-RecordParserFile dtd.xml $dtd)
                        (New-RecordParserFile last.xml '<p:Other xmlns:p="urn:fixture"/>')
                    )
                }
                XmlReadOrder {
                    $files = @(
                        (New-RecordParserFile first.xml $groups $true)
                        (New-RecordParserFile bad.xml $malformed $true)
                        (New-RecordParserFile last.xml $groups $true)
                    )
                }
                XmlDuplicateFile {
                    $file = New-RecordParserFile fixture.xml $groups
                    $files = @($file, $file)
                }
            }
            return @{
                Method = 'ReadXmlRecords'
                Arguments = @{
                    XmlFiles = $files
                }
            }
        }
        'Local*' {
            $files = $null
            switch ($Name) {
                LocalEmpty {
                    $files = @()
                }
                LocalMixedRecovery {
                    $files = @(
                        (New-RecordParserFile first.xml $groups)
                        (New-RecordParserFile malformed.xml $malformed)
                        (New-RecordParserFile dtd.xml $dtd)
                        (New-RecordParserFile ignored.xml '<Other/>')
                        (New-RecordParserFile last.xml $groups)
                    )
                }
                LocalInvalidProperties {
                    $files = @((New-RecordParserFile fixture.xml '<Groups><Group/><Group><Properties action="Z" /></Group><Group disabled="?"><Properties action="U" groupSid="invalid" /></Group><Ignored /></Groups>'))
                }
                LocalNamespace {
                    $xml = '<p:Groups xmlns:p="urn:fixture"><p:Group uid="same" disabled="true" removePolicy="1"><p:Properties action="U" groupSid="S-1-5-32-544" groupName="fixture" deleteAllUsers="1" deleteAllGroups="true"><p:Members><p:Member action="add" sid="S-1-5-11"/><p:Member action="remove" name="fixture user"/><p:Member action="?" sid="invalid"/></p:Members></p:Properties><p:Filters><p:FilterComputer name="fixture" password="' + $script:SyntheticMarker + '"/></p:Filters></p:Group><p:User uid="same"><p:Properties action="c" userName="fixture account" sid="S-1-5-11" disabled="0" neverExpires="1"/></p:User></p:Groups>'
                    $files = @((New-RecordParserFile namespace.xml $xml), (New-RecordParserFile second.xml $xml))
                }
                LocalPipelinePath {
                    $xml = '<Groups><Group uid="first"><Properties action="U"/></Group><Group uid="second"><Properties action="U"/></Group></Groups>'
                    $file = [pscustomobject]@{
                        Scope = 'Computer'
                        Xml = $xml
                    }
                    $file.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Path', {
                                $script:ParserTrace.Add('ReadPath:' + $script:ParserPathState)
                                $script:ParserPathState
                            }))
                    $files = @($file)
                }
                LocalStrictMissingPath {
                    $files = @(
                        [pscustomobject]@{
                            Scope = 'Computer'
                            Xml = '<Groups><Group uid="first"><Properties action="U"/></Group><Group uid="second"><Properties action="U"/></Group></Groups>'
                        }
                        (New-RecordParserFile tail.xml $groups)
                    )
                }
                LocalReadOrder {
                    $files = @(
                        (New-RecordParserFile first.xml $groups $true)
                        (New-RecordParserFile bad.xml $malformed $true)
                        (New-RecordParserFile last.xml $groups $true)
                    )
                }
            }
            return @{
                Method = 'ParseLocalUsersGroups'
                Arguments = @{
                    XmlFiles = $files
                }
            }
        }
    }
    throw "Unknown record parser sample $Name."
}

function Invoke-RecordParserDirect($Parser, [string]$Method, [hashtable]$Arguments) {
    switch ($Method) {
        'GetXmlPath' {
            $Parser.GetXmlPath($Arguments.Node)
        }
        'ResolveIdentities' {
            $Parser.ResolveIdentities($Arguments.Targets)
        }
        'IsSecurityTemplateSource' {
            $Parser.IsSecurityTemplateSource($Arguments.Scope, $Arguments.Source)
        }
        'ParseRestrictedGroups' {
            $Parser.ParseRestrictedGroups($Arguments.IniSettings)
        }
        'ReadXmlRecords' {
            $Parser.ReadXmlRecords($Arguments.XmlFiles)
        }
        'ParseLocalUsersGroups' {
            $Parser.ParseLocalUsersGroups($Arguments.XmlFiles)
        }
    }
}

function Get-RecordParserErrors([Management.Automation.ErrorRecord]$Item) {
    [pscustomobject][ordered]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Type = $Item.Exception.GetType().FullName
        Cause = $Item.Exception.GetBaseException().GetType().FullName
        Message = $Item.Exception.Message
        CauseMessage = $Item.Exception.GetBaseException().Message
    }
}

function Get-RecordParserXmlShape($Row, $File) {
    Assert-RecordParser ([object]::ReferenceEquals($Row.File, $File)) 'XML read did not borrow its exact file record.'
    Assert-RecordParser (($Row.PSObject.Properties.Name -join ',') -ceq 'File,Document,Valid') 'XML record schema changed.'
    Get-RecordParserTyped ([pscustomobject][ordered]@{
            Document = $Row.Document
            Valid = $Row.Valid
        })
}

function Invoke-RecordParserCapture([string]$Name, [string]$Route, [string]$Action, [bool]$Caught, $Parser) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalGpoParser))
    }
    $script:ParserTrace = [Collections.Generic.List[string]]::new()
    $script:ParserPathState = 'initial'
    $sample = New-RecordParserSample $Name
    $method = $sample.Method
    $command = $script:ParserCommands[$method]
    $arguments = $sample.Arguments
    $files = @($arguments.XmlFiles)
    $ErrorActionPreference = $Action
    $Matches = @{
        ParserSentinel = 'caller-owned'
    }
    $Error.Clear()
    $stream = [Collections.Generic.List[object]]::new()
    $fault = $null
    $collect = {
        process {
            $stream.Add($_)
            if ($Name -eq 'LocalPipelinePath' -and $_ -isnot [Management.Automation.ErrorRecord]) {
                $script:ParserTrace.Add('Emit:' + $_.Uid)
                if ($_.Uid -ceq 'first') {
                    $script:ParserPathState = 'updated'
                }
            }
        }
    }
    $invoke = if ($Route -eq 'Direct') {
        { Invoke-RecordParserDirect $Parser $method $arguments }
    }
    elseif ($Name -eq 'LocalStrictMissingPath') {
        {
            & {
                Set-StrictMode -Version Latest
                & $command @arguments
            }
        }
    }
    else {
        { & $command @arguments }
    }
    $success = $false
    if ($Caught) {
        try {
            . $invoke 2>&1 | . $collect
            $success = $?
        }
        catch {
            $fault = Get-RecordParserErrors $_
        }
    }
    else {
        . $invoke 2>&1 | . $collect
        $success = $?
    }
    $trace = $script:ParserTrace.ToArray()
    $recordIndex = 0
    $rows = @(
        foreach ($item in $stream) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                Get-RecordParserErrors $item
            }
            elseif ($method -eq 'ReadXmlRecords') {
                Assert-RecordParser ($recordIndex -lt $files.Count) 'XML read produced extra file rows.'
                Get-RecordParserXmlShape $item $files[$recordIndex]
                $recordIndex++
            }
            else {
                Get-RecordParserTyped $item
            }
        }
    )
    if ($Name -eq 'XmlDuplicateFile') {
        Assert-RecordParser ($stream.Count -eq 2 -and
            -not [object]::ReferenceEquals($stream[0].Document, $stream[1].Document)) 'Separate XML reads shared the same DOM.'
    }
    [pscustomobject][ordered]@{
        Stream = $rows
        Caught = $fault
        Global = @($Error | ForEach-Object { Get-RecordParserErrors $_ })
        Trace = $trace
        CallerMatches = $Matches.ParserSentinel
        Success = $success
    }
}

function Get-RecordParserField($Row, [string]$Name) {
    foreach ($field in $Row.Fields) {
        if ($field.Name -ceq $Name) {
            return $field.Data
        }
    }
}

function Assert-RecordParserBusinessFacts($Observation, [string]$Name) {
    Assert-RecordParser ($null -eq $Observation.Caught -and
        $Observation.CallerMatches -ceq 'caller-owned') "Baseline parser case failed for $Name."
    switch -Wildcard ($Name) {
        'Path*' {
            $path = @{
                PathNull = ''
                PathDocument = ''
                PathText = ''
                PathRoot = 'r[1]'
                PathSibling = 'r[1]/Item[3]'
                PathUidAncestor = 'item#nearest/Child[1]'
                PathUidCurrent = 'item#nearest'
                PathMetadata = 'r[1]/Item[3]/LocalName[1]'
            }[$Name]
            Assert-RecordParser ($Observation.Stream.Count -eq 1 -and
                $Observation.Stream[0].Type -ceq 'System.String' -and
                $Observation.Stream[0].Value -ceq $path) "XML path shape was not exercised for $Name."
        }
        'IdentityCasing' {
            Assert-RecordParser (($Observation.Stream.Value -join ',') -ceq 'a/duplicate/1,B/duplicate/1,A/duplicate/2,b/duplicate/2,first,A/duplicate/3') 'Raw identity casing, order or duplicate positions changed.'
        }
        'Template*' {
            $accepted = $Name -in @('TemplateComputer', 'TemplateComputerSlashes', 'TemplateUser')
            Assert-RecordParser ($Observation.Stream.Count -eq 1 -and
                $Observation.Stream[0].Type -ceq 'System.Boolean' -and
                $Observation.Stream[0].Value -eq $accepted) "Template classification changed for $Name."
        }
        'RestrictedTrace' {
            $trace = 'Section:first,Source:first,Section:ignored,Section:last,Source:last,Name:first,Source:first,Name:first,Name:last,Source:last,Name:last'
            Assert-RecordParser (($Observation.Trace -join ',') -ceq $trace) 'Restricted parser did not preserve authoritative prefilter and native getter order.'
        }
        'XmlMixedRecovery' {
            $valid = @($Observation.Stream | ForEach-Object { (Get-RecordParserField $_ 'Valid').Value })
            Assert-RecordParser (($valid -join ',') -ceq 'True,False,False,True' -and
                @($Observation.Global | Where-Object Cause `
                        -eq 'System.Xml.XmlException').Count -ge 2) 'Malformed and DTD XML were not exercised.'
        }
        'XmlReadOrder' {
            Assert-RecordParser (($Observation.Trace -join ',') -ceq 'Read:first.xml,Read:bad.xml,Read:last.xml') 'XML file getters did not run exactly once in input order.'
        }
        'LocalPipelinePath' {
            $sources = @($Observation.Stream | ForEach-Object { (Get-RecordParserField $_ 'Source').Value })
            Assert-RecordParser (($sources -join ',') -ceq 'initial,updated' -and
                ($Observation.Trace -join ',') -ceq 'ReadPath:initial,Emit:first,ReadPath:updated,Emit:second') 'Local path getter and pipeline emission did not interleave in row order.'
        }
        'LocalReadOrder' {
            Assert-RecordParser (($Observation.Trace -join ',') -ceq 'Read:first.xml,Read:bad.xml,Read:last.xml,Scope:first.xml,Path:first.xml,Scope:last.xml,Path:last.xml') 'Local parser did not read all XML before traversing recovered rows.'
        }
        'LocalNamespace' {
            $json = ConvertTo-RecordParserJson $Observation.Stream
            Assert-RecordParser ($Observation.Stream.Count -eq 4 -and $json -match 'PasswordPresent.*true' -and
                $json -match 'Group#same' -and
                $json -match 'User#same') 'Local rows did not exercise both namespace-aware records and safe filter projection.'
        }
    }
}

function Assert-RecordParserFaultFacts($Observation, [string]$Name, [bool]$Caught) {
    Assert-RecordParser ($Observation.CallerMatches -ceq 'caller-owned' -and
        $Observation.Global.Count -gt 0) "Caller state or native errors were not exercised for $Name."
    $rows = @($Observation.Stream | Where-Object { $null -eq $_.Id })
    switch ($Name) {
        'IdentityNullElement' {
            Assert-RecordParser (@($Observation.Global | Where-Object Id `
                        -eq 'NullArrayIndex').Count -gt 0) 'A native null identity did not exercise the indexed lookup fault.'
            if ($Caught) {
                Assert-RecordParser ($rows.Count -eq 0 -and
                    $Observation.Caught.Id -ceq 'NullArrayIndex') 'A caught identity fault exposed partial rows.'
            }
            else {
                Assert-RecordParser (($rows.Value -join ',') -ceq 'before,after/duplicate/1,AFTER/duplicate/2') 'Native identity loop did not resume around the null input.'
            }
        }
        'RestrictedNameFault' {
            $cause = @($Observation.Global | Where-Object CauseMessage -eq 'synthetic restricted observation Name')
            Assert-RecordParser ($cause.Count -eq 1 -and
                $cause[0].Cause -ceq 'System.InvalidOperationException') 'Name conversion lost its native root cause.'
            $names = @($rows | ForEach-Object { (Get-RecordParserField $_ 'GroupName').Value })
            if ($Caught) {
                Assert-RecordParser (($names -join ',') -ceq 'before' -and
                    $Observation.Caught.CauseMessage -ceq 'synthetic restricted observation Name') 'Caught name conversion did not stop after the first row.'
            }
            else {
                Assert-RecordParser (($names -join ',') -ceq 'before,before,after') 'Native Continue did not preserve the prior regex row and later recovery.'
            }
        }
        'RestrictedValueFault' {
            $cause = @($Observation.Global | Where-Object CauseMessage -eq 'synthetic restricted observation Value')
            Assert-RecordParser ($cause.Count -eq 1 -and
                $cause[0].Cause -ceq 'System.InvalidOperationException') 'Value conversion lost its native root cause.'
            Assert-RecordParser ($rows.Count -eq 3 -and $null -eq $Observation.Caught -and
                (Get-RecordParserField $rows[1] 'Valid').Value -eq $false -and
                (Get-RecordParserField $rows[1] 'Error').Value -ceq 'Malformed group membership value' -and
                (Get-RecordParserField $rows[2] 'GroupName').Value -ceq 'after') 'Malformed value did not remain localized to the middle row.'
        }
    }
}

function Invoke-RecordParserChild([string]$Name, [string]$Action, [bool]$Frozen) {
    $engine = (Get-Process -Id $PID).Path
    $parameters = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Uncaught', '-Fault', $Name, '-Preference', $Action
    )
    if ($Frozen) {
        $parameters += '-Original'
    }
    $ErrorActionPreference = 'Continue'
    $rows = @(& $engine @parameters 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{
        Exit = $LASTEXITCODE
        Rows = @($rows | Where-Object { $_ -match '\S' })
    }
}

$executed = 0
switch ($Case) {
    'VerifyOriginal' {
        $path = Join-Path $root 'bin/ADPolicyAnalysis.ps1'
        Assert-RecordParser ((Get-FileHash `
                    -LiteralPath $path `
                    -Algorithm SHA256).Hash -ieq '1a0bb6bd599d0427a917deb93d81fd620ac65406f53321c6eaa9a21593ab5b37') 'Accepted policy file fingerprint changed.'
        Assert-RecordParserHashes ([IO.File]::ReadAllText($path))
        $executed = $script:OriginalParserHashes.Count
    }
    { $_ -in 'Records', 'Direct' } {
        Assert-RecordParserParameters
        $route = 'Command'
        $parser = $null
        if ($Case -eq 'Direct') {
            foreach ($command in $script:ParserCommands.Values) {
                Set-Item -LiteralPath ('function:' + $command) -Value { throw 'Direct parser delegated to a legacy command.' }
            }
            $route = 'Direct'
            $parser = [ADAnalyzerGpoPolicyRecordParser]::new()
            Assert-RecordParser (@($parser.PSObject.Properties).Count -eq 0) 'Parser retained instance state.'
        }
        $business = $script:ParserBusiness
        if ($Case -eq 'Records') {
            # Direct calls return a result collection. This case covers the legacy stream.
            $business = @($business) + 'LocalPipelinePath'
        }
        foreach ($name in $business) {
            $expected = Invoke-RecordParserCapture $name 'Original' 'Stop' $true $null
            $actual = Invoke-RecordParserCapture $name $route 'Stop' $true $parser
            Assert-RecordParserBusinessFacts $expected $name
            if ($Case -eq 'Direct') {
                Assert-RecordParserBusinessFacts $actual $name
                Assert-RecordParserSame $expected.Stream $actual.Stream "Direct rows $name"
                Assert-RecordParserSame $expected.Trace $actual.Trace "Direct observations $name"
            }
            else {
                Assert-RecordParserSame $expected $actual "Command $name"
            }
            $executed++
        }
        if ($Case -eq 'Direct') {
            foreach ($name in @('IdentityNullElement', 'RestrictedNameFault')) {
                $failure = Invoke-RecordParserCapture $name 'Direct' 'Stop' $true $parser
                $message = if ($name -eq 'IdentityNullElement') {
                    '(?i)null'
                }
                else {
                    'synthetic restricted observation Name'
                }
                Assert-RecordParser ($null -ne $failure.Caught -and $failure.Caught.CauseMessage -match $message -and
                    @($failure.Stream).Count -eq 0) "Direct did not report the native root cause without partial rows for $name."
                $executed++
            }
        }
    }
    'Faults' {
        $strictBaseline = Invoke-RecordParserCapture 'LocalStrictMissingPath' 'Original' 'Continue' $false $null
        $strictActual = Invoke-RecordParserCapture 'LocalStrictMissingPath' 'Command' 'Continue' $false $null
        Assert-RecordParser ($strictBaseline.Stream.Count -eq 3 -and
            $strictBaseline.Stream[0].Id -eq 'PropertyNotFoundStrict' -and
            $strictBaseline.Stream[1].Id -eq 'PropertyNotFoundStrict' -and
            (Get-RecordParserField $strictBaseline.Stream[2] 'Source').Value -ceq 'tail.xml') 'The strict native fixture did not emit two item errors and its tail row.'
        Assert-RecordParserSame $strictBaseline $strictActual 'Strict missing Path per-item recovery'
        $executed++

        foreach ($name in $script:ParserFaults) {
            foreach ($action in @('Continue', 'Stop')) {
                $baseline = Invoke-RecordParserCapture $name 'Original' $action $true $null
                $candidate = Invoke-RecordParserCapture $name 'Command' $action $true $null
                Assert-RecordParserFaultFacts $baseline $name $true
                Assert-RecordParserSame $baseline $candidate "Caught $name/$action"
                $executed++

                if ($action -eq 'Continue') {
                    $baseline = Invoke-RecordParserCapture $name 'Original' $action $false $null
                    $candidate = Invoke-RecordParserCapture $name 'Command' $action $false $null
                    Assert-RecordParserFaultFacts $baseline $name $false
                }
                else {
                    $baseline = Invoke-RecordParserChild $name $action $true
                    $candidate = Invoke-RecordParserChild $name $action $false
                    Assert-RecordParser ($baseline.Rows.Count -gt 1 -and
                        $baseline.Rows[0] -ceq "CASE $name $action") "The uncaught child did not exercise $name."
                }
                Assert-RecordParserSame $baseline $candidate "Uncaught $name/$action"
                $executed++
            }
        }
    }
    'Uncaught' {
        $ErrorView = 'CategoryView'
        Write-Output "CASE $Fault $Preference"
        $route = if ($Original) {
            'Original'
        }
        else {
            'Command'
        }
        $result = Invoke-RecordParserCapture $Fault $route $Preference $false $null
        Write-Output (ConvertTo-RecordParserJson $result)
        Write-Output 'RETURNED'
    }
}
Write-Host "PASS GPO policy record parser $Case $executed"
