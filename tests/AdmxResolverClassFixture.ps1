[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Records', 'Stream', 'Faults', 'Direct', 'Uncaught')]
    [string]$Case = 'Records',
    [ValidateSet('Provider', 'Required')]
    [string]$Fault = 'Provider',
    [ValidateSet('Continue', 'Stop')]
    [string]$Preference = 'Stop',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'bin/ADAnalyzer.ps1')

# Exact accepted U-093 sources. Normalize platform line endings for the hashes.
$script:ValueSource = @'
function Get-ADAnalyzerAdmxValue {
    param([Xml.XmlNode]$Node)
    if (-not $Node) {
        return [pscustomobject]@{
            Valid = $false
            Value = $null
            Deleted = $false
        }
    }
    $value = $Node.SelectSingleNode('./*[1]')
    if (-not $value) {
        return [pscustomobject]@{
            Valid = $false
            Value = $null
            Deleted = $false
        }
    }
    switch ($value.PSBase.LocalName) {
        'decimal' {
            $n = ConvertTo-ADAnalyzerPolicyNumber (Get-ADAnalyzerXmlAttribute $value value)
            return [pscustomobject]@{
                Valid = $n.Valid
                Value = $n.Value
                Deleted = $false
            }
        }
        'longDecimal' {
            $n = ConvertTo-ADAnalyzerPolicyNumber (Get-ADAnalyzerXmlAttribute $value value)
            return [pscustomobject]@{
                Valid = $n.Valid
                Value = $n.Value
                Deleted = $false
            }
        }
        'string' {
            return [pscustomobject]@{
                Valid = $true
                Value = $value.PSBase.InnerText
                Deleted = $false
            }
        }
        'delete' {
            return [pscustomobject]@{
                Valid = $true
                Value = $null
                Deleted = $true
            }
        }
    }
    [pscustomobject]@{
        Valid = $false
        Value = $null
        Deleted = $false
    }
}
'@
$script:ResolverSource = @'
function Resolve-ADAnalyzerRegistryPolicy {
    <# .SYNOPSIS Adds optional offline ADMX/ADML metadata while preserving raw policy records.
       .DESCRIPTION Supports policy enabled/disabled values and boolean, enum and list elements.
       Complex multi-key definitions retain explicit Unknown state; no template is required for parsing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistrySettings,
        [string]$TemplatePath,
        [string]$Language = 'en-US'

    )
    $definitions = @()
    $errors = @()
    $unresolvedDefinition = @{
        Common = @{
            PolicyId = $null
            PolicyNamespace = $null
            DisplayName = $null
        }
        Kind = $null
        ElementId = $null
    }
    $templateMissing = -not $TemplatePath -or -not (Test-Path -LiteralPath $TemplatePath -PathType Container)
    if (-not $templateMissing) {
        foreach ($file in @(Get-ChildItem -LiteralPath $TemplatePath -Filter '*.admx' -File -ErrorAction Stop)) {
            try {
                $xml = Read-AnalyzerPolicyXml $file.FullName
                $resources = @{}
                $resourceFileMissing = $false
                $resourcePath = Join-Path (Join-Path $TemplatePath $Language) ($file.BaseName + '.adml')
                if (Test-Path -LiteralPath $resourcePath -PathType Leaf) {
                    $adml = Read-AnalyzerPolicyXml $resourcePath
                    foreach ($resource in @($adml.SelectNodes('//*[local-name()="stringTable"]/*[local-name()="string"]'))) {
                        $resources[(Get-ADAnalyzerXmlAttribute $resource id)] = $resource.PSBase.InnerText
                    }
                }
                else {
                    $resourceFileMissing = $true
                }
                $namespace = Get-ADAnalyzerXmlAttribute ($xml.SelectSingleNode('//*[local-name()="policyNamespaces"]/*[local-name()="target"]')) namespace
                foreach ($policy in @($xml.SelectNodes('//*[local-name()="policies"]/*[local-name()="policy"]'))) {
                    $languageMissing = $resourceFileMissing
                    $key = Get-ADAnalyzerXmlAttribute $policy key
                    $valueName = Get-ADAnalyzerXmlAttribute $policy valueName
                    $name = Get-ADAnalyzerXmlAttribute $policy name
                    $display = Get-ADAnalyzerXmlAttribute $policy displayName
                    if ($display -match '^\$\(string\.(.+)\)$') {
                        if ($resources.ContainsKey($Matches[1])) {
                            $display = $resources[$Matches[1]]
                        }
                        else {
                            $languageMissing = $true
                            $display = $name
                        }
                    }
                    $common = @{
                        PolicyId = $name
                        PolicyNamespace = $namespace
                        DisplayName = $display
                        Class = (Get-ADAnalyzerXmlAttribute $policy class)
                        Template = $file.Name
                        LanguageMissing = $languageMissing
                        Resources = $resources
                    }
                    if ($valueName) {
                        $definitions += [pscustomobject]@{
                            Common = $common
                            Kind = 'Policy'
                            Key = $key
                            ValueName = $valueName
                            ElementId = $null
                            Node = $policy
                        }
                    }
                    foreach ($element in @($policy.SelectNodes('./*[local-name()="elements"]/*'))) {
                        $elementKey = Get-ADAnalyzerXmlAttribute $element key $key
                        $elementName = Get-ADAnalyzerXmlAttribute $element valueName
                        $definitions += [pscustomobject]@{
                            Common = $common
                            Kind = $element.PSBase.LocalName
                            Key = $elementKey
                            ValueName = $elementName
                            ElementId = (Get-ADAnalyzerXmlAttribute $element id)
                            Node = $element
                        }
                    }
                    foreach ($list in @($policy.SelectNodes('./*[local-name()="enabledList" or local-name()="disabledList"]'))) {
                        foreach ($item in @($list.SelectNodes('./*[local-name()="item"]'))) {
                            $definitions += [pscustomobject]@{
                                Common = $common
                                Kind = 'PolicyValueList'
                                Key = (Get-ADAnalyzerXmlAttribute $item key $key)
                                ValueName = (Get-ADAnalyzerXmlAttribute $item valueName)
                                ElementId = $null
                                Node = $item
                            }
                        }
                    }
                }
            }
            catch {
                $errors += $file.Name
            }
        }
    }
    foreach ($row in @($RegistrySettings)) {
        if (Test-ADAnalyzerSecretName $row.ValueName) {
            $safe = ConvertTo-ADAnalyzerSecretRecord $row
            $safe | Add-Member NoteProperty MetadataStatus 'PresenceOnly' -Force
            $safe | Add-Member NoteProperty State 'Unknown' -Force
            $safe
            continue
        }
        $class = if ($row.Hive -ieq 'HKCU') {
            'User'
        }
        else {
            'Machine'
        }
        $matches = @($definitions | Where-Object { $_.Common.Class -in $class,
                'Both' -and
                $_.Key -ieq $row.Key -and
                ($_.ValueName -ieq $row.ValueName -or
                ($_.Kind -eq 'list' -and
                ([string]$row.ValueName).StartsWith((Get-ADAnalyzerXmlAttribute $_.Node valuePrefix),
                    [StringComparison]::OrdinalIgnoreCase))) })
        $status = if ($templateMissing) {
            'TemplateNotFound'
        }
        elseif (-not $matches.Count -and $errors.Count) {
            'InvalidTemplate'
        }
        elseif (-not $matches.Count) {
            'NoMatch'
        }
        elseif ($matches.Count -gt 1) {
            'Ambiguous'
        }
        else {
            'Resolved'
        }
        $definition = $null
        $state = 'Unknown'
        $options = @()
        if ($matches.Count -eq 1) {
            $definition = $matches[0]
            if ($definition.Common.LanguageMissing) {
                $status = 'LanguageResourceMissing'
            }
            switch ($definition.Kind) {
                'Policy' {
                    foreach ($pair in @(@('enabledValue', 'Enabled'), @('disabledValue', 'Disabled'))) {
                        $value = Get-ADAnalyzerAdmxValue ($definition.Node.SelectSingleNode('./*[local-name()="' + $pair[0] + '"]'))
                        if ($value.Valid -and
                            (($value.Deleted -and
                                (Test-ADAnalyzerAdmxOptionalField $row Deleted) -and
                                $row.Deleted) -or
                            (-not $value.Deleted -and
                            $row.Value -eq $value.Value))) {
                            $state = $pair[1]
                        }
                    }
                }
                'boolean' {
                    foreach ($pair in @(@('trueValue', 'True'), @('falseValue', 'False'))) {
                        $value = Get-ADAnalyzerAdmxValue ($definition.Node.SelectSingleNode('./*[local-name()="' + $pair[0] + '"]'))
                        if ($value.Valid -and $row.Value -eq $value.Value) {
                            $state = $pair[1]
                        }
                    }
                }
                'enum' {
                    foreach ($item in @($definition.Node.SelectNodes('./*[local-name()="item"]'))) {
                        $value = Get-ADAnalyzerAdmxValue ($item.SelectSingleNode('./*[local-name()="value"]'))
                        $label = Get-ADAnalyzerXmlAttribute $item displayName
                        if ($label -match '^\$\(string\.(.+)\)$') {
                            if ($definition.Common.Resources.ContainsKey($Matches[1])) {
                                $label = $definition.Common.Resources[$Matches[1]]
                            }
                            else {
                                $status = 'LanguageResourceMissing'
                            }
                        }
                        $options += [pscustomobject]@{
                            Label = $label
                            Value = $value.Value
                        }
                        if ($value.Valid -and $row.Value -eq $value.Value) {
                            $state = 'Configured'
                        }
                    }
                }
                'list' {
                    $state = 'Configured'
                }
                'PolicyValueList' {
                    $state = 'Unknown'
                }
                default {
                    $status = 'UnsupportedDefinition'
                }
            }
        }
        $reportDefinition = $definition
        if ($null -eq $reportDefinition) {
            $reportDefinition = $unresolvedDefinition
        }
        [pscustomobject]@{
            Scope = $row.Scope
            Hive = $row.Hive
            Key = $row.Key
            ValueName = $row.ValueName
            Type = $row.Type
            Value = $row.Value
            RawData = if (Test-ADAnalyzerAdmxOptionalField $row RawData) {
                , $row.RawData
            }
            else {
                $null
            }
            Source = $row.Source
            KeyOnly = if (Test-ADAnalyzerAdmxOptionalField $row KeyOnly) {
                , $row.KeyOnly
            }
            else {
                $null
            }
            DeletionDirective = if (Test-ADAnalyzerAdmxOptionalField $row DeletionDirective) {
                , $row.DeletionDirective
            }
            else {
                $null
            }
            Deleted = if (Test-ADAnalyzerAdmxOptionalField $row Deleted) {
                , $row.Deleted
            }
            else {
                $null
            }
            MetadataStatus = $status
            State = $state
            PolicyId = $reportDefinition.Common.PolicyId
            PolicyNamespace = $reportDefinition.Common.PolicyNamespace
            DisplayName = $reportDefinition.Common.DisplayName
            DefinitionType = $reportDefinition.Kind
            ElementId = $reportDefinition.ElementId
            Options = $options
            TemplateErrors = $errors
        }
    }
}
'@
$script:Frozen = [ordered]@{
    'Get-ADAnalyzerAdmxValue' = @{
        Text = $script:ValueSource
        Hash = '0f3e4ea4c9822da62be5d8cdbdc02f979252885cd3895be9c9805205bc1f2f20'
    }
    'Resolve-ADAnalyzerRegistryPolicy' = @{
        Text = $script:ResolverSource
        Hash = 'b17fb3131629d7310978f1e9ae518dc49e0e9392d4fd9ba14d366dd87434b9fa'
    }
}

function Assert-Admx($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-AdmxHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-AdmxDefinition([string]$Text, [string]$Name) {
    $tokens = $null
    $errors = $null
    $program = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $definitions = @($program.EndBlock.Statements | Where-Object Name -ceq $Name)
    Assert-Admx ($errors.Count -eq 0 -and $definitions.Count -eq 1) "Could not isolate the exact $Name AST."
    $definitions[0]
}

foreach ($name in $script:Frozen.Keys) {
    $spec = $script:Frozen[$name]
    Assert-Admx ((Get-AdmxHash $spec.Text) -ieq $spec.Hash) "Frozen $name source changed."
    $frozenAst = Get-AdmxDefinition $spec.Text $name
    $ast = (Get-Command $name -CommandType Function).ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    Assert-Admx ((Get-AdmxHash $ast.ParamBlock.Extent.Text) -ceq
        (Get-AdmxHash $frozenAst.Body.ParamBlock.Extent.Text)) "$name binding changed."
}
$script:OriginalSource = $script:ValueSource + [Environment]::NewLine + $script:ResolverSource

function Assert-AdmxSame($Expected, $Actual, [string]$Label) {
    $before = ConvertTo-Json -InputObject $Expected -Depth 15 -Compress
    $after = ConvertTo-Json -InputObject $Actual -Depth 15 -Compress
    Assert-Admx ($before -ceq $after) "$Label differs. Expected $before; actual $after"
}

function Get-AdmxTyped($Value) {
    if ($null -eq $Value) {
        return [pscustomobject]@{
            Type = '<null>'
            Content = $null
        }
    }
    $type = $Value.GetType().FullName
    $content = $Value
    if ($Value -is [array]) {
        $content = @(foreach ($item in $Value) {
                Get-AdmxTyped $item
            })
    }
    elseif ($type -ceq 'System.Management.Automation.PSCustomObject') {
        $content = @(foreach ($property in $Value.PSObject.Properties) {
                [pscustomobject]@{
                    Name = $property.Name
                    Value = (Get-AdmxTyped $property.Value)
                }
            })
    }
    [pscustomobject]@{
        Type = $type
        Content = $content
    }
}

$script:Values = [ordered]@{
    Null = $null
    Empty = '<enabledValue/>'
    Decimal = '<enabledValue xmlns:n="urn:fixture"><n:decimal n:value="-23" LocalName="alias" /></enabledValue>'
    Long = '<enabledValue><longDecimal value="9223372036854775807" /></enabledValue>'
    Invalid = '<enabledValue><longDecimal value="9223372036854775808" /></enabledValue>'
    Text = '<enabledValue><string InnerText="alias">fixture &amp; value</string><delete/></enabledValue>'
    Delete = '<enabledValue><delete LocalName="alias" /></enabledValue>'
    Unsupported = '<enabledValue><fixture /></enabledValue>'
}
$script:RecordModes = 'Default', 'Missing', 'Empty', 'Valid', 'MissingLanguage', 'Ambiguous', 'DamagedSiblings', 'StrictBorrow'
$script:RegistryKey = 'Software\Fixture\Resolver'

function New-AdmxTemplates([string]$Directory) {
    $valid = Join-Path $Directory valid
    $ambiguous = Join-Path $Directory ambiguous
    $damaged = Join-Path $Directory damaged
    $null = [IO.Directory]::CreateDirectory((Join-Path $valid 'en-US'))
    $null = [IO.Directory]::CreateDirectory($ambiguous)
    $null = [IO.Directory]::CreateDirectory((Join-Path $damaged 'en-US'))
    $admx = @'
<policyDefinitions xmlns="urn:fixture:admx" revision="1.0" schemaVersion="1.0">
  <policyNamespaces><target prefix="f" namespace="Fixture.Resolver" /></policyNamespaces>
  <policies>
    <policy name="First" class="Machine" displayName="$(string.First)" key="Software\Fixture\Resolver" valueName="Flag">
      <enabledValue><delete /></enabledValue>
      <disabledValue><decimal value="17" /></disabledValue>
    </policy>
    <policy name="Middle" class="Both" displayName="$(string.Missing)" key="Software\Fixture\Resolver" valueName="Setting">
      <enabledValue><string>fixture-text</string></enabledValue>
    </policy>
    <policy name="Last" class="Both" displayName="$(string.Last)" key="Software\Fixture\Resolver">
      <elements>
        <enum id="Choice" valueName="Choice">
          <item displayName="$(string.Option)"><value><decimal value="2" /></value></item>
        </enum>
        <list id="List" valuePrefix="Entry" />
        <text id="Text" valueName="Unsupported" />
      </elements>
    </policy>
  </policies>
</policyDefinitions>
'@
    $adml = @'
<policyDefinitionResources xmlns="urn:fixture:adml" revision="1.0" schemaVersion="1.0">
  <resources><stringTable>
    <string id="First" InnerText="alias">First localized</string>
    <string id="Last">Last localized</string>
    <string id="Option">Option localized</string>
  </stringTable></resources>
</policyDefinitionResources>
'@
    [IO.File]::WriteAllText((Join-Path $valid 'valid.admx'), $admx)
    [IO.File]::WriteAllText((Join-Path $valid 'en-US/valid.adml'), $adml)
    [IO.File]::WriteAllText((Join-Path $ambiguous 'first.admx'), $admx)
    [IO.File]::WriteAllText((Join-Path $ambiguous 'second.admx'), $admx)
    [IO.File]::WriteAllText((Join-Path $damaged 'valid.admx'), $admx)
    [IO.File]::WriteAllText((Join-Path $damaged 'en-US/valid.adml'), $adml)
    [IO.File]::WriteAllText((Join-Path $damaged 'bad-resource.admx'), $admx)
    [IO.File]::WriteAllText((Join-Path $damaged 'en-US/bad-resource.adml'), '<unclosed>')
    [IO.File]::WriteAllText((Join-Path $damaged 'bad-template.admx'), '<unclosed>')
    @{
        Valid = $valid
        Ambiguous = $ambiguous
        Damaged = $damaged
        Missing = (Join-Path $Directory absent)
    }
}

function New-AdmxRow([string]$Name, $Value, [string]$Hive = 'HKLM') {
    [pscustomobject][ordered]@{
        Scope = 'Computer'
        Hive = $Hive
        Key = $script:RegistryKey.ToLowerInvariant()
        ValueName = $Name
        Type = 4
        Value = $Value
        RawData = [byte[]]@(17, 18)
        Source = 'fixture.pol'
        KeyOnly = $false
        DeletionDirective = $false
    }
}

function Invoke-AdmxValue([string]$Name, [string]$Route, $Resolver) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalSource))
    }
    $node = $null
    if ($null -ne $script:Values[$Name]) {
        $node = ([xml]$script:Values[$Name]).PSBase.DocumentElement
    }
    if ($Route -eq 'Direct') {
        return $Resolver.ReadValue($node)
    }
    Get-ADAnalyzerAdmxValue -Node $node
}

function Invoke-AdmxRecords([string]$Name, [string]$Route, $Resolver) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalSource))
    }
    $options = @{}
    $rows = @(New-AdmxRow 'FLAG' 17)
    $borrowed = $null
    $statuses = 'TemplateNotFound'
    switch ($Name) {
        'Default' {
        }
        'Missing' {
            $options.TemplatePath = $script:Templates.Missing
        }
        'Empty' {
            $rows = @()
            $statuses = ''
        }
        'Valid' {
            $options.TemplatePath = $script:Templates.Valid
            $rows += @(
                New-AdmxRow Setting 'fixture-text' HKCU
                New-AdmxRow Choice 2 HKCU
                New-AdmxRow EntryA 'fixture-list' HKCU
                New-AdmxRow Unsupported 1
                New-AdmxRow Flag 17 HKCU
                [pscustomobject]@{
                    ValueName = 'DefaultPassword'
                    SecretPresent = $true
                }
            )
            $statuses = 'Resolved,LanguageResourceMissing,Resolved,Resolved,UnsupportedDefinition,NoMatch,PresenceOnly'
        }
        'MissingLanguage' {
            $options.TemplatePath = $script:Templates.Valid
            $options.Language = 'xx-XX'
            $statuses = 'LanguageResourceMissing'
        }
        'Ambiguous' {
            $options.TemplatePath = $script:Templates.Ambiguous
            $statuses = 'Ambiguous'
        }
        'DamagedSiblings' {
            $options.TemplatePath = $script:Templates.Damaged
            $rows += @(New-AdmxRow Absent 23)
            $statuses = 'Resolved,InvalidTemplate'
        }
        'StrictBorrow' {
            Set-StrictMode -Version Latest
            $options.TemplatePath = $script:Templates.Valid
            $borrowed = [pscustomobject]@{
                FixtureMarker = 'borrowed value'
            }
            $rows = @(New-AdmxRow Absent $borrowed)
            $rows[0].PSObject.Properties.Remove('KeyOnly')
            $rows[0].RawData = [byte[]]::new(1)
            $statuses = 'NoMatch'
        }
    }
    $result = @(if ($Route -eq 'Direct') {
            if ($options.ContainsKey('Language')) {
                $Resolver.Resolve($rows, $options.TemplatePath, $options.Language)
            }
            elseif ($options.ContainsKey('TemplatePath')) {
                $Resolver.Resolve($rows, $options.TemplatePath)
            }
            else {
                $Resolver.Resolve($rows)
            }
        }
        else {
            Resolve-ADAnalyzerRegistryPolicy -RegistrySettings $rows @options
        })
    $actualStatuses = ($result | ForEach-Object MetadataStatus) -join ','
    Assert-Admx ($result.Count -eq $rows.Count -and
        $actualStatuses -ceq $statuses) "$Route/$Name expected $statuses. Received $actualStatuses."
    if ($Name -eq 'Valid') {
        Assert-Admx (($result[0..5].State -join ',') -ceq 'Disabled,Enabled,Configured,Configured,Unknown,Unknown' -and
            ($result[0..2].DisplayName -join ',') -ceq 'First localized,Middle,Last localized' -and
            $result[2].Options[0].Label -ceq 'Option localized' -and
            $result[6].SecretPresent -eq $true -and
            $null -eq $result[6].PSObject.Properties['Value']) 'Resolver lost a policy state, resource, or presence-only projection.'
    }
    if ($Name -eq 'DamagedSiblings') {
        $files = @($result[0].TemplateErrors | Sort-Object)
        Assert-Admx (($files -join ',') -ceq 'bad-resource.admx,bad-template.admx') 'Damaged templates were not reported once each.'
    }
    if ($null -ne $borrowed) {
        Assert-Admx ([object]::ReferenceEquals($result[0].Value, $borrowed) -and
            [object]::ReferenceEquals($result[0].RawData, $rows[0].RawData) -and
            $result[0].RawData -is [byte[]] -and $null -eq $result[0].KeyOnly -and
            $null -eq $result[0].Deleted -and
            $null -eq $result[0].PolicyId) 'Strict optional projection lost type, borrowed identity, or null fields.'
    }
    $result
}

function Invoke-AdmxStream([bool]$TakeOne, [bool]$Frozen) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:OriginalSource))
    }
    $global:AdmxFixtureTrace = [Collections.Generic.List[string]]::new()
    $global:AdmxFixtureScope = 'initial'
    $rows = @(New-AdmxRow first 17
        New-AdmxRow second 23)
    foreach ($inputRow in $rows) {
        $inputRow.PSObject.Properties.Remove('Scope')
        $inputRow.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Scope', {
                    $current = '<no enumerator>'
                    if ($null -ne $foreach) {
                        $current = $foreach.Current.ValueName
                    }
                    $global:AdmxFixtureTrace.Add('read:' + $current + ':' + $global:AdmxFixtureScope)
                    return $global:AdmxFixtureScope
                }))
    }
    $result = @(if ($TakeOne) {
            Resolve-ADAnalyzerRegistryPolicy $rows | Select-Object -First 1
        }
        else {
            Resolve-ADAnalyzerRegistryPolicy $rows | ForEach-Object {
                $global:AdmxFixtureTrace.Add('emit:' + $_.ValueName)
                $global:AdmxFixtureScope = 'updated'
                $_
            }
        })
    [pscustomobject]@{
        Rows = $result
        Trace = $global:AdmxFixtureTrace.ToArray()
    }
}

function Get-AdmxFaultInput([string]$Name) {
    $rows = @(New-AdmxRow before 1
        New-AdmxRow fault 2
        New-AdmxRow after 3)
    $options = @{
        RegistrySettings = $rows
    }
    if ($Name -eq 'Provider') {
        $options.TemplatePath = 'Alias:\'
    }
    else {
        $rows[1].PSObject.Properties.Remove('Type')
    }
    $options
}

function Get-AdmxDiagnostic([Management.Automation.ErrorRecord]$Item) {
    $cause = $Item.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Invoke-AdmxFault([string]$Name, [string]$Route, [string]$Action, [bool]$Catch, $Resolver) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalSource))
    }
    Set-StrictMode -Version Latest
    $options = Get-AdmxFaultInput $Name
    $ErrorActionPreference = $Action
    $global:Error.Clear()
    $stream = [Collections.Generic.List[object]]::new()
    $invoke = {
        if ($Route -eq 'Direct') {
            $Resolver.Resolve($options.RegistrySettings)
        }
        else {
            Resolve-ADAnalyzerRegistryPolicy @options
        }
    }
    $observe = {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            $stream.Add((Get-AdmxDiagnostic $_))
        }
        else {
            $stream.Add($_.ValueName)
        }
    }
    $caught = $null
    if ($Catch) {
        try {
            & $invoke 2>&1 | ForEach-Object $observe
        }
        catch {
            $caught = Get-AdmxDiagnostic $_
        }
    }
    else {
        & $invoke 2>&1 | ForEach-Object $observe
    }
    [pscustomobject]@{
        Stream = $stream.ToArray()
        Caught = $caught
        GlobalErrors = @($global:Error | ForEach-Object { Get-AdmxDiagnostic $_ })
    }
}

function Invoke-AdmxChild([string]$Name, [string]$Action, [bool]$Frozen) {
    $engine = (Get-Process -Id $PID).Path
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Uncaught', '-Fault', $Name, '-Preference', $Action)
    if ($Frozen) {
        $arguments += '-Original'
    }
    $ErrorActionPreference = 'Continue'
    $lines = @(& $engine @arguments 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{
        Exit = $LASTEXITCODE
        Lines = @($lines | Where-Object { $_ -match '\S' })
    }
}

$count = 0
switch ($Case) {
    'VerifyOriginal' {
        $path = Join-Path $root 'bin/ADPolicyAnalysis.ps1'
        Assert-Admx ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ieq
            '42b1677b4b5a7e64b60901edce20e19c400e719df0583f45c334cb819c894b9a') 'Accepted U-093 policy file changed.'
        $source = [IO.File]::ReadAllText($path)
        $count++
        foreach ($name in $script:Frozen.Keys) {
            $originalAst = Get-AdmxDefinition $source $name
            Assert-Admx ((Get-AdmxHash $originalAst.Extent.Text) -ieq $script:Frozen[$name].Hash) "Accepted $name function changed."
            $count++
        }
    }
    { $_ -in 'Records', 'Direct' } {
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ('admx-resolver-fixture-' + [guid]::NewGuid().ToString('N'))
        try {
            $script:Templates = New-AdmxTemplates $temporary
            $route = 'Command'
            $resolver = $null
            if ($Case -eq 'Direct') {

                function Get-ADAnalyzerAdmxValue {
                    throw 'Direct value parsing called its compatibility command.'
                }

                function Resolve-ADAnalyzerRegistryPolicy {
                    throw 'Direct ADMX resolution called its compatibility command.'
                }
                $resolver = [ADAnalyzerAdmxResolver]::new()
                $route = 'Direct'
            }
            foreach ($name in $script:Values.Keys) {
                $expected = Invoke-AdmxValue $name Original $null
                $actual = Invoke-AdmxValue $name $route $resolver
                Assert-AdmxSame (Get-AdmxTyped $expected) (Get-AdmxTyped $actual) "$Case value $name"
                $count++
            }
            foreach ($name in $script:RecordModes) {
                $expected = @(Invoke-AdmxRecords $name Original $null)
                $actual = @(Invoke-AdmxRecords $name $route $resolver)
                Assert-AdmxSame (Get-AdmxTyped $expected) (Get-AdmxTyped $actual) "$Case records $name"
                $count++
            }
            if ($Case -eq 'Direct') {
                $row = New-AdmxRow FLAG 17
                $first = $resolver.Resolve(@($row), $script:Templates.Valid)
                $first[0].DisplayName = 'caller change'
                $unresolved = $resolver.Resolve(@($row))
                $next = $resolver.Resolve(@($row), $script:Templates.Valid)
                $fresh = [ADAnalyzerAdmxResolver]::new().Resolve(@($row), $script:Templates.Valid)
                Assert-Admx ($unresolved[0].MetadataStatus -ceq 'TemplateNotFound' -and
                    $next[0].DisplayName -ceq 'First localized' -and
                    -not [object]::ReferenceEquals($next[0],
                        $fresh[0])) 'Resolver retained previous templates or result changes.'
                Assert-AdmxSame (Get-AdmxTyped $next) (Get-AdmxTyped $fresh) 'Independent resolver'
                $count++

                $expected = Invoke-AdmxFault Required Original Stop $true $null
                $actual = Invoke-AdmxFault Required Direct Stop $true $resolver
                Assert-Admx ($null -ne $actual.Caught -and $actual.Caught.Message -ceq $expected.Caught.Message -and
                    $actual.Stream.Count -eq 0) 'Direct ADMX projection did not report its native required field cause.'
                $count++
            }
        }
        finally {
            if ([IO.Directory]::Exists($temporary)) {
                [IO.Directory]::Delete($temporary, $true)
            }
        }
    }
    'Stream' {
        foreach ($firstOnly in @($true, $false)) {
            $expected = Invoke-AdmxStream $firstOnly $true
            $actual = Invoke-AdmxStream $firstOnly $false
            $trace = @('read:first:initial')
            if (-not $firstOnly) {
                $trace += @('emit:first', 'read:second:updated', 'emit:second')
            }
            Assert-AdmxSame $trace $expected.Trace 'Frozen native iterator and output ordering'
            Assert-AdmxSame $expected.Trace $actual.Trace 'Native iterator observations'
            Assert-AdmxSame (Get-AdmxTyped $expected.Rows) (Get-AdmxTyped $actual.Rows) 'Streamed rows'
            $count++
        }
    }
    'Faults' {
        foreach ($name in @('Provider', 'Required')) {
            foreach ($action in @('Continue', 'Stop')) {
                $expected = Invoke-AdmxFault $name Original $action $true $null
                $actual = Invoke-AdmxFault $name Command $action $true $null
                Assert-Admx ($null -ne $expected.Caught) "Frozen $name/$action did not exercise a native failure."
                Assert-AdmxSame $expected $actual "Caught $name/$action"
                $count++
                if ($action -eq 'Continue' -and $name -eq 'Required') {
                    $expected = Invoke-AdmxFault $name Original $action $false $null
                    $actual = Invoke-AdmxFault $name Command $action $false $null
                    Assert-Admx ($expected.GlobalErrors.Count -gt 0) "Frozen uncaught $name did not register a native failure."
                    Assert-Admx ($expected.Stream[0] -ceq 'before' -and
                        $expected.Stream[-1] -ceq 'after') 'Required error lost its prior or tail projection.'
                }
                else {
                    $expected = Invoke-AdmxChild $name $action $true
                    $actual = Invoke-AdmxChild $name $action $false
                    Assert-Admx ($expected.Lines[0] -ceq "START $name" -and
                        $expected.Lines.Count -gt 1) "Frozen uncaught $name/$action did not begin and report the error."
                    if ($action -eq 'Stop') {
                        Assert-Admx ($expected.Exit -ne 0 -and
                            'RETURNED' -cnotin $expected.Lines) "Frozen uncaught $name Stop returned after the error."
                    }
                }
                Assert-AdmxSame $expected $actual "Uncaught $name/$action"
                $count++
            }
        }
    }
    'Uncaught' {
        if ($Original) {
            . ([scriptblock]::Create($script:OriginalSource))
        }
        Set-StrictMode -Version Latest
        $options = Get-AdmxFaultInput $Fault
        $ErrorView = 'CategoryView'
        $ErrorActionPreference = $Preference
        Write-Output "START $Fault"
        Resolve-ADAnalyzerRegistryPolicy @options | ForEach-Object { Write-Output ('row:' + $_.ValueName) }
        Write-Output 'RETURNED'
    }
}
Write-Host "PASS ADMX resolver $Case $count"
