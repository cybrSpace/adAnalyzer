[CmdletBinding()]
param([ValidateSet('RecordBaseline',
        'Construction',
        'Parity',
        'Presence',
        'Baselines',
        'Records',
        'XmlNames',
        'Xml',
        'Text',
        'Metadata',
        'Errors',
        'Ownership',
        'Isolation',
        'Serialization',
        'Loading')][string]$Case = 'Construction')
$ErrorActionPreference = 'Stop'

# A same-engine empty class identifies compiler-owned session-state fields.
class ADAnalyzerSecretIndicatorFixtureEmpty {
}
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$secretPath = Join-Path $repositoryRoot 'bin/ADSecret.ps1'
$baselinePath = Join-Path $PSScriptRoot 'SecretIndicatorBaseline.json'
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:Owned = [Collections.Generic.List[IDisposable]]::new()
$script:Names = @('Get-ADAnalyzerSecretNames',
    'Test-ADAnalyzerSecretName',
    'Test-ADAnalyzerSecretPresence',
    'Assert-ADAnalyzerValueBaseline',
    'ConvertTo-ADAnalyzerSecretRecord',
    'Get-ADAnalyzerXmlSecretName',
    'ConvertTo-ADAnalyzerSecretIndicatorXml',
    'ConvertTo-ADAnalyzerSecretIndicatorText')

function Assert-Secret($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-SecretHash([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-SecretXml([string]$Text) {
    $document = [xml]::new()
    $document.PreserveWhitespace = $true
    $document.XmlResolver = $null
    if ($Text) {
        $document.LoadXml($Text)
    }
    return $document
}

function New-SecretSecure([bool]$Present) {
    $value = [Security.SecureString]::new()
    if ($Present) {
        $value.AppendChar('x')
    }
    $script:Owned.Add($value)
    return $value
}

function New-SecretScenario([string]$Name, [string]$Operation, $Value, [bool]$Omit = $false) {
    [pscustomobject]@{
        Name = $Name
        Operation = $Operation
        Value = $Value
        Omit = $Omit
    }
}

function Get-SecretScenarios {
    New-SecretScenario Pattern Pattern $null
    $i = 0
    foreach ($name in @($null,
            '',
            'PASSWORD',
            'HKLM\Software\Password',
            'folder/password',
            'PasswordPresent',
            'prefixPassword',
            'PasswordSuffix',
            'ordinary')) {
        New-SecretScenario ('Name' + $i++) Name $name
    }
    New-SecretScenario NameOmitted Name $null $true
    $presence = @(@('Null',
            $null),
        @('Empty',
            ''),
        @('Whitespace',
            ' '),
        @('String',
            'ordinary'),
        @('False',
            $false),
        @('Zero',
            0),
        @('EmptyArray',
            [object[]]@()),
        @('Array',
            [object[]]@(1,
                2)),
        @('NullArray',
            [object[]]@($null)),
        @('EmptyMap',
            @{}),
        @('Map',
            @{
                Item = 1
            }), @('EmptyOrdered', [ordered]@{}), @('Ordered', [ordered]@{
                Item = 1
            }),
        @('EmptyList',
            [Collections.ArrayList]::new()),
        @('EmptyGeneric',
            [Collections.Generic.Dictionary[string,
            object]]::new()),
        @('EmptySecure',
            (New-SecretSecure $false)),
        @('Secure',
            (New-SecretSecure $true)),
        @('EmptyCredential',
            [pscredential]::new('fixture',
                (New-SecretSecure $false))),
        @('Credential',
            [pscredential]::new('fixture',
                (New-SecretSecure $true))))
    foreach ($row in $presence) {
        New-SecretScenario ('Presence' + $row[0]) Presence $row[1]
    }
    New-SecretScenario PresenceOmitted Presence $null $true
    $i = 0
    foreach ($profile in @($null, @{}, @{
                RegistryRules = @(@{
                        Key = 'Software\Password'
                        ValueName = 'Enabled'
                    })
            }, @{
                ExpectedGpoSettings = @(@{
                        Kind = 'Ini'
                        Name = 'ordinary'
                        ValueName = 'Password'
                    })
            }, @{
                Host = @{
                    RegistryRules = @(@{
                            Key = 'Password'
                            ValueName = 'Enabled'
                        })
                }
            })) {
        New-SecretScenario ('Baseline' + $i++) Baseline $profile
    }
    New-SecretScenario BaselineOmitted Baseline $null $true
    $records = @([pscustomobject][ordered]@{
            Name = 'ordinary'
            Value = 0
        }, [pscustomobject][ordered]@{
            Name = 'Password'
            Value = 'fixture'
            RawData = 'fixture'
            Data = 1
            Bytes = @(1)
            Note = 'keep'
        }, [pscustomobject][ordered]@{
            ValueName = 'Password'
            Value = ''
            SecretPresent = $true
        }, [pscustomobject][ordered]@{
            Attribute = 'Password'
            Value = ''
            SecretPresent = 'true'
        }, [pscustomobject][ordered]@{
            PropertyName = 'Password'
            RawData = 'fixture'
        }, [pscustomobject][ordered]@{
            Name = 'Password'
            Value = $false
            SecretPresent = $false
        }, [pscustomobject][ordered]@{
            Name = 'ordinary'
            ValueName = 'Password'
            Value = $null
        }, [object[]]@(1, 2))
    $i = 0
    foreach ($record in $records) {
        New-SecretScenario ('Record' + $i++) Record $record
    }
    New-SecretScenario XmlNameNull XmlName $null
    New-SecretScenario XmlNameOmitted XmlName $null $true
    $i = 0
    foreach ($text in @('<Setting Name="ordinary" ValueName="Password"><Name>apiKey</Name></Setting>',
            '<Setting ValueName="apiKey" Name="Password" />',
            '<Setting><Name>ordinary</Name><PropertyName>Password</PropertyName></Setting>',
            '<Setting><PropertyName>apiKey</PropertyName><Name>Password</Name></Setting>',
            '<Setting name="ordinary" />')) {
        New-SecretScenario ('XmlName' + $i++) XmlName (New-SecretXml $text).PSBase.DocumentElement
    }
    $i = 0
    $j = 0
    foreach ($text in @('',
            '<Root />',
            '<Root Password="fixture"><Password>fixture</Password></Root>',
            '<Properties name="Password" value="fixture" />',
            '<Setting Name="Password"><Expected>fixture</Expected></Setting>',
            '<Root><PasswordPresent>true</PasswordPresent><Note>keep</Note></Root>',
            '<Outer xmlns:p="urn:fixture"><p:Item>café</p:Item></Outer>')) {
        $document = New-SecretXml $text
        New-SecretScenario ('XmlDocument' + $i++) Xml $document
        if ($null -ne $document.PSBase.DocumentElement) {
            New-SecretScenario ('XmlElement' + $j++) Xml $document.PSBase.DocumentElement
        }
    }
    $i = 0
    foreach ($text in @($null,
            '',
            'ordinary',
            'Password age >90',
            'password="fixture"',
            "password=''; apiKey='fixture'",
            '<Root password="fixture"/>',
            '<Password>fixture</Password><Note>keep</Note>',
            'broken <Root cpassword="fixture"',
            '<Root><!-- <!DOCTYPE Root> --></Root>',
            '<Root><OuterXml><Password>fixture</Password></OuterXml></Root>')) {
        New-SecretScenario ('Text' + $i++) Text $text
    }
    New-SecretScenario TextOmitted Text $null $true
}

function Invoke-SecretScenario($Scenario, $Service) {
    $value = $Scenario.Value
    if ($null -ne $Service) {
        switch ($Scenario.Operation) {
            Pattern {
                $Service.GetNamePattern()
            }
            Name {
                $Service.IsSecretName([string]$value)
            }
            Presence {
                $Service.IsPresent($value)
            }
            Baseline {
                $Service.AssertValueBaseline($value)
            }
            Record {
                $Service.ProjectRecord($value)
            }
            XmlName {
                $Service.FindXmlSecretName($value)
            }
            Xml {
                $Service.ProjectXml($value)
            }
            Text {
                $Service.ProjectText([string]$value)
            }
        }
        return
    }
    switch ($Scenario.Operation) {
        Pattern {
            Get-ADAnalyzerSecretNames
        }
        Name {
            if ($Scenario.Omit) {
                Test-ADAnalyzerSecretName
            }
            else {
                Test-ADAnalyzerSecretName -Name $value
            }
        }
        Presence {
            if ($Scenario.Omit) {
                Test-ADAnalyzerSecretPresence
            }
            else {
                Test-ADAnalyzerSecretPresence -Value $value
            }
        }
        Baseline {
            if ($Scenario.Omit) {
                Assert-ADAnalyzerValueBaseline
            }
            else {
                Assert-ADAnalyzerValueBaseline -Profile $value
            }
        }
        Record {
            ConvertTo-ADAnalyzerSecretRecord -Record $value
        }
        XmlName {
            if ($Scenario.Omit) {
                Get-ADAnalyzerXmlSecretName
            }
            else {
                Get-ADAnalyzerXmlSecretName -Node $value
            }
        }
        Xml {
            ConvertTo-ADAnalyzerSecretIndicatorXml -Node $value
        }
        Text {
            if ($Scenario.Omit) {
                ConvertTo-ADAnalyzerSecretIndicatorText
            }
            else {
                ConvertTo-ADAnalyzerSecretIndicatorText -Text $value
            }
        }
    }
}

function Get-SecretValue($Value) {
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [Xml.XmlNode]) {
        return [pscustomobject][ordered]@{
            Type = $Value.GetType().FullName
            Xml = $Value.PSBase.OuterXml
        }
    }
    if ($Value -is [bool] -or $Value -is [string] -or $Value -is [ValueType]) {
        return [pscustomobject][ordered]@{
            Type = $Value.GetType().FullName
            Value = $Value
        }
    }

    if ($Value -is [Collections.IDictionary]) {
        $entries = @(
            foreach ($key in @($Value.Keys | Sort-Object)) {
                [pscustomobject][ordered]@{
                    Key = Get-SecretValue $key
                    Value = Get-SecretValue $Value[$key]
                }
            }
        )
        return [pscustomobject][ordered]@{
            Type = $Value.GetType().FullName
            Entries = $entries
        }
    }
    if ($Value -is [array] -or $Value -is [Collections.IList]) {
        $items = @(
            foreach ($item in $Value) {
                Get-SecretValue $item
            }
        )
        return [pscustomobject][ordered]@{
            Type = $Value.GetType().FullName
            Items = $items
        }
    }
    $properties = @(foreach ($property in $Value.PSObject.Properties) {
            [pscustomobject][ordered]@{
                Name = $property.Name
                Value = Get-SecretValue $property.Value
            }
        })
    [pscustomobject][ordered]@{
        Type = $Value.GetType().FullName
        Properties = $properties
    }
}

function Get-SecretResult($Scenario, $Service) {
    $rows = [Collections.Generic.List[object]]::new()
    Invoke-SecretScenario $Scenario $Service | ForEach-Object { $rows.Add((Get-SecretValue $_)) }
    [pscustomobject][ordered]@{
        Name = $Scenario.Name
        Operation = $Scenario.Operation
        Count = $rows.Count
        Rows = $rows.ToArray()
    }
}

function Get-SecretMetadata([string]$Name) {
    $command = Get-Command $Name
    $parameters = @(foreach ($key in @($command.Parameters.Keys | Sort-Object)) {
            $parameter = $command.Parameters[$key]
            [pscustomobject][ordered]@{
                Name = $key
                Type = $parameter.ParameterType.FullName
                Aliases = @($parameter.Aliases)
                Sets = @(foreach ($set in @($parameter.ParameterSets.Keys | Sort-Object)) {
                        $value = $parameter.ParameterSets[$set]
                        [pscustomobject][ordered]@{
                            Name = $set
                            Mandatory = $value.IsMandatory
                            Position = $value.Position
                            Pipeline = $value.ValueFromPipeline
                            PipelineByName = $value.ValueFromPipelineByPropertyName
                            Remaining = $value.ValueFromRemainingArguments
                        }
                    })
                Attributes = @($parameter.Attributes | ForEach-Object { $_.GetType().FullName })
            }
        })
    [pscustomobject][ordered]@{
        Name = $Name
        Advanced = $command.CmdletBinding
        Parameters = $parameters
    }
}

function ConvertTo-SecretJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 50 -Compress
}

function Get-SecretErrorScenarios {
    $document = New-SecretXml '<Root />'
    $dtd = New-SecretXml '<!DOCTYPE Root [<!ENTITY x "fixture">]><Root><Password>&x;</Password></Root>'
    @(
        [pscustomobject]@{
            Name = 'RecordNull'
            Command = 'ConvertTo-ADAnalyzerSecretRecord'
            Value = $null
            ReferenceBody = 'throw "Binding should reject null."'
        }
        [pscustomobject]@{
            Name = 'XmlNull'
            Command = 'ConvertTo-ADAnalyzerSecretIndicatorXml'
            Value = $null
            ReferenceBody = 'throw "Binding should reject null."'
        }
        [pscustomobject]@{
            Name = 'XmlKind'
            Command = 'ConvertTo-ADAnalyzerSecretIndicatorXml'
            Value = $document.CreateTextNode('fixture')
            ReferenceBody = 'throw [ArgumentException]::new(''XML projection supports Document and Element nodes only.'', ''Node'')'
        }
        [pscustomobject]@{
            Name = 'XmlDtd'
            Command = 'ConvertTo-ADAnalyzerSecretIndicatorXml'
            Value = $dtd
            ReferenceBody = 'throw [IO.InvalidDataException]::new(''DTD declarations are not supported in secret-presence projection.'')'
        }
        [pscustomobject]@{
            Name = 'BaselineIdentity'
            Command = 'Assert-ADAnalyzerValueBaseline'
            Value = @{
                RegistryRules = @(@{
                        Name = 1
                    })
            }
            ReferenceBody = 'throw ''Custom value baseline identity fields must be strings or null.'''
        }
        [pscustomobject]@{
            Name = 'BaselineSecret'
            Command = 'Assert-ADAnalyzerValueBaseline'
            Value = @{
                RegistryRules = @(@{
                        ValueName = 'Password'
                    })
            }
            ReferenceBody = 'throw ''Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'''
        }
        [pscustomobject]@{
            Name = 'TextDtd'
            Command = 'ConvertTo-ADAnalyzerSecretIndicatorText'
            Value = '<!DOCTYPE Root><Root><Password /></Root>'
            ReferenceBody = 'throw [IO.InvalidDataException]::new(''DTD declarations are not supported in secret-presence projection.'')'
        }
    )
}

function Invoke-SecretErrorCommand($Scenario) {
    $value = $Scenario.Value
    switch ($Scenario.Command) {
        'ConvertTo-ADAnalyzerSecretRecord' {
            ConvertTo-ADAnalyzerSecretRecord -Record $value
        }
        'ConvertTo-ADAnalyzerSecretIndicatorXml' {
            ConvertTo-ADAnalyzerSecretIndicatorXml -Node $value
        }
        'Assert-ADAnalyzerValueBaseline' {
            Assert-ADAnalyzerValueBaseline -Profile $value
        }
        'ConvertTo-ADAnalyzerSecretIndicatorText' {
            ConvertTo-ADAnalyzerSecretIndicatorText -Text $value
        }
    }
}

function Get-SecretErrorProjection($Record) {
    $target = if ($null -eq $Record.TargetObject) {
        $null
    }
    elseif ($Record.TargetObject -is [Xml.XmlNode]) {
        [pscustomobject][ordered]@{
            Type = $Record.TargetObject.GetType().FullName
            NodeType = [string]$Record.TargetObject.PSBase.NodeType
        }
    }
    else {
        [pscustomobject][ordered]@{
            Type = $Record.TargetObject.GetType().FullName
            Text = [string]$Record.TargetObject
        }
    }
    [pscustomobject][ordered]@{
        ExceptionType = $Record.Exception.GetType().FullName
        BaseExceptionType = $Record.Exception.GetBaseException().GetType().FullName
        Message = $Record.Exception.Message
        FullyQualifiedErrorId = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Reason = $Record.CategoryInfo.Reason
        TargetName = $Record.CategoryInfo.TargetName
        TargetType = $Record.CategoryInfo.TargetType
        TargetObject = $target
        ErrorDetails = if ($null -ne $Record.ErrorDetails) {
            $Record.ErrorDetails.Message
        }
        else {
            $null
        }
    }
}

function Get-SecretErrorRow($Scenario, [string]$Preference) {
    $ErrorActionPreference = $Preference
    $errors = [Collections.Generic.List[object]]::new()
    $rows = [Collections.Generic.List[object]]::new()
    $caught = $false
    $stack = $null
    try {
        Invoke-SecretErrorCommand $Scenario 2>&1 | ForEach-Object {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                $errors.Add((Get-SecretErrorProjection $_))
                $stack = $_.ScriptStackTrace
            }
            else {
                $rows.Add((Get-SecretValue $_))
            }
        }
    }
    catch {
        $caught = $true
        $stack = $_.ScriptStackTrace
        $errors.Add((Get-SecretErrorProjection $_))
    }
    [pscustomobject][ordered]@{
        Name = $Scenario.Name
        Preference = $Preference
        Caught = $caught
        Count = $rows.Count
        Rows = $rows.ToArray()
        Errors = $errors.ToArray()
        OriginalStack = $stack
    }
}

function Get-SecretReferenceContracts($Service) {
    $nested = [pscustomobject]@{
        Note = 'metadata'
    }
    $ordinary = [pscustomobject][ordered]@{
        Name = 'ordinary'
        Value = 0
        Metadata = $nested
    }
    $secret = [pscustomobject][ordered]@{
        Name = 'Password'
        Value = 'fixture'
        RawData = 'fixture'
        Data = @(1)
        Bytes = @(1)
        Metadata = $nested
    }
    $before = ConvertTo-SecretJson (Get-SecretValue $secret)
    if ($null -eq $Service) {
        $ordinaryResult = ConvertTo-ADAnalyzerSecretRecord $ordinary
        $secretResult = ConvertTo-ADAnalyzerSecretRecord $secret
        $again = ConvertTo-ADAnalyzerSecretRecord $secretResult
        $arrayRows = @(ConvertTo-ADAnalyzerSecretRecord -Record ([object[]]@(1, 2)))
    }
    else {
        $ordinaryResult = $Service.ProjectRecord($ordinary)
        $secretResult = $Service.ProjectRecord($secret)
        $again = $Service.ProjectRecord($secretResult)
        $arrayRows = @($Service.ProjectRecord([object[]]@(1, 2)))
    }
    [pscustomobject][ordered]@{
        OrdinarySameReference = [object]::ReferenceEquals($ordinary, $ordinaryResult)
        SecretNewTop = -not [object]::ReferenceEquals($secret, $secretResult)
        SharedMetadataReference = [object]::ReferenceEquals($nested, $secretResult.Metadata)
        SourceUnchanged = $before -ceq (ConvertTo-SecretJson (Get-SecretValue $secret))
        RemovedFields = @(@('Value', 'RawData', 'Data', 'Bytes') | Where-Object { $null -eq $secretResult.PSObject.Properties[$_] })
        FlagType = $secretResult.SecretPresent.GetType().FullName
        Flag = $secretResult.SecretPresent
        Idempotent = (ConvertTo-SecretJson (Get-SecretValue $secretResult)) -ceq (ConvertTo-SecretJson (Get-SecretValue $again))
        OrdinaryArrayCount = $arrayRows.Count
        OrdinaryArrayTypes = @($arrayRows | ForEach-Object { $_.GetType().FullName })
    }
}

$script:ExecutedScenarios = 0
$script:Marker = 'SECRET_INDICATOR_FIXTURE_078'
$script:GetterCalls = 0
$script:Unexpected = 0
$script:OwnedTypeData = [Collections.Generic.List[string]]::new()

# Exact signatures from accepted U077 ParseFile FunctionDefinitionAst nodes.
# The immutable capture's Metadata is correct; its Parameters field was empty
# because Get-Command exposes a FunctionDefinitionAst on this engine.
$script:ReferenceParameters = @{
    'Get-ADAnalyzerSecretNames' = ''
    'Test-ADAnalyzerSecretName' = 'param([string]$Name)'
    'Test-ADAnalyzerSecretPresence' = 'param([AllowNull()]$Value)'
    'Assert-ADAnalyzerValueBaseline' = 'param([hashtable]$Profile)'
    'ConvertTo-ADAnalyzerSecretRecord' = 'param([Parameter(Mandatory)]$Record)'
    'Get-ADAnalyzerXmlSecretName' = 'param([Xml.XmlNode]$Node)'
    'ConvertTo-ADAnalyzerSecretIndicatorXml' = 'param([Parameter(Mandatory)][Xml.XmlNode]$Node)'
    'ConvertTo-ADAnalyzerSecretIndicatorText' = 'param([string]$Text)'
}

function Get-SecretCommandBody($Command) {
    $ast = $Command.ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        return $ast.Body
    }
    return $ast
}

function Get-SecretParameterText($Command) {
    $body = Get-SecretCommandBody $Command
    if ($null -ne $body.ParamBlock) {
        return $body.ParamBlock.Extent.Text
    }
    return ''
}

function Assert-SecretOperation([string]$Operation, $Scenarios, $Baseline, $Service) {
    foreach ($scenario in @($Scenarios | Where-Object Operation -eq $Operation)) {
        $expected = @($Baseline.Results | Where-Object Name -ceq $scenario.Name)
        Assert-Secret ($expected.Count -eq 1) 'Frozen scenario identity is ambiguous.'
        $before = if ($scenario.Value -is [Xml.XmlNode]) {
            ConvertTo-SecretJson (Get-SecretXmlState $scenario.Value)
        }
        else {
            $null
        }
        foreach ($target in @($null, $Service)) {
            $actual = Get-SecretResult $scenario $target
            Assert-Secret ((ConvertTo-SecretJson $actual) -ceq (ConvertTo-SecretJson $expected[0])) ('Frozen output/type/cardinality changed: ' + $scenario.Name)
        }
        if ($null -ne $before) {
            Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretXmlState $scenario.Value))) 'Projection changed an XML source.'
        }
        $script:ExecutedScenarios++
    }
}

function Assert-SecretFailure([scriptblock]$Body, [string]$TypeName, [string]$Message, [string]$ParameterName = '') {
    $rows = [Collections.Generic.List[object]]::new()
    $caught = $null
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $caught = $_
    }
    Assert-Secret ([bool]$caught) 'Expected an explicit failure.'
    Assert-Secret ($rows.Count -eq 0) 'Failure emitted partial data.'
    $cause = $caught.Exception.GetBaseException()
    Assert-Secret ($cause.GetType().FullName -ceq $TypeName) 'Failure lost its diagnostic cause.'
    if ($Message) {
        Assert-Secret ($cause.Message.Contains($Message)) 'Failure lost its diagnostic message.'
    }
    if ($ParameterName) {
        Assert-Secret ($cause.ParamName -ceq $ParameterName) 'Failure lost its argument identity.'
    }
    Assert-Secret (-not $caught.ToString().Contains($script:Marker)) 'Failure echoed a fixture payload.'
}

function New-SecretRuleProfile([string]$Location, $Rule) {
    switch ($Location) {
        RegistryRules {
            @{
                RegistryRules = @($Rule)
            }
        }
        ExpectedGpoSettings {
            @{
                ExpectedGpoSettings = @($Rule)
            }
        }
        Host {
            @{
                Host = @{
                    RegistryRules = @($Rule)
                }
            }
        }
    }
}

function Add-SecretShadow($Value, [string]$Name, $Shadow, [Management.Automation.PSMemberTypes]$MemberType = 'NoteProperty') {
    $wrapped = [Management.Automation.PSObject]::AsPSObject($Value)
    $typeName = 'ADAnalyzer.SecretIndicatorFixture.' + [guid]::NewGuid().ToString('N')
    $wrapped.PSTypeNames.Insert(0, $typeName)
    Update-TypeData -TypeName $typeName -MemberType $MemberType -MemberName $Name -Value $Shadow
    $script:OwnedTypeData.Add($typeName)
    return , $wrapped
}

function Get-SecretNativeState($Value) {
    $native = if ($Value -is [pscredential]) {
        $Value.PSBase.Password.PSBase.Length
    }
    elseif ($Value -is [Security.SecureString] -or $Value -is [string]) {
        $Value.PSBase.Length
    }
    elseif ($Value -is [Collections.ICollection]) {
        [Collections.ICollection].GetProperty('Count').GetValue($Value, $null)
    }
    else {
        '<scalar>'
    }
    ConvertTo-SecretJson ([pscustomobject][ordered]@{
            Type = $Value.GetType().FullName
            Native = $native
            TypeNames = @($Value.PSTypeNames)
            Members = @(
                $Value.PSObject.Properties | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name
                        Kind = [string]$_.MemberType
                    }
                }
            )
        })
}

function Get-SecretNativeCases {
    [pscustomobject]@{
        Value = @{
            Count = 0
            Item = $script:Marker
        }
        Expected = $true
    }
    [pscustomobject]@{
        Value = [ordered]@{
            Count = 0
            Item = $script:Marker
        }
        Expected = $true
    }
    $map = [Collections.Generic.Dictionary[string, object]]::new()
    $map.Add('Count', 0)
    $map.Add('Item', $script:Marker)
    [pscustomobject]@{
        Value = $map
        Expected = $true
    }
    [pscustomobject]@{
        Value = (Add-SecretShadow ([object[]]@(1, 2)) Count 0)
        Expected = $true
    }
    [pscustomobject]@{
        Value = (Add-SecretShadow ([object[]]@()) Count 9)
        Expected = $false
    }
    [pscustomobject]@{
        Value = (Add-SecretShadow (New-SecretSecure $true) Length 0)
        Expected = $true
    }
    [pscustomobject]@{
        Value = (Add-SecretShadow (New-SecretSecure $false) Length 9)
        Expected = $false
    }
    [pscustomobject]@{
        Value = (Add-SecretShadow $script:Marker Length 0)
        Expected = $true
    }
    [pscustomobject]@{
        Value = (Add-SecretShadow '' Length 9)
        Expected = $false
    }
    $credential = [pscredential]::new('fixture', (New-SecretSecure $true))
    [pscustomobject]@{
        Value = (Add-SecretShadow $credential Password (New-SecretSecure $false))
        Expected = $true
    }
    $credential = [pscredential]::new('fixture', (New-SecretSecure $false))
    [pscustomobject]@{
        Value = (Add-SecretShadow $credential Password (New-SecretSecure $true))
        Expected = $false
    }
    $password = New-SecretSecure $true
    $null = Add-SecretShadow $password Length 0
    [pscustomobject]@{
        Value = [pscredential]::new('fixture', $password)
        Expected = $true
    }
}

function Get-SecretXmlState([Xml.XmlNode]$Node) {
    [pscustomobject][ordered]@{
        Type = [string]$Node.PSBase.NodeType
        Name = $Node.PSBase.Name
        Value = $Node.PSBase.Value
        Xml = $Node.PSBase.OuterXml
        IsEmpty = if ($Node -is [Xml.XmlElement]) {
            $Node.PSBase.IsEmpty
        }
        else {
            $null
        }
        Attributes = @(
            foreach ($attribute in $Node.PSBase.Attributes) {
                [pscustomobject][ordered]@{
                    Name = $attribute.PSBase.Name
                    Value = $attribute.PSBase.Value
                    Specified = $attribute.PSBase.Specified
                }
            }
        )
        Children = @(
            foreach ($child in $Node.PSBase.ChildNodes) {
                Get-SecretXmlState $child
            }
        )
    }
}

function New-SecretDefaultDocument {
    $schema = '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:element name="Root"><xs:complexType><xs:sequence><xs:element name="Child"><xs:complexType><xs:attribute name="ChildMode" type="xs:string" default="child-default" /></xs:complexType></xs:element></xs:sequence><xs:attribute name="Mode" type="xs:string" default="root-default" /><xs:attribute name="Password" type="xs:string" default="PAYLOAD" /></xs:complexType></xs:element></xs:schema>'
    $schema = $schema.Replace('PAYLOAD', $script:Marker)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $textReader = [IO.StringReader]::new($schema)
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create($textReader, $settings)
        $document = New-SecretXml '<Root><Child /></Root>'
        $null = $document.Schemas.Add('', $reader)
        $document.Validate($null)
        return $document
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        $textReader.Dispose()
    }
}

function Assert-SecretDetachedXml([Xml.XmlNode]$Result, [Xml.XmlDocument]$Source) {
    Assert-Secret (-not [object]::ReferenceEquals($Result, $Source)) 'XML result aliases its source.'
    $owner = if ($Result -is [xml]) {
        $Result
    }
    else {
        $Result.PSBase.OwnerDocument
    }
    Assert-Secret (-not [object]::ReferenceEquals($owner, $Source)) 'XML result retains its source owner.'
    Assert-Secret ($owner.PSBase.Schemas.Count -eq 0) 'XML result retains source schemas.'
    Assert-Secret (-not [object]::ReferenceEquals($owner.PSBase.Schemas, $Source.PSBase.Schemas)) 'XML result shares source schema state.'
    if ($Result -is [Xml.XmlElement]) {
        Assert-Secret ($null -eq $Result.PSBase.ParentNode -and
            $owner.PSBase.ChildNodes.Count -eq 0) 'Detached element gained an owner tree.'
        Assert-Secret (-not [object]::ReferenceEquals($owner.PSBase.NameTable,
                $Source.PSBase.NameTable)) 'Detached element shares source names.'
        Assert-Secret (-not $owner.PSBase.OuterXml.Contains($script:Marker)) 'Detached owner retains a raw sibling.'
    }
    $stack = [Collections.Generic.Stack[Xml.XmlNode]]::new()
    $stack.Push($Result)
    while ($stack.Count) {
        $node = $stack.Pop()
        $information = $node.PSBase.SchemaInfo
        if ($null -ne $information) {
            Assert-Secret ($null -eq $information.SchemaType -and
                $null -eq $information.SchemaElement -and
                $null -eq $information.SchemaAttribute) 'XML result retains source schema metadata.'
        }
        foreach ($child in $node.PSBase.ChildNodes) {
            $stack.Push($child)
        }
        foreach ($attribute in $node.PSBase.Attributes) {
            $stack.Push($attribute)
        }
    }
}

function Get-SecretComparableError($Row) {
    [pscustomobject][ordered]@{
        Name = $Row.Name
        Preference = $Row.Preference
        Caught = $Row.Caught
        Count = $Row.Count
        Rows = $Row.Rows
        Errors = $Row.Errors
    }
}

function Invoke-SecretFresh([string]$Text, [string]$Marker) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    $executable = (Get-Process -Id $PID).Path
    $output = & $executable -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
    Assert-Secret ($LASTEXITCODE -eq 0) 'Fresh loading process failed.'
    Assert-Secret (($output -join ' ').Contains($Marker)) 'Fresh loading process did not execute its constructor and command checks.'
}

function Get-SecretPipelineRow([string]$Name, [hashtable]$Parameters, [string]$Preference) {
    $ErrorActionPreference = $Preference
    $rows = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()
    $caught = $false
    try {
        @(1, 2) | & $Name @Parameters 2>&1 | ForEach-Object {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                $errors.Add((Get-SecretErrorProjection $_))
            }
            else {
                $rows.Add((Get-SecretValue $_))
            }
        }
    }
    catch {
        $caught = $true
        $errors.Add((Get-SecretErrorProjection $_))
    }
    [pscustomobject][ordered]@{
        Caught = $caught
        Rows = $rows.ToArray()
        Errors = $errors.ToArray()
    }
}

try {
    $scenarios = @(Get-SecretScenarios)
    if ($Case -eq 'RecordBaseline') {
        Assert-Secret (-not ('ADAnalyzerSecretIndicator' -as [type])) 'Capture accepted command behavior before class migration.'
        Assert-Secret (-not [IO.File]::Exists($baselinePath)) 'Secret indicator baseline already exists.'
        $before = Get-SecretHash $secretPath
        Assert-Secret ($before -ceq 'd2c293a35b355d06c35fa199d7f1ff0edda04b61b90d959745b4fdd315af6c71') 'Capture source differs from accepted U077.'
        $definitions = @(
            foreach ($name in $script:Names) {
                $command = Get-Command $name
                $param = if ($null -ne $command.ScriptBlock.Ast.ParamBlock) {
                    $command.ScriptBlock.Ast.ParamBlock.Extent.Text
                }
                else {
                    ''
                }
                [pscustomobject][ordered]@{
                    Name = $name
                    Parameters = $param
                    Metadata = Get-SecretMetadata $name
                }
            }
        )
        $results = @($scenarios | ForEach-Object { Get-SecretResult $_ $null })
        $errorRows = @(
            foreach ($errorScenario in @(Get-SecretErrorScenarios)) {
                foreach ($preference in @('Continue', 'Stop')) {
                    Get-SecretErrorRow $errorScenario $preference
                }
            }
        )
        $baseline = [pscustomobject][ordered]@{
            SourceRevision = 'c5eaf5ec151487419d2c6f82bf596ec5a0d27a32'
            SourceSha256 = $before
            Runtime = [string]$PSVersionTable.PSVersion
            Definitions = $definitions
            Results = $results
            Errors = $errorRows
            ReferenceContracts = Get-SecretReferenceContracts $null
        }
        Assert-Secret ($errorRows.Count -eq 14) 'Required error cases were not all captured.'
        Assert-Secret ($before -ceq (Get-SecretHash $secretPath)) 'Source changed during capture.'
        [IO.File]::WriteAllText($baselinePath, (ConvertTo-Json -InputObject $baseline -Depth 50), [Text.UTF8Encoding]::new($true))
        Write-Host ('BASELINE FROZEN ' + $results.Count + '; errors=' + $errorRows.Count + '; sourceSHA256=' + $before + '; baselineSHA256=' + (Get-SecretHash $baselinePath))
        return
    }

    $baseline = Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Secret ($baseline.SourceRevision -ceq 'c5eaf5ec151487419d2c6f82bf596ec5a0d27a32' -and
        $baseline.SourceSha256 -ceq 'd2c293a35b355d06c35fa199d7f1ff0edda04b61b90d959745b4fdd315af6c71') 'Frozen source identity changed.'
    Assert-Secret ($baseline.Results.Count -eq 77 -and
        $baseline.Errors.Count -eq 14 -and
        $baseline.Definitions.Count -eq 8) 'Frozen coverage changed.'
    $service = [ADAnalyzerSecretIndicator]::new()
    switch ($Case) {
        'Construction' {
            $type = $service.GetType()
            Assert-Secret ($type.Name -ceq 'ADAnalyzerSecretIndicator' -and
                $type.GetConstructors().Count -eq 1 -and
                $type.GetConstructors()[0].GetParameters().Count -eq 0) 'Literal no-argument constructor is unavailable.'
            $script:ExecutedScenarios++
            $flags = [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::DeclaredOnly
            $control = [ADAnalyzerSecretIndicatorFixtureEmpty]::new()
            $fieldShape = @(
                $type.GetFields($flags) | ForEach-Object {
                    $_.Name + ':' + $_.FieldType.FullName
                } | Sort-Object
            )
            $controlFieldShape = @(
                $control.GetType().GetFields($flags) | ForEach-Object {
                    $_.Name + ':' + $_.FieldType.FullName
                } | Sort-Object
            )
            $tokens = $null
            $parseErrors = $null
            $sourceAst = [Management.Automation.Language.Parser]::ParseFile(
                $secretPath,
                [ref]$tokens,
                [ref]$parseErrors
            )
            $sourceType = @($sourceAst.FindAll({
                        param($node)
                        $node -is [Management.Automation.Language.TypeDefinitionAst] -and
                        $node.Name -ceq 'ADAnalyzerSecretIndicator'
                    }, $true))
            Assert-Secret ($parseErrors.Count -eq 0 -and $sourceType.Count -eq 1) 'Service source was not parsed.'
            $applicationFields = @(
                $sourceType[0].Members | Where-Object {
                    $_ -is [Management.Automation.Language.PropertyMemberAst]
                }
            )
            Assert-Secret (
                ($fieldShape -join '|') -ceq ($controlFieldShape -join '|') -and
                $applicationFields.Count -eq 0 -and
                @($service.PSObject.Properties).Count -eq 0
            ) 'Stateless service gained application fields or properties.'
            $script:ExecutedScenarios++
            $methods = @($type.GetMethods() | Where-Object { $_.DeclaringType -eq $type } | ForEach-Object Name | Sort-Object)
            $expectedMethods = @('GetNamePattern',
                'IsSecretName',
                'IsPresent',
                'AssertValueBaseline',
                'ProjectRecord',
                'FindXmlSecretName',
                'ProjectXml',
                'ProjectText' | Sort-Object)
            Assert-Secret (($methods -join '|') -ceq ($expectedMethods -join '|')) 'The eight processing methods are incomplete.'
            $script:ExecutedScenarios++
            $other = [ADAnalyzerSecretIndicator]::new()
            Assert-Secret (-not [object]::ReferenceEquals($service, $other)) 'Independent constructors returned shared state.'
            $script:ExecutedScenarios++
            foreach ($name in @('Get-Content', 'Get-Item', 'Get-ChildItem', 'Import-Module', 'Read-Host', 'Invoke-Command')) {
                Set-Item -Path ('Function:' + $name) -Value {
                    $script:Unexpected++
                    throw 'Unexpected constructor effect.'
                }
            }
            $location = (Get-Location).Path
            $beforeErrors = $Error.Count
            $constructed = @([ADAnalyzerSecretIndicator]::new())
            Assert-Secret ($constructed.Count -eq 1 -and
                $constructed[0] -is [ADAnalyzerSecretIndicator] -and
                $script:Unexpected -eq 0 -and
                $Error.Count -eq $beforeErrors -and
                (Get-Location).Path -ceq $location) 'Construction performed an external effect or changed caller state.'
            $script:ExecutedScenarios++
            $pattern = $service.GetNamePattern()
            Assert-Secret ($pattern -is [string] -and
                $pattern.Length -eq 499 -and
                ($pattern -split '\|').Count -eq 33) 'Secret-name vocabulary changed.'
            $script:ExecutedScenarios++
        }
        'Parity' {
            foreach ($operation in @('Pattern', 'Name', 'Presence', 'Baseline', 'Record', 'XmlName', 'Xml', 'Text')) {
                Assert-SecretOperation $operation $scenarios $baseline $service
            }
            foreach ($name in ($service.GetNamePattern() -split '\|')) {
                Assert-Secret ($service.IsSecretName($name) -and
                    (Test-ADAnalyzerSecretName $name)) 'A captured secret-name alternative was lost.'
                $script:ExecutedScenarios++
            }
        }
        'Presence' {
            Assert-SecretOperation Presence $scenarios $baseline $service
            $nativeCases = @(Get-SecretNativeCases)
            Assert-Secret ($nativeCases.Count -eq 12) 'Native metadata cases are incomplete.'
            foreach ($sample in $nativeCases) {
                $before = Get-SecretNativeState $sample.Value
                foreach ($result in @($service.IsPresent($sample.Value), (Test-ADAnalyzerSecretPresence $sample.Value))) {
                    Assert-Secret ($result -is [bool] -and $result -eq $sample.Expected) 'Native metadata did not control presence.'
                }
                Assert-Secret ($before -ceq (Get-SecretNativeState $sample.Value)) 'Presence changed source metadata.'
                $script:ExecutedScenarios++
            }
            foreach ($preference in @('Continue', 'Stop')) {
                $password = New-SecretSecure $true
                $credential = [pscredential]::new('fixture', $password)
                $password.Dispose()
                foreach ($value in @($password, $credential)) {
                    $ErrorActionPreference = $preference
                    $beforeErrors = $Error.Count
                    $direct = @($service.IsPresent($value))
                    $command = @(Test-ADAnalyzerSecretPresence $value)
                    Assert-Secret ($direct.Count -eq 1 -and
                        $direct[0] -is [bool] -and
                        -not $direct[0] -and
                        $command.Count -eq 1 -and
                        $command[0] -is [bool] -and
                        -not $command[0] -and
                        $Error.Count -eq $beforeErrors) 'Disposed secret metadata changed its false/no-error contract.'
                    $script:ExecutedScenarios++
                }
            }
            $ErrorActionPreference = 'Stop'
            foreach ($sample in @(
                    @{
                        Value = [pscredential]::new('fixture', (New-SecretSecure $true))
                        Member = 'Password'
                    },
                    @{
                        Value = (New-SecretSecure $true)
                        Member = 'Length'
                    },
                    @{
                        Value = $script:Marker
                        Member = 'Length'
                    },
                    @{
                        Value = [object[]]@(1)
                        Member = 'Count'
                    }
                )) {
                $value = Add-SecretShadow $sample.Value $sample.Member {
                    $script:GetterCalls++
                    throw 'Adapted metadata getter must not run.'
                } ScriptProperty
                $before = Get-SecretNativeState $value
                $beforeCalls = $script:GetterCalls
                Assert-Secret ($service.IsPresent($value) -and (Test-ADAnalyzerSecretPresence $value)) 'Presence used an adapted getter.'
                Assert-Secret ($script:GetterCalls -eq $beforeCalls -and
                    $before -ceq (Get-SecretNativeState $value)) 'Presence invoked or changed an adapted getter.'
                $script:ExecutedScenarios++
            }
            Add-Type -TypeDefinition @'
using System;
using System.Collections;
namespace ADAnalyzer.SecretIndicatorFixture
{
    public sealed class NativeCollection : ICollection
    {
        private readonly int nativeCount;
        private readonly int publicCount;

        public NativeCollection(int nativeCount, int publicCount)
        {
            this.nativeCount = nativeCount;
            this.publicCount = publicCount;
        }

        public int Reads { get; private set; }

        public int Count
        {
            get
            {
                return publicCount;
            }
        }

        int ICollection.Count
        {
            get
            {
                Reads++;
                return nativeCount;
            }
        }

        public bool IsSynchronized
        {
            get
            {
                return false;
            }
        }

        public object SyncRoot
        {
            get
            {
                return this;
            }
        }

        public void CopyTo(Array array, int index)
        {
            throw new InvalidOperationException("Must not copy.");
        }

        public IEnumerator GetEnumerator()
        {
            throw new InvalidOperationException("Must not enumerate.");
        }
    }
}
'@
            foreach ($sample in @(
                    @{
                        Native = 0
                        Public = 0
                        Expected = $false
                    },
                    @{
                        Native = 2
                        Public = 2
                        Expected = $true
                    },
                    @{
                        Native = 2
                        Public = 0
                        Expected = $true
                    },
                    @{
                        Native = 0
                        Public = 9
                        Expected = $false
                    }
                )) {
                $value = [ADAnalyzer.SecretIndicatorFixture.NativeCollection]::new($sample.Native, $sample.Public)
                Assert-Secret ($service.IsPresent($value) -eq $sample.Expected -and
                    (Test-ADAnalyzerSecretPresence $value) -eq $sample.Expected -and
                    $value.Reads -eq 2) 'Presence changed explicit ICollection metadata or enumerated a value.'
                $script:ExecutedScenarios++
            }
        }
        'Baselines' {
            Assert-SecretOperation Baseline $scenarios $baseline $service
            foreach ($location in @('RegistryRules', 'ExpectedGpoSettings', 'Host')) {
                foreach ($field in @('Kind', 'Name', 'Key', 'ValueName')) {
                    $rule = @{}
                    $rule[$field] = 1
                    $profile = New-SecretRuleProfile $location $rule
                    $before = ConvertTo-SecretJson (Get-SecretValue $profile)
                    Assert-SecretFailure { $service.AssertValueBaseline($profile) } 'System.Management.Automation.RuntimeException' 'identity fields must be strings or null.'
                    Assert-SecretFailure { Assert-ADAnalyzerValueBaseline $profile } 'System.Management.Automation.RuntimeException' 'identity fields must be strings or null.'
                    Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretValue $profile))) 'Baseline validation changed a raw profile.'
                    $script:ExecutedScenarios++
                }
                foreach ($rule in @(@{
                            ValueName = 'Password'
                        }, [pscustomobject]@{
                            ValueName = 'Password'
                        })) {
                    $profile = New-SecretRuleProfile $location $rule
                    Assert-SecretFailure { $service.AssertValueBaseline($profile) } 'System.Management.Automation.RuntimeException' 'secret-bearing settings are not supported.'
                    Assert-SecretFailure { Assert-ADAnalyzerValueBaseline $profile } 'System.Management.Automation.RuntimeException' 'secret-bearing settings are not supported.'
                    $script:ExecutedScenarios++
                }
            }
            $generic = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
            $generic.Add('Kind', 'Ini')
            $generic.Add('Name', 'ordinary')
            $generic.Add('ValueName', 'Password')
            $rawCases = @(
                @{
                    Profile = @{
                        RegistryRules = @(@{
                                Kind = $null
                                Name = 'ordinary'
                                ValueName = 'Password'
                            })
                    }
                    Reject = $false
                },
                @{
                    Profile = @{
                        RegistryRules = @(@{
                                Kind = 'Ini'
                                Name = 'Password'
                                ValueName = 'ordinary'
                            })
                    }
                    Reject = $true
                },
                @{
                    Profile = @{
                        RegistryRules = @(@{
                                Name = 'Password'
                                Key = 'Password'
                                ValueName = 'Enabled'
                            })
                    }
                    Reject = $false
                },
                @{
                    Profile = @{
                        ExpectedGpoSettings = @($generic)
                    }
                    Reject = $false
                }
            )
            foreach ($sample in $rawCases) {
                $profile = $sample.Profile
                if ($sample.Reject) {
                    Assert-SecretFailure { $service.AssertValueBaseline($profile) } 'System.Management.Automation.RuntimeException' 'secret-bearing settings are not supported.'
                    Assert-SecretFailure { Assert-ADAnalyzerValueBaseline $profile } 'System.Management.Automation.RuntimeException' 'secret-bearing settings are not supported.'
                }
                else {
                    Assert-Secret (@($service.AssertValueBaseline($profile)).Count -eq 0 -and
                        @(Assert-ADAnalyzerValueBaseline $profile).Count -eq 0) 'Raw baseline precedence changed.'
                }
                $script:ExecutedScenarios++
            }
        }
        'Records' {
            Assert-SecretOperation Record $scenarios $baseline $service
            foreach ($label in @('Name', 'ValueName', 'Attribute', 'PropertyName')) {
                foreach ($sample in @(@{
                            Value = $null
                            Expected = $false
                        }, @{
                            Value = $false
                            Expected = $true
                        }, @{
                            Value = ''
                            Expected = $false
                        })) {
                    $fields = [ordered]@{}
                    $fields[$label] = 'Password'
                    $fields['Value'] = $sample.Value
                    $fields['RawData'] = $script:Marker
                    $fields['Data'] = @(1)
                    $fields['Bytes'] = @(1)
                    $fields['Note'] = 'keep'
                    $record = [pscustomobject]$fields
                    $before = ConvertTo-SecretJson (Get-SecretValue $record)
                    foreach ($result in @($service.ProjectRecord($record), (ConvertTo-ADAnalyzerSecretRecord $record))) {
                        Assert-Secret ($result.SecretPresent -is [bool] -and
                            $result.SecretPresent -eq $sample.Expected -and
                            $result.Note -ceq 'keep') 'Record label or native presence changed.'
                        foreach ($name in @('Value', 'RawData', 'Data', 'Bytes')) {
                            Assert-Secret ($null -eq $result.PSObject.Properties[$name]) 'Record retained a payload field.'
                        }
                    }
                    Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretValue $record))) 'Record projection changed its source.'
                    $script:ExecutedScenarios++
                }
            }
            Assert-Secret ((ConvertTo-SecretJson (Get-SecretReferenceContracts $service)) -ceq (ConvertTo-SecretJson $baseline.ReferenceContracts)) 'Shallow references, record idempotence or ordinary-array cardinality changed.'
            $script:ExecutedScenarios++
        }

        'XmlNames' {
            Assert-SecretOperation XmlName $scenarios $baseline $service
            foreach ($label in @('Name', 'ValueName', 'Attribute', 'AttributeName', 'Property', 'PropertyName', 'SettingName')) {
                foreach ($text in @(('<Setting ' + $label + '="Password" />'),
                        ('<Setting><' + $label + '>Password</' + $label + '></Setting>'))) {
                    $source = New-SecretXml $text
                    $before = ConvertTo-SecretJson (Get-SecretXmlState $source)
                    $node = $source.PSBase.DocumentElement
                    Assert-Secret ($service.FindXmlSecretName($node) -ceq 'Password' -and
                        (Get-ADAnalyzerXmlSecretName $node) -ceq 'Password') 'An XML identity label was lost.'
                    Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretXmlState $source))) 'XML identity lookup changed its source.'
                    $script:ExecutedScenarios++
                }
            }
            foreach ($sample in @(
                    @{
                        Text = '<Root><Attributes><Name>Password</Name></Attributes></Root>'
                        Expected = ''
                    },
                    @{
                        Text = '<p:Root xmlns:p="urn:fixture" p:Name="Password"><LocalName>ordinary</LocalName></p:Root>'
                        Expected = 'Password'
                    }
                )) {
                $source = New-SecretXml $sample.Text
                $node = $source.PSBase.DocumentElement
                Assert-Secret ($service.FindXmlSecretName($node) -ceq $sample.Expected -and
                    (Get-ADAnalyzerXmlSecretName $node) -ceq $sample.Expected) 'XML identity lookup selected adapted data.'
                $script:ExecutedScenarios++
            }
        }
        'Xml' {
            Assert-SecretOperation Xml $scenarios $baseline $service
            $document = New-SecretXml '<Root />'
            $attribute = $document.CreateAttribute('Password')
            $attribute.Value = $script:Marker
            $fragment = $document.CreateDocumentFragment()
            $fragment.InnerXml = '<Password>' + $script:Marker + '</Password>'
            $unsupported = @(
                $attribute,
                $document.CreateTextNode($script:Marker),
                $document.CreateCDataSection($script:Marker),
                $fragment,
                $document.CreateComment($script:Marker),
                $document.CreateProcessingInstruction('fixture', $script:Marker),
                $document.CreateXmlDeclaration('1.0', 'utf-16', 'yes'),
                $document.CreateDocumentType('Root', '', '', '<!ENTITY x "fixture">'),
                $document.CreateWhitespace('  '),
                $document.CreateSignificantWhitespace('  '),
                $document.CreateEntityReference('unresolved')
            )
            Assert-Secret ($unsupported.Count -eq 11) 'Unsupported XML kinds are incomplete.'
            foreach ($node in $unsupported) {
                $before = $node.PSBase.OuterXml
                Assert-SecretFailure { $service.ProjectXml($node) } 'System.ArgumentException' 'Document and Element nodes only.' 'Node'
                Assert-Secret ($before -ceq $node.PSBase.OuterXml) 'Unsupported XML rejection changed its source.'
                $script:ExecutedScenarios++
            }
            $source = New-SecretXml '<!DOCTYPE Root [<!ENTITY x "fixture">]><Root><Password>&x;</Password></Root>'
            foreach ($node in @($source, $source.PSBase.DocumentElement)) {
                $before = ConvertTo-SecretJson (Get-SecretXmlState $source)
                Assert-SecretFailure { $service.ProjectXml($node) } 'System.IO.InvalidDataException' 'DTD declarations are not supported'
                Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretXmlState $source))) 'DTD rejection changed its source.'
                $script:ExecutedScenarios++
            }
            foreach ($elementOnly in @($false, $true)) {
                $source = New-SecretDefaultDocument
                $before = ConvertTo-SecretJson (Get-SecretXmlState $source)
                $schemaType = $source.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType
                $node = if ($elementOnly) {
                    $source.PSBase.DocumentElement
                }
                else {
                    $source
                }
                $result = $service.ProjectXml($node)
                Assert-SecretDetachedXml $result $source
                $root = if ($result -is [xml]) {
                    $result.PSBase.DocumentElement
                }
                else {
                    $result
                }
                $mode = $root.GetAttributeNode('Mode')
                $childMode = $root.SelectSingleNode('./Child').GetAttributeNode('ChildMode')
                Assert-Secret ($root.GetAttribute('PasswordPresent') -ceq 'true' -and
                    -not $root.HasAttribute('Password')) 'XML schema default secret presence was lost.'
                Assert-Secret ($null -ne $mode -and
                    $mode.Value -ceq 'root-default' -and
                    -not $mode.Specified -and
                    $null -ne $childMode -and
                    $childMode.Value -ceq 'child-default' -and
                    -not $childMode.Specified) 'Ordinary XML defaults were lost or materialized.'
                Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretXmlState $source)) -and
                    [object]::ReferenceEquals($schemaType,
                        $source.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType)) 'XML projection changed source defaults or schemas.'
                Assert-Secret (-not (ConvertTo-Json `
                            -InputObject $result `
                            -Depth 30 `
                            -Compress).Contains($script:Marker) -and
                    -not [Management.Automation.PSSerializer]::Serialize($result).Contains($script:Marker)) 'Projected XML serialization retains source schema payload.'
                $script:ExecutedScenarios++
            }
            foreach ($elementOnly in @($false, $true)) {
                $source = New-SecretXml ('<Root><Item id="source"><Value>ordinary</Value></Item><Sibling Password="' + $script:Marker + '" /></Root>')
                $node = if ($elementOnly) {
                    $source.SelectSingleNode('/Root/Item')
                }
                else {
                    $source
                }
                $before = ConvertTo-SecretJson (Get-SecretXmlState $source)
                $first = $service.ProjectXml($node)
                $second = $service.ProjectXml($node)
                Assert-SecretDetachedXml $first $source
                Assert-SecretDetachedXml $second $source
                $firstRoot = if ($first -is [xml]) {
                    $first.PSBase.DocumentElement
                }
                else {
                    $first
                }
                $firstRoot.SetAttribute('changed', 'result')
                Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretXmlState $source))) 'Result mutation changed the source.'
                Assert-Secret (-not [object]::ReferenceEquals($first,
                        $second) -and
                    -not $second.PSBase.OuterXml.Contains('changed="result"')) 'XML results share mutable nodes.'
                $script:ExecutedScenarios++
            }
            $source = New-SecretXml ('<Root Password="' + $script:Marker + '"><Password>' + $script:Marker + '</Password></Root>')
            $first = $service.ProjectXml($source)
            $second = $service.ProjectXml($first)
            Assert-Secret ((ConvertTo-SecretJson (Get-SecretXmlState $first)) -ceq (ConvertTo-SecretJson (Get-SecretXmlState $second))) 'XML projection is not idempotent.'
            $script:ExecutedScenarios++
        }
        'Text' {
            Assert-SecretOperation Text $scenarios $baseline $service
            foreach ($name in ($service.GetNamePattern() -split '\|')) {
                $text = '<Root ' + $name + '="' + $script:Marker + '"/>'
                $expected = '<Root ' + $name + 'Present="true" />'
                Assert-Secret ($service.ProjectText($text) -ceq $expected -and
                    (ConvertTo-ADAnalyzerSecretIndicatorText $text) -ceq $expected) 'A secret-name alternative was lost in text projection.'
                $script:ExecutedScenarios++
            }
            foreach ($text in @(
                    '<!DOCTYPE Root><Root><Password /></Root>',
                    '<!DOCTYPE Root SYSTEM "urn:adanalyzer:must-not-resolve"><Root><Password /></Root>',
                    'prefix <!DOCTYPE Root><Root><Password /></Root>',
                    '<!DOCTYPE Root [<!ENTITY x "fixture">]<Root><Password>&x;</Password>',
                    '<Wrapper><!DOCTYPE Root><Root /></Wrapper>',
                    '<!doctype Root><Root><Password value="fixture"></Root>'
                )) {
                Assert-SecretFailure { $service.ProjectText($text) } 'System.IO.InvalidDataException' 'DTD declarations are not supported'
                $script:ExecutedScenarios++
            }
        }
        'Metadata' {
            $newline = [Environment]::NewLine
            foreach ($definition in $baseline.Definitions) {
                $command = Get-Command $definition.Name
                $parameters = Get-SecretParameterText $command
                $signature = $script:ReferenceParameters[$definition.Name]
                Assert-Secret ($parameters -ceq $signature) 'A compatibility parameter block changed.'
                $referenceText = 'function ' + $definition.Name + ' {' + $newline + $signature + $newline + '}'
                $expected = & {
                    param(
                        $Text,
                        $Name

                    )
                    . ([scriptblock]::Create($Text))
                    Get-SecretMetadata $Name
                } $referenceText $definition.Name
                $actual = Get-SecretMetadata $definition.Name
                Assert-Secret ((ConvertTo-SecretJson $actual) -ceq (ConvertTo-SecretJson $expected)) 'Compatibility metadata differs from its same-engine reference signature.'
                $advanced = $definition.Name -in @('ConvertTo-ADAnalyzerSecretRecord', 'ConvertTo-ADAnalyzerSecretIndicatorXml')
                Assert-Secret ($actual.Advanced -eq $advanced) 'Simple and advanced command contracts changed.'
                $body = Get-SecretCommandBody $command
                Assert-Secret ($body.EndBlock.Statements.Count -eq 1 -and
                    $command.ScriptBlock.ToString().Contains('ADAnalyzerSecretIndicator')) 'A compatibility command gained processing outside the service.'
                $script:ExecutedScenarios++
            }
            $pipelineNames = [ordered]@{
                Pattern = 'Pattern'
                Name = 'Name2'
                Presence = 'PresenceString'
                Baseline = 'Baseline0'
                Record = 'Record0'
                XmlName = 'XmlNameNull'
                Xml = 'XmlDocument1'
                Text = 'Text2'
            }
            $commandNames = @{
                Pattern = 'Get-ADAnalyzerSecretNames'
                Name = 'Test-ADAnalyzerSecretName'
                Presence = 'Test-ADAnalyzerSecretPresence'
                Baseline = 'Assert-ADAnalyzerValueBaseline'
                Record = 'ConvertTo-ADAnalyzerSecretRecord'
                XmlName = 'Get-ADAnalyzerXmlSecretName'
                Xml = 'ConvertTo-ADAnalyzerSecretIndicatorXml'
                Text = 'ConvertTo-ADAnalyzerSecretIndicatorText'
            }
            foreach ($operation in $pipelineNames.Keys) {
                $scenario = @($scenarios | Where-Object Name -ceq $pipelineNames[$operation])[0]
                $expected = @($baseline.Results | Where-Object Name -ceq $scenario.Name)[0]
                $parameters = switch ($operation) {
                    Pattern {
                        @{}
                    }
                    Name {
                        @{
                            Name = $scenario.Value
                        }
                    }
                    Presence {
                        @{
                            Value = $scenario.Value
                        }
                    }
                    Baseline {
                        @{
                            Profile = $scenario.Value
                        }
                    }
                    Record {
                        @{
                            Record = $scenario.Value
                        }
                    }
                    XmlName {
                        @{
                            Node = $scenario.Value
                        }
                    }
                    Xml {
                        @{
                            Node = $scenario.Value
                        }
                    }
                    Text {
                        @{
                            Text = $scenario.Value
                        }
                    }
                }
                $name = $commandNames[$operation]
                $advanced = $operation -in @('Record', 'Xml')
                $referenceText = 'function ' + $name + ' {' + $newline + $script:ReferenceParameters[$name] + $newline + "'PIPELINE_BODY'" + $newline + '}'
                foreach ($preference in @('Continue', 'Stop')) {
                    $reference = & {
                        param(
                            $Text,
                            $Name,
                            $Parameters,
                            $Preference

                        )
                        . ([scriptblock]::Create($Text))
                        Get-SecretPipelineRow $Name $Parameters $Preference
                    } $referenceText $name $parameters $preference
                    $actual = Get-SecretPipelineRow $name $parameters $preference
                    Assert-Secret ($actual.Caught -eq $reference.Caught -and
                        (ConvertTo-SecretJson $actual.Errors) -ceq (ConvertTo-SecretJson $reference.Errors)) 'Pipeline binding errors or termination changed.'
                    if ($advanced -and $preference -eq 'Stop') {
                        Assert-Secret ($actual.Rows.Count -eq 0 -and
                            $actual.Errors.Count -eq 1 -and
                            $actual.Caught) 'Advanced Stop pipeline contract changed.'
                    }
                    else {
                        Assert-Secret ($actual.Rows.Count -eq $expected.Count -and
                            (ConvertTo-SecretJson $actual.Rows) -ceq (ConvertTo-SecretJson $expected.Rows)) 'Pipeline result/cardinality contract changed.'
                        $errorCount = if ($advanced) {
                            2
                        }
                        else {
                            0
                        }
                        Assert-Secret ($actual.Errors.Count -eq $errorCount -and
                            -not $actual.Caught) 'Pipeline Continue/simple error contract changed.'
                    }
                }
                $script:ExecutedScenarios++
            }
        }
        'Errors' {
            $newline = [Environment]::NewLine
            foreach ($errorScenario in @(Get-SecretErrorScenarios)) {
                $signature = $script:ReferenceParameters[$errorScenario.Command]
                $referenceText = 'function ' + $errorScenario.Command + ' {' + $newline + $signature + $newline + $errorScenario.ReferenceBody + $newline + '}'
                foreach ($preference in @('Continue', 'Stop')) {
                    $expected = & {
                        param(
                            $Text,
                            $Scenario,
                            $Preference

                        )
                        . ([scriptblock]::Create($Text))
                        Get-SecretErrorRow $Scenario $Preference
                    } $referenceText $errorScenario $preference
                    $actual = Get-SecretErrorRow $errorScenario $preference
                    Assert-Secret ((ConvertTo-SecretJson (Get-SecretComparableError $actual)) -ceq (ConvertTo-SecretJson (Get-SecretComparableError $expected))) 'Command error identity, fields, output or termination changed.'
                    Assert-Secret ($actual.Count -eq 0 -and $actual.Errors.Count -eq 1) 'A failure emitted data or lost its diagnostic.'
                    $script:ExecutedScenarios++
                }
                $value = $errorScenario.Value
                switch ($errorScenario.Name) {
                    RecordNull {
                        Assert-SecretFailure { $service.ProjectRecord($null) } 'System.ArgumentNullException' '' 'Record'
                    }
                    XmlNull {
                        Assert-SecretFailure { $service.ProjectXml($null) } 'System.ArgumentNullException' '' 'Node'
                    }
                    XmlKind {
                        Assert-SecretFailure { $service.ProjectXml($value) } 'System.ArgumentException' 'Document and Element nodes only.' 'Node'
                    }
                    XmlDtd {
                        Assert-SecretFailure { $service.ProjectXml($value) } 'System.IO.InvalidDataException' 'DTD declarations are not supported'
                    }
                    BaselineIdentity {
                        Assert-SecretFailure { $service.AssertValueBaseline($value) } 'System.Management.Automation.RuntimeException' 'identity fields must be strings or null.'
                    }
                    BaselineSecret {
                        Assert-SecretFailure { $service.AssertValueBaseline($value) } 'System.Management.Automation.RuntimeException' 'secret-bearing settings are not supported.'
                    }
                    TextDtd {
                        Assert-SecretFailure { $service.ProjectText($value) } 'System.IO.InvalidDataException' 'DTD declarations are not supported'
                    }
                }
                $script:ExecutedScenarios++
            }
        }

        'Ownership' {
            foreach ($name in $script:Names) {
                Set-Item -Path ('Function:' + $name) -Value {
                    $script:Unexpected++
                    throw 'Old command must not own service processing.'
                }
            }
            foreach ($name in @('Get-Content', 'Get-Item', 'Get-ChildItem', 'Import-Module', 'Read-Host', 'Invoke-Command')) {
                Set-Item -Path ('Function:' + $name) -Value {
                    $script:Unexpected++
                    throw 'Unexpected service effect.'
                }
            }
            $service = [ADAnalyzerSecretIndicator]::new()
            foreach ($name in @('Pattern', 'Name2', 'PresenceString', 'Baseline2', 'Record1', 'XmlName0', 'XmlDocument2', 'Text6')) {
                $scenario = @($scenarios | Where-Object Name -ceq $name)[0]
                $expected = @($baseline.Results | Where-Object Name -ceq $name)[0]
                $actual = Get-SecretResult $scenario $service
                Assert-Secret ((ConvertTo-SecretJson $actual) -ceq (ConvertTo-SecretJson $expected)) 'A direct processing method delegated to an old command or effect.'
                $script:ExecutedScenarios++
            }
            $profile = @{
                RegistryRules = @(@{
                        ValueName = 'Password'
                    })
            }
            Assert-SecretFailure { $service.AssertValueBaseline($profile) } 'System.Management.Automation.RuntimeException' 'secret-bearing settings are not supported.'
            $script:ExecutedScenarios++
            $document = New-SecretXml '<Root />'
            Assert-SecretFailure { $service.ProjectXml($document.CreateTextNode($script:Marker)) } 'System.ArgumentException' 'Document and Element nodes only.' 'Node'
            Assert-Secret ($script:Unexpected -eq 0) 'A poisoned command or external boundary ran.'
            $script:ExecutedScenarios++
        }
        'Isolation' {
            $source = New-SecretXml '<Root><Item id="source" /></Root>'
            $first = $service.ProjectXml($source)
            $second = $service.ProjectXml($source)
            $first.PSBase.DocumentElement.SetAttribute('id', 'result')
            Assert-Secret (-not [object]::ReferenceEquals($first,
                    $second) -and
                $source.PSBase.DocumentElement.GetAttribute('id') -ceq '' -and
                $second.PSBase.DocumentElement.GetAttribute('id') -ceq '') 'Document results share source or result nodes.'
            $script:ExecutedScenarios++
            $source = New-SecretXml ('<Root><Item id="source" /><Sibling Password="' + $script:Marker + '" /></Root>')
            $node = $source.SelectSingleNode('/Root/Item')
            $before = ConvertTo-SecretJson (Get-SecretXmlState $source)
            $first = $service.ProjectXml($node)
            $second = $service.ProjectXml($node)
            Assert-SecretDetachedXml $first $source
            Assert-SecretDetachedXml $second $source
            $null = $first.PSBase.OwnerDocument.AppendChild($first.PSBase.OwnerDocument.CreateElement('ResultOnly'))
            $first.SetAttribute('id', 'result')
            Assert-Secret ($before -ceq (ConvertTo-SecretJson (Get-SecretXmlState $source)) -and
                $second.GetAttribute('id') -ceq 'source' -and
                -not [object]::ReferenceEquals($first.PSBase.OwnerDocument,
                    $second.PSBase.OwnerDocument)) 'Detached result owners share state.'
            $script:ExecutedScenarios++
            $ordinary = [pscustomobject]@{
                Name = 'ordinary'
                Note = 'source'
            }
            $ordinaryResult = $service.ProjectRecord($ordinary)
            $ordinaryResult.Note = 'shared'
            Assert-Secret ([object]::ReferenceEquals($ordinary,
                    $ordinaryResult) -and
                $ordinary.Note -ceq 'shared') 'Ordinary record reference contract changed.'
            $script:ExecutedScenarios++
            $metadata = [pscustomobject]@{
                Note = 'source'
            }
            $record = [pscustomobject]@{
                Name = 'Password'
                Value = $script:Marker
                Metadata = $metadata
            }
            $result = $service.ProjectRecord($record)
            $result.Name = 'result'
            $result.Metadata.Note = 'shared'
            Assert-Secret (-not [object]::ReferenceEquals($record,
                    $result) -and
                $record.Name -ceq 'Password' -and
                [object]::ReferenceEquals($metadata,
                    $result.Metadata) -and
                $record.Metadata.Note -ceq 'shared' -and
                $record.Value -ceq $script:Marker -and
                $null -eq $result.PSObject.Properties['Value']) 'Secret record top-level detachment or shallow metadata sharing changed.'
            $script:ExecutedScenarios++
            $other = [ADAnalyzerSecretIndicator]::new()
            $before = ConvertTo-Json -InputObject $other -Compress
            $null = $service.ProjectText('password="' + $script:Marker + '"')
            Assert-Secret ($other.ProjectText('ordinary') -ceq 'ordinary' -and
                $other.GetNamePattern() -ceq $service.GetNamePattern() -and
                $before -ceq (ConvertTo-Json `
                        -InputObject $other `
                        -Compress)) 'Independent service instances inherited input or result state.'
            $script:ExecutedScenarios++
            Assert-SecretFailure { $service.ProjectText('<!DOCTYPE Root><Root />') } 'System.IO.InvalidDataException' 'DTD declarations are not supported'
            Assert-Secret ($service.ProjectText('password=""') -ceq 'passwordPresent="false"' -and
                $service.ProjectText('password="' + $script:Marker + '"') -ceq 'passwordPresent="true"') 'Failure or earlier results changed a later call.'
            $script:ExecutedScenarios++
            $password = New-SecretSecure $true
            $credential = [pscredential]::new('fixture', $password)
            $null = $service.IsPresent($password)
            $projected = $service.ProjectRecord([pscustomobject]@{
                    Name = 'Password'
                    Value = $credential
                })
            Assert-Secret ($projected.SecretPresent -is [bool] -and
                $projected.SecretPresent -and
                $password.PSBase.Length -eq 1 -and
                [object]::ReferenceEquals($credential.PSBase.Password,
                    $password)) 'Service changed or disposed caller credential resources.'
            $script:ExecutedScenarios++
        }
        'Serialization' {
            $empty = [ADAnalyzerSecretIndicator]::new()
            $emptyJson = ConvertTo-Json -InputObject $empty -Depth 30 -Compress
            $emptyControl = [ADAnalyzerSecretIndicatorFixtureEmpty]::new()
            $controlJson = ConvertTo-Json -InputObject $emptyControl -Depth 30 -Compress
            $emptyXml = [Management.Automation.PSSerializer]::Serialize($empty)
            Assert-Secret ($emptyJson -ceq $controlJson) 'Service JSON differs from an inert same-engine empty class.'
            Assert-Secret (
                -not [string]::IsNullOrWhiteSpace($emptyXml)
            ) 'A non-null service produced no CLIXML.'
            Assert-Secret (
                -not ([string]$emptyJson).Contains($script:Marker) -and
                -not $emptyXml.Contains($script:Marker)
            ) 'New service serialization retained fixture data.'
            Write-Host (
                'INFO secret indicator empty-class JSON emitted: ' +
                ($null -ne $emptyJson)
            )
            $script:ExecutedScenarios++
            $document = New-SecretXml ('<Root Password="' + $script:Marker + '"><Password>' + $script:Marker + '</Password></Root>')
            $password = New-SecretSecure $true
            $workloads = @(
                @{
                    Operation = 'Record'
                    Value = [pscustomobject]@{
                        Name = 'Password'
                        Value = $script:Marker
                    }
                },
                @{
                    Operation = 'Xml'
                    Value = $document
                },
                @{
                    Operation = 'Xml'
                    Value = $document.PSBase.DocumentElement
                },
                @{
                    Operation = 'Text'
                    Value = ('password="' + $script:Marker + '"')
                },
                @{
                    Operation = 'Baseline'
                    Value = @{
                        RegistryRules = @(@{
                                ValueName = 'Enabled'
                                Expected = $script:Marker
                            })
                    }
                },
                @{
                    Operation = 'Presence'
                    Value = $password
                },
                @{
                    Operation = 'Presence'
                    Value = [pscredential]::new($script:Marker, $password)
                }
            )
            foreach ($workload in $workloads) {
                $instance = [ADAnalyzerSecretIndicator]::new()
                $beforeJson = ConvertTo-Json -InputObject $instance -Depth 30 -Compress
                $beforeXml = [Management.Automation.PSSerializer]::Serialize($instance)
                Assert-Secret (
                    $beforeJson -ceq $controlJson -and
                    -not [string]::IsNullOrWhiteSpace($beforeXml)
                ) 'New instance serialization differs from the native empty-state contract.'
                $scenario = New-SecretScenario Serialization $workload.Operation $workload.Value
                $result = Invoke-SecretScenario $scenario $instance
                $json = ConvertTo-Json -InputObject $instance -Depth 30 -Compress
                $xml = [Management.Automation.PSSerializer]::Serialize($instance)
                Assert-Secret ($json -ceq $beforeJson -and
                    $xml -ceq $beforeXml -and
                    -not ([string]$json).Contains($script:Marker) -and
                    -not $xml.Contains($script:Marker)) 'Native service serialization captured input or results.'
                $resultJson = ConvertTo-Json -InputObject $result -Depth 30 -Compress
                $nullJson = ConvertTo-Json -InputObject $null -Depth 30 -Compress
                Assert-Secret (
                    ($null -eq $result) -eq ($workload.Operation -eq 'Baseline')
                ) 'Only the void baseline method should produce no result.'
                if ($null -eq $result) {
                    # Windows PowerShell 5.1 emits no JSON for null. Compare
                    # the native engine contract before inspecting its text.
                    Assert-Secret ($resultJson -ceq $nullJson) 'Void result serialization changed.'
                }
                else {
                    Assert-Secret (
                        -not [string]::IsNullOrWhiteSpace([string]$resultJson)
                    ) 'A non-null projected result was not serialized.'
                }
                $resultXml = [Management.Automation.PSSerializer]::Serialize($result)
                Assert-Secret (
                    -not [string]::IsNullOrWhiteSpace($resultXml)
                ) 'Projected result CLIXML was not emitted.'
                if ($null -ne $resultJson) {
                    Assert-Secret (
                        $resultJson -is [string] -and
                        -not $resultJson.Contains($script:Marker)
                    ) 'A supported projected result retained JSON payload.'
                }
                Assert-Secret (
                    -not $resultXml.Contains($script:Marker)
                ) 'A supported projected result retained CLIXML payload.'
                Assert-Secret (@($instance.PSObject.Properties).Count -eq 0) 'A processing call gained retained instance properties.'
                $script:ExecutedScenarios++
            }
            Assert-Secret ($password.PSBase.Length -eq 1 -and
                $document.PSBase.OuterXml.Contains($script:Marker)) 'Serialization processing changed caller resources.'
        }
        'Loading' {
            $newline = [Environment]::NewLine
            $bootstrap = (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1').Replace("'", "''")
            $manifest = (Join-Path $repositoryRoot 'ADEnvironment.psd1').Replace("'", "''")
            $basicChecks = @'
$service = [ADAnalyzerSecretIndicator]::new()
if ($service.GetNamePattern().Length -ne 499 -or -not $service.IsSecretName('Password') -or $service.IsPresent($null)) {
    throw 'Fresh literal constructor failed.'
}
if ((Get-ADAnalyzerSecretNames).Length -ne 499 -or
    -not (Test-ADAnalyzerSecretName 'Password') -or
    -not (Test-ADAnalyzerSecretPresence 'fixture')) {
    throw 'Fresh simple commands failed.'
}
if (@(Assert-ADAnalyzerValueBaseline -Profile $null).Count -ne 0) {
    throw 'Fresh baseline command failed.'
}
$record = ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{
        Name = 'Password'
        Value = 'fixture'
    })
if ($record.SecretPresent -isnot [bool] -or -not $record.SecretPresent -or $null -ne $record.PSObject.Properties['Value']) {
    throw 'Fresh record command failed.'
}
$document = [xml]'<Setting Name="Password" Value="fixture" />'
if ((Get-ADAnalyzerXmlSecretName $document.DocumentElement) -cne 'Password') {
    throw 'Fresh XML name command failed.'
}
$projected = ConvertTo-ADAnalyzerSecretIndicatorXml $document
if ($projected.DocumentElement.GetAttribute('SecretPresent') -cne 'true') {
    throw 'Fresh XML command failed.'
}
if ((ConvertTo-ADAnalyzerSecretIndicatorText 'password="fixture"') -cne 'passwordPresent="true"') {
    throw 'Fresh text command failed.'
}
'@
            $loader = ". '" + $bootstrap + "'" + $newline
            Invoke-SecretFresh ($loader + $basicChecks + $newline + "'PASS secret fresh literal'") 'PASS secret fresh literal'
            $script:ExecutedScenarios++
            Invoke-SecretFresh ($loader + $loader + $basicChecks + $newline + "'PASS secret repeated load'") 'PASS secret repeated load'
            $script:ExecutedScenarios++
            foreach ($file in @('ADProfile.ps1', 'ADGpo.ps1', 'ADPolicyAnalysis.ps1', 'ADDirectoryAnalysis.ps1', 'ADOperations.ps1')) {
                $path = (Join-Path $repositoryRoot ('bin/' + $file)).Replace("'", "''")
                $marker = 'PASS secret standalone ' + $file
                $text = ". '" + $path + "'" + $newline + $basicChecks + $newline + "'" + $marker + "'"
                Invoke-SecretFresh $text $marker
                $script:ExecutedScenarios++
            }
            $moduleChecks = @'
$module = Get-Module ADEnvironment
if ($null -eq $module) {
    throw 'Module command entrypoint did not load.'
}
& $module {
    if ((Get-ADAnalyzerSecretNames).Length -ne 499 -or
        -not (Test-ADAnalyzerSecretName 'Password') -or
        -not (Test-ADAnalyzerSecretPresence 'fixture')) {
        throw 'Module simple commands failed.'
    }
    if (@(Assert-ADAnalyzerValueBaseline -Profile $null).Count -ne 0) {
        throw 'Module baseline command failed.'
    }
    $record = ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{
            Name = 'Password'
            Value = 'fixture'
        })
    if ($record.SecretPresent -isnot [bool] -or -not $record.SecretPresent -or $null -ne $record.PSObject.Properties['Value']) {
        throw 'Module record command failed.'
    }
    $document = [xml]'<Setting Name="Password" Value="fixture" />'
    if ((Get-ADAnalyzerXmlSecretName $document.DocumentElement) -cne 'Password') {
        throw 'Module XML name command failed.'
    }
    $projected = ConvertTo-ADAnalyzerSecretIndicatorXml $document
    if ($projected.DocumentElement.GetAttribute('SecretPresent') -cne 'true') {
        throw 'Module XML command failed.'
    }
    if ((ConvertTo-ADAnalyzerSecretIndicatorText 'password="fixture"') -cne 'passwordPresent="true"') {
        throw 'Module text command failed.'
    }
}
$profile = ADEnvironment\Import-ADAnalyzerProfile -Profile @{
    RegistryRules = @(@{
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Enabled'
            Type = '4'
            Expected = 1
        })
}
if ($profile.RegistryRules.Count -ne 1 -or $profile.RegistryRules[0].ValueName -cne 'Enabled') {
    throw 'Public module profile consumer failed.'
}
'@
            $windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
            if ($windows) {
                $import = "Import-Module '" + $manifest + "' -Force -ErrorAction Stop -WarningAction SilentlyContinue" + $newline
                $route = 'Windows manifest'
            }
            else {
                # Portable coverage uses the established metadata-only script
                # module route; Windows still exercises the actual manifest.
                $assembly = (Join-Path $repositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll').Replace("'", "''")
                $scriptModule = (Join-Path $repositoryRoot 'bin/ADEnvironment.psm1').Replace("'", "''")
                $import = "[void][Reflection.Assembly]::LoadFrom('" + $assembly + "')" + $newline
                $import += "Import-Module '" + $scriptModule + "' -Force -ErrorAction Stop -WarningAction SilentlyContinue" + $newline
                $route = 'portable script module'
            }
            foreach ($moduleFirst in @($false, $true)) {
                $prefix = if ($moduleFirst) {
                    $import + $loader
                }
                else {
                    $loader + $import
                }
                $marker = 'PASS secret ' + $route + ' order ' + [string]$moduleFirst
                Invoke-SecretFresh ($prefix + $basicChecks + $moduleChecks + $newline + "'" + $marker + "'") $marker
                $script:ExecutedScenarios++
            }
        }
    }
    $expectedCounts = @{
        Construction = 6
        Parity = 110
        Presence = 44
        Baselines = 28
        Records = 21
        XmlNames = 23
        Xml = 31
        Text = 51
        Metadata = 16
        Errors = 21
        Ownership = 10
        Isolation = 7
        Serialization = 8
        Loading = 9
    }
    Assert-Secret ($script:ExecutedScenarios -eq $expectedCounts[$Case]) 'Required service scenarios were not all executed.'
    Write-Host ('PASS secret indicator ' + $Case + ' ' + $script:ExecutedScenarios)
}
catch {
    Write-Host (
        'FAIL secret indicator ' + $Case + ' after ' +
        $script:ExecutedScenarios + ' completed scenarios'
    )
    Write-Host $_.ScriptStackTrace
    throw
}
finally {
    foreach ($value in $script:Owned) {
        $value.Dispose()
    }
    foreach ($name in $script:OwnedTypeData) {
        Remove-TypeData -TypeName $name -ErrorAction Stop
    }
}
