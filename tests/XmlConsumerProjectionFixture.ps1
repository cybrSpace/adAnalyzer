[CmdletBinding()]
param(
    [ValidateSet('RecordBaseline', 'Probe', 'Parity', 'Strings',
        'UnsupportedSafe', 'UnsupportedExport', 'ContextSafe', 'ContextExport',
        'DirectDefaults', 'NamedDefaults', 'DefaultExport', 'Collisions', 'DtdConsumer')]
    [string]$Case = 'Parity'
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:Marker = 'CONSUMER_PAYLOAD_075'
$script:Sink = [Collections.Generic.List[object]]::new()
$script:Scenarios = 0

function Assert-Consumer($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-ConsumerDocument([string]$Text) {
    $document = [xml]::new()
    $document.PreserveWhitespace = $true
    $document.XmlResolver = $null
    $document.LoadXml($Text.Replace('PAYLOAD', $script:Marker))
    return $document
}

function Get-ConsumerSourceSnapshot([Xml.XmlNode]$Node) {
    [pscustomobject][ordered]@{
        NodeType = [string]$Node.PSBase.NodeType
        Name = $Node.PSBase.Name
        Value = $Node.PSBase.Value
        OuterXml = $Node.PSBase.OuterXml
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
                Get-ConsumerSourceSnapshot $child
            }
        )
    }
}

function Get-ConsumerSourceJson([Xml.XmlNode]$Node) {
    ConvertTo-Json -InputObject (Get-ConsumerSourceSnapshot $Node) -Depth 60 -Compress
}

function Get-ConsumerOrdinaryScenarios {
    $newline = [string][char]13 + [char]10
    $shapes = [ordered]@{
        Unicode = '<Root id="one"><Item>café</Item><Note>ordinary</Note></Root>'
        EmptyForms = '<Root><Empty/><Full></Full><Item enabled="false" count="0"/></Root>'
        DirectAttributes = '<Root password="PAYLOAD"><Item cpassword=""/></Root>'
        DirectElements = '<Root><Password>PAYLOAD</Password><Credential><![CDATA[PAYLOAD]]></Credential></Root>'
        NamedAttributes = '<Root><Properties name="DefaultPassword" value="PAYLOAD" note="keep"/></Root>'
        NamedChildren = '<Root><Setting><Name>Password</Name><Value>PAYLOAD</Value><Expected>ignored</Expected></Setting></Root>'
        OrdinaryRecord = '<Root><Setting><Name>Enabled</Name><Value>false</Value><Data>keep</Data></Setting></Root>'
        PresenceFlags = '<Root cpasswordPresent="true"><PasswordPresent>false</PasswordPresent><Setting name="Password" SecretPresent="true"/></Root>'
        Namespaces = '<p:Root xmlns:p="urn:fixture"><p:Password>PAYLOAD</p:Password><Item xmlns="urn:default">café</Item></p:Root>'
        Exterior = '<?xml version="1.0" encoding="utf-16" standalone="yes"?><!-- before --><?fixture data?><Root><![CDATA[keep raw]]><!-- inside --></Root><!-- after -->'
        Newlines = "<Root xml:space='preserve'>" + $newline + ' café ' + $newline + '<Empty/></Root>'
        SecretRoot = '<Password>PAYLOAD</Password>'
    }
    foreach ($entry in $shapes.GetEnumerator()) {
        $document = New-ConsumerDocument $entry.Value
        foreach ($kind in @('Document', 'Element')) {
            [pscustomobject]@{
                Name = $entry.Key + $kind
                Source = $document
                Node = if ($kind -eq 'Document') {
                    $document
                }
                else {
                    $document.PSBase.DocumentElement
                }
            }
        }
    }
}

function Get-ConsumerResult($Scenario) {
    $rows = [Collections.Generic.List[object]]::new()
    ConvertTo-ADAnalyzerSafeData -InputObject $Scenario.Node | ForEach-Object {
        $rows.Add($_)
    }
    [pscustomobject][ordered]@{
        Name = $Scenario.Name
        Count = $rows.Count
        Results = @(
            foreach ($row in $rows) {
                [pscustomobject][ordered]@{
                    Type = $row.GetType().FullName
                    Text = [string]$row
                }
            }
        )
    }
}

function Get-ConsumerUnsupportedScenarios {
    $document = New-ConsumerDocument '<Root><Note>source</Note></Root>'
    $attribute = $document.CreateAttribute('password')
    $attribute.PSBase.Value = $script:Marker
    $fragment = $document.CreateDocumentFragment()
    $fragment.PSBase.InnerXml = '<Password>' + $script:Marker + '</Password>'
    $nodes = @(
        $attribute,
        $document.CreateTextNode($script:Marker),
        $document.CreateCDataSection($script:Marker),
        $fragment,
        $document.CreateComment($script:Marker),
        $document.CreateProcessingInstruction('fixture', $script:Marker),
        $document.CreateXmlDeclaration('1.0', 'utf-16', 'yes'),
        $document.CreateDocumentType('Root', '', '', '<!ENTITY x "' + $script:Marker + '">'),
        $document.CreateWhitespace('  '),
        $document.CreateSignificantWhitespace('  '),
        $document.CreateEntityReference('unresolved')
    )
    Assert-Consumer ($nodes.Count -eq 11) 'Unsupported consumer table is incomplete.'
    foreach ($node in $nodes) {
        [pscustomobject]@{
            Name = [string]$node.PSBase.NodeType
            Source = $document
            Node = $node
        }
    }
}

function Get-ConsumerContextScenarios {
    $cases = @(
        @('PasswordText', '<Root><Password>PAYLOAD</Password></Root>', '/Root/Password/text()'),
        @('PasswordCData', '<Root><Password><![CDATA[PAYLOAD]]></Password></Root>', '/Root/Password/node()'),
        @('NamedAttribute', '<Properties name="DefaultPassword" value="PAYLOAD"/>', '/Properties/@value'),
        @('NamedValueText', '<Setting><Name>Password</Name><Value>PAYLOAD</Value></Setting>', '/Setting/Value/text()'),
        @('OrdinaryText', '<Root><Note>ordinary leaf</Note></Root>', '/Root/Note/text()')
    )
    foreach ($row in $cases) {
        $document = New-ConsumerDocument $row[1]
        [pscustomobject]@{
            Name = $row[0]
            Source = $document
            Node = $document.SelectSingleNode($row[2])
        }
    }
}

function New-ConsumerDefaultDocument([string]$Family, [bool]$Present) {
    $value = if ($Present) {
        $script:Marker
    }
    else {
        ''
    }
    $rootName = if ($Family -eq 'Direct') {
        'Root'
    }
    else {
        'Properties'
    }
    $attributeName = if ($Family -eq 'Direct') {
        'Password'
    }
    else {
        'value'
    }
    $schemaText = '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:element name="' + $rootName + '"><xs:complexType><xs:attribute name="name" type="xs:string"/><xs:attribute name="Mode" type="xs:string" default="ordinary-default"/><xs:attribute name="' + $attributeName + '" type="xs:string" default="' + $value + '"/></xs:complexType></xs:element></xs:schema>'
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $textReader = [IO.StringReader]::new($schemaText)
    $schemaReader = $null
    try {
        $schemaReader = [Xml.XmlReader]::Create($textReader, $settings)
        $text = if ($Family -eq 'Direct') {
            '<Root/>'
        }
        else {
            '<Properties name="DefaultPassword"/>'
        }
        $document = New-ConsumerDocument $text
        $null = $document.PSBase.Schemas.Add('', $schemaReader)
        $document.Validate($null)
        $attribute = $document.PSBase.DocumentElement.GetAttributeNode($attributeName)
        Assert-Consumer ($null -ne $attribute -and -not $attribute.PSBase.Specified) 'Fixture default attribute is missing.'
        Assert-Consumer ($attribute.PSBase.Value -ceq $value) 'Fixture default value changed.'
        Assert-Consumer ($null -ne $document.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType) 'Fixture schema information is missing.'
        return $document
    }
    finally {
        if ($null -ne $schemaReader) {
            $schemaReader.Dispose()
        }
        $textReader.Dispose()
    }
}

function Get-ConsumerDefaultExpected([string]$Family, [bool]$Present) {
    $flag = ([string]$Present).ToLowerInvariant()
    if ($Family -eq 'Direct') {
        return '<Root PasswordPresent="' + $flag + '" />'
    }
    return '<Properties name="DefaultPassword" SecretPresent="' + $flag + '" />'
}

# Replace the owned file boundary only. All formatters/export projection run.
function Write-ADAnalyzerFile {
    param(
        $Path,
        [AllowEmptyString()][string]$Content

    )
    $script:Sink.Add([pscustomobject]@{
            Path = $Path
            HasPayload = $Content.Contains($script:Marker)
            HasPresence = $Content -match '(PasswordPresent|SecretPresent)'
        })
    $Path
}

function New-ConsumerAssessment($Evidence) {
    [pscustomobject]@{
        SchemaVersion = 1
        Target = 'fixture'
        Findings = @(
            [pscustomobject]@{
                RuleId = 'FIXTURE'
                Target = 'fixture'
                Status = 'Fail'
                Evidence = $Evidence
            }
        )
    }
}

function Invoke-ConsumerExport($Evidence, [string]$Format = 'All') {
    Export-ADAnalyzerAssessment `
        -Assessment (New-ConsumerAssessment $Evidence) `
        -Path 'memory-only-consumer-output' `
        -Format $Format `
        -Confirm:$false
}

function Assert-ConsumerRejected($Scenario, [scriptblock]$Body, [type]$Cause) {
    $before = Get-ConsumerSourceJson $Scenario.Source
    $beforeNode = Get-ConsumerSourceJson $Scenario.Node
    $rows = [Collections.Generic.List[object]]::new()
    $script:Sink.Clear()
    $caught = $null
    try {
        & $Body | ForEach-Object {
            $rows.Add($_)
        }
    }
    catch {
        $caught = $_
    }
    $payloadWrites = @($script:Sink | Where-Object HasPayload).Count
    $diagnostic = 'XML consumer accepted unsupported input. Outputs={0}; Writes={1}; PayloadWrites={2}.' -f
    $rows.Count, $script:Sink.Count, $payloadWrites
    Assert-Consumer ([bool]$caught) $diagnostic
    Assert-Consumer ($caught.Exception.GetBaseException() -is $Cause) 'XML consumer lost the meaningful rejection cause.'
    Assert-Consumer ($rows.Count -eq 0) 'Rejected XML consumer emitted partial output.'
    Assert-Consumer ($script:Sink.Count -eq 0) 'Rejected XML consumer reached the memory writer.'
    Assert-Consumer (-not $caught.ToString().Contains($script:Marker)) 'XML consumer rejection echoed a payload.'
    Assert-Consumer ($before -ceq (Get-ConsumerSourceJson $Scenario.Source)) 'XML rejection changed its source document.'
    Assert-Consumer ($beforeNode -ceq (Get-ConsumerSourceJson $Scenario.Node)) 'XML rejection changed its input node.'
    $script:Scenarios++
}

function Assert-ConsumerString([Xml.XmlNode]$Node, [string]$Expected) {
    $source = if ($Node -is [xml]) {
        $Node
    }
    else {
        $Node.PSBase.OwnerDocument
    }
    $before = Get-ConsumerSourceJson $source
    $schemaType = $source.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType
    $rows = [Collections.Generic.List[object]]::new()
    ConvertTo-ADAnalyzerSafeData -InputObject $Node | ForEach-Object {
        $rows.Add($_)
    }
    Assert-Consumer ($rows.Count -eq 1 -and $rows[0] -is [string]) 'Supported XML consumer changed its string/cardinality contract.'
    Assert-Consumer ($rows[0] -ceq $Expected) 'Supported XML consumer changed exact text or boolean presence.'
    Assert-Consumer (-not $rows[0].Contains($script:Marker)) 'Supported XML consumer retained a payload.'
    $again = @(ConvertTo-ADAnalyzerSafeData -InputObject $rows[0])
    Assert-Consumer ($again.Count -eq 1 -and
        $again[0] -is [string] -and
        $again[0] -ceq $rows[0]) 'Returned XML string projection is not idempotent.'
    Assert-Consumer (-not (ConvertTo-Json `
                -InputObject $rows[0] `
                -Compress).Contains($script:Marker)) 'Returned string JSON retained a schema payload.'
    Assert-Consumer (-not [Management.Automation.PSSerializer]::Serialize($rows[0]).Contains($script:Marker)) 'Returned string CLIXML retained a schema payload.'
    Assert-Consumer ($before -ceq (Get-ConsumerSourceJson $source)) 'Supported XML consumer changed source values/default flags.'
    Assert-Consumer ([object]::ReferenceEquals($schemaType,
            $source.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType)) 'XML consumer changed source schema metadata.'
    $script:Scenarios++
}

try {
    if ($Case -in @('RecordBaseline', 'Probe')) {
        $body = (Get-Command ConvertTo-ADAnalyzerSafeData).ScriptBlock.ToString()
        Assert-Consumer ($body.Contains('return Protect-ADAnalyzerSecretText $InputObject.PSBase.OuterXml')) 'Capture accepted consumer behavior before the helper-first correction.'
    }
    if ($Case -eq 'RecordBaseline') {
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $bodyHash = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($body))).Replace('-',
                '').ToLowerInvariant()
        }
        finally {
            $hash.Dispose()
        }
        $results = @(
            foreach ($scenario in @(Get-ConsumerOrdinaryScenarios)) {
                Get-ConsumerResult $scenario
            }
        )
        Assert-Consumer ($results.Count -eq 24) 'Ordinary consumer baseline table is incomplete.'
        $baseline = [pscustomobject][ordered]@{
            Source = '516a12dfd4b64e7e3bf5f63cab8a37e1512ec275'
            OriginalSafeDataBodySha256 = $bodyHash
            Results = $results
        }
        $baselinePath = Join-Path $PSScriptRoot 'XmlConsumerProjectionBaseline.json'
        Assert-Consumer (-not [IO.File]::Exists($baselinePath)) 'Original consumer baseline already exists.'
        Assert-Consumer (-not (ConvertTo-Json `
                    -InputObject $baseline `
                    -Depth 30).Contains($script:Marker)) 'Ordinary baseline retained a payload.'
        [IO.File]::WriteAllText(
            $baselinePath,
            (ConvertTo-Json -InputObject $baseline -Depth 30),
            [Text.UTF8Encoding]::new($true)
        )
        Write-Host ('PASS XML consumer baseline captured 24; bodySHA256=' + $bodyHash)
        return
    }
    if ($Case -eq 'Probe') {
        foreach ($scenario in @(Get-ConsumerContextScenarios)) {
            $rows = @(ConvertTo-ADAnalyzerSafeData -InputObject $scenario.Node)
            $script:Sink.Clear()
            $exports = @(Invoke-ConsumerExport $scenario.Node)
            $hasPayload = $rows.Count -eq 1 -and ([string]$rows[0]).Contains($script:Marker)
            $payloadWrites = @($script:Sink | Where-Object HasPayload).Count
            Assert-Consumer ($rows.Count -eq 1 -and
                $exports.Count -eq 3 -and
                $script:Sink.Count -eq 3) 'Original contextual consumer probe did not run.'
            Assert-Consumer ($hasPayload -eq ($scenario.Name -ne 'OrdinaryText')) 'Original contextual payload reproduction changed.'
            $expectedPayloadWrites = if ($hasPayload) {
                3
            }
            else {
                0
            }
            Assert-Consumer ($payloadWrites -eq $expectedPayloadWrites) 'Original exporter payload reproduction changed.'
            Write-Host ('PROBE XML consumer {0}; Outputs={1}; HasPayload={2}; Writes={3}; PayloadWrites={4}' -f
                $scenario.Name, $rows.Count, $hasPayload, $script:Sink.Count, $payloadWrites)
        }
        foreach ($family in @('Direct', 'Named')) {
            $document = New-ConsumerDefaultDocument $family $true
            foreach ($node in @($document, $document.PSBase.DocumentElement)) {
                $rows = @(ConvertTo-ADAnalyzerSafeData -InputObject $node)
                Assert-Consumer ($rows.Count -eq 1 -and $rows[0] -is [string]) 'Original default consumer did not run.'
                $observed = [xml]::new()
                $observed.XmlResolver = $null
                $observed.LoadXml($rows[0])
                $flagName = if ($family -eq 'Direct') {
                    'PasswordPresent'
                }
                else {
                    'SecretPresent'
                }
                Assert-Consumer ($observed.PSBase.DocumentElement.GetAttribute($flagName) -cne 'true') 'Original nonempty default presence defect was not reproduced.'
                $script:Sink.Clear()
                $exports = @(Invoke-ConsumerExport $node)
                Assert-Consumer ($exports.Count -eq 3 -and $script:Sink.Count -eq 3) 'Original default exporter probe did not run.'
                Write-Host ('PROBE XML consumer default {0}/{1}; CorrectPresence=False; Writes={2}; PayloadWrites={3}' -f
                    $family, $node.PSBase.NodeType, $script:Sink.Count, @($script:Sink | Where-Object HasPayload).Count)
            }
        }
        Write-Host 'PASS XML consumer original defects reproduced 9'
        return
    }

    switch ($Case) {
        'Parity' {
            $baseline = Get-Content `
                -LiteralPath (Join-Path $PSScriptRoot 'XmlConsumerProjectionBaseline.json') `
                -Raw `
                -Encoding UTF8 | ConvertFrom-Json
            Assert-Consumer ($baseline.Source -ceq '516a12dfd4b64e7e3bf5f63cab8a37e1512ec275') 'Consumer baseline source changed.'
            $ordinary = @(Get-ConsumerOrdinaryScenarios)
            Assert-Consumer ($ordinary.Count -eq 24 -and $baseline.Results.Count -eq 24) 'Ordinary consumer cases are missing.'
            for ($index = 0; $index -lt $ordinary.Count; $index++) {
                $scenario = $ordinary[$index]
                Assert-Consumer ($scenario.Name -ceq $baseline.Results[$index].Name) 'Ordinary consumer case order changed.'
                $before = Get-ConsumerSourceJson $scenario.Source
                $actual = Get-ConsumerResult $scenario
                $expectedJson = ConvertTo-Json -InputObject $baseline.Results[$index] -Depth 30 -Compress
                $actualJson = ConvertTo-Json -InputObject $actual -Depth 30 -Compress
                Assert-Consumer ($actualJson -ceq $expectedJson) 'Ordinary consumer output/type/cardinality changed.'
                Assert-Consumer ($actual.Count -eq 1 -and
                    $actual.Results[0].Type -ceq 'System.String') 'Ordinary consumer string contract changed.'
                $again = @(ConvertTo-ADAnalyzerSafeData -InputObject $actual.Results[0].Text)
                Assert-Consumer ($again.Count -eq 1 -and
                    $again[0] -is [string] -and
                    $again[0] -ceq $actual.Results[0].Text) 'Ordinary returned-string projection is not idempotent.'
                Assert-Consumer ($before -ceq (Get-ConsumerSourceJson $scenario.Source)) 'Ordinary consumer changed its source tree.'
                $script:Scenarios++
            }
        }
        'Strings' {
            $newline = [string][char]13 + [char]10
            $unicodeText = 'café' + $newline + 'ordinary'
            $strings = @(
                @('', ''),
                @('ordinary text', 'ordinary text'),
                @('Password age >90', 'Password age >90'),
                @('<Root note="ordinary"/>', '<Root note="ordinary"/>'),
                @('<!-- <!DOCTYPE Root> -->', '<!-- <!DOCTYPE Root> -->'),
                @('<![CDATA[<!DOCTYPE Root>]]>', '<![CDATA[<!DOCTYPE Root>]]>'),
                @('prefix password="PAYLOAD" suffix', 'prefix passwordPresent="true" suffix'),
                @('<Root password="PAYLOAD"/>', '<Root passwordPresent="true" />'),
                @('<Password>PAYLOAD</Password><Note>keep</Note>', '<PasswordPresent>true</PasswordPresent><Note>keep</Note>'),
                @('broken <Root password="PAYLOAD"', 'broken <Root passwordPresent="true"'),
                @($unicodeText, $unicodeText)
            )
            foreach ($row in $strings) {
                $source = $row[0].Replace('PAYLOAD', $script:Marker)
                $actual = @(ConvertTo-ADAnalyzerSafeData -InputObject $source)
                Assert-Consumer ($actual.Count -eq 1 -and
                    $actual[0] -is [string] -and
                    $actual[0] -ceq $row[1]) 'Existing string projection changed.'
                $script:Scenarios++
            }
            $emptyDocument = [xml]::new()
            $actual = @(ConvertTo-ADAnalyzerSafeData -InputObject $emptyDocument)
            Assert-Consumer ($actual.Count -eq 1 -and
                $actual[0] -is [string] -and
                $actual[0] -ceq '') 'Empty document changed its single empty-string contract.'
            Assert-Consumer ($emptyDocument.PSBase.ChildNodes.Count -eq 0) 'Empty document source was changed.'
            $script:Scenarios++
        }

        { $_ -in @('UnsupportedSafe', 'UnsupportedExport', 'ContextSafe', 'ContextExport') } {
            $inputScenarios = if ($Case -like 'Unsupported*') {
                @(Get-ConsumerUnsupportedScenarios)
            }
            else {
                @(Get-ConsumerContextScenarios)
            }
            foreach ($scenario in $inputScenarios) {
                if ($Case -like '*Export') {
                    Assert-ConsumerRejected $scenario { Invoke-ConsumerExport $scenario.Node } ([ArgumentException])
                }
                else {
                    Assert-ConsumerRejected $scenario { ConvertTo-ADAnalyzerSafeData -InputObject $scenario.Node } ([ArgumentException])
                }
            }
        }
        { $_ -in @('DirectDefaults', 'NamedDefaults', 'DefaultExport') } {
            $families = if ($Case -eq 'DefaultExport') {
                @('Direct', 'Named')
            }
            elseif ($Case -eq 'DirectDefaults') {
                @('Direct')
            }
            else {
                @('Named')
            }
            foreach ($family in $families) {
                foreach ($present in @($true, $false)) {
                    $document = New-ConsumerDefaultDocument $family $present
                    foreach ($node in @($document, $document.PSBase.DocumentElement)) {
                        $expected = Get-ConsumerDefaultExpected $family $present
                        if ($Case -eq 'DefaultExport') {
                            $before = Get-ConsumerSourceJson $document
                            $schemaType = $document.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType
                            $safe = @(ConvertTo-ADAnalyzerSafeData -InputObject $node)
                            Assert-Consumer ($safe.Count -eq 1 -and
                                $safe[0] -is [string] -and
                                $safe[0] -ceq $expected) 'Default export lost exact boolean presence.'
                            $script:Sink.Clear()
                            $rows = @(Invoke-ConsumerExport $node)
                            Assert-Consumer ($rows.Count -eq 3 -and
                                $script:Sink.Count -eq 3) 'Default export did not exercise all three real formatters.'
                            Assert-Consumer (@($script:Sink | Where-Object HasPayload).Count -eq 0) 'Default export retained a payload.'
                            Assert-Consumer (@($script:Sink | Where-Object { -not $_.HasPresence }).Count -eq 0) 'Default export lost its indicator.'
                            Assert-Consumer ($before -ceq (Get-ConsumerSourceJson $document)) 'Default export changed source values/default flags.'
                            Assert-Consumer ([object]::ReferenceEquals($schemaType,
                                    $document.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType)) 'Default export changed source schema metadata.'
                            $script:Scenarios++
                        }
                        else {
                            Assert-ConsumerString $node $expected
                        }
                    }
                }
            }
        }
        'Collisions' {
            foreach ($source in @(
                    '<OuterXml><Password>PAYLOAD</Password><Note>keep</Note></OuterXml>',
                    '<Root><OuterXml>keep</OuterXml><Password>PAYLOAD</Password></Root>',
                    '<Password><LocalName>Note</LocalName><Value>PAYLOAD</Value></Password>',
                    '<Properties name="DefaultPassword" value="PAYLOAD"><Attributes/></Properties>'
                )) {
                $document = New-ConsumerDocument $source
                $expected = if ($source -like '<Properties*') {
                    '<Properties name="DefaultPassword" SecretPresent="true"><Attributes /></Properties>'
                }
                elseif ($source -like '<Password>*') {
                    '<PasswordPresent>true</PasswordPresent>'
                }
                else {
                    $source.Replace('<Password>PAYLOAD</Password>', '<PasswordPresent>true</PasswordPresent>')
                }
                foreach ($node in @($document, $document.PSBase.DocumentElement)) {
                    Assert-ConsumerString $node $expected
                }
            }
            # The writer is the sole mocked boundary for each real formatter.
            foreach ($format in @('Json', 'Html', 'Csv', 'All')) {
                $script:Sink.Clear()
                $rows = @(Invoke-ConsumerExport (New-ConsumerDocument '<Root><Note>ordinary</Note></Root>') $format)
                $count = if ($format -eq 'All') {
                    3
                }
                else {
                    1
                }
                Assert-Consumer ($rows.Count -eq $count -and
                    $script:Sink.Count -eq $count) 'Ordinary container export changed writer cardinality.'
            }
        }
        'DtdConsumer' {
            $document = New-ConsumerDocument '<!DOCTYPE Root [<!ENTITY x "PAYLOAD">]><Root><Password>&x;</Password></Root>'
            foreach ($node in @($document, $document.PSBase.DocumentElement)) {
                $scenario = [pscustomobject]@{
                    Source = $document
                    Node = $node
                }
                Assert-ConsumerRejected $scenario { ConvertTo-ADAnalyzerSafeData -InputObject $node } ([IO.InvalidDataException])
                Assert-ConsumerRejected $scenario { Invoke-ConsumerExport $node } ([IO.InvalidDataException])
            }
        }
    }
    $expectedScenarios = @{
        Parity = 24
        Strings = 12
        UnsupportedSafe = 11
        UnsupportedExport = 11
        ContextSafe = 5
        ContextExport = 5
        DirectDefaults = 4
        NamedDefaults = 4
        DefaultExport = 8
        Collisions = 8
        DtdConsumer = 4
    }
    Assert-Consumer ($script:Scenarios -eq $expectedScenarios[$Case]) 'Required XML consumer scenarios were not all executed.'
    Write-Host ('PASS XML consumer projection ' + $Case + ' ' + $script:Scenarios)
}
catch {
    $message = $_.Exception.Message.Replace($script:Marker, '[fixture]')
    Write-Host ('FAIL XML consumer projection ' + $Case + ': ' + $message)
    exit 1
}
