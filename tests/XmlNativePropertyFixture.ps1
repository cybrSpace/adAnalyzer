[CmdletBinding()]
param(
    [ValidateSet('RecordBaseline', 'Parity', 'LocalName', 'Attributes', 'Traversal',
        'Payload', 'Presence', 'DataMembers', 'Serialization', 'SafeData', 'Export', 'Policy',
        'Admx', 'Provided', 'Reader', 'Standalone')]
    [string]$Case = 'Parity'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:Marker = 'NATIVE_PROPERTY_PAYLOAD_074'
$script:Sink = [Collections.Generic.List[object]]::new()
$script:Scenarios = 0

function Assert-Native($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-NativeGoldenHash([byte[]]$Bytes) {
    # GetString retains the BOM. Normalize checkout line endings only;
    # escaped JSON literals, other whitespace and every data byte stay exact.
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $utf8.GetString($Bytes).Replace("`r`n", "`n")
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString(
            $hash.ComputeHash($utf8.GetBytes($text))
        ).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hash.Dispose()
    }
}

function New-NativeDocument([string]$Text) {
    $document = [xml]::new()
    $document.PreserveWhitespace = $true
    $document.XmlResolver = $null
    $document.LoadXml($Text.Replace('PAYLOAD', $script:Marker))
    return $document
}

function Get-NativeOrdinaryScenarios {
    $sources = @(
        '<Root id="one"><Item>café</Item><Empty/><Full></Full></Root>',
        '<Root cpassword="PAYLOAD"><Password>PAYLOAD</Password><Note>keep</Note></Root>',
        '<Root><Properties name="DefaultPassword" value="PAYLOAD" /><Setting><Name>Password</Name><Value></Value><Expected>ignored</Expected></Setting></Root>',
        '<Password>PAYLOAD</Password>',
        '<?xml version="1.0" encoding="utf-16" standalone="yes"?><!-- before --><?fixture data?><p:Root xmlns:p="urn:fixture"><p:Password/><p:Note><![CDATA[keep raw]]></p:Note></p:Root><!-- after -->',
        ("<Root xml:space='preserve'>`r`n café `r`n<Item password=''/></Root>")
    )
    for ($index = 0; $index -lt $sources.Count; $index++) {
        $document = New-NativeDocument $sources[$index]
        foreach ($kind in @('Document', 'Element')) {
            [pscustomobject]@{
                Name = $kind + $index
                Kind = $kind
                InputObject = if ($kind -eq 'Document') {
                    $document
                }
                else {
                    $document.PSBase.DocumentElement
                }
            }
        }
    }
    $texts = @(
        '<Root Password="PAYLOAD"><Note>keep</Note></Root>',
        '<Password>PAYLOAD</Password><Note>keep</Note>',
        'prefix password="PAYLOAD" suffix',
        'broken <Root password="PAYLOAD"',
        'Password age >90',
        '<Root><!-- <!DOCTYPE Root> --><![CDATA[ordinary]]></Root>'
    )
    for ($index = 0; $index -lt $texts.Count; $index++) {
        [pscustomobject]@{
            Name = 'Text' + $index
            Kind = 'Text'
            InputObject = $texts[$index].Replace('PAYLOAD', $script:Marker)
        }
    }
}

function Get-NativeResult($Scenario) {
    $rows = [Collections.Generic.List[object]]::new()
    if ($Scenario.Kind -eq 'Text') {
        ConvertTo-ADAnalyzerSecretIndicatorText $Scenario.InputObject | ForEach-Object {
            $rows.Add($_)
        }
    }
    else {
        ConvertTo-ADAnalyzerSecretIndicatorXml $Scenario.InputObject | ForEach-Object {
            $rows.Add($_)
        }
    }
    [pscustomobject][ordered]@{
        Name = $Scenario.Name
        Count = $rows.Count
        Results = @(
            foreach ($row in $rows) {
                [pscustomobject][ordered]@{
                    Type = $row.GetType().FullName
                    NodeType = if ($row -is [Xml.XmlNode]) {
                        [string]$row.PSBase.NodeType
                    }
                    else {
                        $null
                    }
                    Text = if ($row -is [Xml.XmlNode]) {
                        $row.PSBase.OuterXml
                    }
                    else {
                        [string]$row
                    }
                    InnerText = if ($row -is [Xml.XmlNode]) {
                        $row.PSBase.InnerText
                    }
                    else {
                        $null
                    }
                }
            }
        )
    }
}

function Get-NativeCollisionSources([string]$Family) {
    switch ($Family) {
        'LocalName' {
            '<Password><LocalName>Note</LocalName><Value>PAYLOAD</Value></Password>'
            '<Root><Password LocalName="Note">PAYLOAD</Password></Root>'
        }
        'Attributes' {
            '<Properties name="DefaultPassword" value="PAYLOAD"><Attributes /></Properties>'
            '<Setting><Name>Password</Name><Value>PAYLOAD</Value><Attributes /></Setting>'
            '<Root><Item password="PAYLOAD"><Attributes /></Item></Root>'
        }
        'Traversal' {
            '<Setting name="Password"><Value>PAYLOAD</Value><ChildNodes /></Setting>'
            '<Root><Password><ParentNode /></Password></Root>'
            '<Root><OwnerDocument /><Password>PAYLOAD</Password></Root>'
            '<Setting name="Password"><Value><NodeType>Note</NodeType>PAYLOAD</Value></Setting>'
            '<Setting name="Password"><Name>Password</Name><Value>PAYLOAD</Value><HasChildNodes /></Setting>'
            '<Root><Item password="PAYLOAD"><OwnerElement /></Item></Root>'
        }
        'Payload' {
            '<Setting name="Password"><Value><InnerText />PAYLOAD</Value></Setting>'
            '<Setting name="Password"><Value><LocalName>Note</LocalName>PAYLOAD</Value></Setting>'
            '<Root><Password><InnerText />PAYLOAD</Password></Root>'
            '<Properties name="DefaultPassword" value="PAYLOAD"><Value /><IsEmpty /></Properties>'
            '<Setting name="Password"><Value>PAYLOAD</Value><Value>PAYLOAD</Value></Setting>'
        }
    }
}

function Assert-NativeProjection([string]$Text, [string]$Expected) {
    $document = New-NativeDocument $Text
    foreach ($kind in @('Document', 'Element')) {
        $inputObject = if ($kind -eq 'Document') {
            $document
        }
        else {
            $document.PSBase.DocumentElement
        }
        $before = $document.PSBase.OuterXml
        $rows = [Collections.Generic.List[object]]::new()
        ConvertTo-ADAnalyzerSecretIndicatorXml $inputObject | ForEach-Object {
            $rows.Add($_)
        }
        Assert-Native ($rows.Count -eq 1) 'DOM projection changed its output cardinality.'
        $safe = $rows[0]
        Assert-Native ($safe -is [Xml.XmlNode]) 'DOM projection returned a non-node.'
        $actual = $safe.PSBase.OuterXml
        Assert-Native (-not $actual.Contains($script:Marker)) 'DOM projection retained a secret payload.'
        if ($Expected) {
            Assert-Native ($actual -ceq $Expected) 'DOM projection changed the expected XML structure or presence.'
        }
        Assert-Native ($before -ceq $document.PSBase.OuterXml) 'DOM projection mutated the source tree.'
        Assert-Native (-not [object]::ReferenceEquals($safe, $inputObject)) 'DOM projection returned the source node.'
        $script:Scenarios++
    }
}

# Replace only the file boundary; the exporter and all formatters remain real.
function Write-ADAnalyzerFile {
    param(
        $Path,
        [AllowEmptyString()][string]$Content

    )
    $script:Sink.Add([pscustomobject]@{
            Path = $Path
            HasPayload = $Content.Contains($script:Marker)
            HasPresence = $Content -match '(?i)Present'
        })
    $Path
}

function New-NativeAssessment($Evidence) {
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

try {
    if ($Case -eq 'RecordBaseline') {
        $body = (Get-Command Get-ADAnalyzerXmlSecretName).ScriptBlock.ToString()
        Assert-Native ($body.Contains('$Node.Attributes')) 'Capture the accepted implementation before native-member changes.'
        $results = @(
            foreach ($scenario in @(Get-NativeOrdinaryScenarios)) {
                Get-NativeResult $scenario
            }
        )
        Assert-Native ($results.Count -eq 18) 'Ordinary baseline table is incomplete.'
        $baseline = [pscustomobject][ordered]@{
            Source = 'dd4563e95b23cc04294f30f63cd31ee558128c22'
            Results = $results
        }
        [IO.File]::WriteAllText(
            (Join-Path $PSScriptRoot 'XmlNativePropertyBaseline.json'),
            (ConvertTo-Json -InputObject $baseline -Depth 30),
            [Text.UTF8Encoding]::new($true)
        )
        Write-Host 'PASS XML native baseline captured 18'
        return
    }

    switch ($Case) {
        'Parity' {
            $baseline = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'XmlNativePropertyBaseline.json') -Raw | ConvertFrom-Json
            Assert-Native ($baseline.Source -ceq 'dd4563e95b23cc04294f30f63cd31ee558128c22') 'Ordinary baseline source changed.'
            $ordinaryCases = @(Get-NativeOrdinaryScenarios)
            Assert-Native ($baseline.Results.Count -eq $ordinaryCases.Count) 'Ordinary baseline coverage changed.'
            foreach ($scenario in $ordinaryCases) {
                $expected = @($baseline.Results | Where-Object Name -eq $scenario.Name)
                Assert-Native ($expected.Count -eq 1) 'Ordinary baseline identity is ambiguous.'
                $actual = Get-NativeResult $scenario
                $expectedJson = ConvertTo-Json -InputObject $expected[0] -Depth 30 -Compress
                $actualJson = ConvertTo-Json -InputObject $actual -Depth 30 -Compress
                Assert-Native ($actualJson -ceq $expectedJson) 'Ordinary result, type or cardinality changed.'
                $script:Scenarios++
            }
            $oldPath = Join-Path $PSScriptRoot 'XmlNodeBoundaryBaseline.json'
            $oldBytes = [IO.File]::ReadAllBytes($oldPath)
            $oldHash = Get-NativeGoldenHash $oldBytes
            $rawHash = (Get-FileHash -LiteralPath $oldPath -Algorithm SHA256).Hash
            $oldText = [Text.UTF8Encoding]::new($false, $true).GetString($oldBytes)
            $crlfCount = [regex]::Matches($oldText, "`r`n").Count
            $lfCount = [regex]::Matches($oldText, "`n").Count
            $bareCrCount = [regex]::Matches($oldText, "`r").Count - $crlfCount
            $diagnostic = 'RawSHA256={0}; CanonicalSHA256={1}; Bytes={2}; CRLF={3}; LF={4}; BareCR={5}.' -f
            $rawHash, $oldHash, $oldBytes.Length, $crlfCount, $lfCount, $bareCrCount
            if ($rawHash -ine $oldHash) {
                Write-Host ('XML golden checkout normalization. ' + $diagnostic)
            }
            Assert-Native ($oldHash -ieq '136cace20568709834b1af9633379f22bc0f88c1951af0634d0770fccb7145f8') ('Original node golden changed. ' + $diagnostic)
        }
        { $_ -in @('LocalName', 'Attributes', 'Traversal', 'Payload') } {
            foreach ($source in @(Get-NativeCollisionSources $Case)) {
                Assert-NativeProjection $source ''
            }
        }
        'Presence' {
            Assert-NativeProjection '<Password><LocalName>Note</LocalName><Value>PAYLOAD</Value></Password>' '<PasswordPresent>true</PasswordPresent>'
            Assert-NativeProjection '<Properties name="DefaultPassword" value="PAYLOAD"><Attributes /></Properties>' '<Properties name="DefaultPassword" SecretPresent="true"><Attributes /></Properties>'
            Assert-NativeProjection '<Setting name="Password"><Value><InnerText />PAYLOAD</Value></Setting>' '<Setting name="Password" SecretPresent="true" />'
            Assert-NativeProjection '<Setting name="Password"><Value><InnerText /></Value></Setting>' '<Setting name="Password" SecretPresent="false" />'
            Assert-NativeProjection '<Root><Password><InnerText /></Password></Root>' '<Root><PasswordPresent>false</PasswordPresent></Root>'
            $record = [pscustomobject]@{
                Name = 'ordinary'
                Value = 'keep'
                LocalName = 'Password'
                Attributes = 'data'
            }
            Assert-Native ([object]::ReferenceEquals($record, (ConvertTo-ADAnalyzerSecretRecord $record))) 'Ordinary DTO identity changed.'
            $secret = ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{
                    Name = 'Password'
                    Value = $script:Marker
                    Attributes = 'keep'
                })
            Assert-Native ($secret.SecretPresent -is [bool] -and $secret.SecretPresent) 'DTO secret presence changed.'
            Assert-Native ($secret.Attributes -ceq 'keep' -and
                $null -eq $secret.PSObject.Properties['Value']) 'DTO data field handling changed.'
        }
        'DataMembers' {
            $source = '<Root><Attributes>keep</Attributes><ChildNodes>keep</ChildNodes><LocalName>keep</LocalName><Value>keep</Value><InnerText>keep</InnerText><NodeType>keep</NodeType><OwnerDocument>keep</OwnerDocument><OwnerElement>keep</OwnerElement><ParentNode>keep</ParentNode><HasChildNodes>keep</HasChildNodes><IsEmpty>keep</IsEmpty><DocumentElement>keep</DocumentElement><OuterXml>keep</OuterXml><InnerXml>keep</InnerXml></Root>'
            Assert-NativeProjection $source $source
            Assert-Native ((ConvertTo-ADAnalyzerSecretIndicatorText $source) -ceq $source) 'Ordinary text data members changed.'
        }
        'Serialization' {
            foreach ($source in @(
                    '<OuterXml><Password>PAYLOAD</Password><Note>keep</Note></OuterXml>',
                    '<Root><OuterXml><Password>PAYLOAD</Password></OuterXml><Note>keep</Note></Root>',
                    '<DocumentElement><Password>PAYLOAD</Password></DocumentElement>',
                    '<Root><DocumentElement><Password>PAYLOAD</Password></DocumentElement></Root>',
                    '<InnerXml><Password>PAYLOAD</Password></InnerXml>',
                    '<Root><InnerXml><Password>PAYLOAD</Password></InnerXml></Root>',
                    '<OuterXml><Password>PAYLOAD</Password></OuterXml><Note>keep</Note>',
                    '<DocumentElement><Password>PAYLOAD</Password></DocumentElement><InnerXml>keep</InnerXml>'
                )) {
                $text = $source.Replace('PAYLOAD', $script:Marker)
                $rows = @(ConvertTo-ADAnalyzerSecretIndicatorText $text)
                Assert-Native ($rows.Count -eq 1 -and $rows[0] -is [string]) 'Text projection returned the wrong type or count.'
                $expected = $source.Replace('<Password>PAYLOAD</Password>', '<PasswordPresent>true</PasswordPresent>')
                Assert-Native ($rows[0] -ceq $expected) 'Text projection selected a data member instead of native XML.'
                $script:Scenarios++
            }
        }
        { $_ -in @('SafeData', 'Export') } {
            foreach ($source in @(
                    '<Password><LocalName>Note</LocalName><Value>PAYLOAD</Value></Password>',
                    '<Properties name="DefaultPassword" value="PAYLOAD"><Attributes /></Properties>',
                    '<Password><OuterXml>PAYLOAD</OuterXml></Password>',
                    '<OuterXml><Password>PAYLOAD</Password><Note>keep</Note></OuterXml>'
                )) {
                $document = New-NativeDocument $source
                foreach ($inputObject in @($document, $document.PSBase.DocumentElement)) {
                    $before = $document.PSBase.OuterXml
                    if ($Case -eq 'SafeData') {
                        $rows = @(ConvertTo-ADAnalyzerSafeData $inputObject)
                        Assert-Native ($rows.Count -eq 1 -and $rows[0] -is [string]) 'SafeData changed XML output type or count.'
                        Assert-Native (-not $rows[0].Contains($script:Marker)) 'SafeData retained a collision payload.'
                        Assert-Native ($rows[0] -match 'Present') 'SafeData lost collision presence evidence.'
                    }
                    else {
                        $script:Sink.Clear()
                        $rows = @(Export-ADAnalyzerAssessment `
                                -Assessment (New-NativeAssessment $inputObject) `
                                -Path 'memory-only-native-output' `
                                -Format All `
                                -Confirm:$false)
                        Assert-Native ($rows.Count -eq 3 -and $script:Sink.Count -eq 3) 'Export did not exercise all three real formatters.'
                        Assert-Native (@($script:Sink | Where-Object HasPayload).Count -eq 0) 'Export retained a collision payload.'
                        Assert-Native (@($script:Sink | Where-Object { -not $_.HasPresence }).Count -eq 0) 'Export lost presence evidence.'
                    }
                    Assert-Native ($before -ceq $document.PSBase.OuterXml) 'Consumer mutated its source XML.'
                    $script:Scenarios++
                }
            }
        }
        'Policy' {
            $document = New-NativeDocument '<Root><Item uid="first"/><Item uid="second"><Attributes/><LocalName>Note</LocalName><NodeType>Note</NodeType><ParentNode/><PreviousSibling/></Item></Root>'
            $item = $document.SelectSingleNode('/Root/Item[2]')
            Assert-Native ((Get-ADAnalyzerXmlAttribute $item uid) -ceq 'second') 'XML attribute lookup selected a data member.'
            Assert-Native ((Get-ADAnalyzerPolicyXmlPath $item) -ceq 'Item#second') 'UID policy path selected data members.'
            $item.RemoveAttribute('uid')
            Assert-Native ((Get-ADAnalyzerPolicyXmlPath $item) -ceq 'Root[1]/Item[2]') 'Indexed policy path selected data members.'
            $script:Scenarios++
            foreach ($source in @('<OuterXml><Password>PAYLOAD</Password></OuterXml>',
                    '<Root><OuterXml>keep</OuterXml><Password>PAYLOAD</Password></Root>')) {
                $document = New-NativeDocument $source
                foreach ($inputObject in @($document, $document.PSBase.DocumentElement)) {
                    $rows = @(Get-ADAnalyzerPresencePolicyXml $inputObject)
                    Assert-Native ($rows.Count -eq 1 -and $rows[0] -is [string]) 'Policy serializer returned the wrong type or count.'
                    Assert-Native ($rows[0] -ceq $source.Replace('<Password>PAYLOAD</Password>',
                            '<PasswordPresent>true</PasswordPresent>')) 'Policy serializer lost native XML.'
                    $script:Scenarios++
                }
            }
            $groups = [pscustomobject]@{
                Scope = 'Computer'
                Path = 'Groups.xml'
                Xml = '<Groups><DocumentElement/><LocalName>Note</LocalName><ChildNodes/><Group uid="fixture"><LocalName>User</LocalName><Attributes/><Properties groupName="Administrators" action="U"><Attributes/></Properties><Filters><HasChildNodes/></Filters></Group></Groups>'
            }
            $rows = @(ConvertFrom-ADAnalyzerLocalUsersGroups @($groups))
            Assert-Native ($rows.Count -eq 1 -and $rows[0].Kind -ceq 'Group') 'Local group parsing selected XML data members.'
            Assert-Native ($rows[0].Name -ceq 'Administrators' -and $rows[0].Targeted) 'Local group attributes or filter targeting changed.'
            Assert-Native ($rows[0].Filters -ceq '<Filters><HasChildNodes /></Filters>') 'Local group filter serialization changed.'
            $script:Scenarios++
            $document = New-NativeDocument '<enabledValue><string><InnerText />keep</string></enabledValue>'
            $value = Get-ADAnalyzerAdmxValue $document.PSBase.DocumentElement
            Assert-Native ($value.Valid -and $value.Value -ceq 'keep') 'ADMX string selected XML data instead of native text.'
            $script:Scenarios++
            $document = New-NativeDocument '<enabledValue><decimal value="1"><LocalName>string</LocalName><Attributes/></decimal></enabledValue>'
            $value = Get-ADAnalyzerAdmxValue $document.PSBase.DocumentElement
            Assert-Native ($value.Valid -and $value.Value -eq 1) 'ADMX native value kind or attribute lookup changed.'
            $script:Scenarios++
            $policy = [pscustomobject]@{
                SecuritySettings = @()
                RegistrySettings = @()
                IniSettings = @()
                Files = @()
                UnparsedFiles = @()
                XmlFiles = @([pscustomobject]@{
                        Scope = 'Computer'
                        Path = 'Groups.xml'
                        Xml = '<Groups><User uid="fixture"><Attributes/><ParentNode/><Properties action="U" userName="fixture-account" cpassword="' + $script:Marker + '" cpasswordPresent="true"><Attributes/><ParentNode/></Properties></User></Groups>'
                    })
            }
            $gpo = [pscustomobject]@{
                Id = [guid]'07400000-0000-0000-0000-000000000001'
                Flags = 0
                Links = @()
            }
            $checks = @(Test-ADAnalyzerGpoPolicy `
                    -Gpo $gpo `
                    -Policy $policy `
                    -Profile (Get-ADAnalyzerDefaultProfile) | Where-Object RuleId `
                    -eq 'GPO.Preferences.CPassword')
            Assert-Native ($checks.Count -eq 1) 'Credential owner was dropped or counted twice.'
            Assert-Native ($checks[0].Observed -is [bool] -and $checks[0].Observed) 'Credential evidence lost boolean presence.'
            Assert-Native ($checks[0].Evidence.ItemUid -ceq 'fixture' -and
                $checks[0].Evidence.Account -ceq 'fixture-account') 'Credential owner metadata selected XML data members.'
            Assert-Native ($checks[0].Evidence.ItemPath -ceq 'User#fixture/Properties[1]/@cpassword') 'Credential owner path selected XML data members.'
            Assert-Native (-not (ConvertTo-Json `
                        -InputObject $checks `
                        -Depth 30 `
                        -Compress).Contains($script:Marker)) 'Credential caller retained a payload.'
            $script:Scenarios++
        }
        'Admx' {
            $script:TemplateRoot = Join-Path ([IO.Path]::GetTempPath()) 'memory-native-templates'
            $script:Admx = New-NativeDocument '<policyDefinitions><policyNamespaces><target namespace="fixture"/></policyNamespaces><policies><policy name="Fixture" class="Machine" key="Software\Fixture" displayName="$(string.Title)"><elements><boolean id="enabled" valueName="Flag"><LocalName>string</LocalName><Attributes/><trueValue><decimal value="1"><LocalName>string</LocalName></decimal></trueValue></boolean></elements></policy></policies></policyDefinitions>'
            $script:Adml = New-NativeDocument '<policyDefinitionResources><resources><stringTable><string id="Title"><InnerText/>Native title</string></stringTable></resources></policyDefinitionResources>'

            function Test-Path {
                param(
                    $LiteralPath,
                    $PathType

                )
                $true
            }

            function Get-ChildItem {
                param(
                    $LiteralPath,
                    $Filter,
                    [switch]$File,
                    $ErrorAction

                )
                [pscustomobject]@{
                    FullName = Join-Path $script:TemplateRoot 'fixture.admx'
                    BaseName = 'fixture'
                    Name = 'fixture.admx'
                }
            }

            function Read-AnalyzerPolicyXml {
                param($Path)
                if ($Path.EndsWith('.adml')) {
                    $script:Adml
                }
                else {
                    $script:Admx
                }
            }
            $row = [pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Flag'
                Type = 4
                Value = 1
            }
            $rows = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($row) -TemplatePath $script:TemplateRoot)
            Assert-Native ($rows.Count -eq 1 -and $rows[0].MetadataStatus -ceq 'Resolved') 'ADMX collision prevented metadata resolution.'
            Assert-Native ($rows[0].DisplayName -ceq 'Native title') 'ADML resource selected XML data instead of native text.'
            Assert-Native ($rows[0].DefinitionType -ceq 'boolean' -and
                $rows[0].State -ceq 'True') 'ADMX collision changed the native definition kind or value.'
            Assert-Native ($rows[0].Value -eq 1) 'ADMX metadata changed the original DTO value.'
            $script:Scenarios++
        }
        'Provided' {
            foreach ($source in @('<OuterXml><Password>PAYLOAD</Password></OuterXml>',
                    '<Root><OuterXml>keep</OuterXml><Properties name="DefaultPassword" value="PAYLOAD"><Attributes/></Properties></Root>')) {
                $policy = [pscustomobject]@{
                    XmlFiles = @([pscustomobject]@{
                            Scope = 'Computer'
                            Kind = 'Preferences'
                            Path = 'fixture.xml'
                            Xml = $source.Replace('PAYLOAD', $script:Marker)
                        })
                }
                $before = $policy.XmlFiles[0].Xml
                $safe = ConvertTo-ADAnalyzerProvidedGpoPolicy $policy
                Assert-Native ($safe.XmlFiles.Count -eq 1 -and
                    $safe.XmlFiles[0].Xml -is [string]) 'Provided XML changed its record/string contract.'
                Assert-Native (-not $safe.XmlFiles[0].Xml.Contains($script:Marker)) 'Provided XML retained a collision payload.'
                Assert-Native ($safe.XmlFiles[0].Xml -match 'Present' -and
                    $safe.XmlFiles[0].Xml -match 'OuterXml') 'Provided serializer lost XML metadata.'
                Assert-Native ($before -ceq $policy.XmlFiles[0].Xml) 'Provided input was mutated.'
                $script:Scenarios++
            }
        }
        'Reader' {
            # Keep the real reader loop/serialization and replace only the
            # directory inventory and XML input boundaries with memory data.
            $script:ReaderRoot = Join-Path ([IO.Path]::GetTempPath()) 'memory-native-reader'
            $script:ReaderSide = Join-Path $script:ReaderRoot 'Machine'

            function Get-Item {
                param(
                    $LiteralPath,
                    [switch]$Force,
                    $ErrorAction

                )
                if ($LiteralPath -eq $script:ReaderRoot -or $LiteralPath -eq $script:ReaderSide) {
                    [pscustomobject]@{
                        FullName = $LiteralPath
                        PSIsContainer = $true
                    }
                }
            }

            function Get-ChildItem {
                param(
                    $LiteralPath,
                    [switch]$File,
                    [switch]$Force,
                    [switch]$Recurse,
                    $ErrorAction

                )
                if ($LiteralPath -eq $script:ReaderSide) {
                    [pscustomobject]@{
                        Name = 'fixture.xml'
                        FullName = Join-Path $script:ReaderSide 'fixture.xml'
                        Extension = '.xml'
                        Length = 0
                    }
                }
            }

            function Read-AnalyzerPolicyXml {
                param($Path)
                $script:ReaderDocument
            }
            foreach ($source in @(
                    '<OuterXml><Password>PAYLOAD</Password></OuterXml>',
                    '<Root><OuterXml>keep</OuterXml><Password>PAYLOAD</Password></Root>'
                )) {
                $script:ReaderDocument = New-NativeDocument $source
                $before = $script:ReaderDocument.PSBase.OuterXml
                $report = Read-ADAnalyzerGpo -Path $script:ReaderRoot
                Assert-Native ($report.XmlFiles.Count -eq 1 -and
                    $report.XmlFiles[0].Xml -is [string]) 'Reader changed its XML record/string contract.'
                $expected = $source.Replace('<Password>PAYLOAD</Password>', '<PasswordPresent>true</PasswordPresent>')
                Assert-Native ($report.XmlFiles[0].Xml -ceq $expected) 'Reader serializer selected XML data members.'
                Assert-Native ($before -ceq $script:ReaderDocument.PSBase.OuterXml) 'Reader projection mutated input XML.'
                $script:Scenarios++
            }
        }
        'Standalone' {
            . (Join-Path $repositoryRoot 'etc/Get-GPOXML.ps1')
            # The standalone script reimports its real writer; replace its owned
            # boundary after loading it and keep parsing/metadata/serialization.
            function Write-ADAnalyzerFile {
                param(
                    $Path,
                    [AllowEmptyString()][string]$Content

                )
                $script:Sink.Add([pscustomobject]@{
                        Path = $Path
                        HasPayload = $Content.Contains($script:Marker)
                        HasPresence = $Content.Contains('PasswordPresent')
                    })
                $Path
            }

            function Import-Module {
                param(
                    $Name,
                    $ErrorAction

                )
            }

            function Get-ADAnalyzerGpo {
                param(
                    $Domain,
                    $Credential,
                    $Name,
                    $Guid

                ) $script:Metadata
            }

            function Get-ADAnalyzerGpoReport {
                param(
                    $Gpo,
                    $Credential

                ) $script:Report
            }
            $script:Metadata = [pscustomobject]@{
                Id = [guid]'07400000-0000-0000-0000-000000000001'
                DisplayName = 'native fixture'
                Domain = 'example.invalid'
                Server = 'fixture.example.invalid'
                Flags = 0
            }
            $script:Report = '<GPO><OuterXml>keep</OuterXml><DocumentElement/><FirstChild/><LocalName>Note</LocalName><Password>' + $script:Marker + '</Password></GPO>'
            $rows = @(Get-ADAnalyzerGpoXml -Domain example.invalid -Name fixture)
            Assert-Native ($rows.Count -eq 1 -and $rows[0] -is [string]) 'Standalone serializer returned the wrong type or count.'
            Assert-Native (-not $rows[0].Contains($script:Marker)) 'Standalone XML retained a collision payload.'
            $safe = New-NativeDocument $rows[0]
            Assert-Native ($safe.PSBase.FirstChild -is [Xml.XmlDeclaration]) 'Standalone declaration was lost.'
            Assert-Native ($safe.SelectSingleNode('/GPO/DisplayName').PSBase.InnerText -ceq 'native fixture') 'Standalone metadata update selected data members.'
            Assert-Native ($safe.SelectSingleNode('/GPO/OuterXml').PSBase.InnerText -ceq 'keep') 'Standalone serializer lost unrelated XML data.'
            Assert-Native ($safe.SelectSingleNode('/GPO/PasswordPresent').PSBase.InnerText -ceq 'true') 'Standalone serializer lost presence.'
            Assert-Native ($script:Sink.Count -eq 0) 'Standalone read-only call reached the writer.'
            $script:Scenarios++
        }
    }
    $expectedScenarios = @{
        Parity = 18
        LocalName = 4
        Attributes = 6
        Traversal = 12
        Payload = 10
        Presence = 10
        DataMembers = 2
        Serialization = 8
        SafeData = 8
        Export = 8
        Policy = 9
        Admx = 1
        Provided = 2
        Reader = 2
        Standalone = 1
    }
    Assert-Native ($script:Scenarios -eq $expectedScenarios[$Case]) 'Required native-property scenarios were not all executed.'
    Write-Host ('PASS XML native properties ' + $Case + ' ' + $script:Scenarios)
}
catch {
    # Deliberately report only the input-free assertion, never fixture XML/data.
    $message = $_.Exception.Message.Replace($script:Marker, '[fixture]')
    Write-Host ('FAIL XML native properties ' + $Case + ': ' + $message)
    exit 1
}
