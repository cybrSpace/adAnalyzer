[CmdletBinding()]
param(
    [ValidateSet('Owner',
        'Unsupported',
        'Parity',
        'Defaults',
        'Namespace',
        'RootSecret',
        'Document',
        'Isolation',
        'DocumentDefaults',
        'SchemaIsolation',
        'RecordBaseline')]
    [string]$Case = 'Owner'
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:Marker = 'NODE_BOUNDARY_PAYLOAD_072'

function Assert-Node($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-NodeDocument([string]$Text) {
    $document = [xml]::new()
    $document.PreserveWhitespace = $true
    $document.XmlResolver = $null
    $document.LoadXml($Text)
    return $document
}

function New-DefaultNodeDocument {
    $schemaText = @'
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="Root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="Child">
          <xs:complexType>
            <xs:attribute name="ChildMode" type="xs:string" default="child-default" />
          </xs:complexType>
        </xs:element>
      </xs:sequence>
      <xs:attribute name="Id" type="xs:string" />
      <xs:attribute name="Mode" type="xs:string" default="root-default" />
      <xs:attribute name="Password" type="xs:string" default="NODE_BOUNDARY_PAYLOAD_072" />
    </xs:complexType>
  </xs:element>
</xs:schema>
'@
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $textReader = [IO.StringReader]::new($schemaText)
    $schemaReader = $null
    try {
        $schemaReader = [Xml.XmlReader]::Create($textReader, $settings)
        $document = New-NodeDocument '<Root Id="one"><Child /></Root>'
        $null = $document.Schemas.Add('', $schemaReader)
        $document.Validate($null)
        return $document
    }
    finally {
        if ($null -ne $schemaReader) {
            $schemaReader.Dispose()
        }
        $textReader.Dispose()
    }
}

function Get-NodeScenarios {
    $ordinary = New-NodeDocument ('<Root cpassword="' + $script:Marker + '"><Item id="one">café</Item><Password>' + $script:Marker + '</Password></Root>')
    [pscustomobject]@{
        Name = 'Document'
        Node = $ordinary
    }
    [pscustomobject]@{
        Name = 'Element'
        Node = $ordinary.DocumentElement
    }
    $newline = [string][char]13 + [char]10
    $text = "<Outer xmlns:p='urn:fixture' xml:lang='en' xml:space='preserve'><p:Item id='one'>" + $newline + ' café ' + $newline + "<![CDATA[keep raw]]><?fixture value?><!-- keep --><Empty/><Full></Full></p:Item><Sibling password='" + $script:Marker + "'/></Outer>"
    $namespaced = New-NodeDocument $text
    [pscustomobject]@{
        Name = 'Namespace'
        Node = $namespaced.SelectSingleNode('/*/*[local-name()="Item"]')
    }
    $defaultNamespace = New-NodeDocument '<Outer xmlns="urn:default"><Item><Inner /><Full></Full></Item></Outer>'
    [pscustomobject]@{
        Name = 'DefaultNamespace'
        Node = $defaultNamespace.SelectSingleNode('/*/*')
    }
    $secret = New-NodeDocument ('<Outer><Password>' + $script:Marker + '</Password><Sibling>' + $script:Marker + '</Sibling></Outer>')
    [pscustomobject]@{
        Name = 'RootSecret'
        Node = $secret.SelectSingleNode('/Outer/Password')
    }
    $empty = New-NodeDocument '<Outer><Empty /><Full></Full><Item cpassword="" /></Outer>'
    [pscustomobject]@{
        Name = 'EmptyForms'
        Node = $empty.DocumentElement
    }
    $defaults = New-DefaultNodeDocument
    [pscustomobject]@{
        Name = 'Defaults'
        Node = $defaults.DocumentElement
    }
    $declaration = New-NodeDocument '<?xml version="1.0" encoding="utf-16" standalone="yes"?><Root>text</Root>'
    [pscustomobject]@{
        Name = 'Declaration'
        Node = $declaration
    }
}

function Get-NodeSnapshot([Xml.XmlNode]$Node) {
    $attributes = @(
        foreach ($attribute in $Node.PSBase.Attributes) {
            [pscustomobject][ordered]@{
                Name = $attribute.PSBase.Name
                LocalName = $attribute.PSBase.LocalName
                Prefix = $attribute.PSBase.Prefix
                NamespaceURI = $attribute.PSBase.NamespaceURI
                Value = $attribute.PSBase.Value
                Specified = $attribute.PSBase.Specified
            }
        }
    )
    $children = @(
        foreach ($child in $Node.PSBase.ChildNodes) {
            Get-NodeSnapshot $child
        }
    )
    [pscustomobject][ordered]@{
        NodeType = [string]$Node.PSBase.NodeType
        Name = $Node.PSBase.Name
        LocalName = $Node.PSBase.LocalName
        Prefix = $Node.PSBase.Prefix
        NamespaceURI = $Node.PSBase.NamespaceURI
        Value = $Node.PSBase.Value
        IsEmpty = if ($Node -is [Xml.XmlElement]) {
            $Node.PSBase.IsEmpty
        }
        else {
            $null
        }
        OuterXml = $Node.PSBase.OuterXml
        InnerText = $Node.PSBase.InnerText
        Attributes = $attributes
        Children = $children
    }
}

function ConvertTo-NodeJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 60 -Compress
}

function Assert-FreshOwner([Xml.XmlElement]$Result, [Xml.XmlDocument]$Source) {
    $owner = $Result.PSBase.OwnerDocument
    Assert-Node (-not [object]::ReferenceEquals($owner, $Source)) 'Projected element retains the raw source owner.'
    Assert-Node ($null -eq $Result.PSBase.ParentNode) 'Projected element gained a parent.'
    Assert-Node ($owner.PSBase.ChildNodes.Count -eq 0) 'Projected owner contains a document tree.'
    Assert-Node (-not [object]::ReferenceEquals($owner.PSBase.NameTable, $Source.PSBase.NameTable)) 'Result shares the source name table.'
    Assert-Node (-not [object]::ReferenceEquals($owner.PSBase.Schemas, $Source.PSBase.Schemas)) 'Result shares mutable source schemas.'
    Assert-Node ($owner.PSBase.Schemas.Count -eq 0) 'Result copied source schema state.'
    Assert-Node (-not $owner.PSBase.OuterXml.Contains($script:Marker)) 'Source payload is reachable through the projected owner.'
}

if ($Case -eq 'RecordBaseline') {
    $body = (Get-Command ConvertTo-ADAnalyzerSecretIndicatorXml).ScriptBlock.ToString()
    Assert-Node (-not $body.Contains('XmlNodeReader') -and
        -not ('ADAnalyzerSecretIndicator' -as [type])) 'Capture the original node contract before boundary/class changes.'
    $results = @(
        foreach ($scenario in @(Get-NodeScenarios)) {
            $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $scenario.Node
            [pscustomobject]@{
                Name = $scenario.Name
                Result = Get-NodeSnapshot $safe
            }
        }
    )
    $baseline = [pscustomobject]@{
        Source = 'c137a3a54ac1882ed83e5883ed47c30700293938'
        Results = $results
    }
    [IO.File]::WriteAllText(
        (Join-Path $PSScriptRoot 'XmlNodeBoundaryBaseline.json'),
        (ConvertTo-Json -InputObject $baseline -Depth 60),
        [Text.UTF8Encoding]::new($true)
    )
    Write-Host ('PASS XML node baseline captured ' + $results.Count)
    return
}

switch ($Case) {
    'Owner' {
        foreach ($scenario in @(Get-NodeScenarios | Where-Object { $_.Node -is [Xml.XmlElement] })) {
            $source = $scenario.Node.PSBase.OwnerDocument
            $before = ConvertTo-NodeJson (Get-NodeSnapshot $source)
            $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $scenario.Node
            Assert-FreshOwner $safe $source
            Assert-Node ($before -ceq (ConvertTo-NodeJson (Get-NodeSnapshot $source))) 'Projection mutated original tree.'
        }
    }
    'Unsupported' {
        $document = New-NodeDocument '<Root />'
        $attribute = $document.CreateAttribute('cpassword')
        $attribute.Value = $script:Marker
        $fragment = $document.CreateDocumentFragment()
        $fragment.InnerXml = '<Password>' + $script:Marker + '</Password>'
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
        Assert-Node ($nodes.Count -eq 11) 'Unsupported node table missing cases.'
        foreach ($node in $nodes) {
            $rows = [Collections.Generic.List[object]]::new()
            $caught = $null
            $before = $node.PSBase.OuterXml
            try {
                ConvertTo-ADAnalyzerSecretIndicatorXml $node | ForEach-Object {
                    $rows.Add($_)
                }
            }
            catch {
                $caught = $_
            }
            Assert-Node ([bool]$caught) ('Unsupported XML kind accepted: ' + $node.PSBase.NodeType)
            Assert-Node ($rows.Count -eq 0) 'Unsupported node emitted raw result.'
            Assert-Node ($caught.Exception.GetBaseException() -is [ArgumentException]) 'Unsupported kind has no argument diagnostic.'
            Assert-Node (-not $caught.ToString().Contains($script:Marker)) 'Unsupported error echoed payload.'
            Assert-Node ($before -ceq $node.PSBase.OuterXml) 'Unsupported rejection changed input.'
        }
    }
    'Parity' {
        $baseline = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'XmlNodeBoundaryBaseline.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $scenarios = @(Get-NodeScenarios)
        Assert-Node ($baseline.Results.Count -eq 8 -and $scenarios.Count -eq 8) 'Supported node cases missing.'
        for ($i = 0; $i -lt $scenarios.Count; $i++) {
            Assert-Node ($baseline.Results[$i].Name -ceq $scenarios[$i].Name) 'Supported case order changed.'
            $before = ConvertTo-NodeJson (Get-NodeSnapshot $scenarios[$i].Node)
            $actual = ConvertTo-ADAnalyzerSecretIndicatorXml $scenarios[$i].Node
            Assert-Node ((ConvertTo-NodeJson $baseline.Results[$i].Result) -ceq (ConvertTo-NodeJson (Get-NodeSnapshot $actual))) ('Supported node contract changed: ' + $scenarios[$i].Name)
            Assert-Node ($before -ceq (ConvertTo-NodeJson (Get-NodeSnapshot $scenarios[$i].Node))) 'Supported input changed.'
        }
    }
    'Defaults' {
        $source = New-DefaultNodeDocument
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $source.DocumentElement
        $mode = $safe.GetAttributeNode('Mode')
        $childMode = $safe.SelectSingleNode('./Child').GetAttributeNode('ChildMode')
        Assert-Node ($mode.Value -ceq 'root-default' -and -not $mode.Specified) 'Root default lost/materialized.'
        Assert-Node ($childMode.Value -ceq 'child-default' -and -not $childMode.Specified) 'Child default lost/materialized.'
        Assert-Node ($safe.GetAttribute('PasswordPresent') -ceq 'true' -and
            -not $safe.HasAttribute('Password')) 'Default secret not reduced to presence.'
        Assert-FreshOwner $safe $source
    }
    'Namespace' {
        $scenario = @(Get-NodeScenarios | Where-Object Name -eq Namespace)[0]
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $scenario.Node
        Assert-Node ($safe.NamespaceURI -ceq 'urn:fixture' -and $safe.Prefix -ceq 'p') 'Namespace identity changed.'
        Assert-Node ($safe.InnerText.Contains(([string][char]13 + [char]10))) 'CRLF normalized.'
        Assert-Node ($safe.OuterXml -ceq $scenario.Node.OuterXml) 'Namespace/text XML changed.'
        $kinds = @($safe.ChildNodes | ForEach-Object { [string]$_.NodeType }) -join ','
        Assert-Node ($kinds -ceq 'Text,CDATA,ProcessingInstruction,Comment,Element,Element') 'Child kinds changed.'
        Assert-FreshOwner $safe $scenario.Node.PSBase.OwnerDocument
    }
    'RootSecret' {
        $scenario = @(Get-NodeScenarios | Where-Object Name -eq RootSecret)[0]
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $scenario.Node
        Assert-Node ($safe -is [Xml.XmlElement] -and
            $safe.OuterXml -ceq '<PasswordPresent>true</PasswordPresent>') 'Secret root replacement changed.'
        Assert-FreshOwner $safe $scenario.Node.PSBase.OwnerDocument
    }
    'Document' {
        $scenario = @(Get-NodeScenarios | Where-Object Name -eq Declaration)[0]
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $scenario.Node
        Assert-Node ($safe -is [xml] -and $null -eq $safe.PSBase.OwnerDocument) 'Document return kind changed.'
        Assert-Node ($safe.OuterXml -ceq $scenario.Node.OuterXml) 'Document declaration changed.'
        Assert-Node (-not [object]::ReferenceEquals($safe, $scenario.Node)) 'Document aliases input.'
        $text = '<?xml version="1.0" encoding="utf-16" standalone="yes"?><!-- before --><?fixture value?><Root>text</Root><!-- after -->'
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $textReader = [IO.StringReader]::new($text)
        $reader = $null
        try {
            $reader = [Xml.XmlReader]::Create($textReader, $settings, 'urn:adanalyzer:document-control')
            $source = [xml]::new()
            $source.PreserveWhitespace = $true
            $source.XmlResolver = $null
            $source.Load($reader)
            $before = ConvertTo-NodeJson (Get-NodeSnapshot $source)
            $copy = ConvertTo-ADAnalyzerSecretIndicatorXml $source
            Assert-Node ($copy.PSBase.BaseURI -ceq $source.PSBase.BaseURI) 'Document base URI changed.'
            Assert-Node ($copy.PSBase.OuterXml -ceq $source.PSBase.OuterXml) 'Document prolog or exterior nodes changed.'
            Assert-Node ((ConvertTo-NodeJson (Get-NodeSnapshot $copy)) -ceq $before) 'Document control tree changed.'
        }
        finally {
            if ($null -ne $reader) {
                $reader.Dispose()
            }
            $textReader.Dispose()
        }
        $empty = [xml]::new()
        $copy = ConvertTo-ADAnalyzerSecretIndicatorXml $empty
        Assert-Node ($copy -is [xml] -and $copy.PSBase.ChildNodes.Count -eq 0) 'Empty document contract changed.'
    }

    'DocumentDefaults' {
        $source = New-DefaultNodeDocument
        $before = ConvertTo-NodeJson (Get-NodeSnapshot $source)
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $source
        Assert-Node ($safe -is [xml]) 'Document projection changed return kind.'
        $root = $safe.PSBase.DocumentElement
        Assert-Node ($root.GetAttribute('PasswordPresent') -ceq 'true' -and
            -not $root.HasAttribute('Password')) 'Document default secret presence was lost.'
        $mode = $root.GetAttributeNode('Mode')
        $childMode = $root.SelectSingleNode('./Child').GetAttributeNode('ChildMode')
        Assert-Node ($null -ne $mode -and
            $mode.Value -ceq 'root-default' -and
            -not $mode.Specified) 'Document root default lost/materialized.'
        Assert-Node ($null -ne $childMode -and
            $childMode.Value -ceq 'child-default' -and
            -not $childMode.Specified) 'Document descendant default lost/materialized.'
        Assert-Node (($root.Attributes.Name -join ',') -ceq 'Id,Mode,PasswordPresent') 'Document default attribute order changed.'
        Assert-Node ($before -ceq (ConvertTo-NodeJson (Get-NodeSnapshot $source))) 'Document defaults projection changed source.'
        $mode.Value = 'result-only'
        Assert-Node ($source.DocumentElement.GetAttribute('Mode') -ceq 'root-default') 'Default attribute aliases source.'
        Assert-Node (-not [object]::ReferenceEquals($safe, $source)) 'Document result aliases source.'
    }

    'SchemaIsolation' {
        $source = New-DefaultNodeDocument
        $schemaType = $source.PSBase.DocumentElement.PSBase.SchemaInfo.SchemaType
        Assert-Node ($null -ne $schemaType) 'Fixture schema information is missing.'
        $passwordSchema = @($schemaType.AttributeUses.Values | Where-Object Name -eq Password)[0]
        Assert-Node ($passwordSchema.DefaultValue -ceq $script:Marker) 'Fixture schema payload is missing.'
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $source
        Assert-Node ($safe.DocumentElement.GetAttribute('PasswordPresent') -ceq 'true') 'Schema-default secret was not detected.'
        Assert-Node ($safe.PSBase.Schemas.Count -eq 0 -and
            -not [object]::ReferenceEquals($safe.PSBase.Schemas,
                $source.PSBase.Schemas)) 'Result retained source schema collection.'
        $stack = [Collections.Generic.Stack[Xml.XmlNode]]::new()
        $stack.Push($safe)
        $visited = 0
        while ($stack.Count) {
            $node = $stack.Pop()
            $information = $node.PSBase.SchemaInfo
            if ($null -ne $information) {
                Assert-Node ($null -eq $information.SchemaType -and
                    $null -eq $information.SchemaElement -and
                    $null -eq $information.SchemaAttribute) 'Result retained source schema metadata.'
            }
            foreach ($child in $node.PSBase.ChildNodes) {
                $stack.Push($child)
            }
            foreach ($attribute in $node.PSBase.Attributes) {
                $stack.Push($attribute)
            }
            $visited++
        }
        Assert-Node ($visited -gt 4) 'Schema graph was not fully visited.'
        Assert-Node (-not (ConvertTo-Json `
                    -InputObject $safe `
                    -Depth 30 `
                    -Compress).Contains($script:Marker)) 'Document JSON retained schema payload.'
        Assert-Node (-not [Management.Automation.PSSerializer]::Serialize($safe).Contains($script:Marker)) 'Document CLIXML retained schema payload.'
        Assert-Node ($source.DocumentElement.GetAttribute('Password') -ceq $script:Marker) 'Source default secret changed.'
    }

    'Isolation' {
        $source = New-NodeDocument ('<Root><Item id="original"><Value>text</Value></Item><Sibling password="' + $script:Marker + '"/></Root>')
        $node = $source.SelectSingleNode('/Root/Item')
        $before = $source.OuterXml
        $first = ConvertTo-ADAnalyzerSecretIndicatorXml $node
        $second = ConvertTo-ADAnalyzerSecretIndicatorXml $node
        Assert-FreshOwner $first $source
        Assert-FreshOwner $second $source
        Assert-Node (-not [object]::ReferenceEquals($first.PSBase.OwnerDocument, $second.PSBase.OwnerDocument)) 'Calls share owners.'
        $first.SetAttribute('id', 'result')
        $first.SelectSingleNode('./Value').InnerText = 'result-text'
        $null = $first.PSBase.OwnerDocument.AppendChild($first.PSBase.OwnerDocument.CreateElement('Independent'))
        Assert-Node ($source.OuterXml -ceq $before) 'Result/owner edits mutated source.'
        Assert-Node ($second.GetAttribute('id') -ceq 'original' -and $second.InnerText -ceq 'text') 'Results share nodes.'
        $node.SetAttribute('id', 'source')
        Assert-Node ($first.GetAttribute('id') -ceq 'result' -and $second.GetAttribute('id') -ceq 'original') 'Source edit mutated results.'
        Assert-Node (-not (ConvertTo-Json `
                    -InputObject $second `
                    -Depth 30 `
                    -Compress).Contains($script:Marker)) 'JSON retained sibling payload.'
        Assert-Node (-not [Management.Automation.PSSerializer]::Serialize($second).Contains($script:Marker)) 'CLIXML retained sibling payload.'
    }
}
Write-Host ('PASS XML node boundary ' + $Case)
