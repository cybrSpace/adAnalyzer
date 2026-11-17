[CmdletBinding()]
param(
    [ValidateSet('Document', 'Element', 'Text', 'Malformed', 'SafeData', 'Export', 'WhatIf', 'Controls', 'NoExpansion')]
    [string]$Case = 'Document'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:Marker = 'PROJECTION_PAYLOAD_FIXTURE_071'
$script:Sink = [Collections.Generic.List[object]]::new()
$script:Rejected = 0

function Assert-Dtd($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

# Replace only the owned file boundary; exercise the real exporter/projection.
function Write-ADAnalyzerFile {
    param(
        $Path,
        [AllowEmptyString()][string]$Content

    )
    $script:Sink.Add([pscustomobject]@{
            Path = $Path
            HasPayload = $Content.Contains($script:Marker)
        })
    $Path
}

function Get-DtdText {
    '<!DOCTYPE Root [<!ENTITY x "' + $script:Marker + '">]><Root><Password>&x;</Password></Root>'
}

function New-DtdDocument([string]$RootName = 'Root') {
    $document = [xml]::new()
    $document.XmlResolver = $null
    $text = (Get-DtdText).Replace('DOCTYPE Root', ('DOCTYPE ' + $RootName))
    $text = $text.Replace('<Root>', ('<' + $RootName + '>')).Replace('</Root>', ('</' + $RootName + '>'))
    $document.LoadXml($text)
    return $document
}

function Assert-DtdRejected([scriptblock]$Body) {
    $rows = [Collections.Generic.List[object]]::new()
    $caught = $null
    try {
        & $Body | ForEach-Object {
            $rows.Add($_)
        }
    }
    catch {
        $caught = $_
    }
    if (-not $caught -and @($script:Sink | Where-Object HasPayload).Count) {
        throw 'DTD payload reached the memory writer.'
    }
    Assert-Dtd ([bool]$caught) 'DTD input was not rejected.'
    Assert-Dtd ($rows.Count -eq 0) 'DTD projection emitted partial output.'
    Assert-Dtd ($caught.Exception.Message -like '*DTD*') 'DTD rejection lost its diagnostic.'
    Assert-Dtd (-not $caught.ToString().Contains($script:Marker)) 'DTD error echoed a payload value.'
    $script:Rejected++
}

function New-DtdAssessment($Evidence) {
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

switch ($Case) {
    'Document' {
        foreach ($root in @('Root', 'DocumentType')) {
            $document = New-DtdDocument $root
            $before = $document.OuterXml
            Assert-DtdRejected { ConvertTo-ADAnalyzerSecretIndicatorXml $document }
            Assert-Dtd ($before -ceq $document.OuterXml) 'DTD rejection mutated the source document.'
        }
    }

    'Element' {
        $document = New-DtdDocument
        $element = $document.DocumentElement
        $null = $element.AppendChild($document.CreateElement('OwnerDocument'))
        $before = $document.OuterXml
        Assert-DtdRejected { ConvertTo-ADAnalyzerSecretIndicatorXml $element }
        Assert-Dtd ($before -ceq $document.OuterXml) 'DTD element rejection mutated the source.'
    }

    'Text' {
        $text = Get-DtdText
        foreach ($source in @(
                $text,
                ('<?xml version="1.0"?>' + $text),
                ('<!-- prefix --><?fixture value?>' + $text),
                '<!DOCTYPE Root SYSTEM "urn:adanalyzer:fixture-must-not-resolve"><Root><Password /></Root>',
                ('<!DOCTYPE Root [<!ENTITY x "' + $script:Marker + '">]><Root>&x;</Root>')
            )) {
            $before = $source
            Assert-DtdRejected { ConvertTo-ADAnalyzerSecretIndicatorText $source }
            Assert-Dtd ($source -ceq $before) 'DTD text rejection mutated its input.'
        }
    }

    'Malformed' {
        foreach ($source in @(
                ('diagnostic prefix ' + (Get-DtdText)),
                ('<Wrapper>' + (Get-DtdText) + '</Wrapper>'),
                ('<!DOCTYPE Root [<!ENTITY x "' + $script:Marker + '">]<Root><Password>&x;</Password>'),
                ('<!doctype Root><Root><Password value="' + $script:Marker + '"></Root>')
            )) {
            Assert-DtdRejected { ConvertTo-ADAnalyzerSecretIndicatorText $source }
        }
    }

    'SafeData' {
        foreach ($value in @((New-DtdDocument), (Get-DtdText))) {
            $inputObject = [pscustomobject]@{
                Nested = @(
                    [pscustomobject]@{
                        Evidence = $value
                    }
                )
            }
            Assert-DtdRejected { ConvertTo-ADAnalyzerSafeData $inputObject }
        }
    }

    'Export' {
        foreach ($value in @((New-DtdDocument), (Get-DtdText))) {
            foreach ($format in @('Json', 'Html', 'Csv', 'All')) {
                $script:Sink.Clear()
                $assessment = New-DtdAssessment $value
                $parameters = @{
                    Assessment = $assessment
                    Path = 'memory-only-fixture-output'
                    Format = $format
                    Confirm = $false
                }
                Assert-DtdRejected { Export-ADAnalyzerAssessment @parameters }
                Assert-Dtd ($script:Sink.Count -eq 0) 'DTD export reached the memory writer.'
            }
        }
    }

    'WhatIf' {
        $assessment = New-DtdAssessment (Get-DtdText)
        Assert-DtdRejected {
            Export-ADAnalyzerAssessment -Assessment $assessment -Path 'memory-only-fixture-output' -Format All -WhatIf
        }
        Assert-Dtd ($script:Sink.Count -eq 0) 'WhatIf wrote a projection.'
    }

    'Controls' {
        foreach ($source in @(
                'Password age >90',
                'ordinary text',
                '<Root note="plain" />',
                '<Root><![CDATA[<!DOCTYPE Root>]]></Root>',
                '<Root><!-- <!DOCTYPE Root> --></Root>',
                'prefix<![CDATA[<!DOCTYPE Root>]]>suffix',
                'prefix<!-- <!DOCTYPE Root> -->suffix'
            )) {
            $actual = ConvertTo-ADAnalyzerSecretIndicatorText $source
            Assert-Dtd ($actual -ceq $source) 'Safe literal/no-secret text changed.'
        }
        foreach ($source in @(
                '<Root note="Password age >90"><![CDATA[<!DOCTYPE Root>]]></Root>',
                '<Root note="Password age >90"><!-- <!DOCTYPE Root> --></Root>'
            )) {
            $expected = ([xml]$source).OuterXml
            Assert-Dtd ((ConvertTo-ADAnalyzerSecretIndicatorText $source) -ceq $expected) 'Safe parsed literal DTD example changed.'
        }
        $document = [xml]('<Root cpassword="' + $script:Marker + '"><Password>' + $script:Marker + '</Password></Root>')
        $before = $document.OuterXml
        $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $document
        Assert-Dtd ($safe.OuterXml -ceq '<Root cpasswordPresent="true"><PasswordPresent>true</PasswordPresent></Root>') 'Supported XML presence result changed.'
        Assert-Dtd ($before -ceq $document.OuterXml) 'Supported XML projection mutated input.'
        Assert-Dtd ((ConvertTo-ADAnalyzerSecretIndicatorText ('password="' + $script:Marker + '"')) -ceq 'passwordPresent="true"') 'Quoted text projection changed.'
        $safeText = ConvertTo-ADAnalyzerSecretIndicatorText ('broken <Root cpassword="' + $script:Marker + '"')
        Assert-Dtd ($safeText -ceq 'broken <Root cpasswordPresent="true"') 'Non-DTD fallback changed.'
        $script:Sink.Clear()
        $assessment = New-DtdAssessment '<Root PasswordPresent="true" />'
        $rows = @(Export-ADAnalyzerAssessment -Assessment $assessment -Path 'memory-only-fixture-output' -Format All -Confirm:$false)
        Assert-Dtd ($rows.Count -eq 3 -and $script:Sink.Count -eq 3) 'Valid export control did not reach all formats.'
        Assert-Dtd (@($script:Sink | Where-Object HasPayload).Count -eq 0) 'Valid export leaked a fixture payload.'
    }

    'NoExpansion' {
        $compilerParameters = @{}
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $compilerParameters.ReferencedAssemblies = @(
                [Xml.XmlResolver].Assembly.Location
                [Net.ICredentials].Assembly.Location
            )
        }
        Add-Type @compilerParameters -TypeDefinition @'
namespace ADAnalyzer.DtdFixture {
    public sealed class Resolver : System.Xml.XmlResolver {
        public static int Calls;
        public override System.Net.ICredentials Credentials { set {} }
        public override object GetEntity(System.Uri uri, string role, System.Type type) {
            Calls++;
            throw new System.InvalidOperationException("Fixture entity resolution is forbidden.");
        }
    }
}
'@
        $text = '<!DOCTYPE Root SYSTEM "urn:adanalyzer:fixture-must-not-resolve"><Root><Password /></Root>'
        $document = [xml]::new()
        $document.XmlResolver = $null
        $document.LoadXml($text)
        $document.XmlResolver = [ADAnalyzer.DtdFixture.Resolver]::new()
        Assert-DtdRejected { ConvertTo-ADAnalyzerSecretIndicatorXml $document }
        Assert-DtdRejected { ConvertTo-ADAnalyzerSecretIndicatorText $text }
        Assert-Dtd ([ADAnalyzer.DtdFixture.Resolver]::Calls -eq 0) 'Projection tried to resolve an external DTD.'
    }
}

$expectedRejections = @{
    Document = 2
    Element = 1
    Text = 5
    Malformed = 4
    SafeData = 2
    Export = 8
    WhatIf = 1
    Controls = 0
    NoExpansion = 2
}
Assert-Dtd ($script:Rejected -eq $expectedRejections[$Case]) 'Required DTD cases were not all executed.'
Write-Host ('PASS DTD projection ' + $Case)
