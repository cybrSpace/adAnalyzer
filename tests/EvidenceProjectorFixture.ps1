[CmdletBinding()]
param(
    [ValidateSet('RecordBaseline',
        'Characterization',
        'Metadata',
        'References',
        'Errors',
        'Capabilities',
        'Construction',
        'Direct',
        'Binding',
        'Ownership',
        'Isolation',
        'Serialization',
        'Loading',
        'Uncaught')]
    [string]$Case = 'Characterization'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repositoryRoot 'bin/ADOperations.ps1'
$baselinePath = Join-Path $PSScriptRoot 'EvidenceProjectorBaseline.json'
$acceptedSource = '68269b8ca9d638cafbe08b802bbc92e0584a68c6a95a94d955f8636170bf7742'
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:EvidenceOwned = [Collections.Generic.List[IDisposable]]::new()
$script:EvidenceTrace = [Collections.Generic.List[string]]::new()
$script:EvidenceExecuted = 0
$script:EvidenceMarker = 'EVIDENCE_PROJECTOR_FIXTURE_081'

function Assert-Evidence($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-EvidenceHash([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-EvidenceJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 90 -Compress
}

function Get-EvidenceSnapshot($Value, [Collections.Generic.List[object]]$Path = $null) {
    if ($null -eq $Value) {
        return [pscustomobject][ordered]@{
            Type = '<null>'
            Value = $null
        }
    }
    $type = $Value.GetType()
    if ($Value -is [string]) {
        return [pscustomobject][ordered]@{
            Type = $type.FullName
            Value = [string]$Value
        }
    }
    if ($Value -is [ValueType]) {
        $text = if ($Value -is [IFormattable]) {
            [IFormattable].GetMethod('ToString').Invoke($Value, [object[]]@($null, [Globalization.CultureInfo]::InvariantCulture))
        }
        else {
            [string]$Value
        }
        return [pscustomobject][ordered]@{
            Type = $type.FullName
            Value = $text
        }
    }
    if ($Value -is [Xml.XmlNode]) {
        return [pscustomobject][ordered]@{
            Type = $type.FullName
            Xml = $Value.PSBase.OuterXml
        }
    }
    if ($null -eq $Path) {
        $Path = [Collections.Generic.List[object]]::new()
    }
    for ($index = 0; $index -lt $Path.Count; $index++) {
        if ([object]::ReferenceEquals($Value, $Path[$index])) {
            return [pscustomobject][ordered]@{
                Type = $type.FullName
                CycleTo = $index
            }
        }
    }
    $Path.Add($Value)
    try {
        if ($Value -is [Collections.IDictionary]) {
            $entries = @(
                foreach ($key in $Value.Keys) {
                    [pscustomobject][ordered]@{
                        Key = Get-EvidenceSnapshot $key $Path
                        Value = Get-EvidenceSnapshot $Value[$key] $Path
                    }
                }
            )
            return [pscustomobject][ordered]@{
                Type = $type.FullName
                Entries = $entries
            }
        }
        if ($Value -is [array] -or $Value -is [Collections.IList]) {
            $items = @(
                foreach ($item in $Value) {
                    Get-EvidenceSnapshot $item $Path
                }
            )
            return [pscustomobject][ordered]@{
                Type = $type.FullName
                Items = $items
            }
        }
        $properties = @(
            foreach ($property in $Value.PSObject.Properties) {
                [pscustomobject][ordered]@{
                    Name = $property.Name
                    Value = Get-EvidenceSnapshot $property.Value $Path
                }
            }
        )
        return [pscustomobject][ordered]@{
            Type = $type.FullName
            Properties = $properties
        }
    }
    finally {
        $Path.RemoveAt($Path.Count - 1)
    }
}

function New-EvidenceSecure([bool]$Present, [bool]$Disposed = $false) {
    $value = [Security.SecureString]::new()
    if ($Present) {
        $value.AppendChar('x')
    }
    $script:EvidenceOwned.Add($value)
    if ($Disposed) {
        $value.Dispose()
    }
    return $value
}

function New-EvidenceXml([string]$Text) {
    $document = [xml]::new()
    $document.PreserveWhitespace = $true
    $document.XmlResolver = $null
    $document.LoadXml($Text)
    return $document
}

function New-EvidenceScenario(
    [string]$Name,
    [string]$Group,
    [string]$Route,
    $Value,
    [hashtable]$Arguments = @{},
    $Resource = $null
) {
    [pscustomobject]@{
        Name = $Name
        Group = $Group
        Route = $Route
        Value = $Value
        Arguments = $Arguments
        Resource = $Resource
    }
}

function Initialize-EvidenceNativeTypes {
    if (-not ('System.Numerics.BigInteger' -as [type])) {
        Add-Type -AssemblyName System.Numerics
    }
    if ('ADAnalyzer.EvidenceFixture081.EnumerableProbe' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
namespace ADAnalyzer.EvidenceFixture081
{
    public sealed class EnumerableProbe : IEnumerable
    {
        private readonly string failure;
        public EnumerableProbe(string failure)
        {
            this.failure = failure;
        }
        public int Creates { get; private set; }
        public int Moves { get; private set; }
        public int Reads { get; private set; }
        public int Disposes { get; private set; }
        public IEnumerator GetEnumerator()
        {
            Creates++;
            if (failure == "Create")
            {
                throw new InvalidOperationException("Fixture Create failure.");
            }
            return new Cursor(this);
        }
        private sealed class Cursor : IEnumerator, IDisposable
        {
            private readonly EnumerableProbe owner;
            private int index = -1;
            public Cursor(EnumerableProbe owner)
            {
                this.owner = owner;
            }
            public bool MoveNext()
            {
                owner.Moves++;
                index++;
                if (owner.failure == "Move" && index == 1)
                {
                    throw new InvalidOperationException("Fixture Move failure.");
                }
                return index < 2;
            }
            public object Current
            {
                get
                {
                    owner.Reads++;
                    if (owner.failure == "Current" && index == 1)
                    {
                        throw new InvalidOperationException("Fixture Current failure.");
                    }
                    return index + 1;
                }
            }
            public void Reset()
            {
                throw new NotSupportedException();
            }
            public void Dispose()
            {
                owner.Disposes++;
            }
        }
    }
    public sealed class CountProbe : ICollection
    {
        private readonly bool failure;
        public CountProbe(bool failure)
        {
            this.failure = failure;
        }
        public int Reads { get; private set; }
        int ICollection.Count
        {
            get
            {
                Reads++;
                if (failure)
                {
                    throw new InvalidOperationException("Fixture Count failure.");
                }
                return 1;
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
}

function Get-EvidenceCapabilities {
    foreach ($name in @('System.Numerics.BigInteger', 'System.Half', 'System.Int128', 'System.UInt128')) {
        [pscustomobject][ordered]@{
            Name = $name
            Available = $null -ne ($name -as [type])
        }
    }
}

function Get-EvidenceScenarios {
    New-EvidenceScenario Omitted Binding Omitted $null
    New-EvidenceScenario Null Binding Explicit $null
    New-EvidenceScenario EmptyPipeline Binding Pipeline ([object[]]@())
    New-EvidenceScenario PairPipeline Binding Pipeline ([object[]]@(1, 2))
    New-EvidenceScenario OneArrayPipeline Binding PipelineOne ([object[]]@(1, 2))
    New-EvidenceScenario EmptyArrayPipeline Binding PipelineOne ([object[]]@())
    $wrapped = [Management.Automation.PSObject]::AsPSObject([object[]]@(1, 2))
    $wrapped.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new('Note', 'metadata'))
    $wrapped.PSTypeNames.Insert(0, 'ADAnalyzer.EvidenceFixture081.WrappedArray')
    New-EvidenceScenario WrappedExplicit Binding Explicit $wrapped
    New-EvidenceScenario WrappedPipeline Binding PipelineOne $wrapped
    $scalarValues = [ordered]@{
        EmptyString = ''
        OrdinaryString = 'ordinary'
        False = $false
        True = $true
        Byte = [byte]0
        SByte = [sbyte]-1
        Int16 = [int16]-2
        UInt16 = [uint16]2
        Int32 = [int32]-3
        UInt32 = [uint32]3
        Int64 = [int64]-4
        UInt64 = [uint64]4
        Single = [single]1.25
        Double = [double]1.5
        NaN = [double]::NaN
        PositiveInfinity = [double]::PositiveInfinity
        Decimal = [decimal]12.50
        Character = [char]'é'
        Enum = [StringComparison]::OrdinalIgnoreCase
        TimeSpan = [timespan]::FromSeconds(90)
        Guid = [guid]'11111111-2222-3333-4444-555555555555'
        Version = [version]'1.2.3.4'
        DbNull = [DBNull]::Value
    }
    foreach ($name in $scalarValues.Keys) {
        New-EvidenceScenario ('Scalar' + $name) Scalars Explicit $scalarValues[$name]
    }
    $utc = [datetime]::SpecifyKind([datetime]::Parse('2026-01-02T03:04:05.1234567',
            [Globalization.CultureInfo]::InvariantCulture),
        [DateTimeKind]::Utc)
    New-EvidenceScenario DateUtc Scalars Explicit $utc
    New-EvidenceScenario DateLocal Scalars Explicit $utc.ToLocalTime()
    New-EvidenceScenario DateUnspecified Scalars Explicit ([datetime]::SpecifyKind($utc.ToLocalTime(), [DateTimeKind]::Unspecified))
    New-EvidenceScenario DateOffset Scalars Explicit ([datetimeoffset]::Parse('2026-01-02T06:04:05.1234567+03:00',
            [Globalization.CultureInfo]::InvariantCulture))
    foreach ($capability in @(Get-EvidenceCapabilities)) {
        if ($capability.Available) {
            $type = $capability.Name -as [type]
            $value = $type::Parse('123', [Globalization.CultureInfo]::InvariantCulture)
            New-EvidenceScenario ('Numeric' + $capability.Name) Optional Explicit $value
        }
    }
    New-EvidenceScenario ArrayEmpty Containers Explicit ([object[]]@())
    New-EvidenceScenario ArraySingleton Containers Explicit ([object[]]@(1))
    New-EvidenceScenario ArrayPair Containers Explicit ([object[]]@(1, 2))
    New-EvidenceScenario ArrayNull Containers Explicit ([object[]]@($null, 1))
    $inner = [object[]]@(1, 2)
    $nested = [object[]]::new(2)
    $nested[0] = $inner
    $nested[1] = 'tail'
    New-EvidenceScenario ArrayNested Containers Explicit $nested
    $list = [Collections.ArrayList]::new()
    $null = $list.Add($null)
    $null = $list.Add(2)
    New-EvidenceScenario ArrayList Containers Explicit $list
    $genericList = [Collections.Generic.List[object]]::new()
    $genericList.Add(1)
    $genericList.Add(2)
    New-EvidenceScenario GenericList Containers Explicit $genericList
    New-EvidenceScenario Hashtable Containers Explicit @{
        Only = 1
    }
    New-EvidenceScenario Ordered Containers Explicit ([ordered]@{
            First = 1
            Last = 'last'
        })
    New-EvidenceScenario Object Containers Explicit ([pscustomobject][ordered]@{
            First = 1
            Child = [pscustomobject]@{
                Value = 2
            }
            Last = $null
        })
    $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $map.Add('First', 1)
    $map.Add('Last', 2)
    New-EvidenceScenario GenericMap Containers Explicit $map
    $entry = [Collections.DictionaryEntry]::new('ordinary', [pscustomobject]@{
            Item = 1
        })
    New-EvidenceScenario EntryOrdinary Pairs Explicit $entry
    New-EvidenceScenario EntrySecret Pairs Explicit ([Collections.DictionaryEntry]::new('Password', $script:EvidenceMarker))
    New-EvidenceScenario PairOrdinary Pairs Explicit ([Collections.Generic.KeyValuePair[string,
        object]]::new('ordinary',
            [object[]]@(1,
                2)))
    New-EvidenceScenario PairSecret Pairs Explicit ([Collections.Generic.KeyValuePair[string, object]]::new('Password', ''))
    foreach ($present in @($false, $true)) {
        $secure = New-EvidenceSecure $present
        New-EvidenceScenario ('Secure' + $present) Secrets Explicit $secure
        New-EvidenceScenario ('Credential' + $present) Secrets Explicit ([pscredential]::new('fixture', $secure))
    }
    $disposed = New-EvidenceSecure $true $true
    New-EvidenceScenario DisposedSecure Secrets Explicit $disposed
    New-EvidenceScenario DisposedCredential Secrets Explicit ([pscredential]::new('fixture', $disposed))
    foreach ($flagFirst in @($false, $true)) {
        foreach ($rawPresent in @($false, $true)) {
            $fields = [ordered]@{}
            $raw = if ($rawPresent) {
                $script:EvidenceMarker
            }
            else {
                ''
            }
            if ($flagFirst) {
                $fields['passwordPRESENT'] = -not $rawPresent
                $fields['Password'] = $raw
            }
            else {
                $fields['Password'] = $raw
                $fields['passwordPRESENT'] = -not $rawPresent
            }
            New-EvidenceScenario ('Merge' + $flagFirst + $rawPresent) Secrets Explicit $fields
        }
    }
    $taggedIndex = 0
    foreach ($value in @($false, 0, '', $null)) {
        New-EvidenceScenario ('TaggedValue' + $taggedIndex) Secrets Explicit ([pscustomobject][ordered]@{
                Name = 'Password'
                Value = $value
                Expected = $script:EvidenceMarker
                After = 'last'
            })
        $taggedIndex++
    }
    $rawIndex = 0
    foreach ($value in @($null, $false, 0, [object[]]@(), [object[]]@($null), @{}, @{
                Count = 0
                Item = $script:EvidenceMarker
            })) {
        New-EvidenceScenario ('DirectTyped' + $rawIndex) Secrets Explicit ([ordered]@{
                Password = $value
                PasswordPresent = $false
            })
        $rawIndex++
    }
    New-EvidenceScenario PairedNonBool Secrets Explicit ([ordered]@{
            PasswordPresent = 'true'
            Password = ''
        })
    foreach ($reverse in @($false, $true)) {
        $rawCases = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
        if ($reverse) {
            $rawCases.Add('PASSWORD', $script:EvidenceMarker)
            $rawCases.Add('Password', '')
        }
        else {
            $rawCases.Add('Password', '')
            $rawCases.Add('PASSWORD', $script:EvidenceMarker)
        }
        New-EvidenceScenario ('OrdinalRaw' + $reverse) Secrets Explicit $rawCases
    }
    New-EvidenceScenario TaggedObservedFalse Secrets Explicit ([pscustomobject]@{
            Name = 'Password'
            Observed = $false
        })
    New-EvidenceScenario TaggedExpectedOnly Secrets Explicit ([pscustomobject]@{
            Name = 'Password'
            Expected = $script:EvidenceMarker
        })
    New-EvidenceScenario TaggedNonBoolFlag Secrets Explicit ([pscustomobject]@{
            Name = 'Password'
            SecretPresent = 'true'
        })
    foreach ($genericPayload in @($false, $true)) {
        foreach ($rawPresent in @($false, $true)) {
            $raw = if ($rawPresent) {
                $script:EvidenceMarker
            }
            else {
                ''
            }
            $fields = [ordered]@{
                Name = 'Password'
                Secret = $raw
                After = 'last'
            }
            if ($genericPayload) {
                $fields['Value'] = ''
            }
            New-EvidenceScenario ('MixedTagged' + $genericPayload + $rawPresent) Secrets Explicit ([pscustomobject]$fields)
        }
    }
    $ordinal = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $ordinal.Add('Password', '')
    $ordinal.Add('PasswordPresent', $true)
    $ordinal.Add('passwordPresent', $false)
    New-EvidenceScenario OrdinalMerge Secrets Explicit $ordinal
    $flags = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $flags.Add('PasswordPresent', $true)
    $flags.Add('passwordPresent', $false)
    New-EvidenceScenario FlagOnlyCase Secrets Explicit $flags
    New-EvidenceScenario FlagOnlyNonBool Secrets Explicit ([pscustomobject]@{
            PasswordPresent = 'ordinary'
        })
    New-EvidenceScenario SecretText Secrets Explicit ('password="' + $script:EvidenceMarker + '"')
    New-EvidenceScenario SecretFragment Secrets Explicit ('<Password>' + $script:EvidenceMarker + '</Password><Note>keep</Note>')
    $countProbe = [ADAnalyzer.EvidenceFixture081.CountProbe]::new($false)
    New-EvidenceScenario NativePresenceAfterTrue Secrets Explicit ([ordered]@{
            PasswordPresent = $true
            Password = $countProbe
        }) @{} $countProbe
    $document = New-EvidenceXml ('<Root Password="' + $script:EvidenceMarker + '"><Item>café</Item></Root>')
    New-EvidenceScenario XmlDocument Xml Explicit $document
    New-EvidenceScenario XmlElement Xml Explicit $document.PSBase.DocumentElement
    New-EvidenceScenario XmlEmpty Xml Explicit ([xml]::new())
    $schema = '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:element name="Root"><xs:complexType><xs:attribute name="Mode" type="xs:string" default="ordinary"/><xs:attribute name="Password" type="xs:string" default="fixture"/></xs:complexType></xs:element></xs:schema>'
    $schemaReader = [IO.StringReader]::new($schema)
    $reader = [Xml.XmlReader]::Create($schemaReader)
    try {
        $defaultDocument = New-EvidenceXml '<Root/>'
        $null = $defaultDocument.Schemas.Add('', $reader)
        $defaultDocument.Validate($null)
        New-EvidenceScenario XmlDefaultDocument Xml Explicit $defaultDocument
        New-EvidenceScenario XmlDefaultElement Xml Explicit $defaultDocument.PSBase.DocumentElement
    }
    finally {
        $reader.Dispose()
        $schemaReader.Dispose()
    }
    foreach ($depth in @(-1, 0, 40, 41)) {
        New-EvidenceScenario ('DepthScalar' + $depth) Depth Explicit 1 @{
            Depth = $depth
        }
    }
    New-EvidenceScenario DepthNull41 Depth Explicit $null @{
        Depth = 41
    }
    New-EvidenceScenario DepthNested40 Depth Explicit ([pscustomobject]@{
            Item = 1
        }) @{
        Depth = 40
    }
    $cycle = [ordered]@{
        Note = 'cycle'
        Next = $null
    }
    $cycle['Next'] = $cycle
    New-EvidenceScenario Cycle39 Depth Explicit $cycle @{
        Depth = 39
    }
    $getter = [pscustomobject]@{}
    $getter | Add-Member ScriptProperty Name { $script:EvidenceTrace.Add('Name')
        'ordinary' }
    $getter | Add-Member ScriptProperty Item { $script:EvidenceTrace.Add('Item')
        1 }
    New-EvidenceScenario GetterOrder Getters Explicit $getter
    $lookupGetter = [pscustomobject]@{}
    $lookupGetter | Add-Member ScriptProperty Value { $script:EvidenceTrace.Add('LookupValue')
        'borrowed' }
    New-EvidenceScenario LookupGetter Getters Lookup $lookupGetter @{
        Names = @('Missing', 'Value')
    }
    $lookup = [ordered]@{
        Null = $null
        Empty = [object[]]@()
        One = [object[]]@(1)
        Pair = [object[]]@(1, 2)
        Next = 'later'
    }
    New-EvidenceScenario LookupOmitted Lookup LookupOmitted $null
    New-EvidenceScenario LookupNullObject Lookup Lookup $null @{
        Names = @('Item')
        Default = 'fallback'
    }
    foreach ($name in @('Null', 'Empty', 'One', 'Pair', 'Missing')) {
        New-EvidenceScenario ('Lookup' + $name) Lookup Lookup $lookup @{
            Names = @($name, 'Next')
            Default = 'fallback'
        }
    }
    New-EvidenceScenario LookupNoNames Lookup Lookup $lookup @{
        Default = 'fallback'
    }
    New-EvidenceScenario LookupEmptyNames Lookup Lookup $lookup @{
        Names = [string[]]@()
        Default = 'fallback'
    }
    New-EvidenceScenario LookupDefaultArray Lookup Lookup $null @{
        Names = @('Missing')
        Default = [object[]]@(1, 2)
    }
    $caseMap = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $caseMap.Add('Name', $null)
    $caseMap.Add('name', 'lower')
    New-EvidenceScenario LookupOrdinal Lookup Lookup $caseMap @{
        Names = @('NAME', 'Name', 'name')
        Default = 'fallback'
    }
    New-EvidenceScenario LookupOrdinalLower Lookup Lookup $caseMap @{
        Names = @('NAME', 'name')
        Default = 'fallback'
    }
    $ignoreCase = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $ignoreCase.Add('Name', 'matched')
    New-EvidenceScenario LookupIgnoreCase Lookup Lookup $ignoreCase @{
        Names = @('NAME')
        Default = 'fallback'
    }
    $integers = [Collections.Generic.Dictionary[int, object]]::new()
    $integers.Add(1, 'integer')
    New-EvidenceScenario LookupIntegerKey Lookup Lookup $integers @{
        Names = @('1')
        Default = 'fallback'
    }
    $mixedKeys = [Collections.Specialized.OrderedDictionary]::new()
    $mixedKeys.Add(1, 'integer')
    $mixedKeys.Add('1', 'string')
    New-EvidenceScenario LookupStringKey Lookup Lookup $mixedKeys @{
        Names = @('1')
        Default = 'fallback'
    }
    New-EvidenceScenario StringifiedKeys Containers Explicit $mixedKeys
    New-EvidenceScenario LookupPropertyNull Lookup Lookup ([pscustomobject]@{
            First = $null
            Next = 'later'
        }) @{
        Names = @('First', 'Next')
        Default = 'fallback'
    }
}

function Get-EvidenceErrorScenarios {
    $document = New-EvidenceXml '<Root/>'
    $fragment = $document.CreateDocumentFragment()
    $fragment.InnerXml = '<Password>fixture</Password>'
    foreach ($node in @($document.CreateTextNode('fixture'), $document.CreateAttribute('Password'), $fragment)) {
        New-EvidenceScenario ('XmlKind' + [string]$node.PSBase.NodeType) Errors Explicit $node
    }
    $dtd = New-EvidenceXml '<!DOCTYPE Root [<!ENTITY x "fixture">]><Root><Password>&x;</Password></Root>'
    New-EvidenceScenario DtdDocument Errors Explicit $dtd
    New-EvidenceScenario DtdElement Errors Explicit $dtd.PSBase.DocumentElement
    New-EvidenceScenario DtdText Errors Explicit '<!DOCTYPE Root><Root><Password/></Root>'
    foreach ($failure in @('Create', 'Move', 'Current')) {
        $probe = [ADAnalyzer.EvidenceFixture081.EnumerableProbe]::new($failure)
        New-EvidenceScenario ('Enumerable' + $failure) Errors Explicit $probe @{} $probe
    }
    $tail = [pscustomobject]@{}
    $tail | Add-Member ScriptProperty Tail { $script:EvidenceTrace.Add('LateTail')
        3 }
    New-EvidenceScenario LateXml Errors Pipeline ([object[]]@([pscustomobject]@{
                Before = 1
            }, $document.CreateTextNode('fixture'), $tail))
    New-EvidenceScenario LateDtd Errors Pipeline ([object[]]@([pscustomobject]@{
                Before = 1
            }, '<!DOCTYPE Root><Root/>', $tail))
    $probe = [ADAnalyzer.EvidenceFixture081.EnumerableProbe]::new('Move')
    $nested = [object[]]::new(2)
    $nested[0] = [pscustomobject]@{
        Before = 1
    }
    $nested[1] = $probe
    New-EvidenceScenario NestedMove Errors Explicit $nested @{} $probe
    foreach ($name in @('Name', 'Item')) {
        $getter = [pscustomobject]@{}
        $getter | Add-Member ScriptProperty $name { $script:EvidenceTrace.Add('ThrowingGetter')
            throw 'Fixture property getter failure.' }
        New-EvidenceScenario ('GetterThrows' + $name) Errors Explicit $getter
    }
    $count = [ADAnalyzer.EvidenceFixture081.CountProbe]::new($true)
    New-EvidenceScenario NativeCountThrows Errors Explicit ([ordered]@{
            PasswordPresent = $true
            Password = $count
        }) @{} $count
    New-EvidenceScenario InvalidDepth Errors Explicit 'ordinary' @{
        Depth = 'invalid-depth'
    }
}

function Invoke-EvidenceScenario($Scenario) {
    $value = $Scenario.Value
    switch ($Scenario.Route) {
        Omitted {
            ConvertTo-ADAnalyzerSafeData
        }
        Explicit {
            $parameters = @{
                InputObject = $value
            }
            foreach ($key in $Scenario.Arguments.Keys) {
                $parameters[$key] = $Scenario.Arguments[$key]
            }
            ConvertTo-ADAnalyzerSafeData @parameters
        }
        Pipeline {
            $value | ConvertTo-ADAnalyzerSafeData
        }
        PipelineOne {
            , $value | ConvertTo-ADAnalyzerSafeData
        }
        Lookup {
            $parameters = @{
                Object = $value
            }
            foreach ($key in $Scenario.Arguments.Keys) {
                $parameters[$key] = $Scenario.Arguments[$key]
            }
            Get-ADAnalyzerOperationValue @parameters
        }
        LookupOmitted {
            Get-ADAnalyzerOperationValue
        }
    }
}

function Get-EvidenceError($Record) {
    $cause = $Record.Exception.GetBaseException()
    [pscustomobject][ordered]@{
        ExceptionType = $Record.Exception.GetType().FullName
        CauseType = $cause.GetType().FullName
        Message = $Record.Exception.Message
        CauseMessage = $cause.Message
        FullyQualifiedErrorId = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Reason = $Record.CategoryInfo.Reason
        TargetName = $Record.CategoryInfo.TargetName
        TargetType = $Record.CategoryInfo.TargetType
        TargetObjectType = if ($null -ne $Record.TargetObject) {
            $Record.TargetObject.GetType().FullName
        }
        else {
            '<null>'
        }
        ErrorDetails = if ($null -ne $Record.ErrorDetails) {
            $Record.ErrorDetails.Message
        }
        else {
            $null
        }
        OriginalStack = $Record.ScriptStackTrace
    }
}

function Get-EvidenceResource($Resource) {
    if ($null -eq $Resource) {
        return $null
    }
    $properties = @(
        foreach ($name in @('Creates', 'Moves', 'Reads', 'Disposes')) {
            $property = $Resource.PSObject.Properties[$name]
            if ($null -ne $property) {
                [pscustomobject][ordered]@{
                    Name = $name
                    Value = $property.Value
                }
            }
        }
    )
    return $properties
}

function Get-EvidenceCapture($Scenario, [string]$Preference = 'Stop', $Service = $null, [bool]$RetainBinding = $false) {
    $script:EvidenceTrace.Clear()
    $Error.Clear()
    $rows = [Collections.Generic.List[object]]::new()
    $streamErrors = [Collections.Generic.List[object]]::new()
    $caught = $false
    $originalPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = $Preference
        try {
            & {
                if ($null -ne $Service) {
                    Invoke-EvidenceObjectScenario $Scenario $Service $RetainBinding
                }
                else {
                    Invoke-EvidenceScenario $Scenario
                }
            } 2>&1 | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    $streamErrors.Add((Get-EvidenceError $_))
                }
                else {
                    $rows.Add($_)
                }
            }
        }
        catch {
            $caught = $true
            $streamErrors.Add((Get-EvidenceError $_))
        }
        $recordedErrors = @($Error | ForEach-Object { Get-EvidenceError $_ })
        $trace = @($script:EvidenceTrace)
        $resource = @(Get-EvidenceResource $Scenario.Resource)
        $typedRows = @($rows | ForEach-Object { Get-EvidenceSnapshot $_ })
    }
    finally {
        $ErrorActionPreference = $originalPreference
    }
    [pscustomobject][ordered]@{
        Name = $Scenario.Name
        Group = $Scenario.Group
        Route = $Scenario.Route
        Preference = $Preference
        Count = $rows.Count
        Rows = $typedRows
        Caught = $caught
        StreamErrors = $streamErrors.ToArray()
        ErrorCount = $recordedErrors.Count
        RecordedErrors = $recordedErrors
        GetterTrace = $trace
        Resource = $resource
    }
}

function Get-EvidenceComparable($Capture) {
    $copy = ConvertTo-EvidenceJson $Capture | ConvertFrom-Json
    foreach ($errorRow in @($copy.StreamErrors) + @($copy.RecordedErrors)) {
        if ($null -ne $errorRow) {
            $errorRow.PSObject.Properties.Remove('OriginalStack')
        }
    }
    return $copy
}

function Get-EvidenceNativeJsonContract {
    $text = ConvertTo-Json -InputObject $null -Depth 10 -Compress
    if ($null -ne $text) {
        Assert-Evidence ($text -is [string]) 'Native JSON null serialization produced a non-string.'
        return [pscustomobject][ordered]@{
            NullHasOutput = $true
            Text = $text
        }
    }
    return [pscustomobject][ordered]@{
        NullHasOutput = $false
        Text = $null
    }
}

function Get-EvidenceCommandMetadata([string]$Name) {
    $command = Get-Command $Name
    $body = $command.ScriptBlock.Ast
    if ($body -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $body = $body.Body
    }
    $parameters = @(
        foreach ($key in @($command.Parameters.Keys | Sort-Object)) {
            $parameter = $command.Parameters[$key]
            [pscustomobject][ordered]@{
                Name = $key
                Type = $parameter.ParameterType.FullName
                Aliases = @($parameter.Aliases)
                Sets = @(
                    foreach ($set in @($parameter.ParameterSets.Keys | Sort-Object)) {
                        $value = $parameter.ParameterSets[$set]
                        [pscustomobject][ordered]@{
                            Name = $set
                            Mandatory = $value.IsMandatory
                            Position = $value.Position
                            Pipeline = $value.ValueFromPipeline
                            PipelineByName = $value.ValueFromPipelineByPropertyName
                            Remaining = $value.ValueFromRemainingArguments
                        }
                    }
                )
                Attributes = @($parameter.Attributes | ForEach-Object { $_.GetType().FullName })
            }
        }
    )
    [pscustomobject][ordered]@{
        Name = $Name
        Parameters = if ($body.ParamBlock) {
            $body.ParamBlock.Extent.Text.Replace(([string][char]13 + [char]10), [string][char]10)
        }
        else {
            ''
        }
        Advanced = $command.CmdletBinding
        DefaultParameterSet = $command.DefaultParameterSet
        Metadata = $parameters
    }
}

function Get-EvidenceReferences {
    $child = [pscustomobject]@{
        Note = 'source'
    }
    $items = [object[]]@($child)
    $source = [ordered]@{
        First = $child
        Items = $items
        Password = $script:EvidenceMarker
    }
    $before = ConvertTo-EvidenceJson (Get-EvidenceSnapshot $source)
    $first = ConvertTo-ADAnalyzerSafeData -InputObject $source
    $second = ConvertTo-ADAnalyzerSafeData -InputObject $source
    $sourceUnchanged = $before -ceq (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $source))
    $independent = -not [object]::ReferenceEquals($source, $first) -and
    -not [object]::ReferenceEquals($child, $first.First) -and
    -not [object]::ReferenceEquals($items, $first.Items) -and
    -not [object]::ReferenceEquals($first.First, $second.First) -and
    -not [object]::ReferenceEquals($first.First, $first.Items[0])
    $idempotent = (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $first)) -ceq
    (ConvertTo-EvidenceJson (Get-EvidenceSnapshot (ConvertTo-ADAnalyzerSafeData -InputObject $first)))
    $first.First.Note = 'result'
    $mutationIsolated = $child.Note -ceq 'source' -and $second.First.Note -ceq 'source'
    $lookup = [ordered]@{
        Item = $child
        Pair = [object[]]@($child, $child)
        Null = $null
    }
    $borrowed = Get-ADAnalyzerOperationValue $lookup @('Item')
    $pair = @(Get-ADAnalyzerOperationValue $lookup @('Pair'))
    $fallback = Get-ADAnalyzerOperationValue $lookup @('Missing') $child
    [pscustomobject][ordered]@{
        SourceUnchanged = $sourceUnchanged
        DeepContainersDetached = $independent
        ResultMutationIsolated = $mutationIsolated
        Idempotent = $idempotent
        RawLookupBorrowed = [object]::ReferenceEquals($borrowed, $child)
        RawDefaultBorrowed = [object]::ReferenceEquals($fallback, $child)
        RawArrayCount = $pair.Count
        RawArrayMembersBorrowed = $pair.Count -eq 2 -and
        [object]::ReferenceEquals($pair[0],
            $child) -and
        [object]::ReferenceEquals($pair[1],
            $child)
        PresentNullSuppressesFallback = $null -eq (Get-ADAnalyzerOperationValue $lookup @('Null', 'Item') $child)
    }
}

class ADAnalyzerEvidenceFixtureEmpty {
}

# Test-only accepted-source oracle. It is installed only in an isolated scope
# or a fresh child process; the application class never calls this source.
# Source revision eba0a6c; complete original ADOperations SHA is 68269b8c...7742.
$script:EvidenceLegacyCommands = @'
function Get-ADAnalyzerOperationValue {
    param(
        [AllowNull()]$Object,
        [string[]]$Names,
        [AllowNull()]$Default = $null

    )
    if ($null -eq $Object) {
        return $Default
    }
    foreach ($name in $Names) {
        if ($Object -is [Collections.IDictionary]) {
            if (([Collections.IDictionary]$Object).Contains($name)) {
                return $Object[$name]
            }
        }
        else {
            $property = $Object.PSObject.Properties[$name]
            if ($null -ne $property) {
                return $property.Value
            }
        }
    }
    return $Default
}

function ConvertTo-ADAnalyzerSafeData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][AllowNull()]$InputObject,
        [int]$Depth = 0

    )
    process {
        if ($null -eq $InputObject) {
            return $null
        }
        if ($Depth -gt 40) {
            return '[Depth limit]'
        }
        if ($InputObject -is [pscredential] -or $InputObject -is [Security.SecureString]) {
            return [pscustomobject]@{
                SecretPresent = (Test-ADAnalyzerSecretPresence $InputObject)
            }
        }
        if ($InputObject -is [string]) {
            return Protect-ADAnalyzerSecretText $InputObject
        }
        if ($InputObject -is [datetime]) {
            return $InputObject.ToUniversalTime().ToString('o')
        }
        if ($InputObject -is [datetimeoffset]) {
            return $InputObject.ToUniversalTime().ToString('o')
        }
        if ($InputObject -is [guid]) {
            return $InputObject.ToString('D')
        }
        $inputType = $InputObject.GetType()
        if ($inputType.IsPrimitive -or
            $inputType.IsEnum -or
            $inputType.FullName -in @('System.Decimal',
                'System.TimeSpan',
                'System.Numerics.BigInteger',
                'System.Half',
                'System.Int128',
                'System.UInt128')) {
            return $InputObject
        }
        if ($InputObject -is [Collections.DictionaryEntry] -or
            ($inputType.IsGenericType -and
            $inputType.GetGenericTypeDefinition().FullName -eq 'System.Collections.Generic.KeyValuePair`2')) {
            $pair = [ordered]@{
                Key = (ConvertTo-ADAnalyzerSafeData -InputObject $InputObject.Key -Depth ($Depth + 1))
            }
            if (Test-ADAnalyzerSecretName ([string]$InputObject.Key)) {
                $pair.SecretPresent = Test-ADAnalyzerSecretPresence $InputObject.Value
            }
            else {
                $pair.Value = ConvertTo-ADAnalyzerSafeData -InputObject $InputObject.Value -Depth ($Depth + 1)
            }
            return [pscustomobject]$pair
        }
        if ($InputObject -is [Xml.XmlNode]) {
            $safeXml = ConvertTo-ADAnalyzerSecretIndicatorXml $InputObject
            return Protect-ADAnalyzerSecretText $safeXml.PSBase.OuterXml
        }
        if ($InputObject -is [Collections.IEnumerable] -and
            $InputObject -isnot [Collections.IDictionary] -and
            $InputObject -isnot [pscustomobject]) {
            $items = [Collections.ArrayList]::new()
            foreach ($item in $InputObject) {
                $null = $items.Add((ConvertTo-ADAnalyzerSafeData -InputObject $item -Depth ($Depth + 1)))
            }
            return , $items.ToArray()
        }
        $result = [ordered]@{}
        $presence = $null
        $properties = if ($InputObject -is [Collections.IDictionary]) {
            @($InputObject.Keys)
        }
        else {
            @($InputObject.PSObject.Properties.Name)
        }
        $taggedSecret = $false
        foreach ($labelName in @('Name', 'Attribute', 'AttributeName', 'Property', 'PropertyName', 'SettingName', 'ValueName')) {
            if (Test-ADAnalyzerSecretName ([string](Get-ADAnalyzerOperationValue $InputObject @($labelName)))) {
                $taggedSecret = $true
            }
        }
        $present = $false
        $hasPresence = $false
        foreach ($name in $properties) {
            if ($InputObject -is [Collections.IDictionary]) {
                $value = $InputObject[$name]
            }
            else {
                $value = $InputObject.PSObject.Properties[$name].Value
            }
            if (Test-ADAnalyzerSecretName ([string]$name)) {
                $flag = [string]$name + 'Present'
                # Observe every source value before combining prior evidence.
                $fieldPresent = Test-ADAnalyzerSecretPresence $value
                if ($null -eq $presence) {
                    $presence = [ordered]@{}
                }
                if (-not $presence.Contains($flag)) {
                    $presence[$flag] = @{
                        HasSource = $false
                        Present = $false
                        Name = $flag
                    }
                }
                $indicator = $presence[$flag]
                $indicator.HasSource = $true
                $indicator.Present = $indicator.Present -or $fieldPresent
                $indicator.Name = $flag
                $result[$flag] = $fieldPresent
            }
            elseif ($taggedSecret -and [string]$name -in @('Value', 'Observed', 'Expected', 'Data', 'Bytes', 'RawData')) {
                if ($name -ne 'Expected') {
                    $indicator = if ($name -eq 'Observed' -and $value -is [bool]) {
                        $value
                    }
                    else {
                        Test-ADAnalyzerSecretPresence $value
                    }
                    $present = $present -or $indicator
                    $hasPresence = $true
                }
            }
            elseif ($taggedSecret -and $name -eq 'SecretPresent') {
                if ($value -is [bool]) {
                    $present = $present -or $value
                    $hasPresence = $true
                }
            }
            else {
                $propertyName = [string]$name
                $result[$propertyName] = ConvertTo-ADAnalyzerSafeData -InputObject $value -Depth ($Depth + 1)
                if ($propertyName.EndsWith('Present', [StringComparison]::OrdinalIgnoreCase)) {
                    if ($null -eq $presence) {
                        $presence = [ordered]@{}
                    }
                    if (-not $presence.Contains($propertyName)) {
                        $presence[$propertyName] = @{
                            HasSource = $false
                            Present = $false
                            Name = $propertyName
                        }
                    }
                    $indicator = $presence[$propertyName]
                    if ($value -is [bool] -and $value) {
                        $indicator.Present = $true
                    }
                    $indicator.Name = $propertyName
                }
            }
        }
        if ($taggedSecret -and $null -ne $presence -and
            $presence.Contains('SecretPresent') -and $presence['SecretPresent'].HasSource) {
            # Mixed named records use the same final indicator position when
            # their raw Secret field becomes SecretPresent on the next pass.
            $result.Remove('SecretPresent')
            $presence['SecretPresent'].Name = 'SecretPresent'
        }
        if ($taggedSecret -and $hasPresence) {
            $result['SecretPresent'] = $present
            if ($null -ne $presence -and $presence.Contains('SecretPresent')) {
                $presence['SecretPresent'].Name = 'SecretPresent'
            }
        }
        if ($null -ne $presence) {
            foreach ($indicator in $presence.Values) {
                if (-not $indicator.HasSource) {
                    continue
                }
                $fieldPresent = $indicator.Present
                if ($result[$indicator.Name] -is [bool]) {
                    $fieldPresent = $fieldPresent -or $result[$indicator.Name]
                }
                $result[$indicator.Name] = [bool]$fieldPresent
            }
        }
        return [pscustomobject]$result
    }
}
'@
$script:EvidenceOracleCalls = 0

function Get-EvidenceOracleSource {
    return $script:EvidenceLegacyCommands.Replace(
        '    process {',
        '    process {' + [Environment]::NewLine + '        $script:EvidenceOracleCalls++'
    )
}

function Get-EvidenceOracleCapture([string]$Name, [string]$Preference) {
    $scenario = @(Get-EvidenceErrorScenarios | Where-Object Name -ceq $Name)[0]
    $script:EvidenceOracleCalls = 0
    $result = & {
        param(
            $Text,
            $Scenario,
            $Preference

        )
        . ([scriptblock]::Create($Text))
        Get-EvidenceCapture $Scenario $Preference
    } (Get-EvidenceOracleSource) $scenario $Preference
    if ($Name -ne 'InvalidDepth') {
        Assert-Evidence ($script:EvidenceOracleCalls -gt 0) 'The accepted test oracle did not execute.'
    }
    return $result
}

function Invoke-EvidenceObjectScenario($Scenario, $Service, [bool]$RetainBinding) {
    $value = $Scenario.Value
    $depth = if ($Scenario.Arguments.ContainsKey('Depth')) {
        [int]$Scenario.Arguments.Depth
    }
    else {
        0
    }
    switch ($Scenario.Route) {
        Omitted {
            return , $Service.Project($null)
        }
        Explicit {
            if ($RetainBinding) {
                return , $Service.ProjectBoundFrame(@{
                        Value = $value
                        Depth = $depth
                    })
            }
            if ($Scenario.Arguments.ContainsKey('Depth')) {
                return , $Service.Project($value, $depth)
            }
            return , $Service.Project($value)
        }
        Lookup {
            $names = if ($Scenario.Arguments.ContainsKey('Names')) {
                $Scenario.Arguments.Names
            }
            else {
                $null
            }
            if ($Scenario.Arguments.ContainsKey('Default')) {
                return $Service.GetValue($value, $names, $Scenario.Arguments.Default)
            }
            return $Service.GetValue($value, $names)
        }
        LookupOmitted {
            return $Service.GetValue($null, $null)
        }
        Pipeline {
            $value | ForEach-Object {
                , $Service.ProjectBoundFrame(@{
                        Value = $_
                        Depth = 0
                    })
            }
        }
        PipelineOne {
            , $value | ForEach-Object {
                , $Service.ProjectBoundFrame(@{
                        Value = $_
                        Depth = 0
                    })
            }
        }
    }
}

function Assert-EvidenceMissingCapabilities($Capabilities) {
    foreach ($capability in $Capabilities) {
        if (-not $capability.Available) {
            $type = $capability.Name -as [type]
            Assert-Evidence ($null -eq $type) 'An available numeric type was silently omitted.'
            $script:EvidenceExecuted++
        }
    }
}

function Assert-EvidenceCapabilities($Capabilities, $Service) {
    $minimumVersions = @{
        'System.Numerics.BigInteger' = 0
        'System.Half' = 5
        'System.Int128' = 7
        'System.UInt128' = 7
    }
    Assert-Evidence ($Capabilities.Count -eq 4) 'Numeric capability declarations are incomplete.'
    foreach ($capability in $Capabilities) {
        $type = $capability.Name -as [type]
        Assert-Evidence ($capability.Available -eq ($null -ne $type)) 'Numeric capability declaration differs from the engine.'
        $expected = $capability.Name -eq 'System.Numerics.BigInteger' -or
        [Environment]::Version.Major -ge $minimumVersions[$capability.Name]
        Assert-Evidence ($capability.Available -eq $expected) 'The engine lacks a required built-in numeric capability.'
        if ($capability.Available) {
            $value = $type::Parse('123', [Globalization.CultureInfo]::InvariantCulture)
            $actual = $Service.Project($value)
            Assert-Evidence (
                (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $actual)) -ceq
                (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $value))
            ) 'A native numeric type was changed.'
        }
        $script:EvidenceExecuted++
    }
}

function Invoke-EvidenceChild([string]$Text) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    $executable = (Get-Process -Id $PID).Path
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $executable -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    [pscustomobject]@{
        Exit = $exitCode
        Lines = @($output | ForEach-Object { [string]$_ })
    }
}

function Invoke-EvidenceUncaught([string]$ScenarioName, [string]$Action, [bool]$Oracle) {
    $fixturePath = $PSCommandPath.Replace("'", "''")
    $repository = $repositoryRoot.Replace("'", "''")
    $header = @'
$ErrorActionPreference = 'Continue'
$fixtureText = [IO.File]::ReadAllText('FIXTURE')
$boundary = $fixtureText.LastIndexOf([Environment]::NewLine + 'try {')
if ($boundary -lt 0) {
    $boundary = $fixtureText.LastIndexOf([char]10 + 'try {')
}
$helperText = $fixtureText.Substring(0, $boundary)
$helperText = $helperText.Replace('$repositoryRoot = Split-Path -Parent $PSScriptRoot', '$repositoryRoot = ''REPOSITORY''')
$helperText = $helperText.Replace('$baselinePath = Join-Path $PSScriptRoot ''EvidenceProjectorBaseline.json''',
    '$baselinePath = ''REPOSITORY/tests/EvidenceProjectorBaseline.json''')
. ([scriptblock]::Create($helperText))
'@
    $header = $header.Replace('FIXTURE', $fixturePath).Replace('REPOSITORY', $repository)
    if ($Oracle) {
        $header += [Environment]::NewLine + '. ([scriptblock]::Create((Get-EvidenceOracleSource)))'
    }
    $body = @'
$ErrorActionPreference = 'Continue'
Initialize-EvidenceNativeTypes
$script:EvidenceTrace.Clear()
$Error.Clear()
$commandErrors = @('error-seed')
$commandOutput = @('output-seed')
$parameters = @{
    ErrorVariable = '+commandErrors'
    OutVariable = '+commandOutput'
}
ACTION
$first = [pscustomobject]@{
    Before = 1
}
$tail = [pscustomobject]@{}
$tail | Add-Member ScriptProperty Tail { $script:EvidenceTrace.Add('Tail')
    3 }
$document = New-EvidenceXml '<Root/>'
$resource = $null
switch ('SCENARIO') {
    Success {
        $inputRows = [object[]]@(1, 2)
    }
    XmlLate {
        $inputRows = [object[]]@($first, $document.CreateTextNode('fixture'), $tail)
    }
    DtdLate {
        $inputRows = [object[]]@($first, '<!DOCTYPE Root><Root/>', $tail)
    }
    Getter {
        $inputRows = [pscustomobject]@{
            Name = 'ordinary'
        }
        $inputRows | Add-Member ScriptProperty Item { $script:EvidenceTrace.Add('Getter')
            throw 'Fixture uncaught getter.' }
    }
    EnumerableCreate {
        $resource = [ADAnalyzer.EvidenceFixture081.EnumerableProbe]::new('Create')
        $inputRows = [object[]]@($first, [pscustomobject]@{
                Items = $resource
            }, $tail)
    }
    EnumerableMove {
        $resource = [ADAnalyzer.EvidenceFixture081.EnumerableProbe]::new('Move')
        $inputRows = [object[]]@($first, [pscustomobject]@{
                Items = $resource
            }, $tail)
    }
    EnumerableCurrent {
        $resource = [ADAnalyzer.EvidenceFixture081.EnumerableProbe]::new('Current')
        $inputRows = [object[]]@($first, [pscustomobject]@{
                Items = $resource
            }, $tail)
    }
    NativeCount {
        $resource = [ADAnalyzer.EvidenceFixture081.CountProbe]::new($true)
        $inputRows = [object[]]@($first, [ordered]@{
                PasswordPresent = $true
                Password = $resource
            }, $tail)
    }
}
Write-Output 'EVIDENCE_BEGIN'
$observed = @($inputRows | ConvertTo-ADAnalyzerSafeData @parameters)
Write-Output 'EVIDENCE_AFTER'
$observedResource = @(Get-EvidenceResource $resource)
$summary = [pscustomobject][ordered]@{
    Rows = @(foreach ($row in $observed) {
            Get-EvidenceSnapshot $row
        })
    OutVariable = @(foreach ($row in $commandOutput) {
            Get-EvidenceSnapshot $row
        })
    ErrorVariable = @(foreach ($record in $commandErrors) {
            if ($record -is [Management.Automation.ErrorRecord]) {
                $value = Get-EvidenceError $record
                $value.PSObject.Properties.Remove('OriginalStack')
                $value
            }
            else {
                [string]$record
            }
        })
    GlobalErrors = @(foreach ($record in $Error) {
            $value = Get-EvidenceError $record
            $value.PSObject.Properties.Remove('OriginalStack')
            $value
        })
    Trace = @($script:EvidenceTrace)
    Resource = $observedResource
}
Write-Output ('EVIDENCE_SUMMARY ' + (ConvertTo-EvidenceJson $summary))
'@
    $actionText = if ($Action -eq 'Ambient') {
        ''
    }
    else {
        '$parameters.ErrorAction = ''' + $Action + ''''
    }
    $body = $body.Replace('ACTION', $actionText).Replace('SCENARIO', $ScenarioName)
    $result = Invoke-EvidenceChild ($header + [Environment]::NewLine + $body)
    $summaryLine = @($result.Lines | Where-Object { $_ -like 'EVIDENCE_SUMMARY *' })
    $summary = if ($summaryLine.Count) {
        $summaryLine[-1].Substring('EVIDENCE_SUMMARY '.Length) | ConvertFrom-Json
    }
    else {
        $null
    }
    [pscustomobject][ordered]@{
        Exit = $result.Exit
        Began = @($result.Lines | Where-Object { $_ -eq 'EVIDENCE_BEGIN' }).Count -eq 1
        Continued = @($result.Lines | Where-Object { $_ -eq 'EVIDENCE_AFTER' }).Count -eq 1
        Summary = $summary
        HasXmlDiagnostic = ($result.Lines -join ' ').Contains('XML projection supports Document and Element nodes only.')
        HasDtdDiagnostic = ($result.Lines -join ' ').Contains('DTD declarations are not supported')
    }
}

function Assert-EvidenceFailure([scriptblock]$Body, [string]$Cause) {
    $caught = $null
    try {
        $null = & $Body
    }
    catch {
        $caught = $_
    }
    Assert-Evidence ($null -ne $caught) 'A direct method accepted an invalid operation.'
    Assert-Evidence ($caught.Exception.GetBaseException().GetType().FullName -ceq $Cause) 'A direct method lost its meaningful cause.'
}

try {
    Initialize-EvidenceNativeTypes
    $sourceBefore = Get-EvidenceHash $sourcePath
    $capabilities = @(Get-EvidenceCapabilities)
    $scenarios = @(Get-EvidenceScenarios)
    Assert-Evidence (@($scenarios.Name | Sort-Object -Unique).Count -eq $scenarios.Count) 'Scenario identities are not unique.'
    if ($Case -eq 'RecordBaseline') {
        Assert-Evidence (-not ('ADAnalyzerEvidenceProjector' -as [type])) 'Capture accepted original functions before the class migration.'
        Assert-Evidence ($sourceBefore -ceq $acceptedSource) 'Accepted source identity changed before capture.'
        Assert-Evidence (-not [IO.File]::Exists($baselinePath)) 'The immutable evidence baseline already exists.'
        $definitions = @('ConvertTo-ADAnalyzerSafeData', 'Get-ADAnalyzerOperationValue' | ForEach-Object { Get-EvidenceCommandMetadata $_ })
        $results = @(
            foreach ($scenario in $scenarios) {
                $capture = Get-EvidenceCapture $scenario
                if ($scenario.Group -in @('Secrets', 'Pairs', 'Xml')) {
                    $text = ConvertTo-EvidenceJson $capture.Rows
                    Assert-Evidence ($text -is [string] -and
                        -not $text.Contains($script:EvidenceMarker)) 'Known secret payload survived accepted projection.'
                }
                $capture
            }
        )
        $errors = @(
            foreach ($preference in @('Continue', 'Stop')) {
                foreach ($scenario in @(Get-EvidenceErrorScenarios)) {
                    Get-EvidenceCapture $scenario $preference
                }
            }
        )
        $references = Get-EvidenceReferences
        Assert-Evidence ($references.SourceUnchanged -and
            $references.DeepContainersDetached -and
            $references.ResultMutationIsolated -and
            $references.Idempotent -and
            $references.RawLookupBorrowed -and
            $references.RawDefaultBorrowed -and
            $references.RawArrayMembersBorrowed -and
            $references.PresentNullSuppressesFallback) 'Accepted reference contracts were not established.'
        Assert-Evidence ($sourceBefore -ceq (Get-EvidenceHash $sourcePath)) 'Source changed during capture.'
        $baseline = [pscustomobject][ordered]@{
            SourceRevision = 'eba0a6c31417122067c7010b92234b46a63d70ba'
            SourceSha256 = $sourceBefore
            Runtime = [string]$PSVersionTable.PSVersion
            Capabilities = $capabilities
            NativeJson = Get-EvidenceNativeJsonContract
            Definitions = $definitions
            Results = $results
            Errors = $errors
            References = $references
            GroupCounts = @($scenarios | Group-Object Group | ForEach-Object { [pscustomobject]@{
                        Name = $_.Name
                        Count = $_.Count
                    } })
        }
        $baselineJson = ConvertTo-Json -InputObject $baseline -Depth 90
        Assert-Evidence ($baselineJson -is [string] -and
            -not [string]::IsNullOrWhiteSpace($baselineJson)) 'The structured baseline produced no JSON.'
        [IO.File]::WriteAllText($baselinePath, $baselineJson, [Text.UTF8Encoding]::new($true))
        Write-Host ('FROZEN evidence baseline results=' + $results.Count + ' errors=' + $errors.Count + ' source=' + $sourceBefore + ' baseline=' + (Get-EvidenceHash $baselinePath))
        return
    }
    $baseline = Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Evidence ($baseline.SourceSha256 -ceq $acceptedSource) 'Frozen source identity changed.'
    $service = [ADAnalyzerEvidenceProjector]::new()
    switch ($Case) {
        Characterization {
            foreach ($scenario in $scenarios) {
                $expected = @($baseline.Results | Where-Object Name -ceq $scenario.Name)
                Assert-Evidence ($expected.Count -eq 1) 'Frozen scenario is missing.'
                $actual = Get-EvidenceCapture $scenario
                if ((ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -cne (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected[0]))) {
                    Write-Host ('Expected frozen: ' + (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected[0])))
                    Write-Host ('Actual frozen: ' + (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)))
                }
                Assert-Evidence ((ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -ceq (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected[0]))) ('Frozen output changed: ' + $scenario.Name)
                $script:EvidenceExecuted++
            }
            Assert-EvidenceMissingCapabilities $capabilities
        }
        Metadata {
            foreach ($definition in $baseline.Definitions) {
                $attribute = if ($definition.Advanced) {
                    '[CmdletBinding()]' + [Environment]::NewLine
                }
                else {
                    ''
                }
                $text = 'function ' + $definition.Name + ' {' + [Environment]::NewLine + $attribute + $definition.Parameters + [Environment]::NewLine + '}'
                $expected = & {
                    param(
                        $Text,
                        $Name

                    )
                    . ([scriptblock]::Create($Text))
                    Get-EvidenceCommandMetadata $Name
                } $text $definition.Name
                $actual = Get-EvidenceCommandMetadata $definition.Name
                Assert-Evidence ($actual.Parameters -ceq $definition.Parameters) 'Original command parameter text changed.'
                Assert-Evidence ((ConvertTo-EvidenceJson $actual) -ceq (ConvertTo-EvidenceJson $expected)) 'Command metadata differs from its same-engine original signature.'
                $script:EvidenceExecuted++
            }
        }
        References {
            Assert-Evidence ((ConvertTo-EvidenceJson (Get-EvidenceReferences)) -ceq (ConvertTo-EvidenceJson $baseline.References)) 'Reference contracts changed.'
            $script:EvidenceExecuted++
            $child = [pscustomobject]@{
                Note = 'borrowed'
            }
            $source = [ordered]@{
                Child = $child
                Items = [object[]]@($child)
            }
            $projected = $service.Project($source)
            $borrowed = $service.GetValue($source, @('Child'), $null)
            Assert-Evidence (-not [object]::ReferenceEquals($child,
                    $projected.Child) -and
                -not [object]::ReferenceEquals($source.Items,
                    $projected.Items) -and
                [object]::ReferenceEquals($borrowed,
                    $child)) 'Direct deep projection and borrowed lookup contracts differ.'
            $script:EvidenceExecuted++
            # Nullable object methods must return an actual value on 5.1.
            # The command still preserves native no-output and array cardinality.
            $empty = [object[]]@()
            $one = [object[]]@('one')
            $many = [object[]]@(1, 2)
            $nested = [object[]]::new(1)
            $nested[0] = $many
            $noOutput = [pscustomobject]@{}
            $noOutput | Add-Member ScriptProperty Item {}
            $returnCases = @(
                @{
                    Name = 'NullObject'
                    Value = $null
                    Arguments = @{
                        Names = @('Item')
                    }
                    Expected = $null
                },
                @{
                    Name = 'Missing'
                    Value = [ordered]@{
                        Other = 1
                    }
                    Arguments = @{
                        Names = @('Item')
                    }
                    Expected = $null
                },
                @{
                    Name = 'PresentNull'
                    Value = [ordered]@{
                        Item = $null
                    }
                    Arguments = @{
                        Names = @('Item')
                        Default = $one
                    }
                    Expected = $null
                },
                @{
                    Name = 'NoOutputGetter'
                    Value = $noOutput
                    Arguments = @{
                        Names = @('Item')
                        Default = $one
                    }
                    Expected = $null
                },
                @{
                    Name = 'EmptyArray'
                    Value = [ordered]@{
                        Item = $empty
                    }
                    Arguments = @{
                        Names = @('Item')
                    }
                    Expected = $empty
                },
                @{
                    Name = 'EmptyDefault'
                    Value = [ordered]@{}
                    Arguments = @{
                        Names = @('Item')
                        Default = $empty
                    }
                    Expected = $empty
                },
                @{
                    Name = 'Singleton'
                    Value = [ordered]@{
                        Item = $one
                    }
                    Arguments = @{
                        Names = @('Item')
                    }
                    Expected = $one
                },
                @{
                    Name = 'Many'
                    Value = [ordered]@{
                        Item = $many
                    }
                    Arguments = @{
                        Names = @('Item')
                    }
                    Expected = $many
                },
                @{
                    Name = 'Nested'
                    Value = [ordered]@{
                        Item = $nested
                    }
                    Arguments = @{
                        Names = @('Item')
                    }
                    Expected = $nested
                }
            )
            foreach ($item in $returnCases) {
                $scenario = New-EvidenceScenario $item.Name Lookup Lookup $item.Value $item.Arguments
                $expected = & {
                    param(
                        $Text,
                        $Scenario

                    )
                    . ([scriptblock]::Create($Text))
                    Get-EvidenceCapture $Scenario
                } (Get-EvidenceOracleSource) $scenario
                $actual = Get-EvidenceCapture $scenario
                Assert-Evidence (
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -ceq
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected))
                ) ('Nullable lookup command contract changed: ' + $item.Name)
                $fallback = $item.Arguments.Default
                $value = $service.GetValue($item.Value, $item.Arguments.Names, $fallback)
                Assert-Evidence (
                    (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $value)) -ceq
                    (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $item.Expected))
                ) ('Nullable direct lookup changed: ' + $item.Name)
                if ($item.Expected -is [array]) {
                    Assert-Evidence ([object]::ReferenceEquals($item.Expected, $value)) 'Raw lookup copied a borrowed array.'
                }
                if (-not $item.Arguments.ContainsKey('Default')) {
                    $implicit = $service.GetValue($item.Value, $item.Arguments.Names)
                    Assert-Evidence (
                        (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $implicit)) -ceq
                        (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $item.Expected))
                    ) 'Default lookup overload changed a nullable result.'
                }
                $script:EvidenceExecuted++
            }
            foreach ($sample in @(
                    @{
                        Value = $null
                    },
                    @{
                        Value = $empty
                    },
                    @{
                        Value = $one
                    },
                    @{
                        Value = $many
                    },
                    @{
                        Value = $nested
                    }
                )) {
                $actual = $service.Project($sample.Value)
                $explicit = $service.Project($sample.Value, 0)
                $expected = ConvertTo-EvidenceJson (Get-EvidenceSnapshot $sample.Value)
                Assert-Evidence (
                    (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $actual)) -ceq $expected -and
                    (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $explicit)) -ceq $expected
                ) 'Projection changed null/empty/singleton/multiple/nested array shape.'
                if ($null -eq $sample.Value) {
                    Assert-Evidence ($null -eq $service.ProjectPowerShellObject($null) -and
                        $null -eq $service.ProjectPowerShellObject($null, 0)) 'The wrapper-preserving overload lost null.'
                }
                $script:EvidenceExecuted++
            }
        }
        Errors {
            foreach ($preference in @('Continue', 'Stop')) {
                foreach ($scenario in @(Get-EvidenceErrorScenarios)) {
                    $expected = Get-EvidenceOracleCapture $scenario.Name $preference
                    $actual = Get-EvidenceCapture $scenario $preference
                    if ((ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -cne (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected))) {
                        Write-Host ('Expected error: ' + (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected)))
                        Write-Host ('Actual error: ' + (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)))
                    }
                    Assert-Evidence (
                        (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -ceq
                        (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected))
                    ) ('Same-engine error/stream/getter contract changed: ' + $scenario.Name)
                    $script:EvidenceExecuted++
                }
            }
        }
        Capabilities {
            Assert-EvidenceCapabilities $capabilities $service
        }
        Construction {
            $type = $service.GetType()
            Assert-Evidence ($type.GetConstructors().Count -eq 1 -and
                $type.GetConstructors()[0].GetParameters().Count -eq 0) 'Default constructor is not inert and parameterless.'
            $script:EvidenceExecuted++
            $tokens = $null
            $parseErrors = $null
            $sourceAst = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
            $class = $sourceAst.Find({ param($node) $node -is [Management.Automation.Language.TypeDefinitionAst] -and
                    $node.Name -ceq 'ADAnalyzerEvidenceProjector' },
                $true)
            Assert-Evidence ($parseErrors.Count -eq 0 -and
                @($class.Members | Where-Object { $_ -is [Management.Automation.Language.PropertyMemberAst] }).Count -eq 0 -and
                @($service.PSObject.Properties).Count -eq 0) 'Projector gained application fields or properties.'
            $script:EvidenceExecuted++
            foreach ($name in @('Get-Content', 'Get-Item', 'Import-Module', 'Read-Host', 'Get-Credential', 'Get-ADObject')) {
                Set-Item -Path ('Function:' + $name) -Value { throw 'Unexpected constructor effect.' }
            }
            $location = (Get-Location).Path
            $empty = [ADAnalyzerEvidenceProjector]::new()
            Assert-Evidence ((Get-Location).Path -ceq $location -and
                -not [object]::ReferenceEquals($empty,
                    $service)) 'Construction changed caller state or shared an instance.'
            $script:EvidenceExecuted++
            Assert-Evidence ($null -eq $service.Project($null) -and
                $null -eq $service.Project($null,
                    41) -and
                $service.Project('ordinary') -ceq 'ordinary') 'Default/explicit/null method behavior changed.'
            $script:EvidenceExecuted++
        }
        Direct {
            foreach ($scenario in $scenarios) {
                if ($scenario.Route -in @('Pipeline', 'PipelineOne') -or $scenario.Name -eq 'WrappedExplicit') {
                    continue
                }
                $expected = @($baseline.Results | Where-Object Name -ceq $scenario.Name)[0]
                $actual = Get-EvidenceCapture $scenario Stop $service
                Assert-Evidence (
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -ceq
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected))
                ) ('Direct method changed business output: ' + $scenario.Name)
                $script:EvidenceExecuted++
            }
            Assert-EvidenceMissingCapabilities $capabilities
        }
        Binding {
            foreach ($scenario in @($scenarios | Where-Object Group -eq Binding)) {
                $expected = @($baseline.Results | Where-Object Name -ceq $scenario.Name)[0]
                $actual = Get-EvidenceCapture $scenario Stop $service $true
                Assert-Evidence (
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -ceq
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected))
                ) ('Command frame lost binding facts: ' + $scenario.Name)
                $script:EvidenceExecuted++
            }
            $wrapped = [Management.Automation.PSObject]::AsPSObject([object[]]@(1, 2))
            $wrapped.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new('Note', 'metadata'))
            $natural = $service.Project($wrapped)
            Assert-Evidence ($natural -is [array] -and
                $natural.Count -eq 2 -and
                $natural[0] -eq 1 -and
                $natural[1] -eq 2) 'Natural CLR object binding changed.'
            $script:EvidenceExecuted++
            $powerShell = $service.ProjectPowerShellObject($wrapped)
            $explicitDepth = $service.ProjectPowerShellObject($wrapped, 0)
            Assert-Evidence ($powerShell -is [pscustomobject] -and
                $powerShell.Note -ceq 'metadata' -and
                $powerShell.SyncRoot.Count -eq 2 -and
                (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $powerShell)) -ceq (ConvertTo-EvidenceJson (Get-EvidenceSnapshot $explicitDepth))) 'Explicit PowerShell-object route lost its wrapper metadata.'
            $script:EvidenceExecuted++
        }
        Ownership {
            $legacyNames = @(
                'ConvertTo-ADAnalyzerSafeData', 'Get-ADAnalyzerOperationValue',
                'Protect-ADAnalyzerSecretText', 'Get-ADAnalyzerOperationSecretNames',
                'Get-ADAnalyzerSecretNames', 'Test-ADAnalyzerSecretName',
                'Assert-ADAnalyzerValueBaseline', 'Test-ADAnalyzerSecretPresence',
                'ConvertTo-ADAnalyzerSecretRecord', 'Get-ADAnalyzerXmlSecretName',
                'ConvertTo-ADAnalyzerSecretIndicatorXml', 'ConvertTo-ADAnalyzerSecretIndicatorText'
            )
            foreach ($name in $legacyNames) {
                Set-Item -Path ('Function:' + $name) -Value { throw 'Legacy processor was called.' }
            }
            foreach ($scenario in $scenarios) {
                $expected = @($baseline.Results | Where-Object Name -ceq $scenario.Name)[0]
                $actual = Get-EvidenceCapture $scenario Stop $service $true
                Assert-Evidence (
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $actual)) -ceq
                    (ConvertTo-EvidenceJson (Get-EvidenceComparable $expected))
                ) ('Class processing depends on a legacy command: ' + $scenario.Name)
                $script:EvidenceExecuted++
            }
            Assert-EvidenceMissingCapabilities $capabilities
            $tokens = $null
            $parseErrors = $null
            $sourceAst = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
            $class = $sourceAst.Find({ param($node) $node -is [Management.Automation.Language.TypeDefinitionAst] -and
                    $node.Name -ceq 'ADAnalyzerEvidenceProjector' },
                $true)
            $calls = @($class.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and
                        $node.GetCommandName() -in $legacyNames },
                    $true))
            $loops = @($class.FindAll({ param($node) $node -is [Management.Automation.Language.ForEachStatementAst] }, $true))
            Assert-Evidence ($calls.Count -eq 0 -and $loops.Count -ge 3) 'The class is a facade around function-owned processing.'
            $script:EvidenceExecuted++
        }
        Isolation {
            $child = [pscustomobject]@{
                Note = 'source'
            }
            $source = [ordered]@{
                Child = $child
                Items = [object[]]@($child)
            }
            $first = $service.Project($source)
            $second = $service.Project($source)
            $first.Child.Note = 'result'
            Assert-Evidence ($child.Note -ceq 'source' -and
                $second.Child.Note -ceq 'source' -and
                -not [object]::ReferenceEquals($first.Items[0],
                    $child)) 'Projected graphs retain mutable aliases.'
            $script:EvidenceExecuted++
            $borrowed = $service.GetValue($source, @('Child'))
            $borrowed.Note = 'shared'
            Assert-Evidence ([object]::ReferenceEquals($borrowed,
                    $child) -and
                $child.Note -ceq 'shared') 'Raw lookup lost its intentionally borrowed contract.'
            $script:EvidenceExecuted++
            $other = [ADAnalyzerEvidenceProjector]::new()
            $null = $service.Project([ordered]@{
                    Password = $script:EvidenceMarker
                })
            Assert-Evidence ($other.Project('ordinary') -ceq 'ordinary' -and
                @($other.PSObject.Properties).Count -eq 0 -and
                @($service.PSObject.Properties).Count -eq 0) 'Independent instances retained processing state.'
            $script:EvidenceExecuted++
            $document = New-EvidenceXml '<Root/>'
            Assert-EvidenceFailure { $service.Project($document.CreateTextNode('fixture')) } 'System.ArgumentException'
            Assert-Evidence ($service.Project('ordinary') -ceq 'ordinary' -and
                $service.Project(1,
                    -1) -eq 1) 'Failure changed a later call or bounded negative-depth behavior.'
            Assert-EvidenceFailure { $service.Project('ordinary', 'invalid-depth') } 'System.FormatException'
            $script:EvidenceExecuted++
        }
        Serialization {
            $control = [ADAnalyzerEvidenceFixtureEmpty]::new()
            $controlJson = ConvertTo-Json -InputObject $control -Depth 30 -Compress
            $beforeJson = ConvertTo-Json -InputObject $service -Depth 30 -Compress
            $beforeXml = [Management.Automation.PSSerializer]::Serialize($service)
            Assert-Evidence ($beforeJson -ceq $controlJson -and
                -not [string]::IsNullOrWhiteSpace($beforeXml)) 'Native empty service serialization changed.'
            $script:EvidenceExecuted++
            $secure = New-EvidenceSecure $true
            $workloads = @(
                [ordered]@{
                    Password = $script:EvidenceMarker
                },
                [pscredential]::new($script:EvidenceMarker, $secure),
                $secure,
                (New-EvidenceXml ('<Root Password="' + $script:EvidenceMarker + '"/>')),
                ('password="' + $script:EvidenceMarker + '"'),
                $null
            )
            foreach ($value in $workloads) {
                $instance = [ADAnalyzerEvidenceProjector]::new()
                $jsonBefore = ConvertTo-Json -InputObject $instance -Depth 30 -Compress
                $xmlBefore = [Management.Automation.PSSerializer]::Serialize($instance)
                $result = $instance.Project($value)
                $jsonAfter = ConvertTo-Json -InputObject $instance -Depth 30 -Compress
                $xmlAfter = [Management.Automation.PSSerializer]::Serialize($instance)
                Assert-Evidence ($jsonBefore -ceq $controlJson -and
                    $jsonAfter -ceq $jsonBefore -and
                    $xmlAfter -ceq $xmlBefore -and
                    -not $xmlAfter.Contains($script:EvidenceMarker) -and
                    @($instance.PSObject.Properties).Count -eq 0) 'Native service serialization retained input or results.'
                if ($null -ne $jsonAfter) {
                    Assert-Evidence ($jsonAfter -is [string] -and
                        -not $jsonAfter.Contains($script:EvidenceMarker)) 'Service JSON retained payload.'
                }
                $resultJson = ConvertTo-Json -InputObject $result -Depth 60 -Compress
                $nullJson = ConvertTo-Json -InputObject $null -Depth 60 -Compress
                if ($null -eq $value) {
                    Assert-Evidence ($null -eq $result -and
                        $resultJson -ceq $nullJson) 'Null projection lost its native serialization contract.'
                }
                else {
                    Assert-Evidence ($null -ne $result -and
                        $resultJson -is [string] -and
                        -not [string]::IsNullOrWhiteSpace($resultJson)) 'A non-null result was not serialized.'
                }
                if ($null -ne $resultJson) {
                    Assert-Evidence (-not $resultJson.Contains($script:EvidenceMarker)) 'Result JSON retained payload.'
                }
                $resultXml = [Management.Automation.PSSerializer]::Serialize($result)
                Assert-Evidence (-not [string]::IsNullOrWhiteSpace($resultXml) -and
                    -not $resultXml.Contains($script:EvidenceMarker)) 'Result CLIXML retained payload.'
                $script:EvidenceExecuted++
            }
            Assert-Evidence ($secure.PSBase.Length -eq 1) 'Projection changed caller-owned secure data.'
        }
        Uncaught {
            foreach ($scenarioName in @('Success',
                    'XmlLate',
                    'DtdLate',
                    'Getter',
                    'EnumerableCreate',
                    'EnumerableMove',
                    'EnumerableCurrent',
                    'NativeCount')) {
                foreach ($action in @('Ambient', 'Continue', 'Stop')) {
                    $expected = Invoke-EvidenceUncaught $scenarioName $action $true
                    $actual = Invoke-EvidenceUncaught $scenarioName $action $false
                    Assert-Evidence ($expected.Began -and $actual.Began) 'A fresh uncaught child did not start.'
                    if ((ConvertTo-EvidenceJson $actual) -cne (ConvertTo-EvidenceJson $expected)) {
                        Write-Host ('Expected uncaught: ' + (ConvertTo-EvidenceJson $expected))
                        Write-Host ('Actual uncaught: ' + (ConvertTo-EvidenceJson $actual))
                    }
                    Assert-Evidence ((ConvertTo-EvidenceJson $actual) -ceq (ConvertTo-EvidenceJson $expected)) ('Uncaught/common-parameter behavior differs from accepted source: ' + $scenarioName + '/' + $action)
                    $script:EvidenceExecuted++
                }
            }
        }
        Loading {
            $loader = (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1').Replace("'", "''")
            $standalone = (Join-Path $repositoryRoot 'bin/ADOperations.ps1').Replace("'", "''")
            $checks = @'
$service = [ADAnalyzerEvidenceProjector]::new()
$result = $service.Project([ordered]@{
        Password = 'fixture'
        PasswordPresent = $false
    })
if ($result.PasswordPresent -isnot [bool] -or -not $result.PasswordPresent -or $null -ne $result.PSObject.Properties['Password']) {
    throw 'Fresh direct projection failed.'
}
$wrapped = [Management.Automation.PSObject]::AsPSObject([object[]]@(1, 2))
$wrapped.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new('Note', 'metadata'))
if ($service.Project($wrapped).Count -ne 2 -or $service.ProjectPowerShellObject($wrapped).Note -cne 'metadata') {
    throw 'Fresh public binding routes failed.'
}
$raw = [pscustomobject]@{
    Item = 'borrowed'
}
if ($service.GetValue($raw, @('Item')) -cne 'borrowed') {
    throw 'Fresh lookup method failed.'
}
if (-not (ConvertTo-ADAnalyzerSafeData ([ordered]@{
                Password = 'fixture'
                PasswordPresent = $false
            })).PasswordPresent) {
    throw 'Fresh projection command failed.'
}
'@
            foreach ($text in @(
                    (". '" + $loader + "'" + [Environment]::NewLine),
                    (". '" + $standalone + "'" + [Environment]::NewLine),
                    (". '" + $loader + "'" + [Environment]::NewLine + ". '" + $loader + "'" + [Environment]::NewLine)
                )) {
                $result = Invoke-EvidenceChild ($text + $checks + [Environment]::NewLine + "'PASS EVIDENCE FRESH'")
                Assert-Evidence ($result.Exit -eq 0 -and
                    ($result.Lines -join ' ').Contains('PASS EVIDENCE FRESH')) 'Fresh literal constructor loading failed.'
                $script:EvidenceExecuted++
            }
            $manifest = (Join-Path $repositoryRoot 'ADEnvironment.psd1').Replace("'", "''")
            if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                $import = "Import-Module '" + $manifest + "' -Force -ErrorAction Stop -WarningAction SilentlyContinue" + [Environment]::NewLine
            }
            else {
                $assembly = (Join-Path $repositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll').Replace("'", "''")
                $module = (Join-Path $repositoryRoot 'bin/ADEnvironment.psm1').Replace("'", "''")
                $import = "[void][Reflection.Assembly]::LoadFrom('" + $assembly + "')" + [Environment]::NewLine
                $import += "Import-Module '" + $module + "' -Force -ErrorAction Stop -WarningAction SilentlyContinue" + [Environment]::NewLine
            }
            $moduleChecks = @'
$module = Get-Module ADEnvironment
& $module {
    $script:EvidenceMemory = [Collections.Generic.List[string]]::new()

    function script:Write-ADAnalyzerOperationFile {
        param(
            $Path,
            $Content

        )
        $script:EvidenceMemory.Add($Content)
        $Path
    }
    $assessment = [pscustomobject]@{
        SchemaVersion = 1
        Findings = @([pscustomobject]@{
                RuleId = 'fixture'
                Evidence = [ordered]@{
                    Password = 'FRESH_FIXTURE_PAYLOAD'
                    PasswordPresent = $false
                }
            })
    }
    $rows = @(Export-ADAnalyzerAssessment -Assessment $assessment -Path 'memory-evidence' -Format All -Confirm:$false)
    if ($rows.Count -ne 3 -or
        $script:EvidenceMemory.Count -ne 3 -or
        @($script:EvidenceMemory | Where-Object { $_ -like '*FRESH_FIXTURE_PAYLOAD*' }).Count) {
        throw 'Public module consumer did not use safe projection.'
    }
    $json = $script:EvidenceMemory[0] | ConvertFrom-Json
    if (-not $json.Findings[0].Evidence.PasswordPresent) {
        throw 'Public module consumer lost presence.'
    }
}
'@
            foreach ($moduleFirst in @($false, $true)) {
                $dotLoad = ". '" + $loader + "'" + [Environment]::NewLine
                $prefix = if ($moduleFirst) {
                    $import + $dotLoad
                }
                else {
                    $dotLoad + $import
                }
                $result = Invoke-EvidenceChild ($prefix + $checks + $moduleChecks + [Environment]::NewLine + "'PASS EVIDENCE MODULE'")
                Assert-Evidence ($result.Exit -eq 0 -and
                    ($result.Lines -join ' ').Contains('PASS EVIDENCE MODULE')) 'Manifest/dot-source order or public module consumer failed.'
                $script:EvidenceExecuted++
            }
        }
    }

    $expectedCounts = @{
        Characterization = 122
        Metadata = 2
        References = 16
        Errors = 32
        Capabilities = 4
        Construction = 4
        Direct = 116
        Binding = 10
        Ownership = 123
        Isolation = 4
        Serialization = 7
        Loading = 5
        Uncaught = 24
    }
    Assert-Evidence ($script:EvidenceExecuted -eq $expectedCounts[$Case]) 'Not every declared evidence scenario executed.'
    Write-Host ('PASS evidence characterization ' + $Case + ' ' + $script:EvidenceExecuted)
}
catch {
    Write-Host ('FAIL evidence characterization ' + $Case + ' after ' + $script:EvidenceExecuted)
    Write-Host $_.ScriptStackTrace
    throw
}
finally {
    foreach ($value in $script:EvidenceOwned) {
        $value.Dispose()
    }
}
