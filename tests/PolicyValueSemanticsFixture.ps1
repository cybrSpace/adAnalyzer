[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Values', 'Faults', 'Direct', 'Uncaught')]
    [string]$Case = 'Values',
    [string]$Fault,
    [ValidateSet('Continue', 'Stop')]
    [string]$Preference = 'Continue',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/ADAnalyzer.ps1')

# Verbatim accepted functions from 2a2f659. Preserve this immutable text.
$script:OriginalPolicyValues = @'
function Test-ADAnalyzerPolicyValueValid {
    param($Record)
    $marker = Get-ADAnalyzerPolicyValue $Record ValueValid $null
    return $null -eq $marker -or ($marker -is [bool] -and $marker)
}

function ConvertTo-ADAnalyzerPolicyNumber {
    param($Value)
    if ($Value -is [bool] -or $Value -is [array] -or $null -eq $Value) {
        return [pscustomobject]@{
            Valid = $false
            Value = $null
        }
    }
    $number = 0L
    $valid = [long]::TryParse([string]$Value,
        [Globalization.NumberStyles]::Integer,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$number)
    [pscustomobject]@{
        Valid = $valid
        Value = $number
    }
}

function ConvertTo-ADAnalyzerPolicyBoolean {
    param($Value)
    if ($Value -is [bool]) {
        return [pscustomobject]@{
            Valid = $true
            Value = $Value
        }
    }
    if ($null -ne $Value -and $Value -isnot [array]) {
        switch -Regex ([string]$Value) {
            '^(?i:true|1)$' {
                return [pscustomobject]@{
                    Valid = $true
                    Value = $true
                }
            }
            '^(?i:false|0)$' {
                return [pscustomobject]@{
                    Valid = $true
                    Value = $false
                }
            }
        }
    }
    [pscustomobject]@{
        Valid = $false
        Value = $null
    }
}

function Test-ADAnalyzerPolicySid {
    param($Value)
    # MS-DTYP 2.4.2.1: decimal authority below 2^32, otherwise 12 hex digits.
    if ($Value -isnot [string] -or $Value -notmatch '^S-1-(?:0|[1-9][0-9]{0,9}|0x[0-9a-f]{12})(?:-(?:0|[1-9][0-9]{0,9})){1,15}$') {
        return $false
    }
    $parts = $Value.Split('-')
    [uint64]$authority = 0
    if ($parts[2].StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
        if (-not [uint64]::TryParse($parts[2].Substring(2),
                [Globalization.NumberStyles]::AllowHexSpecifier,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$authority) -or
            $authority -lt 4294967296) {
            return $false
        }
    }
    elseif (-not [uint64]::TryParse($parts[2], [ref]$authority) -or $authority -gt 4294967295) {
        return $false
    }
    for ($index = 3; $index -lt $parts.Count; $index++) {
        [uint32]$part = 0
        if (-not [uint32]::TryParse($parts[$index], [ref]$part)) {
            return $false
        }
    }
    return $true
}

function Test-ADAnalyzerPolicySidList {
    param($Value)
    if ($null -eq $Value -or ($Value -isnot [string] -and $Value -isnot [Collections.IList])) {
        return $false
    }
    foreach ($sid in $Value) {
        if (-not (Test-ADAnalyzerPolicySid $sid)) {
            return $false
        }
    }
    return $true
}

function ConvertFrom-ADAnalyzerPolicyPrincipal {
    param([string]$Value)
    $token = $Value.Trim()
    $marked = $token.StartsWith('*')
    if ($marked) {
        $token = $token.Substring(1)
    }
    $sid = $null
    $valid = -not [string]::IsNullOrWhiteSpace($token)
    if (Test-ADAnalyzerPolicySid $token) {
        $sid = $token
    }
    elseif ($marked -or $token -match '^S-\d') {
        $valid = $false
    }
    [pscustomobject]@{
        Sid = $sid
        Name = $(if (-not $sid) {
                $token
            }
            else {
                $null
            })
        Valid = $valid
    }
}

function Test-ADAnalyzerPolicyComparison {
    param(
        $Observed,
        $Expected,
        [string]$Operator = 'Equals'

    )
    switch ($Operator) {
        { $_ -in 'Equals', 'Equal', 'eq', 'NotEquals', 'ne' } {
            $left = @($Observed)
            $right = @($Expected)
            $equal = $left.Count -eq $right.Count
            if ($equal -and $left.Count) {
                $equal = @(Compare-Object -ReferenceObject $left -DifferenceObject $right).Count -eq 0
            }
            if ($Operator -in 'NotEquals', 'ne') {
                return -not $equal
            }
            return $equal
        }
        'In' {
            return @($Expected) -contains $Observed
        }
        'NotIn' {
            return @($Expected) -notcontains $Observed
        }
        { $_ -in 'Minimum', 'AtLeast', 'ge' } {
            $number = ConvertTo-ADAnalyzerPolicyNumber $Observed
            if (-not $number.Valid) {
                throw 'A numeric value is required'
            }
            return $number.Value -ge [long]$Expected
        }
        { $_ -in 'Maximum', 'AtMost', 'le' } {
            $number = ConvertTo-ADAnalyzerPolicyNumber $Observed
            if (-not $number.Valid) {
                throw 'A numeric value is required'
            }
            return $number.Value -le [long]$Expected
        }
        default {
            throw 'Unsupported comparison operator'
        }
    }
}
'@
$script:OriginalHashes = @{
    'Test-ADAnalyzerPolicyValueValid' = '34c46217392141d3f4583ef37bbfaea874b646c51b84fa6cc89213ba08071216'
    'ConvertTo-ADAnalyzerPolicyNumber' = '6d84ecce895c256b74f5bec94e253fe2c660aea85cabe37d5987cc1a945bf3e8'
    'ConvertTo-ADAnalyzerPolicyBoolean' = 'ac8ac21aca6ae2bec521f71e24d0818ae51eb3e725006ea7b297e00336444045'
    'Test-ADAnalyzerPolicySid' = '347911f38889d361d484f76ce67536c8a08c10c793930d6989b661ae430528e4'
    'Test-ADAnalyzerPolicySidList' = 'd1f0aa9778f8291e3f7bbf9d05d008799f863a7a01c54ee6bf337b0566daf6ab'
    'ConvertFrom-ADAnalyzerPolicyPrincipal' = 'c5d726ebd0575435bf4d2d63429028c803609f7b9680d85de248623d4c86a599'
    'Test-ADAnalyzerPolicyComparison' = 'c771877b12ce62694c76d387236df1c900199656509d134c3731103ce6bbed53'
}
$script:CommandNames = [ordered]@{
    IsValueValid = 'Test-ADAnalyzerPolicyValueValid'
    ParseNumber = 'ConvertTo-ADAnalyzerPolicyNumber'
    ParseBoolean = 'ConvertTo-ADAnalyzerPolicyBoolean'
    IsSid = 'Test-ADAnalyzerPolicySid'
    IsSidList = 'Test-ADAnalyzerPolicySidList'
    ParsePrincipal = 'ConvertFrom-ADAnalyzerPolicyPrincipal'
    Compare = 'Test-ADAnalyzerPolicyComparison'
}

function Assert-Semantics($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function ConvertTo-SemanticsJson($Value) {
    if ($null -eq $Value) {
        return 'null'
    }
    ConvertTo-Json -InputObject $Value -Compress -Depth 12
}

function Assert-SemanticsSame($Expected, $Actual, [string]$Label) {
    $first = ConvertTo-SemanticsJson $Expected
    $second = ConvertTo-SemanticsJson $Actual
    Assert-Semantics ($first -ceq $second) "$Label differs. Expected $first; actual $second"
}

function Get-SemanticsDefinitionHashes([string]$Text) {
    $tokens = $null
    $errors = $null
    $program = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    Assert-Semantics ($errors.Count -eq 0) 'Invalid frozen source.'
    $rows = @{}
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($node in $program.EndBlock.Statements) {
            if ($node -is [Management.Automation.Language.FunctionDefinitionAst] -and $script:OriginalHashes.ContainsKey($node.Name)) {
                $normalized = $node.Extent.Text.Replace([string][char]13 + [char]10, [string][char]10)
                $bytes = [Text.Encoding]::UTF8.GetBytes($normalized)
                $rows[$node.Name] = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
            }
        }
    }
    finally {
        $sha.Dispose()
    }
    $rows
}

function Assert-SemanticsHashes([string]$Text) {
    $actual = Get-SemanticsDefinitionHashes $Text
    Assert-Semantics ($actual.Count -eq 7) 'Missing frozen definitions.'
    foreach ($name in $script:OriginalHashes.Keys) {
        Assert-Semantics ($actual[$name] -ceq $script:OriginalHashes[$name]) "Immutable function hash changed for $name."
    }
}

Assert-SemanticsHashes $script:OriginalPolicyValues

function Get-SemanticsParamText([string]$Name) {
    $ast = (Get-Command -Name $Name -CommandType Function).ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    $ast.ParamBlock.Extent.Text.Replace([string][char]13 + [char]10, [string][char]10)
}

function Assert-SemanticsMetadata {
    $actual = @{}
    foreach ($name in $script:CommandNames.Values) {
        $actual[$name] = Get-SemanticsParamText $name
    }
    . ([scriptblock]::Create($script:OriginalPolicyValues))
    foreach ($name in $script:CommandNames.Values) {
        Assert-Semantics ((Get-SemanticsParamText $name) -ceq $actual[$name]) "Command parameter contract changed for $name."
    }
}

function Get-SemanticsTyped($Value) {
    if ($null -eq $Value) {
        return [pscustomobject]@{
            Type = '<null>'
            Data = $null
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
                        Value = Get-SemanticsTyped $property.Value
                    }
                }
            )
        }
    }
    [pscustomobject]@{
        Type = $type
        Data = $Value
    }
}

function New-SemanticsValueCases {
    $sid = 'S-1-5-32-544'
    $sid2 = 'S-1-5-11'
    $maxParts = 'S-1-5-' + ((1..15) -join '-')
    $groups = [ordered]@{
        IsValueValid = @(
            @{
                Record = $null
            }
            @{
                Record = @{}
            }
            @{
                Record = @{
                    ValueValid = $null
                }
            }
            @{
                Record = @{
                    ValueValid = @()
                }
            }
            @{
                Record = @{
                    ValueValid = @($true)
                }
            }
            @{
                Record = @{
                    ValueValid = @($false)
                }
            }
            @{
                Record = @{
                    ValueValid = @($true, $true)
                }
            }
            @{
                Record = @{
                    ValueValid = 'true'
                }
            }
            @{
                Record = [pscustomobject]@{
                    ValueValid = $false
                }
            }
        )
        ParseNumber = @(
            @{
                Value = $null
            }
            @{
                Value = $true
            }
            @{
                Value = @()
            }
            @{
                Value = @(42)
            }
            @{
                Value = ''
            }
            @{
                Value = 'invalid'
            }
            @{
                Value = ' +42 '
            }
            @{
                Value = -42
            }
            @{
                Value = '-9223372036854775808'
            }
            @{
                Value = '9223372036854775807'
            }
            @{
                Value = '9223372036854775808'
            }
            @{
                Value = '-9223372036854775809'
            }
            @{
                Value = [Collections.ArrayList]@('42')
            }
            @{
                Value = '1,234'
            }
            @{
                Value = '42.0'
            }
        )
        ParseBoolean = @(
            @{
                Value = $null
            }
            @{
                Value = @($true)
            }
            @{
                Value = $true
            }
            @{
                Value = $false
            }
            @{
                Value = 'TrUe'
            }
            @{
                Value = 'FaLsE'
            }
            @{
                Value = 1
            }
            @{
                Value = 0
            }
            @{
                Value = ' true '
            }
            @{
                Value = 'true' + [char]10
            }
            @{
                Value = 2
            }
            @{
                Value = 'yes'
            }
        )
        IsSid = @(
            @{
                Value = $null
            }
            @{
                Value = 42
            }
            @{
                Value = $sid
            }
            @{
                Value = $sid.ToLowerInvariant()
            }
            @{
                Value = 'S-1-4294967295-4294967295'
            }
            @{
                Value = 'S-1-4294967296-1'
            }
            @{
                Value = 'S-1-0x000100000000-1'
            }
            @{
                Value = 'S-1-0x0000FFFFFFFF-1'
            }
            @{
                Value = 'S-1-0xFFFFFFFFFFFF-1'
            }
            @{
                Value = 'S-1-5-4294967296'
            }
            @{
                Value = 'S-1-05-01'
            }
            @{
                Value = $maxParts
            }
            @{
                Value = $maxParts + '-16'
            }
            @{
                Value = 'S-1-5'
            }
        )
        IsSidList = @(
            @{
                Value = $null
            }
            @{
                Value = ''
            }
            @{
                Value = @()
            }
            @{
                Value = $sid
            }
            @{
                Value = @($sid)
            }
            @{
                Value = [Collections.ArrayList]@($sid, $sid2)
            }
            @{
                Value = @($sid, 'invalid')
            }
            @{
                Value = @{
                    SID = $sid
                }
            }
        )
        ParsePrincipal = @(
            @{
                Value = ''
            }
            @{
                Value = $null
            }
            @{
                Value = ' fixture group '
            }
            @{
                Value = $sid.ToLowerInvariant()
            }
            @{
                Value = ' *' + $sid + ' '
            }
            @{
                Value = '*S-1-5-4294967296'
            }
            @{
                Value = 'S-1-5-invalid'
            }
            @{
                Value = 'S-example'
            }
            @{
                Value = '**' + $sid
            }
            @{
                Value = '*fixture group'
            }
        )
        Compare = @(
            @{
                Observed = 'same'
                Expected = 'SAME'
            }
            @{
                Observed = 'same'
                Expected = 'same'
                Operator = 'Equal'
            }
            @{
                Observed = 'same'
                Expected = 'different'
                Operator = 'eq'
            }
            @{
                Observed = 'same'
                Expected = 'different'
                Operator = 'NotEquals'
            }
            @{
                Observed = 'same'
                Expected = 'same'
                Operator = 'ne'
            }
            @{
                Observed = @(1, 1, 2)
                Expected = @(1, 2, 1)
            }
            @{
                Observed = @(1, 1, 2)
                Expected = @(1, 2, 2)
            }
            @{
                Observed = @(1, 1)
                Expected = @(1)
            }
            @{
                Observed = @(1, 2)
                Expected = @(2, 1)
            }
            @{
                Observed = @(1, '2')
                Expected = @('1', 2)
            }
            @{
                Observed = @()
                Expected = @()
            }
            @{
                Observed = $null
                Expected = @()
            }
            @{
                Observed = $null
                Expected = @($null)
                Operator = 'In'
            }
            @{
                Observed = 'b'
                Expected = @('a', 'B', 'B')
                Operator = 'In'
            }
            @{
                Observed = 'c'
                Expected = @('a', 'b')
                Operator = 'NotIn'
            }
            @{
                Observed = '42'
                Expected = 42
                Operator = 'Minimum'
            }
            @{
                Observed = -41
                Expected = -42
                Operator = 'ge'
            }
            @{
                Observed = '9223372036854775807'
                Expected = [long]::MaxValue
                Operator = 'AtLeast'
            }
            @{
                Observed = '-9223372036854775808'
                Expected = [long]::MinValue
                Operator = 'Maximum'
            }
            @{
                Observed = -43
                Expected = -42
                Operator = 'le'
            }
            @{
                Observed = 42
                Expected = 41
                Operator = 'AtMost'
            }
            @{
                Observed = 3
                Expected = 2.5
                Operator = 'Maximum'
            }
        )
    }
    foreach ($method in $groups.Keys) {
        $index = 0
        foreach ($arguments in $groups[$method]) {
            $index++
            [pscustomobject]@{
                Method = $method
                Label = $method + '/' + $index
                Arguments = $arguments
            }
        }
    }
}

function Invoke-SemanticsDirect($Service, [string]$Method, [hashtable]$Arguments) {
    switch ($Method) {
        'IsValueValid' {
            $Service.IsValueValid($Arguments.Record)
        }
        'ParseNumber' {
            $Service.ParseNumber($Arguments.Value)
        }
        'ParseBoolean' {
            $Service.ParseBoolean($Arguments.Value)
        }
        'IsSid' {
            $Service.IsSid($Arguments.Value)
        }
        'IsSidList' {
            $Service.IsSidList($Arguments.Value)
        }
        'ParsePrincipal' {
            $Service.ParsePrincipal($Arguments.Value)
        }
        'Compare' {
            if ($Arguments.ContainsKey('Operator')) {
                $Service.Compare($Arguments.Observed, $Arguments.Expected, $Arguments.Operator)
            }
            else {
                $Service.Compare($Arguments.Observed, $Arguments.Expected)
            }
        }
    }
}

function Get-SemanticsRows($Sample, [string]$Route, $Service) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalPolicyValues))
    }
    $arguments = $Sample.Arguments
    $previous = ConvertTo-SemanticsJson $arguments
    $method = $Sample.Method
    $command = $script:CommandNames[$method]
    $rows = @(
        if ($Route -eq 'Direct') {
            Invoke-SemanticsDirect $Service $method $arguments
        }
        else {
            & $command @arguments
        }
    )
    Assert-Semantics ($rows.Count -eq 1) "Expected exactly one row for $($Sample.Label)."
    Assert-Semantics ($previous -ceq (ConvertTo-SemanticsJson $arguments)) "Input mutation for $($Sample.Label)."
    Get-SemanticsTyped $rows[0]
}

function Enable-SemanticsFaultType {
    if ($null -eq ('PolicyValueSemanticsUnstringable' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections;
public sealed class PolicyValueSemanticsUnstringable
{
    public override string ToString()
    {
        throw new InvalidOperationException("fixture policy string conversion failure");
    }
}

public sealed class PolicyValueSemanticsFaultingList : ArrayList
{
    private readonly string fault;
    public int Opens { get; private set; }
    public int Advances { get; private set; }
    public int Reads { get; private set; }

    public PolicyValueSemanticsFaultingList(string fault)
        : base(new object[] { "S-1-5-11", "S-1-5-32-544" })
    {
        this.fault = fault;
    }

    public override IEnumerator GetEnumerator()
    {
        Opens++;
        if (fault == "Open")
        {
            throw new InvalidOperationException("fixture policy enumeration Open");
        }
        return new ProbeEnumerator(this, base.GetEnumerator());
    }

    private sealed class ProbeEnumerator : IEnumerator
    {
        private readonly PolicyValueSemanticsFaultingList owner;
        private readonly IEnumerator source;

        public ProbeEnumerator(PolicyValueSemanticsFaultingList owner, IEnumerator source)
        {
            this.owner = owner;
            this.source = source;
        }

        public bool MoveNext()
        {
            owner.Advances++;
            if (owner.fault == "MoveNext" && owner.Advances == 2)
            {
                throw new InvalidOperationException("fixture policy enumeration MoveNext");
            }
            return source.MoveNext();
        }

        public object Current
        {
            get
            {
                owner.Reads++;
                if (owner.fault == "Current" && owner.Reads == 2)
                {
                    throw new InvalidOperationException("fixture policy enumeration Current");
                }
                return source.Current;
            }
        }

        public void Reset()
        {
            source.Reset();
        }
    }
}
'@
    }
}

function New-SemanticsFault([string]$Name) {
    switch ($Name) {
        'NullEquality' {
            return @{
                Method = 'Compare'
                Arguments = @{
                    Observed = $null
                    Expected = $null
                }
            }
        }
        'InvalidBound' {
            return @{
                Method = 'Compare'
                Arguments = @{
                    Observed = 42
                    Expected = 'invalid-bound'
                    Operator = 'Minimum'
                }
            }
        }
        'NumberStringCast' {
            return @{
                Method = 'ParseNumber'
                Arguments = @{
                    Value = [PolicyValueSemanticsUnstringable]::new()
                }
            }
        }
        'BooleanStringCast' {
            return @{
                Method = 'ParseBoolean'
                Arguments = @{
                    Value = [PolicyValueSemanticsUnstringable]::new()
                }
            }
        }
        'UnsupportedOperator' {
            return @{
                Method = 'Compare'
                Arguments = @{
                    Observed = 42
                    Expected = 42
                    Operator = 'unsupported'
                }
            }
        }
        'InvalidNumber' {
            return @{
                Method = 'Compare'
                Arguments = @{
                    Observed = $true
                    Expected = 42
                    Operator = 'Minimum'
                }
            }
        }
        { $_ -in 'SidListOpen', 'SidListMoveNext', 'SidListCurrent' } {
            $list = [PolicyValueSemanticsFaultingList]::new($Name.Substring(7))
            return @{
                Method = 'IsSidList'
                Arguments = @{
                    Value = $list
                }
                Probe = $list
            }
        }
        default {
            throw "Unknown policy fault $Name"
        }
    }
}

function Get-SemanticsError([Management.Automation.ErrorRecord]$Item) {
    [pscustomobject][ordered]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Type = $Item.Exception.GetType().FullName
        Cause = $Item.Exception.GetBaseException().GetType().FullName
        Message = $Item.Exception.Message
        CauseMessage = $Item.Exception.GetBaseException().Message
    }
}

function Get-SemanticsEnumerationEffects($Probe) {
    if ($null -ne $Probe) {
        [pscustomobject][ordered]@{
            Open = $Probe.Opens
            Advance = $Probe.Advances
            Read = $Probe.Reads
        }
    }
}

function Assert-SemanticsEnumeration($Effects, [string]$Name) {
    Assert-Semantics ($null -ne $Effects -and $Effects.Open -gt 0) "The native iterator was not opened for $Name."
    switch ($Name) {
        'SidListOpen' {
            Assert-Semantics ($Effects.Advance -eq 0 -and $Effects.Read -eq 0) 'A failed iterator open reached its items.'
        }
        'SidListMoveNext' {
            Assert-Semantics ($Effects.Advance -ge 2 -and $Effects.Read -ge 1) 'The advance fault did not follow a successfully read item.'
        }
        'SidListCurrent' {
            Assert-Semantics ($Effects.Advance -ge 1 -and
                $Effects.Read -ge 2) 'The current-item fault did not follow a successfully read item.'
        }
    }
}

function Invoke-SemanticsFault([string]$Name, [string]$Action, [bool]$Caught, [bool]$Frozen) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:OriginalPolicyValues))
    }
    $sample = New-SemanticsFault $Name
    $command = $script:CommandNames[$sample.Method]
    $arguments = $sample.Arguments
    $ErrorActionPreference = $Action
    $Matches = @{
        FixtureSentinel = 'caller-owned'
    }
    $Error.Clear()
    $observed = [Collections.Generic.List[object]]::new()
    $failure = $null
    $collect = {
        process {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                $observed.Add((Get-SemanticsError $_))
            }
            else {
                $observed.Add((Get-SemanticsTyped $_))
            }
        }
    }
    $success = $false
    if ($Caught) {
        try {
            & $command @arguments 2>&1 | . $collect
            $success = $?
        }
        catch {
            $failure = Get-SemanticsError $_
        }
    }
    else {
        & $command @arguments 2>&1 | . $collect
        $success = $?
    }
    [pscustomobject][ordered]@{
        Stream = $observed.ToArray()
        Caught = $failure
        GlobalErrors = @($Error | ForEach-Object { Get-SemanticsError $_ })
        Success = $success
        CallerMatches = $Matches.FixtureSentinel
        Enumeration = Get-SemanticsEnumerationEffects $sample.Probe
    }
}

function Assert-SemanticsNativeContinue($Observation, [string]$Name) {
    Assert-Semantics ($Observation.CallerMatches -ceq 'caller-owned' -and
        $Observation.GlobalErrors.Count -gt 0 -and
        $null -ne $Observation.Stream[0].Id) "The native Continue fault did not exercise the caller or error stream for $Name."
    switch ($Name) {
        'NullEquality' {
            Assert-Semantics ($Observation.Stream.Count -eq 2 -and
                $Observation.Stream[1].Type -ceq 'System.Boolean' -and
                $Observation.Stream[1].Data -eq $true) 'Native null comparison did not emit its expected post-error true result.'
        }
        { $_ -in 'SidListOpen', 'SidListMoveNext', 'SidListCurrent' } {
            Assert-SemanticsEnumeration $Observation.Enumeration $Name
            Assert-Semantics ($Observation.Stream[0].Cause -ceq 'System.InvalidOperationException' -and
                $Observation.Stream[0].CauseMessage -ceq ('fixture policy enumeration ' + $Name.Substring(7))) "The native iterator lost its injected cause for $Name."
            Assert-Semantics ($Observation.Stream.Count -eq 2 -and
                $Observation.Stream[1].Type -ceq 'System.Boolean' -and
                $Observation.Stream[1].Data -eq $true) "Native SID list did not continue to its post-error result for $Name."
        }
        'InvalidBound' {
            Assert-Semantics ($Observation.Stream.Count -eq 1) 'Invalid bound emitted a result after its cast fault.'
        }
        'NumberStringCast' {
            $fields = $Observation.Stream[1].Fields
            Assert-Semantics ($Observation.Stream.Count -eq 2 -and $fields[0].Name -ceq 'Valid' -and
                $fields[0].Value.Type -ceq '<null>' -and $fields[1].Name -ceq 'Value' -and
                $fields[1].Value.Type -ceq 'System.Int64' -and
                $fields[1].Value.Data -eq 0L) 'Numeric cast failure did not preserve null Valid and boxed Int64 zero.'
        }
        'BooleanStringCast' {
            $fields = $Observation.Stream[1].Fields
            Assert-Semantics ($Observation.Stream.Count -eq 2 -and $fields[0].Name -ceq 'Valid' -and
                $fields[0].Value.Type -ceq 'System.Boolean' -and $fields[0].Value.Data -eq $false -and
                $fields[1].Name -ceq 'Value' -and
                $fields[1].Value.Type -ceq '<null>') 'Boolean cast failure did not preserve false Valid and the null result.'
        }
    }
}

function Invoke-SemanticsUncaughtChild([string]$Name, [string]$Action, [bool]$Frozen) {
    $engine = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Uncaught', '-Fault', $Name, '-Preference', $Action
    )
    if ($Frozen) {
        $arguments += '-Original'
    }
    $ErrorActionPreference = 'Continue'
    $rows = @(& $engine @arguments 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{
        Exit = $LASTEXITCODE
        Rows = @($rows | Where-Object { $_ -match '\S' })
    }
}

$executed = 0
switch ($Case) {
    'VerifyOriginal' {
        $policy = Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/ADPolicyAnalysis.ps1'
        Assert-Semantics ((Get-FileHash `
                    -LiteralPath $policy `
                    -Algorithm SHA256).Hash -ieq '3b3e8d70916109b506ca68733735b899338849868d3dbdedb8b66ed7580a554c') 'Pre-edit policy source fingerprint differs.'
        Assert-SemanticsHashes ([IO.File]::ReadAllText($policy))
        $executed = $script:OriginalHashes.Count
    }
    { $_ -in 'Values', 'Direct' } {
        $service = $null
        $route = 'Command'
        Assert-SemanticsMetadata
        if ($Case -eq 'Direct') {
            foreach ($command in $script:CommandNames.Values) {
                Set-Item -LiteralPath ('function:' + $command) -Value { throw 'The object API delegated to a legacy policy command.' }
            }
            $service = [ADAnalyzerPolicyValueSemantics]::new()
            Assert-Semantics (@($service.PSObject.Properties).Count -eq 0) 'Policy semantics retained instance state.'
            $route = 'Direct'
        }
        $previousCulture = [Globalization.CultureInfo]::CurrentCulture
        try {
            foreach ($culture in @('en-US', 'fr-FR')) {
                [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($culture)
                foreach ($sample in @(New-SemanticsValueCases)) {
                    $expected = Get-SemanticsRows $sample 'Original' $null
                    $actual = Get-SemanticsRows $sample $route $service
                    Assert-SemanticsSame $expected $actual "$Case $culture $($sample.Label)"
                    $executed++
                }
            }
        }
        finally {
            [Globalization.CultureInfo]::CurrentCulture = $previousCulture
        }
        if ($Case -eq 'Direct') {
            Enable-SemanticsFaultType
            foreach ($name in @('NullEquality',
                    'InvalidBound',
                    'NumberStringCast',
                    'BooleanStringCast',
                    'UnsupportedOperator',
                    'InvalidNumber',
                    'SidListOpen',
                    'SidListMoveNext',
                    'SidListCurrent')) {
                $sample = New-SemanticsFault $name
                $failure = $null
                try {
                    $null = Invoke-SemanticsDirect $service $sample.Method $sample.Arguments
                }
                catch {
                    $failure = $_.Exception.GetBaseException()
                }
                $cause = @{
                    NullEquality = '(?i)null'
                    InvalidBound = 'invalid-bound'
                    NumberStringCast = 'fixture policy string conversion failure'
                    BooleanStringCast = 'fixture policy string conversion failure'
                    UnsupportedOperator = 'unsupported.*operator|operator.*unsupported'
                    InvalidNumber = 'numeric value is required'
                    SidListOpen = 'fixture policy enumeration Open'
                    SidListMoveNext = 'fixture policy enumeration MoveNext'
                    SidListCurrent = 'fixture policy enumeration Current'
                }[$name]
                Assert-Semantics ($null -ne $failure -and
                    $failure.Message -match $cause) "Direct failure did not surface its expected cause for $name."
                if ($null -ne $sample.Probe) {
                    Assert-Semantics ($failure -is [InvalidOperationException] -and
                        $failure.Message -ceq $cause) "Direct enumeration lost its injected CLR cause for $name."
                    Assert-SemanticsEnumeration (Get-SemanticsEnumerationEffects $sample.Probe) $name
                }
                $executed++
            }
        }
    }
    'Faults' {
        Enable-SemanticsFaultType
        foreach ($name in @('NullEquality',
                'InvalidBound',
                'NumberStringCast',
                'BooleanStringCast',
                'UnsupportedOperator',
                'InvalidNumber',
                'SidListOpen',
                'SidListMoveNext',
                'SidListCurrent')) {
            foreach ($action in @('Continue', 'Stop')) {
                $expected = Invoke-SemanticsFault $name $action $true $true
                $actual = Invoke-SemanticsFault $name $action $true $false
                Assert-Semantics ($null -ne $expected.Caught -and $expected.CallerMatches -ceq 'caller-owned' -and
                    $expected.Stream.Count -eq 0 -and
                    $expected.GlobalErrors.Count -gt 0) "Frozen caught fault did not exercise the catch and caller for $name."
                if ($name.StartsWith('SidList', [StringComparison]::Ordinal)) {
                    Assert-SemanticsEnumeration $expected.Enumeration $name
                    Assert-Semantics ($expected.Caught.Cause -ceq 'System.InvalidOperationException' -and
                        $expected.Caught.CauseMessage -ceq ('fixture policy enumeration ' + $name.Substring(7))) "The caught iterator lost its injected cause for $name."
                }
                Assert-SemanticsSame $expected $actual "Caught $name/$action"
                $executed++

                if ($action -eq 'Continue' -and $name -notin @('UnsupportedOperator', 'InvalidNumber')) {
                    $expected = Invoke-SemanticsFault $name $action $false $true
                    $actual = Invoke-SemanticsFault $name $action $false $false
                    Assert-SemanticsNativeContinue $expected $name
                }
                else {
                    $expected = Invoke-SemanticsUncaughtChild $name $action $true
                    $actual = Invoke-SemanticsUncaughtChild $name $action $false
                    Assert-Semantics ($expected.Exit -ne 0 -and $expected.Rows.Count -gt 1 -and
                        $expected.Rows[0] -ceq "CASE $name $action" -and
                        ($expected.Rows -join ' ') -notmatch 'Expected the native fault to leave the child') "Frozen terminal fault did not terminate child for $name/$action."
                }
                Assert-SemanticsSame $expected $actual "Uncaught $name/$action"
                $executed++
            }
        }
    }
    'Uncaught' {
        Enable-SemanticsFaultType
        $ErrorView = 'CategoryView'
        Write-Output "CASE $Fault $Preference"
        Invoke-SemanticsFault $Fault $Preference $false $Original.IsPresent
        throw 'Expected the native fault to leave the child before this statement.'
    }
}
Write-Host "PASS policy value semantics $Case $executed"
