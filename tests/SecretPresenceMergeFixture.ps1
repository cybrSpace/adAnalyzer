[CmdletBinding()]
param(
    [ValidateSet('Order', 'Aliases', 'Types', 'Tagged', 'Nested', 'Getters', 'Controls', 'Exports')]
    [string]$Case = 'Order'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:MergeExecuted = 0
$script:MergeMarker = 'MERGE_FIXTURE_PAYLOAD_080'
$script:MergeOwned = [Collections.Generic.List[IDisposable]]::new()
$script:MergeSink = [Collections.Generic.List[object]]::new()

function Assert-Merge($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-MergeSecure([bool]$Present) {
    $value = [Security.SecureString]::new()
    if ($Present) {
        $value.AppendChar('x')
    }
    $script:MergeOwned.Add($value)
    return $value
}

function Get-MergeSnapshot($Value) {
    if ($null -eq $Value) {
        return [pscustomobject]@{
            Type = '<null>'
            Value = $null
        }
    }
    $type = $Value.GetType().FullName
    if ($Value -is [pscredential]) {
        return [pscustomobject]@{
            Type = $type
            Length = $Value.PSBase.Password.PSBase.Length
        }
    }
    if ($Value -is [Security.SecureString]) {
        return [pscustomobject]@{
            Type = $type
            Length = $Value.PSBase.Length
        }
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return [pscustomobject]@{
            Type = $type
            Value = $Value
        }
    }
    if ($Value -is [Collections.IDictionary]) {
        $entries = @(
            foreach ($key in $Value.Keys) {
                [pscustomobject]@{
                    Name = [string]$key
                    Value = Get-MergeSnapshot $Value[$key]
                }
            }
        )
        return [pscustomobject]@{
            Type = $type
            Entries = $entries
        }
    }
    if ($Value -is [array] -or $Value -is [Collections.IList]) {
        $items = @(
            foreach ($item in $Value) {
                Get-MergeSnapshot $item
            }
        )
        return [pscustomobject]@{
            Type = $type
            Items = $items
        }
    }
    $properties = @(
        foreach ($property in $Value.PSObject.Properties) {
            [pscustomobject]@{
                Name = $property.Name
                Kind = [string]$property.MemberType
                Value = Get-MergeSnapshot $property.Value
            }
        }
    )
    return [pscustomobject]@{
        Type = $type
        Properties = $properties
    }
}

function Get-MergeJson($Value) {
    ConvertTo-Json -InputObject (Get-MergeSnapshot $Value) -Depth 60 -Compress
}

function Get-MergeNames($Value) {
    if ($Value -is [Collections.IDictionary]) {
        return @($Value.Keys | ForEach-Object { [string]$_ })
    }
    return @($Value.PSObject.Properties.Name)
}

function New-MergeMap([string]$Kind, [Collections.IDictionary]$Fields) {
    switch ($Kind) {
        Object {
            return [pscustomobject]$Fields
        }
        Ordered {
            return $Fields
        }
        Hashtable {
            $map = @{}
        }
        Generic {
            $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        }
        GenericOrdinal {
            $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
        }
        OrderedOrdinal {
            $map = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
        }
    }
    foreach ($key in $Fields.Keys) {
        $map.Add([string]$key, $Fields[$key])
    }
    return $map
}

function New-MergeRecord(
    [string]$Kind,
    [string]$Name,
    $Value,
    $Flag,
    [bool]$FlagFirst,
    [string]$FlagName = ''
) {
    if (-not $FlagName) {
        $FlagName = $Name + 'Present'
    }
    $fields = [ordered]@{
        Before = 'first'
    }
    if ($FlagFirst) {
        $fields[$FlagName] = $Flag
        $fields['Middle'] = 'middle'
        $fields[$Name] = $Value
    }
    else {
        $fields[$Name] = $Value
        $fields['Middle'] = 'middle'
        $fields[$FlagName] = $Flag
    }
    $fields['After'] = 'last'
    return (New-MergeMap $Kind $fields)
}

function Get-MergeExpectedNames($Source) {
    $names = [Collections.Generic.List[string]]::new()
    foreach ($name in @(Get-MergeNames $Source)) {
        $projected = if (Test-ADAnalyzerSecretName $name) {
            $name + 'Present'
        }
        else {
            $name
        }
        $slot = -1
        for ($index = 0; $index -lt $names.Count; $index++) {
            if ($names[$index] -ieq $projected) {
                $slot = $index
                break
            }
        }
        if ($slot -ge 0) {
            $names[$slot] = $projected
        }
        else {
            $names.Add($projected)
        }
    }
    return $names.ToArray()
}

function Assert-MergeResult($Result, [string]$Name, [bool]$Expected, [string[]]$ExpectedNames) {
    $flagName = $Name + 'Present'
    $property = $Result.PSObject.Properties[$flagName]
    Assert-Merge ($null -ne $property -and
        $property.Value -is [bool] -and
        $property.Value -eq $Expected) ('Presence merge is incorrect for ' + $Name)
    Assert-Merge ($null -eq $Result.PSObject.Properties[$Name]) 'A raw secret property survived projection.'
    if ($null -ne $ExpectedNames) {
        Assert-Merge ((@(Get-MergeNames $Result) -join '|') -ceq ($ExpectedNames -join '|')) 'Projection changed the last assigned flag spelling or first property slot.'
    }
    $json = ConvertTo-Json -InputObject $Result -Depth 60 -Compress
    Assert-Merge ($json -is [string] -and -not $json.Contains($script:MergeMarker)) 'Projection retained a synthetic payload.'
}

function Assert-MergeRecord($Source, [string]$Name, [bool]$Expected) {
    $before = Get-MergeJson $Source
    $names = @(Get-MergeExpectedNames $Source)
    $result = ConvertTo-ADAnalyzerSafeData -InputObject $Source
    Assert-MergeResult $result $Name $Expected $names
    Assert-Merge (-not [object]::ReferenceEquals($Source, $result)) 'Projection returned its mutable input.'
    Assert-Merge ($before -ceq (Get-MergeJson $Source)) 'Projection changed its source.'
    $again = ConvertTo-ADAnalyzerSafeData -InputObject $result
    Assert-Merge ((Get-MergeJson $again) -ceq (Get-MergeJson $result)) 'Presence merge is not idempotent.'
    $script:MergeExecuted++
}

function Get-MergePermutations {
    $names = @('Raw', 'TrueFlag', 'FalseFlag')
    foreach ($first in $names) {
        foreach ($second in @($names | Where-Object { $_ -ne $first })) {
            $third = @($names | Where-Object { $_ -ne $first -and $_ -ne $second })[0]
            [pscustomobject]@{
                Names = @($first, $second, $third)
            }
        }
    }
}

function Write-ADAnalyzerOperationFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content

    )
    $script:MergeSink.Add([pscustomobject]@{
            Path = $Path
            Content = $Content
        })
    return $Path
}

function Assert-MergeExportContent($Write, [bool]$Expected) {
    Assert-Merge (-not $Write.Content.Contains($script:MergeMarker)) 'An exported format retained the payload.'
    if ($Write.Path -like '*.json') {
        $document = $Write.Content | ConvertFrom-Json
        Assert-MergeResult $document.Findings[0].Evidence Password $Expected $null
    }
    elseif ($Write.Path -like '*.csv') {
        $rows = @($Write.Content | ConvertFrom-Csv)
        Assert-Merge ($rows.Count -eq 1) 'CSV finding cardinality changed.'
        $evidence = $rows[0].Evidence | ConvertFrom-Json
        Assert-MergeResult $evidence Password $Expected $null
    }
    else {
        $blocks = @([regex]::Matches($Write.Content, '(?s)<pre>(.*?)</pre>'))
        Assert-Merge ($blocks.Count -eq 2) 'HTML evidence and full snapshot blocks were not both produced.'
        foreach ($block in $blocks) {
            $decoded = [Net.WebUtility]::HtmlDecode($block.Groups[1].Value) | ConvertFrom-Json
            $evidence = if ($null -ne $decoded.PSObject.Properties['Findings']) {
                $decoded.Findings[0].Evidence
            }
            else {
                $decoded
            }
            Assert-MergeResult $evidence Password $Expected $null
        }
    }
}

try {
    switch ($Case) {
        Order {
            foreach ($kind in @('Object', 'Ordered', 'Hashtable', 'Generic')) {
                foreach ($rawPresent in @($false, $true)) {
                    foreach ($flag in @($false, $true)) {
                        foreach ($flagFirst in @($false, $true)) {
                            $value = if ($rawPresent) {
                                $script:MergeMarker
                            }
                            else {
                                ''
                            }
                            $source = New-MergeRecord $kind Password $value $flag $flagFirst
                            Assert-MergeRecord $source Password ($rawPresent -or $flag)
                        }
                    }
                }
            }
        }
        Aliases {
            $aliases = @((Get-ADAnalyzerSecretNames) -split '\|')
            Assert-Merge ($aliases.Count -eq 33) 'The accepted secret vocabulary changed.'
            foreach ($name in $aliases) {
                foreach ($flagFirst in @($false, $true)) {
                    $flagName = $name.ToUpperInvariant() + 'PRESENT'
                    $source = New-MergeRecord Ordered $name $script:MergeMarker $false $flagFirst $flagName
                    Assert-MergeRecord $source $name $true
                }
            }
            foreach ($kind in @('GenericOrdinal', 'OrderedOrdinal')) {
                foreach ($reverse in @($false, $true)) {
                    $fields = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
                    if ($reverse) {
                        $fields.Add('PASSWORD', $script:MergeMarker)
                        $fields.Add('passwordPRESENT', $false)
                        $fields.Add('Password', '')
                    }
                    else {
                        $fields.Add('Password', '')
                        $fields.Add('passwordPRESENT', $false)
                        $fields.Add('PASSWORD', $script:MergeMarker)
                    }
                    $source = New-MergeMap $kind $fields
                    Assert-MergeRecord $source Password $true
                }
            }

            foreach ($kind in @('GenericOrdinal', 'OrderedOrdinal')) {
                foreach ($permutation in @(Get-MergePermutations)) {
                    $fields = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
                    foreach ($entry in $permutation.Names) {
                        switch ($entry) {
                            Raw {
                                $fields.Add('Password', '')
                            }
                            TrueFlag {
                                $fields.Add('PasswordPresent', $true)
                            }
                            FalseFlag {
                                $fields.Add('passwordPresent', $false)
                            }
                        }
                    }
                    $source = New-MergeMap $kind $fields
                    Assert-MergeRecord $source Password $true
                }
            }
        }
        Types {
            $emptySecure = New-MergeSecure $false
            $secure = New-MergeSecure $true
            $samples = @(
                @{
                    Value = $null
                    Present = $false
                },
                @{
                    Value = ''
                    Present = $false
                },
                @{
                    Value = $false
                    Present = $true
                },
                @{
                    Value = 0
                    Present = $true
                },
                @{
                    Value = [object[]]@()
                    Present = $false
                },
                @{
                    Value = [object[]]@($null)
                    Present = $true
                },
                @{
                    Value = @{}
                    Present = $false
                },
                @{
                    Value = @{
                        Count = 0
                        Item = $script:MergeMarker
                    }
                    Present = $true
                },
                @{
                    Value = $emptySecure
                    Present = $false
                },
                @{
                    Value = $secure
                    Present = $true
                },
                @{
                    Value = [pscredential]::new('fixture', $emptySecure)
                    Present = $false
                },
                @{
                    Value = [pscredential]::new('fixture', $secure)
                    Present = $true
                }
            )
            foreach ($sample in $samples) {
                foreach ($flagFirst in @($false, $true)) {
                    $source = New-MergeRecord Object Password $sample.Value $false $flagFirst
                    Assert-MergeRecord $source Password $sample.Present
                }
            }
            foreach ($flag in @('true', 'false', 1, $null, [object[]]@(1))) {
                foreach ($rawPresent in @($false, $true)) {
                    foreach ($flagFirst in @($false, $true)) {
                        $value = if ($rawPresent) {
                            $script:MergeMarker
                        }
                        else {
                            ''
                        }
                        $source = New-MergeRecord Ordered Password $value $flag $flagFirst
                        Assert-MergeRecord $source Password $rawPresent
                    }
                }
            }
        }
        Tagged {
            foreach ($sample in @(
                    @{
                        Raw = $script:MergeMarker
                        Flag = $false
                        Value = ''
                        Present = $true
                    },
                    @{
                        Raw = ''
                        Flag = $true
                        Value = ''
                        Present = $true
                    },
                    @{
                        Raw = $script:MergeMarker
                        Flag = $false
                        Value = $script:MergeMarker
                        Present = $true
                    },
                    @{
                        Raw = ''
                        Flag = $false
                        Value = ''
                        Present = $false
                    }
                )) {
                foreach ($flagFirst in @($false, $true)) {
                    $fields = [ordered]@{
                        Name = 'Password'
                        Before = 'first'
                    }
                    if ($flagFirst) {
                        $fields['secretPRESENT'] = $sample.Flag
                        $fields['Secret'] = $sample.Raw
                    }
                    else {
                        $fields['Secret'] = $sample.Raw
                        $fields['secretPRESENT'] = $sample.Flag
                    }
                    $fields['Value'] = $sample.Value
                    $fields['After'] = 'last'
                    $source = [pscustomobject]$fields
                    $before = Get-MergeJson $source
                    $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                    Assert-MergeResult $result Secret $sample.Present $null
                    Assert-Merge ($null -eq $result.PSObject.Properties['Value']) 'Tagged payload survived projection.'
                    Assert-Merge ($before -ceq (Get-MergeJson $source)) 'Tagged projection changed its source.'
                    Assert-Merge ((Get-MergeJson (ConvertTo-ADAnalyzerSafeData $result)) -ceq (Get-MergeJson $result)) 'Tagged presence merge is not idempotent.'
                    $script:MergeExecuted++
                }
            }
            foreach ($sample in @(
                    @{
                        Fields = [ordered]@{
                            Name = 'Password'
                            Expected = $script:MergeMarker
                        }
                        HasFlag = $false
                        Present = $false
                    },
                    @{
                        Fields = [ordered]@{
                            Name = 'Password'
                            Observed = $false
                        }
                        HasFlag = $true
                        Present = $false
                    },
                    @{
                        Fields = [ordered]@{
                            Name = 'Password'
                            Observed = $true
                        }
                        HasFlag = $true
                        Present = $true
                    },
                    @{
                        Fields = [ordered]@{
                            Name = 'Password'
                            Value = $false
                        }
                        HasFlag = $true
                        Present = $true
                    },
                    @{
                        Fields = [ordered]@{
                            Name = 'Password'
                            SecretPresent = $true
                        }
                        HasFlag = $true
                        Present = $true
                    },
                    @{
                        Fields = [ordered]@{
                            Name = 'Password'
                            SecretPresent = 'true'
                        }
                        HasFlag = $false
                        Present = $false
                    }
                )) {
                $result = ConvertTo-ADAnalyzerSafeData -InputObject ([pscustomobject]$sample.Fields)
                $flag = $result.PSObject.Properties['SecretPresent']
                Assert-Merge (($null -ne $flag) -eq $sample.HasFlag) 'Existing tagged flag-only behavior changed.'
                if ($sample.HasFlag) {
                    Assert-Merge ($flag.Value -is [bool] -and $flag.Value -eq $sample.Present) 'Existing tagged Boolean semantics changed.'
                }
                foreach ($name in @('Value', 'Observed', 'Expected')) {
                    Assert-Merge ($null -eq $result.PSObject.Properties[$name]) 'Existing tagged payload omission changed.'
                }
                $script:MergeExecuted++
            }

            foreach ($permutation in @(Get-MergePermutations)) {
                $fields = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
                $fields.Add('Name', 'Password')
                foreach ($entry in $permutation.Names) {
                    switch ($entry) {
                        Raw {
                            $fields.Add('Secret', '')
                        }
                        TrueFlag {
                            $fields.Add('SecretPresent', $true)
                        }
                        FalseFlag {
                            $fields.Add('secretPresent', $false)
                        }
                    }
                }
                $fields.Add('Value', '')
                $source = New-MergeMap GenericOrdinal $fields
                $before = Get-MergeJson $source
                $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                Assert-MergeResult $result Secret $true $null
                Assert-Merge ($null -eq $result.PSObject.Properties['Value']) 'Tagged payload omission changed.'
                Assert-Merge ($before -ceq (Get-MergeJson $source)) 'Tagged flag collision changed its source.'
                Assert-Merge ((Get-MergeJson (ConvertTo-ADAnalyzerSafeData $result)) -ceq (Get-MergeJson $result)) 'Tagged flag collision is not idempotent.'
                $script:MergeExecuted++
            }

            foreach ($rawPresent in @($false, $true)) {
                $raw = if ($rawPresent) {
                    $script:MergeMarker
                }
                else {
                    ''
                }
                $source = [pscustomobject][ordered]@{
                    Name = 'Password'
                    Secret = $raw
                    After = 'last'
                }
                $before = Get-MergeJson $source
                $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                Assert-MergeResult $result Secret $rawPresent $null
                Assert-Merge ($null -eq $result.PSObject.Properties['Value']) 'A direct tagged secret invented a payload field.'
                Assert-Merge ($before -ceq (Get-MergeJson $source)) 'A direct tagged secret changed its source.'
                $again = ConvertTo-ADAnalyzerSafeData -InputObject $result
                Assert-Merge ((Get-MergeJson $again) -ceq (Get-MergeJson $result)) 'A direct tagged secret without a generic payload is not idempotent.'
                $script:MergeExecuted++
            }
        }
        Nested {
            $one = New-MergeRecord Object Password $script:MergeMarker $false $false
            $two = New-MergeRecord Ordered Password '' $true $true
            $source = [pscustomobject]@{
                Child = $one
            }
            $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
            Assert-MergeResult $result.Child Password $true $null
            Assert-Merge (-not [object]::ReferenceEquals($source.Child, $result.Child)) 'Nested projection retained a mutable child.'
            $result.Child.Before = 'result'
            Assert-Merge ($one.Before -ceq 'first') 'Result mutation reached nested source data.'
            $script:MergeExecuted++
            $source = [ordered]@{
                Outer = [ordered]@{
                    Child = $two
                }
            }
            $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
            Assert-MergeResult $result.Outer.Child Password $true $null
            $script:MergeExecuted++
            $items = [object[]]@($one, $two)
            $result = ConvertTo-ADAnalyzerSafeData -InputObject $items
            Assert-Merge ($result -is [array] -and
                $result.Count -eq 2 -and
                -not [object]::ReferenceEquals($items,
                    $result)) 'Explicit array shape or detachment changed.'
            foreach ($item in $result) {
                Assert-MergeResult $item Password $true $null
            }
            $script:MergeExecuted++
            $list = [Collections.ArrayList]::new()
            $null = $list.Add($one)
            $null = $list.Add($two)
            $result = ConvertTo-ADAnalyzerSafeData -InputObject $list
            Assert-Merge ($result -is [array] -and $result.Count -eq 2) 'Collection projection shape changed.'
            foreach ($item in $result) {
                Assert-MergeResult $item Password $true $null
            }
            $script:MergeExecuted++
            $rows = @($items | ConvertTo-ADAnalyzerSafeData)
            Assert-Merge ($rows.Count -eq 2) 'Ordinary pipeline cardinality changed.'
            foreach ($item in $rows) {
                Assert-MergeResult $item Password $true $null
            }
            $script:MergeExecuted++
            $rows = @(, $items | ConvertTo-ADAnalyzerSafeData)
            Assert-Merge ($rows.Count -eq 1 -and $rows[0] -is [pscustomobject]) 'Single wrapped-array pipeline shape changed.'
            Assert-Merge ($rows[0].SyncRoot.Count -eq 2) 'Wrapped array metadata lost its projected source items.'
            foreach ($item in $rows[0].SyncRoot) {
                Assert-MergeResult $item Password $true $null
            }
            $script:MergeExecuted++
        }
        Getters {
            foreach ($rawPresent in @($false, $true)) {
                foreach ($flagFirst in @($false, $true)) {
                    $script:MergeGetterRaw = if ($rawPresent) {
                        $script:MergeMarker
                    }
                    else {
                        ''
                    }
                    $script:MergeGetterFlag = -not $rawPresent
                    $script:MergeReads = @{
                        Raw = 0
                        Flag = 0
                        Note = 0
                    }
                    $source = [pscustomobject]@{}
                    $rawGetter = { $script:MergeReads.Raw++
                        $script:MergeGetterRaw }
                    $flagGetter = { $script:MergeReads.Flag++
                        $script:MergeGetterFlag }
                    if ($flagFirst) {
                        $source | Add-Member ScriptProperty passwordPRESENT $flagGetter
                        $source | Add-Member ScriptProperty Password $rawGetter
                    }
                    else {
                        $source | Add-Member ScriptProperty Password $rawGetter
                        $source | Add-Member ScriptProperty passwordPRESENT $flagGetter
                    }
                    $source | Add-Member ScriptProperty Note { $script:MergeReads.Note++
                        'keep' }
                    $before = @($source.PSObject.Properties | ForEach-Object { $_.Name + ':' + $_.MemberType }) -join '|'
                    $names = @(Get-MergeExpectedNames $source)
                    $beforeErrors = $Error.Count
                    $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                    Assert-MergeResult $result Password $true $names
                    Assert-Merge ($script:MergeReads.Raw -eq 1 -and
                        $script:MergeReads.Flag -eq 1 -and
                        $script:MergeReads.Note -eq 1) 'Projection read a source getter more than once.'
                    Assert-Merge ($Error.Count -eq $beforeErrors) 'Projection emitted an unexpected getter error.'
                    $after = @($source.PSObject.Properties | ForEach-Object { $_.Name + ':' + $_.MemberType }) -join '|'
                    Assert-Merge ($before -ceq $after) 'Projection changed source getter metadata.'
                    Assert-Merge ((Get-MergeJson (ConvertTo-ADAnalyzerSafeData $result)) -ceq (Get-MergeJson $result)) 'Getter-produced projection is not idempotent.'
                    Assert-Merge ($script:MergeReads.Raw -eq 1 -and
                        $script:MergeReads.Flag -eq 1 -and
                        $script:MergeReads.Note -eq 1) 'Result processing reread a source getter.'
                    $script:MergeExecuted++
                }
            }

            Add-Type -TypeDefinition @'
using System;
using System.Collections;
namespace ADAnalyzer.MergeFixture
{
    public sealed class CountedCollection : ICollection
    {
        private readonly int count;
        private readonly bool fail;
        public CountedCollection(int count, bool fail)
        {
            this.count = count;
            this.fail = fail;
        }
        public int Reads { get; private set; }
        int ICollection.Count
        {
            get
            {
                Reads++;
                if (fail)
                {
                    throw new InvalidOperationException("MERGE_NATIVE_COUNT_FAILURE");
                }
                return count;
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
            foreach ($count in @(0, 1)) {
                foreach ($flagFirst in @($false, $true)) {
                    $value = [ADAnalyzer.MergeFixture.CountedCollection]::new($count, $false)
                    $source = New-MergeRecord Ordered Password $value $true $flagFirst
                    $names = @(Get-MergeExpectedNames $source)
                    $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                    Assert-MergeResult $result Password $true $names
                    Assert-Merge ($value.Reads -eq 1) 'Existing true evidence short-circuited a native presence getter.'
                    Assert-Merge ([object]::ReferenceEquals($source['Password'], $value)) 'Projection replaced a native source value.'
                    $script:MergeExecuted++
                }
            }
            foreach ($priorRaw in @($false, $true)) {
                $value = [ADAnalyzer.MergeFixture.CountedCollection]::new(1, $true)
                $fields = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
                if ($priorRaw) {
                    $fields.Add('Password', $script:MergeMarker)
                    $fields.Add('PASSWORD', $value)
                }
                else {
                    $fields.Add('PasswordPresent', $true)
                    $fields.Add('Password', $value)
                }
                $source = New-MergeMap GenericOrdinal $fields
                $caught = $null
                $rows = [Collections.Generic.List[object]]::new()
                try {
                    ConvertTo-ADAnalyzerSafeData -InputObject $source | ForEach-Object { $rows.Add($_) }
                }
                catch {
                    $caught = $_
                }
                Assert-Merge ($null -ne $caught -and
                    $rows.Count -eq 0 -and
                    $value.Reads -eq 1) 'Prior true evidence suppressed a later native getter failure.'
                Assert-Merge ($caught.Exception.GetBaseException().Message.Contains('MERGE_NATIVE_COUNT_FAILURE')) 'Presence projection lost the native getter cause.'
                $script:MergeExecuted++
            }
        }
        Controls {
            foreach ($flag in @($false, $true, 'true', 0, $null, [object[]]@(1))) {
                $source = [pscustomobject][ordered]@{
                    PasswordPresent = $flag
                    Note = 'keep'
                }
                $before = Get-MergeJson $source
                $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                Assert-Merge ((Get-MergeJson $result.PasswordPresent) -ceq (Get-MergeJson $flag)) 'Ordinary flag-only metadata was changed.'
                Assert-Merge ($before -ceq (Get-MergeJson $source) -and $result.Note -ceq 'keep') 'Flag-only control was mutated.'
                $script:MergeExecuted++
            }
            foreach ($name in @('PasswordComplexity', 'PasswordInterval')) {
                $source = [pscustomobject]@{
                    Name = 'ordinary'
                    SecretPresent = 'unchanged'
                }
                $source | Add-Member NoteProperty $name $false
                $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                Assert-Merge ($result.$name -is [bool] -and
                    -not $result.$name -and
                    $result.SecretPresent -ceq 'unchanged') 'An ordinary near-name or flag was treated as a secret.'
                Assert-Merge ($null -eq $result.PSObject.Properties[($name + 'Present')]) 'Projection invented an ordinary presence flag.'
                $script:MergeExecuted++
            }

            foreach ($kind in @('GenericOrdinal', 'OrderedOrdinal')) {
                foreach ($reverse in @($false, $true)) {
                    $fields = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
                    $firstName = if ($reverse) {
                        'passwordPresent'
                    }
                    else {
                        'PasswordPresent'
                    }
                    $lastName = if ($reverse) {
                        'PasswordPresent'
                    }
                    else {
                        'passwordPresent'
                    }
                    $fields.Add($firstName, $true)
                    $fields.Add($lastName, $false)
                    $source = New-MergeMap $kind $fields
                    $before = Get-MergeJson $source
                    $result = ConvertTo-ADAnalyzerSafeData -InputObject $source
                    Assert-Merge ($result.PasswordPresent -is [bool] -and
                        -not $result.PasswordPresent) 'Flag-only case collisions gained new OR semantics.'
                    Assert-Merge ((@(Get-MergeNames $result) -join '|') -ceq $lastName) 'Flag-only collision spelling changed.'
                    Assert-Merge ($before -ceq (Get-MergeJson $source)) 'Flag-only case collision mutated its source.'
                    $script:MergeExecuted++
                }
            }
        }
        Exports {
            foreach ($rawPresent in @($false, $true)) {
                foreach ($flagFirst in @($false, $true)) {
                    $value = if ($rawPresent) {
                        $script:MergeMarker
                    }
                    else {
                        ''
                    }
                    $evidence = New-MergeRecord Object Password $value (-not $rawPresent) $flagFirst
                    $assessment = [pscustomobject]@{
                        SchemaVersion = 1
                        Target = 'merge.example.invalid'
                        Findings = @([pscustomobject]@{
                                RuleId = 'MERGE.FIXTURE'
                                Target = 'merge.example.invalid'
                                Status = 'Fail'
                                Severity = 'High'
                                Evidence = $evidence
                            })
                    }
                    $before = Get-MergeJson $assessment
                    foreach ($format in @('Json', 'Html', 'Csv', 'All')) {
                        $path = 'memory-only-merge'
                        if ($format -ne 'All') {
                            $path += '.' + $format.ToLowerInvariant()
                        }
                        $parameters = @{
                            Assessment = $assessment
                            Path = $path
                            Format = $format
                            Confirm = $false
                        }
                        $script:MergeSink.Clear()
                        $rows = @(Export-ADAnalyzerAssessment @parameters)
                        $expectedWrites = if ($format -eq 'All') {
                            3
                        }
                        else {
                            1
                        }
                        Assert-Merge ($rows.Count -eq $expectedWrites -and
                            $script:MergeSink.Count -eq $expectedWrites) 'Export writer cardinality changed.'
                        foreach ($write in $script:MergeSink) {
                            Assert-MergeExportContent $write $true
                        }
                        Assert-Merge ($before -ceq (Get-MergeJson $assessment)) 'Export mutated its source.'
                        $script:MergeExecuted++
                        $script:MergeSink.Clear()
                        $rows = @(Export-ADAnalyzerAssessment @parameters -WhatIf)
                        Assert-Merge ($rows.Count -eq 0 -and $script:MergeSink.Count -eq 0) 'WhatIf reached the memory writer.'
                        Assert-Merge ($before -ceq (Get-MergeJson $assessment)) 'WhatIf mutated its source.'
                        $script:MergeExecuted++
                    }
                }
            }
        }
    }
    $expectedCounts = @{
        Order = 32
        Aliases = 82
        Types = 44
        Tagged = 22
        Nested = 6
        Getters = 10
        Controls = 12
        Exports = 32
    }
    Assert-Merge ($script:MergeExecuted -eq $expectedCounts[$Case]) 'Not every required merge scenario executed.'
    Write-Host ('PASS secret presence merge ' + $Case + ' ' + $script:MergeExecuted)
}
catch {
    Write-Host ('FAIL secret presence merge ' + $Case + ' after ' + $script:MergeExecuted + ' completed scenarios')
    Write-Host $_.ScriptStackTrace
    throw
}
finally {
    foreach ($value in $script:MergeOwned) {
        $value.Dispose()
    }
}
