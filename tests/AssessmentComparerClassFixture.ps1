[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

function Import-Module {
    throw 'The comparer fixture cannot acquire a module.'
}

function Invoke-Command {
    throw 'The comparer fixture cannot invoke a remote command.'
}

function Get-ADObject {
    throw 'The comparer fixture cannot contact a directory provider.'
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

function script:Write-ADAnalyzerFile {
    throw 'A comparison attempted to write a file.'
}

function script:Write-ADAnalyzerOperationFile {
    throw 'A comparison attempted to write an operation file.'
}

$script:passed = 0

function New-ComparisonFinding([string]$Rule, [string]$Target, [string]$Status, $Evidence) {
    [pscustomobject][ordered]@{
        RuleId = $Rule
        Target = $Target
        Status = $Status
        Evidence = $Evidence
    }
}

function New-ComparisonPair {
    $reference = [pscustomobject][ordered]@{
        SchemaVersion = 1
        RunId = 'reference'
        Target = 'domain.fixture.invalid'
        Context = [pscustomobject]@{
            SearchBase = 'OU=Fixture,DC=domain,DC=fixture,DC=invalid'
        }
        Checks = @(
            New-ComparisonFinding 'FIXTURE.CHECK' 'fixture subject' 'Pass' ([pscustomobject]@{ Data = 'observed' })
        )
    }
    $difference = [pscustomobject][ordered]@{
        SchemaVersion = 1
        RunId = 'difference'
        Target = 'domain.fixture.invalid'
        Context = [pscustomobject]@{
            SearchBase = 'OU=Fixture,DC=domain,DC=fixture,DC=invalid'
        }
        Checks = @(
            New-ComparisonFinding 'FIXTURE.CHECK' 'fixture subject' 'Pass' ([pscustomobject]@{ Data = 'observed' })
        )
    }
    return @{
        Reference = $reference
        Difference = $difference
    }
}

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$TestName, [scriptblock]$Body) {
    try {
        & $Body
        $script:passed++
    }
    catch {
        Write-Host ('FAIL assessment comparer ' + $TestName)
        throw
    }
}

function Get-FixtureFailure([scriptblock]$Operation) {
    try {
        $null = & $Operation
    }
    catch {
        return $_
    }
    throw 'The comparer unexpectedly accepted invalid input.'
}

function Get-FixtureDiagnostic([object]$Entry) {
    if ($null -eq $Entry) {
        return $null
    }
    if ($Entry -is [Collections.IList]) {
        return [ordered]@{
            Type = $Entry.GetType().FullName
            Entries = @(
                foreach ($item in $Entry) {
                    Get-FixtureDiagnostic $item
                }
            )
        }
    }

    $record = $Entry
    if ($Entry -isnot [Management.Automation.ErrorRecord] -and
        $Entry -is [Management.Automation.IContainsErrorRecord]) {
        $record = $Entry.ErrorRecord
    }
    $diagnostic = [ordered]@{
        Type = $Entry.GetType().FullName
        Id = $null
        Category = $null
        Command = $null
        Cause = $null
        Message = $null
    }
    if ($record -is [Management.Automation.ErrorRecord]) {
        $diagnostic.Id = $record.FullyQualifiedErrorId
        $diagnostic.Category = [string]$record.CategoryInfo.Category
        if ($null -ne $record.InvocationInfo -and $null -ne $record.InvocationInfo.MyCommand) {
            $diagnostic.Command = $record.InvocationInfo.MyCommand.Name
        }
        if ($null -ne $record.Exception) {
            $cause = $record.Exception.GetBaseException()
            $diagnostic.Cause = $cause.GetType().FullName
            $diagnostic.Message = $cause.Message.Replace($fixtureDirectory, '<fixture>')
        }
    }
    elseif ($Entry -is [Exception]) {
        $cause = $Entry.GetBaseException()
        $diagnostic.Cause = $cause.GetType().FullName
        $diagnostic.Message = $cause.Message.Replace($fixtureDirectory, '<fixture>')
    }
    return $diagnostic
}

# Exact comparison bodies from accepted 36dfb20. Pair using original names and lexical caller.
if ($Case -eq 'Native') {
    $script:acceptedComparerBodies = [ordered]@{
        # 22aa0b43f8a78c1387acffd2895519958f312cd33b6429b9d687c2945720f3df
        'ConvertTo-ADAnalyzerComparableValue' = @'
    param(
        [AllowNull()]$Value,
        [string]$Field = ''

    )
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary] -and $Value -isnot [pscustomobject]) {
        $items = @(foreach ($item in $Value) {
                ConvertTo-ADAnalyzerComparableValue $item $Field
            })
        if ($Field -eq '' -or
            $Field -in @('Members',
                'MemberOf',
                'TransitiveGroups',
                'EffectiveSids',
                'DirectSids',
                'PrivilegedSids',
                'Unresolved',
                'Cycles',
                'SIDHistory',
                'ServicePrincipalNames')) {
            return ,
            @(foreach ($serialized in @($items | ForEach-Object { ConvertTo-Json `
                                -InputObject $_ `
                                -Depth 100 `
                                -Compress } | Sort-Object)) {
                    $serialized
                })
        }
        return , $items
    }
    $output = [ordered]@{}
    $names = if ($Value -is [Collections.IDictionary]) {
        @(([Collections.IDictionary].GetProperty('Keys')).GetValue($Value, $null))
    }
    else {
        foreach ($property in $Value.PSObject.Properties) {
            $property.Name
        }
    }
    foreach ($name in @($names | Sort-Object)) {
        if ($name -in @('Timestamp',
                'CollectedAt',
                'ObservedAt',
                'RunId',
                'ScanId',
                'StartedAt',
                'CompletedAt',
                'Duration',
                'Elapsed',
                'CheckId')) {
            continue
        }
        if ($Value -is [Collections.IDictionary]) {
            $child = $Value[$name]
        }
        else {
            $child = $Value.PSObject.Properties[$name].Value
        }
        $output[[string]$name] = ConvertTo-ADAnalyzerComparableValue -Value $child -Field ([string]$name)
    }
    return [pscustomobject]$output
'@
        # 696f79c37e61a5cb2844946b4404cdde32e9db70aed3249b140308fa61b8ea81
        'Compare-ADAnalyzerAssessment' = @'
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Reference,
        [Parameter(Mandatory)]$Difference

    )
    $before = Read-ADAnalyzerOperationDocument $Reference
    $after = Read-ADAnalyzerOperationDocument $Difference
    $oldTarget = [string](Get-ADAnalyzerOperationValue $before @('Target'))
    $newTarget = [string](Get-ADAnalyzerOperationValue $after @('Target'))
    if ($oldTarget -and $newTarget -and $oldTarget -ine $newTarget) {
        throw 'Cannot compare different directory targets as configuration drift'
    }
    $oldScope = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $before @('Context')) @('SearchBase'))
    $newScope = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $after @('Context')) @('SearchBase'))
    if ($oldScope -ine $newScope) {
        throw 'Cannot compare different search-base scopes as configuration drift'
    }
    $maps = @(@{}, @{})
    foreach ($pair in @(@($before, 0), @($after, 1))) {
        $rows = @(Get-ADAnalyzerOperationValue $pair[0] @('Checks', 'Findings') @())
        foreach ($row in $rows) {
            if ($null -eq $row) {
                continue
            }
            $rule = [string](Get-ADAnalyzerOperationValue $row @('RuleId'))
            if (-not $rule) {
                $legacy = [string](Get-ADAnalyzerOperationValue $row @('Finding'))
                $rule = switch ($legacy) {
                    'Defect - User Inactivity' {
                        'ACCOUNT.INACTIVE'
                    }
                    'Defect - Computer Inactivity' {
                        'COMPUTER.INACTIVE'
                    }
                    default {
                        if ($legacy) {
                            'LEGACY.' + $legacy
                        }
                        else {
                            throw 'A snapshot finding is missing RuleId'
                        }
                    }
                }
            }
            $target = [string](Get-ADAnalyzerOperationValue $row @('Target', 'DistinguishedName', 'ObjectGuid', 'SID'))
            if (-not $target) {
                throw 'A snapshot finding is missing its stable target'
            }
            if ($rule -in 'HOST.SERVICE', 'HOST.REGISTRY') {
                $evidence = Get-ADAnalyzerOperationValue $row @('Evidence')
                $profileRuleId = Get-ADAnalyzerOperationValue $evidence @('ProfileRuleId')
                if ($null -ne $profileRuleId) {
                    $parts = @()
                    if ($rule -eq 'HOST.REGISTRY') {
                        $path = Get-ADAnalyzerOperationValue $evidence @('RegistryPath')
                        $valueName = Get-ADAnalyzerOperationValue $evidence @('ValueName')
                        if ($path -isnot [string] -or $valueName -isnot [string]) {
                            throw 'A named host registry snapshot is missing its literal path/value identity'
                        }
                        $parts = @($path, $valueName)
                    }
                    $target = Get-ADAnalyzerHostRuleIdentity -Rule @{
                        Id = $profileRuleId
                    } -Target $target -Parts $parts
                }
            }
            $key = $rule.ToUpperInvariant() + [char]0 + $target.ToUpperInvariant()
            if (-not $maps[$pair[1]].ContainsKey($key)) {
                $maps[$pair[1]][$key] = [Collections.ArrayList]::new()
            }
            $null = $maps[$pair[1]][$key].Add((ConvertTo-ADAnalyzerSafeData -InputObject $row))
        }
    }
    $changes = @(foreach ($key in @(@($maps[0].Keys) + @($maps[1].Keys) | Sort-Object -Unique)) {
            $old = @(if ($maps[0].ContainsKey($key)) {
                    $maps[0][$key]
                })
            $new = @(if ($maps[1].ContainsKey($key)) {
                    $maps[1][$key]
                })
            $status = 'Unchanged'
            $reason = $null
            if (-not $maps[0].ContainsKey($key)) {
                $status = 'New'
            }
            elseif (-not $maps[1].ContainsKey($key)) {
                $status = 'Changed'
                $reason = 'NotObservedInDifference'
            }
            else {
                $oldJson = ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $old) -Depth 100 -Compress
                $newJson = ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $new) -Depth 100 -Compress
                if ($oldJson -cne $newJson) {
                    $status = 'Changed'
                }
                $oldFail = @($old | Where-Object Status -in 'Fail', 'Invalid').Count -gt 0
                $newFail = @($new | Where-Object Status -in 'Fail', 'Invalid').Count -gt 0
                $oldGood = @($old | Where-Object Status -notin 'Pass', 'NotApplicable').Count -eq 0
                $newGood = @($new | Where-Object Status -notin 'Pass', 'NotApplicable').Count -eq 0
                if ($oldFail -and $newGood) {
                    $status = 'Resolved'
                }
                elseif ($oldGood -and $newFail) {
                    $status = 'New'
                }
            }
            $sample = if ($new.Count -and $null -ne $new[0]) {
                $new[0]
            }
            else {
                $old[0]
            }
            [pscustomobject]@{
                RuleId = $key.Split([char]0)[0]
                Target = Get-ADAnalyzerOperationValue $sample @('Target', 'DistinguishedName', 'ObjectGuid', 'SID')
                Change = $status
                Reason = $reason
                Reference = $old
                Difference = $new
            }
        })
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        ComparisonType = 'ADAnalyzerAssessmentComparison'
        ReferenceRunId = Get-ADAnalyzerOperationValue $before @('RunId')
        DifferenceRunId = Get-ADAnalyzerOperationValue $after @('RunId')
        Timestamp = [datetimeoffset]::UtcNow.ToString('o')
        Changes = $changes
        Summary = [pscustomobject]@{
            New = @($changes | Where-Object Change -eq 'New').Count
            Resolved = @($changes | Where-Object Change -eq 'Resolved').Count
            Changed = @($changes | Where-Object Change -eq 'Changed').Count
            Unchanged = @($changes | Where-Object Change -eq 'Unchanged').Count
        }
    }
'@
    }
}

function Get-ComparableFixtureResult($Result) {
    $parsed = [datetimeoffset]::MinValue
    Assert-Fixture (
        $Result.Timestamp -is [string] -and [datetimeoffset]::TryParseExact(
            $Result.Timestamp,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$parsed
        ) -and $parsed.Offset -eq [timespan]::Zero
    ) 'The comparison timestamp was not a UTC round-trip string.'
    $copy = $Result.PSObject.Copy()
    $copy.Timestamp = '<comparison UTC>'
    return $copy
}

function New-NativeComparisonCase([string]$Scenario) {
    $pair = New-ComparisonPair
    switch ($Scenario) {
        'BadReference' {
            $path = Join-Path $fixtureDirectory 'malformed [reference].json'
            [IO.File]::WriteAllText($path, '{invalid', [Text.UTF8Encoding]::new($false))
            $pair.Reference = $path
            $pair.Difference.SchemaVersion = 2
        }
        'BadDifference' {
            $pair.Reference | Add-Member -MemberType ScriptProperty -Name Target -Force -Value {
                $script:comparisonTrace.Add('Reference.Target')
                'domain.fixture.invalid'
            }
            $path = Join-Path $fixtureDirectory 'malformed [difference].json'
            [IO.File]::WriteAllText($path, '{invalid', [Text.UTF8Encoding]::new($false))
            $pair.Difference = $path
        }
        'TargetMismatch' {
            $pair.Difference.Target = 'different.fixture.invalid'
            $pair.Reference | Add-Member -MemberType ScriptProperty -Name Context -Force -Value {
                $script:comparisonTrace.Add('Reference.Context')
                @{ SearchBase = 'OU=Unused' }
            }
        }
        'SearchBaseMismatch' {
            $pair.Difference.Context.SearchBase = 'OU=Different'
            $pair.Reference | Add-Member -MemberType ScriptProperty -Name Checks -Force -Value {
                $script:comparisonTrace.Add('Reference.Checks')
                @()
            }
        }
        'MissingRule' {
            $pair.Reference.Checks[0].PSObject.Properties.Remove('RuleId')
        }
        'ThrowingGetter' {
            $pair.Reference.Checks[0].Evidence | Add-Member -MemberType ScriptProperty -Name Failed -Value {
                $script:comparisonTrace.Add('Reference.Evidence.Failed')
                throw [InvalidOperationException]::new('fixture evidence getter')
            }
        }
        'BucketSerializer' {
            $pair.Reference.Checks[0].Evidence.Data = 'compare-serialize-reference'
            $pair.Difference.Checks[0].Evidence.Data = 'compare-serialize-difference'
        }
        'LazyGetters' {
            $pair.Reference | Add-Member -MemberType ScriptProperty -Name Target -Force -Value {
                $script:comparisonTrace.Add('Reference.Target')
                'domain.fixture.invalid'
            }
            $pair.Difference | Add-Member -MemberType ScriptProperty -Name Target -Force -Value {
                $script:comparisonTrace.Add('Difference.Target')
                'domain.fixture.invalid'
            }
            $pair.Reference | Add-Member -MemberType ScriptProperty -Name Context -Force -Value {
                $script:comparisonTrace.Add('Reference.Context')
                @{ SearchBase = 'OU=Fixture,DC=domain,DC=fixture,DC=invalid' }
            }
            $pair.Difference | Add-Member -MemberType ScriptProperty -Name Context -Force -Value {
                $script:comparisonTrace.Add('Difference.Context')
                @{ SearchBase = 'OU=Fixture,DC=domain,DC=fixture,DC=invalid' }
            }
            $pair.Reference | Add-Member -MemberType ScriptProperty -Name Findings -Value {
                $script:comparisonTrace.Add('Reference.Findings')
                throw 'An unused fallback getter was observed.'
            }
        }
    }
    return $pair
}

function Invoke-FixtureNativeComparison([string]$Scenario, [string]$Action) {
    Set-StrictMode -Version Latest
    $script:comparisonTrace = [Collections.Generic.List[string]]::new()
    $pair = New-NativeComparisonCase $Scenario

    function ConvertTo-Json {
        [CmdletBinding()]
        param([Parameter(Mandatory)][AllowNull()]$InputObject, [int]$Depth, [switch]$Compress)

        if ($Scenario -eq 'BucketSerializer' -and $InputObject -is [array] -and
            $InputObject.Count -eq 1 -and $InputObject[0] -is [string]) {
            if ($InputObject[0].Contains('compare-serialize-reference')) {
                $script:comparisonTrace.Add('Serialize.ReferenceBucket')
                Write-Error -Message 'fixture reference bucket write failure' -ErrorId 'Fixture.CompareSerialize'
                return
            }
            if ($InputObject[0].Contains('compare-serialize-difference')) {
                $script:comparisonTrace.Add('Serialize.DifferenceBucket')
            }
        }
        Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
    }

    $captured = [Collections.ArrayList]::new()
    $items = [Collections.Generic.List[object]]::new()
    $caught = $null
    $completed = $false
    $ErrorActionPreference = 'Stop'
    $Error.Clear()
    try {
        if ($Scenario -eq 'NormalizerBinding') {
            $normalizerInputs = @(
                @{
                    Field = 'PolicySequence'
                    Value = @()
                }
                @{
                    Field = 'PolicySequence'
                    Value = @('single')
                }
                @{
                    Field = 'PolicySequence'
                    Value = @('later', 'first', 'later')
                }
                @{
                    Field = 'Members'
                    Value = @('later', 'first', 'later')
                }
            )
            foreach ($inputCase in $normalizerInputs) {
                $result = @(ConvertTo-ADAnalyzerComparableValue -Value $inputCase.Value -Field $inputCase.Field)
                Assert-Fixture (
                    $result.Count -eq 1 -and $result[0] -is [array]
                ) 'The compatible normalizer must emit each array as one item.'
                $items.Add([pscustomobject]@{
                        Type = $result[0].GetType().FullName
                        Value = $result[0]
                    })
            }
        }
        else {
            Compare-ADAnalyzerAssessment -Reference $pair.Reference -Difference $pair.Difference -ErrorAction $Action -ErrorVariable +captured *>&1 |
                ForEach-Object {
                    $items.Add($_)
                }
        }
        $completed = $true
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    $observation = [ordered]@{
        Completed = $completed
        Caught = Get-FixtureDiagnostic $caught
        Captured = Get-FixtureDiagnostic $captured
        History = Get-FixtureDiagnostic $history
        Trace = $script:comparisonTrace.ToArray()
        Stream = @(
            foreach ($item in $items) {
                if ($null -eq $item) {
                    [ordered]@{
                        Type = 'Null'
                    }
                }
                elseif ($item -is [Management.Automation.ErrorRecord]) {
                    Get-FixtureDiagnostic $item
                }
                elseif ($item -is [Management.Automation.InformationalRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = $item.Message
                    }
                }
                elseif ($item -is [Management.Automation.InformationRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = $item.MessageData
                    }
                }
                elseif ($null -ne $item.PSObject.Properties['ComparisonType']) {
                    Get-ComparableFixtureResult $item
                }
                else {
                    $item
                }
            }
        )
    }
    return (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $observation -Depth 30 -Compress)
}

function Assert-FixtureNativeComparison([string]$Scenario, [string]$Action) {
    $originals = [ordered]@{}
    try {
        foreach ($name in $script:acceptedComparerBodies.Keys) {
            $path = 'Function:script:' + $name
            $originals[$name] = (Get-Command $name -CommandType Function).ScriptBlock
            $accepted = [scriptblock]::Create($script:acceptedComparerBodies[$name])
            Set-Item -LiteralPath $path -Value $accepted
            $active = (Get-Command $name -CommandType Function).ScriptBlock
            Assert-Fixture ($active.ToString() -ceq $accepted.ToString()) ('Failed to install archived ' + $name + '.')
        }
        $expected = Invoke-FixtureNativeComparison $Scenario $Action
    }
    finally {
        foreach ($name in $originals.Keys) {
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $originals[$name]
        }
    }
    foreach ($name in $originals.Keys) {
        $active = (Get-Command $name -CommandType Function).ScriptBlock
        Assert-Fixture ($active.ToString() -ceq $originals[$name].ToString()) ('Failed to restore candidate ' + $name + '.')
    }

    $actual = Invoke-FixtureNativeComparison $Scenario $Action
    if ($Scenario -eq 'BucketSerializer' -and $Action -ne 'Ignore') {
        Assert-Fixture (
            $expected.Contains('Fixture.CompareSerialize')
        ) 'The accepted comparison did not reach the native bucket serializer fault.'
    }
    if ($Scenario -eq 'ThrowingGetter' -and $Action -ne 'Ignore') {
        Assert-Fixture (
            $expected.Contains('Reference.Evidence.Failed')
        ) 'The accepted comparison did not reach the input evidence getter.'
    }
    if ($Scenario -eq 'MissingRule') {
        Assert-Fixture (
            $expected.Contains('A snapshot finding is missing RuleId')
        ) 'The accepted comparison did not reach the native missing-rule error.'
    }
    if ($Scenario -eq 'LazyGetters') {
        $trace = (ConvertFrom-Json -InputObject $expected).Trace -join ','
        Assert-Fixture (
            $trace -ceq 'Reference.Target,Difference.Target,Reference.Context,Difference.Context'
        ) ('The accepted lazy lookup fixture did not run its exact getters: ' + $trace)
    }
    if ($Scenario -eq 'NormalizerBinding') {
        $control = ConvertFrom-Json -InputObject $expected
        Assert-Fixture (
            $control.Completed -and $control.Stream.Count -eq 4 -and $null -eq $control.Caught
        ) 'The accepted normalizer did not return every cardinality control.'
    }
    Assert-Fixture ($actual -ceq $expected) (
        "Native comparison changed for $Scenario with ErrorAction=$Action." + [Environment]::NewLine +
        'Accepted: ' + $expected + [Environment]::NewLine + 'Current: ' + $actual
    )
}


function Invoke-DirectComparisonFixtures {
    $nativeCompare = (Get-Command Compare-ADAnalyzerAssessment -CommandType Function).ScriptBlock
    function script:Compare-ADAnalyzerAssessment {
        throw 'Direct comparison called the compatibility command.'
    }
    $comparer = [ADAnalyzerAssessmentComparer]::new()

    Test-Fixture 'comparison preserves all four statuses and ordered duplicate buckets' {
        $pair = New-ComparisonPair
        $pair.Reference.Checks = @(
            New-ComparisonFinding 'FIXTURE.MISSING' 'missing subject' 'Fail' $null
            New-ComparisonFinding 'FIXTURE.RESOLVED' 'resolved subject' 'Fail' @{ Tie = 1 }
            New-ComparisonFinding 'FIXTURE.RESOLVED' 'resolved subject' 'Unknown' @{ Tie = 2 }
            New-ComparisonFinding 'FIXTURE.UNCHANGED' 'unchanged subject' 'Pass' @()
        )
        $pair.Difference.Checks = @(
            New-ComparisonFinding 'FIXTURE.UNCHANGED' 'unchanged subject' 'Pass' @()
            New-ComparisonFinding 'FIXTURE.RESOLVED' 'resolved subject' 'Pass' @{ Tie = 3 }
            New-ComparisonFinding 'FIXTURE.NEW' 'new subject' 'Fail' $null
        )
        $expected = & $nativeCompare @pair
        $actual = $comparer.Compare($pair.Reference, $pair.Difference)
        $baseline = ConvertTo-Json -InputObject (Get-ComparableFixtureResult $expected) -Depth 30 -Compress
        $comparison = ConvertTo-Json -InputObject (Get-ComparableFixtureResult $actual) -Depth 30 -Compress
        Assert-Fixture (
            $comparison -ceq $baseline -and $actual.Changes.Count -eq 4 -and
            ($actual.Changes.RuleId -join ',') -ceq 'FIXTURE.MISSING,FIXTURE.NEW,FIXTURE.RESOLVED,FIXTURE.UNCHANGED' -and
            $actual.Summary.New -eq 1 -and $actual.Summary.Resolved -eq 1 -and
            $actual.Summary.Changed -eq 1 -and $actual.Summary.Unchanged -eq 1
        ) 'The direct route changed status precedence, ordering, or comparison schema.'
        Assert-Fixture (
            $actual.Changes[0].Reason -ceq 'NotObservedInDifference' -and
            $actual.Changes[0].Difference.Count -eq 0 -and
            ($actual.Changes[2].Reference.Evidence.Tie -join ',') -ceq '1,2'
        ) 'The direct route changed missing-observation semantics or duplicate row order.'
    }

    Test-Fixture 'StrictMode retains empty records, multisets and ordered sequences' {
        Set-StrictMode -Version Latest
        $pair = New-ComparisonPair
        $pair.Reference.Checks[0].Evidence = [ordered]@{
            Keys = 'literal keys field'
            Empty = [pscustomobject]@{}
            Members = @('duplicate', @{}, 'duplicate')
            PolicySequence = @('before', 'after')
            ObservedAt = 'earlier'
        }
        $pair.Difference.Checks[0].Evidence = [ordered]@{
            Keys = 'literal keys field'
            Empty = @{}
            Members = @('duplicate', 'duplicate', [pscustomobject]@{})
            PolicySequence = @('before', 'after')
            ObservedAt = 'later'
        }
        $same = $comparer.Compare($pair.Reference, $pair.Difference)
        Assert-Fixture (
            $same.Changes[0].Change -ceq 'Unchanged' -and
            $same.Changes[0].Reference[0].Evidence.Keys -ceq 'literal keys field' -and
            $same.Changes[0].Reference[0].Evidence.Members.Count -eq 3
        ) 'Comparable preparation lost empty evidence, duplicate multiset data, or real dictionary keys.'
        $pair.Difference.Checks[0].Evidence.PolicySequence = @('after', 'before')
        $changed = $comparer.Compare($pair.Reference, $pair.Difference)
        Assert-Fixture ($changed.Changes[0].Change -ceq 'Changed') 'An ordered sequence was normalized as a set.'
    }

    Test-Fixture 'legacy rule aliases and literal named-host identities stay separate' {
        $pair = New-ComparisonPair
        $legacy = [pscustomobject]@{
            Finding = 'Defect - User Inactivity'
            DistinguishedName = 'CN=Fixture'
            Status = 'Pass'
        }
        $first = New-ComparisonFinding 'HOST.REGISTRY' 'fixture/Registry/shared' 'Fail' @{
            ProfileRuleId = 'shared'
            RegistryPath = 'SYSTEM\Fixture'
            ValueName = 'part/Enabled'
        }
        $second = New-ComparisonFinding 'HOST.REGISTRY' 'fixture/Registry/shared' 'Pass' @{
            ProfileRuleId = 'shared'
            RegistryPath = 'SYSTEM\Fixture/part'
            ValueName = 'Enabled'
        }
        $pair.Reference.Checks = @($legacy, $first, $second)
        $pair.Difference.Checks = @($legacy, $second)
        $comparison = $comparer.Compare($pair.Reference, $pair.Difference)
        $gaps = @($comparison.Changes | Where-Object Reason -CEQ 'NotObservedInDifference')
        Assert-Fixture (
            $comparison.Changes.Count -eq 3 -and $comparison.Changes[0].RuleId -ceq 'ACCOUNT.INACTIVE' -and
            $comparison.Changes[0].Target -ceq 'CN=Fixture' -and $comparison.Summary.Unchanged -eq 2 -and
            $gaps.Count -eq 1 -and $gaps[0].Reference[0].Evidence.ValueName -ceq 'part/Enabled'
        ) 'Legacy fallback or a named host literal registry identity changed.'
    }

    Test-Fixture 'object, literal file and mixed inputs share comparable shapes' {
        $pair = New-ComparisonPair
        $oldPath = Join-Path $fixtureDirectory 'reference [literal].json'
        $newPath = Join-Path $fixtureDirectory 'difference [literal].json'
        $encoding = [Text.UTF8Encoding]::new($true)
        [IO.File]::WriteAllText($oldPath, (ConvertTo-Json -InputObject @($pair.Reference) -Depth 12), $encoding)
        [IO.File]::WriteAllText($newPath, (ConvertTo-Json -InputObject $pair.Difference -Depth 12), $encoding)
        $oldBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldPath))
        $newBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($newPath))

        $expected = & $nativeCompare @pair
        $baseline = ConvertTo-Json -InputObject (Get-ComparableFixtureResult $expected) -Depth 25 -Compress
        $routes = @(
            $comparer.Compare($pair.Reference, $pair.Difference)
            $comparer.Compare($oldPath, $newPath)
            $comparer.Compare($pair.Reference, $newPath)
        )
        foreach ($route in $routes) {
            $actual = ConvertTo-Json -InputObject (Get-ComparableFixtureResult $route) -Depth 25 -Compress
            Assert-Fixture ($actual -ceq $baseline) 'A literal file or mixed route changed comparison output.'
        }
        Assert-Fixture (
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldPath)) -ceq $oldBytes -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($newPath)) -ceq $newBytes
        ) 'A comparison changed its input file.'
    }

    Test-Fixture 'invalid inputs retain reader and context causes without effects' {
        $pair = New-ComparisonPair
        $bad = Join-Path $fixtureDirectory 'bad [literal].json'
        [IO.File]::WriteAllText($bad, '{invalid', [Text.UTF8Encoding]::new($false))
        $files = [IO.Directory]::GetFiles($fixtureDirectory).Count
        $failure = Get-FixtureFailure {
            $comparer.Compare($bad, @{ SchemaVersion = 2 })
        }
        Assert-Fixture (
            $failure.FullyQualifiedErrorId -like '*ConvertFromJson*' -or
            $failure.Exception.GetBaseException().GetType().FullName -like '*Json*'
        ) 'The invalid difference replaced the meaningful reference parser diagnostic.'
        $pair.Difference.Context.SearchBase = 'OU=Elsewhere'
        $scope = Get-FixtureFailure {
            $comparer.Compare($pair.Reference, $pair.Difference)
        }
        Assert-Fixture (
            $scope.Exception.GetBaseException().Message -like '*different search-base scopes*' -and
            [IO.Directory]::GetFiles($fixtureDirectory).Count -eq $files
        ) 'An incompatible scope lost its diagnostic or changed a file.'
    }

    Test-Fixture 'comparison exposes detached presence-only result rows' {
        $pair = New-ComparisonPair
        $pair.Reference.Checks[0].Evidence | Add-Member -NotePropertyName Password -NotePropertyValue 'COMPARE_FIXTURE_VALUE'
        $pair.Difference.Checks[0].Evidence | Add-Member -NotePropertyName Password -NotePropertyValue 'COMPARE_FIXTURE_VALUE'
        $before = ConvertTo-Json -InputObject $pair -Depth 20 -Compress
        $value = $comparer.Compare($pair.Reference, $pair.Difference)
        $exported = ConvertTo-Json -InputObject $value -Depth 20 -Compress
        Assert-Fixture (
            $value.Changes[0].Reference[0].Evidence.PasswordPresent -eq $true -and
            $value.Changes[0].Difference[0].Evidence.PasswordPresent -eq $true -and
            $exported -notlike '*COMPARE_FIXTURE_VALUE*' -and
            -not [object]::ReferenceEquals($pair.Reference.Checks[0], $value.Changes[0].Reference[0])
        ) 'A comparison exposed a fixture value or reused caller-owned data.'
        $value.Changes[0].Reference[0].Evidence.Data = 'changed return'
        Assert-Fixture (
            (ConvertTo-Json -InputObject $pair -Depth 20 -Compress) -ceq $before -and
            $value.Changes[0].Difference[0].Evidence.Data -ceq 'observed'
        ) 'The comparison rows retained shared mutable state.'
    }

    Test-Fixture 'comparison preserves scalar run IDs and detaches structured metadata' {
        $pair = New-ComparisonPair
        $identifier = [guid]'77777777-7777-7777-7777-777777777777'
        $pair.Reference.RunId = $identifier
        $pair.Difference.RunId = 'string run identifier'
        $ordinary = $comparer.Compare($pair.Reference, $pair.Difference)
        Assert-Fixture (
            $ordinary.ReferenceRunId -is [guid] -and $ordinary.ReferenceRunId -eq $identifier -and
            $ordinary.DifferenceRunId -is [string] -and $ordinary.DifferenceRunId -ceq 'string run identifier' -and
            $ordinary.Summary.Unchanged -eq 1
        ) 'Supported run ID values or the ordinary comparison changed.'

        $structured = [pscustomobject]@{
            Metadata = [pscustomobject]@{
                Label = 'ordinary run metadata'
                Password = 'COMPARER_RUN_ID_FIXTURE_VALUE'
            }
        }
        $pair.Reference.RunId = $structured
        $pair.Difference.RunId = $structured
        $comparison = $comparer.Compare($pair.Reference, $pair.Difference)
        $json = ConvertTo-Json -InputObject $comparison -Depth 20 -Compress
        Assert-Fixture (
            $comparison.ReferenceRunId.Metadata.PasswordPresent -eq $true -and
            $comparison.DifferenceRunId.Metadata.PasswordPresent -eq $true -and
            $comparison.ReferenceRunId.Metadata.Label -ceq 'ordinary run metadata' -and
            $json -notlike '*COMPARER_RUN_ID_FIXTURE_VALUE*' -and
            -not [object]::ReferenceEquals($structured, $comparison.ReferenceRunId) -and
            -not [object]::ReferenceEquals($structured, $comparison.DifferenceRunId)
        ) 'Structured run metadata exposed a fixture value or a caller-owned object.'
        $comparison.ReferenceRunId.Metadata.Label = 'changed result'
        Assert-Fixture (
            $structured.Metadata.Label -ceq 'ordinary run metadata' -and
            $structured.Metadata.Password -ceq 'COMPARER_RUN_ID_FIXTURE_VALUE' -and
            $comparison.DifferenceRunId.Metadata.Label -ceq 'ordinary run metadata'
        ) 'The result retained shared mutable run metadata.'
    }
}

$fixtureDirectory = $null
if ($Case -ne 'Construction') {
    $fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ('comparer-fixture-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($fixtureDirectory)
}
try {
    switch ($Case) {
        'Native' {
            $faults = @(
                'BadReference', 'BadDifference', 'TargetMismatch', 'SearchBaseMismatch',
                'MissingRule', 'ThrowingGetter', 'BucketSerializer'
            )
            foreach ($scenario in $faults) {
                foreach ($action in 'Continue', 'Stop') {
                    Test-Fixture ($scenario + ' ' + $action) {
                        Assert-FixtureNativeComparison $scenario $action
                    }
                }
            }
            foreach ($scenario in 'BadReference', 'ThrowingGetter', 'BucketSerializer') {
                foreach ($action in 'SilentlyContinue', 'Ignore') {
                    Test-Fixture ($scenario + ' ' + $action) {
                        Assert-FixtureNativeComparison $scenario $action
                    }
                }
            }
            foreach ($scenario in 'NormalizerBinding', 'LazyGetters') {
                Test-Fixture $scenario {
                    Assert-FixtureNativeComparison $scenario 'Stop'
                }
            }
        }

        'Construction' {
            Test-Fixture 'documented literal construction is inert' {
                function script:Test-Path {
                    throw 'The comparer constructor inspected a path.'
                }
                function script:Read-ADAnalyzerOperationDocument {
                    throw 'The comparer constructor read an operation document.'
                }
                $first = [ADAnalyzerAssessmentComparer]::new()
                $second = [ADAnalyzerAssessmentComparer]::new()
                Assert-Fixture (
                    $first.GetType().Name -ceq 'ADAnalyzerAssessmentComparer' -and
                    -not [object]::ReferenceEquals($first, $second)
                ) 'The documented loader did not expose an inert literal comparer.'
            }
            Test-Fixture 'documented comparison method' {
                $type = [ADAnalyzerAssessmentComparer]
                Assert-Fixture (
                    $null -ne $type.GetMethod('Compare', [type[]]@([object], [object]))
                ) 'The documented Compare method is missing.'
            }
        }

        'Standalone' {
            Test-Fixture 'operations alone can compare ordinary in-memory snapshots' {
                $pair = New-ComparisonPair
                $actual = [ADAnalyzerAssessmentComparer]::new().Compare($pair.Reference, $pair.Difference)
                Assert-Fixture (
                    $actual.ComparisonType -ceq 'ADAnalyzerAssessmentComparison' -and
                    $actual.Summary.Unchanged -eq 1
                ) 'The standalone operations file requires the full loader for an ordinary comparison.'
            }
        }

        'Direct' {
            Invoke-DirectComparisonFixtures
        }

        'Isolation' {
            Test-Fixture 'independent and reused instances do not retain old inputs or failures' {
                $first = [ADAnalyzerAssessmentComparer]::new()
                $second = [ADAnalyzerAssessmentComparer]::new()
                $pair = New-ComparisonPair
                $before = $first.Compare($pair.Reference, $pair.Difference)
                $pair.Difference.Checks[0].Evidence.Data = 'different'
                $secondResult = $second.Compare($pair.Reference, $pair.Difference)
                $null = Get-FixtureFailure {
                    $first.Compare(@{ SchemaVersion = 2 }, $pair.Difference)
                }
                $after = $first.Compare($pair.Reference, $pair.Difference)
                Assert-Fixture (
                    $before.Summary.Unchanged -eq 1 -and $secondResult.Summary.Changed -eq 1 -and
                    $after.Summary.Changed -eq 1 -and $before.Changes[0].Difference[0].Evidence.Data -ceq 'observed'
                ) 'A reused comparer retained an old input, result, or failure.'
            }

            Test-Fixture 'same-source secondary runspace disposal preserves literal file comparison' {
                $pair = New-ComparisonPair
                $reference = Join-Path $fixtureDirectory 'runspace [reference].json'
                $difference = Join-Path $fixtureDirectory 'runspace [difference].json'
                $encoding = [Text.UTF8Encoding]::new($true)
                [IO.File]::WriteAllText($reference, (ConvertTo-Json -InputObject $pair.Reference -Depth 12), $encoding)
                [IO.File]::WriteAllText($difference, (ConvertTo-Json -InputObject $pair.Difference -Depth 12), $encoding)
                $comparer = [ADAnalyzerAssessmentComparer]::new()
                Assert-Fixture ($comparer.Compare($reference, $difference).Summary.Unchanged -eq 1) 'The main file comparison failed.'
                $worker = [powershell]::Create()
                try {
                    $snippet = @'
param($Root, $Reference, $Difference)
$ErrorActionPreference = 'Stop'
. (Join-Path $Root 'bin/ADOperations.ps1')
[ADAnalyzerAssessmentComparer]::new().Compare($Reference, $Difference).Summary.Unchanged
'@
                    $inside = @($worker.AddScript($snippet).AddArgument($RepositoryRoot).AddArgument($reference).AddArgument($difference).Invoke())
                    Assert-Fixture (
                        $inside.Count -eq 1 -and [int]$inside[0] -eq 1 -and $worker.Streams.Error.Count -eq 0
                    ) ('Secondary file comparison failed: ' + ($worker.Streams.Error -join [Environment]::NewLine))
                }
                finally {
                    $worker.Dispose()
                }
                Assert-Fixture (
                    $comparer.Compare($reference, $difference).Summary.Unchanged -eq 1 -and
                    (Compare-ADAnalyzerAssessment $reference $difference).Summary.Unchanged -eq 1
                ) 'Disposing the secondary runspace changed a comparison route.'
            }
        }
    }
}
finally {
    if ($null -ne $fixtureDirectory) {
        [IO.Directory]::Delete($fixtureDirectory, $true)
    }
}
'PASS assessment comparer ' + $Case + ' ' + $script:passed
