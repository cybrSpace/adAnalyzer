[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Records', 'Faults', 'Direct', 'Uncaught')]
    [string]$Case = 'Records',
    [ValidateSet('DelValsHiveFault', 'DeleteKeysHiveFault')]
    [string]$Fault = 'DelValsHiveFault',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'bin/ADAnalyzer.ps1')

# Exact corrected replay from accepted revision 6a767d0.
$script:OriginalReplay = @'
function Get-ADAnalyzerEffectiveRegistryRecords {
    param([object[]]$RegistrySettings)
    $state = @{}
    foreach ($row in @($RegistrySettings)) {
        # Native assignment can leave its destination unchanged after an error under Continue.
        $keyPath = $null
        $name = $null
        $keyPath = ([string]$row.Key).TrimEnd('\')
        $name = [string]$row.ValueName
        if ($null -eq $keyPath -or $null -eq $name) {
            continue
        }

        if ($name -match '^\*\*del\.(.*)$') {
            $state[(Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $Matches[1]))] = [pscustomobject]@{
                Hive = $row.Hive
                Key = $row.Key
                ValueName = $Matches[1]
                Value = $null
                Type = $row.Type
                Scope = $row.Scope
                Source = $row.Source
                Deleted = $true
            }
            continue
        }
        if ($name -ieq '**DeleteValues') {
            $data = $null
            $data = if ($row.Value -is [byte[]]) {
                [Text.Encoding]::Unicode.GetString($row.Value).TrimEnd([char]0)
            }
            else {
                [string]$row.Value
            }
            foreach ($entry in @($data -split ';' | Where-Object { $_ })) {
                $state[(Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $entry))] = [pscustomobject]@{
                    Hive = $row.Hive
                    Key = $row.Key
                    ValueName = $entry
                    Value = $null
                    Type = $row.Type
                    Scope = $row.Scope
                    Source = $row.Source
                    Deleted = $true
                }
            }
            continue
        }
        if ($name -ieq '**DelVals') {
            foreach ($key in @($state.Keys | Where-Object { $state[$_].Hive -ieq $row.Hive -and $state[$_].Key -ieq $row.Key })) {
                if ($null -ne $state[$key].PSObject.Properties['Value']) {
                    $state[$key].Value = $null
                }
                if ($null -ne $state[$key].PSObject.Properties['SecretPresent']) {
                    $state[$key].SecretPresent = $false
                }
                $state[$key].Deleted = $true
            }
            continue
        }
        if ($name -ieq '**DeleteKeys') {
            $data = $null
            $data = if ($row.Value -is [byte[]]) {
                [Text.Encoding]::Unicode.GetString($row.Value).TrimEnd([char]0)
            }
            else {
                [string]$row.Value
            }
            foreach ($entry in @($data -split ';' | Where-Object { $_ })) {
                $targetKey = $keyPath + '\' + $entry.TrimEnd('\')
                $prefix = $targetKey + '\'
                foreach ($key in @($state.Keys | Where-Object { $state[$_].Hive -ieq $row.Hive -and
                            ($state[$_].Key -ieq $targetKey -or
                            ([string]$state[$_].Key).StartsWith($prefix,
                                [StringComparison]::OrdinalIgnoreCase)) })) {
                    if ($null -ne $state[$key].PSObject.Properties['Value']) {
                        $state[$key].Value = $null
                    }
                    if ($null -ne $state[$key].PSObject.Properties['SecretPresent']) {
                        $state[$key].SecretPresent = $false
                    }
                    $state[$key].Deleted = $true
                }
            }
            continue
        }
        if ($name.StartsWith('**')) {
            continue
        }
        if (-not $row.KeyOnly) {
            $copy = [ordered]@{}
            foreach ($property in $row.PSObject.Properties) {
                $copy[$property.Name] = $property.Value
            }
            $copy.Deleted = $false
            $state[(Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $name))] = [pscustomobject]$copy
        }
    }
    $state.Values
}
'@
$script:OriginalReplayHash = '39260d5f01d3e9a6dd0a717f7dbc58aad2d32045a27c73a6e9bac416e9e1f4ca'

function Assert-RegistryReplay($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-RegistryReplayHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

Assert-RegistryReplay ((Get-RegistryReplayHash $script:OriginalReplay) -ieq $script:OriginalReplayHash) 'Frozen replay source hash changed.'

function Get-RegistryReplayDefinition([string]$Text) {
    $tokens = $null
    $errors = $null
    $program = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $definitions = @($program.EndBlock.Statements | Where-Object Name -ceq 'Get-ADAnalyzerEffectiveRegistryRecords')
    Assert-RegistryReplay ($errors.Count -eq 0 -and $definitions.Count -eq 1) 'Could not isolate the exact replay AST.'
    $definitions[0]
}

function Assert-RegistryReplayBinding {
    $frozen = Get-RegistryReplayDefinition $script:OriginalReplay
    $ast = (Get-Command Get-ADAnalyzerEffectiveRegistryRecords -CommandType Function).ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    Assert-RegistryReplay ((Get-RegistryReplayHash $ast.ParamBlock.Extent.Text) -ceq
        (Get-RegistryReplayHash $frozen.Body.ParamBlock.Extent.Text)) 'Replay parameter contract changed.'
}

function ConvertTo-RegistryReplayJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 16 -Compress
}

function Assert-RegistryReplaySame($Expected, $Actual, [string]$Label) {
    $before = ConvertTo-RegistryReplayJson $Expected
    $after = ConvertTo-RegistryReplayJson $Actual
    Assert-RegistryReplay ($before -ceq $after) "$Label differs. Expected $before; actual $after"
}

function Get-RegistryReplayTyped($Value) {
    if ($null -eq $Value) {
        return [pscustomobject]@{
            Type = '<null>'
            Content = $null
        }
    }
    $type = $Value.GetType().FullName
    if ($type -ceq 'System.Management.Automation.PSCustomObject') {
        $properties = @(
            foreach ($property in $Value.PSObject.Properties) {
                [pscustomobject]@{
                    Name = $property.Name
                    Data = Get-RegistryReplayTyped $property.Value
                }
            }
        )
        return [pscustomobject]@{
            Type = $type
            Fields = $properties
        }
    }
    if ($Value -is [Collections.IList]) {
        $items = @(foreach ($item in $Value) {
                Get-RegistryReplayTyped $item
            })
        return [pscustomobject]@{
            Type = $type
            Items = $items
        }
    }
    [pscustomobject]@{
        Type = $type
        Content = $Value
    }
}

if ($null -eq ('RegistryReplayFixtureIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Management.Automation;

public static class RegistryReplayFixtureIdentity
{
    public static bool SameProperty(PSObject input, PSObject output, string property)
    {
        return Object.ReferenceEquals(input.Properties[property].Value, output.Properties[property].Value);
    }
}
'@
}

function New-RegistryReplayRow([string]$Source, [string]$Key, [string]$Name, $Value, [string]$Hive = 'HKLM') {
    [pscustomobject][ordered]@{
        Hive = $Hive
        Key = $Key
        ValueName = $Name
        Type = 4
        Value = $Value
        Scope = 'Computer'
        Source = $Source
        KeyOnly = $false
    }
}

function New-RegistryReplayTracked([string]$Tag, [string]$Key, [string]$Name, $Value) {
    $raw = New-RegistryReplayRow "$Tag.pol" $Key $Name $Value
    $row = [pscustomobject]@{
        FixtureRaw = $raw
        FixtureTag = $Tag
    }
    foreach ($property in $raw.PSObject.Properties.Name) {
        $body = '$iteration = "none"; if ($null -ne $foreach -and $null -ne $foreach.Current) { $iteration = $foreach.Current.GetType().Name }; ' +
        '$item = "none"; if ($_ -is [string]) { $item = $_ }; ' +
        '$capture = "none"; if ($Matches -and $Matches[1]) { $capture = $Matches[1] }; ' +
        '$script:ReplayTrace.Add($this.FixtureTag + ":' + $property + ':" + $iteration + ":" + $item + ":" + $capture); ' +
        'return ,$this.FixtureRaw.PSObject.Properties["' + $property + '"].Value'
        $row.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new($property, [scriptblock]::Create($body)))
    }
    $row
}

$script:ReplayRecords = @(
    'Omitted', 'Null', 'Empty', 'SingleNull', 'Borrow', 'Tuples', 'Resurrection',
    'NamedLists', 'BroadExact', 'Subtree', 'Trace', 'CopyGetter'
)
$script:ReplayFaults = @('DelValsHiveFault', 'DeleteKeysHiveFault')

function New-RegistryReplaySample([string]$Name) {
    $rows = $null
    $borrowed = $null
    switch ($Name) {
        'Empty' {
            $rows = [object[]]@()
        }
        'SingleNull' {
            $rows = [object[]]::new(1)
        }
        'Borrow' {
            $value = [psobject]::AsPSObject([Collections.ArrayList]@('first', 17))
            $value.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new('FixtureMarker', 'raw wrapper'))
            $borrowed = [pscustomobject][ordered]@{
                Hive = 'HKLM'
                Key = 'Fixture\Base'
                Deleted = $true
                Value = $value
                Scope = 'Computer'
                Source = 'borrow.pol'
                ValueName = 'setting'
                Type = [long]7
                KeyOnly = $false
            }
            $keyOnly = New-RegistryReplayRow key-only.pol 'Fixture\Base' setting 100
            $keyOnly.KeyOnly = $true
            $rows = @($borrowed, $keyOnly, (New-RegistryReplayRow ignored.pol 'Fixture\Base' '**IgnoreMe' 200))
        }
        'Tuples' {
            $rows = @(
                (New-RegistryReplayRow replaced.pol 'Fixture\Base\' 'child\setting' 1)
                (New-RegistryReplayRow nested.pol 'Fixture\Base\child' setting 2)
                (New-RegistryReplayRow other-hive.pol 'Fixture\Base' 'child\setting' 3 HKCU)
                (New-RegistryReplayRow final.pol 'fixture\base' 'CHILD\setting' ([long]4))
            )
        }
        'Resurrection' {
            $rows = @(
                (New-RegistryReplayRow original.pol 'Fixture\Base' setting 1)
                (New-RegistryReplayRow tombstone.pol 'Fixture\Base\' '**del.setting' $null)
                (New-RegistryReplayRow resurrected.pol 'fixture\base' SETTING 2)
            )
        }
        'NamedLists' {
            $bytes = [Text.Encoding]::Unicode.GetBytes('absent; padded ;;' + [char]0 + [char]0)
            $rows = @(
                (New-RegistryReplayRow old.pol 'Fixture\Base' list 6)
                (New-RegistryReplayRow one.pol 'Fixture\Base' '**del.single' $null)
                (New-RegistryReplayRow list.pol 'Fixture\Base' '**DeleteValues' 'list;extra')
                (New-RegistryReplayRow bytes.pol 'Fixture\Base\' '**DeleteValues' $bytes)
                (New-RegistryReplayRow empty-name.pol 'Fixture\Base' '**del.' $null)
            )
        }
        'BroadExact' {
            $present = New-RegistryReplayRow exact.pol 'Fixture\Base' DefaultPassword $null
            $present.PSObject.Properties.Remove('Value')
            $present | Add-Member -NotePropertyName SecretPresent -NotePropertyValue $true
            $rows = @(
                $present
                (New-RegistryReplayRow raw-slash.pol 'Fixture\Base\' untouched 2)
                (New-RegistryReplayRow child.pol 'Fixture\Base\child' untouched 3)
                (New-RegistryReplayRow other-hive.pol 'Fixture\Base' untouched 4 HKCU)
                (New-RegistryReplayRow directive.pol 'Fixture\Base' '**DelVals' $null)
            )
        }
        'Subtree' {
            $payload = [Text.Encoding]::Unicode.GetBytes('leaf\' + [char]0)
            $rows = @(
                (New-RegistryReplayRow leaf.pol 'Fixture\Base\leaf' setting 1)
                (New-RegistryReplayRow deeper.pol 'Fixture\Base\leaf\child' setting 2)
                (New-RegistryReplayRow adjacent.pol 'Fixture\Base\leaflet' setting 3)
                (New-RegistryReplayRow parent.pol 'Fixture\Base' 'leaf\setting' 4)
                (New-RegistryReplayRow other-hive.pol 'Fixture\Base\leaf' setting 5 HKCU)
                (New-RegistryReplayRow directive.pol 'Fixture\Base\' '**DeleteKeys' $payload)
            )
        }
        'Trace' {
            $rows = @(
                (New-RegistryReplayTracked write 'Fixture\Base\' setting 7)
                (New-RegistryReplayTracked named 'Fixture\Base' '**del.named' $null)
                (New-RegistryReplayTracked list 'Fixture\Base' '**DeleteValues' ([Text.Encoding]::Unicode.GetBytes('list' + [char]0)))
                (New-RegistryReplayTracked broad 'Fixture\Base' '**DelVals' $null)
                (New-RegistryReplayTracked subtree 'Fixture' '**DeleteKeys' 'Base')
            )
        }
        'CopyGetter' {
            $row = New-RegistryReplayRow fixture.pol 'Fixture\Base' setting 8
            $row.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('FaultingProperty', {
                        throw [InvalidOperationException]::new('fixture replay copy getter')
                    }))
            $row | Add-Member -NotePropertyName LaterProperty -NotePropertyValue 'later'
            $rows = @($row)
        }
        { $_ -in 'DelValsHiveFault', 'DeleteKeysHiveFault' } {
            $directive = '**DelVals'
            $data = $null
            if ($Name -eq 'DeleteKeysHiveFault') {
                $directive = '**DeleteKeys'
                $data = 'leaf'
            }
            $bad = New-RegistryReplayRow fault.pol 'Fixture\Base' $directive $data
            $bad.PSObject.Properties.Remove('Hive')
            $rows = @(
                (New-RegistryReplayRow first.pol 'Fixture\Base' setting 6)
                (New-RegistryReplayRow second.pol 'Fixture\Base\leaf' setting 8)
                $bad
                (New-RegistryReplayRow tail.pol 'Fixture\Tail' setting 9)
            )
        }
    }
    @{
        Rows = $rows
        Borrowed = $borrowed
    }
}

function Get-RegistryReplayDiagnostic([Management.Automation.ErrorRecord]$Item) {
    [pscustomobject][ordered]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Type = $Item.Exception.GetType().FullName
        Cause = $Item.Exception.GetBaseException().GetType().FullName
        Message = $Item.Exception.Message
        CauseMessage = $Item.Exception.GetBaseException().Message
    }
}

function Invoke-RegistryReplayCapture([string]$Name, [string]$Route, [string]$Action, [bool]$Caught, $Replay) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalReplay))
    }
    $sample = New-RegistryReplaySample $Name
    $strict = $Name -in $script:ReplayFaults
    $parameters = @{}
    if ($Name -ne 'Omitted') {
        $parameters.RegistrySettings = $sample.Rows
    }
    $before = $null
    if ($Name -eq 'Borrow') {
        $before = ConvertTo-RegistryReplayJson (Get-RegistryReplayTyped $sample.Borrowed)
    }
    $script:ReplayTrace = [Collections.Generic.List[string]]::new()
    $ErrorActionPreference = $Action
    $Matches = @{
        FixtureSentinel = 'caller-owned'
    }
    $Error.Clear()
    $stream = [Collections.Generic.List[object]]::new()
    $fault = $null
    $collect = { process {
            $stream.Add($_)
        } }
    $invoke = {
        if ($strict) {
            Set-StrictMode -Version Latest
        }
        if ($Route -eq 'Direct') {
            $Replay.Replay($sample.Rows)
        }
        else {
            Get-ADAnalyzerEffectiveRegistryRecords @parameters
        }
    }
    if ($Caught) {
        try {
            & $invoke 2>&1 | . $collect
        }
        catch {
            $fault = Get-RegistryReplayDiagnostic $_
        }
    }
    else {
        & $invoke 2>&1 | . $collect
    }
    $nativeErrors = @($Error | ForEach-Object { Get-RegistryReplayDiagnostic $_ })
    if ($Name -eq 'Borrow') {
        Assert-RegistryReplay ($stream.Count -eq 1 -and
            -not [object]::ReferenceEquals($sample.Borrowed, $stream[0]) -and
            [RegistryReplayFixtureIdentity]::SameProperty($sample.Borrowed,
                $stream[0],
                'Value')) 'Replay did not make a shallow fresh copy with the raw nested reference.'
        Assert-RegistryReplay ($before -ceq (ConvertTo-RegistryReplayJson (Get-RegistryReplayTyped $sample.Borrowed))) 'Replay changed the input row.'
    }
    $typed = @(
        foreach ($item in $stream) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                Get-RegistryReplayDiagnostic $item
            }
            else {
                Get-RegistryReplayTyped $item
            }
        }
    )
    [pscustomobject][ordered]@{
        Stream = $typed
        Caught = $fault
        Global = $nativeErrors
        Trace = $script:ReplayTrace.ToArray()
        CallerMatches = $Matches.FixtureSentinel
    }
}

function Get-RegistryReplayField($Row, [string]$Name) {
    foreach ($field in $Row.Fields) {
        if ($field.Name -ceq $Name) {
            return $field.Data
        }
    }
}

function Assert-RegistryReplayFacts($Record, [string]$Name) {
    Assert-RegistryReplay ($null -eq $Record.Caught -and
        $Record.CallerMatches -ceq 'caller-owned') "Unexpected successful replay state for $Name."
    $rows = $Record.Stream
    switch ($Name) {
        { $_ -in 'Omitted', 'Null', 'SingleNull' } {
            Assert-RegistryReplay ($rows.Count -eq 1 -and ($rows[0].Fields.Name -join ',') -ceq 'Deleted' -and
                (Get-RegistryReplayField $rows[0] Deleted).Content -eq $false) "Replay null behavior changed for $Name."
        }
        'Empty' {
            Assert-RegistryReplay ($rows.Count -eq 0) 'Empty input produced a row.'
        }
        'Borrow' {
            Assert-RegistryReplay (($rows[0].Fields.Name -join ',') -ceq 'Hive,Key,Deleted,Value,Scope,Source,ValueName,Type,KeyOnly' -and
                (Get-RegistryReplayField $rows[0] Deleted).Content -eq $false -and
                (Get-RegistryReplayField $rows[0] Type).Type -ceq 'System.Int64') 'Replay changed ordered record construction.'
        }
        'Tuples' {
            $origins = @($rows | ForEach-Object { (Get-RegistryReplayField $_ 'Source').Content })
            Assert-RegistryReplay ($rows.Count -eq 3 -and $origins -contains 'final.pol' -and
                $origins -contains 'nested.pol' -and
                $origins -contains 'other-hive.pol') 'Distinct tuples collided or normalized replacement failed.'
        }
        'Resurrection' {
            Assert-RegistryReplay ($rows.Count -eq 1 -and
                (Get-RegistryReplayField $rows[0] 'Source').Content -ceq 'resurrected.pol' -and
                (Get-RegistryReplayField $rows[0] 'Deleted').Content -eq $false) 'A replacement did not resurrect its tombstone.'
        }
        'NamedLists' {
            $names = @($rows | ForEach-Object { (Get-RegistryReplayField $_ 'ValueName').Content })
            $tombstones = @($rows | Where-Object { (Get-RegistryReplayField $_ 'Deleted').Content })
            Assert-RegistryReplay ($rows.Count -eq 6 -and $tombstones.Count -eq 6 -and
                $names -ccontains ' padded ' -and $names -ccontains '') 'Named replay lost a raw token or did not create a tombstone.'
        }
        { $_ -in 'BroadExact', 'Subtree' } {
            $deleted = @($rows | Where-Object { (Get-RegistryReplayField $_ 'Deleted').Content })
            if ($Name -eq 'BroadExact') {
                Assert-RegistryReplay ($rows.Count -eq 4 -and $deleted.Count -eq 1 -and
                    (Get-RegistryReplayField $deleted[0] 'Source').Content -ceq 'exact.pol' -and
                    (Get-RegistryReplayField $deleted[0] 'SecretPresent').Content -eq $false -and
                    $null -eq (Get-RegistryReplayField $deleted[0] 'Value')) 'Exact-key replay changed the target or invented a value.'
            }
            else {
                $names = @($deleted | ForEach-Object { (Get-RegistryReplayField $_ 'Source').Content })
                Assert-RegistryReplay ($rows.Count -eq 5 -and $deleted.Count -eq 2 -and
                    $names -contains 'leaf.pol' -and
                    $names -contains 'deeper.pol') 'Subtree replay ignored key-segment boundaries or the hive.'
            }
        }
        'Trace' {
            Assert-RegistryReplay (@($Record.Trace | Where-Object { $_ -like 'write:Key:PSCustomObject:*' }).Count -eq 1 -and
                @($Record.Trace | Where-Object { $_ -like 'write:Value:PSScriptProperty:*' }).Count -eq 1 -and
                @($Record.Trace | Where-Object { $_ -like 'named:Hive:*:named' }).Count -eq 2 -and
                @($Record.Trace | Where-Object { $_ -like 'list:Value:*' }).Count -eq 2 -and
                @($Record.Trace | Where-Object { $_ -like 'broad:Hive:*:4:HKLM*' }).Count -eq 3) 'Replay did not exercise the native getter scopes.'
        }
        'CopyGetter' {
            Assert-RegistryReplay ($rows.Count -eq 1 -and $Record.Global.Count -eq 1 -and
                $Record.Global[0].CauseMessage -ceq 'fixture replay copy getter' -and
                (Get-RegistryReplayField $rows[0] 'FaultingProperty').Type -ceq '<null>' -and
                (Get-RegistryReplayField $rows[0] 'LaterProperty').Content -ceq 'later') 'A throwing copied ScriptProperty did not exercise native recovery.'
        }
    }
}

function Invoke-RegistryReplayChild([string]$Name, [bool]$Frozen) {
    $engine = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Uncaught', '-Fault', $Name
    )
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
        Assert-RegistryReplay ((Get-FileHash `
                    -LiteralPath $path `
                    -Algorithm SHA256).Hash -ieq 'd277a59efecaecc576cbda057268c3b439b46410a270c00180d96c6f9a8e0068') 'Accepted U-088 policy file changed.'
        $body = Get-RegistryReplayDefinition ([IO.File]::ReadAllText($path))
        Assert-RegistryReplay ((Get-RegistryReplayHash $body.Extent.Text) -ieq $script:OriginalReplayHash) 'Accepted replay function changed.'
        $count = 2
    }
    { $_ -in 'Records', 'Direct' } {
        Assert-RegistryReplayBinding
        $route = 'Command'
        $service = $null
        if ($Case -eq 'Direct') {

            function Get-ADAnalyzerEffectiveRegistryRecords {
                throw 'Direct replay delegated to its compatibility command.'
            }
            $service = [ADAnalyzerRegistryPolicyReplay]::new()
            Assert-RegistryReplay (@($service.PSObject.Properties).Count -eq 0) 'Replay retains operation state.'
            $route = 'Direct'
        }
        foreach ($name in $script:ReplayRecords) {
            $expected = Invoke-RegistryReplayCapture $name 'Original' 'Stop' $true $null
            $actual = Invoke-RegistryReplayCapture $name $route 'Stop' $true $service
            Assert-RegistryReplayFacts $expected $name
            Assert-RegistryReplaySame $expected $actual "$Case/$name"
            $count++
        }
        if ($Case -eq 'Direct') {
            $independent = [ADAnalyzerRegistryPolicyReplay]::new()
            $rows = @($service.Replay([object[]]@()))
            $next = @($independent.Replay([object[]]@()))
            Assert-RegistryReplay ($rows.Count -eq 0 -and $next.Count -eq 0) 'Reused or independent replay retained earlier state.'
            $count++
            $failed = Invoke-RegistryReplayCapture 'DelValsHiveFault' 'Direct' 'Stop' $true $service
            Assert-RegistryReplay ($null -ne $failed.Caught -and $failed.Caught.CauseMessage -match 'Hive' -and
                $failed.Stream.Count -eq 0) 'Direct replay did not surface the missing Hive failure without rows.'
            $count++
        }
    }
    'Faults' {
        foreach ($name in $script:ReplayFaults) {
            foreach ($action in @('Continue', 'Stop')) {
                $expected = Invoke-RegistryReplayCapture $name 'Original' $action $true $null
                $actual = Invoke-RegistryReplayCapture $name 'Command' $action $true $null
                Assert-RegistryReplay ($null -ne $expected.Caught -and
                    $expected.Caught.Id -like 'PropertyNotFoundStrict*' -and
                    $expected.Stream.Count -eq 0) "Frozen caught replay did not terminate at $name."
                Assert-RegistryReplaySame $expected $actual "Caught $name/$action"
                $count++

                if ($action -eq 'Continue') {
                    $expected = Invoke-RegistryReplayCapture $name 'Original' $action $false $null
                    $actual = Invoke-RegistryReplayCapture $name 'Command' $action $false $null
                    $errors = @($expected.Stream | Where-Object Id -like 'PropertyNotFoundStrict*')
                    $tail = @($expected.Stream | Where-Object { (Get-RegistryReplayField $_ 'Source').Content -ceq 'tail.pol' })
                    Assert-RegistryReplay ($errors.Count -eq 2 -and
                        $tail.Count -eq 1) "Frozen Where did not emit both candidate errors and the tail for $name."
                }
                else {
                    $expected = Invoke-RegistryReplayChild $name $true
                    $actual = Invoke-RegistryReplayChild $name $false
                    Assert-RegistryReplay ($expected.Exit -ne 0 -and
                        $expected.Lines[0] -ceq "START $name" -and
                        ($expected.Lines -join ' ') -notmatch 'RETURNED|REPLAY-ROW') "Frozen uncaught replay Stop returned for $name."
                }
                Assert-RegistryReplaySame $expected $actual "Uncaught $name/$action"
                $count++
            }
        }
    }
    'Uncaught' {
        if ($Original) {
            . ([scriptblock]::Create($script:OriginalReplay))
        }
        $sample = New-RegistryReplaySample $Fault
        Set-StrictMode -Version Latest
        $ErrorView = 'CategoryView'
        Write-Output "START $Fault"
        Get-ADAnalyzerEffectiveRegistryRecords $sample.Rows | ForEach-Object { Write-Output 'REPLAY-ROW' }
        Write-Output 'RETURNED'
    }
}
Write-Host "PASS registry policy replay $Case $count"
