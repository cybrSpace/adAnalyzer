[CmdletBinding()]
param(
    [ValidateSet('Probe',
        'Controls',
        'Projection',
        'FaultChild',
        'Maps',
        'Getter',
        'Faults',
        'Profiles',
        'Exports',
        'Loading',
        'Uncaught',
        'Consumers',
        'Legacy')]
    [string]$Case = 'Projection',
    [ValidateSet('Continue', 'Stop')]
    [string]$Preference = 'Continue',
    [ValidateSet('Keys', 'Move', 'Current')]
    [string]$Failure = 'Keys'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ($Case -eq 'Legacy') {
    $null = [Reflection.Assembly]::LoadFrom((Join-Path $repositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
    $script:MetadataLegacyModule = Import-Module (Join-Path $repositoryRoot 'bin/ADEnvironment.psm1') -Force -PassThru
}
else {
    . (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
}
$script:MetadataScenarios = 0
$script:MetadataMarker = 'DICTIONARY_METADATA_FIXTURE_082'
$script:MetadataTrace = [Collections.Generic.List[string]]::new()

function Assert-Metadata($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-MetadataKeys($Map) {
    return ([Collections.IDictionary].GetProperty('Keys')).GetValue($Map, $null)
}

function New-MetadataMap([string]$Kind, [object[]]$Entries) {
    $map = switch ($Kind) {
        Hashtable {
            @{}
        }
        Ordered {
            [Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
        }
        Ordinal {
            [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
        }
        IgnoreCase {
            [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        }
    }
    foreach ($entry in $Entries) {
        $map.Add($entry.Name, $entry.Value)
    }
    return , $map
}

function Initialize-MetadataProbe {
    if ('ADAnalyzer.DictionaryFixture082.MapProbe' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;

namespace ADAnalyzer.DictionaryFixture082
{
    public class MapProbe : IDictionary
    {
        private readonly OrderedDictionary entries = new OrderedDictionary();
        public readonly List<string> Trace = new List<string>();
        public bool ThrowKeys;
        public bool ThrowMove;
        public bool ThrowCurrent;
        public int NativeKeyReads;
        public int ValueReads;
        public int ContainsReads;
        public int KeyEnumerators;
        public int KeyMoves;
        public int KeyCurrentReads;
        public int KeyDisposes;

        public object this[object key]
        {
            get
            {
                ValueReads++;
                Trace.Add("Value:" + Convert.ToString(key));
                return entries[key];
            }
            set
            {
                entries[key] = value;
            }
        }

        ICollection IDictionary.Keys
        {
            get
            {
                NativeKeyReads++;
                Trace.Add("Keys");
                if (ThrowKeys)
                {
                    throw new InvalidOperationException("Fixture native Keys failure.");
                }
                return new KeyCollection(this, SnapshotKeys());
            }
        }

        public object[] SnapshotKeys()
        {
            object[] result = new object[entries.Count];
            entries.Keys.CopyTo(result, 0);
            return result;
        }

        public object[] SnapshotValues()
        {
            object[] result = new object[entries.Count];
            entries.Values.CopyTo(result, 0);
            return result;
        }

        public bool Contains(object key)
        {
            ContainsReads++;
            Trace.Add("Contains:" + Convert.ToString(key));
            return entries.Contains(key);
        }

        public void Add(object key, object value)
        {
            entries.Add(key, value);
        }

        public void Clear()
        {
            entries.Clear();
        }

        public void Remove(object key)
        {
            entries.Remove(key);
        }

        public IDictionaryEnumerator GetEnumerator()
        {
            return entries.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        ICollection IDictionary.Values
        {
            get
            {
                return entries.Values;
            }
        }

        public int Count
        {
            get
            {
                return entries.Count;
            }
        }

        public bool IsReadOnly
        {
            get
            {
                return false;
            }
        }

        public bool IsFixedSize
        {
            get
            {
                return false;
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
            entries.CopyTo(array, index);
        }

        private sealed class KeyCollection : ICollection
        {
            private readonly MapProbe owner;
            private readonly object[] keys;

            internal KeyCollection(MapProbe owner, object[] keys)
            {
                this.owner = owner;
                this.keys = keys;
            }

            public int Count
            {
                get
                {
                    return keys.Length;
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
                keys.CopyTo(array, index);
            }

            public IEnumerator GetEnumerator()
            {
                owner.KeyEnumerators++;
                owner.Trace.Add("KeyEnumerator");
                return new Cursor(owner, keys);
            }
        }

        private sealed class Cursor : IEnumerator, IDisposable
        {
            private readonly MapProbe owner;
            private readonly object[] keys;
            private int index = -1;

            internal Cursor(MapProbe owner, object[] keys)
            {
                this.owner = owner;
                this.keys = keys;
            }

            public bool MoveNext()
            {
                owner.KeyMoves++;
                owner.Trace.Add("KeyMove");
                if (owner.ThrowMove && index == 0)
                {
                    throw new InvalidOperationException("Fixture native key MoveNext failure.");
                }
                return ++index < keys.Length;
            }

            public object Current
            {
                get
                {
                    owner.KeyCurrentReads++;
                    owner.Trace.Add("KeyCurrent");
                    if (owner.ThrowCurrent && index == 1)
                    {
                        throw new InvalidOperationException("Fixture native key Current failure.");
                    }
                    return keys[index];
                }
            }

            public void Reset()
            {
                index = -1;
            }

            public void Dispose()
            {
                owner.KeyDisposes++;
                owner.Trace.Add("KeyDispose");
            }
        }
    }

    public sealed class AdapterVisibleMap : MapProbe
    {
        public ICollection Keys
        {
            get
            {
                return ((IDictionary)this).Keys;
            }
        }
    }
}
'@
}

function New-MetadataProbe([string]$Failure, [bool]$Visible = $false) {
    $map = if ($Visible) {
        [ADAnalyzer.DictionaryFixture082.AdapterVisibleMap]::new()
    }
    else {
        [ADAnalyzer.DictionaryFixture082.MapProbe]::new()
    }
    $map.Add('Ordinary', 1)
    $map.Add('Password', $script:MetadataMarker)
    switch ($Failure) {
        Keys {
            $map.GetType().GetField('ThrowKeys').SetValue($map, $true)
        }
        Move {
            $map.GetType().GetField('ThrowMove').SetValue($map, $true)
        }
        Current {
            $map.GetType().GetField('ThrowCurrent').SetValue($map, $true)
        }
    }
    $names = $map.SnapshotKeys()
    Assert-Metadata (($names -join '|') -ceq 'Ordinary|Password') 'Fault configuration added a dictionary entry.'
    foreach ($field in @('NativeKeyReads', 'ValueReads', 'ContainsReads', 'KeyEnumerators', 'KeyMoves', 'KeyCurrentReads', 'KeyDisposes')) {
        Assert-Metadata ($map.GetType().GetField($field).GetValue($map) -eq 0) 'A fresh probe already has native activity.'
    }
    if ($Failure) {
        Assert-Metadata ($map.GetType().GetField('Throw' + $Failure).GetValue($map)) 'Native fault configuration did not take effect.'
    }
    return , $map
}

function Get-MetadataCounters($Map) {
    [pscustomobject][ordered]@{
        Keys = $Map.GetType().GetField('NativeKeyReads').GetValue($Map)
        Values = $Map.GetType().GetField('ValueReads').GetValue($Map)
        Contains = $Map.GetType().GetField('ContainsReads').GetValue($Map)
        Enumerators = $Map.GetType().GetField('KeyEnumerators').GetValue($Map)
        Moves = $Map.GetType().GetField('KeyMoves').GetValue($Map)
        Current = $Map.GetType().GetField('KeyCurrentReads').GetValue($Map)
        Disposes = $Map.GetType().GetField('KeyDisposes').GetValue($Map)
        Trace = @($Map.GetType().GetField('Trace').GetValue($Map))
    }
}

function Get-MetadataError($Record) {
    [pscustomobject][ordered]@{
        Type = $Record.Exception.GetType().FullName
        Cause = $Record.Exception.GetBaseException().GetType().FullName
        Message = $Record.Exception.Message
        CauseMessage = $Record.Exception.GetBaseException().Message
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Reason = $Record.CategoryInfo.Reason
        TargetType = if ($null -eq $Record.TargetObject) {
            '<null>'
        }
        else {
            $Record.TargetObject.GetType().FullName
        }
    }
}

function Get-MetadataFault([string]$Failure, [string]$Preference, [bool]$Direct, [bool]$Visible) {
    $map = New-MetadataProbe $Failure $Visible
    $saved = $ErrorActionPreference
    $rows = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()
    $caught = $false
    $Error.Clear()
    try {
        $ErrorActionPreference = $Preference
        try {
            & {
                if ($Direct) {
                    [ADAnalyzerEvidenceProjector]::new().Project($map)
                }
                else {
                    ConvertTo-ADAnalyzerSafeData -InputObject $map
                }
            } 2>&1 | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    $errors.Add((Get-MetadataError $_))
                }
                else {
                    $rows.Add($_)
                }
            }
        }
        catch {
            $caught = $true
            $errors.Add((Get-MetadataError $_))
        }
        $globalErrors = @($Error | ForEach-Object { Get-MetadataError $_ })
        $counters = Get-MetadataCounters $map
    }
    finally {
        $ErrorActionPreference = $saved
    }
    [pscustomobject][ordered]@{
        Failure = $Failure
        Preference = $Preference
        Direct = $Direct
        Visible = $Visible
        Caught = $caught
        Rows = $rows.ToArray()
        Errors = $errors.ToArray()
        GlobalErrors = $globalErrors
        Counters = $counters
    }
}

Initialize-MetadataProbe

# This path deliberately has no enclosing try. The parent captures its process.
if ($Case -eq 'FaultChild') {
    $map = New-MetadataProbe $Failure $true
    $tail = [pscustomobject]@{}
    $tail | Add-Member ScriptProperty Tail {
        $script:MetadataTrace.Add('Tail')
        3
    }
    $inputRows = [object[]]@([pscustomobject]@{
            Before = 1
        }, $map, $tail)
    $parameters = @{
        ErrorAction = $Preference
        ErrorVariable = '+metadataErrors'
        OutVariable = '+metadataOutput'
    }
    $metadataErrors = @('error-seed')
    $metadataOutput = @('output-seed')
    $Error.Clear()
    $ErrorActionPreference = 'Continue'
    Write-Output 'METADATA_BEGIN'
    $rows = @($inputRows | ConvertTo-ADAnalyzerSafeData @parameters)
    Write-Output 'METADATA_AFTER'
    $summary = [pscustomobject][ordered]@{
        Rows = $rows
        Output = $metadataOutput
        Errors = @($metadataErrors | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    Get-MetadataError $_
                }
                elseif ($_ -is [Exception]) {
                    [pscustomobject]@{
                        Type = $_.GetType().FullName
                        Message = $_.Message
                    }
                }
                else {
                    [string]$_
                }
            })
        GlobalErrors = @($Error | ForEach-Object { Get-MetadataError $_ })
        Trace = @($script:MetadataTrace)
        Counters = Get-MetadataCounters $map
    }
    Write-Output ('METADATA_SUMMARY ' + (ConvertTo-Json -InputObject $summary -Depth 40 -Compress))
    return
}

try {
    switch ($Case) {

        Maps {
            $service = [ADAnalyzerEvidenceProjector]::new()
            $payloads = @(
                @{
                    Value = $null
                },
                @{
                    Value = ''
                },
                @{
                    Value = $false
                },
                @{
                    Value = 'ordinary-key-value'
                },
                @{
                    Value = [object[]]@()
                },
                @{
                    Value = [object[]]@(7, 8)
                }
            )
            foreach ($kind in @('Hashtable', 'Ordered', 'Ordinal', 'IgnoreCase')) {
                foreach ($keyName in @('Keys', 'keys', 'KEYS')) {
                    foreach ($payload in $payloads) {
                        $map = New-MetadataMap $kind @(
                            @{
                                Name = $keyName
                                Value = $payload.Value
                            },
                            @{
                                Name = 'Ordinary'
                                Value = 3
                            },
                            @{
                                Name = 'Password'
                                Value = $script:MetadataMarker
                            }
                        )
                        $before = ConvertTo-Json -InputObject $map -Depth 30 -Compress
                        $names = @(Get-MetadataKeys $map)
                        $expectedNames = @($names | ForEach-Object {
                                if ($_ -ceq 'Password') {
                                    'PasswordPresent'
                                }
                                else {
                                    $_
                                }
                            })
                        foreach ($route in @('Command', 'Direct', 'Wrapped')) {
                            $actual = switch ($route) {
                                Command {
                                    ConvertTo-ADAnalyzerSafeData -InputObject $map
                                }
                                Direct {
                                    $service.Project($map)
                                }
                                Wrapped {
                                    $service.ProjectPowerShellObject([Management.Automation.PSObject]::AsPSObject($map))
                                }
                            }
                            Assert-Metadata (($actual.PSObject.Properties.Name -join '|') -ceq
                                ($expectedNames -join '|')) 'Native dictionary field order or completeness changed.'
                            Assert-Metadata ($actual.Ordinary -is [int] -and $actual.Ordinary -eq 3 -and
                                $actual.PasswordPresent -is [bool] -and
                                $actual.PasswordPresent) 'A real field or secret presence disappeared.'
                            $actualKey = $actual.PSObject.Properties[$keyName].Value
                            $expectedKey = $payload.Value
                            if ($null -eq $expectedKey) {
                                Assert-Metadata ($null -eq $actualKey) 'An explicit null Keys payload changed.'
                            }
                            else {
                                Assert-Metadata ($null -ne $actualKey -and
                                    $actualKey.GetType() -eq $expectedKey.GetType() -and
                                    (ConvertTo-Json -InputObject $actualKey -Depth 30 -Compress) -ceq
                                    (ConvertTo-Json `
                                        -InputObject $expectedKey `
                                        -Depth 30 `
                                        -Compress)) 'The Keys payload lost its value or native type.'
                            }
                            $actualJson = ConvertTo-Json -InputObject $actual -Depth 30 -Compress
                            Assert-Metadata (-not $actualJson.Contains($script:MetadataMarker)) 'A projected dictionary retained a secret value.'
                            Assert-Metadata ((ConvertTo-Json -InputObject ($service.Project($actual)) -Depth 30 -Compress) -ceq
                                $actualJson) 'Repeated native-key projection changed the result.'
                            $actual.Ordinary = 9
                            Assert-Metadata ($map['Ordinary'] -eq 3 -and
                                (ConvertTo-Json -InputObject $map -Depth 30 -Compress) -ceq $before) 'Projection mutated caller-owned data.'
                            $script:MetadataScenarios++
                        }
                        $raw = $service.GetValue($map, @($keyName))
                        if ($payload.Value -is [array]) {
                            Assert-Metadata ([object]::ReferenceEquals($raw,
                                    $payload.Value)) 'Direct raw lookup copied an intentionally borrowed value.'
                        }
                        else {
                            Assert-Metadata (($null -eq $raw -and $null -eq $payload.Value) -or
                                ($null -ne $raw -and $raw.GetType() -eq $payload.Value.GetType() -and
                                $raw -ceq $payload.Value)) 'Raw Keys lookup changed its value or type.'
                        }
                        $commandRows = @(Get-ADAnalyzerOperationValue $map @($keyName))
                        $expectedRows = @($payload.Value)
                        Assert-Metadata ((ConvertTo-Json -InputObject $commandRows -Depth 30 -Compress) -ceq
                            (ConvertTo-Json -InputObject $expectedRows -Depth 30 -Compress)) 'Raw Keys command cardinality changed.'
                    }
                }
            }
            $map = [ordered]@{
                Keys = $null
                Nested = [ordered]@{
                    Keys = $false
                    Password = $script:MetadataMarker
                }
            }
            $rows = @([object[]]@($map, $map) | ConvertTo-ADAnalyzerSafeData)
            Assert-Metadata ($rows.Count -eq 2 -and $rows[0].Nested.PasswordPresent -and
                $rows[1].Nested.PasswordPresent -and
                -not [object]::ReferenceEquals($rows[0],
                    $rows[1])) 'Pipeline or nested native-key projection lost records or isolated state.'
            $script:MetadataScenarios++
            $nonStringKey = [object]::new()
            $map = [Collections.Specialized.OrderedDictionary]::new()
            $map.Add($nonStringKey, 5)
            $map.Add('Keys', $null)
            $nativeNames = @(Get-MetadataKeys $map)
            Assert-Metadata ([object]::ReferenceEquals($nativeNames[0], $nonStringKey)) 'Native metadata converted a caller key object.'
            Assert-Metadata (($service.Project($map)).PSObject.Properties['System.Object'].Value -eq 5 -and
                $map[$nonStringKey] -eq 5) 'Non-string key processing failed or changed input.'
            $script:MetadataScenarios++
            Assert-Metadata (@($service.PSObject.Properties).Count -eq 0) 'The stateless projector retained dictionary data.'

            foreach ($kind in @('Hashtable', 'Ordered', 'Ordinal', 'IgnoreCase')) {
                $empty = New-MetadataMap $kind @()
                foreach ($route in @('Command', 'Direct', 'Wrapped')) {
                    $actual = switch ($route) {
                        Command {
                            ConvertTo-ADAnalyzerSafeData $empty
                        }
                        Direct {
                            $service.Project($empty)
                        }
                        Wrapped {
                            $service.ProjectPowerShellObject($empty)
                        }
                    }
                    Assert-Metadata ($actual -is [pscustomobject] -and
                        @($actual.PSObject.Properties).Count -eq 0 -and
                        (ConvertTo-Json -InputObject $actual -Compress) -ceq '{}') 'An empty native dictionary lost its object shape.'
                    $script:MetadataScenarios++
                }
            }
            Assert-Metadata ($script:MetadataScenarios -eq 230) 'Map discovery mismatch.'
        }
        Getter {
            foreach ($visible in @($false, $true)) {
                foreach ($route in @('Command', 'Direct', 'Wrapped')) {
                    $map = New-MetadataProbe '' $visible
                    $map.Add('Keys', $null)
                    $script:MetadataEtsReads = 0
                    $map | Add-Member -MemberType ScriptProperty -Name Keys -Force -Value {
                        $script:MetadataEtsReads++
                        throw 'An adapted Keys getter must not execute.'
                    }
                    $actual = switch ($route) {
                        Command {
                            ConvertTo-ADAnalyzerSafeData $map
                        }
                        Direct {
                            [ADAnalyzerEvidenceProjector]::new().Project($map)
                        }
                        Wrapped {
                            [ADAnalyzerEvidenceProjector]::new().ProjectPowerShellObject($map)
                        }
                    }
                    $counts = Get-MetadataCounters $map
                    Assert-Metadata ($counts.Keys -eq 1 -and $counts.Values -eq 3 -and
                        $counts.Enumerators -eq 1 -and $counts.Moves -eq 4 -and
                        $counts.Current -eq 3 -and
                        $script:MetadataEtsReads -eq 0) 'Native metadata was not read once, or an adapted getter executed.'
                    Assert-Metadata ($actual.PasswordPresent -and $actual.Ordinary -eq 1 -and
                        $null -ne $actual.PSObject.Properties['Keys']) 'Explicit native getter lost data.'
                    Assert-Metadata (($map.SnapshotKeys() -join '|') -ceq 'Ordinary|Password|Keys') 'Metadata access mutated the source map.'
                    $script:MetadataScenarios++
                }
            }
            Assert-Metadata ($script:MetadataScenarios -eq 6) 'Getter discovery mismatch.'
        }
        Faults {
            foreach ($failure in @('Keys', 'Move', 'Current')) {
                foreach ($preference in @('Continue', 'Stop')) {
                    foreach ($direct in @($false, $true)) {
                        foreach ($visible in @($false, $true)) {
                            $fact = Get-MetadataFault $failure $preference $direct $visible
                            Assert-Metadata ($fact.Caught -and $fact.Rows.Count -eq 0 -and
                                $fact.Errors.Count -eq 1 -and $fact.Errors[0].Cause -ceq 'System.InvalidOperationException' -and
                                $fact.Errors[0].CauseMessage.Contains('Fixture native') -and
                                $fact.Counters.Keys -eq 1 -and
                                $fact.Counters.Values -eq 0) 'A native metadata failure became false success or lost its cause.'
                            if ($failure -eq 'Keys') {
                                Assert-Metadata ($fact.Errors[0].Id -like 'InvalidOperationException*' -and
                                    $fact.Counters.Enumerators -eq 0) 'Getter failure changed its phase or classification.'
                            }
                            else {
                                Assert-Metadata ($fact.Errors[0].Id -like 'BadEnumeration*' -and
                                    $fact.Counters.Enumerators -eq 1 -and $fact.Counters.Moves -eq 2 -and
                                    $fact.Counters.Current -eq $(if ($failure -eq 'Move') {
                                            1
                                        }
                                        else {
                                            2
                                        })) 'Native enumeration failure changed its phase or classification.'
                            }
                            Assert-Metadata ($fact.GlobalErrors.Count -ge 1 -and
                                $fact.GlobalErrors[0].Cause -ceq 'System.InvalidOperationException') 'Native failure was omitted from error diagnostics.'
                            $script:MetadataScenarios++
                        }
                    }
                }
            }
            Assert-Metadata ($script:MetadataScenarios -eq 24) 'Fault discovery mismatch.'
        }
        Profiles {
            foreach ($kind in @('Hashtable', 'Ordered', 'Ordinal', 'IgnoreCase')) {
                foreach ($value in @(@{
                            Value = $null
                        }, @{
                            Value = ''
                        }, @{
                            Value = $false
                        })) {
                    $map = New-MetadataMap $kind @(@{
                            Name = 'Keys'
                            Value = $value.Value
                        })
                    foreach ($direct in @($false, $true)) {
                        $profileFailure = $null
                        try {
                            if ($direct) {
                                $null = [ADAnalyzerProfile]::new($map)
                            }
                            else {
                                $null = Import-ADAnalyzerProfile -Profile $map
                            }
                        }
                        catch {
                            $profileFailure = $_
                        }
                        Assert-Metadata ($null -ne $profileFailure -and
                            $profileFailure.Exception.Message.Contains('Unknown profile setting: Keys')) 'Profile validation failed to identify the actual unknown Keys setting.'
                        $script:MetadataScenarios++
                    }
                }
                $allowed = New-MetadataMap $kind @(@{
                        Name = 'Keys'
                        Value = @('S-1-5-18')
                    })
                $hashes = New-MetadataMap $kind @(@{
                        Name = 'Keys'
                        Value = ('a' * 64)
                    })
                $inputProfile = @{
                    Policy = @{
                        AllowedUserRightSids = $allowed
                    }
                    DependencyHashes = $hashes
                }
                $profile = [ADAnalyzerProfile]::new($inputProfile)
                $actual = $profile.ToHashtable()
                Assert-Metadata ($actual.Policy.AllowedUserRightSids['Keys'][0] -ceq 'S-1-5-18' -and
                    $actual.DependencyHashes['Keys'] -ceq ('a' * 64)) 'Supported arbitrary profile keys disappeared.'
                $actual.Policy.AllowedUserRightSids['Keys'][0] = 'changed'
                Assert-Metadata ($profile.ToHashtable().Policy.AllowedUserRightSids['Keys'][0] -ceq 'S-1-5-18' -and
                    $allowed['Keys'][0] -ceq 'S-1-5-18') 'Native-key normalization aliased configuration.'
                $script:MetadataScenarios++
            }
            Assert-Metadata ($script:MetadataScenarios -eq 28) 'Profile discovery mismatch.'
        }

        Exports {
            $script:MetadataWrites = [Collections.Generic.List[object]]::new()

            function Write-ADAnalyzerFile {
                param(
                    $Path,
                    [AllowEmptyString()][string]$Content

                )
                $script:MetadataWrites.Add([pscustomobject]@{
                        Path = $Path
                        Content = $Content
                    })
                return $Path
            }
            $evidence = [ordered]@{
                Keys = $null
                Ordinary = 3
                Password = $script:MetadataMarker
            }
            $coverage = [ordered]@{
                Keys = $null
                Directory = 'Collected'
            }
            $assessment = [pscustomobject]@{
                SchemaVersion = 1
                Target = 'fixture'
                Coverage = $coverage
                Findings = @([pscustomobject]@{
                        RuleId = 'FIXTURE'
                        Target = 'fixture'
                        Status = 'Fail'
                        Evidence = $evidence
                    })
            }
            $before = ConvertTo-Json -InputObject $assessment -Depth 40 -Compress
            foreach ($format in @('Json', 'Html', 'Csv', 'All')) {
                foreach ($action in @('Continue', 'Stop')) {
                    $script:MetadataWrites.Clear()
                    $parameters = @{
                        Assessment = $assessment
                        Path = 'memory-only-metadata'
                        Format = $format
                        Confirm = $false
                        ErrorAction = $action
                    }
                    $paths = @(Export-ADAnalyzerAssessment @parameters)
                    $expectedCount = if ($format -eq 'All') {
                        3
                    }
                    else {
                        1
                    }
                    Assert-Metadata ($paths.Count -eq $expectedCount -and
                        $script:MetadataWrites.Count -eq $expectedCount) 'Export did not execute every requested serializer.'
                    foreach ($write in $script:MetadataWrites) {
                        $text = [Net.WebUtility]::HtmlDecode($write.Content)
                        Assert-Metadata (-not $text.Contains($script:MetadataMarker) -and
                            $text.Contains('PasswordPresent') -and
                            $text.Contains('Ordinary')) 'Export lost real evidence or retained a secret value.'

                        $writtenKind = if ($format -eq 'All') {
                            [IO.Path]::GetExtension($write.Path).TrimStart('.')
                        }
                        else {
                            $format
                        }
                        $writtenEvidence = switch ($writtenKind) {
                            Json {
                                (ConvertFrom-Json -InputObject $write.Content).Findings[0].Evidence
                            }
                            Csv {
                                $csvRows = @(ConvertFrom-Csv -InputObject $write.Content)
                                Assert-Metadata ($csvRows.Count -eq 1) 'CSV export lost finding cardinality.'
                                ConvertFrom-Json -InputObject $csvRows[0].Evidence
                            }
                        }
                        if ($writtenKind -in @('Json', 'Csv')) {
                            Assert-Metadata ($writtenEvidence.PasswordPresent -is [bool] -and
                                $writtenEvidence.PasswordPresent -and $writtenEvidence.Ordinary -eq 3 -and
                                $null -ne $writtenEvidence.PSObject.Properties['Keys']) 'A serializer changed boolean presence or dropped dictionary evidence.'
                        }
                        if ($format -eq 'Html' -or $write.Path -like '*.html') {
                            Assert-Metadata ($text -match '"PasswordPresent"\s*:\s*true') 'HTML did not serialize boolean true presence.'
                            Assert-Metadata ($text.Contains('<td>Keys</td>') -and
                                $text.Contains('<td>Directory</td>') -and
                                -not $text.Contains('Coverage was not recorded.')) 'HTML coverage hid native dictionary fields.'
                        }
                    }
                    Assert-Metadata ((ConvertTo-Json -InputObject $assessment -Depth 40 -Compress) -ceq
                        $before) 'Export modified the supplied assessment.'
                    $script:MetadataScenarios++
                }
                $script:MetadataWrites.Clear()
                $null = Export-ADAnalyzerAssessment -Assessment $assessment -Path 'memory-only-metadata' -Format $format -WhatIf
                Assert-Metadata ($script:MetadataWrites.Count -eq 0) 'WhatIf invoked a file writer.'
                $script:MetadataScenarios++
            }
            $left = [ordered]@{
                Keys = $null
                Ordinary = 1
            }
            $right = [ordered]@{
                Keys = $null
                Ordinary = 2
            }
            $beforeLeft = ConvertTo-Json -InputObject $left -Compress
            $leftComparable = ConvertTo-ADAnalyzerComparableValue $left
            $rightComparable = ConvertTo-ADAnalyzerComparableValue $right
            Assert-Metadata ((ConvertTo-Json -InputObject $leftComparable -Compress) -cne
                (ConvertTo-Json -InputObject $rightComparable -Compress)) 'Comparison lost a real difference behind a Keys entry.'
            Assert-Metadata ($leftComparable.Ordinary -eq 1 -and $rightComparable.Ordinary -eq 2 -and
                (ConvertTo-Json -InputObject $left -Compress) -ceq $beforeLeft) 'Comparison changed values or caller input.'
            $script:MetadataScenarios++
            Assert-Metadata ($script:MetadataScenarios -eq 13) 'Export discovery mismatch.'
        }
        Loading {
            $loader = (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1').Replace("'", "''")
            $operations = (Join-Path $repositoryRoot 'bin/ADOperations.ps1').Replace("'", "''")
            $checks = @'
$service = [ADAnalyzerEvidenceProjector]::new()
if (@($service.PSObject.Properties).Count -ne 0) {
    throw 'Construction retained state.'
}
$source = [ordered]@{
    Keys = $null
    Ordinary = 3
    Password = 'fixture'
}
$result = $service.Project($source)
$command = ConvertTo-ADAnalyzerSafeData $source
if ($result.Ordinary -ne 3 -or -not $result.PasswordPresent -or
    $null -eq $result.PSObject.Properties['Keys'] -or
    (ConvertTo-Json $result -Compress) -cne (ConvertTo-Json $command -Compress)) {
    throw 'Fresh literal dictionary object/command results differ.'
}
if ($null -ne $service.GetValue($source, @('Keys'), 'fallback')) {
    throw 'An explicit null Keys entry became a default.'
}
'@
            foreach ($header in @(
                    (". '" + $loader + "'"),
                    (". '" + $operations + "'"),
                    (". '" + $loader + "'" + [Environment]::NewLine + ". '" + $loader + "'")
                )) {
                $program = $header + [Environment]::NewLine + $checks + [Environment]::NewLine + "'PASS METADATA LITERAL'"
                $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($program))
                $executable = (Get-Process -Id $PID).Path
                $output = & $executable -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
                Assert-Metadata ($LASTEXITCODE -eq 0 -and
                    ($output -join ' ').Contains('PASS METADATA LITERAL')) 'Fresh documented literal loading failed.'
                $script:MetadataScenarios++
            }
            Assert-Metadata ($script:MetadataScenarios -eq 3) 'Loading discovery mismatch.'
        }
        Uncaught {
            foreach ($failure in @('Keys', 'Move', 'Current')) {
                foreach ($preference in @('Continue', 'Stop')) {
                    $executable = (Get-Process -Id $PID).Path
                    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
                        '-Case', 'FaultChild', '-Failure', $failure, '-Preference', $preference)
                    $savedPreference = $ErrorActionPreference
                    try {
                        $ErrorActionPreference = 'Continue'
                        $lines = @(& $executable @arguments 2>&1 | ForEach-Object { [string]$_ })
                        $processExit = $LASTEXITCODE
                    }
                    finally {
                        $ErrorActionPreference = $savedPreference
                    }
                    Assert-Metadata (($lines -join ' ').Contains('METADATA_BEGIN')) 'The uncaught fault child did not start.'
                    if ($preference -eq 'Continue') {
                        Assert-Metadata ($processExit -ne 0 -and
                            -not ($lines -join ' ').Contains('METADATA_AFTER')) 'Uncaught native failure continued as a successful scan.'
                    }
                    else {
                        $summaryLines = @($lines | Where-Object { $_.StartsWith('METADATA_SUMMARY ') })
                        Assert-Metadata ($processExit -eq 0 -and
                            $summaryLines.Count -eq 1) 'The Stop child did not report its established command failure boundary.'
                        $summary = ConvertFrom-Json ($summaryLines[0].Substring('METADATA_SUMMARY '.Length))
                        Assert-Metadata ($summary.Rows.Count -eq 1 -and $summary.Rows[0].Before -eq 1 -and
                            @($summary.Trace).Count -eq 0 -and $summary.Counters.Keys -eq 1 -and
                            $summary.Counters.Values -eq 0 -and
                            @($summary.Errors).Count -gt 1) 'Failure emitted a false-success row, evaluated the tail, or lost common-parameter diagnostics.'
                        Assert-Metadata (@($summary.Output).Count -eq 2 -and
                            $summary.Output[0] -ceq 'output-seed' -and
                            $summary.Output[1].Before -eq 1 -and
                            $summary.Errors[0] -ceq 'error-seed') 'Native failure changed seeded output/error variable behavior.'
                        $nativeErrors = @($summary.Errors | Where-Object {
                                $_ -isnot [string] -and $_.Cause -ceq 'System.InvalidOperationException'
                            })
                        Assert-Metadata ($nativeErrors.Count -ge 1 -and
                            $nativeErrors[0].Id -like $(if ($failure -eq 'Keys') {
                                    'InvalidOperationException*'
                                }
                                else {
                                    'BadEnumeration*'
                                })) 'ErrorVariable lost its native failure classification.'
                        Assert-Metadata (@($summary.GlobalErrors).Count -gt 0 -and
                            $summary.GlobalErrors[0].Cause -ceq 'System.InvalidOperationException') 'Uncaught failure lost its native cause.'
                    }
                    $script:MetadataScenarios++
                }
            }
            Assert-Metadata ($script:MetadataScenarios -eq 6) 'Uncaught discovery mismatch.'
        }

        Consumers {
            $temporary = Join-Path ([IO.Path]::GetTempPath()) ('adAnalyzer-keys-' + [guid]::NewGuid().ToString('N'))
            try {
                $ini = Join-Path $temporary 'Machine/metadata.ini'
                $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ini))
                [IO.File]::WriteAllText($ini, "[Keys]`nOrdinary=one`n[Other]`nTail=two", [Text.UTF8Encoding]::new($false))
                $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ini))
                foreach ($direct in @($false, $true)) {
                    $parsed = if ($direct) {
                        [ADAnalyzerGpoReader]::new().Read($temporary)
                    }
                    else {
                        Read-ADAnalyzerGpo -Path $temporary
                    }
                    $rows = @($parsed.IniSettings)
                    $keys = @($rows | Where-Object { $_.Section -ceq 'Keys' -and $_.Name -ceq 'Ordinary' })
                    $other = @($rows | Where-Object { $_.Section -ceq 'Other' -and $_.Name -ceq 'Tail' })
                    Assert-Metadata ($rows.Count -eq 2 -and $keys.Count -eq 1 -and $keys[0].Value -ceq 'one' -and
                        $other.Count -eq 1 -and $other[0].Value -ceq 'two') 'An INI Keys section hid inventory.'
                    Assert-Metadata ($before -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($ini))) 'INI inventory changed its source.'
                }
                $script:MetadataScenarios++
            }
            finally {
                if ([IO.Directory]::Exists($temporary)) {
                    [IO.Directory]::Delete($temporary, $true)
                }
            }
            $sid = 'S-1-5-21-1-2-3-444'
            $names = @{
                Keys = 'shadow'
                $sid = 'Fixture principal'
            }
            $gpo = [pscustomobject]@{
                Version = 0
                Flags = 0
                Links = @()
            }
            $parsed = [pscustomobject]@{
                SysvolVersion = 0
                SecuritySettings = @([pscustomobject]@{
                        Scope = 'Computer'
                        Kind = 'UserRightsAssignment'
                        Name = 'SeDebugPrivilege'
                        Value = @('*' + $sid)
                        Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
                    })
                RegistrySettings = @()
                XmlFiles = @()
                IniSettings = @()
                Files = @()
            }
            $xml = [xml](ConvertTo-AnalyzerGpoXml -Gpo $gpo -Parsed $parsed -SidNames $names)
            $member = $xml.SelectSingleNode('//UserRightsAssignment/Member')
            Assert-Metadata ($null -ne $member -and
                $member.SelectSingleNode('SID').PSBase.InnerText -ceq $sid -and
                $member.SelectSingleNode('Name').PSBase.InnerText -ceq 'Fixture principal' -and
                $member.SelectSingleNode('Resolution').PSBase.InnerText -ceq 'Resolved') 'SidNames Keys data hid a real SID mapping.'
            Assert-Metadata ($names['Keys'] -ceq 'shadow' -and $names[$sid] -ceq 'Fixture principal') 'XML changed SidNames.'
            $script:MetadataScenarios++

            $profile = Get-ADAnalyzerDefaultProfile
            $rights = [ordered]@{
                Keys = @('S-1-5-32-544')
                SeDebugPrivilege = @('S-1-5-32-545')
            }
            $profile.Policy.AllowedUserRightSids = $rights
            $policy = [pscustomobject]@{
                SecuritySettings = @()
                RegistrySettings = @()
                IniSettings = @()
                XmlFiles = @()
                Files = @()
                UnparsedFiles = @()
            }
            $state = @{
                Gpo = [pscustomobject]@{
                    Id = 'metadata'
                }
                Policy = $policy
                Profile = $profile
                Target = 'GPO:metadata'
                Checks = [Collections.Generic.List[object]]::new()
                CommandContext = $null
                ErrorPreference = 'Stop'
            }
            [ADAnalyzerGpoPolicyEvaluator]::new().EvaluateMembershipAndRights($state)
            $checks = @($state.Checks | Where-Object { $_.RuleId -like 'GPO.UserRights.*' })
            Assert-Metadata ($checks.Count -eq 2 -and
                (@($checks.RuleId | Sort-Object) -join '|') -ceq 'GPO.UserRights.Keys|GPO.UserRights.SeDebugPrivilege') 'Configured rights were omitted or renamed.'
            foreach ($check in $checks) {
                $rightName = $check.RuleId.Substring('GPO.UserRights.'.Length)
                Assert-Metadata ($check.Status -ceq 'NotConfigured' -and @($check.Expected).Count -eq 1 -and
                    $check.Expected[0] -ceq $rights[$rightName][0]) 'An absent configured right lost its exact baseline.'
            }
            Assert-Metadata ($rights['Keys'][0] -ceq 'S-1-5-32-544' -and
                $rights['SeDebugPrivilege'][0] -ceq 'S-1-5-32-545') 'Rights evaluation changed its source.'
            $script:MetadataScenarios++

            $domain = [pscustomobject]@{
                SID = 'S-1-5-21-1-2-3'
                RootDomainSID = 'S-1-5-21-1-2-3'
                PrivilegedSids = @()
            }
            $objects = @(
                [pscustomobject]@{
                    ObjectClass = 'Fixture'
                    ObjectGuid = '11111111-1111-1111-1111-111111111111'
                    DistinguishedName = 'CN=One,DC=example,DC=invalid'
                    ServicePrincipalNames = @('Keys')
                },
                [pscustomobject]@{
                    ObjectClass = 'Fixture'
                    ObjectGuid = '22222222-2222-2222-2222-222222222222'
                    DistinguishedName = 'CN=Two,DC=example,DC=invalid'
                    ServicePrincipalNames = @('KEYS')
                }
            )
            $data = [pscustomobject]@{
                Objects = $objects
                Groups = @()
                Server = 'fixture'
                Trusts = @()
            }
            $evaluation = @{
                Data = $data
                Profile = $profile
                Policy = $profile.Policy
                Domain = $domain
                DomainTarget = 'DC=example,DC=invalid'
                Coverage = @{}
                Checks = [Collections.Generic.List[object]]::new()
                CommandContext = $null
                ErrorPreference = 'Stop'
            }
            [ADAnalyzerDirectoryPolicyEvaluator]::new().EvaluateAccounts($evaluation)
            $duplicate = @($evaluation.Checks | Where-Object RuleId -ceq 'SPN.DUPLICATE')
            Assert-Metadata ($duplicate.Count -eq 1 -and $duplicate[0].Target -ceq 'keys' -and
                $duplicate[0].Status -ceq 'Fail' -and @($duplicate[0].Observed).Count -eq 2) 'Offline SPN Keys owners were omitted.'
            Assert-Metadata ($objects[0].ServicePrincipalNames[0] -ceq 'Keys' -and
                $objects[1].ServicePrincipalNames[0] -ceq 'KEYS') 'SPN evaluation changed input.'
            $script:MetadataScenarios++

            $aces = @(
                foreach ($identity in @('Keys', 'S-1-5-21-1-2-3-9000')) {
                    foreach ($right in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) {
                        [pscustomobject]@{
                            AccessControlType = 'Allow'
                            IdentitySid = $identity
                            TargetType = 'DomainRoot'
                            Target = 'DC=example,DC=invalid'
                            Rights = 'ExtendedRight'
                            ObjectType = $right
                            ObjectTypeName = ''
                            InheritedObjectType = ''
                            IsInherited = $false
                            PropagationFlags = 'None'
                            InheritanceType = 'None'
                        }
                    }
                }
            )
            $evaluation.Data = [pscustomobject]@{
                Trusts = @()
                Acl = [pscustomobject]@{
                    Entries = $aces
                }
            }
            $evaluation.Checks.Clear()
            [ADAnalyzerDirectoryPolicyEvaluator]::new().EvaluateTrustsAndAcl($evaluation)
            $replication = @($evaluation.Checks | Where-Object RuleId -ceq 'ACL.REPLICATION_RIGHTS')
            Assert-Metadata ($replication.Count -eq 2 -and
                @($replication | Where-Object { $_.Observed -ceq 'Keys' -and $_.Status -ceq 'Fail' }).Count -eq 1 -and
                @($replication | Where-Object { $_.Observed -ceq 'S-1-5-21-1-2-3-9000' -and
                        $_.Status -ceq 'Fail' }).Count -eq 1) 'Offline ACL Keys principal hid replication evidence.'
            Assert-Metadata (@($aces | Where-Object IdentitySid -ceq 'Keys').Count -eq 2) 'ACL evaluation changed its source.'
            $script:MetadataScenarios++
            Assert-Metadata ($script:MetadataScenarios -eq 5) 'Consumer discovery mismatch.'
        }

        Legacy {
            $body = [scriptblock]::Create(@'
$ErrorActionPreference = 'Stop'
$assembly = [GroupPolicyObject].Assembly
$convertType = $assembly.GetType('Convert', $true)
$propertyType = $assembly.GetType('Property', $true)
$tableType = $assembly.GetType('Table', $true)
$completed = 0
$source = [ordered]@{
    Keys = 'shadow'
    Name = 'record'
    Ordinary = 1
}
$converted = $convertType::ToOrderedDictionary($source)
$names = @(([Collections.IDictionary].GetProperty('Keys')).GetValue($converted, $null))
if (($names -join '|') -cne 'Keys|Name|Ordinary' -or
    $converted['Keys'] -cne 'shadow' -or $converted['Ordinary'] -ne 1 -or
    [object]::ReferenceEquals($source, $converted)) {
    throw 'Legacy conversion lost dictionary fields or freshness.'
}
if ($source['Keys'] -cne 'shadow' -or $source['Name'] -cne 'record' -or $source['Ordinary'] -ne 1) {
    throw 'Legacy conversion changed source data.'
}
$completed++
$properties = [Activator]::CreateInstance($propertyType)
$properties.AddPropertyName('Keys')
$properties.AddPropertyName('Ordinary')
$names = @($properties.GetNames())
if (($names -join '|') -cne 'Keys|Ordinary') {
    throw 'Legacy property names treated Keys data as metadata.'
}
$completed++
foreach ($rowId in @('record', 'Values')) {
    $table = [Activator]::CreateInstance($tableType)
    $table.Properties.SetKey('Name')
    $source = [ordered]@{
        Keys = 'shadow'
        Name = $rowId
        Ordinary = 1
    }
    $table[$rowId] = $source
    $table.FormatData()
    $row = $table[$rowId]
    $names = @(([Collections.IDictionary].GetProperty('Keys')).GetValue($row, $null))
    if (($names -join '|') -cne 'Keys|Name|Ordinary' -or
        $row['Keys'] -cne 'shadow' -or $row['Name'] -cne $rowId -or $row['Ordinary'] -ne 1 -or
        (@($table.Properties.GetNames()) -join '|') -cne 'Keys|Name|Ordinary') {
        throw 'Legacy Table lost per-row Keys data or the Values row identity.'
    }
    if ($source['Keys'] -cne 'shadow' -or $source['Name'] -cne $rowId -or $source['Ordinary'] -ne 1) {
        throw 'Legacy Table changed its input row.'
    }
    $completed++
}
return $completed
'@)
            $completed = & $script:MetadataLegacyModule $body
            Assert-Metadata ($completed -eq 4) 'Legacy consumer discovery mismatch.'
            $script:MetadataScenarios += $completed
        }

        Probe {
            $results = @(
                foreach ($failure in @('Keys', 'Move', 'Current')) {
                    foreach ($preference in @('Continue', 'Stop')) {
                        foreach ($direct in @($false, $true)) {
                            foreach ($visible in @($false, $true)) {
                                Get-MetadataFault $failure $preference $direct $visible
                            }
                        }
                    }
                }
            )
            Write-Output (ConvertTo-Json -InputObject $results -Depth 40)
            return
        }
        Controls {
            foreach ($kind in @('Hashtable', 'Ordered', 'Ordinal', 'IgnoreCase')) {
                $map = New-MetadataMap $kind @(
                    @{
                        Name = 'Name'
                        Value = 'ordinary'
                    },
                    @{
                        Name = 'Ordinary'
                        Value = 3
                    },
                    @{
                        Name = 'Password'
                        Value = $script:MetadataMarker
                    }
                )
                foreach ($direct in @($false, $true)) {
                    $actual = if ($direct) {
                        [ADAnalyzerEvidenceProjector]::new().Project($map)
                    }
                    else {
                        ConvertTo-ADAnalyzerSafeData $map
                    }
                    Assert-Metadata ($actual.Name -ceq 'ordinary' -and $actual.Ordinary -eq 3 -and
                        $actual.PasswordPresent -is [bool] -and $actual.PasswordPresent) 'An ordinary dictionary control changed.'
                    Assert-Metadata ($map['Password'] -ceq $script:MetadataMarker) 'Projection changed input data.'
                    $script:MetadataScenarios++
                }
            }
            Assert-Metadata ($script:MetadataScenarios -eq 8) 'Control discovery mismatch.'
        }
        Projection {
            foreach ($kind in @('Hashtable', 'Ordered', 'Ordinal', 'IgnoreCase')) {
                $map = New-MetadataMap $kind @(
                    @{
                        Name = 'Keys'
                        Value = $null
                    },
                    @{
                        Name = 'Ordinary'
                        Value = 3
                    },
                    @{
                        Name = 'Password'
                        Value = $script:MetadataMarker
                    }
                )
                $actual = ConvertTo-ADAnalyzerSafeData $map
                Assert-Metadata ($actual.PasswordPresent -is [bool] -and $actual.PasswordPresent -and
                    $actual.Ordinary -eq 3 -and
                    $null -ne $actual.PSObject.Properties['Keys']) 'A Keys data entry hid fields or boolean secret presence.'
                $script:MetadataScenarios++
            }
            Assert-Metadata ($script:MetadataScenarios -eq 4) 'Projection discovery mismatch.'
        }
    }
    Write-Host ('PASS dictionary metadata ' + $Case + ' ' + $script:MetadataScenarios)
}
catch {
    Write-Host ('FAIL dictionary metadata ' + $Case + ' after ' + $script:MetadataScenarios)
    Write-Host $_.ScriptStackTrace
    throw
}
