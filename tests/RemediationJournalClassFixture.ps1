[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
$script:passed = 0
$script:trace = [Collections.Generic.List[string]]::new()
$script:server = 'selected.fixture.invalid'

function Import-Module {
    throw 'The local journal fixture attempted a module import.'
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

foreach ($name in @(
        'Invoke-Command', 'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE', 'Disable-ADAccount',
        'Enable-ADAccount', 'Invoke-ADAnalyzerRemediationPlan', 'Undo-ADAnalyzerRemediation'
    )) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'The local journal fixture encountered an external effect.'
    }
}

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:passed++
    }
    catch {
        Write-Host ('FAIL remediation journal ' + $Name)
        throw
    }
}

function Assert-FixtureFailure([scriptblock]$Body, [string]$Pattern = '') {
    $failure = $null
    try {
        $null = & $Body
    }
    catch {
        $failure = $_
    }
    Assert-Fixture (
        $null -ne $failure -and (-not $Pattern -or $failure.Exception.Message -match $Pattern)
    ) ('Unexpected journal error: ' + $failure)
}

function ConvertTo-FixtureJson([object]$Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Compress -Depth 25
}

function New-FixtureDirectory([string]$Name) {
    $path = Join-Path $script:temporary $Name
    $null = [IO.Directory]::CreateDirectory($path)
    return $path
}

function Get-FixtureFileNames([string]$Path) {
    return @([IO.Directory]::GetFiles($Path, '*', [IO.SearchOption]::AllDirectories) |
        ForEach-Object { [IO.Path]::GetFileName($_) } | Sort-Object)
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
            $diagnostic.Message = $cause.Message
        }
    }
    elseif ($Entry -is [Exception]) {
        $cause = $Entry.GetBaseException()
        $diagnostic.Cause = $cause.GetType().FullName
        $diagnostic.Message = $cause.Message
    }
    return $diagnostic
}

function Get-FixtureUtcTime([object]$Value) {
    if ($Value -is [datetimeoffset]) {
        return $Value
    }
    if ($Value -is [datetime]) {
        return [datetimeoffset]$Value.ToUniversalTime()
    }
    return [datetimeoffset]::ParseExact([string]$Value, 'o', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-StableJournal([object]$Journal) {
    $id = [guid]::Empty
    Assert-Fixture ([guid]::TryParseExact([string]$Journal.JournalId, 'D', [ref]$id)) 'A native journal lost its generated ID.'
    $created = Get-FixtureUtcTime $Journal.CreatedAt
    Assert-Fixture ($created.Offset -eq [timespan]::Zero) 'A native journal creation time is not UTC.'
    $stable = [ordered]@{}
    foreach ($property in $Journal.PSObject.Properties) {
        switch ($property.Name) {
            'JournalId' {
                $stable.JournalId = '{generated}'
            }
            'CreatedAt' {
                $stable.CreatedAt = '{UTC}'
            }
            'UpdatedAt' {
                $stable.UpdatedAt = $null
                if ($null -ne $property.Value) {
                    $updated = Get-FixtureUtcTime $property.Value
                    Assert-Fixture ($updated.Offset -eq [timespan]::Zero) 'A native journal update time is not UTC.'
                    $stable.UpdatedAt = '{UTC}'
                }
            }
            default {
                $stable[$property.Name] = $property.Value
            }
        }
    }
    return $stable
}

function New-NativeFixturePlan {
    $plan = [pscustomobject][ordered]@{
        Remediation = [ordered]@{ AllowDisable = $false; MaximumActions = 2 }
        PrivilegedSids = @('S-1-5-21-10-20-30-2100')
        AccountClassification = [ordered]@{ AttributeRules = @() }
    }
    $plan | Add-Member -MemberType ScriptProperty -Name PlanId -Value {
        $script:trace.Add('Plan.PlanId')
        return '11111111-1111-1111-1111-111111111111'
    }
    return $plan
}

function New-FixtureJournal([object]$Plan) {
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        JournalType = 'ADAnalyzerRemediationJournal'
        JournalId = '33333333-3333-4333-8333-333333333333'
        PlanId = $Plan.PlanId
        Server = $script:server
        CreatedAt = '2025-01-01T00:00:00.0000000+00:00'
        UpdatedAt = $null
        Remediation = $Plan.Remediation
        PrivilegedSids = @($Plan.PrivilegedSids)
        AccountClassification = $Plan.AccountClassification
        Entries = @()
    }
}

# Exact accepted journal helper bodies from 94ccdd1.
$script:acceptedJournalBodies = [ordered]@{
    # 5402e6c94f82712a3add4f6efeb5d685d886bfba64f23a3767cafac3dcd1cf16
    'Enter-ADAnalyzerJournalLease' = @'
    param([Parameter(Mandatory)][string]$Path)
    $full = Resolve-ADAnalyzerOperationFilePath $Path
    if (Test-Path -LiteralPath $full -PathType Container) {
        throw 'JournalPath must name a file'
    }
    $directory = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($directory)) {
        $null = [IO.Directory]::CreateDirectory($directory)
    }
    try {
        # Keep the marker: unlinking after close can race the next owner.
        return [IO.File]::Open(($full + '.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch {
        throw [IO.IOException]::new(('Unable to acquire journal lock for ' + $full + '. Another run may be active or the filesystem may be unavailable.'),
            $_.Exception)
    }
'@
    # b7089d374cc804d032cb7e96ce07aa6cab8ea64aa092908f57790373c546675c
    'Get-ADAnalyzerOperationJournal' = @'
    param(
        $Plan,
        [string]$Server,
        [string]$Path

    )
    if (Test-Path -LiteralPath $Path) {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            throw 'JournalPath must name a file'
        }
        $journal = Read-ADAnalyzerOperationDocument $Path 'Journal'
        if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.PlanId -ne $Plan.PlanId -or $journal.Server -ine $Server) {
            throw 'Existing journal belongs to a different plan or server'
        }
        return $journal
    }
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        JournalType = 'ADAnalyzerRemediationJournal'
        JournalId = [guid]::NewGuid().ToString('D')
        PlanId = $Plan.PlanId
        Server = $Server
        CreatedAt = [datetimeoffset]::UtcNow.ToString('o')
        UpdatedAt = $null
        Remediation = ConvertTo-ADAnalyzerSafeData $Plan.Remediation
        PrivilegedSids = @($Plan.PrivilegedSids)
        AccountClassification = ConvertTo-ADAnalyzerSafeData $Plan.AccountClassification
        Entries = @()
    }
'@
    # 997fa99abb48e72e73944cbba95d7885d3334a5cebac4b3edf4b5f8124837443
    'Save-ADAnalyzerOperationJournal' = @'
    param(
        $Journal,
        [string]$Path

    )
    $Journal.UpdatedAt = [datetimeoffset]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerSafeData $Journal) -Depth 100
    $null = Write-ADAnalyzerOperationFile -Path $Path -Content $json
'@
}

function Invoke-NativeJournalWitness {
    [CmdletBinding()]
    param([scriptblock]$Observer)

    & $Observer
}

function Get-NativeJournalObservation([string]$Route, [string]$Scenario, [string]$Preference) {
    $script:trace = [Collections.Generic.List[string]]::new()
    $root = New-FixtureDirectory 'native'
    $target = Join-Path $root 'journal [native].json'
    $localTarget = $target
    $plan = New-NativeFixturePlan
    $journal = New-FixtureJournal $plan
    $held = $null
    $items = [Collections.Generic.List[object]]::new()
    try {
        switch ($Scenario) {
            'Contention' {
                $held = [IO.File]::Open(
                    $target + '.lock', [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
                )
            }
            'WrongProvider' {
                $target = 'Env:ADANALYZER_LOCAL_JOURNAL_FIXTURE'
            }
            'ParentFile' {
                $parent = Join-Path $root 'parent.txt'
                [IO.File]::WriteAllText($parent, 'fixture parent')
                $target = Join-Path $parent 'journal.json'
                $localTarget = $target
            }
            'WrongPlan' {
                $other = New-FixtureJournal $plan
                $other.PlanId = '22222222-2222-4222-8222-222222222222'
                [IO.File]::WriteAllText($target, (ConvertTo-FixtureJson $other))
            }
            'InvalidJson' {
                [IO.File]::WriteAllText($target, '{"Entries":')
            }
            'DestinationDirectory' {
                $null = [IO.Directory]::CreateDirectory($target)
            }
            'SerializerFault' {
                function ConvertTo-Json {
                    [CmdletBinding()]
                    param([AllowNull()]$InputObject, [int]$Depth)

                    $script:trace.Add('Serialize')
                    throw [InvalidOperationException]::new('FixtureJournalSerializationFault')
                }
            }
        }
        $script:trace.Clear()
        $capture = [Collections.ArrayList]::new()
        $caught = $null
        $completed = $false
        $Error.Clear()
        try {
            if ($Route -eq 'Enter') {
                Enter-ADAnalyzerJournalLease -Path $target -ErrorAction $Preference -ErrorVariable +capture *>&1 |
                    ForEach-Object { $items.Add($_) }
            }
            elseif ($Route -eq 'Get') {
                Invoke-NativeJournalWitness -Observer {
                    Get-ADAnalyzerOperationJournal $plan $script:server $target
                } -ErrorAction $Preference -ErrorVariable +capture *>&1 |
                    ForEach-Object { $items.Add($_) }
            }
            else {
                Invoke-NativeJournalWitness -Observer {
                    Save-ADAnalyzerOperationJournal $journal $target
                } -ErrorAction $Preference -ErrorVariable +capture *>&1 |
                    ForEach-Object { $items.Add($_) }
            }
            $completed = $true
        }
        catch {
            $caught = $_
        }
        $history = @($Error)
        $exists = [IO.File]::Exists($localTarget)
        $saved = $null
        $bom = $false
        if ($Route -eq 'Save' -and $exists) {
            $bytes = [IO.File]::ReadAllBytes($localTarget)
            $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
            $document = [IO.File]::ReadAllText($localTarget) | Microsoft.PowerShell.Utility\ConvertFrom-Json
            $saved = ConvertTo-StableJournal $document
        }
        $updated = $null -ne $journal.UpdatedAt
        if ($updated) {
            Assert-Fixture ((Get-FixtureUtcTime $journal.UpdatedAt).Offset -eq [timespan]::Zero) 'Native Save set a non-UTC timestamp.'
        }
        [ordered]@{
            Completed = $completed
            Caught = Get-FixtureDiagnostic $caught
            Captured = Get-FixtureDiagnostic $capture
            History = Get-FixtureDiagnostic $history
            Trace = $script:trace.ToArray()
            Stream = @(
                foreach ($item in $items) {
                    if ($null -eq $item) {
                        [ordered]@{ Type = 'Null' }
                    }
                    elseif ($item -is [Management.Automation.ErrorRecord]) {
                        Get-FixtureDiagnostic $item
                    }
                    elseif ($item -is [IO.FileStream]) {
                        [ordered]@{
                            Type = $item.GetType().FullName
                            Name = [IO.Path]::GetFileName($item.Name)
                            Open = $item.CanRead -and $item.CanWrite
                        }
                    }
                    elseif ($item.JournalType -eq 'ADAnalyzerRemediationJournal') {
                        [ordered]@{
                            Type = $item.GetType().FullName
                            Journal = ConvertTo-StableJournal $item
                        }
                    }
                    else {
                        [ordered]@{
                            Type = $item.GetType().FullName
                            Value = $item
                        }
                    }
                }
            )
            FileNames = @(Get-FixtureFileNames $root)
            TargetExists = $exists
            UpdatedAtAssigned = $updated
            Saved = $saved
            Utf8Bom = $bom
        }
    }
    finally {
        foreach ($item in $items) {
            if ($item -is [IO.FileStream]) {
                $item.Dispose()
            }
        }
        if ($null -ne $held) {
            $held.Dispose()
        }
        [IO.Directory]::Delete($root, $true)
    }
}

function Assert-NativeJournalParity([string]$Route, [string]$Scenario, [string]$Preference) {
    $originals = [ordered]@{}
    try {
        foreach ($name in $script:acceptedJournalBodies.Keys) {
            $path = 'Function:script:' + $name
            $originals[$name] = (Get-Command $name -CommandType Function).ScriptBlock
            $accepted = [scriptblock]::Create($script:acceptedJournalBodies[$name])
            Set-Item -LiteralPath $path -Value $accepted
            Assert-Fixture (
                (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $accepted.ToString()
            ) ('The archived journal helper was not installed: ' + $name)
        }
        $expected = Get-NativeJournalObservation $Route $Scenario $Preference
    }
    finally {
        foreach ($name in $originals.Keys) {
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $originals[$name]
        }
    }
    foreach ($name in $originals.Keys) {
        Assert-Fixture (
            (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $originals[$name].ToString()
        ) ('The current journal helper was not restored: ' + $name)
    }
    $serialized = ConvertTo-FixtureJson $expected
    $witness = switch ($Scenario) {
        'EnterHealthy' {
            $expected.Completed -and $expected.Stream.Count -eq 1 -and $expected.Stream[0].Open -and
            $expected.Stream[0].Name -ceq 'journal [native].json.lock' -and -not $expected.TargetExists
        }
        'GetFresh' {
            $expected.Completed -and $expected.Stream.Count -eq 1 -and
            $expected.Stream[0].Journal.Entries.Count -eq 0 -and -not $expected.TargetExists
        }
        'SaveHealthy' {
            $expected.Completed -and $expected.Stream.Count -eq 0 -and $expected.UpdatedAtAssigned -and
            $expected.Utf8Bom -and $expected.FileNames.Count -eq 1 -and $expected.Saved.UpdatedAt -ceq '{UTC}'
        }
        'Contention' {
            -not $expected.Completed -and $serialized.Contains('Unable to acquire journal lock') -and $expected.FileNames.Count -eq 1
        }
        'WrongProvider' {
            -not $expected.Completed -and $serialized.Contains('FileSystem') -and $expected.FileNames.Count -eq 0
        }
        'ParentFile' {
            -not $expected.Completed -and $null -ne $expected.Caught -and
            $expected.FileNames.Count -eq 1 -and -not $serialized.Contains('Unable to acquire journal lock')
        }
        'WrongPlan' {
            -not $expected.Completed -and $serialized.Contains('Existing journal belongs to a different plan or server') -and
            ($expected.Trace -join ',') -ceq 'Plan.PlanId'
        }
        'InvalidJson' {
            -not $expected.Completed -and $serialized.Contains('ConvertFromJsonCommand') -and $expected.Trace.Count -eq 0
        }
        'DestinationDirectory' {
            -not $expected.Completed -and $null -ne $expected.Caught -and
            $expected.UpdatedAtAssigned -and $expected.FileNames.Count -eq 0 -and -not $expected.TargetExists
        }
        'SerializerFault' {
            -not $expected.Completed -and $serialized.Contains('FixtureJournalSerializationFault') -and
            $expected.UpdatedAtAssigned -and ($expected.Trace -join ',') -ceq 'Serialize' -and $expected.FileNames.Count -eq 0
        }
    }
    Assert-Fixture $witness (
        "The archive missed $Route/$Scenario with ErrorAction=$Preference." + [Environment]::NewLine + $serialized
    )
    $actual = ConvertTo-FixtureJson (Get-NativeJournalObservation $Route $Scenario $Preference)
    Assert-Fixture ($actual -ceq $serialized) (
        "Native journal changed for $Route/$Scenario with ErrorAction=$Preference." + [Environment]::NewLine +
        'Accepted: ' + $serialized + [Environment]::NewLine + 'Current: ' + $actual
    )
}

function Invoke-NativeCases {
    $cases = @(
        , @('Enter', 'EnterHealthy', 'Stop')
        , @('Enter', 'Contention', 'Continue')
        , @('Enter', 'WrongProvider', 'Ignore')
        , @('Enter', 'ParentFile', 'Stop')
        , @('Get', 'GetFresh', 'Stop')
        , @('Get', 'InvalidJson', 'Continue')
        , @('Get', 'WrongPlan', 'Ignore')
        , @('Save', 'SaveHealthy', 'Stop')
        , @('Save', 'DestinationDirectory', 'Stop')
        , @('Save', 'SerializerFault', 'SilentlyContinue')
    )
    foreach ($route in $cases) {
        Test-Fixture ($route -join '/') {
            Assert-NativeJournalParity $route[0] $route[1] $route[2]
        }
    }
}

function Invoke-ConstructionCases {
    Test-Fixture 'full loader provides independent inert journal objects' {
        foreach ($name in @(
                'Enter-ADAnalyzerJournalLease', 'Get-ADAnalyzerOperationJournal',
                'Resolve-ADAnalyzerOperationFilePath', 'Write-ADAnalyzerOperationFile', 'Test-Path'
            )) {
            Set-Item -LiteralPath ('Function:local:' + $name) -Value {
                throw 'Constructing a journal attempted to acquire or access storage.'
            }
        }
        $first = [ADAnalyzerRemediationJournal]::new()
        $second = [ADAnalyzerRemediationJournal]::new()
        try {
            Assert-Fixture (
                $first -is [IDisposable] -and $second -is [IDisposable] -and
                -not [object]::ReferenceEquals($first, $second)
            ) 'The constructor did not provide an independent disposable owner.'
        }
        finally {
            $first.Dispose()
            $second.Dispose()
        }
    }
    Test-Fixture 'ownership methods expose explicit operation signatures' {
        $type = [ADAnalyzerRemediationJournal]
        $open = $type.GetMethod('Open', [type[]]@([object], [string], [string]))
        $read = $type.GetMethod('Read', [type[]]@())
        $write = $type.GetMethod('Write', [type[]]@([object]))
        Assert-Fixture (
            $null -ne $open -and $open.ReturnType -eq [void] -and $null -ne $read -and $read.ReturnType -eq [object] -and
            $null -ne $write -and $write.ReturnType -eq [void] -and $type.GetMethod('Dispose').ReturnType -eq [void]
        ) 'The documented journal methods or signatures are missing.'
    }
}

function New-ReviewedFixturePlan {
    $account = [pscustomobject]@{
        ObjectGuid = '11111111-1111-4111-8111-111111111111'
        SID = 'S-1-5-21-10-20-30-1101'
        DistinguishedName = 'CN=Journal Fixture,OU=People,DC=offline,DC=invalid'
        ObjectClass = 'User'
        AccountType = 'User'
        Enabled = $true
        UserAccountControl = 512
        WhenChanged = [datetimeoffset]'2025-01-01T00:00:00Z'
        AdminCount = 0
        ProtectedFromAccidentalDeletion = $false
        Privileged = $false
        PrivilegeResolutionStatus = 'Complete'
        IsCriticalSystemObject = $false
        IsDomainController = $false
        PrimaryGroupID = 513
        SafetyMetadataStatus = 'Collected'
        SIDHistory = @()
    }
    $assessment = @{
        SchemaVersion = 1
        RunId = 'offline-journal-fixture'
        Context = @{ Server = $script:server }
        Objects = @($account)
        Data = @{
            Directory = @{
                Domain = @{
                    SID = 'S-1-5-21-10-20-30'
                    PrivilegedSids = @('S-1-5-21-10-20-30-1819')
                }
            }
        }
        Findings = @([pscustomobject]@{
                RuleId = 'ACCOUNT.INACTIVE'
                Status = 'Fail'
                Target = $account.DistinguishedName
                ObjectGuid = $account.ObjectGuid
                SID = $account.SID
                Suppressed = $false
            })
    }
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Remediation.AllowDisable = $true
    $profile.Remediation.ApprovedObjectGuids = @($account.ObjectGuid)
    $profile.Remediation.MaximumActions = 1
    $planner = [ADAnalyzerRemediationPlanner]::new()
    return $planner.CreatePlan($assessment, $profile)
}

function Forbid-LegacyJournalHelpers {
    foreach ($name in $script:acceptedJournalBodies.Keys) {
        Set-Item -LiteralPath ('Function:script:' + $name) -Value {
            throw 'The journal class delegated ownership or storage policy to a compatibility command.'
        }
    }
}

function Assert-FixtureMarker([string]$Path) {
    $marker = [IO.FileInfo]::new($Path + '.lock')
    Assert-Fixture ($marker.Exists -and $marker.Length -eq 0) 'The journal did not retain its empty lock marker.'
}

function Invoke-DirectCases {
    Forbid-LegacyJournalHelpers
    Test-Fixture 'before and after ownership read and write reject, and disposal is repeat-safe' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'lifecycle'
        $path = Join-Path $root 'journal [lifecycle].json'
        $plan = New-ReviewedFixturePlan
        try {
            Assert-FixtureFailure { $store.Read() } 'No remediation journal is open'
            Assert-FixtureFailure { $store.Write(@{}) } 'No remediation journal is open'
            $store.Dispose()
            Assert-Fixture (@(Get-FixtureFileNames $root).Count -eq 0) 'A closed journal touched storage.'
            Assert-Fixture (@($store.Open($plan, $script:server, $path)).Count -eq 0) 'Open emitted output.'
            $document = $store.Read()
            $otherPath = Join-Path $root 'different.json'
            Assert-FixtureFailure { $store.Open($plan, $script:server, $otherPath) } 'already open'
            Assert-Fixture (-not [IO.File]::Exists($otherPath + '.lock')) 'Reopening a live object acquired another path.'
            $store.Dispose()
            $store.Dispose()
            Assert-FixtureFailure { $store.Read() } 'No remediation journal is open'
            Assert-FixtureFailure { $store.Write($document) } 'No remediation journal is open'
            Assert-Fixture (-not [IO.File]::Exists($path)) 'Read-only activity created a journal file.'
            Assert-FixtureMarker $path
        }
        finally {
            $store.Dispose()
        }
    }
    Test-Fixture 'read before the first write retains bound detached policy and one generated identity' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'detached'
        $path = Join-Path $root 'journal.json'
        $plan = New-ReviewedFixturePlan
        $policy = ConvertTo-FixtureJson $plan.Remediation
        $classification = ConvertTo-FixtureJson $plan.AccountClassification
        try {
            $store.Open($plan, $script:server, $path)
            $first = $store.Read()
            $plan.Remediation.MaximumActions = 25
            $plan.AccountClassification.AttributeRules = @(@{ Attribute = 'fixture changed' })
            $plan.PrivilegedSids[0] = 'S-1-5-21-10-20-30-1999'
            $first.Remediation.MaximumActions = 99
            $first.AccountClassification.AttributeRules = @(@{ Attribute = 'result changed' })
            $second = $store.Read()
            $null = ConvertTo-StableJournal $second
            Assert-Fixture (
                $first.JournalId -ceq $second.JournalId -and $second.PlanId -ceq $plan.PlanId -and
                $second.Server -ceq $script:server -and $second.Entries.Count -eq 0 -and
                $null -eq $second.UpdatedAt -and
                (ConvertTo-FixtureJson $second.Remediation) -ceq $policy -and
                (ConvertTo-FixtureJson $second.AccountClassification) -ceq $classification -and
                ($second.PrivilegedSids -join ',') -ceq 'S-1-5-21-10-20-30-1819' -and
                -not [object]::ReferenceEquals($first.Remediation, $second.Remediation)
            ) 'Read detached or replaced the wrong journal or plan state.'
            Assert-Fixture ((Get-FixtureFileNames $root) -join ',' -ceq 'journal.json.lock') 'Open or Read persisted journal data.'
        }
        finally {
            $store.Dispose()
        }
    }
    Test-Fixture 'explicit write keeps reviewed policy, returns detached entries and reopens persisted identity' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'write'
        $path = Join-Path $root 'journal [write].json'
        $plan = New-ReviewedFixturePlan
        $marker = 'journal-entry-inert-fixture-marker'
        try {
            $store.Open($plan, $script:server, $path)
            $submitted = $store.Read()
            $submitted.Remediation.MaximumActions = 99
            $submitted.AccountClassification.AttributeRules = @(@{ Attribute = 'change ignored' })
            $submitted.PrivilegedSids = @('S-1-5-21-10-20-30-1999')
            $submitted.UpdatedAt = '2000-01-01T00:00:00.0000000+00:00'
            $submitted.Entries = @([pscustomobject]@{
                    ActionId = $plan.Actions[0].ActionId
                    Status = 'Prepared'
                    Password = $marker
                })
            $before = ConvertTo-FixtureJson $submitted
            Assert-Fixture (@($store.Write($submitted)).Count -eq 0) 'Write emitted output.'
            $bytes = [IO.File]::ReadAllBytes($path)
            $saved = $store.Read()
            Assert-Fixture (
                $bytes.Length -gt 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191 -and
                -not [IO.File]::ReadAllText($path).Contains($marker) -and
                $saved.Entries[0].PasswordPresent -is [bool] -and $saved.Entries[0].PasswordPresent -and
                $null -eq $saved.Entries[0].PSObject.Properties['Password'] -and
                $saved.Remediation.MaximumActions -eq 1 -and
                (@($saved.AccountClassification.AttributeRules).Count -eq 0) -and
                ($saved.PrivilegedSids -join ',') -ceq 'S-1-5-21-10-20-30-1819' -and
                (Get-FixtureUtcTime $saved.UpdatedAt) -gt [datetimeoffset]'2000-01-01T00:00:00Z' -and
                $saved.Entries[0].ActionId -ceq $plan.Actions[0].ActionId
            ) 'Write lost approved policy, detached evidence, timestamp or UTF-8 BOM.'
            Assert-Fixture ((ConvertTo-FixtureJson $submitted) -ceq $before) 'Writing mutated caller-supplied journal data.'
            $saved.Entries[0].Status = 'edited result'
            $store.Dispose()
            $store.Open($plan, $script:server, $path)
            $reopened = $store.Read()
            Assert-Fixture (
                $reopened.JournalId -ceq $saved.JournalId -and $reopened.Entries[0].Status -ceq 'Prepared' -and
                ((Get-FixtureFileNames $root) -join ',') -ceq 'journal [write].json,journal [write].json.lock'
            ) 'Reopening lost journal identity, persisted an alias or left staging files.'
        }
        finally {
            $store.Dispose()
        }
    }
    Test-Fixture 'wrong submitted identity rejects before storage and keeps its live lease' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'wrong-identity'
        $path = Join-Path $root 'journal.json'
        $plan = New-ReviewedFixturePlan
        try {
            $store.Open($plan, $script:server, $path)
            $store.Write($store.Read())
            $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
            $replacements = [ordered]@{
                JournalType = 'OtherFixtureDocument'
                PlanId = '22222222-2222-4222-8222-222222222222'
                Server = 'foreign.fixture.invalid'
                JournalId = '44444444-4444-4444-8444-444444444444'
            }
            foreach ($replacement in $replacements.GetEnumerator()) {
                $fault = $store.Read()
                $fault.PSObject.Properties[$replacement.Key].Value = $replacement.Value
                Assert-FixtureFailure { $store.Write($fault) }
                Assert-Fixture (
                    [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $before
                ) ('An invalid ' + $replacement.Key + ' changed the journal.')
            }
            Assert-FixtureFailure { $store.Write($path) } 'in-memory'
            $saved = $store.Read()
            Assert-Fixture ($saved.PlanId -ceq $plan.PlanId -and $saved.Server -ceq $script:server) 'Identity rejection released or replaced its owner.'
            Assert-Fixture ((Get-FixtureFileNames $root) -join ',' -ceq 'journal.json,journal.json.lock') 'Identity rejection left unexpected files.'
        }
        finally {
            $store.Dispose()
        }
    }
    Test-Fixture 'bracket path through local FileSystem drive and physical alias share contention' {
        $root = New-FixtureDirectory 'aliases'
        $path = Join-Path $root 'journal [alias].json'
        $driveName = 'JournalFixture' + ([guid]::NewGuid().ToString('N')).Substring(0, 8)
        $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $root -Scope Local
        $first = [ADAnalyzerRemediationJournal]::new()
        $second = [ADAnalyzerRemediationJournal]::new()
        $plan = New-ReviewedFixturePlan
        try {
            $alias = $driveName + ':journal [alias].json'
            $first.Open($plan, $script:server, $alias)
            Assert-FixtureFailure {
                $second.Open($plan, $script:server, $path)
            } 'Unable to acquire journal lock'
            Assert-FixtureFailure { $second.Read() } 'No remediation journal is open'
            $first.Write($first.Read())
            $identity = $first.Read().JournalId
            $first.Dispose()
            $second.Open($plan, $script:server, $path)
            Assert-Fixture (
                $second.Read().JournalId -ceq $identity -and
                ((Get-FixtureFileNames $root) -join ',') -ceq 'journal [alias].json,journal [alias].json.lock'
            ) 'A physical alias did not preserve the opened identity and single marker.'
        }
        finally {
            $second.Dispose()
            $first.Dispose()
            Remove-PSDrive -Name $driveName -Scope Local
        }
    }
    Test-Fixture 'invalid reviewed plan, server and non-file path fail before lease acquisition' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'invalid-open'
        $path = Join-Path $root 'journal.json'
        $plan = New-ReviewedFixturePlan
        try {
            Assert-FixtureFailure { $store.Open(@{}, $script:server, $path) } 'explicit ADAnalyzer remediation plan'
            Assert-FixtureFailure { $store.Open($plan, 'invalid/host', $path) } 'DNS or NetBIOS'
            Assert-FixtureFailure { $store.Open($plan, 'other.fixture.invalid', $path) } 'differs from the DC recorded'
            Assert-FixtureFailure { $store.Open($plan, $script:server, $root) } 'must name a file'
            Assert-FixtureFailure { $store.Open($plan, $script:server, 'Env:ADANALYZER_FIXTURE_JOURNAL') } 'FileSystem'
            Assert-FixtureFailure { $store.Read() } 'No remediation journal is open'
            Assert-Fixture (
                @(Get-FixtureFileNames $root).Count -eq 0 -and -not [IO.File]::Exists($root + '.lock')
            ) 'A rejected Open created storage.'
            $store.Open($plan, $script:server, $path)
            Assert-Fixture ($store.Read().PlanId -ceq $plan.PlanId) 'A failed Open left a partial owner.'
        }
        finally {
            $store.Dispose()
        }
    }
    Test-Fixture 'failed existing journal inspection releases the marker for another owner' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $other = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'corrupt-open'
        $path = Join-Path $root 'journal.json'
        $plan = New-ReviewedFixturePlan
        try {
            $broken = '{"Entries":'
            [IO.File]::WriteAllText($path, $broken)
            Assert-FixtureFailure { $store.Open($plan, $script:server, $path) }
            Assert-FixtureFailure { $store.Read() } 'No remediation journal is open'
            Assert-Fixture ([IO.File]::ReadAllText($path) -ceq $broken) 'Failed Open changed corrupt input.'
            Assert-FixtureMarker $path

            $wrong = New-FixtureJournal $plan
            $wrong.PlanId = '22222222-2222-4222-8222-222222222222'
            $wrongJson = ConvertTo-FixtureJson $wrong
            [IO.File]::WriteAllText($path, $wrongJson)
            Assert-FixtureFailure {
                $other.Open($plan, $script:server, $path)
            } 'different plan or server'
            Assert-Fixture ([IO.File]::ReadAllText($path) -ceq $wrongJson) 'Failed Open changed a mismatched journal.'
            $seed = New-FixtureJournal $plan
            [IO.File]::WriteAllText($path, (ConvertTo-FixtureJson $seed))
            $store.Open($plan, $script:server, $path)
            Assert-Fixture ($store.Read().JournalId -ceq $seed.JournalId) 'Failed Open retained a handle or changed existing identity.'
        }
        finally {
            $other.Dispose()
            $store.Dispose()
        }
    }
    Test-Fixture 'a failed explicit write leaves no staged file and permits reuse under the same lease' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $competing = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'failed-write'
        $path = Join-Path $root 'journal.json'
        $plan = New-ReviewedFixturePlan
        try {
            $store.Open($plan, $script:server, $path)
            $submission = $store.Read()
            $null = [IO.Directory]::CreateDirectory($path)
            Assert-FixtureFailure { $store.Write($submission) }
            Assert-Fixture (
                [IO.Directory]::Exists($path) -and ((Get-FixtureFileNames $root) -join ',') -ceq 'journal.json.lock'
            ) 'Failed Write damaged an existing container or left staging files.'
            [IO.Directory]::Delete($path)
            Assert-FixtureFailure { $competing.Open($plan, $script:server, $path) } 'Unable to acquire journal lock'
            Assert-Fixture ($null -eq $store.Read().UpdatedAt) 'Failed Write committed an update.'
            $store.Write($submission)
            Assert-Fixture ($null -ne $store.Read().UpdatedAt) 'The active owner could not recover from a failed write.'
        }
        finally {
            $competing.Dispose()
            $store.Dispose()
        }
    }
    Test-Fixture 'JSON and CLIXML disclose no owned path, identity or raw handle' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $unopened = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'serialized'
        $path = Join-Path $root 'journal [private-owner-path-marker].json'
        $plan = New-ReviewedFixturePlan
        try {
            $store.Open($plan, $script:server, $path)
            $record = $store.Read()
            $unopened.Lease = @{ Fixture = 'ordinary payload' }
            Assert-FixtureFailure { $unopened.Read() } 'No remediation journal is open'
            Assert-FixtureFailure { $unopened.Write($record) } 'No remediation journal is open'
            $unopened.Dispose()
            $unopened.Lease = $store.Lease
            Assert-FixtureFailure { $unopened.Read() } 'No remediation journal is open'
            Assert-FixtureFailure { $unopened.Write($record) } 'No remediation journal is open'
            $unopened.Dispose()
            Assert-Fixture ($store.Read().JournalId -ceq $record.JournalId) 'An unowned object released the actual owner.'
            $unopened.Lease = $null
            foreach ($stage in 'Active', 'Disposed') {
                if ($stage -eq 'Disposed') {
                    $store.Dispose()
                }
                $json = ConvertTo-FixtureJson $store
                $xml = [Management.Automation.PSSerializer]::Serialize($store, 10)
                foreach ($serialized in $json, $xml) {
                    Assert-Fixture (
                        -not $serialized.Contains('private-owner-path-marker') -and
                        -not $serialized.Contains($script:server) -and -not $serialized.Contains($plan.PlanId) -and
                        -not $serialized.Contains($record.JournalId) -and -not $serialized.Contains('System.IO.FileStream')
                    ) ('Serialized ' + $stage + ' journal disclosed bound state.')
                }
                $exported = [Management.Automation.PSSerializer]::Deserialize($xml)
                Assert-FixtureFailure { $unopened.Write($exported) } 'No remediation journal is open'
            }
        }
        finally {
            $unopened.Lease = $null
            $unopened.Dispose()
            $store.Dispose()
        }
    }
}

function Invoke-IsolationCases {
    Forbid-LegacyJournalHelpers
    Test-Fixture 'independent owners and reopening do not cross-release or retain old identity' {
        $plan = New-ReviewedFixturePlan
        $root = New-FixtureDirectory 'independent'
        $left = Join-Path $root 'left.json'
        $right = Join-Path $root 'right.json'
        $first = [ADAnalyzerRemediationJournal]::new()
        $second = [ADAnalyzerRemediationJournal]::new()
        try {
            $first.Open($plan, $script:server, $left)
            $second.Open($plan, $script:server, $right)
            $leftId = $first.Read().JournalId
            $rightId = $second.Read().JournalId
            $first.Dispose()
            $second.Write($second.Read())
            Assert-Fixture ($second.Read().JournalId -ceq $rightId -and $rightId -cne $leftId) 'Disposing one owner altered another.'
            $first.Open($plan, $script:server, $left)
            Assert-Fixture ($first.Read().JournalId -cne $leftId -and -not [IO.File]::Exists($left)) 'Reopened unwritten path retained stale identity.'
        }
        finally {
            $second.Dispose()
            $first.Dispose()
        }
    }
    Test-Fixture 'a disposed secondary runspace leaves the first acquired owner usable' {
        $store = [ADAnalyzerRemediationJournal]::new()
        $root = New-FixtureDirectory 'runspace'
        $path = Join-Path $root 'journal.json'
        $plan = New-ReviewedFixturePlan
        $worker = [powershell]::Create()
        try {
            $store.Open($plan, $script:server, $path)
            $before = $store.Read().JournalId
            $child = @'
param($Fixture, $RepositoryRoot)
& $Fixture -RepositoryRoot $RepositoryRoot -Case Construction
'@
            $result = @($worker.AddScript($child).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
            Assert-Fixture (
                -not $worker.HadErrors -and @($result | Where-Object { $_ -ceq 'PASS remediation journal Construction 2' }).Count -eq 1
            ) ('Secondary journal loader failed: ' + ($worker.Streams.Error -join ' | '))
            $worker.Dispose()
            $worker = $null
            $store.Write($store.Read())
            Assert-Fixture ($store.Read().JournalId -ceq $before) 'Closing another runspace invalidated the live journal.'
        }
        finally {
            if ($null -ne $worker) {
                $worker.Dispose()
            }
            $store.Dispose()
        }
    }
}

switch ($Case) {
    'Native' {
        $script:temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-journal-fixture-' + [guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($script:temporary)
        try {
            Invoke-NativeCases
        }
        finally {
            [IO.Directory]::Delete($script:temporary, $true)
        }
    }
    'Construction' {
        Invoke-ConstructionCases
    }
    'Standalone' {
        Test-Fixture 'standalone operations support a literal inert journal constructor' {
            $journal = [ADAnalyzerRemediationJournal]::new()
            try {
                Assert-Fixture (
                    $journal -is [IDisposable] -and $null -eq ('ADAnalyzerProfile' -as [type])
                ) 'Standalone journal construction loaded the profile dependency.'
                Assert-FixtureFailure { $journal.Read() } 'No remediation journal is open'
            }
            finally {
                $journal.Dispose()
            }
        }
    }
    { $_ -in 'Direct', 'Isolation' } {
        $script:temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-journal-fixture-' + [guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($script:temporary)
        try {
            if ($Case -eq 'Direct') {
                Invoke-DirectCases
            }
            else {
                Invoke-IsolationCases
            }
        }
        finally {
            [IO.Directory]::Delete($script:temporary, $true)
        }
    }
}
Write-Output ('PASS remediation journal ' + $Case + ' ' + $script:passed)
