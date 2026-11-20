[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RepositoryRoot,
    [ValidateSet('All', 'Apply', 'Undo')]
    [string]$Case = 'All',
    [switch]$DefinitionsOnly
)

$ErrorActionPreference = 'Stop'
$script:FixtureServer = 'uncertain-effect.fixture.invalid'
$script:DomainSid = 'S-1-5-21-10-20-30'
$script:ProviderPath = [IO.Path]::GetFullPath(
    (Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll')
)
$script:TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('ad-remediation-uncertain-' + [guid]::NewGuid().ToString('N'))

. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-ADAnalyzerRemediationAuthorityDirectory {
    [CmdletBinding()]
    param()

    Assert-Fixture ([IO.Directory]::Exists($script:AuthorityDirectory)) 'The disposable reservation directory is missing.'
    $script:AuthorityDirectory
}

foreach ($name in 'Invoke-Command', 'New-PSDrive', 'Get-ADRootDSE', 'Get-ADDomain', 'Set-ADObject') {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'The uncertainty fixture reached an unapproved integration boundary.'
    }
}

function Assert-FixtureBinding($Bound) {
    Assert-Fixture (
        $Bound.Server -ceq $script:FixtureServer -and
        [string]$Bound.ErrorAction -ceq 'Stop' -and
        -not $Bound.ContainsKey('Credential')
    ) 'A synthetic provider call did not use the explicit fixture server and credential mode.'
}

function Read-FixtureObject([guid]$Identity, $Bound) {
    Assert-FixtureBinding $Bound
    Assert-Fixture ($script:Records.ContainsKey($Identity)) 'The synthetic provider received an unreviewed object identity.'
    $script:Records[$Identity].PSObject.Copy()
}

function Read-FixtureGroups($Bound) {
    Assert-FixtureBinding $Bound
    Assert-Fixture ($Bound.Filter -ceq '*') 'The synthetic group query changed its selection.'
    [pscustomobject]@{
        SID = $script:DomainSid + '-513'
        DistinguishedName = 'CN=Fixture Group,DC=fixture,DC=invalid'
        PrimaryGroupToken = 513
        Members = @()
        MemberOf = @()
    }
}

function Set-FixtureDisabled([guid]$Identity) {
    $record = $script:Records[$Identity]
    Assert-Fixture $record.Enabled 'The synthetic provider attempted a duplicate disable.'
    $record.Enabled = $false
    $record.UserAccountControl = 514
    $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
}

function Invoke-FixtureDisable([guid]$Identity, $Bound) {
    $script:Dispatches.Add($Identity)
    Assert-FixtureBinding $Bound
    Assert-Fixture (
        $Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and
        -not $Bound.WhatIf -and -not $Bound.Confirm
    ) 'The approved synthetic effect changed its nested prompt binding.'
    $journal = [IO.File]::ReadAllText($script:DispatchJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $entry = $journal.Entries[-1]
    Assert-Fixture (
        $entry.Status -ceq 'Prepared' -and [guid]$entry.ObjectGuid -eq $Identity
    ) 'A synthetic provider call ran without a durable Prepared entry.'

    if ($Identity -eq $script:DelayedIdentity) {
        Assert-Fixture (-not [IO.File]::Exists($script:QueuedEffect)) 'A second provider call arrived while an earlier effect was pending.'
        [IO.File]::WriteAllText($script:QueuedEffect, $Identity.ToString('D'))
        throw 'Synthetic provider queued the effect and lost its acknowledgment.'
    }

    Set-FixtureDisabled $Identity
}

function Invoke-FixtureEnable([guid]$Identity, $Bound) {
    $script:UndoDispatches.Add($Identity)
    Assert-FixtureBinding $Bound
    Assert-Fixture (
        $Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and
        -not $Bound.WhatIf -and -not $Bound.Confirm
    ) 'The approved synthetic Undo changed its nested prompt binding.'
    $journal = [IO.File]::ReadAllText($script:DispatchJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $entry = $journal.Entries[0]
    Assert-Fixture (
        $entry.Status -ceq 'Succeeded' -and $entry.Undo.Status -ceq 'Prepared' -and
        [guid]$entry.ObjectGuid -eq $Identity -and $entry.Undo.Before.Enabled -eq $false
    ) 'A synthetic Undo ran without a durable Prepared entry.'

    $record = $script:Records[$Identity]
    Assert-Fixture (-not $record.Enabled) 'The synthetic provider attempted a duplicate enable.'
    $record.Enabled = $true
    $record.UserAccountControl = 512
    $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
}

function Get-ADObject {
    [CmdletBinding()]
    param([guid]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Native') 'The direct class used an ambient object command.'
    Read-FixtureObject $Identity $PSBoundParameters
}

function Get-ADGroup {
    [CmdletBinding()]
    param([string]$Filter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Native') 'The direct class used an ambient group command.'
    Read-FixtureGroups $PSBoundParameters
}

function Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Native') 'The direct class used an ambient effect command.'
    Invoke-FixtureDisable $Identity $PSBoundParameters
}

function Enable-ADAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Native') 'The direct class used an ambient Undo command.'
    Invoke-FixtureEnable $Identity $PSBoundParameters
}

function Get-FixtureBundledObject {
    [CmdletBinding()]
    param([guid]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Direct') 'The native command changed to a direct provider lookup.'
    Read-FixtureObject $Identity $PSBoundParameters
}

function Get-FixtureBundledGroup {
    [CmdletBinding()]
    param([string]$Filter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Direct') 'The native command changed to a direct provider lookup.'
    Read-FixtureGroups $PSBoundParameters
}

function Disable-FixtureBundledAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Direct') 'The native command changed to a direct provider effect.'
    Invoke-FixtureDisable $Identity $PSBoundParameters
}

function Enable-FixtureBundledAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:Route -eq 'Direct') 'The native command changed to a direct provider effect.'
    Invoke-FixtureEnable $Identity $PSBoundParameters
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru)

    Assert-Fixture (
        $script:Route -eq 'Direct' -and [IO.Path]::IsPathRooted($Name) -and
        [IO.Path]::GetFullPath($Name) -ceq $script:ProviderPath -and $Scope -ceq 'Local' -and
        $PassThru -and [string]$PSBoundParameters.ErrorAction -ceq 'Stop'
    ) 'A provider import escaped the safe fixture or changed its binding.'
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = @{
            'Get-ADObject' = Get-Command Get-FixtureBundledObject -CommandType Function
            'Get-ADGroup' = Get-Command Get-FixtureBundledGroup -CommandType Function
            'Disable-ADAccount' = Get-Command Disable-FixtureBundledAccount -CommandType Function
            'Enable-ADAccount' = Get-Command Enable-FixtureBundledAccount -CommandType Function
        }
    }
}

function New-FixtureRecord([guid]$Identity, [int]$Number) {
    [pscustomobject]@{
        ObjectGuid = $Identity.ToString('D')
        SID = $script:DomainSid + '-' + (2100 + $Number)
        DistinguishedName = "CN=Fixture$Number,OU=People,DC=fixture,DC=invalid"
        SamAccountName = "fixture$Number"
        ObjectClass = 'User'
        AccountType = 'User'
        Enabled = $true
        UserAccountControl = 512
        WhenChanged = [datetime]'2025-01-01T00:00:00Z'
        WhenCreated = [datetime]'2000-01-01T00:00:00Z'
        LastLogonTimestamp = 0
        LastLogon = $null
        LastLogonDate = $null
        AdminCount = 0
        ProtectedFromAccidentalDeletion = $false
        Privileged = $false
        PrivilegeResolutionStatus = 'Complete'
        IsCriticalSystemObject = $false
        IsDomainController = $false
        PrimaryGroupID = 513
        SafetyMetadataStatus = 'Collected'
        SIDHistory = @()
        MemberOf = @()
    }
}

function New-FixturePlan([guid]$Identity) {
    $record = $script:Records[$Identity]
    $assessment = @{
        SchemaVersion = 1
        RunId = [guid]::NewGuid().ToString('D')
        Context = @{ Server = $script:FixtureServer }
        Objects = @($record)
        Findings = @([pscustomobject]@{
                RuleId = 'ACCOUNT.INACTIVE'
                Status = 'Fail'
                Target = $record.DistinguishedName
                ObjectGuid = $record.ObjectGuid
                SID = $record.SID
                Suppressed = $false
            })
    }
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Remediation.AllowDisable = $true
    $profile.Remediation.ApprovedObjectGuids = @($record.ObjectGuid)
    $profile.AccountClassification.UserGroups = @($script:DomainSid + '-513')
    $planner = [ADAnalyzerRemediationPlanner]::new()
    $plan = $planner.CreatePlan($assessment, $profile)
    Assert-Fixture ($plan.Actions.Count -eq 1) 'The fixture did not create an approved reviewed action.'
    $plan.PlanId = [guid]::NewGuid().ToString('D')
    $plan.Actions[0].ActionId = [guid]::NewGuid().ToString('D')
    $plan
}

function Invoke-FixtureApply([string]$Route, [object]$Plan, [string]$Path) {
    $script:Route = $Route
    $script:DispatchJournal = $Path
    if ($Route -eq 'Native') {
        Invoke-ADAnalyzerRemediationPlan -Plan $Plan -Server $script:FixtureServer -JournalPath $Path -Confirm:$false -ErrorAction Stop
        return
    }

    $executor = [ADAnalyzerRemediationExecutor]::new()
    $executor.Apply($Plan, $script:FixtureServer, $Path, @($Plan.Actions[0].ActionId))
}

function Invoke-FixtureUndo([string]$Route, [string]$EntryId, [string]$Path, [switch]$Preview) {
    $script:Route = $Route
    $script:DispatchJournal = $Path
    if ($Route -eq 'Native') {
        $arguments = @{
            JournalPath = $Path
            Server = $script:FixtureServer
            Confirm = $false
            ErrorAction = 'Stop'
        }
        if ($Preview) {
            $arguments.WhatIf = $true
        }
        Undo-ADAnalyzerRemediation @arguments
        return
    }

    $executor = [ADAnalyzerRemediationExecutor]::new()
    if ($Preview) {
        $executor.PreviewUndo($Path, $script:FixtureServer)
        return
    }
    $executor.Undo($Path, $script:FixtureServer, @($EntryId))
}

function New-FixtureUndoJournal([object]$Plan, [string]$Path) {
    $action = $Plan.Actions[0]
    $identity = [guid]$action.ObjectGuid
    Set-FixtureDisabled $identity

    $guard = [ADAnalyzerRemediationGuard]::new()
    $after = $guard.ReadState($script:Records[$identity])
    $entryId = [guid]::NewGuid().ToString('D')
    $journal = [pscustomobject]@{
        SchemaVersion = 1
        JournalType = 'ADAnalyzerRemediationJournal'
        JournalId = [guid]::NewGuid().ToString('D')
        PlanId = $Plan.PlanId
        Server = $script:FixtureServer
        CreatedAt = '2025-01-01T00:00:00.0000000+00:00'
        UpdatedAt = '2025-01-01T00:00:01.0000000+00:00'
        Remediation = $Plan.Remediation
        PrivilegedSids = @($Plan.PrivilegedSids)
        AccountClassification = $Plan.AccountClassification
        Entries = @([pscustomobject]@{
                EntryId = $entryId
                ActionId = $action.ActionId
                Action = 'DisableAccount'
                ObjectGuid = $action.ObjectGuid
                SID = $action.SID
                DistinguishedName = $action.DistinguishedName
                ObjectClass = $action.ObjectClass
                AccountType = $action.AccountType
                InactivityDays = $action.InactivityDays
                Timestamp = '2025-01-01T00:00:01.0000000+00:00'
                Status = 'Succeeded'
                Before = $action.Preconditions
                After = $after
                Message = $null
                Undo = $null
            })
    }
    $json = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $journal -Depth 35
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($true))
    $entryId
}

function Assert-ApplyPreviewCreatesNoReservation([string]$Route, [object]$Plan, [string]$Path) {
    $script:Route = $Route
    $script:DispatchJournal = $Path
    if ($Route -eq 'Native') {
        $rows = @(Invoke-ADAnalyzerRemediationPlan -Plan $Plan -Server $script:FixtureServer -JournalPath $Path -WhatIf -Confirm:$false -ErrorAction Stop)
    }
    else {
        $executor = [ADAnalyzerRemediationExecutor]::new()
        $rows = @($executor.Preview($Plan, $script:FixtureServer, $Path))
    }
    Assert-Fixture (
        $rows.Count -eq 1 -and $rows[0].Status -ceq 'Skipped' -and
        [IO.Directory]::GetFileSystemEntries($script:AuthorityDirectory).Length -eq 0 -and
        [IO.Directory]::GetFileSystemEntries((Split-Path -Parent $Path)).Length -eq 0 -and
        $script:Dispatches.Count -eq 0 -and $script:UndoDispatches.Count -eq 0
    ) 'Preview created a reservation, journal or provider effect.'
}

function Assert-FixtureFailure([scriptblock]$Body, [string]$Pattern) {
    $failure = $null
    $rows = [Collections.Generic.List[object]]::new()
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-Fixture (
        $null -ne $failure -and
        ($failure.Exception.Message -match $Pattern -or $failure.Exception.GetBaseException().Message -match $Pattern)
    ) ('Unexpected uncertainty fixture error: ' + $failure)
    Assert-Fixture ($rows.Count -eq 0) 'An unsuccessful call emitted a success row.'
}

function New-FixtureScenario([string]$Name) {
    $scenarioRoot = Join-Path $script:TemporaryRoot $Name
    $script:AuthorityDirectory = [IO.Path]::GetFullPath((Join-Path $scenarioRoot 'authority'))
    $firstJournal = Join-Path $scenarioRoot 'first/journal.json'
    $secondJournal = Join-Path $scenarioRoot 'second/journal.json'
    $independentJournal = Join-Path $scenarioRoot 'independent/journal.json'
    $script:QueuedEffect = Join-Path $scenarioRoot 'provider-pending.txt'
    foreach ($directory in $script:AuthorityDirectory, (Split-Path -Parent $firstJournal), (Split-Path -Parent $secondJournal), (Split-Path -Parent $independentJournal)) {
        $null = [IO.Directory]::CreateDirectory($directory)
    }

    $script:DelayedIdentity = [guid]'20000000-0000-4000-8000-000000000001'
    $independentIdentity = [guid]'20000000-0000-4000-8000-000000000002'
    $script:Records = @{}
    $script:Records[$script:DelayedIdentity] = New-FixtureRecord $script:DelayedIdentity 1
    $script:Records[$independentIdentity] = New-FixtureRecord $independentIdentity 2
    $script:Dispatches = [Collections.Generic.List[guid]]::new()
    $script:UndoDispatches = [Collections.Generic.List[guid]]::new()

    return @{
        FirstJournal = $firstJournal
        SecondJournal = $secondJournal
        IndependentJournal = $independentJournal
        IndependentIdentity = $independentIdentity
    }
}

function Test-CrossJournalUncertainty([string]$First, [string]$Second) {
    $scenario = New-FixtureScenario "$First-to-$Second"
    $firstJournal = $scenario.FirstJournal
    $secondJournal = $scenario.SecondJournal
    $independentJournal = $scenario.IndependentJournal
    $independentIdentity = $scenario.IndependentIdentity
    $firstPlan = New-FixturePlan $script:DelayedIdentity
    $secondPlan = New-FixturePlan $script:DelayedIdentity
    Assert-ApplyPreviewCreatesNoReservation $First $firstPlan $firstJournal

    Assert-FixtureFailure {
        Invoke-FixtureApply $First $firstPlan $firstJournal
    } 'queued the effect and lost its acknowledgment'
    Assert-Fixture (
        $script:Dispatches.Count -eq 1 -and $script:Dispatches[0] -eq $script:DelayedIdentity -and
        [IO.File]::Exists($script:QueuedEffect) -and $script:Records[$script:DelayedIdentity].Enabled
    ) 'The first call did not leave exactly one unsettled effect on the still-enabled account.'
    $firstBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($firstJournal))

    Assert-FixtureFailure {
        Invoke-FixtureApply $Second $secondPlan $secondJournal
    } '(?i)uncertain'
    Assert-Fixture (
        $script:Dispatches.Count -eq 1 -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($firstJournal)) -ceq $firstBytes -and
        [IO.File]::Exists($script:QueuedEffect) -and $script:Records[$script:DelayedIdentity].Enabled
    ) 'A competing invocation dispatched or disturbed the earlier unresolved effect.'

    $independentPlan = New-FixturePlan $independentIdentity
    $independent = @(Invoke-FixtureApply $Second $independentPlan $independentJournal)
    Assert-Fixture (
        $independent.Count -eq 1 -and $independent[0].Status -ceq 'Succeeded' -and
        $script:Dispatches.Count -eq 2 -and $script:Dispatches[1] -eq $independentIdentity
    ) 'An unrelated account was blocked or the fixture observed an unexpected effect.'

    # Model a late server effect after the conflicting call has ended.
    $lateTarget = [guid][IO.File]::ReadAllText($script:QueuedEffect)
    Assert-Fixture ($lateTarget -eq $script:DelayedIdentity) 'The queued provider effect lost its original target.'
    Set-FixtureDisabled $lateTarget
    [IO.File]::Delete($script:QueuedEffect)
    Assert-Fixture (-not $script:Records[$lateTarget].Enabled) 'The original provider effect did not settle in the fixture.'
    Write-Output "PASS isolated uncertainty $First to $Second"
}

function Test-CrossJournalUndoUncertainty([string]$First, [string]$Second) {
    $scenario = New-FixtureScenario "$First-to-$Second-undo"
    $firstPlan = New-FixturePlan $script:DelayedIdentity
    $undoPlan = New-FixturePlan $script:DelayedIdentity
    Assert-FixtureFailure {
        Invoke-FixtureApply $First $firstPlan $scenario.FirstJournal
    } 'queued the effect and lost its acknowledgment'
    Assert-Fixture (
        $script:Dispatches.Count -eq 1 -and
        [IO.File]::Exists($script:QueuedEffect) -and $script:Records[$script:DelayedIdentity].Enabled
    ) 'The first call did not leave its synthetic write unsettled.'
    $firstBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($scenario.FirstJournal))

    # An independent observation now matches the second journal's recorded after-state.
    # The provider can still act on the pending request from the first journal.
    $undoEntry = New-FixtureUndoJournal $undoPlan $scenario.SecondJournal
    Assert-Fixture (
        [IO.File]::Exists($script:QueuedEffect) -and -not $script:Records[$script:DelayedIdentity].Enabled
    ) 'The fixture lost the distinction between observed state and pending dispatch.'
    $authorityEntries = ([IO.Directory]::GetFileSystemEntries($script:AuthorityDirectory) | Sort-Object) -join '|'
    $undoBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($scenario.SecondJournal))
    $preview = @(Invoke-FixtureUndo $Second $undoEntry $scenario.SecondJournal -Preview)
    Assert-Fixture (
        $preview.Count -eq 1 -and $preview[0].Status -ceq 'Skipped' -and
        (([IO.Directory]::GetFileSystemEntries($script:AuthorityDirectory) | Sort-Object) -join '|') -ceq $authorityEntries -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($scenario.SecondJournal)) -ceq $undoBytes -and
        $script:UndoDispatches.Count -eq 0
    ) 'Undo preview created a reservation, changed the existing journal or attempted a provider write.'
    Assert-FixtureFailure {
        Invoke-FixtureUndo $Second $undoEntry $scenario.SecondJournal
    } '(?i)uncertain'
    Assert-Fixture (
        $script:UndoDispatches.Count -eq 0 -and $script:Dispatches.Count -eq 1 -and
        [IO.File]::Exists($script:QueuedEffect) -and -not $script:Records[$script:DelayedIdentity].Enabled -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($scenario.FirstJournal)) -ceq $firstBytes
    ) 'A matching observation released the unresolved write or permitted an Undo effect.'

    $controlPlan = New-FixturePlan $scenario.IndependentIdentity
    $controlEntry = New-FixtureUndoJournal $controlPlan $scenario.IndependentJournal
    $control = @(Invoke-FixtureUndo $Second $controlEntry $scenario.IndependentJournal)
    Assert-Fixture (
        $control.Count -eq 1 -and $control[0].Status -ceq 'Undone' -and
        $script:UndoDispatches.Count -eq 1 -and $script:UndoDispatches[0] -eq $scenario.IndependentIdentity -and
        $script:Records[$scenario.IndependentIdentity].Enabled -and [IO.File]::Exists($script:QueuedEffect)
    ) 'The unaffected Undo control did not complete with the earlier effect still pending.'

    # Settle the original request. Its target already has the desired visible state.
    $lateTarget = [guid][IO.File]::ReadAllText($script:QueuedEffect)
    Assert-Fixture ($lateTarget -eq $script:DelayedIdentity) 'The queued provider effect lost its original target.'
    $record = $script:Records[$lateTarget]
    $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
    [IO.File]::Delete($script:QueuedEffect)
    Assert-Fixture (-not $record.Enabled) 'The late write did not preserve its intended disabled state.'
    Write-Output "PASS isolated uncertainty $First Apply to $Second Undo"
}

function Test-ReservationStorageAndNoSend {
    $scenario = New-FixtureScenario 'storage-and-no-send'
    $plan = New-FixturePlan $scenario.IndependentIdentity
    $account = $scenario.IndependentIdentity
    $holdPath = Join-Path $script:AuthorityDirectory ($account.ToString('N') + '.hold')

    [IO.File]::WriteAllText($holdPath, 'unreadable reservation format')
    Assert-FixtureFailure {
        Invoke-FixtureApply Native $plan $scenario.FirstJournal
    } '\bUncertain\b'
    Assert-Fixture (
        $script:Dispatches.Count -eq 0 -and
        [IO.File]::ReadAllText($holdPath) -ceq 'unreadable reservation format'
    ) 'An existing unrecognized reservation was overwritten or permitted a write.'

    [IO.File]::Delete($holdPath)
    $null = [IO.Directory]::CreateDirectory($holdPath)
    Assert-FixtureFailure {
        Invoke-FixtureApply Direct $plan $scenario.FirstJournal
    } '\bUncertain\b'
    Assert-Fixture ([IO.Directory]::Exists($holdPath) -and $script:Dispatches.Count -eq 0) 'A directory at the reservation path was removed or permitted a write.'

    [IO.Directory]::Delete($holdPath)
    $original = $script:Records[$account].WhenChanged
    $script:Records[$account].WhenChanged = $original.AddSeconds(1)
    Assert-FixtureFailure {
        Invoke-FixtureApply Native $plan $scenario.FirstJournal
    } 'precondition failed'
    Assert-Fixture (
        [IO.Directory]::GetFileSystemEntries($script:AuthorityDirectory).Length -eq 0 -and
        $script:Dispatches.Count -eq 0
    ) 'A known pre-dispatch rejection retained a reservation or performed a write.'

    $script:Records[$account].WhenChanged = $original
    $rows = @(Invoke-FixtureApply Direct $plan $scenario.SecondJournal)
    Assert-Fixture (
        $rows.Count -eq 1 -and $rows[0].Status -ceq 'Succeeded' -and
        $script:Dispatches.Count -eq 1 -and
        [IO.Directory]::GetFileSystemEntries($script:AuthorityDirectory).Length -eq 0
    ) 'The successful operation following a known no-send did not complete and release.'

    Write-Output 'PASS account reservation storage failure and known no-send'
}

if ($DefinitionsOnly) {
    return
}

try {
    if ($Case -in 'All', 'Apply') {
        Test-CrossJournalUncertainty Native Direct
        Test-CrossJournalUncertainty Direct Native
    }
    if ($Case -in 'All', 'Undo') {
        Test-CrossJournalUndoUncertainty Native Direct
        Test-CrossJournalUndoUncertainty Direct Native
    }
    if ($Case -eq 'All') {
        Test-ReservationStorageAndNoSend
    }
}
finally {
    if ([IO.Directory]::Exists($script:TemporaryRoot)) {
        [IO.Directory]::Delete($script:TemporaryRoot, $true)
    }
}
