[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [switch]$Baseline
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
. (Join-Path $RepositoryRoot 'tests/UncertainRemediationFixture.ps1') -RepositoryRoot $RepositoryRoot -DefinitionsOnly
$script:PersistencePassed = 0
$script:PersistenceContextKey = 'ADAnalyzer.RemediationReservation'
$script:PersistenceSecret = 'PERSISTENCE_CONTEXT_PRIVATE_FIXTURE_318b'
$script:PersistenceReadHelper = (Get-Command Read-FixtureObject -CommandType Function).ScriptBlock
$script:PersistenceGroupHelper = (Get-Command Read-FixtureGroups -CommandType Function).ScriptBlock
$script:PersistenceArmed = $false

function ConvertTo-Json {
    [CmdletBinding()]
    param([AllowNull()]$InputObject, [int]$Depth, [switch]$Compress)

    if ($script:PersistenceArmed -and $null -ne $InputObject -and
        $InputObject.JournalType -eq 'ADAnalyzerRemediationJournal' -and @($InputObject.Entries).Count -eq 1) {
        $entry = @($InputObject.Entries)[0]
        $failed = if ($script:PersistenceOperation -ceq 'Undo') { $entry.Undo } else { $entry }
        if ($null -ne $failed -and $failed.Status -in 'Failed', 'Rejected') {
            Assert-Fixture ($failed.Message -ceq $script:PersistencePrimaryMessage) 'The serialization fault selected unrelated failure evidence.'
            $script:PersistenceWrites++
            $script:PersistenceDiskAtFailure = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:DispatchJournal))
            $script:PersistenceSecondaryCause = [IO.IOException]::new($script:PersistenceSecondaryMessage)
            throw $script:PersistenceSecondaryCause
        }
    }
    Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
}

function Throw-PersistencePrimary {
    $script:PersistencePrimaryCause = [InvalidOperationException]::new($script:PersistencePrimaryMessage)
    $script:PersistencePrimaryCause.Data['FixturePrivateCanary'] = $script:PersistenceSecret
    Write-Warning ('Synthetic ' + $script:PersistenceOperation + ' primary warning.')
    throw $script:PersistencePrimaryCause
}

function Read-FixtureObject([guid]$Identity, $Bound) {
    $script:PersistenceReads++
    if ($script:PersistencePhase -ceq 'PreDispatch') {
        Assert-FixtureBinding $Bound
        Throw-PersistencePrimary
    }
    & $script:PersistenceReadHelper $Identity $Bound
}

function Read-FixtureGroups($Bound) {
    $script:PersistenceGroups++
    & $script:PersistenceGroupHelper $Bound
}

function Invoke-PersistenceEffect([guid]$Identity, $Bound, [bool]$Undo) {
    Assert-FixtureBinding $Bound
    Assert-Fixture ($script:PersistencePhase -ceq 'Dispatched' -and $Identity -eq $script:DelayedIdentity) 'An unapproved synthetic persistence effect was dispatched.'
    Assert-Fixture ($Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and -not $Bound.WhatIf -and -not $Bound.Confirm) 'The synthetic dispatch changed its nested approval.'
    $journal = [IO.File]::ReadAllText($script:DispatchJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $entry = $journal.Entries[0]
    if ($Undo) {
        Assert-Fixture ($entry.Status -ceq 'Succeeded' -and $entry.Undo.Status -ceq 'Prepared') 'Undo entered the synthetic provider without durable Prepared evidence.'
        $script:UndoDispatches.Add($Identity)
    }
    else {
        Assert-Fixture ($entry.Status -ceq 'Prepared') 'Apply entered the synthetic provider without durable Prepared evidence.'
        $script:Dispatches.Add($Identity)
    }
    Assert-Fixture ([guid]$entry.ObjectGuid -eq $Identity) 'The durable Prepared record selected another account.'
    $script:PersistencePreparedBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:DispatchJournal))
    $record = $script:Records[$Identity]
    $record.Enabled = $Undo
    $record.UserAccountControl = if ($Undo) { 512 } else { 514 }
    $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
    [IO.File]::WriteAllText($script:QueuedEffect, $Identity.ToString('D'))
    Throw-PersistencePrimary
}

function Invoke-FixtureDisable([guid]$Identity, $Bound) {
    Invoke-PersistenceEffect $Identity $Bound $false
}

function Invoke-FixtureEnable([guid]$Identity, $Bound) {
    Invoke-PersistenceEffect $Identity $Bound $true
}

function Get-PersistenceErrors($Caught, [object[]]$History) {
    $records = [Collections.Generic.List[object]]::new()
    $records.Add($Caught)
    foreach ($item in $History) {
        $records.Add($item)
    }
    $exception = $Caught.Exception
    while ($null -ne $exception) {
        if ($exception -is [Management.Automation.IContainsErrorRecord]) {
            $records.Add($exception.ErrorRecord)
        }
        $exception = $exception.InnerException
    }
    return $records.ToArray()
}

function Test-PersistenceContext([string]$Route, [string]$Operation, [string]$Phase) {
    $script:PersistenceArmed = $false
    $scenario = New-FixtureScenario ('persistence-' + $Route + '-' + $Operation + '-' + $Phase)
    $plan = New-FixturePlan $script:DelayedIdentity
    $entryId = $null
    if ($Operation -ceq 'Undo') {
        $entryId = New-FixtureUndoJournal $plan $scenario.FirstJournal
    }
    else {
        $owner = [ADAnalyzerRemediationJournal]::new()
        try {
            $owner.Open($plan, $script:FixtureServer, $scenario.FirstJournal)
            $owner.Write($owner.Read())
        }
        finally {
            $owner.Dispose()
        }
    }
    $originalBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($scenario.FirstJournal))
    $record = $script:Records[$script:DelayedIdentity]
    $enabledBefore = $record.Enabled
    $whenChangedBefore = $record.WhenChanged
    $script:PersistenceOperation = $Operation
    $script:PersistencePhase = $Phase
    $script:PersistenceReads = 0
    $script:PersistenceGroups = 0
    $script:PersistenceWrites = 0
    $script:PersistencePrimaryCause = $null
    $script:PersistenceSecondaryCause = $null
    $script:PersistencePreparedBytes = $null
    $script:PersistenceDiskAtFailure = $null
    $script:PersistencePrimaryMessage = if ($Phase -ceq 'PreDispatch') {
        "Synthetic $Operation pre-dispatch read failed."
    }
    else {
        "Synthetic $Operation effect changed the account then failed."
    }
    $script:PersistenceSecondaryMessage = "Synthetic $Operation failure-journal serialization failed."
    $expected = if ($Operation -ceq 'Undo') {
        'Undo journal persistence failed; no further changes were attempted. ' + $script:PersistencePrimaryMessage + '; ' + $script:PersistenceSecondaryMessage
    }
    else {
        'Journal persistence failed; no further changes were attempted. Inspect the durable journal before retrying. ' + $script:PersistencePrimaryMessage + '; ' + $script:PersistenceSecondaryMessage
    }
    $script:PersistenceArmed = $true
    $stream = [Collections.Generic.List[object]]::new()
    $caught = $null
    $Error.Clear()
    try {
        & {
            if ($Operation -ceq 'Apply') {
                Invoke-FixtureApply $Route $plan $scenario.FirstJournal
            }
            else {
                Invoke-FixtureUndo $Route $entryId $scenario.FirstJournal
            }
        } *>&1 | ForEach-Object {
            $stream.Add($_)
        }
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    $script:PersistenceArmed = $false

    Assert-Fixture ($null -ne $caught -and $null -ne $script:PersistencePrimaryCause -and $script:PersistenceWrites -eq 1) 'The compound failure did not reach both intended faults exactly once.'
    $aggregate = @((Get-PersistenceErrors $caught $history) | Where-Object {
        $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -ceq $expected -and
        $_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::OperationStopped -and
        $_.Exception -is [Management.Automation.RuntimeException] -and $_.Exception.Message -ceq $expected -and
        $_.TargetObject -is [string] -and $_.TargetObject -ceq $expected
    })
    Assert-Fixture ($aggregate.Count -gt 0) 'The accepted aggregate message, FQID, RuntimeException category or target changed.'
    Assert-Fixture ($caught.Exception.GetBaseException().Message -ceq $expected) 'The operator received a replacement aggregate cause.'
    Assert-Fixture ($script:PersistencePrimaryCause.Message -ceq $script:PersistencePrimaryMessage -and $script:PersistenceSecondaryCause.Message -ceq $script:PersistenceSecondaryMessage) 'One original synthetic failure message changed.'
    $warnings = @($stream | Where-Object { $_ -is [Management.Automation.WarningRecord] })
    $other = @($stream | Where-Object { $_ -isnot [Management.Automation.WarningRecord] -and $_ -isnot [Management.Automation.ErrorRecord] })
    Assert-Fixture ($warnings.Count -eq 1 -and $warnings[0].Message -ceq ('Synthetic ' + $Operation + ' primary warning.') -and $other.Count -eq 0) 'The compound failure changed warning output or emitted success.'
    Assert-Fixture ($script:PersistenceReads -eq 1 -and $script:PersistenceGroups -eq $(if ($Phase -ceq 'Dispatched') { 1 } else { 0 })) 'Compound failure handling made an extra directory observation.'
    $dispatches = $script:Dispatches.Count + $script:UndoDispatches.Count
    Assert-Fixture ($dispatches -eq $(if ($Phase -ceq 'Dispatched') { 1 } else { 0 })) 'Compound failure handling made an additional effect attempt.'
    $durableBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($scenario.FirstJournal))
    $expectedBytes = if ($Phase -ceq 'Dispatched') { $script:PersistencePreparedBytes } else { $originalBytes }
    Assert-Fixture ($durableBytes -ceq $expectedBytes -and $script:PersistenceDiskAtFailure -ceq $expectedBytes) 'Failure serialization replaced the preceding durable journal.'
    $journal = [IO.File]::ReadAllText($scenario.FirstJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    if ($Phase -ceq 'Dispatched') {
        $entry = $journal.Entries[0]
        $prepared = if ($Operation -ceq 'Undo') { $entry.Undo } else { $entry }
        Assert-Fixture ($prepared.Status -ceq 'Prepared' -and $null -eq $prepared.After -and [IO.File]::Exists($script:QueuedEffect)) 'The performed effect lost its original durable Prepared evidence.'
        Assert-Fixture ($record.Enabled -eq ($Operation -ceq 'Undo') -and $record.WhenChanged -eq $whenChangedBefore.AddSeconds(1)) 'The one simulated directory effect was repeated or rolled back.'
    }
    else {
        Assert-Fixture ($record.Enabled -eq $enabledBefore -and $record.WhenChanged -eq $whenChangedBefore -and -not [IO.File]::Exists($script:QueuedEffect)) 'A known no-send compound failure changed the account.'
    }
    $lease = [IO.File]::Open(($scenario.FirstJournal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $lease.Dispose()
    $held = Get-ADAnalyzerRemediationReservation -ObjectGuid $script:DelayedIdentity
    Assert-Fixture ($held.Status -ceq 'Held') 'The compound failure lost its conservative account reservation.'
    $contexts = [Collections.Generic.List[object]]::new()
    $exception = $caught.Exception
    while ($null -ne $exception) {
        if ($exception.Data.Contains($script:PersistenceContextKey)) {
            $contexts.Add($exception.Data[$script:PersistenceContextKey])
        }
        $exception = $exception.InnerException
    }
    if ($Baseline -or $Phase -ceq 'PreDispatch') {
        Assert-Fixture ($contexts.Count -eq 0) 'Baseline or known no-send failure unexpectedly gained dispatch context.'
        Assert-Fixture (-not $script:PersistencePrimaryCause.Data.Contains($script:PersistenceContextKey) -and -not $script:PersistenceSecondaryCause.Data.Contains($script:PersistenceContextKey)) 'A baseline or known no-send original cause gained dispatch context.'
    }
    else {
        Assert-Fixture ($contexts.Count -gt 0) 'The dispatched aggregate lacks operator-visible reservation context.'
        foreach ($context in $contexts) {
            Assert-Fixture ($context -is [Collections.IDictionary] -and ((($context.Keys | Sort-Object) -join ',') -ceq 'AttemptId,LastConfirmedStep,ObjectGuid,Status')) 'The compound context exposed unexpected fields.'
            Assert-Fixture ($context['ObjectGuid'] -is [guid] -and $context['ObjectGuid'] -eq $script:DelayedIdentity -and $context['AttemptId'] -is [guid] -and $context['AttemptId'] -eq $held.AttemptId -and $context['Status'] -ceq 'Uncertain' -and $context['LastConfirmedStep'] -ceq 'AccountReserved') 'The aggregate context does not identify the retained account attempt.'
            $json = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $context -Depth 5 -Compress
            Assert-Fixture ($json -notmatch [regex]::Escape($script:PersistenceSecret) -and $json -notmatch 'JournalPath|Credential|Password|DistinguishedName|RawRecord') 'The aggregate context copied private failure data.'
        }
    }
    # Baseline switches only context presence above; legacy aggregate, streams,
    # journal bytes, effects and conservative holds use identical assertions.
    $script:PersistencePassed++
}

try {
    foreach ($route in 'Native', 'Direct') {
        foreach ($operation in 'Apply', 'Undo') {
            foreach ($phase in 'PreDispatch', 'Dispatched') {
                Test-PersistenceContext $route $operation $phase
            }
        }
    }
}
finally {
    if ([IO.Directory]::Exists($script:TemporaryRoot)) {
        [IO.Directory]::Delete($script:TemporaryRoot, $true)
    }
}
Write-Output ('PASS remediation persistence context ' + $script:PersistencePassed)
