[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
# Load the real accepted helper from the supplied product root, never the
# scratch script's directory. DefinitionsOnly performs no scenario execution.
. (Join-Path $RepositoryRoot 'tests/UncertainRemediationFixture.ps1') -RepositoryRoot $RepositoryRoot -DefinitionsOnly
$script:ContextPassed = 0
$script:ContextKey = 'ADAnalyzer.RemediationReservation'
$script:ContextSecret = 'FAILURE_CONTEXT_PRIVATE_FIXTURE_58b3'
$script:ContextReadHelper = (Get-Command Read-FixtureObject -CommandType Function).ScriptBlock
$script:ContextGroupHelper = (Get-Command Read-FixtureGroups -CommandType Function).ScriptBlock

function Throw-ContextFixtureFault {
    [CmdletBinding()]
    param()

    $script:ContextCause = [InvalidOperationException]::new($script:ContextMessage)
    $script:ContextCause.Data['FixtureOriginalMarker'] = 'preserved original cause'
    $script:ContextCause.Data['FixturePrivateCanary'] = $script:ContextSecret
    $script:ContextError = [Management.Automation.ErrorRecord]::new(
        $script:ContextCause, $script:ContextErrorId,
        [Management.Automation.ErrorCategory]::OperationStopped, $script:DelayedIdentity
    )
    Write-Warning $script:ContextWarning
    Write-Information -MessageData $script:ContextInformation -InformationAction Continue
    $PSCmdlet.ThrowTerminatingError($script:ContextError)
}

function Read-FixtureObject([guid]$Identity, $Bound) {
    $script:ContextReads++
    if ($script:ContextPhase -ceq 'PreDispatch') {
        Assert-FixtureBinding $Bound
        Throw-ContextFixtureFault
    }
    & $script:ContextReadHelper $Identity $Bound
}

function Read-FixtureGroups($Bound) {
    $script:ContextGroups++
    & $script:ContextGroupHelper $Bound
}

function Invoke-ContextFixtureMutation([guid]$Identity, $Bound, [bool]$Undo) {
    Assert-FixtureBinding $Bound
    Assert-Fixture ($script:ContextPhase -ceq 'Ambiguous' -and $Identity -eq $script:DelayedIdentity) 'A synthetic dispatch reached an unapproved context scenario.'
    Assert-Fixture ($Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and -not $Bound.WhatIf -and -not $Bound.Confirm) 'Synthetic dispatch changed its nested approval.'
    $journal = [IO.File]::ReadAllText($script:DispatchJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $entry = $journal.Entries[0]
    if ($Undo) {
        Assert-Fixture ($entry.Status -ceq 'Succeeded' -and $entry.Undo.Status -ceq 'Prepared') 'Undo dispatched without durable intent.'
        $script:UndoDispatches.Add($Identity)
    }
    else {
        Assert-Fixture ($entry.Status -ceq 'Prepared') 'Apply dispatched without durable intent.'
        $script:Dispatches.Add($Identity)
    }
    Assert-Fixture ([guid]$entry.ObjectGuid -eq $Identity) 'The durable intent selected another account.'
    [IO.File]::WriteAllText($script:QueuedEffect, $Identity.ToString('D'))
    # Deliberately leave the synthetic account unchanged. There is no fallback
    # directory effect or attempt to model settlement after this lost response.
    Throw-ContextFixtureFault
}

function Invoke-FixtureDisable([guid]$Identity, $Bound) {
    Invoke-ContextFixtureMutation $Identity $Bound $false
}

function Invoke-FixtureEnable([guid]$Identity, $Bound) {
    Invoke-ContextFixtureMutation $Identity $Bound $true
}

function Get-ContextFixtureErrors($Caught, [object[]]$History) {
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

function Test-ContextFixture([string]$Route, [string]$Operation, [string]$Phase) {
    $scenario = New-FixtureScenario ('context-' + $Route + '-' + $Operation + '-' + $Phase)
    $plan = New-FixturePlan $script:DelayedIdentity
    $entryId = $null
    if ($Operation -ceq 'Undo') {
        $entryId = New-FixtureUndoJournal $plan $scenario.FirstJournal
    }
    $accountBefore = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $script:Records[$script:DelayedIdentity] -Depth 10 -Compress
    $script:ContextPhase = $Phase
    $script:ContextReads = 0
    $script:ContextGroups = 0
    $script:ContextCause = $null
    $script:ContextError = $null
    $script:ContextMessage = if ($Phase -ceq 'Ambiguous') {
        "Synthetic $Operation acknowledgment was lost."
    }
    else {
        "Synthetic $Operation pre-dispatch read failed."
    }
    $script:ContextErrorId = 'Fixture' + $Operation + $Phase + 'ContextFault'
    $script:ContextWarning = 'Synthetic ' + $Operation + ' warning before the fault.'
    $script:ContextInformation = 'Synthetic ' + $Operation + ' information before the fault.'
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

    Assert-Fixture ($null -ne $caught -and $null -ne $script:ContextCause) 'The initial synthetic failure was not caught by the caller.'
    Assert-Fixture ([object]::ReferenceEquals($caught.Exception.GetBaseException(), $script:ContextCause)) 'Remediation replaced the original provider cause.'
    Assert-Fixture ($script:ContextCause.Message -ceq $script:ContextMessage -and $script:ContextCause.Data['FixtureOriginalMarker'] -ceq 'preserved original cause') 'Remediation changed the original message or cause data.'
    Assert-Fixture ($script:ContextError.Exception -eq $script:ContextCause -and $script:ContextError.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::OperationStopped -and [guid]$script:ContextError.TargetObject -eq $script:DelayedIdentity) 'The original ErrorRecord properties changed.'
    $matching = @(Get-ContextFixtureErrors $caught $history | Where-Object {
        $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -match ('^' + [regex]::Escape($script:ContextErrorId) + '(,|$)') -and
        $_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::OperationStopped -and
        [object]::ReferenceEquals($_.Exception.GetBaseException(), $script:ContextCause)
    })
    Assert-Fixture ($matching.Count -gt 0) 'The operator error/history lost the original error ID, category or cause.'
    $warnings = @($stream | Where-Object { $_ -is [Management.Automation.WarningRecord] })
    $information = @($stream | Where-Object { $_ -is [Management.Automation.InformationRecord] })
    $other = @($stream | Where-Object { $_ -isnot [Management.Automation.WarningRecord] -and $_ -isnot [Management.Automation.InformationRecord] -and $_ -isnot [Management.Automation.ErrorRecord] })
    Assert-Fixture ($warnings.Count -eq 1 -and $warnings[0].Message -ceq $script:ContextWarning -and $information.Count -eq 1 -and [string]$information[0].MessageData -ceq $script:ContextInformation -and $other.Count -eq 0) 'The failed call changed native streams or emitted a success result.'

    $journal = [IO.File]::ReadAllText($scenario.FirstJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
    Assert-Fixture ($journal.Entries.Count -eq 1) 'The failure changed journal entry cardinality.'
    $entry = $journal.Entries[0]
    $failureEntry = if ($Operation -ceq 'Undo') {
        $entry.Undo
    }
    else {
        $entry
    }
    $expectedStatus = if ($Phase -ceq 'Ambiguous') {
        'Failed'
    }
    else {
        'Rejected'
    }
    Assert-Fixture ($failureEntry.Status -ceq $expectedStatus -and $failureEntry.Message -ceq $script:ContextMessage -and $null -eq $failureEntry.After) 'The original failed/rejected journal evidence changed.'
    if ($Operation -ceq 'Undo') {
        Assert-Fixture ($entry.Status -ceq 'Succeeded') 'Failed Undo changed the successful Apply status.'
    }
    Assert-Fixture ($script:ContextReads -eq 1 -and $script:ContextGroups -eq $(if ($Phase -ceq 'Ambiguous') { 1 } else { 0 })) 'Failure handling performed an extra directory observation.'
    Assert-Fixture ((Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $script:Records[$script:DelayedIdentity] -Depth 10 -Compress) -ceq $accountBefore) 'A directory-effect fallback changed the synthetic account.'
    $dispatched = $script:Dispatches.Count + $script:UndoDispatches.Count
    Assert-Fixture ($dispatched -eq $(if ($Phase -ceq 'Ambiguous') { 1 } else { 0 })) 'Failure handling dispatched an additional directory effect.'
    $lease = [IO.File]::Open(($scenario.FirstJournal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $lease.Dispose()

    if ($Phase -ceq 'PreDispatch') {
        $exception = $caught.Exception
        while ($null -ne $exception) {
            Assert-Fixture (-not $exception.Data.Contains($script:ContextKey)) 'A known no-send failure received uncertain-effect context.'
            $exception = $exception.InnerException
        }
        Assert-Fixture (-not [IO.File]::Exists($script:QueuedEffect) -and [IO.Directory]::GetFileSystemEntries($script:AuthorityDirectory).Count -eq 0) 'A known no-send retained a hold or queued an effect.'
    }
    else {
        $held = Get-ADAnalyzerRemediationReservation -ObjectGuid $script:DelayedIdentity
        Assert-Fixture ($held.Status -ceq 'Held' -and [IO.File]::Exists($script:QueuedEffect)) 'The initial ambiguous failure did not retain its reservation.'
        $context = $script:ContextCause.Data[$script:ContextKey]
        Assert-Fixture ($context -is [Collections.IDictionary]) 'The original cause lacks structured reservation context.'
        Assert-Fixture ((($context.Keys | Sort-Object) -join ',') -ceq 'AttemptId,LastConfirmedStep,ObjectGuid,Status') 'Reservation context exposed unexpected fields.'
        Assert-Fixture ($context['ObjectGuid'] -is [guid] -and $context['ObjectGuid'] -eq $script:DelayedIdentity -and $context['AttemptId'] -is [guid] -and $context['AttemptId'] -eq $held.AttemptId -and $context['Status'] -ceq 'Uncertain' -and $context['LastConfirmedStep'] -ceq 'AccountReserved') 'The initial error context does not identify the exact retained attempt.'
        $json = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $context -Depth 5 -Compress
        Assert-Fixture ($json -notmatch [regex]::Escape($script:ContextSecret) -and $json -notmatch 'JournalPath|Credential|Password|DistinguishedName|RawRecord') 'Reservation context copied private or unvalidated failure data.'
    }
    # Test structured opt-in access only. This does not assert a changed default
    # PowerShell error display or require metadata to appear in error text.
    $script:ContextPassed++
}

try {
    foreach ($route in 'Native', 'Direct') {
        foreach ($operation in 'Apply', 'Undo') {
            foreach ($phase in 'PreDispatch', 'Ambiguous') {
                Test-ContextFixture $route $operation $phase
            }
        }
    }
}
finally {
    if ([IO.Directory]::Exists($script:TemporaryRoot)) {
        [IO.Directory]::Delete($script:TemporaryRoot, $true)
    }
}
Write-Output ('PASS remediation failure context ' + $script:ContextPassed)
