[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RepositoryRoot,
    [ValidateSet('Native', 'Direct')]
    [string]$Route = 'Native',
    [ValidateSet('Parent', 'Sender', 'Challenger')]
    [string]$Role = 'Parent',
    [string]$ScenarioRoot
)

$ErrorActionPreference = 'Stop'
$fixturePath = $MyInvocation.MyCommand.Path
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$identity = [guid]'20000000-0000-4000-8000-000000000001'

function Assert-RestartFixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

if ($Role -ne 'Parent') {
    Assert-RestartFixture (
        $ScenarioRoot -and [IO.Path]::IsPathRooted($ScenarioRoot) -and [IO.Directory]::Exists($ScenarioRoot)
    ) 'Expected the existing disposable restart scenario directory.'
    $script:AuthorityDirectory = [IO.Path]::GetFullPath((Join-Path $ScenarioRoot 'authority'))
    $script:QueuedEffect = Join-Path $ScenarioRoot 'sender.queued'
    $script:DispatchMarker = Join-Path $ScenarioRoot ($Role + '.dispatch')
    $journalPath = Join-Path $ScenarioRoot ($Role + '/journal.json')
    . (Join-Path $PSScriptRoot 'UncertainRemediationFixture.ps1') -RepositoryRoot $RepositoryRoot -DefinitionsOnly

    function Invoke-FixtureDisable([guid]$Identity, $Bound) {
        [IO.File]::WriteAllText($script:DispatchMarker, $Identity.ToString('D'))
        Assert-FixtureBinding $Bound
        Assert-RestartFixture (
            $Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and
            -not $Bound.WhatIf -and -not $Bound.Confirm
        ) 'The synthetic restart provider received an unexpected nested confirmation.'
        Assert-RestartFixture ($Role -eq 'Sender') 'The restarted challenger dispatched a second provider write.'
        $journal = [IO.File]::ReadAllText($script:DispatchJournal) | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $entry = $journal.Entries[-1]
        Assert-RestartFixture (
            $entry.Status -ceq 'Prepared' -and [guid]$entry.ObjectGuid -eq $Identity
        ) 'The sender entered the provider without a durable Prepared entry.'

        # Publish the queue marker atomically before blocking in the simulated provider.
        $staged = $script:QueuedEffect + '.staged'
        [IO.File]::WriteAllText($staged, $Identity.ToString('D'))
        [IO.File]::Move($staged, $script:QueuedEffect)
        Start-Sleep -Seconds 60
        throw 'The parent did not terminate its sender at the synthetic provider barrier.'
    }

    $script:Records = @{}
    $script:Records[$identity] = New-FixtureRecord $identity 1
    $plan = New-FixturePlan $identity
    if ($Role -eq 'Sender') {
        Invoke-FixtureApply $Route $plan $journalPath
        throw 'The sender left its synthetic provider barrier.'
    }

    Assert-RestartFixture (
        [IO.File]::Exists($script:QueuedEffect) -and
        [guid][IO.File]::ReadAllText($script:QueuedEffect) -eq $identity
    ) 'The restarted challenger did not observe the pending synthetic request.'
    Assert-FixtureFailure {
        Invoke-FixtureApply $Route $plan $journalPath
    } '(?i)\buncertain\b'
    Assert-RestartFixture (
        -not [IO.File]::Exists($script:DispatchMarker) -and $script:Records[$identity].Enabled
    ) 'The restarted challenger mutated the synthetic account.'
    Write-Output "PASS restarted $Route Apply holds the pending synthetic effect"
    return
}

$engine = (Get-Process -Id $PID).Path
$ScenarioRoot = Join-Path ([IO.Path]::GetTempPath()) ('ad-effect-restart-' + [guid]::NewGuid().ToString('N'))
$queued = Join-Path $ScenarioRoot 'sender.queued'
$firstJournal = Join-Path $ScenarioRoot 'Sender/journal.json'
$processes = [Collections.Generic.List[Diagnostics.Process]]::new()

function Start-RestartChild([string]$ChildRole, [string]$ChildRoute) {
    $arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" -RepositoryRoot "{1}" -ScenarioRoot "{2}" -Role {3} -Route {4}' -f
        $fixturePath, $RepositoryRoot, $ScenarioRoot, $ChildRole, $ChildRoute
    $launch = @{
        FilePath = $engine
        ArgumentList = $arguments
        PassThru = $true
        RedirectStandardOutput = Join-Path $ScenarioRoot ($ChildRole + '.out')
        RedirectStandardError = Join-Path $ScenarioRoot ($ChildRole + '.err')
    }
    $process = Start-Process @launch
    $processes.Add($process)
    # Cache this before exit for Windows PowerShell 5.1.
    $null = $process.Handle
    return $process
}

try {
    foreach ($name in 'authority', 'Sender', 'Challenger') {
        $null = [IO.Directory]::CreateDirectory((Join-Path $ScenarioRoot $name))
    }
    $sender = Start-RestartChild Sender $Route
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($queued) -and -not $sender.HasExited) {
        Assert-RestartFixture ($watch.Elapsed.TotalSeconds -lt 45) 'Timed out waiting for the sender provider barrier.'
        Start-Sleep -Milliseconds 25
    }
    if ($sender.HasExited) {
        $sender.WaitForExit()
        $senderError = [IO.File]::ReadAllText((Join-Path $ScenarioRoot 'Sender.err'))
        throw ('Sender exited before the parent could interrupt it at the pending provider barrier. ' + $senderError)
    }
    Assert-RestartFixture ([IO.File]::Exists($queued)) 'Sender did not reach the pending provider barrier.'
    Assert-RestartFixture (
        [guid][IO.File]::ReadAllText($queued) -eq $identity -and
        [guid][IO.File]::ReadAllText((Join-Path $ScenarioRoot 'Sender.dispatch')) -eq $identity
    ) 'The provider barrier did not bind the original account.'
    $preparedBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($firstJournal))
    $sender.Kill()
    Assert-RestartFixture ($sender.WaitForExit(10000)) 'The sender did not exit after termination.'

    # The ordinary journal lease released on process exit. That does not settle the request.
    $released = [IO.File]::Open(($firstJournal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $released.Dispose()

    $alternative = if ($Route -eq 'Native') { 'Direct' } else { 'Native' }
    $challenger = Start-RestartChild Challenger $alternative
    Assert-RestartFixture ($challenger.WaitForExit(45000)) 'The restarted challenger did not exit.'
    $challenger.WaitForExit()
    $marker = "PASS restarted $alternative Apply holds the pending synthetic effect"
    $output = [IO.File]::ReadAllLines((Join-Path $ScenarioRoot 'Challenger.out'))
    if ($challenger.ExitCode -ne 0 -or @($output | Where-Object { $_ -ceq $marker }).Count -ne 1) {
        $challengerError = [IO.File]::ReadAllText((Join-Path $ScenarioRoot 'Challenger.err'))
        throw ('The restarted challenger did not report uncertainty. ' + $challengerError)
    }
    Assert-RestartFixture (
        -not [IO.File]::Exists((Join-Path $ScenarioRoot 'Challenger.dispatch')) -and
        [guid][IO.File]::ReadAllText($queued) -eq $identity -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($firstJournal)) -ceq $preparedBytes
    ) 'The restarted challenger dispatched or disturbed the unresolved request.'
    Write-Output "PASS synthetic restart $Route to $alternative"
}
finally {
    foreach ($process in $processes) {
        try {
            if (-not $process.HasExited) {
                $process.Kill()
                $null = $process.WaitForExit(5000)
            }
        }
        finally {
            $process.Dispose()
        }
    }
    if ([IO.Directory]::Exists($ScenarioRoot)) {
        [IO.Directory]::Delete($ScenarioRoot, $true)
    }
}
