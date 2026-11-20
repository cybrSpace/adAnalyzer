param(
    [string]$RepositoryRoot,
    [string]$Mode
)
$ErrorActionPreference = 'Stop'

function Assert-Formatter($Value, [string]$Message) {
    if (-not $Value) {
        throw $Message
    }
}

function Get-FormatterOverlapRules {
    [ordered]@{
        'bad.user' = @{
            msg = 'first fixture'
            value = @('fixture-first', 'fixture-alternate')
        }
        'denied' = @{
            msg = 'middle fixture'
            value = @('fixture-middle')
        }
        'locked' = @{
            msg = 'last fixture'
            value = @('fixture-last')
        }
        'empty fixture' = @{
            msg = ''
            value = @('fixture-empty')
        }
    }
}

function Get-FormatterOutcome([scriptblock]$Operation, [Collections.IDictionary]$State) {
    $results = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Operation | ForEach-Object { $results.Add($_) }
    }
    catch {
        $failure = $_
    }
    $message = $null
    if ($null -ne $failure) {
        $message = $failure.Exception.GetBaseException().Message
    }
    [pscustomobject]@{
        Rows = $results.ToArray()
        Failure = $message
        Attempt = $State['attempt']
    }
}

function Invoke-FormatterDirectCases {
    $path = Join-Path $RepositoryRoot 'bin/ADHostScanState.ps1'
    $workerSource = Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1'
    $originalLocation = (Get-Location).Path
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('ad-formatter-direct-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($directory)
    try {
        Set-Location -LiteralPath $directory
        $sentinel = [hashtable]::Synchronized(@{ attempt = 19 })
        $var = $sentinel
        $syncRoot = $var.SyncRoot
        $load = @(. $path)
        $owner = [ADAnalyzerHostScanState]::new()
        Assert-Formatter ($load.Count -eq 0 -and $owner.GetType().Name -ceq 'ADAnalyzerHostScanState' -and
            [object]::ReferenceEquals($var, $sentinel) -and [object]::ReferenceEquals($syncRoot, $var.SyncRoot) -and
            $var['attempt'] -eq 19 -and -not (Test-Path -LiteralPath 'Function:Format-WindowsServerException') -and
            [IO.Directory]::GetFileSystemEntries($directory).Count -eq 0) 'Class-only loading or construction had caller effects'

        $startup = @(. $workerSource)
        $rules = Get-FormatterOverlapRules
        $ruleText = ConvertTo-Json -InputObject $rules -Depth 8 -Compress
        $constant['error'] = $rules
        $nativeState = $var
        $nativeRoot = $nativeState.SyncRoot
        $directState = [hashtable]::Synchronized(@{ attempt = 0 })
        $directRoot = $directState.SyncRoot
        $overlap = 'fixture-first fixture-middle fixture-last'
        $cases = @(
            @{
                Name = 'ordered scalar'
                Value = $overlap
                Start = 0
                Limit = 10
                Attempts = 2
                Output = 'server_exception(last fixture)'
            }
            @{
                Name = 'ordered array with multiple values in one category'
                Value = @('fixture-first', 'fixture-alternate', 'fixture-middle', 'fixture-last')
                Start = 0
                Limit = 10
                Attempts = 2
                Output = 'server_exception(last fixture)'
            }
            @{
                Name = 'unknown'
                Value = 'fixture-unknown'
                Start = 0
                Limit = 10
                Attempts = 0
                Output = 'server_exception(unknown exception (fixture-unknown))'
            }
            @{
                Name = 'blank matching message'
                Value = 'fixture-empty'
                Start = 0
                Limit = 10
                Attempts = 0
                Output = 'server_exception(unknown exception (fixture-empty))'
            }
            @{
                Name = 'non-auth when already over budget'
                Value = 'fixture-middle'
                Start = 8
                Limit = 2
                Attempts = 8
                Output = 'server_exception(middle fixture)'
            }
            @{
                Name = 'first category reaches threshold before later matches'
                Value = $overlap
                Start = 0
                Limit = 1
                Attempts = 1
                Output = $null
            }
            @{
                Name = 'second category reaches threshold'
                Value = @('fixture-first', 'fixture-middle', 'fixture-last')
                Start = 0
                Limit = 2
                Attempts = 2
                Output = $null
            }
        )
        Assert-Formatter ($startup.Count -eq 0 -and -not [object]::ReferenceEquals($nativeState, $sentinel)) 'Worker setup did not create its own caller state'
        foreach ($case in $cases) {
            $nativeState['attempt'] = $case.Start
            $directState['attempt'] = $case.Start
            $constant['property']['limit'] = $case.Limit
            $native = Get-FormatterOutcome {
                Format-WindowsServerException -value $case.Value
            } $nativeState
            $direct = Get-FormatterOutcome {
                $owner.Format($case.Value, $rules, $case.Limit, $directState)
            } $directState
            Assert-Formatter ($native.Attempt -eq $case.Attempts -and $direct.Attempt -eq $case.Attempts -and
                $native.Failure -ceq $direct.Failure -and $native.Rows.Count -eq $direct.Rows.Count) (
                'Command and direct outcomes diverged for ' + $case.Name
            )
            if ($null -eq $case.Output) {
                Assert-Formatter ($direct.Rows.Count -eq 0 -and $direct.Failure -ceq 'exceeded invalid attempt limit') (
                    'Threshold failed to stop without a result for ' + $case.Name
                )
            }
            else {
                Assert-Formatter ($direct.Rows.Count -eq 1 -and $null -eq $direct.Failure -and
                    $direct.Rows[0] -ceq $case.Output -and $native.Rows[0] -ceq $case.Output) (
                    'Classification changed for ' + $case.Name
                )
            }
            Assert-Formatter ([object]::ReferenceEquals($var, $nativeState) -and
                [object]::ReferenceEquals($nativeState.SyncRoot, $nativeRoot) -and
                [object]::ReferenceEquals($directState.SyncRoot, $directRoot) -and
                [object]::ReferenceEquals($constant['error'], $rules) -and
                (ConvertTo-Json -InputObject $rules -Depth 8 -Compress) -ceq $ruleText) 'Borrowed configuration, state or lock changed'
        }
        $rules['locked'].msg = 'changed caller rule'
        $state = [hashtable]::Synchronized(@{ attempt = 0 })
        $newOwner = [ADAnalyzerHostScanState]::new()
        $lastDirect = $owner.Format('fixture-last', $rules, 10, $state)
        $lastOther = $newOwner.Format('fixture-last', $rules, 10, $state)
        Assert-Formatter ($lastDirect -ceq 'server_exception(changed caller rule)' -and $lastOther -ceq $lastDirect -and
            $state['attempt'] -eq 2 -and $directState['attempt'] -eq 2 -and $nativeState['attempt'] -eq 2 -and
            [Management.Automation.PSSerializer]::Serialize($owner) -cnotmatch 'changed caller rule|fixture-first|attempt') (
            'Owner retained previous state or rule data'
        )
        $shadowedRules = [ordered]@{
            'locked' = @{
                msg = 'auth fixture'
                value = @('fixture-shadow')
            }
            'Keys' = @{
                msg = 'ordinary Keys rule'
                value = @('fixture-shadow')
            }
        }
        $states = @(
            [hashtable]::Synchronized(@{})
            [Collections.Generic.Dictionary[string, object]]::new()
        )
        foreach ($borrowedState in $states) {
            $borrowedState['attempt'] = 0
            $borrowedState['SyncRoot'] = $null
            $output = $owner.Format('fixture-shadow', $shadowedRules, 3, $borrowedState)
            Assert-Formatter ($output -ceq 'server_exception(ordinary Keys rule)' -and
                $borrowedState['attempt'] -eq 1 -and $null -eq $borrowedState['SyncRoot']) (
                'An ordinary dictionary key shadowed ordered rules or the original SyncRoot'
            )
        }
        Invoke-FormatterLockCheck $owner $rules
    }
    finally {
        Set-Location -LiteralPath $originalLocation
        [IO.Directory]::Delete($directory, $true)
    }
}

function Invoke-FormatterLockCheck($Owner, [Collections.IDictionary]$Rules) {
    # Every attempt getter and setter checks the real lock held by the caller.
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Threading;

namespace ADAnalyzer.FormatterFixture
{
    public sealed class MonitorProbe : Hashtable
    {
        private readonly object gate = new object();
        public override object SyncRoot { get { return gate; } }
        public override bool IsSynchronized { get { return true; } }
        public int Attempts { get { return (int)base["attempt"]; } }
        public int Reads { get; private set; }
        public int Writes { get; private set; }

        public MonitorProbe()
        {
            base["attempt"] = 0;
        }

        private void RequireGate()
        {
            if (!Monitor.IsEntered(gate))
            {
                throw new InvalidOperationException("The caller-owned SyncRoot was not held.");
            }
        }

        public override object this[object key]
        {
            get
            {
                if (Object.Equals(key, "attempt"))
                {
                    RequireGate();
                    Reads++;
                }
                return base[key];
            }
            set
            {
                if (Object.Equals(key, "attempt"))
                {
                    RequireGate();
                    Writes++;
                }
                base[key] = value;
            }
        }
    }
}
'@ -ErrorAction Stop
    $state = [ADAnalyzer.FormatterFixture.MonitorProbe]::new()
    $root = $state.SyncRoot
    $state['SyncRoot'] = [object]::new()
    $null = $Owner.Format('fixture-middle', $Rules, 2, $state)
    Assert-Formatter ($state.Reads -eq 0 -and $state.Writes -eq 0) 'Unrelated category accessed the auth budget'
    $actual = $Owner.Format('fixture-first', $Rules, 2, $state)
    Assert-Formatter ($actual -ceq 'server_exception(first fixture)' -and $state.Attempts -eq 1 -and
        $state.Reads -ge 1 -and $state.Writes -eq 1) 'Expected one guarded attempt increment and threshold decision'
    $failure = $null
    try {
        $null = $Owner.Format('fixture-last', $Rules, 2, $state)
    }
    catch {
        $failure = $_
    }
    Assert-Formatter ($null -ne $failure -and $failure.Exception.GetBaseException().Message -ceq 'exceeded invalid attempt limit' -and
        $state.Attempts -eq 2 -and $state.Writes -eq 2 -and -not [Threading.Monitor]::IsEntered($root)) (
        'Threshold failure lost the attempt or left the caller lock held'
    )
}

function Invoke-FormatterActualPoolCases {
    $originalLocation = (Get-Location).Path
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('ad-formatter-pool-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($directory)
    $pool = $null
    $barrier = $null
    $jobs = [Collections.Generic.List[object]]::new()
    try {
        Set-Location -LiteralPath $directory
        $startup = @(. (Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1'))
        Assert-Formatter ($startup.Count -eq 0 -and -not ('ADAnalyzerHostScanState' -as [type])) 'Worker script eagerly loaded formatter state'
        $expectedPath = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'bin/ADHostScanState.ps1'))
        Assert-Formatter ($constant['HostExceptionFormatterPath'] -ceq $expectedPath) 'Cloned formatter configuration lost its absolute class path'
        $var['attempt'] = 0
        $constant['property']['limit'] = 3
        $originalConfig = $constant
        $originalState = $var
        $originalLock = $var.SyncRoot
        $workerCount = 2
        $calls = 20
        $barrier = [Threading.Barrier]::new($workerCount)
        $pool = (Initialize-RunspacePool -MaxRunspaces $workerCount).pool
        $pool.Open()
        $worker = @'
param($ExpectedConfiguration, $ExpectedState, $ExpectedLock, $Barrier, $Calls, $WorkingDirectory)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $WorkingDirectory
if (-not [object]::ReferenceEquals($constant, $ExpectedConfiguration) -or
    -not [object]::ReferenceEquals($var, $ExpectedState) -or
    -not [object]::ReferenceEquals($var.SyncRoot, $ExpectedLock) -or
    ('ADAnalyzerHostScanState' -as [type])) {
    throw 'Official clone did not preserve its caller configuration and lock or inherited a formatter type'
}
if (-not $Barrier.SignalAndWait(10000)) {
    throw 'Official formatter workers did not reach their barrier'
}
$accepted = 0
$rejected = 0
for ($index = 0; $index -lt $Calls; $index++) {
    $key = if ($index % 2) {
        'bad.user'
    }
    else {
        'locked'
    }
    $value = $constant['error'][$key]['value'][0]
    $rows = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        Format-WindowsServerException -value $value | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $failure = $_
    }
    if ($null -eq $failure) {
        if ($rows.Count -ne 1 -or $rows[0] -cne ('server_exception(' + $constant['error'][$key]['msg'] + ')')) {
            throw 'Official formatter worker returned the wrong accepted row'
        }
        $accepted++
    }
    else {
        if ($rows.Count -ne 0 -or $failure.Exception.GetBaseException().Message -cne 'exceeded invalid attempt limit') {
            throw $failure
        }
        $rejected++
    }
    if ('ADAnalyzerHostScanState' -as [type]) {
        throw 'An operation-local formatter type leaked into the cloned worker'
    }
}
[pscustomobject]@{
    Accepted = $accepted
    Rejected = $rejected
}
'@
        for ($index = 0; $index -lt $workerCount; $index++) {
            $shell = [powershell]::Create()
            try {
                $shell.RunspacePool = $pool
                $invocation = $shell.AddScript($worker).AddArgument($originalConfig).AddArgument($originalState).AddArgument($originalLock)
                $null = $invocation.AddArgument($barrier).AddArgument($calls).AddArgument($directory)
                $handle = $shell.BeginInvoke()
                $jobs.Add([pscustomobject]@{
                        Shell = $shell
                        Handle = $handle
                        Wait = $handle.AsyncWaitHandle
                    })
            }
            catch {
                $shell.Dispose()
                throw
            }
        }
        $accepted = 0
        $rejected = 0
        foreach ($job in $jobs) {
            Assert-Formatter ($job.Wait.WaitOne(30000)) 'Official formatter worker exceeded the bounded wait'
            $results = @($job.Shell.EndInvoke($job.Handle))
            Assert-Formatter ($job.Shell.InvocationStateInfo.State -eq 'Completed' -and
                $job.Shell.Streams.Error.Count -eq 0 -and $results.Count -eq 1) (
                'Official formatter worker failed: ' + ($job.Shell.Streams.Error -join ' | ')
            )
            Assert-Formatter ($results[0].Accepted + $results[0].Rejected -eq $calls) 'Worker missed a formatter call'
            $accepted += $results[0].Accepted
            $rejected += $results[0].Rejected
        }
        Assert-Formatter ($accepted -eq 2 -and $rejected -eq ($workerCount * $calls - 2) -and
            $var['attempt'] -eq ($workerCount * $calls) -and [object]::ReferenceEquals($var, $originalState) -and
            [object]::ReferenceEquals($var.SyncRoot, $originalLock) -and [object]::ReferenceEquals($constant, $originalConfig)) (
            'Official pool lost shared counters, thresholds or caller references'
        )
    }
    finally {
        foreach ($job in $jobs) {
            if (-not $job.Handle.IsCompleted) {
                $job.Shell.Stop()
            }
            $job.Wait.Dispose()
            $job.Shell.Dispose()
        }
        if ($null -ne $pool) {
            $pool.Dispose()
        }
        if ($null -ne $barrier) {
            $barrier.Dispose()
        }
        Set-Location -LiteralPath $originalLocation
        [IO.Directory]::Delete($directory, $true)
    }
    $constant['property']['limit'] = [int]::MaxValue
    $final = Format-WindowsServerException -value $constant['error']['locked']['value'][0]
    Assert-Formatter ($final -ceq 'server_exception(account is locked)' -and
        $var['attempt'] -eq ($workerCount * $calls + 1) -and -not ('ADAnalyzerHostScanState' -as [type]) -and
        (Get-Location).Path -ceq $originalLocation) 'Caller formatter failed after disposing the official pool'
}

if ($Mode -eq 'Direct') {
    Invoke-FormatterDirectCases
    'PASS formatter contract ' + $Mode
    return
}
if ($Mode -eq 'ActualPool') {
    Invoke-FormatterActualPoolCases
    'PASS formatter contract ' + $Mode
    return
}

. (Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1')
$var['attempt'] = 0
if ($Mode -eq 'Known') {
    $constant.property.limit = [int]::MaxValue
    foreach ($key in $constant.error.Keys) {
        foreach ($value in $constant.error[$key].value) {
            $actual = Format-WindowsServerException -value $value
            Assert-Formatter ($actual -ceq ('server_exception(' + $constant.error[$key].msg + ')')) ('Known classification failed ' + $key)
        }
    }
    Assert-Formatter ($var['attempt'] -eq 3) 'Non-auth error incremented budget or auth error missed'
}
elseif ($Mode -eq 'Unknown') {
    $message = 'caller-poison'
    $value = 'fixture unknown diagnostic'
    $actual = Format-WindowsServerException -value $value
    Assert-Formatter ($actual -ceq ('server_exception(unknown exception (' + $value + '))') -and
        $message -ceq 'caller-poison' -and
        $var['attempt'] -eq 0) 'Unknown input inherited caller state or changed budget'
    $null = Format-WindowsServerException -value $constant.error.denied.value[0]
    $again = Format-WindowsServerException -value $value
    Assert-Formatter ($again -ceq $actual) 'Previous classification leaked'
}
elseif ($Mode -eq 'Limits') {
    $constant.property.limit = 3
    $null = Format-WindowsServerException -value $constant.error['bad.user'].value[0]
    $null = Format-WindowsServerException -value $constant.error.locked.value[0]
    Assert-Formatter ($var['attempt'] -eq 2) 'Shared category counter changed'
    foreach ($expected in @(3, 4)) {
        $caught = $null
        try {
            $null = Format-WindowsServerException -value $constant.error.locked.value[0]
        }
        catch {
            $caught = $_
        }
        Assert-Formatter ($null -ne $caught -and
            $caught.Exception.Message -match 'exceeded invalid attempt limit' -and
            $var['attempt'] -eq $expected) 'Budget boundary/over-limit behavior changed'
    }
    $denied = Format-WindowsServerException -value $constant.error.denied.value[0]
    Assert-Formatter ($denied -ceq 'server_exception(access denied)' -and $var['attempt'] -eq 4) 'Unrelated diagnostic consumed auth budget'
}
elseif ($Mode -in @('Concurrent', 'ConcurrentLimit')) {
    $constant.property.limit = if ($Mode -eq 'Concurrent') {
        [int]::MaxValue
    }
    else {
        3
    }
    $definition = (Get-Command Format-WindowsServerException -CommandType Function).Definition
    $definition = 'function Format-WindowsServerException {' + [Environment]::NewLine + $definition + [Environment]::NewLine + '}'
    $workers = 4
    $callsPerWorker = if ($Mode -eq 'Concurrent') {
        1000
    }
    else {
        25
    }
    $referenceId = [Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($var)
    $worker = {
        param(
            $definition,
            $constant,
            $var,
            $barrier,
            [int]$callsPerWorker,
            [int]$referenceId

        )
        $ErrorActionPreference = 'Stop'
        if ([Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($var) -ne $referenceId) {
            throw 'Shared table was copied'
        }
        . ([scriptblock]::Create($definition))
        if (-not $barrier.SignalAndWait(30000)) {
            throw 'Worker start barrier timed out'
        }
        $allowed = 0
        $rejected = 0
        for ($i = 0; $i -lt $callsPerWorker; $i++) {
            $key = if ($i % 2) {
                'bad.user'
            }
            else {
                'locked'
            }
            try {
                $formatted = Format-WindowsServerException -value $constant.error[$key].value[0]
                if ($formatted -cne ('server_exception(' + $constant.error[$key].msg + ')')) {
                    throw 'Worker classification failed'
                }
                $allowed++
            }
            catch {
                if ($constant.property.limit -ne 3 -or $_.Exception.Message -notmatch 'exceeded invalid attempt limit') {
                    throw
                }
                $rejected++
            }
        }
        [pscustomobject]@{
            Completed = ($allowed + $rejected)
            Allowed = $allowed
            Rejected = $rejected
            SharedReference = $true
        }
    }
    $pool = $null
    $barrier = $null
    $jobs = [Collections.Generic.List[object]]::new()
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        $barrier = [Threading.Barrier]::new($workers)
        $pool = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($workers, $workers)
        $pool.ThreadOptions = [Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
        $pool.Open()
        for ($i = 0; $i -lt $workers; $i++) {
            $shell = [powershell]::Create()
            try {
                $shell.RunspacePool = $pool
                $null = $shell.AddScript($worker.ToString()).AddArgument($definition).AddArgument($constant).AddArgument($var).AddArgument($barrier).AddArgument($callsPerWorker).AddArgument($referenceId)
                $handle = $shell.BeginInvoke()
                $jobs.Add([pscustomobject]@{
                        Shell = $shell
                        Handle = $handle
                        Wait = $handle.AsyncWaitHandle
                    })
            }
            catch {
                $shell.Dispose()
                throw
            }
        }
        $completed = 0
        $errors = 0
        $allowed = 0
        $rejected = 0
        foreach ($job in $jobs) {
            if (-not $job.Wait.WaitOne(30000)) {
                $job.Shell.Stop()
                throw 'Bounded worker wait timed out'
            }
            $rows = @($job.Shell.EndInvoke($job.Handle))
            $errors += $job.Shell.Streams.Error.Count
            Assert-Formatter ($rows.Count -eq 1 -and $rows[0].SharedReference) 'Worker result was incomplete'
            $completed += $rows[0].Completed
            $allowed += $rows[0].Allowed
            $rejected += $rows[0].Rejected
        }
        $expected = $workers * $callsPerWorker
        Assert-Formatter ($errors -eq 0 -and
            $completed -eq $expected -and
            $var['attempt'] -eq $expected) ('Concurrent counter mismatch: ' + $var['attempt'] + ' / ' + $completed)
        Assert-Formatter ($allowed -eq $(if ($Mode -eq 'Concurrent') {
                    4000
                }
                else {
                    2
                }) -and $rejected -eq $(if ($Mode -eq 'Concurrent') {
                    0
                }
                else {
                    98
                })) 'Concurrent budget decisions changed'
    }
    finally {
        foreach ($job in $jobs) {
            try {
                if (-not $job.Handle.IsCompleted) {
                    $job.Shell.Stop()
                }
            }
            catch {
                $cleanupErrors.Add('Stop')
            }
            try {
                $job.Wait.Dispose()
            }
            catch {
                $cleanupErrors.Add('Wait')
            }
            try {
                $job.Shell.Dispose()
            }
            catch {
                $cleanupErrors.Add('PowerShell')
            }
        }
        if ($null -ne $pool) {
            try {
                $pool.Close()
            }
            catch {
                $cleanupErrors.Add('PoolClose')
            }
            try {
                $pool.Dispose()
            }
            catch {
                $cleanupErrors.Add('PoolDispose')
            }
        }
        if ($null -ne $barrier) {
            try {
                $barrier.Dispose()
            }
            catch {
                $cleanupErrors.Add('Barrier')
            }
        }
    }
    Assert-Formatter ($cleanupErrors.Count -eq 0) 'Concurrent fixture cleanup failed'
}
else {
    throw 'Unknown fixture mode'
}
'PASS formatter contract ' + $Mode
