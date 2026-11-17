[CmdletBinding()]
param(
    [ValidateSet('Inert', 'Construction', 'Direct', 'Command', 'Cli', 'MissingCli', 'EmptyCli', 'WhitespaceCli', 'CliWhatIf', 'InvalidTargets', 'Credential', 'Defaults', 'Legacy', 'LegacyGuard', 'Empty', 'QueryFailure', 'ProjectionFailure', 'CleanupFailure', 'Export', 'WhatIf', 'ExportFailure', 'Isolation')]
    [string]$Case = 'Inert'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $repositoryRoot 'etc/Get-NTLMEvents.ps1'
$global:NtlmFixture_CredentialCalls = 0
$global:NtlmFixture_DateCalls = 0
$global:NtlmFixture_QueryCalls = [Collections.Generic.List[object]]::new()
$global:NtlmFixture_WriteCalls = [Collections.Generic.List[object]]::new()
$global:NtlmFixture_ReturnedEvents = [Collections.Generic.List[object]]::new()
$global:NtlmFixture_Mode = 'Blocked'
$global:NtlmFixture_FixtureCredential = [pscredential]::new(
    'ntlm-fixture-credential-marker',
    (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force)
)
$since = [datetime]'2026-11-01T10:00:00Z'

class NtlmFixtureBadTime {
    [string] ToString([string]$Format) {
        throw 'fixture event projection failure'
    }
}

class NtlmFixtureEvent : IDisposable {
    [object]$TimeCreated
    [object[]]$Properties
    [int]$DisposeCount
    [bool]$FailDispose

    NtlmFixtureEvent([string]$UserName, [bool]$Malformed, [bool]$DisposalFailure) {
        $this.TimeCreated = [datetime]'2026-01-02T03:04:05Z'
        $this.Properties = @(
            foreach ($i in 0..20) {
                [pscustomobject]@{
                    Value = $null
                }
            }
        )
        $this.Properties[5].Value = $UserName
        $this.Properties[8].Value = 3
        $this.Properties[11].Value = 'fixture-workstation'
        $this.Properties[20].Value = 2
        $this.FailDispose = $DisposalFailure
        if ($Malformed) {
            $this.TimeCreated = [NtlmFixtureBadTime]::new()
        }
    }

    [void] Dispose() {
        $this.DisposeCount++
        if ($this.FailDispose) {
            throw 'fixture event cleanup failure'
        }
    }
}

function Assert-Ntlm($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Date {
    [CmdletBinding()]
    param()

    $global:NtlmFixture_DateCalls++
    return [datetime]'2026-11-02T10:00:00Z'
}

function Get-Credential {
    [CmdletBinding()]
    param($UserName, $Message)

    $global:NtlmFixture_CredentialCalls++
    if ($global:NtlmFixture_Mode -eq 'Blocked') {
        throw 'Unexpected credential prompt while loading the NTLM script.'
    }
    return $global:NtlmFixture_FixtureCredential
}

function Get-WinEvent {
    [CmdletBinding()]
    param($FilterHashtable, $LogName, $FilterXPath, $Credential, $ComputerName)

    $global:NtlmFixture_QueryCalls.Add(@{} + $PSBoundParameters)
    if ($global:NtlmFixture_Mode -eq 'Blocked') {
        throw 'Unexpected event query while loading the NTLM script.'
    }
    if ($global:NtlmFixture_Mode -eq 'QueryFailure' -and $ComputerName -eq 'two') {
        throw 'fixture later host query failure'
    }
    if ($global:NtlmFixture_Mode -eq 'NonTerminating') {
        Write-Error 'fixture nonterminating query failure'
        return
    }
    if ($global:NtlmFixture_Mode -eq 'Empty') {
        return
    }

    $malformed = $global:NtlmFixture_Mode -in @('ProjectionFailure', 'ProjectionAndCleanup')
    $disposeFailure = $global:NtlmFixture_Mode -in @('CleanupFailure', 'ProjectionAndCleanup')
    $event = [NtlmFixtureEvent]::new('fixture-user', $malformed, $disposeFailure)
    $global:NtlmFixture_ReturnedEvents.Add($event)
    $event
    if (-not $malformed -and -not $disposeFailure) {
        $anonymous = [NtlmFixtureEvent]::new('ANONYMOUS LOGON', $false, $false)
        $global:NtlmFixture_ReturnedEvents.Add($anonymous)
        $anonymous
    }
}

function Invoke-FixtureWriter {
    [CmdletBinding()]
    param($Path, $Content)

    $global:NtlmFixture_WriteCalls.Add(@{} + $PSBoundParameters)
    if ($global:NtlmFixture_Mode -eq 'Blocked') {
        throw 'Unexpected file write while loading the NTLM script.'
    }
    if ($global:NtlmFixture_Mode -eq 'ExportFailure') {
        throw 'fixture export failure'
    }
    return $Path
}

function Reset-Calls {
    $global:NtlmFixture_CredentialCalls = 0
    $global:NtlmFixture_DateCalls = 0
    $global:NtlmFixture_QueryCalls.Clear()
    $global:NtlmFixture_WriteCalls.Clear()
    $global:NtlmFixture_ReturnedEvents.Clear()
}

function Assert-Query($Call, [datetime]$Start) {
    Assert-Ntlm ($Call.LogName -ceq 'Security') 'Event log changed.'
    $utc = $Start.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $expected = "*[System[(EventID=4624) and TimeCreated[@SystemTime >= '$utc']] and EventData[Data[@Name='LmPackageName']='NTLM V1']]"
    Assert-Ntlm ($Call.FilterXPath -ceq $expected) 'NTLM XPath or UTC start boundary changed.'
    $null = [Xml.XPath.XPathExpression]::Compile($Call.FilterXPath)
    Assert-Ntlm (-not $Call.ContainsKey('FilterHashtable')) 'Modern scan used version-dependent named Hashtable filters.'
    Assert-Ntlm ([string]$Call.ErrorAction -eq 'Stop') 'Event query is not terminating.'
}

function Assert-Rows($Rows, [string[]]$Hosts) {
    Assert-Ntlm ($Rows.Count -eq $Hosts.Count) 'Anonymous exclusion or returned host count changed.'
    $columns = @('Server', 'EventID', 'LogName', 'Time', 'UserName', 'WorkstationName', 'LogonType', 'ImpersonationLevel')
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $row = $Rows[$i]
        $names = if ($row -is [Collections.IDictionary]) {
            @($row.Keys)
        }
        else {
            @($row.PSObject.Properties.Name)
        }
        Assert-Ntlm (($names -join ',') -ceq ($columns -join ',')) 'Eight-field row schema/order changed.'
        Assert-Ntlm ($row.Server -ceq $Hosts[$i]) 'Host order changed.'
        Assert-Ntlm ($row.EventID -eq '4624' -and $row.LogName -ceq 'Security') 'Event identity changed.'
        Assert-Ntlm ($row.Time -ceq ([datetime]'2026-01-02T03:04:05Z').ToString('g')) 'Reported time is not the event creation time.'
        Assert-Ntlm ($row.UserName -ceq 'fixture-user' -and
            $row.WorkstationName -ceq 'fixture-workstation') 'Event principal projection changed.'
        Assert-Ntlm ($row.LogonType -eq 3 -and $row.ImpersonationLevel -eq 2) 'Event type fields changed.'
    }
}

Set-Alias -Name Write-ADAnalyzerFile -Value Invoke-FixtureWriter -Scope Script
$var = [object]::new()
$target = [object]::new()
$ComputerName = 'caller-computer'
$Credential = [object]::new()
$savedVar = $var
$savedTarget = $target
$savedCredential = $Credential

if ($Case -notin @('Cli', 'MissingCli', 'EmptyCli', 'WhitespaceCli', 'CliWhatIf')) {
    $loadedOutput = @(. $sourcePath)
    Assert-Ntlm ($loadedOutput.Count -eq 0 -and $global:NtlmFixture_CredentialCalls -eq 0 -and
        $global:NtlmFixture_QueryCalls.Count -eq 0 -and $global:NtlmFixture_WriteCalls.Count -eq 0 -and
        $global:NtlmFixture_DateCalls -eq 0) 'Loading NTLM definitions performed external work, computed a scan time or emitted output.'
    Assert-Ntlm ([object]::ReferenceEquals($var, $savedVar) -and
        [object]::ReferenceEquals($target, $savedTarget) -and
        [object]::ReferenceEquals($Credential, $savedCredential) -and
        $ComputerName -ceq 'caller-computer') 'Dot sourcing overwrote ordinary caller variables.'
}
$global:NtlmFixture_Mode = 'Success'

switch ($Case) {
    'Inert' {
        Assert-Ntlm ($global:NtlmFixture_QueryCalls.Count -eq 0) 'Inert load queried events.'
    }

    'Construction' {
        $first = [Target]::new([Collections.ArrayList]@('one'), @{})
        $second = [Target]::new([Collections.ArrayList]@('two'), @{})
        Assert-Ntlm (-not [object]::ReferenceEquals($first.Collection, $second.Collection)) 'Constructors share a collection.'
        Assert-Ntlm ($first.Collection.Count -eq 0 -and $second.Collection.Count -eq 0) 'Construction collected events.'
        Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 0 -and $global:NtlmFixture_QueryCalls.Count -eq 0) 'Construction performed external work.'
    }

    'Direct' {
        $servers = [Collections.ArrayList]@('one', 'two')
        $scan = [Target]::Scan($servers, $since, [pscredential]::Empty)
        Assert-Rows @($scan.Report().ToArray()) @('one', 'two')
        Assert-Ntlm ($global:NtlmFixture_QueryCalls.Count -eq 2 -and $global:NtlmFixture_CredentialCalls -eq 0) 'Direct scan prompted or repeated a query.'
        foreach ($call in $global:NtlmFixture_QueryCalls) {
            Assert-Query $call $since
        }
        Assert-Ntlm ($global:NtlmFixture_ReturnedEvents.Count -eq 4) 'Synthetic query discovery changed.'
        Assert-Ntlm (@($global:NtlmFixture_ReturnedEvents | Where-Object DisposeCount -ne 1).Count -eq 0) 'Owned event records were not disposed exactly once.'
        $servers[0] = 'changed-input'
        Assert-Ntlm ($scan.Location[0] -ceq 'one') 'New scan retained the caller selector collection.'
    }

    'Command' {
        $rows = @(Get-ADAnalyzerNtlmEvents -ComputerName @('one', 'two') -StartTime $since)
        Assert-Rows $rows @('one', 'two')
        Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 0 -and $global:NtlmFixture_WriteCalls.Count -eq 0) 'Command prompted or automatically exported.'
        foreach ($call in $global:NtlmFixture_QueryCalls) {
            Assert-Query $call $since
        }
    }

    'Cli' {
        $rows = @(& $sourcePath -ComputerName @('one', 'two') -StartTime $since -Credential $global:NtlmFixture_FixtureCredential)
        Assert-Rows $rows @('one', 'two')
        Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 0 -and $global:NtlmFixture_WriteCalls.Count -eq 0) 'CLI prompted or automatically exported.'
        Assert-Ntlm ($global:NtlmFixture_QueryCalls.Count -eq 2) 'CLI query count changed.'
        foreach ($call in $global:NtlmFixture_QueryCalls) {
            Assert-Query $call $since
            Assert-Ntlm ([object]::ReferenceEquals($call.Credential, $global:NtlmFixture_FixtureCredential)) 'CLI did not forward the supplied credential.'
        }
    }

    { $_ -in @('MissingCli', 'EmptyCli', 'WhitespaceCli') } {
        $global:NtlmFixture_Mode = 'Blocked'
        $failed = $false
        try {
            $arguments = @{}
            if ($Case -eq 'EmptyCli') {
                $arguments.ComputerName = [string[]]@()
            }
            elseif ($Case -eq 'WhitespaceCli') {
                $arguments.ComputerName = @(' ')
            }
            $null = & $sourcePath @arguments
        }
        catch {
            $failed = $true
        }
        Assert-Ntlm $failed 'CLI accepted missing, empty or whitespace targets.'
        Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 0 -and $global:NtlmFixture_QueryCalls.Count -eq 0 -and $global:NtlmFixture_WriteCalls.Count -eq 0) 'Invalid CLI targets reached external work.'
    }

    'CliWhatIf' {
        $rows = @(& $sourcePath -ComputerName one -StartTime $since -OutputPath 'cli.csv' -WhatIf)
        Assert-Rows $rows @('one')
        Assert-Ntlm ($global:NtlmFixture_QueryCalls.Count -eq 1 -and
            $global:NtlmFixture_WriteCalls.Count -eq 0) 'CLI WhatIf did not collect without writes.'
    }

    'InvalidTargets' {
        foreach ($servers in @(
                [Collections.ArrayList]@(),
                [Collections.ArrayList]@(''),
                [Collections.ArrayList]@(' '),
                [Collections.ArrayList]@('one', $null)
            )) {
            $failed = $false
            try {
                $null = [Target]::Scan($servers, $since, [pscredential]::Empty)
            }
            catch {
                $failed = $true
            }
            Assert-Ntlm $failed 'Direct scan accepted empty or whitespace selectors.'
        }
        foreach ($invalidStart in @($null, [datetime]::MinValue)) {
            $failed = $false
            try {
                $null = Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $invalidStart
            }
            catch {
                $failed = $true
            }
            Assert-Ntlm $failed 'Missing start-time value was accepted.'
        }
        Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 0 -and $global:NtlmFixture_QueryCalls.Count -eq 0) 'Invalid selectors/time reached external work.'
    }

    'Credential' {
        foreach ($supplied in @($null, [pscredential]::Empty, $global:NtlmFixture_FixtureCredential)) {
            Reset-Calls
            $scan = [Target]::Scan([Collections.ArrayList]@('one'), $since, $supplied)
            Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 0) 'Modern scan prompted.'
            $call = $global:NtlmFixture_QueryCalls[0]
            if ($null -eq $supplied -or $supplied -eq [pscredential]::Empty) {
                Assert-Ntlm (-not $call.ContainsKey('Credential')) 'Empty credential replaced ambient defaults.'
            }
            else {
                Assert-Ntlm ([object]::ReferenceEquals($supplied, $call.Credential)) 'Credential identity changed.'
            }
            Assert-Ntlm (-not ([Management.Automation.PSSerializer]::Serialize($scan)).Contains('ntlm-fixture-credential-marker')) 'Returned scan retained a credential.'
        }
    }

    'Defaults' {
        $null = Get-ADAnalyzerNtlmEvents -ComputerName @('one', 'two')
        Assert-Ntlm ($global:NtlmFixture_DateCalls -eq 1) 'Default clock was not read exactly once per invocation.'
        Assert-Ntlm ($global:NtlmFixture_QueryCalls.Count -eq 2) 'Default scan query count changed.'
        foreach ($call in $global:NtlmFixture_QueryCalls) {
            Assert-Query $call $since
        }
    }

    'Legacy' {
        $scan = [Target]::Scan([Collections.ArrayList]@('one'), @{
                LogName = 'Security'
                ID = 4624
            }, 'explicit-fixture-user')
        Assert-Rows @($scan.Report().ToArray()) @('one')
        Assert-Ntlm ($global:NtlmFixture_CredentialCalls -eq 1) 'Explicit legacy scan prompt contract changed.'
        Assert-Ntlm ($global:NtlmFixture_QueryCalls[0].ContainsKey('FilterHashtable')) 'Legacy scan replaced its native filter contract.'
        Assert-Ntlm ([object]::ReferenceEquals($global:NtlmFixture_QueryCalls[0].Credential, $global:NtlmFixture_FixtureCredential)) 'Legacy prompt credential was not forwarded.'
    }

    'LegacyGuard' {
        $failed = $false
        try {
            $null = [Target]::Scan([Collections.ArrayList]@('one'), @{
                    LogName = 'Security'
                    LmPackageName = 'NTLM V1'
                }, 'explicit-fixture-user')
        }
        catch {
            $failed = $true
        }
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            Assert-Ntlm ($failed -and $global:NtlmFixture_CredentialCalls -eq 0 -and $global:NtlmFixture_QueryCalls.Count -eq 0) '5.1 legacy named-data filter did not fail before prompt/query.'
        }
        else {
            Assert-Ntlm (-not $failed -and $global:NtlmFixture_CredentialCalls -eq 1 -and $global:NtlmFixture_QueryCalls.Count -eq 1) 'Supported legacy named-data scan changed.'
        }
    }

    'Empty' {
        $global:NtlmFixture_Mode = 'Empty'
        $rows = @(Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $since)
        Assert-Ntlm ($rows.Count -eq 0 -and $global:NtlmFixture_QueryCalls.Count -eq 1) 'Empty successful query gained rows.'
        Assert-Ntlm ($global:NtlmFixture_WriteCalls.Count -eq 0) 'Empty scan automatically exported.'
    }

    'QueryFailure' {
        foreach ($global:NtlmFixture_Mode in @('QueryFailure', 'NonTerminating')) {
            Reset-Calls
            $rows = [Collections.Generic.List[object]]::new()
            $failed = $false
            $preference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                Get-ADAnalyzerNtlmEvents -ComputerName @('one', 'two') -StartTime $since -OutputPath 'fixture.csv' |
                    ForEach-Object {
                        $rows.Add($_)
                    }
            }
            catch {
                $failed = $true
            }
            finally {
                $ErrorActionPreference = $preference
            }
            Assert-Ntlm ($failed -and $rows.Count -eq 0 -and $global:NtlmFixture_WriteCalls.Count -eq 0) 'Query failure emitted a partial report or exported.'
        }
    }

    'ProjectionFailure' {
        foreach ($global:NtlmFixture_Mode in @('ProjectionFailure', 'ProjectionAndCleanup')) {
            Reset-Calls
            $rows = [Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $since |
                    ForEach-Object {
                        $rows.Add($_)
                    }
            }
            catch {
                $failure = $_
            }
            Assert-Ntlm ($null -ne $failure -and $failure.Exception.ToString().Contains('fixture event projection failure')) 'Projection failure lost its original cause.'
            Assert-Ntlm ($rows.Count -eq 0 -and $global:NtlmFixture_ReturnedEvents[0].DisposeCount -eq 1) 'Projection failure emitted rows or leaked the owned record.'
            if ($global:NtlmFixture_Mode -eq 'ProjectionAndCleanup') {
                $cause = $failure.Exception
                $cleanupFound = $false
                while ($null -ne $cause) {
                    if ($cause.Data.Contains('CleanupErrors')) {
                        $cleanupFound = $true
                    }
                    $cause = $cause.InnerException
                }
                Assert-Ntlm $cleanupFound 'Secondary disposal failure hid its diagnostic context.'
            }
        }
    }

    'CleanupFailure' {
        $global:NtlmFixture_Mode = 'CleanupFailure'
        $failed = $false
        $rows = [Collections.Generic.List[object]]::new()
        try {
            Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $since |
                ForEach-Object {
                    $rows.Add($_)
                }
        }
        catch {
            $failed = $true
        }
        Assert-Ntlm ($failed -and $rows.Count -eq 0 -and $global:NtlmFixture_ReturnedEvents[0].DisposeCount -eq 1) 'Disposal-only failure returned success or leaked a record.'
    }

    'Export' {
        $rows = @(Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $since -OutputPath 'chosen.csv' -Confirm:$false)
        Assert-Rows $rows @('one')
        Assert-Ntlm ($global:NtlmFixture_WriteCalls.Count -eq 1 -and $global:NtlmFixture_WriteCalls[0].Path -ceq 'chosen.csv') 'Optional export selected an automatic path.'
        $csv = @($global:NtlmFixture_WriteCalls[0].Content | ConvertFrom-Csv)
        Assert-Rows $csv @('one')
    }

    'WhatIf' {
        $rows = @(Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $since -OutputPath 'chosen.csv' -WhatIf)
        Assert-Rows $rows @('one')
        Assert-Ntlm ($global:NtlmFixture_QueryCalls.Count -eq 1 -and $global:NtlmFixture_WriteCalls.Count -eq 0) 'WhatIf did not collect without writing.'
    }

    'ExportFailure' {
        $global:NtlmFixture_Mode = 'ExportFailure'
        $rows = [Collections.Generic.List[object]]::new()
        $failed = $false
        try {
            Get-ADAnalyzerNtlmEvents -ComputerName one -StartTime $since -OutputPath 'chosen.csv' -Confirm:$false |
                ForEach-Object {
                    $rows.Add($_)
                }
        }
        catch {
            $failed = $true
        }
        Assert-Ntlm ($failed -and $rows.Count -eq 0 -and $global:NtlmFixture_WriteCalls.Count -eq 1) 'Failed export emitted success rows.'
    }

    'Isolation' {
        $servers = [Collections.ArrayList]@('one')
        $first = [Target]::Scan($servers, $since, [pscredential]::Empty)
        $first.Collection[0].UserName = 'mutated-output'
        $servers[0] = 'two'
        $second = [Target]::Scan($servers, $since, [pscredential]::Empty)
        Assert-Rows @($second.Report().ToArray()) @('two')
        Assert-Ntlm ($first.Location[0] -ceq 'one' -and $first.Collection.Count -eq 1 -and
            $second.Collection.Count -eq 1) 'Independent scans shared selectors or accumulated results.'
        Assert-Ntlm (-not [object]::ReferenceEquals($first.Collection, $second.Collection)) 'Repeated scans share a collection.'
    }
}

Write-Output ('PASS NTLM workflow ' + $Case)
