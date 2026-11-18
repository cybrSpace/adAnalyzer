[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Direct', 'Reuse', 'Runspace')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
$script:Checks = 0
$script:Events = [Collections.Generic.List[object]]::new()
$script:Contracts = [Collections.Generic.List[string]]::new()
$script:Sessions = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:Timeout = 17
$script:Credential = [pscredential]::new('fixture\host', [Security.SecureString]::new())
$script:ExpectedCredential = $script:Credential
$script:Mode = 'Healthy'
$script:ServiceName = 'Fixture''Quoted\"Service'
$script:ExpectedFilter = @'
Name='Spooler' OR Name='W32Time' OR Name='Fixture\'Quoted\\\"Service'
'@

function Assert-HostCollector($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-HostCollector([scriptblock]$Test) {
    & $Test
    $script:Checks++
}

function Confirm-FixtureBinding($Condition, [string]$Message) {
    if (-not $Condition) {
        $script:Contracts.Add($Message)
        throw $Message
    }
}

function Add-FixtureEvent([string]$Step, [string]$Computer, [string]$Detail = '') {
    $iterator = Get-Variable -Name foreach -ValueOnly -ErrorAction Ignore
    $scope = if ($null -ne $iterator -and $null -ne $iterator.Current) {
        $iterator.Current.GetType().Name
    }
    else {
        'none'
    }
    $script:Events.Add([pscustomobject][ordered]@{
            Step = $Step
            Computer = $Computer
            Detail = $Detail
            Scope = $scope
        })
}

function New-CimSession {
    [CmdletBinding()]
    param([string]$ComputerName, [pscredential]$Credential, [uint32]$OperationTimeoutSec)

    Confirm-FixtureBinding ($ComputerName -like '*.fixture.invalid') 'Unexpected CIM target.'
    Confirm-FixtureBinding ($OperationTimeoutSec -eq $script:Timeout -and $PSBoundParameters.ErrorAction -eq 'Stop') 'Session timeout or error preference changed.'
    if ($null -eq $script:ExpectedCredential) {
        Confirm-FixtureBinding (-not $PSBoundParameters.ContainsKey('Credential')) 'Empty credential was bound to a CIM session.'
    }
    else {
        Confirm-FixtureBinding ([object]::ReferenceEquals($script:ExpectedCredential, $Credential)) 'Session credential identity changed.'
    }
    Add-FixtureEvent Open $ComputerName
    if ($script:Mode -eq 'AcquireFails' -and $ComputerName -clike 'b.*') {
        throw 'Fixture acquisition failure.'
    }
    $session = [pscustomobject]@{
        Computer = $ComputerName
        PrivateFixtureSession = $true
    }
    $script:Sessions.Add($ComputerName, $session)
    $session
}

function Get-CimInstance {
    [CmdletBinding()]
    param($CimSession, [string]$ClassName, [string]$Filter, [string]$Namespace, [uint32]$OperationTimeoutSec)

    $computer = $CimSession.Computer
    Confirm-FixtureBinding ([object]::ReferenceEquals($script:Sessions[$computer], $CimSession)) 'A class read used a different session.'
    Confirm-FixtureBinding ($OperationTimeoutSec -eq $script:Timeout -and $PSBoundParameters.ErrorAction -eq 'Stop') 'Class query timeout or error preference changed.'
    if ($ClassName -eq 'Win32_Service') {
        Confirm-FixtureBinding ($Filter -ceq $script:ExpectedFilter) 'Service filter changed.'
    }
    elseif ($ClassName -eq 'Win32_NetworkAdapterConfiguration') {
        Confirm-FixtureBinding ($Filter -ceq 'IPEnabled=True') 'DNS observation filter changed.'
    }
    elseif ($ClassName -eq 'MSFT_SmbServerConfiguration') {
        Confirm-FixtureBinding ($Namespace -ceq 'root/Microsoft/Windows/SMB') 'SMB observation namespace changed.'
    }
    Add-FixtureEvent Class $computer $ClassName
    if ($ClassName -eq 'Win32_OperatingSystem' -and $computer -clike 'a.*') {
        if ($script:Mode -eq 'QueryFails') {
            throw 'Fixture class query failure.'
        }
        if ($script:Mode -eq 'Warning') {
            Write-Warning 'Fixture class query warning.'
        }
    }
    if ($computer -clike 'b.*' -and $ClassName -eq 'MSFT_SmbServerConfiguration') {
        return
    }
    [pscustomobject]@{
        ClassName = $ClassName
        Name = $script:ServiceName
        State = 'Running'
    }
}

function Invoke-CimMethod {
    [CmdletBinding()]
    param(
        $CimSession,
        [string]$Namespace,
        [string]$ClassName,
        [string]$MethodName,
        [hashtable]$Arguments,
        [uint32]$OperationTimeoutSec
    )

    $computer = $CimSession.Computer
    Confirm-FixtureBinding ([object]::ReferenceEquals($script:Sessions[$computer], $CimSession)) 'A registry call used a different session.'
    Confirm-FixtureBinding ($OperationTimeoutSec -eq $script:Timeout -and $PSBoundParameters.ErrorAction -eq 'Stop' -and
        $Namespace -ceq 'root/default' -and $ClassName -ceq 'StdRegProv' -and
        $Arguments.hDefKey -eq [uint32]2147483650) 'Registry call binding changed.'
    $detail = '{0}|{1}|{2}' -f $MethodName, $Arguments.sSubKeyName, $Arguments.sValueName
    Add-FixtureEvent Registry $computer $detail
    if ($Arguments.sSubKeyName -ine 'SYSTEM\Fixture') {
        return [pscustomobject]@{
            ReturnValue = 2
            uValue = $null
            sValue = $null
        }
    }
    $type = if ($computer -clike 'b.*') { 1 } else { 4 }
    if ($MethodName -eq 'EnumValues') {
        return [pscustomobject]@{
            ReturnValue = 0
            sNames = @('One', 'Two')
            Types = @($type, 7)
        }
    }
    if ($script:Mode -eq 'RegistryFails' -and $Arguments.sValueName -ieq 'One') {
        throw 'Fixture registry getter failure.'
    }
    if ($Arguments.sValueName -ieq 'Two') {
        Confirm-FixtureBinding ($MethodName -ceq 'GetMultiStringValue') 'Multi-string getter selection changed.'
        return [pscustomobject]@{
            ReturnValue = 0
            sValue = [string[]]@('first', 'second')
        }
    }
    if ($type -eq 1) {
        Confirm-FixtureBinding ($MethodName -ceq 'GetStringValue') 'Observed string type was lost.'
        return [pscustomobject]@{
            ReturnValue = 0
            sValue = 'fixture text'
        }
    }
    Confirm-FixtureBinding ($MethodName -ceq 'GetDWORDValue') 'Observed DWORD type was lost.'
    [pscustomobject]@{
        ReturnValue = 0
        uValue = [uint32]0
    }
}

function Remove-CimSession {
    [CmdletBinding()]
    param($CimSession)

    $computer = $CimSession.Computer
    Confirm-FixtureBinding ([object]::ReferenceEquals($script:Sessions[$computer], $CimSession) -and
        $PSBoundParameters.ErrorAction -eq 'SilentlyContinue') 'Cleanup session identity or error preference changed.'
    Add-FixtureEvent Close $computer
    $null = $script:Sessions.Remove($computer)
    if ($computer -clike 'a.*') {
        if ($script:Mode -eq 'CleanupError') {
            Write-Error -Message 'Fixture cleanup diagnostic.' -ErrorId 'Fixture.HostCleanup'
        }
        elseif ($script:Mode -eq 'CleanupThrow') {
            throw 'Fixture terminating cleanup failure.'
        }
    }
}

. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

function New-FixtureProfile {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Host.Services = @(
        @{
            Name = $script:ServiceName
            State = 'Running'
        }
        @{
            Id = 'alternate'
            Name = $script:ServiceName.ToUpperInvariant()
            State = 'Running'
        }
    )
    $profile.Host.RegistryRules = @(
        @{
            Key = 'SYSTEM\Fixture'
            ValueName = 'One'
            Type = 4
            Expected = 0
        }
        @{
            Id = 'alternate'
            Key = 'system\fixture'
            ValueName = 'ONE'
            Expected = 1
        }
        @{
            Key = 'SYSTEM\Fixture'
            ValueName = 'Two'
            Expected = @('first', 'second')
        }
    )
    $profile
}

function Reset-HostFixture([string]$Mode) {
    $script:Mode = $Mode
    $script:Events.Clear()
    $script:Contracts.Clear()
    $script:Sessions.Clear()
}

function Invoke-FixtureCompatibilityHost {
    [CmdletBinding()]
    param([hashtable]$Arguments)

    Get-ADAnalyzerHostData @Arguments
}

function ConvertTo-HostFixtureDiagnostic($Diagnostic) {
    if ($Diagnostic -is [Management.Automation.ErrorRecord]) {
        return ('{0}|{1}' -f $Diagnostic.FullyQualifiedErrorId, $Diagnostic.Exception.GetBaseException().Message)
    }
    if ($Diagnostic -is [Management.Automation.IContainsErrorRecord]) {
        return ('{0}|{1}' -f $Diagnostic.ErrorRecord.FullyQualifiedErrorId, $Diagnostic.Message)
    }
    [string]$Diagnostic
}

function Invoke-NativeHostFixture([string]$Mode, [switch]$First, [switch]$Plain) {
    Reset-HostFixture $Mode
    $profile = New-FixtureProfile
    $errorSink = [Collections.Generic.List[object]]::new()
    $initial = [pscustomobject]@{
        Collector = 'Earlier'
        Target = 'fixture'
        Status = 'Unknown'
        Message = 'Fixture prior error.'
    }
    $errorSink.Add($initial)
    $arguments = @{
        ComputerNames = @('a.fixture.invalid', '', 'a.fixture.invalid', 'A.fixture.invalid', 'b.fixture.invalid', 'c.fixture.invalid')
        Credential = $script:Credential
        Errors = $errorSink
        TimeoutSeconds = $script:Timeout
        Profile = $profile
    }
    $rows = [Collections.Generic.List[object]]::new()
    $observed = @()
    $warned = @()
    $caught = $null
    $Error.Clear()
    try {
        if ($Plain) {
            Get-ADAnalyzerHostData @arguments -ErrorVariable +observed 3>&1 2>&1 | ForEach-Object {
                $rows.Add($_)
            }
        }
        elseif ($First) {
            Invoke-FixtureCompatibilityHost -Arguments $arguments -ErrorAction Continue -ErrorVariable +observed -WarningVariable +warned 3>&1 2>&1 |
                Select-Object -First 1 | ForEach-Object {
                    $rows.Add($_)
                }
        }
        else {
            Invoke-FixtureCompatibilityHost -Arguments $arguments -ErrorAction Continue -ErrorVariable +observed -WarningVariable +warned 3>&1 2>&1 |
                ForEach-Object {
                    $rows.Add($_)
                }
        }
    }
    catch {
        $caught = ConvertTo-HostFixtureDiagnostic $_
    }

    Assert-HostCollector ($script:Contracts.Count -eq 0 -and $script:Sessions.Count -eq 0) 'A CIM mock contract or owned session failed.'
    Assert-HostCollector ([object]::ReferenceEquals($initial, $errorSink[0])) 'A preexisting error record was removed or replaced.'
    $rec = [pscustomobject][ordered]@{
        Mode = $Mode
        First = [bool]$First
        Plain = [bool]$Plain
        Hosts = @($rows | Where-Object { $_ -isnot [Management.Automation.ErrorRecord] -and $_ -isnot [Management.Automation.WarningRecord] })
        Streams = @(
            foreach ($item in $rows) {
                if ($item -is [Management.Automation.ErrorRecord]) {
                    ConvertTo-HostFixtureDiagnostic $item
                }
                elseif ($item -is [Management.Automation.WarningRecord]) {
                    $item.Message
                }
                else {
                    'host:' + $item.ComputerName
                }
            }
        )
        Errors = $errorSink.ToArray()
        Observed = @($observed | ForEach-Object { ConvertTo-HostFixtureDiagnostic $_ })
        History = @($Error | ForEach-Object { ConvertTo-HostFixtureDiagnostic $_ })
        Warnings = @($warned | ForEach-Object Message)
        Events = $script:Events.ToArray()
        Caught = $caught
    }
    Write-Host ('HOST NATIVE OBSERVATION ' + (ConvertTo-Json -InputObject $rec -Compress -Depth 15))
    $rec
}

if ($Case -eq 'Native') {
    Test-HostCollector {
        $result = Invoke-NativeHostFixture Healthy
        Assert-HostCollector (($result.Hosts.ComputerName -join '|') -ceq 'a.fixture.invalid|A.fixture.invalid|b.fixture.invalid|c.fixture.invalid') 'Host ordering or case-sensitive duplicate behavior changed.'
        Assert-HostCollector (@($result.Hosts | Where-Object Status -ne Observed).Count -eq 0 -and $result.Errors.Count -eq 1) 'Registry return-code evidence incorrectly changed host coverage.'
        Assert-HostCollector (($result.Hosts[0].PSObject.Properties.Name -join '|') -ceq
            'ComputerName|Status|Services|OperatingSystem|Patches|Dns|Smb|Registry|AuditPolicy|Certificates') 'Host DTO keys or ordering changed.'
        Assert-HostCollector ($result.Hosts[0].OperatingSystem -is [array] -and $result.Hosts[0].OperatingSystem.Count -eq 1 -and
            $result.Hosts[2].Smb -is [array] -and $result.Hosts[2].Smb.Count -eq 0) 'Successful zero or singleton CIM arrays changed.'
        Assert-HostCollector ($result.Hosts[0].AuditPolicy.Status -ceq 'Unknown' -and $result.Hosts[0].Certificates.Status -ceq 'Unknown') 'Inventory placeholders changed.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture Healthy
        foreach ($hostRow in $result.Hosts) {
            $events = @($result.Events | Where-Object Computer -CEQ $hostRow.ComputerName)
            Assert-HostCollector ($events[0].Step -ceq 'Open' -and $events[-1].Step -ceq 'Close') 'Host session ownership order changed.'
            $classes = @($events | Where-Object Step -eq Class | ForEach-Object Detail)
            Assert-HostCollector (($classes -join '|') -ceq 'Win32_Service|Win32_OperatingSystem|Win32_QuickFixEngineering|Win32_NetworkAdapterConfiguration|MSFT_SmbServerConfiguration') 'CIM class query order changed.'
            $registry = @($hostRow.Registry | Where-Object Path -ieq 'SYSTEM\Fixture')
            $types = @($registry | ForEach-Object Type)
            $expected = if ($hostRow.ComputerName -clike 'b.*') { '1|7' } else { '4|7' }
            Assert-HostCollector (($types -join '|') -ceq $expected -and ($registry.Name -join '|') -ceq 'One|Two' -and
                ($registry[1].Value -join '|') -ceq 'first|second') 'Per-host type lookup, deduplication or array values changed.'
            Assert-HostCollector (@($events | Where-Object Detail -like 'EnumValues|SYSTEM\Fixture|').Count -eq 1) 'Registry path type enumeration was repeated or shared across hosts.'
        }
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture QueryFails
        Assert-HostCollector ($result.Hosts[0].Status -ceq 'Partial' -and $null -eq $result.Hosts[0].OperatingSystem -and
            $result.Hosts[1].Status -ceq 'Observed' -and $result.Errors[1].Collector -ceq 'Host.OperatingSystem' -and
            $result.Errors.Count -eq 2 -and $result.Observed.Count -gt 0) 'Class query failure lost its host or native diagnostic.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture RegistryFails
        $row = @($result.Hosts[0].Registry | Where-Object Name -CEQ One)[0]
        Assert-HostCollector ($result.Hosts[0].Status -ceq 'Observed' -and $result.Errors.Count -eq 1 -and
            $row.Status -ceq 'Unknown' -and $null -eq $row.Value -and
            $row.Message -ceq 'Fixture registry getter failure.' -and $result.Observed.Count -gt 0) 'Registry error escaped its value boundary or lost diagnostics.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture AcquireFails
        Assert-HostCollector ($result.Hosts[2].Status -ceq 'Unknown' -and $result.Hosts[3].Status -ceq 'Observed' -and
            $result.Errors[1].Collector -ceq 'Host' -and $result.Errors.Count -eq 2 -and
            @($result.Events | Where-Object { $_.Computer -clike 'b.*' -and $_.Step -ne 'Open' }).Count -eq 0) 'Failed acquisition used a session or stopped later hosts.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture CleanupError
        Assert-HostCollector ($result.Hosts.Count -eq 4 -and $result.Errors.Count -eq 1 -and
            ($result.History -join '|') -match 'Fixture.HostCleanup' -and $result.Observed.Count -gt 0) 'Recoverable cleanup changed host output or lost diagnostics.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture CleanupThrow
        Assert-HostCollector ($result.Hosts.Count -eq 0 -and
            ($result.Events.Step -contains 'Close') -and @($result.Events | Where-Object Step -eq Open).Count -eq 1 -and
            ($result.Caught + ($result.Streams -join '|')) -like '*Fixture terminating cleanup failure.*') 'Hard cleanup failure emitted a host or started another session.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture QueryFails -First
        Assert-HostCollector ($result.Hosts.Count -eq 1 -and $result.Hosts[0].Status -ceq 'Partial' -and
            $result.Events[-1].Step -ceq 'Close' -and @($result.Events | Where-Object Step -eq Open).Count -eq 1) 'Early pipeline stop did work after the first host.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture Warning
        Assert-HostCollector ($result.Hosts.Count -eq 4 -and $result.Warnings.Count -eq 1 -and
            $result.Warnings[0] -ceq 'Fixture class query warning.' -and $result.Streams[0] -ceq $result.Warnings[0]) 'Native warning order or capture changed.'
    }
    Test-HostCollector {
        $result = Invoke-NativeHostFixture CleanupError -Plain
        Assert-HostCollector ($result.Hosts.Count -eq 4 -and $result.Observed.Count -eq 0 -and
            ($result.History -join '|') -match 'Fixture.HostCleanup') 'Plain helper binding or ambient error history changed.'
    }
    Write-Host ('PASS host collector Native {0}' -f $script:Checks)
}

if ($Case -ne 'Native') {
    $nativeQueryFailure = if ($Case -eq 'Direct') {
        Invoke-NativeHostFixture QueryFails
    }
    $script:LegacyCalls = 0
    function Get-ADAnalyzerHostData {
        $script:LegacyCalls++
        throw 'The direct collector called the old command.'
    }

    Reset-HostFixture Healthy
    $collector = [ADAnalyzerHostCollector]::new()
    Assert-HostCollector ($script:Events.Count -eq 0) 'Construction opened a CIM session.'
    $profile = New-FixtureProfile
    $hosts = [string[]]@('a.fixture.invalid', '', 'a.fixture.invalid', 'A.fixture.invalid', 'b.fixture.invalid', 'c.fixture.invalid')
}

if ($Case -eq 'Construction') {
    Test-HostCollector {
        $empty = $collector.Collect([string[]]@())
        Assert-HostCollector ($empty.Hosts -is [array] -and $empty.Errors -is [array] -and
            $empty.Hosts.Count -eq 0 -and $empty.Errors.Count -eq 0 -and $script:Events.Count -eq 0) 'Empty default collection had effects or changed its result shape.'
    }
    Test-HostCollector {
        $script:Timeout = 30
        $script:ExpectedCredential = $null
        $script:ExpectedFilter = "Name='Spooler' OR Name='W32Time'"
        $result = $collector.Collect([string[]]@('a.fixture.invalid'))
        Assert-HostCollector ($result.Hosts -is [array] -and $result.Hosts.Count -eq 1 -and
            $result.Errors -is [array] -and $result.Errors.Count -eq 0 -and
            $result.Hosts[0].Status -ceq 'Observed') 'Default direct collection did not preserve single-host results.'
        Assert-HostCollector ($script:Contracts.Count -eq 0 -and $script:Sessions.Count -eq 0 -and
            $script:Events[0].Step -ceq 'Open' -and $script:Events[-1].Step -ceq 'Close') 'Default session ownership or binding changed.'
    }
    Test-HostCollector {
        Reset-HostFixture Healthy
        $invalid = New-FixtureProfile
        $invalid.Host.RegistryRules[0].Type = 99
        $failures = 0
        foreach ($bad in @(
                @{
                    Profile = $invalid
                    Timeout = 30
                }
                @{
                    Profile = $profile
                    Timeout = 0
                }
                @{
                    Profile = $profile
                    Timeout = 3601
                }
            )) {
            try {
                $null = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]$bad.Timeout, $bad.Profile)
            }
            catch {
                $failures++
            }
        }
        Assert-HostCollector ($failures -eq 3 -and $script:Events.Count -eq 0 -and $script:Contracts.Count -eq 0) 'Invalid configuration or timeouts reached CIM.'
    }
}

if ($Case -eq 'Direct') {
    Test-HostCollector {
        Reset-HostFixture QueryFails
        $direct = $collector.Collect($hosts, $script:Credential, [uint32]17, $profile)
        $expected = ConvertTo-Json -InputObject $nativeQueryFailure.Hosts -Compress -Depth 15
        $actual = ConvertTo-Json -InputObject $direct.Hosts -Compress -Depth 15
        Assert-HostCollector ($expected -ceq $actual -and $direct.Errors -is [array] -and
            $direct.Errors.Count -eq 1 -and $direct.Errors[0].Collector -ceq 'Host.OperatingSystem' -and
            $direct.Errors[0].Target -ceq 'a.fixture.invalid') 'Direct collection changed the host/error result contract.'
        $nativeOrder = @($nativeQueryFailure.Events | ForEach-Object { $_.Step + '/' + $_.Computer + '/' + $_.Detail })
        $directOrder = @($script:Events | ForEach-Object { $_.Step + '/' + $_.Computer + '/' + $_.Detail })
        Assert-HostCollector (($nativeOrder -join '|') -ceq ($directOrder -join '|')) 'Direct collection changed request or cleanup order.'
    }
    Test-HostCollector {
        Reset-HostFixture AcquireFails
        $result = $collector.Collect($hosts, $script:Credential, [uint32]17, $profile)
        Assert-HostCollector ($result.Hosts.Count -eq 4 -and $result.Hosts[2].Status -ceq 'Unknown' -and
            $result.Hosts[3].Status -ceq 'Observed' -and $result.Errors.Count -eq 1 -and
            $result.Errors[0].Collector -ceq 'Host' -and $result.Errors[0].Target -ceq 'b.fixture.invalid' -and
            @($script:Events | Where-Object { $_.Computer -clike 'b.*' -and $_.Step -ne 'Open' }).Count -eq 0) 'Direct failed acquisition stranded a session or prevented later collection.'
    }
    Test-HostCollector {
        Reset-HostFixture RegistryFails
        $result = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        $value = @($result.Hosts[0].Registry | Where-Object Name -CEQ One)[0]
        Assert-HostCollector ($result.Hosts[0].Status -ceq 'Observed' -and $result.Errors.Count -eq 0 -and
            $value.Status -ceq 'Unknown' -and $null -eq $value.Value -and
            $value.Message -ceq 'Fixture registry getter failure.') 'Direct registry failure changed host-level error semantics.'
    }
    Test-HostCollector {
        Reset-HostFixture Healthy
        $result = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        $serialized = (ConvertTo-Json -InputObject @($collector, $result) -Compress -Depth 20) +
            [Management.Automation.PSSerializer]::Serialize(@($collector, $result))
        $identity = $script:Credential.UserName
        $escapedIdentity = $identity.Replace('\', '\\')
        Assert-HostCollector ($serialized -notmatch 'PrivateFixtureSession|PSCredential' -and
            -not $serialized.Contains($identity) -and
            -not $serialized.Contains($escapedIdentity)) 'Result or instance exposed credentials or a session handle.'
    }
}

if ($Case -eq 'Reuse') {
    Test-HostCollector {
        $profileBefore = ConvertTo-Json -InputObject $profile -Compress -Depth 20
        Reset-HostFixture QueryFails
        $first = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        $first.Hosts[0].Status = 'Changed first result'
        $first.Errors[0].Message = 'Changed first error'
        $first.Hosts[0].Registry[0].Name = 'Changed first registry value'

        Reset-HostFixture QueryFails
        $second = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        Assert-HostCollector ($second.Hosts.Count -eq 1 -and $second.Hosts[0].Status -ceq 'Partial' -and
            $second.Errors.Count -eq 1 -and $second.Errors[0].Message -ceq 'Fixture class query failure.' -and
            $second.Hosts[0].Registry[0].Name -ceq 'NtpServer') 'Repeated direct collection retained state or mutable results.'
        Assert-HostCollector ($profileBefore -ceq (ConvertTo-Json -InputObject $profile -Compress -Depth 20)) 'Collection mutated the caller profile.'
    }
    Test-HostCollector {
        Reset-HostFixture Healthy
        $other = [ADAnalyzerHostCollector]::new()
        $first = $other.Collect([string[]]@('b.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        Reset-HostFixture Healthy
        $second = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        $before = @($first.Hosts[0].Registry | Where-Object Name -CEQ One)[0]
        $after = @($second.Hosts[0].Registry | Where-Object Name -CEQ One)[0]
        Assert-HostCollector ($first.Errors.Count -eq 0 -and $second.Errors.Count -eq 0 -and
            $before.Type -eq 1 -and $after.Type -eq 4 -and $after.Value -eq 0) 'Instance or host registry state leaked between calls.'
    }
}

if ($Case -eq 'Runspace') {
    Test-HostCollector {
        $initial = $collector.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        Assert-HostCollector ($initial.Hosts.Count -eq 1 -and $initial.Errors.Count -eq 0) 'Initial collector was empty.'
        $worker = [powershell]::Create()
        try {
            $source = @'
param($Root)
$ErrorActionPreference = 'Stop'
function New-CimSession { throw 'Unexpected CIM acquisition in test runspace.' }
function Get-CimInstance { throw 'Unexpected CIM query in test runspace.' }
function Invoke-CimMethod { throw 'Unexpected CIM method in test runspace.' }
function Remove-CimSession { throw 'Unexpected CIM cleanup in test runspace.' }
. (Join-Path $Root 'bin/ADAnalyzer.ps1')
$collector = [ADAnalyzerHostCollector]::new()
$empty = $collector.Collect([string[]]@())
if ($empty.Hosts.Count -ne 0 -or $empty.Errors.Count -ne 0) {
    throw 'Unexpected result in test runspace.'
}
'Host collector loaded'
'@
            $result = @($worker.AddScript($source).AddArgument($RepositoryRoot).Invoke())
            Assert-HostCollector ($result.Count -eq 1 -and [string]$result[0] -ceq 'Host collector loaded' -and
                $worker.Streams.Error.Count -eq 0) 'Secondary runspace could not load and construct the collector.'
        }
        finally {
            $worker.Dispose()
        }

        Reset-HostFixture Healthy
        $reused = $collector.Collect([string[]]@('b.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        Assert-HostCollector ($reused.Hosts.Count -eq 1 -and $reused.Hosts[0].ComputerName -ceq 'b.fixture.invalid' -and
            $reused.Hosts[0].Status -ceq 'Observed' -and $reused.Errors.Count -eq 0) 'Existing collector failed after disposing the other runspace.'
    }
    Test-HostCollector {
        Reset-HostFixture Healthy
        $independent = [ADAnalyzerHostCollector]::new()
        $result = $independent.Collect([string[]]@('a.fixture.invalid'), $script:Credential, [uint32]17, $profile)
        Assert-HostCollector ($result.Hosts.Count -eq 1 -and $result.Hosts[0].ComputerName -ceq 'a.fixture.invalid' -and
            $result.Hosts[0].Status -ceq 'Observed' -and $result.Errors.Count -eq 0) 'Fresh collector failed after disposing the other runspace.'
    }
}

if ($Case -ne 'Native') {
    Assert-HostCollector ($script:LegacyCalls -eq 0 -and $script:Contracts.Count -eq 0 -and
        $script:Sessions.Count -eq 0) 'Direct collection used the legacy command or left a session open.'
    Write-Host ('PASS host collector {0} {1}' -f $Case, $script:Checks)
}
