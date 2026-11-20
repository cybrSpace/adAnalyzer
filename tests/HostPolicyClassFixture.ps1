[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

function Import-Module {
    throw 'Unexpected module acquisition.'
}

function Invoke-Command {
    throw 'Unexpected remoting.'
}

function New-PSSessionOption {
    throw 'Unexpected remoting.'
}

function New-CimSession {
    throw 'Unexpected CIM acquisition.'
}

. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

$script:trace = [Collections.Generic.List[object]]::new()
$script:ids = @('0cce9215-69ae-11d9-bed3-505054503030', '0cce9216-69ae-11d9-bed3-505054503030')
$script:credential = [pscredential]::new('host-policy-fixture', [Security.SecureString]::new())

function Observe-FixtureIterator {
    $iterator = Get-Variable -Name foreach -ValueOnly -ErrorAction Ignore
    if ($iterator -and $iterator.Current -is [Collections.IDictionary]) {
        return 'Endpoint:' + $iterator.Current['HostName']
    }
    if ($iterator -and $iterator.Current.PSObject.Properties['ComputerName']) {
        return 'Host:' + $iterator.Current.ComputerName
    }
    return 'Unknown'
}

function Get-ADAnalyzerAuditPolicy {
    [CmdletBinding()]
    param([string]$ComputerName, [pscredential]$Credential, [int]$TimeoutSeconds)

    if ($ComputerName -notin 'a.fixture.invalid', 'b.fixture.invalid') {
        throw 'Unexpected audit target.'
    }
    $script:trace.Add([ordered]@{
            Step = 'Audit'
            Target = $ComputerName
            Credential = [object]::ReferenceEquals($Credential, $script:credential)
            Timeout = $TimeoutSeconds
            Scope = Observe-FixtureIterator
        })
    [pscustomobject]@{
        SubcategoryGuid = $script:ids[0]
        Flags = 1
    }
    if ($ComputerName -eq 'a.fixture.invalid') {
        switch ($script:scenario) {
            'AuditThrow' {
                throw [InvalidOperationException]::new('fixture audit read failed after one row')
            }
            'AuditWrite' {
                Write-Error -ErrorId 'Fixture.Audit' -Message 'fixture audit nonterminating'
            }
            'AuditWarn' {
                Write-Warning 'fixture audit warning'
            }
            'AuditCast' {
                [pscustomobject]@{
                    SubcategoryGuid = $script:ids[1]
                    Flags = 'malformed audit flag'
                }
                return
            }
        }
    }
    [pscustomobject]@{
        SubcategoryGuid = $script:ids[1]
        Flags = 2
    }
}

function Get-ADAnalyzerTlsCertificate {
    [CmdletBinding()]
    param([string]$HostName, [int]$Port, [string]$ServerName, [int]$TimeoutSeconds)

    if ($HostName -notin 'a.fixture.invalid', 'b.fixture.invalid') {
        throw 'Unexpected TLS target.'
    }
    $script:trace.Add([ordered]@{
            Step = 'Tls'
            Target = $HostName
            Port = $Port
            ServerName = $ServerName
            Timeout = $TimeoutSeconds
            Scope = Observe-FixtureIterator
        })
    if ($HostName -eq 'a.fixture.invalid') {
        switch ($script:scenario) {
            'TlsThrow' {
                throw [InvalidOperationException]::new('fixture handshake failed')
            }
            'TlsWrite' {
                Write-Error -ErrorId 'Fixture.Tls' -Message 'fixture TLS nonterminating'
            }
            'TlsWarn' {
                Write-Warning 'fixture TLS warning'
            }
        }
    }
    $date = if ($HostName -eq 'a.fixture.invalid' -and $script:scenario -eq 'TlsCast') {
        'malformed certificate date'
    }
    else {
        [datetime]'2099-01-01'
    }
    [pscustomobject]@{
        NameValid = $true
        ChainValid = $true
        NotBefore = [datetime]'2001-01-01'
        NotAfter = $date
    }
}

$profile = @{
    Host = @{
        Services = @(@{
                Name = 'FixtureSvc'
                State = 'Running'
            })
        RegistryRules = @(@{
                Key = 'SOFTWARE\Fixture'
                ValueName = 'Enabled'
                Expected = 1
                Type = 4
            })
        AuditRules = @(
            @{
                SubcategoryGuid = $script:ids[0]
                Flags = 1
            },
            @{
                SubcategoryGuid = $script:ids[1]
                Flags = 2
            }
        )
        CertificateEndpoints = @(
            @{
                HostName = 'a.fixture.invalid'
                Port = 443
                ServerName = 'a.fixture.invalid'
                MinimumRemainingDays = 30
            },
            @{
                HostName = 'b.fixture.invalid'
                Port = 443
                ServerName = 'b.fixture.invalid'
                MinimumRemainingDays = 30
            }
        )
    }
}
$hosts = @(
    foreach ($computer in 'a.fixture.invalid', 'b.fixture.invalid') {
        [pscustomobject]@{
            ComputerName = $computer
            Services = @([pscustomobject]@{
                    Name = 'FixtureSvc'
                    State = 'Running'
                })
            Registry = @([pscustomobject]@{
                    Path = 'SOFTWARE\Fixture'
                    Name = 'Enabled'
                    Status = 'Observed'
                    Type = 4
                    Value = 1
                })
        }
    }
)

$script:checks = 0
$script:expected = 0

function Assert-Fixture($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$Name, [scriptblock]$Test) {
    try {
        & $Test
        $script:checks++
    }
    catch {
        throw [InvalidOperationException]::new(
            ('Host policy [{0}] failed: {1}{2}{3}' -f $Name, $_.Exception.Message,
                [Environment]::NewLine, $_.ScriptStackTrace),
            $_.Exception
        )
    }
}

function Reset-FixtureTrace([string]$Scenario = 'Success') {
    $script:trace.Clear()
    $script:scenario = $Scenario
}

function ConvertTo-FixtureDiagnostic($Entry, [object[]]$Ancestors = @()) {
    if ($null -eq $Entry) {
        return [pscustomobject][ordered]@{
            Type = $null
            Id = $null
        }
    }

    $type = $Entry.GetType().FullName
    if ($Entry -is [Collections.IList]) {
        for ($index = 0; $index -lt $Ancestors.Count; $index++) {
            if ([object]::ReferenceEquals($Ancestors[$index], $Entry)) {
                return [pscustomobject][ordered]@{
                    Type = $type
                    Id = $null
                    BackReference = $index
                }
            }
        }

        $path = $Ancestors + , $Entry
        return [pscustomobject][ordered]@{
            Type = $type
            Id = $null
            Entries = @(
                foreach ($child in $Entry) {
                    ConvertTo-FixtureDiagnostic $child $path
                }
            )
        }
    }

    $record = $null
    if ($Entry -is [Management.Automation.ErrorRecord]) {
        $record = $Entry
    }
    elseif ($Entry -is [Management.Automation.IContainsErrorRecord]) {
        $record = $Entry.ErrorRecord
    }
    if ($null -ne $record) {
        $diagnostic = [ordered]@{
            Type = $type
            Id = $record.FullyQualifiedErrorId
            Category = [string]$record.CategoryInfo.Category
            Message = $null
        }
        if ($null -ne $record.Exception) {
            $diagnostic.Message = $record.Exception.Message
        }
        return [pscustomobject]$diagnostic
    }
    if ($Entry -is [Management.Automation.WarningRecord] -or $Entry -is [Exception]) {
        return [pscustomobject][ordered]@{
            Type = $type
            Id = $null
            Message = $Entry.Message
        }
    }
    if ($Entry -is [string]) {
        return [pscustomobject][ordered]@{
            Type = $type
            Id = $null
            Message = $Entry
        }
    }
    return [pscustomobject][ordered]@{
        Type = $type
        Id = $null
    }
}

function Get-FixtureCapturedId([object[]]$Rows) {
    foreach ($row in $Rows) {
        if ($row.Id) {
            $row.Id
        }
        if ($null -ne $row.PSObject.Properties['Entries']) {
            Get-FixtureCapturedId $row.Entries
        }
    }
}

function ConvertTo-FixtureCheckJson([object[]]$Checks) {
    $rows = @(
        foreach ($check in $Checks) {
            $row = [ordered]@{}
            foreach ($property in $check.PSObject.Properties) {
                $value = $property.Value
                if ($value -is [hashtable]) {
                    $entries = [ordered]@{}
                    foreach ($key in ($value.Keys | Sort-Object)) {
                        $entries[$key] = $value[$key]
                    }
                    $value = [pscustomobject][ordered]@{
                        Type = $value.GetType().FullName
                        Entries = $entries
                    }
                }
                $row[$property.Name] = $value
            }
            [pscustomobject]$row
        }
    )
    ConvertTo-Json -InputObject $rows -Compress -Depth 20
}

function Invoke-FixtureCase([string]$Scenario, [string]$Action, [string]$WarnAction) {
    Reset-FixtureTrace $Scenario
    $capture = @()
    $warned = @()
    $rows = [Collections.Generic.List[string]]::new()
    $thrown = $null
    $parameters = @{
        Hosts = $hosts
        Profile = $profile
        Credential = $script:credential
        WarningAction = $WarnAction
        ErrorAction = $Action
        ErrorVariable = '+capture'
        WarningVariable = '+warned'
    }
    if ($Scenario -eq 'ProfileAbort') {
        $parameters.Profile = @{ Name = '' }
    }
    elseif ($Scenario -in 'ServiceFault', 'RegistryFault') {
        Set-StrictMode -Version Latest
        $damaged = [pscustomobject]@{
            ComputerName = 'a.fixture.invalid'
            Services = @([pscustomobject]@{
                    Name = 'FixtureSvc'
                    State = 'Running'
                })
            Registry = @([pscustomobject]@{
                    Path = 'SOFTWARE\Fixture'
                    Name = 'Enabled'
                    Status = 'Observed'
                    Type = 4
                    Value = 1
                })
        }
        if ($Scenario -eq 'ServiceFault') {
            $damaged.Services[0].PSObject.Properties.Remove('State')
        }
        else {
            $damaged.Registry[0].PSObject.Properties.Remove('Value')
        }
        $parameters.Hosts = @($damaged)
    }
    try {
        if ($Scenario -eq 'First') {
            Test-ADAnalyzerHostPolicy @parameters 3>&1 2>&1 | Select-Object -First 1 | ForEach-Object {
                $rows.Add($_.RuleId + '/' + $_.Status + '/' + $_.Target)
            }
        }
        else {
            Test-ADAnalyzerHostPolicy @parameters 3>&1 2>&1 | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    $rows.Add('Error:' + $_.FullyQualifiedErrorId)
                }
                elseif ($_ -is [Management.Automation.WarningRecord]) {
                    $rows.Add('Warning:' + $_.Message)
                }
                else {
                    $rows.Add($_.RuleId + '/' + $_.Status + '/' + $_.Target)
                }
            }
        }
    }
    catch {
        $thrown = $_.FullyQualifiedErrorId
    }
    [ordered]@{
        Scenario = $Scenario
        ErrorAction = $Action
        WarningAction = $WarnAction
        Rows = $rows.ToArray()
        Trace = $script:trace.ToArray()
        Captured = @(
            foreach ($diagnostic in $capture) {
                ConvertTo-FixtureDiagnostic $diagnostic
            }
        )
        Warnings = @(
            foreach ($warning in $warned) {
                ConvertTo-FixtureDiagnostic $warning
            }
        )
        Thrown = $thrown
    }
}

function Assert-NativeObservation($Observation) {
    $scenario = $Observation.Scenario
    $stop = $Observation.ErrorAction -eq 'Stop'
    if ($scenario -eq 'First') {
        Assert-Fixture ($Observation.Rows.Count -eq 1 -and $Observation.Trace.Count -eq 0 -and
            $Observation.Rows[0] -ceq 'HOST.SERVICE/Pass/a.fixture.invalid/Service/FixtureSvc' -and
            $null -eq $Observation.Thrown) 'Early pipeline stop advanced to later observations.'
        return
    }
    if ($scenario -in 'ProfileAbort', 'ServiceFault', 'RegistryFault') {
        $expectedId = 'PropertyNotFoundStrict,Test-ADAnalyzerHostPolicy'
        $expectedRows = 0
        if ($scenario -eq 'ProfileAbort') {
            $expectedId = 'Profile Name and Version are required'
        }
        elseif ($scenario -eq 'RegistryFault') {
            $expectedRows = 1
        }
        $captureId = ($expectedId -split ',', 2)[0]
        $captured = @(Get-FixtureCapturedId $Observation.Captured | Where-Object { ($_ -split ',', 2)[0] -ceq $captureId })
        Assert-Fixture ($Observation.Thrown -ceq $expectedId -and $captured.Count -gt 0 -and
            $Observation.Rows.Count -eq $expectedRows -and $Observation.Trace.Count -eq 0) 'An escaping fault changed its output, error record or acquisition boundary.'
        return
    }

    $scope = @(
        'Host:a.fixture.invalid'
        'Host:b.fixture.invalid'
        'Endpoint:a.fixture.invalid'
        'Endpoint:b.fixture.invalid'
    )
    Assert-Fixture ($null -eq $Observation.Thrown -and $Observation.Trace.Count -eq 4 -and
        ($Observation.Trace.Scope -join '|') -ceq ($scope -join '|') -and
        $Observation.Trace[0].Credential -and $Observation.Trace[1].Credential -and
        @($Observation.Trace | Where-Object Timeout -ne 30).Count -eq 0 -and
        $Observation.Trace[2].Port -eq 443 -and $Observation.Trace[2].ServerName -ceq 'a.fixture.invalid') 'Callback order, iterator scope, credential or binding changed.'

    $expectedCount = 12
    if ($scenario -in 'AuditThrow', 'TlsThrow', 'TlsCast' -or ($stop -and $scenario -in 'AuditWrite', 'TlsWrite')) {
        $expectedCount = 11
    }
    elseif (-not $stop -and $scenario -in 'AuditWrite', 'AuditWarn', 'TlsWrite', 'TlsWarn') {
        $expectedCount = 13
    }
    Assert-Fixture ($Observation.Rows.Count -eq $expectedCount -and
        $Observation.Rows[-1] -ceq 'HOST.CERTIFICATE_REVOCATION/Unknown/b.fixture.invalid:443/b.fixture.invalid') 'Output count or sibling certificate observations changed.'

    $expectedUnreadable = $scenario -in 'AuditThrow', 'AuditCast', 'TlsThrow', 'TlsCast' -or
        ($stop -and $scenario -in 'AuditWrite', 'TlsWrite', 'AuditWarn', 'TlsWarn')
    $unreadable = @($Observation.Rows | Where-Object { $_ -like '*/Unreadable/*' })
    if ($expectedUnreadable) {
        $target = if ($scenario -like 'Audit*') {
            'HOST.AUDIT_POLICY/Unreadable/a.fixture.invalid/Audit'
        }
        else {
            'HOST.TLS_CERTIFICATE/Unreadable/a.fixture.invalid:443/a.fixture.invalid'
        }
        Assert-Fixture ($unreadable.Count -eq 1 -and $unreadable[0] -ceq $target) 'A callback failure changed the affected scope.'
    }
    else {
        Assert-Fixture ($unreadable.Count -eq 0) 'A successful callback was reported as unreadable.'
    }

    if ($scenario -in 'AuditWrite', 'TlsWrite') {
        $id = 'Fixture.Audit,Get-ADAnalyzerAuditPolicy'
        if ($scenario -eq 'TlsWrite') {
            $id = 'Fixture.Tls,Get-ADAnalyzerTlsCertificate'
        }
        Assert-Fixture (@(Get-FixtureCapturedId $Observation.Captured) -ccontains $id) 'The diagnostic identity disappeared from ErrorVariable.'
        Assert-Fixture (($Observation.Rows -ccontains ('Error:' + $id)) -eq (-not $stop)) 'The native error stream did not honor ErrorAction.'
    }
    if ($scenario -in 'AuditWarn', 'TlsWarn') {
        $message = 'Warning:fixture audit warning'
        if ($scenario -eq 'TlsWarn') {
            $message = 'Warning:fixture TLS warning'
        }
        Assert-Fixture ($Observation.Rows -ccontains $message) 'The warning disappeared from the native stream.'
    }
    if ($scenario -eq 'AuditCast') {
        Assert-Fixture ($Observation.Rows[2] -ceq ('HOST.AUDIT_POLICY/Pass/a.fixture.invalid/Audit/' + $script:ids[0]) -and
            $Observation.Rows[3] -ceq 'HOST.AUDIT_POLICY/Unreadable/a.fixture.invalid/Audit') 'A later malformed audit observation discarded an earlier check.'
    }
    if ($scenario -eq 'AuditThrow') {
        Assert-Fixture ($Observation.Rows[2] -ceq 'HOST.AUDIT_POLICY/Unreadable/a.fixture.invalid/Audit') 'Auditing produced a check for a partially read provider result.'
    }
}

if ($Case -eq 'Native') {
    $script:expected = 26
    foreach ($scenario in @(
            'Success', 'First', 'AuditThrow', 'AuditWrite', 'AuditWarn', 'AuditCast',
            'TlsThrow', 'TlsWrite', 'TlsWarn', 'TlsCast', 'ProfileAbort', 'ServiceFault', 'RegistryFault'
        )) {
        foreach ($action in 'Continue', 'Stop') {
            Test-Fixture "$scenario $action" {
                $warning = if ($action -eq 'Stop') {
                    'Stop'
                }
                else {
                    'Continue'
                }
                $observation = Invoke-FixtureCase $scenario $action $warning
                Assert-NativeObservation $observation
                Write-Output ('HOST POLICY NATIVE OBSERVATION ' +
                    (ConvertTo-Json -InputObject $observation -Compress -Depth 20))
            }
        }
    }
}
else {
    $evaluator = [ADAnalyzerHostPolicyEvaluator]::new()
    Assert-Fixture ($script:trace.Count -eq 0) 'The loader or constructor performed acquisition.'

    if ($Case -eq 'Construction') {
        $script:expected = 3
        Test-Fixture 'independent inert instances' {
            $independent = [ADAnalyzerHostPolicyEvaluator]::new()
            Assert-Fixture (-not [object]::ReferenceEquals($evaluator, $independent) -and
                $script:trace.Count -eq 0) 'Construction performed collection or reused an instance.'
        }
        Test-Fixture 'default empty and named host inputs' {
            $empty = $evaluator.Evaluate([object[]]@())
            $named = $evaluator.Evaluate([object[]]@($hosts[0]))
            Assert-Fixture ($empty -is [array] -and $empty.Count -eq 0 -and
                $named -is [array] -and $named.Count -eq 1 -and
                $named[0].RuleId -ceq 'HOST.AUDIT_POLICY' -and $named[0].Status -ceq 'NotConfigured' -and
                $script:trace.Count -eq 0) 'Default object evaluation changed cardinality or acquired data.'
        }
        Test-Fixture 'invalid profile fails before evaluation effects' {
            $invalid = $profile.Clone()
            $invalid.Name = ''
            $failure = $null
            try {
                $null = $evaluator.Evaluate($hosts, $script:credential, $invalid)
            }
            catch {
                $failure = $_
            }
            Assert-Fixture ($null -ne $failure -and
                $failure.Exception.GetBaseException().Message -like '*Profile Name and Version are required*' -and
                $script:trace.Count -eq 0) 'An invalid configuration reached the collectors or lost its cause.'
        }
    }
    elseif ($Case -eq 'Direct') {
        $script:expected = 6
        $native = @{}
        foreach ($scenario in 'Success', 'AuditThrow', 'TlsThrow') {
            Reset-FixtureTrace $scenario
            $native[$scenario] = @(
                Test-ADAnalyzerHostPolicy -Hosts $hosts -Credential $script:credential -Profile $profile -ErrorAction Stop
            )
        }

        function Test-ADAnalyzerHostPolicy {
            throw 'The direct evaluator invoked the compatibility command.'
        }

        foreach ($scenario in 'Success', 'AuditThrow', 'TlsThrow') {
            Test-Fixture "direct ordered parity $scenario" {
                Reset-FixtureTrace $scenario
                $actual = $evaluator.Evaluate($hosts, $script:credential, $profile)
                $observed = ConvertTo-FixtureCheckJson $actual
                $expected = ConvertTo-FixtureCheckJson $native[$scenario]
                Assert-Fixture ($actual -is [array] -and $observed -ceq $expected -and
                    $script:trace.Count -eq 4 -and $script:trace[0].Credential -and
                    $script:trace[1].Credential) 'Direct outcomes, data, order or credential changed.'
            }
        }

        Test-Fixture 'profile overload preserves corrected endpoint defaults' {
            Reset-FixtureTrace
            $defaults = @{
                Host = @{
                    CertificateEndpoints = @(@{ HostName = 'a.fixture.invalid' })
                }
            }
            $actual = & {
                Set-StrictMode -Version Latest
                , $evaluator.Evaluate([object[]]@(), $defaults)
            }
            Assert-Fixture ($actual -is [array] -and $actual.Count -eq 2 -and
                $actual[0].Status -ceq 'Pass' -and $actual[0].Expected.MinimumRemainingDays -eq 30 -and
                $actual[1].RuleId -ceq 'HOST.CERTIFICATE_REVOCATION' -and
                $script:trace.Count -eq 1 -and $script:trace[0].Port -eq 443 -and
                $script:trace[0].ServerName -ceq 'a.fixture.invalid') 'Profile overload lost supported strict endpoint defaults.'
        }
        Test-Fixture 'empty credential does not change audit targeting' {
            Reset-FixtureTrace
            $auditProfile = @{
                Host = @{
                    AuditRules = $profile.Host.AuditRules
                }
            }
            $actual = $evaluator.Evaluate([object[]]@($hosts[0]), [pscredential]::Empty, $auditProfile)
            Assert-Fixture ($actual.Count -eq 2 -and $script:trace.Count -eq 1 -and
                $script:trace[0].Target -ceq 'a.fixture.invalid' -and -not $script:trace[0].Credential -and
                $actual[0].Status -ceq 'Pass' -and $actual[1].Status -ceq 'Pass') 'Audit changed for the default credential.'
        }

        Test-Fixture 'registry type presence preserves native getter order and evidence' {
            Reset-FixtureTrace
            $ruleProfile = @{
                Host = @{
                    RegistryRules = $profile.Host.RegistryRules
                }
            }
            $row = [pscustomobject]@{
                Path = 'SOFTWARE\Fixture'
                Name = 'Enabled'
                Status = 'Observed'
                Value = 1
                TypeReads = 0
            }
            $row.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Type', {
                        $this.TypeReads++
                        if ($this.TypeReads -eq 1) {
                            return 4
                        }
                        if ($this.TypeReads -eq 2) {
                            return , @(0)
                        }
                        return , @(4)
                    }))
            $inputHost = [pscustomobject]@{
                ComputerName = 'a.fixture.invalid'
                Services = @()
                Registry = @($row)
            }
            $actual = & {
                Set-StrictMode -Version Latest
                , $evaluator.Evaluate([object[]]@($inputHost), $ruleProfile)
            }
            Assert-Fixture ($actual.Count -eq 2 -and $actual[0].Status -ceq 'Pass' -and $row.TypeReads -eq 3 -and
                [object]::Equals(4, $actual[0].Evidence.RegistryType) -and
                $script:trace.Count -eq 0) 'The direct registry evaluator changed native type comparison order or evidence.'
        }
    }
    else {
        $script:expected = 2
        Test-Fixture 'repeated direct evaluations detach configuration and rows' {
            Reset-FixtureTrace
            $before = ConvertTo-Json -InputObject $profile -Compress -Depth 20
            $first = $evaluator.Evaluate($hosts, $script:credential, $profile)
            $first[0].Status = 'Fixture changed'
            $first[0].Expected.State = 'Fixture changed'
            $first[0].Evidence.ProfileRuleId = 'Fixture changed'

            Reset-FixtureTrace
            $second = $evaluator.Evaluate($hosts, $script:credential, $profile)
            Assert-Fixture ($second[0].Status -ceq 'Pass' -and $second[0].Expected.State -ceq 'Running' -and
                $null -eq $second[0].Evidence.ProfileRuleId -and $script:trace.Count -eq 4 -and
                (ConvertTo-Json -InputObject $profile -Compress -Depth 20) -ceq $before -and
                (ConvertTo-Json -InputObject $evaluator -Compress -Depth 8) -notlike '*host-policy-fixture*') 'A prior result changed later rule outcomes or exposed operation state.'

            if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                Reset-FixtureTrace
                $nativeService = [Microsoft.Management.Infrastructure.CimInstance]::new('Win32_Service')
                try {
                    $propertyType = [Microsoft.Management.Infrastructure.CimType]::String
                    $flags = [Microsoft.Management.Infrastructure.CimFlags]::None
                    $name = [Microsoft.Management.Infrastructure.CimProperty]::Create('Name', 'FixtureSvc', $propertyType, $flags)
                    $state = [Microsoft.Management.Infrastructure.CimProperty]::Create('State', 'Running', $propertyType, $flags)
                    $null = $nativeService.CimInstanceProperties.Add($name)
                    $null = $nativeService.CimInstanceProperties.Add($state)
                    $origin = 'cim-origin.fixture.invalid'
                    $sessionId = $nativeService.GetCimSessionInstanceId()
                    $sessionComputer = $nativeService.GetCimSessionComputerName()
                    $serviceMetadata = @{
                        InputObject = $nativeService
                        MemberType = 'NoteProperty'
                        Name = 'FixtureCimOrigin'
                        Value = $origin
                        PassThru = $true
                    }
                    $serviceView = Add-Member @serviceMetadata
                    $services = @($serviceView)
                    $inputHost = [pscustomobject]@{
                        ComputerName = 'a.fixture.invalid'
                        Services = $services
                        Registry = @()
                    }
                    $serviceProfile = @{
                        Host = @{
                            Services = $profile.Host.Services
                        }
                    }
                    $checks = $evaluator.Evaluate([object[]]@($inputHost), $serviceProfile)
                    $observed = $checks[0].Observed
                    $returnedService = $observed[0]
                    Assert-Fixture ($checks.Count -eq 2 -and $checks[0].Status -ceq 'Pass' -and
                        $observed -is [array] -and $observed.Count -eq 1 -and
                        -not [object]::ReferenceEquals($services, $observed) -and
                        $returnedService -is [Microsoft.Management.Infrastructure.CimInstance] -and
                        [object]::ReferenceEquals($nativeService.PSObject.BaseObject, $returnedService.PSObject.BaseObject) -and
                        $returnedService.PSObject.Properties['FixtureCimOrigin'].Value -ceq $origin -and
                        $returnedService.GetCimSessionInstanceId() -eq $sessionId -and
                        $returnedService.GetCimSessionComputerName() -ceq $sessionComputer -and
                        $returnedService.CimSystemProperties.ClassName -ceq 'Win32_Service' -and
                        $returnedService.CimInstanceProperties['Name'].Value -ceq 'FixtureSvc' -and
                        $returnedService.CimInstanceProperties['State'].Value -ceq 'Running' -and
                        $nativeService.CimInstanceProperties['State'].Value -ceq 'Running' -and
                        $script:trace.Count -eq 0) 'The evaluator changed or disposed the borrowed CIM row, lost its origin, or reused the input array.'
                }
                finally {
                    $nativeService.Dispose()
                }
            }
        }

        Test-Fixture 'same-source secondary runspace disposal' {
            $worker = [powershell]::Create()
            try {
                $source = @'
param($Fixture, $Root)
$ErrorActionPreference = 'Stop'
& $Fixture -Case Construction -RepositoryRoot $Root
'Secondary host policy evaluator loaded'
'@
                $result = @($worker.AddScript($source).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
                Assert-Fixture ($result.Count -eq 1 -and [string]$result[0] -ceq 'Secondary host policy evaluator loaded' -and
                    $worker.Streams.Error.Count -eq 0) ('Secondary evaluator failed. ' + ($worker.Streams.Error -join [Environment]::NewLine))
            }
            finally {
                $worker.Dispose()
            }

            Reset-FixtureTrace
            $reused = $evaluator.Evaluate($hosts, $script:credential, $profile)
            Reset-FixtureTrace
            $fresh = [ADAnalyzerHostPolicyEvaluator]::new()
            $independent = $fresh.Evaluate($hosts, $script:credential, $profile)
            Assert-Fixture ($reused.Count -eq 12 -and $independent.Count -eq 12 -and $script:trace.Count -eq 4 -and
                (ConvertTo-Json -InputObject $reused -Compress -Depth 20) -ceq
                (ConvertTo-Json -InputObject $independent -Compress -Depth 20)) 'Secondary runspace disposal changed an existing or fresh evaluator result.'
        }
    }
}

Assert-Fixture ($script:checks -eq $script:expected) 'Fixture did not run every expected check.'
Write-Host ('PASS host policy class {0} {1}' -f $Case, $script:checks)
