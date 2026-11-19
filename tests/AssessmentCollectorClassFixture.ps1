[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Direct', 'Isolation', 'Composition')]
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

$script:passed = 0
$script:credential = [pscredential]::new('assessment-fixture-only', [Security.SecureString]::new())

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
        Write-Host ('FAIL assessment collector ' + $Name)
        throw
    }
}

function New-FixtureProfileDirectory {
    $path = Join-Path ([IO.Path]::GetTempPath()) ('assessment-profile-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($path)
    return $path
}

function New-FixtureProfileFile([string]$Directory, [string]$Format) {
    $name = 'profile-from-file-fixture'
    $path = Join-Path $Directory ('profile-fixture.' + $Format)
    if ($Format -eq 'psd1') {
        $content = @'
@{
    Name = 'profile-from-file-fixture'
    Targets = @{
        Domain = 'file-profile.invalid'
        Server = 'file-profile.dc.invalid'
        SearchBase = 'OU=FileProfile,DC=file-profile,DC=invalid'
    }
    Analysis = @{
        IncludeGpo = $false
    }
}
'@
    }
    else {
        $profile = @{
            Name = $name
            Targets = @{
                Domain = 'file-profile.invalid'
                Server = 'file-profile.dc.invalid'
                SearchBase = 'OU=FileProfile,DC=file-profile,DC=invalid'
            }
            Analysis = @{
                IncludeGpo = $false
            }
        }
        $content = ConvertTo-Json -InputObject $profile -Depth 10
    }
    [IO.File]::WriteAllText($path, $content)
    return $path
}

function New-NativeDirectoryFixture([string]$Domain = 'example.invalid') {
    $dn = 'DC=' + ($Domain.Replace('.', ',DC='))
    $coverage = @{}
    foreach ($key in @('Domain',
            'Users',
            'Groups',
            'Computers',
            'Trusts',
            'DefaultPasswordPolicy',
            'FineGrainedPasswordPolicies',
            'ResultantPasswordPolicies',
            'ServiceAccounts',
            'OptionalFeatures')) {
        $coverage[$key] = 'Collected'
    }
    $coverage.Acl = 'NotConfigured'
    $coverage.Hosts = 'NotConfigured'
    [pscustomobject]@{
        Domain = [pscustomobject]@{
            DNSRoot = $Domain
            DistinguishedName = $dn
            SID = 'S-1-5-21-1-2-3'
            MachineAccountQuota = 0
            OptionalFeatures = @([pscustomobject]@{
                    FeatureGUID = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'
                    EnabledScopes = @($dn)
                })
        }
        Server = ('dc.' + $Domain)
        Users = @()
        Groups = @()
        Computers = @()
        ServiceAccounts = @()
        Objects = @()
        Trusts = @()
        DomainControllers = @()
        PasswordPolicies = [pscustomobject]@{
            Default = $null
            FineGrained = @()
            Resultant = @()
        }
        Acl = [pscustomobject]@{
            Entries = @()
        }
        Hosts = @()
        Errors = @()
        Coverage = $coverage
    }
}

function New-NativePolicyFixture {
    [pscustomobject]@{
        Path = 'fixture'
        SysvolVersion = 1
        SecuritySettings = @()
        RegistrySettings = @()
        XmlFiles = @()
        IniSettings = @()
        Files = @()
        UnparsedFiles = @()
    }
}


if ($Case -eq 'Native') {
    # Exact command body from accepted 9ae81a8. Keep its name and scope for native parity.
    # Body SHA-256: c39f6a8c4f6822e6da4c8c67e7395a00810b19accfd5d915fbb263dfe6f6c47e
    $script:AcceptedNativeAssessment = @'
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [string]$SearchBase,
        [string]$ProfilePath,
        $Profile,
        [switch]$IncludeAcl,
        [switch]$IncludeHostChecks,
        [switch]$SkipGpo

    )
    if ($ProfilePath -and $null -ne $Profile) {
        throw 'Specify ProfilePath or Profile, not both'
    }
    $configuration = if ($ProfilePath) {
        Import-ADAnalyzerProfile -Path $ProfilePath
    }
    else {
        Import-ADAnalyzerProfile -Profile $Profile
    }
    if (-not $Domain) {
        $Domain = $configuration.Targets.Domain
    }
    if (-not $Server) {
        $Server = $configuration.Targets.Server
    }
    if (-not $Domain) {
        $Domain = $env:USERDNSDOMAIN
    }
    if (-not $Server) {
        $Server = $Domain
    }
    if ($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Specify Domain or Server (or configure Targets)'
    }
    $connection = @{
        Server = $Server
        ErrorAction = 'Stop'
    }
    if ($Credential -and $Credential -ne [pscredential]::Empty) {
        $connection.Credential = $Credential
    }
    $root = Get-ADRootDSE @connection
    if ($root.DnsHostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Directory returned an invalid DC host name'
    }
    $connection.Server = [string]$root.DnsHostName
    if (-not $Domain) {
        $domainInfo = Get-ADDomain @connection
        $Domain = [string]$domainInfo.DNSRoot
    }
    if ($Domain -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Invalid domain DNS name'
    }
    if (-not $SearchBase) {
        $SearchBase = $configuration.Targets.SearchBase
    }
    $context = [pscustomobject]@{
        Server = $connection.Server
        Domain = $Domain
        Credential = $Credential
        SearchBase = $SearchBase
        IncludeAcl = ($IncludeAcl -or $configuration.Analysis.IncludeAcl)
        IncludeHostChecks = ($IncludeHostChecks -or $configuration.Analysis.IncludeHostChecks)
    }
    $directory = Get-ADAnalyzerDirectoryData -Context $context -Profile $configuration
    $resolvedDomain = if ($directory.Domain.DNSRoot -match '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        [string]$directory.Domain.DNSRoot
    }
    else {
        $Domain
    }
    if ($context.IncludeHostChecks) {
        $hostChecks = @(Test-ADAnalyzerHostPolicy -Hosts @($directory.Hosts) -Credential $Credential -Profile $configuration)
        $directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue $hostChecks -Force
    }
    $policies = [Collections.ArrayList]::new()
    if (-not $SkipGpo -and $configuration.Analysis.IncludeGpo) {
        try {
            $gpos = @(Get-ADAnalyzerGpo -All -Domain $resolvedDomain -Server $context.Server -Credential $Credential)
            foreach ($gpo in $gpos) {
                try {
                    $report = Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $Credential -AsObject
                    $null = $policies.Add([pscustomobject]@{
                            Gpo = $gpo
                            Policy = $report.Policy
                            Error = $null
                        })
                }
                catch {
                    $null = $policies.Add([pscustomobject]@{
                            Gpo = $gpo
                            Policy = $null
                            Error = $_.Exception.Message
                        })
                }
            }
        }
        catch {
            $null = $policies.Add([pscustomobject]@{
                    Gpo = [pscustomobject]@{
                        Id = $Domain
                    }
                    Policy = $null
                    Error = $_.Exception.Message
                })
        }
    }
    $result = Invoke-ADAnalyzerAssessment `
        -DirectoryData $directory `
        -GpoData $policies.ToArray() `
        -Profile $configuration `
        -Target $resolvedDomain
    $result | Add-Member -NotePropertyName Context -NotePropertyValue ([pscustomobject]@{
            Domain = $resolvedDomain
            RequestedDomain = $Domain
            Server = $context.Server
            SearchBase = $SearchBase
            IncludeAcl = $context.IncludeAcl
            IncludeHostChecks = $context.IncludeHostChecks
        })
    $result
'@
    $script:IgnoreDispositions = [Collections.Generic.List[string]]::new()
    $script:NativeAssessmentEngine = ${function:Invoke-ADAnalyzerAssessment}
    $script:PolicyIds = @(
        [guid]'11111111-1111-1111-1111-111111111111'
        [guid]'22222222-2222-2222-2222-222222222222'
        [guid]'33333333-3333-3333-3333-333333333333'
    )

    function script:Get-FixtureCredentialKind([bool]$Bound, $Credential) {
        if (-not $Bound) {
            return 'Omitted'
        }
        if ([object]::ReferenceEquals($Credential, $script:credential)) {
            return 'Exact'
        }
        if ([object]::ReferenceEquals($Credential, [pscredential]::Empty)) {
            return 'Empty'
        }
        if ($null -eq $Credential) {
            return 'Null'
        }
        return 'Other'
    }

    function script:Add-Observation([string]$Stage, [object]$Values) {
        $item = [ordered]@{
            Stage = $Stage
            Values = $Values
        }
        $script:Trace.Add($item)
    }

    function script:Get-ADRootDSE {
        [CmdletBinding()]
        param($Server, $Credential)

        Add-Observation Root ([ordered]@{
            Server = $Server
            Credential = Get-FixtureCredentialKind $PSBoundParameters.ContainsKey('Credential') $Credential
            ErrorAction = [string]$PSBoundParameters.ErrorAction
        })
        if ($script:ScenarioName -eq 'RootThrow') {
            throw [InvalidOperationException]::new('Root fixture failed')
        }
        if ($script:ScenarioName -eq 'RootWriteError') {
            Write-Error -Message 'Root fixture emitted an error' -ErrorId 'Fixture.Root'
        }
        if ($script:ScenarioName -eq 'InvalidSelected') {
            [pscustomobject]@{ DnsHostName = 'invalid selected host' }
            return
        }
        if ($script:ScenarioName -eq 'SelectedGetter') {
            $value = [pscustomobject]@{}
            $script:SelectedReads = 0
            $value | Add-Member ScriptProperty DnsHostName {
                $script:SelectedReads++
                Add-Observation SelectedGetter $script:SelectedReads
                if ($script:SelectedReads -eq 1) {
                    'first.dc.invalid'
                }
                else {
                    'second.dc.invalid'
                }
            }
            $value
            return
        }
        [pscustomobject]@{ DnsHostName = 'selected.dc.invalid' }
    }

    function script:Get-ADDomain {
        [CmdletBinding()]
        param($Server, $Credential, $Identity)

        Add-Observation Domain ([ordered]@{
            Server = $Server
            IdentityBound = $PSBoundParameters.ContainsKey('Identity')
            Credential = Get-FixtureCredentialKind $PSBoundParameters.ContainsKey('Credential') $Credential
            ErrorAction = [string]$PSBoundParameters.ErrorAction
        })
        if ($script:ScenarioName -eq 'DomainThrow') {
            throw [InvalidOperationException]::new('Domain fixture failed')
        }
        if ($script:ScenarioName -eq 'InvalidDomain') {
            [pscustomobject]@{ DNSRoot = 'invalid domain name' }
            return
        }
        [pscustomobject]@{ DNSRoot = 'inferred.invalid' }
    }

    function script:Get-ADAnalyzerDirectoryData {
        [CmdletBinding()]
        param($Context, $Profile)

        Add-Observation Directory ([ordered]@{
            Target = $Context.Domain
            Server = $Context.Server
            SearchBase = $Context.SearchBase
            Credential = Get-FixtureCredentialKind $true $Context.Credential
            IncludeAcl = $Context.IncludeAcl
            IncludeHostChecks = $Context.IncludeHostChecks
            DirectoryConnection = $Profile.Analysis.DirectoryConnection
            Profile = $Profile.Name
        })
        if ($script:ScenarioName -eq 'DirectoryThrow') {
            throw [InvalidOperationException]::new('Directory fixture failed')
        }
        if ($script:ScenarioName -eq 'DirectoryWriteError') {
            Write-Warning 'directory warning'
            Write-Error -Message 'Directory fixture emitted an error' -ErrorId 'Fixture.Directory'
            Write-Information 'directory information' -Tags 'Fixture'
        }
        $script:Directory = New-NativeDirectoryFixture $Context.Domain
        $script:Directory.Domain.DNSRoot = $script:ResolvedDomain
        $script:Directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue @('existing')
        if ($script:RealEvaluation) {
            $script:Directory.HostChecks = @()
        }
        if ($script:ScenarioName -eq 'InvalidResolved') {
            $script:Directory.Domain.DNSRoot = 'invalid resolved name'
        }
        if ($script:ScenarioName -eq 'ResolvedGetter') {
            $script:ResolvedReads = 0
            $script:Directory.Domain.PSObject.Properties.Remove('DNSRoot')
            $script:Directory.Domain | Add-Member ScriptProperty DNSRoot {
                $script:ResolvedReads++
                Add-Observation ResolvedGetter $script:ResolvedReads
                if ($script:ResolvedReads -eq 1) {
                    'first.observed.invalid'
                }
                else {
                    'second.observed.invalid'
                }
            }
        }
        $script:Directory
    }

    function script:Test-ADAnalyzerHostPolicy {
        [CmdletBinding()]
        param($Hosts, $Credential, $Profile)

        Add-Observation Host ([ordered]@{
            HostsType = $Hosts.GetType().FullName
            Count = $Hosts.Count
            Credential = Get-FixtureCredentialKind $PSBoundParameters.ContainsKey('Credential') $Credential
            Profile = $Profile.Name
        })
        if ($script:ScenarioName -eq 'HostThrow') {
            throw [InvalidOperationException]::new('Host fixture failed')
        }
        if ($script:ScenarioName -eq 'HostWriteError') {
            Write-Warning 'host warning'
            Write-Error -Message 'Host fixture emitted an error' -ErrorId 'Fixture.Host'
        }
        'new-host-check'
    }

    function script:Get-ADAnalyzerGpo {
        [CmdletBinding()]
        param([switch]$All, $Domain, $Server, $Credential)

        Add-Observation Catalog ([ordered]@{
            All = [bool]$All
            Domain = $Domain
            Server = $Server
            Credential = Get-FixtureCredentialKind $PSBoundParameters.ContainsKey('Credential') $Credential
            ExplicitErrorAction = $PSBoundParameters.ContainsKey('ErrorAction')
        })
        if ($script:ScenarioName -eq 'CatalogEmpty') {
            return
        }
        if ($script:ScenarioName -in @('CatalogThrow', 'CatalogWriteError')) {
            [pscustomobject]@{
                Id = $script:PolicyIds[0]
                Flags = 0
                Version = 1
                Links = @()
            }
            if ($script:ScenarioName -eq 'CatalogThrow') {
                throw [InvalidOperationException]::new('Catalog fixture failed after an item')
            }
            Write-Error -Message 'Catalog fixture emitted an error after an item' -ErrorId 'Fixture.Catalog'
        }
        foreach ($id in $script:PolicyIds[1..2]) {
            [pscustomobject]@{
                Id = $id
                Flags = 0
                Version = 1
                Links = @()
            }
        }
    }

    function script:Get-ADAnalyzerGpoReport {
        [CmdletBinding()]
        param($Gpo, $Credential, [switch]$AsObject)

        Add-Observation Report ([ordered]@{
            Id = [string]$Gpo.Id
            Credential = Get-FixtureCredentialKind $PSBoundParameters.ContainsKey('Credential') $Credential
            AsObject = [bool]$AsObject
            ExplicitErrorAction = $PSBoundParameters.ContainsKey('ErrorAction')
        })
        if ($Gpo.Id -eq $script:PolicyIds[1]) {
            if ($script:ScenarioName -eq 'MixedRows') {
                throw [InvalidOperationException]::new('Report fixture denied one row')
            }
            if ($script:ScenarioName -eq 'ReportWriteError') {
                Write-Warning 'report warning'
                Write-Error -Message 'Report fixture emitted an error' -ErrorId 'Fixture.Report'
                Write-Information 'report information' -Tags 'Fixture'
            }
            if ($script:ScenarioName -eq 'ReportWarning') {
                Write-Warning 'report version warning'
            }
        }
        [pscustomobject]@{ Policy = New-NativePolicyFixture }
    }

    function script:Invoke-ADAnalyzerAssessment {
        [CmdletBinding()]
        param($DirectoryData, [array]$GpoData, $Profile, $Target)

        if ($script:RealEvaluation) {
            & $script:NativeAssessmentEngine @PSBoundParameters
            return
        }
        $hostChecks = $null
        if ($null -ne $DirectoryData) {
            $hostChecks = $DirectoryData.HostChecks
        }
        Add-Observation Evaluation ([ordered]@{
            DirectoryReference = [object]::ReferenceEquals($script:Directory, $DirectoryData)
            Target = $Target
            Profile = $Profile.Name
            HostChecks = $hostChecks
            Rows = @(
                foreach ($row in $GpoData) {
                    [ordered]@{
                        Id = [string]$row.Gpo.Id
                        Readable = $null -ne $row.Policy
                        Error = $row.Error
                    }
                }
            )
        })
        if ($script:ScenarioName -eq 'EvaluatorThrow') {
            throw [InvalidOperationException]::new('Evaluator fixture failed')
        }
        if ($script:ScenarioName -eq 'EvaluatorWriteError') {
            Write-Error -Message 'Evaluator fixture emitted an error' -ErrorId 'Fixture.Evaluator'
        }
        [pscustomobject]@{
            Target = $Target
            State = 'EvaluationFixture'
        }
    }
}

function Get-NativeAssessmentArguments([string]$Scenario, [string]$Action, [string]$ProfilePath) {
    $env:USERDNSDOMAIN = $null
    $arguments = @{
        Domain = 'requested.invalid'
        ErrorAction = $Action
        InformationAction = 'Continue'
    }
    if ($Scenario -in 'Explicit', 'MixedRows') {
        $arguments.Credential = $script:credential
    }
    switch ($Scenario) {
        'Explicit' {
            $arguments.Server = 'requested.dc.invalid'
            $arguments.SearchBase = 'OU=Requested,DC=requested,DC=invalid'
            $arguments.IncludeAcl = $true
            $arguments.IncludeHostChecks = $true
            $arguments.SkipGpo = $true
            $arguments.Profile = @{
                Name = 'explicit-overrides-fixture'
                Targets = @{
                    Domain = 'profile.invalid'
                    Server = 'profile.dc.invalid'
                    SearchBase = 'OU=Profile,DC=profile,DC=invalid'
                }
            }
            $env:USERDNSDOMAIN = 'ambient.invalid'
        }
        'ProfileDefaults' {
            $null = $arguments.Remove('Domain')
            $arguments.Profile = @{
                Name = 'profile-defaults-fixture'
                Targets = @{
                    Domain = 'profile.invalid'
                    Server = 'profile.dc.invalid'
                    SearchBase = 'OU=Profile,DC=profile,DC=invalid'
                }
                Analysis = @{
                    IncludeAcl = $true
                    IncludeHostChecks = $true
                    IncludeGpo = $false
                    DirectoryConnection = 'Direct'
                }
            }
            $arguments.IncludeAcl = $false
            $arguments.IncludeHostChecks = $false
            $env:USERDNSDOMAIN = 'ambient.invalid'
        }
        { $_ -in @('Ambient', 'AmbientExplicitServer', 'ServerOnly', 'DomainThrow', 'InvalidDomain', 'NoTarget') } {
            $null = $arguments.Remove('Domain')
            if ($_ -in @('Ambient', 'AmbientExplicitServer')) {
                $env:USERDNSDOMAIN = 'ambient.invalid'
            }
            if ($_ -in @('AmbientExplicitServer', 'ServerOnly', 'DomainThrow', 'InvalidDomain')) {
                $arguments.Server = 'requested.dc.invalid'
            }
        }
        { $_ -in @('HostThrow', 'HostWriteError') } {
            $arguments.IncludeHostChecks = $true
        }
        'ReportWarning' {
            $arguments.WarningAction = 'Stop'
        }
        'ProfileFile' {
            $arguments.ProfilePath = $ProfilePath
            $null = $arguments.Remove('Domain')
        }
        'MissingProfileFile' {
            $arguments.ProfilePath = Join-Path (Split-Path -Parent $ProfilePath) 'absent-profile-fixture.psd1'
        }
        'Conflict' {
            $arguments.Profile = @{}
            $arguments.ProfilePath = 'unused.invalid.psd1'
        }
        'InvalidProfile' {
            $arguments.Profile = @{ Analysis = @{ IncludeAcl = 'invalid' } }
        }
        'ExplicitNullCredential' {
            $arguments.Credential = $null
        }
        'SkipExplicitFalse' {
            $arguments.SkipGpo = $false
        }
    }
    return $arguments
}

function Get-FixtureErrorIds([object]$Entry) {
    if ($Entry -is [Management.Automation.ErrorRecord]) {
        $Entry.FullyQualifiedErrorId
    }
    elseif ($Entry -is [Collections.IList]) {
        foreach ($item in $Entry) {
            Get-FixtureErrorIds -Entry $item
        }
    }
}

function ConvertTo-FixtureNativeDiagnostic([object]$Entry) {
    if ($null -eq $Entry) {
        return $null
    }
    if ($Entry -is [Collections.IList]) {
        return [ordered]@{
            Type = $Entry.GetType().FullName
            Entries = @(
                foreach ($item in $Entry) {
                    ConvertTo-FixtureNativeDiagnostic $item
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

function ConvertTo-FixtureNativeOutcome($Rows, $Caught, $Captured, $History, $Trace, [bool]$Continued) {
    $outcome = [ordered]@{
        Stages = $Trace
        Continued = $Continued
        Caught = ConvertTo-FixtureNativeDiagnostic $Caught
        ErrorVariable = ConvertTo-FixtureNativeDiagnostic $Captured
        History = ConvertTo-FixtureNativeDiagnostic $History
        Stream = @(
            foreach ($item in $Rows) {
                if ($null -eq $item) {
                    [ordered]@{
                        Type = 'Null'
                        Value = $null
                    }
                }
                elseif ($item -is [Management.Automation.ErrorRecord]) {
                    [ordered]@{
                        Type = 'Error'
                        Value = ConvertTo-FixtureNativeDiagnostic $item
                    }
                }
                elseif ($item -is [Management.Automation.InformationalRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = $item.Message
                    }
                }
                elseif ($item -is [Management.Automation.InformationRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = $item.MessageData
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
    }
    return (ConvertTo-Json -InputObject $outcome -Depth 32 -Compress)
}

function Assert-NativeAssessment(
    [string]$Scenario,
    [string]$Action,
    [string]$ProfilePath,
    [string]$Stages,
    [string]$TerminalId,
    [bool]$Strict = $false,
    [switch]$Observe
) {
    $script:ScenarioName = $Scenario
    $script:Trace = [Collections.Generic.List[object]]::new()
    $script:Directory = $null
    $script:ResolvedDomain = 'observed.invalid'
    $script:RealEvaluation = $Scenario -in 'MixedRows', 'CatalogThrow', 'CatalogEmpty'
    $savedDomain = $env:USERDNSDOMAIN
    $arguments = Get-NativeAssessmentArguments $Scenario $Action $ProfilePath
    if ($Strict) {
        Set-StrictMode -Version Latest
    }

    $seen = [Collections.ArrayList]::new()
    $output = @()
    $caught = $null
    $continued = $false
    $Error.Clear()
    try {
        $output = @(Get-ADAnalyzerAssessment @arguments -ErrorVariable +seen *>&1)
        $continued = $true
    }
    catch {
        $caught = $_
    }
    finally {
        $env:USERDNSDOMAIN = $savedDomain
    }
    $trace = $script:Trace.ToArray()
    if ($Observe) {
        return (ConvertTo-FixtureNativeOutcome $output $caught $seen @($Error) $trace $continued)
    }
    if ($null -ne $caught) {
        $caught = $caught.FullyQualifiedErrorId
    }
    $capturedIds = @(Get-FixtureErrorIds -Entry $seen)
    $historyIds = @(Get-FixtureErrorIds -Entry $Error)
    Assert-Fixture (($trace.Stage -join ',') -ceq $Stages) ('Unexpected native stages: ' + ($trace.Stage -join ','))
    if ($TerminalId) {
        Assert-Fixture (
            $output.Count -eq 0 -and $caught -like ($TerminalId + '*') -and
            @($capturedIds | Where-Object { $_ -like ($TerminalId + '*') }).Count -gt 0
        ) ('Terminal error or ErrorVariable changed: ' + $caught)
        return
    }

    Assert-Fixture ($null -eq $caught -and $output.Count -gt 0) ('Assessment did not return: ' + $caught)
    $result = $output[-1]
    $context = $result.Context
    Assert-Fixture (
        ($context.PSObject.Properties.Name -join ',') -ceq 'Domain,RequestedDomain,Server,SearchBase,IncludeAcl,IncludeHostChecks'
    ) 'The public context changed.'
    Assert-Fixture ($result.Target -ceq $context.Domain) 'The published target differs from the resolved context.'
    $bootstrap = $trace[0].Values
    Assert-Fixture ($bootstrap.ErrorAction -ceq 'Stop') 'RootDSE did not explicitly require terminating failures.'
    $directory = @($trace | Where-Object Stage -CEQ Directory)[0].Values
    Assert-Fixture ($context.Server -ceq $directory.Server -and $context.RequestedDomain -ceq $directory.Target) 'Directory context differs from the published context.'
    $evaluation = @($trace | Where-Object Stage -CEQ Evaluation)
    if ($evaluation.Count) {
        Assert-Fixture (
            $evaluation[0].Values.DirectoryReference -and $evaluation[0].Values.Target -ceq $result.Target
        ) 'The native evaluator did not receive the original directory object and resolved target.'
    }

    switch ($Scenario) {
        'Explicit' {
            $hostObservation = @($trace | Where-Object Stage -CEQ Host)[0].Values
            Assert-Fixture (
                $bootstrap.Server -ceq 'requested.dc.invalid' -and $bootstrap.Credential -ceq 'Exact' -and
                $directory.Credential -ceq 'Exact' -and $hostObservation.Credential -ceq 'Exact' -and
                $evaluation[0].Values.HostChecks -ceq 'new-host-check' -and
                $context.RequestedDomain -ceq 'requested.invalid' -and $context.Domain -ceq 'observed.invalid' -and
                $context.SearchBase -ceq 'OU=Requested,DC=requested,DC=invalid' -and
                $context.IncludeAcl -and $context.IncludeHostChecks -and $directory.DirectoryConnection -ceq 'PSDrive'
            ) 'Explicit targets, credential, host attachment, or options changed.'
        }
        'ProfileDefaults' {
            Assert-Fixture (
                $bootstrap.Server -ceq 'profile.dc.invalid' -and $context.RequestedDomain -ceq 'profile.invalid' -and
                $context.SearchBase -ceq 'OU=Profile,DC=profile,DC=invalid' -and $context.IncludeAcl -and
                $context.IncludeHostChecks -and $directory.DirectoryConnection -ceq 'Direct'
            ) 'Profile precedence or true profile flags changed.'
        }
        'ProfileFile' {
            Assert-Fixture (
                $bootstrap.Server -ceq 'file-profile.dc.invalid' -and $context.RequestedDomain -ceq 'file-profile.invalid' -and
                $context.SearchBase -ceq 'OU=FileProfile,DC=file-profile,DC=invalid'
            ) 'The legacy profile-file configuration was not applied.'
        }
        'Ambient' {
            Assert-Fixture ($bootstrap.Server -ceq 'ambient.invalid' -and $context.RequestedDomain -ceq 'ambient.invalid') 'Ambient target fallback changed.'
        }
        'AmbientExplicitServer' {
            Assert-Fixture ($bootstrap.Server -ceq 'requested.dc.invalid' -and $context.RequestedDomain -ceq 'ambient.invalid') 'A supplied Server replaced the ambient domain.'
        }
        'ServerOnly' {
            $domain = $trace[1].Values
            Assert-Fixture (
                $domain.Server -ceq 'selected.dc.invalid' -and -not $domain.IdentityBound -and
                $domain.Credential -ceq 'Omitted' -and $context.RequestedDomain -ceq 'inferred.invalid'
            ) 'Server-only bootstrap changed the domain inference request.'
        }
        'InvalidResolved' {
            Assert-Fixture ($context.Domain -ceq 'requested.invalid') 'Invalid collected DNS did not fall back to the requested domain.'
        }
        'SelectedGetter' {
            Assert-Fixture ($context.Server -ceq 'second.dc.invalid') 'Selected DC getter was not reread.'
        }
        'ResolvedGetter' {
            Assert-Fixture ($context.Domain -ceq 'second.observed.invalid') 'Collected DNS getter was not reread.'
        }
        'ExplicitNullCredential' {
            $catalog = @($trace | Where-Object Stage -CEQ Catalog)[0].Values
            Assert-Fixture (
                $bootstrap.Credential -ceq 'Omitted' -and $directory.Credential -ceq 'Null' -and $catalog.Credential -ceq 'Null'
            ) 'Explicit null credential was bound to bootstrap or changed downstream.'
        }
        'MixedRows' {
            $rows = $result.Data.Policies
            Assert-Fixture (
                $result.State -ceq 'Partial' -and $rows.Count -eq 2 -and $rows[0].Gpo.Id -ceq [string]$script:PolicyIds[1] -and
                $rows[0].ReadError -ceq 'Report fixture denied one row' -and $rows[1].Gpo.Id -ceq [string]$script:PolicyIds[2] -and
                $null -eq $rows[1].ReadError
            ) 'A report failure changed its identity, sibling survival, or assessment state.'
            foreach ($entry in @($trace | Where-Object Stage -CEQ Report)) {
                Assert-Fixture (
                    $entry.Values.AsObject -and -not $entry.Values.ExplicitErrorAction -and $entry.Values.Credential -ceq 'Exact'
                ) 'The native report integration changed its binding.'
            }
        }
        'CatalogThrow' {
            $rows = $result.Data.Policies
            Assert-Fixture (
                $result.State -ceq 'Partial' -and $rows.Count -eq 1 -and $rows[0].Gpo.Id -ceq 'requested.invalid' -and
                $rows[0].ReadError -ceq 'Catalog fixture failed after an item'
            ) 'The catalog failure did not discard its partial row and preserve requested target identity.'
        }
        'CatalogEmpty' {
            Assert-Fixture (
                @($result.Data.Policies).Count -eq 0 -and @($result.Errors | Where-Object Collection -CEQ GroupPolicy).Count -eq 0
            ) 'An empty catalog produced a failed policy row.'
        }
    }

    if ($Scenario -like '*WriteError') {
        $stageName = $Scenario.Replace('WriteError', '')
        $fixtureId = 'Fixture.' + $stageName
        $visible = @($output | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
        $recorded = @($capturedIds | Where-Object { $_ -like ($fixtureId + ',*') })
        $history = @($historyIds | Where-Object { $_ -like ($fixtureId + ',*') })
        Assert-Fixture (
            ($visible.Count -gt 0) -eq ($Action -eq 'Continue') -and
            ($recorded.Count -gt 0) -eq ($Action -ne 'Ignore') -and
            ($history.Count -gt 0) -eq ($Action -ne 'Ignore')
        ) 'Native stream, ErrorVariable, or error history no longer matches ErrorAction.'
    }
    if ($Scenario -in 'CatalogWriteError', 'ReportWriteError', 'ReportWarning') {
        $rows = $evaluation[0].Values.Rows
        if ($Scenario -eq 'CatalogWriteError') {
            if ($Action -eq 'Stop') {
                Assert-Fixture ($rows.Count -eq 1 -and $rows[0].Id -ceq 'requested.invalid' -and -not $rows[0].Readable) 'Effective Stop did not convert the whole catalog failure.'
            }
            else {
                Assert-Fixture ($rows.Count -eq 3 -and @($rows | Where-Object { -not $_.Readable }).Count -eq 0) 'Catalog output was discarded under a continuing preference.'
            }
        }
        else {
            $shouldFail = $Action -eq 'Stop' -or $Scenario -eq 'ReportWarning'
            Assert-Fixture (
                $rows.Count -eq 2 -and $rows[0].Readable -eq (-not $shouldFail) -and $rows[1].Readable -and
                @($output | Where-Object { $_ -is [Management.Automation.WarningRecord] }).Count -eq 1
            ) 'Report warning or error changed row-specific recovery or warning visibility.'
        }
    }
}

function Assert-FixtureNativeIgnore([string]$Scenario, [string]$ProfilePath) {
    $functionPath = 'Function:script:Get-ADAnalyzerAssessment'
    $current = (Get-Command Get-ADAnalyzerAssessment -CommandType Function).ScriptBlock
    $accepted = [scriptblock]::Create($script:AcceptedNativeAssessment)
    try {
        Set-Item -LiteralPath $functionPath -Value $accepted
        $installed = (Get-Command Get-ADAnalyzerAssessment -CommandType Function).ScriptBlock
        Assert-Fixture ($installed.ToString() -ceq $accepted.ToString()) 'The accepted native command was not installed.'
        $expected = Assert-NativeAssessment $Scenario 'Ignore' $ProfilePath '' '' -Observe
    }
    finally {
        Set-Item -LiteralPath $functionPath -Value $current
    }
    $restored = (Get-Command Get-ADAnalyzerAssessment -CommandType Function).ScriptBlock
    Assert-Fixture ($restored.ToString() -ceq $current.ToString()) 'The current native command was not restored.'
    $actual = Assert-NativeAssessment $Scenario 'Ignore' $ProfilePath '' '' -Observe
    Assert-Fixture ($actual -ceq $expected) (
        'Native Ignore changed from the accepted command on this runtime.' +
        [Environment]::NewLine + 'Accepted: ' + $expected +
        [Environment]::NewLine + 'Current: ' + $actual
    )
    $observation = ConvertFrom-Json -InputObject $actual -ErrorAction Stop
    if ($observation.Continued) {
        $script:IgnoreDispositions.Add($Scenario + '=Continued')
    }
    else {
        $script:IgnoreDispositions.Add($Scenario + '=Terminal/' + $observation.Caught.Id)
    }
}

if ($Case -eq 'Native') {
    $nativeProfileDirectory = New-FixtureProfileDirectory
    try {
        $nativeProfilePath = New-FixtureProfileFile $nativeProfileDirectory 'psd1'
        $baseStages = 'Root,Directory,Catalog,Report,Report,Evaluation'
        $successStages = [ordered]@{
            Explicit = 'Root,Directory,Host,Evaluation'
            ProfileDefaults = 'Root,Directory,Host,Evaluation'
            ProfileFile = 'Root,Directory,Evaluation'
            Ambient = $baseStages
            AmbientExplicitServer = $baseStages
            ServerOnly = 'Root,Domain,Directory,Catalog,Report,Report,Evaluation'
            InvalidResolved = $baseStages
            SelectedGetter = 'Root,SelectedGetter,SelectedGetter,Directory,Catalog,Report,Report,Evaluation'
            ResolvedGetter = 'Root,Directory,ResolvedGetter,ResolvedGetter,Catalog,Report,Report,Evaluation'
            ExplicitNullCredential = $baseStages
            SkipExplicitFalse = $baseStages
            MixedRows = 'Root,Directory,Catalog,Report,Report'
            CatalogThrow = 'Root,Directory,Catalog'
            CatalogEmpty = 'Root,Directory,Catalog'
            ReportWarning = $baseStages
        }
        foreach ($scenario in $successStages.Keys) {
            Test-Fixture $scenario {
                Assert-NativeAssessment $scenario 'Continue' $nativeProfilePath $successStages[$scenario] ''
            }
        }

        $terminalCases = [ordered]@{
            MissingProfileFile = @('', 'PathNotFound')
            NoTarget = @('', 'Specify Domain or Server')
            Conflict = @('', 'Specify ProfilePath or Profile')
            InvalidProfile = @('', 'Analysis.IncludeAcl must be a boolean')
            InvalidSelected = @('Root', 'Directory returned an invalid DC host name')
            InvalidDomain = @('Root,Domain', 'Invalid domain DNS name')
            RootThrow = @('Root', 'Root fixture failed')
            RootWriteError = @('Root', 'Fixture.Root')
            DomainThrow = @('Root,Domain', 'Domain fixture failed')
            DirectoryThrow = @('Root,Directory', 'Directory fixture failed')
            HostThrow = @('Root,Directory,Host', 'Host fixture failed')
            EvaluatorThrow = @($baseStages, 'Evaluator fixture failed')
        }
        foreach ($scenario in $terminalCases.Keys) {
            Test-Fixture $scenario {
                Assert-NativeAssessment $scenario 'Continue' $nativeProfilePath $terminalCases[$scenario][0] $terminalCases[$scenario][1]
            }
        }

        foreach ($scenario in @('DirectoryWriteError', 'HostWriteError', 'CatalogWriteError', 'ReportWriteError', 'EvaluatorWriteError')) {
            foreach ($action in @('Continue', 'Stop', 'SilentlyContinue', 'Ignore')) {
                Test-Fixture ($scenario + ' ' + $action) {
                    if ($action -eq 'Ignore') {
                        Assert-FixtureNativeIgnore $scenario $nativeProfilePath
                        return
                    }
                    $stages = $baseStages
                    $terminal = ''
                    switch ($scenario) {
                        'DirectoryWriteError' {
                            if ($action -eq 'Stop') {
                                $stages = 'Root,Directory'
                                $terminal = 'Fixture.Directory'
                            }
                        }
                        'HostWriteError' {
                            $stages = 'Root,Directory,Host,Catalog,Report,Report,Evaluation'
                            if ($action -eq 'Stop') {
                                $stages = 'Root,Directory,Host'
                                $terminal = 'Fixture.Host'
                            }
                        }
                        'CatalogWriteError' {
                            $stages = 'Root,Directory,Catalog,Report,Report,Report,Evaluation'
                            if ($action -eq 'Stop') {
                                $stages = 'Root,Directory,Catalog,Evaluation'
                            }
                        }
                        'EvaluatorWriteError' {
                            if ($action -eq 'Stop') {
                                $terminal = 'Fixture.Evaluator'
                            }
                        }
                    }
                    Assert-NativeAssessment $scenario $action $nativeProfilePath $stages $terminal
                }
            }
        }
        foreach ($scenario in 'Explicit', 'SelectedGetter', 'ResolvedGetter', 'ReportWriteError', 'EvaluatorThrow') {
            Test-Fixture ($scenario + ' under Strict Latest') {
                $stages = $baseStages
                $terminal = ''
                if ($successStages.Contains($scenario)) {
                    $stages = $successStages[$scenario]
                }
                elseif ($terminalCases.Contains($scenario)) {
                    $terminal = $terminalCases[$scenario][1]
                }
                Assert-NativeAssessment $scenario 'Continue' $nativeProfilePath $stages $terminal $true
            }
        }
    }
    finally {
        [IO.Directory]::Delete($nativeProfileDirectory, $true)
    }
    Assert-Fixture ($script:IgnoreDispositions.Count -eq 5) 'Expected five same-engine Ignore comparisons.'
    'PASS assessment Ignore parity ' + ($script:IgnoreDispositions -join ', ')
}

if ($Case -eq 'Construction') {
    Test-Fixture 'literal construction after the documented loader' {
        $collector = [ADAnalyzerAssessmentCollector]::new()
        Assert-Fixture ($collector.GetType().Name -ceq 'ADAnalyzerAssessmentCollector') 'Literal constructor returned the wrong public type.'
    }
    Test-Fixture 'literal overload signatures' {
        $type = [ADAnalyzerAssessmentCollector]
        $default = $type.GetMethod('Collect', [type[]]@([hashtable]))
        $explicit = $type.GetMethod('Collect', [type[]]@([hashtable], [pscredential]))
        Assert-Fixture ($null -ne $default -and $null -ne $explicit) 'The published Collect overloads are missing.'
    }
}

if ($Case -in 'Direct', 'Isolation') {
    $script:bundledPath = Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
    $script:bootstrapTrace = [Collections.Generic.List[object]]::new()
    $script:bootstrapMode = 'Root'
    $script:exports = @{}

    function script:Import-Module {
        [CmdletBinding()]
        param([string]$Name, [string]$Scope, [switch]$PassThru)

        Assert-Fixture (
            [IO.Path]::GetFullPath($Name) -ceq [IO.Path]::GetFullPath($script:bundledPath) -and
            $Scope -ceq 'Local' -and $PassThru -and $PSBoundParameters.ErrorAction -eq 'Stop'
        ) 'Assessment bootstrap did not request the operation-local exact bundled provider.'
        $script:bootstrapTrace.Add([pscustomobject]@{
                Stage = 'Import'
            })
        [pscustomobject]@{
            ExportedCmdlets = $script:exports
        }
    }

    function script:Invoke-FixtureBootstrapRoot {
        [CmdletBinding()]
        param([string]$Server, [pscredential]$Credential)

        $script:bootstrapTrace.Add([pscustomobject]@{
                Stage = 'Root'
                Server = $Server
                Credential = $Credential
                CredentialBound = $PSBoundParameters.ContainsKey('Credential')
                ErrorAction = $PSBoundParameters.ErrorAction
            })
        if ($script:bootstrapMode -eq 'Infer') {
            return [pscustomobject]@{
                DnsHostName = 'selected.fixture.invalid'
            }
        }
        throw 'Stopped at the fixture root boundary.'
    }

    function script:Invoke-FixtureBootstrapDomain {
        [CmdletBinding()]
        param([string]$Server, [pscredential]$Credential, [string]$Identity)

        $script:bootstrapTrace.Add([pscustomobject]@{
                Stage = 'Domain'
                Server = $Server
                Credential = $Credential
                CredentialBound = $PSBoundParameters.ContainsKey('Credential')
                IdentityBound = $PSBoundParameters.ContainsKey('Identity')
                ErrorAction = $PSBoundParameters.ErrorAction
            })
        throw 'Stopped at the fixture domain inference boundary.'
    }

    function script:Get-ADRootDSE { throw 'Unexpected legacy RootDSE lookup.' }
    function script:Get-ADDomain { throw 'Unexpected legacy domain lookup.' }
    function script:Get-ADAnalyzerAssessment { throw 'Unexpected legacy collector.' }
    function script:Get-ADAnalyzerDirectoryData { throw 'Unexpected legacy directory collector.' }
    function script:Test-ADAnalyzerHostPolicy { throw 'Unexpected legacy host evaluator.' }
    function script:Get-ADAnalyzerGpo { throw 'Unexpected legacy catalog.' }
    function script:Get-ADAnalyzerGpoReport { throw 'Unexpected legacy report reader.' }
    function script:Invoke-ADAnalyzerAssessment { throw 'Unexpected legacy assessment evaluator.' }

    $script:exports['Get-ADRootDSE'] = Get-Command Invoke-FixtureBootstrapRoot
    $script:exports['Get-ADDomain'] = Get-Command Invoke-FixtureBootstrapDomain
}

function Invoke-FixtureExpectedFailure(
    [scriptblock]$Operation,
    [string]$Message,
    [string]$Stages
) {
    $script:bootstrapTrace.Clear()
    $caught = $null
    try {
        $null = & $Operation
    }
    catch {
        $caught = $_
    }
    Assert-Fixture (
        $null -ne $caught -and $caught.Exception.Message -like ('*' + $Message + '*')
    ) ('Missing expected failure. Received: ' + $caught)
    Assert-Fixture (
        ($script:bootstrapTrace.Stage -join ',') -ceq $Stages
    ) ('Unexpected acquisition stages: ' + ($script:bootstrapTrace.Stage -join ','))
}

if ($Case -eq 'Direct') {
    $savedDomain = $env:USERDNSDOMAIN
    $env:USERDNSDOMAIN = $null
    $directProfileDirectory = New-FixtureProfileDirectory
    try {
        $collector = [ADAnalyzerAssessmentCollector]::new()

        Test-Fixture 'invalid and conflicting configuration fails before acquisition' {
            Invoke-FixtureExpectedFailure { $collector.Collect(@{ Unsupported = $true }) } 'Unsupported assessment option' ''
            Invoke-FixtureExpectedFailure { $collector.Collect(@{ Keys = @() }) } 'Unsupported assessment option: Keys' ''
            Invoke-FixtureExpectedFailure {
                $collector.Collect(@{
                        Domain = 'fixture.invalid'
                        Profile = @{}
                        ProfilePath = 'invalid-path.psd1'
                    })
            } 'Specify ProfilePath or Profile' ''
            Invoke-FixtureExpectedFailure {
                $collector.Collect(@{
                        Domain = 'fixture.invalid'
                        Profile = @{
                            Analysis = @{
                                IncludeAcl = 'not a Boolean'
                            }
                        }
                    })
            } 'Analysis.IncludeAcl must be a boolean' ''
        }

        Test-Fixture 'absence and invalid server fail before acquisition' {
            Invoke-FixtureExpectedFailure { $collector.Collect($null) } 'Specify Domain or Server' ''
            Invoke-FixtureExpectedFailure {
                $collector.Collect(@{
                        Domain = 'fixture.invalid'
                        Server = 'bad server'
                    })
            } 'Specify Domain or Server' ''
        }

        Test-Fixture 'object route uses exact bundled bootstrap and explicit credential' {
            $options = @{
                Domain = 'explicit.fixture.invalid'
                Server = 'server.fixture.invalid'
                Profile = @{
                    Targets = @{
                        Domain = 'profile.fixture.invalid'
                        Server = 'profile-server.fixture.invalid'
                    }
                }
            }
            $before = ConvertTo-Json -InputObject $options -Depth 10 -Compress
            Invoke-FixtureExpectedFailure {
                $collector.Collect($options, $script:credential)
            } 'Stopped at the fixture root boundary.' 'Import,Root'
            $call = $script:bootstrapTrace[1]
            Assert-Fixture (
                $call.Server -ceq 'server.fixture.invalid' -and $call.CredentialBound -and
                [object]::ReferenceEquals($call.Credential, $script:credential) -and $call.ErrorAction -eq 'Stop' -and
                (ConvertTo-Json -InputObject $options -Depth 10 -Compress) -ceq $before
            ) 'Explicit values changed, escaped, or were lost at the exact RootDSE capability.'
        }

        Test-Fixture 'server-only inference uses the repinned host without Identity' {
            $script:bootstrapMode = 'Infer'
            try {
                Invoke-FixtureExpectedFailure {
                    $collector.Collect(@{ Server = 'inference.fixture.invalid' }, $script:credential)
                } 'Stopped at the fixture domain inference boundary.' 'Import,Root,Domain'
                $call = $script:bootstrapTrace[2]
                Assert-Fixture (
                    $script:bootstrapTrace[1].Server -ceq 'inference.fixture.invalid' -and $call.Server -ceq 'selected.fixture.invalid' -and
                    $call.CredentialBound -and [object]::ReferenceEquals($call.Credential, $script:credential) -and
                    -not $call.IdentityBound -and $call.ErrorAction -eq 'Stop'
                ) 'Domain inference changed the selected host, credential, or command shape.'
            }
            finally {
                $script:bootstrapMode = 'Root'
            }
        }

        Test-Fixture 'one-argument overload uses ambient domain as its default server' {
            try {
                $env:USERDNSDOMAIN = 'ambient.fixture.invalid'
                Invoke-FixtureExpectedFailure {
                    $collector.Collect(@{})
                } 'Stopped at the fixture root boundary.' 'Import,Root'
                $call = $script:bootstrapTrace[1]
                Assert-Fixture (
                    $call.Server -ceq 'ambient.fixture.invalid' -and -not $call.CredentialBound
                ) 'Missing options did not use the ambient domain or omitted credential.'
            }
            finally {
                $env:USERDNSDOMAIN = $null
            }
        }

        Test-Fixture 'explicit null credential is omitted from provider parameters' {
            Invoke-FixtureExpectedFailure {
                $collector.Collect(@{ Domain = 'fixture.invalid' }, $null)
            } 'Stopped at the fixture root boundary.' 'Import,Root'
            $call = $script:bootstrapTrace[1]
            Assert-Fixture (
                $call.Server -ceq 'fixture.invalid' -and -not $call.CredentialBound
            ) 'Explicit null unexpectedly became a provider credential.'
        }

        foreach ($format in 'psd1', 'json') {
            Test-Fixture ('direct ' + $format + ' profile configuration') {
                $path = New-FixtureProfileFile $directProfileDirectory $format
                Invoke-FixtureExpectedFailure {
                    $collector.Collect(@{ ProfilePath = $path })
                } 'Stopped at the fixture root boundary.' 'Import,Root'
                Assert-Fixture (
                    $script:bootstrapTrace[1].Server -ceq 'file-profile.dc.invalid'
                ) 'A supported profile file did not establish the bootstrap target.'
            }
        }

        Test-Fixture 'profile read and format errors precede provider import' {
            $unsupported = Join-Path $directProfileDirectory 'fixture.ini'
            $malformed = Join-Path $directProfileDirectory 'malformed.json'
            [IO.File]::WriteAllText($malformed, '{"Name":]')
            Invoke-FixtureExpectedFailure {
                $collector.Collect(@{ ProfilePath = $unsupported })
            } 'Profiles must be .json or restricted .psd1 data files' ''
            $caught = $null
            $script:bootstrapTrace.Clear()
            try {
                $null = $collector.Collect(@{ ProfilePath = $malformed })
            }
            catch {
                $caught = $_
            }
            Assert-Fixture (
                $null -ne $caught -and
                $caught.FullyQualifiedErrorId -match 'ConvertFromJson|Json' -and
                $script:bootstrapTrace.Count -eq 0
            ) ('Malformed JSON did not fail during local parsing: ' + $caught)
        }

        Test-Fixture 'missing exact bootstrap capability is terminal' {
            $savedExport = $script:exports['Get-ADRootDSE']
            $script:exports.Remove('Get-ADRootDSE')
            try {
                Invoke-FixtureExpectedFailure {
                    $collector.Collect(@{ Domain = 'fixture.invalid' })
                } 'The bundled Active Directory provider did not export Get-ADRootDSE' 'Import'
            }
            finally {
                $script:exports['Get-ADRootDSE'] = $savedExport
            }
        }
    }
    finally {
        $env:USERDNSDOMAIN = $savedDomain
        [IO.Directory]::Delete($directProfileDirectory, $true)
    }
}

if ($Case -eq 'Isolation') {
    Test-Fixture 'separate and reused collectors keep arguments operation-local' {
        $first = [ADAnalyzerAssessmentCollector]::new()
        $second = [ADAnalyzerAssessmentCollector]::new()
        $options = @{
            Domain = 'first.fixture.invalid'
        }
        Invoke-FixtureExpectedFailure {
            $first.Collect($options, $script:credential)
        } 'Stopped at the fixture root boundary.' 'Import,Root'
        Assert-Fixture ($script:bootstrapTrace[1].Server -ceq 'first.fixture.invalid') 'The original target was lost.'

        Invoke-FixtureExpectedFailure {
            $second.Collect(@{ Domain = 'second.fixture.invalid' })
        } 'Stopped at the fixture root boundary.' 'Import,Root'
        Assert-Fixture (
            $script:bootstrapTrace[1].Server -ceq 'second.fixture.invalid' -and -not $script:bootstrapTrace[1].CredentialBound
        ) 'A separate collector retained the target or credential from an earlier operation.'

        $options.Domain = 'reused.fixture.invalid'
        Invoke-FixtureExpectedFailure {
            $first.Collect($options)
        } 'Stopped at the fixture root boundary.' 'Import,Root'
        Assert-Fixture (
            $script:bootstrapTrace[1].Server -ceq 'reused.fixture.invalid' -and -not $script:bootstrapTrace[1].CredentialBound -and
            (ConvertTo-Json -InputObject $first -Depth 6 -Compress) -notmatch 'fixture-only|fixture\.invalid'
        ) 'A reused collector retained or serialized operation-local state.'
    }

    Test-Fixture 'secondary runspace disposal preserves the original file-backed collector' {
        $main = [ADAnalyzerAssessmentCollector]::new()
        $directory = New-FixtureProfileDirectory
        try {
            $profilePath = New-FixtureProfileFile $directory 'psd1'
            Invoke-FixtureExpectedFailure {
                $main.Collect(@{ ProfilePath = $profilePath })
            } 'Stopped at the fixture root boundary.' 'Import,Root'

            $worker = [powershell]::Create()
            try {
                $child = @'
param($Fixture, $Root)
$ErrorActionPreference = 'Stop'
& $Fixture -Case Direct -RepositoryRoot $Root
'@
                $output = @($worker.AddScript($child).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
                Assert-Fixture (
                    $output.Count -eq 1 -and [string]$output[0] -ceq 'PASS assessment collector Direct 10' -and
                    $worker.Streams.Error.Count -eq 0
                ) ('Secondary assessment process failed: ' + ($worker.Streams.Error -join [Environment]::NewLine))
            }
            finally {
                $worker.Dispose()
            }

            foreach ($format in 'psd1', 'json') {
                $profilePath = New-FixtureProfileFile $directory $format
                Invoke-FixtureExpectedFailure {
                    $main.Collect(@{ ProfilePath = $profilePath })
                } 'Stopped at the fixture root boundary.' 'Import,Root'
                Assert-Fixture (
                    $script:bootstrapTrace[1].Server -ceq 'file-profile.dc.invalid'
                ) 'Disposing a second runspace changed the original profile-file route.'
            }
        }
        finally {
            [IO.Directory]::Delete($directory, $true)
        }
    }
}

function Add-CompositionEvent([string]$Step, [string]$Detail = '') {
    $script:CompositionTrace.Add($Step + '|' + $Detail)
}

function Install-AssessmentCompositionMocks([string]$RepositoryRoot) {
    $script:CompositionDomain = 'assessment.fixture.invalid'
    $script:CompositionDomainDn = 'DC=assessment,DC=fixture,DC=invalid'
    $script:CompositionRequestedServer = 'alias.' + $script:CompositionDomain
    $script:CompositionPinnedServer = 'dc.' + $script:CompositionDomain
    $script:CompositionSearchBase = 'OU=People,' + $script:CompositionDomainDn
    $script:CompositionCredential = [pscredential]::new('fixture\composition', [Security.SecureString]::new())
    $script:CompositionGpoIds = @(
        [guid]'11111111-1111-1111-1111-111111111111'
        [guid]'22222222-2222-2222-2222-222222222222'
    )
    $script:CompositionAuditId = [guid]'33333333-3333-3333-3333-333333333333'
    $script:CompositionTrace = [Collections.Generic.List[string]]::new()
    $script:CompositionOwned = @{}
    $script:CompositionImports = 0
    $script:CompositionExports = @{}
    $script:CompositionForeignCalls = 0
    $script:CompositionSysvolRoot = '\\{0}\SYSVOL' -f $script:CompositionPinnedServer
    $script:CompositionDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))

    function script:Import-Module {
        [CmdletBinding()]
        param([string]$Name, [string]$Scope, [switch]$PassThru)

        Assert-Fixture ($Name -ceq $script:CompositionDll -and $Scope -ceq 'Local' -and
            $PassThru -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Composition did not import the exact bundled provider locally.'
        $script:CompositionImports++
        Add-CompositionEvent Import ([string]$script:CompositionImports)
        [pscustomobject]@{
            Path = $Name
            ExportedCmdlets = $script:CompositionExports
        }
    }

    $names = @(
        'Get-ADRootDSE', 'Get-ADDomain', 'Get-ADForest',
        'Get-ADObject', 'Get-ADUser', 'Get-ADComputer', 'Get-ADGroup',
        'Get-ADTrust', 'Get-ADDomainController', 'Get-ADServiceAccount',
        'Get-ADDefaultDomainPasswordPolicy', 'Get-ADFineGrainedPasswordPolicy',
        'Get-ADOptionalFeature', 'Get-ADUserResultantPasswordPolicy', 'Get-ADOrganizationalUnit'
    )
    $body = @'
[CmdletBinding()]
param($Server, $Credential, $Identity, $Filter, $SearchBase, $LDAPFilter, $Properties)

Invoke-CompositionProvider 'COMPOSITION_COMMAND' $PSBoundParameters
'@
    foreach ($name in $names) {
        $providerName = 'Invoke-Composition' + $name
        Set-Item -LiteralPath ('Function:script:' + $providerName) -Value (
            [scriptblock]::Create($body.Replace('COMPOSITION_COMMAND', $name))
        )
        $script:CompositionExports[$name] = Get-Command $providerName -CommandType Function
        Set-Item -LiteralPath ('Function:script:' + $name) -Value {
            $script:CompositionForeignCalls++
            throw 'Unexpected ambient AD query in composed assessment.'
        }
    }

    function script:New-PSDrive {
        [CmdletBinding()]
        param([string]$Name, [string]$PSProvider, [string]$Root, [string]$Server,
            [pscredential]$Credential, [string]$Scope, [switch]$WhatIf, [switch]$Confirm)

        Assert-Fixture ($Scope -ceq 'Local' -and $PSBoundParameters['ErrorAction'] -eq 'Stop' -and
            -not $WhatIf -and -not $Confirm -and
            [object]::ReferenceEquals($Credential, $script:CompositionCredential) -and
            $script:CompositionOwned.Count -eq 0) 'Unexpected drive owner, credential, flags or overlap.'
        if ($PSProvider -ceq 'ActiveDirectory') {
            Assert-Fixture ($Name -cmatch '^ADAnalyzerData[0-9a-f]{32}$' -and
                $Root -ceq $script:CompositionDomainDn -and $Server -ceq $script:CompositionPinnedServer) 'Directory drive lost its selected root or server.'
            $kind = 'Directory'
        }
        else {
            Assert-Fixture ($PSProvider -ceq 'FileSystem' -and $Name -cmatch '^ADGpo[0-9a-f]{32}$' -and
                $Root -ceq $script:CompositionSysvolRoot -and -not $PSBoundParameters.ContainsKey('Server')) 'Report did not use the selected local SYSVOL surrogate.'
            $kind = 'Sysvol'
        }
        $mount = @{
            Name = $Name
            Root = $script:CompositionTemp
            PSProvider = 'FileSystem'
            Scope = '1'
            ErrorAction = 'Stop'
            WhatIf = $false
            Confirm = $false
        }
        $drive = Microsoft.PowerShell.Management\New-PSDrive @mount
        $script:CompositionOwned[$Name] = $kind
        Add-CompositionEvent ($kind + 'Mount')
        if ($kind -eq 'Directory') {
            return [pscustomobject]@{
                Name = $Name
                Provider = [pscustomobject]@{ Name = 'ActiveDirectory' }
            }
        }
        $drive
    }

    function script:Set-Location {
        [CmdletBinding()]
        param([string]$LiteralPath)

        $enter = $script:CompositionOwned[[string]$LiteralPath.TrimEnd(':')] -eq 'Directory'
        Assert-Fixture (($enter -or $LiteralPath -ceq $script:CompositionCallerPath) -and
            $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Unexpected location for the owned directory drive.'
        Microsoft.PowerShell.Management\Set-Location @PSBoundParameters
        if ($enter) {
            Add-CompositionEvent DirectoryEnter
        }
        else {
            Add-CompositionEvent DirectoryRestore
        }
    }

    function script:Remove-PSDrive {
        [CmdletBinding()]
        param([string]$Name, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)

        $owned = Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -Scope '1' -ErrorAction Stop
        Assert-Fixture ($script:CompositionOwned.ContainsKey($Name) -and
            $owned.Root -ceq $script:CompositionTemp -and $Force -and -not $WhatIf -and -not $Confirm -and
            $PSBoundParameters['ErrorAction'] -eq 'Stop') 'A drive was removed outside its owning scope.'
        Microsoft.PowerShell.Management\Remove-PSDrive -Scope '1' @PSBoundParameters
        Add-CompositionEvent ($script:CompositionOwned[$Name] + 'Remove')
        $script:CompositionOwned.Remove($Name)
    }

    function script:Get-Item {
        [CmdletBinding()]
        param([string]$LiteralPath, [switch]$Force)

        Assert-Fixture (-not $LiteralPath.StartsWith('\\', [StringComparison]::Ordinal)) 'Unexpected UNC file access in composed assessment.'
        foreach ($driveName in $script:CompositionOwned.Keys) {
            if ($LiteralPath.StartsWith($driveName + ':', [StringComparison]::OrdinalIgnoreCase)) {
                Assert-Fixture ($script:CompositionOwned[$driveName] -ceq 'Sysvol') 'The report attempted a directory-drive file read.'
                Add-CompositionEvent SysvolRead ($LiteralPath.Substring($LiteralPath.LastIndexOf('{')))
            }
        }
        Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
    }

    function script:New-CimSession {
        [CmdletBinding()]
        param([string]$ComputerName, [pscredential]$Credential, [uint32]$OperationTimeoutSec)

        Assert-Fixture ($ComputerName -ceq $script:CompositionPinnedServer -and
            $OperationTimeoutSec -eq 17 -and $PSBoundParameters['ErrorAction'] -eq 'Stop' -and
            [object]::ReferenceEquals($Credential, $script:CompositionCredential) -and $null -eq $script:CompositionSession) 'Host collection changed credential, target, timeout or session ownership.'
        Add-CompositionEvent CimOpen
        $script:CompositionSession = [pscustomobject]@{ ComputerName = $ComputerName }
        $script:CompositionSession
    }

    function script:Get-CimInstance {
        [CmdletBinding()]
        param($CimSession, [string]$ClassName, [string]$Namespace, [string]$Filter, [uint32]$OperationTimeoutSec)

        Assert-Fixture ([object]::ReferenceEquals($CimSession, $script:CompositionSession) -and
            $OperationTimeoutSec -eq 17 -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'CIM class query escaped its owned session.'
        Add-CompositionEvent CimClass $ClassName
        if ($ClassName -ceq 'Win32_Service') {
            Assert-Fixture ($Filter -ceq "Name='Spooler' OR Name='W32Time'") 'Configured host service filter changed.'
            return $script:CompositionService
        }
    }

    function script:Invoke-CimMethod {
        [CmdletBinding()]
        param($CimSession, [string]$ClassName, [string]$Namespace, [string]$MethodName,
            [hashtable]$Arguments, [uint32]$OperationTimeoutSec)

        Assert-Fixture ([object]::ReferenceEquals($CimSession, $script:CompositionSession) -and
            $ClassName -ceq 'StdRegProv' -and $Namespace -ceq 'root/default' -and $OperationTimeoutSec -eq 17 -and
            $Arguments.hDefKey -eq [uint32]2147483650 -and
            $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Registry observation changed its bound session or request.'
        Add-CompositionEvent CimRegistry $MethodName
        [pscustomobject]@{ ReturnValue = 2 }
    }

    function script:Remove-CimSession {
        [CmdletBinding()]
        param($CimSession)

        Assert-Fixture ([object]::ReferenceEquals($CimSession, $script:CompositionSession) -and
            $PSBoundParameters['ErrorAction'] -eq 'SilentlyContinue') 'CIM cleanup used the wrong session or preference.'
        Add-CompositionEvent CimClose
        $script:CompositionSession = $null
    }

    function script:Get-ADAnalyzerAuditPolicy {
        [CmdletBinding()]
        param([string]$ComputerName, [pscredential]$Credential, [int]$TimeoutSeconds)

        Assert-Fixture ($ComputerName -ceq $script:CompositionPinnedServer -and
            $TimeoutSeconds -eq 17 -and [object]::ReferenceEquals($Credential, $script:CompositionCredential) -and
            $script:CompositionOwned.Count -eq 0 -and $null -eq $script:CompositionSession) 'Host policy began before directory and CIM cleanup.'
        Add-CompositionEvent Audit
        [pscustomobject]@{
            SubcategoryGuid = $script:CompositionAuditId.ToString()
            Flags = [uint32]3
        }
    }

    function script:Invoke-Command {
        $script:CompositionForeignCalls++
        throw 'Unexpected remoting in composed assessment.'
    }

    function script:Get-ADAnalyzerTlsCertificate {
        $script:CompositionForeignCalls++
        throw 'Unexpected TLS acquisition in composed assessment.'
    }
}

function Invoke-CompositionProvider([string]$Command, [Collections.IDictionary]$Bound) {
    $server = $script:CompositionPinnedServer
    if ($script:CompositionImports -eq 1 -and $Command -eq 'Get-ADRootDSE') {
        $server = $script:CompositionRequestedServer
    }
    $location = (Microsoft.PowerShell.Management\Get-Location).Drive.Name
    $owned = $script:CompositionOwned[[string]$location] -eq 'Directory'
    Assert-Fixture ($Bound['Server'] -ceq $server -and $Bound['ErrorAction'] -eq 'Stop' -and
        ($owned -or [object]::ReferenceEquals($Bound['Credential'], $script:CompositionCredential)) -and
        (-not $owned -or -not $Bound.ContainsKey('Credential'))) 'A provider request used ambient credentials, scope or the wrong selected DC.'
    Add-CompositionEvent ('AD' + $script:CompositionImports + '/' + $Command) (
        @($Bound['Server'], $Bound['Identity'], $Bound['SearchBase'], $Bound['LDAPFilter'], $owned) -join '/'
    )
    switch ($Command) {
        'Get-ADRootDSE' {
            [pscustomobject]@{
                DnsHostName = $script:CompositionPinnedServer
                DefaultNamingContext = $script:CompositionDomainDn
                ConfigurationNamingContext = 'CN=Configuration,' + $script:CompositionDomainDn
                SchemaNamingContext = 'CN=Schema,CN=Configuration,' + $script:CompositionDomainDn
            }
        }
        'Get-ADDomain' {
            [pscustomobject]@{
                DNSRoot = $script:CompositionDomain
                DistinguishedName = $script:CompositionDomainDn
                DomainSID = 'S-1-5-21-1-2-3'
                DomainMode = 'FixtureDomain'
            }
        }
        'Get-ADForest' {
            [pscustomobject]@{
                RootDomain = $script:CompositionDomain
                ForestMode = 'FixtureForest'
            }
        }
        'Get-ADDomainController' {
            [pscustomobject]@{ HostName = $script:CompositionPinnedServer }
        }
        'Get-ADObject' {
            if ($Bound['LDAPFilter'] -ceq '(objectClass=groupPolicyContainer)') {
                foreach ($id in $script:CompositionGpoIds) {
                    [pscustomobject]@{
                        Name = $id.ToString('B')
                        displayName = 'Composition policy ' + $id
                        DistinguishedName = 'CN={0},CN=Policies,CN=System,{1}' -f $id.ToString('B'), $script:CompositionDomainDn
                        gPCFileSysPath = $script:CompositionSysvolRoot + '\' + $script:CompositionDomain + '\Policies\' + $id.ToString('B')
                        flags = 0
                        whenCreated = [datetime]'2021-01-01'
                        whenChanged = [datetime]'2021-02-01'
                        versionNumber = 64
                        gPCWQLFilter = $null
                        gPCMachineExtensionNames = $null
                        gPCUserExtensionNames = $null
                    }
                }
            }
            elseif ('ms-DS-MachineAccountQuota' -in $Bound['Properties']) {
                [pscustomobject]@{ 'ms-DS-MachineAccountQuota' = 0 }
            }
        }
    }
}

function Invoke-AssessmentCompositionFixture([string]$Transport, [object]$Collector, [switch]$FailEvaluation) {
    $script:CompositionImports = 0
    $script:CompositionTrace.Clear()
    $script:CompositionForeignCalls = 0
    $script:CompositionCallerPath = (Microsoft.PowerShell.Management\Get-Location).Path
    $script:CompositionSession = $null
    $script:CompositionTemp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('assessment-composition-' + [guid]::NewGuid().ToString('N')))
    $nativeService = $null
    try {
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $nativeService = [Microsoft.Management.Infrastructure.CimInstance]::new('Win32_Service')
            $propertyType = [Microsoft.Management.Infrastructure.CimType]::String
            $flags = [Microsoft.Management.Infrastructure.CimFlags]::None
            $properties = [ordered]@{
                Name = 'W32Time'
                State = 'Running'
                StartMode = 'Auto'
            }
            foreach ($property in $properties.Keys) {
                $cimProperty = [Microsoft.Management.Infrastructure.CimProperty]::Create(
                    $property,
                    $properties[$property],
                    $propertyType,
                    $flags
                )
                $null = $nativeService.CimInstanceProperties.Add($cimProperty)
            }
            $metadata = @{
                InputObject = $nativeService
                MemberType = 'NoteProperty'
                Name = 'FixtureCimOrigin'
                Value = 'assessment-cim.fixture.invalid'
                PassThru = $true
            }
            $script:CompositionService = Add-Member @metadata
        }
        else {
            $script:CompositionService = [pscustomobject]@{
                Name = 'W32Time'
                State = 'Running'
                StartMode = 'Auto'
                FixtureCimOrigin = 'assessment-cim.fixture.invalid'
            }
        }
        foreach ($id in $script:CompositionGpoIds) {
            $relative = '{0}/Policies/{1}' -f $script:CompositionDomain, $id.ToString('B')
            $path = Join-Path $script:CompositionTemp $relative
            $machine = Join-Path $path 'Machine'
            $null = [IO.Directory]::CreateDirectory($machine)
            [IO.File]::WriteAllText((Join-Path $path 'GPT.INI'), "[General]`nVersion=64")
            if ($id -eq $script:CompositionGpoIds[0]) {
                [IO.File]::WriteAllBytes((Join-Path $machine 'Registry.pol'), [byte[]]@(1, 2, 3))
            }
            else {
                $security = Join-Path $machine 'Microsoft/Windows NT/SecEdit'
                $null = [IO.Directory]::CreateDirectory($security)
                [IO.File]::WriteAllText(
                    (Join-Path $security 'GptTmpl.inf'),
                    "[Unicode]`nUnicode=yes`n[System Access]`nMinimumPasswordLength=16",
                    [Text.Encoding]::Unicode
                )
            }
        }

        $options = @{
            Domain = $script:CompositionDomain
            Server = $script:CompositionRequestedServer
            SearchBase = $script:CompositionSearchBase
            IncludeHostChecks = $true
            Profile = @{
                Analysis = @{
                    DirectoryConnection = $Transport
                    HostTimeoutSeconds = 17
                }
                Host = @{
                    Services = @(
                        @{
                            Name = 'W32Time'
                            State = 'Running'
                        }
                    )
                    AuditRules = @(
                        @{
                            SubcategoryGuid = $script:CompositionAuditId.ToString()
                            Flags = 3
                        }
                    )
                }
            }
        }
        if ($FailEvaluation) {
            $options.SkipGpo = $true
            $caught = $null
            try {
                $null = $Collector.Collect($options, $script:CompositionCredential)
            }
            catch {
                $caught = $_
            }
            Assert-Fixture (
                $null -ne $caught -and $caught.Exception.Message -like '*Fixture final evaluation failed*' -and
                $script:CompositionTrace[-2] -ceq 'Audit|' -and
                $script:CompositionTrace[-1] -ceq 'FinalEvaluation|' -and
                $script:CompositionImports -eq 2 -and $script:CompositionOwned.Count -eq 0 -and
                $null -eq $script:CompositionSession
            ) 'SkipGpo or terminal assessment failure changed after a successful host stage.'
            Assert-Fixture ($script:CompositionService.State -ceq 'Running') 'A terminal assessment disposed the borrowed service observation.'
            return
        }
        $result = $Collector.Collect($options, $script:CompositionCredential)
        Assert-Fixture (
            $result.Context.Server -ceq $script:CompositionPinnedServer -and
            $result.Context.Domain -ceq $script:CompositionDomain -and
            $result.Context.RequestedDomain -ceq $script:CompositionDomain -and
            $result.Context.SearchBase -ceq $script:CompositionSearchBase -and
            $result.Context.IncludeHostChecks -and -not $result.Context.IncludeAcl
        ) 'Assessment lost the pinned server, domain, scope or switches.'
        $directory = $result.Data.Directory
        $status = if ($Transport -eq 'PSDrive') {
            'Connected'
        }
        else {
            'Direct'
        }
        Assert-Fixture (
            $directory.DirectoryConnection.Mode -ceq $Transport -and
            $directory.DirectoryConnection.Status -ceq $status -and
            $directory.Domain.MachineAccountQuota -eq 0 -and
            $directory.Coverage.Hosts -ceq 'Collected' -and
            @($directory.Hosts).Count -eq 1
        ) 'Composed directory, host, or transport data changed.'
        $services = @($result.Checks | Where-Object RuleId -CEQ 'HOST.SERVICE')
        $audit = @($result.Checks | Where-Object RuleId -CEQ 'HOST.AUDIT_POLICY')
        Assert-Fixture (
            $services.Count -eq 1 -and $services[0].Status -ceq 'Pass' -and
            $services[0].Observed[0].Name -ceq 'W32Time' -and
            $audit.Count -eq 1 -and $audit[0].Status -ceq 'Pass'
        ) 'Actual host policy outcomes were missing from the assessment.'
        $checkService = $services[0].Observed[0]
        $directoryService = $directory.Hosts[0].Services[0]
        Assert-Fixture (
            $checkService -is [pscustomobject] -and $directoryService -is [pscustomobject] -and
            $checkService.FixtureCimOrigin -ceq 'assessment-cim.fixture.invalid' -and
            $directoryService.FixtureCimOrigin -ceq 'assessment-cim.fixture.invalid'
        ) 'Assessment projection lost detached service evidence or its fixture metadata.'
        $checkService.State = 'Fixture changed'
        Assert-Fixture (
            $directoryService.State -ceq 'Running' -and $script:CompositionService.State -ceq 'Running'
        ) 'A projected check reused another result or disposed the original service observation.'
        $policies = @($result.Data.Policies)
        $readFailure = @($result.Checks | Where-Object RuleId -CEQ 'GPO.READ')
        $version = @($result.Checks | Where-Object RuleId -CEQ 'GPO.VERSION_CONSISTENCY')
        $collectionErrors = @($result.Errors | Where-Object Collection -CEQ 'GroupPolicy')
        Assert-Fixture (
            $policies.Count -eq 2 -and [string]$policies[0].Gpo.Id -ceq $script:CompositionGpoIds[0].ToString() -and
            $policies[0].ReadError -like '*Invalid Registry.pol header/version*' -and
            [string]$policies[1].Gpo.Id -ceq $script:CompositionGpoIds[1].ToString() -and
            $null -eq $policies[1].ReadError -and 'GPT.INI' -in $policies[1].Files.Path -and
            'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf' -in $policies[1].Files.Path -and
            $readFailure.Count -eq 1 -and $readFailure[0].Status -ceq 'Unreadable' -and
            $version.Count -eq 1 -and $version[0].Status -ceq 'Pass' -and
            $collectionErrors.Count -eq 1 -and $collectionErrors[0].Target -ceq $script:CompositionGpoIds[0].ToString() -and
            $result.State -ceq 'Partial'
        ) 'A failed GPO read lost its cause, changed policy order or prevented the successful sibling.'
        Assert-Fixture (
            (ConvertTo-Json -InputObject $result -Depth 40 -Compress) -notmatch 'PSCredential|SecureString|fixture.?.?composition'
        ) 'The assessment serialized its integration credential.'

        $summary = @($script:CompositionTrace | ForEach-Object { $_.Split('|')[0] })
        $expected = @(
            'Import', 'AD1/Get-ADRootDSE', 'Import', 'AD2/Get-ADRootDSE', 'AD2/Get-ADDomain'
            if ($Transport -eq 'PSDrive') {
                'DirectoryMount', 'DirectoryEnter'
            }
            'AD2/Get-ADForest', 'AD2/Get-ADObject', 'AD2/Get-ADUser', 'AD2/Get-ADComputer',
            'AD2/Get-ADGroup', 'AD2/Get-ADTrust', 'AD2/Get-ADDomainController', 'AD2/Get-ADServiceAccount',
            'AD2/Get-ADObject', 'AD2/Get-ADDefaultDomainPasswordPolicy',
            'AD2/Get-ADFineGrainedPasswordPolicy', 'AD2/Get-ADOptionalFeature'
            'CimOpen'
            for ($index = 0; $index -lt 5; $index++) {
                'CimClass'
            }
            for ($index = 0; $index -lt 11; $index++) {
                'CimRegistry'
            }
            'CimClose'
            if ($Transport -eq 'PSDrive') {
                'DirectoryRestore', 'DirectoryRemove'
            }
            'Audit', 'Import', 'AD3/Get-ADRootDSE', 'AD3/Get-ADDomain', 'AD3/Get-ADObject',
            'AD3/Get-ADObject', 'AD3/Get-ADObject'
            'SysvolMount', 'SysvolRead', 'SysvolRemove', 'SysvolMount', 'SysvolRead', 'SysvolRemove'
        )
        Assert-Fixture (($expected -join ',') -ceq ($summary -join ',')) (
            'Assessment stage or cleanup order changed: ' + ($script:CompositionTrace -join '; ')
        )
        $mounted = $Transport -eq 'PSDrive'
        $expectedUser = 'AD2/Get-ADUser|{0}//{1}//{2}' -f $script:CompositionPinnedServer, $script:CompositionSearchBase, $mounted
        $expectedGroup = 'AD2/Get-ADGroup|{0}//{1}//{2}' -f $script:CompositionPinnedServer, $script:CompositionDomainDn, $mounted
        Assert-Fixture (
            $expectedUser -cin $script:CompositionTrace -and $expectedGroup -cin $script:CompositionTrace -and
            ('SysvolRead|' + $script:CompositionGpoIds[0].ToString('B')) -cin $script:CompositionTrace -and
            ('SysvolRead|' + $script:CompositionGpoIds[1].ToString('B')) -cin $script:CompositionTrace -and
            $script:CompositionImports -eq 3 -and $script:CompositionOwned.Count -eq 0 -and
            $script:CompositionForeignCalls -eq 0 -and $null -eq $script:CompositionSession -and
            (Microsoft.PowerShell.Management\Get-Location).Path -ceq $script:CompositionCallerPath
        ) 'Collection left its owned drive, escaped a fixture collaborator, or changed scoped requests.'
    }
    finally {
        if ((Microsoft.PowerShell.Management\Get-Location).Path -cne $script:CompositionCallerPath) {
            Microsoft.PowerShell.Management\Set-Location -LiteralPath $script:CompositionCallerPath
        }
        foreach ($driveName in @($script:CompositionOwned.Keys)) {
            Microsoft.PowerShell.Management\Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            $script:CompositionOwned.Remove($driveName)
        }
        if ([IO.Directory]::Exists($script:CompositionTemp)) {
            [IO.Directory]::Delete($script:CompositionTemp, $true)
        }
        if ($null -ne $nativeService) {
            $nativeService.Dispose()
        }
    }
}

if ($Case -eq 'Composition') {
    Install-AssessmentCompositionMocks $RepositoryRoot
    foreach ($name in @(
            'Get-ADAnalyzerAssessment',
            'Get-ADAnalyzerDirectoryData',
            'Test-ADAnalyzerHostPolicy',
            'Get-ADAnalyzerGpo',
            'Get-ADAnalyzerGpoReport',
            'Invoke-ADAnalyzerAssessment'
        )) {
        Set-Item -LiteralPath ('Function:script:' + $name) -Value {
            throw 'Unexpected legacy command in direct assessment composition.'
        }
    }
    $compositionCollector = [ADAnalyzerAssessmentCollector]::new()
    foreach ($transport in 'PSDrive', 'Direct') {
        Test-Fixture ('actual composition with ' + $transport) {
            Invoke-AssessmentCompositionFixture $transport $compositionCollector
        }
    }
    Test-Fixture 'SkipGpo and terminal evaluation preserve the borrowed host observation' {
        function script:Test-ADAnalyzerDirectoryPolicy {
            [CmdletBinding()]
            param($Data, $Profile)

            Add-CompositionEvent FinalEvaluation
            throw 'Fixture final evaluation failed.'
        }

        Invoke-AssessmentCompositionFixture Direct $compositionCollector -FailEvaluation
    }
}

'PASS assessment collector ' + $Case + ' ' + $script:passed
