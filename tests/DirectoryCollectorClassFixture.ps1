[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Direct', 'Isolation', 'UsersCoverage', 'AclCoverage', 'ResultantPolicyCoverage')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
$script:Checks = 0
$script:Domain = 'directory.fixture.invalid'
$script:DomainDn = 'DC=directory,DC=fixture,DC=invalid'
$script:SearchBase = 'OU=People,' + $script:DomainDn
$script:SelectedServer = 'selected.' + $script:Domain
$script:Credential = [pscredential]::new('fixture\collector', [Security.SecureString]::new())
$script:ExpectedDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Commands = @(
    'Get-ADRootDSE'
    'Get-ADDomain'
    'Get-ADForest'
    'Get-ADObject'
    'Get-ADUser'
    'Get-ADComputer'
    'Get-ADGroup'
    'Get-ADTrust'
    'Get-ADDomainController'
    'Get-ADServiceAccount'
    'Get-ADDefaultDomainPasswordPolicy'
    'Get-ADFineGrainedPasswordPolicy'
    'Get-ADOptionalFeature'
    'Get-ADUserResultantPasswordPolicy'
    'Get-ADOrganizationalUnit'
)
$script:Exports = @{}
$script:Imports = [Collections.Generic.List[string]]::new()
$script:Ambient = [Collections.Generic.List[string]]::new()
$script:Trace = [Collections.Generic.List[object]]::new()
$script:Drives = @{}
$script:UseAmbient = $true
$script:ImportAllowed = $false
$script:Fault = ''
$script:PsoDn = 'CN=FixturePolicy,' + $script:DomainDn
$script:RootDomainDn = $script:DomainDn
$script:UsersScenario = ''
$script:UsersQueryStart = $null
$script:UsersNextQuery = $null
$script:UsersGuids = @(
    [guid]'50000000-0000-4000-8000-000000000001'
    [guid]'50000000-0000-4000-8000-000000000002'
)

function Assert-DirectoryCollector($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-DirectoryCollector([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Checks++
    }
    catch {
        $cause = $_.Exception.GetBaseException()
        $diagnostic = @(
            ('Directory collector [{0}] failed: {1}' -f $Name, $_.Exception.Message)
            ('{0}: {1}' -f $cause.GetType().FullName, $cause.Message)
            $_.ScriptStackTrace
            $cause.StackTrace
        ) -join [Environment]::NewLine
        throw [InvalidOperationException]::new($diagnostic, $_.Exception)
    }
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru)

    $script:Imports.Add($Name)
    Assert-DirectoryCollector $script:ImportAllowed 'Loading, construction or validation imported the bundled provider.'
    Assert-DirectoryCollector ([IO.Path]::IsPathRooted($Name) -and $Name -ceq $script:ExpectedDll -and
        $Scope -ceq 'Local' -and $PassThru -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Bundled provider import binding changed.'
    if ($script:Fault -eq 'Import') {
        throw [IO.FileLoadException]::new('Fixture directory provider import failure.')
    }
    $exports = $script:Exports.Clone()
    if ($script:Fault -eq 'MissingExport') {
        $exports.Remove('Get-ADOrganizationalUnit')
    }
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $exports
    }
}

function New-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [string]$PSProvider, [string]$Root, [string]$Server,
        [pscredential]$Credential, [string]$Scope, [switch]$WhatIf, [switch]$Confirm)

    Assert-DirectoryCollector ($PSProvider -ceq 'ActiveDirectory' -and $Scope -ceq 'Local' -and
        $Root -ceq $script:DomainDn -and -not $WhatIf -and -not $Confirm -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'The collector changed owned-drive creation binding.'
    $script:Trace.Add([pscustomobject][ordered]@{
        Step = 'Create'
        Server = $Server
        CredentialBound = $PSBoundParameters.ContainsKey('Credential')
        SameCredential = [object]::ReferenceEquals($Credential, $script:Credential)
    })
    $arguments = @{
        Name = $Name
        PSProvider = 'FileSystem'
        Root = $RepositoryRoot
        Scope = '1'
        ErrorAction = 'Stop'
        WhatIf = $false
        Confirm = $false
    }
    $null = Microsoft.PowerShell.Management\New-PSDrive @arguments
    $script:Drives[$Name] = $Credential
    [pscustomobject]@{
        Name = $Name
        Provider = [pscustomobject]@{
            Name = 'ActiveDirectory'
        }
    }
}

function Set-Location {
    [CmdletBinding()]
    param([string]$LiteralPath)

    $step = if ($LiteralPath.EndsWith(':') -and $script:Drives.ContainsKey($LiteralPath.TrimEnd(':'))) {
        'Enter'
    }
    else {
        'Restore'
    }
    $script:Trace.Add([pscustomobject][ordered]@{ Step = $step })
    if ($step -eq 'Enter' -and $script:Fault -eq 'Enter') {
        throw 'Fixture directory drive entry failure.'
    }
    if ($step -eq 'Restore' -and $script:Fault -eq 'Competing') {
        throw 'Fixture directory location restoration failure.'
    }
    Microsoft.PowerShell.Management\Set-Location -LiteralPath $LiteralPath -ErrorAction Stop
}

function Remove-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)

    Assert-DirectoryCollector ($Force -and -not $WhatIf -and -not $Confirm -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop' -and $script:Drives.ContainsKey($Name) -and
        $null -ne (Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -ErrorAction Stop)) 'Cleanup did not see the owned provider-drive scope.'
    $script:Trace.Add([pscustomobject][ordered]@{ Step = 'Remove' })
    if ($script:Fault -eq 'Competing') {
        throw 'Fixture directory drive removal failure.'
    }
    Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Force -ErrorAction Stop
    $script:Drives.Remove($Name)
}

function New-FixtureUser([string]$Name, [string]$PsoDn) {
    $flag = if ($script:Fault -eq 'Competing') {
        'fixture invalid account flag'
    }
    else {
        512
    }
    $record = [pscustomobject][ordered]@{
        Name = $Name
        SamAccountName = $Name
        DistinguishedName = ('CN={0},{1}' -f $Name, $script:SearchBase)
        ObjectClass = 'user'
        SID = 'S-1-5-21-1-2-3-' + $(
            if ($PsoDn) {
                '1001'
            }
            else {
                '1002'
            }
        )
        PrimaryGroupID = 513
        MemberOf = @()
        UserAccountControl = $flag
        ProtectedFromAccidentalDeletion = $false
        'msDS-ResultantPSO' = $PsoDn
    }
    if ($script:UsersScenario) {
        $identity = $script:UsersGuids[1]
        if ($Name -ceq 'Cached') {
            $identity = $script:UsersGuids[0]
        }
        $record | Add-Member -NotePropertyMembers @{
            ObjectGuid = $identity
            Enabled = $true
            PasswordNeverExpires = ($Name -ceq 'Cached')
        }
    }
    return $record
}

function New-FixturePolicy([string]$Name, [int]$Length) {
    [pscustomobject][ordered]@{
        Name = $Name
        DistinguishedName = $script:PsoDn
        MinPasswordLength = $Length
        PasswordHistoryCount = 10
        ComplexityEnabled = $true
        ReversibleEncryptionEnabled = $false
        LockoutThreshold = 5
        LockoutDuration = [timespan]::FromMinutes(30)
        LockoutObservationWindow = [timespan]::FromMinutes(30)
        MinPasswordAge = [timespan]::FromDays(1)
        MaxPasswordAge = [timespan]::FromDays(90)
    }
}

function Invoke-FixtureProvider([string]$Command, [Collections.IDictionary]$Bound) {
    $driveName = (Microsoft.PowerShell.Management\Get-Location).Drive.Name
    $owned = $script:Drives.ContainsKey($driveName)
    $effective = if ($owned) {
        $script:Drives[$driveName]
    }
    else {
        $Bound['Credential']
    }
    $script:Trace.Add([pscustomobject][ordered]@{
        Step = $Command
        Owned = $owned
        Server = $Bound['Server']
        CredentialBound = $Bound.ContainsKey('Credential')
        SameCredential = [object]::ReferenceEquals($effective, $script:Credential)
        Identity = $Bound['Identity']
        Base = $Bound['SearchBase']
        Filter = $Bound['Filter']
        LdapFilter = $Bound['LDAPFilter']
        Properties = @($Bound['Properties']) -join ','
        Default = $Bound['FixtureDefault']
        ErrorAction = [string]$Bound['ErrorAction']
    })
    if ($script:Fault -eq 'Denied' -and $Command -eq 'Get-ADTrust') {
        Write-Warning 'Fixture directory trust was unreadable.'
        Write-Error -Message 'Fixture directory query denied.' -ErrorId 'Fixture.DirectoryDenied' -ErrorAction Stop
    }

    if ($script:UsersScenario -and $Command -ceq 'Get-ADComputer') {
        $script:UsersNextQuery = [datetimeoffset]::UtcNow
    }
    switch ($Command) {
        'Get-ADRootDSE' {
            $server = 'returned.' + $script:Domain
            if ($script:UsersScenario) {
                $server = $script:SelectedServer
            }
            $root = [pscustomobject][ordered]@{
                DnsHostName = $server
                DefaultNamingContext = $script:RootDomainDn
                SchemaNamingContext = 'CN=Schema,CN=Configuration,' + $script:DomainDn
                ConfigurationNamingContext = 'CN=Configuration,' + $script:DomainDn
            }
            if ($script:UsersScenario -ceq 'ControllerArray') {
                $root.DnsHostName = @($server)
            }
            elseif ($script:UsersScenario -ceq 'ControllerUnreadable') {
                $root.PSObject.Properties.Remove('DnsHostName')
                $root | Add-Member -MemberType ScriptProperty -Name DnsHostName -Value {
                    throw 'Fixture controller witness is unreadable.'
                }
            }
            $root
        }
        'Get-ADDomain' {
            [pscustomobject][ordered]@{
                DistinguishedName = $script:DomainDn
                DNSRoot = $script:Domain
                DomainSID = 'S-1-5-21-1-2-3'
                DomainMode = 'FixtureDomain'
            }
        }
        'Get-ADForest' {
            [pscustomobject][ordered]@{
                RootDomain = $script:Domain
                ForestMode = 'FixtureForest'
            }
        }
        'Get-ADUser' {
            if ($script:UsersScenario) {
                $script:UsersQueryStart = [datetimeoffset]::UtcNow
                switch ($script:UsersScenario) {
                    'Empty' { return }
                    'Denied' {
                        Write-Error -Message 'Fixture Users query Denied' -ErrorId 'Fixture.UsersDenied' -Category PermissionDenied -ErrorAction Stop
                    }
                    'Partial' {
                        New-FixtureUser 'Fallback' ''
                        Write-Error -Message 'Fixture Users query Partial' -ErrorId 'Fixture.UsersPartial' -Category ReadError -ErrorAction Stop
                    }
                }
            }
            New-FixtureUser 'Cached' $script:PsoDn
            New-FixtureUser 'Fallback' ''
        }
        'Get-ADGroup' {
            [pscustomobject][ordered]@{
                SID = 'S-1-5-21-1-2-3-513'
                DistinguishedName = 'CN=Users,' + $script:DomainDn
                Name = 'Fixture users'
                MemberOf = @()
            }
        }
        'Get-ADDomainController' {
            [pscustomobject]@{ HostName = $script:SelectedServer }
        }
        'Get-ADDefaultDomainPasswordPolicy' {
            if ($script:Fault -ceq 'PasswordDefaultDenied') {
                $denial = @{
                    Message = 'Fixture default domain password policy access denied.'
                    ErrorId = 'Fixture.DefaultPolicyDenied'
                    Category = 'PermissionDenied'
                    ErrorAction = 'Stop'
                }
                Write-Error @denial
            }
            if ($script:Fault -ceq 'PasswordDefaultEmpty') {
                return
            }
            $policy = New-FixturePolicy 'Default' 12
            if ($script:Fault -clike 'PasswordDefault*') {
                $policy.DistinguishedName = $script:DomainDn
            }
            $policy
        }
        'Get-ADFineGrainedPasswordPolicy' {
            New-FixturePolicy 'Cached policy' 16
        }
        'Get-ADUserResultantPasswordPolicy' {
            if ($script:Fault -clike 'PasswordDefault*') {
                return
            }
            New-FixturePolicy 'Explicit policy' 18
        }
        'Get-ADOptionalFeature' {
            [pscustomobject]@{ FeatureGUID = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a' }
        }
        'Get-ADOrganizationalUnit' {
            if ($script:Fault -ceq 'AclDenied') {
                Write-Error -Message 'Fixture OU ACL discovery denied.' -ErrorId 'Fixture.AclOuDenied' `
                    -Category PermissionDenied -ErrorAction Stop
            }
            if ($script:Fault -ceq 'AclEmpty') {
                return
            }
            [pscustomobject]@{ DistinguishedName = $script:SearchBase }
        }
        'Get-ADObject' {
            if ('nTSecurityDescriptor' -in $Bound['Properties']) {
                $ace = [pscustomobject][ordered]@{
                    IdentitySid = 'S-1-5-21-1-2-3-9000'
                    Rights = 'ExtendedRight'
                    AccessControlType = 'Allow'
                    ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                }
                if ($script:Fault -clike 'Acl*' -and $Bound['Identity'] -like 'CN=AdminSDHolder,*') {
                    $ace.Rights = 'WriteDacl'
                    $ace.ObjectType = [guid]::Empty.ToString()
                }
                [pscustomobject]@{
                    nTSecurityDescriptor = [pscustomobject]@{
                        Access = @($ace)
                    }
                }
            }
            elseif ('ms-DS-MachineAccountQuota' -in $Bound['Properties']) {
                [pscustomobject]@{ 'ms-DS-MachineAccountQuota' = 5 }
            }
            elseif ($Bound['LDAPFilter'] -like '*lDAPDisplayName=*') {
                [pscustomobject]@{ lDAPDisplayName = 'msDS-ResultantPSO' }
                [pscustomobject]@{ lDAPDisplayName = 'msLAPS-PasswordExpirationTime' }
            }
        }
    }
}

$commandTemplate = @'
[CmdletBinding()]
param($Server, $Credential, $Identity, $SearchBase, $Filter, $LDAPFilter, $Properties, $FixtureDefault)

if (IS_AMBIENT) {
    $script:Ambient.Add('COMMAND_NAME')
    Assert-DirectoryCollector $script:UseAmbient 'Direct collection resolved an ambient directory command.'
}
Invoke-FixtureProvider 'COMMAND_NAME' $PSBoundParameters
'@
foreach ($name in $script:Commands) {
    $template = $commandTemplate.Replace('COMMAND_NAME', $name)
    $ambientBody = [scriptblock]::Create($template.Replace('IS_AMBIENT', '$true'))
    $providerBody = [scriptblock]::Create($template.Replace('IS_AMBIENT', '$false'))
    Set-Item -LiteralPath ('Function:script:' + $name) -Value $ambientBody
    Set-Item -LiteralPath ('Function:script:Invoke-Fixture' + $name) -Value $providerBody
    $script:Exports[$name] = Get-Command ('Invoke-Fixture' + $name) -CommandType Function
}

foreach ($name in 'New-CimSession', 'Get-CimInstance', 'Invoke-CimMethod', 'Remove-CimSession') {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value { throw 'Unexpected CIM integration in directory-only fixture.' }
}

. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

function New-FixtureContext {
    [pscustomobject][ordered]@{
        Server = $script:SelectedServer
        Domain = $script:Domain
        Credential = $script:Credential
        SearchBase = $script:SearchBase
        IncludeAcl = $true
    }
}

function New-FixtureProfile([string]$Transport) {
    $profile = @{
        Analysis = @{}
        AccountClassification = @{ UserOUs = @($script:SearchBase) }
    }
    if ($Transport -ceq 'Direct') {
        $profile.Analysis.DirectoryConnection = $Transport
    }
    $profile
}

function Clear-FixtureObservations {
    $script:Trace.Clear()
    $script:Ambient.Clear()
    $script:Imports.Clear()
    $script:Fault = ''
    $script:RootDomainDn = $script:DomainDn
}

function ConvertTo-FixtureJson($Value) {
    ConvertTo-Json -Depth 28 -Compress -InputObject $Value
}

function ConvertTo-FixtureSnapshotComparisonJson($Snapshot) {
    $observation = $Snapshot.PSObject.Properties['UsersObservation']
    if ($null -eq $observation) {
        return ConvertTo-FixtureJson $Snapshot
    }

    $snapshotFields = [ordered]@{}
    foreach ($property in $Snapshot.PSObject.Properties) {
        $snapshotFields[$property.Name] = $property.Value
    }

    $observationFields = [ordered]@{}
    foreach ($property in $observation.Value.PSObject.Properties) {
        if ($property.Name -ceq 'ObservedAt') {
            $observationFields[$property.Name] = '<validated volatile time>'
        }
        else {
            $observationFields[$property.Name] = $property.Value
        }
    }

    $snapshotFields['UsersObservation'] = [pscustomobject]$observationFields
    ConvertTo-FixtureJson ([pscustomobject]$snapshotFields)
}

function Assert-FixtureUsersObservation(
    $Snapshot,
    [string]$Transport,
    [string]$Status,
    [string]$Scenario
) {
    $property = $Snapshot.PSObject.Properties['UsersObservation']

    Assert-DirectoryCollector ($null -ne $property -and $null -ne $property.Value) 'Missing UsersObservation record.'
    $record = $property.Value
    $names = @($record.PSObject.Properties | ForEach-Object Name)
    Assert-DirectoryCollector (
        ($names | Sort-Object) -join '|' -ceq 'Mode|ObservedAt|RequestedSearchBase|SearchBase|Server|Status|Version'
    ) 'Unexpected UsersObservation fields.'
    Assert-DirectoryCollector (
        $record.Version -is [int] -and $record.Version -eq 1 -and
        $record.RequestedSearchBase -is [string] -and $record.RequestedSearchBase -ceq $script:SearchBase -and
        $record.SearchBase -is [string] -and $record.SearchBase -ceq $script:SearchBase -and
        $record.Mode -ceq $Transport -and $record.Status -ceq $Status
    ) 'UsersObservation lost its version, scope, bound controller, mode, or outcome.'
    if ($Scenario -in 'ControllerArray', 'ControllerUnreadable') {
        Assert-DirectoryCollector ($null -eq $record.Server) 'An unsupported RootDSE hostname was treated as a controller witness.'
    }
    else {
        Assert-DirectoryCollector (
            $record.Server -is [string] -and $record.Server -ceq $script:SelectedServer
        ) 'UsersObservation lost its verified controller witness.'
    }

    if ($Status -ceq 'Unobserved') {
        Assert-DirectoryCollector ($null -eq $record.ObservedAt) 'An unattempted Users query has an observation time.'
        return
    }
    if ($Status -ceq 'Unreadable' -and $null -eq $record.ObservedAt) {
        return
    }

    $instant = [datetimeoffset]::MinValue
    if ($record.ObservedAt -is [datetimeoffset]) {
        $instant = $record.ObservedAt
    }
    else {
        Assert-DirectoryCollector (
            $record.ObservedAt -is [string] -and
            $record.ObservedAt -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}(?:Z|\+00:00)$' -and
            [datetimeoffset]::TryParse(
                $record.ObservedAt,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None,
                [ref]$instant
            )
        ) 'UsersObservation did not contain an invariant UTC timestamp.'
    }
    Assert-DirectoryCollector (
        $instant.Offset -eq [timespan]::Zero -and
        $null -ne $script:UsersQueryStart -and $null -ne $script:UsersNextQuery -and
        $instant -ge $script:UsersQueryStart -and $instant -le $script:UsersNextQuery
    ) 'UsersObservation time was not recorded at the Users query boundary.'
}

function Assert-FixtureUsersResult($Snapshot, [string]$Transport, [string]$Scenario) {
    $requests = @($script:Trace | Where-Object Step -ceq 'Get-ADUser')
    $expectedLegacyStatus = 'Collected'
    $status = 'Completed'
    $expectedCount = 2
    switch ($Scenario) {
        'Empty' { $expectedCount = 0 }
        'Denied' {
            $expectedLegacyStatus = 'Unreadable'
            $status = 'Unreadable'
            $expectedCount = 0
        }
        'Partial' {
            $expectedLegacyStatus = 'Unreadable'
            $status = 'Unreadable'
            $expectedCount = 0
        }
        'DriveEntry' {
            $expectedLegacyStatus = 'Unreadable'
            $status = 'Unobserved'
            $expectedCount = 0
        }
    }

    Assert-DirectoryCollector (
        $Snapshot.Coverage.Users -ceq $expectedLegacyStatus -and
        $Snapshot.Users -is [array] -and $Snapshot.Users.Count -eq $expectedCount
    ) 'Users collection lost its existing scope or completion result.'
    if ($expectedCount -eq 2) {
        Assert-DirectoryCollector (
            $Snapshot.Users[0].Enabled -is [bool] -and $Snapshot.Users[0].Enabled -eq $true -and
            $Snapshot.Users[0].PasswordNeverExpires -is [bool] -and $Snapshot.Users[0].PasswordNeverExpires -eq $true -and
            $Snapshot.Users[1].Enabled -is [bool] -and $Snapshot.Users[1].Enabled -eq $true -and
            $Snapshot.Users[1].PasswordNeverExpires -is [bool] -and $Snapshot.Users[1].PasswordNeverExpires -eq $false -and
            [guid]$Snapshot.Users[0].ObjectGuid -eq $script:UsersGuids[0] -and
            [guid]$Snapshot.Users[1].ObjectGuid -eq $script:UsersGuids[1] -and
            $Snapshot.Users[0].DistinguishedName -ceq ('CN=Cached,' + $script:SearchBase) -and
            $Snapshot.Users[1].DistinguishedName -ceq ('CN=Fallback,' + $script:SearchBase)
        ) 'Users projection changed account identity or its observed Boolean flags.'
    }

    if ($Scenario -ceq 'DriveEntry') {
        Assert-DirectoryCollector (
            $requests.Count -eq 0 -and $null -eq $script:UsersQueryStart -and
            $Snapshot.DirectoryConnection.Status -ceq 'Unreadable'
        ) 'The skipped Users query actually entered the provider.'
    }
    else {
        $owned = $Transport -ceq 'PSDrive'
        Assert-DirectoryCollector (
            $requests.Count -eq 1 -and [bool]$requests[0].Owned -eq $owned -and
            $requests[0].Base -ceq $script:SearchBase -and $requests[0].Filter -ceq '*' -and
            $requests[0].Server -ceq $script:SelectedServer -and
            $requests[0].SameCredential -and [bool]$requests[0].CredentialBound -ne $owned -and
            $requests[0].ErrorAction -ceq 'Stop' -and
            'Enabled' -in $requests[0].Properties.Split(',') -and
            'PasswordNeverExpires' -in $requests[0].Properties.Split(',')
        ) 'The scoped Users query changed request arguments, ownership, credential, or cardinality.'
    }

    $usersErrors = @($Snapshot.Errors | Where-Object Collector -ceq 'Users')
    if ($Scenario -in 'Denied', 'Partial') {
        Assert-DirectoryCollector (
            $usersErrors.Count -eq 1 -and $usersErrors[0].Target -ceq $script:SelectedServer -and
            $usersErrors[0].Status -ceq 'Unreadable' -and
            $usersErrors[0].Message -ceq ('Fixture Users query ' + $Scenario)
        ) 'An unreadable Users query lost its original scoped error.'
    }
    if ($Scenario -ceq 'Unrelated') {
        Assert-DirectoryCollector (
            $usersErrors.Count -eq 0 -and $Snapshot.Coverage.Trusts -ceq 'Unreadable' -and
            @($Snapshot.Errors | Where-Object Collector -ceq 'Trusts').Count -eq 1
        ) 'The unrelated failure changed Users completion or lost its original diagnostic.'
    }

    Assert-FixtureUsersObservation $Snapshot $Transport $status $Scenario
}

function Set-FixtureUsersScenario([string]$Scenario) {
    Clear-FixtureObservations
    $script:UsersScenario = $Scenario
    $script:UsersQueryStart = $null
    $script:UsersNextQuery = $null
    if ($Scenario -ceq 'DriveEntry') {
        $script:Fault = 'Enter'
    }
    elseif ($Scenario -ceq 'Unrelated') {
        $script:Fault = 'Denied'
    }
}

function Invoke-FixtureUsersCoverage($Collector) {
    $legacy = (Get-Command Get-ADAnalyzerDirectoryData -CommandType Function).ScriptBlock
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($transport in 'PSDrive', 'Direct') {
        $scenarios = @('Completed', 'Empty', 'Denied', 'Partial', 'Unrelated', 'ControllerArray', 'ControllerUnreadable')
        if ($transport -ceq 'PSDrive') {
            $scenarios += 'DriveEntry'
        }

        foreach ($scenario in $scenarios) {
            try {
                Test-DirectoryCollector ($transport + ' Users ' + $scenario) {
                    Set-FixtureUsersScenario $scenario
                    $context = New-FixtureContext
                    $profile = New-FixtureProfile $transport
                    $native = Invoke-FixtureNative $context $profile
                    Assert-DirectoryCollector (
                        $native.Rows.Count -eq 1 -and $native.Restored -and $null -eq $native.Failure -and
                        $script:Imports.Count -eq 0
                    ) 'Native did not finish its scoped Users request.'
                    $nativeTrace = ConvertTo-FixtureJson ($script:Trace.ToArray())
                    if ($scenario -in 'Denied', 'Partial') {
                        $expectedId = if ($scenario -ceq 'Denied') {
                            'Fixture.UsersDenied*'
                        }
                        else {
                            'Fixture.UsersPartial*'
                        }
                        Assert-DirectoryCollector (
                            @(Get-FixtureCapturedError $native.Errors | Where-Object Id -like $expectedId).Count -gt 0
                        ) 'Native lost its original Users error ID.'
                    }

                    if ($transport -ceq 'PSDrive') {
                        Assert-DirectoryCollector ($script:Trace[-1].Step -ceq 'Remove') 'Native failed to remove its owned fixture drive.'
                    }
                    else {
                        Assert-DirectoryCollector (@($script:Trace | Where-Object Step -in 'Create', 'Remove').Count -eq 0) 'Native Direct mounted a drive.'
                    }

                    Set-Item -LiteralPath Function:script:Get-ADAnalyzerDirectoryData -Value {
                        throw 'Direct Users coverage called the compatibility command.'
                    }
                    try {
                        # Preserve the independently witnessed native clock before switching stubs.
                        $nativeStart = $script:UsersQueryStart
                        $nativeNext = $script:UsersNextQuery
                        Set-FixtureUsersScenario $scenario
                        $direct = @(Invoke-FixtureDirect $Collector $context $profile 3>$null)
                        Assert-DirectoryCollector (
                            $direct.Count -eq 1 -and $script:Imports.Count -eq 1 -and $script:Ambient.Count -eq 0
                        ) 'The direct method did not use the selected bundled capabilities.'
                        Assert-DirectoryCollector (
                            (ConvertTo-FixtureJson ($script:Trace.ToArray())) -ceq $nativeTrace
                        ) 'The direct method changed provider arguments, order, or drive lifetime.'

                        $directStart = $script:UsersQueryStart
                        $directNext = $script:UsersNextQuery
                        Assert-FixtureUsersResult $direct[0] $transport $scenario
                        $script:UsersQueryStart = $nativeStart
                        $script:UsersNextQuery = $nativeNext
                        Assert-FixtureUsersResult $native.Rows[0] $transport $scenario
                        $script:UsersQueryStart = $directStart
                        $script:UsersNextQuery = $directNext

                        Assert-DirectoryCollector (
                            (ConvertTo-FixtureSnapshotComparisonJson $direct[0]) -ceq
                            (ConvertTo-FixtureSnapshotComparisonJson $native.Rows[0])
                        ) 'Normalized native and direct snapshots differ.'
                    }
                    finally {
                        Set-Item -LiteralPath Function:script:Get-ADAnalyzerDirectoryData -Value $legacy
                    }
                }
            }
            catch {
                $failures.Add($_.Exception.GetBaseException().Message)
                Write-Host ('FAIL UsersCoverage {0}/{1} {2}' -f $transport, $scenario, $failures[$failures.Count - 1])
            }
        }
    }
    if ($failures.Count) {
        throw ('UsersCoverage failed {0} of 15 scenario pairs.' -f $failures.Count)
    }
}

function ConvertTo-FixtureError($Diagnostic) {
    if ($null -eq $Diagnostic) {
        return [pscustomobject][ordered]@{
            Type = $null
            Id = $null
        }
    }
    $type = $Diagnostic.GetType().FullName
    if ($Diagnostic -is [Collections.IList]) {
        return [pscustomobject][ordered]@{
            Type = $type
            Id = $null
            Entries = @(
                foreach ($entry in $Diagnostic) {
                    ConvertTo-FixtureError $entry
                }
            )
        }
    }
    $record = if ($Diagnostic -is [Management.Automation.IContainsErrorRecord]) {
        $Diagnostic.ErrorRecord
    }
    else {
        $Diagnostic
    }
    if ($record -is [Management.Automation.ErrorRecord]) {
        $exception = $record.Exception
        $details = [ordered]@{
            Type = $type
            Id = $record.FullyQualifiedErrorId
            Category = [string]$record.CategoryInfo.Category
            Message = $null
            ExceptionType = $null
            Restore = $null
            Remove = $null
        }
        if ($null -ne $exception) {
            $details.Message = $exception.Message
            $details.ExceptionType = $exception.GetType().FullName
            $details.Restore = $exception.Data['ADAnalyzerLocationRestorationError']
            $details.Remove = $exception.Data['ADAnalyzerDriveRemovalError']
        }
        return [pscustomobject]$details
    }
    if ($Diagnostic -is [Exception]) {
        return [pscustomobject][ordered]@{
            Type = $type
            Id = $null
            Message = $Diagnostic.Message
        }
    }
    return [pscustomobject][ordered]@{
        Type = $type
        Id = $null
    }
}

function Get-FixtureCapturedError([object[]]$Diagnostics) {
    foreach ($diagnostic in $Diagnostics) {
        if ($diagnostic.Id) {
            $diagnostic
        }
        if ($null -ne $diagnostic.PSObject.Properties['Entries']) {
            Get-FixtureCapturedError $diagnostic.Entries
        }
    }
}

function Invoke-FixtureNative($Context, [hashtable]$Profile) {
    $caller = (Microsoft.PowerShell.Management\Get-Location).Path
    $stream = [Collections.Generic.List[object]]::new()
    $failure = $null
    $errors = @()
    $warnings = @()
    try {
        Get-ADAnalyzerDirectoryData -Context $Context -Profile $Profile -ErrorVariable +errors -WarningVariable +warnings 3>&1 |
            ForEach-Object { $stream.Add($_) }
    }
    catch {
        $failure = ConvertTo-FixtureError $_
    }
    finally {
        $restored = (Microsoft.PowerShell.Management\Get-Location).Path -ceq $caller
        if (-not $restored) {
            Microsoft.PowerShell.Management\Set-Location -LiteralPath $caller
        }
        foreach ($driveName in @($script:Drives.Keys)) {
            Microsoft.PowerShell.Management\Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            $script:Drives.Remove($driveName)
        }
    }
    [pscustomobject][ordered]@{
        Rows = @($stream | Where-Object { $_ -isnot [Management.Automation.WarningRecord] })
        WarningStream = @($stream | Where-Object { $_ -is [Management.Automation.WarningRecord] } | ForEach-Object Message)
        Warnings = @($warnings | ForEach-Object Message)
        Errors = @(
            foreach ($diagnostic in $errors) {
                ConvertTo-FixtureError $diagnostic
            }
        )
        Failure = $failure
        Restored = $restored
    }
}

function Assert-FixtureSuccess($Snapshot, [string]$Status) {
    Assert-DirectoryCollector ($Snapshot.DirectoryConnection.Status -ceq $Status -and
        $Snapshot.Domain.OptionalFeatures.Count -eq 1 -and
        $Snapshot.Users.Count -eq 2 -and $Snapshot.Groups.Count -eq 1 -and
        $Snapshot.Coverage.AclOUs -ceq 'Collected' -and $Snapshot.Acl.Entries.Count -eq 3 -and
        $Snapshot.PasswordPolicies.Resultant[0].Policy.MinPasswordLength -eq 16 -and
        $Snapshot.PasswordPolicies.Resultant[1].Policy.MinPasswordLength -eq 18) 'Snapshot lost directory data, ACL evidence or resultant policies.'
}

if ($Case -eq 'Native') {
    foreach ($scenario in 'Drive', 'Direct', 'Denied', 'Enter', 'Competing', 'Invalid') {
        Test-DirectoryCollector $scenario {
            Clear-FixtureObservations
            $context = New-FixtureContext
            $transport = if ($scenario -in 'Direct', 'Denied', 'Invalid') {
                'Direct'
            }
            else {
                'PSDrive'
            }
            $profile = New-FixtureProfile $transport
            $script:Fault = $scenario
            if ($scenario -eq 'Invalid') {
                $context.Server = ''
                $context.Domain = ''
            }
            $actual = Invoke-FixtureNative $context $profile
            switch ($scenario) {
                'Drive' {
                    Assert-FixtureSuccess $actual.Rows[0] 'Connected'
                    Assert-DirectoryCollector ($actual.Restored -and $actual.Failure -eq $null -and
                        $script:Trace[2].Step -ceq 'Create' -and $script:Trace[-1].Step -ceq 'Remove') 'Native drive was not mounted and cleaned in the established order.'
                }
                'Direct' {
                    Assert-FixtureSuccess $actual.Rows[0] 'Direct'
                    Assert-DirectoryCollector ($actual.Restored -and $actual.Failure -eq $null -and
                        $script:Trace[2].Step -ceq 'Get-ADForest') 'Native Direct entered the provider drive.'
                }
                'Denied' {
                    $denied = @(Get-FixtureCapturedError $actual.Errors | Where-Object {
                            $_.Id -like 'Fixture.DirectoryDenied*' -and
                            $_.Message -ceq 'Fixture directory query denied.'
                        })
                    Assert-DirectoryCollector ($actual.Rows.Count -eq 1 -and $actual.Rows[0].Coverage.Trusts -ceq 'Unreadable' -and
                        $actual.Rows[0].Errors[0].Collector -ceq 'Trusts' -and $actual.WarningStream.Count -eq 1 -and
                        $denied.Count -gt 0) 'Native query failure or warning behavior changed.'
                }
                'Enter' {
                    Assert-DirectoryCollector ($actual.Rows.Count -eq 1 -and
                        $actual.Rows[0].DirectoryConnection.Status -ceq 'Unreadable' -and $actual.Restored -and
                        $script:Ambient.Count -eq 2 -and $script:Trace[-1].Step -ceq 'Remove') 'Failed native drive entry skipped cleanup or fell back to bulk queries.'
                }
                'Competing' {
                    $primary = @(Get-FixtureCapturedError $actual.Errors | Where-Object {
                            $_.Id -like 'InvalidCastFromStringToInteger*' -and
                            $_.Message -like '*fixture invalid account flag*'
                        })
                    Assert-DirectoryCollector ($actual.Rows.Count -eq 0 -and
                        $actual.Failure.Message -like '*fixture invalid account flag*' -and
                        $actual.Failure.Restore -ceq 'Fixture directory location restoration failure.' -and
                        $actual.Failure.Remove -ceq 'Fixture directory drive removal failure.' -and
                        $primary.Count -gt 0) 'Native primary/cleanup error evidence changed.'
                }
                'Invalid' {
                    Assert-DirectoryCollector ($actual.Rows.Count -eq 0 -and $script:Trace.Count -eq 0 -and
                        $actual.Failure.Message -ceq 'Context.Server or Context.Domain is required') 'Native validation no longer precedes integration.'
                }
            }
            Assert-DirectoryCollector ($script:Imports.Count -eq 0) 'Native compatibility imported a separate provider.'
            $observation = [ordered]@{
                Scenario = $scenario
                Result = $actual
                Trace = $script:Trace.ToArray()
                Ambient = $script:Ambient.ToArray()
            }
            Write-Output ('DIRECTORY NATIVE OBSERVATION ' + (ConvertTo-FixtureJson $observation))
        }
    }
    Write-Host ('PASS directory collector {0} {1}' -f $Case, $script:Checks)
    return
}

function Invoke-FixtureDirect($Collector, $Context, [hashtable]$Profile) {
    $caller = (Microsoft.PowerShell.Management\Get-Location).Path
    $script:UseAmbient = $false
    $script:ImportAllowed = $true
    try {
        $Collector.Collect($Context, $Profile)
        Assert-DirectoryCollector ((Microsoft.PowerShell.Management\Get-Location).Path -ceq $caller -and
            $script:Drives.Count -eq 0) 'Direct collection returned before restoring location and cleaning its owned drive.'
    }
    finally {
        if ((Microsoft.PowerShell.Management\Get-Location).Path -cne $caller) {
            Microsoft.PowerShell.Management\Set-Location -LiteralPath $caller
        }
        foreach ($driveName in @($script:Drives.Keys)) {
            Microsoft.PowerShell.Management\Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            $script:Drives.Remove($driveName)
        }
        $script:UseAmbient = $true
        $script:ImportAllowed = $false
    }
}

function Assert-FixtureDirectTrace([string]$Server, [bool]$Drive, [bool]$Credential = $true) {
    $queries = @($script:Trace | Where-Object Step -like 'Get-AD*')
    Assert-DirectoryCollector ($script:Imports.Count -eq 1 -and $script:Ambient.Count -eq 0 -and
        @($queries | Where-Object { $_.Server -cne $Server -or $_.SameCredential -ne $Credential -or
                $_.ErrorAction -cne 'Stop' }).Count -eq 0) 'The collector used ambient commands, changed targeting or lost credential identity.'
    Assert-DirectoryCollector ($queries[0].Step -ceq 'Get-ADRootDSE' -and $queries[1].Step -ceq 'Get-ADDomain' -and
        @($queries | Where-Object { ($_.Owned -eq $_.CredentialBound -and $Credential) -or
                ($_.CredentialBound -and -not $Credential) }).Count -eq 0) 'Per-call credential omission or bootstrap ordering changed.'
    if ($Drive) {
        Assert-DirectoryCollector ($script:Trace[2].Step -ceq 'Create' -and
            $script:Trace[2].Server -ceq $Server -and $script:Trace[2].SameCredential -eq $Credential -and
            $script:Trace[3].Step -ceq 'Enter' -and $script:Trace[-2].Step -ceq 'Restore' -and
            $script:Trace[-1].Step -ceq 'Remove' -and -not $queries[0].Owned -and -not $queries[1].Owned -and
            @($queries | Select-Object -Skip 2 | Where-Object { -not $_.Owned }).Count -eq 0) 'Direct API bulk requests escaped the owned local PSDrive.'
    }
    else {
        Assert-DirectoryCollector ($queries.Count -eq $script:Trace.Count -and
            @($queries | Where-Object Owned).Count -eq 0) 'Explicit Direct used a provider drive.'
    }

    $used = @($queries | Select-Object -ExpandProperty Step -Unique)
    $user = $queries | Where-Object Step -ceq 'Get-ADUser'
    $group = $queries | Where-Object Step -ceq 'Get-ADGroup'
    $resultant = @($queries | Where-Object Step -ceq 'Get-ADUserResultantPasswordPolicy')
    Assert-DirectoryCollector ($used.Count -eq $script:Commands.Count -and
        @($script:Commands | Where-Object { $_ -cnotin $used }).Count -eq 0 -and
        $user.Base -ceq $script:SearchBase -and $group.Base -ceq $script:DomainDn -and
        $resultant.Count -eq 1 -and $resultant[0].Identity -like 'CN=Fallback,*') 'Exact bundled call inventory, account scope or cached policy fallback changed.'
    Assert-DirectoryCollector (@($queries | Where-Object {
        $_.Properties -match '(^|,)(msLAPS-Password|msLAPS-EncryptedPassword|ms-Mcs-AdmPwd|msDS-ManagedPassword)(,|$)'
    }).Count -eq 0) 'Directory collection requested a managed-password value.'
}

function Assert-FixtureAclCoverage($Snapshot, [string]$Scenario) {
    $expectedOuStatus = 'Collected'
    $expectedAggregate = 'Collected'
    $expectedCount = 0
    if ($Scenario -ceq 'Denied') {
        $expectedOuStatus = 'Unreadable'
        $expectedAggregate = 'Partial'
        $expectedCount = 1
    }
    $ouErrors = @($Snapshot.Errors | Where-Object Collector -CEQ 'AclOUs')
    Assert-DirectoryCollector ($Snapshot.Coverage.AclOUs -ceq $expectedOuStatus -and
        $ouErrors.Count -eq $expectedCount) 'The scoped OU observation or its diagnostic changed.'
    if ($Scenario -ceq 'Denied') {
        Assert-DirectoryCollector ($ouErrors[0].Target -ceq $script:SelectedServer -and
            $ouErrors[0].Status -ceq 'Unreadable' -and
            $ouErrors[0].Message -ceq 'Fixture OU ACL discovery denied.') 'Missing or altered OU denial diagnostic.'
    }

    $expectedTargets = @($script:DomainDn, ('CN=AdminSDHolder,CN=System,' + $script:DomainDn))
    if ($Scenario -ceq 'Observed') {
        $expectedTargets += $script:SearchBase
    }
    Assert-DirectoryCollector (($Snapshot.Acl.Targets.Target -join '|') -ceq ($expectedTargets -join '|') -and
        @($Snapshot.Acl.Targets | Where-Object Status -CNE 'Collected').Count -eq 0 -and
        ($Snapshot.Acl.Entries.Target -join '|') -ceq ($expectedTargets -join '|') -and
        -not $Snapshot.Acl.EffectiveAccessCalculated) 'Successful ACL descriptors, ACEs or evidence limits changed.'

    $assessment = Invoke-ADAnalyzerAssessment -DirectoryData $Snapshot
    $report = [ADAnalyzerAssessmentReport]::new().Render($assessment, 'Json') | ConvertFrom-Json
    foreach ($result in $assessment, $report) {
        $findings = @($result.Findings | Where-Object RuleId -CEQ 'ACL.DELEGATED_CONTROL')
        Assert-DirectoryCollector ($findings.Count -eq 1 -and $findings[0].Status -ceq 'Fail' -and
            $findings[0].Observed.Target -ceq $expectedTargets[1]) 'A positively observed ACL finding was lost.'
    }

    $coverage = @($assessment.Checks | Where-Object RuleId -CEQ 'COLLECTION.ACL')
    $reportCoverage = @($report.Checks | Where-Object RuleId -CEQ 'COLLECTION.ACL')
    Assert-DirectoryCollector (
        $Snapshot.Coverage.Acl -ceq $expectedAggregate -and
        $report.Data.Directory.Coverage.Acl -ceq $expectedAggregate -and
        $coverage.Count -eq $expectedCount -and $reportCoverage.Count -eq $expectedCount
    ) ('Expected ACL={0} and {1} coverage checks, observed ACL={2}/{3} and {4}/{5} checks (memory/report).' -f
        $expectedAggregate, $expectedCount, $Snapshot.Coverage.Acl, $report.Data.Directory.Coverage.Acl,
        $coverage.Count, $reportCoverage.Count)
    foreach ($check in ($coverage + $reportCoverage)) {
        Assert-DirectoryCollector ($check.Status -ceq 'Unknown' -and $check.Observed -ceq 'Partial' -and
            $check.Expected -ceq 'Collected') 'Incomplete coverage was not visible in the assessment.'
    }
}

function Invoke-FixtureAclCoverage($Collector) {
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($transport in 'PSDrive', 'Direct') {
        foreach ($scenario in 'Denied', 'Empty', 'Observed') {
            $previousFailures = $failures.Count
            foreach ($route in 'Native', 'Class') {
                Clear-FixtureObservations
                $script:Fault = 'Acl' + $scenario
                $context = New-FixtureContext
                $profile = New-FixtureProfile $transport
                $caseName = '{0}/{1}/{2}' -f $transport, $route, $scenario
                try {
                    if ($route -ceq 'Native') {
                        $native = Invoke-FixtureNative $context $profile
                        Assert-DirectoryCollector ($native.Rows.Count -eq 1 -and $native.Restored -and
                            $null -eq $native.Failure -and $script:Imports.Count -eq 0) 'Native collection did not complete.'
                        if ($scenario -ceq 'Denied') {
                            $diagnostics = @(Get-FixtureCapturedError $native.Errors |
                                Where-Object Id -like 'Fixture.AclOuDenied*')
                            Assert-DirectoryCollector ($diagnostics.Count -gt 0) 'Native collection lost its original OU error ID.'
                        }
                        $snapshot = $native.Rows[0]
                    }
                    else {
                        $direct = @(Invoke-FixtureDirect $Collector $context $profile)
                        Assert-DirectoryCollector ($direct.Count -eq 1) 'The class did not produce one snapshot.'
                        Assert-FixtureDirectTrace $script:SelectedServer ($transport -ceq 'PSDrive')
                        $snapshot = $direct[0]
                    }
                    $lookup = @($script:Trace | Where-Object Step -CEQ 'Get-ADOrganizationalUnit')
                    Assert-DirectoryCollector ($lookup.Count -eq 1 -and $lookup[0].Base -ceq $script:SearchBase -and
                        $lookup[0].Server -ceq $script:SelectedServer -and $lookup[0].SameCredential -and
                        $lookup[0].Owned -eq ($transport -ceq 'PSDrive')) 'Scoped OU lookup binding changed.'
                    if ($transport -ceq 'PSDrive') {
                        Assert-DirectoryCollector ($script:Trace[-2].Step -ceq 'Restore' -and
                            $script:Trace[-1].Step -ceq 'Remove') 'The owned drive was not cleaned up.'
                    }
                    else {
                        Assert-DirectoryCollector (@($script:Trace | Where-Object Step -in 'Create', 'Remove').Count -eq 0) `
                            'Explicit Direct mounted a drive.'
                    }
                    Assert-FixtureAclCoverage $snapshot $scenario
                    Write-Host ('PASS AclCoverage {0}' -f $caseName)
                }
                catch {
                    $failures.Add($_.Exception.Message)
                    Write-Host ('FAIL AclCoverage {0} {1}' -f $caseName, $_.Exception.Message)
                }
            }
            if ($failures.Count -eq $previousFailures) {
                $script:Checks++
            }
        }
    }
    if ($failures.Count) {
        throw ('AclCoverage failed {0} of 12 route checks.' -f $failures.Count)
    }
}

function Assert-FixtureResultantPolicyCoverage($Snapshot, [string]$Scenario) {
    $cachedTarget = 'CN=Cached,' + $script:SearchBase
    $fallbackTarget = 'CN=Fallback,' + $script:SearchBase
    $cachedKey = 'ResultantPasswordPolicy:' + $cachedTarget
    $fallbackKey = 'ResultantPasswordPolicy:' + $fallbackTarget
    $resultant = $Snapshot.PasswordPolicies.Resultant
    Assert-DirectoryCollector (
        ($Snapshot.Users.DistinguishedName -join '|') -ceq ($cachedTarget + '|' + $fallbackTarget) -and
        $resultant.Count -eq 2 -and $resultant[0].Target -ceq $cachedTarget -and $resultant[1].Target -ceq $fallbackTarget -and
        $Snapshot.Coverage.Users -ceq 'Collected' -and $Snapshot.Groups.Count -eq 1
    ) 'The snapshot lost the users, their ordered policy records, or sibling group data.'

    $cached = $resultant[0]
    $fallback = $resultant[1]
    Assert-DirectoryCollector (
        $Snapshot.Coverage.FineGrainedPasswordPolicies -ceq 'Collected' -and
        $Snapshot.PasswordPolicies.FineGrained.Count -eq 1 -and
        $Snapshot.Coverage[$cachedKey] -ceq 'Collected' -and $cached.Status -ceq 'Collected' -and
        $cached.Source -ceq 'FineGrained' -and $cached.Policy.DistinguishedName -ceq $script:PsoDn -and
        $cached.Policy.MinPasswordLength -eq 16 -and $fallback.Source -ceq 'DefaultDomain'
    ) 'The positive cached policy or fallback source label changed.'

    $failures = @($Snapshot.Errors | Where-Object {
            $_.Collector -ceq 'DefaultPasswordPolicy' -or $_.Collector -ceq $fallbackKey -or $_.Collector -ceq $cachedKey
        })
    if ($Scenario -ceq 'Denied') {
        Assert-DirectoryCollector (
            $failures.Count -eq 1 -and $failures[0].Collector -ceq 'DefaultPasswordPolicy' -and
            $failures[0].Target -ceq $script:SelectedServer -and $failures[0].Status -ceq 'Unreadable' -and
            $failures[0].Message -ceq 'Fixture default domain password policy access denied.'
        ) 'The real synthetic provider denial was lost or duplicated.'
    }
    else {
        Assert-DirectoryCollector ($failures.Count -eq 0) 'A successful empty or present lookup acquired a provider error.'
    }

    $checks = @(Test-ADAnalyzerDirectoryPolicy -Data $Snapshot -Profile @{ Policy = @{ MinimumPasswordLength = 14 } })
    $lengthChecks = @($checks | Where-Object RuleId -CEQ 'PASSWORD.MIN_LENGTH')
    $policyCoverage = @($checks | Where-Object RuleId -CEQ 'COLLECTION.RESULTANTPASSWORDPOLICIES')
    $expectedFallbackCheck = if ($Scenario -ceq 'Present') { 'Fail' } else { 'Unknown' }
    Assert-DirectoryCollector (
        $lengthChecks.Count -eq 2 -and $lengthChecks[0].Target -ceq $cachedTarget -and
        $lengthChecks[0].Status -ceq 'Pass' -and $lengthChecks[0].Observed -eq 16 -and
        $lengthChecks[1].Target -ceq $fallbackTarget -and $lengthChecks[1].Status -ceq $expectedFallbackCheck
    ) 'The actual evaluator lost the affected users or their password length observations.'

    if ($Scenario -ceq 'Present') {
        Assert-DirectoryCollector (
            $Snapshot.Coverage.DefaultPasswordPolicy -ceq 'Collected' -and
            $Snapshot.Coverage[$fallbackKey] -ceq 'Collected' -and $fallback.Status -ceq 'Collected' -and
            $Snapshot.PasswordPolicies.Default.MinPasswordLength -eq 12 -and $fallback.Policy.MinPasswordLength -eq 12 -and
            $lengthChecks[1].Observed -eq 12 -and
            $Snapshot.Coverage.ResultantPasswordPolicies -ceq 'Collected' -and $policyCoverage.Count -eq 0
        ) 'An empty personal lookup lost its readable domain default.'
        return
    }

    Assert-DirectoryCollector ($null -eq $Snapshot.PasswordPolicies.Default -and $null -eq $fallback.Policy -and
        $null -eq $lengthChecks[1].Observed) 'Unavailable default evidence was replaced with policy values.'
    Assert-DirectoryCollector (
        $Snapshot.Coverage.DefaultPasswordPolicy -ceq 'Unreadable' -and
        $Snapshot.Coverage[$fallbackKey] -ceq 'Unreadable' -and $fallback.Status -ceq 'Unreadable' -and
        $Snapshot.Coverage.ResultantPasswordPolicies -ceq 'Partial' -and $policyCoverage.Count -eq 1
    ) ('Missing default policy must report Unreadable/Unreadable/Unreadable/Partial and one coverage check. Actual={0}/{1}/{2}/{3}, checks={4}.' -f
        $Snapshot.Coverage.DefaultPasswordPolicy, $Snapshot.Coverage[$fallbackKey], $fallback.Status,
        $Snapshot.Coverage.ResultantPasswordPolicies, $policyCoverage.Count)
    Assert-DirectoryCollector ($policyCoverage[0].Status -ceq 'Unknown' -and $policyCoverage[0].Observed -ceq 'Partial' -and
        $policyCoverage[0].Expected -ceq 'Collected') 'Incomplete resultant coverage was not visible in the actual evaluator.'
}

function Invoke-FixtureResultantPolicyCoverage($Collector) {
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($transport in 'PSDrive', 'Direct') {
        foreach ($scenario in 'Present', 'Empty', 'Denied') {
            $previousFailures = $failures.Count
            foreach ($route in 'Native', 'Class') {
                Clear-FixtureObservations
                $script:Fault = 'PasswordDefault' + $scenario
                $context = New-FixtureContext
                $profile = New-FixtureProfile $transport
                $caseName = '{0}/{1}/{2}' -f $transport, $route, $scenario
                try {
                    if ($route -ceq 'Native') {
                        $native = Invoke-FixtureNative $context $profile
                        Assert-DirectoryCollector ($native.Rows.Count -eq 1 -and $native.Restored -and
                            $null -eq $native.Failure -and $script:Imports.Count -eq 0) 'Native collection did not complete.'
                        if ($scenario -ceq 'Denied') {
                            $diagnostics = @(Get-FixtureCapturedError $native.Errors |
                                Where-Object Id -like 'Fixture.DefaultPolicyDenied*')
                            Assert-DirectoryCollector ($diagnostics.Count -gt 0) 'Native collection lost its original provider error ID.'
                        }
                        $snapshot = $native.Rows[0]
                    }
                    else {
                        $direct = @(Invoke-FixtureDirect $Collector $context $profile)
                        Assert-DirectoryCollector ($direct.Count -eq 1) 'The class did not complete with one snapshot.'
                        Assert-FixtureDirectTrace $script:SelectedServer ($transport -ceq 'PSDrive')
                        $snapshot = $direct[0]
                    }
                    $lookups = @($script:Trace | Where-Object Step -in @(
                            'Get-ADDefaultDomainPasswordPolicy'
                            'Get-ADFineGrainedPasswordPolicy'
                            'Get-ADUserResultantPasswordPolicy'
                        ))
                    Assert-DirectoryCollector (
                        ($lookups.Step -join '|') -ceq 'Get-ADDefaultDomainPasswordPolicy|Get-ADFineGrainedPasswordPolicy|Get-ADUserResultantPasswordPolicy' -and
                        $lookups[0].Identity -ceq $script:DomainDn -and
                        $lookups[2].Identity -ceq ('CN=Fallback,' + $script:SearchBase) -and
                        @($lookups | Where-Object {
                                $_.Server -cne $script:SelectedServer -or -not $_.SameCredential -or
                                $_.Owned -ne ($transport -ceq 'PSDrive') -or $_.ErrorAction -cne 'Stop'
                            }).Count -eq 0
                    ) 'Password policy provider order, count, identity, transport or credential binding changed.'
                    Assert-FixtureResultantPolicyCoverage $snapshot $scenario
                    Write-Host ('PASS ResultantPolicyCoverage {0}' -f $caseName)
                }
                catch {
                    $failures.Add($_.Exception.Message)
                    Write-Host ('FAIL ResultantPolicyCoverage {0} {1}' -f $caseName, $_.Exception.Message)
                }
            }
            if ($failures.Count -eq $previousFailures) {
                $script:Checks++
            }
        }
    }
    if ($failures.Count) {
        throw ('ResultantPolicyCoverage failed {0} of 12 route checks.' -f $failures.Count)
    }
}

$collector = [ADAnalyzerDirectoryCollector]::new()
Assert-DirectoryCollector ($script:Imports.Count -eq 0 -and $script:Ambient.Count -eq 0 -and $script:Trace.Count -eq 0) `
    'Loading or construction performed integration calls.'

if ($Case -eq 'UsersCoverage') {
    Invoke-FixtureUsersCoverage $collector
}

if ($Case -eq 'AclCoverage') {
    Invoke-FixtureAclCoverage $collector
}

if ($Case -eq 'ResultantPolicyCoverage') {
    Invoke-FixtureResultantPolicyCoverage $collector
}

if ($Case -eq 'Construction') {
    Test-DirectoryCollector 'constructor is inert' {
        $fresh = [ADAnalyzerDirectoryCollector]::new()
        Assert-DirectoryCollector (-not [object]::ReferenceEquals($collector, $fresh) -and
            $script:Imports.Count -eq 0 -and $script:Trace.Count -eq 0) 'New collector instances caused integration effects.'
    }
    Test-DirectoryCollector 'reject connection mode before imports' {
        $profile = New-FixtureProfile Direct
        $profile.Analysis.DirectoryConnection = 'FixtureInvalid'
        $failure = $null
        try {
            $null = $collector.Collect((New-FixtureContext), $profile)
        }
        catch {
            $failure = $_
        }
        Assert-DirectoryCollector ($null -ne $failure -and $failure.Exception.Message -like '*DirectoryConnection*' -and
            $script:Imports.Count -eq 0 -and $script:Trace.Count -eq 0) 'Invalid transport reached directory integration.'
    }
    Test-DirectoryCollector 'reject missing target before imports' {
        $failure = $null
        try {
            $null = $collector.Collect(
                @{
                    Server = ''
                    Domain = ''
                },
                (New-FixtureProfile Direct)
            )
        }
        catch {
            $failure = $_
        }
        Assert-DirectoryCollector ($null -ne $failure -and $failure.Exception.Message -like '*Context.Server or Context.Domain*' -and
            $script:Imports.Count -eq 0 -and $script:Trace.Count -eq 0) 'Missing target reached directory integration.'
    }
}

if ($Case -eq 'Direct') {
    $native = @{}
    foreach ($transport in 'PSDrive', 'Direct') {
        Clear-FixtureObservations
        $reference = Invoke-FixtureNative (New-FixtureContext) (New-FixtureProfile $transport)
        $native[$transport] = @{
            Snapshot = ConvertTo-FixtureSnapshotComparisonJson $reference.Rows[0]
            Queries = ConvertTo-FixtureJson ($script:Trace.ToArray())
        }
    }

    function Get-ADAnalyzerDirectoryData {
        throw 'Direct collector called the old directory command.'
    }

    foreach ($transport in 'PSDrive', 'Direct') {
        Test-DirectoryCollector ('match compatibility on ' + $transport) {
            Clear-FixtureObservations
            $status = if ($transport -ceq 'Direct') {
                'Direct'
            }
            else {
                'Connected'
            }
            $actual = @(Invoke-FixtureDirect $collector (New-FixtureContext) (New-FixtureProfile $transport))
            Assert-DirectoryCollector ($actual.Count -eq 1) 'Direct collection did not return exactly one snapshot.'
            Assert-FixtureSuccess $actual[0] $status
            Assert-FixtureDirectTrace $script:SelectedServer ($transport -ceq 'PSDrive')
            Assert-DirectoryCollector ((ConvertTo-FixtureSnapshotComparisonJson $actual[0]) -ceq $native[$transport].Snapshot -and
                (ConvertTo-FixtureJson ($script:Trace.ToArray())) -ceq $native[$transport].Queries) `
                'Direct collection changed normalized data, order or request observations.'
        }
    }

    Test-DirectoryCollector 'domain fallback and empty credential' {
        Clear-FixtureObservations
        $context = New-FixtureContext
        $context.Server = ''
        $context.Credential = [pscredential]::Empty
        $actual = Invoke-FixtureDirect $collector $context (New-FixtureProfile Direct)
        Assert-FixtureSuccess $actual 'Direct'
        Assert-FixtureDirectTrace $script:Domain $false $false
        Assert-DirectoryCollector ($actual.Server -ceq $script:Domain -and
            $script:Trace[1].Identity -ceq $script:Domain) 'Domain fallback changed server or bootstrap identity.'
    }

    Test-DirectoryCollector 'RootDSE supplies domain identity without changing chosen server' {
        Clear-FixtureObservations
        $context = New-FixtureContext
        $context.Domain = ''
        $actual = Invoke-FixtureDirect $collector $context (New-FixtureProfile Direct)
        Assert-FixtureSuccess $actual 'Direct'
        Assert-FixtureDirectTrace $script:SelectedServer $false
        Assert-DirectoryCollector ($actual.Server -ceq $script:SelectedServer -and
            $script:Trace[1].Identity -ceq $script:DomainDn) 'RootDSE did not supply only the missing domain identity.'
    }

    Test-DirectoryCollector 'failed drive entry is unreadable and never falls back' {
        Clear-FixtureObservations
        $script:Fault = 'Enter'
        $actual = Invoke-FixtureDirect $collector (New-FixtureContext) (New-FixtureProfile PSDrive)
        Assert-DirectoryCollector ($actual.DirectoryConnection.Status -ceq 'Unreadable' -and
            $actual.Errors[0].Collector -ceq 'DirectoryConnection' -and $actual.Coverage.Users -ceq 'Unreadable' -and
            $script:Trace.Count -eq 6 -and $script:Trace[-1].Step -ceq 'Remove' -and
            $script:Ambient.Count -eq 0) 'Direct method used another connection after drive entry failure.'
    }

    Test-DirectoryCollector 'query failure yields a detached incomplete snapshot' {
        Clear-FixtureObservations
        $script:Fault = 'Denied'
        $actual = Invoke-FixtureDirect $collector (New-FixtureContext) (New-FixtureProfile Direct) 3>$null
        Assert-FixtureSuccess $actual 'Direct'
        Assert-FixtureDirectTrace $script:SelectedServer $false
        Assert-DirectoryCollector ($actual.Coverage.Trusts -ceq 'Unreadable' -and
            $actual.Errors.Count -eq 1 -and $actual.Errors[0].Collector -ceq 'Trusts' -and
            $actual.Errors[0].Message -ceq 'Fixture directory query denied.') 'Provider query failure lost its scope or useful cause.'
    }

    foreach ($providerFault in 'Import', 'MissingExport') {
        Test-DirectoryCollector ('provider preflight ' + $providerFault) {
            Clear-FixtureObservations
            $script:Fault = $providerFault
            $failure = $null
            try {
                $null = Invoke-FixtureDirect $collector (New-FixtureContext) (New-FixtureProfile Direct)
            }
            catch {
                $failure = $_
            }
            $expectedMessage = if ($providerFault -ceq 'Import') {
                '*Fixture directory provider import failure*'
            }
            else {
                '*Get-ADOrganizationalUnit*'
            }
            Assert-DirectoryCollector ($null -ne $failure -and $failure.Exception.Message -like $expectedMessage -and
                $script:Imports.Count -eq 1 -and $script:Trace.Count -eq 0 -and $script:Ambient.Count -eq 0) `
                'Provider preflight did not fail with its useful cause before directory calls.'
        }
    }
}

if ($Case -eq 'Isolation') {
    Test-DirectoryCollector 'reused collector keeps operation state and caller inputs separate' {
        $context = New-FixtureContext
        $profile = New-FixtureProfile Direct
        $beforeContext = ConvertTo-FixtureJson $context
        $beforeProfile = ConvertTo-FixtureJson $profile
        $beforeAmbient = Get-Command Get-ADUser -CommandType Function
        $PSDefaultParameterValues = @{ '*Get-ADUser:FixtureDefault' = 'caller default' }

        Clear-FixtureObservations
        $first = Invoke-FixtureDirect $collector $context $profile
        $first.Users[0].Name = 'modified previous snapshot'
        $first.Coverage['Users'] = 'modified previous coverage'
        $first.PasswordPolicies.Resultant[0].Policy.MinPasswordLength = 99

        Clear-FixtureObservations
        $second = Invoke-FixtureDirect $collector $context $profile
        Assert-FixtureSuccess $second 'Direct'
        Assert-FixtureDirectTrace $script:SelectedServer $false
        $userQuery = $script:Trace | Where-Object Step -ceq 'Get-ADUser'
        Assert-DirectoryCollector ($second.Users[0].Name -ceq 'Cached' -and $second.Coverage.Users -ceq 'Collected' -and
            $userQuery.Default -ceq 'caller default' -and $PSDefaultParameterValues['*Get-ADUser:FixtureDefault'] -ceq 'caller default' -and
            (ConvertTo-FixtureJson $context) -ceq $beforeContext -and (ConvertTo-FixtureJson $profile) -ceq $beforeProfile -and
            [object]::ReferenceEquals($beforeAmbient.ScriptBlock, (Get-Command Get-ADUser -CommandType Function).ScriptBlock)) `
            'A prior snapshot, operation input, ambient lookup or caller default leaked across calls.'
        Assert-DirectoryCollector ((ConvertTo-FixtureJson $collector) -eq '{}' -and
            (ConvertTo-FixtureJson $second) -notmatch 'fixture\\\\collector|ExportedCmdlets|CommandInfo|SessionState') `
            'Directory serialization exposed provider or credential state.'
    }

    Test-DirectoryCollector 'same-source loading in a disposed secondary runspace' {
        $group = [pscustomobject]@{
            DistinguishedName = 'CN=Runspace Fixture,' + $script:DomainDn
            SID = 'S-1-5-21-1-2-3-6700'
            MemberOf = @()
        }
        $staticIndex = [ADAnalyzerMembershipGraph]::BuildIndex(@($group))
        Assert-DirectoryCollector ([object]::ReferenceEquals($staticIndex.ByDn[$group.DistinguishedName], $group) -and
            [object]::ReferenceEquals($staticIndex.BySid[$group.SID], $group)) 'Legacy index no longer keeps its borrowed group references.'

        $worker = [powershell]::Create()
        try {
            $source = @'
param($Fixture, $Root)
$ErrorActionPreference = 'Stop'
& $Fixture -Case Construction -RepositoryRoot $Root
'Secondary directory collector loaded'
'@
            $result = @($worker.AddScript($source).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
            Assert-DirectoryCollector ($result.Count -eq 1 -and [string]$result[0] -ceq 'Secondary directory collector loaded' -and
                $worker.Streams.Error.Count -eq 0) ('Same-source secondary runspace could not load the collector. ' +
                ($worker.Streams.Error -join [Environment]::NewLine))
        }
        finally {
            $worker.Dispose()
        }

        $context = New-FixtureContext
        $profile = New-FixtureProfile Direct
        Clear-FixtureObservations
        $reused = Invoke-FixtureDirect $collector $context $profile
        Assert-FixtureSuccess $reused 'Direct'
        Assert-FixtureDirectTrace $script:SelectedServer $false

        Clear-FixtureObservations
        $fresh = [ADAnalyzerDirectoryCollector]::new()
        $independent = Invoke-FixtureDirect $fresh $context $profile
        Assert-FixtureSuccess $independent 'Direct'
        Assert-FixtureDirectTrace $script:SelectedServer $false
        Assert-DirectoryCollector ((ConvertTo-FixtureSnapshotComparisonJson $reused) -ceq (ConvertTo-FixtureSnapshotComparisonJson $independent)) `
            'Secondary runspace disposal changed the existing or new collector result.'

        $index = New-ADAnalyzerMembershipIndex -Groups @($group)
        Assert-DirectoryCollector ([object]::ReferenceEquals($index.ByDn[$group.DistinguishedName], $group) -and
            [object]::ReferenceEquals($index.BySid[$group.SID], $group)) 'Secondary runspace disposal changed the compatibility index.'
    }
}

Write-Host ('PASS directory collector {0} {1}' -f $Case, $script:Checks)
