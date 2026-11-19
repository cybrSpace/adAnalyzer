[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Direct', 'Isolation')]
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
    [pscustomobject][ordered]@{
        Name = $Name
        SamAccountName = $Name
        DistinguishedName = ('CN={0},{1}' -f $Name, $script:SearchBase)
        ObjectClass = 'user'
        SID = 'S-1-5-21-1-2-3-' + $(if ($PsoDn) { '1001' } else { '1002' })
        PrimaryGroupID = 513
        MemberOf = @()
        UserAccountControl = $flag
        ProtectedFromAccidentalDeletion = $false
        'msDS-ResultantPSO' = $PsoDn
    }
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
    $effective = if ($owned) { $script:Drives[$driveName] } else { $Bound['Credential'] }
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

    switch ($Command) {
        'Get-ADRootDSE' {
            [pscustomobject][ordered]@{
                DnsHostName = ('returned.' + $script:Domain)
                DefaultNamingContext = $script:RootDomainDn
                SchemaNamingContext = 'CN=Schema,CN=Configuration,' + $script:DomainDn
                ConfigurationNamingContext = 'CN=Configuration,' + $script:DomainDn
            }
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
            New-FixturePolicy 'Default' 12
        }
        'Get-ADFineGrainedPasswordPolicy' {
            New-FixturePolicy 'Cached policy' 16
        }
        'Get-ADUserResultantPasswordPolicy' {
            New-FixturePolicy 'Explicit policy' 18
        }
        'Get-ADOptionalFeature' {
            [pscustomobject]@{ FeatureGUID = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a' }
        }
        'Get-ADOrganizationalUnit' {
            [pscustomobject]@{ DistinguishedName = $script:SearchBase }
        }
        'Get-ADObject' {
            if ('nTSecurityDescriptor' -in $Bound['Properties']) {
                [pscustomobject]@{
                    nTSecurityDescriptor = [pscustomobject]@{
                        Access = @([pscustomobject][ordered]@{
                            IdentitySid = 'S-1-5-21-1-2-3-9000'
                            Rights = 'ExtendedRight'
                            AccessControlType = 'Allow'
                            ObjectType = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                        })
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
        return [pscustomobject][ordered]@{
            Type = $type
            Id = $record.FullyQualifiedErrorId
            Category = [string]$record.CategoryInfo.Category
            Message = if ($null -ne $exception) {
                $exception.Message
            }
            ExceptionType = if ($null -ne $exception) {
                $exception.GetType().FullName
            }
            Restore = if ($null -ne $exception) {
                $exception.Data['ADAnalyzerLocationRestorationError']
            }
            Remove = if ($null -ne $exception) {
                $exception.Data['ADAnalyzerDriveRemovalError']
            }
        }
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
            $transport = if ($scenario -in 'Direct', 'Denied', 'Invalid') { 'Direct' } else { 'PSDrive' }
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

$collector = [ADAnalyzerDirectoryCollector]::new()
Assert-DirectoryCollector ($script:Imports.Count -eq 0 -and $script:Ambient.Count -eq 0 -and $script:Trace.Count -eq 0) `
    'Loading or construction performed integration calls.'

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
            $null = $collector.Collect(@{ Server = ''; Domain = '' }, (New-FixtureProfile Direct))
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
            Snapshot = ConvertTo-FixtureJson $reference.Rows[0]
            Queries = ConvertTo-FixtureJson ($script:Trace.ToArray())
        }
    }

    function Get-ADAnalyzerDirectoryData {
        throw 'Direct collector called the old directory command.'
    }

    foreach ($transport in 'PSDrive', 'Direct') {
        Test-DirectoryCollector ('match compatibility on ' + $transport) {
            Clear-FixtureObservations
            $status = if ($transport -ceq 'Direct') { 'Direct' } else { 'Connected' }
            $actual = @(Invoke-FixtureDirect $collector (New-FixtureContext) (New-FixtureProfile $transport))
            Assert-DirectoryCollector ($actual.Count -eq 1) 'Direct collection did not return exactly one snapshot.'
            Assert-FixtureSuccess $actual[0] $status
            Assert-FixtureDirectTrace $script:SelectedServer ($transport -ceq 'PSDrive')
            Assert-DirectoryCollector ((ConvertTo-FixtureJson $actual[0]) -ceq $native[$transport].Snapshot -and
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
            $expectedMessage = if ($providerFault -ceq 'Import') { '*Fixture directory provider import failure*' } else { '*Get-ADOrganizationalUnit*' }
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
        Assert-DirectoryCollector ((ConvertTo-FixtureJson $reused) -ceq (ConvertTo-FixtureJson $independent)) `
            'Secondary runspace disposal changed the existing or new collector result.'

        $index = New-ADAnalyzerMembershipIndex -Groups @($group)
        Assert-DirectoryCollector ([object]::ReferenceEquals($index.ByDn[$group.DistinguishedName], $group) -and
            [object]::ReferenceEquals($index.BySid[$group.SID], $group)) 'Secondary runspace disposal changed the compatibility index.'
    }
}

Write-Host ('PASS directory collector {0} {1}' -f $Case, $script:Checks)
