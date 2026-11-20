[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
$script:checks = 0
$script:expectedDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:fixtureTrace = [Collections.Generic.List[string]]::new()
$script:fixtureMode = $Case
$script:fixtureFault = $null
$script:fixtureImportAllowed = $false
$script:fixtureExpectAmbient = $false

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:checks++
    }
    catch {
        Write-Host ('FAIL fresh remediation guard ' + $Name)
        throw
    }
}

function Get-FixtureFailure([scriptblock]$Operation, [string]$MessagePattern = '') {
    try {
        $null = & $Operation
    }
    catch {
        $record = $_
        Assert-Fixture (
            -not $MessagePattern -or $record.Exception.GetBaseException().Message -match $MessagePattern
        ) ('Unexpected fresh guard error: ' + $record)
        return $record
    }
    throw 'Fresh eligibility unexpectedly succeeded with unusable evidence.'
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru)

    $script:fixtureTrace.Add('Import')
    Assert-Fixture $script:fixtureImportAllowed 'An inert guard route attempted a provider import.'
    Assert-Fixture (
        [IO.Path]::IsPathRooted($Name) -and
        [IO.Path]::GetFullPath($Name) -ceq $script:expectedDll -and
        $Scope -ceq 'Local' -and $PassThru -and
        [string]$PSBoundParameters['ErrorAction'] -ceq 'Stop'
    ) 'Fresh privilege did not import the exact bundled provider locally.'
    if ($script:fixtureFault -eq 'ImportError') {
        throw [IO.FileLoadException]::new('Synthetic group provider import failure')
    }
    $exports = @{}
    if ($script:fixtureFault -ne 'MissingExport') {
        $exports['Get-ADGroup'] = Microsoft.PowerShell.Core\Get-Command Invoke-FixtureBundledGroup -CommandType Function
    }
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $exports
    }
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

if ($Case -eq 'Native') {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;

public sealed class FreshGuardFixtureMembershipDictionary : Hashtable
{
    public List<string> Trace;

    public override bool Contains(object key)
    {
        string name = key as string;
        Trace.Add("Membership.Contains." + name);
        if (String.Equals(name, "Unresolved", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("FixtureUnresolvedAccessorFault");
        }
        return base.Contains(key);
    }
}
'@
}

foreach ($name in @(
        'Invoke-Command', 'New-PSDrive', 'Get-ADObject', 'Get-ADRootDSE', 'Disable-ADAccount',
        'Enable-ADAccount', 'Write-ADAnalyzerOperationFile', 'Enter-ADAnalyzerJournalLease',
        'Get-ADAnalyzerOperationJournal', 'Save-ADAnalyzerOperationJournal'
    )) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'Fresh eligibility attempted an unrelated external effect.'
    }
}

function New-FixtureCredential {
    [pscredential]::new('fixture', [Security.SecureString]::new())
}

function New-ObservedFixtureRecord([string]$Label, [Collections.IDictionary]$Fields) {
    $record = [pscustomobject]@{
        FixtureLabel = $Label
        Raw = $Fields
    }
    foreach ($name in $Fields.Keys) {
        $getter = [scriptblock]::Create(
            '$script:fixtureTrace.Add($this.FixtureLabel + ''.{0}''); return , $this.Raw[''{0}'']' -f $name
        )
        $record | Add-Member -MemberType ScriptProperty -Name $name -Value $getter
    }
    return $record
}

function Reset-FixtureInput([string]$Fault = '', [string]$Server = 'selected.fixture.invalid') {
    $script:fixtureTrace = [Collections.Generic.List[string]]::new()
    $script:fixtureFault = $Fault
    $script:fixtureServer = $Server
    $script:fixtureCredential = New-FixtureCredential
    $script:fixtureCredentialBound = $true
    $script:fixtureImportAllowed = $false
    $script:fixtureExpectAmbient = $script:fixtureMode -eq 'Native'
    $script:domainSid = 'S-1-5-21-1-2-3'
    $script:object = New-ObservedFixtureRecord Object ([ordered]@{
            ObjectGuid = '11111111-1111-1111-1111-111111111111'
            SID = "$script:domainSid-2100"
            DistinguishedName = 'CN=Synthetic,OU=Fixture,DC=fixture,DC=invalid'
            ObjectClass = @('top', 'person', 'user')
            Enabled = $true
            WhenChanged = [datetimeoffset]'2025-04-01T01:30:00Z'
            UserAccountControl = 512L
            PrimaryGroupID = 513
            AdminCount = $null
            ProtectedFromAccidentalDeletion = $false
            ProtectedUser = $false
            Protected = $false
            IsCriticalSystemObject = $null
            IsDomainController = $false
            WellKnownSID = $false
            SIDHistory = @()
            MemberOf = @('CN=Ordinary Group,DC=fixture,DC=invalid')
            Description = 'fixture description'
            LastLogonTimestamp = 0
            LastLogon = $null
            LastLogonDate = $null
            WhenCreated = [datetimeoffset]'2000-04-01T00:00:00Z'
        })
    $script:action = New-ObservedFixtureRecord Action ([ordered]@{
            ObjectClass = 'User'
            AccountType = 'User'
            InactivityDays = 90L
        })
    $script:plan = New-ObservedFixtureRecord Plan ([ordered]@{
            Context = @{ Server = $Server }
            PrivilegedSids = @("$script:domainSid-3000", 'S-1-5-32-544', "$script:domainSid-3000")
            AccountClassification = @{ AttributeRules = @(@{ Attribute = 'Description' }) }
            Remediation = @{
                IncludePrivilegedAccounts = $false
                IncludeServiceAccounts = $false
                ExcludedObjectGuids = @()
                ExcludedOUs = @()
            }
        })
    $script:fixtureMembership = New-ObservedFixtureRecord Membership ([ordered]@{
            Unresolved = @($null)
            IsPrivileged = $false
            EffectiveSids = @("$script:domainSid-2300")
        })
    $script:fixtureGroupRows = @(
        New-ObservedFixtureRecord GroupA ([ordered]@{ SID = "$script:domainSid-512" })
        New-ObservedFixtureRecord GroupB ([ordered]@{ SID = "$script:domainSid-3100" })
    )
    $script:fixtureAccountType = 'User'
    switch ($Fault) {
        'WrongClass' {
            $script:object.Raw.ObjectClass = @('top', 'computer')
        }
        'InvalidSid' {
            $script:object.Raw.SID = 'invalid synthetic identity'
        }
        'IncompleteMembership' {
            $script:fixtureMembership.Raw.Unresolved = @('CN=Unobserved,DC=fixture,DC=invalid')
        }
        'NonBooleanMembership' {
            $script:fixtureMembership.Raw.IsPrivileged = 'false'
        }
        'UnreadableMembership' {
            $membership = [FreshGuardFixtureMembershipDictionary]::new()
            $membership.PSBase.Trace = $script:fixtureTrace
            $membership['Unresolved'] = @()
            $membership['IsPrivileged'] = $false
            $membership['EffectiveSids'] = @("$script:domainSid-2300")
            $script:fixtureMembership = $membership
        }
        'MalformedActivity' {
            $script:object.Raw.LastLogon = 'invalid fixture date'
        }
    }
}

function Add-FixtureGroupTrace([string]$Source, $Bound) {
    $script:fixtureTrace.Add($Source)
    Assert-Fixture (
        $Bound.Server -ceq $script:fixtureServer -and $Bound.Filter -ceq '*' -and
        ($Bound.Properties -join ',') -ceq 'members,memberOf,primaryGroupToken,SID' -and
        [string]$Bound['ErrorAction'] -ceq 'Stop' -and
        $Bound.ContainsKey('Credential') -eq $script:fixtureCredentialBound -and
        (-not $script:fixtureCredentialBound -or [object]::ReferenceEquals($Bound.Credential, $script:fixtureCredential))
    ) 'Fresh group evidence query binding changed.'
}

function Get-ADGroup {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [string]$Filter, [string[]]$Properties)

    Assert-Fixture $script:fixtureExpectAmbient 'Direct privilege resolved an ambient directory command.'
    Add-FixtureGroupTrace 'NativeGroups' $PSBoundParameters
    if ($script:fixtureFault -eq 'GroupError') {
        Write-Error -Message 'Synthetic group evidence read failed' -ErrorId 'FixtureGroupQuery'
    }
    return $script:fixtureGroupRows
}

function Invoke-FixtureBundledGroup {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [string]$Filter, [string[]]$Properties)

    Add-FixtureGroupTrace 'BundledGroups' $PSBoundParameters
    if ($script:fixtureFault -eq 'GroupError') {
        Write-Error -Message 'Synthetic group evidence read failed' -ErrorId 'FixtureGroupQuery'
    }
    return $script:fixtureGroupRows
}

if ($Case -ne 'Standalone') {
    function Resolve-ADAnalyzerMembership {
        [CmdletBinding()]
        param($Object, [object[]]$Groups, [string]$DomainSid, [string[]]$PrivilegedSids)

        $script:fixtureTrace.Add('Resolve')
        Assert-Fixture (
            [object]::ReferenceEquals($Object, $script:object) -and
            $DomainSid -ceq $script:domainSid -and $Groups.Count -eq 2 -and
            [object]::ReferenceEquals($Groups[0], $script:fixtureGroupRows[0]) -and
            [object]::ReferenceEquals($Groups[1], $script:fixtureGroupRows[1])
        ) 'Fresh privilege resolver did not receive the exact scoped evidence.'
        $script:observedPrivilegedSids = $PrivilegedSids
        if ($script:fixtureFault -eq 'MembershipError') {
            Write-Error -Message 'Synthetic membership observation failed' -ErrorId 'FixtureMembership'
        }
        if ($script:fixtureFault -ne 'NullMembership') {
            return $script:fixtureMembership
        }
    }

    function Get-ADAnalyzerAccountType {
        [CmdletBinding()]
        param($Object, [hashtable]$Profile, $Membership)

        $script:fixtureTrace.Add('Classify')
        Assert-Fixture (
            [object]::ReferenceEquals($Membership, $script:fixtureMembership) -and
            $Object.DistinguishedName -ceq $script:object.Raw.DistinguishedName -and
            $Object.Description -ceq $script:object.Raw.Description -and
            ($Object.MemberOf -join ',') -ceq ($script:object.Raw.MemberOf -join ',') -and
            $Profile.AccountClassification.AttributeRules[0].Attribute -ceq 'Description'
        ) 'Fresh classification did not receive the observed membership and selected account facts.'
        [pscustomobject]@{ Type = $script:fixtureAccountType }
    }
}

function Get-FixtureDiagnostic([object]$Entry) {
    if ($null -eq $Entry) {
        return $null
    }
    if ($Entry -is [Collections.IList]) {
        return [ordered]@{
            Type = $Entry.GetType().FullName
            Entries = @(
                foreach ($item in $Entry) {
                    Get-FixtureDiagnostic $item
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

# Exact compatibility bodies from accepted 928244e.
$script:acceptedFreshBodies = [ordered]@{
    # ff08775f7a19a00775f03f92fd06bf72c46d9ca4e2a00a25d838ee1f4bce57e9
    'Assert-ADAnalyzerOperationPrivilege' = @'
    param(
        $Object,
        $Action,
        $Plan,
        [hashtable]$Connection

    )
    if (-not (Get-Command Resolve-ADAnalyzerMembership -ErrorAction SilentlyContinue)) {
        throw 'Fresh privilege resolver is unavailable; remediation is blocked'
    }
    if ((Get-ADAnalyzerOperationKind $Object) -ne $Action.ObjectClass) {
        throw 'Current object class differs from the approved action'
    }
    $groups = @(Get-ADGroup -Filter * -Properties members, memberOf, primaryGroupToken, SID @Connection)
    $sid = Get-ADAnalyzerOperationSid $Object
    if ($sid -notmatch '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
        throw 'A domain SID is required for fresh privilege resolution'
    }
    $domainSid = $Matches[1]
    $privileged = @($Plan.PrivilegedSids) + @('S-1-5-32-544',
        'S-1-5-32-548',
        'S-1-5-32-549',
        'S-1-5-32-550',
        'S-1-5-32-551',
        'S-1-5-32-552')
    foreach ($group in $groups) {
        $groupSid = Get-ADAnalyzerOperationSid $group
        if ($groupSid -match '^S-1-5-21-(?:\d+-){3}(512|516|518|519|520|521|526|527)$') {
            $privileged += , $groupSid
        }
    }
    $membership = Resolve-ADAnalyzerMembership `
        -Object $Object `
        -Groups $groups `
        -DomainSid $domainSid `
        -PrivilegedSids @($privileged | Select-Object `
            -Unique)
    if ($null -eq $membership -or
        @(Get-ADAnalyzerOperationValue $membership @('Unresolved') @() | Where-Object { $null -ne $_ }).Count -gt 0) {
        throw 'Fresh privilege resolution is incomplete; remediation is blocked'
    }
    $isPrivileged = Get-ADAnalyzerOperationValue $membership @('IsPrivileged')
    if ($isPrivileged -isnot [bool]) {
        throw 'Fresh privilege resolution did not return a definite result'
    }
    $state = Get-ADAnalyzerOperationState $Object
    $safe = @{
        ObjectGuid = $state.ObjectGuid
        SID = $state.SID
        DistinguishedName = $state.DistinguishedName
        WhenChanged = $state.WhenChanged
        Enabled = $true
        Privileged = $isPrivileged
        PrivilegeResolutionStatus = 'Complete'
        AccountType = $Action.AccountType
        ObjectClass = $Action.ObjectClass
    }
    foreach ($name in @('AdminCount',
            'ProtectedFromAccidentalDeletion',
            'ProtectedUser',
            'Protected',
            'IsCriticalSystemObject',
            'IsDomainController',
            'UserAccountControl',
            'PrimaryGroupID',
            'WellKnownSID',
            'SIDHistory')) {
        $safe[$name] = Get-ADAnalyzerOperationValue $Object @($name)
    }
    # These optional schema attributes were explicitly requested by our successful
    # query; an unset value differs from a missing or unreadable ACL-derived fact.
    if ($null -eq $safe.AdminCount) {
        $safe.AdminCount = 0
    }
    if ($null -eq $safe.IsCriticalSystemObject) {
        $safe.IsCriticalSystemObject = $false
    }
    $safe.SafetyMetadataStatus = 'Collected'
    $safe.TransitiveGroups = @(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
    $safe.IsDomainController = ([long]$safe.UserAccountControl -band 8192) -ne 0 -or [int]$safe.PrimaryGroupID -in @(516, 521)
    if ($Action.ObjectClass -eq 'User') {
        if (-not (Get-Command Get-ADAnalyzerAccountType -ErrorAction SilentlyContinue)) {
            throw 'Fresh account classification is unavailable; remediation is blocked'
        }
        $classificationObject = @{
            DistinguishedName = $state.DistinguishedName
            MemberOf = Get-ADAnalyzerOperationValue $Object @('MemberOf') @()
            DirectoryObjectClass = [string](Get-ADAnalyzerOperationValue $Object @('ObjectClass'))
        }
        foreach ($rule in @($Plan.AccountClassification.AttributeRules)) {
            if ($null -ne $rule) {
                $attribute = [string](Get-ADAnalyzerOperationValue $rule @('Attribute'))
                $classificationObject[$attribute] = Get-ADAnalyzerOperationValue $Object @($attribute)
            }
        }
        $classificationProfile = @{
            AccountClassification = ConvertTo-ADAnalyzerHashtable $Plan.AccountClassification
        }
        $classification = Get-ADAnalyzerAccountType `
            -Object ([pscustomobject]$classificationObject) `
            -Profile $classificationProfile `
            -Membership $membership
        $safe.AccountType = [string](Get-ADAnalyzerOperationValue $classification @('Type') 'Unknown')
        if ($safe.AccountType -notin @('User', 'Service')) {
            throw 'Fresh account classification is unknown or conflicting'
        }
    }
    $reason = Get-ADAnalyzerOperationExclusion $safe $Plan.Remediation
    if ($reason) {
        throw "Fresh object safety check failed: $reason"
    }
'@
    # 23be823a4e7c5e2e967703b293a4659b48656e735f990e9188ac0611ab83d9e5
    'Assert-ADAnalyzerOperationInactivity' = @'
    param(
        $Object,
        $Action

    )
    $days = 0L
    if (-not [long]::TryParse([string]$Action.InactivityDays, [ref]$days) -or $days -lt 0) {
        throw 'The reviewed action is missing its inactivity threshold'
    }
    $dates = [Collections.Generic.List[datetime]]::new()
    foreach ($name in @('lastLogonTimestamp', 'lastLogon', 'LastLogonDate')) {
        $value = Get-ADAnalyzerOperationValue $Object @($name)
        if ($null -eq $value -or [string]$value -eq '0') {
            continue
        }
        $fileTime = 0L
        try {
            if ([long]::TryParse([string]$value, [ref]$fileTime)) {
                $dates.Add([datetime]::FromFileTimeUtc($fileTime))
            }
            else {
                $dates.Add([datetime]::Parse((ConvertTo-ADAnalyzerOperationTime $value),
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime())
            }
        }
        catch {
            throw 'Fresh activity metadata could not be interpreted'
        }
    }
    if ($dates.Count) {
        $latest = $dates.ToArray() | Sort-Object -Descending | Select-Object -First 1
    }
    else {
        $created = Get-ADAnalyzerOperationValue $Object @('WhenCreated')
        if ($null -eq $created) {
            throw 'Fresh inactivity evidence is unavailable'
        }
        try {
            $latest = [datetime]::Parse((ConvertTo-ADAnalyzerOperationTime $created),
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        }
        catch {
            throw 'Fresh creation metadata could not be interpreted'
        }
    }
    if (([datetime]::UtcNow - $latest).TotalDays -lt $days) {
        throw 'Fresh activity no longer satisfies the reviewed inactivity rule'
    }
    # This checks known activity on the pinned DC and its replicated timestamp;
    # it is not an authoritative all-DC lastLogon sweep.
'@
}

function Invoke-FixtureNative {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    if ($script:fixtureFault -eq 'MalformedActivity') {
        Assert-ADAnalyzerOperationInactivity $script:object $script:action
    }
    else {
        $connection = Get-ADAnalyzerOperationConnection $script:fixtureServer $script:fixtureCredential
        Assert-ADAnalyzerOperationPrivilege $script:object $script:action $script:plan $connection
    }
}

function Get-NativeObservation([string]$Scenario, [string]$Preference) {
    Reset-FixtureInput $Scenario
    $unavailable = @{
        ResolverUnavailable = 'Resolve-ADAnalyzerMembership'
        ClassifierUnavailable = 'Get-ADAnalyzerAccountType'
    }
    $removed = $null
    $path = $null
    if ($unavailable.ContainsKey($Scenario)) {
        $name = $unavailable[$Scenario]
        $path = 'Function:script:' + $name
        $removed = (Get-Command $name -CommandType Function).ScriptBlock
        Remove-Item -LiteralPath ('Function:\' + $name)
    }
    $records = [Collections.Generic.List[object]]::new()
    $seen = [Collections.ArrayList]::new()
    $caught = $null
    $completed = $false
    $Error.Clear()
    try {
        Invoke-FixtureNative -ErrorAction $Preference -ErrorVariable +seen *>&1 |
            ForEach-Object {
                $records.Add($_)
            }
        $completed = $true
    }
    catch {
        $caught = $_
    }
    finally {
        if ($null -ne $removed) {
            Set-Item -LiteralPath $path -Value $removed
        }
    }
    $history = @($Error)
    [ordered]@{
        Completed = $completed
        Caught = Get-FixtureDiagnostic $caught
        Captured = Get-FixtureDiagnostic $seen
        History = Get-FixtureDiagnostic $history
        Trace = $script:fixtureTrace.ToArray()
        Stream = @(
            foreach ($record in $records) {
                if ($null -eq $record) {
                    [ordered]@{ Type = 'Null' }
                }
                elseif ($record -is [Management.Automation.ErrorRecord]) {
                    Get-FixtureDiagnostic $record
                }
                elseif ($record -is [Management.Automation.InformationalRecord]) {
                    [ordered]@{
                        Type = $record.GetType().FullName
                        Value = $record.Message
                    }
                }
                elseif ($record -is [Management.Automation.InformationRecord]) {
                    [ordered]@{
                        Type = $record.GetType().FullName
                        Value = $record.MessageData
                    }
                }
                else {
                    [ordered]@{
                        Type = $record.GetType().FullName
                        Value = $record
                    }
                }
            }
        )
    }
}

function Assert-NativeParity([string]$Scenario, [string]$Preference) {
    $originals = [ordered]@{}
    try {
        foreach ($name in $script:acceptedFreshBodies.Keys) {
            $path = 'Function:script:' + $name
            $originals[$name] = (Get-Command $name -CommandType Function).ScriptBlock
            $accepted = [scriptblock]::Create($script:acceptedFreshBodies[$name])
            Set-Item -LiteralPath $path -Value $accepted
            $current = (Get-Command $name -CommandType Function).ScriptBlock
            Assert-Fixture ($current.ToString() -ceq $accepted.ToString()) ('Failed to install archived ' + $name + '.')
        }
        $expected = Get-NativeObservation $Scenario $Preference
    }
    finally {
        foreach ($name in $originals.Keys) {
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $originals[$name]
        }
    }
    foreach ($name in $originals.Keys) {
        $current = (Get-Command $name -CommandType Function).ScriptBlock
        Assert-Fixture ($current.ToString() -ceq $originals[$name].ToString()) ('Failed to restore ' + $name + '.')
    }

    $serialized = ConvertTo-Json -InputObject $expected -Depth 25 -Compress
    $stages = @($expected.Trace | Where-Object { $_ -in 'Import', 'NativeGroups', 'BundledGroups', 'Resolve', 'Classify' })
    $expectedStages = @{
        Success = 'NativeGroups,Resolve,Classify'
        GroupError = 'NativeGroups'
        InvalidSid = 'NativeGroups'
        WrongClass = ''
        ResolverUnavailable = ''
        MembershipError = 'NativeGroups,Resolve'
        IncompleteMembership = 'NativeGroups,Resolve'
        NonBooleanMembership = 'NativeGroups,Resolve'
        UnreadableMembership = 'NativeGroups,Resolve'
        ClassifierUnavailable = 'NativeGroups,Resolve'
        MalformedActivity = ''
    }
    Assert-Fixture (($stages -join ',') -ceq $expectedStages[$Scenario]) (
        "Unexpected archived $Scenario stages with ErrorAction=$Preference." + [Environment]::NewLine + $serialized
    )
    if ($Scenario -eq 'Success') {
        Assert-Fixture ($expected.Completed -and $null -eq $expected.Caught -and $expected.Stream.Count -eq 0) (
            'The archived success route emitted output or failed.' + [Environment]::NewLine + $serialized
        )
    }
    elseif ($Scenario -eq 'MalformedActivity') {
        Assert-Fixture (
            ($expected.Trace -join ',') -ceq 'Action.InactivityDays,Object.LastLogonTimestamp,Object.LastLogon' -and
            $serialized.Contains('Fresh activity metadata could not be interpreted') -and
            $serialized.Contains('System.FormatException')
        ) ('The archive missed the malformed activity conversion.' + [Environment]::NewLine + $serialized)
    }
    elseif ($Scenario -eq 'UnreadableMembership') {
        Assert-Fixture (
            -not $expected.Completed -and
            $expected.Trace[-1] -ceq 'Membership.Contains.Unresolved' -and
            $serialized.Contains('FixtureUnresolvedAccessorFault') -and
            $serialized.Contains('System.InvalidOperationException')
        ) ("The archive missed the membership accessor error with ErrorAction=$Preference." +
            [Environment]::NewLine + $serialized)
    }
    else {
        $faults = @{
            GroupError = 'FixtureGroupQuery'
            InvalidSid = 'A domain SID is required for fresh privilege resolution'
            WrongClass = 'Current object class differs from the approved action'
            ResolverUnavailable = 'Fresh privilege resolver is unavailable'
            MembershipError = 'FixtureMembership'
            IncompleteMembership = 'Fresh privilege resolution is incomplete'
            NonBooleanMembership = 'Fresh privilege resolution did not return a definite result'
            ClassifierUnavailable = 'Fresh account classification is unavailable'
        }
        Assert-Fixture (-not $expected.Completed -and $serialized.Contains($faults[$Scenario])) (
            "The archived helper missed $Scenario with ErrorAction=$Preference." + [Environment]::NewLine + $serialized
        )
    }
    $actual = ConvertTo-Json -InputObject (Get-NativeObservation $Scenario $Preference) -Depth 25 -Compress
    Assert-Fixture ($actual -ceq $serialized) (
        "Native fresh guard changed for $Scenario with ErrorAction=$Preference." + [Environment]::NewLine +
        'Accepted: ' + $serialized + [Environment]::NewLine + 'Current: ' + $actual
    )
}

function Invoke-NativeCases {
    foreach ($scenario in 'Success', 'GroupError', 'InvalidSid', 'WrongClass') {
        foreach ($preference in 'Continue', 'Stop', 'Ignore') {
            Test-Fixture ($scenario + ' ' + $preference) {
                Assert-NativeParity $scenario $preference
            }
        }
    }
    foreach ($scenario in @(
            'ResolverUnavailable', 'MembershipError', 'IncompleteMembership', 'NonBooleanMembership',
            'ClassifierUnavailable', 'MalformedActivity'
        )) {
        Test-Fixture $scenario {
            Assert-NativeParity $scenario 'Stop'
        }
    }
    foreach ($preference in 'Continue', 'SilentlyContinue', 'Ignore', 'Stop') {
        Test-Fixture ('UnreadableMembership ' + $preference) {
            Assert-NativeParity 'UnreadableMembership' $preference
        }
    }
}

function Assert-DirectSignatures {
    $type = [ADAnalyzerRemediationGuard]
    $short = $type.GetMethod('AssertPrivilege', [type[]]@([object], [object], [object], [string]))
    $long = $type.GetMethod('AssertPrivilege', [type[]]@([object], [object], [object], [string], [pscredential]))
    $activity = $type.GetMethod('AssertInactivity', [type[]]@([object], [object]))
    Assert-Fixture (
        $null -ne $short -and $short.ReturnType -eq [void] -and
        $null -ne $long -and $long.ReturnType -eq [void] -and
        $null -ne $activity -and $activity.ReturnType -eq [void]
    ) 'The literal fresh eligibility methods or documented overloads are absent.'
}

function Forbid-LegacyGuardRoute {
    foreach ($name in $script:acceptedFreshBodies.Keys) {
        Set-Item -LiteralPath ('Function:script:' + $name) -Value {
            throw 'The direct guard delegated processing to a compatibility helper.'
        }
    }
}

function Assert-FixtureStages([string]$Expected) {
    $stages = @($script:fixtureTrace | Where-Object { $_ -in 'Import', 'NativeGroups', 'BundledGroups', 'Resolve', 'Classify' })
    Assert-Fixture (($stages -join ',') -ceq $Expected) ('Unexpected direct integration trace: ' + ($stages -join ','))
}

function Invoke-DirectCases {
    Forbid-LegacyGuardRoute
    $guard = [ADAnalyzerRemediationGuard]::new()
    Test-Fixture 'direct privilege pins the selected provider and optional credential' {
        foreach ($credentialRoute in 'Supplied', 'Omitted', 'Empty') {
            Reset-FixtureInput
            $script:fixtureImportAllowed = $true
            $script:fixtureCredentialBound = $credentialRoute -eq 'Supplied'
            switch ($credentialRoute) {
                'Supplied' {
                    $output = @($guard.AssertPrivilege($script:object, $script:action, $script:plan,
                            $script:fixtureServer, $script:fixtureCredential))
                }
                'Omitted' {
                    $output = @($guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer))
                }
                'Empty' {
                    $output = @($guard.AssertPrivilege($script:object, $script:action, $script:plan,
                            $script:fixtureServer, [pscredential]::Empty))
                }
            }
            Assert-Fixture ($output.Count -eq 0) 'Fresh privilege unexpectedly returned a value.'
            Assert-FixtureStages 'Import,BundledGroups,Resolve,Classify'
        }
    }
    Test-Fixture 'direct import and provider failures cannot fall back or advance' {
        $faults = [ordered]@{
            ImportError = @('Synthetic group provider import failure', 'Import')
            MissingExport = @('Get-ADGroup', 'Import')
            GroupError = @('Synthetic group evidence read failed', 'Import,BundledGroups')
            MembershipError = @('Synthetic membership observation failed', 'Import,BundledGroups,Resolve')
        }
        foreach ($fault in $faults.Keys) {
            Reset-FixtureInput $fault
            $script:fixtureImportAllowed = $true
            $null = Get-FixtureFailure {
                $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
            } $faults[$fault][0]
            Assert-FixtureStages $faults[$fault][1]
        }
    }
    Test-Fixture 'the reviewed and selected server must match before import' {
        Reset-FixtureInput
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, 'invalid/host')
        } 'DNS or NetBIOS'
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, 'elsewhere.fixture.invalid')
        } 'differs from the DC recorded'
        Assert-FixtureStages ''

        Reset-FixtureInput -Server 'SELECTED.FIXTURE.INVALID'
        $script:plan.Raw.Context.Server = 'selected.fixture.invalid'
        $script:fixtureImportAllowed = $true
        $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        Assert-FixtureStages 'Import,BundledGroups,Resolve,Classify'
    }
    Test-Fixture 'ambiguous scope evidence fails before classification and safety projection' {
        $faults = [ordered]@{
            NullMembership = 'Fresh privilege resolution is incomplete'
            IncompleteMembership = 'Fresh privilege resolution is incomplete'
            NonBooleanMembership = 'did not return a definite result'
        }
        foreach ($fault in $faults.Keys) {
            Reset-FixtureInput $fault
            $script:fixtureImportAllowed = $true
            $null = Get-FixtureFailure {
                $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
            } $faults[$fault]
            Assert-FixtureStages 'Import,BundledGroups,Resolve'
            Assert-Fixture ('Object.Enabled' -cnotin $script:fixtureTrace) 'Invalid membership reached the safety snapshot.'
            if ($fault -eq 'IncompleteMembership') {
                Assert-Fixture ('Membership.IsPrivileged' -cnotin $script:fixtureTrace) 'Incomplete membership reached the Boolean check.'
            }
        }
    }
    Test-Fixture 'fresh user eligibility recomputes reviewed groups, classification and exclusions' {
        Reset-FixtureInput
        $script:fixtureImportAllowed = $true
        $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        Assert-Fixture (
            ($script:observedPrivilegedSids -join ',') -ceq
            'S-1-5-21-1-2-3-3000,S-1-5-32-544,S-1-5-32-548,S-1-5-32-549,S-1-5-32-550,S-1-5-32-551,S-1-5-32-552,S-1-5-21-1-2-3-512'
        ) 'Fresh reviewed, built-in and recognized domain privilege identifiers changed.'

        $script:fixtureAccountType = 'Unknown'
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        } 'Fresh account classification is unknown'
        $script:fixtureAccountType = 'Service'
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        } 'Fresh object safety check failed: ServiceAccount'
        $script:fixtureAccountType = 'User'
        $script:fixtureMembership.Raw.IsPrivileged = $true
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        } 'Fresh object safety check failed: PrivilegedAccount'
        $script:fixtureMembership.Raw.IsPrivileged = $false
        $script:object.Raw.AdminCount = 1
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        } 'Fresh object safety check failed: AdminCountProtected'

        Reset-FixtureInput
        $script:fixtureImportAllowed = $true
        $script:plan.Raw.AccountClassification.AttributeRules[0].Attribute = 'UserPassword'
        $script:object | Add-Member -MemberType ScriptProperty -Name UserPassword -Value {
            $script:fixtureTrace.Add('UnexpectedAttributeRead')
            throw 'A disallowed classification field must never be read.'
        }
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        } 'Classification attribute cannot be safely re-queried'
        Assert-FixtureStages 'Import,BundledGroups,Resolve'
        Assert-Fixture ('UnexpectedAttributeRead' -cnotin $script:fixtureTrace) 'A disallowed attribute was observed.'
    }
    Test-Fixture 'current object class controls read and classification' {
        Reset-FixtureInput 'WrongClass'
        $null = Get-FixtureFailure {
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        } 'Current object class differs from the approved action'
        Assert-FixtureStages ''

        $script:fixtureImportAllowed = $true
        $script:action.Raw.ObjectClass = 'Computer'
        $script:action.Raw.AccountType = 'Computer'
        $script:object.Raw.UserAccountControl = 4096
        $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        Assert-FixtureStages 'Import,BundledGroups,Resolve'
    }
    Test-Fixture 'the newest observed UTC activity controls the threshold' {
        Reset-FixtureInput
        $old = [datetime]::UtcNow.AddDays(-500)
        $recent = [datetime]::UtcNow.AddDays(-5)
        $script:object.Raw.LastLogonTimestamp = $old.ToFileTimeUtc()
        $script:object.Raw.LastLogon = $recent.ToFileTimeUtc()
        $script:object.Raw.LastLogonDate = [datetimeoffset]$old
        $null = Get-FixtureFailure {
            $guard.AssertInactivity($script:object, $script:action)
        } 'Fresh activity no longer satisfies'
        $script:object.Raw.LastLogon = $old.AddDays(10).ToFileTimeUtc()
        $script:object.Raw.LastLogonDate = [datetimeoffset]$old.AddDays(20)
        Assert-Fixture (@($guard.AssertInactivity($script:object, $script:action)).Count -eq 0) 'Inactivity unexpectedly returned a value.'
        Assert-Fixture ('Object.WhenCreated' -cnotin $script:fixtureTrace) 'Observed activity unexpectedly fell back to creation.'
        Assert-FixtureStages ''
    }
    Test-Fixture 'creation fallback distinguishes zero, absent and malformed evidence' {
        Reset-FixtureInput
        $script:object.Raw.LastLogon = '0'
        $guard.AssertInactivity($script:object, $script:action)
        Assert-Fixture (
            ($script:fixtureTrace -join ',') -ceq
            'Action.InactivityDays,Object.LastLogonTimestamp,Object.LastLogon,Object.LastLogonDate,Object.WhenCreated'
        ) 'Creation fallback evaluated the wrong evidence or order.'
        $script:object.Raw.WhenCreated = $null
        $null = Get-FixtureFailure {
            $guard.AssertInactivity($script:object, $script:action)
        } 'Fresh inactivity evidence is unavailable'
        $script:object.Raw.WhenCreated = 'invalid fixture creation'
        $null = Get-FixtureFailure {
            $guard.AssertInactivity($script:object, $script:action)
        } 'Fresh creation metadata could not be interpreted'
        Assert-FixtureStages ''
    }
    Test-Fixture 'invalid thresholds and ordered activity errors stop before fallback' {
        foreach ($threshold in 'bad fixture threshold', -1) {
            Reset-FixtureInput
            $script:action.Raw.InactivityDays = $threshold
            $null = Get-FixtureFailure {
                $guard.AssertInactivity($script:object, $script:action)
            } 'missing its inactivity threshold'
            Assert-Fixture (($script:fixtureTrace -join ',') -ceq 'Action.InactivityDays') 'Bad threshold touched activity evidence.'
        }
        Reset-FixtureInput 'MalformedActivity'
        $script:object.Raw.LastLogonDate = [datetimeoffset]'2002-01-01T00:00:00Z'
        $null = Get-FixtureFailure {
            $guard.AssertInactivity($script:object, $script:action)
        } 'Fresh activity metadata could not be interpreted'
        Assert-Fixture (
            ($script:fixtureTrace -join ',') -ceq 'Action.InactivityDays,Object.LastLogonTimestamp,Object.LastLogon'
        ) 'Malformed activity evaluated a later observation or fallback.'
        Assert-FixtureStages ''
    }
}

function Invoke-IsolationCases {
    Forbid-LegacyGuardRoute
    $guard = [ADAnalyzerRemediationGuard]::new()
    Test-Fixture 'one guard keeps each selected operation local and leaves caller input unchanged' {
        $beforeLocation = (Get-Location).Path
        $beforeGroup = (Get-Command Get-ADGroup -CommandType Function).ScriptBlock
        $firstCredential = $null
        foreach ($server in 'first.fixture.invalid', 'second.fixture.invalid') {
            Reset-FixtureInput -Server $server
            $script:fixtureImportAllowed = $true
            $beforeObject = ConvertTo-Json -InputObject $script:object.Raw -Depth 10 -Compress
            $beforePlan = ConvertTo-Json -InputObject $script:plan.Raw -Depth 10 -Compress
            if ($null -eq $firstCredential) {
                $firstCredential = $script:fixtureCredential
            }
            else {
                Assert-Fixture (-not [object]::ReferenceEquals($firstCredential, $script:fixtureCredential)) 'The fixture reused a credential identity.'
            }
            $guard.AssertPrivilege($script:object, $script:action, $script:plan, $server, $script:fixtureCredential)
            Assert-FixtureStages 'Import,BundledGroups,Resolve,Classify'
            Assert-Fixture (
                $beforeObject -ceq (ConvertTo-Json -InputObject $script:object.Raw -Depth 10 -Compress) -and
                $beforePlan -ceq (ConvertTo-Json -InputObject $script:plan.Raw -Depth 10 -Compress) -and
                (Get-Location).Path -ceq $beforeLocation -and
                (Get-Command Get-ADGroup -CommandType Function).ScriptBlock.ToString() -ceq $beforeGroup.ToString()
            ) 'Fresh guard mutated caller data or leaked provider/command scope.'
        }
        $json = ConvertTo-Json -InputObject $guard -Depth 4 -Compress
        Assert-Fixture ($json -cnotmatch 'fixture|Credential|CommandInfo|ExportedCmdlets') 'The reused guard serialized operation-local information.'
    }
    Test-Fixture 'disposing a secondary documented loader leaves the original guard usable' {
        $worker = [powershell]::Create()
        try {
            $childSource = @'
param($FixturePath, $RepositoryRoot)
& $FixturePath -RepositoryRoot $RepositoryRoot -Case Construction
'@
            $child = @($worker.AddScript($childSource).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
            Assert-Fixture (
                -not $worker.HadErrors -and @($child | Where-Object { $_ -ceq 'PASS fresh remediation guard Construction 2' }).Count -eq 1
            ) ('The secondary loader failed: ' + ($worker.Streams.Error -join ' | '))
        }
        finally {
            $worker.Dispose()
        }
        Reset-FixtureInput
        $script:fixtureImportAllowed = $true
        $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
        $guard.AssertInactivity($script:object, $script:action)
        Assert-FixtureStages 'Import,BundledGroups,Resolve,Classify'
    }
}

switch ($Case) {
    'Native' {
        Invoke-NativeCases
    }
    'Construction' {
        Test-Fixture 'documented literal guard construction stays inert' {
            $first = [ADAnalyzerRemediationGuard]::new()
            $second = [ADAnalyzerRemediationGuard]::new()
            Assert-Fixture (
                $first.GetType().Name -ceq 'ADAnalyzerRemediationGuard' -and
                -not [object]::ReferenceEquals($first, $second) -and
                $script:fixtureTrace.Count -eq 0
            ) 'Documented fresh guard construction did not produce independent inert instances.'
        }
        Test-Fixture 'literal fresh guard method signatures' {
            Assert-DirectSignatures
        }
    }
    'Standalone' {
        Test-Fixture 'local inactivity is available and missing resolver fails before import' {
            Reset-FixtureInput
            $guard = [ADAnalyzerRemediationGuard]::new()
            $guard.AssertInactivity($script:object, $script:action)
            $null = Get-FixtureFailure {
                $guard.AssertPrivilege($script:object, $script:action, $script:plan, $script:fixtureServer, $script:fixtureCredential)
            } 'Fresh privilege resolver is unavailable'
            Assert-FixtureStages ''
        }
    }
    'Direct' {
        Invoke-DirectCases
    }
    'Isolation' {
        Invoke-IsolationCases
    }
}

Write-Output ('PASS fresh remediation guard ' + $Case + ' ' + $script:checks)
