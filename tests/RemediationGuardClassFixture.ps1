[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
function Import-Module {
    throw 'The offline guard fixture cannot acquire a module.'
}
function Invoke-Command {
    throw 'The offline guard fixture cannot invoke a remote command.'
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

foreach ($name in @(
        'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE',
        'Disable-ADAccount', 'Enable-ADAccount',
        'Resolve-ADAnalyzerOperationFilePath', 'Enter-ADAnalyzerJournalLease',
        'Get-ADAnalyzerOperationJournal', 'Save-ADAnalyzerOperationJournal',
        'Write-ADAnalyzerOperationFile', 'Write-ADAnalyzerFile'
    )) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'The offline guard fixture encountered an external effect.'
    }
}

$script:passed = 0

function New-GuardRecord {
    [pscustomobject][ordered]@{
        ObjectGuid = '11111111-1111-1111-1111-111111111111'
        SID = 'S-1-5-21-1-2-3-1101'
        DistinguishedName = 'CN=Fixture,OU=People,DC=offline,DC=invalid'
        ObjectClass = 'user'
        Enabled = $true
        WhenChanged = '2026-01-01T02:00:00+02:00'
        UserAccountControl = 512
        PrimaryGroupID = 513
        SafetyMetadataStatus = 'Collected'
        ProtectedFromAccidentalDeletion = $false
        IsDomainController = $false
        IsCriticalSystemObject = $false
        AdminCount = 0
        SIDHistory = @()
        PrivilegeResolutionStatus = 'Complete'
        Privileged = $false
        AccountType = 'User'
    }
}

function New-GuardSettings {
    $profile = [ADAnalyzerProfile]::new().ToHashtable()
    return $profile.Remediation
}

function New-GuardPlan {
    $first = '11111111-1111-1111-1111-111111111111'
    $second = '22222222-2222-2222-2222-222222222222'
    [pscustomobject]@{
        PlanType = 'ADAnalyzerRemediationPlan'
        PlanId = '33333333-3333-3333-3333-333333333333'
        Remediation = [pscustomobject]@{
            AllowDisable = $true
            IncludePrivilegedAccounts = $false
            IncludeServiceAccounts = $false
            MaximumActions = 2
            ApprovedObjectGuids = @($first, $second)
        }
        Actions = @(
            [pscustomobject]@{
                ActionId = '1234abcd-4444-4444-8444-444444444444'
                Action = 'DisableAccount'
                ObjectGuid = $first
                Preconditions = [pscustomobject]@{ ObjectGuid = $first }
                RuleId = 'ACCOUNT.INACTIVE'
                ObjectClass = 'User'
                InactivityDays = 30
            }
            [pscustomobject]@{
                ActionId = '55555555-5555-5555-9555-555555555555'
                Action = 'DisableAccount'
                ObjectGuid = $second
                Preconditions = [pscustomobject]@{ ObjectGuid = $second }
                RuleId = 'COMPUTER.INACTIVE'
                ObjectClass = 'Computer'
                InactivityDays = 45
            }
        )
    }
}

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$TestName, [scriptblock]$Body) {
    try {
        & $Body
        $script:passed++
    }
    catch {
        Write-Host ('FAIL remediation guard ' + $TestName)
        throw
    }
}

function Get-FixtureFailure([scriptblock]$Operation) {
    try {
        $null = & $Operation
    }
    catch {
        return $_
    }
    throw 'The offline guard unexpectedly accepted invalid input.'
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

# Exact offline guard bodies from accepted f0fab80.
if ($Case -eq 'Native') {
    $script:acceptedGuardBodies = [ordered]@{
        # 686b20be320ece5908e69a20a1c91f1917bf212afe0a00abf7a90a52d4029af5
        'Get-ADAnalyzerOperationState' = @'
    param([Parameter(Mandatory)]$Object)
    $enabled = Get-ADAnalyzerOperationValue $Object @('Enabled')
    if ($null -eq $enabled) {
        $uac = Get-ADAnalyzerOperationValue $Object @('UserAccountControl')
        if ($null -ne $uac) {
            $enabled = ([long]$uac -band 2) -eq 0
        }
    }
    [pscustomobject][ordered]@{
        ObjectGuid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $Object @('ObjectGuid'))
        SID = Get-ADAnalyzerOperationSid $Object
        DistinguishedName = [string](Get-ADAnalyzerOperationValue $Object @('DistinguishedName', 'DN'))
        Enabled = $enabled
        WhenChanged = ConvertTo-ADAnalyzerOperationTime (Get-ADAnalyzerOperationValue $Object @('WhenChanged'))
    }
'@
        # e2f72e7450e5801ac32adf0efaa93fd6e940be6642fd847d3ca7e8c5bb9c76ce
        'Get-ADAnalyzerOperationKind' = @'
    param($Object)
    $classes = @(Get-ADAnalyzerOperationValue $Object @('ObjectClass', 'Class'))
    if ($classes -contains 'computer') {
        return 'Computer'
    }
    if ($classes -contains 'group') {
        return 'Group'
    }
    if ($classes -contains 'user') {
        return 'User'
    }
    return 'Unknown'
'@
        # a61e5c30c084bf826c1b53b4b9a0e97a05074a0fd377dec93baf90760e8ff2b3
        'Get-ADAnalyzerOperationExclusion' = @'
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)]$Settings

    )
    $state = Get-ADAnalyzerOperationState $Object
    if (-not $state.ObjectGuid -or $state.SID -notmatch '^S-\d+(?:-\d+)+$' -or -not $state.DistinguishedName -or -not $state.WhenChanged) {
        return 'MissingIdentityOrPreconditions'
    }
    if ($state.Enabled -isnot [bool] -or -not $state.Enabled) {
        return 'AccountNotEnabled'
    }
    $kind = Get-ADAnalyzerOperationKind $Object
    if ($kind -notin @('User', 'Computer')) {
        return 'UnsupportedObjectClass'
    }
    $metadata = [string](Get-ADAnalyzerOperationValue $Object @('SafetyMetadataStatus'))
    if ($metadata -ne 'Collected') {
        return 'MissingSafetyEvidence'
    }
    foreach ($name in @('ProtectedFromAccidentalDeletion', 'IsDomainController')) {
        if ((Get-ADAnalyzerOperationValue $Object @($name)) -isnot [bool]) {
            return 'MissingSafetyEvidence'
        }
    }
    $critical = Get-ADAnalyzerOperationValue $Object @('IsCriticalSystemObject')
    if ($null -ne $critical -and $critical -isnot [bool]) {
        return 'MissingSafetyEvidence'
    }
    if ($null -eq (Get-ADAnalyzerOperationValue $Object @('UserAccountControl')) -or
        $null -eq (Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID'))) {
        return 'MissingSafetyEvidence'
    }
    if ($state.SID -match '^S-1-5-32-' -or
        $state.SID -match '^S-1-5-21-(?:\d+-){3}(500|501|502)$' -or
        [bool](Get-ADAnalyzerOperationValue $Object @('WellKnownSID') $false)) {
        return 'WellKnownAccount'
    }
    $uac = Get-ADAnalyzerOperationValue $Object @('UserAccountControl') 0
    $primary = Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID') 0
    if ([bool](Get-ADAnalyzerOperationValue $Object @('IsDomainController') $false) -or
        ([long]$uac -band 8192) -ne 0 -or
        [int]$primary -in @(516,
            521)) {
        return 'DomainController'
    }
    if ([int](Get-ADAnalyzerOperationValue $Object @('AdminCount') 0) -ne 0) {
        return 'AdminCountProtected'
    }
    if (@(Get-ADAnalyzerOperationValue $Object @('SIDHistory') @() | Where-Object { $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace([string]$_) }).Count) {
        return 'SidHistoryRequiresReview'
    }
    foreach ($name in @('ProtectedFromAccidentalDeletion', 'ProtectedUser', 'Protected', 'IsCriticalSystemObject')) {
        if ([bool](Get-ADAnalyzerOperationValue $Object @($name) $false)) {
            return 'ProtectedOrCriticalObject'
        }
    }
    $membership = Get-ADAnalyzerOperationValue $Object @('Membership')
    $effective = @(Get-ADAnalyzerOperationValue $Object @('TransitiveGroups',
            'EffectiveSids') @()) + @(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
    if (@($effective | Where-Object { $_ -match '^S-1-5-21-(?:\d+-){3}525$' }).Count) {
        return 'ProtectedOrCriticalObject'
    }
    if ([string](Get-ADAnalyzerOperationValue $Object @('PrivilegeResolutionStatus', 'MembershipResolutionStatus')) -ne 'Complete') {
        return 'PrivilegeResolutionIncomplete'
    }
    $privileged = Get-ADAnalyzerOperationValue $Object @('Privileged', 'IsPrivileged')
    if ($privileged -isnot [bool]) {
        return 'PrivilegeResolutionIncomplete'
    }
    if ($privileged -and -not $Settings.IncludePrivilegedAccounts) {
        return 'PrivilegedAccount'
    }
    if ($kind -eq 'User') {
        $accountType = [string](Get-ADAnalyzerOperationValue $Object @('AccountType'))
        if ($accountType -in @('Unknown',
                '') -or
            $accountType -notin @('User',
                'Personal',
                'Human',
                'Service',
                'Non-Personal',
                'gMSA',
                'ManagedServiceAccount')) {
            return 'UnknownAccountClassification'
        }
        if ($accountType -in @('Service', 'Non-Personal', 'gMSA', 'ManagedServiceAccount') -and -not $Settings.IncludeServiceAccounts) {
            return 'ServiceAccount'
        }
    }
    foreach ($excluded in @($Settings.ExcludedObjectGuids)) {
        if ((ConvertTo-ADAnalyzerOperationGuid $excluded) -eq $state.ObjectGuid) {
            return 'ExplicitObjectExclusion'
        }
    }
    foreach ($ou in @($Settings.ExcludedOUs)) {
        if ($ou -and
            ($state.DistinguishedName.Equals([string]$ou,
                [StringComparison]::OrdinalIgnoreCase) -or
            $state.DistinguishedName.EndsWith(',' + [string]$ou,
                [StringComparison]::OrdinalIgnoreCase))) {
            return 'ExcludedOrganizationalUnit'
        }
    }
    return $null
'@
        # 96f805eebc183a0ab2eeeb47e22f85b6237548581513878e7442466c91005f5b
        'Assert-ADAnalyzerOperationPreconditions' = @'
    param(
        $Expected,
        $Actual,
        [bool]$Enabled

    )
    $current = Get-ADAnalyzerOperationState $Actual
    foreach ($name in @('ObjectGuid', 'SID', 'DistinguishedName', 'WhenChanged')) {
        $wanted = Get-ADAnalyzerOperationValue $Expected @($name)
        if ($name -eq 'WhenChanged') {
            $wanted = ConvertTo-ADAnalyzerOperationTime $wanted
        }
        if ($name -eq 'ObjectGuid') {
            $wanted = ConvertTo-ADAnalyzerOperationGuid $wanted
        }
        if (-not $wanted -or [string]$wanted -ine [string]$current.$name) {
            throw "Remediation precondition failed: $name changed or is missing"
        }
    }
    if ($Expected.Enabled -isnot [bool] -or
        $Expected.Enabled -ne $Enabled -or
        $current.Enabled -isnot [bool] -or
        $current.Enabled -ne $Enabled) {
        throw 'Remediation precondition failed: Enabled changed or is missing'
    }
    return $current
'@
        # bcee74ecc72df8e288a39041e3d1b6723547e02b5663618c4c8b745301b862e3
        'Assert-ADAnalyzerOperationPlan' = @'
    param($Plan)
    if ($Plan.PlanType -ne 'ADAnalyzerRemediationPlan' -or -not (ConvertTo-ADAnalyzerOperationGuid $Plan.PlanId)) {
        throw 'Only an explicit ADAnalyzer remediation plan may be executed'
    }
    if ($Plan.Remediation.AllowDisable -isnot [bool] -or -not $Plan.Remediation.AllowDisable) {
        throw 'The plan does not enable account disabling'
    }
    foreach ($name in @('IncludeServiceAccounts', 'IncludePrivilegedAccounts')) {
        if ($Plan.Remediation.$name -isnot [bool]) {
            throw "Invalid plan boolean setting: $name"
        }
    }
    $limit = 0
    if (-not [int]::TryParse([string]$Plan.Remediation.MaximumActions,
            [ref]$limit) -or
        $limit -lt 1 -or
        $limit -gt 1000 -or
        @($Plan.Actions).Count -gt $limit) {
        throw 'Invalid remediation action limit'
    }
    $approved = @(foreach ($value in @($Plan.Remediation.ApprovedObjectGuids)) {
            ConvertTo-ADAnalyzerOperationGuid $value
        })
    $seen = @{}
    $seenActionIds = @{}
    foreach ($action in @($Plan.Actions)) {
        if ($null -eq $action) {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid $action.ObjectGuid
        if ($action.Action -ne 'DisableAccount' -or
            -not $guid -or
            $guid -notin $approved -or
            $action.Preconditions.ObjectGuid -ne $guid -or
            -not ($actionId = ConvertTo-ADAnalyzerOperationGuid $action.ActionId)) {
            throw 'Plan includes an unsupported, unapproved, or unbound action'
        }
        if (($action.RuleId -eq 'ACCOUNT.INACTIVE' -and
                $action.ObjectClass -ne 'User') -or
            ($action.RuleId -eq 'COMPUTER.INACTIVE' -and
            $action.ObjectClass -ne 'Computer') -or
            $action.RuleId -notin @('ACCOUNT.INACTIVE',
                'COMPUTER.INACTIVE')) {
            throw 'Plan rule and object class do not match'
        }
        $days = 0L
        if (-not [long]::TryParse([string]$action.InactivityDays, [ref]$days) -or $days -lt 0) {
            throw 'Plan action is missing its reviewed inactivity threshold'
        }
        if ($seen.ContainsKey($guid)) {
            throw 'Plan contains duplicate object actions'
        }
        if ($seenActionIds.ContainsKey($actionId)) {
            throw 'Plan contains duplicate action IDs'
        }
        $seen[$guid] = $true
        $seenActionIds[$actionId] = $true
    }
'@
    }
}

function Invoke-GuardNativeRoute {
    [CmdletBinding()]
    param([string]$Scenario)

    switch ($Scenario) {
        'StateExplicit' {
            $record = New-GuardRecord
            $record.Enabled = $false
            $record | Add-Member -MemberType ScriptProperty -Name UserAccountControl -Force -Value {
                $script:guardTrace.Add('Unexpected UAC read')
                throw 'An explicit false Enabled must short-circuit UAC.'
            }
            Get-ADAnalyzerOperationState -Object $record
        }
        'KindAliases' {
            Get-ADAnalyzerOperationKind @{ Class = @('User', 'Group', 'Computer') }
            Get-ADAnalyzerOperationKind @{
                ObjectClass = $null
                Class = 'User'
            }
        }
        'ExclusionPriority' {
            $record = New-GuardRecord
            $record.SID = 'invalid fixture SID'
            $record.Enabled = $false
            $record.AdminCount = 1
            Get-ADAnalyzerOperationExclusion -Object $record -Settings (New-GuardSettings)
        }
        'PreconditionsValid' {
            $record = New-GuardRecord
            $expected = $record.PSObject.Copy()
            $expected.ObjectGuid = ([guid]$record.ObjectGuid).ToString('B')
            $expected.WhenChanged = [datetimeoffset]'2026-01-01T00:00:00Z'
            Assert-ADAnalyzerOperationPreconditions $expected $record $true
        }
        'BadUac' {
            $record = New-GuardRecord
            $record.Enabled = $null
            $record.UserAccountControl = 'nonnumeric UAC fixture'
            Get-ADAnalyzerOperationState $record
        }
        'BadExclusionEvidence' {
            $record = New-GuardRecord
            $record | Add-Member -MemberType ScriptProperty -Name AdminCount -Force -Value {
                $script:guardTrace.Add('Read AdminCount')
                return 'nonnumeric evidence fixture'
            }
            Get-ADAnalyzerOperationExclusion $record (New-GuardSettings)
        }
        'PreconditionPriority' {
            $record = New-GuardRecord
            $expected = $record.PSObject.Copy()
            $expected.SID = 'S-1-5-21-1-2-3-9999'
            $expected.DistinguishedName = 'CN=Different,DC=offline,DC=invalid'
            $expected.Enabled = 'true'
            Assert-ADAnalyzerOperationPreconditions $expected $record $true
        }
        'BadPlanBool' {
            $plan = New-GuardPlan
            $plan.Remediation.IncludeServiceAccounts = 'false'
            Assert-ADAnalyzerOperationPlan $plan
        }
        'BadPlanStructure' {
            $plan = New-GuardPlan
            $plan.Actions[0].Preconditions.ObjectGuid = '99999999-9999-9999-9999-999999999999'
            Assert-ADAnalyzerOperationPlan $plan
        }
        'DuplicateAction' {
            $plan = New-GuardPlan
            $plan.Actions[1].ActionId = ([guid]$plan.Actions[0].ActionId).ToString('B').ToUpperInvariant()
            Assert-ADAnalyzerOperationPlan $plan
        }
    }
}

function Invoke-GuardNativeObservation([string]$Scenario, [string]$Action) {
    $script:guardTrace = [Collections.Generic.List[string]]::new()
    $records = [Collections.Generic.List[object]]::new()
    $seen = [Collections.ArrayList]::new()
    $caught = $null
    $completed = $false
    $ErrorActionPreference = 'Stop'
    $Error.Clear()
    try {
        Invoke-GuardNativeRoute -Scenario $Scenario -ErrorAction $Action -ErrorVariable +seen *>&1 |
            ForEach-Object {
                $records.Add($_)
            }
        $completed = $true
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    $report = [ordered]@{
        Completed = $completed
        Caught = Get-FixtureDiagnostic $caught
        Captured = Get-FixtureDiagnostic $seen
        History = Get-FixtureDiagnostic $history
        Trace = $script:guardTrace.ToArray()
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
    return (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $report -Depth 22 -Compress)
}

function Assert-GuardNativeParity([string]$Scenario, [string]$Action) {
    $originals = [ordered]@{}
    try {
        foreach ($name in $script:acceptedGuardBodies.Keys) {
            $path = 'Function:script:' + $name
            $originals[$name] = (Get-Command $name -CommandType Function).ScriptBlock
            $accepted = [scriptblock]::Create($script:acceptedGuardBodies[$name])
            Set-Item -LiteralPath $path -Value $accepted
            $active = (Get-Command $name -CommandType Function).ScriptBlock
            Assert-Fixture ($active.ToString() -ceq $accepted.ToString()) ('Failed to install archived ' + $name + '.')
        }
        $expected = Invoke-GuardNativeObservation $Scenario $Action
    }
    finally {
        foreach ($name in $originals.Keys) {
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $originals[$name]
        }
    }
    foreach ($name in $originals.Keys) {
        $active = (Get-Command $name -CommandType Function).ScriptBlock
        Assert-Fixture ($active.ToString() -ceq $originals[$name].ToString()) ('Failed to restore candidate ' + $name + '.')
    }

    $faults = @{
        BadUac = 'InvalidCastFromStringToInteger'
        PreconditionPriority = 'Remediation precondition failed: SID'
        BadPlanBool = 'Invalid plan boolean setting: IncludeServiceAccounts'
        BadPlanStructure = 'Plan includes an unsupported, unapproved, or unbound action'
        DuplicateAction = 'Plan contains duplicate action IDs'
    }
    if ($Scenario -eq 'BadExclusionEvidence') {
        $witness = ConvertFrom-Json -InputObject $expected
        $referenceCast = Get-FixtureFailure { [int]'nonnumeric cast control' }
        $castId = ($referenceCast.FullyQualifiedErrorId -split ',', 2)[0]
        $diagnostics = @($witness.History.Entries) + @($witness.Caught) + @($witness.Stream)
        $observedCast = $false
        foreach ($diagnostic in $diagnostics) {
            if ($null -ne $diagnostic -and $diagnostic.Id -and
                ($diagnostic.Id -split ',', 2)[0] -ceq $castId) {
                $observedCast = $true
                break
            }
        }
        Assert-Fixture ($observedCast -and ($witness.Trace -join ',') -ceq 'Read AdminCount') (
            "The archived helper did not read AdminCount once and record the native cast ${castId} with ErrorAction=$Action." +
            [Environment]::NewLine + $expected
        )
    }
    elseif ($faults.ContainsKey($Scenario)) {
        if ($Action -ne 'Ignore') {
            Assert-Fixture ($expected.Contains($faults[$Scenario])) ('The archived helper did not reach ' + $Scenario + '.')
        }
    }
    else {
        $witness = ConvertFrom-Json -InputObject $expected
        Assert-Fixture (
            $witness.Completed -and $null -eq $witness.Caught -and @($witness.Trace).Count -eq 0
        ) ('An archived success control failed or evaluated an unneeded getter for ' + $Scenario + '.')
        if ($Scenario -eq 'KindAliases') {
            Assert-Fixture (($witness.Stream.Value -join ',') -ceq 'Computer,Unknown') 'The legacy kind control did not reach both alias shapes.'
        }
        else {
            Assert-Fixture ($witness.Stream.Count -eq 1) ('Unexpected archived control output for ' + $Scenario + '.')
        }
    }
    $actual = Invoke-GuardNativeObservation $Scenario $Action
    Assert-Fixture ($actual -ceq $expected) (
        "Native guard changed for $Scenario with ErrorAction=$Action." + [Environment]::NewLine +
        'Accepted: ' + $expected + [Environment]::NewLine + 'Current: ' + $actual
    )
}


function Assert-GuardFailure([scriptblock]$Operation, [string]$Message) {
    $failure = Get-FixtureFailure $Operation
    Assert-Fixture (
        $failure.Exception.GetBaseException().Message -like ('*' + $Message + '*')
    ) ('Unexpected guard diagnostic: ' + $failure)
}

function Invoke-GuardDirectFixtures {
    foreach ($name in @(
            'Get-ADAnalyzerOperationState', 'Get-ADAnalyzerOperationKind', 'Get-ADAnalyzerOperationExclusion',
            'Assert-ADAnalyzerOperationPreconditions', 'Assert-ADAnalyzerOperationPlan'
        )) {
        Set-Item -LiteralPath ('Function:script:' + $name) -Value {
            throw 'The direct guard called a retained compatibility command.'
        }
    }
    $guard = [ADAnalyzerRemediationGuard]::new()

    Test-Fixture 'state normalizes identities and preserves typed Enabled fallback' {
        $guid = [guid]'1234abcd-1234-4556-8687-98abcdef0123'
        $record = [ordered]@{
            ObjectGuid = $guid.ToString('B').ToUpperInvariant()
            ObjectSid = [pscustomobject]@{
                Value = 'S-1-5-21-1-2-3-1101'
            }
            DN = 'CN=Fixture,DC=offline,DC=invalid'
            Enabled = $null
            UserAccountControl = 514
            WhenChanged = [datetimeoffset]'2026-01-01T02:00:00+02:00'
        }
        $before = ConvertTo-Json -InputObject $record -Depth 12 -Compress
        $state = $guard.ReadState($record)
        Assert-Fixture (
            ($state.PSObject.Properties.Name -join ',') -ceq 'ObjectGuid,SID,DistinguishedName,Enabled,WhenChanged' -and
            $state.ObjectGuid -ceq $guid.ToString('D') -and $state.SID -ceq $record.ObjectSid.Value -and
            $state.DistinguishedName -ceq $record.DN -and $state.WhenChanged -ceq '2026-01-01T00:00:00.0000000Z' -and
            $state.Enabled -is [bool] -and -not $state.Enabled -and
            (ConvertTo-Json -InputObject $record -Depth 12 -Compress) -ceq $before
        ) 'ReadState changed identity, ordered output, the fallback type, or its input.'
        $record.Enabled = 'false'
        $record.UserAccountControl = 'unused numeric fallback'
        $state = $guard.ReadState($record)
        Assert-Fixture (
            $state.Enabled -is [string] -and $state.Enabled -ceq 'false'
        ) 'ReadState coerced an explicitly supplied Enabled value.'
    }

    Test-Fixture 'object kind preserves class precedence and aliases' {
        Assert-Fixture (
            $guard.GetObjectKind(@{ Class = @('User', 'Group', 'Computer') }) -ceq 'Computer' -and
            $guard.GetObjectKind(@{ ObjectClass = @('user', 'group') }) -ceq 'Group' -and
            $guard.GetObjectKind(@{ Class = 'USER' }) -ceq 'User' -and
            $guard.GetObjectKind(@{
                ObjectClass = $null
                Class = 'User'
            }) -ceq 'Unknown' -and
            $guard.GetObjectKind(@{ ObjectClass = 'not a class' }) -ceq 'Unknown'
        ) 'GetObjectKind changed classification precedence or fallback behavior.'
    }

    Test-Fixture 'exclusion reasons preserve their order and ordinary eligible shape' {
        $settings = New-GuardSettings
        $record = New-GuardRecord
        Assert-Fixture (
            $null -eq $guard.GetExclusion($record, $settings)
        ) 'The ordinary control acquired an exclusion.'
        $scenarios = @(
            @{
                Field = 'Enabled'
                Value = 'true'
                Reason = 'AccountNotEnabled'
            }
            @{
                Field = 'ObjectClass'
                Value = 'group'
                Reason = 'UnsupportedObjectClass'
            }
            @{
                Field = 'SafetyMetadataStatus'
                Value = 'Unknown'
                Reason = 'MissingSafetyEvidence'
            }
            @{
                Field = 'SID'
                Value = 'S-1-5-21-1-2-3-500'
                Reason = 'WellKnownAccount'
            }
            @{
                Field = 'IsDomainController'
                Value = $true
                Reason = 'DomainController'
            }
            @{
                Field = 'AdminCount'
                Value = 1
                Reason = 'AdminCountProtected'
            }
            @{
                Field = 'SIDHistory'
                Value = @('S-1-5-21-1-2-3-1100')
                Reason = 'SidHistoryRequiresReview'
            }
            @{
                Field = 'ProtectedFromAccidentalDeletion'
                Value = $true
                Reason = 'ProtectedOrCriticalObject'
            }
            @{
                Field = 'PrivilegeResolutionStatus'
                Value = 'Unknown'
                Reason = 'PrivilegeResolutionIncomplete'
            }
            @{
                Field = 'Privileged'
                Value = $true
                Reason = 'PrivilegedAccount'
            }
            @{
                Field = 'AccountType'
                Value = 'Unknown'
                Reason = 'UnknownAccountClassification'
            }
            @{
                Field = 'AccountType'
                Value = 'Service'
                Reason = 'ServiceAccount'
            }
        )
        foreach ($scenario in $scenarios) {
            $record = New-GuardRecord
            $record.($scenario.Field) = $scenario.Value
            $observed = $guard.GetExclusion($record, $settings)
            Assert-Fixture ($observed -ceq $scenario.Reason) ('Wrong exclusion for ' + $scenario.Field + '.')
        }
        $record = New-GuardRecord
        $settings.ExcludedObjectGuids = @($record.ObjectGuid)
        $settings.ExcludedOUs = @('ou=people,dc=offline,dc=invalid')
        Assert-Fixture (
            $guard.GetExclusion($record, $settings) -ceq 'ExplicitObjectExclusion'
        ) 'The explicit object exclusion lost priority over the OU.'
        $settings.ExcludedObjectGuids = @()
        Assert-Fixture (
            $guard.GetExclusion($record, $settings) -ceq 'ExcludedOrganizationalUnit'
        ) 'The OU exclusion did not match its full suffix.'
        $record.WhenChanged = $null
        $record.Enabled = $false
        $record.AdminCount = 1
        Assert-Fixture (
            $guard.GetExclusion($record, $settings) -ceq 'MissingIdentityOrPreconditions'
        ) 'Later exclusions replaced earlier missing identity evidence.'
    }

    Test-Fixture 'preconditions preserve both enabled states and earliest diagnostic' {
        foreach ($enabled in $true, $false) {
            $record = New-GuardRecord
            $record.Enabled = $enabled
            $expected = $record.PSObject.Copy()
            $expected.ObjectGuid = ([guid]$record.ObjectGuid).ToString('B')
            $expected.WhenChanged = [datetimeoffset]'2026-01-01T00:00:00Z'
            $read = $guard.AssertPreconditions($expected, $record, $enabled)
            Assert-Fixture (
                $read.Enabled -is [bool] -and $read.Enabled -eq $enabled -and
                $read.WhenChanged -ceq '2026-01-01T00:00:00.0000000Z'
            ) 'Valid preconditions changed canonical state or polarity.'

            $expected.Enabled = [string]$enabled
            Assert-GuardFailure {
                $guard.AssertPreconditions($expected, $record, $enabled)
            } 'Enabled changed or is missing'
            $expected.SID = 'different SID fixture'
            $expected.DistinguishedName = 'CN=Other,DC=offline,DC=invalid'
            Assert-GuardFailure {
                $guard.AssertPreconditions($expected, $record, $enabled)
            } 'SID changed or is missing'
        }
    }

    Test-Fixture 'valid plan validation is silent, bounded and nonmutating' {
        $plan = New-GuardPlan
        foreach ($validLimit in 2, 1000) {
            $plan.Remediation.MaximumActions = $validLimit
            $before = ConvertTo-Json -InputObject $plan -Depth 15 -Compress
            $output = @($guard.AssertPlan($plan))
            Assert-Fixture (
                $output.Count -eq 0 -and (ConvertTo-Json -InputObject $plan -Depth 15 -Compress) -ceq $before
            ) 'Valid plan validation emitted output or changed supplied plan fields.'
        }
        foreach ($invalidLimit in 0, 1, 1001, 'nonnumeric fixture limit') {
            $plan.Remediation.MaximumActions = $invalidLimit
            Assert-GuardFailure { $guard.AssertPlan($plan) } 'Invalid remediation action limit'
        }
        $plan.Actions = @()
        $plan.Remediation.MaximumActions = 1
        Assert-Fixture (@($guard.AssertPlan($plan)).Count -eq 0) 'The empty bounded plan changed its accepted validation contract.'
    }

    Test-Fixture 'plan structure and direct settings require real boolean evidence' {
        $malformed = [ordered]@{
            String = 'false'
            Number = 1
            Null = $null
            SingletonArray = [bool[]]@($true)
        }
        foreach ($flag in 'IncludePrivilegedAccounts', 'IncludeServiceAccounts') {
            foreach ($shape in $malformed.Keys) {
                $settings = New-GuardSettings
                $settings[$flag] = $malformed[$shape]
                $record = New-GuardRecord
                $record.Privileged = $true
                $record.AccountType = 'Service'
                $null = Get-FixtureFailure {
                    $guard.GetExclusion($record, $settings)
                }
            }
        }
        $plan = New-GuardPlan
        $plan.Remediation.AllowDisable = 'true'
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'The plan does not enable account disabling'
        $plan = New-GuardPlan
        $plan.Remediation.IncludeServiceAccounts = 'false'
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Invalid plan boolean setting: IncludeServiceAccounts'
        $plan = New-GuardPlan
        $plan.Remediation.ApprovedObjectGuids = @($plan.Actions[1].ObjectGuid)
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Plan includes an unsupported, unapproved, or unbound action'
        $plan = New-GuardPlan
        $plan.Actions[0].InactivityDays = -1
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Plan action is missing its reviewed inactivity threshold'
        $plan = New-GuardPlan
        $plan.Actions[0].ObjectClass = 'Computer'
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Plan rule and object class do not match'
    }

    Test-Fixture 'canonical duplicate actions and object precedence stay distinct' {
        $plan = New-GuardPlan
        $plan.Actions[1].ActionId = ([guid]$plan.Actions[0].ActionId).ToString('B').ToUpperInvariant()
        $before = ConvertTo-Json -InputObject $plan -Depth 15 -Compress
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Plan contains duplicate action IDs'
        Assert-Fixture (
            (ConvertTo-Json -InputObject $plan -Depth 15 -Compress) -ceq $before
        ) 'Validation rewrote a submitted identity.'
        $plan.Actions[1].ObjectGuid = $plan.Actions[0].ObjectGuid
        $plan.Actions[1].Preconditions.ObjectGuid = $plan.Actions[0].ObjectGuid
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Plan contains duplicate object actions'
        $plan.Actions[1].ActionId = 'bad fixture identity'
        Assert-GuardFailure { $guard.AssertPlan($plan) } 'Plan includes an unsupported, unapproved, or unbound action'
    }
}

switch ($Case) {
    'Native' {
        foreach ($scenario in 'StateExplicit', 'KindAliases', 'ExclusionPriority', 'PreconditionsValid') {
            Test-Fixture $scenario {
                Assert-GuardNativeParity $scenario 'Stop'
            }
        }
        $faults = @(
            'BadUac', 'BadExclusionEvidence', 'PreconditionPriority',
            'BadPlanBool', 'BadPlanStructure', 'DuplicateAction'
        )
        foreach ($scenario in $faults) {
            foreach ($action in 'Continue', 'Stop') {
                Test-Fixture ($scenario + ' ' + $action) {
                    Assert-GuardNativeParity $scenario $action
                }
            }
        }
        foreach ($scenario in 'BadUac', 'BadPlanStructure') {
            foreach ($action in 'SilentlyContinue', 'Ignore') {
                Test-Fixture ($scenario + ' ' + $action) {
                    Assert-GuardNativeParity $scenario $action
                }
            }
        }
    }

    'Construction' {
        Test-Fixture 'literal constructor is inert after the documented loader' {
            function script:Test-Path {
                throw 'The offline guard constructor touched a path.'
            }
            function script:Read-ADAnalyzerOperationDocument {
                throw 'The offline guard constructor read a document.'
            }
            $first = [ADAnalyzerRemediationGuard]::new()
            $second = [ADAnalyzerRemediationGuard]::new()
            Assert-Fixture (
                $first.GetType().Name -ceq 'ADAnalyzerRemediationGuard' -and
                -not [object]::ReferenceEquals($first, $second)
            ) 'The documented loader did not expose an inert literal constructor.'
        }
        Test-Fixture 'documented guard methods expose the intended operation contracts' {
            $type = [ADAnalyzerRemediationGuard]
            $preconditions = $type.GetMethod('AssertPreconditions')
            $plan = $type.GetMethod('AssertPlan')
            Assert-Fixture (
                $null -ne $type.GetMethod('ReadState', [type[]]@([object])) -and
                $null -ne $type.GetMethod('GetObjectKind', [type[]]@([object])) -and
                $null -ne $type.GetMethod('GetExclusion') -and $null -ne $preconditions -and
                $preconditions.GetParameters()[2].ParameterType -eq [bool] -and
                $null -ne $plan -and $plan.ReturnType -eq [void]
            ) 'A documented guard method or signature is missing.'
        }
    }

    'Standalone' {
        Test-Fixture 'the operations file validates an ordinary local plan by itself' {
            $guard = [ADAnalyzerRemediationGuard]::new()
            Assert-Fixture (
                @($guard.AssertPlan((New-GuardPlan))).Count -eq 0 -and
                $guard.ReadState((New-GuardRecord)).Enabled -eq $true
            ) 'The operations file requires the full loader for offline validation.'
        }
    }

    'Direct' {
        Invoke-GuardDirectFixtures
    }

    'Isolation' {
        Test-Fixture 'separate and reused guards retain no prior state or rejection' {
            $first = [ADAnalyzerRemediationGuard]::new()
            $second = [ADAnalyzerRemediationGuard]::new()
            $record = New-GuardRecord
            $prior = $first.ReadState($record)
            $record.Enabled = $false
            $plan = New-GuardPlan
            $plan.Remediation.MaximumActions = 0
            Assert-GuardFailure { $first.AssertPlan($plan) } 'Invalid remediation action limit'
            $plan.Remediation.MaximumActions = 2
            Assert-Fixture (
                @($first.AssertPlan($plan)).Count -eq 0 -and $prior.Enabled -eq $true -and
                $second.ReadState($record).Enabled -eq $false -and $first.ReadState($record).Enabled -eq $false
            ) 'Reusing the guard carried forward supplied data or a failure.'
        }

        Test-Fixture 'secondary runspace disposal preserves offline decisions' {
            $guard = [ADAnalyzerRemediationGuard]::new()
            $worker = [powershell]::Create()
            try {
                $snippet = @'
param($Root)
$ErrorActionPreference = 'Stop'
. (Join-Path $Root 'bin/ADOperations.ps1')
[ADAnalyzerRemediationGuard]::new().GetObjectKind(@{ ObjectClass = 'Computer' })
'@
                $rows = @($worker.AddScript($snippet).AddArgument($RepositoryRoot).Invoke())
                Assert-Fixture (
                    $rows.Count -eq 1 -and [string]$rows[0] -ceq 'Computer' -and $worker.Streams.Error.Count -eq 0
                ) ('Secondary guard failed: ' + ($worker.Streams.Error -join [Environment]::NewLine))
            }
            finally {
                $worker.Dispose()
            }
            Assert-Fixture (
                $guard.GetObjectKind((New-GuardRecord)) -ceq 'User' -and @($guard.AssertPlan((New-GuardPlan))).Count -eq 0
            ) 'Disposing the secondary runspace changed an offline decision.'
        }
    }
}
'PASS remediation guard ' + $Case + ' ' + $script:passed
