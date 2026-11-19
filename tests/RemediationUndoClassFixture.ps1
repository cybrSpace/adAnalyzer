[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
$script:passed = 0
$script:trace = [Collections.Generic.List[string]]::new()
$script:server = 'selected.fixture.invalid'
$script:domainSid = 'S-1-5-21-10-20-30'
$script:mode = $Case
$script:expectedDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:allowProvider = $false
$script:fault = $null

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

foreach ($name in @('Invoke-Command', 'New-PSDrive', 'Get-ADRootDSE', 'Get-ADDomain', 'Disable-ADAccount')) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'The synthetic Undo fixture encountered an external effect.'
    }
}

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
        Write-Host ('FAIL remediation undo ' + $Name)
        throw
    }
}

function Assert-FixtureFailure([scriptblock]$Body, [string]$Pattern = '') {
    $failure = $null
    $output = [Collections.Generic.List[object]]::new()
    try {
        & $Body | ForEach-Object { $output.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-Fixture (
        $null -ne $failure -and (-not $Pattern -or $failure.Exception.Message -match $Pattern)
    ) ('Unexpected Apply error: ' + $failure)
    Assert-Fixture ($output.Count -eq 0) 'A failed object call emitted a result.'
}

function ConvertTo-FixtureJson([object]$Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Compress -Depth 35
}

function Read-FixtureJournal {
    [IO.File]::ReadAllText($script:path) | Microsoft.PowerShell.Utility\ConvertFrom-Json
}

function Assert-LiveFixtureLease {
    $marker = $script:path + '.lock'
    Assert-Fixture ([IO.File]::Exists($marker)) 'A provider stage ran before acquiring the local journal marker.'
    $entrant = $null
    $blocked = $false
    try {
        $entrant = [IO.File]::Open($marker, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] {
        $blocked = $true
    }
    finally {
        if ($null -ne $entrant) {
            $entrant.Dispose()
        }
    }
    Assert-Fixture $blocked 'A provider stage ran without exclusive local journal ownership.'
}

function Assert-FixtureLeaseReleased {
    $marker = [IO.FileInfo]::new($script:path + '.lock')
    Assert-Fixture ($marker.Exists -and $marker.Length -eq 0) 'The approved run lost the empty lease marker.'
    $reacquired = [IO.File]::Open($marker.FullName, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $reacquired.Dispose()
    $files = @([IO.Directory]::GetFiles($script:root) | ForEach-Object { [IO.Path]::GetFileName($_) })
    $journalName = [IO.Path]::GetFileName($script:path)
    Assert-Fixture (
        @($files | Where-Object { $_ -notin ($journalName, ($journalName + '.lock')) }).Count -eq 0
    ) 'The failed or completed invocation left staging files.'
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

# Exact native Undo body from accepted 37d5041.
# 2a96169c890d798b7399aa293c9f86b7493edd4ae7a3d474b1496e854dc9b722
$script:acceptedUndoBody = @'
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][string]$Server,
        [pscredential]$Credential = [pscredential]::Empty

    )
    $JournalPath = Resolve-ADAnalyzerOperationFilePath $JournalPath
    $journal = Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
    if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server) {
        throw 'Journal type/server does not match this undo request'
    }
    $connection = Get-ADAnalyzerOperationConnection $Server $Credential
    $lease = $null
    try {
        foreach ($candidate in @($journal.Entries | Where-Object { $_.Action -eq 'DisableAccount' -and $_.Status -eq 'Succeeded' })) {
            if (-not $PSCmdlet.ShouldProcess($candidate.DistinguishedName, 'Undo a journaled account disable')) {
                [pscustomobject]@{
                    EntryId = $candidate.EntryId
                    ObjectGuid = $candidate.ObjectGuid
                    Status = 'Skipped'
                }
                continue
            }
            if ($null -eq $lease) {
                $reviewedJournalId = [string](Get-ADAnalyzerOperationValue $journal @('JournalId'))
                $reviewedPlanId = [string](Get-ADAnalyzerOperationValue $journal @('PlanId'))
                $lease = Enter-ADAnalyzerJournalLease $JournalPath
                $journal = Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
                if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server) {
                    throw 'Journal type/server does not match this undo request'
                }
                $ownedJournalId = [string](Get-ADAnalyzerOperationValue $journal @('JournalId'))
                $ownedPlanId = [string](Get-ADAnalyzerOperationValue $journal @('PlanId'))
                if ($ownedJournalId -ine $reviewedJournalId -or $ownedPlanId -ine $reviewedPlanId) {
                    throw 'Journal identity changed after undo review'
                }
                $plan = [pscustomobject]@{
                    Remediation = $journal.Remediation
                    PrivilegedSids = $journal.PrivilegedSids
                    AccountClassification = $journal.AccountClassification
                }
            }
            $matching = @($journal.Entries | Where-Object { $_.EntryId -eq $candidate.EntryId })
            if (-not $candidate.EntryId -or $matching.Count -ne 1) {
                throw 'Journal entry identity is missing or ambiguous'
            }
            $entry = $matching[0]
            if ($entry.Action -ne 'DisableAccount' -or $entry.Status -ne 'Succeeded') {
                continue
            }
            foreach ($name in 'ActionId', 'ObjectGuid', 'SID', 'DistinguishedName') {
                $reviewedValue = [string](Get-ADAnalyzerOperationValue $candidate @($name))
                $ownedValue = [string](Get-ADAnalyzerOperationValue $entry @($name))
                if ($ownedValue -ine $reviewedValue) {
                    throw 'Journal entry identity changed after undo review'
                }
            }
            try {
                if ($entry.Before.Enabled -ne $true -or $entry.After.Enabled -ne $false) {
                    throw 'Journal does not contain a reversible enabled-to-disabled transition'
                }
                $approved = @(foreach ($value in @($journal.Remediation.ApprovedObjectGuids)) {
                        ConvertTo-ADAnalyzerOperationGuid $value
                    })
                if ($entry.ObjectGuid -notin $approved -or
                    $entry.ObjectGuid -ne $entry.Before.ObjectGuid -or
                    $entry.ObjectGuid -ne $entry.After.ObjectGuid -or
                    $entry.SID -ne $entry.Before.SID -or
                    $entry.SID -ne $entry.After.SID) {
                    throw 'Journal entry identity is not bound to an approved reversible action'
                }
                $current = Get-ADAnalyzerOperationCurrentObject $entry.ObjectGuid $connection $plan
                $state = Assert-ADAnalyzerOperationPreconditions $entry.After $current $false
                Assert-ADAnalyzerOperationPrivilege $current $entry $plan $connection
                $entry.Undo = [pscustomobject]@{
                    Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                    Status = 'Prepared'
                    Before = $state
                    After = $null
                    Message = $null
                }
                Save-ADAnalyzerOperationJournal $journal $JournalPath
                Enable-ADAccount -Identity ([guid]$entry.ObjectGuid) @connection -WhatIf:$false -Confirm:$false
                $after = Get-ADAnalyzerOperationCurrentObject $entry.ObjectGuid $connection $plan
                $entry.Undo.After = Get-ADAnalyzerOperationState $after
                if ($entry.Undo.After.ObjectGuid -ne $entry.Before.ObjectGuid -or
                    $entry.Undo.After.SID -ne $entry.Before.SID -or
                    $entry.Undo.After.DistinguishedName -ine $entry.Before.DistinguishedName -or
                    $entry.Undo.After.Enabled -isnot [bool] -or
                    -not $entry.Undo.After.Enabled) {
                    throw 'Unable to verify the account enable result'
                }
                $entry.Undo.Status = 'Succeeded'
                $entry.Status = 'Undone'
                Save-ADAnalyzerOperationJournal $journal $JournalPath
            }
            catch {
                $failure = $_
                if ($entry.Undo) {
                    $entry.Undo.Status = 'Failed'
                    $entry.Undo.Message = $failure.Exception.Message
                }
                else {
                    $entry.Undo = [pscustomobject]@{
                        Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                        Status = 'Rejected'
                        Before = $null
                        After = $null
                        Message = $failure.Exception.Message
                    }
                }
                try {
                    Save-ADAnalyzerOperationJournal $journal $JournalPath
                }
                catch {
                    throw ('Undo journal persistence failed; no further changes were attempted. ' + $failure.Exception.Message + '; ' + $_.Exception.Message)
                }
                throw $failure
            }
            ConvertTo-ADAnalyzerSafeData $entry
        }
    }
    finally {
        if ($null -ne $lease) {
            $lease.Dispose()
        }
    }
'@

function New-FixtureInput([string]$Name, [string]$Fault = '', [bool]$UseCredential = $true) {
    $script:trace = [Collections.Generic.List[string]]::new()
    $script:allowProvider = $false
    $script:fault = $Fault
    $script:faultIndex = 1
    $script:credential = [pscredential]::new('fixture', [Security.SecureString]::new())
    $script:expectCredential = $UseCredential
    $script:objects = @{}
    $script:entriesById = @{}
    $script:root = Join-Path $script:temporary $Name
    $null = [IO.Directory]::CreateDirectory($script:root)
    $script:path = Join-Path $script:root 'journal [undo].json'
    $accounts = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($number in 1..3) {
        $id = [guid]('20000000-0000-4000-8000-00000000000' + $number)
        $record = [pscustomobject][ordered]@{
            Number = $number
            ObjectGuid = $id.ToString('D')
            SID = $script:domainSid + '-' + (2100 + $number)
            DistinguishedName = 'CN=Fixture' + $number + ',OU=People,DC=offline,DC=invalid'
            ObjectClass = 'User'
            AccountType = 'User'
            Enabled = $true
            UserAccountControl = 512
            WhenChanged = [datetime]'2025-01-01T00:00:00Z'
            WhenCreated = [datetime]'2000-01-01T00:00:00Z'
            LastLogonTimestamp = 0
            LastLogon = $null
            AdminCount = 0
            ProtectedFromAccidentalDeletion = $false
            Privileged = $false
            PrivilegeResolutionStatus = 'Complete'
            IsCriticalSystemObject = $false
            IsDomainController = $false
            PrimaryGroupID = 513
            SafetyMetadataStatus = 'Collected'
            SIDHistory = @()
            MemberOf = @()
        }
        $accounts.Add($record)
        $findings.Add([pscustomobject]@{
                RuleId = 'ACCOUNT.INACTIVE'
                Status = 'Fail'
                Target = $record.DistinguishedName
                ObjectGuid = $record.ObjectGuid
                SID = $record.SID
                Suppressed = $false
            })
        $script:objects[$id] = $record
    }
    $assessment = @{
        SchemaVersion = 1
        RunId = 'offline-undo-fixture'
        Context = @{ Server = $script:server }
        Objects = $accounts.ToArray()
        Findings = $findings.ToArray()
    }
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Remediation.AllowDisable = $true
    $profile.Remediation.MaximumActions = 3
    $profile.Remediation.ApprovedObjectGuids = @($accounts | ForEach-Object ObjectGuid)
    $profile.AccountClassification.UserGroups = @($script:domainSid + '-513')
    $planner = [ADAnalyzerRemediationPlanner]::new()
    $plan = $planner.CreatePlan($assessment, $profile)
    Assert-Fixture ($plan.Actions.Count -eq 3) 'The fixture did not produce a reviewed plan.'
    $guard = [ADAnalyzerRemediationGuard]::new()
    $entries = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $plan.Actions.Count; $index++) {
        $action = $plan.Actions[$index]
        $record = $script:objects[[guid]$action.ObjectGuid]
        $record.Enabled = $false
        $record.UserAccountControl = 514
        $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
        $entry = [pscustomobject][ordered]@{
            EntryId = '40000000-0000-4000-8000-00000000000' + ($index + 1)
            ActionId = '30000000-0000-4000-8000-00000000000' + ($index + 1)
            Action = 'DisableAccount'
            ObjectGuid = $action.ObjectGuid
            SID = $action.SID
            DistinguishedName = $action.DistinguishedName
            ObjectClass = $action.ObjectClass
            AccountType = $action.AccountType
            InactivityDays = $action.InactivityDays
            Timestamp = '2025-01-01T00:00:01.0000000+00:00'
            Status = 'Succeeded'
            Before = $action.Preconditions
            After = $guard.ReadState($record)
            Message = $null
            Undo = $null
        }
        $entries.Add($entry)
        $script:entriesById[[guid]$entry.ObjectGuid] = $entry
    }
    return [pscustomobject][ordered]@{
        SchemaVersion = 1
        JournalType = 'ADAnalyzerRemediationJournal'
        JournalId = '50000000-0000-4000-8000-000000000000'
        PlanId = '11111111-1111-4111-8111-111111111111'
        Server = $script:server
        CreatedAt = '2025-01-01T00:00:00.0000000+00:00'
        UpdatedAt = '2025-01-01T00:00:01.0000000+00:00'
        Remediation = $plan.Remediation
        PrivilegedSids = @($plan.PrivilegedSids)
        AccountClassification = $plan.AccountClassification
        Entries = $entries.ToArray()
    }
}

function Save-FixtureSeed([object]$Journal) {
    [IO.File]::WriteAllText($script:path, (ConvertTo-FixtureJson $Journal), [Text.UTF8Encoding]::new($false))
    return [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:path))
}

function Assert-PinnedProvider($Bound) {
    Assert-Fixture (
        $Bound.Server -ceq $script:server -and [string]$Bound.ErrorAction -ceq 'Stop' -and
        $Bound.ContainsKey('Credential') -eq $script:expectCredential -and
        (-not $script:expectCredential -or [object]::ReferenceEquals($Bound.Credential, $script:credential))
    ) 'The synthetic Undo command did not receive the exact selected server and credential.'
    Assert-LiveFixtureLease
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru)

    $script:trace.Add('Import')
    Assert-Fixture (
        $script:allowProvider -and
        [IO.Path]::IsPathRooted($Name) -and [IO.Path]::GetFullPath($Name) -ceq $script:expectedDll -and
        $Scope -ceq 'Local' -and $PassThru -and [string]$PSBoundParameters['ErrorAction'] -ceq 'Stop'
    ) 'Undo tried a provider other than the operation-local bundled import.'
    Assert-LiveFixtureLease
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = @{
            'Get-ADObject' = Get-Command Get-FixtureBundledObject -CommandType Function
            'Get-ADGroup' = Get-Command Get-FixtureBundledGroup -CommandType Function
            'Enable-ADAccount' = Get-Command Enable-FixtureBundledAccount -CommandType Function
        }
    }
}

function Read-FixtureObject([guid]$Identity, $Bound) {
    Assert-PinnedProvider $Bound
    Assert-Fixture ($script:objects.ContainsKey($Identity)) 'The synthetic provider received an unreviewed object identity.'
    $properties = 'objectGUID,objectSid,distinguishedName,userAccountControl,whenChanged,whenCreated,lastLogonTimestamp,lastLogon,sIDHistory,adminCount,isCriticalSystemObject,ProtectedFromAccidentalDeletion,memberOf,primaryGroupID,sAMAccountName'
    Assert-Fixture (($Bound.Properties -join ',') -ceq $properties) 'Undo changed the requested fresh evidence.'
    $record = $script:objects[$Identity]
    $script:trace.Add('Read:' + $record.Number)
    return $record.PSObject.Copy()
}

function Read-FixtureGroups($Bound) {
    Assert-PinnedProvider $Bound
    Assert-Fixture (
        $Bound.Filter -ceq '*' -and ($Bound.Properties -join ',') -ceq 'members,memberOf,primaryGroupToken,SID'
    ) 'Undo changed the group evidence binding.'
    $script:trace.Add('Group')
    [pscustomobject]@{
        SID = $script:domainSid + '-513'
        DistinguishedName = 'CN=Fixture Ordinary Group,DC=offline,DC=invalid'
        PrimaryGroupToken = 513
        Members = @()
        MemberOf = @()
    }
}

function Confirm-FixtureUndoPrepared([guid]$Identity, $Bound) {
    Assert-PinnedProvider $Bound
    Assert-Fixture (
        $Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and -not $Bound.WhatIf -and -not $Bound.Confirm
    ) 'The approved synthetic Undo effect did not suppress nested confirmation.'
    $record = $script:objects[$Identity]
    $entry = $script:entriesById[$Identity]
    $prepared = @((Read-FixtureJournal).Entries | Where-Object EntryId -eq $entry.EntryId)
    Assert-Fixture (
        $prepared.Count -eq 1 -and $prepared[0].Status -ceq 'Succeeded' -and $prepared[0].Undo.Status -ceq 'Prepared' -and
        $prepared[0].ObjectGuid -ceq $record.ObjectGuid -and $prepared[0].Undo.Before.Enabled -eq $false -and -not $record.Enabled
    ) 'The synthetic Undo effect ran without durable Prepared evidence for the exact approved entry.'
    $script:trace.Add('Effect:' + $record.Number)
    return $record
}

function Get-ADObject {
    [CmdletBinding()]
    param([guid]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:mode -eq 'Native') 'Direct Undo used an ambient object command.'
    Read-FixtureObject $Identity $PSBoundParameters
}

function Get-ADGroup {
    [CmdletBinding()]
    param([string]$Filter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:mode -eq 'Native') 'Direct Undo used an ambient group command.'
    Read-FixtureGroups $PSBoundParameters
}

function Enable-ADAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:mode -eq 'Native') 'Direct Undo used an ambient effect command.'
    $record = Confirm-FixtureUndoPrepared $Identity $PSBoundParameters
    if ($record.Number -eq $script:faultIndex -and $script:fault -eq 'EffectFault') {
        Write-Error -ErrorId 'FixtureUndoProviderFault' -Message 'Synthetic Undo provider failure'
    }
    if ($record.Number -ne $script:faultIndex -or $script:fault -ne 'Postcondition') {
        $record.Enabled = $true
        $record.UserAccountControl = 512
        $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
    }
}

function Get-FixtureBundledObject {
    [CmdletBinding()]
    param([guid]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Read-FixtureObject $Identity $PSBoundParameters
}

function Get-FixtureBundledGroup {
    [CmdletBinding()]
    param([string]$Filter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Read-FixtureGroups $PSBoundParameters
}

function Enable-FixtureBundledAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    $record = Confirm-FixtureUndoPrepared $Identity $PSBoundParameters
    if ($record.Number -eq $script:faultIndex -and $script:fault -eq 'EffectFault') {
        Write-Error -ErrorId 'FixtureUndoProviderFault' -Message 'Synthetic Undo provider failure'
    }
    if ($record.Number -ne $script:faultIndex -or $script:fault -ne 'Postcondition') {
        $record.Enabled = $true
        $record.UserAccountControl = 512
        $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
    }
}

function ConvertTo-Json {
    [CmdletBinding()]
    param([AllowNull()]$InputObject, [int]$Depth, [switch]$Compress)

    if ($script:fault -in 'PrepareSerialize', 'TerminalSerialize' -and
        $null -ne $InputObject -and $InputObject.JournalType -eq 'ADAnalyzerRemediationJournal') {
        $observe = @($InputObject.Entries | Where-Object { $null -ne $_.Undo } | Select-Object -Last 1)
        if ($observe.Count) {
            $status = $observe[0].Undo.Status
            $script:trace.Add('Serialize:' + $status)
            if (($script:fault -eq 'PrepareSerialize' -and $status -eq 'Prepared') -or
                ($script:fault -eq 'TerminalSerialize' -and $status -eq 'Succeeded')) {
                throw [IO.IOException]::new('Synthetic Undo ' + $status + ' persistence failure')
            }
        }
    }
    Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
}

function ConvertTo-StableUndoEntry([object]$Entry) {
    $stable = [ordered]@{}
    foreach ($property in $Entry.PSObject.Properties) {
        if ($property.Name -eq 'Undo' -and $null -ne $property.Value) {
            $undo = [ordered]@{}
            foreach ($field in $property.Value.PSObject.Properties) {
                if ($field.Name -eq 'Timestamp') {
                    Assert-Fixture ($null -ne $field.Value) 'A native Undo entry lacks a generated timestamp.'
                    $undo.Timestamp = '{UTC}'
                }
                else {
                    $undo[$field.Name] = $field.Value
                }
            }
            $stable.Undo = $undo
        }
        else {
            $stable[$property.Name] = $property.Value
        }
    }
    return $stable
}

function Get-NativeUndoObservation([string]$Scenario, [string]$Preference) {
    $journal = New-FixtureInput ('native-' + $Scenario) $Scenario
    $parameters = @{
        Server = $script:server
        Credential = $script:credential
        JournalPath = $script:path
        Confirm = $false
        ErrorAction = $Preference
        ErrorVariable = '+capture'
    }
    switch ($Scenario) {
        'WhatIf' {
            $parameters.WhatIf = $true
        }
        'WrongServer' {
            $journal.Server = 'foreign.fixture.invalid'
        }
        'Ambiguous' {
            $journal.Entries[1].EntryId = $journal.Entries[0].EntryId
        }
        'Transition' {
            $journal.Entries[0].Before.Enabled = $false
        }
    }
    $seed = Save-FixtureSeed $journal
    $records = [Collections.Generic.List[object]]::new()
    $capture = [Collections.ArrayList]::new()
    $caught = $null
    $completed = $false
    try {
        $Error.Clear()
        if ($Scenario -eq 'Cutoff') {
            Undo-ADAnalyzerRemediation @parameters *>&1 | Select-Object -First 1 | ForEach-Object {
                $records.Add($_)
                if ($_.Status -eq 'Undone') {
                    Assert-Fixture (
                        (Read-FixtureJournal).Entries[0].Undo.Status -ceq 'Succeeded'
                    ) 'The streamed Undo result preceded durable terminal evidence.'
                }
            }
        }
        else {
            Undo-ADAnalyzerRemediation @parameters *>&1 | ForEach-Object { $records.Add($_) }
        }
        $completed = $true
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    try {
        $marker = [IO.File]::Exists($script:path + '.lock')
        if ($marker) {
            Assert-FixtureLeaseReleased
        }
        $stored = @(
            foreach ($entry in (Read-FixtureJournal).Entries) {
                ConvertTo-StableUndoEntry $entry
            }
        )
        [ordered]@{
            Completed = $completed
            Caught = Get-FixtureDiagnostic $caught
            Captured = Get-FixtureDiagnostic $capture
            History = Get-FixtureDiagnostic $history
            Trace = $script:trace.ToArray()
            Stream = @(
                foreach ($item in $records) {
                    if ($null -eq $item) {
                        [ordered]@{ Type = 'Null' }
                    }
                    elseif ($item -is [Management.Automation.ErrorRecord]) {
                        Get-FixtureDiagnostic $item
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
                    elseif ($null -ne $item.Status) {
                        [ordered]@{
                            Type = $item.GetType().FullName
                            Row = ConvertTo-StableUndoEntry $item
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
            Stored = $stored
            Marker = $marker
            SeedUnchanged = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:path)) -ceq $seed
        }
    }
    finally {
        [IO.Directory]::Delete($script:root, $true)
    }
}

function Assert-NativeUndoParity([string]$Scenario, [string]$Preference) {
    $name = 'Undo-ADAnalyzerRemediation'
    $path = 'Function:script:' + $name
    $original = (Get-Command $name -CommandType Function).ScriptBlock
    $accepted = [scriptblock]::Create($script:acceptedUndoBody)
    $originalAst = $original.Ast
    if ($originalAst -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $originalAst = $originalAst.Body
    }
    Assert-Fixture (
        $accepted.Ast.ParamBlock.Extent.Text.Replace("`r`n", "`n") -ceq $originalAst.ParamBlock.Extent.Text.Replace("`r`n", "`n")
    ) 'The native Undo parameter declaration changed.'
    try {
        Set-Item -LiteralPath $path -Value $accepted
        Assert-Fixture (
            (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $accepted.ToString()
        ) 'The archived Undo command was not installed in script scope.'
        $expected = Get-NativeUndoObservation $Scenario $Preference
    }
    finally {
        Set-Item -LiteralPath $path -Value $original
    }
    Assert-Fixture (
        (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $original.ToString()
    ) 'The current Undo command was not restored.'
    $serialized = ConvertTo-FixtureJson $expected
    $trace = $expected.Trace -join ','
    $terminal = switch ($Scenario) {
        'WhatIf' {
            $expected.Completed -and @($expected.Stream | Where-Object { $_.Row.Status -eq 'Skipped' }).Count -eq 3 -and
            $expected.Trace.Count -eq 0 -and $expected.SeedUnchanged -and -not $expected.Marker
        }
        'Cutoff' {
            $expected.Completed -and $expected.Stream.Count -eq 1 -and $expected.Stream[0].Row.Status -ceq 'Undone' -and
            ($expected.Stored.Status -join ',') -ceq 'Undone,Succeeded,Succeeded' -and
            $trace -ceq 'Read:1,Group,Effect:1,Read:1' -and $expected.Marker
        }
        'WrongServer' {
            -not $expected.Completed -and $expected.Trace.Count -eq 0 -and $expected.SeedUnchanged -and -not $expected.Marker -and
            $serialized.Contains('Journal type/server does not match this undo request')
        }
        'Ambiguous' {
            -not $expected.Completed -and $expected.Trace.Count -eq 0 -and $expected.SeedUnchanged -and $expected.Marker -and
            $serialized.Contains('Journal entry identity is missing or ambiguous')
        }
        'Transition' {
            -not $expected.Completed -and $expected.Trace.Count -eq 0 -and $expected.Stored[0].Undo.Status -ceq 'Rejected' -and
            $serialized.Contains('reversible enabled-to-disabled transition')
        }
        'PrepareSerialize' {
            -not $expected.Completed -and $trace -ceq 'Read:1,Group,Serialize:Prepared,Serialize:Failed' -and
            $expected.Stored[0].Undo.Status -ceq 'Failed' -and $serialized.Contains('Synthetic Undo Prepared persistence failure')
        }
        'EffectFault' {
            -not $expected.Completed -and $trace -ceq 'Read:1,Group,Effect:1' -and
            $expected.Stored[0].Undo.Status -ceq 'Failed' -and $serialized.Contains('FixtureUndoProviderFault')
        }
        'TerminalSerialize' {
            -not $expected.Completed -and
            $trace -ceq 'Read:1,Group,Serialize:Prepared,Effect:1,Read:1,Serialize:Succeeded,Serialize:Failed' -and
            $expected.Stored[0].Status -ceq 'Undone' -and $expected.Stored[0].Undo.Status -ceq 'Failed' -and
            $serialized.Contains('Synthetic Undo Succeeded persistence failure')
        }
    }
    Assert-Fixture $terminal (
        "The archive missed $Scenario with ErrorAction=$Preference." + [Environment]::NewLine + $serialized
    )
    $actual = ConvertTo-FixtureJson (Get-NativeUndoObservation $Scenario $Preference)
    Assert-Fixture ($actual -ceq $serialized) (
        "Native Undo changed for $Scenario with ErrorAction=$Preference." + [Environment]::NewLine +
        'Accepted: ' + $serialized + [Environment]::NewLine + 'Current: ' + $actual
    )
}

function Invoke-NativeCases {
    $cases = [ordered]@{
        WhatIf = 'Stop'
        Cutoff = 'Stop'
        WrongServer = 'Ignore'
        Ambiguous = 'Continue'
        Transition = 'Stop'
        PrepareSerialize = 'SilentlyContinue'
        EffectFault = 'Stop'
        TerminalSerialize = 'Stop'
    }
    foreach ($scenario in $cases.Keys) {
        Test-Fixture $scenario {
            Assert-NativeUndoParity $scenario $cases[$scenario]
        }
    }
}

function Invoke-ConstructionCases {
    Test-Fixture 'the documented loader constructs independent inert executors' {
        foreach ($name in @(
                'Resolve-ADAnalyzerOperationFilePath', 'Enter-ADAnalyzerJournalLease',
                'Read-ADAnalyzerOperationDocument'
            )) {
            Set-Item -LiteralPath ('Function:local:' + $name) -Value {
                throw 'Constructing the executor attempted to resolve or read journal data.'
            }
        }
        $first = [ADAnalyzerRemediationExecutor]::new()
        $second = [ADAnalyzerRemediationExecutor]::new()
        Assert-Fixture (
            $first.GetType().Name -ceq 'ADAnalyzerRemediationExecutor' -and
            -not [object]::ReferenceEquals($first, $second) -and $script:trace.Count -eq 0
        ) 'The documented loader did not provide independent inert executors.'
    }
    Test-Fixture 'PreviewUndo and Undo expose explicit operation signatures' {
        $type = [ADAnalyzerRemediationExecutor]
        Assert-Fixture (
            $null -ne $type.GetMethod('PreviewUndo', [type[]]@([string], [string])) -and
            $null -ne $type.GetMethod('Undo', [type[]]@([string], [string], [object[]])) -and
            $null -ne $type.GetMethod('Undo', [type[]]@([string], [string], [object[]], [pscredential]))
        ) 'The documented Undo methods or signatures are missing.'
    }
}

function Forbid-NativeUndo {
    Set-Item -LiteralPath 'Function:script:Undo-ADAnalyzerRemediation' -Value {
        throw 'The executor delegated Undo to the compatibility command.'
    }
}

function Assert-NoUndoWork([string]$Seed, [bool]$MarkerAllowed = $false) {
    Assert-Fixture (
        $script:trace.Count -eq 0 -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:path)) -ceq $Seed -and
        ($MarkerAllowed -or -not [IO.File]::Exists($script:path + '.lock'))
    ) 'Undo validation touched the reviewed journal, lease or provider.'
}

function Assert-SkippedUndo([object[]]$Rows, [object[]]$Entries) {
    Assert-Fixture ($Rows.Count -eq $Entries.Count) 'Preview lost eligible rows.'
    for ($index = 0; $index -lt $Rows.Count; $index++) {
        Assert-Fixture (
            ($Rows[$index].PSObject.Properties.Name -join ',') -ceq 'EntryId,ObjectGuid,Status' -and
            $Rows[$index].EntryId -ceq $Entries[$index].EntryId -and
            $Rows[$index].ObjectGuid -ceq $Entries[$index].ObjectGuid -and $Rows[$index].Status -ceq 'Skipped'
        ) 'Undo preview changed the ordered three-field Skipped contract.'
    }
}

function Assert-JournalUndoFailure([string]$Outer, [string]$Nested, [string]$Trace) {
    $entry = (Read-FixtureJournal).Entries[0]
    Assert-Fixture (
        $entry.Status -ceq $Outer -and $entry.Undo.Status -ceq $Nested -and
        -not [string]::IsNullOrWhiteSpace($entry.Undo.Message) -and
        ($script:trace -join ',') -ceq $Trace
    ) ('Unexpected Undo failure trace or terminal status: ' + ($script:trace -join ','))
    Assert-FixtureLeaseReleased
}

function Invoke-DirectCases {
    Forbid-NativeUndo
    $executor = [ADAnalyzerRemediationExecutor]::new()
    Test-Fixture 'literal preview and empty consent are detached offline reads' {
        $journal = New-FixtureInput 'preview'
        $journal.Entries[1].Status = 'Undone'
        $seed = Save-FixtureSeed $journal
        $expected = @($journal.Entries[0], $journal.Entries[2])
        $rows = $executor.PreviewUndo($script:path, $script:server)
        Assert-SkippedUndo $rows $expected
        $rows[0].ObjectGuid = 'fixture changed result'
        $rows[0].EntryId = 'fixture changed result'
        Assert-SkippedUndo ($executor.PreviewUndo($script:path, $script:server)) $expected
        Assert-SkippedUndo ($executor.Undo($script:path, $script:server, @())) $expected
        Assert-NoUndoWork $seed
    }
    Test-Fixture 'Undo requires an existing usable journal at the reviewed controller' {
        $journal = New-FixtureInput 'existing-only'
        $approved = @($journal.Entries[0].EntryId)
        Assert-FixtureFailure { $executor.PreviewUndo($script:path, $script:server) }
        Assert-FixtureFailure { $executor.Undo($script:path, $script:server, $approved) }
        Assert-FixtureFailure { $executor.Undo($script:path, $script:server, @()) }
        Assert-Fixture (
            [IO.Directory]::GetFiles($script:root).Count -eq 0 -and $script:trace.Count -eq 0
        ) 'Undo created a journal or lease for an absent path.'

        Assert-FixtureFailure {
            Write-ADAnalyzerFile -Path $script:path -Content '{}' -RequireExisting
        }
        $missingParent = Join-Path $script:root 'absent'
        $missingTarget = Join-Path $missingParent 'journal.json'
        Assert-FixtureFailure {
            Write-ADAnalyzerFile -Path $missingTarget -Content '{}' -RequireExisting
        } 'Journal file does not exist'
        Assert-Fixture (
            [IO.Directory]::GetFileSystemEntries($script:root).Count -eq 0 -and $script:trace.Count -eq 0
        ) 'Existing-only storage created a destination, parent or staging file.'

        $malformed = '{"Entries":'
        [IO.File]::WriteAllText($script:path, $malformed)
        $badBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:path))
        Assert-FixtureFailure { $executor.PreviewUndo($script:path, $script:server) }
        Assert-FixtureFailure { $executor.Undo($script:path, $script:server, $approved) }
        Assert-NoUndoWork $badBytes

        $seed = Save-FixtureSeed $journal
        Assert-FixtureFailure { $executor.Undo($script:path, 'foreign.fixture.invalid', $approved) } 'type/server'
        Assert-FixtureFailure { $executor.PreviewUndo('Env:ADANALYZER_LOCAL_UNDO_FIXTURE', $script:server) } 'FileSystem'
        Assert-NoUndoWork $seed
        $journal.PlanId = 17
        $seed = Save-FixtureSeed $journal
        Assert-FixtureFailure { $executor.PreviewUndo($script:path, $script:server) }
        Assert-NoUndoWork $seed
        $journal.PlanId = '11111111-1111-4111-8111-111111111111'
        $journal.JournalId = $null
        $seed = Save-FixtureSeed $journal
        Assert-FixtureFailure { $executor.Undo($script:path, $script:server, $approved) }
        Assert-NoUndoWork $seed
    }
    Test-Fixture 'canonical consent and ambiguous or ineligible requests fail before the lease' {
        $journal = New-FixtureInput 'approval-validation'
        $journal.Entries[2].Status = 'Undone'
        $seed = Save-FixtureSeed $journal
        $first = $journal.Entries[0].EntryId
        $second = $journal.Entries[1].EntryId
        $faults = @(
            , @('66666666-6666-4666-8666-666666666666', 'does not belong')
            , @('not a fixture ID', 'does not belong')
            , @(@{ EntryId = $second }, 'does not belong')
            , @($null, 'does not belong')
            , @($journal.Entries[2].EntryId, 'does not belong')
            , @(([guid]$first).ToString('B'), 'must be unique')
        )
        foreach ($fault in $faults) {
            Assert-FixtureFailure {
                $executor.Undo($script:path, $script:server, @($first, $fault[0]), $script:credential)
            } $fault[1]
            Assert-NoUndoWork $seed
        }
        Assert-FixtureFailure { $executor.Undo($script:path, $script:server, $null) } 'Supply explicit approved undo entry IDs'
        Assert-NoUndoWork $seed

        $journal.Entries[2].EntryId = ([guid]$second).ToString('B')
        $seed = Save-FixtureSeed $journal
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($first, $second))
        } 'Journal entry identity is missing or ambiguous'
        Assert-NoUndoWork $seed

        $malformed = [ordered]@{
            Action = @('DisableAccount', 'OtherFixtureAction')
            Status = @('Succeeded', 'OtherFixtureStatus')
        }
        foreach ($item in $malformed.GetEnumerator()) {
            foreach ($length in 1, 2) {
                $journal = New-FixtureInput ('approval-shape-' + $item.Key + '-' + $length)
                $journal.Entries[0].PSObject.Properties[$item.Key].Value = @($item.Value | Select-Object -First $length)
                $seed = Save-FixtureSeed $journal
                Assert-SkippedUndo ($executor.PreviewUndo($script:path, $script:server)) @($journal.Entries[1], $journal.Entries[2])
                Assert-FixtureFailure {
                    $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId))
                } 'does not belong'
                Assert-NoUndoWork $seed
            }
        }
        $journal = New-FixtureInput 'approval-entryid-array'
        $id = $journal.Entries[0].EntryId
        $journal.Entries[0].EntryId = @($id)
        $seed = Save-FixtureSeed $journal
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($id))
        } 'does not belong'
        Assert-NoUndoWork $seed
    }
    Test-Fixture 'explicit reversed subset uses journal order and pinned bundled observations' {
        $journal = New-FixtureInput 'ordered-subset'
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        $approved = @([guid]$journal.Entries[2].EntryId, ([guid]$journal.Entries[0].EntryId).ToString('B'))
        $rows = $executor.Undo($script:path, $script:server, $approved, $script:credential)
        $persisted = Read-FixtureJournal
        Assert-Fixture (
            ($rows.Status -join ',') -ceq 'Undone,Skipped,Undone' -and
            ($rows.EntryId -join ',') -ceq ($journal.Entries.EntryId -join ',') -and
            ($persisted.Entries.Status -join ',') -ceq 'Undone,Succeeded,Undone' -and
            ($script:trace -join ',') -ceq 'Import,Read:1,Import,Group,Effect:1,Read:1,Read:3,Import,Group,Effect:3,Read:3'
        ) 'Undo changed selection order, persistence or pinned provider timing.'
        Assert-SkippedUndo @($rows[1]) @($journal.Entries[1])
        Assert-Fixture (
            $rows[0].Undo.Status -ceq 'Succeeded' -and
            $rows[0].Undo.Before.Enabled -is [bool] -and -not $rows[0].Undo.Before.Enabled -and
            $rows[0].Undo.After.Enabled -is [bool] -and $rows[0].Undo.After.Enabled -and
            $persisted.Entries[2].Undo.Status -ceq 'Succeeded' -and
            $persisted.JournalId -ceq $journal.JournalId -and $persisted.PlanId -ceq $journal.PlanId -and
            (ConvertTo-FixtureJson $persisted.Remediation) -ceq (ConvertTo-FixtureJson $journal.Remediation)
        ) 'The result lost verified enabled evidence or journal identity and policy.'
        $rows[0].Undo.After.DistinguishedName = 'changed detached result'
        Assert-Fixture (
            (Read-FixtureJournal).Entries[0].Undo.After.DistinguishedName -ceq $journal.Entries[0].DistinguishedName
        ) 'Returned Undo evidence retained mutable storage.'
        Assert-FixtureLeaseReleased
    }
    Test-Fixture 'existing contention blocks Undo and the same executor can retry after release' {
        $journal = New-FixtureInput 'contention'
        $seed = Save-FixtureSeed $journal
        $held = [IO.File]::Open(
            ($script:path + '.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
        )
        $approved = @($journal.Entries[0].EntryId)
        try {
            Assert-SkippedUndo ($executor.PreviewUndo($script:path, $script:server)) $journal.Entries
            Assert-SkippedUndo ($executor.Undo($script:path, $script:server, @())) $journal.Entries
            Assert-FixtureFailure {
                $executor.Undo($script:path, $script:server, $approved, $script:credential)
            } 'Unable to acquire journal lock'
            Assert-NoUndoWork $seed $true
        }
        finally {
            $held.Dispose()
        }
        $script:allowProvider = $true
        $rows = $executor.Undo($script:path, $script:server, $approved, $script:credential)
        Assert-Fixture (($rows.Status -join ',') -ceq 'Undone,Skipped,Skipped') 'The released owner could not retry.'
        Assert-FixtureLeaseReleased
    }
    Test-Fixture 'transition and fresh evidence failures persist Rejected without an effect' {
        $invalid = [ordered]@{
            Reversed = @{
                Before = $false
                After = $false
            }
            StringBefore = @{
                Before = 'true'
                After = $false
            }
            StringAfter = @{
                Before = $true
                After = 'false'
            }
        }
        foreach ($item in $invalid.GetEnumerator()) {
            $journal = New-FixtureInput ('transition-' + $item.Key)
            $journal.Entries[0].Before.Enabled = $item.Value.Before
            $journal.Entries[0].After.Enabled = $item.Value.After
            $null = Save-FixtureSeed $journal
            Assert-FixtureFailure {
                $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
            } 'reversible enabled-to-disabled transition'
            Assert-JournalUndoFailure 'Succeeded' 'Rejected' ''
        }

        $journal = New-FixtureInput 'invalid-current'
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        $first = $script:objects[[guid]$journal.Entries[0].ObjectGuid]
        $first.WhenChanged = $first.WhenChanged.AddSeconds(1)
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
        } 'precondition failed'
        Assert-JournalUndoFailure 'Succeeded' 'Rejected' 'Import,Read:1'
        Assert-Fixture (-not $first.Enabled) 'Fresh precondition failure ran the synthetic effect.'
    }
    Test-Fixture 'provider failure keeps its cause and records Failed without a post-read' {
        $journal = New-FixtureInput 'provider-fault' 'EffectFault'
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
        } 'Synthetic Undo provider failure'
        Assert-JournalUndoFailure 'Succeeded' 'Failed' 'Import,Read:1,Import,Group,Effect:1'
    }
    Test-Fixture 'a no-op effect keeps the disabled postcondition evidence and emits no success' {
        $journal = New-FixtureInput 'postcondition-fault' 'Postcondition'
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
        } 'Unable to verify the account enable result'
        Assert-JournalUndoFailure 'Succeeded' 'Failed' 'Import,Read:1,Import,Group,Effect:1,Read:1'
        Assert-Fixture (
            (Read-FixtureJournal).Entries[0].Undo.After.Enabled -eq $false
        ) 'The failed verification lost its observed disabled state.'
    }
    Test-Fixture 'preparation and terminal persistence recover without false success' {
        $journal = New-FixtureInput 'prepare-fault' 'PrepareSerialize'
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
        } 'Synthetic Undo Prepared persistence failure'
        Assert-JournalUndoFailure 'Succeeded' 'Failed' 'Import,Read:1,Import,Group,Serialize:Prepared,Serialize:Failed'

        $journal = New-FixtureInput 'terminal-fault' 'TerminalSerialize'
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
        } 'Synthetic Undo Succeeded persistence failure'
        Assert-JournalUndoFailure 'Undone' 'Failed' 'Import,Read:1,Import,Group,Serialize:Prepared,Effect:1,Read:1,Serialize:Succeeded,Serialize:Failed'
        $entry = (Read-FixtureJournal).Entries[0]
        Assert-Fixture (-not $entry.Undo.Before.Enabled -and $entry.Undo.After.Enabled) 'Recovery lost the verified enabled state.'
    }
    Test-Fixture 'late failure preserves durable earlier success and stops before later entries' {
        $journal = New-FixtureInput 'partial' 'EffectFault' $false
        $null = Save-FixtureSeed $journal
        $script:allowProvider = $true
        $script:faultIndex = 2
        Assert-FixtureFailure {
            $executor.Undo($script:path, $script:server, @($journal.Entries.EntryId))
        } 'Synthetic Undo provider failure'
        $persisted = Read-FixtureJournal
        Assert-Fixture (
            ($persisted.Entries.Status -join ',') -ceq 'Undone,Succeeded,Succeeded' -and
            $persisted.Entries[0].Undo.Status -ceq 'Succeeded' -and $persisted.Entries[1].Undo.Status -ceq 'Failed' -and
            $null -eq $persisted.Entries[2].Undo -and
            ($script:trace -join ',') -ceq 'Import,Read:1,Import,Group,Effect:1,Read:1,Read:2,Import,Group,Effect:2'
        ) 'A late failure lost earlier evidence or reached an unprocessed entry.'
        Assert-FixtureLeaseReleased
    }
}

function Invoke-IsolationCases {
    Forbid-NativeUndo
    $executor = [ADAnalyzerRemediationExecutor]::new()
    Test-Fixture 'independent and reused executors retain no prior approval or bound state' {
        $first = New-FixtureInput 'first-owner' '' $false
        $null = Save-FixtureSeed $first
        $script:allowProvider = $true
        $rows = $executor.Undo($script:path, $script:server, @($first.Entries[0].EntryId))
        Assert-Fixture (($rows.Status -join ',') -ceq 'Undone,Skipped,Skipped') 'The first object run changed approval.'
        Assert-FixtureLeaseReleased
        $second = New-FixtureInput 'second-owner' '' $false
        $seed = Save-FixtureSeed $second
        $independent = [ADAnalyzerRemediationExecutor]::new()
        Assert-SkippedUndo ($independent.PreviewUndo($script:path, $script:server)) $second.Entries
        Assert-SkippedUndo ($executor.Undo($script:path, $script:server, @())) $second.Entries
        Assert-NoUndoWork $seed
        $script:allowProvider = $true
        $rows = $executor.Undo($script:path, $script:server, @($second.Entries[2].EntryId), [pscredential]::Empty)
        Assert-Fixture (($rows.Status -join ',') -ceq 'Skipped,Skipped,Undone') 'Reused executor retained previous review scope.'
        Assert-Fixture (
            (ConvertTo-FixtureJson $executor) -cnotmatch 'fixture|Credential|JournalPath|ApprovedEntryIds'
        ) 'Executor serialization retained scoped Undo data.'
        Assert-FixtureLeaseReleased
    }
    Test-Fixture 'disposing a secondary documented loader leaves original Undo usable' {
        $journal = New-FixtureInput 'second-loader'
        $null = Save-FixtureSeed $journal
        $worker = [powershell]::Create()
        try {
            $child = @'
param($Fixture, $RepositoryRoot)
& $Fixture -RepositoryRoot $RepositoryRoot -Case Construction
'@
            $result = @($worker.AddScript($child).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
            Assert-Fixture (
                -not $worker.HadErrors -and @($result | Where-Object { $_ -ceq 'PASS remediation undo Construction 2' }).Count -eq 1
            ) ('Secondary Undo loader failed: ' + ($worker.Streams.Error -join ' | '))
        }
        finally {
            $worker.Dispose()
        }
        $script:allowProvider = $true
        $rows = $executor.Undo($script:path, $script:server, @($journal.Entries[0].EntryId), $script:credential)
        Assert-Fixture (($rows.Status -join ',') -ceq 'Undone,Skipped,Skipped') 'Disposing another loader invalidated Undo.'
        Assert-FixtureLeaseReleased
    }
}

switch ($Case) {
    'Construction' {
        Invoke-ConstructionCases
    }
    'Standalone' {
        Test-Fixture 'the operations file exposes literal executor construction without a profile import' {
            $executor = [ADAnalyzerRemediationExecutor]::new()
            Assert-Fixture (
                $executor.GetType().Name -ceq 'ADAnalyzerRemediationExecutor' -and
                $null -eq ('ADAnalyzerProfile' -as [type]) -and $script:trace.Count -eq 0
            ) 'Standalone construction acquired a dependency or touched a provider.'
        }
    }
    { $_ -in 'Native', 'Direct', 'Isolation' } {
        $script:temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-undo-fixture-' + [guid]::NewGuid().ToString('N'))
        $null = [IO.Directory]::CreateDirectory($script:temporary)
        try {
            switch ($Case) {
                'Native' {
                    Invoke-NativeCases
                }
                'Direct' {
                    Invoke-DirectCases
                }
                'Isolation' {
                    Invoke-IsolationCases
                }
            }
        }
        finally {
            [IO.Directory]::Delete($script:temporary, $true)
        }
    }
}
Write-Output ('PASS remediation undo ' + $Case + ' ' + $script:passed)
