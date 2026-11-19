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

foreach ($name in @('Invoke-Command', 'New-PSDrive', 'Get-ADRootDSE', 'Get-ADDomain', 'Enable-ADAccount')) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'The synthetic Apply fixture encountered an external effect.'
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
        Write-Host ('FAIL remediation apply ' + $Name)
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

function New-FixtureInput([string]$Name, [string]$Fault = '', [bool]$UseCredential = $true) {
    $script:trace = [Collections.Generic.List[string]]::new()
    $script:allowProvider = $false
    $script:fault = $Fault
    $script:faultIndex = 1
    $script:credential = [pscredential]::new('fixture', [Security.SecureString]::new())
    $script:expectCredential = $UseCredential
    $script:objects = @{}
    $script:findingsById = @{}
    $script:root = Join-Path $script:temporary $Name
    $null = [IO.Directory]::CreateDirectory($script:root)
    $script:path = Join-Path $script:root 'journal [apply].json'
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
            LastLogonDate = $null
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
        $finding = [pscustomobject]@{
            RuleId = 'ACCOUNT.INACTIVE'
            Status = 'Fail'
            Target = $record.DistinguishedName
            ObjectGuid = $record.ObjectGuid
            SID = $record.SID
            Suppressed = $false
        }
        $accounts.Add($record)
        $findings.Add($finding)
        $script:objects[$id] = $record
    }
    $assessment = @{
        SchemaVersion = 1
        RunId = 'offline-apply-fixture'
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
    Assert-Fixture ($plan.Actions.Count -eq 3) 'The fixture did not create a genuine reviewed plan.'
    $plan.PlanId = '11111111-1111-4111-8111-111111111111'
    for ($index = 0; $index -lt $plan.Actions.Count; $index++) {
        $action = $plan.Actions[$index]
        $action.ActionId = '30000000-0000-4000-8000-00000000000' + ($index + 1)
        $script:findingsById[[guid]$action.ObjectGuid] = $action
    }
    return $plan
}

function Assert-PinnedProvider($Bound) {
    Assert-Fixture (
        $Bound.Server -ceq $script:server -and [string]$Bound.ErrorAction -ceq 'Stop' -and
        $Bound.ContainsKey('Credential') -eq $script:expectCredential -and
        (-not $script:expectCredential -or [object]::ReferenceEquals($Bound.Credential, $script:credential))
    ) 'The synthetic command did not receive the exact selected server/credential context.'
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
    ) 'Apply tried a provider other than the inert operation-local bundled import.'
    Assert-LiveFixtureLease
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = @{
            'Get-ADObject' = Get-Command Get-FixtureBundledObject -CommandType Function
            'Get-ADGroup' = Get-Command Get-FixtureBundledGroup -CommandType Function
            'Disable-ADAccount' = Get-Command Disable-FixtureBundledAccount -CommandType Function
        }
    }
}

function Read-FixtureObject([guid]$Identity, $Bound) {
    Assert-PinnedProvider $Bound
    Assert-Fixture ($script:objects.ContainsKey($Identity)) 'The synthetic provider received an unreviewed object identity.'
    $properties = 'objectGUID,objectSid,distinguishedName,userAccountControl,whenChanged,whenCreated,lastLogonTimestamp,lastLogon,sIDHistory,adminCount,isCriticalSystemObject,ProtectedFromAccidentalDeletion,memberOf,primaryGroupID,sAMAccountName'
    Assert-Fixture (($Bound.Properties -join ',') -ceq $properties) 'Apply changed the requested fresh evidence.'
    $record = $script:objects[$Identity]
    $script:trace.Add('Read:' + $record.Number)
    if ($script:fault -eq 'PrepareConflict' -and $record.Number -eq $script:faultIndex -and -not [IO.Directory]::Exists($script:path)) {
        $null = [IO.Directory]::CreateDirectory($script:path)
    }
    return $record.PSObject.Copy()
}

function Read-FixtureGroups($Bound) {
    Assert-PinnedProvider $Bound
    Assert-Fixture (
        $Bound.Filter -ceq '*' -and ($Bound.Properties -join ',') -ceq 'members,memberOf,primaryGroupToken,SID'
    ) 'Apply changed the group evidence binding.'
    $script:trace.Add('Group')
    [pscustomobject]@{
        SID = $script:domainSid + '-513'
        DistinguishedName = 'CN=Fixture Ordinary Group,DC=offline,DC=invalid'
        PrimaryGroupToken = 513
        Members = @()
        MemberOf = @()
    }
}

function Confirm-FixturePrepared([guid]$Identity, $Bound) {
    Assert-PinnedProvider $Bound
    Assert-Fixture (
        $Bound.ContainsKey('WhatIf') -and $Bound.ContainsKey('Confirm') -and -not $Bound.WhatIf -and -not $Bound.Confirm
    ) 'The approved synthetic effect did not explicitly suppress nested prompts.'
    $record = $script:objects[$Identity]
    $action = $script:findingsById[$Identity]
    $journal = Read-FixtureJournal
    Assert-Fixture (
        $journal.Entries[-1].Status -ceq 'Prepared' -and $journal.Entries[-1].ActionId -ceq $action.ActionId -and
        $journal.Entries[-1].ObjectGuid -ceq $record.ObjectGuid -and $record.Enabled
    ) 'The synthetic effect ran without durable Prepared evidence for this exact reviewed action.'
    $script:trace.Add('Effect:' + $record.Number)
    return $record
}

function Get-ADObject {
    [CmdletBinding()]
    param([guid]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:mode -eq 'Native') 'Direct Apply used an ambient object command.'
    Read-FixtureObject $Identity $PSBoundParameters
}

function Get-ADGroup {
    [CmdletBinding()]
    param([string]$Filter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:mode -eq 'Native') 'Direct Apply used an ambient group command.'
    Read-FixtureGroups $PSBoundParameters
}

function Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-Fixture ($script:mode -eq 'Native') 'Direct Apply used an ambient effect command.'
    $record = Confirm-FixturePrepared $Identity $PSBoundParameters
    if ($record.Number -eq $script:faultIndex -and $script:fault -eq 'EffectFault') {
        Write-Error -ErrorId 'FixtureApplyProviderFault' -Message 'Synthetic Apply provider failure'
    }
    if ($record.Number -ne $script:faultIndex -or $script:fault -ne 'Postcondition') {
        $record.Enabled = $false
        $record.UserAccountControl = 514
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

function Disable-FixtureBundledAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([guid]$Identity, [string]$Server, [pscredential]$Credential)

    $record = Confirm-FixturePrepared $Identity $PSBoundParameters
    if ($record.Number -eq $script:faultIndex -and $script:fault -eq 'EffectFault') {
        Write-Error -ErrorId 'FixtureApplyProviderFault' -Message 'Synthetic Apply provider failure'
    }
    if ($record.Number -ne $script:faultIndex -or $script:fault -ne 'Postcondition') {
        $record.Enabled = $false
        $record.UserAccountControl = 514
        $record.WhenChanged = $record.WhenChanged.AddSeconds(1)
    }
}

function ConvertTo-Json {
    [CmdletBinding()]
    param([AllowNull()]$InputObject, [int]$Depth, [switch]$Compress)

    if ($script:fault -in 'PrepareSerialize', 'TerminalSerialize' -and
        $null -ne $InputObject -and $InputObject.JournalType -eq 'ADAnalyzerRemediationJournal' -and
        @($InputObject.Entries).Count -gt 0) {
        $status = $InputObject.Entries[-1].Status
        $script:trace.Add('Serialize:' + $status)
        if (($script:fault -eq 'PrepareSerialize' -and $status -eq 'Prepared') -or
            ($script:fault -eq 'TerminalSerialize' -and $status -eq 'Succeeded')) {
            throw [IO.IOException]::new('Synthetic ' + $status + ' persistence failure')
        }
    }
    Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
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

# Exact native Apply body from accepted edbcc7a.
# 4f90d17c43310d4c44806912e23f3c4d8d7998f9652c508b7bfe39571e20ee00
$script:acceptedApplyBody = @'
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [Parameter(Mandatory)][string]$JournalPath

    )
    $planObject = Read-ADAnalyzerOperationDocument $Plan 'Plan'
    Assert-ADAnalyzerOperationPlan $planObject
    $JournalPath = Resolve-ADAnalyzerOperationFilePath $JournalPath
    $connection = Get-ADAnalyzerOperationConnection $Server $Credential
    $reviewedServer = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $planObject @('Context')) @('Server'))
    if ($reviewedServer -and $reviewedServer -ine $Server) {
        throw 'Server differs from the DC recorded in the reviewed assessment'
    }
    $journal = $null
    $lease = $null
    try {
        foreach ($action in @($planObject.Actions)) {
            if ($null -eq $action) {
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($action.DistinguishedName, 'Disable account from explicit reviewed plan')) {
                [pscustomobject]@{
                    ActionId = $action.ActionId
                    ObjectGuid = $action.ObjectGuid
                    Status = 'Skipped'
                    JournalPath = $null
                }
                continue
            }
            if ($null -eq $journal) {
                $lease = Enter-ADAnalyzerJournalLease $JournalPath
                $journal = Get-ADAnalyzerOperationJournal $planObject $Server $JournalPath
            }
            if (@($journal.Entries | Where-Object { $_.ActionId -eq $action.ActionId -and $_.Status -in @('Succeeded', 'Undone') }).Count) {
                throw 'This plan action has already been applied; create a fresh assessment and plan'
            }
            $entry = [pscustomobject][ordered]@{
                EntryId = [guid]::NewGuid().ToString('D')
                ActionId = $action.ActionId
                Action = 'DisableAccount'
                ObjectGuid = $action.ObjectGuid
                SID = $action.SID
                DistinguishedName = $action.DistinguishedName
                ObjectClass = $action.ObjectClass
                AccountType = $action.AccountType
                InactivityDays = $action.InactivityDays
                Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                Status = 'Rejected'
                Before = $null
                After = $null
                Message = $null
                Undo = $null
            }
            $added = $false
            try {
                $current = Get-ADAnalyzerOperationCurrentObject $action.ObjectGuid $connection $planObject
                $entry.Before = Assert-ADAnalyzerOperationPreconditions $action.Preconditions $current $true
                Assert-ADAnalyzerOperationPrivilege $current $action $planObject $connection
                Assert-ADAnalyzerOperationInactivity $current $action
                $entry.Status = 'Prepared'
                $journal.Entries = @($journal.Entries) + @($entry)
                $added = $true
                # Durable intent precedes the mutation. A failed journal write aborts.
                Save-ADAnalyzerOperationJournal $journal $JournalPath
                Disable-ADAccount -Identity ([guid]$action.ObjectGuid) @connection -WhatIf:$false -Confirm:$false
                $after = Get-ADAnalyzerOperationCurrentObject $action.ObjectGuid $connection $planObject
                $entry.After = Get-ADAnalyzerOperationState $after
                if ($entry.After.ObjectGuid -ne $entry.Before.ObjectGuid -or
                    $entry.After.SID -ne $entry.Before.SID -or
                    $entry.After.DistinguishedName -ine $entry.Before.DistinguishedName -or
                    $entry.After.Enabled -isnot [bool] -or
                    $entry.After.Enabled -or
                    -not $entry.After.WhenChanged) {
                    throw 'Unable to verify the account disable result'
                }
                $entry.Status = 'Succeeded'
                Save-ADAnalyzerOperationJournal $journal $JournalPath
            }
            catch {
                $failure = $_
                $entry.Status = if ($entry.Status -eq 'Rejected') {
                    'Rejected'
                }
                else {
                    'Failed'
                }
                $entry.Message = $failure.Exception.Message
                if (-not $added) {
                    $journal.Entries = @($journal.Entries) + @($entry)
                }
                try {
                    Save-ADAnalyzerOperationJournal $journal $JournalPath
                }
                catch {
                    throw ('Journal persistence failed; no further changes were attempted. Inspect the durable journal before retrying. ' + $failure.Exception.Message + '; ' + $_.Exception.Message)
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

function New-FixtureJournalReplay([object]$Plan, [string]$Status) {
    $owner = [ADAnalyzerRemediationJournal]::new()
    try {
        $owner.Open($Plan, $script:server, $script:path)
        $journal = $owner.Read()
        $journal.Entries = @([pscustomobject]@{
                EntryId = '40000000-0000-4000-8000-000000000001'
                ActionId = $Plan.Actions[0].ActionId
                ObjectGuid = $Plan.Actions[0].ObjectGuid
                Action = 'DisableAccount'
                Status = $Status
            })
        $owner.Write($journal)
    }
    finally {
        $owner.Dispose()
    }
}

function ConvertTo-StableEntry([object]$Entry) {
    $stable = [ordered]@{}
    foreach ($property in $Entry.PSObject.Properties) {
        switch ($property.Name) {
            'EntryId' {
                Assert-Fixture ([guid]::ParseExact([string]$property.Value, 'D') -ne [guid]::Empty) 'An Apply entry lacks a generated identity.'
                $stable.EntryId = '{generated}'
            }
            'Timestamp' {
                Assert-Fixture ($null -ne $property.Value) 'An Apply entry lacks a timestamp.'
                $stable.Timestamp = '{UTC}'
            }
            default {
                $stable[$property.Name] = $property.Value
            }
        }
    }
    return $stable
}

function Get-NativeApplyObservation([string]$Scenario, [string]$Preference) {
    $plan = New-FixtureInput ('native-' + $Scenario) $Scenario
    $parameters = @{
        Plan = $plan
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
        'WrongController' {
            $plan.Context.Server = 'other.fixture.invalid'
        }
        'Replay' {
            New-FixtureJournalReplay $plan 'Succeeded'
        }
        'Precondition' {
            $first = $script:objects[[guid]$plan.Actions[0].ObjectGuid]
            $first.WhenChanged = $first.WhenChanged.AddSeconds(1)
        }
    }
    $records = [Collections.Generic.List[object]]::new()
    $capture = [Collections.ArrayList]::new()
    $caught = $null
    $completed = $false
    try {
        $Error.Clear()
        if ($Scenario -eq 'Cutoff') {
            Invoke-ADAnalyzerRemediationPlan @parameters *>&1 | Select-Object -First 1 | ForEach-Object {
                $records.Add($_)
                if ($_.Status -eq 'Succeeded') {
                    Assert-Fixture (
                        (Read-FixtureJournal).Entries[-1].Status -ceq 'Succeeded'
                    ) 'The streamed success preceded durable terminal evidence.'
                }
            }
        }
        else {
            Invoke-ADAnalyzerRemediationPlan @parameters *>&1 | ForEach-Object { $records.Add($_) }
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
            if ([IO.File]::Exists($script:path)) {
                foreach ($entry in (Read-FixtureJournal).Entries) {
                    ConvertTo-StableEntry $entry
                }
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
                            Row = ConvertTo-StableEntry $item
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
        }
    }
    finally {
        [IO.Directory]::Delete($script:root, $true)
    }
}

function Assert-NativeApplyParity([string]$Scenario, [string]$Preference) {
    $name = 'Invoke-ADAnalyzerRemediationPlan'
    $path = 'Function:script:' + $name
    $original = (Get-Command $name -CommandType Function).ScriptBlock
    $accepted = [scriptblock]::Create($script:acceptedApplyBody)
    $originalAst = $original.Ast
    if ($originalAst -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $originalAst = $originalAst.Body
    }
    Assert-Fixture (
        $accepted.Ast.ParamBlock.Extent.Text.Replace("`r`n", "`n") -ceq $originalAst.ParamBlock.Extent.Text.Replace("`r`n", "`n")
    ) 'The native Apply parameter declaration changed.'
    try {
        Set-Item -LiteralPath $path -Value $accepted
        Assert-Fixture (
            (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $accepted.ToString()
        ) 'The archived Apply command was not installed in script scope.'
        $expected = Get-NativeApplyObservation $Scenario $Preference
    }
    finally {
        Set-Item -LiteralPath $path -Value $original
    }
    Assert-Fixture (
        (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $original.ToString()
    ) 'The current Apply command was not restored.'
    $serialized = ConvertTo-FixtureJson $expected
    $trace = $expected.Trace -join ','
    $terminal = switch ($Scenario) {
        'WhatIf' {
            $expected.Completed -and @($expected.Stream | Where-Object { $_.Row.Status -eq 'Skipped' }).Count -eq 3 -and
            $expected.Trace.Count -eq 0 -and -not $expected.Marker
        }
        'Cutoff' {
            $expected.Completed -and $expected.Stream.Count -eq 1 -and $expected.Stream[0].Row.Status -ceq 'Succeeded' -and
            $expected.Stored.Count -eq 1 -and $trace -ceq 'Read:1,Group,Effect:1,Read:1' -and $expected.Marker
        }
        'WrongController' {
            -not $expected.Completed -and $expected.Trace.Count -eq 0 -and -not $expected.Marker -and
            $serialized.Contains('differs from the DC recorded')
        }
        'Replay' {
            -not $expected.Completed -and $expected.Trace.Count -eq 0 -and $expected.Marker -and
            $expected.Stored[0].Status -ceq 'Succeeded' -and $serialized.Contains('already been applied')
        }
        'Precondition' {
            -not $expected.Completed -and $trace -ceq 'Read:1' -and $expected.Stored[0].Status -ceq 'Rejected' -and
            $serialized.Contains('precondition failed')
        }
        'PrepareSerialize' {
            -not $expected.Completed -and $trace -ceq 'Read:1,Group,Serialize:Prepared,Serialize:Failed' -and
            $expected.Stored[0].Status -ceq 'Failed' -and $serialized.Contains('Synthetic Prepared persistence failure')
        }
        'EffectFault' {
            -not $expected.Completed -and $trace -ceq 'Read:1,Group,Effect:1' -and
            $expected.Stored[0].Status -ceq 'Failed' -and $serialized.Contains('FixtureApplyProviderFault')
        }
        'Postcondition' {
            -not $expected.Completed -and $trace -ceq 'Read:1,Group,Effect:1,Read:1' -and
            $expected.Stored[0].Status -ceq 'Failed' -and $serialized.Contains('Unable to verify the account disable result')
        }
    }
    Assert-Fixture $terminal (
        "The archive missed $Scenario with ErrorAction=$Preference." + [Environment]::NewLine + $serialized
    )
    $actual = ConvertTo-FixtureJson (Get-NativeApplyObservation $Scenario $Preference)
    Assert-Fixture ($actual -ceq $serialized) (
        "Native Apply changed for $Scenario with ErrorAction=$Preference." + [Environment]::NewLine +
        'Accepted: ' + $serialized + [Environment]::NewLine + 'Current: ' + $actual
    )
}

function Invoke-NativeCases {
    $cases = [ordered]@{
        WhatIf = 'Stop'
        Cutoff = 'Stop'
        WrongController = 'Ignore'
        Replay = 'Stop'
        Precondition = 'Continue'
        PrepareSerialize = 'SilentlyContinue'
        EffectFault = 'Stop'
        Postcondition = 'Stop'
    }
    foreach ($scenario in $cases.Keys) {
        Test-Fixture $scenario {
            Assert-NativeApplyParity $scenario $cases[$scenario]
        }
    }
}

function Invoke-ConstructionCases {
    Test-Fixture 'documented executor construction stays inert and detached' {
        foreach ($name in @(
                'Resolve-ADAnalyzerOperationFilePath', 'Enter-ADAnalyzerJournalLease',
                'Get-ADAnalyzerOperationJournal', 'Read-ADAnalyzerOperationDocument'
            )) {
            Set-Item -LiteralPath ('Function:local:' + $name) -Value {
                throw 'Constructing an executor attempted to resolve or read operation data.'
            }
        }
        $first = [ADAnalyzerRemediationExecutor]::new()
        $second = [ADAnalyzerRemediationExecutor]::new()
        Assert-Fixture (
            $first.GetType().Name -ceq 'ADAnalyzerRemediationExecutor' -and
            -not [object]::ReferenceEquals($first, $second) -and $script:trace.Count -eq 0
        ) 'The documented loader did not provide independent inert executors.'
    }
    Test-Fixture 'preview and apply expose explicit operation signatures' {
        $type = [ADAnalyzerRemediationExecutor]
        Assert-Fixture (
            $null -ne $type.GetMethod('Preview', [type[]]@([object], [string], [string])) -and
            $null -ne $type.GetMethod('Apply', [type[]]@([object], [string], [string], [object[]])) -and
            $null -ne $type.GetMethod('Apply', [type[]]@([object], [string], [string], [object[]], [pscredential]))
        ) 'The documented executor methods or signatures are missing.'
    }
}

function Forbid-NativeApply {
    Set-Item -LiteralPath 'Function:script:Invoke-ADAnalyzerRemediationPlan' -Value {
        throw 'The executor delegated Apply to the compatibility command.'
    }
}

function Assert-DryFixtureApply([object[]]$Rows, [object]$Plan) {
    Assert-Fixture ($Rows.Count -eq $Plan.Actions.Count -and $script:trace.Count -eq 0) 'Dry run observed a provider or lost reviewed rows.'
    for ($index = 0; $index -lt $Rows.Count; $index++) {
        Assert-Fixture (
            $Rows[$index].Status -ceq 'Skipped' -and $null -eq $Rows[$index].JournalPath -and
            $Rows[$index].ActionId -ceq $Plan.Actions[$index].ActionId -and
            $Rows[$index].ObjectGuid -ceq $Plan.Actions[$index].ObjectGuid
        ) 'Dry run changed the ordered native Skipped contract.'
    }
    Assert-Fixture (
        -not [IO.File]::Exists($script:path) -and -not [IO.File]::Exists($script:path + '.lock')
    ) 'Dry run persisted or acquired a journal.'
}

function Assert-FailedFixtureApply([string]$Status, [string]$Trace) {
    $journal = Read-FixtureJournal
    Assert-Fixture (
        $journal.Entries.Count -eq 1 -and $journal.Entries[0].Status -ceq $Status -and
        -not [string]::IsNullOrWhiteSpace($journal.Entries[0].Message) -and
        ($script:trace -join ',') -ceq $Trace
    ) ('Unexpected guarded failure sequence: ' + ($script:trace -join ','))
    Assert-FixtureLeaseReleased
}

function Invoke-DirectCases {
    Forbid-NativeApply
    $executor = [ADAnalyzerRemediationExecutor]::new()
    Test-Fixture 'preview and an empty approval set are offline including literal plan paths' {
        $plan = New-FixtureInput 'dry-run'
        $planPath = Join-Path $script:root 'reviewed [plan].json'
        $before = ConvertTo-FixtureJson $plan
        [IO.File]::WriteAllText($planPath, $before, [Text.UTF8Encoding]::new($false))
        Assert-DryFixtureApply ($executor.Preview($planPath, $script:server, $script:path)) $plan
        Assert-DryFixtureApply ($executor.Apply($plan, $script:server, $script:path, @())) $plan
        Assert-FixtureFailure {
            $executor.Preview($plan, 'other.fixture.invalid', $script:path)
        } 'differs from the DC recorded'
        Assert-FixtureFailure {
            $executor.Preview($plan, $script:server, 'Env:ADANALYZER_LOCAL_APPLY_FIXTURE')
        } 'FileSystem'
        Assert-Fixture (
            $script:trace.Count -eq 0 -and [IO.File]::ReadAllText($planPath) -ceq $before -and
            [IO.Directory]::GetFiles($script:root).Count -eq 1
        ) 'Local dry-run validation changed the approved snapshot or touched storage.'
    }
    Test-Fixture 'all approval IDs are validated before any lease or provider action' {
        $plan = New-FixtureInput 'invalid-approvals'
        $first = $plan.Actions[0].ActionId
        $alias = ([guid]$first).ToString('B')
        $faults = @(
            , @('44444444-4444-4444-8444-444444444444', 'does not belong')
            , @('not a fixture identity', 'does not belong')
            , @(@{ ActionId = $first }, 'does not belong')
            , @($null, 'does not belong')
            , @($alias, 'must be unique')
        )
        foreach ($fault in $faults) {
            Assert-FixtureFailure {
                $executor.Apply($plan, $script:server, $script:path, @($first, $fault[0]), $script:credential)
            } $fault[1]
            Assert-Fixture (
                $script:trace.Count -eq 0 -and [IO.Directory]::GetFiles($script:root).Count -eq 0
            ) 'An approved prefix ran before later malformed consent was rejected.'
        }
    }
    Test-Fixture 'canonical subset uses the pinned bundled provider in reviewed order' {
        $plan = New-FixtureInput 'ordered-subset'
        $script:allowProvider = $true
        $before = ConvertTo-FixtureJson $plan
        $requested = @([guid]$plan.Actions[2].ActionId, ([guid]$plan.Actions[0].ActionId).ToString('B'))
        $rows = $executor.Apply($plan, $script:server, $script:path, $requested, $script:credential)
        $journal = Read-FixtureJournal
        Assert-Fixture (
            ($rows.Status -join ',') -ceq 'Succeeded,Skipped,Succeeded' -and
            ($rows.ActionId -join ',') -ceq ($plan.Actions.ActionId -join ',') -and
            ($journal.Entries.ActionId -join ',') -ceq ($plan.Actions[0].ActionId + ',' + $plan.Actions[2].ActionId) -and
            ($journal.Entries.Status -join ',') -ceq 'Succeeded,Succeeded' -and
            $journal.PlanId -ceq $plan.PlanId -and $journal.Server -ceq $script:server -and
            ($script:trace -join ',') -ceq 'Import,Read:1,Import,Group,Effect:1,Read:1,Read:3,Import,Group,Effect:3,Read:3'
        ) 'Subset Apply changed plan ordering, persistence, provider timing or approval scope.'
        Assert-Fixture (
            $rows[0].Before.Enabled -is [bool] -and $rows[0].Before.Enabled -and
            $rows[0].After.Enabled -is [bool] -and -not $rows[0].After.Enabled -and
            $rows[0].After.ObjectGuid -ceq $plan.Actions[0].ObjectGuid -and
            (ConvertTo-FixtureJson $plan) -ceq $before
        ) 'The direct effect lost approved precondition/postcondition evidence or changed caller input.'
        $rows[0].After.DistinguishedName = 'changed result'
        Assert-Fixture (
            (Read-FixtureJournal).Entries[0].After.DistinguishedName -ceq $plan.Actions[0].DistinguishedName
        ) 'Returned rows retained mutable journal storage.'
        Assert-FixtureLeaseReleased
    }
    Test-Fixture 'completed replay and wrong journal scope reject before fresh provider reads' {
        foreach ($status in 'Succeeded', 'Undone', 'WrongScope') {
            $plan = New-FixtureInput ('replay-' + $status)
            New-FixtureJournalReplay $plan $status
            if ($status -eq 'WrongScope') {
                $outside = Read-FixtureJournal
                $outside.Server = 'foreign.fixture.invalid'
                [IO.File]::WriteAllText($script:path, (ConvertTo-FixtureJson $outside), [Text.UTF8Encoding]::new($false))
            }
            $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:path))
            Assert-FixtureFailure {
                $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
            } 'already been applied|different plan or server'
            Assert-Fixture (
                $script:trace.Count -eq 0 -and
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:path)) -ceq $before
            ) 'Replay or wrong-scope detection changed storage or used a provider.'
            Assert-FixtureLeaseReleased
        }
    }
    Test-Fixture 'fresh precondition and inactivity denials persist Rejected without an effect' {
        $plan = New-FixtureInput 'fresh-precondition'
        $script:allowProvider = $true
        $first = $script:objects[[guid]$plan.Actions[0].ObjectGuid]
        $first.WhenChanged = $first.WhenChanged.AddSeconds(1)
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'precondition failed'
        Assert-FailedFixtureApply 'Rejected' 'Import,Read:1'
        Assert-Fixture $first.Enabled 'A precondition denial ran the synthetic effect.'

        $plan = New-FixtureInput 'fresh-activity'
        $script:allowProvider = $true
        $first = $script:objects[[guid]$plan.Actions[0].ObjectGuid]
        $first.LastLogon = [datetime]::UtcNow.AddDays(-1).ToFileTimeUtc()
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'Fresh activity no longer satisfies'
        Assert-FailedFixtureApply 'Rejected' 'Import,Read:1,Import,Group'
        Assert-Fixture $first.Enabled 'A fresh inactivity denial ran the synthetic effect.'
    }
    Test-Fixture 'failed durable preparation stops before effects and releases the owner' {
        $plan = New-FixtureInput 'prepare-failure' 'PrepareConflict'
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'Journal persistence failed'
        Assert-Fixture (
            [IO.Directory]::Exists($script:path) -and -not [IO.File]::Exists($script:path) -and
            ($script:trace -join ',') -ceq 'Import,Read:1,Import,Group'
        ) 'Preparation failure attempted an effect, lost the original conflict or left a journal.'
        Assert-FixtureLeaseReleased

        $plan = New-FixtureInput 'prepare-secondary-recovery' 'PrepareSerialize'
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'Synthetic Prepared persistence failure'
        Assert-FailedFixtureApply 'Failed' 'Import,Read:1,Import,Group,Serialize:Prepared,Serialize:Failed'
    }
    Test-Fixture 'provider error keeps its cause and records Failed without a post-read' {
        $plan = New-FixtureInput 'provider-fault' 'EffectFault'
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'Synthetic Apply provider failure'
        Assert-FailedFixtureApply 'Failed' 'Import,Read:1,Import,Group,Effect:1'
    }
    Test-Fixture 'a performed but unverified effect never yields a success record' {
        $plan = New-FixtureInput 'postcondition-fault' 'Postcondition'
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'Unable to verify the account disable result'
        Assert-FailedFixtureApply 'Failed' 'Import,Read:1,Import,Group,Effect:1,Read:1'
        Assert-Fixture ((Read-FixtureJournal).Entries[0].After.Enabled -eq $true) 'Verification lost observed failure evidence.'
    }
    Test-Fixture 'terminal persistence failure keeps verified evidence and records Failed' {
        $plan = New-FixtureInput 'terminal-persistence' 'TerminalSerialize'
        $script:allowProvider = $true
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        } 'Synthetic Succeeded persistence failure'
        Assert-FailedFixtureApply 'Failed' 'Import,Read:1,Import,Group,Serialize:Prepared,Effect:1,Read:1,Serialize:Succeeded,Serialize:Failed'
        $entry = (Read-FixtureJournal).Entries[0]
        Assert-Fixture ($entry.Before.Enabled -and -not $entry.After.Enabled) 'Persistence recovery lost observed effect evidence.'
    }
    Test-Fixture 'late failed action preserves previous durable success and stops later work' {
        $plan = New-FixtureInput 'partial' 'EffectFault' $false
        $script:allowProvider = $true
        $script:faultIndex = 2
        Assert-FixtureFailure {
            $executor.Apply($plan, $script:server, $script:path, @($plan.Actions.ActionId))
        } 'Synthetic Apply provider failure'
        $journal = Read-FixtureJournal
        Assert-Fixture (
            ($journal.Entries.Status -join ',') -ceq 'Succeeded,Failed' -and
            ($journal.Entries.ActionId -join ',') -ceq ($plan.Actions[0].ActionId + ',' + $plan.Actions[1].ActionId) -and
            ($script:trace -join ',') -ceq 'Import,Read:1,Import,Group,Effect:1,Read:1,Read:2,Import,Group,Effect:2'
        ) 'A late failure lost committed evidence or began a later action.'
        Assert-FixtureLeaseReleased
    }
}

function Invoke-IsolationCases {
    Forbid-NativeApply
    $executor = [ADAnalyzerRemediationExecutor]::new()
    Test-Fixture 'separate and reused executors isolate consent and serialized state' {
        $firstPlan = New-FixtureInput 'first-reused' '' $false
        $script:allowProvider = $true
        $firstRows = $executor.Apply($firstPlan, $script:server, $script:path, @($firstPlan.Actions[1].ActionId))
        Assert-Fixture (($firstRows.Status -join ',') -ceq 'Skipped,Succeeded,Skipped') 'First operation changed consent.'
        Assert-FixtureLeaseReleased

        $secondPlan = New-FixtureInput 'second-reused' '' $false
        $independent = [ADAnalyzerRemediationExecutor]::new()
        Assert-DryFixtureApply ($independent.Preview($secondPlan, $script:server, $script:path)) $secondPlan
        Assert-DryFixtureApply ($executor.Apply($secondPlan, $script:server, $script:path, @())) $secondPlan
        $script:allowProvider = $true
        $secondRows = $executor.Apply($secondPlan, $script:server, $script:path, @($secondPlan.Actions[2].ActionId), [pscredential]::Empty)
        Assert-Fixture (($secondRows.Status -join ',') -ceq 'Skipped,Skipped,Succeeded') 'Reuse retained prior approval or provider state.'
        Assert-Fixture (
            (ConvertTo-FixtureJson $executor) -cnotmatch 'fixture|Credential|JournalPath|ApprovedActionIds'
        ) 'Executor serialization retained operation-local data.'
        Assert-FixtureLeaseReleased
    }
    Test-Fixture 'secondary documented loader disposal leaves original executor usable' {
        $plan = New-FixtureInput 'secondary-loader'
        $worker = [powershell]::Create()
        try {
            $child = @'
param($Fixture, $RepositoryRoot)
& $Fixture -RepositoryRoot $RepositoryRoot -Case Construction
'@
            $result = @($worker.AddScript($child).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
            Assert-Fixture (
                -not $worker.HadErrors -and @($result | Where-Object { $_ -ceq 'PASS remediation apply Construction 2' }).Count -eq 1
            ) ('Secondary executor loader failed: ' + ($worker.Streams.Error -join ' | '))
        }
        finally {
            $worker.Dispose()
        }
        $script:allowProvider = $true
        $rows = $executor.Apply($plan, $script:server, $script:path, @($plan.Actions[0].ActionId), $script:credential)
        Assert-Fixture (($rows.Status -join ',') -ceq 'Succeeded,Skipped,Skipped') 'Disposing another loader invalidated the live executor.'
        Assert-FixtureLeaseReleased
    }
}

switch ($Case) {
    'Construction' {
        Invoke-ConstructionCases
    }
    'Standalone' {
        Test-Fixture 'the operations module can construct the executor without its profile loader' {
            $executor = [ADAnalyzerRemediationExecutor]::new()
            Assert-Fixture (
                $executor.GetType().Name -ceq 'ADAnalyzerRemediationExecutor' -and
                $null -eq ('ADAnalyzerProfile' -as [type]) -and $script:trace.Count -eq 0
            ) 'Standalone construction acquired a dependency or provider.'
        }
    }
    { $_ -in 'Native', 'Direct', 'Isolation' } {
        $script:temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-apply-fixture-' + [guid]::NewGuid().ToString('N'))
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
Write-Output ('PASS remediation apply ' + $Case + ' ' + $script:passed)
