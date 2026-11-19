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

function Import-Module {
    throw 'The offline planner fixture attempted a module import.'
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

foreach ($name in @(
        'Invoke-Command', 'New-PSDrive', 'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE', 'Disable-ADAccount',
        'Enable-ADAccount', 'Invoke-ADAnalyzerRemediationPlan', 'Undo-ADAnalyzerRemediation', 'Enter-ADAnalyzerJournalLease',
        'Get-ADAnalyzerOperationJournal', 'Save-ADAnalyzerOperationJournal', 'Write-ADAnalyzerOperationFile', 'Write-ADAnalyzerFile'
    )) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        throw 'The offline planner fixture encountered an external effect.'
    }
}

if ($Case -eq 'Native') {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;

public sealed class FixturePlannerObservationDictionary : Hashtable
{
    public List<string> Trace;
    public string Label;
    public string FailingName;
    public int FailOnRead;
    public string FailureMessage;
    private int matchingReads;

    public override bool Contains(object key)
    {
        string name = key as string;
        Trace.Add(Label + ".Contains." + name);
        if (String.Equals(name, FailingName, StringComparison.OrdinalIgnoreCase))
        {
            matchingReads++;
            if (matchingReads == FailOnRead)
            {
                throw new InvalidOperationException(FailureMessage);
            }
        }
        return base.Contains(key);
    }
}
'@
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
        Write-Host ('FAIL remediation planner ' + $Name)
        throw
    }
}

function Assert-FixtureFailure([scriptblock]$Body, [string]$Pattern) {
    $failure = $null
    try {
        $null = & $Body
    }
    catch {
        $failure = $_
    }
    Assert-Fixture (
        $null -ne $failure -and $failure.Exception.Message -match $Pattern
    ) ('Unexpected planner error: ' + $failure)
}

function New-FixtureInput {
    $object = [pscustomobject][ordered]@{
        ObjectGuid = '11111111-1111-4111-8111-111111111111'
        SID = 'S-1-5-21-10-20-30-1101'
        DistinguishedName = 'CN=Fixture,OU=People,DC=offline,DC=invalid'
        ObjectClass = 'User'
        AccountType = 'User'
        Enabled = $true
        UserAccountControl = 512
        WhenChanged = [datetimeoffset]'2026-01-01T02:00:00+02:00'
        AdminCount = 0
        ProtectedFromAccidentalDeletion = $false
        Privileged = $false
        PrivilegeResolutionStatus = 'Complete'
        IsCriticalSystemObject = $false
        IsDomainController = $false
        PrimaryGroupID = 513
        SafetyMetadataStatus = 'Collected'
        SIDHistory = @()
    }
    $finding = [pscustomobject][ordered]@{
        RuleId = 'ACCOUNT.INACTIVE'
        Status = 'Fail'
        Target = $object.DistinguishedName
        ObjectGuid = $object.ObjectGuid
        SID = $object.SID
        Suppressed = $false
    }
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Remediation.AllowDisable = $true
    $profile.Remediation.ApprovedObjectGuids = @($object.ObjectGuid)
    $profile.Policy.UserInactivityDays = 44
    $profile.Policy.ComputerInactivityDays = 77
    $assessment = [pscustomobject][ordered]@{
        SchemaVersion = 1
        RunId = 'planner-fixture'
        Target = 'offline.invalid'
        Context = @{ Server = 'selected.fixture.invalid' }
        Objects = @($object)
        Findings = @($finding)
    }
    [pscustomobject]@{
        Assessment = $assessment
        Profile = $profile
        Object = $object
        Finding = $finding
    }
}

function New-FixtureSnapshot([string]$Name, [AllowNull()][string]$Text) {
    $path = Join-Path $script:temporary $Name
    [IO.File]::WriteAllText($path, $Text, [Text.UTF8Encoding]::new($false))
    return $path
}

function ConvertTo-StablePlan([object]$Plan) {
    $identity = [guid]::Empty
    Assert-Fixture (
        [guid]::TryParseExact([string]$Plan.PlanId, 'D', [ref]$identity) -and $identity -ne [guid]::Empty
    ) 'The planner did not produce a valid plan identity.'
    $created = [datetimeoffset]::ParseExact(
        $Plan.CreatedAt, 'o', [Globalization.CultureInfo]::InvariantCulture
    )
    Assert-Fixture ($created.Offset -eq [timespan]::Zero) 'The plan timestamp is not UTC.'
    $actionIds = [Collections.Generic.HashSet[guid]]::new()
    $stable = [ordered]@{}
    foreach ($member in $Plan.PSObject.Properties) {
        switch ($member.Name) {
            'PlanId' {
                $stable.PlanId = '{generated}'
            }
            'CreatedAt' {
                $stable.CreatedAt = '{generated UTC}'
            }
            'Actions' {
                Assert-Fixture ($member.Value -is [array]) 'The actions lost their array shape.'
                $stable.Actions = @(
                    foreach ($action in $member.Value) {
                        $actionId = [guid]::Empty
                        Assert-Fixture (
                            [guid]::TryParseExact([string]$action.ActionId, 'D', [ref]$actionId) -and
                            $actionId -ne [guid]::Empty -and $actionIds.Add($actionId)
                        ) 'The offline actions have malformed or duplicate generated identities.'
                        $fields = [ordered]@{}
                        foreach ($property in $action.PSObject.Properties) {
                            if ($property.Name -eq 'ActionId') {
                                $fields.ActionId = '{generated}'
                            }
                            else {
                                $fields[$property.Name] = $property.Value
                            }
                        }
                        $fields
                    }
                )
            }
            default {
                $stable[$member.Name] = $member.Value
            }
        }
    }
    Assert-Fixture ($Plan.Excluded -is [array] -and $Plan.PrivilegedSids -is [array]) 'The plan lost an array field.'
    return $stable
}

function ConvertTo-FixtureJson([object]$Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Compress -Depth 25
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

# Exact New-ADAnalyzerRemediationPlan body from accepted d632e15.
# 015f9a4127d9f129013acd69472c2e1cf772e7e40a6f5a75cd81f827d73a5a26
$script:acceptedPlannerBody = @'
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Assessment,
        [AllowNull()]$Profile

    )
    $assessmentObject = Read-ADAnalyzerOperationDocument $Assessment
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $settings = $configuration.Remediation
    $data = Get-ADAnalyzerOperationValue $assessmentObject @('Data')
    $directory = Get-ADAnalyzerOperationValue $data @('Directory')
    $domain = Get-ADAnalyzerOperationValue $directory @('Domain')
    $domainSid = [string](Get-ADAnalyzerOperationValue $domain @('SID', 'DomainSID'))
    $rootDomainSid = [string](Get-ADAnalyzerOperationValue $domain @('RootDomainSID'))
    $privilegeContextMissing = $false
    $privileged = @(Get-ADAnalyzerOperationValue $domain @('PrivilegedSids') @() | Where-Object { $null -ne $_ })
    for ($index = 0; $index -lt $privileged.Count; $index++) {
        $entry = $privileged[$index]
        if ($entry -is [string]) {
            $privileged[$index] = [string]$entry
        }
        elseif ($entry -is [System.Security.Principal.SecurityIdentifier]) {
            $privileged[$index] = [string]$entry.PSBase.Value
        }
        else {
            throw 'Assessment privilege policy contains an unsupported SID value type'
        }
    }
    foreach ($sid in @($configuration.Policy.PrivilegedSids)) {
        if (([string]$sid).Contains('{DomainSid}') -and -not $domainSid) {
            $privilegeContextMissing = $true
        }
        if (([string]$sid).Contains('{RootDomainSid}') -and -not $rootDomainSid) {
            $privilegeContextMissing = $true
        }
        $expanded = ([string]$sid).Replace('{DomainSid}', $domainSid).Replace('{RootDomainSid}', $rootDomainSid)
        if ($expanded -and $expanded -match '^S-\d-') {
            $privileged += , $expanded
        }
    }
    $objects = @{}
    foreach ($object in @(Get-ADAnalyzerOperationValue $assessmentObject @('Objects') @())) {
        if ($null -eq $object) {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $object @('ObjectGuid'))
        if ($guid) {
            $objects[$guid] = $object
        }
    }
    $approved = @(foreach ($value in @($settings.ApprovedObjectGuids)) {
            ConvertTo-ADAnalyzerOperationGuid $value
        })
    $actions = [Collections.ArrayList]::new()
    $excluded = [Collections.ArrayList]::new()
    $seen = @{}
    foreach ($finding in @(Get-ADAnalyzerOperationValue $assessmentObject @('Findings') @())) {
        if ($null -eq $finding) {
            continue
        }
        $rule = [string](Get-ADAnalyzerOperationValue $finding @('RuleId'))
        if ($rule -notin @('ACCOUNT.INACTIVE',
                'COMPUTER.INACTIVE') -or
            [string](Get-ADAnalyzerOperationValue $finding @('Status')) -ne 'Fail') {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $finding @('ObjectGuid'))
        $reason = $null
        if (-not $settings.AllowDisable) {
            $reason = 'RemediationDisabled'
        }
        elseif ($privilegeContextMissing) {
            $reason = 'PrivilegedPolicyContextMissing'
        }
        elseif ([bool](Get-ADAnalyzerOperationValue $finding @('Suppressed') $false)) {
            $reason = 'SuppressedFinding'
        }
        elseif (-not $guid -or -not $objects.ContainsKey($guid)) {
            $reason = 'MissingObjectEvidence'
        }
        elseif ($guid -notin $approved) {
            $reason = 'ObjectNotExplicitlyApproved'
        }
        elseif (($rule -eq 'ACCOUNT.INACTIVE' -and
                (Get-ADAnalyzerOperationKind $objects[$guid]) -ne 'User') -or
            ($rule -eq 'COMPUTER.INACTIVE' -and
            (Get-ADAnalyzerOperationKind $objects[$guid]) -ne 'Computer')) {
            $reason = 'RuleObjectClassMismatch'
        }
        else {
            $reason = Get-ADAnalyzerOperationExclusion $objects[$guid] $settings
        }
        if (-not $reason -and $actions.Count -ge $settings.MaximumActions) {
            $reason = 'MaximumActionsReached'
        }
        if ($reason) {
            $null = $excluded.Add([pscustomobject]@{
                    RuleId = $rule
                    ObjectGuid = $guid
                    Target = Get-ADAnalyzerOperationValue $finding @('Target')
                    Reason = $reason
                })
            continue
        }
        if ($seen.ContainsKey($guid)) {
            continue
        }
        $seen[$guid] = $true
        $object = $objects[$guid]
        $state = Get-ADAnalyzerOperationState $object
        $null = $actions.Add([pscustomobject][ordered]@{
                ActionId = [guid]::NewGuid().ToString('D')
                Action = 'DisableAccount'
                RuleId = $rule
                ObjectGuid = $state.ObjectGuid
                SID = $state.SID
                DistinguishedName = $state.DistinguishedName
                ObjectClass = Get-ADAnalyzerOperationKind $object
                AccountType = Get-ADAnalyzerOperationValue $object @('AccountType')
                InactivityDays = $(if ((Get-ADAnalyzerOperationKind $object) -eq 'Computer') {
                        $configuration.Policy.ComputerInactivityDays
                    }
                    else {
                        $configuration.Policy.UserInactivityDays
                    })
                Preconditions = $state
            })
    }
    $plan = [pscustomobject][ordered]@{
        SchemaVersion = 1
        PlanType = 'ADAnalyzerRemediationPlan'
        PlanId = [guid]::NewGuid().ToString('D')
        CreatedAt = [datetimeoffset]::UtcNow.ToString('o')
        AssessmentRunId = Get-ADAnalyzerOperationValue $assessmentObject @('RunId')
        Target = Get-ADAnalyzerOperationValue $assessmentObject @('Target')
        Context = ConvertTo-ADAnalyzerSafeData (Get-ADAnalyzerOperationValue $assessmentObject @('Context'))
        Remediation = ConvertTo-ADAnalyzerSafeData $settings
        AccountClassification = ConvertTo-ADAnalyzerSafeData $configuration.AccountClassification
        PrivilegedSids = @($privileged | Select-Object -Unique)
        Actions = $actions.ToArray()
        Excluded = $excluded.ToArray()
    }
    $projector = [ADAnalyzerEvidenceProjector]::new()
    $plan.AssessmentRunId = $projector.ProjectIdentityMetadata($plan.AssessmentRunId)
    $plan.Target = $projector.ProjectIdentityMetadata($plan.Target)
    foreach ($item in $plan.Excluded) {
        $item.Target = $projector.ProjectIdentityMetadata($item.Target)
    }
    foreach ($action in $plan.Actions) {
        $action.AccountType = $projector.ProjectIdentityMetadata($action.AccountType)
    }
    return $plan
'@

function Invoke-NativePlanner {
    [CmdletBinding()]
    param([Collections.IDictionary]$Arguments)

    New-ADAnalyzerRemediationPlan @Arguments
}

function New-FixtureFaultDictionary(
    [object]$Source,
    [string]$Label,
    [string]$Property,
    [int]$Occurrence,
    [string]$Message
) {
    $record = [FixturePlannerObservationDictionary]::new()
    $record.PSBase.Trace = $script:trace
    $record.PSBase.Label = $Label
    $record.PSBase.FailingName = $Property
    $record.PSBase.FailOnRead = $Occurrence
    $record.PSBase.FailureMessage = $Message
    foreach ($member in $Source.PSObject.Properties) {
        $record[$member.Name] = $member.Value
    }
    return $record
}

function Get-NativePlannerObservation([string]$Scenario, [string]$Preference) {
    $script:trace = [Collections.Generic.List[string]]::new()
    $fixture = New-FixtureInput
    $arguments = [ordered]@{
        Assessment = $fixture.Assessment
        Profile = $fixture.Profile
    }
    switch ($Scenario) {
        'Approved' {
            $fixture.Object | Add-Member -MemberType ScriptProperty -Name ObjectClass -Force -Value {
                $script:trace.Add('Object.ObjectClass')
                return 'User'
            }
            $fixture.Assessment | Add-Member -MemberType ScriptProperty -Name RunId -Force -Value {
                $script:trace.Add('Assessment.RunId')
                return 'planner-fixture'
            }
        }
        'DefaultProfile' {
            $arguments.Remove('Profile')
        }
        'NullProfile' {
            $arguments.Profile = $null
        }
        'SkippedStatus' {
            $fixture.Finding.RuleId = 'PASSWORD.AGE'
            $fixture.Finding | Add-Member -MemberType ScriptProperty -Name Status -Force -Value {
                $script:trace.Add('Unexpected.Status')
                throw 'The planner must not read the status of an unrelated rule.'
            }
        }
        'StatusFault' {
            $fixture.Finding | Add-Member -MemberType ScriptProperty -Name Status -Force -Value {
                $script:trace.Add('Finding.Status')
                throw [InvalidOperationException]::new('FixturePlannerStatusFault')
            }
        }
        { $_ -in 'ProfileFault', 'DocumentFault' } {
            $profile = [pscustomobject]@{}
            $profile | Add-Member -MemberType ScriptProperty -Name Remediation -Value {
                $script:trace.Add('Profile.Remediation')
                return @{ AllowDisable = 'invalid fixture Boolean' }
            }
            $arguments.Profile = $profile
            if ($Scenario -eq 'DocumentFault') {
                $arguments.Assessment = New-FixtureSnapshot 'malformed [planner].json' '{"SchemaVersion":'
            }
        }
        'UnsupportedSid' {
            $data = @{
                Directory = @{
                    Domain = @{
                        PrivilegedSids = @(@{ Value = 'S-1-5-21-10-20-30-1201' })
                    }
                }
            }
            $fixture.Assessment | Add-Member -NotePropertyName Data -NotePropertyValue $data
        }
        'RunIdFault' {
            $arguments.Assessment = New-FixtureFaultDictionary $fixture.Assessment 'Assessment' 'RunId' 1 'FixturePlannerRunIdFault'
        }
        { $_ -in 'ObjectClass1', 'ObjectClass2', 'ObjectClass4' } {
            $occurrence = [int]$Scenario.Substring('ObjectClass'.Length)
            $parameters = @{
                Source = $fixture.Object
                Label = 'Object'
                Property = 'ObjectClass'
                Occurrence = $occurrence
                Message = 'FixturePlannerObjectClassFault' + $occurrence
            }
            $fixture.Assessment.Objects[0] = New-FixtureFaultDictionary @parameters
        }
    }

    $records = [Collections.Generic.List[object]]::new()
    $captured = [Collections.ArrayList]::new()
    $caught = $null
    $completed = $false
    $Error.Clear()
    try {
        Invoke-NativePlanner -Arguments $arguments -ErrorAction $Preference -ErrorVariable +captured *>&1 |
            ForEach-Object {
                $records.Add($_)
            }
        $completed = $true
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    [ordered]@{
        Completed = $completed
        Caught = Get-FixtureDiagnostic $caught
        Captured = Get-FixtureDiagnostic $captured
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
                elseif ($item.PlanType -eq 'ADAnalyzerRemediationPlan') {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Plan = ConvertTo-StablePlan $item
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
}

function Assert-NativePlannerParity([string]$Scenario, [string]$Preference) {
    $name = 'New-ADAnalyzerRemediationPlan'
    $path = 'Function:script:' + $name
    $original = (Get-Command $name -CommandType Function).ScriptBlock
    $accepted = [scriptblock]::Create($script:acceptedPlannerBody)
    $acceptedParameters = $accepted.Ast.ParamBlock.Extent.Text.Replace("`r`n", "`n")
    $originalAst = $original.Ast
    if ($originalAst -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $originalAst = $originalAst.Body
    }
    $actualParameters = $originalAst.ParamBlock.Extent.Text.Replace("`r`n", "`n")
    Assert-Fixture ($acceptedParameters -ceq $actualParameters) 'The native planner parameter declaration changed.'
    try {
        Set-Item -LiteralPath $path -Value $accepted
        Assert-Fixture (
            (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $accepted.ToString()
        ) 'The archived planner body was not installed in script scope.'
        $expected = Get-NativePlannerObservation $Scenario $Preference
    }
    finally {
        Set-Item -LiteralPath $path -Value $original
    }
    Assert-Fixture (
        (Get-Command $name -CommandType Function).ScriptBlock.ToString() -ceq $original.ToString()
    ) 'The current planner body was not restored.'
    $serialized = ConvertTo-FixtureJson $expected
    $witness = switch ($Scenario) {
        'Approved' {
            $expected.Completed -and $expected.Stream.Count -eq 1 -and $expected.Stream[0].Plan.Actions.Count -eq 1 -and
            ($expected.Trace -join ',') -ceq 'Object.ObjectClass,Object.ObjectClass,Object.ObjectClass,Object.ObjectClass,Assessment.RunId'
        }
        { $_ -in 'DefaultProfile', 'NullProfile' } {
            $expected.Completed -and $expected.Stream[0].Plan.Actions.Count -eq 0 -and
            $expected.Stream[0].Plan.Excluded[0].Reason -ceq 'RemediationDisabled'
        }
        'SkippedStatus' {
            $expected.Completed -and $expected.Trace.Count -eq 0 -and
            $expected.Stream[0].Plan.Actions.Count -eq 0 -and $expected.Stream[0].Plan.Excluded.Count -eq 0
        }
        'StatusFault' {
            ($expected.Trace -join ',') -ceq 'Finding.Status' -and $serialized.Contains('FixturePlannerStatusFault')
        }
        'ProfileFault' {
            -not $expected.Completed -and ($expected.Trace -join ',') -ceq 'Profile.Remediation' -and
            $serialized.Contains('Remediation.AllowDisable must be a boolean')
        }
        'DocumentFault' {
            -not $expected.Completed -and $expected.Trace.Count -eq 0 -and $serialized.Contains('ConvertFromJsonCommand')
        }
        'UnsupportedSid' {
            -not $expected.Completed -and $serialized.Contains('Assessment privilege policy contains an unsupported SID value type')
        }
        'RunIdFault' {
            -not $expected.Completed -and $expected.Trace[-1] -ceq 'Assessment.Contains.RunId' -and
            $serialized.Contains('FixturePlannerRunIdFault') -and $serialized.Contains('System.InvalidOperationException')
        }
        { $_ -in 'ObjectClass1', 'ObjectClass2', 'ObjectClass4' } {
            $occurrence = [int]$Scenario.Substring('ObjectClass'.Length)
            $reads = @($expected.Trace | Where-Object { $_ -ceq 'Object.Contains.ObjectClass' })
            -not $expected.Completed -and $expected.Stream.Count -eq 0 -and $reads.Count -eq $occurrence -and
            $expected.Trace[-1] -ceq 'Object.Contains.ObjectClass' -and
            $expected.Caught.Cause -ceq 'System.InvalidOperationException' -and
            $expected.Caught.Message -ceq ('FixturePlannerObjectClassFault' + $occurrence)
        }
    }
    Assert-Fixture $witness (
        "The archive missed $Scenario with ErrorAction=$Preference." + [Environment]::NewLine + $serialized
    )
    $actual = ConvertTo-FixtureJson (Get-NativePlannerObservation $Scenario $Preference)
    Assert-Fixture ($actual -ceq $serialized) (
        "Native planner changed for $Scenario with ErrorAction=$Preference." + [Environment]::NewLine +
        'Accepted: ' + $serialized + [Environment]::NewLine + 'Current: ' + $actual
    )
}

function Invoke-NativeCases {
    foreach ($scenario in @(
            'Approved', 'DefaultProfile', 'NullProfile', 'SkippedStatus', 'ProfileFault', 'DocumentFault', 'UnsupportedSid',
            'RunIdFault', 'ObjectClass1', 'ObjectClass2', 'ObjectClass4'
        )) {
        Test-Fixture $scenario {
            Assert-NativePlannerParity $scenario 'Stop'
        }
    }
    foreach ($preference in 'Continue', 'Ignore') {
        Test-Fixture ('StatusFault ' + $preference) {
            Assert-NativePlannerParity 'StatusFault' $preference
        }
    }
}

function Invoke-ConstructionCases {
    Test-Fixture 'documented literal construction stays inert and independent' {
        function Read-ADAnalyzerOperationDocument {
            throw 'The planner constructor attempted to read an assessment.'
        }
        function Import-ADAnalyzerProfile {
            throw 'The planner constructor attempted to load a profile.'
        }
        function Test-Path {
            throw 'The planner constructor attempted to query a path.'
        }
        $left = [ADAnalyzerRemediationPlanner]::new()
        $right = [ADAnalyzerRemediationPlanner]::new()
        Assert-Fixture (
            $left.GetType().Name -ceq 'ADAnalyzerRemediationPlanner' -and
            -not [object]::ReferenceEquals($left, $right)
        ) 'The documented loader did not provide independent planner instances.'
    }
    Test-Fixture 'public CreatePlan overloads accept assessment and optional profile' {
        $type = [ADAnalyzerRemediationPlanner]
        $short = $type.GetMethod('CreatePlan', [type[]]@([object]))
        $long = $type.GetMethod('CreatePlan', [type[]]@([object], [object]))
        Assert-Fixture (
            $null -ne $short -and $short.ReturnType -eq [object] -and
            $null -ne $long -and $long.ReturnType -eq [object]
        ) 'The documented plan creation overloads are absent.'
    }
}

function Forbid-PlannerWrapper {
    Set-Item -LiteralPath 'Function:script:New-ADAnalyzerRemediationPlan' -Value {
        throw 'The class delegated its planning operation to the compatibility command.'
    }
}

function Add-FixturePlanMetadata($Fixture, [string]$Marker) {
    $metadata = [ordered]@{
        Nested = [pscustomobject][ordered]@{
            Label = 'plan identity fixture'
            Password = $Marker
            Values = @(
                [guid]'33333333-3333-4333-8333-333333333333'
                [datetime]'2026-01-02T01:00:00Z'
                [datetimeoffset]'2026-01-02T01:00:00+01:00'
            )
        }
    }
    $Fixture.Assessment.RunId = $metadata
    $Fixture.Assessment.Target = $metadata
    $Fixture.Object.ObjectClass = 'Computer'
    $Fixture.Object.AccountType = $metadata
    $Fixture.Object.UserAccountControl = 4096
    $Fixture.Object.PrimaryGroupID = 515
    $Fixture.Finding.RuleId = 'COMPUTER.INACTIVE'
    $suppressed = $Fixture.Finding.PSObject.Copy()
    $suppressed.Target = $metadata
    $suppressed.Suppressed = $true
    $Fixture.Assessment.Findings += , $suppressed
    return $metadata
}

function Invoke-DirectCases {
    $reference = New-FixtureInput
    $expected = New-ADAnalyzerRemediationPlan -Assessment $reference.Assessment -Profile $reference.Profile
    Forbid-PlannerWrapper
    $planner = [ADAnalyzerRemediationPlanner]::new()

    Test-Fixture 'default and explicit null profiles remain offline and disabled' {
        $fixture = New-FixtureInput
        foreach ($plan in @(
                $planner.CreatePlan($fixture.Assessment)
                $planner.CreatePlan($fixture.Assessment, $null)
            )) {
            Assert-Fixture (
                $plan.Actions.Count -eq 0 -and $plan.Excluded.Count -eq 1 -and
                $plan.Excluded[0].Reason -ceq 'RemediationDisabled'
            ) 'Default review unexpectedly proposed an action.'
            $null = ConvertTo-StablePlan $plan
        }
    }
    Test-Fixture 'direct approved plan matches the command and retains its ordered bound schema' {
        $fixture = New-FixtureInput
        $assessmentBefore = ConvertTo-FixtureJson $fixture.Assessment
        $profileBefore = ConvertTo-FixtureJson $fixture.Profile
        $plan = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            (ConvertTo-FixtureJson (ConvertTo-StablePlan $plan)) -ceq
            (ConvertTo-FixtureJson (ConvertTo-StablePlan $expected))
        ) 'Direct and command approved plan content diverged.'
        Assert-Fixture (
            ($plan.PSObject.Properties.Name -join ',') -ceq
            'SchemaVersion,PlanType,PlanId,CreatedAt,AssessmentRunId,Target,Context,Remediation,AccountClassification,PrivilegedSids,Actions,Excluded' -and
            ($plan.Actions[0].PSObject.Properties.Name -join ',') -ceq
            'ActionId,Action,RuleId,ObjectGuid,SID,DistinguishedName,ObjectClass,AccountType,InactivityDays,Preconditions'
        ) 'The direct planner changed the ordered DTO schema.'
        Assert-Fixture (
            $plan.Actions.Count -eq 1 -and $plan.Actions[0].InactivityDays -eq 44 -and
            $plan.Actions[0].Preconditions.ObjectGuid -ceq $fixture.Object.ObjectGuid -and
            $plan.Actions[0].Preconditions.SID -ceq $fixture.Object.SID
        ) 'The direct planner lost reviewed User identity or threshold.'
        $guard = [ADAnalyzerRemediationGuard]::new()
        $guard.AssertPlan($plan)
        Assert-Fixture (
            (ConvertTo-FixtureJson $fixture.Assessment) -ceq $assessmentBefore -and
            (ConvertTo-FixtureJson $fixture.Profile) -ceq $profileBefore
        ) 'The direct planner mutated its supplied assessment or profile.'
    }
    Test-Fixture 'class selection, last observation, action cap and deduplication keep their priority' {
        $fixture = New-FixtureInput
        $old = $fixture.Object.PSObject.Copy()
        $old.ObjectGuid = ([guid]$old.ObjectGuid).ToString('B')
        $old.AdminCount = 1
        $duplicate = $fixture.Finding.PSObject.Copy()
        $duplicate.ObjectGuid = $old.ObjectGuid
        $computer = $fixture.Object.PSObject.Copy()
        $computer.ObjectGuid = '22222222-2222-4222-8222-222222222222'
        $computer.SID = 'S-1-5-21-10-20-30-1102'
        $computer.DistinguishedName = 'CN=Fixture Computer,DC=offline,DC=invalid'
        $computer.ObjectClass = @('top', 'User', 'Computer')
        $computer.AccountType = 'Computer'
        $computer.UserAccountControl = 4096
        $computer.PrimaryGroupID = 515
        $rightRule = $fixture.Finding.PSObject.Copy()
        $rightRule.ObjectGuid = $computer.ObjectGuid
        $rightRule.SID = $computer.SID
        $rightRule.Target = $computer.DistinguishedName
        $rightRule.RuleId = 'COMPUTER.INACTIVE'
        $wrongRule = $rightRule.PSObject.Copy()
        $wrongRule.RuleId = 'ACCOUNT.INACTIVE'
        $fixture.Assessment.Objects = @($old, $fixture.Object, $computer)
        $fixture.Assessment.Findings = @($fixture.Finding, $duplicate, $wrongRule, $rightRule)
        $fixture.Profile.Remediation.ApprovedObjectGuids = @($old.ObjectGuid, $computer.ObjectGuid)

        $fixture.Profile.Remediation.MaximumActions = 2
        $open = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $open.Actions.Count -eq 2 -and $open.Excluded.Count -eq 1 -and
            $open.Excluded[0].Reason -ceq 'RuleObjectClassMismatch' -and
            ($open.Actions.ObjectGuid -join ',') -ceq ($fixture.Object.ObjectGuid + ',' + $computer.ObjectGuid) -and
            $open.Actions[1].ObjectClass -ceq 'Computer' -and $open.Actions[1].InactivityDays -eq 77
        ) 'Duplicate identities or Computer classification changed the plan.'
        $null = ConvertTo-StablePlan $open

        $fixture.Profile.Remediation.MaximumActions = 1
        $limited = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $limited.Actions.Count -eq 1 -and $limited.Excluded.Count -eq 3 -and
            ($limited.Excluded.Reason -join ',') -ceq 'MaximumActionsReached,RuleObjectClassMismatch,MaximumActionsReached' -and
            ($limited.Excluded.ObjectGuid -join ',') -ceq ($fixture.Object.ObjectGuid + ',' + $computer.ObjectGuid + ',' + $computer.ObjectGuid)
        ) 'The reviewed cap no longer precedes duplicate skips and keeps exclusion order.'
    }
    Test-Fixture 'structured plan metadata yields detached typed leaves and Boolean presence only' {
        $fixture = New-FixtureInput
        $marker = 'fixture-planner-inert-value'
        $source = Add-FixturePlanMetadata $fixture $marker
        $plan = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $plan.Actions.Count -eq 1 -and $plan.Excluded.Count -eq 1 -and
            $plan.Excluded[0].Reason -ceq 'SuppressedFinding' -and -not (ConvertTo-FixtureJson $plan).Contains($marker)
        ) 'Structured plan metadata changed eligibility or exposed source data.'
        $projected = @($plan.AssessmentRunId, $plan.Target, $plan.Actions[0].AccountType, $plan.Excluded[0].Target)
        foreach ($entry in $projected) {
            $leaves = $entry.Nested.Values
            Assert-Fixture (
                $entry.Nested.Label -ceq 'plan identity fixture' -and
                $entry.Nested.PasswordPresent -is [bool] -and $entry.Nested.PasswordPresent -and
                $null -eq $entry.Nested.PSObject.Properties['Password'] -and
                -not [object]::ReferenceEquals($entry, $source) -and
                -not [object]::ReferenceEquals($entry.Nested, $source.Nested)
            ) 'A structured result lost its typed presence or retained input references.'
            Assert-Fixture (
                $leaves -is [array] -and $leaves.Count -eq 3 -and $leaves[0] -is [guid] -and
                $leaves[1] -is [datetime] -and $leaves[2] -is [datetimeoffset] -and
                $leaves[0] -eq $source.Nested.Values[0] -and $leaves[1] -eq $source.Nested.Values[1] -and
                $leaves[1].Kind -eq $source.Nested.Values[1].Kind -and $leaves[2] -eq $source.Nested.Values[2] -and
                $leaves[2].Offset -eq $source.Nested.Values[2].Offset
            ) 'Structured plan metadata changed its supported nested values.'
        }
        $projected[0].Nested.Label = 'changed result'
        Assert-Fixture (
            $projected[1].Nested.Label -ceq 'plan identity fixture' -and
            $source.Nested.Label -ceq 'plan identity fixture' -and $source.Nested.Password -ceq $marker
        ) 'Projected result slots share mutable metadata.'
    }
    Test-Fixture 'literal bracket paths read offline and malformed documents fail before profile inspection' {
        $fixture = New-FixtureInput
        $encoded = ConvertTo-FixtureJson $fixture.Assessment
        $path = New-FixtureSnapshot 'assessment [planner].json' $encoded
        $filePlan = $planner.CreatePlan($path, $fixture.Profile)
        $objectPlan = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            (ConvertTo-FixtureJson (ConvertTo-StablePlan $filePlan)) -ceq
            (ConvertTo-FixtureJson (ConvertTo-StablePlan $objectPlan)) -and
            [IO.File]::ReadAllText($path) -ceq $encoded
        ) 'A literal saved assessment changed the approved plan or was rewritten.'

        $script:trace = [Collections.Generic.List[string]]::new()
        $profile = [pscustomobject]@{}
        $profile | Add-Member -MemberType ScriptProperty -Name Remediation -Value {
            $script:trace.Add('Unexpected.Profile')
            throw 'A malformed assessment must fail before observing its profile.'
        }
        $bad = New-FixtureSnapshot 'bad [planner].json' '{"SchemaVersion":'
        $reader = [ADAnalyzerOperationDocumentReader]::new()
        $referenceFailure = $null
        try {
            $null = $reader.Read($bad)
        }
        catch {
            $referenceFailure = $_.Exception.GetBaseException().Message
        }
        Assert-Fixture (-not [string]::IsNullOrEmpty($referenceFailure)) 'The malformed reader control did not fail.'
        Assert-FixtureFailure { $planner.CreatePlan($bad, $profile) } ([regex]::Escape($referenceFailure))
        Assert-Fixture ($script:trace.Count -eq 0) 'The malformed assessment observed its profile.'
    }
    Test-Fixture 'snapshot privilege identities detach strings and reject rich SID values' {
        $fixture = New-FixtureInput
        $wrapped = Add-Member -InputObject 's-1-5-21-10-20-30-3169' -NotePropertyName cpassword -NotePropertyValue 'inert-note' -PassThru
        $domain = @{
            SID = 'S-1-5-21-10-20-30'
            RootDomainSID = 'S-1-5-21-40-50-60'
            PrivilegedSids = @($wrapped, '{DomainSid}-3167', 's-1-5-21-10-20-30-3169', $null)
        }
        $fixture.Assessment | Add-Member -NotePropertyName Data -NotePropertyValue @{ Directory = @{ Domain = $domain } }
        $fixture.Profile.Policy.PrivilegedSids = @('{DomainSid}-3167')
        $plan = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $plan.Actions.Count -eq 1 -and $plan.PrivilegedSids -is [array] -and
            ($plan.PrivilegedSids -join ',') -ceq 's-1-5-21-10-20-30-3169,{DomainSid}-3167,S-1-5-21-10-20-30-3167' -and
            $plan.PrivilegedSids[0] -is [string] -and $null -eq $plan.PrivilegedSids[0].PSObject.Properties['cpassword'] -and
            $wrapped.cpassword -ceq 'inert-note'
        ) 'The planner altered privilege ordering or exposed an extended SID property.'
        $domain.PrivilegedSids = @(@{ Value = 'S-1-5-21-10-20-30-3171' })
        Assert-FixtureFailure {
            $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        } '^.*Assessment privilege policy contains an unsupported SID value type'
    }
    Test-Fixture 'direct exclusion preserves priority and leaves unused account evidence untouched' {
        $fixture = New-FixtureInput
        $fixture.Profile.Remediation.AllowDisable = $false
        $fixture.Profile.Policy.PrivilegedSids = @('{RootDomainSid}-3168')
        $fixture.Finding.Suppressed = $true
        $disabled = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        $fixture.Profile.Remediation.AllowDisable = $true
        $missingScope = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $disabled.Actions.Count -eq 0 -and $disabled.Excluded[0].Reason -ceq 'RemediationDisabled' -and
            $missingScope.Actions.Count -eq 0 -and $missingScope.Excluded[0].Reason -ceq 'PrivilegedPolicyContextMissing'
        ) 'Plan review and required privilege scope changed priority.'

        $script:trace = [Collections.Generic.List[string]]::new()
        $fixture.Finding.Suppressed = $false
        $fixture.Profile.Policy.PrivilegedSids = @()
        $fixture.Profile.Remediation.ApprovedObjectGuids = @()
        $fixture.Object | Add-Member -MemberType ScriptProperty -Name AccountType -Force -Value {
            $script:trace.Add('Unexpected.AccountType')
            throw 'An unapproved candidate must never observe its account metadata.'
        }
        $unapproved = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $unapproved.Actions.Count -eq 0 -and $unapproved.Excluded[0].Reason -ceq 'ObjectNotExplicitlyApproved' -and
            $script:trace.Count -eq 0
        ) 'An unapproved candidate was processed beyond eligibility.'
    }
}

function Invoke-IsolationCases {
    Forbid-PlannerWrapper
    $planner = [ADAnalyzerRemediationPlanner]::new()
    Test-Fixture 'reused and independent planners isolate review state and result mutation' {
        $fixture = New-FixtureInput
        $independent = [ADAnalyzerRemediationPlanner]::new()
        $first = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        $other = $independent.CreatePlan($fixture.Assessment)
        $first.Actions[0].Preconditions.DistinguishedName = 'changed result'
        $second = $planner.CreatePlan($fixture.Assessment, $fixture.Profile)
        Assert-Fixture (
            $first.PlanId -cne $second.PlanId -and $first.Actions[0].ActionId -cne $second.Actions[0].ActionId -and
            $other.Actions.Count -eq 0 -and $second.Actions.Count -eq 1 -and
            $second.Actions[0].Preconditions.DistinguishedName -ceq $fixture.Object.DistinguishedName
        ) 'Planner reuse leaked review state or result mutations.'
        Assert-Fixture (
            (ConvertTo-FixtureJson $planner) -cnotmatch 'fixture|ApprovedObjectGuids|DistinguishedName'
        ) 'The planner retained caller state in serialization.'
    }
    Test-Fixture 'secondary loader disposal leaves a live first planner usable' {
        $fixture = New-FixtureInput
        $before = ConvertTo-FixtureJson (ConvertTo-StablePlan ($planner.CreatePlan($fixture.Assessment, $fixture.Profile)))
        $worker = [powershell]::Create()
        try {
            $child = @'
param($Fixture, $RepositoryRoot)
& $Fixture -RepositoryRoot $RepositoryRoot -Case Construction
'@
            $result = @($worker.AddScript($child).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
            Assert-Fixture (
                -not $worker.HadErrors -and @($result | Where-Object { $_ -ceq 'PASS remediation planner Construction 2' }).Count -eq 1
            ) ('The secondary planner loader failed: ' + ($worker.Streams.Error -join ' | '))
        }
        finally {
            $worker.Dispose()
        }
        $after = ConvertTo-FixtureJson (ConvertTo-StablePlan ($planner.CreatePlan($fixture.Assessment, $fixture.Profile)))
        Assert-Fixture ($before -ceq $after) 'Disposing another loader invalidated the live planner.'
    }
}

switch ($Case) {
    'Native' {
        $script:temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-planner-fixture-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:temporary -ItemType Directory
        try {
            Invoke-NativeCases
        }
        finally {
            Remove-Item -LiteralPath $script:temporary -Recurse -Force
        }
    }
    'Construction' {
        Invoke-ConstructionCases
    }
    'Standalone' {
        Test-Fixture 'operations file supports inert literal construction without loading the profile' {
            $planner = [ADAnalyzerRemediationPlanner]::new()
            Assert-Fixture (
                $planner.GetType().Name -ceq 'ADAnalyzerRemediationPlanner' -and
                $null -eq ('ADAnalyzerProfile' -as [type])
            ) 'The standalone constructor eagerly loaded the profile dependency.'
        }
    }
    'Direct' {
        $script:temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-planner-fixture-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -Path $script:temporary -ItemType Directory
        try {
            Invoke-DirectCases
        }
        finally {
            Remove-Item -LiteralPath $script:temporary -Recurse -Force
        }
    }
    'Isolation' {
        Invoke-IsolationCases
    }
}
Write-Output ('PASS remediation planner ' + $Case + ' ' + $script:passed)
