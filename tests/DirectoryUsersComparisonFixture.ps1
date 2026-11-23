[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Direct')]
    [string]$Case,

    [Parameter(Mandatory)]
    [string]$RepositoryRoot,

    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

$ErrorActionPreference = 'Stop'

function Import-Module {
    throw 'The comparison fixture cannot acquire a module.'
}

function Invoke-Command {
    throw 'The comparison fixture cannot contact a host.'
}

function Get-ADUser {
    throw 'The comparison fixture cannot query a directory.'
}

. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

function script:Write-ADAnalyzerFile {
    throw 'The comparison fixture cannot write a result.'
}

function script:Write-ADAnalyzerOperationFile {
    throw 'The comparison fixture cannot write an operation result.'
}

if ($Case -ceq 'Direct') {
    function script:Compare-ADAnalyzerAssessment {
        throw 'The direct comparison routed through the compatibility command.'
    }
}

$script:RuleId = 'ACCOUNT.PASSWORD_NEVER_EXPIRES'
$script:OtherRuleId = 'FIXTURE.UNRELATED'
$script:Scope = 'OU=Selected,DC=directory,DC=fixture,DC=invalid'
$script:OtherScope = 'OU=Other,DC=directory,DC=fixture,DC=invalid'
$script:Domain = 'directory.fixture.invalid'
$script:Server = 'dc1.directory.fixture.invalid'
$script:SubjectGuid = '10000000-0000-4000-8000-000000000001'
$script:OtherGuid = '10000000-0000-4000-8000-000000000002'
$script:Subject = 'CN=Observed Account,' + $script:Scope
$script:Earlier = '2026-02-09T12:00:00.0000000Z'
$script:Later = '2026-02-09T12:05:00.0000000Z'

function Assert-ComparisonFixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-UserRecord([string]$Guid, [string]$Name, [bool]$NeverExpires) {
    [pscustomobject][ordered]@{
        ObjectGuid = $Guid
        DistinguishedName = $Name
        ObjectClass = 'User'
        Enabled = $true
        PasswordNeverExpires = $NeverExpires
    }
}

function New-ComparisonSnapshot([string]$Name, [string]$ObservedAt, [bool]$Violates) {
    $status = if ($Violates) {
        'Fail'
    }
    else {
        'Pass'
    }

    [pscustomobject][ordered]@{
        SchemaVersion = 1
        RunId = $Name
        Target = $script:Domain
        State = 'Complete'
        Timestamp = $ObservedAt
        Context = [pscustomobject]@{
            SearchBase = $script:Scope
            Server = $script:Server
        }
        Configuration = [pscustomobject]@{
            Policy = [pscustomobject]@{
                AllowPasswordNeverExpires = $false
            }
        }
        Checks = @(
            [pscustomobject]@{
                RuleId = $script:RuleId
                ObjectGuid = $script:SubjectGuid
                Target = $script:Subject
                Status = $status
                Observed = $Violates
                Expected = $false
                Evidence = @()
                Applicability = 'Configured'
            }
            [pscustomobject]@{
                RuleId = $script:OtherRuleId
                Target = 'Unrelated subject'
                Status = $status
            }
        )
        Data = [pscustomobject]@{
            Directory = [pscustomobject]@{
                Server = $script:Server
                DirectoryConnection = [pscustomobject]@{
                    Mode = 'PSDrive'
                    Server = $script:Server
                    Status = 'Connected'
                }
                Coverage = [pscustomobject]@{
                    Users = 'Collected'
                    DirectoryConnection = 'Collected'
                }
                Users = @(
                    (New-UserRecord $script:SubjectGuid $script:Subject $Violates)
                    (New-UserRecord $script:OtherGuid ('CN=Sibling,' + $script:Scope) $false)
                )
                UsersObservation = [pscustomobject][ordered]@{
                    Version = 1
                    RequestedSearchBase = $script:Scope
                    SearchBase = $script:Scope
                    Server = $script:Server
                    Mode = 'PSDrive'
                    ObservedAt = $ObservedAt
                    Status = 'Completed'
                }
            }
        }
    }
}

$cases = @(
    @{ Name = 'ObservedNegative'; Change = 'Resolved' }
    @{
        Name = 'DirectObservedNegative'; Change = 'Resolved'
        ChangeInputs = {
            param($Old, $New)
            foreach ($snapshot in $Old, $New) {
                $snapshot.Data.Directory.DirectoryConnection.Mode = 'Direct'
                $snapshot.Data.Directory.DirectoryConnection.Status = 'Direct'
                $snapshot.Data.Directory.Coverage.DirectoryConnection = 'NotConfigured'
                $snapshot.Data.Directory.UsersObservation.Mode = 'Direct'
            }
        }
    }
    @{
        Name = 'LegacyPair'; Change = 'Resolved'
        ChangeInputs = {
            param($Old, $New)
            $Old.Data.Directory.PSObject.Properties.Remove('UsersObservation')
            $New.Data.Directory.PSObject.Properties.Remove('UsersObservation')
        }
    }
    @{
        Name = 'AbsentCheck'; Change = 'Changed'; Reason = 'NotObservedInDifference'
        ChangeInputs = {
            param($Old, $New)
            $New.Checks = @($New.Checks[1])
            $New.Data.Directory.Users = @($New.Data.Directory.Users[1])
            $New.Data.Directory.UsersObservation.Status = 'Unreadable'
            $New.Data.Directory.Coverage.Users = 'Unreadable'
        }
    }
    @{
        Name = 'OuterScopeMismatch'; ErrorPattern = '*different search-base scopes*'
        ChangeInputs = {
            param($Old, $New)
            $New.Context.SearchBase = $script:OtherScope
        }
    }
    @{
        Name = 'ContextScopeConflict'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $Old.Context.SearchBase = $script:OtherScope
            $New.Context.SearchBase = $script:OtherScope
        }
    }
    @{
        Name = 'ContextControllerConflict'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Context.Server = 'dc3.directory.fixture.invalid'
        }
    }
    @{
        Name = 'LegacyReference'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $Old.Data.Directory.PSObject.Properties.Remove('UsersObservation')
        }
    }
    @{
        Name = 'LegacyDifference'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.PSObject.Properties.Remove('UsersObservation')
        }
    }
    @{
        Name = 'Denied'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.Status = 'Unreadable'
            $New.Data.Directory.Coverage.Users = 'Unreadable'
        }
    }
    @{
        Name = 'Unobserved'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.Status = 'Unobserved'
        }
    }
    @{
        Name = 'DifferentRequestedOu'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.RequestedSearchBase = $script:OtherScope
        }
    }
    @{
        Name = 'DifferentEffectiveOu'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.SearchBase = $script:OtherScope
        }
    }
    @{
        Name = 'DifferentController'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $otherServer = 'dc2.directory.fixture.invalid'
            $New.Context.Server = $otherServer
            $New.Data.Directory.Server = $otherServer
            $New.Data.Directory.DirectoryConnection.Server = $otherServer
            $New.Data.Directory.UsersObservation.Server = $otherServer
        }
    }
    @{
        Name = 'DifferentTransport'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.Mode = 'Direct'
            $New.Data.Directory.DirectoryConnection.Mode = 'Direct'
            $New.Data.Directory.DirectoryConnection.Status = 'Direct'
            $New.Data.Directory.Coverage.DirectoryConnection = 'NotConfigured'
        }
    }
    @{
        Name = 'SameObservationTime'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.ObservedAt = $script:Earlier
        }
    }
    @{
        Name = 'EarlierObservationTime'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.ObservedAt = '2026-02-09T11:00:00.0000000Z'
        }
    }
    @{
        Name = 'MissingObservationTime'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.PSObject.Properties.Remove('ObservedAt')
        }
    }
    @{
        Name = 'MalformedObservationTime'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.ObservedAt = 'time not observed'
        }
    }
    @{
        Name = 'UnsupportedCoverageVersion'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.UsersObservation.Version = 2
        }
    }
    @{
        Name = 'EmptyUsers'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.Users = @()
        }
    }
    @{
        Name = 'MissingUsers'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.PSObject.Properties.Remove('Users')
        }
    }
    @{
        Name = 'ReplacementGuid'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $replacement = '10000000-0000-4000-8000-000000000099'
            $New.Checks[0].ObjectGuid = $replacement
            $New.Data.Directory.Users[0].ObjectGuid = $replacement
        }
    }
    @{
        Name = 'DisabledSubject'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.Users[0].Enabled = $false
        }
    }
    @{
        Name = 'OutsideScopeSubject'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            foreach ($snapshot in $Old, $New) {
                $outside = 'CN=Observed Account,' + $script:OtherScope
                $snapshot.Checks[0].Target = $outside
                $snapshot.Data.Directory.Users[0].DistinguishedName = $outside
            }
        }
    }
    @{
        Name = 'EscapedScopeBoundary'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            foreach ($snapshot in $Old, $New) {
                $outside = 'CN=Escaped\,' + $script:Scope
                $snapshot.Checks[0].Target = $outside
                $snapshot.Data.Directory.Users[0].DistinguishedName = $outside
            }
        }
    }
    @{
        Name = 'MalformedFlag'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Data.Directory.Users[0].PasswordNeverExpires = 'False'
        }
    }
    @{
        Name = 'AmbiguousSubject'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $again = New-UserRecord $script:SubjectGuid $script:Subject $true
            $New.Data.Directory.Users = @($New.Data.Directory.Users) + @($again)
        }
    }
    @{
        Name = 'ChangedAllowance'; Change = 'Changed'
        ChangeInputs = {
            param($Old, $New)
            $New.Configuration.Policy.AllowPasswordNeverExpires = $true
            $New.Checks[0].Expected = $true
            $New.Checks[0].Observed = $true
            $New.Data.Directory.Users[0].PasswordNeverExpires = $true
        }
    }
)

$root = Join-Path $ScratchRoot ('adanalyzer-ad03-data-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
$referencePath = Join-Path $root 'reference.json'
$differencePath = Join-Path $root 'difference.json'
$encoding = [Text.UTF8Encoding]::new($true)
$comparer = [ADAnalyzerAssessmentComparer]::new()
$passed = 0
$failed = 0
try {
    foreach ($scenario in $cases) {
        $reference = New-ComparisonSnapshot 'reference' $script:Earlier $true
        $difference = New-ComparisonSnapshot 'difference' $script:Later $false
        if ($scenario.ContainsKey('ChangeInputs')) {
            & $scenario.ChangeInputs $reference $difference
        }

        $referenceJson = ConvertTo-Json -InputObject $reference -Depth 15 -Compress
        $differenceJson = ConvertTo-Json -InputObject $difference -Depth 15 -Compress
        [IO.File]::WriteAllText($referencePath, $referenceJson, $encoding)
        [IO.File]::WriteAllText($differencePath, $differenceJson, $encoding)
        $referenceBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($referencePath))
        $differenceBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($differencePath))
        $result = $null
        $caught = $null
        try {
            $result = if ($Case -ceq 'Native') {
                Compare-ADAnalyzerAssessment -Reference $referencePath -Difference $differencePath
            }
            else {
                $comparer.Compare($referencePath, $differencePath)
            }
        }
        catch {
            $caught = $_
        }

        try {
            Assert-ComparisonFixture (
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($referencePath)) -ceq $referenceBytes -and
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($differencePath)) -ceq $differenceBytes -and
                [IO.Directory]::GetFileSystemEntries($root).Count -eq 2
            ) 'Comparison changed or added files.'

            if ($scenario.ContainsKey('ErrorPattern')) {
                Assert-ComparisonFixture (
                    $null -ne $caught -and $null -eq $result -and
                    $caught.Exception.Message -like $scenario.ErrorPattern
                ) 'The existing outer search-base check did not reject differing scopes.'
            }
            else {
                Assert-ComparisonFixture ($null -eq $caught -and $null -ne $result) 'Comparison did not return a result.'
                $changes = @($result.Changes | Where-Object RuleId -ceq $script:RuleId)
                $unrelated = @($result.Changes | Where-Object RuleId -ceq $script:OtherRuleId)
                Assert-ComparisonFixture (
                    $changes.Count -eq 1 -and $unrelated.Count -eq 1 -and $unrelated[0].Change -ceq 'Resolved'
                ) 'Comparison altered the rule bucket or unrelated transition.'
                $change = $changes[0]
                $expected = $scenario.Change
                Assert-ComparisonFixture ($change.Change -ceq $expected) (
                    'Expected {0}; observed {1}.' -f $expected, $change.Change
                )
                if ($expected -ceq 'Changed') {
                    $reason = switch ($scenario.Name) {
                        'AbsentCheck' { 'NotObservedInDifference' }
                        'ChangedAllowance' { 'RulePredicateChanged' }
                        'SameObservationTime' { 'DirectoryObservationNotNewer' }
                        'EarlierObservationTime' { 'DirectoryObservationNotNewer' }
                        default { 'DirectoryEvidenceInsufficient' }
                    }
                    Assert-ComparisonFixture ($change.Reason -ceq $reason) (
                        'Expected comparison reason {0}; observed {1}.' -f $reason, $change.Reason
                    )
                }
            }
            $passed++
        }
        catch {
            $failed++
            'FAIL AD-03 compare {0} {1}: {2}' -f $Case, $scenario.Name, $_.Exception.Message
        }
    }
}
finally {
    [IO.Directory]::Delete($root, $true)
}

if ($failed) {
    throw ('AD-03 comparison cases failed: {0}; passed: {1}.' -f $failed, $passed)
}
'PASS AD-03 compare {0} {1}' -f $Case, $passed
