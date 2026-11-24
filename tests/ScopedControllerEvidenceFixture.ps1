[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Direct')]
    [string]$Case,

    [Parameter(Mandatory)]
    [string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

function Assert-ControllerFixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

$domain = 'controller.fixture.invalid'
$server = 'dc.' + $domain
$otherServer = 'other.' + $domain
$domainDn = 'DC=controller,DC=fixture,DC=invalid'
$scope = 'OU=Observed,' + $domainDn
$subject = 'CN=Fixture User,' + $scope
$rule = 'ACCOUNT.PASSWORD_NEVER_EXPIRES'
$unrelatedRule = 'ACCOUNT.PASSWORD_NOT_REQUIRED'
$legacyMessage = 'Exceptions and account purpose require explicit profile decisions.'
$limitedMessage = 'did not corroborate the selected directory controller'
$profile = @{ Policy = @{ AllowPasswordNeverExpires = $false } }

function New-ControllerFixtureDirectory([object]$AccountControl, [bool]$Enabled, [bool]$Flag) {
    return [pscustomobject]@{
        Server = $server
        Domain = [pscustomobject]@{
            DNSRoot = $domain
            DistinguishedName = $domainDn
            SID = 'S-1-5-21-1-2-3'
        }
        Users = @(
            [pscustomobject]@{
                ObjectClass = 'User'
                AccountType = 'User'
                DistinguishedName = $subject
                ObjectGuid = '4bba9958-e7c0-4102-9ad8-ddba376b91f7'
                SID = 'S-1-5-21-1-2-3-3201'
                Enabled = $Enabled
                PasswordNeverExpires = $Flag
                UserAccountControl = $AccountControl
            }
        )
        Computers = @()
        ServiceAccounts = @()
        Errors = @()
        Coverage = @{
            Users = 'Collected'
            DirectoryConnection = 'Collected'
        }
        DirectoryConnection = [pscustomobject]@{
            Mode = 'PSDrive'
            Server = $server
            Status = 'Connected'
        }
        UsersObservation = [pscustomobject][ordered]@{
            Version = 1
            RequestedSearchBase = $scope
            SearchBase = $scope
            Server = $server
            Mode = 'PSDrive'
            ObservedAt = '2026-02-09T12:05:00.0000000Z'
            Status = 'Completed'
        }
    }
}

$script:UnexpectedAcquisition = [Collections.Generic.List[string]]::new()
foreach ($name in @('Import-Module', 'Get-ADRootDSE', 'Get-ADDomain', 'Get-ADUser', 'Get-ADObject',
        'Get-ADAnalyzerDirectoryData', 'Get-ADAnalyzerAssessment', 'New-PSDrive', 'New-CimSession', 'Invoke-Command')) {
    Set-Item -Path ('Function:script:' + $name) -Value {
        $script:UnexpectedAcquisition.Add($MyInvocation.MyCommand.Name)
        throw 'Offline scoped controller assessment attempted acquisition.'
    }
}

if ($Case -eq 'Direct') {
    function script:Invoke-ADAnalyzerAssessment {
        throw 'The class assessment attempted to call its compatibility command.'
    }
}

$subjects = @{
    Clear = @{
        AccountControl = [long]512
        Enabled = $true
        Flag = $false
        Verdict = 'Pass'
    }
    Set = @{
        AccountControl = [int]66080
        Enabled = $true
        Flag = $true
        Verdict = 'Fail'
    }
    Disabled = @{
        AccountControl = [int]514
        Enabled = $false
        Flag = $false
        Verdict = 'NotApplicable'
    }
}

$cases = @(
    # Scenario, recorded account state, and whether controller evidence is insufficient.
    @('KnownClear', 'Clear', $false),
    @('KnownSet', 'Set', $false),
    @('KnownDisabled', 'Disabled', $false),
    @('CaseOnly', 'Clear', $false),
    @('LegacyWithoutBindings', 'Clear', $false),
    @('NullWitnessClear', 'Clear', $true),
    @('NullWitnessSet', 'Set', $true),
    @('NullWitnessDisabled', 'Disabled', $true),
    @('MissingWitness', 'Clear', $true),
    @('BlankWitness', 'Clear', $true),
    @('ArrayWitness', 'Clear', $true),
    @('OtherWitness', 'Clear', $true),
    @('OtherDirectoryServer', 'Clear', $true),
    @('OtherConnectionServer', 'Clear', $true),
    @('MissingDirectoryServer', 'Clear', $true),
    @('MissingConnectionServer', 'Clear', $true)
)

$engine = [ADAnalyzerAssessmentEngine]::new($profile)
$renderer = [ADAnalyzerAssessmentReport]::new()
$passed = 0
$failures = [Collections.Generic.List[string]]::new()
$healthySiblings = @{}
$original = $null
$knownCheckId = $null
foreach ($fixture in $cases) {
    $caseName, $subjectName, $limited = $fixture
    try {
        $subjectState = $subjects[$subjectName]
        $directory = New-ControllerFixtureDirectory $subjectState.AccountControl $subjectState.Enabled $subjectState.Flag
        switch -Wildcard -CaseSensitive ($caseName) {
            'CaseOnly' {
                $directory.UsersObservation.Server = $server.ToUpperInvariant()
                $directory.DirectoryConnection.Server = $server.ToUpperInvariant()
            }
            'LegacyWithoutBindings' {
                foreach ($field in 'UsersObservation', 'Server', 'DirectoryConnection') {
                    $directory.PSObject.Properties.Remove($field)
                }
            }
            'NullWitness*' {
                $directory.UsersObservation.Server = $null
            }
            'MissingWitness' {
                $directory.UsersObservation.PSObject.Properties.Remove('Server')
            }
            'BlankWitness' {
                $directory.UsersObservation.Server = ' '
            }
            'ArrayWitness' {
                $directory.UsersObservation.Server = @($server)
            }
            'OtherWitness' {
                $directory.UsersObservation.Server = $otherServer
            }
            'OtherDirectoryServer' {
                $directory.Server = $otherServer
            }
            'OtherConnectionServer' {
                $directory.DirectoryConnection.Server = $otherServer
            }
            'MissingDirectoryServer' {
                $directory.PSObject.Properties.Remove('Server')
            }
            'MissingConnectionServer' {
                $directory.DirectoryConnection.PSObject.Properties.Remove('Server')
            }
        }

        $originalInput = ConvertTo-Json -InputObject $directory -Depth 20 -Compress
        $jsonInput = ConvertFrom-Json -InputObject $originalInput
        $expectedRetained = ConvertTo-Json -InputObject $jsonInput -Depth 20 -Compress
        $result = if ($Case -eq 'Native') {
            Invoke-ADAnalyzerAssessment -DirectoryData $directory -Profile $profile -Target $domain
        }
        else {
            $engine.Evaluate($directory, @(), $domain)
        }
        $report = $renderer.Render($result, 'Json') | ConvertFrom-Json
        $unchangedInput = ConvertTo-Json -InputObject $directory -Depth 20 -Compress
        Assert-ControllerFixture ($originalInput -ceq $unchangedInput) 'Evaluation or rendering mutated the source fixture.'

        $siblings = @($result.Checks | Where-Object RuleId -CEQ $unrelatedRule)
        Assert-ControllerFixture (
            $siblings.Count -eq 1 -and
            $siblings[0].Evidence.UserAccountControl.GetType() -eq $subjectState.AccountControl.GetType()
        ) 'The sibling check lost its native UAC type.'
        if ($caseName -cne 'LegacyWithoutBindings') {
            $sibling = ConvertTo-Json -InputObject $siblings[0] -Depth 15 -Compress
            if ($healthySiblings.ContainsKey($subjectName)) {
                Assert-ControllerFixture ($sibling -ceq $healthySiblings[$subjectName]) 'Controller evidence altered an unrelated check.'
            }
            else {
                $healthySiblings[$subjectName] = $sibling
            }
        }

        foreach ($item in $result, $report) {
            $rows = @($item.Checks | Where-Object RuleId -CEQ $rule)
            Assert-ControllerFixture (
                $rows.Count -eq 1 -and $rows[0].Target -ceq $subject -and
                $rows[0].Expected -is [bool] -and -not $rows[0].Expected
            ) 'The scoped rule changed its target, count, or configured expectation.'
            if ($null -eq $knownCheckId) {
                $knownCheckId = $rows[0].CheckId
            }
            Assert-ControllerFixture (
                $rows[0].CheckId -is [string] -and $rows[0].CheckId -and $rows[0].CheckId -ceq $knownCheckId
            ) 'The scoped verdict changed the existing check identity.'
            $retained = $item.Data.Directory
            $captured = ConvertTo-Json -InputObject $retained -Depth 20 -Compress
            # Both sides pass through the same JSON reader because newer engines
            # turn the retained ISO time string into a DateTime on decode.
            $decoded = ConvertFrom-Json -InputObject $captured
            $decodedJson = ConvertTo-Json -InputObject $decoded -Depth 20 -Compress
            Assert-ControllerFixture ($decodedJson -ceq $expectedRetained) 'Evaluation or rendering altered retained directory evidence.'

            $row = $rows[0]
            if ($limited) {
                Assert-ControllerFixture ($row.Status -ceq 'Unknown') ('Expected Unknown, observed {0}.' -f $row.Status)
                Assert-ControllerFixture (
                    $null -eq $row.Observed -and $row.Message.Contains($limitedMessage)
                ) 'An uncorroborated controller produced a flag verdict or lost its explanation.'
            }
            else {
                Assert-ControllerFixture (
                    $row.Status -ceq $subjectState.Verdict -and $row.Observed -is [bool] -and
                    $row.Observed -eq $subjectState.Flag -and $row.Message -ceq $legacyMessage
                ) 'Corroborated or legacy evidence changed its established check.'
            }
        }

        if ($caseName -ceq 'KnownClear') {
            $original = $result
        }
        $passed++
    }
    catch {
        $failures.Add(('{0}/{1}: {2}' -f $Case, $caseName, $_.Exception.Message))
    }
}

try {
    Assert-ControllerFixture ($null -ne $original) 'The known clear control did not produce its assessment.'
    $original.Data.Directory.UsersObservation.Server = $null
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('scoped-controller-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($directory)
    try {
        $path = Join-Path $directory 'recorded.json'
        [IO.File]::WriteAllText($path, $renderer.Render($original, 'Json'))
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $reader = [ADAnalyzerOperationDocumentReader]::new()
        $saved = $reader.Read($path)
        $rendered = $renderer.Render($saved, 'Json') | ConvertFrom-Json
        foreach ($item in $saved, $rendered) {
            $recorded = @($item.Checks | Where-Object RuleId -CEQ $rule)
            Assert-ControllerFixture (
                $null -eq $item.Data.Directory.UsersObservation.Server -and
                $recorded.Count -eq 1 -and $recorded[0].Status -ceq 'Pass' -and
                $recorded[0].Observed -is [bool] -and -not $recorded[0].Observed -and
                $recorded[0].Message -ceq $legacyMessage
            ) 'Passive read or rendering reevaluated a historical recorded verdict.'
        }
        Assert-ControllerFixture (
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $hash
        ) 'Passive reads altered the original bytes.'
    }
    finally {
        [IO.Directory]::Delete($directory, $true)
    }
    $passed++
}
catch {
    $failures.Add(('Historical/{0}: {1}' -f $Case, $_.Exception.Message))
}

Assert-ControllerFixture ($script:UnexpectedAcquisition.Count -eq 0) 'Controller fixture attempted acquisition.'
foreach ($failure in $failures) {
    Write-Host ('AD-09 fixture ' + $failure)
}
if ($failures.Count) {
    throw ('AD-09 scoped controller fixture failed {0}, passed {1}.' -f $failures.Count, $passed)
}
'PASS AD-09 scoped controller {0} {1}' -f $Case, $passed
