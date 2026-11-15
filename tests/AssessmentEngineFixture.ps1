[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [ValidateSet('Contract', 'Constructors', 'Isolation', 'Validation', 'Failures', 'States')]
    [string]$Mode = 'Contract'
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$bootstrap = Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1'
if (-not [IO.File]::Exists($bootstrap)) {
    throw 'The primary constructor API bootstrap is missing.'
}
$global:AssessmentEngineFixture = @{
    DirectoryCalls = 0
    PolicyCalls = 0
    ExternalCalls = 0
    Fault = ''
}

function Import-Module {
    $global:AssessmentEngineFixture.ExternalCalls++
    throw 'Unexpected native module import'
}

function Get-ADRootDSE {
    $global:AssessmentEngineFixture.ExternalCalls++
    throw 'Unexpected directory call'
}

$component = 'caller-sentinel'
. $bootstrap
if ($component -ne 'caller-sentinel') {
    throw 'The constructor bootstrap changed caller state.'
}

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function Assert-Fails([scriptblock]$Body, [string]$Message) {
    $rows = [Collections.Generic.List[object]]::new()
    $caught = $null
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $caught = $_
    }
    Assert-Equal $false ($null -eq $caught)
    Assert-Equal 0 $rows.Count
    if ($Message -and $caught.Exception.ToString() -notmatch [regex]::Escape($Message)) {
        throw 'The expected failure cause was not preserved.'
    }
}

function New-DirectoryFixture {
    [pscustomobject]@{
        Domain = [pscustomobject]@{
            DNSRoot = 'example.invalid'
        }
        Users = @()
        Computers = @()
        ServiceAccounts = @()
        HostChecks = @()
        Errors = @()
        TestChecks = @()
    }
}

function Test-ADAnalyzerDirectoryPolicy {
    [CmdletBinding()]
    param($Data, $Profile)
    $global:AssessmentEngineFixture.DirectoryCalls++
    if ($global:AssessmentEngineFixture.Fault -eq 'Throw') {
        throw 'Fixture evaluation failed'
    }
    if ($global:AssessmentEngineFixture.Fault -eq 'Error') {
        Write-Error 'Fixture nonterminating evaluation failure'
    }
    $Data.TestChecks
}

function Test-ADAnalyzerGpoPolicy {
    [CmdletBinding()]
    param($Gpo, $Policy, $Profile)
    $global:AssessmentEngineFixture.PolicyCalls++
    $Policy.TestChecks
}

function Get-ComparableJson($Report) {
    $copy = ConvertTo-ADAnalyzerSafeData $Report
    $copy.RunId = ''
    $copy.Timestamp = ''
    ConvertTo-Json -InputObject $copy -Depth 100 -Compress
}

Assert-Equal 0 $global:AssessmentEngineFixture.ExternalCalls
Assert-Equal 0 $global:AssessmentEngineFixture.DirectoryCalls
Assert-Equal 0 $global:AssessmentEngineFixture.PolicyCalls
$directory = New-DirectoryFixture

switch ($Mode) {
    'Contract' {
        $directory.TestChecks = @(
            (New-ADAnalyzerCheck -RuleId 'Fixture.Fail' -Target 'one' -Status Fail)
            (New-ADAnalyzerCheck -RuleId 'Fixture.Pass' -Target 'two' -Status Pass)
        )
        $directory.Users = @([pscustomobject]@{
                Name = 'fixture'
                Password = 'CLASS_FIXTURE_SECRET_ONLY'
            })
        $gpos = @([pscustomobject]@{
                Gpo = [pscustomobject]@{
                    Id = 'fixture-gpo'
                    Version = 1
                }
                Policy = [pscustomobject]@{
                    SysvolVersion = 1
                    TestChecks = @()
                    Files = @()
                    UnparsedFiles = @()
                }
            })
        $engine = [ADAnalyzerAssessmentEngine]::new()
        $direct = $engine.Evaluate($directory, $gpos, 'example.invalid')
        $compatibility = Invoke-ADAnalyzerAssessment -DirectoryData $directory -GpoData $gpos -Target 'example.invalid'
        Assert-Equal (Get-ComparableJson $compatibility) (Get-ComparableJson $direct)
        Assert-Equal 'Complete' $direct.State
        Assert-Equal 3 $direct.Coverage.Total
        Assert-Equal 1 $direct.Coverage.Fail
        Assert-Equal 1 $direct.Findings.Count
        Assert-Equal 'Fixture.Fail|Fixture.Pass|GPO.VERSION_CONSISTENCY' ($direct.Checks.RuleId -join '|')
        Assert-Equal 1 $direct.Objects.Count
        Assert-Equal $true $direct.Objects[0].PasswordPresent
        Assert-Equal $false ((ConvertTo-Json $direct -Depth 100) -match 'CLASS_FIXTURE_SECRET_ONLY|REDACTED')
        Assert-Equal 'CLASS_FIXTURE_SECRET_ONLY' $directory.Users[0].Password
        $parameters = (Get-Command Invoke-ADAnalyzerAssessment).Parameters
        foreach ($name in @('DirectoryData', 'GpoData', 'Profile', 'Target', 'ErrorAction', 'Verbose')) {
            Assert-Equal $true $parameters.ContainsKey($name)
        }
    }
    'Constructors' {
        $first = [ADAnalyzerAssessmentEngine]::new()
        $second = [ADAnalyzerAssessmentEngine]::new(@{
                Name = 'Instance profile'
                Policy = @{
                    MinimumPasswordLength = 20
                }
            })
        Assert-Equal 0 $global:AssessmentEngineFixture.DirectoryCalls
        Assert-Equal 0 $global:AssessmentEngineFixture.PolicyCalls
        Assert-Equal 0 $global:AssessmentEngineFixture.ExternalCalls
        Assert-Equal 'offline' $first.Evaluate($directory).Target
        Assert-Equal 0 $first.Evaluate($directory, @()).Objects.Count
        Assert-Equal 20 $second.Evaluate($directory).Configuration.Policy.MinimumPasswordLength
        $serialized = ConvertTo-Json -InputObject $second -Depth 100
        Assert-Equal $false ($serialized -match 'Credential|CommandInfo|SessionState|CLASS_FIXTURE_SECRET_ONLY')
        $secretProfile = @{
            AccountClassification = @{
                AttributeRules = @(@{
                        Attribute = 'Password'
                        Type = 'Service'
                        Value = 'CLASS_PROFILE_SECRET_PAYLOAD'
                    })
            }
        }
        $private = [ADAnalyzerAssessmentEngine]::new($secretProfile)
        $serialized = ConvertTo-Json -InputObject $private -Depth 100
        Assert-Equal $false ($serialized -match 'CLASS_PROFILE_SECRET_PAYLOAD')
        $report = $private.Evaluate($directory)
        Assert-Equal $true $report.Configuration.AccountClassification.AttributeRules[0].SecretPresent
        Assert-Equal 'CLASS_PROFILE_SECRET_PAYLOAD' $secretProfile.AccountClassification.AttributeRules[0].Value
    }
    'Isolation' {
        $profile = @{
            Policy = @{
                MinimumPasswordLength = 21
            }
        }
        $before = ConvertTo-Json -InputObject $profile -Depth 100 -Compress
        $first = [ADAnalyzerAssessmentEngine]::new($profile)
        $second = [ADAnalyzerAssessmentEngine]::new()
        $result = $first.Evaluate($directory)
        Assert-Equal $before (ConvertTo-Json -InputObject $profile -Depth 100 -Compress)
        $profile.Policy.MinimumPasswordLength = 30
        $result.Configuration.Policy.MinimumPasswordLength = 40
        Assert-Equal 21 $first.Evaluate($directory).Configuration.Policy.MinimumPasswordLength
        Assert-Equal 12 $second.Evaluate($directory).Configuration.Policy.MinimumPasswordLength
        Assert-Equal 0 $first.Evaluate($directory).Coverage.Total
    }
    'Validation' {
        Assert-Fails { [ADAnalyzerAssessmentEngine]::new(@{
                    Policy = @{
                        MisspelledRule = 1
                    }
                }) } 'Unknown'
        $engine = [ADAnalyzerAssessmentEngine]::new()
        Assert-Fails { $engine.Evaluate($null) } 'DirectoryData'
        Assert-Equal 0 $global:AssessmentEngineFixture.DirectoryCalls
        Assert-Equal 0 $global:AssessmentEngineFixture.ExternalCalls
    }
    'Failures' {
        $engine = [ADAnalyzerAssessmentEngine]::new()
        foreach ($preference in @('Continue', 'Stop')) {
            $ErrorActionPreference = $preference
            $global:AssessmentEngineFixture.Fault = 'Throw'
            Assert-Fails { $engine.Evaluate($directory) } 'Fixture evaluation failed'
            Assert-Fails { Invoke-ADAnalyzerAssessment -DirectoryData $directory } 'Fixture evaluation failed'
            $global:AssessmentEngineFixture.Fault = ''
            Assert-Equal 0 $engine.Evaluate($directory).Coverage.Total
            $directory.TestChecks = @(
                (New-ADAnalyzerCheck -RuleId 'duplicate' -Target 'one' -Status Fail)
                (New-ADAnalyzerCheck -RuleId 'duplicate' -Target 'one' -Status Fail)
            )
            Assert-Fails { $engine.Evaluate($directory) } 'Duplicate check identities'
            $directory.TestChecks = @()
        }
        $ErrorActionPreference = 'Stop'
        $global:AssessmentEngineFixture.Fault = 'Error'
        Assert-Fails { $engine.Evaluate($directory) } 'Fixture nonterminating evaluation failure'
        Assert-Fails { Invoke-ADAnalyzerAssessment -DirectoryData $directory } 'Fixture nonterminating evaluation failure'
        $ErrorActionPreference = 'Continue'
        Assert-Fails { $engine.Evaluate($directory) } 'Fixture nonterminating evaluation failure'
        $compatibilityStream = @(Invoke-ADAnalyzerAssessment -DirectoryData $directory -ErrorAction Continue 2>&1)
        Assert-Equal 1 @($compatibilityStream | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count
        Assert-Equal 1 @($compatibilityStream | Where-Object { $_.SchemaVersion -eq 1 }).Count
        foreach ($preference in @('SilentlyContinue', 'Ignore')) {
            $savedErrors = @()
            $compatibilityStream = @(Invoke-ADAnalyzerAssessment -DirectoryData $directory -ErrorAction $preference -ErrorVariable savedErrors 2>&1)
            Assert-Equal 0 @($compatibilityStream | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count
            Assert-Equal 1 @($compatibilityStream | Where-Object { $_.SchemaVersion -eq 1 }).Count
            $expected = if ($preference -eq 'SilentlyContinue') {
                1
            }
            else {
                0
            }
            Assert-Equal $expected $savedErrors.Count
        }
        $global:AssessmentEngineFixture.Fault = ''
        $ErrorActionPreference = 'Stop'
        Assert-Equal 0 $engine.Evaluate($directory).Coverage.Total
    }
    'States' {
        $engine = [ADAnalyzerAssessmentEngine]::new()
        foreach ($status in @('Pass', 'Fail', 'Unknown', 'Unreadable', 'NotConfigured', 'NotApplicable', 'Invalid')) {
            $directory.TestChecks = @((New-ADAnalyzerCheck -RuleId 'fixture' -Target 'one' -Status $status))
            $report = $engine.Evaluate($directory)
            $expected = if ($status -in @('Unknown', 'Unreadable', 'Invalid')) {
                'Partial'
            }
            else {
                'Complete'
            }
            Assert-Equal $expected $report.State
            Assert-Equal 1 $report.Coverage.$status
        }
        $directory.Domain = $null
        Assert-Equal 'Failed' $engine.Evaluate($directory, @(), 'example.invalid').State
        $directory = New-DirectoryFixture
        $unreadable = @([pscustomobject]@{
                Gpo = [pscustomobject]@{
                    Id = 'failed-policy'
                }
                Error = 'Fixture unreadable policy'
            })
        $report = $engine.Evaluate($directory, $unreadable)
        Assert-Equal 'Partial' $report.State
        Assert-Equal 1 $report.Coverage.Unreadable
        Assert-Equal 1 $report.Errors.Count
        $suppressed = [ADAnalyzerAssessmentEngine]::new(@{
                Exceptions = @(@{
                        RuleId = 'fixture'
                        Target = 'one'
                        Owner = 'fixture owner'
                        Reason = 'fixture approval'
                        Expires = [datetimeoffset]::UtcNow.AddDays(2).ToString('o')
                    })
            })
        $directory.TestChecks = @((New-ADAnalyzerCheck -RuleId 'fixture' -Target 'one' -Status Fail))
        $report = $suppressed.Evaluate($directory)
        Assert-Equal 1 $report.Coverage.Suppressed
        Assert-Equal $true $report.Checks[0].Suppressed
    }
}

Assert-Equal 0 $global:AssessmentEngineFixture.ExternalCalls
Write-Output ('PASS assessment engine ' + $Mode)
