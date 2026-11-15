[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [ValidateSet('RecordBaseline', 'Construction', 'Parity', 'PartialProfile', 'Secrets', 'Types', 'Streaming', 'Validation', 'Isolation', 'Order')]
    [string]$Mode = 'Construction'
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function ConvertTo-Canonical($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary] -and $Value -isnot [pscustomobject]) {
        return , @(foreach ($item in $Value) { ConvertTo-Canonical $item })
    }
    [string[]]$names = if ($Value -is [Collections.IDictionary]) {
        @($Value.Keys)
    }
    else {
        @($Value.PSObject.Properties.Name)
    }
    if ($null -ne $names) {
        [Array]::Sort($names, [StringComparer]::Ordinal)
    }
    $result = [ordered]@{}
    foreach ($name in $names) {
        $result[$name] = ConvertTo-Canonical $Value.$name
    }
    return [pscustomobject]$result
}

function Get-CanonicalJson($Value) {
    ConvertTo-Json -InputObject (ConvertTo-Canonical $Value) -Depth 100 -Compress
}

function New-Context([switch]$Mixed) {
    $policy = [pscustomobject]@{
        SecuritySettings = @()
        RegistrySettings = @()
        IniSettings = @()
        XmlFiles = @()
        Files = @()
        UnparsedFiles = @()
    }
    $profile = Get-ADAnalyzerDefaultProfile
    if ($Mixed) {
        $source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        $policy.SecuritySettings = @(
            [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Account'
                Name = 'MinimumPasswordLength'
                Value = 0L
                Source = $source
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Account'
                Name = 'PasswordComplexity'
                Value = $false
                ValueValid = $true
                Source = $source
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'UserRightsAssignment'
                Name = 'SeBackupPrivilege'
                Value = [string[]]@('*S-1-5-32-544')
                Source = $source
            }
        )
        $policy.RegistrySettings = @([pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Enabled'
                Value = [uint32]0
                Type = 4
                RawData = [byte[]]@(0, 0, 0, 0)
                Source = 'Machine/Registry.pol'
            })
        $policy.IniSettings = @(
            [pscustomobject]@{
                Scope = 'Computer'
                Section = 'Group Membership'
                Name = '*S-1-5-32-544__Members'
                Value = '*S-1-5-32-544'
                Source = $source
                Analyzed = $true
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Section = 'System Access'
                Name = 'UnknownSetting'
                Value = '0'
                Source = $source
                Analyzed = $false
            }
        )
        $policy.XmlFiles = @([pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Preferences'
                Path = 'Machine/Preferences/Groups/Groups.xml'
                Xml = '<Groups><User uid="secret"><Properties userName="fixture" cpassword="GPO_CLASS_SECRET_MARKER" /></User><Group uid="admins"><Properties groupSid="S-1-5-32-544" action="U"><Members><Member action="ADD" sid="S-1-5-32-544" /></Members></Properties></Group></Groups>'
            })
        $policy.UnparsedFiles = @([pscustomobject]@{
                Scope = 'Computer'
                Path = 'Machine/example.cmd'
                Kind = 'Unparsed'
            })
        $profile.Policy.AllowedUserRightSids.SeBackupPrivilege = @('S-1-5-32-544')
        $profile.RegistryRules = @(@{
                Id = 'FixtureEnabled'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Enabled'
                Type = 4
                Expected = 0
            })
    }
    return @{
        Gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Flags = 0
            Links = @()
        }
        Policy = $policy
        Profile = $profile
    }
}

function New-LateFailureContext {
    $context = New-Context
    $context.Profile.RegistryRules = @(@{
            Id = 'InvalidSeverity'
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Absent'
            Expected = 0
            Severity = 'invalid-severity'
        })
    return $context
}

function Invoke-CommandProbe($Context, [string]$Preference) {
    $rows = [Collections.Generic.List[object]]::new()
    $caught = $null
    $savedErrors = @()
    try {
        Test-ADAnalyzerGpoPolicy @Context -ErrorAction $Preference -ErrorVariable savedErrors |
            ForEach-Object { $rows.Add($_) }
    }
    catch {
        $caught = $_
    }
    return [pscustomobject]@{
        Rows = $rows.ToArray()
        Terminated = $null -ne $caught
        ErrorReason = $(if ($caught) { $caught.CategoryInfo.Reason } else { $null })
        HadError = $savedErrors.Count -gt 0
    }
}

$baselinePath = Join-Path $PSScriptRoot 'GpoPolicyClassBaseline.json'
if ($Mode -eq 'RecordBaseline') {
    if ($null -ne ('ADAnalyzerGpoPolicyEvaluator' -as [type])) {
        throw 'RecordBaseline requires the original function-only source revision.'
    }
    $empty = New-Context
    $mixed = New-Context -Mixed
    $late = New-LateFailureContext
    $golden = [ordered]@{
        SourceRevision = 'f2a8d4b8e5ee8e81bb1d01707b53ef258bdb4677'
        Empty = (Get-CanonicalJson @(Test-ADAnalyzerGpoPolicy @empty))
        Mixed = (Get-CanonicalJson @(Test-ADAnalyzerGpoPolicy @mixed))
        Late = @{}
    }
    foreach ($preference in @('Continue', 'Stop')) {
        $probe = Invoke-CommandProbe $late $preference
        $golden.Late[$preference] = @{
            Rows = Get-CanonicalJson $probe.Rows
            Terminated = $probe.Terminated
            ErrorReason = $probe.ErrorReason
            HadError = $probe.HadError
        }
    }
    $json = ConvertTo-Json -InputObject $golden -Depth 100
    Assert-Equal $false ($json -match 'GPO_CLASS_SECRET_MARKER|REDACTED')
    [IO.File]::WriteAllText($baselinePath, $json, [Text.UTF8Encoding]::new($true))
    Write-Output 'PASS recorded original GPO policy baseline'
    exit 0
}
if ($null -eq ('ADAnalyzerGpoPolicyEvaluator' -as [type])) {
    throw 'The constructor-based GPO policy evaluator is missing.'
}
$golden = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
$evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
$context = New-Context

switch ($Mode) {
    'Construction' {
        Assert-Equal '{}' (Get-CanonicalJson $evaluator)
        Assert-Equal 0 @($evaluator.PSObject.Properties).Count
    }
    'Parity' {
        foreach ($name in @('Empty', 'Mixed')) {
            $context = New-Context -Mixed:($name -eq 'Mixed')
            $before = Get-CanonicalJson $context
            $checks = $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile)
            Assert-Equal $golden.$name (Get-CanonicalJson $checks)
            Assert-Equal $golden.$name (Get-CanonicalJson @(Test-ADAnalyzerGpoPolicy @context))
            Assert-Equal $before (Get-CanonicalJson $context)
        }
    }
    'PartialProfile' {
        $checks = $evaluator.Evaluate($context.Gpo, $context.Policy, @{})
        Assert-Equal 34 $checks.Count
        Assert-Equal (Get-CanonicalJson @(Test-ADAnalyzerGpoPolicy -Gpo $context.Gpo -Policy $context.Policy -Profile @{})) (Get-CanonicalJson $checks)
        $raw = @{
            IgnoredExtensionKey = 'fixture extension'
        }
        $before = Get-CanonicalJson $raw
        $checks = $evaluator.Evaluate($context.Gpo, $context.Policy, $raw)
        Assert-Equal 34 $checks.Count
        Assert-Equal 'Pass' $checks[0].Status
        Assert-Equal $before (Get-CanonicalJson $raw)
    }
    'Secrets' {
        $context = New-Context -Mixed
        $checks = $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile)
        Assert-Equal 1 @($checks | Where-Object { $_.RuleId -eq 'GPO.Preferences.CPassword' -and $_.Observed -eq $true }).Count
        Assert-Equal $false ((Get-CanonicalJson $checks) -match 'GPO_CLASS_SECRET_MARKER|REDACTED')
        Assert-Equal $true $context.Policy.XmlFiles[0].Xml.Contains('GPO_CLASS_SECRET_MARKER')
        Assert-Equal '{}' (Get-CanonicalJson $evaluator)
    }
    'Types' {
        $context = New-Context -Mixed
        $checks = $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile)
        $zero = @($checks | Where-Object RuleId -eq 'GPO.Expected.FixtureEnabled')[0]
        Assert-Equal 0 $zero.Observed
        Assert-Equal 'System.UInt32' $zero.Observed.GetType().FullName
        $longZero = @($checks | Where-Object RuleId -eq 'GPO.Account.MinimumPasswordLength')[0]
        Assert-Equal 'System.Int64' $longZero.Observed.GetType().FullName
        $falseCheck = @($checks | Where-Object RuleId -eq 'GPO.Account.PasswordComplexity')[0]
        Assert-Equal $false $falseCheck.Observed
        Assert-Equal 'System.Boolean' $falseCheck.Observed.GetType().FullName
        foreach ($allowlist in @($null, [string[]]@())) {
            $context.Profile.Policy.AllowedUserRightSids.SeBackupPrivilege = $allowlist
            Assert-Equal (Get-CanonicalJson @(Test-ADAnalyzerGpoPolicy @context)) (Get-CanonicalJson $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile))
        }
    }
    'Streaming' {
        $context = New-LateFailureContext
        foreach ($preference in @('Continue', 'Stop')) {
            $probe = Invoke-CommandProbe $context $preference
            $expected = $golden.Late.$preference
            Assert-Equal $expected.Rows (Get-CanonicalJson $probe.Rows)
            Assert-Equal $expected.Terminated $probe.Terminated
            Assert-Equal $expected.ErrorReason $probe.ErrorReason
            Assert-Equal $expected.HadError $probe.HadError
        }
        $rows = [Collections.Generic.List[object]]::new()
        $caught = $null
        try {
            $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile) | ForEach-Object { $rows.Add($_) }
        }
        catch {
            $caught = $_
        }
        Assert-Equal $false ($null -eq $caught)
        Assert-Equal 0 $rows.Count
        $valid = New-Context
        Assert-Equal 1 @(Test-ADAnalyzerGpoPolicy @valid | Select-Object -First 1).Count
    }
    'Validation' {
        $context.Profile.RegistryRules = @(@{
                Key = 'Software\Fixture'
                ValueName = 'Password'
                Expected = 'GPO_BASELINE_SECRET'
            })
        $probe = Invoke-CommandProbe $context Stop
        Assert-Equal $true $probe.Terminated
        Assert-Equal 0 $probe.Rows.Count
        $directRows = [Collections.Generic.List[object]]::new()
        $directError = $null
        try {
            $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile) | ForEach-Object { $directRows.Add($_) }
        }
        catch {
            $directError = $_
        }
        Assert-Equal $false ($null -eq $directError)
        Assert-Equal 0 $directRows.Count
        $caught = $null
        try {
            $null = $evaluator.Evaluate($null, $context.Policy, $context.Profile)
        }
        catch {
            $caught = $_
        }
        Assert-Equal $false ($null -eq $caught)
    }
    'Isolation' {
        $second = [ADAnalyzerGpoPolicyEvaluator]::new()
        $firstChecks = $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile)
        $firstChecks[0].Status = 'ChangedByCaller'
        Assert-Equal $golden.Empty (Get-CanonicalJson $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile))
        Assert-Equal $golden.Empty (Get-CanonicalJson $second.Evaluate($context.Gpo, $context.Policy, $context.Profile))
    }
    'Order' {
        $context = New-Context -Mixed
        $checks = $evaluator.Evaluate($context.Gpo, $context.Policy, $context.Profile)
        $categories = @($checks.Category | Select-Object -Unique)
        Assert-Equal 'CredentialExposure|AccountPolicy|SecurityOptions|RestrictedGroups|LocalUsersGroups|UserRightsAssignment|PolicyBaseline|PolicyCoverage' ($categories -join '|')
    }
}

Write-Output ('PASS GPO policy class ' + $Mode)
