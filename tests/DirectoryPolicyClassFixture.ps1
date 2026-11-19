[CmdletBinding()]
param(
    [ValidateSet('RecordBaseline', 'Construction', 'Parity', 'PartialProfile', 'Types', 'Isolation', 'Secrets', 'Errors', 'Streaming', 'Order', 'OperatingSystem')]
    [string]$Case = 'Construction'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')

function Assert-Policy($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function ConvertTo-Canonical($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }
    if ($Value -is [array] -or
        $Value -is [Collections.IList] -or
        ($Value -is [Collections.IEnumerable] -and
            $Value -isnot [Collections.IDictionary] -and
            $Value -isnot [pscustomobject])) {
        return , @(
            foreach ($item in $Value) {
                ConvertTo-Canonical $item
            }
        )
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

function Get-PolicyUtcReferenceTime($Value) {
    $referenceTime = [datetimeoffset]::MinValue
    Assert-Policy (
        $Value -is [string] -and
        [datetimeoffset]::TryParseExact(
            $Value,
            'o',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None,
            [ref]$referenceTime
        ) -and
        $referenceTime.Offset -eq [timespan]::Zero -and
        $Value -ceq $referenceTime.ToString('o')
    ) 'Operating-system reference time is not canonical round-trip UTC.'
    return $referenceTime
}

function Get-GoldenPolicyJson([object[]]$Checks) {
    $comparison = ConvertTo-Canonical $Checks
    foreach ($check in $comparison) {
        if ($check.RuleId -eq 'COMPUTER.OS_POLICY') {
            $null = Get-PolicyUtcReferenceTime $check.Evidence.ReferenceTime
            $check.Evidence.ReferenceTime = '2026-01-01T00:00:00.0000000+00:00'
        }
    }
    return (ConvertTo-Json -InputObject $comparison -Depth 100 -Compress)
}

function Assert-CanonicalEqual([string]$Expected, [string]$Actual, [string]$Message) {
    if ($Expected -ceq $Actual) {
        return
    }

    $offset = 0
    $limit = [math]::Min($Expected.Length, $Actual.Length)
    while ($offset -lt $limit -and $Expected[$offset] -ceq $Actual[$offset]) {
        $offset++
    }
    $start = [math]::Max(0, $offset - 80)
    $expectedContext = $Expected.Substring($start, [math]::Min(250, $Expected.Length - $start))
    $actualContext = $Actual.Substring($start, [math]::Min(250, $Actual.Length - $start))
    $expectedCode = if ($offset -lt $Expected.Length) {
        [int][char]$Expected[$offset]
    }
    else {
        -1
    }
    $actualCode = if ($offset -lt $Actual.Length) {
        [int][char]$Actual[$offset]
    }
    else {
        -1
    }
    throw ($Message + ' JSON offset=' + $offset + ', expectedChar=' + $expectedCode +
        ', actualChar=' + $actualCode + '; expected: ' + $expectedContext +
        '; actual: ' + $actualContext)
}

function New-PolicyContext([switch]$Mixed) {
    $profile = Get-ADAnalyzerDefaultProfile
    $data = [pscustomobject]@{
        Domain = [pscustomobject]@{
            DistinguishedName = 'DC=example,DC=invalid'
            SID = 'S-1-5-21-1-2-3'
            RootDomainSID = 'S-1-5-21-1-2-3'
            MachineAccountQuota = [uint32]0
            PrivilegedSids = @('S-1-5-21-1-2-3-512')
            FeatureSchema = @('msLAPS-PasswordExpirationTime')
            OptionalFeatures = @()
        }
        Server = 'dc.example.invalid'
        Coverage = @{}
        Groups = @()
        Objects = @()
        Trusts = @()
        Acl = [pscustomobject]@{
            Entries = @()
        }
        PasswordPolicies = [pscustomobject]@{
            Resultant = @()
        }
        Hosts = @()
    }
    if ($Mixed) {
        foreach ($name in @(
                'Domain', 'Users', 'Groups', 'Computers', 'Trusts',
                'DefaultPasswordPolicy', 'FineGrainedPasswordPolicies',
                'ResultantPasswordPolicies', 'ServiceAccounts', 'Acl',
                'Hosts', 'OptionalFeatures'
            )) {
            $data.Coverage[$name] = 'Collected'
        }
        $data.Domain.OptionalFeatures = @([pscustomobject]@{
                FeatureGUID = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'
                EnabledScopes = @('CN=Partitions,CN=Configuration,DC=example,DC=invalid')
            })
        $data.Groups = @(
            [pscustomobject]@{
                DistinguishedName = 'CN=Child'
                SID = 'S-1-5-21-1-2-3-3000'
                MemberOf = @('CN=Privileged')
            },
            [pscustomobject]@{
                DistinguishedName = 'CN=Privileged'
                SID = 'S-1-5-21-1-2-3-512'
                MemberOf = @()
            }
        )
        $data.Objects = @(
            [pscustomobject]@{
                DistinguishedName = 'CN=User'
                SID = 'S-1-5-21-1-2-3-2100'
                ObjectGuid = '11111111-1111-1111-1111-111111111111'
                ObjectClass = 'User'
                AccountType = 'User'
                AccountClassification = [pscustomobject]@{
                    Type = 'User'
                    InvalidRules = @()
                }
                Enabled = $false
                UserAccountControl = 0L
                PasswordNeverExpires = $false
                SupportedEncryptionTypes = [uint32]0
                DelegationSchemaStatus = 'Collected'
                ServicePrincipalNames = @('HTTP/shared')
                SIDHistory = @('S-1-5-21-1-2-3-3000', 'S-1-5-99-100')
            },
            [pscustomobject]@{
                DistinguishedName = 'CN=Computer'
                SID = 'S-1-5-21-1-2-3-2101'
                ObjectGuid = '22222222-2222-2222-2222-222222222222'
                ObjectClass = 'Computer'
                AccountType = 'Unknown'
                Enabled = $true
                UserAccountControl = 524288L
                SupportedEncryptionTypes = [uint32]24
                DelegationSchemaStatus = 'Collected'
                ServicePrincipalNames = @('HTTP/shared')
                IsDomainController = $false
            },
            [pscustomobject]@{
                DistinguishedName = 'CN=ManagedService'
                SID = 'S-1-5-21-1-2-3-2102'
                ObjectGuid = '33333333-3333-3333-3333-333333333333'
                ObjectClass = 'ServiceAccount'
                DirectoryObjectClass = 'msDS-GroupManagedServiceAccount'
                AccountType = 'Service'
                UserAccountControl = 0L
                SupportedEncryptionTypes = [uint32]24
                DelegationSchemaStatus = 'Collected'
                PrincipalsAllowedToRetrieveManagedPassword = @('S-1-5-32-544')
                ManagedPasswordIntervalInDays = 30
            }
        )
        $profile.Policy.ApprovedGmsaReaderSids = @('S-1-5-32-544')
        $data.Trusts = @(
            [pscustomobject]@{
                Target = 'child.example.invalid'
                IntraForest = $true
                ForestTransitive = $false
                SIDFilteringQuarantined = $false
            },
            [pscustomobject]@{
                Target = 'external.example.invalid'
                IntraForest = $false
                ForestTransitive = $true
                SIDFilteringForestAware = $false
            }
        )
        $data.Acl.Entries = @([pscustomobject]@{
                Target = $data.Domain.DistinguishedName
                TargetType = 'DomainRoot'
                IdentitySid = 'S-1-5-21-1-2-3-9999'
                Rights = 'GenericAll'
                AccessControlType = 'Allow'
                ObjectType = [guid]::Empty.ToString()
                ObjectTypeName = 'msLAPS-Password'
                InheritedObjectType = ''
                IsInherited = $false
                PropagationFlags = 'None'
                InheritanceType = 'All'
            })
        $data.PasswordPolicies.Resultant = @([pscustomobject]@{
                Target = 'CN=User'
                Source = 'Default'
                Status = 'Collected'
                Policy = [pscustomobject]@{
                    DistinguishedName = $data.Domain.DistinguishedName
                    MinPasswordLength = 0L
                    LockoutThreshold = 0L
                    PasswordHistoryCount = 0L
                    ComplexityEnabled = $false
                    ReversibleEncryptionEnabled = $true
                    LockoutDuration = [timespan]::Zero
                    LockoutObservationWindow = [timespan]::Zero
                    MinPasswordAge = [timespan]::Zero
                    MaxPasswordAge = [timespan]::Zero
                }
            })
        $data.Hosts = @([pscustomobject]@{
                ComputerName = 'host.example.invalid'
                CollectionStatus = 'Collected'
            })
    }
    return @{
        Data = $data
        Profile = $profile
    }
}

function New-ErrorContext([string]$Kind) {
    $context = New-PolicyContext
    if ($Kind -eq 'Numeric') {
        $context.Data.Objects = @([pscustomobject]@{
                DistinguishedName = 'CN=Malformed'
                ObjectClass = 'Other'
                SupportedEncryptionTypes = 'not-a-number'
            })
    }
    else {
        $context.Data.Hosts = @(
            [pscustomobject]@{
                ComputerName = 'first.example.invalid'
            },
            [pscustomobject]@{
                ComputerName = ''
            },
            [pscustomobject]@{
                ComputerName = 'last.example.invalid'
            }
        )
    }
    return $context
}

function Get-FailureContract($Context, [string]$Preference) {
    $checks = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()
    $terminated = $false
    try {
        & {
            Test-ADAnalyzerDirectoryPolicy -Data $Context.Data -Profile $Context.Profile -ErrorAction $Preference
        } 2>&1 | ForEach-Object {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                $errors.Add($_)
            }
            else {
                $checks.Add($_)
            }
        }
    }
    catch {
        $terminated = $true
        $errors.Add($_)
    }
    [pscustomobject]@{
        Checks = (Get-CanonicalJson $checks.ToArray())
        Terminated = $terminated
        ErrorCategories = @($errors | ForEach-Object {
                [string]$_.CategoryInfo.Category
            })
        ErrorReasons = @($errors | ForEach-Object {
                $_.CategoryInfo.Reason
            })
    }
}

if ($Case -eq 'RecordBaseline') {
    Assert-Policy (-not ('ADAnalyzerDirectoryPolicyEvaluator' -as [type])) 'Record the baseline only before migrating the evaluator.'
    $baseline = [ordered]@{
        SourceRevision = '18b0fb2aeae8397f60322f20d4acb44da639d6bc'
    }
    foreach ($kind in @('Empty', 'Mixed')) {
        $context = New-PolicyContext -Mixed:($kind -eq 'Mixed')
        $baseline[$kind] = Get-GoldenPolicyJson @(Test-ADAnalyzerDirectoryPolicy -Data $context.Data -Profile $context.Profile)
    }
    foreach ($kind in @('Numeric', 'Factory')) {
        foreach ($preference in @('Continue', 'Stop')) {
            $baseline[$kind + $preference] = Get-FailureContract (New-ErrorContext $kind) $preference
        }
    }
    $baseline | ConvertTo-Json -Depth 20
    return
}

Assert-Policy ([bool]('ADAnalyzerDirectoryPolicyEvaluator' -as [type])) 'The constructor-based directory policy evaluator is missing.'
$baseline = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'DirectoryPolicyClassBaseline.json') -Raw | ConvertFrom-Json

# Compare the original golden values using this engine's JSON writer. Windows
# PowerShell 5.1 writes Double zero as 0; Core writes 0.0. Concrete types are
# asserted independently below. Preserve ISO strings when the parser supports it.
foreach ($name in @('Empty', 'Mixed')) {
    $parseArguments = @{
        InputObject = $baseline.$name
    }
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $parseArguments.DateKind = 'String'
    }
    $expectedRows = ConvertFrom-Json @parseArguments
    Assert-Policy ($expectedRows -is [array] -or $expectedRows -is [Collections.IList]) 'Golden check list is no longer an array.'
    $expectedCount = if ($name -eq 'Empty') {
        13
    }
    else {
        47
    }
    Assert-Policy ($expectedRows.Count -eq $expectedCount) ($name + ' golden row count changed.')

    # JSON omits .NET numeric types. These four observations come from the
    # accepted source's TimeSpan.TotalDays/TotalMinutes, both Double properties.
    # Restore that known comparison type without changing any golden value.
    foreach ($row in $expectedRows) {
        if ($row.RuleId -in @(
                'PASSWORD.LOCKOUT_DURATION',
                'PASSWORD.LOCKOUT_RESET',
                'PASSWORD.MIN_AGE',
                'PASSWORD.MAX_AGE'
            )) {
            Assert-Policy ($row.Observed -is [ValueType] -and
                $row.Observed -isnot [bool] -and
                $row.Observed -eq 0) 'Original duration golden is no longer numeric zero.'
            $row.Observed = [double]$row.Observed
        }
    }

    $baseline.$name = Get-CanonicalJson $expectedRows
    Assert-Policy ($baseline.$name.StartsWith('[')) 'Golden canonicalization changed the top-level array shape.'
}

switch ($Case) {
    'Construction' {
        $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        Assert-Policy (@($evaluator.PSObject.Properties).Count -eq 0) 'Evaluator retains state.'
        Assert-Policy ((ConvertTo-Json -InputObject $evaluator -Compress) -eq '{}') 'Evaluator serialized internal state.'
        Assert-Policy (@(Get-Module ActiveDirectory, GroupPolicy).Count -eq 0) 'Construction imported native modules.'
        $context = New-PolicyContext
        Assert-Policy (@($evaluator.Evaluate($context.Data, $context.Profile)).Count -eq 13) 'Default evaluation did not run.'
    }

    'Parity' {
        foreach ($kind in @('Empty', 'Mixed')) {
            $context = New-PolicyContext -Mixed:($kind -eq 'Mixed')
            $before = Get-CanonicalJson $context
            $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
            $direct = $evaluator.Evaluate($context.Data, $context.Profile)
            $command = @(Test-ADAnalyzerDirectoryPolicy -Data $context.Data -Profile $context.Profile)
            Assert-CanonicalEqual $baseline.$kind (Get-GoldenPolicyJson $direct) ($kind + ' direct results differ from the original baseline.')
            Assert-CanonicalEqual $baseline.$kind (Get-GoldenPolicyJson $command) ($kind + ' command results differ from the original baseline.')
            Assert-Policy ((Get-CanonicalJson $context) -ceq $before) 'Evaluation mutated input data or profile.'
        }
    }

    'PartialProfile' {
        $context = New-PolicyContext -Mixed
        $profile = @{
            IgnoredExtensionKey = 'fixture extension'
        }
        $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        foreach ($raw in @(@{}, $profile)) {
            $before = Get-CanonicalJson $raw
            $checks = $evaluator.Evaluate($context.Data, $raw)
            $minimum = @($checks | Where-Object RuleId -eq PASSWORD.MIN_LENGTH)
            Assert-Policy ($minimum.Count -eq 1 -and $null -eq $minimum[0].Expected) 'Raw profile was merged with defaults.'
            Assert-Policy ($minimum[0].Status -eq 'NotConfigured') 'Absent profile expectation gained compliance meaning.'
            Assert-Policy ((Get-CanonicalJson $raw) -ceq $before) 'Raw profile was normalized in place.'
        }
    }

    'Types' {
        $context = New-PolicyContext -Mixed
        $checks = [ADAnalyzerDirectoryPolicyEvaluator]::new().Evaluate($context.Data, $context.Profile)
        $quota = @($checks | Where-Object RuleId -eq DOMAIN.MACHINE_ACCOUNT_QUOTA)[0]
        Assert-Policy ($quota.Observed -is [uint32] -and $quota.Observed -eq 0) 'Typed quota zero changed.'
        $flag = @($checks | Where-Object {
                $_.RuleId -eq 'ACCOUNT.PASSWORD_NOT_REQUIRED' -and $_.Target -eq 'CN=User'
            })[0]
        Assert-Policy ($flag.Observed -is [bool] -and -not $flag.Observed) 'False account flag changed.'
        Assert-Policy ($flag.Evidence.UserAccountControl -is [long]) 'Int64 account-control metadata changed width.'
        $minimum = @($checks | Where-Object RuleId -eq PASSWORD.MIN_LENGTH)[0]
        Assert-Policy ($minimum.Observed -is [long] -and $minimum.Observed -eq 0) 'Int64 password-policy zero changed.'
        foreach ($rule in @(
                'PASSWORD.LOCKOUT_DURATION',
                'PASSWORD.LOCKOUT_RESET',
                'PASSWORD.MIN_AGE',
                'PASSWORD.MAX_AGE'
            )) {
            $duration = @($checks | Where-Object RuleId -eq $rule)
            Assert-Policy ($duration.Count -eq 1) ($rule + ' check count changed.')
            Assert-Policy ($duration[0].Observed -is [double] -and
                $duration[0].Observed -eq 0) ($rule + ' is no longer Double zero.')
        }
        $history = @($checks | Where-Object RuleId -eq SIDHISTORY.PRIVILEGED)[0]
        Assert-Policy ($history.Evidence.Privileged -is [string[]]) 'Privileged history array type changed.'
        Assert-Policy ($history.Status -eq 'Fail') 'Privileged historical group lost its failure status.'
        Assert-Policy ($history.Evidence.Unresolved.Count -eq 1) 'Unresolved historical SID was lost.'
    }

    'Isolation' {
        $context = New-PolicyContext -Mixed
        $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        $first = $evaluator.Evaluate($context.Data, $context.Profile)
        $first[0].Status = 'Invalid'
        for ($i = 0; $i -lt 3; $i++) {
            $again = $evaluator.Evaluate($context.Data, $context.Profile)
            Assert-CanonicalEqual $baseline.Mixed (Get-GoldenPolicyJson $again) 'Repeated evaluation retained result mutation or duplicate checks.'
        }
        $other = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        $empty = New-PolicyContext
        Assert-Policy ((Get-CanonicalJson ($other.Evaluate($empty.Data, $empty.Profile))) -ceq $baseline.Empty) 'Independent evaluator inherited another instance input.'
    }

    'Secrets' {
        $context = New-PolicyContext -Mixed
        $marker = 'directory-policy-fixture-sensitive-value'
        $context.Data.Objects[0] | Add-Member NoteProperty Password $marker
        $context.Profile.IgnoredExtensionKey = $marker
        $before = Get-CanonicalJson $context
        $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        $checks = $evaluator.Evaluate($context.Data, $context.Profile)
        Assert-Policy (-not (Get-CanonicalJson $checks).Contains($marker)) 'Unrelated input secret appeared in checks.'
        Assert-Policy (-not ([Management.Automation.PSSerializer]::Serialize($evaluator)).Contains($marker)) 'Evaluator serialization retained a secret.'
        Assert-Policy ((ConvertTo-Json -InputObject $evaluator -Compress) -eq '{}') 'Evaluator retained input state.'
        Assert-Policy ((Get-CanonicalJson $context) -ceq $before) 'Secret-bearing input was modified.'
    }

    'Errors' {
        foreach ($kind in @('Numeric', 'Factory')) {
            foreach ($preference in @('Continue', 'Stop')) {
                $context = New-ErrorContext $kind
                $actual = Get-FailureContract $context $preference
                $expected = $baseline.($kind + $preference)
                Assert-Policy ((Get-CanonicalJson $actual) -ceq (Get-CanonicalJson $expected)) ($kind + '/' + $preference + ' command failure contract changed: ' + (Get-CanonicalJson $actual))
                $rows = [Collections.Generic.List[object]]::new()
                $failed = $false
                try {
                    [ADAnalyzerDirectoryPolicyEvaluator]::new().Evaluate($context.Data, $context.Profile) | ForEach-Object {
                        $rows.Add($_)
                    }
                }
                catch {
                    $failed = $true
                }
                Assert-Policy ($failed -and $rows.Count -eq 0) 'Direct evaluation returned partial results after failure.'
            }
        }
        $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        $nullFailures = 0
        foreach ($arguments in @(
                @($null, @{}),
                @([pscustomobject]@{}, $null)
            )) {
            try {
                $null = $evaluator.Evaluate($arguments[0], $arguments[1])
            }
            catch {
                $nullFailures++
            }
        }
        Assert-Policy ($nullFailures -eq 2) 'Direct null arguments were accepted.'
    }

    'Streaming' {
        $context = New-PolicyContext -Mixed
        $capturedErrors = @()
        $first = @(Test-ADAnalyzerDirectoryPolicy -Data $context.Data -Profile $context.Profile -ErrorVariable capturedErrors |
                Select-Object -First 1)
        Assert-Policy ($first.Count -eq 1 -and $first[0].RuleId -eq 'DOMAIN.MACHINE_ACCOUNT_QUOTA') 'Early pipeline selection changed.'
        Assert-Policy ($capturedErrors.Count -eq 0) 'Early pipeline cancellation became an error.'
        $context = New-ErrorContext Numeric
        $contract = Get-FailureContract $context Stop
        Assert-Policy (@($contract.Checks | ConvertFrom-Json).Count -gt 0) 'Compatibility command lost its emitted prefix before a late failure.'
    }

    'Order' {
        $context = New-PolicyContext -Mixed
        $checks = [ADAnalyzerDirectoryPolicyEvaluator]::new().Evaluate($context.Data, $context.Profile)
        $rules = [string[]]$checks.RuleId
        $spn = [Array]::IndexOf($rules, 'SPN.DUPLICATE')
        $trust = [Array]::IndexOf($rules, 'TRUST.SID_FILTERING')
        $acl = [Array]::IndexOf($rules, 'ACL.DELEGATED_CONTROL')
        $password = [Array]::IndexOf($rules, 'PASSWORD.MIN_LENGTH')
        $hostEvidence = [Array]::IndexOf($rules, 'HOST.OBSERVATIONS')
        Assert-Policy ($spn -gt 0 -and $trust -gt $spn -and $acl -gt $trust) 'Account/SPN/trust/ACL order changed.'
        Assert-Policy ($password -gt $acl -and $hostEvidence -gt $password) 'Password/host evidence order changed.'
        Assert-Policy ($rules[0] -eq 'DOMAIN.MACHINE_ACCOUNT_QUOTA' -and $rules[-1] -eq 'HOST.OBSERVATIONS') 'First or last policy phase changed.'
    }

    'OperatingSystem' {
        $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
        $clock = [datetimeoffset]'2041-08-11T05:00:00+02:00'
        $computer = [pscustomobject]@{
            OperatingSystem = 'Fixture OS'
            OperatingSystemVersion = '10.0 (20348)'
            BuildNumber = $null
            EsuStatus = 'Active'
            EsuValidUntil = $clock.UtcDateTime.ToString('o')
        }
        $rule = @{
            Name = 'Fixture OS'
            VersionPattern = '^10\.0'
            MinimumBuild = 20348
            MaximumBuild = 20348
            SupportedUntil = $clock.UtcDateTime.ToString('o')
            RequireEsu = $false
        }
        $entries = [object[]]@('Unmatched*', $rule)
        $beforeComputer = Get-CanonicalJson $computer

        foreach ($requireEsu in @($false, $true)) {
            $rule.RequireEsu = $requireEsu
            if ($requireEsu) {
                $rule.SupportedUntil = $clock.UtcDateTime.AddDays(-1).ToString('o')
                $expiredReason = 'Required ESU evidence is inactive or expired'
            }
            else {
                $expiredReason = 'Configured support lifecycle has expired'
            }
            $beforeEntries = Get-CanonicalJson $entries
            $atDeadline = $evaluator.EvaluateOperatingSystem($computer, $entries, $clock)
            Assert-Policy (
                $atDeadline.Status -ceq 'Pass' -and
                $atDeadline.Observed.Build -is [long] -and $atDeadline.Observed.Build -eq 20348L -and
                $atDeadline.Evidence.ReferenceTime -ceq $clock.ToString('o') -and
                $atDeadline.Evidence.LifecycleInferred -is [bool] -and -not $atDeadline.Evidence.LifecycleInferred
            ) 'Explicit OS clock, build provenance, or deadline equality changed.'
            Assert-Policy (
                [object]::ReferenceEquals($entries, $atDeadline.Expected) -and
                $atDeadline.Evidence.Matches -is [object[]] -and $atDeadline.Evidence.Matches.Count -eq 1 -and
                [object]::ReferenceEquals($rule, $atDeadline.Evidence.Matches[0].Entry)
            ) 'OS lifecycle evaluation changed the identity or cardinality of configured observations.'

            $afterDeadline = $evaluator.EvaluateOperatingSystem($computer, $entries, $clock.AddTicks(1))
            Assert-Policy (
                $afterDeadline.Status -ceq 'Fail' -and $afterDeadline.Evidence.Matches[0].Reason -ceq $expiredReason
            ) 'Elapsed lifecycle or ESU expiry did not fail immediately after the deadline.'

            $command = @(Test-ADAnalyzerOperatingSystemProfile -Object $computer -Entries $entries -ReferenceTime $clock)
            Assert-Policy ($command.Count -eq 1) 'OS compatibility adapter emitted an unexpected number of results.'
            Assert-CanonicalEqual (Get-CanonicalJson $atDeadline) (Get-CanonicalJson $command[0]) 'Explicit OS compatibility result changed.'
            Assert-Policy ((Get-CanonicalJson $entries) -ceq $beforeEntries) 'OS evaluation mutated its input entries.'
        }
        Assert-Policy ((Get-CanonicalJson $computer) -ceq $beforeComputer) 'OS evaluation mutated its input computer.'

        $beforeDefault = [datetimeoffset]::UtcNow
        $defaultDirect = $evaluator.EvaluateOperatingSystem($computer, [object[]]@())
        $defaultAdapter = Test-ADAnalyzerOperatingSystemProfile -Object $computer
        $afterDefault = [datetimeoffset]::UtcNow
        foreach ($result in @($defaultDirect, $defaultAdapter)) {
            $referenceTime = Get-PolicyUtcReferenceTime $result.Evidence.ReferenceTime
            Assert-Policy (
                $referenceTime -ge $beforeDefault -and $referenceTime -le $afterDefault -and
                $result.Status -ceq 'NotConfigured' -and $result.Expected -is [object[]] -and
                $result.Expected.Count -eq 0 -and $result.Evidence.Matches.Count -eq 0
            ) 'Default OS clock or omitted entries changed.'
        }

        function Test-ADAnalyzerOperatingSystemProfile {
            throw 'Composed directory policy called the legacy OS helper.'
        }

        $context = New-PolicyContext -Mixed
        $context.Data.Objects[1] | Add-Member -NotePropertyMembers @{
            OperatingSystem = $computer.OperatingSystem
            OperatingSystemVersion = $computer.OperatingSystemVersion
        }
        $rule.RequireEsu = $false
        $rule.SupportedUntil = [datetimeoffset]::UtcNow.AddYears(1).ToString('o')
        $context.Profile.Policy.SupportedOperatingSystems = $entries
        $beforeEvaluation = Get-CanonicalJson $context
        $directChecks = $evaluator.Evaluate($context.Data, $context.Profile)
        $commandChecks = @(Test-ADAnalyzerDirectoryPolicy -Data $context.Data -Profile $context.Profile)
        foreach ($checks in @($directChecks, $commandChecks)) {
            $index = [array]::IndexOf([string[]]$checks.RuleId, 'COMPUTER.OS_POLICY')
            Assert-Policy ($index -gt 0 -and $checks[$index - 1].RuleId -ceq 'LAPS.ROTATION_METADATA') 'Composed OS check order changed.'
            $osCheck = $checks[$index]
            Assert-Policy (
                $osCheck.Status -ceq 'Pass' -and $osCheck.Target -ceq 'CN=Computer' -and
                $osCheck.Observed.Build -is [long] -and $osCheck.Observed.Build -eq 20348L
            ) 'Composed OS check no longer contains the expected lifecycle result.'
        }
        Assert-CanonicalEqual (Get-GoldenPolicyJson $directChecks) (Get-GoldenPolicyJson $commandChecks) 'Composed OS policy command and direct result differ.'
        Assert-Policy ((Get-CanonicalJson $context) -ceq $beforeEvaluation) 'Composed OS evaluation mutated input data or policy.'
    }
}

Write-Output ('PASS directory policy class ' + $Case)
