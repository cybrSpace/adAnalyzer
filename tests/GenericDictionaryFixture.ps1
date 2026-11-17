[CmdletBinding()]
param(
    [ValidateSet('Probe', 'Lookup', 'Comparers', 'Projection', 'ExportDefault',
        'ExportContinue', 'ExportStop', 'Baseline', 'Membership', 'Rights',
        'Legacy', 'HostIdentity', 'Normalization')]
    [string]$Case = 'Lookup'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ($Case -eq 'Legacy') {
    # Load metadata and the real script module without registering the provider.
    $null = [Reflection.Assembly]::LoadFrom(
        (Join-Path $repositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll')
    )
    $script:LegacyModule = Import-Module (
        Join-Path $repositoryRoot 'bin/ADEnvironment.psm1'
    ) -Force -PassThru
}
else {
    . (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
}

$script:Marker = 'DICTIONARY_PAYLOAD_076'
$script:Scenarios = 0
$script:Sink = [Collections.Generic.List[object]]::new()

function Assert-Dictionary($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-DictionaryMap([string]$Kind, [hashtable]$Values) {
    $map = switch ($Kind) {
        'Generic' {
            [Collections.Generic.Dictionary[string, object]]::new(
                [StringComparer]::Ordinal
            )
        }
        'Hashtable' {
            @{}
        }
        'Ordered' {
            [Collections.Specialized.OrderedDictionary]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
        }
        default {
            throw 'Unknown dictionary fixture kind.'
        }
    }
    foreach ($key in $Values.Keys) {
        $map.Add($key, $Values[$key])
    }
    return , $map
}

function Get-DictionarySnapshot($Map) {
    ConvertTo-Json -InputObject $Map -Depth 30 -Compress
}

function Get-DictionaryTypedRows([AllowNull()][object[]]$Rows) {
    $typed = @(
        foreach ($row in $Rows) {
            [pscustomobject][ordered]@{
                Type = if ($null -eq $row) {
                    '<null>'
                }
                else {
                    $row.GetType().FullName
                }
                Json = ConvertTo-Json -InputObject $row -Depth 30 -Compress
            }
        }
    )
    ConvertTo-Json -InputObject $typed -Depth 40 -Compress
}

function Invoke-DictionaryLookup($Map, [string]$Helper, [string]$Name = 'Field') {
    switch ($Helper) {
        'Operation' {
            Get-ADAnalyzerOperationValue $Map @('Missing', $Name) 'fallback'
        }
        'Directory' {
            Get-ADAnalyzerDirectoryField $Map $Name 'fallback'
        }
        'Policy' {
            Get-ADAnalyzerPolicyValue $Map $Name 'fallback'
        }
    }
}

function Write-ADAnalyzerFile {
    param(
        $Path,
        [AllowEmptyString()][string]$Content

    )
    $script:Sink.Add([pscustomobject]@{
            Path = $Path
            Content = $Content
            HasPayload = $Content.Contains($script:Marker)
        })
    $Path
}

function Invoke-DictionaryExport($Evidence, [string]$Mode) {
    $assessment = [pscustomobject]@{
        SchemaVersion = 1
        Target = 'fixture'
        Findings = @(
            [pscustomobject]@{
                RuleId = 'FIXTURE'
                Target = 'fixture'
                Status = 'Fail'
                Evidence = $Evidence
            }
        )
    }
    $parameters = @{
        Assessment = $assessment
        Path = 'memory-only-dictionary'
        Format = 'All'
        Confirm = $false
    }
    if ($Mode -ne 'Default') {
        $parameters.ErrorAction = $Mode
    }
    Export-ADAnalyzerAssessment @parameters
}

function New-DictionaryPolicy {
    [pscustomobject]@{
        SecuritySettings = @()
        RegistrySettings = @()
        IniSettings = @()
        PreferenceSettings = @()
        XmlFiles = @()
        Files = @()
        UnparsedFiles = @()
    }
}

# The default/Continue reproduction deliberately has no enclosing try block.
if ($Case -eq 'Probe') {
    $body = (Get-Command Get-ADAnalyzerOperationValue).ScriptBlock.ToString()
    Assert-Dictionary ($body.Contains('$Object.Contains($name)')) 'Capture the accepted dictionary defect before correction.'
    $ErrorActionPreference = 'Continue'
    foreach ($mode in @('Default', 'Continue')) {
        $map = New-DictionaryMap Generic @{
            Name = 'Password'
            Value = $script:Marker
        }
        $before = Get-DictionarySnapshot $map
        $script:Sink.Clear()
        $rows = @(Invoke-DictionaryExport $map $mode 2>&1)
        $errors = @($rows | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
        $paths = @($rows | Where-Object { $_ -isnot [Management.Automation.ErrorRecord] })
        $payloadWrites = @($script:Sink | Where-Object HasPayload).Count
        Assert-Dictionary ($errors.Count -eq 7 -and $paths.Count -eq 3) 'Original Continue dispatch path was not reproduced.'
        Assert-Dictionary ($script:Sink.Count -eq 3 -and
            $payloadWrites -eq 3) 'Original generic dictionary export disclosure was not reproduced.'
        Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $map)) 'Original probe changed its input.'
        Write-Host ('PROBE dictionary {0}; OutwardErrors={1}; Paths={2}; Writes={3}; PayloadWrites={4}' -f
            $mode, $errors.Count, $paths.Count, $script:Sink.Count, $payloadWrites)
    }
    $script:Sink.Clear()
    $caught = $null
    try {
        $null = Invoke-DictionaryExport $map Stop
    }
    catch {
        $caught = $_
    }
    Assert-Dictionary ([bool]$caught -and $script:Sink.Count -eq 0) 'Original Stop behavior was not reproduced.'
    Write-Host 'PASS dictionary original Default/Continue disclosure and Stop failure reproduced'
    return
}

switch ($Case) {
    'Lookup' {
        $samples = @(
            @{
                Value = $null
                Expected = @($null)
            }
            @{
                Value = $false
                Expected = @($false)
            }
            @{
                Value = 0
                Expected = @(0)
            }
            @{
                Value = ''
                Expected = @('')
            }
            @{
                Value = @()
                Expected = @()
            }
            @{
                Value = @(1)
                Expected = @(1)
            }
            @{
                Value = @(1, 2)
                Expected = @(1, 2)
            }
            @{
                Value = 'ordinary'
                Expected = @('ordinary')
            }
        )
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            foreach ($helper in @('Operation', 'Directory', 'Policy')) {
                foreach ($sample in $samples) {
                    $map = New-DictionaryMap $kind @{
                        Field = $sample.Value
                    }
                    $before = Get-DictionarySnapshot $map
                    $rows = @(Invoke-DictionaryLookup $map $helper)
                    $actual = Get-DictionaryTypedRows -Rows $rows
                    $expected = Get-DictionaryTypedRows -Rows @($sample.Expected)
                    Assert-Dictionary ($actual -ceq $expected) 'Lookup changed present-value type/cardinality or used the absent fallback.'
                    Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $map)) 'Lookup mutated its dictionary.'
                    $script:Scenarios++
                }
            }
        }
    }
    'Comparers' {
        foreach ($helper in @('Operation', 'Directory', 'Policy')) {
            foreach ($comparer in @([StringComparer]::Ordinal, [StringComparer]::OrdinalIgnoreCase)) {
                $map = [Collections.Generic.Dictionary[string, object]]::new($comparer)
                $map.Add('Field', 'ordinary')
                foreach ($name in @('Field', 'field')) {
                    $expected = if ($comparer.Equals($name, 'Field')) {
                        'ordinary'
                    }
                    else {
                        'fallback'
                    }
                    $rows = @(Invoke-DictionaryLookup $map $helper $name)
                    Assert-Dictionary ($rows.Count -eq 1 -and $rows[0] -ceq $expected) 'Lookup changed the native dictionary comparer.'
                    $script:Scenarios++
                }
            }
            $integerKeys = [Collections.Generic.Dictionary[int, object]]::new()
            $integerKeys.Add(1, 'integer')
            $rows = @(Invoke-DictionaryLookup $integerKeys $helper '1')
            Assert-Dictionary ($rows.Count -eq 1 -and $rows[0] -ceq 'fallback') 'Lookup coerced a string field into an integer key.'
            $script:Scenarios++
            $stringKeys = [Collections.Generic.Dictionary[string, object]]::new()
            $stringKeys.Add('1', 'string')
            $rows = @(Invoke-DictionaryLookup $stringKeys $helper '1')
            Assert-Dictionary ($rows.Count -eq 1 -and $rows[0] -ceq 'string') 'Lookup lost the actual string key.'
            $script:Scenarios++
        }
    }

    'Projection' {
        $labels = @('Name', 'ValueName', 'Attribute', 'AttributeName', 'Property', 'PropertyName', 'SettingName')
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            foreach ($label in $labels) {
                foreach ($variant in @('Value', 'Expected', 'ObservedFalse', 'ExistingTrue')) {
                    $values = @{
                        $label = 'Password'
                    }
                    switch ($variant) {
                        'Value' {
                            $values.Value = $script:Marker
                        }
                        'Expected' {
                            $values.Expected = $script:Marker
                        }
                        'ObservedFalse' {
                            $values.Observed = $false
                        }
                        'ExistingTrue' {
                            $values.Value = ''
                            $values.SecretPresent = $true
                        }
                    }
                    $map = New-DictionaryMap $kind $values
                    $before = Get-DictionarySnapshot $map
                    $rows = @(ConvertTo-ADAnalyzerSafeData -InputObject $map -ErrorAction Stop)
                    Assert-Dictionary ($rows.Count -eq 1 -and $rows[0] -is [pscustomobject]) 'Dictionary projection changed output shape.'
                    $safe = $rows[0]
                    Assert-Dictionary (-not (ConvertTo-Json `
                                -InputObject $safe `
                                -Compress).Contains($script:Marker)) 'Dictionary projection retained a payload.'
                    foreach ($payloadName in @('Value', 'Expected', 'Observed')) {
                        Assert-Dictionary ($null -eq $safe.PSObject.Properties[$payloadName]) 'Tagged payload field survived projection.'
                    }
                    if ($variant -eq 'Expected') {
                        Assert-Dictionary ($null -eq $safe.PSObject.Properties['SecretPresent']) 'Expected-only data invented presence evidence.'
                    }
                    else {
                        $expected = $variant -ne 'ObservedFalse'
                        Assert-Dictionary ($safe.SecretPresent -is [bool] -and
                            $safe.SecretPresent -eq $expected) 'Dictionary projection changed typed presence semantics.'
                    }
                    Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $map)) 'Projection changed source evidence.'
                    $script:Scenarios++
                }
            }
        }
    }
    { $_ -in @('ExportDefault', 'ExportContinue', 'ExportStop') } {
        $mode = $Case.Substring('Export'.Length)
        $ErrorActionPreference = if ($mode -eq 'Stop') {
            'Stop'
        }
        else {
            'Continue'
        }
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            $map = New-DictionaryMap $kind @{
                Name = 'Password'
                Value = $script:Marker
            }
            $before = Get-DictionarySnapshot $map
            $script:Sink.Clear()
            $rows = @(Invoke-DictionaryExport $map $mode 2>&1)
            $errors = @($rows | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
            $paths = @($rows | Where-Object { $_ -isnot [Management.Automation.ErrorRecord] })
            Assert-Dictionary ($errors.Count -eq 0) 'Export emitted dictionary dispatch errors.'
            Assert-Dictionary ($paths.Count -eq 3 -and $script:Sink.Count -eq 3) 'Real export did not exercise JSON/HTML/CSV.'
            Assert-Dictionary (@($script:Sink | Where-Object HasPayload).Count -eq 0) 'Generic dictionary payload reached an export formatter.'
            $jsonRows = @($script:Sink | Where-Object { $_.Path -like '*.json' })
            Assert-Dictionary ($jsonRows.Count -eq 1) 'JSON formatter was not executed.'
            $json = $jsonRows[0].Content | ConvertFrom-Json
            $evidence = $json.Findings[0].Evidence
            Assert-Dictionary ($evidence.SecretPresent -is [bool] -and $evidence.SecretPresent) 'JSON export lost typed true presence.'
            Assert-Dictionary ($null -eq $evidence.PSObject.Properties['Value']) 'JSON export retained a secret Value property.'
            Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $map)) 'Export changed its source.'
            $script:Scenarios++
        }
    }
    'Baseline' {
        $samples = @(
            @{
                Collection = 'ExpectedGpoSettings'
                Values = @{
                    Kind = 'Account'
                    Name = 'ordinary'
                }
                Error = $null
            }
            @{
                Collection = 'ExpectedGpoSettings'
                Values = @{
                    Kind = 'Account'
                    Name = 'Password'
                }
                Error = 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'
            }
            @{
                Collection = 'ExpectedGpoSettings'
                Values = @{
                    Kind = 'Account'
                    Name = 'ordinary'
                    ValueName = 'Password'
                }
                Error = $null
            }
            @{
                Collection = 'RegistryRules'
                Values = @{
                    Kind = 'Registry'
                    Name = 'Password'
                    ValueName = 'Enabled'
                }
                Error = $null
            }
            @{
                Collection = 'Host'
                Values = @{
                    Key = 'Software\Fixture'
                    ValueName = 'Password'
                }
                Error = 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'
            }
            @{
                Collection = 'ExpectedGpoSettings'
                Values = @{
                    Kind = 'Account'
                    Name = 42
                }
                Error = 'Custom value baseline identity fields must be strings or null.'
            }
        )
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            foreach ($sample in $samples) {
                $rule = New-DictionaryMap $kind $sample.Values
                $profile = @{
                    Host = @{
                        RegistryRules = @()
                    }
                    RegistryRules = @()
                    ExpectedGpoSettings = @()
                }
                if ($sample.Collection -eq 'Host') {
                    $profile.Host.RegistryRules = @($rule)
                }
                else {
                    $profile[$sample.Collection] = @($rule)
                }
                $before = Get-DictionarySnapshot $profile
                $caught = $null
                $rows = [Collections.Generic.List[object]]::new()
                try {
                    Assert-ADAnalyzerValueBaseline $profile | ForEach-Object {
                        $rows.Add($_)
                    }
                }
                catch {
                    $caught = $_
                }
                if ($null -eq $sample.Error) {
                    Assert-Dictionary ($null -eq $caught) 'A valid raw dictionary baseline failed.'
                }
                else {
                    Assert-Dictionary ([bool]$caught -and
                        $caught.Exception.Message -ceq $sample.Error) 'Baseline validation lost its established diagnostic.'
                }
                Assert-Dictionary ($rows.Count -eq 0) 'Baseline validation emitted an unintended result.'
                Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $profile)) 'Baseline validation changed its input.'
                $script:Scenarios++
            }
        }
    }
    'Membership' {
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            $profile = Get-ADAnalyzerDefaultProfile
            $profile.Policy = New-DictionaryMap $kind @{
                ApprovedLocalAdminSids = @('S-1-5-32-544')
                AllowedUserRightSids = @{}
            }
            $before = Get-DictionarySnapshot $profile
            $state = @{
                Gpo = [pscustomobject]@{
                    Id = 'fixture'
                }
                Policy = New-DictionaryPolicy
                Profile = $profile
                Target = 'GPO:fixture'
                Checks = [Collections.Generic.List[object]]::new()
                CommandContext = $null
                ErrorPreference = 'Stop'
            }
            [ADAnalyzerGpoPolicyEvaluator]::new().EvaluateMembershipAndRights($state)
            Assert-Dictionary ($state.Checks.Count -eq 2) 'Membership phase changed empty-policy coverage.'
            foreach ($check in $state.Checks) {
                Assert-Dictionary ($check.Status -ceq 'NotConfigured') 'Membership phase changed an empty-policy status.'
            }
            Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $profile)) 'Membership evaluation changed raw policy input.'
            $script:Scenarios++
        }
    }
    'Rights' {
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            foreach ($stateName in @('Matching', 'Absent', 'PresentNull', 'Unapproved')) {
                $values = @{}
                $expected = switch ($stateName) {
                    'Matching' {
                        $values.SeDebugPrivilege = @('S-1-5-32-544')
                        'Pass'
                    }
                    'Absent' {
                        'Unknown'
                    }
                    'PresentNull' {
                        $values.SeDebugPrivilege = $null
                        'Invalid'
                    }
                    'Unapproved' {
                        $values.SeDebugPrivilege = @('S-1-5-32-545')
                        'Fail'
                    }
                }
                $profile = Get-ADAnalyzerDefaultProfile
                $profile.Policy.AllowedUserRightSids = New-DictionaryMap $kind $values
                $policy = New-DictionaryPolicy
                $policy.SecuritySettings = @(
                    [pscustomobject]@{
                        Kind = 'UserRightsAssignment'
                        Name = 'SeDebugPrivilege'
                        Value = @('*S-1-5-32-544')
                        Scope = 'Computer'
                        Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
                    }
                )
                $gpo = [pscustomobject]@{
                    Id = 'fixture'
                }
                $before = Get-DictionarySnapshot $profile
                foreach ($api in @('Object', 'Command')) {
                    $checks = if ($api -eq 'Object') {
                        [ADAnalyzerGpoPolicyEvaluator]::new().Evaluate($gpo, $policy, $profile)
                    }
                    else {
                        @(Test-ADAnalyzerGpoPolicy $gpo $policy $profile -ErrorAction Stop)
                    }
                    $right = @($checks | Where-Object RuleId -eq 'GPO.UserRights.SeDebugPrivilege')
                    Assert-Dictionary ($right.Count -eq 1 -and
                        $right[0].Status -ceq $expected) 'Raw dictionary rights evaluation changed the required status.'
                    Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $profile)) 'Rights evaluation changed its profile.'
                    $script:Scenarios++
                }
            }
        }
    }

    'Legacy' {
        $cases = [Collections.Generic.List[object]]::new()
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            foreach ($stateName in @('Matching', 'Absent', 'PresentNull', 'Unapproved')) {
                $values = @{}
                $label = $null
                switch ($stateName) {
                    'Matching' {
                        $values.SeDebugPrivilege = @('S-1-5-32-544')
                    }
                    'Absent' {
                        $label = 'Validate - UserRightsAssignment Allowlist Not Configured'
                    }
                    'PresentNull' {
                        $values.SeDebugPrivilege = $null
                        $label = 'Validate - Invalid UserRightsAssignment Allowlist'
                    }
                    'Unapproved' {
                        $values.SeDebugPrivilege = @('S-1-5-32-545')
                        $label = 'Defect - Invalid UserRightsAssignment'
                    }
                }
                $rights = New-DictionaryMap $kind $values
                $cases.Add([pscustomobject]@{
                        Rights = $rights
                        Before = Get-DictionarySnapshot $rights
                        ExpectedCount = if ($stateName -eq 'Matching') {
                            0
                        }
                        else {
                            1
                        }
                        Label = $label
                    })
            }
        }
        $body = [scriptblock]::Create(@'
param([object[]]$Cases)
$ErrorActionPreference = 'Stop'
$prior = Get-Variable -Name ADAnalyzerLegacyProfile -Scope Script -ErrorAction SilentlyContinue
$hadProfile = $null -ne $prior
$previousProfile = if ($hadProfile) {
    $prior.Value
}
else {
    $null
}
$completed = 0
try {
    foreach ($sample in $Cases) {
        $script:ADAnalyzerLegacyProfile = @{
            Policy = @{
                AllowedUserRightSids = $sample.Rights
            }
        }
        $row = [pscustomobject]@{
            'ext.property.name' = 'UserRightsAssignment'
            'gpo.linked.ou' = 'OU=Domain Controllers,DC=example,DC=invalid'
            'property.setting.right' = 'SeDebugPrivilege'
            'property.setting.sid' = 'S-1-5-32-544'
            'property.setting.empty' = $false
        }
        $findings = [GroupPolicyObject]::Analyze($row)
        if ($findings -isnot [Finding] -or $findings.Count -ne $sample.ExpectedCount) {
            throw 'Legacy dictionary finding type/count changed.'
        }
        if ($sample.ExpectedCount -eq 1 -and $findings[0].finding -cne $sample.Label) {
            throw 'Legacy dictionary finding label changed.'
        }
        $after = ConvertTo-Json -InputObject $sample.Rights -Depth 30 -Compress
        if ($after -cne $sample.Before) {
            throw 'Legacy analysis changed its allowlist.'
        }
        $completed++
    }
    return $completed
}
finally {
    if ($hadProfile) {
        $script:ADAnalyzerLegacyProfile = $previousProfile
    }
    else {
        Remove-Variable -Name ADAnalyzerLegacyProfile -Scope Script -ErrorAction SilentlyContinue
    }
}
'@)
        $script:Scenarios = & $script:LegacyModule $body ($cases.ToArray())
    }
    'HostIdentity' {
        foreach ($kind in @('Generic', 'Hashtable', 'Ordered')) {
            foreach ($stateName in @('Absent', 'Valid', 'Null', 'Empty', 'Nul')) {
                $values = @{}
                if ($stateName -ne 'Absent') {
                    $values.Id = switch ($stateName) {
                        'Valid' {
                            'one'
                        }
                        'Null' {
                            $null
                        }
                        'Empty' {
                            ''
                        }
                        'Nul' {
                            'bad' + [char]0 + 'id'
                        }
                    }
                }
                $rule = New-DictionaryMap $kind $values
                $before = Get-DictionarySnapshot $rule
                $caught = $null
                $result = $null
                try {
                    $result = Get-ADAnalyzerHostRuleIdentity -Rule $rule -Target 'host' -Parts @('part')
                }
                catch {
                    $caught = $_
                }
                if ($stateName -in @('Absent', 'Valid')) {
                    $expected = if ($stateName -eq 'Absent') {
                        'host'
                    }
                    else {
                        'HostRuleId' + [char]0 + '4:host4:part3:one'
                    }
                    Assert-Dictionary ($null -eq $caught -and $result -ceq $expected) 'Host identity changed valid/absent Id semantics.'
                }
                else {
                    Assert-Dictionary ([bool]$caught -and
                        $caught.Exception.Message -ceq 'Host rule Id must be a nonempty string without NUL characters') 'Host identity lost its invalid-Id diagnostic.'
                }
                Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $rule)) 'Host identity changed its input.'
                $script:Scenarios++
            }
        }
    }
    'Normalization' {
        $samples = @(
            @{
                Section = 'Services'
                Rule = @{
                    Name = 'Fixture'
                    State = 'Running'
                    StartMode = 'Automatic'
                }
            }
            @{
                Section = 'RegistryRules'
                Rule = @{
                    Key = 'Software\Fixture'
                    ValueName = 'Enabled'
                    Expected = 1
                    Type = 4
                    Operator = 'Equals'
                }
            }
            @{
                Section = 'CertificateEndpoints'
                Rule = @{
                    HostName = 'fixture.invalid'
                    Port = 443
                    MinimumRemainingDays = 1
                }
            }
            @{
                Section = 'ExpectedGpoSettings'
                Rule = @{
                    Kind = 'Account'
                    Name = 'MinimumPasswordLength'
                    Expected = 14
                    Operator = 'Minimum'
                    Severity = 'High'
                }
            }
        )
        foreach ($sample in $samples) {
            $rule = New-DictionaryMap Generic $sample.Rule
            $profile = @{}
            if ($sample.Section -eq 'ExpectedGpoSettings') {
                $profile.ExpectedGpoSettings = @($rule)
            }
            else {
                $profile.Host = @{
                    $sample.Section = @($rule)
                }
            }
            $before = Get-DictionarySnapshot $profile
            $normalized = [ADAnalyzerProfile]::new($profile).ToHashtable()
            $rules = @(if ($sample.Section -eq 'ExpectedGpoSettings') {
                    $normalized.ExpectedGpoSettings
                }
                else {
                    $normalized.Host[$sample.Section]
                })
            Assert-Dictionary ($rules.Count -eq 1 -and
                $rules[0] -is [hashtable]) 'Public profile construction did not normalize generic rules before validation.'
            Assert-Dictionary ($before -ceq (Get-DictionarySnapshot $profile)) 'Profile construction changed caller rules.'
            $script:Scenarios++
        }
    }
}

$expectedCases = @{
    Lookup = 72
    Comparers = 18
    Projection = 84
    ExportDefault = 3
    ExportContinue = 3
    ExportStop = 3
    Baseline = 18
    Membership = 3
    Rights = 24
    Legacy = 12
    HostIdentity = 15
    Normalization = 4
}
Assert-Dictionary ($script:Scenarios -eq $expectedCases[$Case]) 'Required dictionary cases were not all executed.'
Write-Host ('PASS dictionary interface ' + $Case + ' ' + $script:Scenarios)
