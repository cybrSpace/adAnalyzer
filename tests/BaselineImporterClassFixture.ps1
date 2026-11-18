[CmdletBinding()]
param(
    [ValidateSet('Contracts', 'Direct')][string]$Case = 'Contracts',
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

# Exact Import-ADAnalyzerBaseline function accepted at U-098.
$script:OriginalBaseline = @'
function Import-ADAnalyzerBaseline {
    <# Import an extracted GPO backup (including SCT backups) as stored-setting
       expectations. The input root contains Machine/User and GPT.INI, usually
       <backup>/DomainSysvol/GPO. It does not calculate effective policy. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$GpoPath,
        [string]$Name = 'Imported GPO baseline',
        [Parameter(Mandatory)][string]$Version

    )
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Name = $Name
    $profile.Version = $Version
    $registry = [Collections.ArrayList]::new()
    $settings = [Collections.ArrayList]::new()
    $seen = @{}
    foreach ($path in $GpoPath) {
        $policy = Read-ADAnalyzerGpo -Path $path
        if (-not $policy.Files.Count) {
            throw "No policy files in baseline: $path"
        }
        foreach ($row in @(Get-ADAnalyzerEffectiveRegistryRecords -RegistrySettings $policy.RegistrySettings)) {
            if ($row.Deleted -or $row.DeletionDirective -or $row.KeyOnly -or (Test-ADAnalyzerSecretName $row.ValueName)) {
                continue
            }
            $parts = @($row.Hive, $row.Key, $row.ValueName)
            $key = ('{0}|{1}|{2}' -f $parts).ToLowerInvariant()
            $identity = (Join-ADAnalyzerPolicyIdentity $parts).ToLowerInvariant()
            $value = ConvertTo-Json -InputObject ([ordered]@{
                    Type = [int]$row.Type
                    Value = $row.Value
                }) -Compress -Depth 20
            if ($seen.ContainsKey($identity)) {
                if ($seen[$identity] -ne $value) {
                    throw "Conflicting baseline registry setting: $key"
                }
                continue
            }
            $seen[$identity] = $value
            # Keep the established hash seed when the components contain no literal pipe.
            $hashTarget = $key
            if ($key.Split('|').Count -gt 3) {
                $hashTarget = $identity
            }
            $stable = (New-ADAnalyzerCheck -RuleId 'BASELINE.REGISTRY' -Target $hashTarget -Status Pass).CheckId.Substring(0, 16)
            $null = $registry.Add(@{
                    Id = 'BASELINE.REGISTRY.' + $stable
                    Hive = $row.Hive
                    Key = $row.Key
                    ValueName = $row.ValueName
                    Type = [int]$row.Type
                    Operator = 'Equals'
                    Expected = $row.Value
                    Severity = 'Medium'
                    Source = $path
                })
        }
        $securityGroups = @($policy.SecuritySettings | Where-Object { $_.Kind -in 'Account',
                'SecurityOptions' -and
                -not (Test-ADAnalyzerSecretName $_.Name) } | Group-Object Scope,
            Kind,
            Name)
        foreach ($group in $securityGroups) {
            if (@($group.Group | Where-Object { -not (Test-ADAnalyzerPolicyValueValid $_) }).Count) {
                throw 'Baseline contains an invalid stored policy value'
            }
            $row = $group.Group[0]
            $aggregate = $group.Count -gt 1
            $expected = if ($aggregate) {
                , @($group.Group | ForEach-Object Value | Sort-Object)
            }
            else {
                $row.Value
            }
            $key = ('{0}|{1}|{2}' -f $row.Scope, $row.Kind, $row.Name).ToLowerInvariant()
            $value = ConvertTo-Json -InputObject $expected -Compress -Depth 20
            if ($seen.ContainsKey($key)) {
                if ($seen[$key] -ne $value) {
                    throw "Conflicting baseline security setting: $key"
                }
                continue
            }
            $seen[$key] = $value
            $stable = (New-ADAnalyzerCheck -RuleId 'BASELINE.SECURITY' -Target $key -Status Pass).CheckId.Substring(0, 16)
            $null = $settings.Add(@{
                    Id = 'BASELINE.SECURITY.' + $stable
                    Kind = $row.Kind
                    Scope = $row.Scope
                    Name = $row.Name
                    Aggregate = $aggregate
                    Operator = 'Equals'
                    Expected = $expected
                    Severity = 'Medium'
                    Source = $path
                })
        }
    }
    $profile.RegistryRules = $registry.ToArray()
    $profile.ExpectedGpoSettings = $settings.ToArray()
    Import-ADAnalyzerProfile -Profile $profile
}
'@
$script:OriginalHash = '3d6c9cd09672f353ee5be6f1e6080c2870e3310312ba66b0f20880e800d5df6d'
$script:Count = 0

function Assert-BaselineFixture($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-BaselineFixtureHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Assert-BaselineBinding {
    Assert-BaselineFixture ((Get-BaselineFixtureHash $script:OriginalBaseline) -ieq $script:OriginalHash) 'Frozen baseline importer source changed.'
    $tokens = $null
    $errors = $null
    $oracle = [Management.Automation.Language.Parser]::ParseInput($script:OriginalBaseline, [ref]$tokens, [ref]$errors)
    $actual = (Get-Command Import-ADAnalyzerBaseline -CommandType Function).ScriptBlock.Ast
    if ($actual -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $actual = $actual.Body
    }
    Assert-BaselineFixture ($errors.Count -eq 0 -and
        (Get-BaselineFixtureHash $actual.ParamBlock.Extent.Text) -ceq
        (Get-BaselineFixtureHash $oracle.EndBlock.Statements[0].Body.ParamBlock.Extent.Text)) 'The compatibility command parameter contract changed.'
}

function Assert-BaselineSame($Expected, $Actual, [string]$Label) {
    $before = ConvertTo-Json -InputObject $Expected -Depth 15 -Compress
    $after = ConvertTo-Json -InputObject $Actual -Depth 15 -Compress
    Assert-BaselineFixture ($before -ceq $after) "$Label differs from the frozen same-runtime importer."
}

function Get-BaselineFixtureRecord($Profile) {
    [pscustomobject]@{
        Name = $Profile.Name
        Version = $Profile.Version
        Registry = @(foreach ($rule in $Profile.RegistryRules) {
                [pscustomobject]@{
                    Id = $rule.Id
                    Key = $rule.Key
                    Hive = $rule.Hive
                    ValueName = $rule.ValueName
                    Type = $rule.Type
                    Expected = $rule.Expected
                    ExpectedType = $rule.Expected.GetType().FullName
                    Operator = $rule.Operator
                    Severity = $rule.Severity
                    Source = $rule.Source
                }
            })
        Security = @(foreach ($rule in $Profile.ExpectedGpoSettings) {
                [pscustomobject]@{
                    Id = $rule.Id
                    Scope = $rule.Scope
                    Kind = $rule.Kind
                    Name = $rule.Name
                    Aggregate = $rule.Aggregate
                    Expected = $rule.Expected
                    ExpectedType = $rule.Expected.GetType().FullName
                    Operator = $rule.Operator
                    Severity = $rule.Severity
                    Source = $rule.Source
                }
            })
    }
}

function Get-BaselineFixtureError([Management.Automation.ErrorRecord]$Record) {
    $cause = $Record.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Invoke-BaselineNativeObservation($Scenario, [bool]$Frozen) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:OriginalBaseline))
    }

    function Read-ADAnalyzerGpo {
        [CmdletBinding()]
        param([string]$Path)

        $paths.Add($Path)
        if ($Path -eq 'observe') {
            Write-Error -Message 'inert baseline reader diagnostic' -ErrorId 'BaselineFixtureReader'
        }
        $files = @([pscustomobject]@{
                Path = 'Machine/Registry.pol'
            })
        if ($Path -eq 'empty') {
            $files = @()
        }
        [pscustomobject]@{
            Files = $files
            RegistrySettings = @([pscustomobject]@{
                    Scope = 'Computer'
                    Hive = 'HKLM'
                    Key = 'Software\Fixture'
                    ValueName = 'FixtureValue'
                    Type = 4
                    Value = [uint32]21
                    KeyOnly = $false
                    DeletionDirective = $false
                })
            SecuritySettings = @()
        }
    }

    $paths = [Collections.Generic.List[string]]::new()
    $observations = [Collections.Generic.List[object]]::new()
    $nativeErrors = @()
    $arguments = @{
        GpoPath = $Scenario.Paths
        Version = $Scenario.Version
        ErrorAction = $Scenario.Action
        ErrorVariable = 'nativeErrors'
    }
    if ($Scenario.ContainsKey('ImportName')) {
        $arguments.Name = $Scenario.ImportName
    }
    $observe = {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            $observations.Add((Get-BaselineFixtureError $_))
        }
        else {
            $observations.Add((Get-BaselineFixtureRecord $_))
        }
    }
    $caught = $null
    if ($Scenario.Catch) {
        try {
            Import-ADAnalyzerBaseline @arguments 2>&1 | ForEach-Object $observe
        }
        catch {
            $caught = Get-BaselineFixtureError $_
        }
    }
    else {
        Import-ADAnalyzerBaseline @arguments 2>&1 | ForEach-Object $observe
    }
    [pscustomobject]@{
        Paths = $paths.ToArray()
        Stream = $observations.ToArray()
        Caught = $caught
        ErrorVariable = @($nativeErrors | Where-Object { $_ -is [Management.Automation.ErrorRecord] } | ForEach-Object { Get-BaselineFixtureError $_ })
    }
}

function Invoke-FrozenBaseline($Arguments) {
    . ([scriptblock]::Create($script:OriginalBaseline))
    Import-ADAnalyzerBaseline @Arguments
}

function Write-BaselineFixtureBackup([string]$Root, [object[]]$Rows, [int]$MinimumLength = 16) {
    $security = Join-Path $Root 'Machine/Microsoft/Windows NT/SecEdit'
    $null = [IO.Directory]::CreateDirectory($security)
    [IO.File]::WriteAllLines((Join-Path $Root 'GPT.INI'), @('[General]', 'Version=1'))
    [IO.File]::WriteAllLines((Join-Path $security 'GptTmpl.inf'), @(
            '[System Access]'
            "MinimumPasswordLength=$MinimumLength"
            '[Registry Values]'
            'MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,"z","a","z"'
        ), [Text.Encoding]::Unicode)
    $writer = [IO.BinaryWriter]::new([IO.File]::Create((Join-Path $Root 'Machine/Registry.pol')))
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'))
        $writer.Write([uint32]1)
        foreach ($row in $Rows) {
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Key + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Name + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([uint32]4)
            $writer.Write([uint16]59)
            $writer.Write([uint32]4)
            $writer.Write([uint16]59)
            $writer.Write([uint32]$row.Value)
            $writer.Write([uint16]93)
        }
    }
    finally {
        $writer.Dispose()
    }
    $Root
}

function Assert-BaselineFixtureFailure([scriptblock]$Operation, [string]$Message) {
    $actual = ''
    try {
        $null = & $Operation
    }
    catch {
        $actual = $_.Exception.GetBaseException().Message
    }
    Assert-BaselineFixture ($actual -match $Message) "Expected an importer failure matching $Message."
}

Assert-BaselineBinding
if ($Case -eq 'Contracts') {
    $script:Count++
    $scenarios = @(
        @{
            Label = 'Default'
            Paths = @('first', 'tail')
            Version = 'fixture-v'
            Action = 'Stop'
            Catch = $true
        }
        @{
            Label = 'Explicit'
            Paths = @('first', 'tail')
            Version = 'named-v'
            Action = 'Stop'
            Catch = $true
            ImportName = 'Named baseline'
        }
        @{
            Label = 'Continue'
            Paths = @('first', 'observe', 'tail')
            Version = 'fixture-v'
            Action = 'Continue'
            Catch = $false
        }
        @{
            Label = 'CaughtContinue'
            Paths = @('first', 'observe', 'tail')
            Version = 'fixture-v'
            Action = 'Continue'
            Catch = $true
        }
        @{
            Label = 'Stop'
            Paths = @('first', 'observe', 'tail')
            Version = 'fixture-v'
            Action = 'Stop'
            Catch = $true
        }
        @{
            Label = 'NoFiles'
            Paths = @('first', 'empty', 'tail')
            Version = 'fixture-v'
            Action = 'Continue'
            Catch = $true
        }
        @{
            Label = 'EmptyName'
            Paths = @('first')
            Version = 'fixture-v'
            Action = 'Stop'
            Catch = $true
            ImportName = ''
        }
        @{
            Label = 'EmptyVersion'
            Paths = @('first')
            Version = ''
            Action = 'Stop'
            Catch = $true
        }
    )
    foreach ($scenario in $scenarios) {
        $expected = Invoke-BaselineNativeObservation $scenario $true
        $actual = Invoke-BaselineNativeObservation $scenario $false
        Assert-BaselineSame $expected $actual $scenario.Label
        switch ($scenario.Label) {
            'Default' {
                Assert-BaselineFixture ($expected.Stream[0].Name -ceq 'Imported GPO baseline' -and
                    $expected.Stream[0].Version -ceq 'fixture-v') 'The default profile contract was not exercised.'
            }
            'Explicit' {
                Assert-BaselineFixture ($expected.Stream[0].Name -ceq 'Named baseline' -and
                    $expected.Stream[0].Version -ceq 'named-v') 'The explicit profile contract was not exercised.'
            }
            { $_ -in 'Continue', 'CaughtContinue' } {
                Assert-BaselineFixture (($expected.Paths -join ',') -ceq 'first,observe,tail' -and
                    $null -eq $expected.Caught -and $expected.Stream.Count -eq 2 -and
                    $expected.Stream[0].Id -like 'BaselineFixtureReader,*' -and
                    $expected.Stream[1].Registry[0].Source -ceq 'first' -and
                    $expected.ErrorVariable.Count -gt 0) 'The native Continue path did not emit its error, continue, and return a profile.'
            }
            'Stop' {
                Assert-BaselineFixture (($expected.Paths -join ',') -ceq 'first,observe' -and
                    $expected.Stream.Count -eq 0 -and
                    $expected.Caught.Id -like 'BaselineFixtureReader,*') 'Stop did not abort on the observed reader error.'
            }
            'NoFiles' {
                Assert-BaselineFixture (($expected.Paths -join ',') -ceq 'first,empty' -and
                    $expected.Stream.Count -eq 0 -and
                    $expected.Caught.Message -ceq 'No policy files in baseline: empty') 'The empty backup did not abort before the tail.'
            }
            'EmptyName' {
                Assert-BaselineFixture (($expected.Paths -join ',') -ceq 'first' -and
                    $expected.Caught.Message -ceq 'Profile Name and Version are required') 'Name was not rejected by final profile validation after reading.'
            }
            'EmptyVersion' {
                Assert-BaselineFixture ($expected.Paths.Count -eq 0 -and
                    $expected.Caught.Id -like 'ParameterArgumentValidationError*') 'The empty required Version was not rejected by command binding.'
            }
        }
        $script:Count++
    }
}
else {
    # Constructor activity should hit neither the offline reader nor the old importer command.
    function Import-ADAnalyzerBaseline {
        throw 'The direct importer delegated to its compatibility command.'
    }
    $service = & {

        function Read-ADAnalyzerGpo {
            throw 'Baseline importer construction tried to collect policy.'
        }
        [ADAnalyzerBaselineImporter]::new()
    }
    Assert-BaselineFixture ($service.GetType().Name -ceq 'ADAnalyzerBaselineImporter') 'Literal construction did not return the importer.'
    $script:Count++
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('baseline-importer-fixture-' + [guid]::NewGuid().ToString('N'))
try {
    $recordA = @{
        Key = 'Software\Fixture|Tail'
        Name = 'Setting'
        Value = 7
    }
    $recordB = @{
        Key = 'Software\Fixture'
        Name = 'Tail|Setting'
        Value = 9
    }
    $variant = @{
        Key = 'SOFTWARE\FIXTURE|TAIL'
        Name = 'setting'
        Value = 7
    }
    $first = Write-BaselineFixtureBackup (Join-Path $temporary 'one/DomainSysvol/GPO') @($recordA)
    $second = Write-BaselineFixtureBackup (Join-Path $temporary 'two/DomainSysvol/GPO') @($variant, $recordB)
    $paths = [string[]]@($first, $second)
    $arguments = @{
        GpoPath = $paths
        Version = 'real-v'
    }
    $expected = Get-BaselineFixtureRecord (Invoke-FrozenBaseline $arguments)
    Assert-BaselineFixture ($expected.Registry.Count -eq 2 -and $expected.Registry[0].Source -ceq $first -and
        $expected.Registry[1].Source -ceq $second -and $expected.Registry[0].ExpectedType -ceq 'System.UInt32' -and
        $expected.Registry[1].ExpectedType -ceq 'System.UInt32' -and
        $expected.Registry[0].Id -ne $expected.Registry[1].Id) 'Registry fixtures did not exercise typed distinct tuples and first-source deduplication.'
    $set = @($expected.Security | Where-Object Aggregate)[0]
    Assert-BaselineFixture ($expected.Security.Count -eq 2 -and $set.Source -ceq $first -and
        ($set.Expected -join ',') -ceq 'a,z,z' -and
        $set.ExpectedType -ceq 'System.Object[]') 'Security fixture did not exercise ordered grouping with a duplicate member.'
    if ($Case -eq 'Contracts') {
        Assert-BaselineSame $expected (Get-BaselineFixtureRecord (Import-ADAnalyzerBaseline @arguments)) 'Real default profile'
        $script:Count++
    }
    else {
        $profile = $service.Import($paths, 'real-v')
        Assert-BaselineSame $expected (Get-BaselineFixtureRecord $profile) 'Direct default profile'
        $script:Count++

        $arguments.Name = 'Named real profile'
        $expectedNamed = Get-BaselineFixtureRecord (Invoke-FrozenBaseline $arguments)
        Assert-BaselineSame $expectedNamed (Get-BaselineFixtureRecord ($service.Import($paths,
                    'Named real profile',
                    'real-v'))) 'Direct named profile'
        $script:Count++

        $reverse = [string[]]@($second, $first)
        $arguments.GpoPath = $reverse
        $reverseExpected = Get-BaselineFixtureRecord (Invoke-FrozenBaseline $arguments)
        Assert-BaselineSame $reverseExpected (Get-BaselineFixtureRecord ($service.Import($reverse,
                    'Named real profile',
                    'real-v'))) 'Direct reordered duplicate provenance'
        $script:Count++

        $registryConflict = Write-BaselineFixtureBackup (Join-Path $temporary 'registry-conflict') @(@{
                Key = $recordA.Key
                Name = $recordA.Name
                Value = 22
            })
        $securityConflict = Write-BaselineFixtureBackup (Join-Path $temporary 'security-conflict') @($recordA) -MinimumLength 17
        Assert-BaselineFixtureFailure { $service.Import([string[]]@($first,
                    $registryConflict),
                'real-v') } '^Conflicting baseline registry setting:'
        $script:Count++
        Assert-BaselineFixtureFailure { $service.Import([string[]]@($first,
                    $securityConflict),
                'real-v') } '^Conflicting baseline security setting:'
        $script:Count++

        Assert-BaselineFixtureFailure { $service.Import([string[]]@(), 'real-v') } '(?i)path|backup'
        $script:Count++
        Assert-BaselineFixtureFailure { $service.Import($paths, '') } '(?i)version'
        $script:Count++
        Assert-BaselineFixtureFailure { $service.Import($paths, '', 'real-v') } '^Profile Name and Version are required$'
        $script:Count++

        $profile.RegistryRules[0].Expected = 99
        $independent = [ADAnalyzerBaselineImporter]::new()
        $again = $service.Import($paths, 'real-v')
        $fromIndependent = $independent.Import($paths, 'real-v')
        Assert-BaselineSame $expected (Get-BaselineFixtureRecord $again) 'Direct reused importer after success and failure'
        Assert-BaselineSame $expected (Get-BaselineFixtureRecord $fromIndependent) 'Direct independent importer'
        Assert-BaselineFixture (-not [object]::ReferenceEquals($again.RegistryRules[0],
                $fromIndependent.RegistryRules[0])) 'Independent imports shared a mutable rule.'
        $script:Count++
    }
}
finally {
    if ([IO.Directory]::Exists($temporary)) {
        [IO.Directory]::Delete($temporary, $true)
    }
}

Write-Host "PASS baseline importer $Case $script:Count"
