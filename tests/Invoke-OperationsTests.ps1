[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
. (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
. (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
$script:Passed = 0
$script:Failed = 0
$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-operations-tests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $script:Temporary -ItemType Directory
$script:RemediationAuthorityDirectory = $null

function Get-ADAnalyzerRemediationAuthorityDirectory {
    if ([string]::IsNullOrEmpty($script:RemediationAuthorityDirectory) -or
        -not [IO.Directory]::Exists($script:RemediationAuthorityDirectory)) {
        throw 'The fixture has no disposable remediation authority.'
    }
    return $script:RemediationAuthorityDirectory
}

function Assert-Equal($Expected, $Actual) {
    if ($Expected -ne $Actual) {
        throw "Expected [$Expected], received [$Actual]"
    }
}

function Assert-True($Value, [string]$Message = 'Assertion failed') {
    if (-not $Value) {
        throw $Message
    }
}

function Assert-Throws([scriptblock]$Body) {
    $thrown = $false
    try {
        & $Body
    }
    catch {
        $thrown = $true
    }
    if (-not $thrown) {
        throw 'Expected a terminating failure'
    }
}

function Assert-ThrowsMessage([scriptblock]$Body, [string]$Message) {
    $caught = $null
    try {
        $null = & $Body
    }
    catch {
        $caught = $_.Exception.Message
    }
    Assert-Equal $Message $caught
}

function Reset-Fixture {
    $script:RemediationAuthorityDirectory = Join-Path $script:Temporary ('authority-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($script:RemediationAuthorityDirectory)
    $script:Reads = 0
    $script:GroupReads = 0
    $script:Disables = 0
    $script:DisableDispatches = 0
    $script:Enables = 0
    $script:FreshPrivileged = $false
    $script:FreshAccountType = 'User'
    $script:Unresolved = @()
    $script:FailMutation = $false
    $script:SeenCredential = $null
    $script:SeenServer = $null
    $script:SeenIdentity = $null
    $script:Current = [pscustomobject][ordered]@{
        ObjectGuid = '11111111-1111-1111-1111-111111111111'
        SID = 'S-1-5-21-10-20-30-1101'
        DistinguishedName = 'CN=Fixture User,OU=People,DC=example,DC=invalid'
        SamAccountName = 'fixture'
        ObjectClass = 'User'
        AccountType = 'User'
        Enabled = $true
        UserAccountControl = 512
        WhenChanged = [datetime]'2026-01-01T00:00:00Z'
        AdminCount = 0
        ProtectedFromAccidentalDeletion = $false
        Privileged = $false
        PrivilegeResolutionStatus = 'Complete'
        IsCriticalSystemObject = $false
        IsDomainController = $false
        MemberOf = @()
        PrimaryGroupID = 513
        SafetyMetadataStatus = 'Collected'
        SIDHistory = @()
        WhenCreated = [datetime]::UtcNow.AddDays(-365)
        lastLogonTimestamp = [datetime]::UtcNow.AddDays(-100).ToFileTimeUtc()
        lastLogon = 0
    }
    $script:Profile = Get-ADAnalyzerDefaultProfile
    $script:Profile.Remediation.AllowDisable = $true
    $script:Profile.Remediation.ApprovedObjectGuids = @($script:Current.ObjectGuid)
    $script:Assessment = [pscustomobject]@{
        SchemaVersion = 1
        RunId = 'run-fixture'
        Timestamp = '2026-01-01T00:00:00Z'
        Target = 'example.invalid'
        Objects = @($script:Current)
        Findings = @([pscustomobject]@{
                RuleId = 'ACCOUNT.INACTIVE'
                Status = 'Fail'
                Target = $script:Current.DistinguishedName
                ObjectGuid = $script:Current.ObjectGuid
                SID = $script:Current.SID
                Evidence = @{
                    DaysInactive = 90
                }
                Suppressed = $false
            })
    }
    $script:Journal = Join-Path $script:Temporary ([guid]::NewGuid().ToString('N') + '.json')
}

function Invoke-Test([string]$Name, [scriptblock]$Body) {
    Reset-Fixture
    try {
        & $Body
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name : $_"
    }
}

function Assert-AssessmentCoverageExport {
    param(
        [string]$Name,
        [object]$Assessment,
        [string[]]$ExpectedRows = @()
    )

    $expectedCoverage = if ($ExpectedRows.Count -eq 0) {
        '<tr><td colspan="2" class="muted">Coverage was not recorded.</td></tr>'
    }
    else {
        $ExpectedRows -join ''
    }
    $reference = @{}
    Set-StrictMode -Off
    foreach ($mode in 'Off', '1.0', '2.0', 'Latest') {
        if ($mode -ne 'Off') {
            Set-StrictMode -Version $mode
        }

        $caseDescription = "$Name with StrictMode $mode"
        $directory = Join-Path $script:Temporary ($Name + '-' + $mode)
        $prefix = Join-Path $directory 'assessment'
        $standalone = Join-Path $directory 'standalone.html'
        $exportParameters = @{
            Assessment = $Assessment
            Confirm = $false
            ErrorAction = 'Stop'
        }

        $paths = @(Export-ADAnalyzerAssessment @exportParameters -Path $prefix -Format All)
        $extensions = @('.json', '.html', '.csv')
        Assert-Equal $extensions.Count $paths.Count
        for ($index = 0; $index -lt $extensions.Count; $index++) {
            $extension = $extensions[$index]
            $path = $prefix + $extension
            Assert-True ($paths[$index] -ceq $path) "$caseDescription emitted an unexpected path or order"
            Assert-True ([IO.File]::Exists($path)) "$caseDescription did not write $extension"
            $bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
            if ($mode -eq 'Off') {
                $reference[$extension] = $bytes
            }
            else {
                Assert-True ($bytes -ceq $reference[$extension]) "$caseDescription changed $extension bytes"
            }
        }

        $paths = @(Export-ADAnalyzerAssessment @exportParameters -Path $standalone -Format Html)
        Assert-Equal 1 $paths.Count
        Assert-True ($paths[0] -ceq $standalone) "$caseDescription emitted an unexpected standalone HTML path"
        Assert-True ([IO.File]::Exists($standalone)) "$caseDescription did not write standalone HTML"
        $bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($standalone))
        Assert-True ($bytes -ceq $reference['.html']) "$caseDescription changed standalone HTML bytes"

        $html = [IO.File]::ReadAllText($standalone)
        $coverage = [regex]::Match($html, '(?s)<h2>Collection coverage</h2>.*?<tbody>(.*?)</tbody>')
        Assert-True $coverage.Success "$caseDescription is missing the coverage table"
        Assert-True ($coverage.Groups[1].Value -ceq $expectedCoverage) "$caseDescription rendered unexpected coverage rows"
        Assert-Equal 4 ([IO.Directory]::GetFiles($directory)).Count
    }
}

function Assert-StrictAssessmentComparison {
    param(
        [object]$Reference,
        [object]$Difference
    )

    $ordinary = $null
    $expected = $null
    Set-StrictMode -Off
    foreach ($mode in 'Off', '2.0', 'Latest') {
        if ($mode -ne 'Off') {
            Set-StrictMode -Version $mode
        }
        $captured = @()
        $errorCount = $Error.Count
        $arguments = @{
            Reference = $Reference
            Difference = $Difference
            ErrorAction = 'Stop'
            ErrorVariable = '+captured'
        }
        $results = @(Compare-ADAnalyzerAssessment @arguments)
        Assert-Equal 1 $results.Count
        Assert-Equal 0 $captured.Count
        Assert-Equal $errorCount $Error.Count

        $comparison = $results[0]
        $time = [datetimeoffset]::ParseExact(
            $comparison.Timestamp,
            'o',
            [Globalization.CultureInfo]::InvariantCulture
        )
        Assert-Equal ([timespan]::Zero) $time.Offset
        $comparison.PSObject.Properties.Remove('Timestamp')
        $actual = ConvertTo-Json -InputObject $comparison -Depth 20 -Compress
        if ($mode -eq 'Off') {
            $ordinary = $comparison
            $expected = $actual
        }
        else {
            Assert-True ($actual -ceq $expected) "StrictMode $mode changed the comparison result"
        }
    }
    return $ordinary
}

function New-IdentityMetadataFixture([string]$Marker) {
    return [ordered]@{
        Nested = [pscustomobject][ordered]@{
            Label = 'identity fixture'
            Password = $Marker
            Values = @(
                [guid]'11111111-1111-4111-8111-111111111111'
                [datetime]'2026-01-01T02:03:04Z'
                [datetimeoffset]'2026-01-01T02:03:04+02:00'
            )
        }
    }
}

function Assert-IdentityMetadataPresence($Metadata) {
    Assert-Equal 'identity fixture' $Metadata.Nested.Label
    Assert-True ($Metadata.Nested.PasswordPresent -is [bool] -and $Metadata.Nested.PasswordPresent) 'Identity metadata did not expose Boolean secret presence.'
    Assert-Equal $null $Metadata.Nested.PSObject.Properties['Password']
}

function Assert-IdentityMetadataValueTypes($Metadata, $Source) {
    $values = $Metadata.Nested.Values
    Assert-True ($values -is [array]) 'Identity metadata lost its nested array.'
    Assert-Equal 3 $values.Count
    Assert-True ($values[0] -is [guid]) 'A nested GUID changed type.'
    Assert-True ($values[1] -is [datetime]) 'A nested DateTime changed type.'
    Assert-True ($values[2] -is [datetimeoffset]) 'A nested DateTimeOffset changed type.'
    Assert-Equal $Source.Nested.Values[0] $values[0]
    Assert-Equal $Source.Nested.Values[1] $values[1]
    Assert-Equal $Source.Nested.Values[1].Kind $values[1].Kind
    Assert-Equal $Source.Nested.Values[2] $values[2]
    Assert-Equal $Source.Nested.Values[2].Offset $values[2].Offset
}

Invoke-Test 'composite structs and typed pairs project nested secrets through every export' {
    Add-Type -TypeDefinition 'namespace ADAnalyzer.SafeStructFixture { public struct Evidence { public object Payload; } }'
    $marker = 'STRUCT_FIXTURE_SECRET'
    $nested = @{
        Password = $marker
    }
    $pair = [Collections.Generic.KeyValuePair[string, object]]::new('wrapper', $nested)
    $entry = [Collections.DictionaryEntry]::new('wrapper', $nested)
    $structure = [ADAnalyzer.SafeStructFixture.Evidence]::new()
    $structure.Payload = $nested
    $direct = [Collections.Generic.KeyValuePair[string, object]]::new('Password', $marker)
    $empty = [Collections.DictionaryEntry]::new('Password', '')
    $payload = [pscustomobject]@{
        Pair = $pair
        Entry = $entry
        Structure = $structure
        Direct = $direct
        Empty = $empty
        Array = @($pair, $entry, $structure)
    }
    $before = ConvertTo-Json -InputObject $payload -Depth 100 -Compress
    $safe = ConvertTo-ADAnalyzerSafeData -InputObject $payload
    $json = ConvertTo-Json -InputObject $safe -Depth 100 -Compress
    Assert-True (-not $json.Contains($marker)) 'Composite value type retained a nested secret'
    Assert-Equal $true $safe.Pair.Value.PasswordPresent
    Assert-Equal $true $safe.Entry.Value.PasswordPresent
    Assert-Equal $true $safe.Structure.Payload.PasswordPresent
    Assert-Equal $true $safe.Direct.SecretPresent
    Assert-Equal $false $safe.Empty.SecretPresent
    Assert-Equal $null $safe.Direct.PSObject.Properties['Value']
    Assert-Equal $null $safe.Empty.PSObject.Properties['Value']
    Assert-Equal $json (ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerSafeData -InputObject $safe) -Depth 100 -Compress)
    Assert-Equal $before (ConvertTo-Json -InputObject $payload -Depth 100 -Compress)
    Assert-Equal $marker $nested.Password
    $document = [pscustomobject]@{
        SchemaVersion = 1
        Target = 'fixture'
        Evidence = $payload
        Findings = @([pscustomobject]@{
                RuleId = 'FIXTURE'
                Evidence = $payload
            })
    }
    $path = Join-Path $script:Temporary 'struct-export'
    $null = Export-ADAnalyzerAssessment $document $path -Format All -Confirm:$false
    foreach ($extension in @('.json', '.html', '.csv')) {
        Assert-True (-not [IO.File]::ReadAllText($path + $extension).Contains($marker)) ('Struct secret leaked through ' + $extension)
    }
    $date = [datetime]'2026-01-01T00:00:00Z'
    $guid = [guid]'11111111-1111-1111-1111-111111111111'
    $scalars = [pscustomobject]@{
        False = $false
        Zero = 0
        Decimal = [decimal]1.25
        Enum = [DayOfWeek]::Friday
        Span = [timespan]::FromMinutes(7)
        Date = $date
        Guid = $guid
        Big = [bigint]123
    }
    $copy = ConvertTo-ADAnalyzerSafeData -InputObject $scalars
    Assert-Equal $false $copy.False
    Assert-Equal 0 $copy.Zero
    Assert-True ($copy.Decimal -is [decimal] -and
        $copy.Enum -is [DayOfWeek] -and
        $copy.Span -is [timespan] -and
        $copy.Big -is [bigint]) 'Scalar type contracts changed'
    Assert-Equal $date.ToUniversalTime().ToString('o') $copy.Date
    Assert-Equal $guid.ToString('D') $copy.Guid
}

function Get-ADObject {
    [CmdletBinding()]param(
        $Identity,
        $Properties,
        $Server,
        $Credential

    )
    $script:Reads++
    $script:SeenIdentity = $Identity
    $script:SeenServer = $Server
    $script:SeenCredential = $Credential
    if ([string]$Identity -ne $script:Current.ObjectGuid) {
        throw 'Fixture query was not bound to the approved GUID'
    }
    return $script:Current
}

function Get-ADGroup {
    [CmdletBinding()]param(
        $Filter,
        $Properties,
        $Server,
        $Credential

    )
    $script:GroupReads++
    $script:SeenServer = $Server
    $script:SeenCredential = $Credential
    [pscustomobject]@{
        SID = 'S-1-5-21-10-20-30-512'
        Members = @()
        MemberOf = @()
        PrimaryGroupToken = 512
    }
}

function Resolve-ADAnalyzerMembership {
    param(
        $Object,
        $Groups,
        $DomainSid,
        $PrivilegedSids

    )
    [pscustomobject]@{
        IsPrivileged = $script:FreshPrivileged
        Unresolved = $script:Unresolved
        DirectSids = @()
        EffectiveSids = @()
        PrivilegedSids = @()
        Cycles = @()
    }
}

function Get-ADAnalyzerAccountType {
    param(
        $Object,
        $Profile,
        $Membership

    )
    [pscustomobject]@{
        Type = $script:FreshAccountType
        Conflicting = $false
        InvalidRules = @()
        Evidence = @()
    }
}

function Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]param(
        $Identity,
        $Server,
        $Credential

    )
    if (-not (Test-Path -LiteralPath $script:Journal)) {
        throw 'No durable journal before mutation'
    }
    $persisted = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
    if ($persisted.Entries[-1].Status -ne 'Prepared') {
        throw 'Mutation intent was not journaled'
    }
    $script:DisableDispatches++
    if ($script:FailMutation) {
        throw 'Fixture mutation failure'
    }
    $script:Disables++
    $script:Current.Enabled = $false
    $script:Current.UserAccountControl = 514
    $script:Current.WhenChanged = $script:Current.WhenChanged.AddSeconds(1)
    $script:SeenCredential = $Credential
    $script:SeenServer = $Server
}

function Enable-ADAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]param(
        $Identity,
        $Server,
        $Credential

    )
    $persisted = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
    if ($persisted.Entries[-1].Undo.Status -ne 'Prepared') {
        throw 'Undo intent was not journaled'
    }
    $script:Enables++
    $script:Current.Enabled = $true
    $script:Current.UserAccountControl = 512
    $script:Current.WhenChanged = $script:Current.WhenChanged.AddSeconds(1)
    $script:SeenCredential = $Credential
    $script:SeenServer = $Server
}

function New-FixturePlan {
    New-ADAnalyzerRemediationPlan -Assessment $script:Assessment -Profile $script:Profile
}

function New-ActionIdentityFixturePlan {
    $plan = New-FixturePlan
    $first = $plan.Actions[0]
    $first.ActionId = 'aabbcdef-1234-4556-8687-98abcdef0123'
    $second = ConvertTo-Json -InputObject $first -Depth 20 -Compress | ConvertFrom-Json
    $second.ActionId = '{BBBCCDEF-1234-4556-8687-98ABCDEF0123}'
    $second.ObjectGuid = '22222222-2222-2222-2222-222222222222'
    $second.SID = 'S-1-5-21-10-20-30-1102'
    $second.DistinguishedName = 'CN=Second,OU=People,DC=example,DC=invalid'
    $second.Preconditions.ObjectGuid = $second.ObjectGuid
    $second.Preconditions.SID = $second.SID
    $second.Preconditions.DistinguishedName = $second.DistinguishedName
    $plan.Remediation.ApprovedObjectGuids += , $second.ObjectGuid
    $plan.Actions = @($first, $second)
    return $plan
}

function Apply-FixturePlan {
    param($Plan = (New-FixturePlan))
    Invoke-ADAnalyzerRemediationPlan -Plan $Plan -Server dc.example.invalid -JournalPath $script:Journal -Confirm:$false
}

function Test-ConcurrentJournal([string]$Operation) {
    $plan = New-FixturePlan
    if ($Operation -eq 'Undo') {
        $null = Apply-FixturePlan $plan
    }
    $directory = Join-Path $script:Temporary ([guid]::NewGuid().ToString('N'))
    $null = New-Item -Path $directory -ItemType Directory
    $script:Current | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $directory 'state.json') -Encoding UTF8
    $plan | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath (Join-Path $directory 'plan.json') -Encoding UTF8
    $engine = (Get-Process -Id $PID).Path
    $fixture = Join-Path $RepositoryRoot 'tests/JournalConcurrencyFixture.ps1'
    $processes = @()

    function Wait-ConcurrentStage($Process, [string]$File) {
        $watch = [Diagnostics.Stopwatch]::StartNew()
        while (-not $Process.HasExited -and -not (Test-Path -LiteralPath $File)) {
            if ($watch.Elapsed.TotalSeconds -gt 20) {
                throw 'Concurrent fixture timed out'
            }
            Start-Sleep -Milliseconds 25
        }
    }
    try {
        foreach ($role in @('First', 'Second')) {
            $arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" -RepositoryRoot "{1}" -Coordination "{2}" -JournalPath "{3}" -Role {4} -Operation {5}' -f $fixture,
            $RepositoryRoot,
            $directory,
            $script:Journal,
            $role,
            $Operation
            $process = Start-Process `
                -FilePath $engine `
                -ArgumentList $arguments `
                -PassThru `
                -RedirectStandardOutput (Join-Path $directory ($role + '.out')) `
                -RedirectStandardError (Join-Path $directory ($role + '.err'))
            # Windows PowerShell 5.1 requires the handle cached before exit to retain ExitCode.
            $null = $process.Handle
            $processes += , $process
            Wait-ConcurrentStage $process (Join-Path $directory ($role + '-ready'))
            if ($role -eq 'First' -and $process.HasExited) {
                throw (Get-Content -LiteralPath (Join-Path $directory 'First.err') -Raw)
            }
        }
        Set-Content -LiteralPath (Join-Path $directory 'First-release') -Value release
        Assert-True ($processes[0].WaitForExit(20000)) 'First writer did not complete'
        $processes[0].WaitForExit()
        Set-Content -LiteralPath (Join-Path $directory 'Second-release') -Value release
        Assert-True ($processes[1].WaitForExit(20000)) 'Second writer did not complete'
        $processes[1].WaitForExit()
        Assert-Equal 0 $processes[0].ExitCode
        Assert-True ($processes[1].ExitCode -ne 0) 'Competing writer unexpectedly completed'
        $journal = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        $expected = if ($Operation -eq 'Undo') {
            'Undone'
        }
        else {
            'Succeeded'
        }
        Assert-Equal 1 @($journal.Entries | Where-Object Status -eq $expected).Count
        Assert-Equal 1 @(Get-Content -LiteralPath (Join-Path $directory 'mutations.txt')).Count
        Assert-True ((Get-Content `
                    -LiteralPath (Join-Path $directory 'Second.err') `
                    -Raw) -match 'journal.*lock') 'Competing writer did not fail at the journal lease'
        Assert-Equal $false (Test-Path -LiteralPath (Join-Path $directory 'Second-reads.txt'))
    }
    finally {
        foreach ($process in $processes) {
            if (-not $process.HasExited) {
                $process.Kill()
                $null = $process.WaitForExit(5000)
            }
            $process.Dispose()
        }
    }
}

try {
    Invoke-Test 'safe projection is a deep copy and preserves policy thresholds' {
        $value = [pscustomobject]@{
            Members = @('one', 'two')
            PasswordComplexity = $true
            MaximumPasswordAge = 90
            Nested = @{
                Password = 'fixture-secret'
                Credential = [pscredential]::New('fixture', (ConvertTo-SecureString 'secret' -AsPlainText -Force))
            }
        }
        $safe = ConvertTo-ADAnalyzerSafeData $value
        $safe.Members[0] = 'changed'
        Assert-Equal 'one' $value.Members[0]
        Assert-Equal $true $safe.Nested.PasswordPresent
        Assert-Equal $null $safe.Nested.PSObject.Properties['Password']
        Assert-Equal $true $safe.Nested.CredentialPresent
        Assert-Equal $true $safe.PasswordComplexity
        Assert-Equal 90 $safe.MaximumPasswordAge
    }
    Invoke-Test 'safe projection preserves empty and singleton array contracts' {
        $safe = ConvertTo-ADAnalyzerSafeData ([pscustomobject]@{
                Empty = @()
                One = @('one')
                Objects = @([pscustomobject]@{
                        Name = 'one'
                    })
            })
        Assert-True ($safe.Empty -is [array])
        Assert-Equal 0 $safe.Empty.Count
        Assert-True ($safe.One -is [array])
        Assert-Equal 1 $safe.One.Count
        Assert-True ($safe.Objects -is [array])
        Assert-Equal 1 $safe.Objects.Count
    }
    Invoke-Test 'JSON HTML and CSV exports retain only secret presence and escape HTML' {
        $script:Assessment | Add-Member NoteProperty Xml '<Properties cpassword="unique-fixture-secret"><password>nested-secret</password></Properties>'
        $script:Assessment.Target = '<script>fixture</script>'
        $script:Assessment.Findings[0].Evidence = @{
            ManagedPassword = 'another-fixture-secret'
            Xml = $script:Assessment.Xml
        }
        $prefix = Join-Path $script:Temporary 'assessment'
        $paths = @(Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path $prefix -Format All -Confirm:$false)
        Assert-Equal 3 $paths.Count
        foreach ($path in $paths) {
            $text = Get-Content -LiteralPath $path -Raw
            Assert-True ($text -notmatch 'unique-fixture-secret|nested-secret|another-fixture-secret|\[REDACTED\]')
        }
        $html = Get-Content -LiteralPath ($prefix + '.html') -Raw
        Assert-True ($html -notmatch '<script>')
        Assert-True ($html -match '&lt;script&gt;')
        Assert-True ($script:Assessment.Xml -match 'unique-fixture-secret') 'Projection mutated the source XML'
        Assert-True ($html -match '<th>Expected</th>' -and
            $html -match '<th>Observed</th>' -and
            $html -match 'Collection coverage' -and
            $html -match 'View evidence') 'Readable report structure is missing'
    }
    Invoke-Test 'strict HTML export renders absent null and empty coverage' {
        $fixtures = [ordered]@{
            'coverage-absent' = @{
                SchemaVersion = 1
            }
            'coverage-null' = @{
                SchemaVersion = 1
                Coverage = $null
            }
            'coverage-empty-dictionary' = @{
                SchemaVersion = 1
                Coverage = @{}
            }
            'coverage-empty-record' = @{
                SchemaVersion = 1
                Coverage = [pscustomobject]@{}
            }
        }
        foreach ($name in $fixtures.Keys) {
            Assert-AssessmentCoverageExport -Name $name -Assessment $fixtures[$name]
        }
    }
    Invoke-Test 'strict HTML export preserves singleton coverage labels and nested precedence' {
        $escaped = @{
            SchemaVersion = 1
            Coverage = @{
                'Policy <A> & logs' = 'Read & verified'
            }
        }
        Assert-AssessmentCoverageExport -Name 'coverage-escaped' -Assessment $escaped -ExpectedRows @(
            '<tr><td>Policy &lt;A&gt; &amp; logs</td><td>Read &amp; verified</td></tr>'
        )

        $literalCount = @{
            SchemaVersion = 1
            Coverage = [pscustomobject]@{
                Count = 0
            }
        }
        Assert-AssessmentCoverageExport -Name 'coverage-count' -Assessment $literalCount -ExpectedRows @(
            '<tr><td>Count</td><td>0</td></tr>'
        )

        $nested = @{
            SchemaVersion = 1
            Coverage = @{
                Top = 'outer'
                Other = 'outer'
            }
            Data = @{
                Directory = @{
                    Coverage = @{
                        Nested = 'inner'
                    }
                }
            }
        }
        Assert-AssessmentCoverageExport -Name 'coverage-nested' -Assessment $nested -ExpectedRows @(
            '<tr><td>Nested</td><td>inner</td></tr>'
        )
    }
    Invoke-Test 'strict HTML export retains sorted rows with multiple coverage labels' {
        $assessment = @{
            SchemaVersion = 1
            Coverage = [ordered]@{
                Zoo = 'Collected'
                Keys = 'Verified'
                Count = 0
            }
        }
        Assert-AssessmentCoverageExport -Name 'coverage-multiple' -Assessment $assessment -ExpectedRows @(
            '<tr><td>Count</td><td>0</td></tr>'
            '<tr><td>Keys</td><td>Verified</td></tr>'
            '<tr><td>Zoo</td><td>Collected</td></tr>'
        )
    }
    Invoke-Test 'evidence projector preserves empty adapted records from strict callers' {
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $empty = [pscustomobject]@{}
        $source = [pscustomobject][ordered]@{
            Empty = $empty
            Visible = 'fixture'
        }
        foreach ($mode in '2.0', 'Latest') {
            Set-StrictMode -Version $mode
            $errorCount = $Error.Count
            $flat = $projector.Project($empty)
            $nested = $projector.Project($source)

            Assert-True ($flat -is [pscustomobject]) "StrictMode $mode did not preserve the top-level record"
            Assert-True ($nested.Empty -is [pscustomobject]) "StrictMode $mode did not preserve the nested record"
            Assert-Equal '{}' (ConvertTo-Json -InputObject $flat -Compress)
            Assert-Equal '{"Empty":{},"Visible":"fixture"}' (ConvertTo-Json -InputObject $nested -Compress)
            Assert-Equal $errorCount $Error.Count
        }
    }
    Invoke-Test 'tagged secret evidence becomes a boolean without hiding policy values' {
        $value = @{
            Evidence = @{
                Name = 'cpassword'
                Value = 'tagged-secret'
            }
            PasswordHistorySize = 12
            EvidenceXml = '<x ns:cpassword=''attribute-secret'' />'
        }
        $safe = ConvertTo-ADAnalyzerSafeData $value
        Assert-Equal $true $safe.Evidence.SecretPresent
        Assert-Equal $null $safe.Evidence.PSObject.Properties['Value']
        Assert-Equal 12 $safe.PasswordHistorySize
        Assert-True ($safe.EvidenceXml -notmatch 'attribute-secret')
        $native = ConvertTo-ADAnalyzerSafeData @{
            unicodePwd = 'native-secret'
            'msLAPS-EncryptedPassword' = [byte[]]@(1, 2, 3)
            ManagedPasswordIntervalInDays = 30
            Record = @{
                Name = 'registry'
                ValueName = 'cpassword'
                Expected = 'expected-secret'
                Value = 'value-secret'
            }
        }
        Assert-Equal $true $native.unicodePwdPresent
        Assert-Equal $true $native.'msLAPS-EncryptedPasswordPresent'
        Assert-Equal 30 $native.ManagedPasswordIntervalInDays
        Assert-Equal $true $native.Record.SecretPresent
        Assert-Equal $null $native.Record.PSObject.Properties['Expected']
        Assert-Equal $null $native.Record.PSObject.Properties['Value']
    }
    Invoke-Test 'presence is boolean for empty values and independent of expected text and property order' {
        foreach ($record in @(@{
                    Name = 'cpassword'
                    Value = ''
                    Expected = 'no secret'
                }, [ordered]@{
                    Name = 'password'
                    SecretPresent = $false
                    Value = ''
                }, [ordered]@{
                    Name = 'password'
                    Value = ''
                    SecretPresent = $false
                })) {
            $safe = ConvertTo-ADAnalyzerSafeData $record
            Assert-Equal $false $safe.SecretPresent
            Assert-Equal $null $safe.PSObject.Properties['Expected']
        }
        $empty = ConvertTo-ADAnalyzerSafeData @{
            Password = ''
            Credential = [pscredential]::Empty
        }
        Assert-Equal $false $empty.PasswordPresent
        Assert-Equal $false $empty.CredentialPresent
    }
    Invoke-Test 'XML presence projection handles nested containers and is idempotent' {
        $xml = '<Credentials><Credential userName="u" password="nested-secret" /></Credentials>'
        $safe = ConvertTo-ADAnalyzerSafeData $xml
        Assert-True ($safe -match '<CredentialsPresent>true</CredentialsPresent>') $safe
        Assert-True ($safe -notmatch 'nested-secret|REDACTED') $safe
        Assert-Equal $safe (ConvertTo-ADAnalyzerSafeData $safe)
        $safe = ConvertTo-ADAnalyzerSafeData '<Item cpasswordPresent="false" cpassword="value" password="" />'
        Assert-True ($safe -match 'cpasswordPresent="true"' -and $safe -match 'passwordPresent="false"') $safe
    }
    Invoke-Test 'empty snapshots compare deterministically' {
        $comparison = Compare-ADAnalyzerAssessment @{
            SchemaVersion = 1
            Findings = @()
        } @{
            SchemaVersion = 1
            Findings = @()
        }
        Assert-Equal 0 @($comparison.Changes).Count
    }
    Invoke-Test 'concurrent apply preserves the successful journal and blocks the stale writer before AD reads' { Test-ConcurrentJournal Apply }
    Invoke-Test 'concurrent undo preserves the successful undo and blocks the stale writer before AD reads' { Test-ConcurrentJournal Undo }
    Invoke-Test 'relative export paths follow PowerShell location rather than the process directory' {
        $location = Get-Location
        $dotnet = [Environment]::CurrentDirectory
        $processDirectory = Join-Path $script:Temporary 'process-export'
        $psDirectory = Join-Path $script:Temporary 'powershell-export'
        $null = New-Item -Path $processDirectory, $psDirectory -ItemType Directory
        try {
            [Environment]::CurrentDirectory = $processDirectory
            Set-Location -LiteralPath $psDirectory
            $path = Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path 'report.json' -Confirm:$false
            Assert-Equal (Join-Path $psDirectory 'report.json') $path
            Assert-Equal $true (Test-Path -LiteralPath (Join-Path $psDirectory 'report.json'))
            Assert-Equal $false (Test-Path -LiteralPath (Join-Path $processDirectory 'report.json'))
            Assert-Throws { Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path 'Env:\ADAnalyzerTestOutput' -Confirm:$false }
        }
        finally {
            Set-Location -LiteralPath $location.Path
            [Environment]::CurrentDirectory = $dotnet
        }
    }
    Invoke-Test 'relative journal reads writes undo and ownership bind one path and preserve unrelated files' {
        $location = Get-Location
        $dotnet = [Environment]::CurrentDirectory
        $processDirectory = Join-Path $script:Temporary 'process-journal'
        $psDirectory = Join-Path $script:Temporary 'powershell-journal'
        $null = New-Item -Path $processDirectory, $psDirectory -ItemType Directory
        $other = Join-Path $processDirectory 'journal.json'
        [IO.File]::WriteAllText($other, 'unrelated journal bytes')
        try {
            [Environment]::CurrentDirectory = $processDirectory
            Set-Location -LiteralPath $psDirectory
            $script:Journal = 'journal.json'
            $plan = New-FixturePlan
            $null = Apply-FixturePlan $plan
            $null = Undo-ADAnalyzerRemediation -JournalPath 'journal.json' -Server dc.example.invalid -Confirm:$false
            Assert-Equal $true $script:Current.Enabled
            Assert-Equal 'unrelated journal bytes' ([IO.File]::ReadAllText($other))
            Assert-Equal $false (Test-Path -LiteralPath ($other + '.lock'))
            Assert-Equal Undone (Get-Content -LiteralPath (Join-Path $psDirectory 'journal.json') -Raw | ConvertFrom-Json).Entries[0].Status
            $lease = Enter-ADAnalyzerJournalLease (Join-Path $psDirectory 'journal.json')
            try {
                $before = $script:Reads
                $message = ''
                try {
                    $null = Apply-FixturePlan $plan
                }
                catch {
                    $message = $_.Exception.Message
                }
                Assert-True ($message -match 'journal.*lock') 'Relative and absolute paths did not contend for the same ownership'
                Assert-Equal $before $script:Reads
            }
            finally {
                $lease.Dispose()
            }
        }
        finally {
            Set-Location -LiteralPath $location.Path
            [Environment]::CurrentDirectory = $dotnet
        }
    }
    Invoke-Test 'journal ownership releases after a failed mutation but Uncertain blocks the same-plan retry' {
        $plan = New-FixturePlan
        $script:FailMutation = $true
        Assert-Throws { Apply-FixturePlan $plan }
        $lease = [IO.File]::Open(($script:Journal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $lease.Dispose()
        $dispatches = $script:DisableDispatches
        Assert-Equal 1 $dispatches
        $script:FailMutation = $false
        $retryFailure = $null
        try {
            $null = Apply-FixturePlan $plan
        }
        catch {
            $retryFailure = $_
        }
        Assert-True ($null -ne $retryFailure -and $retryFailure.Exception.Message -match '\bUncertain\b') 'The uncertain provider mutation did not block retry.'
        $lease = [IO.File]::Open(($script:Journal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $lease.Dispose()
        Assert-Equal $dispatches $script:DisableDispatches
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'early result selection preserves successful evidence and releases journal ownership' {
        $plan = New-FixturePlan
        $second = $plan.Actions[0] | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $second.ActionId = [guid]::NewGuid().ToString('D')
        $second.ObjectGuid = '22222222-2222-2222-2222-222222222222'
        $second.Preconditions.ObjectGuid = $second.ObjectGuid
        $plan.Actions = @($plan.Actions[0], $second)
        $plan.Remediation.ApprovedObjectGuids += , $second.ObjectGuid
        $result = Invoke-ADAnalyzerRemediationPlan `
            -Plan $plan `
            -Server dc.example.invalid `
            -JournalPath $script:Journal `
            -Confirm:$false | Select-Object `
            -First 1
        Assert-Equal Succeeded $result.Status
        Assert-Equal 1 $script:Disables
        $journal = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        Assert-Equal Succeeded $journal.Entries[0].Status
        $lease = [IO.File]::Open(($script:Journal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $lease.Dispose()
    }
    Invoke-Test 'named XML secret payloads become idempotent boolean presence without losing normal settings' {
        $fixtures = @(
            @('<Registry><Properties name="DefaultPassword" value="unit2-secret"/><Properties name="PasswordComplexity" value="0"/></Registry>',
                $true),
            @('<Setting ValueName="HKLM\Software\Fixture\DefaultPassword" Data="unit2-secret"/>', $true),
            @('<p:Setting xmlns:p="urn:fixture" p:AttributeName="PASSWORD"><p:Value>unit2-secret</p:Value></p:Setting>', $true),
            @('<Setting><Name>DefaultPassword</Name><Value>unit2-secret</Value></Setting>', $true),
            @('<Setting name="DefaultPassword"><![CDATA[unit2-secret]]></Setting>', $true),
            @('<Setting name="DefaultPassword">unit2-secret</Setting>', $true),
            @('<Setting name="DefaultPassword" value="" Expected="unit2-expected"/>', $false),
            @('<Setting><Name>DefaultPassword</Name><Value/></Setting>', $false),
            @('<Setting name="DefaultPassword" SecretPresent="true" value=""/>', $true),
            @('<Setting name="DefaultPassword" SecretPresent="false" value="unit2-secret"/>', $true)
        )
        foreach ($fixture in $fixtures) {
            $source = [xml]$fixture[0]
            $original = $source.OuterXml
            $safe = ConvertTo-ADAnalyzerSafeData $source
            Assert-True ($safe -notmatch 'unit2-secret|unit2-expected|REDACTED') $safe
            $projected = [xml]$safe
            $flag = @($projected.SelectNodes('//@*') | Where-Object LocalName -eq SecretPresent)[0]
            Assert-Equal ([string]$fixture[1]).ToLowerInvariant() $flag.Value
            Assert-Equal $safe (ConvertTo-ADAnalyzerSafeData $safe)
            Assert-Equal $original $source.OuterXml
        }
        $normal = ConvertTo-ADAnalyzerSafeData '<Settings><Setting name="PasswordComplexity" value="0"/><Setting name="ClearTextPassword" value="false"/><Setting name="ManagedPasswordIntervalInDays" value="30"/></Settings>'
        Assert-True ($normal -match 'value="0"' -and
            $normal -match 'value="false"' -and
            $normal -match 'value="30"' -and
            $normal -notmatch 'SecretPresent') $normal
        $fragment = ConvertTo-ADAnalyzerSafeData 'prefix <Properties name="DefaultPassword" value="unit2-secret"/> suffix'
        Assert-True ($fragment -notmatch 'unit2-secret|REDACTED' -and
            $fragment -match 'SecretPresent="true"' -and
            $fragment.StartsWith('prefix ') -and
            $fragment.EndsWith(' suffix')) $fragment
        Assert-Equal $fragment (ConvertTo-ADAnalyzerSafeData $fragment)
        Assert-Equal 'passwordPresent="true"' (ConvertTo-ADAnalyzerSafeData 'password="unit2-secret"')
        $mixed = ConvertTo-ADAnalyzerSafeData 'password="unit2-secret" <Other/>'
        Assert-True ($mixed -notmatch 'unit2-secret' -and $mixed -match 'passwordPresent="true"') $mixed
        Assert-Equal 'Password age > 90' (ConvertTo-ADAnalyzerSafeData 'Password age > 90')
    }
    Invoke-Test 'comparison preserves evidence sequences where order is meaningful' {
        $old = @{
            SchemaVersion = 1
            Findings = @(@{
                    RuleId = 'precedence'
                    Target = 'a'
                    Evidence = @{
                        PolicySequence = @('first', 'second')
                    }
                })
        }
        $new = @{
            SchemaVersion = 1
            Findings = @(@{
                    RuleId = 'precedence'
                    Target = 'a'
                    Evidence = @{
                        PolicySequence = @('second', 'first')
                    }
                })
        }
        Assert-Equal 1 (Compare-ADAnalyzerAssessment $old $new).Summary.Changed
    }
    Invoke-Test 'native comparison projects and detaches both in-memory run identifiers' {
        $marker = 'native-comparison-identity-fixture-value'
        $metadata = New-IdentityMetadataFixture $marker
        $assessment = @{
            SchemaVersion = 1
            RunId = $metadata
        }
        $comparison = Compare-ADAnalyzerAssessment -Reference $assessment -Difference $assessment
        $json = ConvertTo-Json -InputObject $comparison -Depth 20 -Compress
        Assert-True (-not $json.Contains($marker)) 'Raw native comparison exposed a fixture value.'
        Assert-IdentityMetadataPresence $comparison.ReferenceRunId
        Assert-IdentityMetadataPresence $comparison.DifferenceRunId
        Assert-IdentityMetadataValueTypes $comparison.ReferenceRunId $metadata
        Assert-IdentityMetadataValueTypes $comparison.DifferenceRunId $metadata
        Assert-True (-not [object]::ReferenceEquals($metadata, $comparison.ReferenceRunId)) 'Native comparison retained the caller-owned identifier.'

        $comparison.ReferenceRunId.Nested.Label = 'altered result'
        Assert-Equal 'identity fixture' $comparison.DifferenceRunId.Nested.Label
        Assert-Equal 'identity fixture' $metadata.Nested.Label
        Assert-Equal $marker $metadata.Nested.Password
        Assert-Equal 0 $comparison.Changes.Count
    }
    Invoke-Test 'direct comparison preserves typed identities nested in compound metadata' {
        $marker = 'direct-comparison-identity-fixture-value'
        $metadata = New-IdentityMetadataFixture $marker
        $identifier = [guid]'22222222-2222-4222-8222-222222222222'
        $assessment = @{
            SchemaVersion = 1
            RunId = @($identifier, $metadata)
        }
        $comparer = [ADAnalyzerAssessmentComparer]::new()
        $comparison = $comparer.Compare($assessment, $assessment)
        Assert-True ($comparison.ReferenceRunId -is [array]) 'Compound identity lost its captured array.'
        Assert-Equal 2 $comparison.ReferenceRunId.Count
        Assert-True ($comparison.ReferenceRunId[0] -is [guid]) 'A GUID beside a composite identity changed type.'
        Assert-Equal $identifier $comparison.ReferenceRunId[0]
        Assert-IdentityMetadataPresence $comparison.ReferenceRunId[1]
        Assert-IdentityMetadataValueTypes $comparison.ReferenceRunId[1] $metadata
        $json = ConvertTo-Json -InputObject $comparison -Depth 20 -Compress
        Assert-True (-not $json.Contains($marker)) 'Raw direct comparison exposed a fixture value.'

        $projector = [ADAnalyzerEvidenceProjector]::new()
        $identity = $projector.ProjectIdentityMetadata($metadata)
        Assert-IdentityMetadataPresence $identity
        Assert-IdentityMetadataValueTypes $identity $metadata
        $evidence = $projector.Project($metadata)
        Assert-IdentityMetadataPresence $evidence
        Assert-Equal $metadata.Nested.Values[0].ToString('D') $evidence.Nested.Values[0]
        Assert-Equal $metadata.Nested.Values[1].ToUniversalTime().ToString('o') $evidence.Nested.Values[1]
        Assert-Equal $metadata.Nested.Values[2].ToUniversalTime().ToString('o') $evidence.Nested.Values[2]
        foreach ($value in $evidence.Nested.Values) {
            Assert-True ($value -is [string]) 'Ordinary evidence projection changed its identifier encoding.'
        }
    }
    Invoke-Test 'literal assessment JSON produces safe comparison and plan metadata' {
        $marker = 'saved-assessment-identity-fixture-value'
        $metadata = New-IdentityMetadataFixture $marker
        $assessment = [ordered]@{
            SchemaVersion = 1
            RunId = $metadata
            Target = $metadata
        }
        $path = Join-Path $script:Temporary 'assessment [identity].json'
        $encoding = [Text.UTF8Encoding]::new($false)
        $source = ConvertTo-Json -InputObject $assessment -Depth 20 -Compress
        [IO.File]::WriteAllText($path, $source, $encoding)
        $comparison = Compare-ADAnalyzerAssessment -Reference $path -Difference $path
        $comparer = [ADAnalyzerAssessmentComparer]::new()
        $direct = $comparer.Compare($path, $path)
        $plan = New-ADAnalyzerRemediationPlan -Assessment $path
        foreach ($result in @($comparison, $direct, $plan)) {
            $json = ConvertTo-Json -InputObject $result -Depth 20 -Compress
            Assert-True (-not $json.Contains($marker)) 'A raw result from a saved assessment exposed a fixture value.'
        }
        Assert-IdentityMetadataPresence $comparison.ReferenceRunId
        Assert-IdentityMetadataPresence $comparison.DifferenceRunId
        Assert-IdentityMetadataPresence $direct.ReferenceRunId
        Assert-IdentityMetadataPresence $direct.DifferenceRunId
        Assert-IdentityMetadataPresence $plan.AssessmentRunId
        Assert-IdentityMetadataPresence $plan.Target
        Assert-Equal 0 $plan.Actions.Count
        Assert-True ([IO.File]::ReadAllText($path, $encoding) -ceq $source) 'The comparison or plan rewrote the saved assessment.'
    }
    Invoke-Test 'identity metadata retains native null singleton and multiple-value shapes' {
        $identifier = [guid]'11111111-1111-4111-8111-111111111111'
        $missing = @{
            SchemaVersion = 1
        }
        $explicitNull = @{
            SchemaVersion = 1
            RunId = $null
        }
        $empty = @{
            SchemaVersion = 1
            RunId = @()
        }
        $singleton = @{
            SchemaVersion = 1
            RunId = @($identifier)
        }
        $multiple = @{
            SchemaVersion = 1
            RunId = @($identifier, $false, 17)
        }
        $nativeNull = Compare-ADAnalyzerAssessment $missing $explicitNull
        Assert-Equal $null $nativeNull.ReferenceRunId
        Assert-Equal $null $nativeNull.DifferenceRunId
        $native = Compare-ADAnalyzerAssessment $empty $singleton
        $direct = [ADAnalyzerAssessmentComparer]::new().Compare($singleton, $multiple)
        $nativeMultiple = Compare-ADAnalyzerAssessment $missing $multiple
        Assert-Equal $null $native.ReferenceRunId
        Assert-True ($native.DifferenceRunId -is [guid] -and $direct.ReferenceRunId -is [guid]) 'A collapsed singleton lost its scalar GUID type.'
        Assert-Equal $identifier $native.DifferenceRunId
        Assert-Equal $identifier $direct.ReferenceRunId
        $plan = New-ADAnalyzerRemediationPlan -Assessment @{
            SchemaVersion = 1
            RunId = @()
            Target = @($identifier)
        }
        Assert-Equal $null $plan.AssessmentRunId
        Assert-True ($plan.Target -is [guid]) 'Offline planning changed a collapsed singleton target.'
        Assert-Equal $identifier $plan.Target
        $multiplePlan = New-ADAnalyzerRemediationPlan -Assessment $multiple
        foreach ($array in @($direct.DifferenceRunId, $nativeMultiple.DifferenceRunId, $multiplePlan.AssessmentRunId)) {
            Assert-True ($array -is [array]) 'Multiple identifier values lost array shape.'
            Assert-Equal 3 $array.Count
            Assert-True ($array[0] -is [guid] -and $array[1] -is [bool] -and $array[2] -is [int]) 'Multiple identifier values lost scalar types or order.'
            Assert-Equal $identifier $array[0]
            Assert-Equal $false $array[1]
            Assert-Equal 17 $array[2]
        }
    }
    Invoke-Test 'strict comparison preserves empty evidence records and set members' {
        $sides = [ordered]@{
            Reference = [ordered]@{
                'FIXTURE.EMPTY' = @{}
                'FIXTURE.NULL' = $null
                'FIXTURE.SET' = @{
                    Members = @(@{}, 'ordinary')
                    PolicySequence = @('first', 'second')
                    Detail = [pscustomobject]@{
                        State = 'observed'
                    }
                }
            }
            Difference = [ordered]@{
                'FIXTURE.EMPTY' = [pscustomobject]@{}
                'FIXTURE.NULL' = [pscustomobject]@{}
                'FIXTURE.SET' = [ordered]@{
                    Detail = @{
                        State = 'observed'
                    }
                    PolicySequence = @('first', 'second')
                    Members = @('ordinary', [pscustomobject]@{})
                }
            }
        }
        $snapshots = @(
            foreach ($side in $sides.Keys) {
                [ordered]@{
                    SchemaVersion = 1
                    RunId = $side
                    Checks = @(
                        foreach ($rule in $sides[$side].Keys) {
                            [ordered]@{
                                RuleId = $rule
                                Target = 'fixture'
                                Status = 'Pass'
                                Evidence = $sides[$side][$rule]
                            }
                        }
                    )
                }
            }
        )

        $comparison = Assert-StrictAssessmentComparison -Reference $snapshots[0] -Difference $snapshots[1]
        Assert-Equal 3 $comparison.Changes.Count
        Assert-Equal 2 $comparison.Summary.Unchanged
        Assert-Equal 1 $comparison.Summary.Changed
        $empty = $comparison.Changes[0]
        Assert-Equal 'FIXTURE.EMPTY' $empty.RuleId
        Assert-Equal 'Unchanged' $empty.Change
        Assert-True ($empty.Reference -is [array] -and $empty.Difference -is [array]) 'Singleton change rows lost their array shape.'
        Assert-True ($empty.Reference[0].Evidence -is [pscustomobject]) 'Empty dictionary evidence lost its record shape.'
        Assert-True ($empty.Difference[0].Evidence -is [pscustomobject]) 'Empty adapted evidence lost its record shape.'
        Assert-Equal '{}' (ConvertTo-Json -InputObject $empty.Reference[0].Evidence -Compress)
        Assert-Equal '{}' (ConvertTo-Json -InputObject $empty.Difference[0].Evidence -Compress)

        $nullChange = $comparison.Changes[1]
        Assert-Equal 'FIXTURE.NULL' $nullChange.RuleId
        Assert-Equal 'Changed' $nullChange.Change
        Assert-Equal $null $nullChange.Reference[0].Evidence
        Assert-Equal '{}' (ConvertTo-Json -InputObject $nullChange.Difference[0].Evidence -Compress)

        $set = $comparison.Changes[2]
        Assert-Equal 'FIXTURE.SET' $set.RuleId
        Assert-Equal 'Unchanged' $set.Change
        Assert-Equal '[{},"ordinary"]' (ConvertTo-Json -InputObject $set.Reference[0].Evidence.Members -Compress)
        Assert-Equal '["ordinary",{}]' (ConvertTo-Json -InputObject $set.Difference[0].Evidence.Members -Compress)
    }
    Invoke-Test 'strict comparison reads empty evidence from literal JSON snapshots' {
        $snapshot = [ordered]@{
            SchemaVersion = 1
            Checks = @(
                [ordered]@{
                    RuleId = 'FIXTURE.JSON'
                    Target = 'fixture'
                    Status = 'Pass'
                    Evidence = [pscustomobject]@{}
                }
            )
        }
        $json = ConvertTo-Json -InputObject $snapshot -Depth 8 -Compress
        $encoding = [Text.UTF8Encoding]::new($false)
        $referencePath = Join-Path $script:Temporary 'comparison [reference].json'
        $differencePath = Join-Path $script:Temporary 'comparison [difference].json'
        [IO.File]::WriteAllText($referencePath, $json, $encoding)
        [IO.File]::WriteAllText($differencePath, $json, $encoding)

        $comparison = Assert-StrictAssessmentComparison -Reference $referencePath -Difference $differencePath
        Assert-Equal 1 $comparison.Changes.Count
        Assert-Equal 1 $comparison.Summary.Unchanged
        Assert-Equal '{}' (ConvertTo-Json -InputObject $comparison.Changes[0].Reference[0].Evidence -Compress)
        Assert-Equal '{}' (ConvertTo-Json -InputObject $comparison.Changes[0].Difference[0].Evidence -Compress)
        Assert-Equal $json ([IO.File]::ReadAllText($referencePath, $encoding))
        Assert-Equal $json ([IO.File]::ReadAllText($differencePath, $encoding))
    }
    Invoke-Test 'strict comparable helper returns an empty adapted record' {
        foreach ($mode in '2.0', 'Latest') {
            Set-StrictMode -Version $mode
            $normalized = @(ConvertTo-ADAnalyzerComparableValue -Value ([pscustomobject]@{}))
            Assert-Equal 1 $normalized.Count
            Assert-True ($normalized[0] -is [pscustomobject]) 'Empty comparable evidence lost its record shape.'
            Assert-Equal '{}' (ConvertTo-Json -InputObject $normalized[0] -Compress)
        }
    }
    Invoke-Test 'export WhatIf has no filesystem effects' {
        $path = Join-Path $script:Temporary 'not-created/assessment.json'
        $null = Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path $path -WhatIf
        Assert-Equal $false (Test-Path -LiteralPath (Split-Path -Parent $path))
    }
    Invoke-Test 'comparison returns stable four-state changes and ignores timestamp/order noise' {
        $old = [pscustomobject]@{
            SchemaVersion = 1
            RunId = 'old'
            Findings = @(
                [pscustomobject]@{
                    RuleId = 'same'
                    Target = 'a'
                    Timestamp = 'old'
                    Evidence = @{
                        Members = @('one', 'two')
                        Count = 2
                    }
                },
                [pscustomobject]@{
                    RuleId = 'changed'
                    Target = 'b'
                    Evidence = @{
                        Value = 1
                    }
                },
                [pscustomobject]@{
                    RuleId = 'resolved'
                    Target = 'c'
                    Status = 'Fail'
                    Evidence = @{
                        Value = 1
                    }
                })
        }
        $new = [pscustomobject]@{
            SchemaVersion = 1
            RunId = 'new'
            Findings = @(
                [pscustomobject]@{
                    RuleId = 'same'
                    Target = 'a'
                    Timestamp = 'new'
                    Evidence = @{
                        Count = 2
                        Members = @('two', 'one')
                    }
                },
                [pscustomobject]@{
                    RuleId = 'changed'
                    Target = 'b'
                    Evidence = @{
                        Value = 2
                    }
                },
                [pscustomobject]@{
                    RuleId = 'resolved'
                    Target = 'c'
                    Status = 'Pass'
                    Evidence = @{
                        Value = 2
                    }
                },
                [pscustomobject]@{
                    RuleId = 'new'
                    Target = 'd'
                    Evidence = @{
                        Value = 1
                    }
                })
        }
        $comparison = Compare-ADAnalyzerAssessment $old $new
        Assert-Equal 1 $comparison.Summary.Unchanged
        Assert-Equal 1 $comparison.Summary.Changed
        Assert-Equal 1 $comparison.Summary.Resolved
        Assert-Equal 1 $comparison.Summary.New
    }
    Invoke-Test 'comparison reads saved snapshots and accepts legacy inactivity rule labels' {
        $legacy = @{
            Findings = @(@{
                    Finding = 'Defect - User Inactivity'
                    Target = 'a'
                    Evidence = @{
                        Days = 90
                    }
                })
        }
        $path = Join-Path $script:Temporary 'legacy.json'
        $legacy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path
        $comparison = Compare-ADAnalyzerAssessment $path $legacy
        Assert-Equal 1 $comparison.Summary.Unchanged
        Assert-Throws { Compare-ADAnalyzerAssessment @{
                SchemaVersion = 2
                Findings = @()
            } $legacy }
    }
    Invoke-Test 'standalone and shallow singleton documents compare as one snapshot' {
        $snapshot = [pscustomobject]@{
            SchemaVersion = '1.2'
            Target = 'document.fixture.invalid'
            Checks = @([pscustomobject]@{
                    RuleId = 'FIXTURE.DOCUMENT'
                    Target = 'CN=Fixture'
                    Status = 'Pass'
                    Observed = 'same fixture value'
                })
        }
        $array = [pscustomobject[]]@($snapshot)
        $read = @(Read-ADAnalyzerOperationDocument -InputObject $array)
        Assert-Equal 1 $read.Count
        Assert-True ([object]::ReferenceEquals($snapshot, $read[0])) 'The singleton array lost its original record.'

        $json = ConvertTo-Json -InputObject $snapshot -Depth 8 -Compress
        $path = Join-Path $script:Temporary 'one snapshot [literal].json'
        $encoding = [Text.UTF8Encoding]::new($false)
        $inputs = @($json, ('[' + $json + ']'))
        foreach ($text in $inputs) {
            [IO.File]::WriteAllText($path, $text, $encoding)
            $comparison = Compare-ADAnalyzerAssessment -Reference $array -Difference $path
            Assert-Equal 1 $comparison.Changes.Count
            Assert-Equal 1 $comparison.Summary.Unchanged
            Assert-Equal 0 $comparison.Summary.Changed
            Assert-Equal 0 $comparison.Summary.Resolved
            Assert-Equal 0 $comparison.Summary.New
            Assert-Equal $text ([IO.File]::ReadAllText($path, $encoding))
        }
    }
    Invoke-Test 'operation document reader rejects invalid array shapes' {
        $snapshot = [pscustomobject]@{
            SchemaVersion = 1
        }
        $singleton = , $snapshot
        $nested = , $singleton
        $matrix = [array]::CreateInstance([object], 1, 1)
        $matrix.SetValue($snapshot, 0, 0)
        $invalid = [ordered]@{
            'empty' = @()
            'multiple' = @($snapshot, $snapshot)
            'nested' = $nested
            'rectangular' = $matrix
            'singleton null' = , $null
            'singleton scalar' = @(42)
        }
        $accepted = [Collections.Generic.List[string]]::new()
        foreach ($label in $invalid.Keys) {
            try {
                $null = Read-ADAnalyzerOperationDocument -InputObject $invalid[$label]
                $accepted.Add($label)
            }
            catch {
                Assert-Equal 'Assessment must be a structured object or JSON file' $_.Exception.Message
            }
        }

        $path = Join-Path $script:Temporary 'invalid array [literal].json'
        $encoding = [Text.UTF8Encoding]::new($false)
        foreach ($text in @('[]', '[{},{}]', '[[{}]]', '[[]]', '[null]', '[42]')) {
            [IO.File]::WriteAllText($path, $text, $encoding)
            try {
                $null = Read-ADAnalyzerOperationDocument -InputObject $path
                $accepted.Add($text)
            }
            catch {
                Assert-Equal 'Assessment must be a structured object or JSON file' $_.Exception.Message
            }
        }
        Assert-True ($accepted.Count -eq 0) ('Reader accepted invalid document shapes: ' + ($accepted -join ', '))
    }
    Invoke-Test 'comparison rejects multiple records on either side before reporting drift' {
        $matching = [pscustomobject]@{
            SchemaVersion = 1
            Target = 'document.fixture.invalid'
            Checks = @([pscustomobject]@{
                    RuleId = 'FIXTURE.DOCUMENT'
                    Target = 'CN=Fixture'
                    Status = 'Pass'
                    Observed = 'same fixture value'
                })
        }
        $other = [pscustomobject]@{
            SchemaVersion = 1
            Target = $matching.Target
            Checks = @()
        }
        $documents = @($matching, $other)
        $path = Join-Path $script:Temporary 'two snapshots [literal].json'
        $text = ConvertTo-Json -InputObject $documents -Depth 8 -Compress
        [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))

        Assert-Throws { $null = Compare-ADAnalyzerAssessment -Reference $matching -Difference $path }
        Assert-Throws { $null = Compare-ADAnalyzerAssessment -Reference $path -Difference $matching }
        Assert-Throws { $null = Compare-ADAnalyzerAssessment -Reference $matching -Difference $documents }
        Assert-Throws { $null = Compare-ADAnalyzerAssessment -Reference $documents -Difference $matching }
    }
    Invoke-Test 'shallow singleton documents receive kind-specific schema validation' {
        $unsupported = [pscustomobject]@{
            SchemaVersion = 2
        }
        $path = Join-Path $script:Temporary 'unsupported singleton [literal].json'
        [IO.File]::WriteAllText($path, '[{"SchemaVersion":2}]', [Text.UTF8Encoding]::new($false))
        $inputs = [ordered]@{
            Record = $unsupported
            Array = @($unsupported)
            Json = $path
        }
        $accepted = 0
        foreach ($kind in @('Assessment', 'Plan', 'Journal')) {
            foreach ($inputCase in $inputs.Values) {
                try {
                    $null = Read-ADAnalyzerOperationDocument -InputObject $inputCase -Kind $kind
                    $accepted++
                }
                catch {
                    Assert-Equal "Unsupported $kind SchemaVersion" $_.Exception.Message
                }
            }
        }
        Assert-Equal 0 $accepted
    }
    Invoke-Test 'document reader preserves legacy records and native input diagnostics' {
        $records = @(
            [pscustomobject]@{ Label = 'absent schema' }
            [ordered]@{
                SchemaVersion = $null
                Label = 'null schema'
            }
            @{
                SchemaVersion = 1
                Label = 'versioned dictionary'
            }
        )
        foreach ($record in $records) {
            $read = @(Read-ADAnalyzerOperationDocument -InputObject $record)
            Assert-Equal 1 $read.Count
            Assert-True ([object]::ReferenceEquals($record, $read[0])) 'The reader replaced the original structured record.'
        }
        Assert-Throws { $null = Read-ADAnalyzerOperationDocument -InputObject $null }
        Assert-Throws { $null = Read-ADAnalyzerOperationDocument -InputObject 42 }
        Assert-Throws { $null = Read-ADAnalyzerOperationDocument -InputObject $script:Temporary }

        $path = Join-Path $script:Temporary 'invalid snapshot [literal].json'
        $encoding = [Text.UTF8Encoding]::new($false)
        try {
            $null = Read-ADAnalyzerOperationDocument -InputObject $path -Kind Journal
            throw 'Expected a missing file error.'
        }
        catch {
            Assert-Equal 'Journal file does not exist' $_.Exception.Message
        }
        foreach ($text in @('', ' ', 'null', '42', 'false', '"fixture"')) {
            [IO.File]::WriteAllText($path, $text, $encoding)
            Assert-Throws { $null = Read-ADAnalyzerOperationDocument -InputObject $path }
        }
        [IO.File]::WriteAllText($path, '{"Label":', $encoding)
        $parserError = $null
        try {
            $null = Read-ADAnalyzerOperationDocument -InputObject $path
        }
        catch {
            $parserError = $_
        }
        Assert-True ($null -ne $parserError -and $parserError.FullyQualifiedErrorId -like '*ConvertFromJsonCommand*') 'Malformed JSON must retain its native parser error.'
    }
    Invoke-Test 'default remediation profile never proposes a write' {
        $plan = New-ADAnalyzerRemediationPlan -Assessment $script:Assessment
        Assert-Equal 0 @($plan.Actions).Count
        Assert-Equal 'RemediationDisabled' $plan.Excluded[0].Reason
        Assert-Equal 0 $script:Reads
    }
    Invoke-Test 'offline plan projects run and assessment and exclusion target metadata' {
        function Write-ADAnalyzerOperationFile {
            throw 'Offline plan attempted a file write.'
        }
        function Enter-ADAnalyzerJournalLease {
            throw 'Offline plan attempted to acquire a journal lease.'
        }

        $marker = 'offline-plan-identity-fixture-value'
        $metadata = New-IdentityMetadataFixture $marker
        $script:Assessment.RunId = $metadata
        $script:Assessment.Target = $metadata
        $script:Assessment.Findings[0].Target = $metadata
        $plan = New-ADAnalyzerRemediationPlan -Assessment $script:Assessment
        $json = ConvertTo-Json -InputObject $plan -Depth 20 -Compress
        Assert-True (-not $json.Contains($marker)) 'Raw offline plan exposed a fixture value.'
        Assert-Equal 0 $plan.Actions.Count
        Assert-Equal 1 $plan.Excluded.Count
        Assert-Equal 'RemediationDisabled' $plan.Excluded[0].Reason
        foreach ($projected in $plan.AssessmentRunId, $plan.Target, $plan.Excluded[0].Target) {
            Assert-IdentityMetadataPresence $projected
            Assert-IdentityMetadataValueTypes $projected $metadata
            Assert-True (-not [object]::ReferenceEquals($metadata, $projected)) 'The plan retained caller-owned identity metadata.'
        }
        $plan.Target.Nested.Label = 'altered plan'
        Assert-Equal 'identity fixture' $plan.AssessmentRunId.Nested.Label
        Assert-Equal 'identity fixture' $plan.Excluded[0].Target.Nested.Label
        Assert-Equal 'identity fixture' $metadata.Nested.Label
        Assert-Equal $marker $metadata.Nested.Password

        $script:Assessment.RunId = 'approved-run'
        $script:Assessment.Target = 'example.invalid'
        $script:Assessment.Findings[0].Target = $script:Current.DistinguishedName
        $approved = New-FixturePlan
        Assert-Equal 'approved-run' $approved.AssessmentRunId
        Assert-Equal 'example.invalid' $approved.Target
        Assert-True ([guid]::Parse($approved.PlanId) -ne [guid]::Empty) 'The offline plan lost its generated ID.'
        $created = [datetimeoffset]::ParseExact($approved.CreatedAt, 'o', [Globalization.CultureInfo]::InvariantCulture)
        Assert-Equal ([timespan]::Zero) $created.Offset
        Assert-Equal 1 $approved.Actions.Count
        Assert-Equal 0 $approved.Excluded.Count
        Assert-Equal 'DisableAccount' $approved.Actions[0].Action
        Assert-Equal $script:Current.ObjectGuid $approved.Actions[0].Preconditions.ObjectGuid
        Assert-Equal 0 $script:Reads
        Assert-Equal 0 $script:GroupReads
        Assert-Equal 0 $script:Disables
        Assert-Equal 0 $script:Enables
    }
    & {
        function Write-ADAnalyzerOperationFile {
            throw 'Offline account metadata planning attempted a file write.'
        }
        function Enter-ADAnalyzerJournalLease {
            throw 'Offline account metadata planning attempted to acquire a journal lease.'
        }
        function Set-ApprovedComputerFixture {
            $script:Current.ObjectClass = 'Computer'
            $script:Current.UserAccountControl = 4096
            $script:Current.PrimaryGroupID = 515
            $script:Assessment.Findings[0].RuleId = 'COMPUTER.INACTIVE'
        }
        function Assert-AccountMetadataPlanStayedOffline {
            Assert-Equal 0 $script:Reads
            Assert-Equal 0 $script:GroupReads
            Assert-Equal 0 $script:Disables
            Assert-Equal 0 $script:Enables
            Assert-True (-not (Test-Path -LiteralPath $script:Journal)) 'Offline account metadata planning created a journal.'
        }

        Invoke-Test 'offline action projects detached presence from structured account metadata' {
            Set-ApprovedComputerFixture
            foreach ($shape in 'Dictionary', 'Adapted') {
                $marker = 'account-metadata-fixture-value-' + $shape
                $metadata = New-IdentityMetadataFixture $marker
                if ($shape -eq 'Adapted') {
                    $metadata = [pscustomobject]$metadata
                }
                $script:Current.AccountType = $metadata
                $plan = New-FixturePlan
                Assert-Equal 1 $plan.Actions.Count
                Assert-Equal 0 $plan.Excluded.Count
                $action = $plan.Actions[0]
                Assert-Equal 'Computer' $action.ObjectClass
                Assert-Equal 'COMPUTER.INACTIVE' $action.RuleId
                Assert-Equal $script:Current.ObjectGuid $action.Preconditions.ObjectGuid
                $json = ConvertTo-Json -InputObject $plan -Depth 20 -Compress
                Assert-True (-not $json.Contains($marker)) 'Raw offline action exposed a fixture value.'
                Assert-IdentityMetadataPresence $action.AccountType
                Assert-IdentityMetadataValueTypes $action.AccountType $metadata
                Assert-True (
                    -not [object]::ReferenceEquals($action.AccountType, $metadata) -and
                    -not [object]::ReferenceEquals($action.AccountType.Nested, $metadata.Nested) -and
                    -not [object]::ReferenceEquals($action.AccountType.Nested.Values, $metadata.Nested.Values)
                ) 'The offline action retained caller-owned account metadata.'
                $action.AccountType.Nested.Label = 'altered result'
                Assert-Equal 'identity fixture' $metadata.Nested.Label
                Assert-Equal $marker $metadata.Nested.Password
                Assert-True ([object]::ReferenceEquals($script:Current.AccountType, $metadata)) 'The planner replaced caller-owned account metadata.'
            }
            Assert-AccountMetadataPlanStayedOffline
        }
        Invoke-Test 'offline action projects account metadata from bracket-literal assessment JSON' {
            Set-ApprovedComputerFixture
            $marker = 'saved-account-metadata-fixture-value'
            $script:Current.AccountType = New-IdentityMetadataFixture $marker
            $path = Join-Path $script:Temporary 'assessment [account-type].json'
            $encoding = [Text.UTF8Encoding]::new($false)
            $source = ConvertTo-Json -InputObject $script:Assessment -Depth 20 -Compress
            [IO.File]::WriteAllText($path, $source, $encoding)
            $plan = New-ADAnalyzerRemediationPlan -Assessment $path -Profile $script:Profile
            Assert-Equal 1 $plan.Actions.Count
            Assert-Equal 0 $plan.Excluded.Count
            Assert-Equal 'Computer' $plan.Actions[0].ObjectClass
            $json = ConvertTo-Json -InputObject $plan -Depth 20 -Compress
            Assert-True (-not $json.Contains($marker)) 'An offline action from saved assessment JSON exposed a fixture value.'
            Assert-IdentityMetadataPresence $plan.Actions[0].AccountType
            Assert-True ([IO.File]::ReadAllText($path, $encoding) -ceq $source) 'The offline planner rewrote the saved assessment.'
            Assert-AccountMetadataPlanStayedOffline
        }
        Invoke-Test 'offline action keeps scalar null and excluded account metadata behavior' {
            $user = New-FixturePlan
            Assert-Equal 1 $user.Actions.Count
            Assert-True ($user.Actions[0].AccountType -is [string]) 'A User classification lost its string type.'
            Assert-Equal 'User' $user.Actions[0].AccountType

            Set-ApprovedComputerFixture
            $wrapped = Add-Member -InputObject 'Computer' -MemberType NoteProperty -Name cpassword -Value 'fixture-only' -PassThru
            $script:Current.AccountType = $wrapped
            $computer = New-FixturePlan
            Assert-Equal 1 $computer.Actions.Count
            Assert-True ($computer.Actions[0].AccountType -is [string]) 'A Computer classification lost its string type.'
            Assert-Equal 'Computer' $computer.Actions[0].AccountType
            Assert-True (
                $null -eq $computer.Actions[0].AccountType.PSObject.Properties['cpassword']
            ) 'The scalar classification retained its synthetic note.'
            Assert-Equal 'fixture-only' $wrapped.cpassword

            $script:Current.AccountType = $null
            $explicit = New-FixturePlan
            $script:Current.PSObject.Properties.Remove('AccountType')
            $absent = New-FixturePlan
            foreach ($plan in $explicit, $absent) {
                Assert-Equal 1 $plan.Actions.Count
                Assert-Equal 0 $plan.Excluded.Count
                Assert-True (
                    $null -ne $plan.Actions[0].PSObject.Properties['AccountType'] -and $null -eq $plan.Actions[0].AccountType
                ) 'Null or absent Computer classification changed the action shape.'
            }

            $script:UnexpectedAccountTypeReads = 0
            $script:Current | Add-Member -MemberType ScriptProperty -Name AccountType -Value {
                $script:UnexpectedAccountTypeReads++
                throw 'Excluded account metadata must never be evaluated.'
            }
            $script:Profile.Remediation.ApprovedObjectGuids = @()
            $excluded = New-FixturePlan
            Assert-Equal 0 $excluded.Actions.Count
            Assert-Equal 1 $excluded.Excluded.Count
            Assert-Equal 'ObjectNotExplicitlyApproved' $excluded.Excluded[0].Reason
            Assert-Equal $null $excluded.Excluded[0].PSObject.Properties['AccountType']
            Assert-Equal 0 $script:UnexpectedAccountTypeReads
            Assert-AccountMetadataPlanStayedOffline
        }
    }
    & {
        # Load the real membership resolver without replacing the execution fixture's mocks.
        . (Join-Path $RepositoryRoot 'bin/ADDirectoryAnalysis.ps1')
        foreach ($name in @(
                'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE', 'Import-Module', 'New-PSDrive', 'Invoke-Command',
                'Disable-ADAccount', 'Enable-ADAccount', 'Enter-ADAnalyzerJournalLease', 'Write-ADAnalyzerOperationFile'
            )) {
            Set-Item -LiteralPath ('Function:local:' + $name) -Value {
                throw 'Offline privilege policy testing encountered an external effect.'
            }
        }

        function New-PrivilegePolicyDomainFixture {
            @{
                SID = 'S-1-5-21-10-20-30'
                RootDomainSID = 'S-1-5-21-40-50-60'
            }
        }
        function Set-PrivilegePolicyDomainFixture([hashtable]$Domain) {
            $data = @{
                Directory = @{
                    Domain = $Domain
                }
            }
            $script:Assessment | Add-Member -NotePropertyName Data -NotePropertyValue $data -Force
        }
        function Assert-PrivilegePlanStrings($Plan, [string[]]$Expected) {
            Assert-Equal 1 $Plan.Actions.Count
            Assert-Equal 0 $Plan.Excluded.Count
            Assert-True ($Plan.PrivilegedSids -is [array]) 'The offline privilege policy lost its list shape.'
            Assert-Equal $Expected.Count $Plan.PrivilegedSids.Count
            for ($index = 0; $index -lt $Expected.Count; $index++) {
                Assert-True (
                    $Plan.PrivilegedSids[$index] -is [string] -and
                    $Plan.PrivilegedSids[$index] -ceq $Expected[$index]
                ) 'The privilege policy changed SID spelling, type, duplicate handling or order.'
            }
        }
        function Assert-PrivilegePolicyRejection($Assessment, [string]$Marker) {
            $output = [Collections.Generic.List[object]]::new()
            $captured = [Collections.ArrayList]::new()
            $caught = $null
            $parameters = @{
                Assessment = $Assessment
                Profile = $script:Profile
                ErrorAction = 'Stop'
                ErrorVariable = '+captured'
            }
            try {
                New-ADAnalyzerRemediationPlan @parameters | ForEach-Object {
                    $output.Add($_)
                }
            }
            catch {
                $caught = $_
            }
            Assert-True ($null -ne $caught) 'Malformed privilege policy did not fail.'
            Assert-Equal 'Assessment privilege policy contains an unsupported SID value type' $caught.Exception.Message
            Assert-Equal 0 $output.Count
            Assert-True (
                $captured.Count -gt 0 -and
                -not ($captured | Out-String).Contains($Marker) -and
                -not $caught.Exception.ToString().Contains($Marker)
            ) 'The captured privilege policy error was missing or disclosed fixture data.'
        }

        Invoke-Test 'offline privilege policy preserves string shapes templates and detached values' {
            $script:Profile.Policy.PrivilegedSids = @()
            Assert-PrivilegePlanStrings (New-FixturePlan) @()
            $domain = New-PrivilegePolicyDomainFixture
            Set-PrivilegePolicyDomainFixture $domain
            Assert-PrivilegePlanStrings (New-FixturePlan) @()
            $domain.PrivilegedSids = $null
            Assert-PrivilegePlanStrings (New-FixturePlan) @()
            $domain.PrivilegedSids = @()
            Assert-PrivilegePlanStrings (New-FixturePlan) @()
            $domain.PrivilegedSids = 's-1-5-21-10-20-30-3169'
            Assert-PrivilegePlanStrings (New-FixturePlan) @('s-1-5-21-10-20-30-3169')

            $templates = @('{DomainSid}-3167', '{RootDomainSid}-3168', 's-1-5-21-10-20-30-3169')
            $script:Profile.Policy.PrivilegedSids = $templates
            $collector = [ADAnalyzerDirectoryCollector]::new()
            $observed = $collector.ClassifyAccounts(
                @(), @(), @(), @(), $domain.SID, $domain.RootDomainSID, $script:Profile, [ordered]@{}, $false
            )
            $snapshot = $collector.CreateSnapshot(@{
                    Server = 'selected.fixture.invalid'
                    DomainSid = $domain.SID
                    RootDomainSid = $domain.RootDomainSID
                    PrivilegedSids = $observed.PrivilegedSids
                    Resultant = [Collections.Generic.List[object]]::new()
                    Errors = [Collections.Generic.List[object]]::new()
                    ConnectionMode = 'Direct'
                })
            $script:Assessment.Data.Directory = $snapshot
            $expectedTemplateItems = @(
                '{DomainSid}-3167'
                '{RootDomainSid}-3168'
                's-1-5-21-10-20-30-3169'
                'S-1-5-21-10-20-30-3167'
                'S-1-5-21-40-50-60-3168'
            )
            $withTemplates = New-FixturePlan
            Assert-True (
                (@($withTemplates.PrivilegedSids | Where-Object { $_ -like '*316[789]' }) -join ',') -ceq
                ($expectedTemplateItems -join ',') -and $withTemplates.Actions.Count -eq 1
            ) 'The offline planner changed observed template identities.'
            $script:Profile.Policy.PrivilegedSids = @()
            $observedOnly = New-FixturePlan
            Assert-PrivilegePlanStrings $observedOnly $withTemplates.PrivilegedSids

            $script:Profile.Policy.PrivilegedSids = @('{RootDomainSid}-3168')
            Set-PrivilegePolicyDomainFixture @{ SID = $domain.SID }
            $needsContext = New-FixturePlan
            Assert-Equal 0 $needsContext.Actions.Count
            Assert-Equal 'PrivilegedPolicyContextMissing' $needsContext.Excluded[0].Reason

            $script:Profile.Policy.PrivilegedSids = @()
            $note = @{
                InputObject = 's-1-5-21-10-20-30-3171'
                NotePropertyName = 'cpassword'
                NotePropertyValue = 'fixture-only'
                PassThru = $true
            }
            $wrapped = Add-Member @note
            $domain.PrivilegedSids = @($null, $wrapped, 'S-1-5-21-10-20-30-3172', 's-1-5-21-10-20-30-3171', $null)
            Set-PrivilegePolicyDomainFixture $domain
            $plan = New-FixturePlan
            Assert-PrivilegePlanStrings $plan @('s-1-5-21-10-20-30-3171', 'S-1-5-21-10-20-30-3172')
            Assert-True (
                $null -eq $plan.PrivilegedSids[0].PSObject.Properties['cpassword']
            ) 'The ordinary SID retained its synthetic source note.'
            Assert-Equal 'fixture-only' $wrapped.cpassword
            Assert-True ([object]::ReferenceEquals($domain.PrivilegedSids[1], $wrapped)) 'The planner replaced the source SID.'
        }
        Invoke-Test 'offline privilege policy rejects structured in-memory SID entries without output' {
            $script:Profile.Policy.PrivilegedSids = @()
            $domain = New-PrivilegePolicyDomainFixture
            Set-PrivilegePolicyDomainFixture $domain
            $marker = 'unsupported-privilege-sid-fixture'
            $list = [Collections.Generic.List[object]]::new()
            $list.Add($marker)
            $invalidValues = [ordered]@{
                Dictionary = @{
                    Value = 'S-1-5-21-10-20-30-3171'
                    Password = $marker
                }
                Record = [pscustomobject]@{
                    Value = 'S-1-5-21-10-20-30-3171'
                    Password = $marker
                }
                List = $list
                Credential = [pscredential]::new($marker, [Security.SecureString]::new())
            }
            foreach ($entry in $invalidValues.GetEnumerator()) {
                $items = [object[]]::new(2)
                $items[0] = 'S-1-5-21-10-20-30-3172'
                $items[1] = $entry.Value
                $domain.PrivilegedSids = $items
                Assert-PrivilegePolicyRejection $script:Assessment $marker
                Assert-True (
                    [object]::ReferenceEquals($domain.PrivilegedSids, $items) -and
                    [object]::ReferenceEquals($domain.PrivilegedSids[1], $entry.Value)
                ) 'A rejected privilege policy modified the source list or entry.'
            }
        }
        Invoke-Test 'offline privilege policy rejects malformed bracket-literal assessment JSON' {
            $script:Profile.Policy.PrivilegedSids = @()
            $domain = New-PrivilegePolicyDomainFixture
            $marker = 'saved-unsupported-privilege-sid-fixture'
            $domain.PrivilegedSids = @([ordered]@{
                    Value = 'S-1-5-21-10-20-30-3171'
                    Password = $marker
                })
            Set-PrivilegePolicyDomainFixture $domain
            $path = Join-Path $script:Temporary 'assessment [privilege-sids].json'
            $encoding = [Text.UTF8Encoding]::new($false)
            $source = ConvertTo-Json -InputObject $script:Assessment -Depth 20 -Compress
            [IO.File]::WriteAllText($path, $source, $encoding)
            Assert-PrivilegePolicyRejection $path $marker
            Assert-True ([IO.File]::ReadAllText($path, $encoding) -ceq $source) 'The planner rewrote the saved assessment.'
        }
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            Invoke-Test 'offline privilege policy normalizes native Windows SID values with identical membership' {
                $script:Profile.Policy.PrivilegedSids = @()
                $domain = New-PrivilegePolicyDomainFixture
                Set-PrivilegePolicyDomainFixture $domain
                $canonical = $domain.SID + '-3171'
                $neighborBefore = $domain.SID + '-3170'
                $neighborAfter = $domain.SID + '-3172'
                $native = [Security.Principal.SecurityIdentifier]::new($canonical)
                $wrapped = Add-Member -InputObject $native -NotePropertyName cpassword -NotePropertyValue 'fixture-only' -PassThru
                Assert-True (
                    $wrapped.PSBase.Value -ceq $canonical -and $wrapped -is [Security.Principal.SecurityIdentifier]
                ) 'The native test did not construct the expected CLR SID.'

                $domain.PrivilegedSids = @($neighborBefore, $wrapped, $canonical, $neighborAfter)
                $typed = New-FixturePlan
                $domain.PrivilegedSids = @($neighborBefore, $canonical, $neighborAfter)
                $expected = $domain.PrivilegedSids
                $ordinary = New-FixturePlan
                Assert-PrivilegePlanStrings $typed $expected
                Assert-PrivilegePlanStrings $ordinary $expected
                Assert-True (
                    $null -eq $typed.PrivilegedSids[1].PSObject.Properties['cpassword']
                ) 'The native SID retained a synthetic source note.'
                Assert-Equal 'fixture-only' $wrapped.cpassword

                $group = [pscustomobject]@{
                    SID = $canonical
                    DistinguishedName = 'CN=Fixture Privileged Group,DC=example,DC=invalid'
                    MemberOf = @()
                }
                $member = [pscustomobject]@{
                    SID = $domain.SID + '-1201'
                    MemberOf = @($group.DistinguishedName)
                }
                $arguments = @{
                    Object = $member
                    Groups = @($group)
                    DomainSid = $domain.SID
                }
                $graph = [ADAnalyzerMembershipGraph]::new(@($group))
                foreach ($membership in @(
                        Resolve-ADAnalyzerMembership @arguments -PrivilegedSids @($wrapped)
                        Resolve-ADAnalyzerMembership @arguments -PrivilegedSids $ordinary.PrivilegedSids
                        Resolve-ADAnalyzerMembership @arguments -PrivilegedSids $typed.PrivilegedSids
                        $graph.Resolve($member, $domain.SID, $typed.PrivilegedSids)
                    )) {
                    Assert-Equal 'Complete' $membership.ResolutionStatus
                    Assert-True ($membership.IsPrivileged -is [bool] -and $membership.IsPrivileged) 'The normalized SID changed the membership decision.'
                    Assert-Equal 1 $membership.PrivilegedSids.Count
                    Assert-True ($membership.PrivilegedSids[0] -ceq $canonical) 'The normalized SID changed the matched membership identity.'
                }
            }
        }
    }
    Invoke-Test 'only explicitly approved Fail inactivity findings become DisableAccount actions' {
        $plan = New-FixturePlan
        Assert-Equal 1 @($plan.Actions).Count
        Assert-Equal 'DisableAccount' $plan.Actions[0].Action
        Assert-Equal $true $plan.Actions[0].Preconditions.Enabled
        Assert-Equal $script:Current.SID $plan.Actions[0].Preconditions.SID
        $script:Assessment.Findings[0].Status = 'Unknown'
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
        $script:Assessment.Findings[0].Status = 'Fail'
        $script:Profile.Remediation.ApprovedObjectGuids = @()
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    Invoke-Test 'suppressed findings and unrelated rules cannot create actions' {
        $script:Assessment.Findings[0].Suppressed = $true
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
        $script:Assessment.Findings[0].Suppressed = $false
        $script:Assessment.Findings[0].RuleId = 'PASSWORD.AGE'
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    foreach ($case in @(
            @('ObjectClass',
                'Group'),
            @('SID',
                'S-1-5-21-10-20-30-500'),
            @('SID',
                'S-1-5-21-10-20-30-501'),
            @('SID',
                'S-1-5-21-10-20-30-502'),
            @('AdminCount', 1), @('ProtectedFromAccidentalDeletion', $true), @('Privileged', $true), @('IsCriticalSystemObject', $true),
            @('IsDomainController', $true), @('UserAccountControl', 8192), @('PrimaryGroupID', 516), @('PrimaryGroupID', 521),
            @('AccountType', 'Service'), @('AccountType', 'Unknown'), @('PrivilegeResolutionStatus', 'Unknown'), @('WhenChanged', $null),
            @('SafetyMetadataStatus',
                'Unknown'),
            @('UserAccountControl',
                $null),
            @('PrimaryGroupID',
                $null),
            @('ProtectedFromAccidentalDeletion',
                $null)
        )) {
        $field = $case[0]
        $value = $case[1]
        Invoke-Test ('planner excludes ' + $field + '=' + $value) {
            $script:Current.$field = $value
            Assert-Equal 0 @((New-FixturePlan).Actions).Count
        }
    }
    Invoke-Test 'critical exclusions survive opt-in service/privileged settings' {
        $script:Profile.Remediation.IncludeServiceAccounts = $true
        $script:Profile.Remediation.IncludePrivilegedAccounts = $true
        $script:Current.AdminCount = 1
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    Invoke-Test 'explicit object and OU exclusions are enforced' {
        $script:Profile.Remediation.ExcludedObjectGuids = @($script:Current.ObjectGuid)
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
        $script:Profile.Remediation.ExcludedObjectGuids = @()
        $script:Profile.Remediation.ExcludedOUs = @('OU=People,DC=example,DC=invalid')
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    Invoke-Test 'maximum action count is enforced without replacing explicit approvals' {
        $second = $script:Current | ConvertTo-Json | ConvertFrom-Json
        $second.ObjectGuid = '22222222-2222-2222-2222-222222222222'
        $second.SID = 'S-1-5-21-10-20-30-1102'
        $second.DistinguishedName = 'CN=Second,OU=People,DC=example,DC=invalid'
        $script:Assessment.Objects += , $second
        $script:Assessment.Findings += , [pscustomobject]@{
            RuleId = 'ACCOUNT.INACTIVE'
            Status = 'Fail'
            Target = $second.DistinguishedName
            ObjectGuid = $second.ObjectGuid
        }
        $script:Profile.Remediation.ApprovedObjectGuids += , $second.ObjectGuid
        $script:Profile.Remediation.MaximumActions = 1
        $plan = New-FixturePlan
        Assert-Equal 1 @($plan.Actions).Count
        Assert-Equal 'MaximumActionsReached' $plan.Excluded[0].Reason
    }
    Invoke-Test 'plan execution WhatIf performs no query mutation or journal write' {
        $null = Invoke-ADAnalyzerRemediationPlan -Plan (New-FixturePlan) -Server dc.example.invalid -JournalPath $script:Journal -WhatIf
        Assert-Equal 0 $script:Reads
        Assert-Equal 0 $script:GroupReads
        Assert-Equal 0 $script:Disables
        Assert-Equal $false (Test-Path -LiteralPath $script:Journal)
        Assert-Equal $false (Test-Path -LiteralPath ($script:Journal + '.lock'))
    }
    Invoke-Test 'plan validation preserves distinct action IDs and prior error priority' {
        $plan = New-ActionIdentityFixturePlan
        $original = ConvertTo-Json -InputObject $plan -Depth 20 -Compress
        $validation = @(Assert-ADAnalyzerOperationPlan $plan)
        Assert-Equal 0 $validation.Count
        Assert-True ((ConvertTo-Json -InputObject $plan -Depth 20 -Compress) -ceq $original) 'Validation rewrote a valid action ID.'

        $plan.Actions[1].ObjectGuid = $plan.Actions[0].ObjectGuid
        $plan.Actions[1].Preconditions.ObjectGuid = $plan.Actions[0].ObjectGuid
        $plan.Actions[1].ActionId = 'not-a-guid'
        Assert-ThrowsMessage { Assert-ADAnalyzerOperationPlan $plan } 'Plan includes an unsupported, unapproved, or unbound action'
        $plan.Actions[1].ActionId = $plan.Actions[0].ActionId
        Assert-ThrowsMessage { Assert-ADAnalyzerOperationPlan $plan } 'Plan contains duplicate object actions'
    }
    foreach ($spelling in 'literal', 'equivalent') {
        Invoke-Test "plan validation rejects $spelling duplicate action IDs" {
            $plan = New-ActionIdentityFixturePlan
            $plan.Actions[1].ActionId = $plan.Actions[0].ActionId
            if ($spelling -eq 'equivalent') {
                $plan.Actions[1].ActionId = ([guid]$plan.Actions[0].ActionId).ToString('B').ToUpperInvariant()
                Assert-True ($plan.Actions[1].ActionId -cne $plan.Actions[0].ActionId) 'Canonical-equivalence fixture used identical input text.'
            }
            $original = ConvertTo-Json -InputObject $plan -Depth 20 -Compress
            Assert-ThrowsMessage { Assert-ADAnalyzerOperationPlan $plan } 'Plan contains duplicate action IDs'
            Assert-True ((ConvertTo-Json -InputObject $plan -Depth 20 -Compress) -ceq $original) 'Validation rewrote a rejected action ID.'
        }
        Invoke-Test "plan WhatIf rejects $spelling duplicate action IDs before resolving the journal" {
            $pathCalls = [Collections.Generic.List[string]]::new()
            $resolvePath = ${function:Resolve-ADAnalyzerOperationFilePath}
            function Resolve-ADAnalyzerOperationFilePath {
                param([string]$Path)
                $pathCalls.Add($Path)
                & $resolvePath -Path $Path
            }
            function Enter-ADAnalyzerJournalLease {
                throw 'WhatIf attempted to acquire a journal lease.'
            }
            function Get-ADObject {
                throw 'WhatIf attempted a directory object read.'
            }
            function Get-ADGroup {
                throw 'WhatIf attempted a directory group read.'
            }
            function Disable-ADAccount {
                throw 'WhatIf attempted to disable an account.'
            }
            function Enable-ADAccount {
                throw 'WhatIf attempted to enable an account.'
            }

            $plan = New-ActionIdentityFixturePlan
            $journal = Join-Path $script:Temporary 'action-id-preview/journal.json'
            $arguments = @{
                Plan = $plan
                Server = 'dc.example.invalid'
                JournalPath = $journal
                WhatIf = $true
                ErrorAction = 'Stop'
            }
            $expectedIds = @($plan.Actions[0].ActionId, $plan.Actions[1].ActionId)
            $preview = @(Invoke-ADAnalyzerRemediationPlan @arguments)
            Assert-Equal 1 $pathCalls.Count
            Assert-Equal $journal $pathCalls[0]
            Assert-Equal 2 $preview.Count
            for ($index = 0; $index -lt $preview.Count; $index++) {
                Assert-Equal 'Skipped' $preview[$index].Status
                Assert-Equal $plan.Actions[$index].ObjectGuid $preview[$index].ObjectGuid
                Assert-True ($preview[$index].ActionId -ceq $expectedIds[$index]) 'WhatIf changed a valid action ID or order.'
                Assert-Equal $null $preview[$index].JournalPath
            }

            $pathCalls.Clear()
            $plan.Actions[1].ActionId = $plan.Actions[0].ActionId
            if ($spelling -eq 'equivalent') {
                $plan.Actions[1].ActionId = ([guid]$plan.Actions[0].ActionId).ToString('B').ToUpperInvariant()
            }
            Assert-ThrowsMessage { Invoke-ADAnalyzerRemediationPlan @arguments } 'Plan contains duplicate action IDs'
            Assert-Equal 0 $pathCalls.Count
            Assert-True (-not [IO.Directory]::Exists((Split-Path -Parent $journal))) 'WhatIf created a journal directory.'
        }
    }
    Invoke-Test 'reviewed server context cannot be silently changed at execution' {
        $script:Assessment | Add-Member NoteProperty Context ([pscustomobject]@{
                Server = 'reviewed.example.invalid'
                Domain = 'example.invalid'
            })
        $plan = New-FixturePlan
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Reads
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'execution journals intent before disabling and binds server credential GUID' {
        $credential = [pscredential]::New('fixture', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $result = Invoke-ADAnalyzerRemediationPlan `
            -Plan (New-FixturePlan) `
            -Server dc.example.invalid `
            -Credential $credential `
            -JournalPath $script:Journal `
            -Confirm:$false
        Assert-Equal 'Succeeded' $result.Status
        Assert-Equal 1 $script:Disables
        Assert-Equal 'dc.example.invalid' $script:SeenServer
        Assert-Equal $credential $script:SeenCredential
        Assert-True ($script:SeenIdentity -is [guid])
        Assert-Equal $false $script:Current.Enabled
        $journal = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        Assert-Equal $true $journal.Entries[0].Before.Enabled
        Assert-Equal $false $journal.Entries[0].After.Enabled
        Assert-True ((Get-Content -LiteralPath $script:Journal -Raw) -notmatch 'fixture-only')
    }
    Invoke-Test 'failed journal persistence prevents the mutation' {
        $plan = New-FixturePlan
        $script:Journal = $script:Temporary
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Disables
    }
    foreach ($case in @(@('SID',
                'S-1-5-21-10-20-30-9999'),
            @('DistinguishedName',
                'CN=Replaced,DC=example,DC=invalid'),
            @('Enabled',
                $false),
            @('WhenChanged',
                [datetime]'2026-01-02T00:00:00Z'))) {
        $field = $case[0]
        $value = $case[1]
        Invoke-Test ('execution rejects changed precondition ' + $field) {
            $plan = New-FixturePlan
            $script:Current.$field = $value
            Assert-Throws { Apply-FixturePlan $plan }
            Assert-Equal 0 $script:Disables
        }
    }
    Invoke-Test 'fresh membership race is detected even without a user whenChanged change' {
        $plan = New-FixturePlan
        $script:FreshPrivileged = $true
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 1 $script:GroupReads
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'unresolved fresh membership fails closed' {
        $script:Unresolved = @('CN=UnreadableGroup,DC=example,DC=invalid')
        Assert-Throws { Apply-FixturePlan }
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'missing fresh privilege resolver fails closed' {
        $isolated = [powershell]::Create()
        try {
            $source = ". '" + (Join-Path $RepositoryRoot 'bin/ADOperations.ps1').Replace("'",
                "''") + "'; Assert-ADAnalyzerOperationPrivilege -Object @{} -Action @{} -Plan @{} -Connection @{}"
            $message = ''
            try {
                $null = $isolated.AddScript($source).Invoke()
            }
            catch {
                $message = $_.Exception.ToString()
            }
            $message += ($isolated.Streams.Error | Out-String)
            Assert-True ($message -match 'privilege resolver is unavailable')
        }
        finally {
            $isolated.Dispose()
        }
    }
    Invoke-Test 'journal decoding survives closing a nested runspace that loaded the same source' {
        $journalText = '{"SchemaVersion":1,"JournalType":"ADAnalyzerRemediationJournal","JournalId":"fixture-runspace","Entries":[]}'
        [IO.File]::WriteAllText($script:Journal, $journalText, [Text.UTF8Encoding]::new($true))
        $bytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:Journal))
        $before = @(Read-ADAnalyzerOperationDocument -InputObject $script:Journal -Kind Journal)

        $isolated = [powershell]::Create()
        try {
            $source = @'
param($OperationsPath, $JournalPath)
$ErrorActionPreference = 'Stop'
. $OperationsPath
Read-ADAnalyzerOperationDocument -InputObject $JournalPath -Kind Journal
'@
            $operations = Join-Path $RepositoryRoot 'bin/ADOperations.ps1'
            $null = $isolated.AddScript($source).AddArgument($operations).AddArgument($script:Journal)
            $inside = @($isolated.Invoke())
            Assert-Equal 0 $isolated.Streams.Error.Count
        }
        finally {
            $isolated.Dispose()
        }

        $after = @(Read-ADAnalyzerOperationDocument -InputObject $script:Journal -Kind Journal)
        Assert-Equal 1 $before.Count
        Assert-Equal 1 $inside.Count
        Assert-Equal 1 $after.Count
        foreach ($journal in @($before[0], $inside[0], $after[0])) {
            Assert-Equal 1 $journal.SchemaVersion
            Assert-Equal 'ADAnalyzerRemediationJournal' $journal.JournalType
            Assert-Equal 'fixture-runspace' $journal.JournalId
            Assert-Equal 0 $journal.Entries.Count
        }
        Assert-Equal $bytes ([Convert]::ToBase64String([IO.File]::ReadAllBytes($script:Journal)))
    }
    foreach ($classification in @('Unknown', 'Service')) {
        Invoke-Test ('fresh classification change to ' + $classification + ' is blocked') {
            $plan = New-FixturePlan
            $script:FreshAccountType = $classification
            Assert-Throws { Apply-FixturePlan $plan }
            Assert-Equal 0 $script:Disables
        }
    }
    Invoke-Test 'fresh adminCount protection cannot be bypassed by stale evidence' {
        $plan = New-FixturePlan
        $script:Current.AdminCount = 1
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'unsupported deletion and duplicate object actions are rejected before reads' {
        $plan = New-FixturePlan
        $plan.Actions[0].Action = 'Delete'
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Reads
        $plan = New-FixturePlan
        $plan.Actions = @($plan.Actions[0], $plan.Actions[0])
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Reads
    }
    Invoke-Test 'failed AD mutation has failure evidence and cannot be automatically undone' {
        $script:FailMutation = $true
        Assert-Throws { Apply-FixturePlan }
        $journal = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        Assert-Equal 'Failed' $journal.Entries[0].Status
        Assert-True ($journal.Entries[0].Message -match 'Fixture mutation failure')
        $null = Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false
        Assert-Equal 0 $script:Enables
    }
    Invoke-Test 'undo only enables a successful unchanged journaled disable' {
        $null = Apply-FixturePlan
        $result = Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false
        Assert-Equal 'Undone' $result.Status
        Assert-Equal 1 $script:Enables
        Assert-Equal $true $script:Current.Enabled
        $null = Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false
        Assert-Equal 1 $script:Enables
    }
    Invoke-Test 'undo WhatIf performs no read mutation or journal update' {
        $null = Apply-FixturePlan
        $script:Reads = 0
        $before = Get-Content -LiteralPath $script:Journal -Raw
        $lease = [IO.File]::Open(($script:Journal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $null = Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -WhatIf
        }
        finally {
            $lease.Dispose()
        }
        Assert-Equal 0 $script:Reads
        Assert-Equal 0 $script:Enables
        Assert-Equal $before (Get-Content -LiteralPath $script:Journal -Raw)
    }
    & {
        function Assert-UndoReviewBinding(
            [string]$Field,
            [string]$ChangedValue,
            [string]$ExpectedMessage,
            [switch]$JournalField
        ) {
            Reset-Fixture
            $plan = New-FixturePlan
            $action = $plan.Actions[0]
            $server = 'dc.example.invalid'
            $owner = [ADAnalyzerRemediationJournal]::new()
            try {
                $owner.Open($plan, $server, $script:Journal)
                $journal = $owner.Read()
                $after = $action.Preconditions.PSObject.Copy()
                $after.Enabled = $false
                $journal.Entries = @([pscustomobject]@{
                        EntryId = '44444444-4444-4444-8444-444444444444'
                        ActionId = $action.ActionId
                        ObjectGuid = $action.ObjectGuid
                        SID = $action.SID
                        DistinguishedName = $action.DistinguishedName
                        ObjectClass = $action.ObjectClass
                        AccountType = $action.AccountType
                        Action = 'DisableAccount'
                        Before = $action.Preconditions
                        After = $after
                        Status = 'Succeeded'
                        Undo = $null
                    })
                $owner.Write($journal)
            }
            finally {
                $owner.Dispose()
            }

            $originalBytes = [IO.File]::ReadAllBytes($script:Journal)
            $edited = [IO.File]::ReadAllText($script:Journal) | ConvertFrom-Json
            $subject = $edited
            if (-not $JournalField) {
                $subject = $edited.Entries[0]
            }
            $property = $subject.PSObject.Properties[$Field]
            Assert-True ($null -ne $property -and $property.Value -cne $ChangedValue) 'The fixture did not select a changed field.'
            $property.Value = $ChangedValue
            $expectedJson = ConvertTo-Json -InputObject $edited -Depth 30 -Compress
            $encoding = [Text.UTF8Encoding]::new($false)
            $expectedBytes = $encoding.GetBytes($expectedJson)
            $expected = [Convert]::ToBase64String($expectedBytes)
            Assert-True (
                $expected -cne [Convert]::ToBase64String($originalBytes)
            ) 'The review fixture did not change its journal.'

            $script:UndoConsentLeaseCalls = 0
            $script:UndoConsentEffects = [Collections.Generic.List[string]]::new()
            $nativeLease = (Get-Command Enter-ADAnalyzerJournalLease -CommandType Function).ScriptBlock
            function Enter-ADAnalyzerJournalLease([string]$Path) {
                Assert-Equal $script:Journal $Path
                $lease = & $nativeLease -Path $Path
                try {
                    Assert-True (
                        [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) -ceq [Convert]::ToBase64String($originalBytes)
                    ) 'The journal changed before the fixture acquired its lease.'
                    [IO.File]::WriteAllBytes($Path, $expectedBytes)
                    $script:UndoConsentLeaseCalls++
                    return $lease
                }
                catch {
                    $lease.Dispose()
                    throw
                }
            }
            foreach ($name in @(
                    'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE', 'Enable-ADAccount', 'Disable-ADAccount',
                    'Get-ADAnalyzerOperationCurrentObject', 'Save-ADAnalyzerOperationJournal', 'Write-ADAnalyzerOperationFile',
                    'Write-ADAnalyzerFile', 'Import-Module', 'Invoke-Command', 'New-PSDrive'
                )) {
                Set-Item -LiteralPath ('Function:local:' + $name) -Value {
                    $script:UndoConsentEffects.Add($MyInvocation.MyCommand.Name)
                    throw 'The isolated Undo review fixture reached an external effect.'
                }
            }

            $parameters = @{
                JournalPath = $script:Journal
                Server = $server
                Confirm = $false
            }
            if ($ExpectedMessage) {
                Assert-ThrowsMessage { Undo-ADAnalyzerRemediation @parameters } $ExpectedMessage
            }
            else {
                Assert-Equal 0 @(Undo-ADAnalyzerRemediation @parameters).Count
            }
            Assert-Equal 1 $script:UndoConsentLeaseCalls
            Assert-Equal 0 $script:UndoConsentEffects.Count
            Assert-Equal 0 $script:Reads
            Assert-Equal 0 $script:GroupReads
            Assert-Equal 0 $script:Enables
            Assert-Equal 0 $script:Disables
            Assert-True (
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:Journal)) -ceq $expected
            ) 'Undo wrote beyond the fixture change.'
            $reacquired = [IO.File]::Open(
                ($script:Journal + '.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
            )
            try {
                Assert-Equal 0 $reacquired.Length
            }
            finally {
                $reacquired.Dispose()
            }
        }

        Invoke-Test 'undo approval rejects changed journal and plan identifiers under the lease' {
            foreach ($field in 'JournalId', 'PlanId') {
                $binding = @{
                    Field = $field
                    ChangedValue = '55555555-5555-4555-8555-555555555555'
                    ExpectedMessage = 'Journal identity changed after undo review'
                    JournalField = $true
                }
                Assert-UndoReviewBinding @binding
            }
        }
        Invoke-Test 'undo approval rejects changed selected entry identity and preserves ineligible skip' {
            $fields = [ordered]@{
                ActionId = '66666666-6666-4666-8666-666666666666'
                ObjectGuid = '77777777-7777-4777-8777-777777777777'
                SID = 'S-1-5-21-10-20-30-1777'
                DistinguishedName = 'CN=Changed Fixture,DC=offline,DC=invalid'
            }
            foreach ($item in $fields.GetEnumerator()) {
                Assert-UndoReviewBinding $item.Key $item.Value 'Journal entry identity changed after undo review'
            }
            Assert-UndoReviewBinding 'Status' 'Undone' ''
        }
    }
    Invoke-Test 'undo rejects concurrent state changes and new privileged membership' {
        $null = Apply-FixturePlan
        $script:Current.WhenChanged = $script:Current.WhenChanged.AddSeconds(30)
        Assert-Throws { Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false }
        Assert-Equal 0 $script:Enables
    }
    Invoke-Test 'undo rejects new privileged membership without a user timestamp change' {
        $null = Apply-FixturePlan
        $script:FreshPrivileged = $true
        Assert-Throws { Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false }
        Assert-Equal 0 $script:Enables
        $journal = Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        Assert-Equal 'Rejected' $journal.Entries[0].Undo.Status
    }
    Invoke-Test 'passing checks still report configured drift when findings are empty' {
        $a = [pscustomobject]@{
            SchemaVersion = 1
            Findings = @()
            Checks = @([pscustomobject]@{
                    RuleId = 'Fixture'
                    Target = 'one'
                    Status = 'Pass'
                    Observed = 4
                })
        }
        $b = [pscustomobject]@{
            SchemaVersion = 1
            Findings = @()
            Checks = @([pscustomobject]@{
                    RuleId = 'Fixture'
                    Target = 'one'
                    Status = 'Pass'
                    Observed = 5
                })
        }
        $comparison = Compare-ADAnalyzerAssessment -Reference $a -Difference $b
        Assert-Equal 1 @($comparison.Changes | Where-Object Change -eq Changed).Count
    }
    Invoke-Test 'check status transitions distinguish a resolved finding from unknown coverage' {
        $a = [pscustomobject]@{
            Checks = @([pscustomobject]@{
                    RuleId = 'Fixture'
                    Target = 'one'
                    Status = 'Fail'
                    Observed = 4
                })
        }
        $b = [pscustomobject]@{
            Checks = @([pscustomobject]@{
                    RuleId = 'Fixture'
                    Target = 'one'
                    Status = 'Pass'
                    Observed = 5
                })
        }
        Assert-Equal Resolved (Compare-ADAnalyzerAssessment $a $b).Changes[0].Change
        $b.Checks[0].Status = 'Unknown'
        Assert-Equal Changed (Compare-ADAnalyzerAssessment $a $b).Changes[0].Change
    }
    Invoke-Test 'named host comparisons distinguish removal, ordering and expectation changes' {
        foreach ($file in @('ADGpo', 'ADPolicyAnalysis', 'ADHostAnalysis')) {
            . (Join-Path $RepositoryRoot ('bin/' + $file + '.ps1'))
        }
        $hostRecord = [pscustomobject]@{
            ComputerName = 'fixture'
            Services = @([pscustomobject]@{
                    Name = 'Spooler'
                    State = 'Stopped'
                    StartMode = 'Disabled'
                })
            Registry = @()
        }
        $profile = Get-ADAnalyzerDefaultProfile
        $profile.Host.Services = @(@{
                Id = 'missing'
                Name = 'Spooler'
                State = 'Running'
            }, @{
                Id = 'observed'
                Name = 'Spooler'
                State = 'Stopped'
            })
        $a = @{
            Checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -eq HOST.SERVICE)
        }
        $profile.Host.Services = @($profile.Host.Services[1])
        $b = @{
            Checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -eq HOST.SERVICE)
        }
        $comparison = Compare-ADAnalyzerAssessment $a $b
        Assert-Equal 2 $comparison.Changes.Count
        Assert-Equal 0 $comparison.Summary.Resolved
        $missing = @($comparison.Changes | Where-Object { $_.Reference[0].Evidence.ProfileRuleId -eq 'missing' })[0]
        Assert-Equal Changed $missing.Change
        Assert-Equal NotObservedInDifference $missing.Reason
        Assert-Equal 0 $missing.Difference.Count
        Assert-Equal 1 $comparison.Summary.Unchanged
        $profile.Host.Services = @(@{
                Id = 'observed'
                Name = 'Spooler'
                State = 'Stopped'
            }, @{
                Id = 'missing'
                Name = 'Spooler'
                State = 'Running'
            })
        $b = @{
            Checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -eq HOST.SERVICE)
        }
        foreach ($check in $b.Checks) {
            $check.CheckId = 'volatile-' + $check.Evidence.ProfileRuleId
        }
        Assert-Equal 2 (Compare-ADAnalyzerAssessment $a $b).Summary.Unchanged
        $profile.Host.Services[0].StartMode = 'Disabled'
        $profile.Host.Services[1].State = 'Stopped'
        $b = @{
            Checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -eq HOST.SERVICE)
        }
        $comparison = Compare-ADAnalyzerAssessment $a $b
        Assert-Equal 0 $comparison.Summary.Resolved
        Assert-Equal 2 $comparison.Summary.Changed
        $relaxed = @($comparison.Changes | Where-Object { $_.Reference[0].Evidence.ProfileRuleId -ceq 'missing' })[0]
        Assert-Equal 'RulePredicateChanged' $relaxed.Reason
        $unchangedStatus = @($comparison.Changes | Where-Object { $_.Reference[0].Evidence.ProfileRuleId -ceq 'observed' })[0]
        Assert-True ($null -eq $unchangedStatus.Reason) 'An unchanged status was misclassified as a predicate transition.'
    }
    Invoke-Test 'host service comparison distinguishes changed predicates from changed observations' {
        foreach ($file in @('ADGpo', 'ADPolicyAnalysis', 'ADHostAnalysis')) {
            . (Join-Path $RepositoryRoot ('bin/' + $file + '.ps1'))
        }
        $computer = 'service-comparison.fixture.invalid'
        $makeSnapshot = {
            param([string]$State, [string]$Mode, [hashtable]$Expected, [string]$Status)

            $profile = Get-ADAnalyzerDefaultProfile
            $profile.Host.Services = @(@{
                    Id = 'spooler-control'
                    Name = 'Spooler'
                } + $Expected)
            $hostRecord = [pscustomobject]@{
                ComputerName = $computer
                Services = @([pscustomobject]@{
                        Name = 'Spooler'
                        State = $State
                        StartMode = $Mode
                    })
                Registry = @()
            }
            $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -CEQ 'HOST.SERVICE')
            Assert-Equal 1 $checks.Count
            Assert-Equal $Status $checks[0].Status
            @{
                Checks = $checks
            }
        }

        $running = @{
            State = 'Running'
            StartMode = 'Disabled'
        }
        $stopped = @{
            State = 'Stopped'
            StartMode = 'Disabled'
        }
        $automatic = @{
            State = 'Stopped'
            StartMode = 'Auto'
        }
        $noStartMode = @{ State = 'Stopped' }
        $caseFoldedRunning = @{
            State = 'RUNNING'
            StartMode = 'DISABLED'
        }
        $runningAndAutoStart = @{
            State = 'Running'
            StartMode = 'Auto'
        }
        $snapshots = [ordered]@{
            RequireRunning = & $makeSnapshot 'Stopped' 'Disabled' $running 'Fail'
            AcceptStopped = & $makeSnapshot 'Stopped' 'Disabled' $stopped 'Pass'
            RequireAuto = & $makeSnapshot 'Stopped' 'Disabled' $automatic 'Fail'
            NoStartMode = & $makeSnapshot 'Stopped' 'Disabled' $noStartMode 'Pass'
            ActuallyRunning = & $makeSnapshot 'Running' 'Disabled' $running 'Pass'
            CaseFolded = & $makeSnapshot 'Running' 'Disabled' $caseFoldedRunning 'Pass'
            BothChanged = & $makeSnapshot 'Running' 'Auto' $runningAndAutoStart 'Pass'
            ActuallyAuto = & $makeSnapshot 'Stopped' 'Auto' $automatic 'Pass'
            ModeAndRequirementChanged = & $makeSnapshot 'Stopped' 'Auto' $noStartMode 'Pass'
            Legacy = & $makeSnapshot 'Stopped' 'Disabled' $stopped 'Pass'
            Contradictory = & $makeSnapshot 'Stopped' 'Disabled' $stopped 'Pass'
            Ambiguous = & $makeSnapshot 'Stopped' 'Disabled' $stopped 'Pass'
        }
        $snapshots.Legacy.Checks[0].PSObject.Properties.Remove('Expected')
        $snapshots.Contradictory.Checks[0].Expected.State = 'Paused'
        $single = $snapshots.Ambiguous.Checks[0].Observed[0]
        $snapshots.Ambiguous.Checks[0].Observed = @($single, $single)

        $paths = @{}
        $hashes = @{}
        $exporter = [ADAnalyzerAssessmentReport]::new()
        foreach ($name in $snapshots.Keys) {
            Assert-Equal $snapshots.RequireRunning.Checks[0].CheckId $snapshots[$name].Checks[0].CheckId
            $paths[$name] = Join-Path $script:Temporary ('host-service-predicate-' + $name + '.json')
            $null = $exporter.Write($snapshots[$name], $paths[$name], 'Json')
            $hashes[$name] = (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }

        $comparer = [ADAnalyzerAssessmentComparer]::new()
        $differences = [Collections.Generic.List[string]]::new()
        foreach ($representation in 'Object', 'Json') {
            $documents = if ($representation -ceq 'Object') {
                $snapshots
            }
            else {
                $paths
            }
            foreach ($case in @(
                    @('RequireRunning', 'AcceptStopped', 'Changed', 'RulePredicateChanged'),
                    @('AcceptStopped', 'RequireRunning', 'Changed', 'RulePredicateChanged'),
                    @('RequireAuto', 'NoStartMode', 'Changed', 'RulePredicateChanged'),
                    @('NoStartMode', 'RequireAuto', 'Changed', 'RulePredicateChanged'),
                    @('RequireAuto', 'AcceptStopped', 'Changed', 'RulePredicateChanged'),
                    @('RequireRunning', 'ActuallyRunning', 'Resolved', $null),
                    @('ActuallyRunning', 'RequireRunning', 'New', $null),
                    @('RequireRunning', 'CaseFolded', 'Resolved', $null),
                    @('RequireRunning', 'BothChanged', 'Resolved', $null),
                    @('RequireAuto', 'ActuallyAuto', 'Resolved', $null),
                    @('RequireAuto', 'ModeAndRequirementChanged', 'Resolved', $null),
                    @('RequireRunning', 'Legacy', 'Resolved', $null),
                    @('RequireRunning', 'Contradictory', 'Resolved', $null),
                    @('RequireRunning', 'Ambiguous', 'Resolved', $null)
                )) {
                $before, $after, $change, $reason = $case
                $reference = $documents[$before]
                $difference = $documents[$after]
                $results = [ordered]@{
                    Native = Compare-ADAnalyzerAssessment -Reference $reference -Difference $difference
                    Direct = $comparer.Compare($reference, $difference)
                }
                foreach ($api in $results.Keys) {
                    Assert-Equal 1 $results[$api].Changes.Count
                    $row = $results[$api].Changes[0]
                    Assert-True (
                        $row.RuleId -ceq 'HOST.SERVICE' -and $row.Target -ceq ($computer + '/Service/Spooler') -and
                        $row.Reference.Count -eq 1 -and $row.Difference.Count -eq 1 -and
                        $row.Reference[0].Status -ceq $snapshots[$before].Checks[0].Status -and
                        $row.Difference[0].Status -ceq $snapshots[$after].Checks[0].Status
                    ) 'Service identity, recorded outcomes or evidence cardinality changed.'
                    if ($row.Change -cne $change -or $row.Reason -cne $reason) {
                        $label = "$representation/$api/$before-$after"
                        $differences.Add("$label expected $change/$reason, received $($row.Change)/$($row.Reason)")
                    }
                }
            }
        }
        foreach ($name in $paths.Keys) {
            Assert-Equal $hashes[$name] (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }
        Assert-True ($differences.Count -eq 0) ($differences -join [Environment]::NewLine)
    }
    Invoke-Test 'named host registry comparison preserves literal key and value identity' {
        foreach ($file in @('ADGpo', 'ADPolicyAnalysis', 'ADHostAnalysis')) {
            . (Join-Path $RepositoryRoot ('bin/' + $file + '.ps1'))
        }
        $profile = Get-ADAnalyzerDefaultProfile
        $profile.Host.RegistryRules = @(@{
                Id = 'shared'
                Key = 'SYSTEM\Fixture'
                ValueName = 'part/Enabled'
                Expected = 1
            }, @{
                Id = 'shared'
                Key = 'SYSTEM\Fixture/part'
                ValueName = 'Enabled'
                Expected = 0
            })
        $hostRecord = [pscustomobject]@{
            ComputerName = 'fixture'
            Services = @()
            Registry = @([pscustomobject]@{
                    Path = 'SYSTEM\Fixture'
                    Name = 'part/Enabled'
                    Status = 'Observed'
                    Value = 0
                }, [pscustomobject]@{
                    Path = 'SYSTEM\Fixture/part'
                    Name = 'Enabled'
                    Status = 'Observed'
                    Value = 0
                })
        }
        $a = @{
            Checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -eq HOST.REGISTRY)
        }
        $profile.Host.RegistryRules = @($profile.Host.RegistryRules[1])
        $b = @{
            Checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile | Where-Object RuleId -eq HOST.REGISTRY)
        }
        $comparison = Compare-ADAnalyzerAssessment $a $b
        Assert-Equal 2 $comparison.Changes.Count
        Assert-Equal 0 $comparison.Summary.Resolved
        Assert-Equal 1 $comparison.Summary.Unchanged
        Assert-Equal 1 $comparison.Summary.Changed
        Assert-Equal NotObservedInDifference ($comparison.Changes | Where-Object Change -eq Changed).Reason
    }
    Invoke-Test 'malformed named host snapshot identities are rejected instead of merged' {
        foreach ($id in @('', ' ', 1, ('bad' + [char]0 + 'id'))) {
            $snapshot = @{
                Checks = @(@{
                        RuleId = 'HOST.SERVICE'
                        Target = 'fixture/Service/Spooler'
                        Status = 'Fail'
                        Evidence = @{
                            ProfileRuleId = $id
                        }
                    })
            }
            Assert-Throws { Compare-ADAnalyzerAssessment $snapshot $snapshot }
        }
        $snapshot = @{
            Checks = @(@{
                    RuleId = 'HOST.REGISTRY'
                    Target = 'fixture/Registry/Key/Name'
                    Status = 'Fail'
                    Evidence = @{
                        ProfileRuleId = 'named'
                    }
                })
        }
        Assert-Throws { Compare-ADAnalyzerAssessment $snapshot $snapshot }
    }
    Invoke-Test 'missing observations never establish resolution regardless of state or prior status' {
        foreach ($state in @('Partial', 'Complete')) {
            foreach ($status in @('Fail', 'Invalid', 'Pass', 'Unknown', $null)) {
                $a = @{
                    SchemaVersion = 1
                    Target = 'example.invalid'
                    Checks = @(@{
                            RuleId = 'GPO.Fixture'
                            Target = 'one'
                            Status = $status
                        })
                }
                $b = @{
                    SchemaVersion = 1
                    Target = 'example.invalid'
                    State = $state
                    Checks = @()
                    Configuration = @{
                        Analysis = @{
                            IncludeGpo = $false
                        }
                    }
                }
                $comparison = Compare-ADAnalyzerAssessment $a $b
                Assert-Equal Changed $comparison.Changes[0].Change
                Assert-Equal NotObservedInDifference $comparison.Changes[0].Reason
                Assert-Equal 0 $comparison.Summary.Resolved
                Assert-True ($comparison.Changes[0].Difference -is [array])
                Assert-Equal 0 $comparison.Changes[0].Difference.Count
            }
        }
        $new = Compare-ADAnalyzerAssessment @{
            Checks = @()
        } @{
            Checks = @(@{
                    RuleId = 'new'
                    Target = 'one'
                    Status = 'Fail'
                })
        }
        Assert-True ($new.Changes[0].Reference -is [array])
        Assert-Equal 0 $new.Changes[0].Reference.Count
    }
    Invoke-Test 'observed resolution survives unrelated partial coverage but unknown evidence does not resolve' {
        foreach ($oldStatus in @('Fail', 'Invalid')) {
            foreach ($newStatus in @('Pass', 'NotApplicable', 'Unknown', 'Unreadable', 'NotConfigured')) {
                $a = @{
                    Checks = @(@{
                            RuleId = 'Fixture'
                            Target = 'one'
                            Status = $oldStatus
                        })
                }
                $b = @{
                    State = 'Partial'
                    Checks = @(@{
                            RuleId = 'Fixture'
                            Target = 'one'
                            Status = $newStatus
                        })
                }
                $change = (Compare-ADAnalyzerAssessment $a $b).Changes[0]
                $expected = if ($newStatus -in 'Pass', 'NotApplicable') {
                    'Resolved'
                }
                else {
                    'Changed'
                }
                Assert-Equal $expected $change.Change
                Assert-Equal $null $change.Reason
            }
        }
    }
    Invoke-Test 'different targets or collection scopes cannot imply resolved findings' {
        $a = [pscustomobject]@{
            Target = 'a.invalid'
            Checks = @()
            Context = [pscustomobject]@{
                SearchBase = 'OU=People'
            }
        }
        $b = [pscustomobject]@{
            Target = 'b.invalid'
            Checks = @()
            Context = [pscustomobject]@{
                SearchBase = 'OU=People'
            }
        }
        Assert-Throws { Compare-ADAnalyzerAssessment $a $b }
        $b.Target = 'a.invalid'
        $b.Context.SearchBase = 'OU=Other'
        Assert-Throws { Compare-ADAnalyzerAssessment $a $b }
    }
    Invoke-Test 'SIDHistory requires manual review even when a GUID was approved' {
        $script:Current.SIDHistory = @('S-1-5-21-10-20-30-512')
        $plan = New-FixturePlan
        Assert-Equal 0 $plan.Actions.Count
        Assert-Equal SidHistoryRequiresReview $plan.Excluded[0].Reason
    }
    Invoke-Test 'fresh SIDHistory cannot bypass the approved snapshot' {
        $plan = New-FixturePlan
        $script:Current.SIDHistory = @('S-1-5-21-10-20-30-512')
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'fresh local activity blocks disable even without a whenChanged update' {
        $plan = New-FixturePlan
        $script:Current.lastLogon = [datetime]::UtcNow.AddMinutes(-1).ToFileTimeUtc()
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'missing fresh activity and creation evidence blocks disable' {
        $plan = New-FixturePlan
        $script:Current.lastLogon = 0
        $script:Current.lastLogonTimestamp = 0
        $script:Current.WhenCreated = $null
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'reviewed DC binding rejects a different server before querying' {
        $script:Assessment | Add-Member NoteProperty Context ([pscustomobject]@{
                Server = 'reviewed.example.invalid'
                Domain = 'example.invalid'
            })
        $plan = New-FixturePlan
        Assert-Throws { Apply-FixturePlan $plan }
        Assert-Equal 0 $script:Reads
    }

    foreach ($case in @(
            'Document',
            'Element',
            'Text',
            'Malformed',
            'SafeData',
            'Export',
            'WhatIf',
            'Controls',
            'NoExpansion'
        )) {
        Invoke-Test ('DTD presence boundary: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $output = & $executable -NoLogo -NoProfile -NonInteractive -File (
                Join-Path $PSScriptRoot 'DtdProjectionFixture.ps1'
            ) -Case $case 2>&1
            if ($LASTEXITCODE -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw ($output -join [Environment]::NewLine)
            }
            Assert-True (($output -join ' ') -like ('*PASS DTD projection ' + $case + '*')) 'Fresh process did not execute the selected case.'
        }
    }

    foreach ($case in @(
            'Owner',
            'Unsupported',
            'Parity',
            'Defaults',
            'Namespace',
            'RootSecret',
            'Document',
            'Isolation',
            'DocumentDefaults',
            'SchemaIsolation'
        )) {
        Invoke-Test ('XML node boundary: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $output = & $executable -NoLogo -NoProfile -NonInteractive -File (
                Join-Path $PSScriptRoot 'XmlNodeBoundaryFixture.ps1'
            ) -Case $case 2>&1
            if ($LASTEXITCODE -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw ($output -join [Environment]::NewLine)
            }
            Assert-True (($output -join ' ') -like ('*PASS XML node boundary ' + $case + '*')) 'Fresh process did not execute selected case.'
        }
    }
    $nativeCases = [ordered]@{
        Parity = 18
        LocalName = 4
        Attributes = 6
        Traversal = 12
        Payload = 10
        Presence = 10
        DataMembers = 2
        Serialization = 8
        SafeData = 8
        Export = 8
        Policy = 9
        Admx = 1
        Provided = 2
        Reader = 2
        Standalone = 1
    }
    foreach ($case in $nativeCases.Keys) {
        Invoke-Test ('XML native properties: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $output = & $executable -NoLogo -NoProfile -NonInteractive -File (
                Join-Path $PSScriptRoot 'XmlNativePropertyFixture.ps1'
            ) -Case $case 2>&1
            if ($LASTEXITCODE -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh native-property fixture failed.'
            }
            $marker = 'PASS XML native properties ' + $case + ' ' + $nativeCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute every selected scenario.'
        }
    }
    $consumerCases = [ordered]@{
        Parity = 24
        Strings = 12
        UnsupportedSafe = 11
        UnsupportedExport = 11
        ContextSafe = 5
        ContextExport = 5
        DirectDefaults = 4
        NamedDefaults = 4
        DefaultExport = 8
        Collisions = 8
        DtdConsumer = 4
    }
    foreach ($case in $consumerCases.Keys) {
        Invoke-Test ('XML consumer projection: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'XmlConsumerProjectionFixture.ps1')
                '-Case'
                $case
            )
            $output = & $executable @arguments 2>&1
            if ($LASTEXITCODE -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh XML consumer fixture failed.'
            }
            $marker = 'PASS XML consumer projection ' + $case + ' ' + $consumerCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute every selected consumer scenario.'
        }
    }

    $dictionaryCases = [ordered]@{
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
    foreach ($case in $dictionaryCases.Keys) {
        Invoke-Test ('Dictionary interface: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'GenericDictionaryFixture.ps1')
                '-Case'
                $case
            )
            $output = & $executable @arguments 2>&1
            if ($LASTEXITCODE -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh dictionary interface fixture failed.'
            }
            $marker = 'PASS dictionary interface ' + $case + ' ' + $dictionaryCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute all required dictionary scenarios.'
        }
    }

    $nativeValueCases = [ordered]@{
        Ordinary = 20
        Shadows = 15
        Records = 15
        SafeData = 15
        Export = 15
        Disposed = 4
        GetterIsolation = 4
        ExplicitCollection = 4
    }
    foreach ($case in $nativeValueCases.Keys) {
        Invoke-Test ('Native secret presence: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'SecretNativeValueFixture.ps1')
                '-Case'
                $case
            )
            $output = & $executable @arguments 2>&1
            if ($LASTEXITCODE -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh native secret presence fixture failed.'
            }
            $marker = 'PASS native secret presence ' + $case + ' ' + $nativeValueCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute every native presence scenario.'
        }
    }

    $secretIndicatorCases = [ordered]@{
        Construction = 6
        Parity = 110
        Presence = 44
        Baselines = 28
        Records = 21
        XmlNames = 23
        Xml = 31
        Text = 51
        Metadata = 16
        Errors = 21
        Ownership = 10
        Isolation = 7
        Serialization = 8
        Loading = 9
    }
    foreach ($case in $secretIndicatorCases.Keys) {
        Invoke-Test ('Secret indicator object API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'SecretIndicatorFixture.ps1')
                '-Case'
                $case
            )
            $fixtureErrorPreference = $ErrorActionPreference
            try {
                # Collect complete native stderr on 5.1 before enforcing the
                # same child exit-code and discovery gates below.
                $ErrorActionPreference = 'Continue'
                $output = & $executable @arguments 2>&1
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $fixtureErrorPreference
            }
            if ($fixtureExitCode -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh secret indicator fixture failed.'
            }
            foreach ($line in @($output | Where-Object {
                        [string]$_ -like 'INFO secret indicator*'
                    })) {
                Write-Host ([string]$line)
            }
            $marker = 'PASS secret indicator ' + $case + ' ' + $secretIndicatorCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute all required secret indicator scenarios.'
        }
    }

    $presenceMergeCases = [ordered]@{
        Order = 32
        Aliases = 82
        Types = 44
        Tagged = 22
        Nested = 6
        Getters = 10
        Controls = 12
        Exports = 32
    }
    foreach ($case in $presenceMergeCases.Keys) {
        Invoke-Test ('Secret presence merge: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'SecretPresenceMergeFixture.ps1')
                '-Case'
                $case
            )
            $fixtureErrorPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = & $executable @arguments 2>&1
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $fixtureErrorPreference
            }
            if ($fixtureExitCode -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh secret presence merge fixture failed.'
            }
            $marker = 'PASS secret presence merge ' + $case + ' ' + $presenceMergeCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute every required presence-merge scenario.'
        }
    }

    $evidenceProjectorCases = [ordered]@{
        Characterization = 122
        Metadata = 2
        References = 16
        Errors = 32
        Capabilities = 4
        Construction = 4
        Direct = 116
        Binding = 10
        Ownership = 123
        Isolation = 4
        Serialization = 7
        Loading = 5
        Uncaught = 24
    }
    foreach ($case in $evidenceProjectorCases.Keys) {
        Invoke-Test ('Evidence projector object API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'EvidenceProjectorFixture.ps1')
                '-Case'
                $case
            )
            $fixtureErrorPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = & $executable @arguments 2>&1
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $fixtureErrorPreference
            }
            if ($fixtureExitCode -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh evidence projector fixture failed.'
            }
            $marker = 'PASS evidence characterization ' + $case + ' ' + $evidenceProjectorCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute every required evidence scenario.'
        }
    }

    $dictionaryMetadataCases = [ordered]@{
        Controls = 8
        Projection = 4
        Maps = 230
        Getter = 6
        Faults = 24
        Profiles = 28
        Exports = 13
        Loading = 3
        Uncaught = 6
        Consumers = 5
        Legacy = 4
    }
    foreach ($case in $dictionaryMetadataCases.Keys) {
        Invoke-Test ('Native dictionary metadata: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'DictionaryMetadataFixture.ps1')
                '-Case'
                $case
            )
            $fixtureErrorPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = & $executable @arguments 2>&1
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $fixtureErrorPreference
            }
            if ($fixtureExitCode -ne 0) {
                foreach ($line in $output) {
                    Write-Host ('Fixture output: ' + [string]$line)
                }
                throw 'Fresh dictionary metadata fixture failed.'
            }
            $marker = 'PASS dictionary metadata ' + $case + ' ' + $dictionaryMetadataCases[$case]
            Assert-True (($output -join ' ') -like ('*' + $marker + '*')) 'Fresh process did not execute every required dictionary metadata scenario.'
        }
    }

    $operationReaderCases = [ordered]@{
        Native = 40
        Construction = 2
        Standalone = 1
        Direct = 13
        Isolation = 2
    }
    foreach ($case in $operationReaderCases.Keys) {
        Invoke-Test ('Operation document reader API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'OperationDocumentReaderClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Operation reader fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }
            $marker = 'PASS operation document reader ' + $case + ' ' + $operationReaderCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }


    $assessmentReportCases = [ordered]@{
        Native = 20
        Approval = 4
        Construction = 2
        Standalone = 1
        Direct = 6
        Isolation = 2
    }
    foreach ($case in $assessmentReportCases.Keys) {
        Invoke-Test ('Assessment report API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'AssessmentReportClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Assessment report fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }
            $marker = 'PASS assessment report ' + $case + ' ' + $assessmentReportCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }


    $assessmentComparerCases = [ordered]@{
        Native = 22
        Construction = 2
        Standalone = 1
        Direct = 7
        Isolation = 2
    }
    foreach ($case in $assessmentComparerCases.Keys) {
        Invoke-Test ('Assessment comparer API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'AssessmentComparerClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Assessment comparer fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS assessment comparer ' + $case + ' ' + $assessmentComparerCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }


    $remediationGuardCases = [ordered]@{
        Native = 20
        Construction = 2
        Standalone = 1
        Direct = 7
        Isolation = 2
    }
    foreach ($case in $remediationGuardCases.Keys) {
        Invoke-Test ('Offline remediation guard API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'RemediationGuardClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Remediation guard fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS remediation guard ' + $case + ' ' + $remediationGuardCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    $freshRemediationGuardCases = [ordered]@{
        Native = 22
        Construction = 2
        Standalone = 1
        Direct = 9
        Isolation = 2
    }
    foreach ($case in $freshRemediationGuardCases.Keys) {
        Invoke-Test ('Fresh remediation guard API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'FreshRemediationGuardClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Fresh remediation guard fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS fresh remediation guard ' + $case + ' ' + $freshRemediationGuardCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    $remediationPlannerCases = [ordered]@{
        Native = 13
        Construction = 2
        Standalone = 1
        Direct = 7
        Isolation = 2
    }
    foreach ($case in $remediationPlannerCases.Keys) {
        Invoke-Test ('Remediation planner API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'RemediationPlannerClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Remediation planner fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS remediation planner ' + $case + ' ' + $remediationPlannerCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    $remediationJournalCases = [ordered]@{
        Native = 10
        Construction = 2
        Standalone = 1
        Direct = 9
        Isolation = 2
    }
    foreach ($case in $remediationJournalCases.Keys) {
        Invoke-Test ('Remediation journal API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'RemediationJournalClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Remediation journal fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS remediation journal ' + $case + ' ' + $remediationJournalCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    Invoke-Test 'compound journal failures identify the dispatched reservation' {
        $engine = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'RemediationPersistenceContextFixture.ps1'
        $output = @(& $engine -NoLogo -NoProfile -NonInteractive -File $fixture -RepositoryRoot $RepositoryRoot)
        if ($LASTEXITCODE -ne 0) {
            throw 'The compound remediation failure fixture failed.'
        }
        $marker = 'PASS remediation persistence context 8'
        Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
    }

    Invoke-Test 'ambiguous remediation errors identify the held account attempt' {
        $engine = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'RemediationFailureContextFixture.ps1'
        $output = @(& $engine -NoLogo -NoProfile -NonInteractive -File $fixture -RepositoryRoot $RepositoryRoot)
        if ($LASTEXITCODE -ne 0) {
            throw 'The remediation failure context fixture failed.'
        }
        $marker = 'PASS remediation failure context 8'
        Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
    }

    Invoke-Test 'read-only reservation inspection reports local state' {
        $engine = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'ReservationInspectionFixture.ps1'
        $output = @(& $engine -NoLogo -NoProfile -NonInteractive -File $fixture -RepositoryRoot $RepositoryRoot)
        if ($LASTEXITCODE -ne 0) {
            throw 'The reservation inspection fixture failed.'
        }
        $marker = 'PASS remediation reservation inspection 8'
        Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
    }

    Invoke-Test 'shared account reservation blocks cross-journal retries and undo' {
        $engine = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'UncertainRemediationFixture.ps1'
        $output = @(& $engine -NoLogo -NoProfile -NonInteractive -File $fixture -RepositoryRoot $RepositoryRoot)
        if ($LASTEXITCODE -ne 0) {
            throw 'The shared account reservation fixture failed.'
        }

        $expected = @(
            'PASS isolated uncertainty Native to Direct'
            'PASS isolated uncertainty Direct to Native'
            'PASS isolated uncertainty Native Apply to Direct Undo'
            'PASS isolated uncertainty Direct Apply to Native Undo'
            'PASS account reservation storage failure and known no-send'
        )
        foreach ($marker in $expected) {
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    Invoke-Test 'account reservation survives interruption and a new PowerShell process' {
        $engine = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'UncertainRemediationRestartFixture.ps1'
        foreach ($route in 'Native', 'Direct') {
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                $fixture
                '-RepositoryRoot'
                $RepositoryRoot
                '-Route'
                $route
            )
            $output = @(& $engine @arguments)
            if ($LASTEXITCODE -ne 0) {
                throw ('The account reservation restart fixture failed for ' + $route)
            }

            $next = if ($route -eq 'Native') {
                'Direct'
            }
            else {
                'Native'
            }
            $marker = "PASS synthetic restart $route to $next"
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    $remediationApplyCases = [ordered]@{
        Native = 8
        Construction = 2
        Standalone = 1
        Direct = 10
        Isolation = 2
    }
    foreach ($case in $remediationApplyCases.Keys) {
        Invoke-Test ('Remediation Apply API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'RemediationApplyClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Remediation Apply fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS remediation apply ' + $case + ' ' + $remediationApplyCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }

    $remediationUndoCases = [ordered]@{
        Native = 8
        Construction = 2
        Standalone = 1
        Direct = 10
        Isolation = 2
    }
    foreach ($case in $remediationUndoCases.Keys) {
        Invoke-Test ('Remediation Undo API: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $arguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $PSScriptRoot 'RemediationUndoClassFixture.ps1')
                '-Case'
                $case
                '-RepositoryRoot'
                $RepositoryRoot
            )
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = @(& $executable @arguments 2>&1)
                $fixtureExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            if ($fixtureExitCode -ne 0) {
                throw ("Remediation Undo fixture exited with code {0}.{1}{2}" -f
                    $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
            }

            $marker = 'PASS remediation undo ' + $case + ' ' + $remediationUndoCases[$case]
            Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        }
    }


    $legacyValueCases = [ordered]@{
        Parity = 44
        Collision = 16
    }
    foreach ($case in $legacyValueCases.Keys) {
        Invoke-Test ('Legacy table values: ' + $case) {
            $executable = (Get-Process -Id $PID).Path
            $fixture = Join-Path $PSScriptRoot 'LegacyTableValuesFixture.ps1'
            $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case
            Assert-True ($LASTEXITCODE -eq 0) 'Legacy table values fixture failed.'
            $marker = 'PASS legacy table values ' + $case + ' ' + $legacyValueCases[$case]
            Assert-True ($marker -cin @($output)) 'Fresh process did not execute every legacy table case.'
        }
    }
}
finally {
    Remove-Item -LiteralPath $script:Temporary -Recurse -Force -WhatIf:$false -Confirm:$false
}
Write-Host ("{0} operations tests passed; {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed) {
    exit 1
}
