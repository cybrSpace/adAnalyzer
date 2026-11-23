[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
foreach ($name in @('ADProfile', 'ADGpo', 'ADPolicyAnalysis', 'ADDirectoryAnalysis', 'ADHostAnalysis', 'ADOperations', 'ADAssessment')) {
    . (Join-Path $RepositoryRoot ('bin/' + $name + '.ps1'))
}
$script:Passed = 0
$script:Failed = 0

function Assert-Equal($Expected, $Actual) {
    if ($Expected -ne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function Assert-True($Actual, [string]$Message) {
    if (-not $Actual) {
        throw $Message
    }
}

function Assert-Throws([scriptblock]$Body) {
    $failed = $false
    try {
        & $Body > $null
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        throw 'Expected a terminating error'
    }
}

function Test-Assessment([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name : $_"
        Write-Host $_.ScriptStackTrace
    }
}

function New-AssessmentFixture([string]$Domain = 'example.invalid') {
    $dn = 'DC=' + ($Domain.Replace('.', ',DC='))
    $coverage = @{}
    foreach ($key in @('Domain',
            'Users',
            'Groups',
            'Computers',
            'Trusts',
            'DefaultPasswordPolicy',
            'FineGrainedPasswordPolicies',
            'ResultantPasswordPolicies',
            'ServiceAccounts',
            'OptionalFeatures')) {
        $coverage[$key] = 'Collected'
    }
    $coverage.Acl = 'NotConfigured'
    $coverage.Hosts = 'NotConfigured'
    [pscustomobject]@{
        Domain = [pscustomobject]@{
            DNSRoot = $Domain
            DistinguishedName = $dn
            SID = 'S-1-5-21-1-2-3'
            MachineAccountQuota = 0
            OptionalFeatures = @([pscustomobject]@{
                    FeatureGUID = '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'
                    EnabledScopes = @($dn)
                })
        }
        Server = ('dc.' + $Domain)
        Users = @()
        Groups = @()
        Computers = @()
        ServiceAccounts = @()
        Objects = @()
        Trusts = @()
        DomainControllers = @()
        PasswordPolicies = [pscustomobject]@{
            Default = $null
            FineGrained = @()
            Resultant = @()
        }
        Acl = [pscustomobject]@{
            Entries = @()
        }
        Hosts = @()
        Errors = @()
        Coverage = $coverage
    }
}

function New-PolicyFixture {
    [pscustomobject]@{
        Path = 'fixture'
        SysvolVersion = 1
        SecuritySettings = @()
        RegistrySettings = @()
        XmlFiles = @()
        IniSettings = @()
        Files = @()
        UnparsedFiles = @()
    }
}

function Write-AssessmentPol([string]$Path, [array]$Records) {
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream = [IO.File]::Create($Path)
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'))
        $writer.Write([uint32]1)
        foreach ($row in $Records) {
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Key + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Name + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([uint32]$row.Type)
            $writer.Write([uint16]59)
            $writer.Write([uint32]$row.Bytes.Length)
            $writer.Write([uint16]59)
            $writer.Write([byte[]]$row.Bytes)
            $writer.Write([uint16]93)
        }
    }
    finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function New-RegistryIdentityFixture([string]$Name, [switch]$Deleted) {
    $root = Join-Path $temp $Name
    $templates = Join-Path $root 'templates'
    $null = [IO.Directory]::CreateDirectory((Join-Path $templates 'en-US'))
    [IO.File]::WriteAllText((Join-Path $templates 'fixture.admx'),
        '<policyDefinitions><policyNamespaces><target prefix="f" namespace="Fixture.Policies"/></policyNamespaces><policies><policy name="EnabledPolicy" class="Both" displayName="$(string.Title)" key="Software\Fixture" valueName="Enabled"><enabledValue><decimal value="1"/></enabledValue><disabledValue><delete/></disabledValue></policy></policies></policyDefinitions>')
    [IO.File]::WriteAllText((Join-Path $templates 'en-US/fixture.adml'),
        '<policyDefinitionResources><resources><stringTable><string id="Title">Fixture title</string></stringTable></resources></policyDefinitionResources>')
    foreach ($side in @('Machine', 'User')) {
        $rows = @(@{
                Key = 'Software\Fixture'
                Name = 'Enabled'
                Type = 4
                Bytes = [BitConverter]::GetBytes([uint32]0)
            }, @{
                Key = 'Software\Fixture'
                Name = 'Enabled'
                Type = 4
                Bytes = [BitConverter]::GetBytes([uint32]1)
            })
        if ($Deleted) {
            $rows += @{
                Key = 'Software\Fixture'
                Name = '**del.Enabled'
                Type = 1
                Bytes = [byte[]]@()
            }
        }
        $rows += @{
            Key = 'Software\Fixture'
            Name = 'DefaultPassword'
            Type = 1
            Bytes = [Text.Encoding]::Unicode.GetBytes("REGISTRY_IDENTITY_FIXTURE_SECRET`0")
        }
        if ($side -eq 'Machine') {
            $rows += @{
                Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
                Name = 'EnableLUA'
                Type = 4
                Bytes = [BitConverter]::GetBytes([uint32]1)
            }
        }
        Write-AssessmentPol (Join-Path $root ($side + '/Registry.pol')) $rows
    }
    [IO.File]::WriteAllText((Join-Path $root 'GPT.INI'), "[General]`nVersion=1")
    $policy = Read-ADAnalyzerGpo $root
    $profile = @{
        Analysis = @{
            TemplatePath = $templates
        }
        RegistryRules = @(@{
                Id = 'FixtureEnabled'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Enabled'
                Expected = 1
                Type = 4
            })
    }
    [pscustomobject]@{
        Root = $root
        Policy = $policy
        Profile = $profile
        Gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Version = 1
            Flags = 0
            Links = @()
        }
    }
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('ad-assessment-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $temp -ItemType Directory
try {
    foreach ($mode in @('Contract', 'Constructors', 'Isolation', 'Validation', 'Failures', 'States')) {
        Test-Assessment ('constructor assessment engine: ' + $mode) {
            $childArguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                (Join-Path $RepositoryRoot 'tests/AssessmentEngineFixture.ps1')
                '-RepositoryRoot'
                $RepositoryRoot
                '-Mode'
                $mode
            )
            $output = @(& (Get-Process -Id $PID).Path @childArguments)
            Assert-Equal 0 $LASTEXITCODE
            Assert-True (($output -join ' ') -match ('PASS assessment engine ' + $mode)) 'Assessment engine consumer did not finish'
        }
    }
    Test-Assessment 'invalid-only evidence is Partial while evaluated failures remain Complete' {
        $directory = New-AssessmentFixture
        $profile = Get-ADAnalyzerDefaultProfile
        $profile.Host.RegistryRules = @(@{
                Key = 'SYSTEM\Fixture'
                ValueName = 'Enabled'
                Type = 4
                Expected = 0
            })
        $record = [pscustomobject]@{
            ComputerName = 'fixture'
            Services = @()
            Registry = @([pscustomobject]@{
                    Path = 'SYSTEM\Fixture'
                    Name = 'Enabled'
                    Status = 'Observed'
                    Value = 0
                    Type = 1
                })
        }
        $directory | Add-Member `
            -NotePropertyName HostChecks `
            -NotePropertyValue @(Test-ADAnalyzerHostPolicy `
                -Hosts @($record) `
                -Profile $profile)
        $hostResult = Invoke-ADAnalyzerAssessment -DirectoryData $directory -Profile $profile
        $policy = New-PolicyFixture
        $policy.SecuritySettings = @([pscustomobject]@{
                Kind = 'Account'
                Name = 'MinimumPasswordLength'
                Value = 12
                ValueValid = $false
                Scope = 'Computer'
                Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            })
        $gpo = [pscustomobject]@{
            Id = [guid]::Empty
            Version = 1
            Flags = 0
            Links = @()
        }
        $gpoResult = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $policy
            })
        foreach ($result in @($hostResult, $gpoResult)) {
            Assert-Equal 0 $result.Coverage.Unknown
            Assert-Equal 0 $result.Coverage.Unreadable
            Assert-Equal 0 $result.Errors.Count
            Assert-Equal 1 $result.Coverage.Invalid
            Assert-Equal Partial $result.State
            $path = Join-Path $temp ('invalid-only-' + $result.RunId)
            $null = Export-ADAnalyzerAssessment $result $path -Format All -Confirm:$false
            $saved = Get-Content -LiteralPath ($path + '.json') -Raw | ConvertFrom-Json
            Assert-Equal Partial $saved.State
            Assert-Equal 1 $saved.Coverage.Invalid
            Assert-True ((Get-Content -LiteralPath ($path + '.html') -Raw) -match 'State: Partial') 'HTML state disagrees with assessment'
        }
        $directory = New-AssessmentFixture
        $directory.Domain.MachineAccountQuota = 99
        $failed = Invoke-ADAnalyzerAssessment -DirectoryData $directory
        Assert-True ($failed.Coverage.Fail -gt 0) 'Fail-only control missing'
        Assert-Equal 0 $failed.Coverage.Invalid
        Assert-Equal Complete $failed.State
    }
    Test-Assessment 'registry metadata identities preserve literal component separators' {
        $fixture = New-RegistryIdentityFixture 'metadata-separators'
        $fixture.Policy.RegistrySettings = @(
            [pscustomobject]@{
                Hive = 'HKLM'
                Scope = 'Computer'
                Key = 'Software\Fixture'
                ValueName = 'part/Enabled'
                Value = 1
                Type = 4
                Source = 'Machine/Registry.pol'
            },
            [pscustomobject]@{
                Hive = 'HKLM'
                Scope = 'Computer'
                Key = 'Software\Fixture/part'
                ValueName = 'Enabled'
                Value = 2
                Type = 4
                Source = 'Machine/Registry.pol'
            }
        )
        $before = ConvertTo-Json -InputObject $fixture.Policy -Depth 50 -Compress
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $fixture.Gpo
                Policy = $fixture.Policy
            }) -Profile $fixture.Profile
        $checks = @($result.Checks | Where-Object RuleId -eq GPO.TEMPLATE_METADATA)
        Assert-Equal 2 $checks.Count
        Assert-Equal 2 @($checks.CheckId | Select-Object -Unique).Count
        Assert-Equal $before (ConvertTo-Json -InputObject $fixture.Policy -Depth 50 -Compress)
    }
    Test-Assessment 'removing Registry.pol preserves an unchanged authoritative INF security check' {
        $policies = @()
        foreach ($name in @('with-registry-source', 'without-registry-source')) {
            $root = Join-Path $temp $name
            $inf = Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($inf))
            [IO.File]::WriteAllText($inf,
                "[Registry Values]`nMACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0")
            if ($name -eq 'with-registry-source') {
                Write-AssessmentPol (Join-Path $root 'Machine/Registry.pol') @(@{
                        Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
                        Name = 'EnableLUA'
                        Type = 4
                        Bytes = [BitConverter]::GetBytes([uint32]1)
                    })
            }
            $gpo = [pscustomobject]@{
                Id = [guid]'11111111-1111-1111-1111-111111111111'
                Flags = 0
                Links = @()
            }
            $policies += Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                    Gpo = $gpo
                    Policy = (Read-ADAnalyzerGpo $root)
                })
        }
        $rule = 'GPO.Security.SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'
        $old = @($policies[0].Checks | Where-Object { $_.RuleId -eq $rule -and $_.Evidence.Path -like '*GptTmpl.inf' })
        $new = @($policies[1].Checks | Where-Object { $_.RuleId -eq $rule -and $_.Evidence.Path -like '*GptTmpl.inf' })
        Assert-Equal 1 $old.Count
        Assert-Equal 1 $new.Count
        Assert-Equal Fail $old[0].Status
        Assert-Equal Fail $new[0].Status
        Assert-Equal $old[0].CheckId $new[0].CheckId
        $changes = @((Compare-ADAnalyzerAssessment $policies[0] $policies[1]).Changes | Where-Object RuleId -eq $rule.ToUpperInvariant())
        Assert-Equal 1 @($changes | Where-Object Change -eq Unchanged).Count
        Assert-Equal 1 @($changes | Where-Object { $_.Change -eq 'Changed' -and $_.Reason -eq 'NotObservedInDifference' }).Count
        Assert-Equal 0 @($changes | Where-Object Change -eq New).Count
    }
    Test-Assessment 'logical GPO paths are canonical and comparisons survive physical separator differences' {
        $root = Join-Path $temp 'logical-source'
        $null = [IO.Directory]::CreateDirectory((Join-Path $root 'Machine'))
        $null = [IO.Directory]::CreateDirectory((Join-Path $root 'User'))
        $script:LogicalSourceRoot = (Get-Item -LiteralPath $root).FullName
        $script:LogicalReads = [Collections.Generic.List[string]]::new()
        $script:LogicalFiles = @('Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf',
            'Machine/Extra.ini',
            'Machine/Preferences/Groups/Groups.xml',
            'Machine/Scripts/unsupported.cmd')
        $ini = (Get-Command Read-AnalyzerPolicyIni).ScriptBlock
        $xml = (Get-Command Read-AnalyzerPolicyXml).ScriptBlock
        $listing = Get-Command Get-ChildItem
        try {

            function script:Get-ChildItem {
                param(
                    $LiteralPath,
                    [switch]$Recurse,
                    [switch]$File,
                    [switch]$Force,
                    $ErrorAction

                )
                if ($LiteralPath -eq (Join-Path $script:LogicalSourceRoot 'Machine')) {
                    foreach ($path in $script:LogicalFiles) {
                        [pscustomobject]@{
                            FullName = $script:LogicalSourceRoot + $script:LogicalSeparator + $path.Replace('/', $script:LogicalSeparator)
                            Name = ($path.Split('/')[-1])
                            Extension = [IO.Path]::GetExtension($path)
                            Length = 100
                        }
                    }
                }
            }

            function script:Read-AnalyzerPolicyIni {
                param($Path)
                $script:LogicalReads.Add($Path)
                if ($Path -like '*GptTmpl.inf') {
                    return [ordered]@{
                        'System Access' = [ordered]@{
                            MinimumPasswordLength = '16'
                        }
                    }
                }
                return [ordered]@{
                    Fixture = [ordered]@{
                        Setting = 'value'
                    }
                }
            }

            function script:Read-AnalyzerPolicyXml {
                param($Path)
                $script:LogicalReads.Add($Path)
                return [xml]'<Groups><Group uid="stable"><Properties action="U" groupSid="S-1-5-32-544"/></Group></Groups>'
            }
            $results = @()
            foreach ($separator in @([string][char]92, '/')) {
                $script:LogicalSeparator = $separator
                $script:LogicalReads.Clear()
                $policy = Read-ADAnalyzerGpo $root
                Assert-Equal $script:LogicalSourceRoot $policy.Path
                foreach ($path in @($policy.SecuritySettings.Source) + @($policy.IniSettings.Source) + @($policy.XmlFiles.Path) + @($policy.Files.Path) + @($policy.UnparsedFiles.Path)) {
                    Assert-True (-not $path.Contains([string][char]92)) ('Noncanonical logical path ' + $path)
                    Assert-True (-not [IO.Path]::IsPathRooted($path)) 'Physical root escaped into logical metadata'
                }
                Assert-Equal 3 $script:LogicalReads.Count
                foreach ($path in $script:LogicalReads) {
                    Assert-True ($path.StartsWith($script:LogicalSourceRoot + $separator,
                            [StringComparison]::Ordinal)) 'File I/O path was normalized'
                    Assert-True ($path.Contains($separator + 'Machine' + $separator)) 'Original file I/O path was replaced'
                }
                $gpo = [pscustomobject]@{
                    Id = [guid]'11111111-1111-1111-1111-111111111111'
                    Flags = 0
                    Links = @()
                }
                $results += Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                        Gpo = $gpo
                        Policy = $policy
                    })
            }
            $changes = @((Compare-ADAnalyzerAssessment $results[0] $results[1]).Changes | Where-Object RuleId -like 'GPO.*')
            Assert-True ($changes.Count -gt 5) 'Policy paths were not assessed'
            Assert-Equal 0 @($changes | Where-Object Change -ne Unchanged).Count
            Assert-Equal (ConvertTo-Json `
                    -InputObject $results[0].Data.Policies `
                    -Depth 100 `
                    -Compress) (ConvertTo-Json `
                    -InputObject $results[1].Data.Policies `
                    -Depth 100 `
                    -Compress)
        }
        finally {
            Set-Item Function:script:Read-AnalyzerPolicyIni $ini
            Set-Item Function:script:Read-AnalyzerPolicyXml $xml
            if ($listing -is [Management.Automation.FunctionInfo]) {
                Set-Item Function:script:Get-ChildItem $listing.ScriptBlock
            }
            else {
                Remove-Item Function:Get-ChildItem
            }
            Assert-Equal $listing.CommandType (Get-Command Get-ChildItem).CommandType
        }
    }
    Test-Assessment 'native GPO files retain canonical logical paths and original bytes' {
        $root = Join-Path $temp 'native-logical-source'
        $files = @{
            'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf' = "[System Access]`nMinimumPasswordLength=16"
            'Machine/Extra.ini' = "[Fixture]`nSetting=value"
            'Machine/Preferences/Groups/Groups.xml' = '<Groups><Group uid="stable"><Properties action="U" groupSid="S-1-5-32-544"/></Group></Groups>'
            'Machine/Scripts/unsupported.cmd' = 'fixture content'
        }
        $bytes = @{}
        foreach ($relative in $files.Keys) {
            $path = Join-Path $root $relative
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
            [IO.File]::WriteAllText($path, $files[$relative])
            $bytes[$path] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        }
        $policy = Read-ADAnalyzerGpo $root
        foreach ($path in @($policy.SecuritySettings.Source) + @($policy.IniSettings.Source) + @($policy.XmlFiles.Path) + @($policy.Files.Path) + @($policy.UnparsedFiles.Path)) {
            Assert-True (-not $path.Contains([string][char]92)) 'Native logical path was not canonical'
        }
        Assert-Equal 1 $policy.SecuritySettings.Count
        Assert-Equal 2 $policy.IniSettings.Count
        Assert-Equal 1 $policy.XmlFiles.Count
        Assert-Equal 1 $policy.UnparsedFiles.Count
        foreach ($path in $bytes.Keys) {
            Assert-Equal $bytes[$path] ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)))
        }
    }
    Test-Assessment 'registry template metadata uses final effective writes in each hive without altering raw inventory' {
        foreach ($deleted in @($false, $true)) {
            $fixture = New-RegistryIdentityFixture ('registry-effective-' + $deleted) -Deleted:$deleted
            $before = ConvertTo-Json -InputObject $fixture.Policy -Depth 100 -Compress
            $bytes = @{}
            foreach ($file in Get-ChildItem -LiteralPath $fixture.Root -Recurse -File) {
                $bytes[$file.FullName] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
            }
            $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @($fixture) -Profile $fixture.Profile
            $metadata = @($result.Checks | Where-Object { $_.RuleId -eq 'GPO.TEMPLATE_METADATA' -and $_.Observed.ValueName -eq 'Enabled' })
            Assert-Equal 2 $metadata.Count
            Assert-Equal 'HKCU,HKLM' (($metadata.Observed.Hive | Sort-Object) -join ',')
            foreach ($check in $metadata) {
                Assert-Equal Pass $check.Status
                if ($deleted) {
                    Assert-Equal Disabled $check.Observed.State
                    Assert-Equal $true $check.Observed.Deleted
                }
                else {
                    Assert-Equal Enabled $check.Observed.State
                    Assert-Equal 1 $check.Observed.Value
                    Assert-Equal $false $check.Observed.Deleted
                }
            }
            Assert-Equal 0 @($result.Checks | Group-Object CheckId | Where-Object Count -gt 1).Count
            Assert-Equal $before (ConvertTo-Json -InputObject $fixture.Policy -Depth 100 -Compress)
            foreach ($path in $bytes.Keys) {
                Assert-Equal $bytes[$path] ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)))
            }
            Assert-True ((ConvertTo-Json `
                        -InputObject $result `
                        -Depth 100) -notmatch 'REGISTRY_IDENTITY_FIXTURE_SECRET|REDACTED') 'Secret escaped metadata assessment'
        }
    }
    Test-Assessment 'identical GPO registry policies at different roots retain unchanged check identities' {
        $a = New-RegistryIdentityFixture 'registry-root-a'
        $b = New-RegistryIdentityFixture 'registry-root-b'
        $before = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @($a) -Profile $a.Profile
        $after = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @($b) -Profile $b.Profile
        $changes = @((Compare-ADAnalyzerAssessment $before $after).Changes | Where-Object RuleId -like 'GPO.*')
        Assert-True ($changes.Count -gt 5) 'Registry assessment paths were not exercised'
        Assert-Equal 0 @($changes | Where-Object Change -ne Unchanged).Count
        foreach ($pattern in @('GPO.SECURITY.*', 'GPO.EXPECTED.*', 'GPO.STOREDSECRET', 'GPO.TEMPLATE_METADATA')) {
            Assert-True (@($changes | Where-Object RuleId -like $pattern).Count -gt 0) ('Missing assessment path ' + $pattern)
        }
        foreach ($rule in @('GPO.Security.SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
                'GPO.Expected.FixtureEnabled')) {
            $checks = @($after.Checks | Where-Object RuleId -eq $rule)
            Assert-Equal 1 $checks.Count
            Assert-Equal Pass $checks[0].Status
            Assert-Equal 'Machine/Registry.pol' $checks[0].Evidence.Path
        }
        Assert-Equal 0 @($after.Checks | Where-Object { $_.RuleId -eq 'GPO.StoredSecret' -and $_.Observed -ne $true }).Count
    }
    Test-Assessment 'offline assessment reports explicit coverage without directory calls' {
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture)
        Assert-True ($result.Checks.Count -gt 0) 'No checks returned'
        Assert-Equal $result.Checks.Count $result.Coverage.Total
        Assert-Equal 'Pass' ($result.Checks | Where-Object RuleId -eq DOMAIN.MACHINE_ACCOUNT_QUOTA).Status
        Assert-Equal 'NotConfigured' ($result.Checks | Where-Object RuleId -eq COLLECTION.ACL).Status
        Assert-Equal 1 $result.SchemaVersion
    }
    Test-Assessment 'offline password expiration requires a Boolean account observation' {
        $unexpectedCalls = [Collections.Generic.List[string]]::new()
        $denyAcquisition = {
            $unexpectedCalls.Add($MyInvocation.InvocationName)
            throw 'Unexpected acquisition in the offline password expiration fixture.'
        }
        foreach ($commandName in @(
                'Import-Module'
                'Get-ADRootDSE'
                'Get-ADAnalyzerDirectoryData'
                'Get-ADAnalyzerHostData'
                'Get-ADAnalyzerGpo'
                'Get-ADAnalyzerGpoReport'
                'Invoke-Command'
                'New-CimSession'
            )) {
            Set-Item -LiteralPath ('Function:local:' + $commandName) -Value $denyAcquisition
        }
        Assert-Throws { Get-ADRootDSE }
        Assert-Equal 1 $unexpectedCalls.Count
        $unexpectedCalls.Clear()

        $flags = [ordered]@{
            BooleanTrue = $true
            BooleanFalse = $false
            DisabledBooleanTrue = $true
            Null = $null
            EmptyString = ''
            TextFalse = 'false'
            NumericZero = 0
            EmptyArray = @()
            SingletonBooleanArray = @($false)
        }
        $caseNames = @($flags.Keys) + 'Missing'
        $statusWhenDisallowed = @{
            BooleanTrue = 'Fail'
            BooleanFalse = 'Pass'
            DisabledBooleanTrue = 'Fail'
        }
        $projector = [ADAnalyzerDirectoryObjectProjector]::new()
        $identities = @{}
        $statusDifferences = [Collections.Generic.List[string]]::new()
        foreach ($projection in 'Snapshot', 'Class', 'Command') {
            $directory = New-AssessmentFixture
            $directory.Users = @(
                for ($index = 0; $index -lt $caseNames.Count; $index++) {
                    $caseName = $caseNames[$index]
                    $fields = [ordered]@{
                        DistinguishedName = 'CN=' + $caseName + ',DC=example,DC=invalid'
                        SID = 'S-1-5-21-1-2-3-' + (2300 + $index)
                        ObjectClass = 'User'
                        Enabled = $caseName -ne 'DisabledBooleanTrue'
                    }
                    if ($flags.Contains($caseName)) {
                        $fields['PasswordNeverExpires'] = $flags[$caseName]
                    }
                    $record = [pscustomobject]$fields
                    switch ($projection) {
                        'Snapshot' {
                            $record
                        }
                        'Class' {
                            $projector.Project($record, 'User')
                        }
                        'Command' {
                            ConvertTo-ADAnalyzerDirectoryObject -Record $record -Kind User
                        }
                    }
                }
            )

            foreach ($allowNeverExpires in $false, $true) {
                $profile = @{
                    Analysis = @{
                        IncludeGpo = $false
                        IncludeHostChecks = $false
                    }
                    Policy = @{
                        AllowPasswordNeverExpires = $allowNeverExpires
                    }
                }
                $result = Invoke-ADAnalyzerAssessment -DirectoryData $directory -Profile $profile
                $checks = @($result.Checks | Where-Object RuleId -CEQ 'ACCOUNT.PASSWORD_NEVER_EXPIRES')
                Assert-Equal $caseNames.Count $checks.Count
                for ($index = 0; $index -lt $caseNames.Count; $index++) {
                    $caseName = $caseNames[$index]
                    $row = $checks[$index]
                    $userRecord = $directory.Users[$index]
                    $expectedStatus = $statusWhenDisallowed[$caseName]
                    if ($null -eq $expectedStatus) {
                        $expectedStatus = 'Unknown'
                    }
                    elseif ($allowNeverExpires) {
                        $expectedStatus = 'Pass'
                    }
                    if ($row.Status -cne $expectedStatus) {
                        $statusDifferences.Add(('{0}/{1} (allow={2}): expected {3}, got {4}' -f
                                $projection, $caseName, $allowNeverExpires, $expectedStatus, $row.Status))
                    }
                    Assert-True (
                        $row.Target -ceq $userRecord.DistinguishedName -and
                        $row.DistinguishedName -ceq $userRecord.DistinguishedName -and
                        $row.SID -ceq $userRecord.SID -and
                        $row.CheckId -cmatch '^[0-9a-f]{64}$' -and
                        $row.Applicability -ceq 'Configured' -and
                        $row.Expected -is [bool] -and $row.Expected -eq $allowNeverExpires -and
                        $null -ne $row.PSObject.Properties['Observed']
                    ) ('The password expiration check lost its identity or result shape for ' + $caseName)
                    if ($identities.ContainsKey($caseName)) {
                        Assert-Equal $identities[$caseName] $row.CheckId
                    }
                    else {
                        $identities[$caseName] = $row.CheckId
                    }
                    if ($flags[$caseName] -is [bool]) {
                        Assert-True ($row.Observed -is [bool] -and $row.Observed -eq $flags[$caseName]) (
                            'The password expiration check lost its Boolean observation for ' + $caseName
                        )
                    }
                }
            }
        }
        Assert-Equal 0 $unexpectedCalls.Count
        Assert-True ($statusDifferences.Count -eq 0) ($statusDifferences -join '; ')
    }
    Test-Assessment 'password expiry allowance changes are not recorded as account flag changes' {
        $ruleId = 'ACCOUNT.PASSWORD_NEVER_EXPIRES'
        $accountDn = 'CN=Expiry Test,DC=example,DC=invalid'
        $makeSnapshot = {
            param([bool]$NeverExpires, [bool]$Allowed)

            $directory = New-AssessmentFixture
            $directory.Objects = @([pscustomobject]@{
                    ObjectClass = 'User'
                    AccountType = 'User'
                    Enabled = $true
                    DistinguishedName = $accountDn
                    ObjectGuid = [guid]'4bba9958-e7c0-4102-9ad8-ddba376b91f7'
                    SID = 'S-1-5-21-1-2-3-3201'
                    PasswordNeverExpires = $NeverExpires
                })
            $profile = @{ Policy = @{ AllowPasswordNeverExpires = $Allowed } }
            Invoke-ADAnalyzerAssessment -DirectoryData $directory -Profile $profile -Target 'example.invalid'
        }

        $snapshots = [ordered]@{}
        $checks = @{}
        foreach ($fixture in @(
                @('Disallowed', $true, $false, 'Fail'),
                @('Allowed', $true, $true, 'Pass'),
                @('FlagCleared', $false, $false, 'Pass'),
                @('BothChanged', $false, $true, 'Pass')
            )) {
            $name, $flag, $allowance, $status = $fixture
            $snapshot = & $makeSnapshot $flag $allowance
            $rows = @($snapshot.Checks | Where-Object RuleId -eq $ruleId)
            Assert-Equal 1 $rows.Count
            $row = $rows[0]
            Assert-Equal $accountDn $row.Target
            Assert-Equal $status $row.Status
            Assert-True ($row.Observed -is [bool] -and $row.Observed -eq $flag -and
                $row.Expected -is [bool] -and $row.Expected -eq $allowance) 'Assessment lost the typed Boolean evidence'
            $snapshots[$name] = $snapshot
            $checks[$name] = $row
        }

        $snapshots.LegacyAllowance = & $makeSnapshot $true $true
        $checks.LegacyAllowance = $snapshots.LegacyAllowance.Checks | Where-Object RuleId -eq $ruleId
        $checks.LegacyAllowance.Expected = 'True'
        $snapshots.CaseFoldedAllowance = & $makeSnapshot $true $true
        $checks.CaseFoldedAllowance = $snapshots.CaseFoldedAllowance.Checks | Where-Object RuleId -eq $ruleId
        $checks.CaseFoldedAllowance.RuleId = $ruleId.ToLowerInvariant()
        $snapshots.ArrayRuleId = & $makeSnapshot $true $true
        $checks.ArrayRuleId = $snapshots.ArrayRuleId.Checks | Where-Object RuleId -eq $ruleId
        $checks.ArrayRuleId.RuleId = @($ruleId)

        $paths = @{}
        $hashes = @{}
        foreach ($name in $snapshots.Keys) {
            Assert-Equal $checks.Disallowed.CheckId $checks[$name].CheckId
            $paths[$name] = Join-Path $temp ('password-expiry-comparison-' + $name + '.json')
            $null = Export-ADAnalyzerAssessment -Assessment $snapshots[$name] -Path $paths[$name] -Format Json -Confirm:$false
            $hashes[$name] = (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }

        $comparer = [ADAnalyzerAssessmentComparer]::new()
        $cases = @(
            @('Disallowed', 'FlagCleared', 'Resolved', $null),
            @('FlagCleared', 'Disallowed', 'New', $null),
            @('Disallowed', 'BothChanged', 'Resolved', $null),
            @('Disallowed', 'LegacyAllowance', 'Resolved', $null),
            @('Disallowed', 'Allowed', 'Changed', 'RulePredicateChanged'),
            @('Allowed', 'Disallowed', 'Changed', 'RulePredicateChanged'),
            @('Disallowed', 'CaseFoldedAllowance', 'Changed', 'RulePredicateChanged'),
            @('Disallowed', 'ArrayRuleId', 'Resolved', $null)
        )
        foreach ($documents in @($snapshots, $paths)) {
            foreach ($case in $cases) {
                $before, $after, $expectedChange, $expectedReason = $case
                $reference = $documents[$before]
                $difference = $documents[$after]
                $command = Compare-ADAnalyzerAssessment -Reference $reference -Difference $difference
                $direct = $comparer.Compare($reference, $difference)
                foreach ($result in @($command, $direct)) {
                    $changes = @($result.Changes | Where-Object RuleId -eq $ruleId)
                    Assert-Equal 1 $changes.Count
                    $change = $changes[0]
                    Assert-True ($change.Change -eq $expectedChange -and $change.Reason -eq $expectedReason) (
                        "Comparison $before to $after expected $expectedChange/$expectedReason, received $($change.Change)/$($change.Reason)"
                    )
                    Assert-Equal $accountDn $change.Target
                    foreach ($field in @('Status', 'Observed', 'Expected')) {
                        Assert-Equal $checks[$before].$field $change.Reference[0].$field
                        Assert-Equal $checks[$after].$field $change.Difference[0].$field
                    }
                }
            }
        }
        foreach ($name in $paths.Keys) {
            Assert-Equal $hashes[$name] (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }
    }
    Test-Assessment 'unreadable collectors produce partial coverage and preserve errors' {
        $data = New-AssessmentFixture
        $data.Coverage.Users = 'Unreadable'
        $data.Errors = @([pscustomobject]@{
                Collection = 'Users'
                Message = 'fixture access denied'
            })
        $result = Invoke-ADAnalyzerAssessment -DirectoryData $data
        Assert-Equal Partial $result.State
        Assert-Equal Unreadable ($result.Checks | Where-Object RuleId -eq COLLECTION.USERS).Status
        Assert-Equal 'fixture access denied' $result.Errors[0].Message
    }
    Test-Assessment 'missing domain metadata cannot produce a complete live assessment' {
        $data = New-AssessmentFixture
        $data.Domain = $null
        $data.Coverage.Domain = 'Unreadable'
        $result = Invoke-ADAnalyzerAssessment -DirectoryData $data -Target example.invalid
        Assert-Equal Failed $result.State
    }
    Test-Assessment 'exceptions preserve failed evidence with owned expiring suppression metadata' {
        $data = New-AssessmentFixture
        $data.Domain.MachineAccountQuota = 10
        $profile = @{
            Exceptions = @(@{
                    RuleId = 'DOMAIN.MACHINE_ACCOUNT_QUOTA'
                    Target = $data.Domain.DistinguishedName
                    Owner = 'Ops'
                    Reason = 'Lab migration'
                    Expires = [datetime]::UtcNow.AddDays(1).ToString('o')
                })
        }
        $result = Invoke-ADAnalyzerAssessment -DirectoryData $data -Profile $profile
        $check = $result.Checks | Where-Object RuleId -eq DOMAIN.MACHINE_ACCOUNT_QUOTA
        Assert-Equal Fail $check.Status
        Assert-True $check.Suppressed 'Owned exception not applied'
        Assert-Equal Ops $check.Exception.Owner
    }
    Test-Assessment 'separate snapshots do not share nested evidence or configuration' {
        $data = New-AssessmentFixture
        $a = Invoke-ADAnalyzerAssessment -DirectoryData $data
        $b = Invoke-ADAnalyzerAssessment -DirectoryData $data
        $a.Data.Directory.Domain.MachineAccountQuota = 99
        $a.Configuration.Policy.MinimumPasswordLength = 99
        Assert-Equal 0 $b.Data.Directory.Domain.MachineAccountQuota
        Assert-Equal 12 $b.Configuration.Policy.MinimumPasswordLength
        Assert-Equal 0 $data.Domain.MachineAccountQuota
    }
    Test-Assessment 'assessment boundary retains only credential and XML secret presence' {
        $data = New-AssessmentFixture
        $data | Add-Member `
            -NotePropertyName Credential `
            -NotePropertyValue ([pscredential]::new('fixture',
                (ConvertTo-SecureString 'fixture-password' `
                    -AsPlainText `
                    -Force)))
        $policy = New-PolicyFixture
        $policy.XmlFiles = @([pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Preferences'
                Path = 'Machine/Preferences/Groups.xml'
                Xml = '<Groups><User uid="fixture" cpassword="fixture-secret" /></Groups>'
            })
        $gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Flags = 0
            Version = 1
            Links = @()
        }
        $result = Invoke-ADAnalyzerAssessment -DirectoryData $data -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $policy
                Error = $null
            })
        $json = ConvertTo-Json -InputObject $result -Depth 100
        Assert-True ($json -notmatch 'fixture-secret|fixture-password') 'Secret crossed assessment boundary'
        Assert-Equal Fail ($result.Checks | Where-Object RuleId -eq GPO.Preferences.CPassword).Status
    }
    Test-Assessment 'omitted inventoried GPO XML limits credential evidence through both assessment APIs' {
        $data = New-AssessmentFixture
        $policy = New-PolicyFixture
        $xml = [pscustomobject]@{
            Scope = 'Computer'
            Path = 'Machine/Preferences/Groups/Groups.xml'
            Kind = 'Preferences'
            Xml = '<Groups><User cpasswordPresent="false" /></Groups>'
        }
        $policy.XmlFiles = @($xml)
        $policy.Files = @([pscustomobject]@{
                Scope = $xml.Scope
                Path = $xml.Path
                Kind = 'Xml'
                Length = 52
            })
        $gpoData = @([pscustomobject]@{
                Gpo = [pscustomobject]@{
                    Id = [guid]'11111111-1111-1111-1111-111111111111'
                    Flags = 0
                    Version = 1
                    Links = @()
                }
                Policy = $policy
                Error = $null
            })
        $target = $data.Domain.DNSRoot
        $engine = [ADAnalyzerAssessmentEngine]::new()
        $clean = $engine.Evaluate($data, $gpoData, $target)
        $original = $clean.Checks | Where-Object RuleId -eq GPO.Preferences.CPassword
        Assert-Equal Pass $original.Status
        Assert-True ($original.Observed -is [bool] -and -not $original.Observed) 'Readable clean XML lost Boolean absence'
        Assert-Equal 0 @($clean.Checks | Where-Object RuleId -eq GPO.Coverage.MissingXml).Count

        $policy.Files += [pscustomobject]@{
            Scope = 'User'
            Path = 'User/Preferences/Groups/Groups.xml'
            Kind = 'Xml'
            Length = 51
        }
        $arguments = @{
            DirectoryData = $data
            GpoData = $gpoData
            Target = $target
        }
        foreach ($result in @((Invoke-ADAnalyzerAssessment @arguments), $engine.Evaluate($data, $gpoData, $target))) {
            Assert-Equal Partial $result.State
            $credential = $result.Findings | Where-Object RuleId -eq GPO.Preferences.CPassword
            Assert-Equal Unknown $credential.Status
            Assert-Equal $original.CheckId $credential.CheckId
            Assert-True ($null -eq $credential.Observed -and $null -eq $credential.Evidence.SecretPresent) 'Incomplete evidence established absence'
            $coverage = @($result.Findings | Where-Object RuleId -eq GPO.Coverage.MissingXml)
            Assert-Equal 1 $coverage.Count
            Assert-Equal Unknown $coverage[0].Status
            Assert-True ($coverage[0].Observed -is [int] -and $coverage[0].Observed -eq 1) 'Missing XML lost its integer count'
            Assert-Equal 0 $coverage[0].Expected
            Assert-Equal 0 @($result.Checks | Where-Object RuleId -eq GPO.Xml.Readable).Count
        }

        $xml.Xml = '<Groups><User cpasswordPresent="true" /></Groups>'
        $result = Invoke-ADAnalyzerAssessment @arguments
        $json = ConvertTo-Json -InputObject $result -Depth 100
        $decoded = ConvertFrom-Json -InputObject $json
        Assert-Equal Partial $decoded.State
        $positive = $decoded.Findings | Where-Object RuleId -eq GPO.Preferences.CPassword
        Assert-Equal Fail $positive.Status
        Assert-True ($positive.Observed -is [bool] -and $positive.Observed -and
            $positive.Evidence.SecretPresent -is [bool] -and $positive.Evidence.SecretPresent) 'Incomplete coverage erased confirmed presence'
        $gap = $decoded.Findings | Where-Object RuleId -eq GPO.Coverage.MissingXml
        Assert-Equal Unknown $gap.Status
        Assert-Equal 1 $gap.Observed
        Assert-True ($json -notmatch '<Groups') 'Raw XML escaped through the assessment'
    }
    Test-Assessment 'custom GPO comparison distinguishes changed operators, values and registry types' {
        $ruleId = 'GPO.Expected.FixtureLevel'
        $key = 'Software\Fixture'
        $gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Version = 1
            Flags = 0
            Links = @()
        }
        $directory = New-AssessmentFixture
        $inputs = [ordered]@{
            Strict = @{
                Observed = 1
                Operator = 'Minimum'
                Expected = 2
                Status = 'Fail'
            }
            Inverted = @{
                Observed = 1
                Operator = 'Maximum'
                Expected = 2
                Status = 'Pass'
            }
            Relaxed = @{
                Observed = 1
                Operator = 'Minimum'
                Expected = 1
                Status = 'Pass'
            }
            Improved = @{
                Observed = 3
                Operator = 'Minimum'
                Expected = 2
                Status = 'Pass'
            }
            EqualStrict = @{
                Observed = 1
                Expected = [uint32]2
                Status = 'Fail'
            }
            EqualRelaxed = @{
                Observed = 1
                Operator = 'Equals'
                Expected = [int]1
                Status = 'Pass'
            }
            EqualImproved = @{
                Observed = 2
                Operator = 'Equals'
                Expected = [long]2
                Status = 'Pass'
            }
            NotEqualStrict = @{
                Observed = 1
                Operator = 'NotEquals'
                Expected = [uint32]1
                Status = 'Fail'
            }
            NotEqualRelaxed = @{
                Observed = 1
                Operator = 'NotEquals'
                Expected = [int]2
                Status = 'Pass'
            }
            TypeConstraintWrong = @{
                Observed = 1
                Expected = 1
                RuleType = 'REG_SZ'
                Status = 'Invalid'
            }
            TypeConstraintWrongText = @{
                Observed = 1
                Expected = 1
                RuleType = ' +1 '
                Status = 'Invalid'
            }
            TypeConstraintMatched = @{
                Observed = 1
                Expected = 1
                RuleType = 'REG_DWORD'
                Status = 'Pass'
            }
            TypeUnconstrained = @{
                Observed = 1
                Expected = 1
                RuleType = $null
                Status = 'Pass'
            }
            TypeObservationWrong = @{
                Observed = 1
                Expected = 1
                RuleType = [long]4
                ObservedType = [uint32]5
                Status = 'Invalid'
            }
            TypeObservationWrongText = @{
                Observed = 1
                Expected = 1
                RuleType = ' +4 '
                ObservedType = [uint32]5
                Status = 'Invalid'
            }
            UserTypeWrong = @{
                Observed = 1
                Expected = 1
                RuleType = 1
                UserPolicy = $true
                Status = 'Invalid'
            }
            UserTypeMatched = @{
                Observed = 1
                Expected = 1
                RuleType = 4
                UserPolicy = $true
                Status = 'Pass'
            }
            AggregateLow = @{
                Observed = 1
                Operator = 'Equals'
                Expected = @([uint32]3)
                Status = 'Fail'
                Aggregate = $true
            }
            AggregateHigh = @{
                Observed = 3
                Operator = 'Equals'
                Expected = @([uint32]3)
                Status = 'Pass'
                Aggregate = $true
            }
        }
        $assessments = @{}
        $checks = @{}
        $paths = @{}
        $pathHashes = @{}
        foreach ($name in $inputs.Keys) {
            $inputCase = $inputs[$name]
            $policy = New-PolicyFixture
            $policy.RegistrySettings = @([pscustomobject]@{
                    Hive = 'HKLM'
                    Scope = 'Computer'
                    Key = $key
                    ValueName = 'Level'
                    Value = [uint32]$inputCase.Observed
                    Type = 4
                    Source = 'Machine/Registry.pol'
                    KeyOnly = $false
                })
            if ($inputCase.ContainsKey('ObservedType')) {
                $policy.RegistrySettings[0].Type = $inputCase.ObservedType
            }
            if ($inputCase.UserPolicy) {
                $policy.RegistrySettings[0].Hive = 'HKCU'
                $policy.RegistrySettings[0].Scope = 'User'
                $policy.RegistrySettings[0].Source = 'User/Registry.pol'
            }
            $rule = @{
                Id = 'FixtureLevel'
                Hive = $policy.RegistrySettings[0].Hive
                Key = $key
                ValueName = 'Level'
                Expected = $inputCase.Expected
                Type = 4
            }
            $operator = 'Equals'
            if ($inputCase.ContainsKey('Operator')) {
                $operator = $inputCase.Operator
                $rule.Operator = $operator
            }
            if ($inputCase.ContainsKey('Aggregate')) {
                $rule.Aggregate = $true
            }
            if ($inputCase.ContainsKey('RuleType')) {
                if ($null -eq $inputCase.RuleType) {
                    $rule.Remove('Type')
                }
                else {
                    $rule.Type = $inputCase.RuleType
                }
            }
            $arguments = @{
                DirectoryData = $directory
                GpoData = @([pscustomobject]@{
                        Gpo = $gpo
                        Policy = $policy
                    })
                Profile = @{ RegistryRules = @($rule) }
            }
            $assessments[$name] = Invoke-ADAnalyzerAssessment @arguments
            $ruleChecks = @($assessments[$name].Checks | Where-Object RuleId -eq $ruleId)
            Assert-Equal 1 $ruleChecks.Count
            $checks[$name] = $ruleChecks[0]
            Assert-Equal $inputCase.Status $ruleChecks[0].Status
            Assert-Equal $inputCase.Observed (@($ruleChecks[0].Observed)[0])
            Assert-Equal $operator $ruleChecks[0].Evidence.Operator
        }
        foreach ($name in @(
            'Inverted'
            'Relaxed'
            'Improved'
            'EqualStrict'
            'EqualRelaxed'
            'EqualImproved'
            'NotEqualStrict'
            'NotEqualRelaxed'
            'TypeConstraintWrong'
            'TypeConstraintWrongText'
            'TypeConstraintMatched'
            'TypeUnconstrained'
            'TypeObservationWrong'
            'TypeObservationWrongText'
        )) {
            Assert-Equal $checks.Strict.CheckId $checks[$name].CheckId
        }
        Assert-Equal $checks.AggregateLow.CheckId $checks.AggregateHigh.CheckId
        Assert-Equal $checks.UserTypeWrong.CheckId $checks.UserTypeMatched.CheckId
        Assert-Equal User $checks.UserTypeWrong.Evidence.Scope
        Assert-Equal 'User/Registry.pol' $checks.UserTypeWrong.Evidence.Path
        Assert-Equal 1 $checks.TypeConstraintWrong.Evidence.ExpectedRegistryType
        Assert-True ($checks.TypeConstraintWrongText.Evidence.ExpectedRegistryType -is [string]) 'The evaluator did not retain the numeric type text'
        Assert-Equal ' +1 ' $checks.TypeConstraintWrongText.Evidence.ExpectedRegistryType
        Assert-Equal 4 $checks.TypeConstraintMatched.Evidence.ExpectedRegistryType
        Assert-Equal 4 $checks.TypeConstraintWrong.Evidence.RegistryType
        Assert-Equal 4 $checks.TypeConstraintMatched.Evidence.RegistryType
        Assert-Equal 5 $checks.TypeObservationWrong.Evidence.RegistryType
        Assert-Equal $null (Get-ADAnalyzerOperationValue $checks.TypeUnconstrained.Evidence @('ExpectedRegistryType') ([object]::new()))

        $assessments.Legacy = [pscustomobject]@{
            SchemaVersion = 1
            Target = $assessments.Strict.Target
            Checks = @([pscustomobject]@{
                    RuleId = $ruleId
                    Target = $checks.Relaxed.Target
                    Status = $checks.Relaxed.Status
                    Observed = $checks.Relaxed.Observed
                    Expected = $checks.Relaxed.Expected
                })
        }
        $legacyEqual = $checks.EqualRelaxed.PSObject.Copy()
        $legacyEqual.PSObject.Properties.Remove('Expected')
        $assessments.LegacyEqual = [pscustomobject]@{
            SchemaVersion = 1
            Target = $assessments.Strict.Target
            Checks = @($legacyEqual)
        }
        $legacyType = $checks.TypeConstraintMatched.PSObject.Copy()
        $legacyType.Evidence = [pscustomobject]@{
            Path = $checks.TypeConstraintMatched.Evidence.Path
            Scope = $checks.TypeConstraintMatched.Evidence.Scope
            Operator = $checks.TypeConstraintMatched.Evidence.Operator
            RegistryType = $checks.TypeConstraintMatched.Evidence.RegistryType
        }
        $assessments.LegacyType = [pscustomobject]@{
            SchemaVersion = 1
            Target = $assessments.Strict.Target
            Checks = @($legacyType)
        }
        $unknown = $checks.Relaxed.PSObject.Copy()
        $unknown.Status = 'Unknown'
        $assessments.Unknown = [pscustomobject]@{
            SchemaVersion = 1
            Target = $assessments.Strict.Target
            Checks = @($unknown)
        }
        $assessments.Unobserved = [pscustomobject]@{
            SchemaVersion = 1
            Target = $assessments.Strict.Target
            Checks = @()
        }

        foreach ($name in $assessments.Keys) {
            $paths[$name] = Join-Path $temp ('gpo-compare-predicate-' + $name + '.json')
            $null = Export-ADAnalyzerAssessment -Assessment $assessments[$name] -Path $paths[$name] -Format Json -Confirm:$false
            $pathHashes[$name] = (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }
        $comparer = [ADAnalyzerAssessmentComparer]::new()
        $cases = @(
            @('Strict', 'Inverted', 'Changed', 'RulePredicateChanged'),
            @('Strict', 'Relaxed', 'Changed', 'RulePredicateChanged'),
            @('Relaxed', 'Strict', 'Changed', 'RulePredicateChanged'),
            @('Strict', 'Improved', 'Resolved', $null),
            @('EqualStrict', 'EqualRelaxed', 'Changed', 'RulePredicateChanged'),
            @('EqualRelaxed', 'EqualStrict', 'Changed', 'RulePredicateChanged'),
            @('EqualStrict', 'EqualImproved', 'Resolved', $null),
            @('NotEqualStrict', 'NotEqualRelaxed', 'Changed', 'RulePredicateChanged'),
            @('NotEqualRelaxed', 'NotEqualStrict', 'Changed', 'RulePredicateChanged'),
            @('EqualStrict', 'LegacyEqual', 'Resolved', $null),
            @('TypeConstraintWrongText', 'TypeConstraintMatched', 'Changed', 'RulePredicateChanged'),
            @('TypeConstraintWrong', 'TypeConstraintMatched', 'Changed', 'RulePredicateChanged'),
            @('TypeConstraintMatched', 'TypeConstraintWrong', 'Changed', 'RulePredicateChanged'),
            @('TypeConstraintWrong', 'TypeUnconstrained', 'Changed', 'RulePredicateChanged'),
            @('TypeUnconstrained', 'TypeConstraintWrong', 'Changed', 'RulePredicateChanged'),
            @('TypeObservationWrong', 'TypeConstraintMatched', 'Resolved', $null),
            @('TypeObservationWrongText', 'TypeConstraintMatched', 'Resolved', $null),
            @('TypeConstraintWrong', 'LegacyType', 'Resolved', $null),
            @('UserTypeWrong', 'UserTypeMatched', 'Changed', 'RulePredicateChanged'),
            @('AggregateLow', 'AggregateHigh', 'Resolved', $null),
            @('Strict', 'Legacy', 'Resolved', $null),
            @('Strict', 'Unknown', 'Changed', $null),
            @('Strict', 'Unobserved', 'Changed', 'NotObservedInDifference'),
            @('Unobserved', 'Strict', 'New', $null)
        )
        foreach ($documents in @($assessments, $paths)) {
            foreach ($case in $cases) {
                $before, $after, $expectedChange, $expectedReason = $case
                $arguments = @{
                    Reference = $documents[$before]
                    Difference = $documents[$after]
                }
                $commandResult = Compare-ADAnalyzerAssessment @arguments
                $classResult = $comparer.Compare($arguments.Reference, $arguments.Difference)
                foreach ($result in @($commandResult, $classResult)) {
                    $changes = @($result.Changes | Where-Object RuleId -eq $ruleId)
                    Assert-Equal 1 $changes.Count
                    Assert-True ($changes[0].Change -eq $expectedChange) (
                        "Comparison $before to $after expected $expectedChange, received $($changes[0].Change)"
                    )
                    Assert-Equal $expectedReason $changes[0].Reason
                    if ($before -eq 'Unobserved') {
                        Assert-Equal 0 $changes[0].Reference.Count
                    }
                    else {
                        Assert-Equal $checks[$before].Status $changes[0].Reference[0].Status
                    }
                    if ($after -eq 'Unobserved') {
                        Assert-Equal 0 $changes[0].Difference.Count
                    }
                    else {
                        Assert-Equal 1 $changes[0].Difference.Count
                    }
                }
            }
        }
        foreach ($name in $paths.Keys) {
            Assert-Equal $pathHashes[$name] (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }
    }
    Test-Assessment 'comparison qualifies changes only on the recorded mismatched Registry.pol side' {
        $gpoId = [guid]'11111111-1111-1111-1111-111111111111'
        $otherId = [guid]'22222222-2222-2222-2222-222222222222'
        # Directory encodes 0x80010002 as a signed DWORD. User and Computer occupy different halves.
        $directoryVersion = [int]-2147418110
        $consistentVersion = [uint32]2147549186
        $computerMismatch = [uint32]2147549187
        $userMismatch = [uint32]2147614722
        $key = 'Software\Fixture'
        $directory = New-AssessmentFixture
        $versionRule = 'GPO.VERSION_CONSISTENCY'

        $makeSnapshot = {
            param(
                [uint32]$Value,
                $SysvolVersion,
                [uint32]$Expected = 2,
                [switch]$OtherMismatch,
                $Identity = $gpoId
            )

            $gpo = [pscustomobject]@{
                Id = $Identity
                Flags = 0
                Version = $directoryVersion
                Links = @()
            }
            $policy = New-PolicyFixture
            $policy.SysvolVersion = $SysvolVersion
            $policy.RegistrySettings = @(
                [pscustomobject]@{
                    Hive = 'HKLM'
                    Scope = 'Computer'
                    Key = $key
                    ValueName = 'Level'
                    Value = $Value
                    Type = 4
                    Source = 'Machine/Registry.pol'
                }
                [pscustomobject]@{
                    Hive = 'HKCU'
                    Scope = 'User'
                    Key = $key
                    ValueName = 'Level'
                    Value = $Value
                    Type = 4
                    Source = 'User/Registry.pol'
                }
            )
            $policies = @([pscustomobject]@{ Gpo = $gpo; Policy = $policy })
            if ($OtherMismatch) {
                $other = [pscustomobject]@{ Id = $otherId; Flags = 0; Version = 1; Links = @() }
                $otherPolicy = New-PolicyFixture
                $otherPolicy.SysvolVersion = [uint32]2
                $policies += [pscustomobject]@{ Gpo = $other; Policy = $otherPolicy }
            }
            $rules = @(
                @{ Id = 'FixtureComputerVersion'; Hive = 'HKLM'; Key = $key; ValueName = 'Level'; Expected = $Expected }
                @{ Id = 'FixtureUserVersion'; Hive = 'HKCU'; Key = $key; ValueName = 'Level'; Expected = $Expected }
            )
            Invoke-ADAnalyzerAssessment -DirectoryData $directory -GpoData $policies -Profile @{ RegistryRules = $rules }
        }

        $snapshots = [ordered]@{
            Before = & $makeSnapshot 1 $consistentVersion
            Healthy = & $makeSnapshot 2 $consistentVersion
            ComputerMismatch = & $makeSnapshot 2 $computerMismatch
            UserMismatch = & $makeSnapshot 2 $userMismatch
            EarlierMismatch = & $makeSnapshot 1 $computerMismatch
            UnrelatedMismatch = & $makeSnapshot 2 $consistentVersion -OtherMismatch
            UnknownVersion = & $makeSnapshot 2 $null
            ChangedPredicate = & $makeSnapshot 1 $computerMismatch -Expected 1
        }
        $gpoVersionTarget = [string]$gpoId + '/Version'
        foreach ($entry in $snapshots.GetEnumerator()) {
            $version = @($entry.Value.Checks | Where-Object {
                    $_.RuleId -eq $versionRule -and $_.Target -eq $gpoVersionTarget
                })
            Assert-Equal 1 $version.Count
            Assert-Equal $directoryVersion $version[0].Expected
            $expectedVersionStatus = switch ($entry.Key) {
                { $_ -in 'Before', 'Healthy', 'UnrelatedMismatch' } { 'Pass' }
                'UnknownVersion' { 'Unknown' }
                default { 'Fail' }
            }
            Assert-Equal $expectedVersionStatus $version[0].Status
        }
        Assert-Equal 'Fail' ($snapshots.UnrelatedMismatch.Checks | Where-Object {
                $_.RuleId -eq $versionRule -and $_.Target -eq ([string]$otherId + '/Version')
            }).Status

        $snapshots.DisplayNameBefore = & $makeSnapshot 1 $consistentVersion -Identity 'Fixture GPO'
        $snapshots.DisplayNameAfter = & $makeSnapshot 2 $computerMismatch -Identity 'Fixture GPO'
        $mismatchedVersionRow = $snapshots.ComputerMismatch.Checks | Where-Object RuleId -eq $versionRule
        $snapshots.Legacy = $snapshots.ComputerMismatch.PSObject.Copy()
        $snapshots.Legacy.Checks = @($snapshots.ComputerMismatch.Checks | Where-Object RuleId -ne $versionRule)
        $snapshots.Ambiguous = $snapshots.ComputerMismatch.PSObject.Copy()
        $snapshots.Ambiguous.Checks = @($snapshots.ComputerMismatch.Checks) + @($mismatchedVersionRow)
        $malformedVersion = $mismatchedVersionRow.PSObject.Copy()
        $malformedVersion.Observed = [string]$malformedVersion.Observed
        $snapshots.Malformed = $snapshots.Legacy.PSObject.Copy()
        $snapshots.Malformed.Checks = @($snapshots.Legacy.Checks) + @($malformedVersion)

        $paths = @{}
        $hashes = @{}
        $originals = @{}
        foreach ($name in $snapshots.Keys) {
            $originals[$name] = ConvertTo-Json -InputObject $snapshots[$name] -Depth 100 -Compress
            $paths[$name] = Join-Path $temp ('gpo-version-comparison-' + $name + '.json')
            $null = Export-ADAnalyzerAssessment -Assessment $snapshots[$name] -Path $paths[$name] -Format Json -Confirm:$false
            $hashes[$name] = (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }

        $comparer = [ADAnalyzerAssessmentComparer]::new()
        $cases = @(
            @('Before', 'ComputerMismatch', 'Computer', 'Fail', 'Pass', 'Changed', 'PolicyVersionMismatch'),
            @('ComputerMismatch', 'Before', 'Computer', 'Pass', 'Fail', 'Changed', 'PolicyVersionMismatch'),
            @('EarlierMismatch', 'Healthy', 'Computer', 'Fail', 'Pass', 'Changed', 'PolicyVersionMismatch'),
            @('Before', 'UserMismatch', 'User', 'Fail', 'Pass', 'Changed', 'PolicyVersionMismatch'),
            @('Before', 'ComputerMismatch', 'User', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'UserMismatch', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'Healthy', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Healthy', 'Before', 'Computer', 'Pass', 'Fail', 'New', $null),
            @('Before', 'UnrelatedMismatch', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'UnknownVersion', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'Legacy', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'Ambiguous', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'Malformed', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('DisplayNameBefore', 'DisplayNameAfter', 'Computer', 'Fail', 'Pass', 'Resolved', $null),
            @('Before', 'ChangedPredicate', 'Computer', 'Fail', 'Pass', 'Changed', 'RulePredicateChanged')
        )
        foreach ($documents in @($snapshots, $paths)) {
            foreach ($case in $cases) {
                $before, $after, $side, $beforeStatus, $afterStatus, $expectedChange, $expectedReason = $case
                $ruleId = 'GPO.Expected.Fixture' + $side + 'Version'
                $reference = $snapshots[$before].Checks | Where-Object RuleId -eq $ruleId
                $difference = $snapshots[$after].Checks | Where-Object {
                    $_.RuleId -eq $ruleId -and $_.Target -eq $reference.Target
                }
                Assert-Equal $reference.CheckId $difference.CheckId
                Assert-Equal $beforeStatus $reference.Status
                Assert-Equal $afterStatus $difference.Status
                $command = Compare-ADAnalyzerAssessment -Reference $documents[$before] -Difference $documents[$after]
                $direct = $comparer.Compare($documents[$before], $documents[$after])
                foreach ($result in @($command, $direct)) {
                    $changes = @($result.Changes | Where-Object {
                            $_.RuleId -eq $ruleId -and $_.Target -eq $reference.Target
                        })
                    Assert-Equal 1 $changes.Count
                    $change = $changes[0]
                    Assert-True ($change.Change -eq $expectedChange -and $change.Reason -eq $expectedReason) (
                        "Comparison $before to $after ($side) expected $expectedChange/$expectedReason, received $($change.Change)/$($change.Reason)"
                    )
                    Assert-Equal $beforeStatus $change.Reference[0].Status
                    Assert-Equal $afterStatus $change.Difference[0].Status
                    Assert-Equal $reference.Observed $change.Reference[0].Observed
                    Assert-Equal $difference.Observed $change.Difference[0].Observed
                }
            }
        }

        $report = $snapshots.ComputerMismatch.PSObject.Copy()
        $report | Add-Member -NotePropertyName Comparison -NotePropertyValue (
            Compare-ADAnalyzerAssessment -Reference $paths.Before -Difference $paths.ComputerMismatch
        )
        $htmlPath = Join-Path $temp 'gpo-version-comparison.html'
        $null = Export-ADAnalyzerAssessment -Assessment $report -Path $htmlPath -Format Html -Confirm:$false
        $html = Get-Content -LiteralPath $htmlPath -Raw
        Assert-True ($html.Contains('PolicyVersionMismatch Check the recorded directory and SYSVOL versions for this policy side.')) (
            'HTML did not explain the recorded policy-side version mismatch'
        )
        foreach ($name in $snapshots.Keys) {
            Assert-Equal $originals[$name] (ConvertTo-Json -InputObject $snapshots[$name] -Depth 100 -Compress)
            Assert-Equal $hashes[$name] (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }
    }
    Test-Assessment 'report exports preserve the selected saved assessment source' {
        $directory = Join-Path $temp 'report source preservation'
        $null = [IO.Directory]::CreateDirectory($directory)
        $null = [IO.Directory]::CreateDirectory((Join-Path $directory 'subfolder'))
        $leaf = 'source [literal].json'
        $source = Join-Path $directory $leaf
        $content = '{"SchemaVersion":1,"Target":"artifact.example.invalid","Checks":[],"Findings":[]}'
        $encoding = [Text.UTF8Encoding]::new($false)
        [IO.File]::WriteAllText($source, $content, $encoding)
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash

        # The reader accepts JSON by content regardless of the extension.
        $prefix = Join-Path $directory 'report [literal]'
        $priorOutput = $prefix + '.json'
        $laterSource = $prefix + '.html'
        $laterOutput = $prefix + '.csv'
        [IO.File]::WriteAllText($priorOutput, 'prior report bytes', $encoding)
        [IO.File]::WriteAllText($laterSource, $content, $encoding)
        $priorHash = (Get-FileHash -LiteralPath $priorOutput -Algorithm SHA256).Hash
        $laterHash = (Get-FileHash -LiteralPath $laterSource -Algorithm SHA256).Hash

        $report = [ADAnalyzerAssessmentReport]::new()
        $routes = [ordered]@{
            Command = {
                param($InputFile, $OutputPath, $Format, $Preview, $ErrorMode = 'Stop')

                $exportParameters = @{
                    Assessment = $InputFile
                    Path = $OutputPath
                    Format = $Format
                    Confirm = $false
                    WhatIf = $Preview
                    ErrorAction = $ErrorMode
                }
                Export-ADAnalyzerAssessment @exportParameters
            }
            Direct = {
                param($InputFile, $OutputPath, $Format, $Preview)
                $report.Write($InputFile, $OutputPath, $Format, $Preview)
            }
        }
        $assertCollision = {
            param($InvokeExport, $InputFile, $OutputPath, $Format, $Case, $ErrorMode = 'Stop')

            $failure = $null
            $paths = [Collections.Generic.List[object]]::new()
            try {
                & $InvokeExport $InputFile $OutputPath $Format $false $ErrorMode | ForEach-Object {
                    $paths.Add($_)
                }
            }
            catch {
                $failure = $_
            }
            Assert-True ($null -ne $failure -and
                $failure.Exception.GetBaseException().Message -ceq 'A report destination matches the saved assessment source.') (
                "Expected report source collision rejection for $Case"
            )
            Assert-Equal 0 $paths.Count
        }

        $driveName = 'ADReportSourceFixture'
        $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $directory -Scope Script -ErrorAction Stop
        try {
            Push-Location -LiteralPath $directory
            try {
                $separator = [IO.Path]::DirectorySeparatorChar
                $relative = 'subfolder' + $separator + '..' + $separator + $leaf
                $mapped = $driveName + ':' + $separator + $leaf
                $qualified = 'FileSystem::' + $source
                $aliases = @(
                    @('literal', $source, $source),
                    @('relative destination', $source, $relative),
                    @('mapped input', $mapped, $source),
                    @('qualified destination', $source, $qualified)
                )
                if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                    $aliases += , @('Windows case alias', $source, (Join-Path $directory $leaf.ToUpperInvariant()))
                }

                foreach ($entry in $routes.GetEnumerator()) {
                    foreach ($case in $aliases) {
                        $label, $inputFile, $outputPath = $case
                        & $assertCollision $entry.Value $inputFile $outputPath 'Json' ($entry.Key + ' ' + $label)
                        Assert-Equal $sourceHash (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
                    }
                    & $assertCollision $entry.Value $laterSource $prefix 'All' ($entry.Key + ' later format')
                    if ($entry.Key -eq 'Command') {
                        & $assertCollision $entry.Value $laterSource $prefix 'All' 'Command later format under Continue' 'Continue'
                    }
                    Assert-Equal $laterHash (Get-FileHash -LiteralPath $laterSource -Algorithm SHA256).Hash
                    Assert-Equal $priorHash (Get-FileHash -LiteralPath $priorOutput -Algorithm SHA256).Hash
                    Assert-True (-not [IO.File]::Exists($laterOutput)) 'The rejected All export wrote a later sibling.'

                    $preview = @(& $entry.Value $laterSource $prefix 'All' $true)
                    Assert-Equal 0 $preview.Count
                    Assert-Equal $laterHash (Get-FileHash -LiteralPath $laterSource -Algorithm SHA256).Hash
                    Assert-Equal $priorHash (Get-FileHash -LiteralPath $priorOutput -Algorithm SHA256).Hash
                    Assert-True (-not [IO.File]::Exists($laterOutput)) 'The All preview wrote a later sibling.'

                    $unsupported = Join-Path $directory 'unsupported.json'
                    [IO.File]::WriteAllText($unsupported, '{"SchemaVersion":2}', $encoding)
                    Assert-Throws { & $entry.Value $unsupported $prefix 'All' $true }

                    $distinct = Join-Path $directory ($entry.Key + ' destination.json')
                    [IO.File]::WriteAllText($distinct, 'old destination bytes', $encoding)
                    $written = @(& $entry.Value $source $distinct 'Json' $false)
                    Assert-Equal 1 $written.Count
                    $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($distinct))
                    Assert-Equal 'artifact.example.invalid' $saved.Target
                    Assert-Equal $sourceHash (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
                }

                $invalidDestinationFailure = $null
                try {
                    $null = & $routes.Command $source 'Variable:ADReportSourceFixtureInvalid' 'Json' $false
                }
                catch {
                    $invalidDestinationFailure = $_
                }
                Assert-True ($null -ne $invalidDestinationFailure -and
                    $invalidDestinationFailure.Exception.GetBaseException().Message -ceq
                    'Report paths must use the FileSystem provider') 'Expected the existing non-FileSystem destination error.'
                Assert-Equal $sourceHash (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
            }
            finally {
                Pop-Location
            }
        }
        finally {
            Remove-PSDrive -Name $driveName -Scope Script -Force -ErrorAction Stop
        }
    }
    Test-Assessment 'create-only JSON export preserves existing bytes and honors preview' {
        $directory = Join-Path $temp 'create-only JSON'
        $null = [IO.Directory]::CreateDirectory($directory)
        $document = [pscustomobject]@{
            SchemaVersion = 1
            Target = 'assessment-' + [char]233 + '.example.invalid'
            Checks = @()
            Findings = @()
        }
        $report = [ADAnalyzerAssessmentReport]::new()
        $routes = [ordered]@{
            Native = {
                param($InputDocument, $Destination, [bool]$Preview)

                $parameters = @{
                    Assessment = $InputDocument
                    Path = $Destination
                    Format = 'Json'
                    CreateOnly = $true
                    Confirm = $false
                    WhatIf = $Preview
                    ErrorAction = 'Stop'
                }
                Export-ADAnalyzerAssessment @parameters
            }
            Direct = {
                param($InputDocument, $Destination, [bool]$Preview)

                if ($Preview) {
                    $report.WriteNew($InputDocument, $Destination, $true)
                }
                else {
                    $report.WriteNew($InputDocument, $Destination)
                }
            }
        }
        Assert-True ((Get-Command Export-ADAnalyzerAssessment).Parameters.ContainsKey('CreateOnly')) (
            'The native exporter has no create-only option.'
        )
        Assert-True ($null -ne $report.PSObject.Methods['WriteNew']) (
            'The direct report API has no create-only method.'
        )

        foreach ($route in $routes.GetEnumerator()) {
            $previewParent = Join-Path $directory ($route.Key + ' preview')
            $previewPath = Join-Path $previewParent 'assessment [literal].json'
            $preview = @(& $route.Value $document $previewPath $true)
            Assert-Equal 0 $preview.Count
            Assert-True (-not [IO.Directory]::Exists($previewParent)) 'Preview created a destination directory.'
            $invalidProviderPreview = @(& $route.Value $document 'Variable:ADAnalyzerCreateOnlyFixture' $true)
            Assert-Equal 0 $invalidProviderPreview.Count
            Assert-Throws { & $route.Value ([pscustomobject]@{ SchemaVersion = 2 }) $previewPath $true }
            Assert-True (-not [IO.Directory]::Exists($previewParent)) 'Invalid preview created a destination directory.'

            $path = Join-Path $directory ($route.Key + ' assessment [literal].json')
            $published = @(& $route.Value $document $path $false)
            Assert-Equal 1 $published.Count
            Assert-Equal $path $published[0]
            $bytes = [IO.File]::ReadAllBytes($path)
            Assert-True (
                $bytes.Length -gt 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
            ) 'The JSON writer did not preserve its UTF-8 BOM.'
            $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path))
            Assert-Equal $document.Target $saved.Target
            $original = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            $replacement = [pscustomobject]@{
                SchemaVersion = 1
                Target = 'replacement.example.invalid'
            }

            $failure = $null
            $unexpectedPaths = [Collections.Generic.List[object]]::new()
            try {
                & $route.Value $replacement $path $false | ForEach-Object {
                    $unexpectedPaths.Add($_)
                }
            }
            catch {
                $failure = $_
            }
            Assert-True (
                $null -ne $failure -and
                $failure.Exception.GetBaseException().Message -ceq 'The report destination already exists.'
            ) ('Expected the create-only conflict diagnostic for ' + $route.Key)
            Assert-Equal 0 $unexpectedPaths.Count
            Assert-Equal $original (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash

            $sourceOverlap = $null
            try {
                $null = & $route.Value $path $path $false
            }
            catch {
                $sourceOverlap = $_
            }
            Assert-True (
                $null -ne $sourceOverlap -and
                $sourceOverlap.Exception.GetBaseException().Message -ceq 'A report destination matches the saved assessment source.'
            ) ('Create-only export lost the saved source protection for ' + $route.Key)
            Assert-Equal $original (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash

            if ($route.Key -eq 'Native') {
                $overwritten = @(Export-ADAnalyzerAssessment -Assessment $replacement -Path $path -Format Json -Confirm:$false)
            }
            else {
                $overwritten = @($report.Write($replacement, $path, 'Json'))
            }
            Assert-Equal 1 $overwritten.Count
            Assert-Equal $path $overwritten[0]
            $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path))
            Assert-Equal $replacement.Target $saved.Target
        }
        foreach ($format in 'Html', 'Csv', 'All') {
            $invalidParent = Join-Path $directory ('invalid ' + $format)
            $invalidPath = Join-Path $invalidParent 'report'
            $failure = $null
            try {
                $null = Export-ADAnalyzerAssessment -Assessment $document -Path $invalidPath -Format $format -CreateOnly -Confirm:$false
            }
            catch {
                $failure = $_
            }
            Assert-True (
                $null -ne $failure -and
                $failure.Exception.GetBaseException().Message -match 'CreateOnly.*Json|Json.*CreateOnly'
            ) ('Create-only export did not identify the unsupported ' + $format + ' format.')
            Assert-True (-not [IO.Directory]::Exists($invalidParent)) 'Invalid create-only format created a destination directory.'
        }
        Assert-Equal 0 @(Get-ChildItem -LiteralPath $directory -Force -Filter '.ad-analyzer-*.tmp').Count
    }
    Test-Assessment 'create-only export preserves a staging file it could not open' {
        $directory = Join-Path $temp 'create-only staging ownership'
        $null = [IO.Directory]::CreateDirectory($directory)
        $destination = Join-Path $directory 'report.json'
        $sentinel = [byte[]]@(0, 1, 239, 255)
        $state = [pscustomobject]@{
            StagePath = $null
            Failure = $null
            OutputPaths = [Collections.Generic.List[object]]::new()
        }
        try {
            & {
                # Restrict the shadow to this one write and its private staging directory.
                function Join-Path {
                    [CmdletBinding()]
                    param(
                        [Parameter(Mandatory, Position = 0)][string[]]$Path,
                        [Parameter(Mandatory, Position = 1)][string]$ChildPath
                    )

                    $resolved = Microsoft.PowerShell.Management\Join-Path @PSBoundParameters
                    if ($Path.Count -eq 1 -and $Path[0] -eq $directory -and $ChildPath -like '.ad-analyzer-*.tmp') {
                        Assert-True ($null -eq $state.StagePath -and -not [IO.File]::Exists($resolved)) (
                            'Unexpected staging retry or fixture name collision.'
                        )
                        [IO.File]::WriteAllBytes($resolved, $sentinel)
                        $state.StagePath = $resolved
                    }
                    return $resolved
                }

                $parameters = @{
                    Assessment = [pscustomobject]@{
                        SchemaVersion = 1
                        Target = 'stage-ownership.example.invalid'
                    }
                    Path = $destination
                    Format = 'Json'
                    CreateOnly = $true
                    Confirm = $false
                    ErrorAction = 'Stop'
                }
                try {
                    Export-ADAnalyzerAssessment @parameters | ForEach-Object {
                        $state.OutputPaths.Add($_)
                    }
                }
                catch {
                    $state.Failure = $_
                }
            }
            Assert-True ($null -ne $state.StagePath) 'The staging-name fault was not exercised.'
            Assert-True (
                $null -ne $state.Failure -and $state.Failure.Exception.GetBaseException() -is [IO.IOException]
            ) 'Create-only export did not report the failed staging open.'
            Assert-Equal 0 $state.OutputPaths.Count
            Assert-True (-not [IO.File]::Exists($destination)) 'A failed staging open published a report.'
            Assert-True ([IO.File]::Exists($state.StagePath)) 'The writer removed a staging file it never owned.'
            Assert-Equal ([Convert]::ToBase64String($sentinel)) (
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($state.StagePath))
            )
        }
        finally {
            if ($null -ne $state.StagePath) {
                [IO.File]::Delete($state.StagePath)
            }
        }
        Assert-Equal 0 @([IO.Directory]::GetFileSystemEntries($directory)).Count
    }
    Test-Assessment 'overlapping create-only writers publish one complete JSON report' {
        $directory = Join-Path $temp 'create-only concurrency'
        $null = [IO.Directory]::CreateDirectory($directory)
        $destination = Join-Path $directory 'shared [literal].json'
        $fixture = Join-Path $RepositoryRoot 'tests/AssessmentCreateOnlyWorker.ps1'
        $engine = (Get-Process -Id $PID).Path
        $workers = [ordered]@{}
        try {
            foreach ($role in 'Native', 'Direct') {
                $arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}" -RepositoryRoot "{1}" -Destination "{2}" -Coordination "{3}" -Role {4}' -f
                    $fixture, $RepositoryRoot, $destination, $directory, $role
                $parameters = @{
                    FilePath = $engine
                    ArgumentList = $arguments
                    PassThru = $true
                    RedirectStandardOutput = Join-Path $directory ($role + '.out')
                    RedirectStandardError = Join-Path $directory ($role + '.err')
                }
                $process = Start-Process @parameters
                $workers[$role] = $process
                # Windows PowerShell needs the process handle cached before exit.
                $null = $process.Handle
            }

            $stages = [Collections.Generic.List[string]]::new()
            $watch = [Diagnostics.Stopwatch]::StartNew()
            foreach ($role in $workers.Keys) {
                $readyPath = Join-Path $directory ($role + '.ready')
                $process = $workers[$role]
                while (-not [IO.File]::Exists($readyPath) -and -not $process.HasExited) {
                    Assert-True ($watch.Elapsed.TotalSeconds -lt 30) ('Timed out waiting for ' + $role + ' to reach staging.')
                    Start-Sleep -Milliseconds 25
                }
                if ($process.HasExited) {
                    throw ('Fixture ' + $role + ' exited before release. ' +
                        [IO.File]::ReadAllText((Join-Path $directory ($role + '.err'))))
                }
            }
            Assert-True (-not [IO.File]::Exists($destination)) 'A writer published before both reached the staging boundary.'

            foreach ($role in $workers.Keys) {
                $releasePath = Join-Path $directory ($role + '.release')
                [IO.File]::WriteAllText($releasePath, 'release')
                $process = $workers[$role]
                Assert-True ($process.WaitForExit(20000)) ('Timed out waiting for ' + $role + ' to finish.')
                $process.WaitForExit()
                $stages.Add([IO.File]::ReadAllText((Join-Path $directory ($role + '.ready'))))
                $processOutput = [IO.File]::ReadAllText((Join-Path $directory ($role + '.out'))).Trim()
                $processError = [IO.File]::ReadAllText((Join-Path $directory ($role + '.err'))).Trim()
                if ($role -eq 'Native') {
                    Assert-True ($process.ExitCode -eq 0 -and $processOutput -ceq 'Published') (
                        'The first fixture writer did not publish. ' + $processError
                    )
                    $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($destination))
                    Assert-Equal 'Native.example.invalid' $saved.Target
                    Assert-Equal ('Native|' * 1024) $saved.Payload
                    $publishedHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
                }
                else {
                    Assert-True ($process.ExitCode -eq 4 -and $processOutput -ceq 'The report destination already exists.') (
                        'The competing writer did not report a create-only conflict. ' + $processError
                    )
                    Assert-Equal $publishedHash (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
                }
            }
            Assert-True ($stages[0] -cne $stages[1]) 'The workers shared a staging path.'
            foreach ($stage in $stages) {
                Assert-True (-not [IO.File]::Exists($stage)) 'An owned staging file remained after the writer exited.'
            }
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $directory -Force -Filter '*.json').Count
            Assert-Equal 0 @(Get-ChildItem -LiteralPath $directory -Force -Filter '.ad-analyzer-*.tmp').Count
        }
        finally {
            foreach ($process in $workers.Values) {
                try {
                    if (-not $process.HasExited) {
                        $process.Kill()
                        $null = $process.WaitForExit(5000)
                    }
                }
                finally {
                    $process.Dispose()
                }
            }
        }
    }
    Test-Assessment 'SYSVOL version mismatch and policy read errors remain explicit' {
        $policy = New-PolicyFixture
        $policy.SysvolVersion = 2
        $gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Flags = 0
            Version = 1
            Links = @()
        }
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $policy
                Error = $null
            })
        Assert-Equal Fail ($result.Checks | Where-Object RuleId -eq GPO.VERSION_CONSISTENCY).Status
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $null
                Error = 'fixture SYSVOL denied'
            })
        Assert-Equal Unreadable ($result.Checks | Where-Object RuleId -eq GPO.READ).Status
        Assert-Equal Partial $result.State
    }
    Test-Assessment 'named XML secrets remain boolean findings through assessment and all exports' {
        $policy = New-PolicyFixture
        $policy.XmlFiles = @([pscustomobject]@{
                Scope = 'Computer'
                Kind = 'Preferences'
                Path = 'Machine/Preferences/Registry.xml'
                Xml = '<RegistrySettings><Registry uid="one"><Properties name="DefaultPassword" value="unit2-assessment-secret"/></Registry></RegistrySettings>'
            })
        $gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Flags = 0
            Version = 1
            Links = @()
        }
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $policy
                Error = $null
            })
        $finding = $result.Findings | Where-Object RuleId -eq GPO.StoredSecret
        Assert-Equal Fail $finding.Status
        Assert-Equal $true $finding.Observed
        Assert-Equal $true $finding.Evidence.SecretPresent
        Assert-True (($result | ConvertTo-Json `
                    -Depth 100) -notmatch 'unit2-assessment-secret|REDACTED') 'Assessment retained a named XML secret'
        foreach ($path in @(Export-ADAnalyzerAssessment `
                    -Assessment $result `
                    -Path (Join-Path $temp 'named-secret') `
                    -Format All `
                    -Confirm:$false)) {
            Assert-True ((Get-Content `
                        -LiteralPath $path `
                        -Raw) -notmatch 'unit2-assessment-secret|REDACTED') 'Export retained a named XML secret'
        }
    }
    Test-Assessment 'missing policy versions remain unknown' {
        $policy = New-PolicyFixture
        $policy.SysvolVersion = $null
        $gpo = [pscustomobject]@{
            Id = [guid]'11111111-1111-1111-1111-111111111111'
            Flags = 0
            Version = 1
            Links = @()
        }
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $policy
                Error = $null
            })
        Assert-Equal Unknown ($result.Checks | Where-Object RuleId -eq GPO.VERSION_CONSISTENCY).Status
    }
    Test-Assessment 'failed GPO reads and skipped GPO collection cannot resolve stored failures' {
        $collector = (Get-Command Get-ADAnalyzerDirectoryData).ScriptBlock
        $gpos = (Get-Command Get-ADAnalyzerGpo).ScriptBlock
        $report = (Get-Command Get-ADAnalyzerGpoReport).ScriptBlock
        $script:ComparisonReadFails = $false

        function script:Get-ADRootDSE {
            param(
                $Server,
                $Credential,
                $ErrorAction

            ) [pscustomobject]@{
                DnsHostName = 'dc.example.invalid'
            }
        }

        function script:Get-ADAnalyzerDirectoryData {
            param(
                $Context,
                $Profile

            ) New-AssessmentFixture
        }

        function script:Get-ADAnalyzerGpo {
            param(
                [switch]$All,
                $Domain,
                $Server,
                $Credential

            ) [pscustomobject]@{
                Id = [guid]'11111111-1111-1111-1111-111111111111'
                Flags = 0
                Version = 1
                Links = @()
            }
        }

        function script:Get-ADAnalyzerGpoReport {
            param(
                $Gpo,
                $Credential,
                [switch]$AsObject

            )
            if ($script:ComparisonReadFails) {
                throw 'fixture GPO read denied'
            }
            $policy = New-PolicyFixture
            $policy.SecuritySettings = @([pscustomobject]@{
                    Scope = 'Computer'
                    Kind = 'Account'
                    Name = 'MinimumPasswordLength'
                    Value = 0
                    Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
                })
            [pscustomobject]@{
                Policy = $policy
            }
        }
        try {
            $before = Get-ADAnalyzerAssessment -Domain example.invalid
            Assert-True (@($before.Checks | Where-Object { $_.RuleId -like 'GPO.*' -and
                        $_.Status -eq 'Fail' }).Count -gt 0) 'Missing failing GPO baseline'
            $script:ComparisonReadFails = $true
            $failed = Get-ADAnalyzerAssessment -Domain example.invalid
            Assert-Equal Partial $failed.State
            $skipped = Get-ADAnalyzerAssessment -Domain example.invalid -SkipGpo
            Assert-Equal Complete $skipped.State
            foreach ($after in @($failed, $skipped)) {
                $changes = @((Compare-ADAnalyzerAssessment $before $after).Changes | Where-Object { $_.RuleId -like 'GPO.*' -and
                        $_.Reason -eq 'NotObservedInDifference' })
                Assert-True ($changes.Count -gt 0) 'Missing explicit unobserved policy checks'
                Assert-Equal 0 @($changes | Where-Object Change -ne Changed).Count
                Assert-Equal 0 @((Compare-ADAnalyzerAssessment $before $after).Changes | Where-Object { $_.RuleId -like 'GPO.*' -and
                        $_.Change -eq 'Resolved' }).Count
            }
        }
        finally {
            Set-Item Function:script:Get-ADAnalyzerDirectoryData $collector
            Set-Item Function:script:Get-ADAnalyzerGpo $gpos
            Set-Item Function:script:Get-ADAnalyzerGpoReport $report
            Remove-Item Function:Get-ADRootDSE
            $script:ComparisonReadFails = $false
        }
    }
    Test-Assessment 'SCT-style extracted GPO backup becomes typed baseline expectations' {
        $path = Join-Path $temp 'baseline/DomainSysvol/GPO'
        $machine = Join-Path $path 'Machine/Microsoft/Windows NT/SecEdit'
        $null = New-Item -Path $machine -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $path 'GPT.INI') -Value "[General]`nVersion=1"
        Set-Content -LiteralPath (Join-Path $machine 'GptTmpl.inf') -Value "[System Access]`nMinimumPasswordLength=16`nPasswordComplexity=1"
        $profile = Import-ADAnalyzerBaseline -GpoPath $path -Name Fixture -Version '2026.11'
        Assert-Equal Fixture $profile.Name
        Assert-Equal '2026.11' $profile.Version
        Assert-Equal 2 $profile.ExpectedGpoSettings.Count
        $parsed = Read-ADAnalyzerGpo $path
        $gpo = [pscustomobject]@{
            Id = [guid]::Empty
            Flags = 0
            Version = 1
            Links = @()
        }
        $checks = @(Test-ADAnalyzerGpoPolicy -Gpo $gpo -Policy $parsed -Profile $profile | Where-Object RuleId -like 'GPO.Expected.*')
        Assert-Equal 2 $checks.Count
        Assert-Equal 0 @($checks | Where-Object Status -ne Pass).Count
        $again = Import-ADAnalyzerBaseline -GpoPath $path -Name Fixture -Version '2026.11'
        Assert-Equal ($profile.ExpectedGpoSettings.Id -join '|') ($again.ExpectedGpoSettings.Id -join '|')
    }
    $strictBaselineRoot = Join-Path $temp 'strict-baseline/DomainSysvol/GPO'
    $strictBaselineSecurity = Join-Path $strictBaselineRoot 'Machine/Microsoft/Windows NT/SecEdit'
    $null = [IO.Directory]::CreateDirectory($strictBaselineSecurity)
    [IO.File]::WriteAllLines((Join-Path $strictBaselineRoot 'GPT.INI'), @('[General]', 'Version=1'))
    [IO.File]::WriteAllLines((Join-Path $strictBaselineSecurity 'GptTmpl.inf'),
        @('[System Access]', 'MinimumPasswordLength=16', 'PasswordComplexity=1'), [Text.Encoding]::Unicode)
    Write-AssessmentPol (Join-Path $strictBaselineRoot 'Machine/Registry.pol') @(
        @{
            Key = 'Software\Fixture'
            Name = 'Enabled'
            Type = 4
            Bytes = [BitConverter]::GetBytes([uint32]1)
        }
        @{
            Key = 'Software\Fixture'
            Name = 'Timeout'
            Type = 4
            Bytes = [BitConverter]::GetBytes([uint32]9)
        }
    )
    $generatedStrictBaseline = Import-ADAnalyzerBaseline -GpoPath $strictBaselineRoot -Version 'strict-rehydrate'
    $persistedStrictBaseline = Join-Path $temp 'strict-baseline.json'
    [IO.File]::WriteAllText($persistedStrictBaseline,
        (ConvertTo-Json -InputObject $generatedStrictBaseline -Depth 25), [Text.Encoding]::UTF8)
    $strictBaselineRoutes = [ordered]@{
        Registry = @{ RegistryRules = $generatedStrictBaseline.RegistryRules }
        Security = @{ ExpectedGpoSettings = $generatedStrictBaseline.ExpectedGpoSettings }
        Combined = $generatedStrictBaseline
        Json = $null
    }
    foreach ($strictBaselineRoute in $strictBaselineRoutes.Keys) {
        Test-Assessment ('generated baseline rehydrates under Strict Latest via ' + $strictBaselineRoute) {
            Assert-Equal 2 $generatedStrictBaseline.RegistryRules.Count
            Assert-Equal 2 $generatedStrictBaseline.ExpectedGpoSettings.Count
            foreach ($rule in $generatedStrictBaseline.RegistryRules) {
                Assert-True (-not $rule.ContainsKey('Kind') -and -not $rule.ContainsKey('Name')) 'The generated registry fixture no longer omits Kind and Name.'
            }
            foreach ($rule in $generatedStrictBaseline.ExpectedGpoSettings) {
                Assert-True ($rule.Kind -ceq 'Account' -and $rule.ContainsKey('Name') -and
                    -not $rule.ContainsKey('Key') -and -not $rule.ContainsKey('ValueName')) 'The generated security fixture no longer has Account-only identity fields.'
            }

            foreach ($strictMode in @($false, $true)) {
                $rehydrated = & {
                    if ($strictMode) {
                        Set-StrictMode -Version Latest
                    }
                    if ($strictBaselineRoute -ceq 'Json') {
                        Import-ADAnalyzerProfile -Path $persistedStrictBaseline
                    }
                    else {
                        Import-ADAnalyzerProfile -Profile $strictBaselineRoutes[$strictBaselineRoute]
                    }
                }

                foreach ($collection in @('RegistryRules', 'ExpectedGpoSettings')) {
                    $expected = @($generatedStrictBaseline[$collection])
                    if (($strictBaselineRoute -ceq 'Registry' -and $collection -ceq 'ExpectedGpoSettings') -or
                        ($strictBaselineRoute -ceq 'Security' -and $collection -ceq 'RegistryRules')) {
                        $expected = @()
                    }
                    $actual = @($rehydrated[$collection])
                    Assert-Equal $expected.Count $actual.Count
                    for ($index = 0; $index -lt $expected.Count; $index++) {
                        $expectedKeys = @($expected[$index].Keys | Sort-Object)
                        $actualKeys = @($actual[$index].Keys | Sort-Object)
                        Assert-Equal ($expectedKeys -join '|') ($actualKeys -join '|')
                        foreach ($key in $expectedKeys) {
                            Assert-Equal $expected[$index][$key] $actual[$index][$key]
                        }
                    }
                }
            }
        }
    }

    $secretBaselineMessage = 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'
    $typeBaselineMessage = 'Custom value baseline identity fields must be strings or null.'
    $identityCases = @(
        @{
            Name = 'absent Kind selects registry ValueName over both fallback names'
            Rule = @{
                Name = 'Password'
                Key = 'Software\Password'
                ValueName = 'Enabled'
            }
            Diagnostic = ''
            AlsoImport = $true
        }
        @{
            Name = 'explicit null Kind selects Name ahead of ValueName'
            Rule = @{
                Kind = $null
                Name = 'Password'
                Key = 'Software\Fixture'
                ValueName = 'Enabled'
            }
            Diagnostic = $secretBaselineMessage
            AlsoImport = $true
        }
        @{
            Name = 'empty registry ValueName checks the Key even with an ordinary Name'
            Rule = @{
                Name = 'Enabled'
                Key = 'Software\Password'
                ValueName = ''
            }
            Diagnostic = $secretBaselineMessage
        }
        @{
            Name = 'absent registry ValueName checks the Name when Key is missing'
            Rule = @{ Name = 'Password' }
            Diagnostic = $secretBaselineMessage
        }
        @{
            Name = 'nonregistry Name wins over ValueName and Key'
            Rule = @{
                Kind = 'Account'
                Name = 'Enabled'
                Key = 'Software\Password'
                ValueName = 'Password'
            }
            Diagnostic = ''
        }
        @{
            Name = 'nonregistry identity can fall back to Key'
            Rule = @{
                Kind = 'Account'
                Key = 'Software\Password'
            }
            Diagnostic = $secretBaselineMessage
        }
        @{
            Name = 'host registry precedence ignores explicit null Kind'
            Rule = @{
                Kind = $null
                Name = 'Password'
                Key = 'Software\Password'
                ValueName = 'Enabled'
                Expected = 1
            }
            Location = 'Host'
            Diagnostic = ''
            AlsoImport = $true
        }
        @{
            Name = 'nonstring Name is rejected before selection of a safe ValueName'
            Rule = @{
                Kind = 'Registry'
                Name = 9
                Key = 'Software\Fixture'
                ValueName = 'Enabled'
            }
            Diagnostic = $typeBaselineMessage
        }
    )
    $ordinalIdentity = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $foldedIdentity = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($map in @($ordinalIdentity, $foldedIdentity)) {
        $map.Add('kind', $null)
        $map.Add('Name', 'Password')
        $map.Add('Key', 'Software\Fixture')
        $map.Add('ValueName', 'Enabled')
    }
    $identityCases += @(
        @{
            Name = 'ordinal dictionary treats differently cased Kind as absent'
            Rule = $ordinalIdentity
            Diagnostic = ''
        }
        @{
            Name = 'ignore-case dictionary finds the explicit null Kind'
            Rule = $foldedIdentity
            Diagnostic = $secretBaselineMessage
        }
    )
    foreach ($identityCase in $identityCases) {
        Test-Assessment ('strict baseline identity: ' + $identityCase.Name) {
            $profile = Get-ADAnalyzerDefaultProfile
            if ($identityCase['Location'] -ceq 'Host') {
                $profile.Host.RegistryRules = @($identityCase.Rule)
            }
            else {
                $profile.RegistryRules = @($identityCase.Rule)
            }
            $routes = @('Raw')
            if ($identityCase['AlsoImport']) {
                $routes += 'Import'
            }
            foreach ($route in $routes) {
                foreach ($strictMode in @($false, $true)) {
                    $diagnostic = ''
                    try {
                        & {
                            if ($strictMode) {
                                Set-StrictMode -Version Latest
                            }
                            if ($route -ceq 'Import') {
                                $null = Import-ADAnalyzerProfile -Profile $profile
                            }
                            else {
                                Assert-ADAnalyzerValueBaseline -Profile $profile
                            }
                        }
                    }
                    catch {
                        $diagnostic = $_.Exception.GetBaseException().Message
                    }
                    Assert-Equal $identityCase.Diagnostic $diagnostic
                }
            }
        }
    }

    foreach ($getterKind in @('Registry', 'Account')) {
        Test-Assessment ('baseline identity getter order is preserved for ' + $getterKind) {
            $trace = [Collections.Generic.List[string]]::new()
            $rule = [pscustomobject]@{
                Trace = $trace
                FixtureKind = $getterKind
            }
            $rule.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Kind', {
                        $this.Trace.Add('Kind')
                        $this.FixtureKind
                    }))
            $rule.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Name', {
                        $this.Trace.Add('Name')
                        'Enabled'
                    }))
            $rule.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Key', {
                        $this.Trace.Add('Key')
                        'Software\Fixture'
                    }))
            $rule.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('ValueName', {
                        $this.Trace.Add('ValueName')
                        'Enabled'
                    }))
            $profile = Get-ADAnalyzerDefaultProfile
            $profile.RegistryRules = @($rule)
            $chosenName = if ($getterKind -ceq 'Registry') {
                'ValueName,ValueName'
            }
            else {
                'Name,Name'
            }
            $expected = 'Kind,Kind,Name,Name,Key,Key,ValueName,ValueName,Kind,' + $chosenName
            foreach ($strictMode in @($false, $true)) {
                $trace.Clear()
                & {
                    if ($strictMode) {
                        Set-StrictMode -Version Latest
                    }
                    Assert-ADAnalyzerValueBaseline -Profile $profile
                }
                Assert-Equal $expected ($trace -join ',')
            }
        }
    }

    Test-Assessment 'misplaced account-template entries are excluded from baselines and leave explicit coverage' {
        $root = Join-Path $temp 'section-baseline'
        $directory = Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit'
        $null = [IO.Directory]::CreateDirectory($directory)
        [IO.File]::WriteAllText((Join-Path $root 'GPT.INI'), "[General]`nVersion=1")
        [IO.File]::WriteAllText((Join-Path $directory 'GptTmpl.inf'),
            "[System Access]`nMinimumPasswordLength=16`nTicketValidateClient=1`n[Kerberos Policy]`nPasswordComplexity=1`nMaxTicketAge=10",
            [Text.Encoding]::Unicode)
        $profile = Import-ADAnalyzerBaseline -GpoPath $root -Version section
        Assert-Equal 2 @($profile.ExpectedGpoSettings).Count
        Assert-Equal 0 @($profile.ExpectedGpoSettings | Where-Object { $_.Name -in 'TicketValidateClient', 'PasswordComplexity' }).Count
        $gpo = [pscustomobject]@{
            Id = [guid]::Empty
            Flags = 0
            Version = 1
            Links = @()
        }
        $policy = Read-ADAnalyzerGpo $root
        $result = Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{
                Gpo = $gpo
                Policy = $policy
                Error = $null
            }) -Profile $profile
        Assert-Equal 'Unknown' ($result.Checks | Where-Object RuleId -eq GPO.Coverage.UnsupportedInfSettings).Status
        Assert-Equal 'Partial' $result.State
        Assert-Equal 'NotConfigured' ($result.Checks | Where-Object RuleId -eq GPO.Account.PasswordComplexity).Status
        Assert-Equal 0 @($result.Checks | Where-Object { $_.RuleId -like 'GPO.Expected.*' -and $_.Status -ne 'Pass' }).Count
    }

    $firstRegistryRow = @{
        Key = 'Software\Fixture\Alpha|Beta'
        Name = 'Gamma'
        Type = 4
        Bytes = [BitConverter]::GetBytes([uint32]9)
    }
    $secondRegistryRow = @{
        Key = 'Software\Fixture\Alpha'
        Name = 'Beta|Gamma'
        Type = 4
        Bytes = [BitConverter]::GetBytes([uint32]9)
    }
    $secondDifferent = $secondRegistryRow.Clone()
    $secondDifferent.Bytes = [BitConverter]::GetBytes([uint32]13)
    $secondText = $secondRegistryRow.Clone()
    $secondText.Type = 1
    $secondText.Bytes = [Text.Encoding]::Unicode.GetBytes("fixture text`0")
    $firstCaseVariant = $firstRegistryRow.Clone()
    $firstCaseVariant.Key = $firstRegistryRow.Key.ToUpperInvariant()
    $firstCaseVariant.Name = $firstRegistryRow.Name.ToLowerInvariant()
    $firstConflict = $firstRegistryRow.Clone()
    $firstConflict.Bytes = [BitConverter]::GetBytes([uint32]99)
    $ordinaryRegistryRow = @{
        Key = 'Software\Fixture\Ordinary'
        Name = 'Setting'
        Type = 4
        Bytes = [BitConverter]::GetBytes([uint32]7)
    }

    $registryBackups = [ordered]@{
        SameEqual = @($firstRegistryRow, $secondRegistryRow)
        SameDifferent = @($firstRegistryRow, $secondDifferent)
        SameTyped = @($firstRegistryRow, $secondText)
        First = @($firstRegistryRow)
        Second = @($secondRegistryRow)
        SecondText = @($secondText)
        CaseVariant = @($firstCaseVariant)
        Conflict = @($firstConflict)
        Ordinary = @($ordinaryRegistryRow)
    }
    $registryRoots = @{}
    foreach ($name in $registryBackups.Keys) {
        $registryRoots[$name] = Join-Path $temp ('registry-baseline-' + $name + '/DomainSysvol/GPO')
        Write-AssessmentPol (Join-Path $registryRoots[$name] 'Machine/Registry.pol') $registryBackups[$name]
        [IO.File]::WriteAllText((Join-Path $registryRoots[$name] 'GPT.INI'), "[General]`nVersion=1")
    }

    $collisionCases = @(
        @{
            Name = 'equal values in one backup'
            Paths = @($registryRoots.SameEqual)
            Evaluate = $registryRoots.SameEqual
            SecondType = 4
            SecondExpected = [uint32]9
        }
        @{
            Name = 'different values in one backup'
            Paths = @($registryRoots.SameDifferent)
            Evaluate = $registryRoots.SameDifferent
            SecondType = 4
            SecondExpected = [uint32]13
        }
        @{
            Name = 'equal values from separate backups'
            Paths = @($registryRoots.First, $registryRoots.Second)
            Evaluate = $registryRoots.SameEqual
            SecondType = 4
            SecondExpected = [uint32]9
        }
        @{
            Name = 'different typed values from separate backups'
            Paths = @($registryRoots.First, $registryRoots.SecondText)
            Evaluate = $registryRoots.SameTyped
            SecondType = 1
            SecondExpected = 'fixture text'
        }
    )
    foreach ($case in $collisionCases) {
        Test-Assessment ('registry baseline keeps pipe-bearing identities distinct for ' + $case.Name) {
            $profile = Import-ADAnalyzerBaseline -GpoPath $case.Paths -Version identity
            Assert-Equal 2 $profile.RegistryRules.Count
            $firstRule = @($profile.RegistryRules | Where-Object Key -CEQ $firstRegistryRow.Key)
            $secondRule = @($profile.RegistryRules | Where-Object Key -CEQ $secondRegistryRow.Key)
            Assert-True ($firstRule.Count -eq 1 -and $secondRule.Count -eq 1) 'The rules lost their separate registry keys.'
            Assert-True ($firstRule[0].Id -ne $secondRule[0].Id -and
                $firstRule[0].Hive -ceq 'HKLM' -and $secondRule[0].Hive -ceq 'HKLM' -and
                $firstRule[0].ValueName -ceq $firstRegistryRow.Name -and $secondRule[0].ValueName -ceq $secondRegistryRow.Name -and
                $firstRule[0].Type -eq 4 -and $secondRule[0].Type -eq $case.SecondType -and
                $firstRule[0].Expected -is [uint32] -and $firstRule[0].Expected -eq 9 -and
                $secondRule[0].Expected.GetType() -eq $case.SecondExpected.GetType() -and
                $secondRule[0].Expected -ceq $case.SecondExpected -and
                $firstRule[0].Source -ceq $case.Paths[0] -and $secondRule[0].Source -ceq $case.Paths[-1]) 'The rules lost their IDs, original names, typed values, or provenance.'

            $gpo = [pscustomobject]@{
                Id = [guid]::Empty
                Flags = 0
                Version = 1
                Links = @()
            }
            $ruleIds = @(
                'GPO.Expected.' + $firstRule[0].Id
                'GPO.Expected.' + $secondRule[0].Id
            )
            $parsed = Read-ADAnalyzerGpo -Path $case.Evaluate
            $checks = @(Test-ADAnalyzerGpoPolicy -Gpo $gpo -Policy $parsed -Profile $profile |
                Where-Object { $_.RuleId -in $ruleIds })
            Assert-True ($checks.Count -eq 2 -and @($checks.RuleId | Sort-Object -Unique).Count -eq 2 -and
                @($checks.CheckId | Sort-Object -Unique).Count -eq 2 -and
                @($checks | Where-Object Status -NE Pass).Count -eq 0) 'The offline evaluator did not return two independent passing checks.'
            if ($case.Evaluate -eq $registryRoots.SameDifferent) {
                $changed = Read-ADAnalyzerGpo -Path $registryRoots.SameEqual
                $checks = @(Test-ADAnalyzerGpoPolicy -Gpo $gpo -Policy $changed -Profile $profile |
                    Where-Object { $_.RuleId -in $ruleIds })
                Assert-Equal Pass ($checks | Where-Object RuleId -EQ $ruleIds[0]).Status
                Assert-Equal Fail ($checks | Where-Object RuleId -EQ $ruleIds[1]).Status
            }
        }
    }

    Test-Assessment 'registry baseline assigns stable independent IDs to imported pipe-bearing tuples' {
        $first = (Import-ADAnalyzerBaseline -GpoPath $registryRoots.First -Version identity).RegistryRules[0]
        $second = (Import-ADAnalyzerBaseline -GpoPath $registryRoots.Second -Version identity).RegistryRules[0]
        $secondText = (Import-ADAnalyzerBaseline -GpoPath $registryRoots.SecondText -Version identity).RegistryRules[0]
        $equivalent = (Import-ADAnalyzerBaseline -GpoPath $registryRoots.CaseVariant -Version identity).RegistryRules[0]
        Assert-True ($first.Id -ne $second.Id) 'Independent imports assigned both distinct tuples the same public ID.'
        Assert-Equal $first.Id $equivalent.Id
        Assert-Equal $second.Id $secondText.Id
        $together = Import-ADAnalyzerBaseline -GpoPath $registryRoots.SameEqual -Version identity
        Assert-Equal $first.Id ($together.RegistryRules | Where-Object Key -EQ $firstRegistryRow.Key).Id
        Assert-Equal $second.Id ($together.RegistryRules | Where-Object Key -EQ $secondRegistryRow.Key).Id
    }

    Test-Assessment 'registry baseline preserves ordinary legacy IDs and true duplicate provenance' {
        $ordinary = (Import-ADAnalyzerBaseline -GpoPath $registryRoots.Ordinary -Version identity).RegistryRules[0]
        $legacyCheck = New-ADAnalyzerCheck -RuleId BASELINE.REGISTRY -Target 'hklm|software\fixture\ordinary|setting' -Status Pass
        Assert-Equal ('BASELINE.REGISTRY.' + $legacyCheck.CheckId.Substring(0, 16)) $ordinary.Id
        foreach ($order in @(@('First', 'CaseVariant'), @('CaseVariant', 'First'))) {
            $profile = Import-ADAnalyzerBaseline -GpoPath @($registryRoots[$order[0]], $registryRoots[$order[1]]) -Version identity
            Assert-Equal 1 $profile.RegistryRules.Count
            Assert-Equal $registryRoots[$order[0]] $profile.RegistryRules[0].Source
            Assert-Equal ([uint32]9) $profile.RegistryRules[0].Expected
        }
    }

    Test-Assessment 'registry baseline preserves the true pipe-bearing conflict diagnostic' {
        $failure = $null
        try {
            $null = Import-ADAnalyzerBaseline -GpoPath @($registryRoots.First, $registryRoots.Conflict) -Version identity
        }
        catch {
            $failure = $_.Exception.Message
        }
        Assert-Equal 'Conflicting baseline registry setting: hklm|software\fixture\alpha|beta|gamma' $failure
    }
    Test-Assessment 'conflicting baseline inputs are rejected without silently overwriting' {
        $a = Join-Path $temp 'baseline/DomainSysvol/GPO'
        $b = Join-Path $temp 'conflict'
        $null = New-Item -Path (Join-Path $b 'Machine/Microsoft/Windows NT/SecEdit') -ItemType Directory -Force
        Set-Content `
            -LiteralPath (Join-Path $b 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf') `
            -Value "[System Access]`nMinimumPasswordLength=8"
        Assert-Throws { Import-ADAnalyzerBaseline -GpoPath @($a, $b) -Version one }
    }
    Test-Assessment 'baseline omits stored secret values instead of accepting them as expectations' {
        $reader = (Get-Item Function:Read-ADAnalyzerGpo).ScriptBlock
        $script:BaselinePolicy = New-PolicyFixture
        $script:BaselinePolicy.Files = @([pscustomobject]@{
                Path = 'Machine/Registry.pol'
            })
        $script:BaselinePolicy.RegistrySettings = @([pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'DefaultPassword'
                SecretPresent = $true
                Type = 1
                Source = 'Machine/Registry.pol'
                KeyOnly = $false
            })
        $script:BaselinePolicy.SecuritySettings = @([pscustomobject]@{
                Scope = 'Computer'
                Kind = 'SecurityOptions'
                Name = 'MACHINE\Software\Fixture\DefaultPassword'
                SecretPresent = $true
                Source = 'Machine/GptTmpl.inf'
            })

        function script:Read-ADAnalyzerGpo {
            param($Path) $script:BaselinePolicy
        }
        try {
            $profile = Import-ADAnalyzerBaseline -GpoPath fixture -Version one
            Assert-Equal 0 $profile.RegistryRules.Count
            Assert-Equal 0 $profile.ExpectedGpoSettings.Count
        }
        finally {
            Set-Item Function:script:Read-ADAnalyzerGpo $reader
        }
    }
    Test-Assessment 'invalid marked policy values cannot become baseline expectations' {
        $reader = (Get-Command Read-ADAnalyzerGpo).ScriptBlock

        function script:Read-ADAnalyzerGpo {
            param($Path)
            $policy = New-PolicyFixture
            $policy.Files = @([pscustomobject]@{
                    Path = 'Machine/GptTmpl.inf'
                })
            $policy.SecuritySettings = @([pscustomobject]@{
                    Scope = 'Computer'
                    Kind = 'Account'
                    Name = 'PasswordComplexity'
                    Value = 'true'
                    ValueValid = $false
                    Source = 'Machine/GptTmpl.inf'
                })
            $policy
        }
        try {
            Assert-Throws { Import-ADAnalyzerBaseline -GpoPath fixture -Version one }
        }
        finally {
            Set-Item Function:script:Read-ADAnalyzerGpo $reader
        }
    }
    Test-Assessment 'baseline replay uses final writes and omits deleted registry values' {
        $reader = (Get-Command Read-ADAnalyzerGpo).ScriptBlock
        $script:BaselinePolicy = New-PolicyFixture
        $script:BaselinePolicy.Files = @([pscustomobject]@{
                Path = 'Machine/Registry.pol'
            })
        $script:BaselinePolicy.RegistrySettings = @(
            [pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'X'
                Type = 4
                Value = 0
                KeyOnly = $false
                DeletionDirective = $false
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'X'
                Type = 4
                Value = 1
                KeyOnly = $false
                DeletionDirective = $false
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Y'
                Type = 4
                Value = 1
                KeyOnly = $false
                DeletionDirective = $false
            }
            [pscustomobject]@{
                Scope = 'Computer'
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = '**del.Y'
                Type = 0
                Value = ''
                KeyOnly = $false
                DeletionDirective = $true
            }
        )

        function script:Read-ADAnalyzerGpo {
            param($Path) $script:BaselinePolicy
        }
        try {
            $profile = Import-ADAnalyzerBaseline -GpoPath fixture -Version one
            Assert-Equal 1 $profile.RegistryRules.Count
            Assert-Equal X $profile.RegistryRules[0].ValueName
            Assert-Equal 1 $profile.RegistryRules[0].Expected
        }
        finally {
            Set-Item Function:script:Read-ADAnalyzerGpo $reader
        }
    }
    Test-Assessment 'cross-policy registry type conflicts are not hidden by equal decoded values' {
        $reader = (Get-Command Read-ADAnalyzerGpo).ScriptBlock

        function script:Read-ADAnalyzerGpo {
            param($Path)
            $policy = New-PolicyFixture
            $policy.Files = @([pscustomobject]@{
                    Path = 'Machine/Registry.pol'
                })
            $policy.RegistrySettings = @([pscustomobject]@{
                    Scope = 'Computer'
                    Hive = 'HKLM'
                    Key = 'Software\Fixture'
                    ValueName = 'X'
                    Type = $(if ($Path -eq 'a') {
                            4
                        }
                        else {
                            5
                        })
                    Value = 0
                    KeyOnly = $false
                    DeletionDirective = $false
                })
            $policy
        }
        try {
            Assert-Throws { Import-ADAnalyzerBaseline -GpoPath a, b -Version one }
        }
        finally {
            Set-Item Function:script:Read-ADAnalyzerGpo $reader
        }
    }
    Test-Assessment 'multi-string security baseline values aggregate into one set expectation' {
        $reader = (Get-Command Read-ADAnalyzerGpo).ScriptBlock
        $script:BaselinePolicy = New-PolicyFixture
        $script:BaselinePolicy.Files = @([pscustomobject]@{
                Path = 'Machine/GptTmpl.inf'
            })
        $script:BaselinePolicy.SecuritySettings = @('LSARPC', 'NETLOGON', 'SAMR' | ForEach-Object { [pscustomobject]@{
                    Scope = 'Computer'
                    Kind = 'SecurityOptions'
                    Name = 'Network access: Named Pipes that can be accessed anonymously'
                    Value = $_
                    Source = 'Machine/GptTmpl.inf'
                } })

        function script:Read-ADAnalyzerGpo {
            param($Path) $script:BaselinePolicy
        }
        try {
            $profile = Import-ADAnalyzerBaseline -GpoPath fixture -Version one
            Assert-Equal 1 $profile.ExpectedGpoSettings.Count
            Assert-True $profile.ExpectedGpoSettings[0].Aggregate 'Missing set semantics'
            Assert-Equal 3 $profile.ExpectedGpoSettings[0].Expected.Count
            $gpo = [pscustomobject]@{
                Id = [guid]::Empty
                Flags = 0
                Links = @()
            }
            $checks = @(Test-ADAnalyzerGpoPolicy `
                    -Gpo $gpo `
                    -Policy $script:BaselinePolicy `
                    -Profile $profile | Where-Object RuleId `
                    -like GPO.Expected.*)
            Assert-Equal 1 $checks.Count
            Assert-Equal Pass $checks[0].Status
        }
        finally {
            Set-Item Function:script:Read-ADAnalyzerGpo $reader
        }
    }
    Test-Assessment 'live orchestration pins each independent context to its returned DC' {
        $collector = (Get-Command Get-ADAnalyzerDirectoryData).ScriptBlock
        $script:Contexts = [Collections.ArrayList]::new()
        $script:RootQueries = [Collections.ArrayList]::new()

        function script:Get-ADRootDSE {
            param(
                $Server,
                $Credential,
                $ErrorAction

            )
            $null = $script:RootQueries.Add(@{
                    Server = $Server
                    Credential = $Credential
                })
            [pscustomobject]@{
                DnsHostName = $Server.Replace('alias.', 'dc.')
            }
        }

        function script:Get-ADAnalyzerDirectoryData {
            param(
                $Context,
                $Profile

            )
            $null = $script:Contexts.Add($Context)
            New-AssessmentFixture $Context.Domain
        }
        $credential = [pscredential]::new('fixture', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        try {
            $a = Get-ADAnalyzerAssessment -Domain a.invalid -Server alias.a.invalid -Credential $credential -SkipGpo -IncludeAcl
            $b = Get-ADAnalyzerAssessment -Domain b.invalid -Server alias.b.invalid -Credential $credential -SkipGpo -IncludeHostChecks
            Assert-Equal dc.a.invalid $a.Context.Server
            Assert-Equal dc.b.invalid $b.Context.Server
            Assert-Equal a.invalid $a.Target
            Assert-Equal b.invalid $b.Target
            Assert-True ([object]::ReferenceEquals($credential, $script:Contexts[0].Credential)) 'Credential lost'
            Assert-True $script:Contexts[0].IncludeAcl 'ACL option lost'
            Assert-True $script:Contexts[1].IncludeHostChecks 'Host option lost'
            Assert-True ($null -eq $a.Context.PSObject.Properties['Credential']) 'Credential included in public context'
        }
        finally {
            Set-Item Function:script:Get-ADAnalyzerDirectoryData $collector
            Remove-Item Function:Get-ADRootDSE
        }
    }
    Test-Assessment 'prerequisite check detects missing package DLL without invoking RSAT install' {
        $checks = @(Get-ADAnalyzerPrerequisite -RepositoryRoot $temp)
        Assert-Equal Fail ($checks | Where-Object RuleId -eq PACKAGE.BUNDLED_AD).Status
    }

    $prerequisiteLocation = (Get-Location).Path
    $prerequisiteProcessDirectory = [Environment]::CurrentDirectory
    $prerequisiteDrive = $null
    try {
        $fixtureRoot = Join-Path $temp 'prerequisite-paths'
        $packageName = 'copied[package]'
        $packageRoot = Join-Path $fixtureRoot $packageName
        $separateDirectory = Join-Path $fixtureRoot 'process-directory'
        $dllName = 'Microsoft.ActiveDirectory.Management.dll'
        $dllRelativePath = Join-Path 'lib' $dllName
        $packageFile = Join-Path $packageRoot $dllRelativePath
        $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $packageFile))
        $null = [IO.Directory]::CreateDirectory($separateDirectory)
        [IO.File]::Copy((Join-Path $RepositoryRoot $dllRelativePath), $packageFile)
        $sha = (Get-FileHash -LiteralPath $packageFile -Algorithm SHA256).Hash
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($packageFile).FileVersion
        $pins = @{
            DependencyHashes = @{
                $dllName = $sha
            }
        }
        $originalPins = ConvertTo-Json -InputObject $pins -Depth 6 -Compress
        $driveName = 'Prereq' + [guid]::NewGuid().ToString('N')
        $prerequisiteDrive = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $fixtureRoot
        [Environment]::CurrentDirectory = $separateDirectory
        $fixtureProcessDirectory = [Environment]::CurrentDirectory

        $roots = [ordered]@{
            'absolute FileSystem path' = $packageRoot
            'relative PowerShell path' = (Join-Path '.' $packageName)
            'named FileSystem drive' = ('{0}:/{1}' -f $driveName, $packageName)
            'provider-qualified path from Env' = ('FileSystem::' + $packageRoot)
        }
        foreach ($pathCase in $roots.Keys) {
            Test-Assessment ('prerequisite inspects the same DLL through ' + $pathCase) {
                if ($pathCase -eq 'provider-qualified path from Env') {
                    Set-Location Env:
                }
                else {
                    Set-Location -LiteralPath $fixtureRoot
                }
                $root = $roots[$pathCase]
                $target = Join-Path $root $dllRelativePath
                $callerLocation = (Get-Location).Path
                $checks = @(Get-ADAnalyzerPrerequisite -RepositoryRoot $root -Profile $pins)
                Assert-Equal 'PACKAGE.WINDOWS,PACKAGE.POWERSHELL,PACKAGE.BUNDLED_AD,PACKAGE.CHECKSUM' ($checks.RuleId -join ',')
                Assert-Equal $root $checks[0].Target
                Assert-Equal $root $checks[1].Target
                Assert-Equal 'Pass' $checks[2].Status
                Assert-Equal 'Pass' $checks[3].Status
                Assert-Equal $version $checks[2].Observed.Version
                Assert-Equal $sha $checks[2].Observed.Sha256
                Assert-Equal $sha $checks[3].Observed
                Assert-Equal $sha $checks[3].Expected

                foreach ($check in $checks[2..3]) {
                    Assert-Equal $target $check.Target
                    $shape = New-ADAnalyzerCheck -RuleId $check.RuleId -Target $target -Status Pass
                    Assert-Equal $shape.CheckId $check.CheckId
                }
                Assert-Equal $callerLocation (Get-Location).Path
                Assert-Equal $fixtureProcessDirectory ([Environment]::CurrentDirectory)
                Assert-Equal $originalPins (ConvertTo-Json -InputObject $pins -Depth 6 -Compress)
            }
        }

        Set-Location -LiteralPath $fixtureRoot
        Test-Assessment 'prerequisite keeps package evidence on a wrong pin and rejects an invalid online server' {
            $wrongPin = @{
                DependencyHashes = @{
                    $dllName = ('0' * 64)
                }
            }
            $parameters = @{
                RepositoryRoot = $packageRoot
                Profile = $wrongPin
                Online = $true
                Server = '! invalid fixture host !'
            }
            $observed = [Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                Get-ADAnalyzerPrerequisite @parameters | ForEach-Object { $observed.Add($_) }
            }
            catch {
                $failure = $_.Exception.Message
            }
            Assert-Equal 'Online checks require a valid Server host name' $failure
            Assert-Equal 'PACKAGE.WINDOWS,PACKAGE.POWERSHELL,PACKAGE.BUNDLED_AD,PACKAGE.CHECKSUM' ($observed.RuleId -join ',')
            Assert-Equal 'Pass' $observed[2].Status
            Assert-Equal 'Fail' $observed[3].Status
            Assert-Equal $sha $observed[3].Observed
            Assert-Equal $wrongPin.DependencyHashes[$dllName] $observed[3].Expected
        }

        Test-Assessment 'prerequisite streams its platform check before inspecting a package path' {
            $missingDrive = 'Missing' + [guid]::NewGuid().ToString('N')
            $invalidRoot = '{0}:/no-package' -f $missingDrive
            $first = @(Get-ADAnalyzerPrerequisite -RepositoryRoot $invalidRoot | Select-Object -First 1)
            Assert-Equal 1 $first.Count
            Assert-Equal 'PACKAGE.WINDOWS' $first[0].RuleId
            $failure = $null
            try {
                $null = Get-ADAnalyzerPrerequisite -RepositoryRoot $invalidRoot -ErrorAction Stop
            }
            catch {
                $failure = $_.FullyQualifiedErrorId
            }
            Assert-True ($failure -like 'DriveNotFound,*') 'A full inspection lost the native drive error'
        }
    }
    finally {
        Set-Location -LiteralPath $prerequisiteLocation
        [Environment]::CurrentDirectory = $prerequisiteProcessDirectory
        if ($null -ne $prerequisiteDrive) {
            Remove-PSDrive -Name $prerequisiteDrive.Name
        }
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -WhatIf:$false -Confirm:$false
}

# U124 optional assessment fields meet the same StrictMode contract on both entry paths.
function Invoke-AssessmentOptionalFieldFixture([string]$Route, $Directory, [object[]]$Policies = @()) {
    Set-StrictMode -Version Latest
    if ($Route -eq 'Engine') {
        $engine = [ADAnalyzerAssessmentEngine]::new()
        return $engine.Evaluate($Directory, $Policies, 'assessment.fixture.invalid')
    }
    Invoke-ADAnalyzerAssessment -DirectoryData $Directory -GpoData $Policies -Target 'assessment.fixture.invalid'
}

function New-AssessmentOptionalPolicyRow([string]$Id, $Policy, [string]$ReadError = '') {
    [pscustomobject]@{
        Gpo = [pscustomobject]@{
            Id = $Id
            Version = 1
        }
        Policy = $Policy
        Error = $ReadError
    }
}

$originalOptionalDirectoryPolicy = (Get-Command Test-ADAnalyzerDirectoryPolicy).ScriptBlock
$originalOptionalGpoPolicy = (Get-Command Test-ADAnalyzerGpoPolicy).ScriptBlock
$script:OptionalAssessmentEvents = [Collections.Generic.List[string]]::new()
try {
    function script:Test-ADAnalyzerDirectoryPolicy {
        [CmdletBinding()]
        param($Data, $Profile)

        $script:OptionalAssessmentEvents.Add('DirectoryPolicy')
        New-ADAnalyzerCheck -RuleId 'FIXTURE.DIRECTORY' -Status Pass -Target 'directory fixture'
    }

    function script:Test-ADAnalyzerGpoPolicy {
        [CmdletBinding()]
        param($Gpo, $Policy, $Profile)

        $script:OptionalAssessmentEvents.Add('GpoPolicy')
        New-ADAnalyzerCheck -RuleId 'FIXTURE.GPO' -Status Pass -Target ([string]$Gpo.Id)
    }

    foreach ($route in 'Engine', 'Command') {
        Test-Assessment ("StrictMode {0} preserves omitted HostChecks" -f $route) {
            $directory = New-AssessmentFixture
            $result = Invoke-AssessmentOptionalFieldFixture $route $directory

            Assert-Equal Complete $result.State
            Assert-Equal 'FIXTURE.DIRECTORY' ($result.Checks.RuleId -join ',')
            Assert-True ($null -eq $directory.PSObject.Properties['HostChecks']) 'The input gained HostChecks.'
            Assert-True ($null -eq $result.Data.Directory.PSObject.Properties['HostChecks']) 'The detached snapshot gained HostChecks.'
            Assert-True (
                -not [object]::ReferenceEquals($directory, $result.Data.Directory)
            ) 'The snapshot reused the caller-owned directory record.'
        }

        Test-Assessment ("StrictMode {0} preserves present HostChecks shapes" -f $route) {
            $first = New-ADAnalyzerCheck -RuleId 'FIXTURE.HOST' -Status Pass -Target 'first'
            $second = New-ADAnalyzerCheck -RuleId 'FIXTURE.HOST' -Status Pass -Target 'second'
            $shapes = [ordered]@{
                Null = $null
                Empty = @()
                Scalar = $first
                Singleton = @($first)
                Multiple = @($first, $null, $second)
            }
            foreach ($shape in $shapes.Keys) {
                $directory = New-AssessmentFixture
                $inputChecks = $shapes[$shape]
                $directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue $inputChecks
                $result = Invoke-AssessmentOptionalFieldFixture $route $directory
                $property = $result.Data.Directory.PSObject.Properties['HostChecks']
                Assert-True ($null -ne $property) ('The snapshot lost explicit HostChecks ' + $shape + '.')
                $expected = 'directory fixture'
                if ($shape -in 'Scalar', 'Singleton') {
                    $expected += ',first'
                }
                elseif ($shape -eq 'Multiple') {
                    $expected += ',first,second'
                }
                Assert-Equal $expected ($result.Checks.Target -join ',')
                Assert-Equal Complete $result.State

                $detached = $property.Value
                if ($shape -eq 'Null') {
                    Assert-True ($null -eq $detached) 'Explicit null HostChecks was changed.'
                }
                elseif ($shape -eq 'Scalar') {
                    Assert-True ($detached -is [pscustomobject]) 'The scalar HostChecks record changed shape.'
                    Assert-Equal $first.CheckId $detached.CheckId
                }
                else {
                    Assert-True ($detached -is [array]) ('The snapshot changed the HostChecks array for ' + $shape + '.')
                    Assert-Equal $inputChecks.Count $detached.Count
                    if ($shape -eq 'Singleton') {
                        Assert-Equal $first.CheckId $detached[0].CheckId
                    }
                    elseif ($shape -eq 'Multiple') {
                        Assert-True ($null -eq $detached[1]) 'The detached snapshot removed an input null observation.'
                        Assert-Equal $first.CheckId $detached[0].CheckId
                        Assert-Equal $second.CheckId $detached[2].CheckId
                        $detached[0].Target = 'changed result'
                        Assert-Equal 'first' $directory.HostChecks[0].Target
                        Assert-Equal 'first' $result.Checks[1].Target
                    }
                }
            }
        }

        Test-Assessment ("StrictMode {0} reports unreadable and healthy GPOs together" -f $route) {
            $readError = 'fixture policy read failed'
            $failedId = '11111111-1111-1111-1111-111111111111'
            $healthyId = '22222222-2222-2222-2222-222222222222'
            $directory = New-AssessmentFixture
            $directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue $null
            $fileShapes = [ordered]@{
                Null = $null
                Empty = @()
                Single = @([pscustomobject]@{ Path = 'Machine/one.inf' })
                Multiple = @(
                    [pscustomobject]@{ Path = 'Machine/one.inf' }
                    [pscustomobject]@{ Path = 'Machine/two.inf' }
                )
            }
            foreach ($shape in $fileShapes.Keys) {
                $policy = New-PolicyFixture
                $policy.Files = $fileShapes[$shape]
                $policy.UnparsedFiles = $fileShapes[$shape]
                $rows = @(
                    New-AssessmentOptionalPolicyRow $failedId $null $readError
                    New-AssessmentOptionalPolicyRow $healthyId $policy
                )
                $result = Invoke-AssessmentOptionalFieldFixture $route $directory $rows

                Assert-Equal Partial $result.State
                Assert-Equal 1 $result.Coverage.Unreadable
                Assert-Equal 1 $result.Errors.Count
                Assert-Equal GroupPolicy $result.Errors[0].Collection
                Assert-Equal $failedId $result.Errors[0].Target
                Assert-Equal $readError $result.Errors[0].Message
                Assert-Equal 'FIXTURE.DIRECTORY,GPO.READ,GPO.VERSION_CONSISTENCY,FIXTURE.GPO' ($result.Checks.RuleId -join ',')
                Assert-Equal $failedId $result.Checks[1].Target
                Assert-Equal ($healthyId + '/Version') $result.Checks[2].Target
                Assert-Equal Pass $result.Checks[2].Status

                Assert-Equal 2 $result.Data.Policies.Count
                $failed = $result.Data.Policies[0]
                $healthy = $result.Data.Policies[1]
                Assert-Equal $failedId $failed.Gpo.Id
                Assert-Equal $readError $failed.ReadError
                Assert-True ($null -eq $failed.Files -and $null -eq $failed.UnparsedFiles) 'Unreadable policy metadata changed.'
                Assert-Equal $healthyId $healthy.Gpo.Id
                Assert-Equal '' $healthy.ReadError
                foreach ($name in 'Files', 'UnparsedFiles') {
                    $expected = ConvertTo-Json -InputObject $policy.$name -Depth 6 -Compress
                    $actual = ConvertTo-Json -InputObject $healthy.$name -Depth 6 -Compress
                    Assert-Equal $expected $actual
                }
                if ($shape -eq 'Multiple') {
                    $healthy.Files[0].Path = 'changed result'
                    Assert-Equal 'Machine/one.inf' $policy.Files[0].Path
                    Assert-Equal 'Machine/one.inf' $healthy.UnparsedFiles[0].Path
                }
            }
        }

        Test-Assessment ("StrictMode {0} retains required readable GPO member errors" -f $route) {
            $directory = New-AssessmentFixture
            $directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue $null
            foreach ($member in 'Policy', 'Files', 'UnparsedFiles') {
                $policy = New-PolicyFixture
                $row = New-AssessmentOptionalPolicyRow '33333333-3333-3333-3333-333333333333' $policy
                $owner = $policy
                if ($member -eq 'Policy') {
                    $owner = $row
                }
                $owner.PSObject.Properties.Remove($member)
                $caught = $null
                try {
                    $null = Invoke-AssessmentOptionalFieldFixture $route $directory @($row)
                }
                catch {
                    $caught = $_
                }
                Assert-True (
                    $null -ne $caught -and $caught.FullyQualifiedErrorId -like 'PropertyNotFoundStrict*' -and
                    $caught.Exception.GetBaseException().Message -like ("*'{0}'*" -f $member)
                ) ("Required member {0} did not retain its native property error. Received {1}" -f $member, $caught)
            }
        }

        Test-Assessment ("StrictMode {0} preserves HostChecks and Policy getter order" -f $route) {
            $script:OptionalAssessmentEvents.Clear()
            $script:OptionalHostReads = 0
            $script:OptionalPolicyReads = 0
            $script:OptionalHostFirst = New-ADAnalyzerCheck -RuleId 'FIXTURE.HOST' -Status Pass -Target 'first'
            $script:OptionalHostLater = New-ADAnalyzerCheck -RuleId 'FIXTURE.HOST' -Status Pass -Target 'later'
            $directory = New-AssessmentFixture
            $directory | Add-Member -MemberType ScriptProperty -Name HostChecks -Value {
                $script:OptionalHostReads++
                $script:OptionalAssessmentEvents.Add('HostChecks:' + $script:OptionalHostReads)
                if ($script:OptionalHostReads -eq 1) {
                    return $script:OptionalHostFirst
                }
                return $script:OptionalHostLater
            }
            $script:OptionalPolicyHealth = New-PolicyFixture
            $script:OptionalPolicyFiles = [pscustomobject]@{}
            $script:OptionalPolicyOther = [pscustomobject]@{}
            $script:OptionalPolicyFiles | Add-Member -MemberType ScriptProperty -Name Files -Value {
                $script:OptionalAssessmentEvents.Add('Files')
                return 'files from fifth read'
            }
            $script:OptionalPolicyOther | Add-Member -MemberType ScriptProperty -Name UnparsedFiles -Value {
                $script:OptionalAssessmentEvents.Add('UnparsedFiles')
                return 'unparsed from sixth read'
            }
            $row = New-AssessmentOptionalPolicyRow '44444444-4444-4444-4444-444444444444' $null
            $row.PSObject.Properties.Remove('Policy')
            $row | Add-Member -MemberType ScriptProperty -Name Policy -Value {
                $script:OptionalPolicyReads++
                $script:OptionalAssessmentEvents.Add('Policy:' + $script:OptionalPolicyReads)
                if ($script:OptionalPolicyReads -le 4) {
                    return $script:OptionalPolicyHealth
                }
                if ($script:OptionalPolicyReads -eq 5) {
                    return $script:OptionalPolicyFiles
                }
                return $script:OptionalPolicyOther
            }

            $result = Invoke-AssessmentOptionalFieldFixture $route $directory @($row)
            $expectedEvents = @(
                'DirectoryPolicy', 'HostChecks:1'
                'Policy:1', 'Policy:2', 'Policy:3', 'Policy:4', 'GpoPolicy'
                'Policy:5', 'Files', 'Policy:6', 'UnparsedFiles', 'HostChecks:2'
            )
            Assert-Equal ($expectedEvents -join ',') ($script:OptionalAssessmentEvents -join ',')
            Assert-Equal 'first' $result.Checks[1].Target
            Assert-Equal 'later' $result.Data.Directory.HostChecks.Target
            Assert-Equal 'files from fifth read' $result.Data.Policies[0].Files
            Assert-Equal 'unparsed from sixth read' $result.Data.Policies[0].UnparsedFiles
        }
    }

    Test-Assessment 'StrictMode native collector handles host-disabled and unreadable GPO rows' {
        $savedIntegrations = @{}
        $integrations = @{
            'Get-ADRootDSE' = {
                [CmdletBinding()]
                param($Server, $Credential)

                Assert-Equal 'assessment.fixture.invalid' $Server
                [pscustomobject]@{ DnsHostName = 'dc.assessment.fixture.invalid' }
            }
            'Get-ADAnalyzerDirectoryData' = {
                [CmdletBinding()]
                param($Context, $Profile)

                Assert-Equal 'dc.assessment.fixture.invalid' $Context.Server
                Assert-True (-not $Context.IncludeHostChecks) 'This fixture must keep host collection disabled.'
                New-AssessmentFixture $Context.Domain
            }
            'Get-ADAnalyzerGpo' = {
                [CmdletBinding()]
                param([switch]$All, $Domain, $Server, $Credential)

                Assert-True (
                    $All -and $Domain -ceq 'assessment.fixture.invalid' -and $Server -ceq 'dc.assessment.fixture.invalid'
                ) 'The fixture catalog request used an unexpected target.'
                foreach ($id in '55555555-5555-5555-5555-555555555555', '66666666-6666-6666-6666-666666666666') {
                    [pscustomobject]@{
                        Id = $id
                        Version = 1
                    }
                }
            }
            'Get-ADAnalyzerGpoReport' = {
                [CmdletBinding()]
                param($Gpo, $Credential, [switch]$AsObject)

                Assert-True $AsObject 'The fixture expected an object report.'
                if ($Gpo.Id -eq '55555555-5555-5555-5555-555555555555') {
                    throw 'fixture policy read failed'
                }
                [pscustomobject]@{ Policy = New-PolicyFixture }
            }
        }
        try {
            foreach ($name in $integrations.Keys) {
                $path = 'Function:script:' + $name
                $previous = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                if ($null -ne $previous) {
                    $savedIntegrations[$path] = $previous.ScriptBlock
                }
                else {
                    $savedIntegrations[$path] = $null
                }
                Set-Item -LiteralPath $path -Value $integrations[$name]
            }
            Set-StrictMode -Version Latest
            $result = Get-ADAnalyzerAssessment -Domain 'assessment.fixture.invalid'

            Assert-Equal Partial $result.State
            Assert-Equal 'dc.assessment.fixture.invalid' $result.Context.Server
            Assert-True ($null -eq $result.Data.Directory.PSObject.Properties['HostChecks']) 'Unexpected host configuration in snapshot.'
            Assert-Equal 2 $result.Data.Policies.Count
            Assert-Equal '55555555-5555-5555-5555-555555555555' $result.Errors[0].Target
            Assert-Equal 'fixture policy read failed' $result.Data.Policies[0].ReadError
            Assert-True (
                $null -eq $result.Data.Policies[0].Files -and $null -eq $result.Data.Policies[0].UnparsedFiles
            ) 'The unreadable report did not preserve null metadata.'
            Assert-True (
                $result.Data.Policies[1].Files -is [array] -and $result.Data.Policies[1].Files.Count -eq 0 -and
                $result.Data.Policies[1].UnparsedFiles -is [array] -and $result.Data.Policies[1].UnparsedFiles.Count -eq 0
            ) 'The readable sibling did not retain its empty arrays.'
        }
        finally {
            foreach ($path in $savedIntegrations.Keys) {
                if ($null -eq $savedIntegrations[$path]) {
                    Remove-Item -LiteralPath $path
                }
                else {
                    Set-Item -LiteralPath $path -Value $savedIntegrations[$path]
                }
            }
        }
    }
}
finally {
    Set-Item Function:script:Test-ADAnalyzerDirectoryPolicy $originalOptionalDirectoryPolicy
    Set-Item Function:script:Test-ADAnalyzerGpoPolicy $originalOptionalGpoPolicy
}

foreach ($case in @(
        'Construction',
        'Parity',
        'Types',
        'Merge',
        'Files',
        'Validation',
        'Isolation',
        'Serialization',
        'Ownership',
        'ProfileOnly',
        'NativeValues'
    )) {
    Test-Assessment ('constructor profile API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File (
            Join-Path $PSScriptRoot 'ProfileClassFixture.ps1'
        ) -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            foreach ($line in $output) {
                Write-Host ('Fixture output: ' + [string]$line)
            }
            throw ($output -join [Environment]::NewLine)
        }
        Assert-True (($output -join ' ') -like ('*PASS profile class ' + $case + '*')) 'Fresh process did not execute the selected profile case.'
        if ($case -eq 'NativeValues') {
            Assert-True (($output -join ' ') -like '*PASS native hash scenarios 256*') 'Fresh process did not execute every native hash scenario.'
        }
    }
}

$checkFactoryCases = [ordered]@{
    Creation = 17
    Suppression = 18
    Failures = 72
    Direct = 38
}
foreach ($case in $checkFactoryCases.Keys) {
    Test-Assessment ('check factory API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'CheckFactoryFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS check factory ' + $case + ' ' + $checkFactoryCases[$case]
        Assert-True ($marker -cin @($output)) 'Fresh process did not execute every check factory case.'
    }
}

$baselineImporterCases = [ordered]@{
    Contracts = 10
    Direct = 10
}
foreach ($case in $baselineImporterCases.Keys) {
    Test-Assessment ('baseline importer API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $arguments = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File'
            (Join-Path $PSScriptRoot 'BaselineImporterClassFixture.ps1')
            '-Case'
            $case
            '-RepositoryRoot'
            $RepositoryRoot
        )

        $fixtureErrorPreference = $ErrorActionPreference
        try {
            # Capture native stderr before checking the child exit code on 5.1.
            $ErrorActionPreference = 'Continue'
            $output = @(& $executable @arguments 2>&1)
            $fixtureExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $fixtureErrorPreference
        }

        if ($fixtureExitCode -ne 0) {
            throw ("Baseline importer fixture exited with code {0}.{1}{2}" -f
                $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
        }

        $sentinels = @($output | Where-Object { $_ -is [string] -and $_ -clike 'PASS baseline importer*' })
        Assert-Equal 1 $sentinels.Count
        $summary = [regex]::Match($sentinels[0], ('\APASS baseline importer {0} ([1-9][0-9]*)\z' -f $case))
        $executed = 0
        Assert-True (
            $summary.Success -and
            [int]::TryParse($summary.Groups[1].Value, [ref]$executed) -and
            $executed -ge $baselineImporterCases[$case]
        ) ("Fresh process did not report at least {0} baseline importer {1} cases." -f
            $baselineImporterCases[$case], $case)
    }
}
foreach ($case in 'Native', 'Direct') {
    Test-Assessment ('scoped Users evidence comparison: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $arguments = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File'
            (Join-Path $PSScriptRoot 'DirectoryUsersComparisonFixture.ps1')
            '-Case'
            $case
            '-RepositoryRoot'
            $RepositoryRoot
        )
        $priorPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $executable @arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $priorPreference
        }
        if ($exitCode -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS AD-03 compare ' + $case + ' 29'
        Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
    }
}

$assessmentCollectorCases = [ordered]@{
    Native = 52
    Construction = 2
    Direct = 11
    Isolation = 2
    Composition = 8
}
foreach ($case in $assessmentCollectorCases.Keys) {
    Test-Assessment ('assessment collector API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $arguments = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File'
            (Join-Path $PSScriptRoot 'AssessmentCollectorClassFixture.ps1')
            '-Case'
            $case
            '-RepositoryRoot'
            $RepositoryRoot
        )
        $fixtureErrorPreference = $ErrorActionPreference
        try {
            # Capture native stderr before checking the child exit code on 5.1.
            $ErrorActionPreference = 'Continue'
            $output = @(& $executable @arguments 2>&1)
            $fixtureExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $fixtureErrorPreference
        }
        if ($fixtureExitCode -ne 0) {
            throw ("Assessment collector fixture exited with code {0}.{1}{2}" -f
                $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
        }
        $marker = 'PASS assessment collector ' + $case + ' ' + $assessmentCollectorCases[$case]
        Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
        if ($case -eq 'Native') {
            $ignoreParity = @($output | Where-Object { $_ -is [string] -and $_ -clike 'PASS assessment Ignore parity *' })
            Assert-Equal 1 $ignoreParity.Count
            Write-Host $ignoreParity[0]
        }
    }
}

$prerequisiteInspectorCases = [ordered]@{
    Native = 10
    Standalone = 2
    Direct = 4
    Isolation = 2
    Online = 14
    RootDse = 21
}
foreach ($case in $prerequisiteInspectorCases.Keys) {
    Test-Assessment ('prerequisite inspector API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $arguments = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File'
            (Join-Path $PSScriptRoot 'PrerequisiteInspectorClassFixture.ps1')
            '-Case'
            $case
            '-RepositoryRoot'
            $RepositoryRoot
        )
        $fixtureErrorPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $executable @arguments 2>&1)
            $fixtureExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $fixtureErrorPreference
        }
        if ($fixtureExitCode -ne 0) {
            throw ("Prerequisite inspector fixture exited with code {0}.{1}{2}" -f
                $fixtureExitCode, [Environment]::NewLine, ($output -join [Environment]::NewLine))
        }
        $marker = 'PASS prerequisite inspector ' + $case + ' ' + $prerequisiteInspectorCases[$case]
        Assert-Equal 1 @($output | Where-Object { $_ -is [string] -and $_ -ceq $marker }).Count
    }
}

Write-Host ("{0} assessment-integration tests passed; {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed) {
    exit 1
}
