[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
. (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
. (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
. (Join-Path $RepositoryRoot 'bin/ADPolicyAnalysis.ps1')
. (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
$script:Passed = 0
$script:Failed = 0

function Assert-Policy($Actual, [string]$Message) {
    if (-not $Actual) {
        throw $Message
    }
}

function Test-Policy([string]$Name, [scriptblock]$Body) {
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

function New-PolicyFixture {
    [pscustomobject]@{
        SecuritySettings = @()
        RegistrySettings = @()
        IniSettings = @()
        XmlFiles = @()
        Files = @()
        UnparsedFiles = @()
    }
}

function New-RegistryFixture([string]$Key, [string]$ValueName, $Value, [int]$Type = 4) {
    [pscustomobject]@{
        Scope = 'Computer'
        Hive = 'HKLM'
        Key = $Key
        ValueName = $ValueName
        Value = $Value
        Type = $Type
        RawData = [byte[]]@()
        Source = 'Machine/Registry.pol'
        KeyOnly = $false
    }
}

function Get-PolicyChecks($Policy, $Profile = $script:Profile, $Gpo = $script:Gpo) {
    @(Test-ADAnalyzerGpoPolicy -Gpo $Gpo -Policy $Policy -Profile $Profile)
}
$script:Profile = Get-ADAnalyzerDefaultProfile
$script:Gpo = [pscustomobject]@{
    Id = [guid]'11111111-1111-1111-1111-111111111111'
    Flags = 0
    Links = @()
}

function New-IdentityPreferenceFile([string]$Path, [object[]]$Entries, [string]$Scope = 'Computer') {
    $document = [xml]'<Groups/>'
    foreach ($entry in $Entries) {
        $item = $document.CreateElement('Group')
        if ($null -ne $entry.Uid) {
            $item.SetAttribute('uid', [string]$entry.Uid)
        }
        $properties = $document.CreateElement('Properties')
        $properties.SetAttribute('action', 'U')
        $properties.SetAttribute('groupSid', 'S-1-5-32-544')
        $properties.SetAttribute('groupName', 'Administrators')
        $null = $item.AppendChild($properties)
        $null = $document.DocumentElement.AppendChild($item)
    }
    [pscustomobject]@{
        Scope = $Scope
        Path = $Path
        Kind = 'Preferences'
        Xml = $document.OuterXml
    }
}

function Get-IdentityPreferenceChecks($Policy) {
    @(Get-PolicyChecks $Policy | Where-Object RuleId -eq 'GPO.Preferences.LocalUsersGroups')
}
foreach ($mode in @('Construction', 'Parity', 'PartialProfile', 'Secrets', 'Types', 'Streaming', 'Validation', 'Isolation', 'Order')) {
    Test-Policy ('constructor GPO policy: ' + $mode) {
        $childArguments = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File'
            (Join-Path $RepositoryRoot 'tests/GpoPolicyClassFixture.ps1')
            '-RepositoryRoot'
            $RepositoryRoot
            '-Mode'
            $mode
        )
        $output = @(& (Get-Process -Id $PID).Path @childArguments)
        Assert-Policy ($LASTEXITCODE -eq 0) 'GPO policy class child failed'
        Assert-Policy (($output -join ' ') -match ('PASS GPO policy class ' + $mode)) 'GPO policy class child did not finish'
    }
}
Test-Policy 'raw credentials and presence markers describe one XML owner' {
    foreach ($attributes in @('cpassword="fixture-secret" cpasswordPresent="true"',
            'cpassword="fixture-secret" cpasswordPresent="false"',
            'cpassword="" cpasswordPresent="true"',
            'cpassword="" cpasswordPresent="false"')) {
        $xml = '<Groups><User uid="same"><Properties ' + $attributes + '/></User><User uid="same"><Properties ' + $attributes + '/></User></Groups>'
        $ids = @()
        $counts = @()
        foreach ($text in @($xml, (ConvertTo-ADAnalyzerSecretIndicatorXml ([xml]$xml)).OuterXml)) {
            $policy = New-PolicyFixture
            $policy.XmlFiles = @([pscustomobject]@{
                    Scope = 'Computer'
                    Path = 'Groups.xml'
                    Xml = $text
                })
            $checks = @(Get-PolicyChecks $policy | Where-Object RuleId -eq GPO.Preferences.CPassword)
            $ids += , ($checks.CheckId -join ',')
            $counts += @($checks | Where-Object Status -eq Fail).Count
            Assert-Policy (@($checks | Group-Object CheckId | Where-Object Count -gt 1).Count -eq 0) 'Distinct owners collided'
            Assert-Policy (($checks | ConvertTo-Json -Depth 50) -notmatch 'fixture-secret') 'Credential value escaped'
        }
        $expected = if ($attributes -eq 'cpassword="" cpasswordPresent="false"') {
            0
        }
        else {
            2
        }
        Assert-Policy ($counts[0] -eq $expected -and
            $counts[1] -eq $expected -and
            $ids[0] -eq $ids[1]) 'One owner counted twice or changed identity after projection'
    }
}
Test-Policy 'XML credential and named secret duplicates retain unique stable assessment identities' {
    foreach ($name in @('ADDirectoryAnalysis', 'ADAssessment')) {
        . (Join-Path $RepositoryRoot ('bin/' + $name + '.ps1'))
    }
    $xml = '<Groups><User uid="dup"><Properties action="U" userName="one" cpassword="fixture-a"/></User><User uid="dup"><Properties action="U" userName="two" cpassword="fixture-b"/></User><User uid="named"><Properties name="DefaultPassword" value="fixture-c"/></User><User uid="named"><Properties name="DefaultPassword" value="fixture-d"/></User><User uid="unique"><Properties action="U" cpassword="fixture-e"/></User></Groups>'
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Machine/Preferences/Groups/Groups.xml'
            Xml = $xml
        })
    $before = ConvertTo-Json -InputObject $policy -Depth 50 -Compress
    $old = @(Get-PolicyChecks $policy | Where-Object { $_.RuleId -in 'GPO.Preferences.CPassword', 'GPO.StoredSecret' })
    Assert-Policy ($old.Count -eq 5 -and
        @($old | Group-Object CheckId | Where-Object Count `
                -gt 1).Count -eq 0) 'Duplicate secret records collided or were dropped'
    $projected = New-PolicyFixture
    $projected.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = $policy.XmlFiles[0].Path
            Xml = (ConvertTo-ADAnalyzerSecretIndicatorXml ([xml]$xml)).OuterXml
        })
    $new = @(Get-PolicyChecks $projected | Where-Object { $_.RuleId -in 'GPO.Preferences.CPassword', 'GPO.StoredSecret' })
    Assert-Policy (($old.CheckId -join ',') -eq ($new.CheckId -join ',')) 'Projection changed secret identities'
    $projected.XmlFiles[0].Xml = $projected.XmlFiles[0].Xml.Replace('<Groups>',
        '<Groups><User uid="unrelated/duplicate/1"><Properties action="U" cpasswordPresent="true"/></User>')
    $inserted = @(Get-PolicyChecks $projected | Where-Object { $_.RuleId -in 'GPO.Preferences.CPassword', 'GPO.StoredSecret' })
    Assert-Policy (@($old | Where-Object { $_.CheckId -notin $inserted.CheckId }).Count -eq 0) 'Unrelated UID insertion renumbered secret records'
    $result = Invoke-ADAnalyzerAssessment -DirectoryData ([pscustomobject]@{
            Users = @()
            Computers = @()
            ServiceAccounts = @()
            Errors = @()
        }) -GpoData @([pscustomobject]@{
            Gpo = $script:Gpo
            Policy = $policy
        }) -Profile $script:Profile
    Assert-Policy (@($result.Checks | Group-Object CheckId | Where-Object Count `
                -gt 1).Count -eq 0) 'Public assessment retained duplicate identities'
    Assert-Policy (($result | ConvertTo-Json -Depth 100) -notmatch 'fixture-[a-e]') 'Assessment retained secret payloads'
    Assert-Policy ($before -ceq (ConvertTo-Json -InputObject $policy -Depth 50 -Compress)) 'Secret evaluation mutated source'
}
Test-Policy 'GPP UID identities survive unrelated insertion item reorder and file reorder' {
    $before = New-PolicyFixture
    $before.XmlFiles = @(
        (New-IdentityPreferenceFile 'Machine/Preferences/A.xml' @(@{
                Uid = 'alpha'
            }, @{
                Uid = 'beta'
            })),
        (New-IdentityPreferenceFile 'Machine/Preferences/B.xml' @(@{
                Uid = 'gamma'
            }))
    )
    $after = New-PolicyFixture
    $after.XmlFiles = @(
        $before.XmlFiles[1], (New-IdentityPreferenceFile 'Machine/Preferences/A.xml' @(@{
                    Uid = 'unrelated'
                }, @{
                    Uid = 'beta'
                }, @{
                    Uid = 'alpha'
                }))
    )
    $source = ConvertTo-Json -InputObject $before -Depth 100 -Compress
    $old = @(Get-IdentityPreferenceChecks $before)
    $new = @(Get-IdentityPreferenceChecks $after)
    foreach ($check in $old) {
        $match = @($new | Where-Object { $_.Observed.Uid -eq $check.Observed.Uid })
        Assert-Policy ($match.Count -eq 1 -and $match[0].CheckId -eq $check.CheckId) 'Unrelated GPP change renumbered an existing UID'
    }
    $comparison = Compare-ADAnalyzerAssessment @{
        SchemaVersion = 1
        Checks = $old
    } @{
        SchemaVersion = 1
        Checks = $new
    }
    Assert-Policy ($comparison.Summary.Unchanged -eq 3 -and
        $comparison.Summary.New -eq 1 -and
        $comparison.Summary.Changed -eq 0) 'UID comparison introduced false drift'
    Assert-Policy ($source -eq (ConvertTo-Json -InputObject $before -Depth 100 -Compress)) 'Identity evaluation mutated source'
}
Test-Policy 'GPP identity collisions remain local and missing UIDs remain file-local' {
    $policy = New-PolicyFixture
    $policy.XmlFiles = @(
        (New-IdentityPreferenceFile 'Machine/Preferences/A.xml' @(@{
                Uid = 'dup'
            }, @{
                Uid = 'dup'
            }, @{
                Uid = 'dup/duplicate/1'
            }, @{})),
        (New-IdentityPreferenceFile 'Machine/Preferences/B.xml' @(@{
                Uid = 'dup'
            }, @{})),
        (New-IdentityPreferenceFile 'User/Preferences/A.xml' @(@{
                Uid = 'dup'
            }) User),
        (New-IdentityPreferenceFile 'Machine/Preferences/A.xml/Uid' @(@{
                Uid = 'literal'
            })),
        (New-IdentityPreferenceFile 'Machine/Preferences/A.xml' @(@{
                Uid = 'Uid/literal'
            }))
    )
    $old = @(Get-IdentityPreferenceChecks $policy)
    Assert-Policy ($old.Count -eq 9 -and
        @($old | Group-Object CheckId | Where-Object Count `
                -gt 1).Count -eq 0) 'Duplicate records were dropped or identities collided'
    $reordered = New-PolicyFixture
    $files = @($policy.XmlFiles)
    [array]::Reverse($files)
    $reordered.XmlFiles = @((New-IdentityPreferenceFile 'Machine/Preferences/Other.xml' @(@{
                    Uid = 'unrelated'
                }))) + $files
    $new = @(Get-IdentityPreferenceChecks $reordered)
    $comparison = Compare-ADAnalyzerAssessment @{
        SchemaVersion = 1
        Checks = $old
    } @{
        SchemaVersion = 1
        Checks = $new
    }
    Assert-Policy ($comparison.Summary.Unchanged -eq 9 -and
        $comparison.Summary.New -eq 1 -and
        $comparison.Summary.Changed -eq 0) 'File order or another family renumbered retained items'
    $missing = @($old | Where-Object { -not $_.Observed.Uid })
    Assert-Policy ($missing.Count -eq 2 -and
        @($missing | Where-Object { -not $_.Observed.ItemPath }).Count -eq 0) 'Missing UID lost its file-local path'
}
Test-Policy 'GPP literal identity components support long and non-ASCII UIDs without encoding limits' {
    $uid = ('x' * 70000) + [char]0x00FC + '/duplicate/1:|'
    $policy = New-PolicyFixture
    $policy.XmlFiles = @(New-IdentityPreferenceFile 'Machine/Preferences/Long.xml' @(@{
                Uid = $uid
            }, @{
                Uid = 'short'
            }))
    $checks = @(Get-IdentityPreferenceChecks $policy)
    Assert-Policy ($checks.Count -eq 2 -and $checks[0].Observed.Uid.Length -eq $uid.Length) 'Large UID was truncated or rejected'
    Assert-Policy ($checks[0].CheckId -ne $checks[1].CheckId) 'Literal identity components collided'
}
Test-Policy 'repeated security source identities keep all rows and local occurrence numbers' {
    $source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
    $name = 'Network access: Named Pipes that can be accessed anonymously'
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @(
        [pscustomobject]@{
            Scope = 'Computer'
            Source = $source
            Kind = 'SecurityOptions'
            Name = $name
            Value = 'LSARPC'
        },
        [pscustomobject]@{
            Scope = 'Computer'
            Source = $source
            Kind = 'SecurityOptions'
            Name = $name
            Value = 'NETLOGON'
        },
        [pscustomobject]@{
            Scope = 'User'
            Source = 'User/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            Kind = 'SecurityOptions'
            Name = $name
            Value = 'SAMR'
        }
    )
    $policy.RegistrySettings = @(New-RegistryFixture 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' NullSessionPipes @('LSARPC') 7)
    $before = ConvertTo-Json -InputObject $policy -Depth 100 -Compress
    $old = @(Get-PolicyChecks $policy | Where-Object RuleId -eq GPO.Security.Server.NullSessionPipes)
    $other = New-PolicyFixture
    $other.SecuritySettings = $policy.SecuritySettings
    $new = @(Get-PolicyChecks $other | Where-Object RuleId -eq GPO.Security.Server.NullSessionPipes)
    Assert-Policy ($old.Count -eq 4 -and
        $new.Count -eq 3 -and
        @($old | Group-Object CheckId | Where-Object Count `
                -gt 1).Count -eq 0) 'Repeated security rows were dropped or collided'
    foreach ($check in $new) {
        Assert-Policy ($check.CheckId -in $old.CheckId -and
            $check.Status -eq 'Pass') 'Another source changed retained security identity or evaluation'
    }
    $comparison = Compare-ADAnalyzerAssessment @{
        SchemaVersion = 1
        Checks = $old
    } @{
        SchemaVersion = 1
        Checks = $new
    }
    Assert-Policy ($comparison.Summary.Unchanged -eq 3 -and
        $comparison.Summary.Changed -eq 1 -and
        $comparison.Summary.New -eq 0) 'Security comparison introduced false drift'
    Assert-Policy ($before -eq (ConvertTo-Json -InputObject $policy -Depth 100 -Compress)) 'Security identity evaluation mutated source'
}

Test-Policy 'direct raw profiles reject secret-value rules before emitting any policy checks' {
    foreach ($section in @('RegistryRules', 'ExpectedGpoSettings')) {
        foreach ($rule in @(
                @{
                    Kind = 'Registry'
                    Key = 'Software\Fixture'
                    ValueName = 'DefaultPassword'
                    Expected = 'unit7-policy-secret'
                }
                @{
                    Kind = 'SecurityOptions'
                    Name = 'MACHINE\Software\Fixture\DefaultPassword'
                    Expected = 'unit7-policy-secret'
                }
                @{
                    Kind = 'SecurityOptions'
                    Key = 'MACHINE\Software\Fixture\DefaultPassword'
                    Expected = 'unit7-policy-secret'
                }
                @{
                    Name = 'Friendly label'
                    ValueName = 'DefaultPassword'
                    Expected = 'unit7-policy-secret'
                }
                @{
                    Name = 'Friendly label'
                    Key = 'Software\Fixture\DefaultPassword'
                    Expected = 'unit7-policy-secret'
                }
                @{
                    Kind = 'SecurityOptions'
                    Name = 'MACHINE\Software\Fixture\DefaultPassword'
                    ValueName = 'Enabled'
                    Expected = 'unit7-policy-secret'
                }
            )) {
            $profile = Get-ADAnalyzerDefaultProfile
            $profile[$section] = @($rule)
            $emitted = [Collections.ArrayList]::new()
            $caught = $null
            try {
                Test-ADAnalyzerGpoPolicy `
                    -Gpo $script:Gpo `
                    -Policy (New-PolicyFixture) `
                    -Profile $profile | ForEach-Object { $null = $emitted.Add($_) }
            }
            catch {
                $caught = $_
            }
            Assert-Policy ($null -ne $caught) 'Raw profile secret baseline accepted'
            Assert-Policy ($emitted.Count -eq 0) 'Policy emitted checks before rejecting a secret rule'
            Assert-Policy ($caught.Exception.Message -eq 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.') 'Unexpected error contract'
            Assert-Policy (([string]$caught.TargetObject) -notmatch 'unit7-policy-secret') 'Secret in error target'
        }
    }
}
Test-Policy 'missing settings are NotConfigured with unknown applicability' {
    $checks = Get-PolicyChecks (New-PolicyFixture)
    $length = $checks | Where-Object RuleId -eq 'GPO.Account.MinimumPasswordLength'
    Assert-Policy ($length.Status -eq 'NotConfigured' -and
        $length.Applicability -eq 'Unknown') 'Missing setting was reported as compliant/effective'
    Assert-Policy (@($checks | Group-Object CheckId | Where-Object Count -gt 1).Count -eq 0) 'Duplicate check identities'
}
Test-Policy 'malformed baseline identities cannot conceal a secret or act as a multi-setting query' {
    foreach ($section in @('RegistryRules', 'ExpectedGpoSettings', 'Host')) {
        foreach ($rule in @(
                @{
                    ValueName = ''
                    Name = @('DefaultPassword', 'Friendly')
                    Key = 'Software\Fixture'
                    Expected = 'unit7-array-secret'
                }
                @{
                    Kind = 'SecurityOptions'
                    Name = @($null, $null)
                    ValueName = 'DefaultPassword'
                    Expected = 'unit7-array-secret'
                }
                @{
                    Kind = @('SecurityOptions', 'Registry')
                    Name = 'Friendly'
                    ValueName = 'DefaultPassword'
                    Expected = 'unit7-array-secret'
                }
                @{
                    Key = @{
                        Name = 'DefaultPassword'
                    }
                    Expected = 'unit7-array-secret'
                }
            )) {
            $profile = Get-ADAnalyzerDefaultProfile
            if ($section -eq 'Host') {
                $profile.Host.RegistryRules = @($rule)
            }
            else {
                $profile[$section] = @($rule)
            }
            $caught = $null
            try {
                $null = Import-ADAnalyzerProfile -Profile $profile
            }
            catch {
                $caught = $_
            }
            Assert-Policy ($null -ne $caught -and
                $caught.Exception.Message -eq 'Custom value baseline identity fields must be strings or null.') 'Malformed profile identity accepted'
            $emitted = [Collections.ArrayList]::new()
            $caught = $null
            try {
                Test-ADAnalyzerGpoPolicy `
                    -Gpo $script:Gpo `
                    -Policy (New-PolicyFixture) `
                    -Profile $profile | ForEach-Object { $null = $emitted.Add($_) }
            }
            catch {
                $caught = $_
            }
            Assert-Policy ($null -ne $caught -and $emitted.Count -eq 0) 'Malformed raw profile emitted evidence'
            Assert-Policy ($caught.Exception.Message -eq 'Custom value baseline identity fields must be strings or null.' -and
                ([string]$caught.TargetObject) -notmatch 'unit7-array-secret') 'Malformed identity error exposed supplied data'
        }
    }
}
Test-Policy 'password and lockout sentinel values retain their meaning' {
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @(
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'MaximumPasswordAge'
            Value = -1L
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        }
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'LockoutBadCount'
            Value = 0L
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        }
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'LockoutDuration'
            Value = -1L
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        }
    )
    $checks = Get-PolicyChecks $policy
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Account.MaximumPasswordAge).Status -eq 'Fail') 'Never-expiring password passed positive max age'
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Account.LockoutBadCount).Status -eq 'Fail') 'Disabled lockout passed positive threshold'
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Account.LockoutDuration).Status -eq 'Pass') 'Manual unlock was misread as short duration'
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Policy.AllowPasswordNeverExpires = $true
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Account.MaximumPasswordAge).Status -eq 'Pass') 'Never-expire profile override ignored'
}
Test-Policy 'invalid account types are not coerced to compliance values' {
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @([pscustomobject]@{
            Kind = 'Account'
            Name = 'MinimumPasswordLength'
            Value = 'twelve'
            Scope = 'Computer'
        })
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object RuleId `
                -eq GPO.Account.MinimumPasswordLength).Status -eq 'Invalid') 'Invalid length did not remain Invalid'
}
Test-Policy 'real INF invalid flags cannot pass and valid neighboring settings remain assessed' {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('ad-invalid-flags-' + [guid]::NewGuid().ToString('N'))
    try {
        $directory = Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit'
        $null = [IO.Directory]::CreateDirectory($directory)
        foreach ($token in @('-1', '65537', 'true', '')) {
            $text = "[System Access]`nPasswordComplexity=$token`nClearTextPassword=$token`nLSAAnonymousNameLookup=$token`nMinimumPasswordLength=16"
            [IO.File]::WriteAllText((Join-Path $directory 'GptTmpl.inf'), $text, [Text.Encoding]::Unicode)
            $checks = Get-PolicyChecks (Read-ADAnalyzerGpo $root)
            foreach ($id in @('GPO.Account.PasswordComplexity', 'GPO.Account.ClearTextPassword', 'GPO.Security.LSAAnonymousNameLookup')) {
                Assert-Policy (($checks | Where-Object RuleId `
                            -eq $id).Status -eq 'Invalid') ($id + ' incorrectly classified a malformed flag')
            }
            Assert-Policy (($checks | Where-Object RuleId `
                        -eq GPO.Account.MinimumPasswordLength).Status -eq 'Pass') 'Valid neighbor was lost'
        }
    }
    finally {
        if ([IO.Directory]::Exists($root)) {
            [IO.Directory]::Delete($root, $true)
        }
    }
}
Test-Policy 'misplaced INF account and Kerberos settings cannot satisfy baselines' {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('ad-section-policy-' + [guid]::NewGuid().ToString('N'))
    try {
        $directory = Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit'
        $null = [IO.Directory]::CreateDirectory($directory)
        [IO.File]::WriteAllText((Join-Path $directory 'GptTmpl.inf'),
            "[System Access]`nMinimumPasswordLength=16`nTicketValidateClient=1`n[Kerberos Policy]`nPasswordComplexity=1`nMaxTicketAge=10",
            [Text.Encoding]::Unicode)
        $policy = Read-ADAnalyzerGpo $root
        $checks = Get-PolicyChecks $policy
        Assert-Policy (($checks | Where-Object RuleId `
                    -eq GPO.Account.PasswordComplexity).Status -eq 'NotConfigured') 'Misplaced password flag became compliance evidence'
        Assert-Policy (@($policy.SecuritySettings | Where-Object Name `
                    -eq TicketValidateClient).Count -eq 0) 'Misplaced Kerberos setting promoted'
        Assert-Policy (($checks | Where-Object RuleId -eq GPO.Account.MinimumPasswordLength).Status -eq 'Pass') 'Valid neighbor lost'
        $coverage = @($checks | Where-Object RuleId -eq GPO.Coverage.UnsupportedInfSettings)
        Assert-Policy ($coverage.Count -eq 1 -and
            $coverage[0].Status -eq 'Unknown' -and
            @($coverage[0].Observed).Count -eq 2) 'Unsupported section settings missing from coverage'
        Assert-Policy (@($coverage[0].Observed | Where-Object { $null -ne $_.PSObject.Properties['Value'] }).Count -eq 0) 'Coverage unexpectedly includes payload values'
    }
    finally {
        if ([IO.Directory]::Exists($root)) {
            [IO.Directory]::Delete($root, $true)
        }
    }
}
Test-Policy 'unsupported INF coverage requires explicit false metadata and authoritative account provenance' {
    $policy = New-PolicyFixture
    $policy.IniSettings = @(
        [pscustomobject]@{
            Scope = 'Computer'
            Source = 'Machine/Scripts/GptTmpl.inf'
            Section = 'System Access'
            Name = 'Unknown'
            Analyzed = $false
        }
        [pscustomobject]@{
            Scope = 'Computer'
            Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            Section = 'Version'
            Name = 'Revision'
            Analyzed = $false
        }
        [pscustomobject]@{
            Scope = 'Computer'
            Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            Section = 'System Access'
            Name = 'OldDto'
        }
        [pscustomobject]@{
            Scope = 'Computer'
            Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            Section = 'System Access'
            Name = 'StringMarker'
            Analyzed = 'false'
        }
    )
    Assert-Policy (@((Get-PolicyChecks $policy) | Where-Object RuleId `
                -eq GPO.Coverage.UnsupportedInfSettings).Count -eq 0) 'Compatibility rows produced unsupported coverage'
    $policy.IniSettings += @([pscustomobject]@{
            Scope = 'User'
            Source = 'User\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            Section = 'kerberos policy'
            Name = 'Unknown'
            Analyzed = $false
        })
    $checks = @((Get-PolicyChecks $policy) | Where-Object RuleId -eq GPO.Coverage.UnsupportedInfSettings)
    Assert-Policy ($checks.Count -eq 1 -and @($checks[0].Observed).Count -eq 1) 'User template provenance or case handling lost'
}
Test-Policy 'explicit invalid metadata overrides default and custom value comparisons' {
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @([pscustomobject]@{
            Kind = 'Account'
            Name = 'PasswordComplexity'
            Value = 'true'
            ValueValid = $false
            Scope = 'Computer'
            Source = 'Machine/GptTmpl.inf'
        })
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.ExpectedGpoSettings = @(@{
            Id = 'single-invalid'
            Kind = 'Account'
            Name = 'PasswordComplexity'
            Expected = 'true'
        }, @{
            Id = 'aggregate-invalid'
            Kind = 'Account'
            Name = 'PasswordComplexity'
            Expected = @('true')
            Aggregate = $true
        })
    $checks = Get-PolicyChecks $policy $profile
    foreach ($id in @('GPO.Account.PasswordComplexity', 'GPO.Expected.single-invalid', 'GPO.Expected.aggregate-invalid')) {
        Assert-Policy (($checks | Where-Object RuleId -eq $id).Status -eq 'Invalid') 'Invalid source passed a configured comparison'
    }
    $policy.SecuritySettings[0].Value = $true
    $policy.SecuritySettings[0].PSObject.Properties.Remove('ValueValid')
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object RuleId `
                -eq GPO.Account.PasswordComplexity).Status -eq 'Pass') 'Unmarked existing DTO behavior changed'
}
Test-Policy 'cpassword is detected in disabled stored content without leaking it' {
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Machine/Preferences/Groups/Groups.xml'
            Xml = '<Groups><User disabled="1" uid="id1"><Properties action="U" userName="fixture" cpassword="DO_NOT_OUTPUT_THIS_SECRET" /></User></Groups>'
        })
    $gpo = [pscustomobject]@{
        Id = $script:Gpo.Id
        Flags = 3
        Links = @()
    }
    $checks = Get-PolicyChecks $policy $script:Profile $gpo
    $exposure = $checks | Where-Object RuleId -eq GPO.Preferences.CPassword
    Assert-Policy ($exposure.Status -eq 'Fail' -and $exposure.Applicability -eq 'Configured') 'Disabled GPO hid exposed credentials'
    Assert-Policy ($exposure.Observed -is [bool] -and
        $exposure.Observed -and
        $exposure.Evidence.SecretPresent) 'Expected boolean secret presence'
    Assert-Policy (($checks | ConvertTo-Json -Depth 30) -notmatch 'DO_NOT_OUTPUT_THIS_SECRET') 'Secret leaked into assessment'
}
Test-Policy 'presence-only XML retains the same credential finding identity' {
    $policy = New-PolicyFixture
    $file = [pscustomobject]@{
        Scope = 'Computer'
        Path = 'Groups.xml'
        Xml = '<Groups><User uid="stable"><Properties cpassword="fixture-secret" /></User></Groups>'
    }
    $policy.XmlFiles = @($file)
    $raw = (Get-PolicyChecks $policy) | Where-Object RuleId -eq GPO.Preferences.CPassword
    $file.Xml = ConvertTo-ADAnalyzerSecretIndicatorText $file.Xml
    $safe = (Get-PolicyChecks $policy) | Where-Object RuleId -eq GPO.Preferences.CPassword
    Assert-Policy ($safe.CheckId -eq $raw.CheckId -and $safe.Observed -eq $true) 'Presence-only reading changed detection identity'
    $file.Xml = '<Groups><User cpasswordPresent="false" /></Groups>'
    $empty = (Get-PolicyChecks $policy) | Where-Object RuleId -eq GPO.Preferences.CPassword
    Assert-Policy ($empty.Status -eq 'Pass' -and $empty.Observed -is [bool] -and -not $empty.Observed) 'False presence became a finding'
}
Test-Policy 'stored registry and INI secrets expose booleans and locations only' {
    $policy = New-PolicyFixture
    $row = New-RegistryFixture 'Software\Fixture' 'DefaultPassword' 'fixture-secret' 1
    $policy.RegistrySettings = @(ConvertTo-ADAnalyzerSecretRecord $row)
    $policy.IniSettings = @([pscustomobject]@{
            Name = 'Password'
            SecretPresent = $false
            Scope = 'User'
            Source = 'settings.ini'
            Section = 'Account'
            Analyzed = $false
        })
    $checks = @((Get-PolicyChecks $policy) | Where-Object RuleId -eq GPO.StoredSecret)
    Assert-Policy ($checks.Count -eq 2 -and
        @($checks | Where-Object { $_.Observed -eq $true }).Count -eq 1) 'Secret presence coverage is incorrect'
    Assert-Policy (($checks | ConvertTo-Json -Depth 20) -notmatch 'fixture-secret|REDACTED') 'A value or masked placeholder leaked'
    $resolved = @(Resolve-ADAnalyzerRegistryPolicy $policy.RegistrySettings)
    Assert-Policy ($resolved[0].SecretPresent -eq $true -and
        $null -eq $resolved[0].PSObject.Properties['Value']) 'Enrichment lost presence or reconstructed a value'
}
Test-Policy 'malformed XML produces Unreadable and unknown credential coverage' {
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'broken.xml'
            Xml = '<broken'
        })
    $checks = Get-PolicyChecks $policy
    Assert-Policy (($checks | Where-Object RuleId -eq GPO.Xml.Readable).Status -eq 'Unreadable') 'Malformed XML was hidden'
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Preferences.CPassword).Status -eq 'Unknown') 'Unreadable XML was called credential-clean'
}
Test-Policy 'inventoried XML requires matching evidence before reporting credential absence' {
    $policy = New-PolicyFixture
    $path = 'Machine/Preferences/Groups/Groups.xml'
    $inventory = [pscustomobject]@{
        Scope = 'Computer'
        Kind = 'Xml'
        Path = $path
    }
    $file = [pscustomobject]@{
        Scope = 'Computer'
        Kind = 'Preferences'
        Path = $path
        Xml = '<Groups><User cpasswordPresent="false" /></Groups>'
    }
    $policy.Files = @($inventory)
    $policy.XmlFiles = @($file)

    $complete = @(Get-PolicyChecks $policy)
    $original = $complete | Where-Object RuleId -eq 'GPO.Preferences.CPassword'
    Assert-Policy ($original.Status -eq 'Pass' -and
        $original.Observed -is [bool] -and -not $original.Observed) 'Complete negative evidence was lost'
    Assert-Policy (-not ($complete | Where-Object RuleId -eq 'GPO.Coverage.MissingXml')) 'Matched XML was reported missing'

    $evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
    foreach ($scenario in @('Omitted', 'WrongScope', 'WrongPath', 'DuplicateInventory')) {
        $policy.Files = @($inventory)
        $policy.XmlFiles = @($file)
        $file.Scope = 'Computer'
        $file.Path = $path
        switch ($scenario) {
            'Omitted' {
                $policy.XmlFiles = @()
            }
            'WrongScope' {
                $file.Scope = 'User'
            }
            'WrongPath' {
                $file.Path = $path.ToLowerInvariant()
            }
            'DuplicateInventory' {
                $policy.Files = @($inventory, $inventory)
            }
        }

        $commandChecks = @(Get-PolicyChecks $policy)
        $classChecks = $evaluator.Evaluate($script:Gpo, $policy, $script:Profile)
        foreach ($checks in @(@{ Values = $commandChecks }, @{ Values = $classChecks })) {
            $credential = $checks.Values | Where-Object RuleId -eq 'GPO.Preferences.CPassword'
            $gap = @($checks.Values | Where-Object RuleId -eq 'GPO.Coverage.MissingXml')
            Assert-Policy ($credential.CheckId -ceq $original.CheckId -and
                $credential.Status -eq 'Unknown' -and
                $null -eq $credential.Observed -and
                $null -eq $credential.Evidence.SecretPresent) "$scenario was treated as confirmed absence"
            Assert-Policy ($gap.Count -eq 1 -and
                $gap[0].Status -eq 'Unknown' -and
                $gap[0].Observed -is [int] -and $gap[0].Observed -eq 1) "$scenario did not report one missing payload"
        }
    }

    $policy.Files = @($inventory)
    $file.Xml = '<invalid'
    $unreadable = @(Get-PolicyChecks $policy)
    Assert-Policy (($unreadable | Where-Object RuleId -eq 'GPO.Xml.Readable').Status -eq 'Unreadable') 'Parse failure was hidden'
    Assert-Policy (-not ($unreadable | Where-Object RuleId -eq 'GPO.Coverage.MissingXml')) 'Present unreadable XML was counted as missing'

    $policy.PSObject.Properties.Remove('Files')
    $file.Xml = '<Groups />'
    $legacy = (Get-PolicyChecks $policy) | Where-Object RuleId -eq 'GPO.Preferences.CPassword'
    Assert-Policy ($legacy.CheckId -ceq $original.CheckId -and $legacy.Status -eq 'Pass' -and
        $legacy.Observed -is [bool] -and -not $legacy.Observed) 'Legacy XML without an inventory changed'
}
Test-Policy 'named XML secret detection keeps booleans locations and stable raw versus projected identity' {
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Machine/Preferences/Registry/Registry.xml'
            Xml = '<RegistrySettings><Registry uid="one" name="DefaultPassword"><Properties name="DefaultPassword" value="unit2-policy-secret"/></Registry><Registry uid="two"><Properties name="DefaultPassword" value=""/></Registry></RegistrySettings>'
        })
    $raw = @(Get-PolicyChecks $policy | Where-Object RuleId -eq GPO.StoredSecret)
    Assert-Policy ($raw.Count -eq 2 -and
        @($raw | Where-Object Status `
                -eq Fail).Count -eq 1 -and
        @($raw | Where-Object Status `
                -eq Pass).Count -eq 1) 'Named XML presence is not correctly assessed'
    foreach ($check in $raw) {
        Assert-Policy ($check.Observed -is [bool] -and
            $check.Evidence.Path -eq $policy.XmlFiles[0].Path -and
            $check.Evidence.ItemPath) 'Presence or location contract missing'
    }
    Assert-Policy (($raw | ConvertTo-Json -Depth 30) -notmatch 'unit2-policy-secret|REDACTED') 'Named XML secret leaked into checks'
    $policy.XmlFiles[0].Xml = ConvertTo-ADAnalyzerSecretIndicatorText $policy.XmlFiles[0].Xml
    $safe = @(Get-PolicyChecks $policy | Where-Object RuleId -eq GPO.StoredSecret)
    Assert-Policy ((@($raw.CheckId | Sort-Object) -join ',') -eq (@($safe.CheckId | Sort-Object) -join ',')) 'Projection changed a secret check identity'
}
Test-Policy 'Restricted Groups requires authoritative source and scope before parsing membership' {
    foreach ($source in @($null,
            'GptTmpl.inf',
            'Other.inf',
            'Machine/Scripts/GptTmpl.inf',
            'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf.bak',
            'User/Microsoft/Windows NT/SecEdit/GptTmpl.inf')) {
        $policy = New-PolicyFixture
        $policy.IniSettings = @([pscustomobject]@{
                Section = 'Group Membership'
                Name = '*S-1-5-32-544__Members'
                Value = '"unterminated'
                Scope = 'Computer'
                Source = $source
            })
        $checks = @((Get-PolicyChecks $policy) | Where-Object Category -eq RestrictedGroups)
        Assert-Policy ($checks.Count -eq 1 -and
            $checks[0].Status -eq 'NotConfigured') 'Auxiliary or mismatched INI became Restricted Groups policy'
    }
    foreach ($scope in @($null, 'Unknown', 'User')) {
        $policy = New-PolicyFixture
        $policy.IniSettings = @([pscustomobject]@{
                Section = 'Group Membership'
                Name = '*S-1-5-32-544__Members'
                Value = '*S-1-5-21-1-2-3-1001'
                Scope = $scope
                Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            })
        Assert-Policy (((Get-PolicyChecks $policy) | Where-Object Category `
                    -eq RestrictedGroups).Status -eq 'NotConfigured') 'Unknown or mismatched scope became policy'
    }
    $policy = New-PolicyFixture
    $policy.IniSettings = @([pscustomobject]@{
            Section = 'Group Membership'
            Name = '*S-1-5-32-544__Members'
            Value = '"unterminated'
            Scope = 'Computer'
            Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        })
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object Category `
                -eq RestrictedGroups).Status -eq 'Invalid') 'Authoritative malformed configuration was hidden'
}
Test-Policy 'actual reader retains auxiliary Group Membership inventory without treating it as active policy' {
    $root = Join-Path ([IO.Path]::GetTempPath()) ('ad-restricted-source-' + [guid]::NewGuid().ToString('N'))
    try {
        $authoritative = Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        $auxiliary = Join-Path $root 'Machine/Scripts/backup.inf'
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($authoritative))
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($auxiliary))
        $valid = "[Group Membership]`n*S-1-5-32-544__Members="
        $raw = "[Group Membership]`n*S-1-5-32-544__Members=*S-1-5-21-1-2-3-1001`nMalformed=" + '"unterminated'
        [IO.File]::WriteAllText($authoritative, $valid, [Text.Encoding]::Unicode)
        [IO.File]::WriteAllText($auxiliary, $raw, [Text.Encoding]::Unicode)
        $before = @([Convert]::ToBase64String([IO.File]::ReadAllBytes($authoritative)),
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($auxiliary)))
        $policy = Read-ADAnalyzerGpo $root
        $checks = @((Get-PolicyChecks $policy) | Where-Object Category -eq RestrictedGroups)
        Assert-Policy ($checks.Count -eq 1 -and
            $checks[0].Status -eq 'Pass' -and
            @($checks[0].Observed.Members).Count -eq 0) 'Auxiliary content changed active membership findings'
        Assert-Policy (@($policy.IniSettings).Count -eq 3 -and
            @($policy.IniSettings | Where-Object Analyzed).Count -eq 0) 'Raw Group Membership inventory changed'
        Assert-Policy (($policy.IniSettings | Where-Object Name -eq Malformed).Value -ceq '"unterminated') 'Auxiliary value was changed'
        [xml]$xml = ConvertTo-AnalyzerGpoXml -Gpo $script:Gpo -Parsed $policy
        Assert-Policy ($xml.SelectNodes('//ExtensionData[Name="Ini"]/Extension/Record').Count -eq 3) 'Canonical raw INI inventory was dropped'
        Assert-Policy ([Convert]::ToBase64String([IO.File]::ReadAllBytes($authoritative)) -ceq $before[0] -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($auxiliary)) -ceq $before[1]) 'Source template bytes changed'
    }
    finally {
        if ([IO.Directory]::Exists($root)) {
            [IO.Directory]::Delete($root, $true)
        }
    }
}
Test-Policy 'RestrictedGroups preserves Members versus MemberOf and empty assignments' {
    $policy = New-PolicyFixture
    $policy.IniSettings = @(
        [pscustomobject]@{
            Section = 'Group Membership'
            Name = '*S-1-5-32-544__Members'
            Value = '*S-1-5-21-1-2-3-1001'
            Scope = 'Computer'
            Source = 'MACHINE\Microsoft\Windows NT\SecEdit\GPTTMPL.INF'
        }
        [pscustomobject]@{
            Section = 'Group Membership'
            Name = '*S-1-5-21-1-2-3-1002__Memberof'
            Value = '*S-1-5-32-544'
            Scope = 'Computer'
            Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        }
        [pscustomobject]@{
            Section = 'Group Membership'
            Name = '*S-1-5-32-544__Members'
            Value = ''
            Scope = 'User'
            Source = 'USER/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        }
    )
    $checks = @((Get-PolicyChecks $policy) | Where-Object Category -eq RestrictedGroups)
    Assert-Policy (@($checks | Where-Object Status `
                -eq Fail).Count -eq 2) 'Unexpected principals were not found through both membership directions'
    Assert-Policy (($checks | Where-Object { $_.Observed.Scope -eq 'User' }).Observed.Members.Count -eq 0) 'Empty membership became an unknown/missing assignment'
}
Test-Policy 'approved group SID and member removal do not become unauthorized additions' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Policy.ApprovedLocalAdminSids = @('S-1-5-21-1-2-3-1001')
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Machine/Preferences/Groups/Groups.xml'
            Xml = '<Groups><Group uid="g1"><Properties action="U" groupSid="S-1-5-32-544" deleteAllUsers="1"><Members><Member action="ADD" sid="S-1-5-21-1-2-3-1001"/><Member action="REMOVE" sid="S-1-5-21-1-2-3-2000"/></Members></Properties><Filters><FilterComputer name="fixture"/></Filters></Group></Groups>'
        })
    $check = (Get-PolicyChecks $policy $profile) | Where-Object RuleId -eq GPO.Preferences.LocalUsersGroups
    Assert-Policy ($check.Status -eq 'Pass' -and $check.Applicability -eq 'Unknown') 'Approved targeted update was misclassified'
    Assert-Policy ($check.Observed.DeleteAllUsers -and $check.Observed.Members[1].Action -eq 'REMOVE') 'Preference action details were lost'
}
Test-Policy 'malformed LocalUsersGroups item is Invalid instead of throwing' {
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Groups.xml'
            Xml = '<Groups><Group uid="missing-properties" /></Groups>'
        })
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object RuleId `
                -eq GPO.Preferences.LocalUsersGroups).Status -eq 'Invalid') 'Invalid preference schema was not retained'
}
Test-Policy 'raw registry security settings are typed and evaluated' {
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @(
        (New-RegistryFixture 'SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 2)
        (New-RegistryFixture 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' RequireSecuritySignature 0)
        (New-RegistryFixture 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' EnableLUA '1' 1)
    )
    $checks = Get-PolicyChecks $policy
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Security.Lsa.LmCompatibilityLevel).Status -eq 'Fail') 'Weak raw NTLM policy was not checked'
    Assert-Policy (($checks | Where-Object { $_.RuleId -like '*LanManServer*RequireSecuritySignature' }).Status -eq 'Fail') 'Raw disabled signing was not checked'
    Assert-Policy (($checks | Where-Object { $_.RuleId -like '*EnableLUA' }).Status -eq 'Invalid') 'Wrong registry type was accepted as enabled UAC'
}
Test-Policy 'invalid raw LDAP enum does not become the valid None state' {
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @(New-RegistryFixture 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 42)
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object RuleId `
                -eq GPO.Security.NTDS.LDAPServerIntegrity).Status -eq 'Invalid') 'Out-of-range LDAP enum was silently normalized'
}
Test-Policy 'registry deletion follows file order and means NotConfigured' {
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @(
        (New-RegistryFixture 'SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel 0)
        (New-RegistryFixture 'SYSTEM\CurrentControlSet\Control\Lsa' '**del.LmCompatibilityLevel' $null 0)
    )
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object RuleId `
                -eq GPO.Security.Lsa.LmCompatibilityLevel).Status -eq 'NotConfigured') 'Deleted policy still assessed the stale value'
}
Test-Policy 'registry tuple identities preserve slash-containing value names and deletion boundaries' {
    $a = New-RegistryFixture 'Software\Fixture' 'Child\Setting' 1
    $b = New-RegistryFixture 'Software\Fixture\Child' 'Setting' 2
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @($a, $b)
    $before = ConvertTo-Json -InputObject $policy -Depth 30 -Compress
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.RegistryRules = @(
        @{
            Id = 'ParentValue'
            Hive = 'HKLM'
            Key = $a.Key
            ValueName = $a.ValueName
            Type = 4
            Expected = 1
        },
        @{
            Id = 'ChildValue'
            Hive = 'HKLM'
            Key = $b.Key
            ValueName = $b.ValueName
            Type = 4
            Expected = 2
        }
    )
    $checks = @(Get-PolicyChecks $policy $profile | Where-Object RuleId -like 'GPO.Expected.*')
    Assert-Policy ($checks.Count -eq 2 -and @($checks | Where-Object Status -ne Pass).Count -eq 0) 'Distinct registry tuples collided'
    foreach ($directive in @('**del.Child\Setting', '**DeleteValues')) {
        $data = if ($directive -eq '**DeleteValues') {
            'Child\Setting'
        }
        else {
            $null
        }
        $rows = @(Get-ADAnalyzerEffectiveRegistryRecords @($a, $b, (New-RegistryFixture $a.Key $directive $data 0)))
        Assert-Policy ($rows.Count -eq 2 -and
            ($rows | Where-Object Key `
                -eq $a.Key).Deleted -and
            -not ($rows | Where-Object Key `
                    -eq $b.Key).Deleted) 'Value deletion crossed tuple boundaries'
    }
    $secret = [pscustomobject]@{
        Scope = 'Computer'
        Hive = 'HKLM'
        Key = $a.Key
        ValueName = 'Child\DefaultPassword'
        SecretPresent = $true
        Type = 1
        Source = 'Machine/Registry.pol'
        KeyOnly = $false
    }
    $rows = @(Get-ADAnalyzerEffectiveRegistryRecords @($secret,
            $b,
            (New-RegistryFixture 'Software\Fixture\Child\Grandchild' Setting 3),
            (New-RegistryFixture $a.Key '**DeleteKeys' 'Child' 0)))
    $parent = $rows | Where-Object Key -eq $a.Key
    Assert-Policy ($rows.Count -eq 3 -and
        -not $parent.Deleted -and
        $parent.SecretPresent -and
        @($rows | Where-Object { $_.Key -ne $a.Key -and
                -not $_.Deleted }).Count -eq 0) 'Subtree deletion used value-name separators as key boundaries'
    $policy.RegistrySettings = @($secret, (New-RegistryFixture $a.Key '**DeleteKeys' 'Child' 0))
    Assert-Policy (@(Get-PolicyChecks $policy | Where-Object RuleId `
                -eq GPO.StoredSecret).Count -eq 1) 'Subtree deletion concealed parent secret presence'
    $rows = @(Get-ADAnalyzerEffectiveRegistryRecords @($a, (New-RegistryFixture 'software\fixture' 'child\setting' 7)))
    Assert-Policy ($rows.Count -eq 1 -and $rows[0].Value -eq 7) 'Case-insensitive last-write-wins changed'
    $policy.RegistrySettings = @($a, $b)
    Assert-Policy ($before -ceq (ConvertTo-Json -InputObject $policy -Depth 30 -Compress)) 'Effective-state calculation mutated source'
}
Test-Policy 'user rights use exact approved SIDs and support an empty allowlist' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Policy.AllowedUserRightSids = @{
        SeDebugPrivilege = @('S-1-5-32-544')
        SeDenyNetworkLogonRight = @()
    }
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @(
        [pscustomobject]@{
            Kind = 'UserRightsAssignment'
            Name = 'SeDebugPrivilege'
            Value = @('NotAdministrators')
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        }
        [pscustomobject]@{
            Kind = 'UserRightsAssignment'
            Name = 'SeDenyNetworkLogonRight'
            Value = @()
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        }
    )
    $checks = Get-PolicyChecks $policy $profile
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.UserRights.SeDebugPrivilege).Status -eq 'Unknown') 'A principal-name substring was treated as an approved SID'
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.UserRights.SeDenyNetworkLogonRight).Status -eq 'Pass') 'Explicit empty allowlist was treated as unspecified'
}
Test-Policy 'modern policy principals enforce SID bounds and consumed allowlist shape' {
    $valid = @('S-1-5-32-544', 'S-1-4294967295-4294967295', 'S-1-0xffffffffffff-4294967295')
    $invalid = @('S-1-5-4294967296',
        'S-1-281474976710656-1',
        'S-1-4294967296-1',
        'S-2-5-1',
        'S-1-5-0544',
        ('S-1-5' + ('-1' * 16)),
        ('S-1-' + [char]0x0665 + '-1'),
        '**S-1-5-32-544',
        '')
    foreach ($sid in $valid + $invalid) {
        $good = $sid -in $valid
        $policy = New-PolicyFixture
        $policy.SecuritySettings = @([pscustomobject]@{
                Kind = 'UserRightsAssignment'
                Name = 'SeDebugPrivilege'
                Value = @('*' + $sid)
                Scope = 'Computer'
                Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            })
        $profile = Get-ADAnalyzerDefaultProfile
        $profile.Policy.AllowedUserRightSids = @{
            SeDebugPrivilege = @($sid)
        }
        $check = Get-PolicyChecks $policy $profile | Where-Object RuleId -eq GPO.UserRights.SeDebugPrivilege
        Assert-Policy ($check.Status -eq $(if ($good) {
                    'Pass'
                }
                else {
                    'Invalid'
                })) ('Unexpected user-right SID outcome: ' + $sid)
        $policy.IniSettings = @([pscustomobject]@{
                Section = 'Group Membership'
                Name = '*S-1-5-32-544__Members'
                Value = ('*' + $sid)
                Scope = 'Computer'
                Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
            })
        $group = @(ConvertFrom-ADAnalyzerRestrictedGroups $policy.IniSettings)[0]
        Assert-Policy ($group.Valid -eq $good) 'Restricted Groups SID validation diverged'
        if ($sid) {
            $policy.XmlFiles = @([pscustomobject]@{
                    Scope = 'Computer'
                    Path = 'Groups.xml'
                    Xml = ('<Groups><Group><Properties action="U" groupSid="' + $sid + '"><Members><Member sid="' + $sid + '" action="ADD"/></Members></Properties></Group></Groups>')
                })
            Assert-Policy (@(ConvertFrom-ADAnalyzerLocalUsersGroups $policy.XmlFiles)[0].Valid -eq $good) 'GPP SID validation diverged'
        }
    }
    foreach ($allow in @($null, @{
                Sid = 'S-1-5-32-544'
            }, @(@('S-1-5-32-544', 'S-1-5-32-545'), 'S-1-5-32-546'), 'S-1-5-4294967296')) {
        $profile = Get-ADAnalyzerDefaultProfile
        $profile.Policy.AllowedUserRightSids = @{
            SeDebugPrivilege = $allow
        }
        $policy = New-PolicyFixture
        $policy.SecuritySettings = @([pscustomobject]@{
                Kind = 'UserRightsAssignment'
                Name = 'SeDebugPrivilege'
                Value = @('*S-1-5-32-544')
                Scope = 'Computer'
                Source = 'GptTmpl.inf'
            })
        Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                    -eq GPO.UserRights.SeDebugPrivilege).Status -eq 'Invalid') 'Malformed allowlist produced a valid approval'
    }
    $principal = ConvertFrom-ADAnalyzerPolicyPrincipal 'Localized User'
    Assert-Policy ($principal.Valid -and
        -not $principal.Sid -and
        $principal.Name -eq 'Localized User') 'Unresolved names must remain available'
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Groups.xml'
            Xml = '<Groups><Group><Properties action="U" groupSid="S-1-5-32-544"><Members><Member sid="Administrators" action="ADD"/></Members></Properties></Group></Groups>'
        })
    Assert-Policy (-not @(ConvertFrom-ADAnalyzerLocalUsersGroups $policy.XmlFiles)[0].Valid) 'Explicit non-SID attribute became a principal name'
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Policy.ApprovedLocalAdminSids = @('S-1-5-4294967296')
    $policy.XmlFiles[0].Xml = $policy.XmlFiles[0].Xml.Replace('sid="Administrators"', 'sid="S-1-5-32-544"')
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Preferences.LocalUsersGroups).Status -eq 'Invalid') 'Invalid local administrator allowlist accepted'
    $policy = New-PolicyFixture
    $policy.IniSettings = @([pscustomobject]@{
            Section = 'Group Membership'
            Name = '*S-1-5-32-544__Members'
            Value = ''
            Scope = 'Computer'
            Source = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
        })
    $profile.Policy.ApprovedLocalAdminSids = @()
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.RestrictedGroups.LocalAdministrators).Status -eq 'Pass') 'Explicit empty local administrator allowlist was lost'
    $profile.Policy.ApprovedLocalAdminSids = $null
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.RestrictedGroups.LocalAdministrators).Status -eq 'Invalid') 'Null local administrator allowlist was treated as empty'
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Groups.xml'
            Xml = '<Groups><Group><Properties action="U" groupSid="S-1-5-32-544"><Members><Member sid="S-1-5-32-544" action="ADD"/></Members></Properties></Group></Groups>'
        })
    foreach ($objectSection in @($false, $true)) {
        foreach ($case in @(@{
                    Value = @()
                    Status = 'Fail'
                }, @{
                    Value = $null
                    Status = 'Invalid'
                }, @{
                    Value = @('S-1-5-32-544')
                    Status = 'Pass'
                }, @{
                    Value = 'S-1-5-32-544'
                    Status = 'Pass'
                })) {
            $profile = Get-ADAnalyzerDefaultProfile
            $profile.Policy.ApprovedLocalAdminSids = $case.Value
            if ($objectSection) {
                $profile.Policy = [pscustomobject]$profile.Policy
            }
            $check = Get-PolicyChecks $policy $profile | Where-Object RuleId -eq GPO.Preferences.LocalUsersGroups
            Assert-Policy ($check.Status -eq $case.Status) 'Object/dictionary policy sections disagree on explicit local administrator allowlist'
        }
    }
}
Test-Policy 'custom top-level rules assess values and preserve missing state' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.RegistryRules = @(@{
            Id = 'Fixture'
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Level'
            Operator = 'Minimum'
            Expected = 2
        }, @{
            Id = 'EmptyList'
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Empty'
            Expected = @()
        })
    $profile.ExpectedGpoSettings = @(@{
            Id = 'Missing'
            Kind = 'Account'
            Name = 'CustomSetting'
            Expected = 1
        })
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @((New-RegistryFixture 'Software\Fixture' Level 3),
        (New-RegistryFixture 'Software\Fixture' Empty ([string[]]@()) 7))
    $checks = Get-PolicyChecks $policy $profile
    Assert-Policy (($checks | Where-Object RuleId -eq GPO.Expected.Fixture).Status -eq 'Pass') 'Custom minimum rule failed'
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Expected.EmptyList).Status -eq 'Pass') 'Explicit empty expected multi-string was not preserved'
    Assert-Policy (($checks | Where-Object RuleId -eq GPO.Expected.Missing).Status -eq 'NotConfigured') 'Missing custom setting was hidden'
}
Test-Policy 'disabled configuration retains stored risk but explicit nonapplicability' {
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @([pscustomobject]@{
            Kind = 'Account'
            Name = 'MinimumPasswordLength'
            Value = 0L
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        })
    $gpo = [pscustomobject]@{
        Id = $script:Gpo.Id
        Flags = 2
        Links = @()
    }
    $check = (Get-PolicyChecks $policy $script:Profile $gpo) | Where-Object RuleId -eq GPO.Account.MinimumPasswordLength
    Assert-Policy ($check.Status -eq 'Fail' -and
        $check.Applicability -eq 'NotApplicable') 'Disabled stored risk became a proven applied defect'
}
Test-Policy 'targeting evidence retains only credential presence and keeps stable item identity' {
    $policy = New-PolicyFixture
    $policy.XmlFiles = @([pscustomobject]@{
            Scope = 'Computer'
            Path = 'Groups.xml'
            Xml = '<Groups><Group uid="stable-item"><Properties action="U" groupSid="S-1-5-32-544"/><Filters><FilterCustom cpassword="FILTER_SECRET"/></Filters></Group></Groups>'
        })
    $checks = Get-PolicyChecks $policy
    Assert-Policy (($checks | ConvertTo-Json -Depth 30) -notmatch 'FILTER_SECRET') 'Targeting XML leaked an exposed credential'
    Assert-Policy (($checks | Where-Object RuleId `
                -eq GPO.Preferences.CPassword).Target -match 'stable-item') 'Credential check identity does not use item identity'
}
Test-Policy 'LDAP requirement profile overrides do not bypass raw validation' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Policy.RequireLdapClientSigning = $false
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @(New-RegistryFixture 'SYSTEM\CurrentControlSet\Services\LDAP' LDAPClientIntegrity 1)
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Security.LDAP.LDAPClientIntegrity).Status -eq 'Pass') 'Profile signing override was ignored'
    $policy.RegistrySettings[0].Value = 99
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Security.LDAP.LDAPClientIntegrity).Status -eq 'Invalid') 'Profile override allowed invalid enum data'
}
Test-Policy 'DelVals deletes only values in the exact key' {
    $rows = @(New-RegistryFixture 'Software\Fixture' Parent 1
        New-RegistryFixture 'Software\Fixture\Child' Child 2
        New-RegistryFixture 'Software\Fixture' '**DelVals' $null 0)
    $effective = @(Get-ADAnalyzerEffectiveRegistryRecords $rows)
    Assert-Policy (($effective | Where-Object ValueName -eq Parent).Deleted) 'Exact-key value was not deleted'
    Assert-Policy (-not ($effective | Where-Object ValueName -eq Child).Deleted) 'DelVals incorrectly deleted descendant key values'
}
Test-Policy 'INF raw registry type survives normalization and is validated' {
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @([pscustomobject]@{
            Kind = 'SecurityOptions'
            Name = 'User Account Control: Run all administrators in Admin Approval Mode'
            Value = $true
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        })
    $policy.IniSettings = @([pscustomobject]@{
            Section = 'Registry Values'
            Name = 'MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'
            Value = '1,"1"'
            Scope = 'Computer'
            Source = 'GptTmpl.inf'
        })
    Assert-Policy (((Get-PolicyChecks $policy) | Where-Object { $_.RuleId -like '*EnableLUA' }).Status -eq 'Invalid') 'Normalized boolean hid a raw registry type mismatch'
}
Test-Policy 'optional template resolution accepts an empty policy registry' {
    Assert-Policy (@(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @()).Count -eq 0) 'Empty policy required template metadata'
}
Test-Policy 'expected GPO settings honor exact user and computer scope' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.ExpectedGpoSettings = @(@{
            Id = 'Scope'
            Kind = 'Account'
            Name = 'CustomSetting'
            Scope = 'Computer'
            Expected = 1
        })
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @(
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'CustomSetting'
            Value = 0L
            Scope = 'User'
            Source = 'User/GptTmpl.inf'
        }
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'CustomSetting'
            Value = 1L
            Scope = 'Computer'
            Source = 'Machine/GptTmpl.inf'
        }
    )
    $checks = @((Get-PolicyChecks $policy $profile) | Where-Object RuleId -eq GPO.Expected.Scope)
    Assert-Policy ($checks.Count -eq 1 -and
        $checks[0].Status -eq 'Pass' -and
        $checks[0].Evidence.Scope -eq 'Computer') 'User and Computer settings were conflated'
    $profile.ExpectedGpoSettings[0].Scope = 'User'
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Expected.Scope).Status -eq 'Fail') 'User scope matched the Computer value'
    $policy.SecuritySettings = @($policy.SecuritySettings | Where-Object Scope -eq Computer)
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Expected.Scope).Status -eq 'NotConfigured') 'Absent requested scope fell back to another scope'
}
Test-Policy 'custom registry baseline rejects equal text with the wrong registry type' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.RegistryRules = @(@{
            Id = 'Typed'
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Zero'
            Type = 4
            Expected = 0
        })
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @(New-RegistryFixture 'Software\Fixture' Zero '0' 1)
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Expected.Typed).Status -eq 'Invalid') 'REG_SZ zero passed an expected DWORD zero'
    $policy.RegistrySettings[0].Type = 4
    $profile.RegistryRules[0].Type = 'REG_DWORD'
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Expected.Typed).Status -eq 'Pass') 'Registry type alias did not match the correct DWORD'
}
Test-Policy 'baseline check identities survive reordering of distinct source settings' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.ExpectedGpoSettings = @(@{
            Id = 'Stable'
            Kind = 'Account'
            Name = 'CustomSetting'
            Expected = 1
        })
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @(
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'CustomSetting'
            Value = 0L
            Scope = 'User'
            Source = 'User/GptTmpl.inf'
        }
        [pscustomobject]@{
            Kind = 'Account'
            Name = 'CustomSetting'
            Value = 1L
            Scope = 'Computer'
            Source = 'Machine/GptTmpl.inf'
        }
    )
    $first = @((Get-PolicyChecks $policy $profile) | Where-Object RuleId -eq GPO.Expected.Stable | Sort-Object CheckId)
    [array]::Reverse($policy.SecuritySettings)
    $second = @((Get-PolicyChecks $policy $profile) | Where-Object RuleId -eq GPO.Expected.Stable | Sort-Object CheckId)
    Assert-Policy (($first.CheckId -join '|') -eq ($second.CheckId -join '|')) 'Check identity depended on source enumeration order'
}

Test-Policy 'aggregate security expectations compare a complete multi-string set once' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.ExpectedGpoSettings = @(@{
            Id = 'Aggregate'
            Kind = 'SecurityOptions'
            Scope = 'Computer'
            Name = 'Fixture collection'
            Expected = @('one', 'two', 'three')
            Aggregate = $true
        })
    $policy = New-PolicyFixture
    $policy.SecuritySettings = @('three', 'one', 'two' | ForEach-Object { [pscustomobject]@{
                Scope = 'Computer'
                Kind = 'SecurityOptions'
                Name = 'Fixture collection'
                Value = $_
                Source = 'Machine/GptTmpl.inf'
            } })
    $checks = @((Get-PolicyChecks $policy $profile) | Where-Object RuleId -eq GPO.Expected.Aggregate)
    Assert-Policy ($checks.Count -eq 1 -and $checks[0].Status -eq 'Pass') 'Multi-string was assessed as unrelated scalar values'
    $policy.SecuritySettings[0].Value = 'different'
    Assert-Policy (((Get-PolicyChecks $policy $profile) | Where-Object RuleId `
                -eq GPO.Expected.Aggregate).Status -eq 'Fail') 'Changed set member was missed'
}
Test-Policy 'aggregate registry comparisons distinguish a different selector from genuine resolution' {
    $key = 'Software\AggregateFixture'
    $path = 'Machine/Registry.pol'
    $ruleId = 'GPO.Expected.AggregateSelector'
    $policy = New-PolicyFixture
    $policy.RegistrySettings = @(
        New-RegistryFixture $key Level ([uint32]1)
        New-RegistryFixture $key '' ([uint32]3)
    )
    $improvedPolicy = New-PolicyFixture
    $improvedPolicy.RegistrySettings = @(
        New-RegistryFixture $key Level ([uint32]3)
        New-RegistryFixture $key '' ([uint32]3)
    )
    $utcName = '2026-01-01T00:00:00Z'
    $offsetName = '2025-12-31T19:00:00-05:00'
    $dateNamedPolicy = New-PolicyFixture
    $dateNamedPolicy.RegistrySettings = @(
        New-RegistryFixture $key $utcName ([uint32]1)
        New-RegistryFixture $key $offsetName ([uint32]3)
    )
    $rule = @{
        Id = 'AggregateSelector'
        Key = $key
        ValueName = 'Level'
        Expected = @([uint32]3)
        Type = 4
        Aggregate = $true
    }
    $caseOnlyPolicy = New-PolicyFixture
    $caseOnlyPolicy.RegistrySettings = @(
        New-RegistryFixture $key.ToLowerInvariant() level ([uint32]1)
        New-RegistryFixture $key.ToLowerInvariant() '' ([uint32]3)
    )
    $retargetedRule = $rule.Clone()
    $retargetedRule.ValueName = ''
    $utcRule = $rule.Clone()
    $utcRule.ValueName = $utcName
    $offsetRule = $rule.Clone()
    $offsetRule.ValueName = $offsetName
    $equivalentRule = $rule.Clone()
    $equivalentRule.Hive = 'hklm'
    $equivalentRule.Key = $key.ToLowerInvariant()
    $equivalentRule.ValueName = 'level'

    $recordCheck = {
        param($Artifact, $SelectedRule, [string]$Status, [uint32]$Observed)

        $profile = @{
            RegistryRules = @($SelectedRule)
        }
        $rows = @(Get-PolicyChecks $Artifact $profile | Where-Object RuleId -eq $ruleId)
        Assert-Policy ($rows.Count -eq 1) 'Expected one aggregate check'
        $row = $rows[0]
        Assert-Policy ($row.Status -ceq $Status) ('Unexpected observation status: ' + $row.Status)
        Assert-Policy ($row.Observed -is [array] -and $row.Observed.Count -eq 1 -and
            $row.Observed[0] -is [uint32] -and $row.Observed[0] -eq $Observed) 'Unexpected stored DWORD observation'
        Assert-Policy ($row.Evidence.Path -ceq $path -and $row.Evidence.Scope -ceq 'Computer') 'Aggregate source or scope changed'
        return $row
    }
    $checks = [ordered]@{
        Reference = & $recordCheck $policy $rule Fail 1
        Retargeted = & $recordCheck $policy $retargetedRule Pass 3
        Equivalent = & $recordCheck $policy $equivalentRule Fail 1
        EquivalentStored = & $recordCheck $caseOnlyPolicy $equivalentRule Fail 1
        DateNamedReference = & $recordCheck $dateNamedPolicy $utcRule Fail 1
        DateNamedRetargeted = & $recordCheck $dateNamedPolicy $offsetRule Pass 3
        Improved = & $recordCheck $improvedPolicy $equivalentRule Pass 3
    }
    foreach ($check in $checks.Values) {
        Assert-Policy ($check.Target -ceq $checks.Reference.Target -and
            $check.CheckId -ceq $checks.Reference.CheckId) 'The matched aggregate identity changed'
    }
    $checks['Legacy'] = $checks.Reference.PSObject.Copy()
    $legacyEvidence = @{}
    foreach ($name in $checks.Reference.Evidence.Keys) {
        if ($name -ne 'RegistrySelector') {
            $legacyEvidence[$name] = $checks.Reference.Evidence[$name]
        }
    }
    $checks.Legacy.Evidence = $legacyEvidence
    $documents = [ordered]@{}
    foreach ($name in $checks.Keys) {
        $documents[$name] = [pscustomobject]@{
            SchemaVersion = 1
            Target = 'fixture.invalid'
            Checks = @($checks[$name])
        }
    }

    $comparer = [ADAnalyzerAssessmentComparer]::new()
    $cases = @(
        @('Reference', 'Retargeted', 'Changed', 'RulePredicateChanged'),
        @('Retargeted', 'Reference', 'Changed', 'RulePredicateChanged'),
        @('DateNamedReference', 'DateNamedRetargeted', 'Changed', 'RulePredicateChanged'),
        @('Reference', 'Equivalent', 'Unchanged', $null),
        @('Reference', 'EquivalentStored', 'Unchanged', $null),
        @('Legacy', 'Reference', 'Unchanged', $null),
        @('Reference', 'Improved', 'Resolved', $null),
        @('Legacy', 'Retargeted', 'Resolved', $null)
    )
    $checkComparison = {
        param($Inputs)

        foreach ($case in $cases) {
            $before, $after, $change, $reason = $case
            $results = @(
                Compare-ADAnalyzerAssessment -Reference $Inputs[$before] -Difference $Inputs[$after]
                $comparer.Compare($Inputs[$before], $Inputs[$after])
            )
            Assert-Policy ($results.Count -eq 2) 'Expected a comparison from each public route'
            foreach ($result in $results) {
                Assert-Policy ($result.Changes.Count -eq 1) 'The comparer split the stable aggregate check'
                $row = $result.Changes[0]
                Assert-Policy ($row.Change -ceq $change -and $row.Reason -ceq $reason) (
                    "Comparison $before to $after expected $change/$reason, received $($row.Change)/$($row.Reason)"
                )
                Assert-Policy ($result.Summary.$change -eq 1 -and
                    ($change -eq 'Resolved' -or $result.Summary.Resolved -eq 0)) 'The comparison summary misclassified the check'
                Assert-Policy ($row.Reference.Count -eq 1 -and $row.Difference.Count -eq 1 -and
                    $row.Reference[0].Observed[0] -eq $checks[$before].Observed[0] -and
                    $row.Difference[0].Observed[0] -eq $checks[$after].Observed[0] -and
                    $row.Reference[0].Evidence.Path -ceq $path -and
                    $row.Difference[0].Evidence.Path -ceq $path) 'The comparison lost a recorded observation or its source'
                $referenceSelector = $row.Reference[0].Evidence.RegistrySelector
                $differenceSelector = $row.Difference[0].Evidence.RegistrySelector
                foreach ($field in @('Hive', 'Key', 'ValueName')) {
                    Assert-Policy ($referenceSelector.$field -ceq $checks[$before].Evidence.RegistrySelector.$field -and
                        $differenceSelector.$field -ceq $checks[$after].Evidence.RegistrySelector.$field) (
                        'The comparison did not retain recorded selector evidence'
                    )
                }
            }
        }
    }
    & $checkComparison $documents

    foreach ($name in @('Reference', 'Retargeted')) {
        $selector = $checks[$name].Evidence.RegistrySelector
        $valueName = if ($name -eq 'Reference') {
            'Level'
        }
        else {
            ''
        }
        Assert-Policy ($selector.Hive -ceq 'HKLM' -and $selector.Key -ceq (':' + $key) -and
            $selector.ValueName -is [string] -and $selector.ValueName -ceq (':' + $valueName)) 'Expected the selected registry identity'
    }
    Assert-Policy ($policy.RegistrySettings[0].Value -eq 1 -and
        $policy.RegistrySettings[1].Value -eq 3 -and $rule.ValueName -ceq 'Level') 'Evaluation changed the original policy or profile'

    foreach ($unsafeName in @('cpassword="fixture-marker"', '<!DOCTYPE fixture>')) {
        $unsafePolicy = New-PolicyFixture
        $unsafePolicy.RegistrySettings = @(New-RegistryFixture $key $unsafeName ([uint32]1))
        $unsafeRule = $rule.Clone()
        $unsafeRule.ValueName = $unsafeName
        $check = & $recordCheck $unsafePolicy $unsafeRule Fail 1
        Assert-Policy ($null -eq $check.Evidence.RegistrySelector) 'Unsafe selector text entered the recorded identity'
    }

    $directory = Join-Path ([IO.Path]::GetTempPath()) ('ad-analyzer-selectors-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($directory)
    try {
        $paths = [ordered]@{}
        $hashes = @{}
        foreach ($name in $documents.Keys) {
            $paths[$name] = Join-Path $directory ($name + '.json')
            $null = Export-ADAnalyzerAssessment -Assessment $documents[$name] -Path $paths[$name] -Format Json -Confirm:$false
            $hashes[$name] = (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash
        }
        & $checkComparison $paths
        foreach ($name in $paths.Keys) {
            Assert-Policy ($hashes[$name] -ceq (Get-FileHash -LiteralPath $paths[$name] -Algorithm SHA256).Hash) (
                'Comparison rewrote a saved assessment'
            )
        }
    }
    finally {
        [IO.Directory]::Delete($directory, $true)
    }
}

Test-Policy 'a retained WMI filter keeps applicability unknown despite an assume flag' {
    $profile = Get-ADAnalyzerDefaultProfile
    $profile.Analysis.AssumeGpoApplicable = $true
    $gpo = [pscustomobject]@{
        Flags = 0
        Links = @()
        WmiFilter = 'fixture-filter'
    }
    Assert-Policy ((Get-ADAnalyzerPolicyApplicability `
                -Gpo $gpo `
                -Scope Computer `
                -Profile $profile) -eq 'Unknown') 'Unresolved WMI filter was treated as evaluated'
}

$taskTemp = Join-Path ([IO.Path]::GetTempPath()) ('ad-policy-analysis-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory((Join-Path $taskTemp 'en-US'))
try {
    [IO.File]::WriteAllText((Join-Path $taskTemp 'fixture.admx'), @'
<policyDefinitions><policyNamespaces><target prefix="f" namespace="Fixture.Policies"/></policyNamespaces><policies>
<policy name="EnabledPolicy" class="Machine" displayName="$(string.Title)" key="Software\Fixture" valueName="Enabled"><enabledValue><decimal value="1"/></enabledValue><disabledValue><decimal value="0"/></disabledValue></policy>
<policy name="ElementsPolicy" class="Machine" displayName="$(string.Title)" key="Software\Fixture"><elements>
<boolean id="Flag" valueName="Flag"><trueValue><decimal value="1"/></trueValue><falseValue><decimal value="0"/></falseValue></boolean>
<enum id="Choice" valueName="Choice"><item displayName="$(string.Option)"><value><decimal value="2"/></value></item></enum>
<list id="Entries" key="Software\Fixture\List" valuePrefix="Entry"/>
</elements></policy></policies></policyDefinitions>
'@)
    [IO.File]::WriteAllText((Join-Path $taskTemp 'en-US/fixture.adml'),
        '<policyDefinitionResources><resources><stringTable><string id="Title">Fixture title</string><string id="Option">Option two</string></stringTable></resources></policyDefinitionResources>')
    Test-Policy 'offline ADMX and ADML resolve policy boolean enum and list records' {
        $rows = @(New-RegistryFixture 'Software\Fixture' Enabled 1
            New-RegistryFixture 'Software\Fixture' Flag 0
            New-RegistryFixture 'Software\Fixture' Choice 2
            New-RegistryFixture 'Software\Fixture\List' Entry1 'fixture' 1)
        $resolved = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings $rows -TemplatePath $taskTemp)
        Assert-Policy ($resolved.Count -eq 4 -and
            @($resolved | Where-Object MetadataStatus `
                    -ne Resolved).Count -eq 0) 'Template metadata was not resolved'
        Assert-Policy ($resolved[0].State -eq 'Enabled' -and $resolved[1].State -eq 'False') 'Boolean policy states were not resolved'
        Assert-Policy ($resolved[2].Options[0].Label -eq 'Option two' -and
            $resolved[3].DefinitionType -eq 'list') 'Enum resource or list definition was not resolved'
    }
    Test-Policy 'missing template metadata remains explicit and preserves raw data' {
        $row = New-RegistryFixture 'Software\Unknown' Unmapped 99
        $missing = Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($row) -TemplatePath (Join-Path $taskTemp missing)
        Assert-Policy ($missing.MetadataStatus -eq 'TemplateNotFound' -and
            $missing.Value -eq 99 -and
            $missing.State -eq 'Unknown') 'Missing template erased raw data or implied a state'
        $language = Resolve-ADAnalyzerRegistryPolicy `
            -RegistrySettings @(New-RegistryFixture 'Software\Fixture' Enabled 1) `
            -TemplatePath $taskTemp `
            -Language xx-XX
        Assert-Policy ($language.MetadataStatus -eq 'LanguageResourceMissing') 'Missing language was not identified'
    }
    Test-Policy 'an absent ADML label affects only its own policy' {
        $templateName = 'fixture-localization'
        [IO.File]::WriteAllText((Join-Path $taskTemp ($templateName + '.admx')), @'
<policyDefinitions revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="localization" namespace="Fixture.Localization" />
  </policyNamespaces>
  <policies>
    <policy name="FirstPolicy" class="Machine" displayName="$(string.FirstLabel)"
            key="Software\Fixture\Localization" valueName="FirstSetting">
      <enabledValue><decimal value="1" /></enabledValue>
    </policy>
    <policy name="MiddlePolicy" class="Machine" displayName="$(string.MissingLabel)"
            key="Software\Fixture\Localization" valueName="MiddleSetting">
      <enabledValue><decimal value="2" /></enabledValue>
    </policy>
    <policy name="LastPolicy" class="Machine" displayName="$(string.LastLabel)"
            key="Software\Fixture\Localization" valueName="LastSetting">
      <enabledValue><decimal value="3" /></enabledValue>
    </policy>
  </policies>
</policyDefinitions>
'@)
        [IO.File]::WriteAllText((Join-Path $taskTemp ('en-US/' + $templateName + '.adml')), @'
<policyDefinitionResources revision="1.0" schemaVersion="1.0">
  <resources>
    <stringTable>
      <string id="FirstLabel">First localized label</string>
      <string id="LastLabel">Last localized label</string>
    </stringTable>
  </resources>
</policyDefinitionResources>
'@)
        $key = 'Software\Fixture\Localization'
        $rows = @(
            New-RegistryFixture $key FirstSetting 1
            New-RegistryFixture $key MiddleSetting 2
            New-RegistryFixture $key LastSetting 3
        )
        $parameters = @{
            RegistrySettings = $rows
            TemplatePath = $taskTemp
            Language = 'en-US'
        }
        $resolved = @(Resolve-ADAnalyzerRegistryPolicy @parameters)
        $statuses = $resolved.MetadataStatus -join ','
        Assert-Policy ($statuses -ceq 'Resolved,LanguageResourceMissing,Resolved') "Unexpected localization statuses $statuses."
        Assert-Policy (($resolved.DisplayName -join ',') -ceq 'First localized label,MiddlePolicy,Last localized label') 'Localized and fallback labels were not preserved.'
        Assert-Policy (($resolved.PolicyId -join ',') -ceq 'FirstPolicy,MiddlePolicy,LastPolicy' -and
            ($resolved.State -join ',') -ceq 'Enabled,Enabled,Enabled' -and
            ($resolved.Value -join ',') -ceq '1,2,3') 'Localization changed policy order, state, or raw values.'

        $parameters.Language = 'xx-XX'
        $missing = @(Resolve-ADAnalyzerRegistryPolicy @parameters)
        Assert-Policy (($missing.MetadataStatus -join ',') -ceq 'LanguageResourceMissing,LanguageResourceMissing,LanguageResourceMissing') 'A missing ADML file did not mark every policy.'
        Assert-Policy (($missing.DisplayName -join ',') -ceq 'FirstPolicy,MiddlePolicy,LastPolicy') 'A missing ADML file did not preserve fallback labels.'
    }

    $projectionPath = Join-Path $taskTemp 'strict-projection'
    $duplicatePath = Join-Path $taskTemp 'strict-ambiguous'
    $invalidPath = Join-Path $taskTemp 'strict-invalid'
    $projectionKey = 'Software\Fixture\Projection'
    $null = [IO.Directory]::CreateDirectory((Join-Path $projectionPath 'en-US'))
    $null = [IO.Directory]::CreateDirectory($duplicatePath)
    $null = [IO.Directory]::CreateDirectory($invalidPath)
    $projectionAdmx = Join-Path $projectionPath 'projection.admx'
    [IO.File]::WriteAllText($projectionAdmx, @'
<policyDefinitions revision="1.0" schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="projection" namespace="Fixture.Projection" />
  </policyNamespaces>
  <policies>
    <policy name="DeleteAware" class="Machine" displayName="$(string.Label)"
            key="Software\Fixture\Projection" valueName="FixtureValue">
      <enabledValue><delete /></enabledValue>
      <disabledValue><decimal value="17" /></disabledValue>
    </policy>
  </policies>
</policyDefinitions>
'@)
    [IO.File]::WriteAllText((Join-Path $projectionPath 'en-US/projection.adml'), @'
<policyDefinitionResources revision="1.0" schemaVersion="1.0">
  <resources>
    <stringTable><string id="Label">Delete aware label</string></stringTable>
  </resources>
</policyDefinitionResources>
'@)
    [IO.File]::Copy($projectionAdmx, (Join-Path $duplicatePath 'first.admx'))
    [IO.File]::Copy($projectionAdmx, (Join-Path $duplicatePath 'second.admx'))
    [IO.File]::WriteAllText((Join-Path $invalidPath 'invalid.admx'), '<policyDefinitions>')

    $unresolved = [ordered]@{
        TemplateNotFound = (Join-Path $taskTemp 'absent')
        NoMatch = $projectionPath
        Ambiguous = $duplicatePath
        InvalidTemplate = $invalidPath
    }
    foreach ($status in $unresolved.Keys) {
        Test-Policy ('strict registry projection reports ' + $status) {
            Set-StrictMode -Version Latest
            $name = 'FixtureValue'
            $templateError = ''
            if ($status -eq 'NoMatch') {
                $name = 'Unmapped'
            }
            if ($status -eq 'InvalidTemplate') {
                $templateError = 'invalid.admx'
            }
            $row = New-RegistryFixture $projectionKey $name 23
            $row | Add-Member -NotePropertyMembers @{
                DeletionDirective = $false
                Deleted = $false
            }
            $result = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($row) -TemplatePath $unresolved[$status])
            Assert-Policy ($result.Count -eq 1 -and $result[0].MetadataStatus -ceq $status -and $result[0].State -ceq 'Unknown') "Expected explicit unresolved metadata $status."
            foreach ($field in @('PolicyId', 'PolicyNamespace', 'DisplayName', 'DefinitionType', 'ElementId')) {
                Assert-Policy ($null -eq $result[0].$field) "$status did not project a null $field."
            }
            Assert-Policy ($result[0].ValueName -ceq $name -and $result[0].Value -eq 23 -and
                $result[0].Type -eq 4 -and [object]::ReferenceEquals($result[0].RawData, $row.RawData) -and
                $result[0].Options.Count -eq 0 -and ($result[0].TemplateErrors -join ',') -ceq $templateError) "$status changed raw data or diagnostics."
        }
    }

    Test-Policy 'strict registry projection accepts a named replay tombstone' {
        Set-StrictMode -Version Latest
        $directive = New-RegistryFixture $projectionKey '**del.FixtureValue' $null
        $tombstone = @(Get-ADAnalyzerEffectiveRegistryRecords -RegistrySettings @($directive))
        Assert-Policy ($tombstone.Count -eq 1 -and $tombstone[0].Deleted -eq $true -and
            $null -eq $tombstone[0].PSObject.Properties['RawData']) 'Named replay did not make a tombstone without raw bytes.'
        $result = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings $tombstone -TemplatePath $projectionPath)
        Assert-Policy ($result.Count -eq 1 -and $result[0].MetadataStatus -ceq 'Resolved' -and
            $result[0].PolicyId -ceq 'DeleteAware' -and $result[0].State -ceq 'Enabled' -and
            $result[0].Deleted -eq $true -and $null -eq $result[0].Value -and
            $null -eq $result[0].RawData -and $null -eq $result[0].KeyOnly -and
            $null -eq $result[0].DeletionDirective) 'Replay deletion lost its rule state or optional null fields.'
    }

    Test-Policy 'strict registry projection retains optional raw data types and references' {
        Set-StrictMode -Version Latest
        $inputs = @(
            @{ RawData = [byte]17 }
            @{ RawData = [byte[]]::new(0) }
            @{ RawData = [byte[]]@(17) }
            @{ RawData = [byte[]]@(17, 18) }
        )
        foreach ($inputCase in $inputs) {
            $row = New-RegistryFixture $projectionKey FixtureValue 17
            $row.RawData = $inputCase.RawData
            $row | Add-Member -NotePropertyName DeletionDirective -NotePropertyValue $false
            $result = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($row) -TemplatePath $projectionPath)
            Assert-Policy ($result.Count -eq 1 -and $result[0].MetadataStatus -ceq 'Resolved' -and
                $result[0].State -ceq 'Disabled' -and $result[0].Type -eq 4 -and $result[0].Value -eq 17 -and
                $null -eq $result[0].Deleted -and $result[0].KeyOnly -eq $false -and
                $result[0].DeletionDirective -eq $false -and
                $result[0].RawData.GetType() -eq $row.RawData.GetType()) 'A raw reader record changed type, state, or optional fields.'
            if ($row.RawData -is [byte[]]) {
                Assert-Policy ([object]::ReferenceEquals($result[0].RawData, $row.RawData)) 'Raw bytes lost their original reference.'
            }
            else {
                Assert-Policy ($result[0].RawData -eq $row.RawData) 'A raw byte changed value.'
            }
        }

        $dictionary = [ordered]@{
            Scope = 'Computer'
            Hive = 'HKLM'
            Key = $projectionKey
            ValueName = 'FixtureValue'
            Type = 4
            Value = 17
            Source = 'Machine/Registry.pol'
        }
        $result = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($dictionary) -TemplatePath $projectionPath)
        Assert-Policy ($result.Count -eq 1 -and $result[0].State -ceq 'Disabled' -and
            $null -eq $result[0].RawData -and $null -eq $result[0].KeyOnly -and
            $null -eq $result[0].DeletionDirective -and $null -eq $result[0].Deleted) 'Omitted dictionary options did not project as null.'
        $dictionary.RawData = $null
        $dictionary.KeyOnly = $null
        $dictionary.DeletionDirective = $null
        $dictionary.Deleted = $null
        $explicitNull = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($dictionary) -TemplatePath $projectionPath)
        Assert-Policy ($explicitNull.Count -eq 1 -and $explicitNull[0].State -ceq 'Disabled' -and
            $null -eq $explicitNull[0].RawData -and $null -eq $explicitNull[0].KeyOnly -and
            $null -eq $explicitNull[0].DeletionDirective -and $null -eq $explicitNull[0].Deleted) 'Explicit null dictionary options changed their projection.'
    }

    foreach ($projectionEntryPoint in @('Resolver', 'Command')) {
        Test-Policy ('strict dictionary registry secret projection via ' + $projectionEntryPoint) {
            Set-StrictMode -Version Latest
            $marker = 'FIXTURE_ONLY_S040_ADMX_PAYLOAD'
            $records = @(
                @{
                    Scope = 'Computer'
                    Hive = 'HKLM'
                    Key = $projectionKey
                    ValueName = 'DefaultPassword'
                    Type = 1
                    Source = 'Machine/Registry.pol'
                    FixtureMetadata = 'retained'
                    Value = $marker
                    RawData = $marker
                }
                [ordered]@{
                    Scope = 'Computer'
                    Hive = 'HKLM'
                    Key = $projectionKey
                    ValueName = 'DefaultPassword'
                    Type = 1
                    Source = 'Machine/Registry.pol'
                    FixtureMetadata = 'retained'
                    KeyOnly = $false
                    DeletionDirective = $null
                    SecretPresent = $false
                    Value = $marker
                    Data = $marker
                    Bytes = [Text.Encoding]::UTF8.GetBytes($marker)
                }
            )

            foreach ($record in $records) {
                $before = ConvertTo-Json -InputObject $record -Depth 12 -Compress
                $inputRows = [object[]]@($record)
                $results = if ($projectionEntryPoint -ceq 'Resolver') {
                    @([ADAnalyzerAdmxResolver]::new().Resolve($inputRows, $projectionPath))
                }
                else {
                    @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings $inputRows -TemplatePath $projectionPath)
                }

                $after = ConvertTo-Json -InputObject $record -Depth 12 -Compress
                Assert-Policy ($before -ceq $after) 'Registry secret projection modified its dictionary input.'
                $rows = @($results)
                Assert-Policy ($rows.Count -eq 1) 'Registry secret projection did not return one row per input.'
                $row = $rows[0]
                Assert-Policy (
                    $row -is [pscustomobject] -and
                    $row -isnot [Collections.IDictionary] -and
                    -not [object]::ReferenceEquals($row, $record)
                ) 'Registry secret projection did not return a detached record.'

                $json = ConvertTo-Json -InputObject $row -Depth 12 -Compress
                $xml = [Management.Automation.PSSerializer]::Serialize($row)
                Assert-Policy (
                    -not $json.Contains($marker) -and -not $xml.Contains($marker)
                ) 'Registry secret projection exposed fixture data in serialization.'

                foreach ($name in @(
                        'Value', 'RawData', 'Data', 'Bytes',
                        'Keys', 'Values', 'Count', 'Comparer', 'EqualityComparer',
                        'IsReadOnly', 'IsFixedSize', 'IsSynchronized', 'SyncRoot'
                    )) {
                    Assert-Policy (
                        $null -eq $row.PSObject.Properties[$name]
                    ) 'Registry secret projection retained a payload field or dictionary container.'
                }

                Assert-Policy (
                    $row.SecretPresent -is [bool] -and
                    $row.SecretPresent -and
                    $row.MetadataStatus -ceq 'PresenceOnly' -and
                    $row.State -ceq 'Unknown'
                ) 'Registry secret projection did not report a positive presence-only state.'
                Assert-Policy (
                    $row.Scope -ceq 'Computer' -and
                    $row.Hive -ceq 'HKLM' -and
                    $row.Key -ceq $projectionKey -and
                    $row.ValueName -ceq 'DefaultPassword' -and
                    $row.Type -eq 1 -and
                    $row.Source -ceq 'Machine/Registry.pol' -and
                    $row.FixtureMetadata -ceq 'retained'
                ) 'Registry secret projection lost identity or explicit metadata.'

                if ($record -is [Collections.Specialized.OrderedDictionary]) {
                    Assert-Policy (
                        $row.KeyOnly -is [bool] -and
                        -not $row.KeyOnly -and
                        $null -ne $row.PSObject.Properties['DeletionDirective'] -and
                        $null -eq $row.DeletionDirective
                    ) 'Registry secret projection changed explicitly supplied optional metadata.'
                }
                else {
                    Assert-Policy (
                        $null -eq $row.PSObject.Properties['KeyOnly'] -and
                        $null -eq $row.PSObject.Properties['DeletionDirective']
                    ) 'Registry secret projection added omitted optional metadata.'
                }
            }
        }
    }

    Test-Policy 'strict registry projection retains the native missing required field error' {
        Set-StrictMode -Version Latest
        $row = New-RegistryFixture $projectionKey FixtureValue 17
        $row.PSObject.Properties.Remove('ValueName')
        $failure = $null
        try {
            $null = Resolve-ADAnalyzerRegistryPolicy -RegistrySettings @($row) -TemplatePath $projectionPath
        }
        catch {
            $failure = $_
        }
        Assert-Policy ($null -ne $failure -and $failure.FullyQualifiedErrorId -like 'PropertyNotFoundStrict*' -and
            $failure.Exception.Message -match 'ValueName') 'Missing required ValueName did not retain its native strict property diagnostic.'
    }
    Test-Policy 'nested registry input preserves native optional member enumeration' {
        Set-StrictMode -Off
        $first = New-RegistryFixture $projectionKey FirstValue 13
        $first.RawData = [byte]1
        $first | Add-Member -NotePropertyMembers @{
            DeletionDirective = $false
            Deleted = $false
        }
        $second = New-RegistryFixture $projectionKey SecondValue 17
        $second.RawData = [byte]2
        $second.KeyOnly = $true
        $second | Add-Member -NotePropertyMembers @{
            DeletionDirective = $true
            Deleted = $true
        }

        $inner = [object[]]@($first, $second)
        $nested = [object[]]::new(1)
        $nested[0] = $inner
        $result = @(Resolve-ADAnalyzerRegistryPolicy -RegistrySettings $nested)
        Assert-Policy ($result.Count -eq 1 -and $result[0].MetadataStatus -ceq 'TemplateNotFound') 'Nested input changed the native projection shape.'
        foreach ($name in @('RawData', 'KeyOnly', 'DeletionDirective', 'Deleted')) {
            $expected = $inner.$name
            $observed = $result[0].$name
            Assert-Policy ($null -ne $observed -and $observed.GetType() -eq $expected.GetType() -and
                ($observed -join ',') -ceq ($expected -join ',')) "Nested input lost native member values or types for $name."
        }
    }
}
finally {
    Remove-Item -LiteralPath $taskTemp -Recurse -Force
}

$policyValueCases = [ordered]@{
    Values = 180
    Faults = 36
    Direct = 189
}
foreach ($case in $policyValueCases.Keys) {
    Test-Policy ('policy value semantics API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'PolicyValueSemanticsFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS policy value semantics ' + $case + ' ' + $policyValueCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every policy value scenario.'
    }
}

$admxResolverCases = [ordered]@{
    Records = 16
    Stream = 2
    Faults = 8
    Direct = 18
}
foreach ($case in $admxResolverCases.Keys) {
    Test-Policy ('ADMX resolver API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'AdmxResolverClassFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS ADMX resolver ' + $case + ' ' + $admxResolverCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every ADMX resolver API case.'
    }
}

$securityCatalogueCases = [ordered]@{
    Records = 9
    Stream = 4
    Faults = 8
    Direct = 11
}
foreach ($case in $securityCatalogueCases.Keys) {
    Test-Policy ('GPO security catalogue API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'GpoSecurityCatalogueFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS GPO security catalogue ' + $case + ' ' + $securityCatalogueCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every security catalogue API case.'
    }
}

$applicabilityCases = [ordered]@{
    Records = 31
    Faults = 16
    Direct = 33
}
foreach ($case in $applicabilityCases.Keys) {
    Test-Policy ('GPO applicability API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'GpoApplicabilityFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS GPO applicability ' + $case + ' ' + $applicabilityCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every GPO applicability API case.'
    }
}

$registryReplayCases = [ordered]@{
    Records = 12
    Faults = 8
    Direct = 14
}
foreach ($case in $registryReplayCases.Keys) {
    Test-Policy ('Registry policy replay API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'RegistryPolicyReplayFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS registry policy replay ' + $case + ' ' + $registryReplayCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every registry replay API case.'
    }
}

$replayConversionCases = [ordered]@{
    Continue = 5
    Compatibility = 13
}
foreach ($case in $replayConversionCases.Keys) {
    Test-Policy ('Registry replay conversion: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'RegistryReplayConversionFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS registry replay conversion ' + $case + ' ' + $replayConversionCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every registry replay conversion case.'
    }
}

$gpoParserCases = [ordered]@{
    Records = 41
    Faults = 13
    Direct = 42
}
foreach ($case in $gpoParserCases.Keys) {
    Test-Policy ('GPO policy record parser API: ' + $case) {
        $executable = (Get-Process -Id $PID).Path
        $fixture = Join-Path $PSScriptRoot 'GpoPolicyRecordParserFixture.ps1'
        $output = & $executable -NoLogo -NoProfile -NonInteractive -File $fixture -Case $case 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ($output -join [Environment]::NewLine)
        }
        $marker = 'PASS GPO policy record parser ' + $case + ' ' + $gpoParserCases[$case]
        Assert-Policy ($marker -cin @($output)) 'Fresh process did not execute every GPO parser case.'
    }
}
Write-Host ("{0} policy-analysis tests passed; {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed) {
    throw 'Policy-analysis tests failed'
}
