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
