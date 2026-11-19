[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
foreach ($name in @('ADProfile', 'ADGpo', 'ADPolicyAnalysis', 'ADHostAnalysis')) {
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

function Test-HostPolicy([string]$Name, [scriptblock]$Body) {
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
$script:AuditFlags = 3
$script:AuditFails = $false
$script:AuditCalls = 0
$script:TlsCalls = 0
$script:Credential = [pscredential]::new('fixture', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))

function Get-ADAnalyzerAuditPolicy {
    param(
        $ComputerName,
        $Credential,
        $TimeoutSeconds

    )
    $script:AuditCalls++
    $script:AuditCredential = $Credential
    if ($script:AuditFails) {
        throw 'fixture WinRM denied'
    }
    [pscustomobject]@{
        SubcategoryGuid = '0cce9215-69ae-11d9-bed3-505054503030'
        Flags = $script:AuditFlags
    }
}
$script:CertificateValid = $true
$script:CertificateFails = $false

function Get-ADAnalyzerTlsCertificate {
    param(
        $HostName,
        $Port,
        $ServerName,
        $TimeoutSeconds

    )
    $script:TlsCalls++
    if ($script:CertificateFails) {
        throw 'fixture TLS failed'
    }
    [pscustomobject]@{
        Subject = 'CN=fixture'
        Thumbprint = 'fixture'
        NameValid = $script:CertificateValid
        ChainValid = $script:CertificateValid
        NotBefore = [datetime]::UtcNow.AddDays(-1)
        NotAfter = [datetime]::UtcNow.AddDays(90)
        Protocol = 'Tls12'
        RevocationChecked = $false
    }
}
$hostRecord = [pscustomobject]@{
    ComputerName = 'dc.example.invalid'
    Services = @([pscustomobject]@{
            Name = 'Spooler'
            State = 'Stopped'
            StartMode = 'Disabled'
        })
    Registry = @([pscustomobject]@{
            Path = 'SYSTEM\Fixture'
            Name = 'Enabled'
            Status = 'Observed'
            Value = 0
        })
}
$profile = Get-ADAnalyzerDefaultProfile
$profile.Host.Services = @(@{
        Name = 'Spooler'
        State = 'Stopped'
        StartMode = 'Disabled'
    })
$profile.Host.RegistryRules = @(@{
        Key = 'SYSTEM\Fixture'
        ValueName = 'Enabled'
        Expected = 0
    })
$profile.Host.AuditRules = @(@{
        SubcategoryGuid = '0cce9215-69ae-11d9-bed3-505054503030'
        Flags = 3
    })
$profile.Host.CertificateEndpoints = @(@{
        HostName = 'dc.example.invalid'
        Port = 636
        ServerName = 'dc.example.invalid'
        MinimumRemainingDays = 30
    })
Test-HostPolicy 'secret registry baselines fail before any host check audit or TLS observation' {
    foreach ($rule in @(
            @{
                Kind = 'Account'
                Name = 'Friendly label'
                Key = 'Software\Fixture'
                ValueName = 'DefaultPassword'
                Expected = 'unit7-host-secret'
            }
            @{
                Name = 'Friendly label'
                Key = 'Software\Fixture\DefaultPassword'
                Expected = 'unit7-host-secret'
            }
        )) {
        $copy = Get-ADAnalyzerDefaultProfile
        $copy.Host.RegistryRules = @($rule)
        $copy.Host.AuditRules = $profile.Host.AuditRules
        $copy.Host.CertificateEndpoints = $profile.Host.CertificateEndpoints
        $audit = $script:AuditCalls
        $tls = $script:TlsCalls
        $emitted = [Collections.ArrayList]::new()
        $caught = $null
        try {
            Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy | ForEach-Object { $null = $emitted.Add($_) }
        }
        catch {
            $caught = $_
        }
        Assert-True ($null -ne $caught) 'Secret host rule accepted'
        Assert-Equal 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.' $caught.Exception.Message
        Assert-True (([string]$caught.TargetObject) -notmatch 'unit7-host-secret') 'Secret error target'
        Assert-Equal 0 $emitted.Count
        Assert-Equal $audit $script:AuditCalls
        Assert-Equal $tls $script:TlsCalls
    }
}
Test-HostPolicy 'host services and explicit registry overrides are evaluated from observations' {
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile -Credential $script:Credential)
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.SERVICE).Status
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.REGISTRY).Status
}
Test-HostPolicy 'duplicate canonical audit and certificate identities fail before observations' {
    foreach ($kind in @('Audit', 'Tls')) {
        $copy = Get-ADAnalyzerDefaultProfile
        if ($kind -eq 'Audit') {
            $copy.Host.AuditRules = @(@{
                    SubcategoryGuid = '0cce9215-69ae-11d9-bed3-505054503030'
                    Flags = 1
                }, @{
                    SubcategoryGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                    Flags = 2
                })
        }
        else {
            $copy.Host.CertificateEndpoints = @(@{
                    HostName = 'dc.example.invalid'
                }, @{
                    HostName = 'DC.EXAMPLE.INVALID'
                    Port = 443
                    ServerName = 'dc.example.invalid'
                })
        }
        $before = ConvertTo-Json -InputObject $copy -Depth 50 -Compress
        $audit = $script:AuditCalls
        $tls = $script:TlsCalls
        $emitted = [Collections.Generic.List[object]]::new()
        $caught = $null
        try {
            Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy | ForEach-Object { $emitted.Add($_) }
        }
        catch {
            $caught = $_
        }
        Assert-True ($null -ne $caught -and
            $caught.Exception.Message -match 'Duplicate host (audit|certificate)') 'Ambiguous profile was not rejected'
        Assert-Equal 0 $emitted.Count
        Assert-Equal $audit $script:AuditCalls
        Assert-Equal $tls $script:TlsCalls
        Assert-Equal $before (ConvertTo-Json -InputObject $copy -Depth 50 -Compress)
    }
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.AuditRules = @(@{
            SubcategoryGuid = '0cce9215-69ae-11d9-bed3-505054503030'
            Flags = 1
        }, @{
            SubcategoryGuid = '0cce9216-69ae-11d9-bed3-505054503030'
            Flags = 2
        })
    $copy.Host.CertificateEndpoints = @(@{
            HostName = 'dc.example.invalid'
        }, @{
            HostName = 'dc.example.invalid'
            Port = 636
        }, @{
            HostName = 'dc.example.invalid'
            ServerName = 'other.example.invalid'
        })
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy)
    Assert-Equal 0 @($checks | Group-Object CheckId | Where-Object Count -gt 1).Count
    $audit = @($checks | Where-Object RuleId -eq HOST.AUDIT_POLICY)
    Assert-Equal 2 $audit.Count
    Assert-Equal (New-ADAnalyzerCheck `
            -RuleId HOST.AUDIT_POLICY `
            -Target ($hostRecord.ComputerName + '/Audit/0cce9215-69ae-11d9-bed3-505054503030') `
            -Status Pass).CheckId $audit[0].CheckId
    Assert-Equal 3 @($checks | Where-Object RuleId -eq HOST.TLS_CERTIFICATE).Count
}
Test-HostPolicy 'declared host registry types require observed matching type evidence' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.RegistryRules = @(@{
            Id = 'typed'
            Key = 'SYSTEM\Fixture'
            ValueName = 'Enabled'
            Expected = 0
            Operator = 'Equals'
            Type = 4
        })
    $record = [pscustomobject]@{
        ComputerName = 'fixture'
        Services = @()
        Registry = @()
    }
    $observation = @{
        Path = 'SYSTEM\Fixture'
        Name = 'Enabled'
        Status = 'Observed'
        Value = 0
    }
    $cases = @(
        @{
            Name = 'absent Type on a custom object'
            Rows = @([pscustomobject]$observation)
            Status = 'Unknown'
            Type = $null
        }
        @{
            Name = 'absent Type on a hashtable'
            Rows = @($observation.Clone())
            Status = 'Unknown'
            Type = $null
        }
        @{
            Name = 'explicitly null Type'
            Rows = @([pscustomobject]($observation + @{ Type = $null }))
            Status = 'Unknown'
            Type = $null
        }
        @{
            Name = 'mismatching Type'
            Rows = @([pscustomobject]($observation + @{ Type = 1 }))
            Status = 'Invalid'
            Type = 1
        }
        @{
            Name = 'matching Type on a hashtable'
            Rows = @($observation + @{ Type = 4 })
            Status = 'Pass'
            Type = 4
        }
        @{
            Name = 'no matching value'
            Rows = @()
            Status = 'Unknown'
            Type = $null
        }
        @{
            Name = 'ambiguous matching value'
            Rows = @($observation.Clone(), $observation.Clone())
            Status = 'Unknown'
            Type = $null
        }
        @{
            Name = 'unavailable value with omitted Type'
            Rows = @([pscustomobject]@{
                    Path = 'SYSTEM\Fixture'
                    Name = 'Enabled'
                    Status = 'Unknown'
                })
            Status = 'Unknown'
            Type = $null
        }
    )
    foreach ($case in $cases) {
        $record.Registry = $case.Rows
        $profileBefore = ConvertTo-Json -InputObject $copy -Depth 30 -Compress
        $recordBefore = ConvertTo-Json -InputObject $record -Depth 10 -Compress
        $ordinary = @(Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy)
        $strict = @(& {
                Set-StrictMode -Version Latest
                Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy
            })
        $check = $strict | Where-Object RuleId -eq 'HOST.REGISTRY'
        Assert-True ($check.Status -ceq $case.Status) ('Unexpected registry status for ' + $case.Name)
        Assert-True ([object]::Equals($case.Type, $check.Evidence.RegistryType)) ('Unexpected registry evidence for ' + $case.Name)
        Assert-Equal 4 $check.Evidence.ExpectedRegistryType
        Assert-Equal (ConvertTo-Json -InputObject $ordinary -Depth 30 -Compress) (ConvertTo-Json -InputObject $strict -Depth 30 -Compress)
        Assert-Equal $profileBefore (ConvertTo-Json -InputObject $copy -Depth 30 -Compress)
        Assert-Equal $recordBefore (ConvertTo-Json -InputObject $record -Depth 10 -Compress)
    }
}
Test-HostPolicy 'StrictMode service rules accept omitted or null startup expectations' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.Services = @(
        @{
            Name = 'Spooler'
            State = 'Stopped'
        }
        @{
            Id = 'state-only'
            Name = 'Spooler'
            State = 'Stopped'
            StartMode = $null
        }
        @{
            Id = 'startup-mismatch'
            Name = 'Spooler'
            State = 'Stopped'
            StartMode = 'Auto'
        }
    )
    $target = $hostRecord.ComputerName + '/Service/Spooler'
    $profileBefore = ConvertTo-Json -InputObject $copy -Depth 30 -Compress
    $recordBefore = ConvertTo-Json -InputObject $hostRecord -Depth 10 -Compress
    $ordinary = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy)
    $strict = @(& {
            Set-StrictMode -Version Latest
            Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy
        })
    Assert-Equal 'HOST.SERVICE,HOST.SERVICE,HOST.SERVICE,HOST.AUDIT_POLICY' ($strict.RuleId -join ',')
    Assert-Equal 'Pass,Pass,Fail,NotConfigured' ($strict.Status -join ',')
    Assert-Equal (New-ADAnalyzerCheck -RuleId 'HOST.SERVICE' -Target $target -Status Pass).CheckId $strict[0].CheckId
    Assert-True ($null -eq $strict[0].Evidence.ProfileRuleId) 'Unnamed service rule acquired a profile rule ID'
    Assert-Equal 'state-only' $strict[1].Evidence.ProfileRuleId
    Assert-Equal 'startup-mismatch' $strict[2].Evidence.ProfileRuleId
    Assert-Equal 3 @($strict[0..2] | Select-Object -ExpandProperty CheckId -Unique).Count
    Assert-Equal ($target + ',' + $target + ',' + $target) ($strict[0..2].Target -join ',')
    Assert-Equal (ConvertTo-Json -InputObject $ordinary -Depth 30 -Compress) (ConvertTo-Json -InputObject $strict -Depth 30 -Compress)
    Assert-Equal $profileBefore (ConvertTo-Json -InputObject $copy -Depth 30 -Compress)
    Assert-Equal $recordBefore (ConvertTo-Json -InputObject $hostRecord -Depth 10 -Compress)
}
Test-HostPolicy 'StrictMode registry rules preserve optional field defaults and evidence' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.RegistryRules = @(
        @{
            Key = 'SYSTEM\Fixture'
            ValueName = 'Enabled'
            Expected = 0
        }
        @{
            Id = 'not-one'
            Key = 'SYSTEM\Fixture'
            ValueName = 'Enabled'
            Expected = 1
            Operator = 'NotEquals'
            Type = 4
        }
    )
    $record = [pscustomobject]@{
        ComputerName = $hostRecord.ComputerName
        Services = @()
        Registry = @([ordered]@{
                Path = 'SYSTEM\Fixture'
                Name = 'Enabled'
                Status = 'Observed'
                Value = 0
                Type = 4
            })
    }
    $target = $record.ComputerName + '/Registry/SYSTEM\Fixture/Enabled'
    $profileBefore = ConvertTo-Json -InputObject $copy -Depth 30 -Compress
    $recordBefore = ConvertTo-Json -InputObject $record -Depth 10 -Compress
    $ordinary = @(Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy)
    $strict = @(& {
            Set-StrictMode -Version Latest
            Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy
        })
    Assert-Equal 'HOST.REGISTRY,HOST.REGISTRY,HOST.AUDIT_POLICY' ($strict.RuleId -join ',')
    Assert-Equal 'Pass,Pass,NotConfigured' ($strict.Status -join ',')
    Assert-Equal (New-ADAnalyzerCheck -RuleId 'HOST.REGISTRY' -Target $target -Status Pass).CheckId $strict[0].CheckId
    Assert-True ($null -eq $strict[0].Evidence.ProfileRuleId) 'Unnamed registry rule acquired a profile rule ID'
    Assert-True ($null -eq $strict[0].Evidence.ExpectedRegistryType) 'Untyped rule acquired an expected registry type'
    Assert-Equal 4 $strict[0].Evidence.RegistryType
    Assert-Equal 'not-one' $strict[1].Evidence.ProfileRuleId
    Assert-Equal 4 $strict[1].Evidence.ExpectedRegistryType
    Assert-True ($strict[0].CheckId -cne $strict[1].CheckId) 'Named and unnamed registry identities collided'
    Assert-Equal (ConvertTo-Json -InputObject $ordinary -Depth 30 -Compress) (ConvertTo-Json -InputObject $strict -Depth 30 -Compress)
    Assert-Equal $profileBefore (ConvertTo-Json -InputObject $copy -Depth 30 -Compress)
    Assert-Equal $recordBefore (ConvertTo-Json -InputObject $record -Depth 10 -Compress)
    $copy.Host.RegistryRules[0].Expected = 1
    $strict = @(& {
            Set-StrictMode -Version Latest
            Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy
        })
    Assert-Equal Fail $strict[0].Status
    Assert-Equal Pass $strict[1].Status
}
Test-HostPolicy 'registry type reads preserve custom getters and comparison cardinality' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.RegistryRules = @(@{
            Id = 'typed'
            Key = 'SYSTEM\Fixture'
            ValueName = 'Enabled'
            Expected = 0
            Operator = 'Equals'
            Type = 4
        })
    $observation = [pscustomobject]@{
        Path = 'SYSTEM\Fixture'
        Name = 'Enabled'
        Status = 'Observed'
        Value = 0
        TypeReads = 0
    }
    $observation.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Type', {
                $this.TypeReads++
                if ($this.TypeReads -eq 1) {
                    return 4
                }
                if ($this.TypeReads -eq 2) {
                    return ,@(0)
                }
                return ,@(4)
            }))
    $record = [pscustomobject]@{
        ComputerName = 'fixture'
        Services = @()
        Registry = @($observation)
    }
    $ordinary = @(Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy)
    Assert-Equal 3 $observation.TypeReads
    $observation.TypeReads = 0
    $strict = @(& {
            Set-StrictMode -Version Latest
            Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy
        })
    Assert-Equal 3 $observation.TypeReads
    Assert-Equal Pass $strict[0].Status
    Assert-True ([object]::Equals(4, $strict[0].Evidence.RegistryType)) 'Registry evidence did not preserve the native scalar'
    Assert-Equal (ConvertTo-Json -InputObject $ordinary -Depth 30 -Compress) (ConvertTo-Json -InputObject $strict -Depth 30 -Compress)
}
Test-HostPolicy 'optional profile rule IDs keep shared host targets independent and stable' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.Services = @(@{
            Id = 'running'
            Name = 'Spooler'
            State = 'Running'
        }, @{
            Id = 'stopped'
            Name = 'spooler'
            State = 'Stopped'
        })
    $copy.Host.RegistryRules = @(@{
            Id = 'zero'
            Key = 'SYSTEM\Fixture'
            ValueName = 'Enabled'
            Expected = 0
        }, @{
            Id = 'one'
            Key = 'system\fixture'
            ValueName = 'enabled'
            Expected = 1
        })
    $before = ConvertTo-Json -InputObject $copy -Depth 30 -Compress
    $checks = @(Test-ADAnalyzerHostPolicy `
            -Hosts @($hostRecord) `
            -Profile $copy | Where-Object { $_.RuleId -in 'HOST.SERVICE',
            'HOST.REGISTRY' })
    Assert-Equal 4 $checks.Count
    Assert-Equal 0 @($checks | Group-Object CheckId | Where-Object Count -gt 1).Count
    Assert-Equal 2 @($checks | Where-Object Status -eq Pass).Count
    Assert-Equal 2 @($checks | Where-Object Status -eq Fail).Count
    Assert-Equal $before (ConvertTo-Json -InputObject $copy -Depth 30 -Compress)
    $byId = @{}
    foreach ($check in $checks) {
        $byId[$check.RuleId + '/' + $check.Evidence.ProfileRuleId] = $check.CheckId
    }
    [array]::Reverse($copy.Host.Services)
    [array]::Reverse($copy.Host.RegistryRules)
    $copy.Host.Services[0].State = 'Running'
    $copy.Host.RegistryRules[0].Expected = 0
    foreach ($check in @(Test-ADAnalyzerHostPolicy `
                -Hosts @($hostRecord) `
                -Profile $copy | Where-Object { $_.RuleId -in 'HOST.SERVICE',
                'HOST.REGISTRY' })) {
        Assert-Equal $byId[$check.RuleId + '/' + $check.Evidence.ProfileRuleId] $check.CheckId
        Assert-True ($check.Target -notmatch 'HostRuleId' -and
            $check.Target.IndexOf([char]0) -lt 0) 'Internal identity escaped into readable target'
    }
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.Services = @(@{
            Name = 'Spooler'
            State = 'Stopped'
        })
    $copy.Host.RegistryRules = @(@{
            Key = 'SYSTEM\Fixture'
            ValueName = 'Enabled'
            Expected = 0
        })
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy)
    Assert-Equal (New-ADAnalyzerCheck `
            -RuleId HOST.SERVICE `
            -Target ($hostRecord.ComputerName + '/Service/Spooler') `
            -Status Pass).CheckId ($checks | Where-Object RuleId `
            -eq HOST.SERVICE).CheckId
    Assert-Equal (New-ADAnalyzerCheck `
            -RuleId HOST.REGISTRY `
            -Target ($hostRecord.ComputerName + '/Registry/SYSTEM\Fixture/Enabled') `
            -Status Pass).CheckId ($checks | Where-Object RuleId `
            -eq HOST.REGISTRY).CheckId
    $copy.Host.Services += @(@{
            Id = 'zero'
            Name = 'Other'
            State = 'Running'
        })
    $copy.Host.RegistryRules[0].Id = 'zero'
    $null = Import-ADAnalyzerProfile -Profile $copy
}
Test-HostPolicy 'named registry identities distinguish literal key and value separators' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.RegistryRules = @(@{
            Id = 'shared'
            Key = 'SYSTEM\Fixture'
            ValueName = 'part/Enabled'
            Expected = 0
        }, @{
            Id = 'shared'
            Key = 'SYSTEM\Fixture/part'
            ValueName = 'Enabled'
            Expected = 0
        })
    $record = [pscustomobject]@{
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
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($record) -Profile $copy | Where-Object RuleId -eq HOST.REGISTRY)
    Assert-Equal 2 $checks.Count
    Assert-Equal 2 @($checks | Where-Object Status -eq Pass).Count
    Assert-Equal 0 @($checks | Group-Object CheckId | Where-Object Count -gt 1).Count
    Assert-Equal 2 @($checks | ForEach-Object { $_.Evidence.RegistryPath } | Select-Object -Unique).Count
}
Test-HostPolicy 'ambiguous or malformed host profile IDs fail before observations' {
    foreach ($kind in @('Services', 'RegistryRules')) {
        $base = if ($kind -eq 'Services') {
            @{
                Name = 'Spooler'
                State = 'Running'
            }
        }
        else {
            @{
                Key = 'SYSTEM\Fixture'
                ValueName = 'Enabled'
                Expected = 0
            }
        }
        $cases = @(, @($base.Clone(), $base.Clone()))
        $first = $base.Clone()
        $second = $base.Clone()
        $first.Id = 'same'
        $second.Id = 'SAME'
        $cases += , @($first, $second)
        foreach ($invalid in @($null, '', ' ', 1, @('one', 'two'), ('bad' + [char]0 + 'id'))) {
            $rule = $base.Clone()
            $rule.Id = $invalid
            $cases += , @($rule)
        }
        foreach ($rules in $cases) {
            $copy = Get-ADAnalyzerDefaultProfile
            $copy.Host[$kind] = @($rules)
            $copy.Host.AuditRules = $profile.Host.AuditRules
            $copy.Host.CertificateEndpoints = $profile.Host.CertificateEndpoints
            $audit = $script:AuditCalls
            $tls = $script:TlsCalls
            $caught = $false
            try {
                $null = Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy
            }
            catch {
                $caught = $true
            }
            Assert-True $caught 'Ambiguous or malformed host identity accepted'
            Assert-Equal $audit $script:AuditCalls
            Assert-Equal $tls $script:TlsCalls
        }
    }
}
Test-HostPolicy 'numeric audit masks verify success and failure without localized text' {
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile -Credential $script:Credential)
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.AUDIT_POLICY).Status
    Assert-True ([object]::ReferenceEquals($script:Credential, $script:AuditCredential)) 'Audit credential lost'
    $script:AuditFlags = 1
    try {
        Assert-Equal Fail (@(Test-ADAnalyzerHostPolicy `
                    -Hosts @($hostRecord) `
                    -Profile $profile) | Where-Object RuleId `
                -eq HOST.AUDIT_POLICY).Status
    }
    finally {
        $script:AuditFlags = 3
    }
}
Test-HostPolicy 'unavailable audit permissions become unreadable instead of compliant' {
    $script:AuditFails = $true
    try {
        Assert-Equal Unreadable (@(Test-ADAnalyzerHostPolicy `
                    -Hosts @($hostRecord) `
                    -Profile $profile) | Where-Object RuleId `
                -eq HOST.AUDIT_POLICY).Status
    }
    finally {
        $script:AuditFails = $false
    }
}
Test-HostPolicy 'TLS name chain validity and expiry are checked with revocation explicit' {
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile)
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.TLS_CERTIFICATE).Status
    Assert-Equal Unknown ($checks | Where-Object RuleId -eq HOST.CERTIFICATE_REVOCATION).Status
    $script:CertificateValid = $false
    try {
        Assert-Equal Fail (@(Test-ADAnalyzerHostPolicy `
                    -Hosts @($hostRecord) `
                    -Profile $profile) | Where-Object RuleId `
                -eq HOST.TLS_CERTIFICATE).Status
    }
    finally {
        $script:CertificateValid = $true
    }
}
Test-HostPolicy 'TLS handshake errors are visible and never produce a passing certificate' {
    $script:CertificateFails = $true
    try {
        Assert-Equal Unreadable (@(Test-ADAnalyzerHostPolicy `
                    -Hosts @($hostRecord) `
                    -Profile $profile) | Where-Object RuleId `
                -eq HOST.TLS_CERTIFICATE).Status
    }
    finally {
        $script:CertificateFails = $false
    }
}
Test-HostPolicy 'missing registry overrides remain unknown and unconfigured audit causes no read' {
    $copy = Get-ADAnalyzerDefaultProfile
    $copy.Host.RegistryRules = @(@{
            Key = 'Missing'
            ValueName = 'Enabled'
            Expected = 0
        })
    $checks = @(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy)
    Assert-Equal Unknown ($checks | Where-Object RuleId -eq HOST.REGISTRY).Status
    Assert-Equal NotConfigured ($checks | Where-Object RuleId -eq HOST.AUDIT_POLICY).Status
}
Test-HostPolicy 'native audit and TLS adapter source compiles without third party assemblies' {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'bin/ADHostAnalysis.ps1'),
        [ref]$tokens,
        [ref]$errors)
    $sources = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
                $node.Value -like '*namespace ADAnalyzer*' },
            $true))
    Assert-Equal 2 $sources.Count
    foreach ($source in $sources) {
        if ($source.Value -like '*class TlsInspector*' -and -not ('ADAnalyzer.TlsInspector' -as [type])) {
            Add-Type -TypeDefinition $source.Value
        }
        if ($source.Value -like '*class NativeAuditPolicy*' -and -not ('ADAnalyzer.NativeAuditPolicy' -as [type])) {
            Add-Type -TypeDefinition $source.Value
        }
    }
    Assert-True ([bool]('ADAnalyzer.TlsInspector' -as [type])) 'TLS inspector not compiled'
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $records = @([ADAnalyzer.NativeAuditPolicy]::Read())
        Assert-True ($records.Count -gt 0) 'No native audit subcategories returned'
        foreach ($record in $records) {
            Assert-True ($record.Flags -le 7) 'Invalid native audit flags'
        }
    }
}
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Test-HostPolicy 'native TLS inspector observes a loopback server without trusting its self-signed certificate' {
        Add-Type `
            -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
namespace ADAnalyzer {
 public sealed class TestTlsServer : IDisposable {
  TcpListener listener; X509Certificate2 cert; RSA key; Task server;
  public int Port; public Exception Error;
  public TestTlsServer() {
   key=RSA.Create(2048);
   CertificateRequest request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   // Schannel needs an importable key container for server authentication.
   // Do not install the fixture certificate in a trusted certificate store.
   X509Certificate2 generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
   if(Environment.OSVersion.Platform==PlatformID.Win32NT) {
    using(generated) {
     // Select the framework-compatible import API without a modern-runtime
     // obsolete-constructor compile warning in this shared test source.
     cert=(X509Certificate2)typeof(X509Certificate2).GetConstructor(new Type[] {typeof(byte[]),typeof(string),typeof(X509KeyStorageFlags)}).Invoke(new object[] {generated.Export(X509ContentType.Pfx),null,X509KeyStorageFlags.UserKeySet});
    }
   } else {cert=generated;}
   listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;
   server=Task.Run(delegate {
    try {
     using(TcpClient client=listener.AcceptTcpClient()) using(SslStream stream=new SslStream(client.GetStream(),false)) {
      stream.AuthenticateAsServer(cert,false,SslProtocols.Tls12,false);
      stream.ReadTimeout=5000;
      try {stream.ReadByte();} catch(System.IO.IOException) {}
     }
    } catch(Exception error) {Error=error;throw;}
   });
  }
  public void Dispose() {listener.Stop();try{server.Wait(5000);}catch{}cert.Dispose();key.Dispose();}
 }
}
'@
        $server = [ADAnalyzer.TestTlsServer]::new()
        try {
            $record = [ADAnalyzer.TlsInspector]::Read('127.0.0.1', $server.Port, 'wrong.example.invalid', 5000)
            Assert-Equal $false $record.NameValid
            Assert-Equal $false $record.ChainValid
            Assert-Equal Tls12 $record.Protocol
            Assert-True (-not [string]::IsNullOrWhiteSpace($record.Thumbprint)) 'Missing inspected certificate'
        }
        catch {
            if ($server.Error) {
                throw ('TLS fixture server failed: ' + $server.Error.ToString())
            }
            throw
        }
        finally {
            $server.Dispose()
        }
    }
}
Write-Host ("{0} host-analysis tests passed; {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed) {
    exit 1
}
