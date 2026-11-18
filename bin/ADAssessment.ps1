# Keep configuration in real private .NET state; PowerShell hidden fields serialize.
if (-not ('ADAnalyzer.ConfigurationState' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'ADConfiguration.cs') -ErrorAction Stop
}

class ADAnalyzerAssessmentEngine {
    hidden [object]$Settings

    ADAnalyzerAssessmentEngine() {
        $profile = Import-ADAnalyzerProfile
        $this.Settings = [Activator]::CreateInstance(
            ('ADAnalyzer.ConfigurationState' -as [type]),
            [object[]]@($profile)
        )
    }

    ADAnalyzerAssessmentEngine([object]$Profile) {
        $configuration = Import-ADAnalyzerProfile -Profile $Profile
        $this.Settings = [Activator]::CreateInstance(
            ('ADAnalyzer.ConfigurationState' -as [type]),
            [object[]]@($configuration)
        )
    }

    [object] Evaluate([object]$DirectoryData) {
        return $this.Evaluate($DirectoryData, @(), 'offline')
    }

    [object] Evaluate([object]$DirectoryData, [array]$GpoData) {
        return $this.Evaluate($DirectoryData, $GpoData, 'offline')
    }

    [object] Evaluate([object]$DirectoryData, [array]$GpoData, [string]$Target) {
        return $this.EvaluateCore($DirectoryData, $GpoData, $Target, $null, 'Stop')
    }

    hidden [object] EvaluateForCommand(
        [object]$DirectoryData,
        [array]$GpoData,
        [string]$Target,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        return $this.EvaluateCore($DirectoryData, $GpoData, $Target, $CommandContext, $ErrorPreference)
    }

    hidden [object[]] InvokeChecks(
        [Management.Automation.CommandInfo]$Command,
        [hashtable]$Arguments,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        $ErrorActionPreference = if ($null -ne $CommandContext -and
            $ErrorPreference -ne 'Stop') {
            'Continue'
        }
        else {
            $ErrorPreference
        }
        $commandArguments = $Arguments.Clone()
        if ($ErrorPreference -eq 'Ignore') {
            # Windows PowerShell 5.1 supports Ignore as a parameter, not a preference variable.
            $commandArguments.ErrorAction = 'Ignore'
        }
        $values = [Collections.Generic.List[object]]::new()
        foreach ($item in @(& $Command @commandArguments 2>&1)) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                if ($null -eq $CommandContext) {
                    throw $item
                }
                $CommandContext.WriteError($item)
            }
            else {
                $values.Add($item)
            }
        }
        return $values.ToArray()
    }

    hidden [object] EvaluateCore(
        [object]$DirectoryData,
        [array]$GpoData,
        [string]$Target,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        $ErrorActionPreference = if ($ErrorPreference -eq 'Stop') {
            'Stop'
        }
        else {
            'Continue'
        }
        if ($null -eq $DirectoryData) {
            throw 'DirectoryData is required.'
        }
        $configuration = $this.Settings.GetProfile()
        $checks = [Collections.ArrayList]::new()
        $directoryArguments = @{
            Data = $DirectoryData
            Profile = $configuration
        }
        $directoryChecks = $this.InvokeChecks(
            (Get-Command Test-ADAnalyzerDirectoryPolicy),
            $directoryArguments,
            $CommandContext,
            $ErrorPreference
        )
        foreach ($check in $directoryChecks) {
            $null = $checks.Add($check)
        }
        foreach ($check in @($DirectoryData.HostChecks | Where-Object { $null -ne $_ })) {
            $null = $checks.Add($check)
        }
        foreach ($gpo in $GpoData) {
            if ($gpo.Error) {
                $identity = if ($gpo.Gpo.Id) {
                    [string]$gpo.Gpo.Id
                }
                else {
                    $Target
                }
                $null = $checks.Add((New-ADAnalyzerCheck `
                            -RuleId 'GPO.READ' `
                            -Status Unreadable `
                            -Severity High `
                            -Category GroupPolicy `
                            -Target $identity `
                            -Message ([string]$gpo.Error)))
                continue
            }
            $versionStatus = 'Unknown'
            if ($null -ne $gpo.Policy.SysvolVersion -and $null -ne $gpo.Gpo.Version) {
                $versionStatus = if ([long]$gpo.Policy.SysvolVersion -eq ([long]$gpo.Gpo.Version -band [long]4294967295)) {
                    'Pass'
                }
                else {
                    'Fail'
                }
            }
            $null = $checks.Add((New-ADAnalyzerCheck `
                        -RuleId 'GPO.VERSION_CONSISTENCY' `
                        -Status $versionStatus `
                        -Severity Medium `
                        -Category PolicyCoverage `
                        -Target ([string]$gpo.Gpo.Id + '/Version') `
                        -Observed $gpo.Policy.SysvolVersion `
                        -Expected $gpo.Gpo.Version `
                        -Message 'Directory and SYSVOL versions should agree; missing versions or replication differences limit interpretation'))
            $policyArguments = @{
                Gpo = $gpo.Gpo
                Policy = $gpo.Policy
                Profile = $configuration
            }
            $policyChecks = $this.InvokeChecks(
                (Get-Command Test-ADAnalyzerGpoPolicy),
                $policyArguments,
                $CommandContext,
                $ErrorPreference
            )
            foreach ($check in $policyChecks) {
                $null = $checks.Add($check)
            }
            if ($configuration.Analysis.TemplatePath) {
                $metadataArguments = @{
                    RegistrySettings = @(Get-ADAnalyzerEffectiveRegistryRecords $gpo.Policy.RegistrySettings)
                    TemplatePath = $configuration.Analysis.TemplatePath
                    Language = $configuration.Analysis.Language
                }
                $metadata = $this.InvokeChecks(
                    (Get-Command Resolve-ADAnalyzerRegistryPolicy),
                    $metadataArguments,
                    $CommandContext,
                    $ErrorPreference
                )
                foreach ($record in $metadata) {
                    $label = Join-ADAnalyzerPolicyIdentity @([string]$gpo.Gpo.Id, $record.Hive, $record.Key, $record.ValueName)
                    $status = if ($record.MetadataStatus -eq 'Resolved') {
                        'Pass'
                    }
                    else {
                        'Unknown'
                    }
                    $null = $checks.Add((New-ADAnalyzerCheck `
                                -RuleId 'GPO.TEMPLATE_METADATA' `
                                -Status $status `
                                -Category Metadata `
                                -Target $label `
                                -Observed $record `
                                -Expected 'Matching ADMX/ADML metadata' `
                                -Message 'Metadata enrichment does not establish policy applicability'))
                }
            }
        }
        $evaluated = @($checks | Set-ADAnalyzerCheckException -Profile $configuration)
        # Duplicate identities would make snapshot comparisons ambiguous.
        $duplicates = @($evaluated | Group-Object CheckId | Where-Object Count -gt 1)
        if ($duplicates.Count) {
            throw ('Duplicate check identities: ' + (($duplicates | ForEach-Object Name) -join ', '))
        }
        $coverage = [ordered]@{}
        foreach ($status in @('Pass', 'Fail', 'Unknown', 'Unreadable', 'NotApplicable', 'NotConfigured', 'Invalid')) {
            $coverage[$status] = @($evaluated | Where-Object Status -eq $status).Count
        }
        $coverage['Suppressed'] = @($evaluated | Where-Object Suppressed).Count
        $coverage['Total'] = $evaluated.Count
        $objects = @(@($DirectoryData.Users) + @($DirectoryData.Computers) + @($DirectoryData.ServiceAccounts) | Where-Object { $null -ne $_ })
        $errors = @($DirectoryData.Errors | Where-Object { $null -ne $_ }) + @($GpoData | Where-Object Error | ForEach-Object { [pscustomobject]@{
                    Collection = 'GroupPolicy'
                    Target = [string]$_.Gpo.Id
                    Message = [string]$_.Error
                } })
        $state = if ($errors.Count -or $coverage.Unreadable -or $coverage.Unknown -or $coverage.Invalid) {
            'Partial'
        }
        else {
            'Complete'
        }
        if (-not $DirectoryData.Domain -and $Target -ne 'offline') {
            $state = 'Failed'
        }
        $result = [pscustomobject][ordered]@{
            SchemaVersion = 1
            RunId = [guid]::NewGuid().ToString()
            Timestamp = [datetime]::UtcNow.ToString('o')
            Target = $Target
            State = $state
            Profile = [pscustomobject]@{
                Name = $configuration.Name
                Version = $configuration.Version
                SchemaVersion = $configuration.SchemaVersion
            }
            Configuration = $configuration
            Objects = $objects
            Checks = $evaluated
            Findings = @($evaluated | Where-Object { $_.Status -notin 'Pass', 'NotApplicable' })
            Coverage = [pscustomobject]$coverage
            Errors = $errors
            Data = [pscustomobject]@{
                Directory = $DirectoryData
                Policies = @($GpoData | ForEach-Object { [pscustomobject]@{
                            Gpo = $_.Gpo
                            Files = $_.Policy.Files
                            UnparsedFiles = $_.Policy.UnparsedFiles
                            ReadError = $_.Error
                        } })
            }
        }
        # No credentials or secret-bearing native records escape the assessment boundary.
        return (ConvertTo-ADAnalyzerSafeData -InputObject $result)
    }
}

function Invoke-ADAnalyzerAssessment {
    <# Evaluate a collected snapshot without opening a directory connection. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$DirectoryData,
        [array]$GpoData = @(),
        $Profile,
        [string]$Target = 'offline'

    )
    $engine = [ADAnalyzerAssessmentEngine]::new($Profile)
    $preference = if ($PSBoundParameters.ContainsKey('ErrorAction')) {
        $PSBoundParameters.ErrorAction
    }
    else {
        $ErrorActionPreference
    }
    return $engine.EvaluateForCommand($DirectoryData, $GpoData, $Target, $PSCmdlet, $preference)
}

function Get-ADAnalyzerAssessment {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [string]$SearchBase,
        [string]$ProfilePath,
        $Profile,
        [switch]$IncludeAcl,
        [switch]$IncludeHostChecks,
        [switch]$SkipGpo

    )
    if ($ProfilePath -and $null -ne $Profile) {
        throw 'Specify ProfilePath or Profile, not both'
    }
    $configuration = if ($ProfilePath) {
        Import-ADAnalyzerProfile -Path $ProfilePath
    }
    else {
        Import-ADAnalyzerProfile -Profile $Profile
    }
    if (-not $Domain) {
        $Domain = $configuration.Targets.Domain
    }
    if (-not $Server) {
        $Server = $configuration.Targets.Server
    }
    if (-not $Domain) {
        $Domain = $env:USERDNSDOMAIN
    }
    if (-not $Server) {
        $Server = $Domain
    }
    if ($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Specify Domain or Server (or configure Targets)'
    }
    $connection = @{
        Server = $Server
        ErrorAction = 'Stop'
    }
    if ($Credential -and $Credential -ne [pscredential]::Empty) {
        $connection.Credential = $Credential
    }
    $root = Get-ADRootDSE @connection
    if ($root.DnsHostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Directory returned an invalid DC host name'
    }
    $connection.Server = [string]$root.DnsHostName
    if (-not $Domain) {
        $domainInfo = Get-ADDomain @connection
        $Domain = [string]$domainInfo.DNSRoot
    }
    if ($Domain -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Invalid domain DNS name'
    }
    if (-not $SearchBase) {
        $SearchBase = $configuration.Targets.SearchBase
    }
    $context = [pscustomobject]@{
        Server = $connection.Server
        Domain = $Domain
        Credential = $Credential
        SearchBase = $SearchBase
        IncludeAcl = ($IncludeAcl -or $configuration.Analysis.IncludeAcl)
        IncludeHostChecks = ($IncludeHostChecks -or $configuration.Analysis.IncludeHostChecks)
    }
    $directory = Get-ADAnalyzerDirectoryData -Context $context -Profile $configuration
    $resolvedDomain = if ($directory.Domain.DNSRoot -match '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        [string]$directory.Domain.DNSRoot
    }
    else {
        $Domain
    }
    if ($context.IncludeHostChecks) {
        $hostChecks = @(Test-ADAnalyzerHostPolicy -Hosts @($directory.Hosts) -Credential $Credential -Profile $configuration)
        $directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue $hostChecks -Force
    }
    $policies = [Collections.ArrayList]::new()
    if (-not $SkipGpo -and $configuration.Analysis.IncludeGpo) {
        try {
            $gpos = @(Get-ADAnalyzerGpo -All -Domain $resolvedDomain -Server $context.Server -Credential $Credential)
            foreach ($gpo in $gpos) {
                try {
                    $report = Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $Credential -AsObject
                    $null = $policies.Add([pscustomobject]@{
                            Gpo = $gpo
                            Policy = $report.Policy
                            Error = $null
                        })
                }
                catch {
                    $null = $policies.Add([pscustomobject]@{
                            Gpo = $gpo
                            Policy = $null
                            Error = $_.Exception.Message
                        })
                }
            }
        }
        catch {
            $null = $policies.Add([pscustomobject]@{
                    Gpo = [pscustomobject]@{
                        Id = $Domain
                    }
                    Policy = $null
                    Error = $_.Exception.Message
                })
        }
    }
    $result = Invoke-ADAnalyzerAssessment `
        -DirectoryData $directory `
        -GpoData $policies.ToArray() `
        -Profile $configuration `
        -Target $resolvedDomain
    $result | Add-Member -NotePropertyName Context -NotePropertyValue ([pscustomobject]@{
            Domain = $resolvedDomain
            RequestedDomain = $Domain
            Server = $context.Server
            SearchBase = $SearchBase
            IncludeAcl = $context.IncludeAcl
            IncludeHostChecks = $context.IncludeHostChecks
        })
    $result
}

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
