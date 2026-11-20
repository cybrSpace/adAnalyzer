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
        # A snapshot can omit HostChecks when host policy was not requested.
        if (Test-ADAnalyzerOptionalSecretRecordMember @{
                Record = $DirectoryData
            } 'HostChecks') {
            foreach ($check in @($DirectoryData.HostChecks | Where-Object { $null -ne $_ })) {
                $null = $checks.Add($check)
            }
        }
        $unreadablePolicyIndexes = [Collections.Generic.HashSet[int]]::new()
        $policyIndex = -1
        foreach ($gpo in $GpoData) {
            $policyIndex++
            if ($gpo.Error) {
                $null = $unreadablePolicyIndexes.Add($policyIndex)
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
        $reportIndex = -1
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
                Policies = @(
                    $GpoData | ForEach-Object {
                        $reportIndex++
                        $unreadable = $unreadablePolicyIndexes.Contains($reportIndex)
                        $gpoMetadata = $_.Gpo

                        # Each field uses its own native Policy observation.
                        $policy = $_.Policy
                        $files = $null
                        if ($null -ne $policy -or -not $unreadable) {
                            $files = $policy.Files
                        }
                        $policy = $_.Policy
                        $unparsedFiles = $null
                        if ($null -ne $policy -or -not $unreadable) {
                            $unparsedFiles = $policy.UnparsedFiles
                        }
                        [pscustomobject]@{
                            Gpo = $gpoMetadata
                            Files = $files
                            UnparsedFiles = $unparsedFiles
                            ReadError = $_.Error
                        }
                    }
                )
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

class ADAnalyzerAssessmentCollector {
    ADAnalyzerAssessmentCollector() {
    }

    [object] Collect([hashtable]$Options) {
        return $this.Collect($Options, [pscredential]::Empty)
    }

    [object] Collect([hashtable]$Options, [pscredential]$Credential) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Options) {
            $Options = @{}
        }
        foreach ($key in $Options.PSBase.Keys) {
            if ($key -notin @('Domain', 'Server', 'SearchBase', 'ProfilePath', 'Profile', 'IncludeAcl', 'IncludeHostChecks', 'SkipGpo')) {
                throw [ArgumentException]::new("Unsupported assessment option: $key", 'Options')
            }
        }

        $configuration = $this.ReadConfiguration([string]$Options['ProfilePath'], $Options['Profile'])
        $domain = [string]$Options['Domain']
        $server = [string]$Options['Server']
        $searchBase = [string]$Options['SearchBase']
        if (-not $domain) {
            $domain = [string]$configuration.Targets.Domain
        }
        if (-not $server) {
            $server = [string]$configuration.Targets.Server
        }
        $target = $this.ResolveEnvironmentTarget($domain, $server)
        $domain = $target.Domain
        $server = $target.Server
        if (-not $this.IsDirectoryHostName($server)) {
            throw 'Specify Domain or Server (or configure Targets)'
        }

        # Offline consumers load this file without the live collection components.
        $directoryCollectorType = 'ADAnalyzerDirectoryCollector' -as [type]
        $hostEvaluatorType = 'ADAnalyzerHostPolicyEvaluator' -as [type]
        if ($null -eq $directoryCollectorType -or $null -eq $hostEvaluatorType) {
            throw 'Dot source bin/ADAnalyzer.ps1 to use the assessment collector.'
        }

        $connection = $this.NewBootstrapArguments($server, $Credential)
        $providerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        $rootCommand = $this.GetBootstrapCommand($provider, 'Get-ADRootDSE')
        $root = & $rootCommand @connection
        if (-not $this.IsDirectoryHostName($root.DnsHostName)) {
            throw 'Directory returned an invalid DC host name'
        }
        $connection.Server = [string]$root.DnsHostName
        if (-not $domain) {
            $domainCommand = $this.GetBootstrapCommand($provider, 'Get-ADDomain')
            $domainInfo = & $domainCommand @connection
            $domain = [string]$domainInfo.DNSRoot
        }
        if (-not $this.IsDirectoryHostName($domain)) {
            throw 'Invalid domain DNS name'
        }
        if (-not $searchBase) {
            $searchBase = [string]$configuration.Targets.SearchBase
        }
        $context = $this.NewDirectoryContext(
            $connection.Server,
            $domain,
            $Credential,
            $searchBase,
            [bool]$Options['IncludeAcl'],
            [bool]$Options['IncludeHostChecks'],
            $configuration
        )
        $directoryCollector = $directoryCollectorType::new()
        $directory = $directoryCollector.Collect($context, $configuration)
        $resolvedDomain = $domain
        if ($directory.Domain.DNSRoot -match '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
            $resolvedDomain = [string]$directory.Domain.DNSRoot
        }
        if ($context.IncludeHostChecks) {
            $hostEvaluator = $hostEvaluatorType::new()
            $hostChecks = $hostEvaluator.Evaluate(@($directory.Hosts), $Credential, $configuration)
            $directory | Add-Member -NotePropertyName HostChecks -NotePropertyValue $hostChecks -Force
        }

        $policies = [Collections.ArrayList]::new()
        if ($this.ShouldCollectGpo([bool]$Options['SkipGpo'], $configuration)) {
            $catalog = [ADAnalyzerGpoCatalog]::new()
            $reportService = [ADAnalyzerGpoReportService]::new()
            try {
                $gpos = $catalog.GetAll($resolvedDomain, $context.Server, $Credential)
                foreach ($gpo in $gpos) {
                    try {
                        $report = $reportService.Read($gpo, $Credential)
                        $null = $policies.Add($this.NewPolicyOutcome($gpo, $report.Policy, $null))
                    }
                    catch {
                        $null = $policies.Add($this.NewPolicyOutcome($gpo, $null, $_.Exception.Message))
                    }
                }
            }
            catch {
                $null = $policies.Add($this.NewCatalogFailure($domain, $_.Exception.Message))
            }
        }

        $engine = [ADAnalyzerAssessmentEngine]::new($configuration)
        $result = $engine.Evaluate($directory, $policies.ToArray(), $resolvedDomain)
        $resultContext = $this.NewResultContext($resolvedDomain, $domain, $searchBase, $context)
        $result | Add-Member -NotePropertyName Context -NotePropertyValue $resultContext
        return $result
    }

    hidden [hashtable] ReadConfiguration([string]$ProfilePath, [object]$Profile) {
        if ($ProfilePath -and $null -ne $Profile) {
            throw 'Specify ProfilePath or Profile, not both'
        }
        if ($ProfilePath) {
            $definition = [ADAnalyzerProfileDefinition]::new()
            return $definition.ReadProfile($ProfilePath).ToHashtable()
        }
        return [ADAnalyzerProfile]::new($Profile).ToHashtable()
    }

    hidden [hashtable] ResolveEnvironmentTarget([string]$Domain, [string]$Server) {
        if (-not $Domain) {
            $Domain = $env:USERDNSDOMAIN
        }
        if (-not $Server) {
            $Server = $Domain
        }
        return @{
            Domain = $Domain
            Server = $Server
        }
    }

    hidden [bool] IsDirectoryHostName([object]$Value) {
        return -not ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$')
    }

    hidden [hashtable] NewBootstrapArguments([string]$Server, [pscredential]$Credential) {
        $arguments = @{
            Server = $Server
            ErrorAction = 'Stop'
        }
        if ($Credential -and $Credential -ne [pscredential]::Empty) {
            $arguments.Credential = $Credential
        }
        return $arguments
    }

    hidden [Management.Automation.CommandInfo] GetBootstrapCommand([object]$Provider, [string]$Name) {
        if ($null -ne $Provider -and $Provider.ExportedCmdlets) {
            $command = $Provider.ExportedCmdlets[$Name]
            if ($command -is [Management.Automation.CommandInfo]) {
                return $command
            }
        }
        throw "The bundled Active Directory provider did not export $Name"
    }

    hidden [pscustomobject] NewDirectoryContext(
        [string]$Server,
        [string]$Domain,
        [pscredential]$Credential,
        [string]$SearchBase,
        [bool]$IncludeAcl,
        [bool]$IncludeHostChecks,
        [hashtable]$Configuration
    ) {
        return [pscustomobject]@{
            Server = $Server
            Domain = $Domain
            Credential = $Credential
            SearchBase = $SearchBase
            IncludeAcl = ($IncludeAcl -or $Configuration.Analysis.IncludeAcl)
            IncludeHostChecks = ($IncludeHostChecks -or $Configuration.Analysis.IncludeHostChecks)
        }
    }

    hidden [bool] ShouldCollectGpo([bool]$SkipGpo, [hashtable]$Configuration) {
        return (-not $SkipGpo -and $Configuration.Analysis.IncludeGpo)
    }

    hidden [pscustomobject] NewPolicyOutcome([object]$Gpo, [object]$Policy, [object]$ErrorMessage) {
        return [pscustomobject]@{
            Gpo = $Gpo
            Policy = $Policy
            Error = $ErrorMessage
        }
    }

    hidden [pscustomobject] NewCatalogFailure([string]$RequestedDomain, [string]$ErrorMessage) {
        $marker = [pscustomobject]@{
            Id = $RequestedDomain
        }
        return $this.NewPolicyOutcome($marker, $null, $ErrorMessage)
    }

    hidden [pscustomobject] NewResultContext(
        [string]$ResolvedDomain,
        [string]$RequestedDomain,
        [string]$SearchBase,
        [object]$Context
    ) {
        return [pscustomobject]@{
            Domain = $ResolvedDomain
            RequestedDomain = $RequestedDomain
            Server = $Context.Server
            SearchBase = $SearchBase
            IncludeAcl = $Context.IncludeAcl
            IncludeHostChecks = $Context.IncludeHostChecks
        }
    }
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
    $collector = [ADAnalyzerAssessmentCollector]::new()
    if (-not $Domain) {
        $Domain = $configuration.Targets.Domain
    }
    if (-not $Server) {
        $Server = $configuration.Targets.Server
    }
    $target = $collector.ResolveEnvironmentTarget($Domain, $Server)
    $Domain = $target.Domain
    $Server = $target.Server
    if (-not $collector.IsDirectoryHostName($Server)) {
        throw 'Specify Domain or Server (or configure Targets)'
    }
    $connection = $collector.NewBootstrapArguments($Server, $Credential)

    # Keep native provider reads, property casts, and terminal errors in command scope.
    $root = Get-ADRootDSE @connection
    if ($root.DnsHostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Directory returned an invalid DC host name'
    }
    $connection.Server = [string]$root.DnsHostName
    if (-not $Domain) {
        $domainInfo = Get-ADDomain @connection
        $Domain = [string]$domainInfo.DNSRoot
    }
    if (-not $collector.IsDirectoryHostName($Domain)) {
        throw 'Invalid domain DNS name'
    }
    if (-not $SearchBase) {
        $SearchBase = $configuration.Targets.SearchBase
    }
    $context = $collector.NewDirectoryContext(
        $connection.Server,
        $Domain,
        $Credential,
        $SearchBase,
        [bool]$IncludeAcl,
        [bool]$IncludeHostChecks,
        $configuration
    )
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
    if ($collector.ShouldCollectGpo([bool]$SkipGpo, $configuration)) {
        try {
            $gpos = @(Get-ADAnalyzerGpo -All -Domain $resolvedDomain -Server $context.Server -Credential $Credential)
            foreach ($gpo in $gpos) {
                try {
                    $report = Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $Credential -AsObject
                    $policy = $report.Policy
                    $null = $policies.Add($collector.NewPolicyOutcome($gpo, $policy, $null))
                }
                catch {
                    $null = $policies.Add($collector.NewPolicyOutcome($gpo, $null, $_.Exception.Message))
                }
            }
        }
        catch {
            $null = $policies.Add($collector.NewCatalogFailure($Domain, $_.Exception.Message))
        }
    }
    $result = Invoke-ADAnalyzerAssessment `
        -DirectoryData $directory `
        -GpoData $policies.ToArray() `
        -Profile $configuration `
        -Target $resolvedDomain
    $resultContext = $collector.NewResultContext($resolvedDomain, $Domain, $SearchBase, $context)
    $result | Add-Member -NotePropertyName Context -NotePropertyValue $resultContext
    $result
}

class ADAnalyzerBaselineImporter {
    ADAnalyzerBaselineImporter() {
    }

    [hashtable] Import([string[]]$GpoPath, [string]$Version) {
        return $this.Import($GpoPath, 'Imported GPO baseline', $Version)
    }

    [hashtable] Import([string[]]$GpoPath, [string]$Name, [string]$Version) {
        if ($null -eq $GpoPath -or $GpoPath.Count -eq 0) {
            throw [ArgumentException]::new('At least one baseline backup path is required.', 'GpoPath')
        }
        if ([string]::IsNullOrEmpty($Version)) {
            throw [ArgumentException]::new('A baseline version is required.', 'Version')
        }

        $importer = $this
        $state = $this.BeginImport([ADAnalyzerProfile]::DefaultSnapshot(), $Name, $Version)
        $reader = [ADAnalyzerGpoReader]::new()
        $replay = [ADAnalyzerRegistryPolicyReplay]::new()
        foreach ($path in $GpoPath) {
            if ([string]::IsNullOrEmpty($path)) {
                throw [ArgumentException]::new('A baseline backup path cannot be empty.', 'GpoPath')
            }
            $policy = $reader.Read($path)
            if (-not $policy.Files.Count) {
                throw "No policy files in baseline: $path"
            }
            foreach ($row in $replay.Replay($policy.RegistrySettings)) {
                if ($row.Deleted -or $row.DeletionDirective -or $row.KeyOnly -or (Test-ADAnalyzerSecretName $row.ValueName)) {
                    continue
                }
                $identity = $importer.RegistryIdentity(@($row.Hive, $row.Key, $row.ValueName))
                $value = ConvertTo-Json -InputObject ([ordered]@{
                        Type = [int]$row.Type
                        Value = $row.Value
                    }) -Compress -Depth 20
                $decision = $importer.RegisterIdentity($state, $identity.Identity, $value)
                if ($decision -ne 'New') {
                    if ($decision -eq 'Conflict') {
                        throw "Conflicting baseline registry setting: $($identity.Key)"
                    }
                    continue
                }
                $id = $importer.RuleId('BASELINE.REGISTRY', $identity.HashTarget)
                $importer.AddRegistryRule($state, $id, @{
                    Hive = $row.Hive
                    Key = $row.Key
                    ValueName = $row.ValueName
                    Type = [int]$row.Type
                    Value = $row.Value
                }, $path)
            }

            $securityGroups = @(
                $policy.SecuritySettings | Where-Object {
                    $importer.IsSecurityKind($_.Kind) -and -not (Test-ADAnalyzerSecretName $_.Name)
                } | Group-Object -Property ($importer.SecurityGroupingFields())
            )
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
                $key = $importer.SecurityIdentity(@($row.Scope, $row.Kind, $row.Name))
                $value = ConvertTo-Json -InputObject $expected -Compress -Depth 20
                $decision = $importer.RegisterIdentity($state, $key, $value)
                if ($decision -ne 'New') {
                    if ($decision -eq 'Conflict') {
                        throw "Conflicting baseline security setting: $key"
                    }
                    continue
                }
                $id = $importer.RuleId('BASELINE.SECURITY', $key)
                $importer.AddSecurityRule($state, $id, @{
                    Kind = $row.Kind
                    Scope = $row.Scope
                    Name = $row.Name
                    Aggregate = $aggregate
                    Value = $expected
                }, $path)
            }
        }

        $profile = [ADAnalyzerProfile]::new($this.BuildProfile($state))
        return $profile.ToHashtable()
    }

    hidden [hashtable] BeginImport([hashtable]$Profile, [string]$Name, [string]$Version) {
        $Profile.Name = $Name
        $Profile.Version = $Version
        return @{
            Profile = $Profile
            Registry = [Collections.ArrayList]::new()
            Settings = [Collections.ArrayList]::new()
            Seen = @{}
        }
    }

    hidden [hashtable] RegistryIdentity([object[]]$Parts) {
        $key = ('{0}|{1}|{2}' -f $Parts).ToLowerInvariant()
        $identity = (Join-ADAnalyzerPolicyIdentity $Parts).ToLowerInvariant()
        $hashTarget = $key

        # Keep the established hash seed when the components contain no literal pipe.
        if ($key.Split('|').Count -gt 3) {
            $hashTarget = $identity
        }
        return @{
            Key = $key
            Identity = $identity
            HashTarget = $hashTarget
        }
    }

    hidden [string] SecurityIdentity([object[]]$Parts) {
        return ('{0}|{1}|{2}' -f $Parts).ToLowerInvariant()
    }

    hidden [string] RegisterIdentity([hashtable]$State, [string]$Identity, [object]$Value) {
        if ($State.Seen.ContainsKey($Identity)) {
            if ($State.Seen[$Identity] -ne $Value) {
                return 'Conflict'
            }
            return 'Duplicate'
        }
        $State.Seen[$Identity] = $Value
        return 'New'
    }

    hidden [string] RuleId([string]$Category, [string]$Target) {
        $check = [ADAnalyzerCheckFactory]::new().Create($Category, 'Pass', $Target)
        return $Category + '.' + $check.CheckId.Substring(0, 16)
    }

    hidden [void] AddRegistryRule(
        [hashtable]$State,
        [string]$Id,
        [hashtable]$Fields,
        [string]$Path
    ) {
        $null = $State.Registry.Add(@{
                Id = $Id
                Hive = $Fields.Hive
                Key = $Fields.Key
                ValueName = $Fields.ValueName
                Type = $Fields.Type
                Operator = 'Equals'
                Expected = $Fields.Value
                Severity = 'Medium'
                Source = $Path
            })
    }

    hidden [void] AddSecurityRule(
        [hashtable]$State,
        [string]$Id,
        [hashtable]$Fields,
        [string]$Path
    ) {
        $null = $State.Settings.Add(@{
                Id = $Id
                Kind = $Fields.Kind
                Scope = $Fields.Scope
                Name = $Fields.Name
                Aggregate = $Fields.Aggregate
                Operator = 'Equals'
                Expected = $Fields.Value
                Severity = 'Medium'
                Source = $Path
            })
    }

    hidden [bool] IsSecurityKind([object]$Kind) {
        return $Kind -in 'Account', 'SecurityOptions'
    }

    hidden [string[]] SecurityGroupingFields() {
        return @('Scope', 'Kind', 'Name')
    }

    hidden [hashtable] BuildProfile([hashtable]$State) {
        $State.Profile.RegistryRules = $State.Registry.ToArray()
        $State.Profile.ExpectedGpoSettings = $State.Settings.ToArray()
        return $State.Profile
    }
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
    $importer = [ADAnalyzerBaselineImporter]::new()
    $state = $importer.BeginImport($profile, $Name, $Version)

    # Keep native reads, conversions, and throws at their original command scope.
    foreach ($path in $GpoPath) {
        $policy = Read-ADAnalyzerGpo -Path $path
        if (-not $policy.Files.Count) {
            throw "No policy files in baseline: $path"
        }
        foreach ($row in @(Get-ADAnalyzerEffectiveRegistryRecords -RegistrySettings $policy.RegistrySettings)) {
            if ($row.Deleted -or $row.DeletionDirective -or $row.KeyOnly -or (Test-ADAnalyzerSecretName $row.ValueName)) {
                continue
            }
            $identity = $importer.RegistryIdentity(@($row.Hive, $row.Key, $row.ValueName))
            $value = ConvertTo-Json -InputObject ([ordered]@{
                    Type = [int]$row.Type
                    Value = $row.Value
                }) -Compress -Depth 20
            $decision = $importer.RegisterIdentity($state, $identity.Identity, $value)
            if ($decision -ne 'New') {
                if ($decision -eq 'Conflict') {
                    throw "Conflicting baseline registry setting: $($identity.Key)"
                }
                continue
            }
            $id = $importer.RuleId('BASELINE.REGISTRY', $identity.HashTarget)
            $importer.AddRegistryRule($state, $id, @{
                Hive = $row.Hive
                Key = $row.Key
                ValueName = $row.ValueName
                Type = [int]$row.Type
                Value = $row.Value
            }, $path)
        }

        $securityGroups = @(
            $policy.SecuritySettings | Where-Object {
                $importer.IsSecurityKind($_.Kind) -and -not (Test-ADAnalyzerSecretName $_.Name)
            } | Group-Object -Property ($importer.SecurityGroupingFields())
        )
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
            $key = $importer.SecurityIdentity(@($row.Scope, $row.Kind, $row.Name))
            $value = ConvertTo-Json -InputObject $expected -Compress -Depth 20
            $decision = $importer.RegisterIdentity($state, $key, $value)
            if ($decision -ne 'New') {
                if ($decision -eq 'Conflict') {
                    throw "Conflicting baseline security setting: $key"
                }
                continue
            }
            $id = $importer.RuleId('BASELINE.SECURITY', $key)
            $importer.AddSecurityRule($state, $id, @{
                Kind = $row.Kind
                Scope = $row.Scope
                Name = $row.Name
                Aggregate = $aggregate
                Value = $expected
            }, $path)
        }
    }
    Import-ADAnalyzerProfile -Profile ($importer.BuildProfile($state))
}
