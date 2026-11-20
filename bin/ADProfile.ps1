# Shared configuration and result contracts. No external modules are required.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
. (Join-Path $PSScriptRoot 'ADFile.ps1')

# Configuration capsules expose no automatically serialized profile properties.
if (-not ('ADAnalyzer.ConfigurationState' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'ADConfiguration.cs') -ErrorAction Stop
}

function ConvertTo-ADAnalyzerHashtable {
    param([AllowNull()]$InputObject)
    if ($null -eq $InputObject) {
        return $null
    }
    # Pipeline commands can wrap scalars in PSObject. Test their actual scalar
    # and collection contracts before PSCustomObject to avoid turning strings
    # into a dictionary containing their Length property.
    if ($InputObject -is [string]) {
        return [string]$InputObject
    }
    if ($InputObject -is [ValueType]) {
        return $InputObject
    }
    if ($InputObject -is [Collections.IDictionary]) {
        $result = @{}
        foreach ($key in ([Collections.IDictionary].GetProperty('Keys')).GetValue($InputObject, $null)) {
            $result[[string]$key] = ConvertTo-ADAnalyzerHashtable $InputObject[$key]
        }
        return $result
    }
    if ($InputObject -is [array] -or $InputObject -is [Collections.IList]) {
        $items = @(foreach ($item in $InputObject) {
                ConvertTo-ADAnalyzerHashtable $item
            })
        return , $items
    }
    if ($InputObject -is [pscustomobject]) {
        $result = @{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-ADAnalyzerHashtable $property.Value
        }
        return $result
    }
    return $InputObject
}

# Profile initialization uses instance methods so a secondary Windows
# PowerShell runspace cannot rebind its default and merge operations.
class ADAnalyzerProfileDefinition {
    ADAnalyzerProfileDefinition() {
    }

    [hashtable] CreateSnapshot() {
        # Return a fresh graph on every call; a scan must not change another scan's rules.
        return @{
            SchemaVersion = 1
            Name = 'AD Tactical Hardening'
            Version = '1.0.0'
            Targets = @{
                Domain = ''
                Server = ''
                SearchBase = ''
            }
            Analysis = @{
                IncludeAcl = $false
                IncludeHostChecks = $false
                IncludeGpo = $true
                AssumeGpoApplicable = $false
                HostTimeoutSeconds = 30
                TemplatePath = ''
                Language = 'en-US'
                DirectoryConnection = 'PSDrive'
            }
            Policy = @{
                MinimumPasswordLength = 12
                MinimumPasswordAgeDays = 1
                MaximumPasswordAgeDays = 90
                UserPasswordAgeDays = 90
                ServicePasswordAgeDays = 365
                AllowPasswordNeverExpires = $false
                PasswordHistorySize = 10
                PasswordComplexity = $true
                AllowReversibleEncryption = $false
                LockoutThreshold = 6
                LockoutDurationMinutes = 30
                ResetLockoutMinutes = 30
                UserInactivityDays = 60
                ComputerInactivityDays = 60
                MachineAccountQuota = 0
                MinimumLmCompatibilityLevel = 5
                RequireLdapClientSigning = $true
                RequireLdapServerSigning = $true
                AllowedAnonymousPipes = @('LSARPC', 'NETLOGON', 'SAMR')
                ApprovedLocalAdminSids = @('S-1-5-32-544')
                AllowedUserRightSids = @{}
                PrivilegedSids = @()
                ApprovedDelegationTargets = @()
                ApprovedReplicationSids = @()
                IncludeAdministrativeReplicationRoles = $true
                ApprovedLapsReaderSids = @()
                ApprovedGmsaReaderSids = @()
                SupportedOperatingSystems = @()
                RequireLaps = $true
                RequireGmsaForServiceAccounts = $false
            }
            AccountClassification = @{
                UserOUs = @()
                ServiceOUs = @()
                UserGroups = @()
                ServiceGroups = @()
                AttributeRules = @()
            }
            Host = @{
                Services = @()
                RegistryRules = @()
                AuditRules = @()
                CertificateEndpoints = @()
            }
            Remediation = @{
                AllowDisable = $false
                ApprovedObjectGuids = @()
                ExcludedObjectGuids = @()
                ExcludedOUs = @()
                IncludeServiceAccounts = $false
                IncludePrivilegedAccounts = $false
                MaximumActions = 10
            }
            RegistryRules = @()
            ExpectedGpoSettings = @()
            ApprovedDelegationTargets = @()
            ApprovedReplicationSids = @()
            Exceptions = @()
            DependencyHashes = @{}
        }
    }

    [void] MergeInto(
        [hashtable]$Defaults,
        [hashtable]$Overrides,
        [string]$Prefix
    ) {
        foreach ($key in ([Collections.IDictionary].GetProperty('Keys')).GetValue($Overrides, $null)) {
            if (-not $Defaults.ContainsKey($key)) {
                throw "Unknown profile setting: $Prefix$key"
            }
            if ($Defaults[$key] -is [hashtable]) {
                if ($Overrides[$key] -isnot [hashtable]) {
                    throw "Profile setting $Prefix$key must be a dictionary"
                }
                if ($key -in 'AllowedUserRightSids', 'DependencyHashes') {
                    $Defaults[$key] = $Overrides[$key]
                }
                else {
                    $this.MergeInto($Defaults[$key], $Overrides[$key], ($Prefix + $key + '.'))
                }
            }
            else {
                $Defaults[$key] = $Overrides[$key]
            }
        }
    }

    [ADAnalyzerProfile] ReadProfile([string]$Path) {
        $loaded = $null
        switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
            '.psd1' {
                $loaded = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
            }
            '.json' {
                $readParameters = Get-ADAnalyzerJsonReadParameters $Path
                $PSDefaultParameterValues = Get-ADAnalyzerJsonReadDefaults
                $loaded = Get-Content @readParameters |
                    ConvertTo-ADAnalyzerJsonText |
                    ConvertFrom-Json -ErrorAction Stop
            }
            default {
                throw 'Profiles must be .json or restricted .psd1 data files'
            }
        }
        if ($null -eq $loaded) {
            return [ADAnalyzerProfile]::new()
        }
        return [ADAnalyzerProfile]::new($loaded)
    }
}

class ADAnalyzerProfile {
    hidden [object]$Settings

    ADAnalyzerProfile() {
        $this.Initialize($null)
    }

    ADAnalyzerProfile([object]$Profile) {
        $this.Initialize($Profile)
    }

    hidden [void] Initialize([object]$Profile) {
        $definition = [ADAnalyzerProfileDefinition]::new()
        $result = $definition.CreateSnapshot()
        if ($null -ne $Profile) {
            $overrides = ConvertTo-ADAnalyzerHashtable $Profile
            if ($overrides -isnot [hashtable]) {
                throw 'Profile must be a dictionary'
            }
            $definition.MergeInto($result, $overrides, '')
        }

        $this.ValidateCommon($result)
        $this.ValidateRules($result)
        $this.ValidateHostRules($result)
        $this.Settings = [Activator]::CreateInstance(
            ('ADAnalyzer.ConfigurationState' -as [type]),
            [object[]]@($result)
        )
    }

    [hashtable] ToHashtable() {
        return (ConvertTo-ADAnalyzerHashtable $this.Settings.GetProfile())
    }

    static [hashtable] DefaultSnapshot() {
        $definition = [ADAnalyzerProfileDefinition]::new()
        return $definition.CreateSnapshot()
    }

    hidden static [void] MergeInto(
        [hashtable]$Defaults,
        [hashtable]$Overrides,
        [string]$Prefix
    ) {
        $definition = [ADAnalyzerProfileDefinition]::new()
        $definition.MergeInto($Defaults, $Overrides, $Prefix)
    }

    static [ADAnalyzerProfile] Load([string]$Path) {
        $definition = [ADAnalyzerProfileDefinition]::new()
        return $definition.ReadProfile($Path)
    }

    hidden [void] ValidateCommon([hashtable]$result) {
        Assert-ADAnalyzerValueBaseline -Profile $result
        if (($result.SchemaVersion -isnot [int] -and $result.SchemaVersion -isnot [long]) -or $result.SchemaVersion -ne 1) {
            throw 'Unsupported profile SchemaVersion'
        }
        if ([string]::IsNullOrWhiteSpace($result.Name) -or [string]::IsNullOrWhiteSpace($result.Version)) {
            throw 'Profile Name and Version are required'
        }
        foreach ($name in @('MinimumPasswordLength',
                'MinimumPasswordAgeDays',
                'MaximumPasswordAgeDays',
                'UserPasswordAgeDays',
                'ServicePasswordAgeDays',
                'PasswordHistorySize',
                'LockoutThreshold',
                'LockoutDurationMinutes',
                'ResetLockoutMinutes',
                'UserInactivityDays',
                'ComputerInactivityDays',
                'MachineAccountQuota',
                'MinimumLmCompatibilityLevel')) {
            $number = 0L
            if (-not [long]::TryParse([string]$result.Policy[$name], [ref]$number) -or $number -lt 0) {
                throw "Policy.$name must be a nonnegative integer"
            }
            $result.Policy[$name] = $number
        }
        $definition = [ADAnalyzerProfileDefinition]::new()
        foreach ($section in @('Analysis', 'Policy', 'Remediation')) {
            $default = $definition.CreateSnapshot()
            foreach ($key in $default[$section].Keys) {
                if ($default[$section][$key] -is [bool] -and $result[$section][$key] -isnot [bool]) {
                    throw "$section.$key must be a boolean"
                }
            }
        }
        if ($result.Policy.LockoutThreshold -gt 65535 -or $result.Policy.MinimumLmCompatibilityLevel -gt 5) {
            throw 'Invalid lockout/LM policy range'
        }
        if ($result.Policy.LockoutThreshold -gt 0 -and $result.Policy.LockoutDurationMinutes -lt $result.Policy.ResetLockoutMinutes) {
            throw 'Lockout duration must be at least the reset interval'
        }
        $timeout = 0
        if (-not [int]::TryParse([string]$result.Analysis.HostTimeoutSeconds, [ref]$timeout) -or $timeout -lt 1 -or $timeout -gt 300) {
            throw 'Analysis.HostTimeoutSeconds must be an integer 1..300'
        }
        $result.Analysis.HostTimeoutSeconds = $timeout
        if ($result.Analysis.DirectoryConnection -isnot [string] -or $result.Analysis.DirectoryConnection -notin 'PSDrive', 'Direct') {
            throw 'Analysis.DirectoryConnection must be PSDrive or Direct'
        }
        $result.Analysis.DirectoryConnection = if ($result.Analysis.DirectoryConnection -ieq 'PSDrive') {
            'PSDrive'
        }
        else {
            'Direct'
        }
        if ($result.Remediation.MaximumActions -isnot [int] -and $result.Remediation.MaximumActions -isnot [long]) {
            throw 'Remediation.MaximumActions must be an integer'
        }
        if ($result.Remediation.MaximumActions -lt 1 -or $result.Remediation.MaximumActions -gt 1000) {
            throw 'Remediation.MaximumActions must be 1..1000'
        }
    }

    hidden [void] ValidateRules([hashtable]$result) {
        foreach ($exception in @($result.Exceptions)) {
            foreach ($key in @('RuleId', 'Target', 'Owner', 'Reason', 'Expires')) {
                if (-not $exception.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$exception[$key])) {
                    throw "Exception requires $key"
                }
            }
            $date = [datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse([string]$exception.Expires, [ref]$date)) {
                throw 'Exception Expires must be an ISO date/time'
            }
            $exception.Expires = $date.ToUniversalTime().ToString('o')
        }
        foreach ($rule in @($result.RegistryRules) + @($result.ExpectedGpoSettings)) {
            if ($rule -isnot [Collections.IDictionary]) {
                throw 'Custom rules must be dictionaries'
            }
            if ($rule.Contains('Operator') -and $rule.Operator -notin @('Equals', 'NotEquals', 'In', 'NotIn', 'Minimum', 'Maximum')) {
                throw 'Unsupported custom-rule operator'
            }
            if ($rule.Contains('Severity') -and $rule.Severity -notin @('Critical', 'High', 'Medium', 'Low', 'Information')) {
                throw 'Unsupported custom-rule severity'
            }
            if ($rule.Contains('Scope') -and $rule.Scope -notin @('Computer', 'User')) {
                throw 'Custom-rule Scope must be Computer or User'
            }
            if ($rule.Contains('Aggregate') -and $rule.Aggregate -isnot [bool]) {
                throw 'Custom-rule Aggregate must be a boolean'
            }
        }
        foreach ($rule in $result.AccountClassification.AttributeRules) {
            if (-not $rule.Attribute -or
                $rule.Type -notin @('User',
                    'Service') -or
                ($rule.Match -and
                $rule.Match -notin @('Equals',
                    'Regex'))) {
                throw 'Invalid account classification attribute rule'
            }
        }
        foreach ($value in @($result.Remediation.ApprovedObjectGuids) + @($result.Remediation.ExcludedObjectGuids)) {
            $id = [guid]::Empty
            if (-not [guid]::TryParse([string]$value, [ref]$id)) {
                throw 'Remediation object identities must be GUIDs'
            }
        }
    }

    hidden [void] ValidateHostRules([hashtable]$result) {
        $hostServiceIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($rule in @($result.Host.Services)) {
            if ($rule -isnot [Collections.IDictionary] -or
                $rule.Name -isnot [string] -or
                [string]::IsNullOrWhiteSpace($rule.Name) -or
                $rule.State -isnot [string] -or
                [string]::IsNullOrWhiteSpace($rule.State)) {
                throw 'Host service rules require nonempty string Name and State'
            }
            if ($rule.Name.IndexOf([char]0) -ge 0) {
                throw 'Host service Name cannot contain NUL characters'
            }
            if ($rule.Contains('StartMode') -and $null -ne $rule.StartMode -and $rule.StartMode -isnot [string]) {
                throw 'Host service StartMode must be a string or null'
            }
            if (-not $hostServiceIds.Add((Get-ADAnalyzerHostRuleIdentity -Rule $rule -Target $rule.Name -Parts @($rule.Name)))) {
                throw 'Duplicate host service rule identity; use distinct Id values for separate expectations'
            }
        }
        $hostRegistryIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($rule in @($result.Host.RegistryRules)) {
            if ($rule -isnot [Collections.IDictionary] -or
                $rule.Key -isnot [string] -or
                [string]::IsNullOrWhiteSpace($rule.Key) -or
                $rule.ValueName -isnot [string]) {
                throw 'Host registry rules require a nonempty string Key and a string ValueName'
            }
            if ($rule.Key.IndexOf([char]0) -ge 0 -or $rule.ValueName.IndexOf([char]0) -ge 0) {
                throw 'Host registry identities cannot contain NUL characters'
            }
            if ($rule.Contains('Type')) {
                $registryType = 0
                if (-not [int]::TryParse([string]$rule.Type, [ref]$registryType) -or $registryType -notin 1, 2, 3, 4, 7, 11) {
                    throw 'Host registry Type must be 1, 2, 3, 4, 7, or 11'
                }
                $rule.Type = $registryType
            }
            if ($rule.Contains('Operator') -and $rule.Operator -notin @('Equals', 'NotEquals', 'In', 'NotIn', 'Minimum', 'Maximum')) {
                throw 'Unsupported host registry operator'
            }
            if (-not $hostRegistryIds.Add((Get-ADAnalyzerHostRuleIdentity `
                            -Rule $rule `
                            -Target ($rule.Key + '/' + $rule.ValueName) `
                            -Parts @($rule.Key,
                            $rule.ValueName)))) {
                throw 'Duplicate host registry rule identity; use distinct Id values for separate expectations'
            }
        }
        $hostAuditIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($rule in @($result.Host.AuditRules)) {
            $id = [guid]::Empty
            if (-not [guid]::TryParse([string]$rule.SubcategoryGuid, [ref]$id) -or [int]$rule.Flags -notin 1, 2, 3) {
                throw 'Host audit rules require SubcategoryGuid and Flags 1, 2, or 3'
            }
            if (-not $hostAuditIds.Add($id.ToString('D'))) {
                throw 'Duplicate host audit subcategory identity; combine required flags in one rule'
            }
        }
        foreach ($hash in ([Collections.IDictionary].GetProperty('Values')).GetValue($result.DependencyHashes, $null)) {
            if ([string]$hash -notmatch '^[a-fA-F0-9]{64}$') {
                throw 'DependencyHashes values must be SHA256 hex strings'
            }
        }
        $hostCertificateIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($endpoint in @($result.Host.CertificateEndpoints)) {
            if ($endpoint.HostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
                throw 'Certificate endpoint HostName must be a DNS/NetBIOS name or IPv4 address'
            }
            if ($endpoint.Contains('Port') -and ([int]$endpoint.Port -lt 1 -or [int]$endpoint.Port -gt 65535)) {
                throw 'Certificate endpoint Port must be 1..65535'
            }
            if ($endpoint.Contains('MinimumRemainingDays') -and [int]$endpoint.MinimumRemainingDays -lt 0) {
                throw 'Certificate minimum remaining days must be nonnegative'
            }
            $hostName = [string]$endpoint.HostName
            $port = if ($endpoint['Port']) {
                [int]$endpoint['Port']
            }
            else {
                443
            }
            $serverName = if ($endpoint['ServerName']) {
                [string]$endpoint['ServerName']
            }
            else {
                $hostName
            }
            if (-not $hostCertificateIds.Add(('{0}:{1}/{2}' -f $hostName, $port, $serverName))) {
                throw 'Duplicate host certificate endpoint identity; use one rule per host, port, and server name'
            }
        }
    }
}

function Get-ADAnalyzerDefaultProfile {
    [CmdletBinding()]
    param()

    [ADAnalyzerProfile]::DefaultSnapshot()
}

function Get-ADAnalyzerLegacyProfile {
    if ($null -ne $script:ADAnalyzerLegacyProfile) {
        return $script:ADAnalyzerLegacyProfile
    }
    Get-ADAnalyzerDefaultProfile
}

function Get-ADAnalyzerLmLevel {
    param([string]$Value)
    $levels = @('Send LM & NTLM responses',
        'Send LM & NTLM - use NTLMv2 session security if negotiated',
        'Send NTLM response only',
        'Send NTLMv2 response only',
        'Send NTLMv2 response only. Refuse LM',
        'Send NTLMv2 response only. Refuse LM & NTLM')
    if ($Value -ieq 'Send NTLMv2 responses only. Refuse LM & NTLM') {
        return 5
    }
    for ($i = 0; $i -lt $levels.Count; $i++) {
        if ($Value -ieq $levels[$i]) {
            return $i
        }
    }
    return -1
}

function Get-ADAnalyzerSidValue {
    param($Value)
    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [string]) {
        return $Value
    }
    if ($Value.Value) {
        return [string]$Value.Value
    }
    return [string]$Value
}

function Get-ADAnalyzerPrivilegedSids {
    param(
        [string]$DomainSid,
        [string]$RootDomainSid,
        [hashtable]$Profile

    )
    if (-not $RootDomainSid) {
        $RootDomainSid = $DomainSid
    }
    $sids = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551')
    if ($DomainSid) {
        $sids += @("$DomainSid-512", "$DomainSid-516", "$DomainSid-521", "$DomainSid-526")
    }
    if ($RootDomainSid) {
        $sids += @("$RootDomainSid-518", "$RootDomainSid-519", "$RootDomainSid-527")
    }
    if ($Profile) {
        $sids += @($Profile.Policy.PrivilegedSids)
    }
    $sids | Sort-Object -Unique
}

function Merge-ADAnalyzerProfile {
    param(
        [hashtable]$Defaults,
        [hashtable]$Overrides,
        [string]$Prefix = ''

    )
    [ADAnalyzerProfile]::MergeInto($Defaults, $Overrides, $Prefix)
}

function Get-ADAnalyzerHostRuleIdentity {
    param(
        [Collections.IDictionary]$Rule,
        [string]$Target,
        [string[]]$Parts = @()

    )
    if (-not ([Collections.IDictionary]$Rule).Contains('Id')) {
        return $Target
    }
    if ($Rule.Id -isnot [string] -or [string]::IsNullOrWhiteSpace($Rule.Id) -or $Rule.Id.IndexOf([char]0) -ge 0) {
        throw 'Host rule Id must be a nonempty string without NUL characters'
    }
    # Length prefixes keep literal path separators and rule IDs unambiguous.
    $encoded = [Text.StringBuilder]::new()
    foreach ($part in @($Target) + @($Parts) + @($Rule.Id)) {
        $null = $encoded.Append($part.Length.ToString([Globalization.CultureInfo]::InvariantCulture)).Append(':').Append($part)
    }
    'HostRuleId' + [char]0 + $encoded.ToString()
}

function Import-ADAnalyzerProfile {
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$Path,
        [Parameter(ParameterSetName = 'Object')][AllowNull()]$Profile

    )
    $configuration = if ($PSCmdlet.ParameterSetName -eq 'Path') {
        [ADAnalyzerProfile]::Load($Path)
    }
    else {
        [ADAnalyzerProfile]::new($Profile)
    }
    $configuration.ToHashtable()
}

class ADAnalyzerCheckFactory {
    ADAnalyzerCheckFactory() {
    }

    [pscustomobject] Create([string]$RuleId, [string]$Status, [string]$Target) {
        return $this.Create(@{
            RuleId = $RuleId
            Status = $Status
            Target = $Target
        })
    }

    [pscustomobject] Create([hashtable]$Specification) {
        if ($null -eq $Specification) {
            throw [ArgumentNullException]::new('Specification')
        }

        $fields = @{
            RuleId = $this.GetString($Specification, 'RuleId', '')
            Status = $this.GetString($Specification, 'Status', '')
            Target = $this.GetString($Specification, 'Target', '')
            Severity = $this.GetString($Specification, 'Severity', 'Information')
            Category = $this.GetString($Specification, 'Category', 'General')
            Observed = $Specification['Observed']
            Expected = $Specification['Expected']
            Evidence = $Specification['Evidence']
            Message = $this.GetString($Specification, 'Message', '')
            Applicability = $this.GetString($Specification, 'Applicability', 'Unknown')
        }
        $this.Validate($fields)
        $id = $this.CreateId($fields.RuleId, $fields.Target)

        $object = $Specification['Object']
        $metadata = @{
            ObjectGuid = $null
            SID = $null
            DistinguishedName = $null
        }
        # Each getter can change whether the object is still truthy.
        if ($object) {
            $metadata.ObjectGuid = [string]$object.ObjectGuid
        }
        if ($object) {
            $metadata.SID = [string]$object.SID
        }
        if ($object) {
            $metadata.DistinguishedName = [string]$object.DistinguishedName
        }
        return $this.BuildCheck($id, $fields, $metadata)
    }

    hidden [string] GetString([hashtable]$Specification, [string]$Name, [string]$Default) {
        if (-not $Specification.ContainsKey($Name)) {
            return $Default
        }

        $value = $Specification[$Name]
        if ($value -is [array]) {
            throw [ArgumentException]::new("$Name expects a scalar string.", $Name)
        }
        return [string]$value
    }

    hidden [void] Validate([hashtable]$Fields) {
        foreach ($name in @('RuleId', 'Target')) {
            if ([string]::IsNullOrEmpty($Fields[$name])) {
                throw [ArgumentException]::new("$name is required.", $name)
            }
        }
        if ($Fields.Status -notin @('Pass', 'Fail', 'Unknown', 'Unreadable', 'NotApplicable', 'NotConfigured', 'Invalid')) {
            throw [ArgumentException]::new('Invalid check status.', 'Status')
        }
        if ($Fields.Severity -notin @('Critical', 'High', 'Medium', 'Low', 'Information')) {
            throw [ArgumentException]::new('Invalid check severity.', 'Severity')
        }
        if ($Fields.Applicability -notin @('Configured', 'Applicable', 'Unknown', 'NotApplicable')) {
            throw [ArgumentException]::new('Invalid check applicability.', 'Applicability')
        }
    }

    hidden [string] CreateId([string]$RuleId, [string]$Target) {
        $identity = $RuleId.ToUpperInvariant() + [char]0 + $Target.ToUpperInvariant()
        $bytes = [Text.Encoding]::UTF8.GetBytes($identity)
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $hash.Dispose()
        }
    }

    hidden [pscustomobject] BuildCheck([string]$Id, [hashtable]$Fields, [hashtable]$Metadata) {
        return [pscustomobject][ordered]@{
            CheckId = $Id
            RuleId = $Fields.RuleId
            Status = $Fields.Status
            Severity = $Fields.Severity
            Category = $Fields.Category
            Target = $Fields.Target
            Observed = $Fields.Observed
            Expected = $Fields.Expected
            Evidence = $Fields.Evidence
            Message = $Fields.Message
            Applicability = $Fields.Applicability
            ObjectGuid = $Metadata.ObjectGuid
            SID = $Metadata.SID
            DistinguishedName = $Metadata.DistinguishedName
            Suppressed = $false
            Exception = $null
        }
    }

    [object] ApplyException([object]$Check, [hashtable]$Profile) {
        if ($null -eq $Check) {
            throw [ArgumentNullException]::new('Check')
        }

        foreach ($candidate in @($Profile.Exceptions)) {
            if ($this.MatchesRule(@{
                        CheckRule = $Check.RuleId
                        CandidateRule = $candidate.RuleId
                    }) -and
                $Check.Target -like $candidate.Target -and
                $this.IsFresh([datetimeoffset]$candidate.Expires)) {
                $Check.Suppressed = $true
                $Check.Exception = $this.BuildException(@{
                    Owner = $candidate.Owner
                    Reason = $candidate.Reason
                    Expires = $candidate.Expires
                })
                break
            }
        }
        return $Check
    }

    hidden [bool] MatchesRule([hashtable]$Observation) {
        return [bool]($Observation.CheckRule -eq $Observation.CandidateRule)
    }

    hidden [bool] IsFresh([datetimeoffset]$Expiration) {
        return $Expiration -gt [datetimeoffset]::UtcNow
    }

    hidden [pscustomobject] BuildException([hashtable]$Metadata) {
        return [pscustomobject]@{
            Owner = $Metadata.Owner
            Reason = $Metadata.Reason
            Expires = $Metadata.Expires
        }
    }
}

function New-ADAnalyzerCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][ValidateSet('Pass',
            'Fail',
            'Unknown',
            'Unreadable',
            'NotApplicable',
            'NotConfigured',
            'Invalid')][string]$Status,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Information')][string]$Severity = 'Information',
        [string]$Category = 'General',
        [Parameter(Mandatory)][string]$Target,
        [AllowNull()]$Observed,
        [AllowNull()]$Expected,
        [AllowNull()]$Evidence,
        [string]$Message = '',
        [ValidateSet('Configured', 'Applicable', 'Unknown', 'NotApplicable')][string]$Applicability = 'Unknown',
        [AllowNull()]$Object

    )
    $factory = [ADAnalyzerCheckFactory]::new()
    $id = $factory.CreateId($RuleId, $Target)
    # Observe metadata in command scope to preserve native conversion errors.
    $factory.BuildCheck($id, @{
        RuleId = $RuleId
        Status = $Status
        Severity = $Severity
        Category = $Category
        Target = $Target
        Observed = $Observed
        Expected = $Expected
        Evidence = $Evidence
        Message = $Message
        Applicability = $Applicability
    }, @{
        ObjectGuid = $(if ($Object) {
                [string]$Object.ObjectGuid
            }
            else {
                $null
            })
        SID = $(if ($Object) {
                [string]$Object.SID
            }
            else {
                $null
            })
        DistinguishedName = $(if ($Object) {
                [string]$Object.DistinguishedName
            }
            else {
                $null
            })
    })
}

function Set-ADAnalyzerCheckException {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Check,
        [hashtable]$Profile

    )
    process {
        $factory = [ADAnalyzerCheckFactory]::new()
        # Native foreach exposes its enumerator to property getters in this scope.
        foreach ($exception in @($Profile.Exceptions)) {
            if ($factory.MatchesRule(@{
                        CheckRule = $Check.RuleId
                        CandidateRule = $exception.RuleId
                    }) -and
                $Check.Target -like $exception.Target -and
                $factory.IsFresh([datetimeoffset]$exception.Expires)) {
                # Keep the two native writes in order for PowerShell continuation.
                $Check.Suppressed = $true
                $Check.Exception = $factory.BuildException(@{
                    Owner = $exception.Owner
                    Reason = $exception.Reason
                    Expires = $exception.Expires
                })
                break
            }
        }
        $Check
    }
}

function Get-ADAnalyzerPrerequisiteObservation {
    param([string]$Kind)

    switch ($Kind) {
        'Platform' {
            return {
                $windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
            }
        }
        'Package' {
            return {
                $dll = Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
                $packagePath = $null
                $packageLiteralPath = $null
                $version = $null
                $sha = $null
                $packageAvailable = Test-Path -LiteralPath $dll -PathType Leaf
                if ($packageAvailable) {
                    $packageProvider = $null
                    $packageDrive = $null
                    $packagePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                        $dll,
                        [ref]$packageProvider,
                        [ref]$packageDrive
                    )
                    if ($packageProvider.Name -ne 'FileSystem') {
                        throw 'The package AD assembly must use the FileSystem provider'
                    }

                    $packageLiteralPath = 'FileSystem::' + $packagePath
                    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($packagePath).FileVersion
                    $sha = (Get-FileHash -LiteralPath $packageLiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash
                }
            }
        }
        'Tcp' {
            return {
                $client = [Net.Sockets.TcpClient]::new()
                $probeFailure = $null
                try {
                    $pending = $client.BeginConnect($Server, $port, $null, $null)
                    if (-not $pending.AsyncWaitHandle.WaitOne($timeoutMilliseconds)) {
                        throw 'Connection timed out'
                    }
                    $client.EndConnect($pending)
                }
                catch {
                    $probeFailure = $_
                }
                finally {
                    $client.Dispose()
                }
            }
        }
        'Directory' {
            return {
                $binary = Import-Module -Name $packagePath -Scope Local -PassThru -ErrorAction Stop
                $command = $binary.ExportedCmdlets['Get-ADRootDSE']
                if ($null -eq $command) {
                    throw 'Bundled AD assembly does not provide RootDSE queries'
                }
                $root = & $command @splat
                $rootHostName = $root.DnsHostName
            }
        }
    }
}

class ADAnalyzerPrerequisiteInspector {
    ADAnalyzerPrerequisiteInspector() {
    }

    [object[]] Inspect() {
        return $this.Inspect((Split-Path -Parent $PSScriptRoot), $null)
    }

    [object[]] Inspect([string]$RepositoryRoot, [hashtable]$Profile) {
        return $this.InspectCore($RepositoryRoot, $null, [pscredential]::Empty, $Profile, $false)
    }

    [object[]] InspectOnline(
        [string]$RepositoryRoot,
        [string]$Server,
        [pscredential]$Credential,
        [hashtable]$Profile
    ) {
        return $this.InspectCore($RepositoryRoot, $Server, $Credential, $Profile, $true)
    }

    hidden [object[]] InspectCore(
        [string]$RepositoryRoot,
        [string]$Server,
        [pscredential]$Credential,
        [hashtable]$Profile,
        [bool]$Online
    ) {
        $ErrorActionPreference = 'Stop'
        $configuration = [ADAnalyzerProfile]::new($Profile).ToHashtable()
        $factory = [ADAnalyzerCheckFactory]::new()
        $checks = [Collections.Generic.List[object]]::new()

        $windows = $false
        $platformObservation = Get-ADAnalyzerPrerequisiteObservation -Kind Platform
        . $platformObservation
        $checks.Add($factory.Create($this.PlatformCheck($RepositoryRoot, $windows)))
        $runtime = Get-Variable -Name PSVersionTable -ValueOnly -ErrorAction Stop
        $checks.Add($factory.Create($this.PowerShellCheck($RepositoryRoot, $runtime.PSVersion)))

        $dll = $null
        $packagePath = $null
        $packageLiteralPath = $null
        $packageAvailable = $false
        $version = $null
        $sha = $null
        $packageObservation = Get-ADAnalyzerPrerequisiteObservation -Kind Package
        . $packageObservation
        $checks.Add($factory.Create($this.PackageCheck($dll, $packageAvailable, $version, $sha)))
        $expected = $null
        if ($packageAvailable) {
            $expected = $this.ExpectedPin($configuration)
            $checks.Add($factory.Create($this.ChecksumCheck($dll, $sha, $expected)))
        }
        if (-not $Online) {
            return $checks.ToArray()
        }

        if (-not $this.IsValidServer($Server)) {
            throw 'Online checks require a valid Server host name'
        }
        $tcpPlan = $this.TcpPlan()
        $timeoutMilliseconds = $tcpPlan.TimeoutMilliseconds
        $probeFailure = $null
        $tcpObservation = Get-ADAnalyzerPrerequisiteObservation -Kind Tcp
        foreach ($port in $tcpPlan.Ports) {
            . $tcpObservation
            $checks.Add($factory.Create($this.TcpCheck($Server, $port, $probeFailure)))
        }

        $splat = $this.DirectoryArguments($Server, $Credential)
        $rootHostName = $null
        try {
            if (-not $this.CanCheckDirectoryPackage($windows, $packageLiteralPath) -or
                -not (Test-Path -LiteralPath $packageLiteralPath -PathType Leaf)) {
                throw 'Online directory checks require the bundled Windows AD assembly'
            }
            if ($this.HasPinMismatch($expected, $sha)) {
                throw 'Bundled AD assembly checksum does not match the configured pin'
            }
            $directoryObservation = Get-ADAnalyzerPrerequisiteObservation -Kind Directory
            . $directoryObservation
            $check = $this.DirectoryCheck($Server, $null)
            $check.Observed = $rootHostName
            $checks.Add($factory.Create($check))
        }
        catch {
            $checks.Add($factory.Create($this.DirectoryCheck($Server, $_)))
        }
        return $checks.ToArray()
    }

    hidden [hashtable] PlatformCheck([string]$RepositoryRoot, [bool]$Windows) {
        $status = 'NotApplicable'
        if ($Windows) {
            $status = 'Pass'
        }
        return @{
            RuleId = 'PACKAGE.WINDOWS'
            Status = $status
            Category = 'Prerequisite'
            Target = $RepositoryRoot
            Observed = $Windows
            Expected = $true
            Message = 'Live AD/SMB collection uses Windows; offline policy analysis is portable'
        }
    }

    hidden [hashtable] PowerShellCheck([string]$RepositoryRoot, [object]$Version) {
        $status = 'Fail'
        if ($Version -ge [version]'5.1') {
            $status = 'Pass'
        }
        return @{
            RuleId = 'PACKAGE.POWERSHELL'
            Status = $status
            Category = 'Prerequisite'
            Target = $RepositoryRoot
            Observed = $Version.ToString()
            Expected = '>=5.1'
        }
    }

    hidden [hashtable] PackageCheck([string]$Path, [bool]$Available, [object]$Version, [string]$Hash) {
        if (-not $Available) {
            return @{
                RuleId = 'PACKAGE.BUNDLED_AD'
                Status = 'Fail'
                Severity = 'High'
                Category = 'Prerequisite'
                Target = $Path
                Message = 'The package AD assembly is missing'
            }
        }
        return @{
            RuleId = 'PACKAGE.BUNDLED_AD'
            Status = 'Pass'
            Category = 'Prerequisite'
            Target = $Path
            Observed = @{
                Version = $Version
                Sha256 = $Hash
            }
            Expected = 'Bundled AD assembly; no installed RSAT required'
        }
    }

    hidden [object] ExpectedPin([hashtable]$Configuration) {
        if ($Configuration.DependencyHashes.ContainsKey('Microsoft.ActiveDirectory.Management.dll')) {
            return $Configuration.DependencyHashes['Microsoft.ActiveDirectory.Management.dll']
        }
        return $null
    }

    hidden [bool] HasPinMismatch([object]$Expected, [string]$Hash) {
        return ($Expected -and $Hash -ine $Expected)
    }

    hidden [hashtable] ChecksumCheck([string]$Path, [string]$Hash, [object]$Expected) {
        $status = 'NotConfigured'
        if ($this.HasPinMismatch($Expected, $Hash)) {
            $status = 'Fail'
        }
        elseif ($Expected) {
            $status = 'Pass'
        }
        return @{
            RuleId = 'PACKAGE.CHECKSUM'
            Status = $status
            Severity = 'High'
            Category = 'Prerequisite'
            Target = $Path
            Observed = $Hash
            Expected = $Expected
            Message = 'Pin a trusted SHA256 in DependencyHashes to verify the bundled assembly; availability alone is not signature verification'
        }
    }

    hidden [bool] IsValidServer([string]$Server) {
        return ($Server -match '^[A-Za-z0-9][A-Za-z0-9._-]*$')
    }

    hidden [hashtable] TcpPlan() {
        return @{
            Ports = [int[]]@(9389, 445)
            TimeoutMilliseconds = 3000
        }
    }

    hidden [hashtable] TcpCheck(
        [string]$Server,
        [int]$Port,
        [Management.Automation.ErrorRecord]$Failure
    ) {
        $status = 'Pass'
        $observed = ''
        if ($null -ne $Failure) {
            $status = 'Unreadable'
            $observed = $Failure.Exception.Message
        }
        return @{
            RuleId = 'CONNECTIVITY.TCP.' + $Port
            Status = $status
            Category = 'Prerequisite'
            Target = $Server
            Observed = $observed
            Expected = 'Reachable'
            Message = 'Port reachability does not verify authentication or directory/SYSVOL permissions'
        }
    }

    hidden [bool] CanCheckDirectoryPackage([bool]$Windows, [string]$PackageLiteralPath) {
        return ($Windows -and $PackageLiteralPath)
    }

    hidden [hashtable] DirectoryArguments([string]$Server, [pscredential]$Credential) {
        $arguments = @{
            Server = $Server
            ErrorAction = 'Stop'
        }
        if ($Credential -and $Credential -ne [pscredential]::Empty) {
            $arguments.Credential = $Credential
        }
        return $arguments
    }

    hidden [hashtable] DirectoryCheck(
        [string]$Server,
        [Management.Automation.ErrorRecord]$Failure
    ) {
        if ($null -ne $Failure) {
            return @{
                RuleId = 'CONNECTIVITY.DIRECTORY'
                Status = 'Unreadable'
                Category = 'Prerequisite'
                Target = $Server
                Message = $Failure.Exception.Message
            }
        }
        return @{
            RuleId = 'CONNECTIVITY.DIRECTORY'
            Status = 'Pass'
            Category = 'Prerequisite'
            Target = $Server
            Expected = 'Authenticated RootDSE query through the package assembly'
        }
    }
}

function Get-ADAnalyzerPrerequisite {
    [CmdletBinding()]
    param(
        [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [switch]$Online,
        [hashtable]$Profile

    )
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $inspector = [ADAnalyzerPrerequisiteInspector]::new()

    $platformObservation = Get-ADAnalyzerPrerequisiteObservation -Kind Platform
    . $platformObservation
    $check = $inspector.PlatformCheck($RepositoryRoot, $windows)
    New-ADAnalyzerCheck @check
    $check = $inspector.PowerShellCheck($RepositoryRoot, $PSVersionTable.PSVersion)
    New-ADAnalyzerCheck @check

    # Keep native file failures and ErrorVariable capture in the command scope.
    $dll = Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
    $packagePath = $null
    $packageLiteralPath = $null
    if (Test-Path -LiteralPath $dll -PathType Leaf) {
        $packageProvider = $null
        $packageDrive = $null
        $packagePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $dll,
            [ref]$packageProvider,
            [ref]$packageDrive
        )
        if ($packageProvider.Name -ne 'FileSystem') {
            throw 'The package AD assembly must use the FileSystem provider'
        }

        $packageLiteralPath = 'FileSystem::' + $packagePath
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($packagePath)
        $sha = (Get-FileHash -LiteralPath $packageLiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $check = $inspector.PackageCheck($dll, $true, $info.FileVersion, $sha)
        New-ADAnalyzerCheck @check
        $expected = $inspector.ExpectedPin($configuration)
        $check = $inspector.ChecksumCheck($dll, $sha, $expected)
        New-ADAnalyzerCheck @check
    }
    else {
        $check = $inspector.PackageCheck($dll, $false, $null, $null)
        New-ADAnalyzerCheck @check
    }
    if ($Online) {
        if (-not $inspector.IsValidServer($Server)) {
            throw 'Online checks require a valid Server host name'
        }
        $tcpPlan = $inspector.TcpPlan()
        $timeoutMilliseconds = $tcpPlan.TimeoutMilliseconds
        $tcpObservation = Get-ADAnalyzerPrerequisiteObservation -Kind Tcp
        foreach ($port in $tcpPlan.Ports) {
            . $tcpObservation
            $check = $inspector.TcpCheck($Server, $port, $probeFailure)
            New-ADAnalyzerCheck @check
        }

        $splat = $inspector.DirectoryArguments($Server, $Credential)
        try {
            if (-not $inspector.CanCheckDirectoryPackage($windows, $packageLiteralPath) -or
                -not (Test-Path -LiteralPath $packageLiteralPath -PathType Leaf)) {
                throw 'Online directory checks require the bundled Windows AD assembly'
            }
            if ($inspector.HasPinMismatch($expected, $sha)) {
                throw 'Bundled AD assembly checksum does not match the configured pin'
            }

            # The exact import, export, invocation and getter share the caller's error scope.
            $binary = Import-Module -Name $packagePath -Scope Local -PassThru -ErrorAction Stop
            $command = $binary.ExportedCmdlets['Get-ADRootDSE']
            if ($null -eq $command) {
                throw 'Bundled AD assembly does not provide RootDSE queries'
            }
            $root = & $command @splat
            $check = $inspector.DirectoryCheck($Server, $null)
            New-ADAnalyzerCheck @check -Observed $root.DnsHostName
        }
        catch {
            $check = $inspector.DirectoryCheck($Server, $_)
            New-ADAnalyzerCheck @check
        }
    }
}
