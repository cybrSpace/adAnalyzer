# Shared configuration and result contracts. No external modules are required.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
function ConvertTo-ADAnalyzerHashtable {
    param([AllowNull()]$InputObject)
    if($null -eq $InputObject){return $null}
    # Pipeline commands can wrap scalars in PSObject. Test their actual scalar
    # and collection contracts before PSCustomObject to avoid turning strings
    # into a dictionary containing their Length property.
    if($InputObject -is [string]){return [string]$InputObject}
    if($InputObject -is [ValueType]){return $InputObject}
    if($InputObject -is [Collections.IDictionary]) {
        $result=@{};foreach($key in $InputObject.Keys){$result[[string]$key]=ConvertTo-ADAnalyzerHashtable $InputObject[$key]};return $result
    }
    if($InputObject -is [array] -or $InputObject -is [Collections.IList]) {
        $items=@(foreach($item in $InputObject){ConvertTo-ADAnalyzerHashtable $item});return ,$items
    }
    if($InputObject -is [pscustomobject]) {
        $result=@{};foreach($property in $InputObject.PSObject.Properties){$result[$property.Name]=ConvertTo-ADAnalyzerHashtable $property.Value};return $result
    }
    return $InputObject
}

function Get-ADAnalyzerDefaultProfile {
    [CmdletBinding()]
    param()
    # Return a fresh graph on every call; a scan must not change another scan's rules.
    @{
        SchemaVersion=1;Name='AD Tactical Hardening';Version='1.0.0'
        Targets=@{Domain='';Server='';SearchBase=''}
        Analysis=@{IncludeAcl=$false;IncludeHostChecks=$false;IncludeGpo=$true;AssumeGpoApplicable=$false;HostTimeoutSeconds=30;TemplatePath='';Language='en-US'}
        Policy=@{
            MinimumPasswordLength=12;MinimumPasswordAgeDays=1;MaximumPasswordAgeDays=90
            UserPasswordAgeDays=90;ServicePasswordAgeDays=365;AllowPasswordNeverExpires=$false
            PasswordHistorySize=10;PasswordComplexity=$true;AllowReversibleEncryption=$false
            LockoutThreshold=6;LockoutDurationMinutes=30;ResetLockoutMinutes=30
            UserInactivityDays=60;ComputerInactivityDays=60;MachineAccountQuota=0
            MinimumLmCompatibilityLevel=5;RequireLdapClientSigning=$true;RequireLdapServerSigning=$true
            AllowedAnonymousPipes=@('LSARPC','NETLOGON','SAMR');ApprovedLocalAdminSids=@('S-1-5-32-544')
            AllowedUserRightSids=@{};PrivilegedSids=@();ApprovedDelegationTargets=@();ApprovedReplicationSids=@()
            IncludeAdministrativeReplicationRoles=$true
            ApprovedLapsReaderSids=@();ApprovedGmsaReaderSids=@()
            SupportedOperatingSystems=@();RequireLaps=$true;RequireGmsaForServiceAccounts=$false
        }
        AccountClassification=@{UserOUs=@();ServiceOUs=@();UserGroups=@();ServiceGroups=@();AttributeRules=@()}
        Host=@{Services=@();RegistryRules=@();AuditRules=@();CertificateEndpoints=@()}
        Remediation=@{AllowDisable=$false;ApprovedObjectGuids=@();ExcludedObjectGuids=@();ExcludedOUs=@();IncludeServiceAccounts=$false;IncludePrivilegedAccounts=$false;MaximumActions=10}
        RegistryRules=@();ExpectedGpoSettings=@();ApprovedDelegationTargets=@();ApprovedReplicationSids=@()
        Exceptions=@();DependencyHashes=@{}
    }
}

function Get-ADAnalyzerLegacyProfile {
    if($null -ne $script:ADAnalyzerLegacyProfile){return $script:ADAnalyzerLegacyProfile}
    Get-ADAnalyzerDefaultProfile
}

function Get-ADAnalyzerLmLevel {
    param([string]$Value)
    $levels=@('Send LM & NTLM responses','Send LM & NTLM - use NTLMv2 session security if negotiated','Send NTLM response only','Send NTLMv2 response only','Send NTLMv2 response only. Refuse LM','Send NTLMv2 response only. Refuse LM & NTLM')
    if($Value -ieq 'Send NTLMv2 responses only. Refuse LM & NTLM'){return 5}
    for($i=0;$i -lt $levels.Count;$i++){if($Value -ieq $levels[$i]){return $i}}
    return -1
}

function Get-ADAnalyzerSidValue {
    param($Value)
    if($null -eq $Value){return ''}
    if($Value -is [string]){return $Value}
    if($Value.Value){return [string]$Value.Value}
    return [string]$Value
}

function Get-ADAnalyzerPrivilegedSids {
    param([string]$DomainSid,[string]$RootDomainSid,[hashtable]$Profile)
    if(-not $RootDomainSid){$RootDomainSid=$DomainSid}
    $sids=@('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')
    if($DomainSid){$sids+=@("$DomainSid-512","$DomainSid-516","$DomainSid-521","$DomainSid-526")}
    if($RootDomainSid){$sids+=@("$RootDomainSid-518","$RootDomainSid-519","$RootDomainSid-527")}
    if($Profile){$sids+=@($Profile.Policy.PrivilegedSids)}
    $sids | Sort-Object -Unique
}

function Merge-ADAnalyzerProfile {
    param([hashtable]$Defaults,[hashtable]$Overrides,[string]$Prefix='')
    foreach($key in $Overrides.Keys) {
        if(-not $Defaults.ContainsKey($key)){throw "Unknown profile setting: $Prefix$key"}
        if($Defaults[$key] -is [hashtable]) {
            if($Overrides[$key] -isnot [hashtable]){throw "Profile setting $Prefix$key must be a dictionary"}
            if($key -in 'AllowedUserRightSids','DependencyHashes'){$Defaults[$key]=$Overrides[$key]}
            else{Merge-ADAnalyzerProfile $Defaults[$key] $Overrides[$key] ($Prefix+$key+'.')}
        } else {$Defaults[$key]=$Overrides[$key]}
    }
}

function Import-ADAnalyzerProfile {
    [CmdletBinding(DefaultParameterSetName='Object')]
    param([Parameter(Mandatory,ParameterSetName='Path')][string]$Path,[Parameter(ParameterSetName='Object')][AllowNull()]$Profile)
    $result=Get-ADAnalyzerDefaultProfile
    if($PSCmdlet.ParameterSetName -eq 'Path') {
        switch([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
            '.psd1' {$Profile=Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop}
            '.json' {$Profile=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop}
            default {throw 'Profiles must be .json or restricted .psd1 data files'}
        }
    }
    if($null -ne $Profile){$overrides=ConvertTo-ADAnalyzerHashtable $Profile;if($overrides -isnot [hashtable]){throw 'Profile must be a dictionary'};Merge-ADAnalyzerProfile $result $overrides}
    Assert-ADAnalyzerValueBaseline -Profile $result
    if(($result.SchemaVersion -isnot [int] -and $result.SchemaVersion -isnot [long]) -or $result.SchemaVersion -ne 1){throw 'Unsupported profile SchemaVersion'}
    if([string]::IsNullOrWhiteSpace($result.Name) -or [string]::IsNullOrWhiteSpace($result.Version)){throw 'Profile Name and Version are required'}
    foreach($name in @('MinimumPasswordLength','MinimumPasswordAgeDays','MaximumPasswordAgeDays','UserPasswordAgeDays','ServicePasswordAgeDays','PasswordHistorySize','LockoutThreshold','LockoutDurationMinutes','ResetLockoutMinutes','UserInactivityDays','ComputerInactivityDays','MachineAccountQuota','MinimumLmCompatibilityLevel')) {
        $number=0L
        if(-not [long]::TryParse([string]$result.Policy[$name],[ref]$number) -or $number -lt 0){throw "Policy.$name must be a nonnegative integer"}
        $result.Policy[$name]=$number
    }
    foreach($section in @('Analysis','Policy','Remediation')) {
        $default=Get-ADAnalyzerDefaultProfile
        foreach($key in $default[$section].Keys) {
            if($default[$section][$key] -is [bool] -and $result[$section][$key] -isnot [bool]){throw "$section.$key must be a boolean"}
        }
    }
    if($result.Policy.LockoutThreshold -gt 65535 -or $result.Policy.MinimumLmCompatibilityLevel -gt 5){throw 'Invalid lockout/LM policy range'}
    if($result.Policy.LockoutThreshold -gt 0 -and $result.Policy.LockoutDurationMinutes -lt $result.Policy.ResetLockoutMinutes){throw 'Lockout duration must be at least the reset interval'}
    $timeout=0
    if(-not [int]::TryParse([string]$result.Analysis.HostTimeoutSeconds,[ref]$timeout) -or $timeout -lt 1 -or $timeout -gt 300){throw 'Analysis.HostTimeoutSeconds must be an integer 1..300'}
    $result.Analysis.HostTimeoutSeconds=$timeout
    if($result.Remediation.MaximumActions -isnot [int] -and $result.Remediation.MaximumActions -isnot [long]){throw 'Remediation.MaximumActions must be an integer'}
    if($result.Remediation.MaximumActions -lt 1 -or $result.Remediation.MaximumActions -gt 1000){throw 'Remediation.MaximumActions must be 1..1000'}
    foreach($exception in @($result.Exceptions)) {
        foreach($key in @('RuleId','Target','Owner','Reason','Expires')){if(-not $exception.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$exception[$key])){throw "Exception requires $key"}}
        $date=[datetimeoffset]::MinValue
        if(-not [datetimeoffset]::TryParse([string]$exception.Expires,[ref]$date)){throw 'Exception Expires must be an ISO date/time'}
        $exception.Expires=$date.ToUniversalTime().ToString('o')
    }
    foreach($rule in @($result.RegistryRules)+@($result.ExpectedGpoSettings)) {
        if($rule -isnot [Collections.IDictionary]){throw 'Custom rules must be dictionaries'}
        if($rule.Contains('Operator') -and $rule.Operator -notin @('Equals','NotEquals','In','NotIn','Minimum','Maximum')){throw 'Unsupported custom-rule operator'}
        if($rule.Contains('Severity') -and $rule.Severity -notin @('Critical','High','Medium','Low','Information')){throw 'Unsupported custom-rule severity'}
        if($rule.Contains('Scope') -and $rule.Scope -notin @('Computer','User')){throw 'Custom-rule Scope must be Computer or User'}
        if($rule.Contains('Aggregate') -and $rule.Aggregate -isnot [bool]){throw 'Custom-rule Aggregate must be a boolean'}
    }
    foreach($rule in $result.AccountClassification.AttributeRules) {
        if(-not $rule.Attribute -or $rule.Type -notin @('User','Service') -or ($rule.Match -and $rule.Match -notin @('Equals','Regex'))){throw 'Invalid account classification attribute rule'}
    }
    foreach($value in @($result.Remediation.ApprovedObjectGuids)+@($result.Remediation.ExcludedObjectGuids)){$id=[guid]::Empty;if(-not [guid]::TryParse([string]$value,[ref]$id)){throw 'Remediation object identities must be GUIDs'}}
    foreach($rule in @($result.Host.Services)) {
        if($rule -isnot [Collections.IDictionary] -or $rule.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.Name) -or $rule.State -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.State)){throw 'Host service rules require nonempty string Name and State'}
        if($rule.Contains('StartMode') -and $null -ne $rule.StartMode -and $rule.StartMode -isnot [string]){throw 'Host service StartMode must be a string or null'}
    }
    foreach($rule in @($result.Host.RegistryRules)) {
        if($rule -isnot [Collections.IDictionary] -or $rule.Key -isnot [string] -or [string]::IsNullOrWhiteSpace($rule.Key) -or $rule.ValueName -isnot [string]){throw 'Host registry rules require a nonempty string Key and a string ValueName'}
        if($rule.Contains('Type')){
            $registryType=0
            if(-not [int]::TryParse([string]$rule.Type,[ref]$registryType) -or $registryType -notin 1,2,3,4,7,11){throw 'Host registry Type must be 1, 2, 3, 4, 7, or 11'}
            $rule.Type=$registryType
        }
        if($rule.Contains('Operator') -and $rule.Operator -notin @('Equals','NotEquals','In','NotIn','Minimum','Maximum')){throw 'Unsupported host registry operator'}
    }
    foreach($rule in @($result.Host.AuditRules)) {
        $id=[guid]::Empty
        if(-not [guid]::TryParse([string]$rule.SubcategoryGuid,[ref]$id) -or [int]$rule.Flags -notin 1,2,3){throw 'Host audit rules require SubcategoryGuid and Flags 1, 2, or 3'}
    }
    foreach($hash in $result.DependencyHashes.Values){if([string]$hash -notmatch '^[a-fA-F0-9]{64}$'){throw 'DependencyHashes values must be SHA256 hex strings'}}
    foreach($endpoint in @($result.Host.CertificateEndpoints)) {
        if($endpoint.HostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Certificate endpoint HostName must be a DNS/NetBIOS name or IPv4 address'}
        if($endpoint.Contains('Port') -and ([int]$endpoint.Port -lt 1 -or [int]$endpoint.Port -gt 65535)){throw 'Certificate endpoint Port must be 1..65535'}
        if($endpoint.Contains('MinimumRemainingDays') -and [int]$endpoint.MinimumRemainingDays -lt 0){throw 'Certificate minimum remaining days must be nonnegative'}
    }
    return $result
}

function New-ADAnalyzerCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','Unknown','Unreadable','NotApplicable','NotConfigured','Invalid')][string]$Status,
        [ValidateSet('Critical','High','Medium','Low','Information')][string]$Severity='Information',
        [string]$Category='General',[Parameter(Mandatory)][string]$Target,
        [AllowNull()]$Observed,[AllowNull()]$Expected,[AllowNull()]$Evidence,[string]$Message='',
        [ValidateSet('Configured','Applicable','Unknown','NotApplicable')][string]$Applicability='Unknown',[AllowNull()]$Object
    )
    $hash=[Security.Cryptography.SHA256]::Create()
    try{$id=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($RuleId.ToUpperInvariant()+[char]0+$Target.ToUpperInvariant()))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    [pscustomobject][ordered]@{
        CheckId=$id;RuleId=$RuleId;Status=$Status;Severity=$Severity;Category=$Category;Target=$Target
        Observed=$Observed;Expected=$Expected;Evidence=$Evidence;Message=$Message;Applicability=$Applicability
        ObjectGuid=$(if($Object){[string]$Object.ObjectGuid}else{$null});SID=$(if($Object){[string]$Object.SID}else{$null})
        DistinguishedName=$(if($Object){[string]$Object.DistinguishedName}else{$null});Suppressed=$false;Exception=$null
    }
}

function Set-ADAnalyzerCheckException {
    param([Parameter(Mandatory,ValueFromPipeline)]$Check,[hashtable]$Profile)
    process {
        foreach($exception in @($Profile.Exceptions)) {
            if($Check.RuleId -eq $exception.RuleId -and $Check.Target -like $exception.Target -and [datetimeoffset]$exception.Expires -gt [datetimeoffset]::UtcNow) {
                $Check.Suppressed=$true;$Check.Exception=[pscustomobject]@{Owner=$exception.Owner;Reason=$exception.Reason;Expires=$exception.Expires};break
            }
        }
        $Check
    }
}

function Get-ADAnalyzerPrerequisite {
    [CmdletBinding()]
    param([string]$RepositoryRoot=(Split-Path -Parent $PSScriptRoot),[string]$Server,[pscredential]$Credential=[pscredential]::Empty,[switch]$Online,[hashtable]$Profile)
    $configuration=Import-ADAnalyzerProfile -Profile $Profile
    $windows=[Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    New-ADAnalyzerCheck -RuleId 'PACKAGE.WINDOWS' -Status $(if($windows){'Pass'}else{'NotApplicable'}) -Category Prerequisite -Target $RepositoryRoot -Observed $windows -Expected $true -Message 'Live AD/SMB collection uses Windows; offline policy analysis is portable'
    New-ADAnalyzerCheck -RuleId 'PACKAGE.POWERSHELL' -Status $(if($PSVersionTable.PSVersion -ge [version]'5.1'){'Pass'}else{'Fail'}) -Category Prerequisite -Target $RepositoryRoot -Observed $PSVersionTable.PSVersion.ToString() -Expected '>=5.1'
    $dll=Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
    if(Test-Path -LiteralPath $dll -PathType Leaf) {
        $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($dll)
        $sha=(Get-FileHash -LiteralPath $dll -Algorithm SHA256 -ErrorAction Stop).Hash
        New-ADAnalyzerCheck -RuleId 'PACKAGE.BUNDLED_AD' -Status Pass -Category Prerequisite -Target $dll -Observed @{Version=$info.FileVersion;Sha256=$sha} -Expected 'Bundled AD assembly; no installed RSAT required'
        $expected=if($configuration.DependencyHashes.ContainsKey('Microsoft.ActiveDirectory.Management.dll')){$configuration.DependencyHashes['Microsoft.ActiveDirectory.Management.dll']}else{$null}
        New-ADAnalyzerCheck -RuleId 'PACKAGE.CHECKSUM' -Status $(if(-not $expected){'NotConfigured'}elseif($sha -ieq $expected){'Pass'}else{'Fail'}) -Severity High -Category Prerequisite -Target $dll -Observed $sha -Expected $expected -Message 'Pin a trusted SHA256 in DependencyHashes to verify the bundled assembly; availability alone is not signature verification'
    } else {New-ADAnalyzerCheck -RuleId 'PACKAGE.BUNDLED_AD' -Status Fail -Severity High -Category Prerequisite -Target $dll -Message 'The package AD assembly is missing'}
    if($Online) {
        if($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Online checks require a valid Server host name'}
        foreach($port in @(9389,445)) {
            $client=[Net.Sockets.TcpClient]::new();$status='Unknown';$message=''
            try{$pending=$client.BeginConnect($Server,$port,$null,$null);if(-not $pending.AsyncWaitHandle.WaitOne(3000)){throw 'Connection timed out'};$client.EndConnect($pending);$status='Pass'}catch{$status='Unreadable';$message=$_.Exception.Message}finally{$client.Dispose()}
            New-ADAnalyzerCheck -RuleId ('CONNECTIVITY.TCP.'+$port) -Status $status -Category Prerequisite -Target $Server -Observed $message -Expected 'Reachable' -Message 'Port reachability does not verify authentication or directory/SYSVOL permissions'
        }
        $splat=@{Server=$Server;ErrorAction='Stop'};if($Credential -and $Credential -ne [pscredential]::Empty){$splat.Credential=$Credential}
        try {
            if(-not $windows -or -not (Test-Path -LiteralPath $dll -PathType Leaf)){throw 'Online directory checks require the bundled Windows AD assembly'}
            if($expected -and $sha -ine $expected){throw 'Bundled AD assembly checksum does not match the configured pin'}
            $binary=Import-Module -Name $dll -Scope Local -PassThru -ErrorAction Stop
            $command=$binary.ExportedCmdlets['Get-ADRootDSE']
            if($null -eq $command){throw 'Bundled AD assembly does not provide RootDSE queries'}
            $root=& $command @splat
            New-ADAnalyzerCheck -RuleId 'CONNECTIVITY.DIRECTORY' -Status Pass -Category Prerequisite -Target $Server -Observed $root.DnsHostName -Expected 'Authenticated RootDSE query through the package assembly'
        } catch {New-ADAnalyzerCheck -RuleId 'CONNECTIVITY.DIRECTORY' -Status Unreadable -Category Prerequisite -Target $Server -Message $_.Exception.Message}
    }
}
