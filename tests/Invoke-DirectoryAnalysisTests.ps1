[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
. (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
. (Join-Path $RepositoryRoot 'bin/ADDirectoryAnalysis.ps1')
$script:Passed=0;$script:Failed=0
function Assert-DirectoryEqual($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], received [$Actual]"}}
function Assert-DirectoryTrue($Actual,[string]$Message){if(-not $Actual){throw $Message}}
function Invoke-DirectoryTest([string]$Name,[scriptblock]$Body){
    try{& $Body;$script:Passed++;Write-Host "PASS $Name"}catch{$script:Failed++;Write-Host "FAIL $Name : $_"}
}
$script:Credential=[pscredential]::new('fixture-user',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
$script:Queries=[System.Collections.Generic.List[object]]::new()
$script:Denied='';$script:IncludeLapsSchema=$true;$script:HostUnavailable=$false;$script:DeniedHostClass=''
$script:DomainDn='DC=example,DC=invalid';$script:DomainSid='S-1-5-21-1-2-3'
$script:User=[pscustomobject]@{
    ObjectClass='user';ObjectGuid='11111111-1111-1111-1111-111111111111';SID=($script:DomainSid+'-1001')
    DistinguishedName='CN=Alice,OU=People,DC=example,DC=invalid';SamAccountName='arbitrary-name';Name='Alice';Enabled=$true
    MemberOf=@('CN=Child,DC=example,DC=invalid');PrimaryGroupID=513;UserAccountControl=512;AdminCount=0
    ProtectedFromAccidentalDeletion=$false;WhenCreated=[datetime]::UtcNow.AddDays(-200);WhenChanged=[datetime]::UtcNow.AddDays(-5)
    LastLogonDate=[datetime]::UtcNow.AddDays(-100);PasswordLastSet=[datetime]::UtcNow.AddDays(-120);PasswordNeverExpires=$false
    ServicePrincipalNames=@('HTTP/app.example.invalid');'msDS-SupportedEncryptionTypes'=4;SIDHistory=@('S-1-5-21-9-9-9-512')
}
$script:Computer=[pscustomobject]@{
    ObjectClass='computer';ObjectGuid='22222222-2222-2222-2222-222222222222';SID=($script:DomainSid+'-1002')
    DistinguishedName='CN=PC,OU=Computers,DC=example,DC=invalid';SamAccountName='PC$';Name='PC';Enabled=$true
    MemberOf=@();PrimaryGroupID=513;UserAccountControl=4096;IsCriticalSystemObject=$false;ProtectedFromAccidentalDeletion=$false
    WhenCreated=[datetime]::UtcNow.AddDays(-200);WhenChanged=[datetime]::UtcNow.AddDays(-5)
    LastLogonDate=[datetime]::UtcNow.AddDays(-1);PasswordLastSet=[datetime]::UtcNow.AddDays(-1)
    ServicePrincipalNames=@('http/APP.example.invalid');'msDS-SupportedEncryptionTypes'=24
    OperatingSystem='Windows 10';OperatingSystemVersion='10.0 fixture';DNSHostName='pc.example.invalid'
    'msLAPS-PasswordExpirationTime'=[datetime]::UtcNow.AddDays(5).ToFileTimeUtc()
}
$script:Groups=@(
    [pscustomobject]@{SID=($script:DomainSid+'-513');DistinguishedName='CN=Ordinary,DC=example,DC=invalid';MemberOf=@();Name='Localized ordinary group'},
    [pscustomobject]@{SID=($script:DomainSid+'-512');DistinguishedName='CN=Renamed,DC=example,DC=invalid';MemberOf=@('CN=Child,DC=example,DC=invalid');Name='Renamed privileged group'},
    [pscustomobject]@{SID=($script:DomainSid+'-1100');DistinguishedName='CN=Child,DC=example,DC=invalid';MemberOf=@('CN=Renamed,DC=example,DC=invalid');Name='Child'}
)
$script:PasswordPolicy=[pscustomobject]@{
    DistinguishedName='DC=example,DC=invalid';MinPasswordLength=8;PasswordHistoryCount=5;ComplexityEnabled=$false
    ReversibleEncryptionEnabled=$false;LockoutThreshold=0;LockoutDuration=[timespan]::Zero
    LockoutObservationWindow=[timespan]::FromMinutes(30);MaxPasswordAge=[timespan]::FromDays(90);MinPasswordAge=[timespan]::FromDays(1)
}
function Register-DirectoryQuery([string]$Command,$Bound){
    $copy=@{};foreach($key in $Bound.Keys){$copy[$key]=$Bound[$key]}
    $script:Queries.Add([pscustomobject]@{Command=$Command;Parameters=$copy})
    if($Bound['Server'] -ne 'dc.example.invalid'){throw "Missing explicit server for $Command"}
    if($Bound['Credential'] -ne $script:Credential){throw "Missing explicit credential for $Command"}
    if($script:Denied -eq $Command){throw "fixture denied: $Command"}
}
function Get-ADRootDSE {param($Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADRootDSE' $PSBoundParameters;[pscustomobject]@{DefaultNamingContext=$script:DomainDn;SchemaNamingContext=('CN=Schema,CN=Configuration,'+$script:DomainDn);ConfigurationNamingContext=('CN=Configuration,'+$script:DomainDn)}}
function Get-ADDomain {param($Identity,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADDomain' $PSBoundParameters;[pscustomobject]@{DistinguishedName=$script:DomainDn;DNSRoot='example.invalid';DomainSID=$script:DomainSid;DomainMode='fixture'}}
function Get-ADForest {param($Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADForest' $PSBoundParameters;[pscustomobject]@{RootDomain='example.invalid';ForestMode='fixture'}}
function Get-ADUser {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADUser' $PSBoundParameters; $script:User}
function Get-ADComputer {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADComputer' $PSBoundParameters; $script:Computer}
function Get-ADGroup {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADGroup' $PSBoundParameters; $script:Groups}
function Get-ADTrust {param($Filter,$Properties,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADTrust' $PSBoundParameters;[pscustomobject]@{Name='partner.invalid';Target='partner.invalid';IntraForest=$false;ForestTransitive=$false;SIDFilteringQuarantined=$false;TrustType='External'}}
function Get-ADDomainController {param($Filter,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADDomainController' $PSBoundParameters;[pscustomobject]@{HostName='dc.example.invalid'}}
function Get-ADServiceAccount {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADServiceAccount' $PSBoundParameters}
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADDefaultDomainPasswordPolicy' $PSBoundParameters;$script:PasswordPolicy}
function Get-ADFineGrainedPasswordPolicy {param($Filter,$Properties,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADFineGrainedPasswordPolicy' $PSBoundParameters}
function Get-ADUserResultantPasswordPolicy {param($Identity,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADUserResultantPasswordPolicy' $PSBoundParameters}
function Get-ADOptionalFeature {param($Filter,$Properties,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADOptionalFeature' $PSBoundParameters;[pscustomobject]@{FeatureGUID='766ddcd8-acd0-445e-f3b9-a7f9b6744f2a';EnabledScopes=@('fixture')}}
function Get-ADOrganizationalUnit {param($Filter,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADOrganizationalUnit' $PSBoundParameters;[pscustomobject]@{DistinguishedName='OU=People,DC=example,DC=invalid'}}
function Get-ADObject {
    param($Identity,$Properties,$SearchBase,$LDAPFilter,$Server,$Credential,$ErrorAction)
    Register-DirectoryQuery 'Get-ADObject' $PSBoundParameters
    if($Properties -contains 'nTSecurityDescriptor'){
        $rights=@(
            [pscustomobject]@{IdentitySid='S-1-5-21-1-2-3-9000';Rights='ExtendedRight';AccessControlType='Allow';ObjectType='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'},
            [pscustomobject]@{IdentitySid='S-1-5-21-1-2-3-9000';Rights='ExtendedRight';AccessControlType='Allow';ObjectType='1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'}
        )
        return [pscustomobject]@{nTSecurityDescriptor=[pscustomobject]@{Access=$rights}}
    }
    if($Properties -contains 'ms-DS-MachineAccountQuota'){return [pscustomobject]@{'ms-DS-MachineAccountQuota'=10}}
    if($LDAPFilter -eq '(objectClass=groupPolicyContainer)'){return [pscustomobject]@{DistinguishedName=('CN={fixture},CN=Policies,CN=System,'+$script:DomainDn)}}
    if($LDAPFilter -eq '(objectClass=controlAccessRight)'){return [pscustomobject]@{rightsGuid='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2';displayName='Replication changes'}}
    if($Properties -contains 'schemaIDGUID'){
        if($script:IncludeLapsSchema){[pscustomobject]@{lDAPDisplayName='msLAPS-PasswordExpirationTime';schemaIDGUID=([guid]'11111111-2222-3333-4444-555555555555').ToByteArray()}}
        [pscustomobject]@{lDAPDisplayName='msDS-AllowedToActOnBehalfOfOtherIdentity';schemaIDGUID=([guid]'22222222-2222-3333-4444-555555555555').ToByteArray()}
    }
}
function New-CimSession {param($ComputerName,$Credential,$OperationTimeoutSec,$ErrorAction) if($script:HostUnavailable){throw 'fixture CIM unavailable'};if($Credential -ne $script:Credential){throw 'Missing host credential'};if($OperationTimeoutSec -ne 30){throw 'Missing host timeout'};[pscustomobject]@{ComputerName=$ComputerName}}
function Get-CimInstance {param($CimSession,$ClassName,$Filter,$Namespace,$OperationTimeoutSec,$ErrorAction) if($script:DeniedHostClass -eq $ClassName){throw 'fixture host class denied'};if($OperationTimeoutSec -ne 30){throw 'Missing CIM query timeout'};[pscustomobject]@{ClassName=$ClassName;Observed=$true}}
function Invoke-CimMethod {param($CimSession,$Namespace,$ClassName,$MethodName,$Arguments,$OperationTimeoutSec,$ErrorAction) if($OperationTimeoutSec -ne 30){throw 'Missing registry query timeout'};[pscustomobject]@{ReturnValue=2;uValue=$null;sValue=$null}}
function Remove-CimSession {param($CimSession,$ErrorAction) $script:RemovedSession=$true}
function New-DirectoryContext([bool]$Acl=$false,[bool]$Hosts=$false){[pscustomobject]@{Server='dc.example.invalid';Domain='example.invalid';Credential=$script:Credential;SearchBase='';IncludeAcl=$Acl;IncludeHostChecks=$Hosts}}
function New-DirectoryProfile {
    $profile=Get-ADAnalyzerDefaultProfile
    $profile.AccountClassification.UserOUs=@('OU=People,DC=example,DC=invalid')
    return $profile
}
function Select-DirectoryCheck($Checks,[string]$Rule,[string]$Target=''){
    @($Checks | Where-Object {$_.RuleId -eq $Rule -and (-not $Target -or $_.Target -eq $Target)}) | Select-Object -First 1
}

Invoke-DirectoryTest 'SID graph follows primary and transitive membership and stops cycles' {
    $object=[pscustomobject]@{SID=($script:DomainSid+'-1001');PrimaryGroupID=513;MemberOf=@('CN=Child,DC=example,DC=invalid')}
    $m=Resolve-ADAnalyzerMembership -Object $object -Groups $script:Groups -DomainSid $script:DomainSid -PrivilegedSids @($script:DomainSid+'-512')
    Assert-DirectoryTrue $m.IsPrivileged 'Renamed privileged SID must be found'
    Assert-DirectoryTrue (($script:DomainSid+'-513') -in $m.EffectiveSids) 'Primary group must be included'
    Assert-DirectoryEqual 'Complete' $m.ResolutionStatus
    Assert-DirectoryTrue ($m.Cycles.Count -gt 0) 'Cycle must be bounded and reported'
}
Invoke-DirectoryTest 'unresolved foreign membership is Unknown rather than safe' {
    $m=Resolve-ADAnalyzerMembership -Object ([pscustomobject]@{MemberOf=@('CN=Foreign,DC=other')}) -Groups $script:Groups
    Assert-DirectoryEqual 'Unknown' $m.ResolutionStatus
    Assert-DirectoryEqual 1 $m.Unresolved.Count
}
Invoke-DirectoryTest 'classification defaults Unknown and records conflicting explicit evidence' {
    $profile=Get-ADAnalyzerDefaultProfile
    $object=[pscustomobject]@{DistinguishedName='CN=Alice,OU=People,DC=example,DC=invalid';SamAccountName='adoe'}
    Assert-DirectoryEqual 'Unknown' (Get-ADAnalyzerAccountType -Object $object -Profile $profile).Type
    $profile.AccountClassification.UserOUs=@('OU=People,DC=example,DC=invalid')
    $profile.AccountClassification.ServiceOUs=@('OU=People,DC=example,DC=invalid')
    $type=Get-ADAnalyzerAccountType -Object $object -Profile $profile
    Assert-DirectoryEqual 'Unknown' $type.Type
    Assert-DirectoryTrue $type.Conflicting 'Conflicting rules must not choose a type'
}
Invoke-DirectoryTest 'gMSA type comes from schema class rather than account name' {
    $type=Get-ADAnalyzerAccountType -Object ([pscustomobject]@{DirectoryObjectClass='msDS-GroupManagedServiceAccount';SamAccountName='anything'}) -Profile (Get-ADAnalyzerDefaultProfile)
    Assert-DirectoryEqual 'Service' $type.Type
}
Invoke-DirectoryTest 'collector forwards server and credentials and avoids password values' {
    $script:Queries.Clear();$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
    Assert-DirectoryEqual 'Collected' $data.Coverage.Users
    Assert-DirectoryEqual 1 $data.Users.Count
    Assert-DirectoryEqual 'User' $data.Users[0].AccountType
    Assert-DirectoryEqual 'Complete' $data.Users[0].PrivilegeResolutionStatus
    Assert-DirectoryEqual 'Collected' $data.Users[0].SafetyMetadataStatus
    Assert-DirectoryEqual $false $data.Users[0].IsCriticalSystemObject
    Assert-DirectoryEqual 0 $data.Computers[0].AdminCount
    Assert-DirectoryTrue ((@($script:Queries | Where-Object Command -eq 'Get-ADUser')[0].Parameters.Properties) -contains 'IsCriticalSystemObject') 'Critical-object safety metadata must be queried explicitly'
    foreach($query in $script:Queries){
        Assert-DirectoryEqual 'dc.example.invalid' $query.Parameters.Server
        Assert-DirectoryEqual $script:Credential $query.Parameters.Credential
        foreach($attribute in @($query.Parameters.Properties)){
            Assert-DirectoryTrue ($attribute -notin @('*','msDS-ManagedPassword','msLAPS-Password','msLAPS-EncryptedPassword','ms-Mcs-AdmPwd')) ('Forbidden attribute value query: '+$attribute)
        }
    }
    Assert-DirectoryEqual 'NotConfigured' $data.Coverage.Acl
    Assert-DirectoryEqual 0 @($script:Queries | Where-Object {$_.Parameters.Properties -contains 'nTSecurityDescriptor'}).Count
}
Invoke-DirectoryTest 'OU-scoped users retain domain-scoped group resolution' {
    $context=New-DirectoryContext;$context.SearchBase='OU=People,DC=example,DC=invalid'
    $script:Queries.Clear();$null=Get-ADAnalyzerDirectoryData -Context $context -Profile (New-DirectoryProfile)
    $userQuery=@($script:Queries | Where-Object Command -eq 'Get-ADUser')[0]
    $groupQuery=@($script:Queries | Where-Object Command -eq 'Get-ADGroup')[0]
    Assert-DirectoryEqual $context.SearchBase $userQuery.Parameters.SearchBase
    Assert-DirectoryEqual $script:DomainDn $groupQuery.Parameters.SearchBase
}
Invoke-DirectoryTest 'failed group collection prevents a complete privilege assertion' {
    $script:Denied='Get-ADGroup'
    try{$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)}
    finally{$script:Denied=''}
    Assert-DirectoryEqual 'Unreadable' $data.Coverage.Groups
    Assert-DirectoryEqual 'Unknown' $data.Users[0].PrivilegeResolutionStatus
    Assert-DirectoryTrue ($data.Errors.Count -gt 0) 'Read failures need explicit errors'
}
Invoke-DirectoryTest 'quota trust inactivity SPN and effective lockout checks are evidence based' {
    $profile=New-DirectoryProfile
    $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    foreach($rule in @('DOMAIN.MACHINE_ACCOUNT_QUOTA','TRUST.SID_FILTERING','ACCOUNT.INACTIVE','SPN.DUPLICATE','PASSWORD.LOCKOUT_THRESHOLD')){
        Assert-DirectoryEqual 'Fail' (Select-DirectoryCheck $checks $rule).Status
    }
    $inactive=Select-DirectoryCheck $checks 'ACCOUNT.INACTIVE'
    Assert-DirectoryEqual $script:User.ObjectGuid $inactive.ObjectGuid
    Assert-DirectoryEqual $script:User.DistinguishedName $inactive.Target
    Assert-DirectoryEqual 'Unknown' (Select-DirectoryCheck $checks 'SIDHISTORY.PRIVILEGED').Status
    Assert-DirectoryEqual 'Pass' (Select-DirectoryCheck $checks 'PASSWORD.LOCKOUT_DURATION').Status
}
Invoke-DirectoryTest 'no configured OS baseline is NotConfigured and zero encryption is Unknown' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
    $data.Users[0].SupportedEncryptionTypes=0
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'NotConfigured' (Select-DirectoryCheck $checks 'COMPUTER.OS_POLICY').Status
    Assert-DirectoryEqual 'Unknown' (Select-DirectoryCheck $checks 'KERBEROS.ENCRYPTION_METADATA' $script:User.DistinguishedName).Status
}
Invoke-DirectoryTest 'optional targeted ACL collection identifies potential replication grants' {
    $profile=New-DirectoryProfile;$script:Queries.Clear()
    $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $true) -Profile $profile
    Assert-DirectoryEqual 4 $data.Acl.Targets.Count
    Assert-DirectoryEqual 'Collected' $data.Coverage.Acl
    Assert-DirectoryTrue ($data.Acl.GuidMap.Count -gt 0) 'GUID mapping metadata must be retained'
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    $finding=Select-DirectoryCheck $checks 'ACL.REPLICATION_RIGHTS'
    Assert-DirectoryEqual 'Fail' $finding.Status
    Assert-DirectoryEqual $false $finding.Evidence.EffectiveAccessCalculated
}
Invoke-DirectoryTest 'missing LAPS schema is Unknown and never queries managed password values' {
    $script:IncludeLapsSchema=$false
    try{$profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile}
    finally{$script:IncludeLapsSchema=$true}
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Unknown' (Select-DirectoryCheck $checks 'LAPS.ROTATION_METADATA').Status
}
Invoke-DirectoryTest 'CIM host inventory uses credentials and keeps unsupported observations Unknown' {
    $script:RemovedSession=$false
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $false $true) -Profile $profile
    Assert-DirectoryTrue $script:RemovedSession 'Temporary CIM session must close'
    Assert-DirectoryEqual 'Unknown' $data.Hosts[0].AuditPolicy.Status
    Assert-DirectoryEqual 'Unknown' $data.Hosts[0].Certificates.Status
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Unknown' (Select-DirectoryCheck $checks 'HOST.OBSERVATIONS').Status
}
Invoke-DirectoryTest 'failed CIM access is reported rather than interpreted as host compliance' {
    $script:HostUnavailable=$true
    try{$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $false $true) -Profile (New-DirectoryProfile)}
    finally{$script:HostUnavailable=$false}
    Assert-DirectoryEqual 'Partial' $data.Coverage.Hosts
    Assert-DirectoryEqual 'Unknown' $data.Hosts[0].Status
    Assert-DirectoryTrue ($data.Errors.Count -gt 0) 'Host errors must remain explicit'
}
Invoke-DirectoryTest 'shared ancestors in an acyclic graph are not labeled cycles' {
    $groups=@(
        [pscustomobject]@{SID='S-1-5-21-1-1';DistinguishedName='CN=A';MemberOf=@('CN=B','CN=C')},
        [pscustomobject]@{SID='S-1-5-21-1-2';DistinguishedName='CN=B';MemberOf=@('CN=D')},
        [pscustomobject]@{SID='S-1-5-21-1-3';DistinguishedName='CN=C';MemberOf=@('CN=D')},
        [pscustomobject]@{SID='S-1-5-21-1-4';DistinguishedName='CN=D';MemberOf=@()}
    )
    $m=Resolve-ADAnalyzerMembership -Object ([pscustomobject]@{MemberOf=@('CN=A')}) -Groups $groups
    Assert-DirectoryEqual 0 $m.Cycles.Count
    Assert-DirectoryEqual 4 $m.EffectiveSids.Count
}
Invoke-DirectoryTest 'attribute classification is collected and unsafe credential attributes are rejected' {
    $profile=New-DirectoryProfile;$profile.AccountClassification.UserOUs=@()
    $profile.AccountClassification.AttributeRules=@(@{Attribute='employeeType';Type='Service';Value='Application'})
    $script:User | Add-Member NoteProperty employeeType 'Application' -Force
    try{
        $script:Queries.Clear();$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
        Assert-DirectoryEqual 'Service' $data.Users[0].AccountType
        Assert-DirectoryTrue ((@($script:Queries | Where-Object Command -eq 'Get-ADUser')[0].Parameters.Properties) -contains 'employeeType') 'Classifier attributes must be requested'
        $profile.AccountClassification.AttributeRules=@(@{Attribute='msDS-ManagedPassword';Type='Service';Value='irrelevant'})
        $script:Queries.Clear();$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
        Assert-DirectoryEqual 'Unknown' $data.Users[0].AccountType
        Assert-DirectoryTrue ($data.Errors.Count -gt 0) 'Unsafe profile fields need explicit errors'
        Assert-DirectoryEqual 0 @($script:Queries | Where-Object {$_.Parameters.Properties -contains 'msDS-ManagedPassword'}).Count
    }finally{$script:User.PSObject.Properties.Remove('employeeType')}
}
Invoke-DirectoryTest 'multiple ACL principals and identical ACEs produce unique stable checks' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $true) -Profile $profile
    $first=[pscustomobject]@{Target=$script:DomainDn;TargetType='DomainRoot';IdentitySid='S-1-5-21-1-2-3-9001';Rights='GenericAll';AccessControlType='Allow';ObjectType='';InheritedObjectType='';IsInherited=$false}
    $second=[pscustomobject]@{Target=$script:DomainDn;TargetType='DomainRoot';IdentitySid='S-1-5-21-1-2-3-9002';Rights='GenericAll';AccessControlType='Allow';ObjectType='';InheritedObjectType='';IsInherited=$false}
    $data.Acl.Entries=@($data.Acl.Entries)+@($first,$first,$second)
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 2 @($checks | Where-Object RuleId -eq 'ACL.DELEGATED_CONTROL').Count
    Assert-DirectoryEqual 3 @($checks | Where-Object RuleId -eq 'ACL.REPLICATION_RIGHTS').Count
    Assert-DirectoryEqual $checks.Count @($checks.CheckId | Select-Object -Unique).Count
}
Invoke-DirectoryTest 'Policy approval arrays remain effective when compatibility root arrays are empty' {
    $profile=New-DirectoryProfile;$profile.Policy.ApprovedReplicationSids=@('S-1-5-21-1-2-3-9000')
    $profile.Policy.ApprovedDelegationTargets=@('HTTP/approved.example.invalid','S-1-5-21-1-2-3-9000')
    $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $true) -Profile $profile
    $data.Users[0].AllowedToDelegateTo=@('HTTP/approved.example.invalid')
    $data.Users[0].ResourceBasedDelegation=@([pscustomobject]@{IdentitySid='S-1-5-21-1-2-3-9000';AccessControlType='Allow';Rights='GenericAll'})
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Pass' (Select-DirectoryCheck $checks 'DELEGATION.EXPOSURE' $script:User.DistinguishedName).Status
    Assert-DirectoryEqual 'Pass' (Select-DirectoryCheck $checks 'ACL.REPLICATION_RIGHTS').Status
    $data.Users[0].ResourceBasedDelegation=@([pscustomobject]@{IdentitySid='S-1-5-21-1-2-3-9999';AccessControlType='Allow';Rights='GenericAll'})
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Fail' (Select-DirectoryCheck $checks 'DELEGATION.EXPOSURE' $script:User.DistinguishedName).Status
}
Invoke-DirectoryTest 'SID history resolves a privileged transitive group and preserves foreign uncertainty' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
    $data.Users[0].SIDHistory=@($script:DomainSid+'-1100')
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Fail' (Select-DirectoryCheck $checks 'SIDHISTORY.PRIVILEGED').Status
    $data.Users[0].SIDHistory=@('S-1-5-21-9-9-9-1234')
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Unknown' (Select-DirectoryCheck $checks 'SIDHISTORY.PRIVILEGED').Status
}
Invoke-DirectoryTest 'normal intra-forest trusts are not boundary-filtering failures' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
    $data.Trusts[0].IntraForest=$true
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'NotApplicable' (Select-DirectoryCheck $checks 'TRUST.SID_FILTERING').Status
    $data.Trusts[0].PSObject.Properties.Remove('IntraForest')
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Unknown' (Select-DirectoryCheck $checks 'TRUST.SID_FILTERING').Status
}
Invoke-DirectoryTest 'OS support requires explicit build and lifecycle evidence' {
    $object=[pscustomobject]@{OperatingSystem='Windows Server 2022 Datacenter';OperatingSystemVersion='10.0 (20348)';BuildNumber=$null;EsuStatus=$null;EsuValidUntil=$null}
    $entry=@{Name='Windows Server 2022*';VersionPattern='^10\.0';MinimumBuild=20348;MaximumBuild=29999;SupportedUntil='2031-10-14';RequireEsu=$false}
    Assert-DirectoryEqual 'Pass' (Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @($entry) -ReferenceTime ([datetimeoffset]'2026-11-12')).Status
    $entry.SupportedUntil='2025-01-01'
    Assert-DirectoryEqual 'Fail' (Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @($entry) -ReferenceTime ([datetimeoffset]'2026-11-12')).Status
    $entry.SupportedUntil='2031-10-14';$object.OperatingSystemVersion='unreported'
    Assert-DirectoryEqual 'Unknown' (Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @($entry)).Status
    Assert-DirectoryEqual 'Unknown' (Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @('Windows Server 2022*')).Status
}
Invoke-DirectoryTest 'required ESU support does not pass without active enrollment evidence' {
    $object=[pscustomobject]@{OperatingSystem='FixtureOS';OperatingSystemVersion='10.0.20348';BuildNumber=20348;EsuStatus=$null;EsuValidUntil=$null}
    $entry=@{Name='FixtureOS';VersionPattern='^10\.0';MinimumBuild=20348;SupportedUntil='2025-01-01';RequireEsu=$true}
    Assert-DirectoryEqual 'Unknown' (Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @($entry) -ReferenceTime ([datetimeoffset]'2026-11-12')).Status
    $object.EsuStatus='Active';$object.EsuValidUntil='2027-01-01'
    Assert-DirectoryEqual 'Pass' (Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @($entry) -ReferenceTime ([datetimeoffset]'2026-11-12')).Status
}
Invoke-DirectoryTest 'partial CIM inventory retains per-class errors and partial coverage' {
    $script:DeniedHostClass='Win32_Service'
    try{$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $false $true) -Profile (New-DirectoryProfile)}finally{$script:DeniedHostClass=''}
    Assert-DirectoryEqual 'Partial' $data.Coverage.Hosts
    Assert-DirectoryTrue ($data.Errors.Count -gt 0) 'Denied host providers must remain explicit'
}
Invoke-DirectoryTest 'managed service-account retrieval readers require an explicit baseline' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
    $service=ConvertTo-ADAnalyzerDirectoryObject ([pscustomobject]@{ObjectClass='msDS-GroupManagedServiceAccount';SID=($script:DomainSid+'-2001');ObjectGuid='33333333-3333-3333-3333-333333333333';DistinguishedName='CN=Managed,CN=Managed Service Accounts,DC=example,DC=invalid';PrincipalsAllowedToRetrieveManagedPassword=@([pscustomobject]@{SID='S-1-5-21-1-2-3-9000'});ManagedPasswordIntervalInDays=30}) 'ServiceAccount'
    $service | Add-Member NoteProperty AccountType 'Service'
    $data.Objects=@($data.Objects)+@($service)
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'NotConfigured' (Select-DirectoryCheck $checks 'GMSA.RETRIEVAL_PRINCIPALS').Status
    $profile.Policy.ApprovedGmsaReaderSids=@('S-1-5-21-1-2-3-9000')
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Pass' (Select-DirectoryCheck $checks 'GMSA.RETRIEVAL_PRINCIPALS').Status
    $profile.Policy.ApprovedGmsaReaderSids=@('S-1-5-21-1-2-3-9999')
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    Assert-DirectoryEqual 'Fail' (Select-DirectoryCheck $checks 'GMSA.RETRIEVAL_PRINCIPALS').Status
}
Invoke-DirectoryTest 'LAPS attribute ACE reporting does not claim effective plaintext retrieval' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $true) -Profile $profile
    $ace=[pscustomobject]@{Target='OU=People,DC=example,DC=invalid';TargetType='OU';IdentitySid='S-1-5-21-1-2-3-9000';Rights='ReadProperty';AccessControlType='Allow';ObjectType='11111111-1111-1111-1111-111111111111';ObjectTypeName='msLAPS-EncryptedPassword';InheritedObjectType='';IsInherited=$false}
    $data.Acl.Entries=@($data.Acl.Entries)+@($ace)
    $profile.Policy.ApprovedLapsReaderSids=@('S-1-5-21-1-2-3-9999')
    $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
    $check=Select-DirectoryCheck $checks 'LAPS.ATTRIBUTE_READ_ACL'
    Assert-DirectoryEqual 'Fail' $check.Status
    Assert-DirectoryEqual $false $check.Evidence.EffectiveAccessCalculated
    Assert-DirectoryEqual $false $check.Evidence.DecryptionPermissionsCalculated
}
Invoke-DirectoryTest 'missing mandatory protection or role metadata never becomes safe by coercion' {
    $previous=$script:User.ProtectedFromAccidentalDeletion;$script:User.ProtectedFromAccidentalDeletion=$null
    try{$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)}finally{$script:User.ProtectedFromAccidentalDeletion=$previous}
    Assert-DirectoryEqual 'Unknown' $data.Users[0].SafetyMetadataStatus
    Assert-DirectoryEqual $null $data.Users[0].Protected
    $previous=$script:User.UserAccountControl;$script:User.UserAccountControl=$null
    try{$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)}finally{$script:User.UserAccountControl=$previous}
    Assert-DirectoryEqual 'Unknown' $data.Users[0].SafetyMetadataStatus
}
Invoke-DirectoryTest 'native zero password age and disabled profile lockout use explicit policy semantics' {
    $old=$script:PasswordPolicy.MaxPasswordAge;$script:PasswordPolicy.MaxPasswordAge=[timespan]::Zero
    try{
        $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
        $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
        Assert-DirectoryEqual 'Fail' (Select-DirectoryCheck $checks 'PASSWORD.MAX_AGE').Status
        $profile.Policy.AllowPasswordNeverExpires=$true
        $profile.Policy.LockoutThreshold=0
        $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile)
        Assert-DirectoryEqual 'Pass' (Select-DirectoryCheck $checks 'PASSWORD.MAX_AGE').Status
        Assert-DirectoryEqual 'NotConfigured' (Select-DirectoryCheck $checks 'PASSWORD.LOCKOUT_THRESHOLD').Status
    }finally{$script:PasswordPolicy.MaxPasswordAge=$old}
}
Invoke-DirectoryTest 'normal administrative replication authority is distinct from an unexpected direct user grant' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $true) -Profile $profile
    $ace=[pscustomobject]@{Target=$script:DomainDn;TargetType='DomainRoot';IdentitySid=($script:DomainSid+'-512');Rights='GenericAll';AccessControlType='Allow';ObjectType=[guid]::Empty.ToString();InheritedObjectType='';IsInherited=$false;PropagationFlags='None'}
    $data.Acl.Entries=@($ace)
    Assert-DirectoryEqual Pass (Select-DirectoryCheck @(Test-ADAnalyzerDirectoryPolicy $data $profile) ACL.REPLICATION_RIGHTS).Status
    $profile.Policy.IncludeAdministrativeReplicationRoles=$false
    Assert-DirectoryEqual Fail (Select-DirectoryCheck @(Test-ADAnalyzerDirectoryPolicy $data $profile) ACL.REPLICATION_RIGHTS).Status
    $profile.Policy.IncludeAdministrativeReplicationRoles=$true;$ace.IdentitySid=$script:DomainSid+'-9000'
    Assert-DirectoryEqual Fail (Select-DirectoryCheck @(Test-ADAnalyzerDirectoryPolicy $data $profile) ACL.REPLICATION_RIGHTS).Status
}
Invoke-DirectoryTest 'inherit-only descendant rights are not counted as current domain-root replication rights' {
    $profile=New-DirectoryProfile;$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $true) -Profile $profile
    $data.Acl.Entries=@([pscustomobject]@{Target=$script:DomainDn;TargetType='DomainRoot';IdentitySid=($script:DomainSid+'-9000');Rights='GenericAll';AccessControlType='Allow';ObjectType=[guid]::Empty.ToString();InheritedObjectType='';IsInherited=$false;PropagationFlags='InheritOnly'})
    $checks=@(Test-ADAnalyzerDirectoryPolicy $data $profile)
    Assert-DirectoryEqual 0 @($checks | Where-Object RuleId -eq ACL.REPLICATION_RIGHTS).Count
}
Invoke-DirectoryTest 'generic AD objects with raw objectSid retain stable group identity' {
    $group=[pscustomobject]@{objectSid=($script:DomainSid+'-512');DistinguishedName='CN=Localized Name,DC=example,DC=invalid';MemberOf=@()}
    $user=[pscustomobject]@{objectSid=($script:DomainSid+'-9000');MemberOf=@($group.DistinguishedName)}
    $membership=Resolve-ADAnalyzerMembership -Object $user -Groups @($group) -DomainSid $script:DomainSid -PrivilegedSids @($script:DomainSid+'-512')
    Assert-DirectoryTrue $membership.IsPrivileged 'Raw LDAP attribute name lost the privileged SID'
    Assert-DirectoryEqual 0 $membership.Unresolved.Count
}
Write-Host ("{0} directory tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
