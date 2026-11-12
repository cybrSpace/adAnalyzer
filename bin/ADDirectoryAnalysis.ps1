# Read-only directory assessment. No managed password values are requested.
function Get-ADAnalyzerDirectoryField {
    param($InputObject,[string]$Name,$Default=$null)
    if($null -eq $InputObject){return $Default}
    if($InputObject -is [System.Collections.IDictionary]){
        if($InputObject.Contains($Name)){return $InputObject[$Name]};return $Default
    }
    $property=$InputObject.PSObject.Properties[$Name]
    if($null -ne $property){return $property.Value}
    return $Default
}
function ConvertTo-ADAnalyzerSid {
    param($Value)
    if($null -eq $Value){return $null}
    $sid=Get-ADAnalyzerDirectoryField $Value 'Value'
    if($null -ne $sid){return [string]$sid}
    return [string]$Value
}
function ConvertTo-ADAnalyzerDirectoryDate {
    param($Value,[switch]$FileTime)
    if($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)){return $null}
    try {
        if($FileTime){if([long]$Value -le 0){return $null};return [datetime]::FromFileTimeUtc([long]$Value)}
        return ([datetime]$Value).ToUniversalTime()
    }catch{return $null}
}
function Get-ADAnalyzerDirectoryTarget {
    param($Object)
    foreach($name in @('DistinguishedName','SID','ObjectGuid','SamAccountName','Name')){
        $value=Get-ADAnalyzerDirectoryField $Object $name
        if($null -ne $value -and -not [string]::IsNullOrEmpty([string]$value)){return [string]$value}
    }
    return 'Unknown'
}
function Test-ADAnalyzerClassificationAttribute {
    param([string]$Name)
    $Name -match '^[A-Za-z][A-Za-z0-9-]*$' -and $Name -notin @('unicodePwd','userPassword','dBCSPwd','ntPwdHistory','lmPwdHistory','supplementalCredentials','msDS-ManagedPassword','msDS-ManagedPasswordId','msLAPS-Password','msLAPS-EncryptedPassword','msLAPS-EncryptedPasswordHistory','msLAPS-EncryptedDSRMPassword','msLAPS-EncryptedDSRMPasswordHistory','ms-Mcs-AdmPwd')
}
function New-ADAnalyzerMembershipIndex {
    param([object[]]$Groups=@())
    $byDn=@{};$bySid=@{}
    foreach($group in $Groups){
        $dn=[string](Get-ADAnalyzerDirectoryField $group 'DistinguishedName')
        $sid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $group 'SID' (Get-ADAnalyzerDirectoryField $group 'objectSid'))
        if($dn){$byDn[$dn]=$group};if($sid){$bySid[$sid]=$group}
    }
    [pscustomobject]@{ByDn=$byDn;BySid=$bySid}
}
function Resolve-ADAnalyzerMembership {
    [CmdletBinding()]
    param($Object,[object[]]$Groups=@(),[string]$DomainSid,[string[]]$PrivilegedSids=@(),$GroupIndex)
    if($null -eq $GroupIndex){$GroupIndex=New-ADAnalyzerMembershipIndex -Groups $Groups}
    $byDn=$GroupIndex.ByDn;$bySid=$GroupIndex.BySid
    $queue=[System.Collections.Queue]::new()
    $direct=[System.Collections.Generic.List[string]]::new()
    $effective=[System.Collections.Generic.List[string]]::new()
    $unresolved=[System.Collections.Generic.List[string]]::new()
    $cycles=[System.Collections.Generic.List[string]]::new();$visited=@{}
    foreach($parent in @(Get-ADAnalyzerDirectoryField $Object 'MemberOf' @())){
        if($parent){$queue.Enqueue([pscustomobject]@{Identity=[string]$parent;Path=@()});$direct.Add([string]$parent)}
    }
    $primary=Get-ADAnalyzerDirectoryField $Object 'PrimaryGroupID'
    if($null -ne $primary){
        $objectSid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $Object 'SID' (Get-ADAnalyzerDirectoryField $Object 'objectSid'))
        $sidRoot=if($objectSid -match '^S-\d-\d+(?:-\d+)+-\d+$'){$objectSid -replace '-\d+$',''}else{$DomainSid}
        if($sidRoot){$identity='{0}-{1}' -f $sidRoot,$primary;$queue.Enqueue([pscustomobject]@{Identity=$identity;Path=@()});$direct.Add($identity)}
        else{$unresolved.Add('PrimaryGroupID:'+ $primary)}
    }
    while($queue.Count){
        $item=$queue.Dequeue();$identity=[string]$item.Identity
        $group=if($byDn.ContainsKey($identity)){$byDn[$identity]}elseif($bySid.ContainsKey($identity)){$bySid[$identity]}else{$null}
        $sid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $group 'SID' (Get-ADAnalyzerDirectoryField $group 'objectSid'))
        $canonical=if($sid){$sid}else{$identity}
        if($canonical -in @($item.Path)){$cycles.Add($canonical);continue}
        if($visited.ContainsKey($canonical)){continue};$visited[$canonical]=$true
        if($null -eq $group){
            if($identity -match '^S-\d-' -and -not $effective.Contains($identity)){$effective.Add($identity)}
            $unresolved.Add($identity);continue
        }
        if($sid -and -not $effective.Contains($sid)){$effective.Add($sid)}
        if(-not $sid){$unresolved.Add($identity+':SID')}
        foreach($parent in @(Get-ADAnalyzerDirectoryField $group 'MemberOf' @())){if($parent){$queue.Enqueue([pscustomobject]@{Identity=[string]$parent;Path=@($item.Path)+@($canonical)})}}
    }
    $privileged=@($effective | Where-Object {$_ -in $PrivilegedSids})
    [pscustomobject]@{
        DirectSids=@($direct.ToArray() | ForEach-Object {if($byDn.ContainsKey($_)){ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $byDn[$_] 'SID')}else{$_}} | Where-Object {$_} | Select-Object -Unique)
        EffectiveSids=$effective.ToArray();PrivilegedSids=$privileged;IsPrivileged=$privileged.Count -gt 0
        Unresolved=@($unresolved.ToArray() | Select-Object -Unique);Cycles=@($cycles.ToArray() | Select-Object -Unique)
        ResolutionStatus=if($unresolved.Count){'Unknown'}else{'Complete'}
    }
}
function Get-ADAnalyzerAccountType {
    [CmdletBinding()]
    param($Object,[hashtable]$Profile,$Membership)
    $classification=Get-ADAnalyzerDirectoryField $Profile 'AccountClassification' @{}
    $evidence=[System.Collections.Generic.List[object]]::new();$invalidRules=[System.Collections.Generic.List[string]]::new()
    $objectClass=[string](Get-ADAnalyzerDirectoryField $Object 'DirectoryObjectClass')
    if($objectClass -in @('msDS-GroupManagedServiceAccount','msDS-ManagedServiceAccount')){$evidence.Add([pscustomobject]@{Type='Service';Source='DirectoryObjectClass';Value=$objectClass})}
    $dn=[string](Get-ADAnalyzerDirectoryField $Object 'DistinguishedName')
    foreach($type in @('User','Service')){
        foreach($ou in @(Get-ADAnalyzerDirectoryField $classification ($type+'OUs') @())){
            if($ou -and ($dn -ieq $ou -or $dn.EndsWith(','+$ou,[StringComparison]::OrdinalIgnoreCase))){$evidence.Add([pscustomobject]@{Type=$type;Source='OU';Value=[string]$ou})}
        }
        $identities=@(Get-ADAnalyzerDirectoryField $Object 'MemberOf' @())
        if($Membership){$identities+=@($Membership.EffectiveSids)}
        foreach($group in @(Get-ADAnalyzerDirectoryField $classification ($type+'Groups') @())){
            if($group -in $identities){$evidence.Add([pscustomobject]@{Type=$type;Source='Group';Value=[string]$group})}
        }
    }
    foreach($rule in @(Get-ADAnalyzerDirectoryField $classification 'AttributeRules' @())){
        $attribute=[string](Get-ADAnalyzerDirectoryField $rule 'Attribute')
        $type=[string](Get-ADAnalyzerDirectoryField $rule 'Type')
        if(-not $attribute -or $type -notin @('User','Service')){continue}
        if(-not (Test-ADAnalyzerClassificationAttribute $attribute)){$invalidRules.Add($attribute);continue}
        $actual=Get-ADAnalyzerDirectoryField $Object $attribute
        $expected=Get-ADAnalyzerDirectoryField $rule 'Value'
        $matchType=Get-ADAnalyzerDirectoryField $rule 'Match' 'Equals'
        $matched=$false
        if($matchType -eq 'Regex'){try{$matched=[string]$actual -match [string]$expected}catch{$matched=$false;$invalidRules.Add($attribute+':Regex')}}
        else{$matched=$null -ne $actual -and [string]$actual -ieq [string]$expected}
        if($matched){$evidence.Add([pscustomobject]@{Type=$type;Source=('Attribute:'+$attribute);Value=$actual})}
    }
    $types=@($evidence.ToArray() | Select-Object -ExpandProperty Type -Unique)
    [pscustomobject]@{Type=if($types.Count -eq 1 -and -not $invalidRules.Count){$types[0]}else{'Unknown'};Evidence=$evidence.ToArray();Conflicting=$types.Count -gt 1;InvalidRules=$invalidRules.ToArray()}
}
function Invoke-ADAnalyzerDirectoryQuery {
    param([string]$Command,[hashtable]$Parameters,[string]$Key,$Coverage,$Errors,[string]$Target)
    try {
        $items=@(& $Command @Parameters -ErrorAction Stop)
        $Coverage[$Key]='Collected';return $items
    }catch{
        $Coverage[$Key]='Unreadable'
        $Errors.Add([pscustomobject]@{Collector=$Key;Target=$Target;Status='Unreadable';Message=$_.Exception.Message;ExceptionType=$_.Exception.GetType().FullName}) > $null
    }
}
function Get-ADAnalyzerSecurityAces {
    param($Descriptor,[string]$Target,[string]$TargetType)
    if($null -eq $Descriptor){return}
    if($Descriptor -is [byte[]]){
        $security=[System.DirectoryServices.ActiveDirectorySecurity]::new()
        $security.SetSecurityDescriptorBinaryForm($Descriptor);$Descriptor=$security
    }
    $access=if($Descriptor.PSObject.Methods['GetAccessRules']){$Descriptor.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])}else{Get-ADAnalyzerDirectoryField $Descriptor 'Access' @()}
    foreach($ace in $access){
        [pscustomobject]@{
            Target=$Target;TargetType=$TargetType
            IdentitySid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $ace 'IdentityReference' (Get-ADAnalyzerDirectoryField $ace 'IdentitySid'))
            Rights=[string](Get-ADAnalyzerDirectoryField $ace 'ActiveDirectoryRights' (Get-ADAnalyzerDirectoryField $ace 'Rights'))
            AccessControlType=[string](Get-ADAnalyzerDirectoryField $ace 'AccessControlType')
            ObjectType=[string](Get-ADAnalyzerDirectoryField $ace 'ObjectType')
            InheritedObjectType=[string](Get-ADAnalyzerDirectoryField $ace 'InheritedObjectType')
            IsInherited=[bool](Get-ADAnalyzerDirectoryField $ace 'IsInherited' $false)
            PropagationFlags=[string](Get-ADAnalyzerDirectoryField $ace 'PropagationFlags' 'None')
            InheritanceType=[string](Get-ADAnalyzerDirectoryField $ace 'InheritanceType' 'None')
        }
    }
}
function ConvertTo-ADAnalyzerDirectoryObject {
    param($Record,[string]$Kind,[string[]]$AdditionalProperties=@())
    $result=[ordered]@{ObjectClass=$Kind}
    foreach($name in @('ObjectGuid','DistinguishedName','SamAccountName','Name','Enabled','AdminCount','PrimaryGroupID','IsCriticalSystemObject','ProtectedFromAccidentalDeletion','ServicePrincipalNames','MemberOf','Members','ManagedBy','DNSHostName','OperatingSystem','OperatingSystemVersion','UserAccountControl','TrustedForDelegation','PrincipalsAllowedToDelegateToAccount','PrincipalsAllowedToRetrieveManagedPassword','ManagedPasswordIntervalInDays','Description')){
        $result[$name]=Get-ADAnalyzerDirectoryField $Record $name
    }
    $result['SID']=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $Record 'SID')
    foreach($name in @('BuildNumber','EsuStatus','EsuValidUntil')+$AdditionalProperties){if(Test-ADAnalyzerClassificationAttribute $name){$result[$name]=Get-ADAnalyzerDirectoryField $Record $name}}
    $result['ObjectGuid']=if($result['ObjectGuid']){[string]$result['ObjectGuid']}else{$null}
    $result['DirectoryObjectClass']=[string](Get-ADAnalyzerDirectoryField $Record 'ObjectClass')
    foreach($name in @('WhenChanged','WhenCreated','LastLogonDate','PasswordLastSet')){$result[$name]=ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record $name)}
    $result['PasswordNeverExpires']=Get-ADAnalyzerDirectoryField $Record 'PasswordNeverExpires'
    $result['SIDHistory']=@(Get-ADAnalyzerDirectoryField $Record 'SIDHistory' @() | ForEach-Object {ConvertTo-ADAnalyzerSid $_})
    $result['AllowedToDelegateTo']=@(Get-ADAnalyzerDirectoryField $Record 'msDS-AllowedToDelegateTo' @())
    $result['SupportedEncryptionTypes']=Get-ADAnalyzerDirectoryField $Record 'msDS-SupportedEncryptionTypes'
    $result['Protected']=if($null -eq $result['ProtectedFromAccidentalDeletion']){$null}else{[bool]$result['ProtectedFromAccidentalDeletion']}
    $uac=if($null -ne $result['UserAccountControl']){[long]$result['UserAccountControl']}else{0}
    $result['IsDomainController']=$Kind -eq 'Computer' -and (($uac -band 8192) -ne 0 -or $result['PrimaryGroupID'] -in @(516,521))
    $result['ResourceBasedDelegation']=@(Get-ADAnalyzerSecurityAces (Get-ADAnalyzerDirectoryField $Record 'msDS-AllowedToActOnBehalfOfOtherIdentity') ([string]$result['DistinguishedName']) 'RBCD')
    $result['LapsExpiration']=ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record 'msLAPS-PasswordExpirationTime') -FileTime
    $result['LegacyLapsExpiration']=ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record 'ms-Mcs-AdmPwdExpirationTime') -FileTime
    [pscustomobject]$result
}
function Get-ADAnalyzerHostData {
    param([string[]]$ComputerNames,[pscredential]$Credential=[pscredential]::Empty,$Errors,[ValidateRange(1,3600)][uint32]$TimeoutSeconds=30)
    foreach($computer in @($ComputerNames | Where-Object {$_} | Select-Object -Unique)){
        $session=$null;$initialErrorCount=$Errors.Count
        $data=[ordered]@{ComputerName=$computer;Status='Unknown';Services=@();OperatingSystem=$null;Patches=@();Dns=@();Smb=$null;Registry=@();AuditPolicy=[pscustomobject]@{Status='Unknown';Reason='Effective audit policy is not available from this CIM inventory'};Certificates=[pscustomobject]@{Status='Unknown';Reason='Certificate validation requires explicit endpoints and trust policy'}}
        try {
            $arguments=@{ComputerName=$computer;OperationTimeoutSec=$TimeoutSeconds;ErrorAction='Stop'}
            if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$arguments['Credential']=$Credential}
            $session=New-CimSession @arguments
            foreach($query in @(
                @{Key='Services';ClassName='Win32_Service';Filter="Name='Spooler' OR Name='W32Time'"},
                @{Key='OperatingSystem';ClassName='Win32_OperatingSystem'},
                @{Key='Patches';ClassName='Win32_QuickFixEngineering'},
                @{Key='Dns';ClassName='Win32_NetworkAdapterConfiguration';Filter='IPEnabled=True'},
                @{Key='Smb';ClassName='MSFT_SmbServerConfiguration';Namespace='root/Microsoft/Windows/SMB'}
            )){
                try {
                    $splat=@{CimSession=$session;ClassName=$query.ClassName;OperationTimeoutSec=$TimeoutSeconds;ErrorAction='Stop'}
                    if($query.ContainsKey('Filter')){$splat['Filter']=$query.Filter}
                    if($query.ContainsKey('Namespace')){$splat['Namespace']=$query.Namespace}
                    $data[$query.Key]=@(Get-CimInstance @splat)
                }catch{$Errors.Add([pscustomobject]@{Collector=('Host.'+$query.Key);Target=$computer;Status='Unknown';Message=$_.Exception.Message}) > $null}
            }
            $registry=[System.Collections.Generic.List[object]]::new()
            $settings=@(
                @{Path='SYSTEM\CurrentControlSet\Services\W32Time\Parameters';Name='NtpServer';Method='GetStringValue'},
                @{Path='SYSTEM\CurrentControlSet\Services\W32Time\Parameters';Name='Type';Method='GetStringValue'},
                @{Path='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';Name='SMB1';Method='GetDWORDValue'}
            )
            foreach($version in @('TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3')){foreach($side in @('Client','Server')){$settings+=@{Path=('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$version+'\'+$side);Name='Enabled';Method='GetDWORDValue'}}}
            foreach($setting in $settings){
                try {
                    $value=Invoke-CimMethod -CimSession $session -Namespace root/default -ClassName StdRegProv -MethodName $setting.Method -Arguments @{hDefKey=[uint32]2147483650;sSubKeyName=$setting.Path;sValueName=$setting.Name} -OperationTimeoutSec $TimeoutSeconds -ErrorAction Stop
                    $registry.Add([pscustomobject]@{Path=$setting.Path;Name=$setting.Name;Status=if($value.ReturnValue -eq 0){'Observed'}else{'Unknown'};Value=if($setting.Method -eq 'GetStringValue'){$value.sValue}else{$value.uValue};ReturnValue=$value.ReturnValue})
                }catch{$registry.Add([pscustomobject]@{Path=$setting.Path;Name=$setting.Name;Status='Unknown';Value=$null;Message=$_.Exception.Message})}
            }
            $data['Registry']=$registry.ToArray();$data['Status']=if($Errors.Count -gt $initialErrorCount){'Partial'}else{'Observed'}
        }catch{$Errors.Add([pscustomobject]@{Collector='Host';Target=$computer;Status='Unknown';Message=$_.Exception.Message}) > $null}
        finally{if($null -ne $session){Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue}}
        [pscustomobject]$data
    }
}

function Get-ADAnalyzerDirectoryData {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Context,[Parameter(Mandatory=$true)][hashtable]$Profile)
    $server=[string](Get-ADAnalyzerDirectoryField $Context 'Server')
    if([string]::IsNullOrWhiteSpace($server)){$server=[string](Get-ADAnalyzerDirectoryField $Context 'Domain')}
    if([string]::IsNullOrWhiteSpace($server)){throw 'Context.Server or Context.Domain is required'}
    $credential=Get-ADAnalyzerDirectoryField $Context 'Credential'
    $common=@{Server=$server}
    if($null -ne $credential -and $credential -ne [pscredential]::Empty){$common['Credential']=$credential}
    $coverage=[ordered]@{};$errors=[System.Collections.Generic.List[object]]::new()
    $query={param($Command,$Arguments,$Key) $splat=@{}+$common+$Arguments;@(Invoke-ADAnalyzerDirectoryQuery $Command $splat $Key $coverage $errors $server)}
    $root=@(& $query 'Get-ADRootDSE' @{} 'RootDSE') | Select-Object -First 1
    $domainIdentity=[string](Get-ADAnalyzerDirectoryField $Context 'Domain')
    if([string]::IsNullOrWhiteSpace($domainIdentity)){$domainIdentity=[string](Get-ADAnalyzerDirectoryField $root 'DefaultNamingContext' $server)}
    $domain=@(& $query 'Get-ADDomain' @{Identity=$domainIdentity} 'Domain') | Select-Object -First 1
    $domainDn=[string](Get-ADAnalyzerDirectoryField $domain 'DistinguishedName' (Get-ADAnalyzerDirectoryField $root 'DefaultNamingContext'))
    $domainSid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $domain 'DomainSID')
    $forest=@(& $query 'Get-ADForest' @{} 'Forest') | Select-Object -First 1
    $rootDomainSid=$domainSid;$forestRoot=[string](Get-ADAnalyzerDirectoryField $forest 'RootDomain')
    if($forestRoot -and $forestRoot -ine (Get-ADAnalyzerDirectoryField $domain 'DNSRoot')){
        $rootDomain=@(& $query 'Get-ADDomain' @{Identity=$forestRoot} 'ForestRootDomain') | Select-Object -First 1
        $rootDomainSid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $rootDomain 'DomainSID')
    }
    # Query schema metadata only, never managed-password attribute values.
    $featureNames=@('msLAPS-PasswordExpirationTime','ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-EncryptedPassword','ms-Mcs-AdmPwd','msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-GroupMSAMembership')
    $schema=@();$schemaDn=[string](Get-ADAnalyzerDirectoryField $root 'SchemaNamingContext')
    if($schemaDn){
        $clauses=($featureNames | ForEach-Object {'(lDAPDisplayName='+$_+')'}) -join ''
        $schema=@(& $query 'Get-ADObject' @{SearchBase=$schemaDn;LDAPFilter=('(|'+$clauses+')');Properties=@('lDAPDisplayName','schemaIDGUID')} 'FeatureSchema')
    }else{$coverage['FeatureSchema']='Unreadable'}
    $available=@($schema | ForEach-Object {[string](Get-ADAnalyzerDirectoryField $_ 'lDAPDisplayName')})
    $searchBase=[string](Get-ADAnalyzerDirectoryField $Context 'SearchBase')
    if([string]::IsNullOrWhiteSpace($searchBase)){$searchBase=$domainDn}
    $userProperties=@('ObjectGuid','SID','SIDHistory','SamAccountName','Enabled','WhenChanged','WhenCreated','LastLogonDate','PasswordLastSet','PasswordNeverExpires','AdminCount','IsCriticalSystemObject','MemberOf','PrimaryGroupID','ServicePrincipalNames','UserAccountControl','ProtectedFromAccidentalDeletion','msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes','Description')
    $computerProperties=@('ObjectGuid','SID','SIDHistory','SamAccountName','Enabled','WhenChanged','WhenCreated','LastLogonDate','PasswordLastSet','AdminCount','MemberOf','PrimaryGroupID','UserAccountControl','ServicePrincipalNames','TrustedForDelegation','IsCriticalSystemObject','ProtectedFromAccidentalDeletion','OperatingSystem','OperatingSystemVersion','DNSHostName','msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes')
    $classificationAttributes=@()
    foreach($rule in @(Get-ADAnalyzerDirectoryField (Get-ADAnalyzerDirectoryField $Profile 'AccountClassification' @{}) 'AttributeRules' @())){
        $attribute=[string](Get-ADAnalyzerDirectoryField $rule 'Attribute')
        if(Test-ADAnalyzerClassificationAttribute $attribute){$classificationAttributes+=$attribute}
        else{$errors.Add([pscustomobject]@{Collector='AccountClassification';Target=$server;Status='Invalid';Message=('Unsafe or invalid classification attribute: '+$attribute)})}
    }
    $classificationAttributes=@($classificationAttributes | Select-Object -Unique)
    $userProperties=@($userProperties+$classificationAttributes | Select-Object -Unique)
    $computerProperties=@($computerProperties+$classificationAttributes | Select-Object -Unique)
    foreach($attribute in @('msLAPS-PasswordExpirationTime','ms-Mcs-AdmPwdExpirationTime','msDS-AllowedToActOnBehalfOfOtherIdentity')){
        if($attribute -in $available){$computerProperties+=$attribute;if($attribute -eq 'msDS-AllowedToActOnBehalfOfOtherIdentity'){$userProperties+=$attribute}}
    }
    $userArgs=@{Filter='*';Properties=$userProperties};$computerArgs=@{Filter='*';Properties=$computerProperties}
    if($searchBase){$userArgs['SearchBase']=$searchBase;$computerArgs['SearchBase']=$searchBase}
    $rawUsers=@(& $query 'Get-ADUser' $userArgs 'Users')
    $rawComputers=@(& $query 'Get-ADComputer' $computerArgs 'Computers')
    # Groups are collected at domain scope even when account scanning is OU-scoped.
    $groupArgs=@{Filter='*';Properties=@('SID','ObjectGuid','MemberOf','Members','PrimaryGroupID','AdminCount','ProtectedFromAccidentalDeletion','ManagedBy')}
    if($domainDn){$groupArgs['SearchBase']=$domainDn}
    $groups=@(& $query 'Get-ADGroup' $groupArgs 'Groups')
    $trusts=@(& $query 'Get-ADTrust' @{Filter='*';Properties=@('SIDFilteringForestAware','SIDFilteringQuarantined','SelectiveAuthentication','TGTDelegation','ForestTransitive','IntraForest','Direction','TrustType','Source','Target')} 'Trusts')
    $controllers=@(& $query 'Get-ADDomainController' @{Filter='*'} 'DomainControllers')
    $serviceArgs=@{Filter='*';Properties=@('SID','ObjectGuid','SIDHistory','Enabled','AdminCount','IsCriticalSystemObject','UserAccountControl','MemberOf','PrimaryGroupID','ServicePrincipalNames','PrincipalsAllowedToRetrieveManagedPassword','ManagedPasswordIntervalInDays','DNSHostName','msDS-SupportedEncryptionTypes','WhenChanged','WhenCreated','ProtectedFromAccidentalDeletion')}
    $serviceArgs.Properties=@($serviceArgs.Properties+$classificationAttributes | Select-Object -Unique)
    if($domainDn){$serviceArgs['SearchBase']=$domainDn}
    $rawServices=@(& $query 'Get-ADServiceAccount' $serviceArgs 'ServiceAccounts')
    $settings=$null;$optional=@();$defaultPolicy=$null;$fineGrained=@();$resultant=[System.Collections.Generic.List[object]]::new()
    if($domainDn){
        $settings=@(& $query 'Get-ADObject' @{Identity=$domainDn;Properties=@('ms-DS-MachineAccountQuota','msDS-Behavior-Version')} 'DomainSettings') | Select-Object -First 1
        $defaultPolicy=@(& $query 'Get-ADDefaultDomainPasswordPolicy' @{Identity=$domainDn} 'DefaultPasswordPolicy') | Select-Object -First 1
        $fineGrained=@(& $query 'Get-ADFineGrainedPasswordPolicy' @{Filter='*';Properties=@('AppliesTo','Precedence','MinPasswordLength','PasswordHistoryCount','ComplexityEnabled','MaxPasswordAge','MinPasswordAge','LockoutThreshold','LockoutDuration','LockoutObservationWindow')} 'FineGrainedPasswordPolicies')
        $optional=@(& $query 'Get-ADOptionalFeature' @{Filter='*';Properties=@('EnabledScopes','FeatureGUID')} 'OptionalFeatures')
    }else{foreach($key in @('DomainSettings','DefaultPasswordPolicy','FineGrainedPasswordPolicies','OptionalFeatures')){$coverage[$key]='Unreadable'}}
    $users=@($rawUsers | ForEach-Object {ConvertTo-ADAnalyzerDirectoryObject $_ 'User' $classificationAttributes})
    $computers=@($rawComputers | ForEach-Object {ConvertTo-ADAnalyzerDirectoryObject $_ 'Computer' $classificationAttributes})
    $services=@($rawServices | ForEach-Object {ConvertTo-ADAnalyzerDirectoryObject $_ 'ServiceAccount' $classificationAttributes})
    $serviceIds=@($services | ForEach-Object {if($_.SID){$_.SID}else{$_.DistinguishedName}})
    $computers=@($computers | Where-Object {$(if($_.SID){$_.SID}else{$_.DistinguishedName}) -notin $serviceIds})
    $policy=Get-ADAnalyzerDirectoryField $Profile 'Policy' @{}
    $privilegedSids=@(Get-ADAnalyzerPrivilegedSids -DomainSid $domainSid -RootDomainSid $rootDomainSid -Profile $Profile)
    foreach($sid in @(Get-ADAnalyzerDirectoryField $policy 'PrivilegedSids' @())){
        $expanded=([string]$sid).Replace('{DomainSid}',[string]$domainSid).Replace('{RootDomainSid}',[string]$rootDomainSid)
        if($expanded){$privilegedSids+=$expanded}
    }
    $groupIndex=New-ADAnalyzerMembershipIndex -Groups $groups
    foreach($object in @($users)+@($computers)+@($services)){
        $sourceKey=if($object.ObjectClass -eq 'User'){'Users'}elseif($object.ObjectClass -eq 'Computer'){'Computers'}else{'ServiceAccounts'}
        $safetyStatus='Unknown'
        if($coverage[$sourceKey] -eq 'Collected'){
            # Unset optional schema flags have defined defaults only after an explicit successful query.
            if($null -eq $object.AdminCount){$object.AdminCount=0}
            if($null -eq $object.IsCriticalSystemObject){$object.IsCriticalSystemObject=$false}
            if($object.SID -and $null -ne $object.UserAccountControl -and $null -ne $object.PrimaryGroupID -and $null -ne $object.ProtectedFromAccidentalDeletion){$safetyStatus='Collected'}
        }
        $object | Add-Member NoteProperty SafetyMetadataStatus $safetyStatus -Force
        $membership=Resolve-ADAnalyzerMembership -Object $object -Groups $groups -DomainSid $domainSid -PrivilegedSids $privilegedSids -GroupIndex $groupIndex
        $type=Get-ADAnalyzerAccountType -Object $object -Profile $Profile -Membership $membership
        $object | Add-Member NoteProperty TransitiveGroups $membership.EffectiveSids -Force
        $object | Add-Member NoteProperty Membership $membership -Force
        $object | Add-Member NoteProperty Privileged $membership.IsPrivileged -Force
        $complete=$coverage['Groups'] -eq 'Collected' -and $membership.ResolutionStatus -eq 'Complete' -and $object.SID -and $null -ne $object.PrimaryGroupID
        $object | Add-Member NoteProperty PrivilegeResolutionStatus $(if($complete){'Complete'}else{'Unknown'}) -Force
        $object | Add-Member NoteProperty AccountType $type.Type -Force
        $object | Add-Member NoteProperty AccountClassification $type -Force
        $object | Add-Member NoteProperty DelegationSchemaStatus $coverage['FeatureSchema'] -Force
    }
    foreach($user in $users){
        $key='ResultantPasswordPolicy:'+$user.DistinguishedName
        $effective=@(& $query 'Get-ADUserResultantPasswordPolicy' @{Identity=$user.DistinguishedName} $key) | Select-Object -First 1
        $resultant.Add([pscustomobject]@{Target=$user.DistinguishedName;Policy=if($effective){$effective}else{$defaultPolicy};Source=if($effective){'FineGrained'}else{'DefaultDomain'};Status=$coverage[$key]})
    }
    $coverage['ResultantPasswordPolicies']=if(@($resultant | Where-Object Status -ne 'Collected').Count){'Partial'}elseif($coverage['Users'] -eq 'Collected'){'Collected'}else{'Unreadable'}
    $analysis=Get-ADAnalyzerDirectoryField $Profile 'Analysis' @{}
    $includeAcl=[bool](Get-ADAnalyzerDirectoryField $Context 'IncludeAcl' (Get-ADAnalyzerDirectoryField $analysis 'IncludeAcl' $false))
    $aces=[System.Collections.Generic.List[object]]::new();$aclTargets=[System.Collections.Generic.List[object]]::new();$guidMap=@{}
    if($includeAcl -and $domainDn){
        if($schemaDn){
            foreach($entry in @(& $query 'Get-ADObject' @{SearchBase=$schemaDn;LDAPFilter='(|(objectClass=attributeSchema)(objectClass=classSchema))';Properties=@('lDAPDisplayName','schemaIDGUID')} 'AclSchema')){
                $guid=Get-ADAnalyzerDirectoryField $entry 'schemaIDGUID'
                if($guid){try{$guidMap[([guid]$guid).ToString()]=[string](Get-ADAnalyzerDirectoryField $entry 'lDAPDisplayName')}catch{$errors.Add([pscustomobject]@{Collector='AclSchema';Target=$schemaDn;Status='Unknown';Message='Unparseable schema GUID'})}}
            }
        }
        $configDn=[string](Get-ADAnalyzerDirectoryField $root 'ConfigurationNamingContext')
        if($configDn){
            foreach($right in @(& $query 'Get-ADObject' @{SearchBase=('CN=Extended-Rights,'+$configDn);LDAPFilter='(objectClass=controlAccessRight)';Properties=@('rightsGuid','displayName')} 'ExtendedRights')){
                $guidMap[[string](Get-ADAnalyzerDirectoryField $right 'rightsGuid')]=[string](Get-ADAnalyzerDirectoryField $right 'displayName')
            }
        }
        $targets=[System.Collections.Generic.List[object]]::new()
        $targets.Add([pscustomobject]@{DN=$domainDn;Type='DomainRoot'})
        $targets.Add([pscustomobject]@{DN=('CN=AdminSDHolder,CN=System,'+$domainDn);Type='AdminSDHolder'})
        $ouBase=if($searchBase){$searchBase}else{$domainDn}
        foreach($ou in @(& $query 'Get-ADOrganizationalUnit' @{Filter='*';SearchBase=$ouBase} 'AclOUs')){$targets.Add([pscustomobject]@{DN=[string](Get-ADAnalyzerDirectoryField $ou 'DistinguishedName');Type='OU'})}
        foreach($gpo in @(& $query 'Get-ADObject' @{SearchBase=('CN=Policies,CN=System,'+$domainDn);LDAPFilter='(objectClass=groupPolicyContainer)';Properties=@('displayName')} 'AclGPOs')){$targets.Add([pscustomobject]@{DN=[string](Get-ADAnalyzerDirectoryField $gpo 'DistinguishedName');Type='GPO'})}
        foreach($target in $targets){
            $key='Acl:'+$target.DN
            $record=@(& $query 'Get-ADObject' @{Identity=$target.DN;Properties=@('nTSecurityDescriptor')} $key) | Select-Object -First 1
            $descriptor=Get-ADAnalyzerDirectoryField $record 'nTSecurityDescriptor'
            $status=$coverage[$key]
            if($status -eq 'Collected' -and $null -eq $descriptor){$status='Unreadable'}
            try{
                foreach($ace in @(Get-ADAnalyzerSecurityAces $descriptor $target.DN $target.Type)){
                    $ace | Add-Member NoteProperty ObjectTypeName (Get-ADAnalyzerDirectoryField $guidMap $ace.ObjectType $ace.ObjectType)
                    $aces.Add($ace)
                }
            }catch{$status='Unreadable';$errors.Add([pscustomobject]@{Collector='Acl';Target=$target.DN;Status='Unreadable';Message=$_.Exception.Message})}
            $aclTargets.Add([pscustomobject]@{Target=$target.DN;Type=$target.Type;Status=$status})
        }
        $coverage['Acl']=if(@($aclTargets | Where-Object Status -ne 'Collected').Count){'Partial'}else{'Collected'}
    }else{$coverage['Acl']=if($includeAcl){'Unreadable'}else{'NotConfigured'}}
    $hosts=@();$includeHosts=[bool](Get-ADAnalyzerDirectoryField $Context 'IncludeHostChecks' (Get-ADAnalyzerDirectoryField $analysis 'IncludeHostChecks' $false))
    if($includeHosts){
        $names=@($controllers | ForEach-Object {[string](Get-ADAnalyzerDirectoryField $_ 'HostName')})
        $hosts=@(Get-ADAnalyzerHostData -ComputerNames $names -Credential $credential -Errors $errors -TimeoutSeconds (Get-ADAnalyzerDirectoryField $analysis 'HostTimeoutSeconds' 30))
        $coverage['Hosts']=if(@($hosts | Where-Object Status -ne 'Observed').Count){'Partial'}elseif($hosts.Count){'Collected'}else{'Unreadable'}
    }else{$coverage['Hosts']='NotConfigured'}
    $domainDto=[pscustomobject]@{DistinguishedName=$domainDn;DNSRoot=Get-ADAnalyzerDirectoryField $domain 'DNSRoot';SID=$domainSid;RootDomainSID=$rootDomainSid;DomainMode=Get-ADAnalyzerDirectoryField $domain 'DomainMode';ForestMode=Get-ADAnalyzerDirectoryField $forest 'ForestMode';MachineAccountQuota=Get-ADAnalyzerDirectoryField $settings 'ms-DS-MachineAccountQuota';OptionalFeatures=$optional;FeatureSchema=$available;PrivilegedSids=@($privilegedSids | Select-Object -Unique)}
    [pscustomobject]@{
        Server=$server;Domain=$domainDto;Users=$users;Groups=$groups;Computers=$computers;ServiceAccounts=$services
        Objects=@($users)+@($computers)+@($services);Trusts=$trusts
        PasswordPolicies=[pscustomobject]@{Default=$defaultPolicy;FineGrained=$fineGrained;Resultant=$resultant.ToArray()}
        DomainControllers=$controllers;Acl=[pscustomobject]@{Targets=$aclTargets.ToArray();Entries=$aces.ToArray();GuidMap=$guidMap;EffectiveAccessCalculated=$false}
        Hosts=$hosts;Errors=$errors.ToArray();Coverage=$coverage
    }
}

function Add-ADAnalyzerDirectoryCheck {
    param([string]$RuleId,[string]$Status,[string]$Severity,[string]$Category,[string]$Target,$Observed,$Expected,$Evidence,[string]$Message,$Object,[string]$Applicability='Unknown')
    $splat=@{RuleId=$RuleId;Status=$Status;Severity=$Severity;Category=$Category;Target=$Target;Observed=$Observed;Expected=$Expected;Evidence=$Evidence;Message=$Message;Applicability=$Applicability}
    if($null -ne $Object){$splat['Object']=$Object}
    New-ADAnalyzerCheck @splat
}
function Test-ADAnalyzerOperatingSystemProfile {
    param($Object,[object[]]$Entries=@(),[datetimeoffset]$ReferenceTime=[datetimeoffset]::UtcNow)
    $name=[string](Get-ADAnalyzerDirectoryField $Object 'OperatingSystem')
    $version=[string](Get-ADAnalyzerDirectoryField $Object 'OperatingSystemVersion')
    $build=Get-ADAnalyzerDirectoryField $Object 'BuildNumber'
    if($null -eq $build -and $version -match '\((\d+)\)'){$build=[long]$Matches[1]}
    if($null -eq $build){$parsed=$null;if([version]::TryParse($version,[ref]$parsed) -and $parsed.Build -ge 0){$build=$parsed.Build}}
    $esu=Get-ADAnalyzerDirectoryField $Object 'EsuStatus';$esuUntil=Get-ADAnalyzerDirectoryField $Object 'EsuValidUntil'
    $results=[System.Collections.Generic.List[object]]::new()
    foreach($entry in $Entries){
        if($entry -is [string]){if($name -like $entry){$results.Add([pscustomobject]@{Status='Unknown';Reason='A name-only allowlist is not lifecycle/build support evidence';Entry=$entry})};continue}
        $pattern=[string](Get-ADAnalyzerDirectoryField $entry 'Name')
        if(-not $pattern){$results.Add([pscustomobject]@{Status='Invalid';Reason='OS profile entry requires Name';Entry=$entry});continue}
        if($name -notlike $pattern){continue}
        $versionPattern=Get-ADAnalyzerDirectoryField $entry 'VersionPattern'
        $minimum=Get-ADAnalyzerDirectoryField $entry 'MinimumBuild';$maximum=Get-ADAnalyzerDirectoryField $entry 'MaximumBuild'
        $until=Get-ADAnalyzerDirectoryField $entry 'SupportedUntil';$requireEsu=Get-ADAnalyzerDirectoryField $entry 'RequireEsu'
        $status='Pass';$reason='Explicit profile version/build/lifecycle metadata matches'
        $deadline=[datetimeoffset]::MinValue;$deadlineValid=$null -ne $until -and [datetimeoffset]::TryParse([string]$until,[ref]$deadline)
        if($null -ne $until -and -not $deadlineValid){$status='Invalid';$reason='Invalid SupportedUntil timestamp'}
        elseif($versionPattern -and $version -and $null -ne $build){
            try{if($version -notmatch [string]$versionPattern){$status='Fail';$reason='Operating-system version differs from the explicit profile'}}catch{$status='Invalid';$reason='Invalid OS VersionPattern'}
        }
        if($status -eq 'Pass' -and $null -ne $build -and (($null -ne $minimum -and [long]$build -lt [long]$minimum) -or ($null -ne $maximum -and [long]$build -gt [long]$maximum))){$status='Fail';$reason='Build lies outside the configured range'}
        if($status -eq 'Pass' -and $deadlineValid -and $deadline -lt $ReferenceTime -and $requireEsu -eq $false){$status='Fail';$reason='Configured support lifecycle has expired'}
        if($status -eq 'Pass' -and ($null -eq $build -or $null -eq $minimum -or -not $versionPattern -or -not $version -or -not $deadlineValid -or $null -eq $requireEsu)){$status='Unknown';$reason='Build, version, lifecycle or ESU applicability metadata is missing'}
        if($status -eq 'Pass' -and $requireEsu){
            $expiry=[datetimeoffset]::MinValue
            if($null -eq $esu -or $null -eq $esuUntil -or -not [datetimeoffset]::TryParse([string]$esuUntil,[ref]$expiry)){$status='Unknown';$reason='Required ESU enrollment/expiry evidence is missing'}
            elseif($esu -ne 'Active' -or $expiry -lt $ReferenceTime){$status='Fail';$reason='Required ESU evidence is inactive or expired'}
        }
        $results.Add([pscustomobject]@{Status=$status;Reason=$reason;Entry=$entry})
    }
    $status=if(-not $Entries.Count){'NotConfigured'}elseif(-not $name){'Unknown'}elseif(@($results | Where-Object Status -eq 'Invalid').Count){'Invalid'}elseif(@($results | Where-Object Status -eq 'Pass').Count){'Pass'}elseif(@($results | Where-Object Status -eq 'Unknown').Count){'Unknown'}else{'Fail'}
    [pscustomobject]@{Status=$status;Observed=[pscustomobject]@{Name=$name;Version=$version;Build=$build;EsuStatus=$esu;EsuValidUntil=$esuUntil};Expected=$Entries;Evidence=@{Matches=$results.ToArray();ReferenceTime=$ReferenceTime.ToString('o');LifecycleInferred=$false}}
}
function Test-ADAnalyzerDirectoryPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Data,[Parameter(Mandatory=$true)][hashtable]$Profile)
    $policy=Get-ADAnalyzerDirectoryField $Profile 'Policy' @{}
    $domain=Get-ADAnalyzerDirectoryField $Data 'Domain'
    $domainTarget=Get-ADAnalyzerDirectoryTarget $domain
    $coverage=Get-ADAnalyzerDirectoryField $Data 'Coverage' @{}
    foreach($key in @('Domain','Users','Groups','Computers','Trusts','DefaultPasswordPolicy','FineGrainedPasswordPolicies','ResultantPasswordPolicies','ServiceAccounts','Acl','Hosts')){
        $state=[string](Get-ADAnalyzerDirectoryField $coverage $key 'Unreadable')
        if($state -ne 'Collected'){
            $status=if($state -eq 'NotConfigured'){'NotConfigured'}elseif($state -eq 'Unreadable'){'Unreadable'}else{'Unknown'}
            Add-ADAnalyzerDirectoryCheck ('COLLECTION.'+$key.ToUpperInvariant()) $status Information Coverage $domainTarget $state 'Collected' @() ('Collection coverage: '+$key) $null
        }
    }
    $quota=Get-ADAnalyzerDirectoryField $domain 'MachineAccountQuota'
    $expectedQuota=Get-ADAnalyzerDirectoryField $policy 'MachineAccountQuota' 0
    $status=if($null -eq $quota){'Unknown'}elseif([long]$quota -gt [long]$expectedQuota){'Fail'}else{'Pass'}
    Add-ADAnalyzerDirectoryCheck 'DOMAIN.MACHINE_ACCOUNT_QUOTA' $status High Domain $domainTarget $quota $expectedQuota @() 'Configured quota; join rights may also be delegated through directory ACLs.' $null Configured
    $recycle=@(Get-ADAnalyzerDirectoryField $domain 'OptionalFeatures' @() | Where-Object {[string](Get-ADAnalyzerDirectoryField $_ 'FeatureGUID') -eq '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'})
    $recycleStatus=if((Get-ADAnalyzerDirectoryField $coverage 'OptionalFeatures') -ne 'Collected'){'Unknown'}elseif(-not $recycle.Count){'Unknown'}elseif(@(Get-ADAnalyzerDirectoryField $recycle[0] 'EnabledScopes' @()).Count){'Pass'}else{'Fail'}
    Add-ADAnalyzerDirectoryCheck 'DOMAIN.RECYCLE_BIN' $recycleStatus Medium Domain $domainTarget @($recycle | ForEach-Object {Get-ADAnalyzerDirectoryField $_ 'EnabledScopes'}) 'Recycle Bin optional feature enabled' @() 'This check observes optional-feature configuration and does not enable it.' $null Configured
    $allObjects=@(Get-ADAnalyzerDirectoryField $Data 'Objects' @())
    if(-not $allObjects.Count){$allObjects=@(Get-ADAnalyzerDirectoryField $Data 'Users' @())+@(Get-ADAnalyzerDirectoryField $Data 'Computers' @())+@(Get-ADAnalyzerDirectoryField $Data 'ServiceAccounts' @())}
    $groups=@(Get-ADAnalyzerDirectoryField $Data 'Groups' @());$sidLookup=@{};$spns=@{}
    $groupIndex=New-ADAnalyzerMembershipIndex -Groups $groups
    foreach($object in $allObjects+$groups){
        $sid=ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $object 'SID');if($sid){$sidLookup[$sid]=$object}
    }
    foreach($object in $allObjects){
        $target=Get-ADAnalyzerDirectoryTarget $object
        $kind=[string](Get-ADAnalyzerDirectoryField $object 'ObjectClass')
        $classification=[string](Get-ADAnalyzerDirectoryField $object 'AccountType' 'Unknown')
        if($kind -in @('User','ServiceAccount')){
            $classificationEvidence=Get-ADAnalyzerDirectoryField $object 'AccountClassification'
            $classificationStatus=if(@(Get-ADAnalyzerDirectoryField $classificationEvidence 'InvalidRules' @()).Count){'Invalid'}elseif($classification -eq 'Unknown'){'Unknown'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck 'ACCOUNT.CLASSIFICATION' $classificationStatus Information Account $target $classification 'Explicit User or Service classification' $classificationEvidence 'No username-based classification is used.' $object
        }
        if($kind -in @('User','Computer')){
            $inactiveKey=if($kind -eq 'Computer'){'ComputerInactivityDays'}else{'UserInactivityDays'}
            $inactiveDays=Get-ADAnalyzerDirectoryField $policy $inactiveKey 60
            $last=ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $object 'LastLogonDate')
            $created=ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $object 'WhenCreated')
            $age=if($last){[math]::Floor(([datetime]::UtcNow-$last).TotalDays)}elseif($created){[math]::Floor(([datetime]::UtcNow-$created).TotalDays)}else{$null}
            $enabled=Get-ADAnalyzerDirectoryField $object 'Enabled'
            $status=if($null -eq $enabled -or $null -eq $age){'Unknown'}elseif(-not $enabled){'NotApplicable'}elseif($age -ge $inactiveDays){'Fail'}else{'Pass'}
            $rule=if($kind -eq 'Computer'){'COMPUTER.INACTIVE'}else{'ACCOUNT.INACTIVE'}
            Add-ADAnalyzerDirectoryCheck $rule $status Medium Account $target $age $inactiveDays @{LastLogonDate=$last;WhenCreated=$created;Signal='Replicated LastLogonDate, or creation age when no logon is recorded';Approximate=$true} 'Inactivity is a signal, not authorization to disable this object.' $object Applicable
        }
        if($kind -eq 'User'){
            $passwordDate=ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $object 'PasswordLastSet')
            $maxAge=if($classification -eq 'User'){Get-ADAnalyzerDirectoryField $policy 'UserPasswordAgeDays'}elseif($classification -eq 'Service'){Get-ADAnalyzerDirectoryField $policy 'ServicePasswordAgeDays'}else{$null}
            $passwordAge=if($passwordDate){[math]::Floor(([datetime]::UtcNow-$passwordDate).TotalDays)}else{$null}
            $status=if($null -eq $maxAge -or $classification -eq 'Unknown' -or $null -eq $passwordAge){'Unknown'}elseif($maxAge -eq 0){'NotConfigured'}elseif($passwordAge -gt $maxAge){'Fail'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck 'ACCOUNT.PASSWORD_AGE' $status Medium Account $target $passwordAge $maxAge @{AccountType=$classification;PasswordStrengthEvaluated=$false} 'Account age policy is profile-controlled and is not a password-strength test.' $object Configured
            $never=Get-ADAnalyzerDirectoryField $object 'PasswordNeverExpires'
            $allowed=Get-ADAnalyzerDirectoryField $policy 'AllowPasswordNeverExpires'
            $status=if($null -eq $never -or $null -eq $allowed){'Unknown'}elseif($never -and -not $allowed){'Fail'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck 'ACCOUNT.PASSWORD_NEVER_EXPIRES' $status Medium Account $target $never $allowed @() 'Exceptions and account purpose require explicit profile decisions.' $object Configured
        }
        $uac=Get-ADAnalyzerDirectoryField $object 'UserAccountControl'
        $unconstrained=Get-ADAnalyzerDirectoryField $object 'TrustedForDelegation'
        if($null -ne $uac){$unconstrained=([long]$uac -band 524288) -ne 0}
        $protocol=if($null -ne $uac){([long]$uac -band 16777216) -ne 0}else{$null}
        $targets=@(Get-ADAnalyzerDirectoryField $object 'AllowedToDelegateTo' @())
        $approved=@(@(Get-ADAnalyzerDirectoryField $Profile 'ApprovedDelegationTargets' @())+@(Get-ADAnalyzerDirectoryField $policy 'ApprovedDelegationTargets' @()) | Select-Object -Unique)
        $unapproved=@($targets | Where-Object {$_ -notin $approved})
        $rbcd=@(Get-ADAnalyzerDirectoryField $object 'ResourceBasedDelegation' @() | Where-Object {$_.AccessControlType -eq 'Allow'})
        $unapprovedRbcd=@($rbcd | Where-Object {$_.IdentitySid -notin $approved})
        $delegationStatus=if($unconstrained -or $protocol -or $unapproved.Count -or $unapprovedRbcd.Count){'Fail'}elseif($null -eq $unconstrained -and $null -eq $protocol){'Unknown'}elseif((Get-ADAnalyzerDirectoryField $object 'DelegationSchemaStatus') -ne 'Collected'){'Unknown'}else{'Pass'}
        Add-ADAnalyzerDirectoryCheck 'DELEGATION.EXPOSURE' $delegationStatus High Delegation $target @{Unconstrained=$unconstrained;ProtocolTransition=$protocol;ConstrainedTargets=$targets;ResourceBasedPrincipals=$rbcd} $approved @{EffectiveAccessCalculated=$false} 'Review delegation configuration; ACEs do not constitute a complete effective-access calculation.' $object Configured
        if($null -ne $uac){
            foreach($flag in @(@{Rule='ACCOUNT.PASSWORD_NOT_REQUIRED';Mask=32},@{Rule='KERBEROS.PREAUTH_NOT_REQUIRED';Mask=4194304},@{Rule='KERBEROS.DES_ONLY';Mask=2097152},@{Rule='ACCOUNT.REVERSIBLE_ENCRYPTION';Mask=128})){
                $set=([long]$uac -band $flag.Mask) -ne 0
                $allowed=$flag.Rule -eq 'ACCOUNT.REVERSIBLE_ENCRYPTION' -and (Get-ADAnalyzerDirectoryField $policy 'AllowReversibleEncryption' $false)
                Add-ADAnalyzerDirectoryCheck $flag.Rule $(if($set -and -not $allowed){'Fail'}else{'Pass'}) High Account $target $set $allowed @{UserAccountControl=$uac} 'Configured account-control flag.' $object Configured
            }
        }
        $enc=Get-ADAnalyzerDirectoryField $object 'SupportedEncryptionTypes'
        $encStatus=if($null -eq $enc -or [long]$enc -eq 0){'Unknown'}elseif(([long]$enc -band 24) -eq 0){'Fail'}else{'Pass'}
        Add-ADAnalyzerDirectoryCheck 'KERBEROS.ENCRYPTION_METADATA' $encStatus Medium Kerberos $target $enc 'AES flags in explicit supported-encryption metadata' @{PasswordStrengthEvaluated=$false} 'Missing or zero metadata can inherit domain behavior and does not prove weak keys.' $object Configured
        foreach($spn in @(Get-ADAnalyzerDirectoryField $object 'ServicePrincipalNames' @())){
            if(-not $spn){continue};$key=([string]$spn).ToLowerInvariant()
            if(-not $spns.ContainsKey($key)){$spns[$key]=[System.Collections.Generic.List[object]]::new()}
            $spns[$key].Add($object)
        }
        $history=@(Get-ADAnalyzerDirectoryField $object 'SIDHistory' @())
        if($history.Count){
            $privileged=@(Get-ADAnalyzerDirectoryField $domain 'PrivilegedSids' @())
            $knownPrivileged=[System.Collections.Generic.List[string]]::new();$unresolved=[System.Collections.Generic.List[string]]::new()
            foreach($sid in $history){
                if($sid -in $privileged){$knownPrivileged.Add([string]$sid)}
                elseif($sidLookup.ContainsKey([string]$sid)){
                    $historical=$sidLookup[[string]$sid]
                    $membership=Resolve-ADAnalyzerMembership -Object $historical -Groups $groups -DomainSid $domain.SID -PrivilegedSids $privileged -GroupIndex $groupIndex
                    if($membership.IsPrivileged -or (Get-ADAnalyzerDirectoryField $historical 'Privileged' $false)){$knownPrivileged.Add([string]$sid)}
                    elseif($membership.ResolutionStatus -ne 'Complete'){$unresolved.Add([string]$sid)}
                }else{$unresolved.Add([string]$sid)}
            }
            $status=if($knownPrivileged.Count){'Fail'}elseif($unresolved.Count){'Unknown'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck 'SIDHISTORY.PRIVILEGED' $status High Identity $target $history 'No privileged historical SIDs' @{Privileged=$knownPrivileged.ToArray();Unresolved=$unresolved.ToArray()} 'Unresolved historical SIDs are not declared invalid.' $object Configured
        }
        if($kind -eq 'Computer'){
            $schema=@(Get-ADAnalyzerDirectoryField $domain 'FeatureSchema' @())
            $lapsKnown='msLAPS-PasswordExpirationTime' -in $schema -or 'ms-Mcs-AdmPwdExpirationTime' -in $schema
            $expiry=Get-ADAnalyzerDirectoryField $object 'LapsExpiration'
            if($null -eq $expiry){$expiry=Get-ADAnalyzerDirectoryField $object 'LegacyLapsExpiration'}
            $require=Get-ADAnalyzerDirectoryField $policy 'RequireLaps'
            $status=if($null -eq $require){'NotConfigured'}elseif(-not $require -or (Get-ADAnalyzerDirectoryField $object 'IsDomainController' $false)){'NotApplicable'}elseif(-not $lapsKnown -or $null -eq $expiry){'Unknown'}elseif([datetime]$expiry -lt [datetime]::UtcNow){'Fail'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck 'LAPS.ROTATION_METADATA' $status Medium LAPS $target $expiry 'Present, unexpired LAPS rotation metadata' @{SecretValuesRead=$false;SchemaAvailable=$lapsKnown;DomainControllerRequiresSeparateDsrmAssessment=$object.IsDomainController} 'Metadata is not proof of effective retrieval permissions or successful rotation.' $object Configured
            $osResult=Test-ADAnalyzerOperatingSystemProfile -Object $object -Entries @(Get-ADAnalyzerDirectoryField $policy 'SupportedOperatingSystems' @())
            Add-ADAnalyzerDirectoryCheck 'COMPUTER.OS_POLICY' $osResult.Status Medium Host $target $osResult.Observed $osResult.Expected $osResult.Evidence 'Support requires explicit version/build/lifecycle metadata and ESU evidence when required.' $object Configured
        }
        if($classification -eq 'Service'){
            $required=Get-ADAnalyzerDirectoryField $policy 'RequireGmsaForServiceAccounts' $false
            $managed=$object.DirectoryObjectClass -in @('msDS-GroupManagedServiceAccount','msDS-ManagedServiceAccount')
            Add-ADAnalyzerDirectoryCheck 'SERVICE_ACCOUNT.MANAGED_IDENTITY' $(if(-not $required){'NotApplicable'}elseif($managed){'Pass'}else{'Fail'}) Medium ServiceAccount $target $object.DirectoryObjectClass 'Managed service account when required by profile' @{RetrievalPrincipals=Get-ADAnalyzerDirectoryField $object 'PrincipalsAllowedToRetrieveManagedPassword';IntervalDays=Get-ADAnalyzerDirectoryField $object 'ManagedPasswordIntervalInDays';SecretValuesRead=$false} 'Managed-account configuration metadata; managed password values are never read.' $object Configured
            if($managed){
                $principals=@(Get-ADAnalyzerDirectoryField $object 'PrincipalsAllowedToRetrieveManagedPassword' @() | ForEach-Object {ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $_ 'SID' $_)})
                $approvedReaders=@(Get-ADAnalyzerDirectoryField $policy 'ApprovedGmsaReaderSids' @())
                $unresolvedReaders=@($principals | Where-Object {$_ -notmatch '^S-\d-'})
                $readerStatus=if(-not $approvedReaders.Count){'NotConfigured'}elseif(-not $principals.Count -or $unresolvedReaders.Count){'Unknown'}elseif(@($principals | Where-Object {$_ -notin $approvedReaders}).Count){'Fail'}else{'Pass'}
                Add-ADAnalyzerDirectoryCheck 'GMSA.RETRIEVAL_PRINCIPALS' $readerStatus High ServiceAccount $target $principals $approvedReaders @{Unresolved=$unresolvedReaders;EffectiveAccessCalculated=$false;SecretValuesRead=$false} 'Configured retrieval-principal metadata; nested tokens and deny precedence are not an effective-access calculation.' $object Configured
            }
        }
    }
    foreach($key in $spns.Keys){
        $owners=@($spns[$key] | ForEach-Object {Get-ADAnalyzerDirectoryTarget $_} | Select-Object -Unique)
        if($owners.Count -gt 1){Add-ADAnalyzerDirectoryCheck 'SPN.DUPLICATE' Fail High Kerberos $key $owners 'One owner per SPN in the collected scope' @{Scope=$Data.Server} 'Duplicate SPN owners require review, without inferring password strength.' $null Configured}
    }
    foreach($trust in @(Get-ADAnalyzerDirectoryField $Data 'Trusts' @())){
        $intraForest=Get-ADAnalyzerDirectoryField $trust 'IntraForest'
        $forestTrust=Get-ADAnalyzerDirectoryField $trust 'ForestTransitive'
        $filtering=if($forestTrust){Get-ADAnalyzerDirectoryField $trust 'SIDFilteringForestAware'}else{Get-ADAnalyzerDirectoryField $trust 'SIDFilteringQuarantined'}
        $status=if($intraForest -eq $true){'NotApplicable'}elseif($null -eq $intraForest -or $null -eq $forestTrust -or $null -eq $filtering){'Unknown'}elseif([bool]$filtering){'Pass'}else{'Fail'}
        Add-ADAnalyzerDirectoryCheck 'TRUST.SID_FILTERING' $status High Trust ([string](Get-ADAnalyzerDirectoryField $trust 'Target' (Get-ADAnalyzerDirectoryField $trust 'Name'))) $filtering $true @{IntraForest=$intraForest;Direction=Get-ADAnalyzerDirectoryField $trust 'Direction';Type=Get-ADAnalyzerDirectoryField $trust 'TrustType';SelectiveAuthentication=Get-ADAnalyzerDirectoryField $trust 'SelectiveAuthentication';TGTDelegation=Get-ADAnalyzerDirectoryField $trust 'TGTDelegation'} 'Boundary SID filtering is not applied to normal intra-forest parent/child trusts.' $null Configured
    }
    $acl=Get-ADAnalyzerDirectoryField $Data 'Acl'
    $approvedReplication=@(@(Get-ADAnalyzerDirectoryField $Profile 'ApprovedReplicationSids' @())+@(Get-ADAnalyzerDirectoryField $policy 'ApprovedReplicationSids' @()) | Select-Object -Unique)
    if($domain.SID){$approvedReplication+=($domain.SID+'-516')};$approvedReplication+='S-1-5-9'
    if(Get-ADAnalyzerDirectoryField $policy 'IncludeAdministrativeReplicationRoles' $true) {
        $approvedReplication+=@('S-1-5-18','S-1-5-32-544')
        if($domain.SID){$approvedReplication+=($domain.SID+'-512')}
        if($domain.RootDomainSID){$approvedReplication+=($domain.RootDomainSID+'-519')}
    }
    $replication=@{};$seenAces=@{}
    foreach($ace in @(Get-ADAnalyzerDirectoryField $acl 'Entries' @())){
        if($ace.AccessControlType -ne 'Allow' -or -not $ace.IdentitySid){continue}
        $aceKey=(@($ace.Target,$ace.IdentitySid,$ace.ObjectType,$ace.Rights,$ace.InheritedObjectType,[string]$ace.IsInherited,[string]$ace.PropagationFlags,[string]$ace.InheritanceType) -join '|')
        if($seenAces.ContainsKey($aceKey)){continue};$seenAces[$aceKey]=$true
        if($ace.TargetType -eq 'DomainRoot' -and [string]$ace.PropagationFlags -notmatch 'InheritOnly'){
            if(-not $replication.ContainsKey($ace.IdentitySid)){$replication[$ace.IdentitySid]=@{Changes=$false;All=$false;Evidence=[System.Collections.Generic.List[object]]::new()}}
            $grant=$replication[$ace.IdentitySid]
            $allRights=$ace.Rights -match 'GenericAll' -or ($ace.Rights -match 'ExtendedRight' -and (!$ace.ObjectType -or $ace.ObjectType -eq ([guid]::Empty).ToString()))
            if($allRights -or ($ace.Rights -match 'ExtendedRight' -and $ace.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')){$grant.Changes=$true}
            if($allRights -or ($ace.Rights -match 'ExtendedRight' -and $ace.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')){$grant.All=$true}
            $grant.Evidence.Add($ace)
        }
        if($ace.Rights -match 'GenericAll|WriteDacl|WriteOwner' -and $ace.IdentitySid -notin @($domain.PrivilegedSids)){
            Add-ADAnalyzerDirectoryCheck 'ACL.DELEGATED_CONTROL' Fail High ACL $aceKey $ace @{ApprovedPrivilegedSids=$domain.PrivilegedSids} @{EffectiveAccessCalculated=$false} 'Potential broad delegated control; ACE order, deny rules and token semantics still require review.' $null Configured
        }
        if($ace.ObjectTypeName -in @('msLAPS-Password','msLAPS-EncryptedPassword','msLAPS-EncryptedPasswordHistory','msLAPS-EncryptedDSRMPassword','ms-Mcs-AdmPwd') -and $ace.Rights -match 'ReadProperty|ExtendedRight|GenericRead|GenericAll'){
            $approvedReaders=@(Get-ADAnalyzerDirectoryField $policy 'ApprovedLapsReaderSids' @())
            $readerStatus=if(-not $approvedReaders.Count){'NotConfigured'}elseif($ace.IdentitySid -in $approvedReaders){'Pass'}else{'Fail'}
            Add-ADAnalyzerDirectoryCheck 'LAPS.ATTRIBUTE_READ_ACL' $readerStatus High ACL $aceKey $ace $approvedReaders @{EffectiveAccessCalculated=$false;ConfidentialAttributeAccessCalculated=$false;DecryptionPermissionsCalculated=$false} 'An allow ACE references LAPS data; this does not establish plaintext retrieval or effective access.' $null Configured
        }
    }
    foreach($sid in $replication.Keys){
        $grant=$replication[$sid]
        if($grant.Changes -and $grant.All){
            Add-ADAnalyzerDirectoryCheck 'ACL.REPLICATION_RIGHTS' $(if($sid -in $approvedReplication){'Pass'}else{'Fail'}) Critical ACL ($domainTarget+'|SID='+$sid) $sid $approvedReplication @{Aces=$grant.Evidence.ToArray();EffectiveAccessCalculated=$false} 'Direct allow ACEs expose replication capabilities; this is not complete effective access.' $null Configured
        }
    }
    $effective=Get-ADAnalyzerDirectoryField (Get-ADAnalyzerDirectoryField $Data 'PasswordPolicies') 'Resultant' @()
    foreach($entry in @($effective)){
        $password=$entry.Policy
        foreach($spec in @(
            @{Rule='PASSWORD.MIN_LENGTH';Field='MinPasswordLength';Profile='MinimumPasswordLength';Mode='Minimum'},
            @{Rule='PASSWORD.LOCKOUT_THRESHOLD';Field='LockoutThreshold';Profile='LockoutThreshold';Mode='MaximumNonzero'},
            @{Rule='PASSWORD.HISTORY';Field='PasswordHistoryCount';Profile='PasswordHistorySize';Mode='Minimum'},
            @{Rule='PASSWORD.COMPLEXITY';Field='ComplexityEnabled';Profile='PasswordComplexity';Mode='Equal'},
            @{Rule='PASSWORD.REVERSIBLE_ENCRYPTION';Field='ReversibleEncryptionEnabled';Profile='AllowReversibleEncryption';Mode='Allow'}
        )){
            $expected=Get-ADAnalyzerDirectoryField $policy $spec.Profile
            $actual=Get-ADAnalyzerDirectoryField $password $spec.Field
            $status=if($null -eq $expected -or ($spec.Mode -eq 'MaximumNonzero' -and $expected -eq 0)){'NotConfigured'}elseif($entry.Status -ne 'Collected' -or $null -eq $actual){'Unknown'}elseif($spec.Mode -eq 'Minimum' -and $actual -lt $expected){'Fail'}elseif($spec.Mode -eq 'MaximumNonzero' -and ($actual -eq 0 -or $actual -gt $expected)){'Fail'}elseif($spec.Mode -eq 'Equal' -and $actual -ne $expected){'Fail'}elseif($spec.Mode -eq 'Allow' -and $actual -and -not $expected){'Fail'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck $spec.Rule $status Medium PasswordPolicy $entry.Target $actual $expected @{PolicySource=$entry.Source;PolicyDN=Get-ADAnalyzerDirectoryField $password 'DistinguishedName'} 'Effective/default policy metadata; actual password content is not inspected.' $null Applicable
        }
        foreach($spec in @(
            @{Rule='PASSWORD.LOCKOUT_DURATION';Field='LockoutDuration';Profile='LockoutDurationMinutes';Unit='Minutes';Zero='Unlimited'},
            @{Rule='PASSWORD.LOCKOUT_RESET';Field='LockoutObservationWindow';Profile='ResetLockoutMinutes';Unit='Minutes';Zero='Normal'},
            @{Rule='PASSWORD.MIN_AGE';Field='MinPasswordAge';Profile='MinimumPasswordAgeDays';Unit='Days';Zero='Normal'},
            @{Rule='PASSWORD.MAX_AGE';Field='MaxPasswordAge';Profile='MaximumPasswordAgeDays';Unit='Days';Zero='Never'}
        )){
            $expected=Get-ADAnalyzerDirectoryField $policy $spec.Profile
            $raw=Get-ADAnalyzerDirectoryField $password $spec.Field;$actual=$null
            if($null -ne $raw){try{$span=[timespan]$raw;$actual=if($spec.Unit -eq 'Days'){$span.TotalDays}else{$span.TotalMinutes}}catch{}}
            $allowNever=Get-ADAnalyzerDirectoryField $policy 'AllowPasswordNeverExpires' $false
            $status=if($null -eq $expected){'NotConfigured'}elseif($entry.Status -ne 'Collected' -or $null -eq $actual){'Unknown'}elseif($spec.Zero -eq 'Unlimited' -and $actual -eq 0){'Pass'}elseif($spec.Zero -eq 'Never' -and $actual -eq 0 -and $allowNever){'Pass'}elseif($spec.Zero -eq 'Never' -and $expected -eq 0){'NotConfigured'}elseif($spec.Zero -eq 'Never' -and ($actual -eq 0 -or $actual -gt $expected)){'Fail'}elseif($spec.Zero -ne 'Never' -and $actual -lt $expected){'Fail'}else{'Pass'}
            Add-ADAnalyzerDirectoryCheck $spec.Rule $status Medium PasswordPolicy $entry.Target $actual $expected @{PolicySource=$entry.Source;ZeroSemantics=$spec.Zero;AllowPasswordNeverExpires=$allowNever} 'Durations use explicit zero-value semantics.' $null Applicable
        }
    }
    foreach($hostRecord in @(Get-ADAnalyzerDirectoryField $Data 'Hosts' @())){
        Add-ADAnalyzerDirectoryCheck 'HOST.OBSERVATIONS' Unknown Information Host $hostRecord.ComputerName $hostRecord 'Explicit host baseline and effective-state validation' @{ObservedOnly=$true} 'CIM and registry observations are not implied effective compliance.' $null Unknown
    }
}
