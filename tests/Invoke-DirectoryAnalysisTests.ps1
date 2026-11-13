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
$script:ExpectedDirectoryCredential=$script:Credential
$script:DriveEvents=[Collections.Generic.List[object]]::new();$script:DriveConnections=@{};$script:DriveFailure=''
function New-PSDrive {
    param($Server,$Name,$PSProvider,$Root,$Credential,$Scope,$ErrorAction,[switch]$WhatIf,[switch]$Confirm)
    $script:DriveEvents.Add([pscustomobject]@{Action='Create';Name=$Name;Parameters=@{}+$PSBoundParameters;CallerPath=(Microsoft.PowerShell.Management\Get-Location).Path})
    if($script:DriveFailure -eq 'Create'){throw 'fixture drive creation failure'}
    $null=Microsoft.PowerShell.Management\New-PSDrive -Name $Name -PSProvider FileSystem -Root $RepositoryRoot -Scope Script -ErrorAction Stop -WhatIf:$false -Confirm:$false
    $script:DriveConnections[$Name]=[pscustomobject]@{Credential=$(if($PSBoundParameters.ContainsKey('Credential')){$Credential}else{[pscredential]::Empty});CallerPath=(Microsoft.PowerShell.Management\Get-Location).Path}
    [pscustomobject]@{Name=$Name;Provider=[pscustomobject]@{Name='ActiveDirectory'}}
}
function Set-Location {
    param($LiteralPath,$Path,$ErrorAction)
    $destination=if($PSBoundParameters.ContainsKey('LiteralPath')){$LiteralPath}else{$Path}
    $entering=@($script:DriveConnections.Keys | Where-Object {$destination -eq ($_+':')}).Count -gt 0
    $restoring=@($script:DriveConnections.Values | Where-Object {$_.CallerPath -eq $destination}).Count -gt 0
    if($entering -and $script:DriveFailure -eq 'Enter'){throw 'fixture drive entry failure'}
    if($restoring -and $script:DriveFailure -in 'Restore','Both'){throw 'fixture drive restoration failure'}
    Microsoft.PowerShell.Management\Set-Location -LiteralPath $destination -ErrorAction Stop
}
function Remove-PSDrive {
    param($Name,$ErrorAction,[switch]$Force,[switch]$WhatIf,[switch]$Confirm)
    $script:DriveEvents.Add([pscustomobject]@{Action='Remove';Name=$Name;Force=[bool]$Force})
    if($script:DriveFailure -in 'Remove','Both'){throw 'fixture drive removal failure'}
    Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Force:$Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
    $script:DriveConnections.Remove($Name)
}
$script:Queries=[System.Collections.Generic.List[object]]::new()
$script:Denied='';$script:IncludeLapsSchema=$true;$script:HostUnavailable=$false;$script:DeniedHostClass=''
$script:ServiceAccount=$null
$script:IncludePsoSchema=$false;$script:FineGrainedFixture=@();$script:ResultantFixture=$null
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
    $driveName=(Microsoft.PowerShell.Management\Get-Location).Drive.Name
    $effectiveCredential=if($Bound.ContainsKey('Credential')){$Bound['Credential']}elseif($script:DriveConnections.ContainsKey($driveName)){$script:DriveConnections[$driveName].Credential}else{[pscredential]::Empty}
    $script:Queries.Add([pscustomobject]@{Command=$Command;Parameters=$copy;Drive=$driveName;EffectiveCredential=$effectiveCredential})
    if($Bound['Server'] -ne 'dc.example.invalid'){throw "Missing explicit server for $Command"}
    if($effectiveCredential -ne $script:ExpectedDirectoryCredential){throw "Missing pinned credential for $Command"}
    if($script:Denied -eq $Command){throw "fixture denied: $Command"}
    if($script:DriveFailure -eq 'Drift' -and $Command -eq 'Get-ADForest' -and $script:DriveConnections.ContainsKey($driveName)){
        Microsoft.PowerShell.Management\Set-Location -LiteralPath $script:DriveConnections[$driveName].CallerPath -ErrorAction Stop
    }
}
function Get-ADRootDSE {param($Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADRootDSE' $PSBoundParameters;[pscustomobject]@{DefaultNamingContext=$script:DomainDn;SchemaNamingContext=('CN=Schema,CN=Configuration,'+$script:DomainDn);ConfigurationNamingContext=('CN=Configuration,'+$script:DomainDn)}}
function Get-ADDomain {param($Identity,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADDomain' $PSBoundParameters;[pscustomobject]@{DistinguishedName=$script:DomainDn;DNSRoot='example.invalid';DomainSID=$script:DomainSid;DomainMode='fixture'}}
function Get-ADForest {param($Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADForest' $PSBoundParameters;[pscustomobject]@{RootDomain='example.invalid';ForestMode='fixture'}}
function Select-RequestedDirectoryFixture($Record,$Properties) {
    if($null -eq $Record){return}
    $result=[ordered]@{}
    foreach($property in $Record.PSObject.Properties){
        if($property.Name -ieq 'SIDHistory' -and 'SIDHistory' -notin $Properties){continue}
        if($property.Name -ieq 'msDS-ResultantPSO' -and 'msDS-ResultantPSO' -notin $Properties){continue}
        $result[$property.Name]=$property.Value
    }
    [pscustomobject]$result
}
function Get-ADUser {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADUser' $PSBoundParameters;foreach($record in @($script:User)){Select-RequestedDirectoryFixture $record $Properties}}
function Get-ADComputer {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADComputer' $PSBoundParameters; Select-RequestedDirectoryFixture $script:Computer $Properties}
function Get-ADGroup {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADGroup' $PSBoundParameters; $script:Groups}
function Get-ADTrust {param($Filter,$Properties,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADTrust' $PSBoundParameters;[pscustomobject]@{Name='partner.invalid';Target='partner.invalid';IntraForest=$false;ForestTransitive=$false;SIDFilteringQuarantined=$false;TrustType='External'}}
function Get-ADDomainController {param($Filter,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADDomainController' $PSBoundParameters;[pscustomobject]@{HostName='dc.example.invalid'}}
function Get-ADServiceAccount {param($Filter,$Properties,$SearchBase,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADServiceAccount' $PSBoundParameters; Select-RequestedDirectoryFixture $script:ServiceAccount $Properties}
function Get-ADDefaultDomainPasswordPolicy {param($Identity,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADDefaultDomainPasswordPolicy' $PSBoundParameters;$script:PasswordPolicy}
function Get-ADFineGrainedPasswordPolicy {
    param($Filter,$Properties,$Server,$Credential,$ErrorAction)
    Register-DirectoryQuery 'Get-ADFineGrainedPasswordPolicy' $PSBoundParameters
    foreach($row in @($script:FineGrainedFixture)){
        $projected=[ordered]@{};foreach($property in $row.PSObject.Properties){if($property.Name -in @('DistinguishedName','Name','ObjectGuid')+@($Properties)){$projected[$property.Name]=$property.Value}}
        [pscustomobject]$projected
    }
}
function Get-ADUserResultantPasswordPolicy {param($Identity,$Server,$Credential,$ErrorAction) Register-DirectoryQuery 'Get-ADUserResultantPasswordPolicy' $PSBoundParameters;$script:ResultantFixture}
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
        if($script:IncludePsoSchema){[pscustomobject]@{lDAPDisplayName='msDS-ResultantPSO';schemaIDGUID=([guid]'33333333-2222-3333-4444-555555555555').ToByteArray()}}
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

Invoke-DirectoryTest 'modern bulk collection defaults to an owned AD provider drive with pinned context' {
    $script:DriveEvents.Clear();$script:Queries.Clear();$before=(Get-Location).Path
    $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
    $created=@($script:DriveEvents | Where-Object Action -eq Create);$removed=@($script:DriveEvents | Where-Object Action -eq Remove)
    Assert-DirectoryEqual 1 $created.Count;Assert-DirectoryEqual 1 $removed.Count
    Assert-DirectoryEqual ActiveDirectory $created[0].Parameters.PSProvider;Assert-DirectoryEqual Local $created[0].Parameters.Scope
    Assert-DirectoryEqual dc.example.invalid $created[0].Parameters.Server;Assert-DirectoryEqual $script:DomainDn $created[0].Parameters.Root
    Assert-DirectoryEqual $script:Credential $created[0].Parameters.Credential
    Assert-DirectoryEqual $created[0].Name $removed[0].Name;Assert-DirectoryEqual $true $removed[0].Force
    foreach($query in @($script:Queries | Select-Object -Skip 2)){
        Assert-DirectoryEqual $created[0].Name $query.Drive
        Assert-DirectoryTrue (-not $query.Parameters.ContainsKey('Credential')) 'Bulk query bypassed the drive credential context'
        Assert-DirectoryEqual $script:Credential $query.EffectiveCredential
    }
    Assert-DirectoryEqual $before (Get-Location).Path
    Assert-DirectoryEqual PSDrive $data.DirectoryConnection.Mode;Assert-DirectoryEqual Connected $data.DirectoryConnection.Status
    Assert-DirectoryEqual 0 @($script:DriveConnections.Keys).Count
    Assert-DirectoryTrue (-not (Get-PSDrive -Name $created[0].Name -ErrorAction SilentlyContinue)) 'Owned drive leaked'
}
Invoke-DirectoryTest 'direct collection is explicit and returns the same typed datasets as drive collection' {
    $profile=New-DirectoryProfile;$context=New-DirectoryContext
    $a=Get-ADAnalyzerDirectoryData -Context $context -Profile $profile
    $profile.Analysis.DirectoryConnection='Direct';$script:DriveEvents.Clear();$script:Queries.Clear()
    $b=Get-ADAnalyzerDirectoryData -Context $context -Profile $profile
    Assert-DirectoryEqual 0 $script:DriveEvents.Count;Assert-DirectoryEqual Direct $b.DirectoryConnection.Mode
    foreach($query in $script:Queries){Assert-DirectoryEqual $script:Credential $query.Parameters.Credential}
    foreach($field in @('Domain','Users','Computers','Groups','ServiceAccounts','Trusts','PasswordPolicies','DomainControllers','Acl')){
        Assert-DirectoryEqual (ConvertTo-Json -InputObject $a.$field -Depth 40 -Compress) (ConvertTo-Json -InputObject $b.$field -Depth 40 -Compress)
    }
}
Invoke-DirectoryTest 'current-identity drive access omits credentials and preserves the caller drive' {
    $before=(Get-Location).Path;$caller='ADAnalyzerCaller'+[guid]::NewGuid().ToString('N')
    $null=Microsoft.PowerShell.Management\New-PSDrive -Name $caller -PSProvider FileSystem -Root $RepositoryRoot -Scope Script -ErrorAction Stop -WhatIf:$false -Confirm:$false
    try{
        Microsoft.PowerShell.Management\Set-Location -LiteralPath ($caller+':') -ErrorAction Stop
        $callerPath=(Get-Location).Path;$script:DriveEvents.Clear();$script:Queries.Clear();$script:ExpectedDirectoryCredential=[pscredential]::Empty
        $context=New-DirectoryContext;$context.Credential=[pscredential]::Empty
        $data=Get-ADAnalyzerDirectoryData -Context $context -Profile (New-DirectoryProfile)
        $create=@($script:DriveEvents | Where-Object Action -eq Create)[0]
        Assert-DirectoryTrue (-not $create.Parameters.ContainsKey('Credential')) 'Empty credential was passed to the provider'
        Assert-DirectoryEqual $callerPath (Get-Location).Path
        Assert-DirectoryTrue ([bool](Get-PSDrive -Name $caller -ErrorAction Stop)) 'Caller drive was removed'
        Assert-DirectoryEqual Connected $data.DirectoryConnection.Status
    }finally{
        $script:ExpectedDirectoryCredential=$script:Credential
        Microsoft.PowerShell.Management\Set-Location -LiteralPath $before -ErrorAction Stop
        Microsoft.PowerShell.Management\Remove-PSDrive -Name $caller -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
    }
}
Invoke-DirectoryTest 'provider setup and read failures never silently fall back to direct bulk queries' {
    foreach($mode in @('Create','Enter','Drift')){
        $before=(Get-Location).Path;$script:DriveEvents.Clear();$script:Queries.Clear();$script:DriveFailure=$mode
        try{
            $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
            Assert-DirectoryEqual Unreadable $data.Coverage.DirectoryConnection;Assert-DirectoryEqual Unreadable $data.Coverage.Users
            Assert-DirectoryEqual 0 @($script:Queries | Where-Object Command -in 'Get-ADUser','Get-ADComputer','Get-ADGroup','Get-ADServiceAccount').Count
            Assert-DirectoryTrue ($data.Errors.Count -gt 0) 'Unavailable provider context was hidden'
            Assert-DirectoryEqual $before (Get-Location).Path;Assert-DirectoryEqual 0 @($script:DriveConnections.Keys).Count
        }finally{
            $script:DriveFailure=''
            Microsoft.PowerShell.Management\Set-Location -LiteralPath $before -ErrorAction Stop
            foreach($name in @($script:DriveConnections.Keys)){Microsoft.PowerShell.Management\Remove-PSDrive -Name $name -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false;$script:DriveConnections.Remove($name)}
        }
    }
    $before=(Get-Location).Path;$script:Denied='Get-ADUser';$script:DriveEvents.Clear()
    try{
        $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
        Assert-DirectoryEqual Unreadable $data.Coverage.Users;Assert-DirectoryEqual 0 @($data.Users).Count
        Assert-DirectoryEqual 1 @($script:DriveEvents | Where-Object Action -eq Remove).Count
        Assert-DirectoryEqual $before (Get-Location).Path
    }finally{$script:Denied=''}
}
Invoke-DirectoryTest 'drive cleanup failures preserve both causes and suppress a successful DTO' {
    foreach($mode in @('Restore','Remove','Both')){
        $before=(Get-Location).Path;$script:DriveEvents.Clear();$script:DriveFailure=$mode;$emitted=[Collections.ArrayList]::new();$caught=$null
        try{
            try{Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile) | ForEach-Object {$null=$emitted.Add($_)}}catch{$caught=$_}
            Assert-DirectoryTrue ($null -ne $caught) 'Cleanup failure was swallowed';Assert-DirectoryEqual 0 $emitted.Count
            $remove=@($script:DriveEvents | Where-Object Action -eq Remove);Assert-DirectoryEqual 1 $remove.Count;Assert-DirectoryEqual $true $remove[0].Force
            if($mode -in 'Restore','Both'){Assert-DirectoryTrue ($caught.Exception.Message.Contains('fixture drive restoration failure')) 'Restoration cause was lost'}
            if($mode -eq 'Both'){Assert-DirectoryTrue ($caught.Exception.Data['ADAnalyzerDriveRemovalError'].Contains('fixture drive removal failure')) 'Secondary cleanup cause was lost'}
        }finally{
            $script:DriveFailure=''
            Microsoft.PowerShell.Management\Set-Location -LiteralPath $before -ErrorAction Stop
            foreach($name in @($script:DriveConnections.Keys)){Microsoft.PowerShell.Management\Remove-PSDrive -Name $name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false;$script:DriveConnections.Remove($name)}
        }
    }
}
Invoke-DirectoryTest 'owned drive is cleaned before the first collected snapshot reaches its consumer' {
    $script:DriveEvents.Clear()
    $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile) | ForEach-Object {
        Assert-DirectoryEqual 0 @($script:DriveConnections.Keys).Count
        Assert-DirectoryEqual 1 @($script:DriveEvents | Where-Object Action -eq Remove).Count
        $_
    } | Select-Object -First 1
    Assert-DirectoryEqual 1 $data.Users.Count
}
Invoke-DirectoryTest 'invalid directory connection mode fails before metadata or bulk queries' {
    foreach($mode in @('Unknown',1,@('PSDrive','Direct'),$null)){
        $profile=New-DirectoryProfile;$profile.Analysis.DirectoryConnection=$mode;$script:Queries.Clear();$caught=$false
        try{$null=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile}catch{$caught=$true}
        Assert-DirectoryTrue $caught 'Invalid connection mode accepted';Assert-DirectoryEqual 0 $script:Queries.Count
    }
}
function New-ResultantPolicyFixture {
    [pscustomobject][ordered]@{DistinguishedName=('CN=SharedPSO,CN=Password Settings Container,CN=System,'+$script:DomainDn);MinPasswordLength=16;PasswordHistoryCount=20;ComplexityEnabled=$true;ReversibleEncryptionEnabled=$false;LockoutThreshold=0;LockoutDuration=[timespan]::FromMinutes(30);LockoutObservationWindow=[timespan]::FromMinutes(30);MaxPasswordAge=[timespan]::FromDays(90);MinPasswordAge=[timespan]::Zero}
}
Invoke-DirectoryTest 'positive computed PSO metadata reuses a complete shared policy instead of per-user queries' {
    $saved=$script:User;$script:IncludePsoSchema=$true
    $script:ParityOperatingSystemPolicy=(Get-Command Test-ADAnalyzerOperatingSystemProfile).ScriptBlock
    function script:Test-ADAnalyzerOperatingSystemProfile {param($Object,$Entries,$ReferenceTime) & $script:ParityOperatingSystemPolicy -Object $Object -Entries $Entries -ReferenceTime ([datetimeoffset]'2026-11-13T00:00:00Z')}
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
    try{
        $policy=New-ResultantPolicyFixture;$script:FineGrainedFixture=@($policy);$script:ResultantFixture=$policy
        $script:User=@(foreach($index in 1..100){$row=$saved.PSObject.Copy();$row.ObjectGuid=[guid]::NewGuid().ToString();$row.DistinguishedName=('CN=User'+$index+',OU=People,'+$script:DomainDn);$row.SID=$script:DomainSid+'-'+(2000+$index);$row | Add-Member -NotePropertyName 'msDS-ResultantPSO' -NotePropertyValue $policy.DistinguishedName;$row})
        foreach($mode in @('PSDrive','Direct')){
            $profile=New-DirectoryProfile;$profile.Analysis.DirectoryConnection=$mode;$script:Queries.Clear()
            $before=ConvertTo-Json -InputObject $script:User -Depth 30 -Compress
            $cached=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
            $cachedCalls=@($script:Queries | Where-Object Command -eq Get-ADUserResultantPasswordPolicy).Count
            Assert-DirectoryEqual 0 $cachedCalls
            Assert-DirectoryEqual 1 @($script:Queries | Where-Object Command -eq Get-ADFineGrainedPasswordPolicy).Count
            Assert-DirectoryEqual 100 $cached.PasswordPolicies.Resultant.Count
            Assert-DirectoryEqual 100 @($cached.Users.DistinguishedName | Select-Object -Unique).Count
            Assert-DirectoryEqual 0 @($cached.PasswordPolicies.Resultant | Where-Object {$_.Status -ne 'Collected' -or $_.Source -ne 'FineGrained'}).Count
            Assert-DirectoryEqual $policy.DistinguishedName $cached.Users[0].ResultantPasswordPolicyDN
            Assert-DirectoryTrue ($cached.PasswordPolicies.Resultant[0].Policy.LockoutDuration -is [timespan]) 'Cached duration lost its type'
            Assert-DirectoryEqual $false $cached.PasswordPolicies.Resultant[0].Policy.ReversibleEncryptionEnabled
            Assert-DirectoryEqual 0 $cached.PasswordPolicies.Resultant[0].Policy.LockoutThreshold
            Assert-DirectoryEqual ([timespan]::Zero) $cached.PasswordPolicies.Resultant[0].Policy.MinPasswordAge
            Assert-DirectoryEqual $before (ConvertTo-Json -InputObject $script:User -Depth 30 -Compress)
            foreach($row in $script:User){$row.'msDS-ResultantPSO'=$null}
            $script:Queries.Clear();$baseline=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
            $baselineCalls=@($script:Queries | Where-Object Command -eq Get-ADUserResultantPasswordPolicy).Count;Assert-DirectoryEqual 100 $baselineCalls
            $a=@(Test-ADAnalyzerDirectoryPolicy -Data $cached -Profile $profile | Sort-Object CheckId)
            $b=@(Test-ADAnalyzerDirectoryPolicy -Data $baseline -Profile $profile | Sort-Object CheckId)
            Assert-DirectoryEqual $a.Count $b.Count
            for($index=0;$index -lt $a.Count;$index++){
                Assert-DirectoryEqual $a[$index].CheckId $b[$index].CheckId
                $left=ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $a[$index]) -Depth 50 -Compress
                $right=ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $b[$index]) -Depth 50 -Compress
                Assert-DirectoryTrue ($left -ceq $right) ('Cache changed check '+$a[$index].RuleId+' for '+$a[$index].Target)
            }
            foreach($row in $script:User){$row.'msDS-ResultantPSO'=$policy.DistinguishedName}
            Write-Host ("MEASURE {0}: 100 users, resultant calls fallback={1}, cache={2}; one bulk PSO query" -f $mode,$baselineCalls,$cachedCalls)
        }
    }finally{Set-Item Function:script:Test-ADAnalyzerOperatingSystemProfile $script:ParityOperatingSystemPolicy;$script:User=$saved;$script:IncludePsoSchema=$false;$script:FineGrainedFixture=@();$script:ResultantFixture=$null}
}
Invoke-DirectoryTest 'uncertain computed PSO or cache evidence retains per-user lookup and error semantics' {
    $saved=$script:User
    try{
        foreach($case in @('Absent','Multiple','NonString','Malformed','Unmatched','Ambiguous','MixedDuplicate','Incomplete','SchemaUnavailable','SchemaDenied','BulkDenied')){
            $policy=New-ResultantPolicyFixture;$script:FineGrainedFixture=@($policy);$script:ResultantFixture=$policy;$script:IncludePsoSchema=$case -ne 'SchemaUnavailable'
            $script:User=$saved.PSObject.Copy()
            $value=switch($case){Absent{$null};Multiple{,@($policy.DistinguishedName,$policy.DistinguishedName)};NonString{1};Malformed{'not a policy DN'};Unmatched{'CN=Other,'+$script:DomainDn};default{$policy.DistinguishedName}}
            $script:User | Add-Member -NotePropertyName 'msDS-ResultantPSO' -NotePropertyValue $value
            if($case -eq 'Ambiguous'){$script:FineGrainedFixture+=@($policy.PSObject.Copy())}
            if($case -eq 'MixedDuplicate'){$partial=$policy.PSObject.Copy();$partial.PSObject.Properties.Remove('LockoutDuration');$script:FineGrainedFixture+=@($partial)}
            if($case -eq 'Incomplete'){$script:FineGrainedFixture=@($policy.PSObject.Copy());$script:FineGrainedFixture[0].PSObject.Properties.Remove('LockoutDuration')}
            $script:Denied=if($case -eq 'BulkDenied'){'Get-ADFineGrainedPasswordPolicy'}elseif($case -eq 'SchemaDenied'){'Get-ADObject'}else{''};$script:Queries.Clear()
            $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
            Assert-DirectoryEqual 1 @($script:Queries | Where-Object Command -eq Get-ADUserResultantPasswordPolicy).Count
            Assert-DirectoryEqual Collected $data.PasswordPolicies.Resultant[0].Status;Assert-DirectoryEqual FineGrained $data.PasswordPolicies.Resultant[0].Source
            $userQuery=@($script:Queries | Where-Object Command -eq Get-ADUser)[0]
            Assert-DirectoryEqual ($case -notin 'SchemaUnavailable','SchemaDenied') ('msDS-ResultantPSO' -in $userQuery.Parameters.Properties)
        }
        $script:IncludePsoSchema=$true;$script:FineGrainedFixture=@();$script:ResultantFixture=$null;$script:Denied='Get-ADUserResultantPasswordPolicy'
        $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
        Assert-DirectoryEqual Unreadable $data.PasswordPolicies.Resultant[0].Status;Assert-DirectoryEqual Partial $data.Coverage.ResultantPasswordPolicies
        $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile (New-DirectoryProfile))
        Assert-DirectoryEqual Unknown (Select-DirectoryCheck $checks PASSWORD.MIN_LENGTH).Status
    }finally{$script:User=$saved;$script:IncludePsoSchema=$false;$script:FineGrainedFixture=@();$script:ResultantFixture=$null;$script:Denied=''}
}
Invoke-DirectoryTest 'mixed explicit and absent computed policy evidence queries only uncertain users' {
    $saved=$script:User
    try{
        $policy=New-ResultantPolicyFixture;$script:IncludePsoSchema=$true;$script:FineGrainedFixture=@($policy);$script:ResultantFixture=$policy
        $script:User=@(foreach($index in 1..3){$row=$saved.PSObject.Copy();$row.DistinguishedName=('CN=Mixed'+$index+',OU=People,'+$script:DomainDn);$row | Add-Member -NotePropertyName 'msDS-ResultantPSO' -NotePropertyValue $(if($index -eq 1){$policy.DistinguishedName}elseif($index -eq 2){$null}else{'CN=Missing,'+$script:DomainDn});$row})
        $script:Queries.Clear();$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
        $lookups=@($script:Queries | Where-Object Command -eq Get-ADUserResultantPasswordPolicy)
        Assert-DirectoryEqual 2 $lookups.Count
        Assert-DirectoryTrue ($data.Users[0].DistinguishedName -notin $lookups.Parameters.Identity) 'A known cached user was queried again'
        Assert-DirectoryEqual 3 $data.PasswordPolicies.Resultant.Count
        Assert-DirectoryEqual 0 @($data.PasswordPolicies.Resultant | Where-Object Status -ne Collected).Count
    }finally{$script:User=$saved;$script:IncludePsoSchema=$false;$script:FineGrainedFixture=@();$script:ResultantFixture=$null}
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
        Assert-DirectoryEqual $script:Credential $query.EffectiveCredential
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
Invoke-DirectoryTest 'live collection requests and preserves SIDHistory for every account class' {
    $originalUser=$script:User;$originalComputer=$script:Computer
    try {
        $history=$script:DomainSid+'-512'
        $script:User=$originalUser.PSObject.Copy();$script:User.SIDHistory=@($history)
        $script:Computer=$originalComputer.PSObject.Copy();$script:Computer | Add-Member NoteProperty SIDHistory @($history) -Force
        $script:ServiceAccount=$script:User.PSObject.Copy()
        $script:ServiceAccount.ObjectClass='msDS-GroupManagedServiceAccount'
        $script:ServiceAccount.ObjectGuid='33333333-3333-3333-3333-333333333333'
        $script:ServiceAccount.SID=$script:DomainSid+'-1003'
        $script:ServiceAccount.DistinguishedName='CN=Service,OU=Services,DC=example,DC=invalid'
        $profile=New-DirectoryProfile;$script:Queries.Clear()
        $data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
        foreach($command in @('Get-ADUser','Get-ADComputer','Get-ADServiceAccount')){
            $query=@($script:Queries | Where-Object Command -eq $command)[0]
            Assert-DirectoryTrue ('SIDHistory' -in $query.Parameters.Properties) ($command+' omitted SIDHistory')
        }
        foreach($object in @($data.Users)+@($data.Computers)+@($data.ServiceAccounts)){
            Assert-DirectoryEqual 1 $object.SIDHistory.Count
            Assert-DirectoryEqual $history $object.SIDHistory[0]
        }
        $checks=@(Test-ADAnalyzerDirectoryPolicy -Data $data -Profile $profile | Where-Object RuleId -eq SIDHISTORY.PRIVILEGED)
        Assert-DirectoryEqual 3 $checks.Count
        Assert-DirectoryEqual 3 @($checks | Where-Object Status -eq Fail).Count
    } finally {$script:User=$originalUser;$script:Computer=$originalComputer;$script:ServiceAccount=$null}
    $clean=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile (New-DirectoryProfile)
    Assert-DirectoryEqual 0 $clean.Computers[0].SIDHistory.Count
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
function Invoke-ConfiguredHostFixture([hashtable]$Profile,[string]$Mode='Normal',[switch]$Direct) {
    $saved=@{};foreach($name in @('New-CimSession','Get-CimInstance','Invoke-CimMethod','Remove-CimSession')){$saved[$name]=(Get-Command $name).ScriptBlock}
    $script:ConfiguredCalls=[Collections.Generic.List[object]]::new();$script:ConfiguredClosed=0;$script:ConfiguredMode=$Mode
    $script:ConfiguredTimeout=$Profile.Analysis.HostTimeoutSeconds
    $script:ConfiguredServiceName='Custom''Quoted\"Name$'
    $script:ConfiguredRegistry=[ordered]@{
        Text=@{Type=1;Value=''};Expand=@{Type=2;Value='%SystemRoot%'};Bytes=@{Type=3;Value=[byte[]]@(0,255)}
        Flag=@{Type=4;Value=[uint32]0};Multi=@{Type=7;Value=[string[]]@('one','two')};Wide=@{Type=11;Value=[uint64]::MaxValue}
        Unsupported=@{Type=99;Value=$null};''=@{Type=1;Value='default'}
    }
    function script:New-CimSession {param($ComputerName,$Credential,$OperationTimeoutSec,$ErrorAction)
        $script:ConfiguredCalls.Add([pscustomobject]@{Command='Session';Parameters=$PSBoundParameters})
        if($Credential -ne $script:Credential -or $OperationTimeoutSec -ne $script:ConfiguredTimeout){throw 'Session credential/timeout mismatch'}
        [pscustomobject]@{ComputerName=$ComputerName}
    }
    function script:Get-CimInstance {param($CimSession,$ClassName,$Filter,$Namespace,$OperationTimeoutSec,$ErrorAction)
        $script:ConfiguredCalls.Add([pscustomobject]@{Command='Class';Parameters=$PSBoundParameters})
        if($OperationTimeoutSec -ne $script:ConfiguredTimeout){throw 'Query timeout mismatch'}
        if($ClassName -eq 'Win32_Service'){
            $pattern="Name='((?:\\.|[^'\\])*)'";$parts=[regex]::Matches($Filter,$pattern)
            if(([regex]::Replace($Filter,$pattern,'') -replace ' OR ','') -ne ''){throw 'Unsafe WQL literal syntax'}
            $names=@($parts | ForEach-Object {[regex]::Replace($_.Groups[1].Value,'\\(.)','$1')})
            if(@($names | Where-Object {$_ -ieq $script:ConfiguredServiceName}).Count -gt 1){throw 'Duplicate service request'}
            if($script:ConfiguredServiceName -in $names){[pscustomobject]@{Name=$script:ConfiguredServiceName;State='Running';StartMode='Auto'}}
        }else{[pscustomobject]@{ClassName=$ClassName;Observed=$true}}
    }
    function script:Invoke-CimMethod {param($CimSession,$Namespace,$ClassName,$MethodName,$Arguments,$OperationTimeoutSec,$ErrorAction)
        $script:ConfiguredCalls.Add([pscustomobject]@{Command='Registry';Parameters=$PSBoundParameters})
        if($OperationTimeoutSec -ne $script:ConfiguredTimeout -or $Namespace -ne 'root/default' -or $ClassName -ne 'StdRegProv' -or $Arguments.hDefKey -ne [uint32]2147483650){throw 'Registry contract mismatch'}
        if($Arguments.sSubKeyName -ine 'SYSTEM\Custom'){return [pscustomobject]@{ReturnValue=2;uValue=$null;sValue=$null}}
        if($script:ConfiguredMode -eq 'Throw'){throw 'fixture registry exception'}
        if($script:ConfiguredMode -eq 'Denied'){return [pscustomobject]@{ReturnValue=5}}
        if($MethodName -eq 'EnumValues'){
            if($script:ConfiguredMode -eq 'DefaultOnly'){return [pscustomobject]@{ReturnValue=0;sNames=$null;Types=$null}}
            $names=@($script:ConfiguredRegistry.Keys | Where-Object {$_ -ne '' -and -not ($script:ConfiguredMode -eq 'Missing' -and $_ -eq 'Flag')})
            return [pscustomobject]@{ReturnValue=0;sNames=$names;Types=@($names | ForEach-Object {$script:ConfiguredRegistry[$_].Type})}
        }
        if($script:ConfiguredMode -eq 'GetterDenied'){return [pscustomobject]@{ReturnValue=5;uValue=999;sValue='must not be treated as observed'}}
        $row=$script:ConfiguredRegistry[$Arguments.sValueName]
        $expected=@{1='GetStringValue';2='GetExpandedStringValue';3='GetBinaryValue';4='GetDWORDValue';7='GetMultiStringValue';11='GetQWORDValue'}[[int]$row.Type]
        if($MethodName -ne $expected){throw 'Wrong registry getter'}
        $result=[pscustomobject]@{ReturnValue=0;uValue=$null;sValue=$null}
        if($row.Type -in 1,2,7){$result.sValue=$row.Value}else{$result.uValue=$row.Value};$result
    }
    function script:Remove-CimSession {param($CimSession,$ErrorAction) $script:ConfiguredClosed++}
    try{
        if($Direct){$errors=[Collections.Generic.List[object]]::new();$data=[pscustomobject]@{Hosts=@(Get-ADAnalyzerHostData -ComputerNames 'dc.example.invalid' -Credential $script:Credential -Errors $errors -Profile $Profile -TimeoutSeconds $Profile.Analysis.HostTimeoutSeconds)}}
        else{$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext $false $true) -Profile $Profile}
        [pscustomobject]@{Data=$data;Calls=$script:ConfiguredCalls.ToArray();Closed=$script:ConfiguredClosed}
    }finally{foreach($name in $saved.Keys){Set-Item ('Function:script:'+$name) $saved[$name]}}
}
Invoke-DirectoryTest 'custom host configuration reaches bounded service and typed registry collection' {
    $profile=New-DirectoryProfile;$profile.Analysis.HostTimeoutSeconds=17
    $service='Custom''Quoted\"Name$';$profile.Host.Services=@(@{Name=$service;State='Running';StartMode='Auto'},@{Id='alternate';Name=$service.ToUpperInvariant();State='Running'})
    $profile.Host.RegistryRules=@('Text','Expand','Bytes','Flag','Multi','Wide' | ForEach-Object {@{Key='SYSTEM\Custom';ValueName=$_;Expected=$null}})
    $profile.Host.RegistryRules+=@(@{Id='alternate';Key='system\custom';ValueName='FLAG';Expected=0})
    $before=ConvertTo-Json -InputObject $profile -Depth 30 -Compress;$r=Invoke-ConfiguredHostFixture $profile
    $hostData=$r.Data.Hosts[0];Assert-DirectoryEqual 1 @($hostData.Services).Count;Assert-DirectoryEqual $service $hostData.Services[0].Name
    $rows=@($hostData.Registry | Where-Object Path -ieq 'SYSTEM\Custom');Assert-DirectoryEqual 6 $rows.Count
    Assert-DirectoryEqual '' ($rows | Where-Object Name -eq Text).Value
    Assert-DirectoryEqual '%SystemRoot%' ($rows | Where-Object Name -eq Expand).Value
    Assert-DirectoryEqual '0,255' (($rows | Where-Object Name -eq Bytes).Value -join ',')
    Assert-DirectoryEqual 0 ($rows | Where-Object Name -eq Flag).Value
    Assert-DirectoryEqual 'one,two' (($rows | Where-Object Name -eq Multi).Value -join ',')
    Assert-DirectoryEqual ([uint64]::MaxValue) ($rows | Where-Object Name -eq Wide).Value
    Assert-DirectoryEqual 0 @($rows | Where-Object Status -ne Observed).Count
    Assert-DirectoryEqual 1 @($r.Calls | Where-Object {$_.Command -eq 'Registry' -and $_.Parameters.MethodName -eq 'EnumValues' -and $_.Parameters.Arguments.sSubKeyName -ieq 'SYSTEM\Custom'}).Count
    Assert-DirectoryEqual 6 @($r.Calls | Where-Object {$_.Command -eq 'Registry' -and $_.Parameters.MethodName -ne 'EnumValues' -and $_.Parameters.Arguments.sSubKeyName -ieq 'SYSTEM\Custom'}).Count
    Assert-DirectoryEqual 1 $r.Closed;Assert-DirectoryEqual $before (ConvertTo-Json -InputObject $profile -Depth 30 -Compress)
}
Invoke-DirectoryTest 'actual custom host collection feeds passing failing and unknown assessment checks' {
    foreach($file in @('ADGpo','ADPolicyAnalysis','ADHostAnalysis','ADOperations','ADAssessment')){. (Join-Path $RepositoryRoot ('bin/'+$file+'.ps1'))}
    $profile=New-DirectoryProfile
    $profile.Host.Services=@(@{Name='Custom''Quoted\"Name$';State='Running';StartMode='Auto'})
    $profile.Host.RegistryRules=@(@{Key='SYSTEM\Custom';ValueName='Flag';Expected=0;Type=4},@{Key='SYSTEM\Custom';ValueName='Text';Expected='';Type=1},@{Key='SYSTEM\Custom';ValueName='Multi';Expected=@('one','two');Type=7},@{Id='nonzero';Key='SYSTEM\Custom';ValueName='Flag';Expected=1;Type=4})
    $r=Invoke-ConfiguredHostFixture $profile
    $checks=@(Test-ADAnalyzerHostPolicy -Hosts $r.Data.Hosts -Profile $profile)
    Assert-DirectoryEqual 4 @($checks | Where-Object {$_.RuleId -in 'HOST.SERVICE','HOST.REGISTRY' -and $_.Status -eq 'Pass'}).Count
    Assert-DirectoryEqual 1 @($checks | Where-Object {$_.RuleId -eq 'HOST.REGISTRY' -and $_.Status -eq 'Fail'}).Count
    $r.Data | Add-Member -NotePropertyName HostChecks -NotePropertyValue $checks
    $assessment=Invoke-ADAnalyzerAssessment -DirectoryData $r.Data -Profile $profile
    Assert-DirectoryEqual 4 @($assessment.Checks | Where-Object {$_.RuleId -in 'HOST.SERVICE','HOST.REGISTRY' -and $_.Status -eq 'Pass'}).Count
    $profile.Host.Services[0].State='Stopped';$profile.Host.RegistryRules[0].Expected=1
    $checks=@(Test-ADAnalyzerHostPolicy -Hosts $r.Data.Hosts -Profile $profile)
    Assert-DirectoryEqual 3 @($checks | Where-Object {$_.RuleId -in 'HOST.SERVICE','HOST.REGISTRY' -and $_.Status -eq 'Fail'}).Count
    $r=Invoke-ConfiguredHostFixture $profile GetterDenied;$checks=@(Test-ADAnalyzerHostPolicy -Hosts $r.Data.Hosts -Profile $profile)
    Assert-DirectoryEqual 4 @($checks | Where-Object {$_.RuleId -eq 'HOST.REGISTRY' -and $_.Status -eq 'Unknown'}).Count
}
Invoke-DirectoryTest 'unavailable custom registry observations remain Unknown and always close their session' {
    foreach($mode in @('Missing','Denied','Throw','GetterDenied')){
        $profile=New-DirectoryProfile;$profile.Host.RegistryRules=@(@{Key='SYSTEM\Custom';ValueName='Flag';Expected=0})
        $r=Invoke-ConfiguredHostFixture $profile $mode;$row=@($r.Data.Hosts[0].Registry | Where-Object Path -eq 'SYSTEM\Custom')[0]
        Assert-DirectoryEqual Unknown $row.Status;Assert-DirectoryEqual $null $row.Value;Assert-DirectoryEqual 1 $r.Closed
    }
    $profile=New-DirectoryProfile;$profile.Host.RegistryRules=@(@{Key='SYSTEM\Custom';ValueName='Unsupported';Expected=0})
    $r=Invoke-ConfiguredHostFixture $profile;$row=@($r.Data.Hosts[0].Registry | Where-Object Path -eq 'SYSTEM\Custom')[0]
    Assert-DirectoryEqual Unknown $row.Status;Assert-DirectoryEqual $null $row.Value;Assert-DirectoryEqual 1 $r.Closed
}
Invoke-DirectoryTest 'default registry values require known type evidence and support an explicit getter type' {
    $profile=New-DirectoryProfile;$profile.Host.RegistryRules=@(@{Key='SYSTEM\Custom';ValueName='';Expected='default'})
    $r=Invoke-ConfiguredHostFixture $profile DefaultOnly;$row=@($r.Data.Hosts[0].Registry | Where-Object Path -eq 'SYSTEM\Custom')[0];Assert-DirectoryEqual Unknown $row.Status
    $profile.Host.RegistryRules[0].Type=1;$r=Invoke-ConfiguredHostFixture $profile DefaultOnly;$row=@($r.Data.Hosts[0].Registry | Where-Object Path -eq 'SYSTEM\Custom')[0]
    Assert-DirectoryEqual Observed $row.Status;Assert-DirectoryEqual default $row.Value;Assert-DirectoryEqual 1 $row.Type;Assert-DirectoryEqual 1 $r.Closed
}
Invoke-DirectoryTest 'invalid or secret host rules reject before any CIM access' {
    foreach($case in @(
        @{Services=@(@{Name='';State='Running'})},@{Services=@(@{Name=@('one','two');State='Running'})},
        @{RegistryRules=@(@{Key='';ValueName='Enabled';Expected=0})},@{RegistryRules=@(@{Key='SYSTEM\Custom';ValueName='Flag';Type=99;Expected=0})},
        @{RegistryRules=@(@{Key='SYSTEM\Custom';ValueName='DefaultPassword';Expected='unit14-not-requested'})}
    )){
        $profile=New-DirectoryProfile;foreach($key in $case.Keys){$profile.Host[$key]=$case[$key]}
        $caught=$false;try{$null=Invoke-ConfiguredHostFixture $profile -Direct}catch{$caught=$true}
        Assert-DirectoryTrue $caught 'Invalid host rule was accepted';Assert-DirectoryEqual 0 $script:ConfiguredCalls.Count
    }
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
        $profile.AccountClassification.AttributeRules=@(@{Attribute='apiKey';Type='Service';Value='unit3-secret'})
        $script:Queries.Clear();$data=Get-ADAnalyzerDirectoryData -Context (New-DirectoryContext) -Profile $profile
        Assert-DirectoryEqual 'Unknown' $data.Users[0].AccountType
        Assert-DirectoryTrue ($data.Errors.Count -gt 0) 'Generic secret fields need explicit errors'
        Assert-DirectoryEqual 0 @($script:Queries | Where-Object {$_.Parameters.Properties -contains 'apiKey'}).Count
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
    Assert-DirectoryEqual ($script:DomainSid+'-512') ($membership.DirectSids -join ',')
    Assert-DirectoryEqual ($script:DomainSid+'-512') ($membership.EffectiveSids -join ',')
    Assert-DirectoryEqual ($script:DomainSid+'-512') $group.objectSid
    Assert-DirectoryEqual $false ([bool]$group.PSObject.Properties['SID'])
    Assert-DirectoryEqual 0 $membership.Unresolved.Count
}
Write-Host ("{0} directory tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
