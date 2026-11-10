[CmdletBinding()]
param([string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$script:ClassPassed = 0
$script:ClassFailed = 0

function Assert-ClassEqual($Expected, $Actual) {
    if ($Expected -ne $Actual) { throw "Expected [$Expected], received [$Actual]" }
}
function Assert-ClassTrue($Actual, [string]$Message) {
    if (-not $Actual) { throw $Message }
}
function Invoke-ClassTest([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:ClassPassed++; Write-Host "PASS $Name" }
    catch { $script:ClassFailed++; Write-Host "FAIL $Name : $_" }
}

# These DTOs supply only external CLR contracts. All analyzer class definitions,
# inheritance, factories, formatting and processing methods come from the full
# actual module. Every directory/drive/mutation command is replaced below.
Add-Type -TypeDefinition @'
namespace Microsoft.ActiveDirectory.Management {
    public class ADPropertyValueCollection : System.Collections.ArrayList {}
    public class ADEntity {
        public string DomainNamingMaster {get;set;}
        public string SchemaMaster {get;set;}
        public string RootDomain {get;set;}
    }
    public class ADPartition : ADEntity {
        public string DomainSID {get;set;}
        public string DNSRoot {get;set;}
        public string Name {get;set;}
        public string NetBIOSName {get;set;}
        public string DistinguishedName {get;set;}
        public string ComputersContainer {get;set;}
        public string DomainControllersContainer {get;set;}
        public string DeletedObjectsContainer {get;set;}
        public string ForeignSecurityPrincipalsContainer {get;set;}
        public string UsersContainer {get;set;}
        public string InfrastructureMaster {get;set;}
        public string PDCEmulator {get;set;}
        public string RIDMaster {get;set;}
    }
}
namespace Microsoft.ActiveDirectory.Management.Provider {
    public class ADDriveInfo { public string Name {get;set;} }
}
'@

$script:ClassModule = Import-Module (Join-Path $RepositoryRoot 'bin/ADEnvironment.psm1') -Force -PassThru
function Invoke-ClassScope([string]$Source) {
    & $script:ClassModule ([scriptblock]::Create($Source))
}

Invoke-ClassScope @'
$script:FixtureWrites = 0
$script:AllowFixtureWrites = $false
$script:FixtureDrives = [System.Collections.ArrayList]::new()
$script:RemovedDrives = [System.Collections.ArrayList]::new()
$script:SecureChannel = $true
$script:FailDomainQuery = $false
$script:LastMutationServer = ''
$script:LastDriveScope = ''
$script:QueryServers = [System.Collections.ArrayList]::new()
$script:FailUserQuery = $false
$script:FixturePolicyXml = $null
$script:FailGpoRead = $false
$script:UserRecord = [ordered]@{
    samaccountname='adoe'; givenName='Alice'; surName='Doe'; name='Alice Doe'
    userPrincipalName='adoe@example.invalid'; distinguishedName='CN=Alice Doe,OU=People,DC=example,DC=invalid'
    enabled=$true; userAccountControl=512; adminCount=1; memberOf=@()
    passwordlastset=[datetime]::Now.AddDays(-10); lastlogondate=[datetime]::Now.AddDays(-80)
    whenCreated=[datetime]::Now.AddDays(-100); whenChanged=[datetime]::Now.AddDays(-5)
    SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'}
}
$script:GroupRecord = [ordered]@{
    samaccountname='FixtureGroup'; name='Fixture Group'; distinguishedName='CN=Fixture Group,OU=Groups,DC=example,DC=invalid'
    managedBy='CN=Owner,DC=example,DC=invalid'; members=@('CN=Alice Doe,OU=People,DC=example,DC=invalid')
    memberOf=@('CN=Parent,OU=Groups,DC=example,DC=invalid'); whenCreated=[datetime]::Now.AddDays(-100)
    whenChanged=[datetime]::Now.AddDays(-5); SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1002'}
}
$script:ComputerRecord = [ordered]@{
    samaccountname='FIXTURE$'; name='FIXTURE'; distinguishedName='CN=FIXTURE,OU=Computers,DC=example,DC=invalid'
    enabled=$true; passwordlastset=[datetime]::Now.AddDays(-10); lastlogondate=[datetime]::Now.AddDays(-80)
    whenCreated=[datetime]::Now.AddDays(-100); whenChanged=[datetime]::Now.AddDays(-5)
    OperatingSystem='Windows Server 2022'; SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1003'}
}
function script:Get-CimInstance { param($ClassName) [pscustomobject]@{Domain='example.invalid'} }
function script:Test-ComputerSecureChannel { param($Server,$Credential,[switch]$WhatIf,[switch]$Confirm) return $script:SecureChannel }
function script:Get-ADDomain {
    param($Server,$Credential,$ErrorAction)
    if($script:FailDomainQuery){throw 'fixture authentication failure'}
    $null=$script:QueryServers.Add($Server)
    $domain=[Microsoft.ActiveDirectory.Management.ADPartition]::new()
    $domain.DomainSID='S-1-5-21-1-2-3'; $domain.DNSRoot='example.invalid'; $domain.Name='example.invalid'
    $domain.NetBIOSName='FIXTURE'; $domain.DistinguishedName='DC=example,DC=invalid'
    $domain.UsersContainer='CN=Users,DC=example,DC=invalid'
    $domain.ComputersContainer='CN=Computers,DC=example,DC=invalid'
    $domain.DomainControllersContainer='OU=Domain Controllers,DC=example,DC=invalid'
    return $domain
}
function script:Get-ADForest { param($Server,$ErrorAction) $forest=[Microsoft.ActiveDirectory.Management.ADEntity]::new(); $forest.RootDomain='example.invalid'; return $forest }
function script:Get-ADOptionalFeature { param($Filter,$Properties,$Server,$ErrorAction) [pscustomobject]@{Name='Recycle Bin Feature'; EnabledScopes=@('fixture'); RequiredDomainMode='fixture'; RequiredForestMode='fixture'; DistinguishedName='CN=Feature'} }
function script:Get-ADObject { param($Filter,$Properties,$Server,$ErrorAction) $script:UserRecord; $script:GroupRecord; $script:ComputerRecord }
function script:Get-ADUser { param($Filter,$Properties,$Server,$ErrorAction) if($script:FailUserQuery){throw 'fixture query failure'}; return $script:UserRecord }
function script:Get-ADGroup { param($Filter,$Properties,$Server,$ErrorAction) return $script:GroupRecord }
function script:Get-ADComputer { param($Filter,$Properties,$Server,$ErrorAction) return $script:ComputerRecord }
function script:Get-ADAnalyzerGpo { param([switch]$All,$Domain,$Server,$ErrorAction,$Credential) $script:GpoQueryCredential=$Credential; [pscustomobject]@{DisplayName='FixturePolicy';CreationTime=[datetime]::Now;ModificationTime=[datetime]::Now;GPOStatus='AllSettingsEnabled';Id=[guid]::Empty} }
function script:Get-ADAnalyzerGpoReport { param($Gpo,$SidNames,$Credential) $script:GpoReportCredential=$Credential; if($script:FailGpoRead){throw 'fixture unreadable SYSVOL'}; if($script:FixturePolicyXml){return $script:FixturePolicyXml}; '<GPO><ReadTime>2026-01-01T00:00:00</ReadTime><Computer><Enabled>true</Enabled></Computer><User><Enabled>true</Enabled></User></GPO>' }
function script:Get-PSDrive { $script:FixtureDrives }
function script:Get-Location { [pscustomobject]@{Path='fixture-start'} }
function script:Set-Location { param($Path,$LiteralPath,$ErrorAction) }
function script:New-PSDrive {
    param($Server,$Name,$PSProvider,$Root,$Credential,$Scope,$ErrorAction,[switch]$WhatIf,[switch]$Confirm)
    $script:LastDriveScope=$Scope
    $drive=[Microsoft.ActiveDirectory.Management.Provider.ADDriveInfo]::new(); $drive.Name=$Name
    $null=$script:FixtureDrives.Add($drive); return $drive
}
function script:Remove-PSDrive {
    param($Name,$ErrorAction,[switch]$WhatIf,[switch]$Confirm)
    $null=$script:RemovedDrives.Add($Name)
    @($script:FixtureDrives | Where-Object {$_.Name -eq $Name}) | ForEach-Object {$script:FixtureDrives.Remove($_)}
}
function script:Set-ADObject {
    param($Identity,$Server,$Replace,$ErrorAction)
    if(-not $script:AllowFixtureWrites){throw 'Unexpected AD mutation'}
    if($Replace.ContainsKey(1)){throw 'Invalid numeric AD attribute key'}
    $script:LastMutationServer=$Server; $script:FixtureWrites++
}
function script:Disable-ADAccount { param($Identity,$Server,$ErrorAction) if(-not $script:AllowFixtureWrites){throw 'Unexpected AD mutation'}; $script:LastMutationServer=$Server; $script:FixtureWrites++ }
function script:Remove-ADObject { param($Identity,$Server,[switch]$Recursive,[switch]$Confirm,$ErrorAction) if(-not $script:AllowFixtureWrites){throw 'Unexpected AD mutation'}; $script:LastMutationServer=$Server; $script:FixtureWrites++ }
'@

Invoke-ClassTest 'all Data subclasses construct and inherit shared typed containers' {
    $count=Invoke-ClassScope @'
$count=0
foreach($name in @('DomainData','ObjectData','UserData','GroupData','ComputerData','GroupPolicyData')) {
    $model=New-Object $name
    if($model -isnot [Data]){throw $name}
    $model.Data=[Table]::new(); $model.Report=[Table]::new(); $model.Finding=[Finding]::new()
    if($model.Data -isnot [Table] -or $model.Finding -isnot [Finding]){throw $name}
    $count++
}
$count
'@
    Assert-ClassEqual 6 $count
}

Invoke-ClassTest 'all table factories initialize valid keys and metadata' {
    $count=Invoke-ClassScope @'
$count=0
foreach($name in @('UserTable','GroupTable','ComputerTable','GroupPolicyTable')) {
    $table=(New-Object $name)::SetDefault()
    if($table -isnot [Table] -or -not $table.Properties.Key){throw $name}
    $count++
}
$count
'@
    Assert-ClassEqual 4 $count
}

Invoke-ClassTest 'diagnostic timer is initialized and usable' {
    $running=Invoke-ClassScope '$d=[ADDiagnostic]::Initialize(); $d["StopWatch"].Start(); $r=$d["StopWatch"].IsRunning; $d["StopWatch"].Stop(); $r'
    Assert-ClassTrue $running 'Expected a running instance stopwatch'
}

Invoke-ClassTest 'process flags reset when initialized with false' {
    $result=Invoke-ClassScope '[Process]::Initialize($true,$true); [Process]::Initialize($false,$false); [Process]::WhatIf -or [Process]::Confirm'
    Assert-ClassEqual $false $result
}

Invoke-ClassTest 'collection factory maps all object classes and dependencies' {
    $result=Invoke-ClassScope '$c=[ADCollection]::Initialize([System.Collections.ArrayList]@("User","Group","Computer","GroupPolicy")); ($c.Keys -join ",")'
    Assert-ClassEqual 'Domain,Object,User,Group,Computer,GroupPolicy' $result
}

Invoke-ClassTest 'environment factories cover local-domain and credential overloads' {
    $count=Invoke-ClassScope @'
$count=0
try {
    $e=[ADEnvironment]::Initialize()
    if($e.Group -isnot [GroupData] -or [ADTarget]::FQDN -ne 'example.invalid'){throw 'Default factory'}
    $count++;[ADEnvironment]::Close()
    $e=[ADEnvironment]::Initialize([System.Collections.ArrayList]@('User'))
    if($e.User -isnot [UserData] -or $e.Finding -isnot [Finding]){throw 'Class-list factory'}
    $count++;[ADEnvironment]::Close()
    $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    $e=[ADEnvironment]::Initialize($credential,[System.Collections.ArrayList]@('User'))
    if($e.User -isnot [UserData] -or [ADTarget]::FQDN -ne 'example.invalid'){throw 'Credential factory'}
    $count++
} finally {[ADEnvironment]::Close()}
$count
'@
    Assert-ClassEqual 3 $count
}

Invoke-ClassTest 'group-member lookup uses the shared object table' {
    $name=Invoke-ClassScope @'
try {
    $null=[ADCollection]::Initialize([System.Collections.ArrayList]@('Group'))
    [ObjectData]::GetInstance().Data=[Table]::new()
    [ObjectData]::GetInstance().Data['CN=Fixture']=[ordered]@{samaccountname='fixture-member'}
    [GroupData]::GetInstance().LookupGroupMembers(@('CN=Fixture','CN=Missing')) -join ','
} finally {[ADEnvironment]::Close()}
'@
    Assert-ClassEqual 'fixture-member' $name
}

Invoke-ClassTest 'full report pipeline handles all four classes and aggregate findings' {
    $result=Invoke-ClassScope @'
$e=Get-ADEnvironment -Class @('User','Group','Computer','GroupPolicy') -FQDN 'target.example.invalid'
[pscustomobject]@{User=$e.User.Report.Count;Group=$e.Group.Report.Count;Computer=$e.Computer.Report.Count;GPO=$e.GroupPolicy.Data.Count;Finding=$e.Finding.Count;Target=$e.Domain.FQDN;PolicyRetained=$null -ne $e.Domain.PasswordPolicy;Stopped=$null -eq [ADDiagnostic]::Instance}
'@
    Assert-ClassEqual 1 $result.User
    Assert-ClassEqual 1 $result.Group
    Assert-ClassEqual 1 $result.Computer
    Assert-ClassEqual 1 $result.GPO
    Assert-ClassTrue ($result.Finding -ge 3) 'Expected per-class findings in global aggregation'
    Assert-ClassEqual 'target.example.invalid' $result.Target
    Assert-ClassTrue $result.PolicyRetained 'Cleanup must preserve returned reports'
    Assert-ClassTrue $result.Stopped 'Cleanup should release singleton diagnostics'
}

Invoke-ClassTest 'public report accepts a scalar class and reinitializes cleanly' {
    $count=Invoke-ClassScope '$e=Get-ADEnvironment -Analyze User -FQDN "target.example.invalid"; $e.User.Report.Count'
    Assert-ClassEqual 1 $count
}

Invoke-ClassTest 'query failures clean up class singletons' {
    $result=Invoke-ClassScope @'
$script:FailUserQuery=$true; $failed=$false
try { $null=Get-ADEnvironment -Class User -FQDN 'target.example.invalid' } catch { $failed=$true } finally { $script:FailUserQuery=$false }
$failed -and $null -eq [ADEnvironment]::Instance -and $null -eq [ADCollection]::Data -and $null -eq [FindingData]::Instance
'@
    Assert-ClassTrue $result 'Expected failure propagation and cleanup'
}

Invoke-ClassTest 'repeated cleanup is safe before or after initialization' {
    Invoke-ClassScope '[ADEnvironment]::Close(); [ADEnvironment]::Close()'
}

Invoke-ClassTest 'credential connections persist until cleanup and preserve preexisting drives' {
    $result=Invoke-ClassScope @'
$existing=[Microsoft.ActiveDirectory.Management.Provider.ADDriveInfo]::new(); $existing.Name='FIXTURE'; $null=$script:FixtureDrives.Add($existing)
$credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
$e=[ADEnvironment]::Initialize('target.example.invalid',$credential,[System.Collections.ArrayList]@('User'))
$during=$script:FixtureDrives.Count; [ADEnvironment]::Close()
[pscustomobject]@{During=$during;After=$script:FixtureDrives.Count;Preserved=$script:FixtureDrives[0].Name;Scope=$script:LastDriveScope}
'@
    Assert-ClassEqual 2 $result.During
    Assert-ClassEqual 1 $result.After
    Assert-ClassEqual 'FIXTURE' $result.Preserved
    Assert-ClassEqual 'Script' $result.Scope
}

Invoke-ClassTest 'failed directory authentication never creates a connection drive' {
    $result=Invoke-ClassScope @'
$script:FailDomainQuery=$true; $before=$script:FixtureDrives.Count; $failed=$false
try { $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force)); $null=[ADTarget]::new('target.example.invalid',$credential) } catch { $failed=$true } finally {$script:FailDomainQuery=$false;[ADEnvironment]::Close()}
$failed -and $script:FixtureDrives.Count -eq $before
'@
    Assert-ClassTrue $result 'A failed connection check must not be ignored'
}

Invoke-ClassTest 'approved remediation executes mocked actions against the requested target' {
    $result=Invoke-ClassScope @'
$script:AllowFixtureWrites=$true; $script:FixtureWrites=0
try {
    $e=Set-ADEnvironment -Class User -FQDN 'target.example.invalid' -Confirm:$false
    [pscustomobject]@{Writes=$script:FixtureWrites;Target=$script:LastMutationServer;Result=$e.User.Finding[0].result;Aggregate=$e.Finding.Count}
} finally { $script:AllowFixtureWrites=$false }
'@
    Assert-ClassEqual 2 $result.Writes
    Assert-ClassEqual 'target.example.invalid' $result.Target
    Assert-ClassEqual $true $result.Result
    Assert-ClassTrue ($result.Aggregate -gt 0) 'Expected refreshed aggregate results'
}

Invoke-ClassTest 'full-module preview never executes a directory mutation' {
    $result=Invoke-ClassScope '$before=$script:FixtureWrites; $null=Set-ADEnvironment -Class User -FQDN "target.example.invalid" -WhatIf; $script:FixtureWrites -eq $before'
    Assert-ClassTrue $result 'Preview must never reach a mutation'
}

$temporaryDirectory=Join-Path ([IO.Path]::GetTempPath()) ('ad-class-tests-'+[guid]::NewGuid())
New-Item -Path $temporaryDirectory -ItemType Directory > $null
try {
    Invoke-ClassTest 'aggregate findings export as usable CSV records' {
        $path=Join-Path $temporaryDirectory 'findings.csv'
        $escaped=$path.Replace("'","''")
        Invoke-ClassScope ("`$e=Get-ADEnvironment -Class User -FQDN 'target.example.invalid'; `$e.Finding.ExportCSV('$escaped')")
        $rows=@(Import-Csv -LiteralPath $path)
        Assert-ClassTrue ($rows.Count -gt 0) 'Expected exported findings'
        Assert-ClassEqual 'User' $rows[0].class
    }
    Invoke-ClassTest 'user group and computer report tables export their record columns' {
        foreach($class in @('User','Group','Computer')) {
            $path=Join-Path $temporaryDirectory ($class+'.csv')
            $escaped=$path.Replace("'","''")
            Invoke-ClassScope ("`$e=Get-ADEnvironment -Class '$class' -FQDN 'target.example.invalid'; `$e.$class.Report.ExportCSV('$escaped')")
            $rows=@(Import-Csv -LiteralPath $path)
            Assert-ClassEqual 1 $rows.Count
            Assert-ClassTrue ($rows[0].PSObject.Properties.Name -contains 'samaccountname') 'Expected object record columns'
            Assert-ClassTrue ($rows[0].PSObject.Properties.Name -contains 'orgUnit.L0') 'Expected normalized directory hierarchy'
        }
    }
    foreach($name in @('ObjectContractCases.ps1','GroupPolicyContractCases.ps1')) {
        $path=Join-Path (Join-Path $RepositoryRoot 'tests') $name
        if(-not (Test-Path -LiteralPath $path)){throw "Missing required test cases: $name"}
        . $path
    }
}
finally {
    Invoke-ClassScope '[ADEnvironment]::Close()'
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -WhatIf:$false -Confirm:$false
}
Write-Host ("{0} class-contract tests passed; {1} failed" -f $script:ClassPassed,$script:ClassFailed)
if($script:ClassFailed){exit 1}
