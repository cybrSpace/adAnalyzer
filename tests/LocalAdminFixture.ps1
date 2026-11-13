param([string]$RepositoryRoot,[string]$Mode)
$ErrorActionPreference='Stop'
function Assert-LocalAdmin($Value,[string]$Message){if(-not $Value){throw $Message}}
$path=Join-Path $RepositoryRoot 'etc/Get-LocalAdministrators.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Assert-LocalAdmin ($errors.Count -eq 0) 'Local-admin source did not parse'
$global:LocalAdminLookups=[Collections.Generic.List[object]]::new()
function Get-LocalUser {[CmdletBinding()]param($SID,$Name) $global:LocalAdminLookups.Add($PSBoundParameters);throw 'Pure classifier attempted local account I/O'}
if($Mode -like 'Classifier*'){
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-LocalAdminObject'},$true)
    . ([scriptblock]::Create($function.Extent.Text))
    if($Mode -eq 'ClassifierGroup'){
        foreach($authority in @('DOMAIN','NT AUTHORITY','fixture-host-extra','fixture.host')){
            $row=New-LocalAdminObject -Domain $authority -Name Group -Class Group -MachineName fixture-host -SID 'S-1-5-21-1-2-3-1001' -SidValid $true
            Assert-LocalAdmin ($row.memberLocal -eq $false -and $null -eq $row.memberLocalEnabled) 'Nonlocal group was treated as local or disabled'
        }
    }elseif($Mode -eq 'ClassifierCloud'){
        $row=New-LocalAdminObject -Domain AzureAD -Name 'S-1-12-1-1-2-3-4' -Class User -MachineName fixture-host -SID 'S-1-12-1-1-2-3-4' -SidValid $true
        Assert-LocalAdmin ($row.memberInvalid -eq $false -and $row.memberLocal -eq $false -and $null -eq $row.memberLocalEnabled -and $row.memberSID -eq 'S-1-12-1-1-2-3-4') 'Valid unresolved Entra SID was invalid or local'
    }elseif($Mode -eq 'ClassifierUnknown'){
        $row=New-LocalAdminObject -Domain fixture-host -Name unresolved -Class User -MachineName fixture-host
        Assert-LocalAdmin ($null -eq $row.memberInvalid -and $null -eq $row.memberLocalEnabled -and $row.memberLocal -eq $false) 'Missing identity evidence became a definite invalid/disabled/local conclusion'
        $bad=New-LocalAdminObject -Domain fixture-host -Name invalid -Class User -MachineName fixture-host -SID malformed -SidValid $false
        Assert-LocalAdmin ($bad.memberInvalid -eq $true -and $bad.memberLocal -eq $false) 'Demonstrated malformed SID was not invalid'
    }elseif($Mode -eq 'ClassifierLocal'){
        foreach($enabled in @($true,$false,$null)){
            $row=New-LocalAdminObject -Domain FIXTURE-HOST -Name local -Class User -MachineName fixture-host -SID 'S-1-5-21-1-2-3-1001' -SidValid $true -EnabledEvidence $enabled
            Assert-LocalAdmin ($row.hostname -eq 'fixture-host' -and $row.memberLocal -eq $true -and $row.memberInvalid -eq $false -and $row.memberLocalEnabled -eq $enabled) 'Exact local evidence or false/unknown enabled state changed'
        }
    }else{throw 'Unknown classifier case'}
    Assert-LocalAdmin ($global:LocalAdminLookups.Count -eq 0) 'Classifier performed account lookup'
}else{
    # Only external CLR type references are adapted. All product branches and CLI binding run unchanged.
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
namespace ADAnalyzer.LocalAdminFixture {
 public static class Probe {
  public static string Fault="",Path="";
  public static int Entries,Disposals,Translations;
  public static bool Disposed;
  public static void Reset(string fault){Fault=fault;Path="";Entries=Disposals=Translations=0;Disposed=false;}
 }
 public class Account {public string Value {get{return "BUILTIN\\Localized Admins";}}}
 public class Sid {
  public string Value {get;private set;}
  public Sid(string value){if(value==null || !value.StartsWith("S-1-") || value=="malformed")throw new ArgumentException("fixture malformed SID");Value=value;}
  public Sid(byte[] value,int offset){
   int code=value[offset];
   if(code==9)throw new ArgumentException("fixture malformed SID");
   if(code==5)Value="S-1-12-1-1-2-3-4";
   else if(code==7)Value="S-1-5-18";
   else if(code==8)Value="S-1-5-32-545";
   else if(code==3 || code==4)Value="S-1-5-21-4-5-6-"+(3000+code);
   else Value="S-1-5-21-1-2-3-"+(1000+code);
  }
  public Account Translate(Type target){Probe.Translations++;if(Value!="S-1-5-32-544" || target.FullName!="System.Security.Principal.NTAccount")throw new Exception("Unexpected SID translation");if(Probe.Fault=="Translate")throw new Exception("fixture translation failure");return new Account();}
  public override string ToString(){return Value;}
 }
 public class Member {
  string name,path,kind;int code;
  public Member(string n,string p,string k,int c){name=n;path=p;kind=k;code=c;}
  void Check(){if(Probe.Disposed)throw new ObjectDisposedException("fixture member");}
  public string Name {get{Check();if(Probe.Fault=="Member" && name=="local-enabled")throw new Exception("fixture member name failure");return name;}}
  public string AdsPath {get{Check();return path;}}
  public string Class {get{Check();return kind;}}
  public object Get(string key){Check();if(key!="objectSID")throw new Exception("Unexpected custom property");if(Probe.Fault=="SidRead" && name=="local-enabled")throw new Exception("fixture SID read failure");return code==0 ? null : (object)new byte[]{(byte)code};}
 }
 public class Entry : IDisposable {
  public Entry(string path){Probe.Path=path;if(path!="WinNT://./Localized Admins,group")throw new Exception("Nonlocal or nonlocalized group path");if(Probe.Fault=="Factory")throw new Exception("fixture entry failure");Probe.Entries++;Probe.Disposed=false;}
  IEnumerable Read(){
   if(Probe.Fault=="Empty")yield break;
   string machine=Environment.MachineName;
   yield return new Member("local-enabled","WinNT://"+machine+"/local-enabled","User",1);
   if(Probe.Fault=="Enumeration" || Probe.Fault=="EnumerationDispose")throw new Exception("fixture enumeration failure");
   yield return new Member("local-disabled","WinNT://"+machine+"/local-disabled","User",2);
   yield return new Member("local-enabled","WinNT://DOMAIN/local-enabled","User",3);
   yield return new Member("Domain Admins","WinNT://DOMAIN/Domain Admins","Group",4);
   yield return new Member("S-1-12-1-1-2-3-4","WinNT://AzureAD/S-1-12-1-1-2-3-4","User",5);
   yield return new Member("cloud-user","WinNT://AzureAD/cloud-user","User",5);
   yield return new Member("local-group","WinNT://"+machine+"/local-group","Group",6);
   yield return new Member("SYSTEM","WinNT://NT AUTHORITY/SYSTEM","User",7);
   yield return new Member("Users","WinNT://BUILTIN/Users","Group",8);
   yield return new Member("malformed","WinNT://"+machine+"/malformed","User",9);
   yield return new Member("missing","WinNT://"+machine+"/missing","User",0);
   yield return new Member("nested-local","WinNT://DOMAIN/"+machine+"/nested-local","User",10);
  }
  public object Invoke(string name,params object[] arguments){if(name!="Members" || arguments.Length!=0)throw new Exception("Unexpected ADSI invocation");return Read();}
  public void Dispose(){Probe.Disposals++;Probe.Disposed=true;if(Probe.Fault=="Dispose" || Probe.Fault=="EnumerationDispose")throw new Exception("fixture disposal failure");}
 }
}
'@
    $source=$ast.Extent.Text
    foreach($node in @($ast.FindAll({param($n) $n -is [Management.Automation.Language.TypeExpressionAst]},$true) | Sort-Object {$_.Extent.StartOffset} -Descending)){
        $replacement=switch($node.TypeName.FullName){
            'System.Security.Principal.SecurityIdentifier' {'[ADAnalyzer.LocalAdminFixture.Sid]'}
            'Security.Principal.SecurityIdentifier' {'[ADAnalyzer.LocalAdminFixture.Sid]'}
            'SecurityIdentifier' {'[ADAnalyzer.LocalAdminFixture.Sid]'}
            'System.DirectoryServices.DirectoryEntry' {'[ADAnalyzer.LocalAdminFixture.Entry]'}
            'DirectoryServices.DirectoryEntry' {'[ADAnalyzer.LocalAdminFixture.Entry]'}
            'DirectoryEntry' {'[ADAnalyzer.LocalAdminFixture.Entry]'}
        }
        if($replacement){$source=$source.Remove($node.Extent.StartOffset,$node.Extent.EndOffset-$node.Extent.StartOffset).Insert($node.Extent.StartOffset,$replacement)}
    }
    Assert-LocalAdmin ($source -match 'ADAnalyzer.LocalAdminFixture.Entry' -and $source -match 'ADAnalyzer.LocalAdminFixture.Sid') 'External framework adapter did not bind both contracts'
    $block=[scriptblock]::Create($source)
    $Invoke='caller-invoke'
    $startup=@(. $block)
    Assert-LocalAdmin ($startup.Count -eq 0 -and [ADAnalyzer.LocalAdminFixture.Probe]::Entries -eq 0 -and [ADAnalyzer.LocalAdminFixture.Probe]::Translations -eq 0) 'Dot source bound or enumerated local accounts'
    Assert-LocalAdmin ($Invoke -ceq 'caller-invoke') 'Dot source changed caller Invoke variable'
    $global:LocalAdminFault=''
    function Get-LocalUser {
        [CmdletBinding()]param($SID,$Name)
        $global:LocalAdminLookups.Add([pscustomobject]@{SID=[string]$SID;Name=$Name})
        if($Name){throw 'Name lookup is forbidden'}
        if($global:LocalAdminFault -eq 'Lookup'){throw 'fixture local-user lookup'}
        if($global:LocalAdminFault -eq 'Missing'){return}
        $returned=if($global:LocalAdminFault -eq 'Mismatch'){'S-1-5-21-1-2-3-9999'}else{[string]$SID}
        $enabled=if([string]$SID -eq 'S-1-5-21-1-2-3-1002'){$false}else{$true}
        if($global:LocalAdminFault -eq 'NonBoolean'){$enabled='true'}
        $result=[pscustomobject]@{SID=[ADAnalyzer.LocalAdminFixture.Sid]::new($returned);Enabled=$enabled}
        $result;if($global:LocalAdminFault -eq 'Multiple'){$result}
    }
    if($Mode -eq 'Inert'){
        Assert-LocalAdmin ($global:LocalAdminLookups.Count -eq 0) 'Dot source queried enabled state'
    }elseif($Mode -eq 'Inventory'){
        [ADAnalyzer.LocalAdminFixture.Probe]::Reset('');$rows=@(Get-LocalAdministrators)
        Assert-LocalAdmin ($rows.Count -eq 12 -and [ADAnalyzer.LocalAdminFixture.Probe]::Entries -eq 1 -and [ADAnalyzer.LocalAdminFixture.Probe]::Disposals -eq 1 -and [ADAnalyzer.LocalAdminFixture.Probe]::Translations -eq 1) 'Inventory/owned entry contract changed'
        Assert-LocalAdmin (($rows[0].PSObject.Properties.Name | Select-Object -First 8) -join ',' -eq 'hostname,memberNetBIOS,memberName,memberClass,memberLocal,memberLocalEnabled,memberInvalid,whenCollected') 'Original output fields changed'
        $enabled=@($rows | Where-Object {$_.memberName -eq 'local-enabled' -and $_.memberLocal})[0]
        $disabled=@($rows | Where-Object memberName -eq local-disabled)[0]
        Assert-LocalAdmin ($enabled.memberLocalEnabled -eq $true -and $disabled.memberLocalEnabled -eq $false) 'Exact local enabled evidence changed'
        Assert-LocalAdmin (@($rows | Where-Object {$_.memberSID -like 'S-1-12-*' -and $_.memberInvalid -eq $false -and $_.memberLocal -eq $false -and $null -eq $_.memberLocalEnabled}).Count -eq 2) 'Entra records misclassified'
        Assert-LocalAdmin (@($rows | Where-Object {$_.memberNetBIOS -eq 'DOMAIN' -and $_.memberLocal -eq $false -and $null -eq $_.memberLocalEnabled}).Count -eq 2) 'Domain principal classified as local'
        Assert-LocalAdmin (@($rows | Where-Object {$_.memberName -eq 'nested-local' -and $_.memberLocal -eq $true}).Count -eq 1) 'Three-part WinNT path lost local authority'
        Assert-LocalAdmin (@($rows | Where-Object {$_.memberName -eq 'malformed' -and $_.memberInvalid -eq $true}).Count -eq 1 -and @($rows | Where-Object {$_.memberName -eq 'missing' -and $null -eq $_.memberInvalid}).Count -eq 1) 'Unknown/invalid SID evidence collapsed'
        Assert-LocalAdmin ($global:LocalAdminLookups.Count -eq 3 -and ($global:LocalAdminLookups.SID -join ',') -eq 'S-1-5-21-1-2-3-1001,S-1-5-21-1-2-3-1002,S-1-5-21-1-2-3-1010') 'Enabled lookup scope expanded beyond exact local users'
        foreach($row in $rows){Assert-LocalAdmin ($row -is [pscustomobject] -and $row.hostname -eq [Environment]::MachineName) 'Returned native principal or wrong machine'}
    }elseif($Mode -eq 'LookupEvidence'){
        foreach($fault in @('Lookup','Mismatch','Missing','Multiple','NonBoolean')){
            [ADAnalyzer.LocalAdminFixture.Probe]::Reset('');$global:LocalAdminFault=$fault;$rows=@(Get-LocalAdministrators)
            Assert-LocalAdmin (@($rows | Where-Object {$_.memberClass -eq 'User' -and $_.memberLocal -and $null -ne $_.memberLocalEnabled}).Count -eq 0) ('Unverified enabled evidence copied '+$fault)
        }
    }elseif($Mode -eq 'Partial'){
        foreach($fault in @('Member','SidRead')){
            [ADAnalyzer.LocalAdminFixture.Probe]::Reset($fault);$rows=@(Get-LocalAdministrators)
            Assert-LocalAdmin ($rows.Count -eq 12 -and @($rows | Where-Object {$_.memberMessage -match 'fixture'}).Count -ge 1 -and [ADAnalyzer.LocalAdminFixture.Probe]::Disposals -eq 1) ('Member failure erased inventory/evidence '+$fault)
            if($fault -eq 'SidRead'){Assert-LocalAdmin ($null -eq $rows[0].memberInvalid -and $null -eq $rows[0].memberLocalEnabled) 'Unreadable SID became invalid/disabled'}
        }
    }elseif($Mode -eq 'Failures'){
        foreach($fault in @('Translate','Factory','Enumeration','Dispose','EnumerationDispose')){
            [ADAnalyzer.LocalAdminFixture.Probe]::Reset($fault);$emitted=[Collections.Generic.List[object]]::new();$caught=$null
            try{Get-LocalAdministrators | ForEach-Object {$emitted.Add($_)}}catch{$caught=$_}
            Assert-LocalAdmin ($null -ne $caught -and $emitted.Count -eq 0) ('Lifecycle failure emitted success '+$fault)
            Assert-LocalAdmin ([ADAnalyzer.LocalAdminFixture.Probe]::Disposals -eq $(if($fault -in @('Translate','Factory')){0}else{1})) ('Owned entry not cleaned '+$fault)
            if($fault -eq 'EnumerationDispose'){Assert-LocalAdmin ($caught.Exception.Message -match 'enumeration' -and $caught.Exception.Data['ADAnalyzerCleanupErrors']) 'Cleanup hid original failure'}
        }
    }elseif($Mode -eq 'Empty'){
        [ADAnalyzer.LocalAdminFixture.Probe]::Reset('Empty');$rows=@(Get-LocalAdministrators)
        Assert-LocalAdmin ($rows.Count -eq 0 -and [ADAnalyzer.LocalAdminFixture.Probe]::Disposals -eq 1) 'Empty group had fake/stale rows or leaked'
    }elseif($Mode -eq 'Cli'){
        [ADAnalyzer.LocalAdminFixture.Probe]::Reset('');$caught=$false;try{& $block | Out-Null}catch{$caught=$true}
        Assert-LocalAdmin ($caught -and [ADAnalyzer.LocalAdminFixture.Probe]::Entries -eq 0) 'CLI enumerated without explicit Invoke'
        $rows=@(& $block -Invoke);Assert-LocalAdmin ($rows.Count -eq 12 -and [ADAnalyzer.LocalAdminFixture.Probe]::Disposals -eq 1) 'Explicit CLI failed'
    }else{throw 'Unknown fixture mode'}
}
'PASS local-admin inventory '+$Mode
