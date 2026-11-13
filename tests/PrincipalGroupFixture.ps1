using namespace ADAnalyzer.PrincipalFixture
param([string]$RepositoryRoot,[string]$ScriptName,[string]$Mode)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace ADAnalyzer.PrincipalFixture {
 public enum ContextType { Machine }
 public enum IdentityType { SamAccountName }
 public static class Probe {
  public static string Fault=""; public static int Prompts,Contexts,ContextDisposals,Groups,GroupDisposals,Arity;
  public static bool CredentialsCorrect; public static List<string> Events=new List<string>();
  public static void Reset(string fault) { Fault=fault;Prompts=Contexts=ContextDisposals=Groups=GroupDisposals=Arity=0;CredentialsCorrect=false;Events.Clear(); }
 }
 public class PrincipalContext : IDisposable {
  public static bool FixtureMarker {get{return true;}}
  public bool Disposed;
  void Initialize(ContextType type,string name,int arity) {
   if(type!=ContextType.Machine || name!="fixture-host")throw new Exception("Unexpected context target");
   Probe.Arity=arity;Probe.Events.Add("context.create");
   if(Probe.Fault=="Constructor")throw new Exception("fixture constructor failure");Probe.Contexts++;
  }
  public PrincipalContext(ContextType type,string name){Initialize(type,name,2);}
  public PrincipalContext(ContextType type,string name,string user,string password){Initialize(type,name,4);Probe.CredentialsCorrect=user=="fixture-user" && password=="fixture-only";}
  public void Dispose(){Disposed=true;Probe.ContextDisposals++;Probe.Events.Add("context.dispose");if(Probe.Fault=="ContextDispose" || Probe.Fault=="BothDispose" || Probe.Fault=="ProjectionAndDispose" || Probe.Fault=="LookupContextDispose")throw new Exception("fixture context cleanup failure");}
 }
 public class FixtureSid {public string Value {get{return "S-1-5-32-544";}}}
 public class GroupPrincipal : IDisposable {
  bool disposed;
  void Check(){if(disposed)throw new ObjectDisposedException("fixture principal");if(Probe.Fault=="Projection" || Probe.Fault=="ProjectionAndDispose")throw new Exception("fixture projection failure");}
  public string Name {get{Check();return "Fixture Group";}}
  public string SamAccountName {get{Check();return "FixtureGroup";}}
  public FixtureSid Sid {get{Check();return new FixtureSid();}}
  public string Description {get{Check();return "Detached fixture metadata";}}
  public static GroupPrincipal FindByIdentity(PrincipalContext context,IdentityType type,string identity) {
   if(context.Disposed || type!=IdentityType.SamAccountName || identity!="FixtureGroup")throw new Exception("Unexpected lookup contract");
   Probe.Events.Add("group.lookup");if(Probe.Fault=="Lookup" || Probe.Fault=="LookupContextDispose")throw new Exception("fixture lookup failure");
   if(Probe.Fault=="Missing")return null;Probe.Groups++;return new GroupPrincipal();
  }
  public void Dispose(){disposed=true;Probe.GroupDisposals++;Probe.Events.Add("group.dispose");if(Probe.Fault=="GroupDispose" || Probe.Fault=="BothDispose" || Probe.Fault=="ProjectionAndDispose")throw new Exception("fixture group cleanup failure");}
 }
}
'@
function Assert-Principal($Value,[string]$Message){if(-not $Value){throw $Message}}
function ConvertTo-PrincipalFixtureBlock($Ast){
    $source=$Ast.Extent.Text;$offset=$Ast.Extent.StartOffset
    $mapping=@{PrincipalContext='PrincipalContext';GroupPrincipal='GroupPrincipal';ContextType='ContextType';IdentityType='IdentityType'}
    $edits=@($Ast.FindAll({param($node) $node -is [Management.Automation.Language.TypeExpressionAst]},$true) | Sort-Object {$_.Extent.StartOffset} -Descending)
    foreach($node in $edits){
        $name=$node.TypeName.FullName -replace '^System\.DirectoryServices\.AccountManagement\.',''
        if($mapping.ContainsKey($name)){
            $replacement='[ADAnalyzer.PrincipalFixture.'+$mapping[$name]+']'
            $source=$source.Remove($node.Extent.StartOffset-$offset,$node.Extent.EndOffset-$node.Extent.StartOffset).Insert($node.Extent.StartOffset-$offset,$replacement)
        }
    }
    [scriptblock]::Create($source)
}
$global:ADAnalyzerHpaFrameworkLoads=0
function Add-Type {
    [CmdletBinding()]param([string]$AssemblyName)
    Assert-Principal ($AssemblyName -eq 'System.DirectoryServices.AccountManagement') 'Unexpected framework dependency'
    $global:ADAnalyzerHpaFrameworkLoads++
}
$global:ADAnalyzerHpaPromptBlocked=$Mode -in 'Inert','Cli','Validation'
function Get-Credential {
    [ADAnalyzer.PrincipalFixture.Probe]::Prompts++
    if($global:ADAnalyzerHpaPromptBlocked){throw 'Unexpected credential prompt'}
    [pscredential]::new('fixture-user',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
}
$path=Join-Path $RepositoryRoot ('etc/'+$ScriptName)
if($Mode -eq 'Inert'){
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('');$computer='caller-computer';$target='caller-target'
    $output=@(. $path)
    Assert-Principal ($output.Count -eq 0 -and [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0) 'Dot sourcing performed authentication or emitted data'
    Assert-Principal ($computer -eq 'caller-computer' -and $target -eq 'caller-target') 'Dot sourcing changed caller inputs'
}else{
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Assert-Principal ($errors.Count -eq 0) 'Host-group source did not parse'
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ServerHPA'},$true)
    Assert-Principal ($null -ne $function) 'Host-group function is missing'
    . (ConvertTo-PrincipalFixtureBlock $function)
    Assert-Principal ([ADAnalyzer.PrincipalFixture.PrincipalContext]::FixtureMarker) 'Fixture did not bind its isolated CLR contracts'
    if($Mode -eq 'Success'){
        foreach($explicit in @($false,$true)){
            [ADAnalyzer.PrincipalFixture.Probe]::Reset('');$arguments=@{Computer='fixture-host';Target='FixtureGroup'}
            if($explicit){$arguments.Credential=[pscredential]::new('fixture-user',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))}
            $rows=@(Get-ServerHPA @arguments)
            $name=$rows[0].Name
            Assert-Principal ($rows.Count -eq 1 -and $rows[0] -is [pscustomobject] -and $name -eq 'Fixture Group') 'Host-group result was not one detached record'
            Assert-Principal ($rows[0].Computer -eq 'fixture-host' -and $rows[0].Name -eq 'Fixture Group' -and $rows[0].SamAccountName -eq 'FixtureGroup' -and $rows[0].SID -eq 'S-1-5-32-544' -and $rows[0].Description -eq 'Detached fixture metadata') 'Detached metadata changed or was read after disposal'
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 1 -and [ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq 1 -and [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq 1) 'Owned resources or prompt contract failed'
            $arity=if($explicit){4}else{2};Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::Arity -eq $arity) 'Wrong context constructor selected'
            if($explicit){Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::CredentialsCorrect) 'Explicit credential identity changed'}
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::Events.IndexOf('group.dispose') -lt [ADAnalyzer.PrincipalFixture.Probe]::Events.IndexOf('context.dispose')) 'Cleanup ownership order changed'
            foreach($property in $rows[0].PSObject.Properties){Assert-Principal ($property.Value -isnot [ADAnalyzer.PrincipalFixture.PrincipalContext] -and $property.Value -isnot [ADAnalyzer.PrincipalFixture.GroupPrincipal]) 'A live or disposed principal reference escaped'}
        }
    }elseif($Mode -eq 'Failures'){
        foreach($fault in @('Constructor','Lookup','Missing','Projection','GroupDispose','ContextDispose','BothDispose','ProjectionAndDispose','LookupContextDispose')){
            [ADAnalyzer.PrincipalFixture.Probe]::Reset($fault);$emitted=[Collections.Generic.List[object]]::new();$caught=$null
            try{Get-ServerHPA -Computer fixture-host -Target FixtureGroup | ForEach-Object {$emitted.Add($_)}}catch{$caught=$_}
            Assert-Principal ($null -ne $caught -and $emitted.Count -eq 0) ('Failure emitted success: '+$fault)
            $expected=if($fault -eq 'Missing'){'not found'}elseif($fault -like 'Lookup*'){'fixture lookup failure'}elseif($fault -like 'Projection*'){'fixture projection failure'}elseif($fault -eq 'Constructor'){'fixture constructor failure'}elseif($fault -eq 'ContextDispose'){'fixture context cleanup failure'}else{'fixture group cleanup failure'}
            Assert-Principal ($caught.Exception.Message -match [regex]::Escape($expected)) ('Primary failure was lost: '+$fault)
            $contexts=if($fault -eq 'Constructor'){0}else{1};$groups=if($fault -in 'Constructor','Lookup','Missing','LookupContextDispose'){0}else{1}
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq $contexts -and [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq $groups) ('Cleanup was incomplete: '+$fault)
            if($fault -in 'BothDispose','ProjectionAndDispose','LookupContextDispose'){
                $secondary=$false;$exception=$caught.Exception
                while($null -ne $exception){if($exception.Data.Contains('ADAnalyzerCleanupErrors')){$secondary=$true};$exception=$exception.InnerException}
                Assert-Principal $secondary ('Secondary cleanup evidence was lost: '+$fault)
            }
        }
    }elseif($Mode -eq 'Validation'){
        foreach($arguments in @(@{},@{Computer=' ';Target='FixtureGroup'},@{Computer='fixture-host';Target=''})){
            [ADAnalyzer.PrincipalFixture.Probe]::Reset('');$caught=$false;try{$null=Get-ServerHPA @arguments}catch{$caught=$true}
            Assert-Principal ($caught -and [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0) 'Invalid inputs reached authentication'
        }
    }elseif($Mode -eq 'Cli'){
        $entry=ConvertTo-PrincipalFixtureBlock $ast
        [ADAnalyzer.PrincipalFixture.Probe]::Reset('');$caught=$false;try{& $entry | Out-Null}catch{$caught=$true}
        Assert-Principal ($caught -and [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0) 'CLI without selectors reached authentication'
        [ADAnalyzer.PrincipalFixture.Probe]::Reset('');$rows=@(& $entry -Computer fixture-host -Target FixtureGroup)
        Assert-Principal ($rows.Count -eq 1 -and $rows[0].SID -eq 'S-1-5-32-544' -and [ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq 1 -and [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq 1) 'Explicit CLI did not return detached metadata'
    }else{throw 'Unknown principal fixture mode'}
}
'PASS host-group principal contract '+$ScriptName+' '+$Mode
