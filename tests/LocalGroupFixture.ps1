param([string]$RepositoryRoot,[string]$ScriptName,[string]$Mode)
$ErrorActionPreference='Stop';$env:COMPUTERNAME='fixture-local'
Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
namespace ADAnalyzer.LocalGroupFixture {
 public enum ContextType {Machine}
 public enum IdentityType {SamAccountName,Sid}
 public static class Probe {
  public static string Fault="";public static bool Empty,CredentialsCorrect;public static int Contexts,ContextDisposals,Groups,GroupDisposals,Results,ResultDisposals,Enumerators,EnumeratorDisposals,Retrieved,MemberDisposals,BorrowedDisposals,Prompts,Arity;
  public static List<string> Events=new List<string>();
  public static void Reset(string fault){Fault=fault;Empty=false;CredentialsCorrect=false;Contexts=ContextDisposals=Groups=GroupDisposals=Results=ResultDisposals=Enumerators=EnumeratorDisposals=Retrieved=MemberDisposals=BorrowedDisposals=Prompts=Arity=0;Events.Clear();}
  public static bool Bad(string stage){return Fault==stage || (Fault=="ProjectionAndCleanup" && (stage=="Projection" || stage.EndsWith("Dispose")) );}
 }
 public class PrincipalContext:IDisposable {
  bool disposed,borrowed;string name;
  PrincipalContext(string label){name=label;borrowed=true;}
  public static PrincipalContext Borrowed(){return new PrincipalContext("CONTOSO");}
  void Initialize(ContextType type,string host,int arity){if(type!=ContextType.Machine || !host.StartsWith("fixture-"))throw new Exception("Unexpected machine target");Probe.Arity=arity;if(Probe.Bad("Constructor"))throw new Exception("fixture constructor failure");name=host;Probe.Contexts++;}
  public PrincipalContext(ContextType type,string host){Initialize(type,host,2);}
  public PrincipalContext(ContextType type,string host,string user,string password){Initialize(type,host,4);Probe.CredentialsCorrect=user=="fixture-user" && password=="fixture-only";}
  public string Name {get{if(disposed)throw new ObjectDisposedException("context");if(borrowed && Probe.Bad("ContextProjection"))throw new Exception("fixture context projection failure");return name;}}
  public void Dispose(){disposed=true;if(borrowed){Probe.BorrowedDisposals++;return;}Probe.ContextDisposals++;Probe.Events.Add("context.dispose");if(Probe.Bad("ContextDispose"))throw new Exception("fixture context cleanup failure");}
 }
 public class Principal:IDisposable {
  bool disposed;int number;PrincipalContext context;
  public Principal(int index){number=index;context=PrincipalContext.Borrowed();}
  void Check(){if(disposed)throw new ObjectDisposedException("member");if(Probe.Bad("Projection"))throw new Exception("fixture member projection failure");}
  public string SamAccountName {get{Check();return number==0?"UserOne":"DirectGroup";}}
  public PrincipalContext Context {get{Check();return context;}}
  public void Dispose(){if(disposed)throw new Exception("Member disposed twice");disposed=true;Probe.MemberDisposals++;Probe.Events.Add("member.dispose");if(Probe.Bad("MemberDispose"))throw new Exception("fixture member cleanup failure");}
 }
 public class Result:IEnumerable,IDisposable {
  public Result(){Probe.Results++;}
  public IEnumerator GetEnumerator(){if(Probe.Bad("GetEnumerator"))throw new Exception("fixture enumerator failure");return new ResultEnumerator();}
  public void Dispose(){Probe.ResultDisposals++;Probe.Events.Add("result.dispose");if(Probe.Bad("ResultDispose"))throw new Exception("fixture result cleanup failure");}
 }
 public class ResultEnumerator:IEnumerator,IDisposable {
  int index=-1,lastRead=-1;
  public ResultEnumerator(){Probe.Enumerators++;}
  public bool MoveNext(){if(Probe.Bad("MoveNext") || (Probe.Bad("MoveNextAfterFirst") && index==0))throw new Exception("fixture iteration failure");index++;return !Probe.Empty && index<2;}
  public object Current {get{if(Probe.Bad("Current"))throw new Exception("fixture current failure");if(lastRead==index)throw new Exception("Current read twice");lastRead=index;Probe.Retrieved++;return new Principal(index);}}
  public void Reset(){throw new NotSupportedException();}
  public void Dispose(){Probe.EnumeratorDisposals++;Probe.Events.Add("enumerator.dispose");if(Probe.Bad("EnumeratorDispose"))throw new Exception("fixture enumerator cleanup failure");}
 }
 public class GroupPrincipal:IDisposable {
  public static GroupPrincipal FindByIdentity(PrincipalContext context,IdentityType type,string identity){if(type!=IdentityType.Sid || identity!="S-1-5-32-544")throw new Exception("Localized group lookup did not use SID544");if(Probe.Bad("Lookup"))throw new Exception("fixture lookup failure");if(Probe.Bad("Missing"))return null;Probe.Groups++;return new GroupPrincipal();}
  public object Members {get{throw new Exception("Members property used instead of owned result");}}
  public Result GetMembers(bool recursive){if(recursive)throw new Exception("Direct group members were flattened");if(Probe.Bad("GetMembers"))throw new Exception("fixture members failure");return new Result();}
  public void Dispose(){Probe.GroupDisposals++;Probe.Events.Add("group.dispose");if(Probe.Bad("GroupDispose"))throw new Exception("fixture group cleanup failure");}
 }
}
'@
function Assert-LocalGroup($Value,[string]$Message){if(-not $Value){throw $Message}}
function ConvertTo-LocalGroupFixtureBlock($Ast){
    $source=$Ast.Extent.Text;$offset=$Ast.Extent.StartOffset
    $mapping=@{PrincipalContext='PrincipalContext';GroupPrincipal='GroupPrincipal';ContextType='ContextType';IdentityType='IdentityType';Principal='Principal'}
    foreach($node in @($Ast.FindAll({param($node) $node -is [Management.Automation.Language.TypeExpressionAst]},$true) | Sort-Object {$_.Extent.StartOffset} -Descending)){
        $name=$node.TypeName.FullName -replace '^System\.DirectoryServices\.AccountManagement\.',''
        if($mapping.ContainsKey($name)){$source=$source.Remove($node.Extent.StartOffset-$offset,$node.Extent.EndOffset-$node.Extent.StartOffset).Insert($node.Extent.StartOffset-$offset,'[ADAnalyzer.LocalGroupFixture.'+$mapping[$name]+']')}
    }
    [scriptblock]::Create($source)
}
function Add-Type {[CmdletBinding()]param($AssemblyName) Assert-LocalGroup ($AssemblyName -eq 'System.DirectoryServices.AccountManagement') 'Unexpected framework dependency'}
function Get-Credential {[ADAnalyzer.LocalGroupFixture.Probe]::Prompts++;throw 'Unexpected credential prompt'}
function New-Object {
    [CmdletBinding()]param($TypeName,[object[]]$ArgumentList)
    Assert-LocalGroup ($TypeName -eq 'System.DirectoryServices.AccountManagement.PrincipalContext') 'Unexpected legacy object activation'
    [ADAnalyzer.LocalGroupFixture.PrincipalContext]::new($ArgumentList[0],$ArgumentList[1])
}
$path=Join-Path $RepositoryRoot ('etc/'+$ScriptName)
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Assert-LocalGroup ($errors.Count -eq 0) 'Local group source did not parse'
if($Mode -eq 'Inert'){
    foreach($statement in $ast.EndBlock.Statements){
        $safe=$statement -is [Management.Automation.Language.FunctionDefinitionAst] -or ($statement -is [Management.Automation.Language.IfStatementAst] -and $statement.Extent.Text -match '^if\s*\(\s*\$MyInvocation\.InvocationName\s+-ne\s+''\.''')
        Assert-LocalGroup $safe 'Unsafe automatic startup prevented before source execution'
    }
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');$computerName=@('caller-computer')
    $output=@(. $path)
    Assert-LocalGroup ($output.Count -eq 0 -and [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0 -and [ADAnalyzer.LocalGroupFixture.Probe]::Prompts -eq 0) 'Dot source performed authentication'
    Assert-LocalGroup ($computerName[0] -eq 'caller-computer') 'Dot source changed caller input'
}else{
    foreach($function in @($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})){. (ConvertTo-LocalGroupFixtureBlock $function)}
    if($Mode -eq 'Success'){
        foreach($explicit in @($false,$true)){
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');$arguments=@{ComputerName=@('fixture-one')}
            if($explicit){$arguments.Credential=[pscredential]::new('fixture-user',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))}
            $rows=@(Get-LocalGroupMember @arguments)
            Assert-LocalGroup ($rows.Count -eq 2 -and ($rows.Computer -join ',') -eq 'fixture-one,fixture-one' -and ($rows.Domain -join ',') -eq 'CONTOSO,CONTOSO' -and ($rows.samaccountname -join ',') -eq 'UserOne,DirectGroup') 'Detached direct member rows changed'
            Assert-LocalGroup (($rows[0].PSObject.Properties.Name -join ',') -ceq 'Computer,Domain,samaccountname') 'Member columns changed'
            Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -eq 2 -and [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq 2 -and [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) 'Member/borrowed context ownership failed'
            foreach($name in @('ContextDisposals','GroupDisposals','ResultDisposals','EnumeratorDisposals')){Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::$name -eq 1) ('Cleanup count failed '+$name)}
            $arity=if($explicit){4}else{2};Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::Arity -eq $arity) 'Wrong credential constructor'
            if($explicit){Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::CredentialsCorrect) 'Credential identity changed'}
            $events=[ADAnalyzer.LocalGroupFixture.Probe]::Events
            Assert-LocalGroup ($events.IndexOf('enumerator.dispose') -lt $events.IndexOf('result.dispose') -and $events.IndexOf('result.dispose') -lt $events.IndexOf('group.dispose') -and $events.IndexOf('group.dispose') -lt $events.IndexOf('context.dispose')) 'Resource cleanup order changed'
        }
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');[ADAnalyzer.LocalGroupFixture.Probe]::Empty=$true
        Assert-LocalGroup (@(Get-LocalGroupMember -ComputerName fixture-one).Count -eq 0) 'Empty group produced a fabricated row'
        Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ResultDisposals -eq 1 -and [ADAnalyzer.LocalGroupFixture.Probe]::EnumeratorDisposals -eq 1) 'Empty enumeration leaked resources'
    }elseif($Mode -eq 'Pipeline'){
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');$rows=@(@('fixture-one','fixture-two') | Get-LocalGroupMember)
        Assert-LocalGroup ($rows.Count -eq 4 -and ($rows.Computer -join ',') -eq 'fixture-one,fixture-one,fixture-two,fixture-two') 'Pipeline host order changed'
        Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 2 -and [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq 4 -and [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) 'Pipeline resources leaked'
    }elseif($Mode -eq 'Failures'){
        foreach($fault in @('Constructor','Lookup','Missing','GetMembers','GetEnumerator','MoveNext','MoveNextAfterFirst','Current','Projection','ContextProjection','MemberDispose','EnumeratorDispose','ResultDispose','GroupDispose','ContextDispose','ProjectionAndCleanup')){
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset($fault);$emitted=[Collections.Generic.List[object]]::new();$caught=$null
            try{Get-LocalGroupMember -ComputerName fixture-one | ForEach-Object {$emitted.Add($_)}}catch{$caught=$_}
            Assert-LocalGroup ($null -ne $caught -and $emitted.Count -eq 0) ('Failure emitted partial host data: '+$fault)
            Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -and [ADAnalyzer.LocalGroupFixture.Probe]::GroupDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Groups -and [ADAnalyzer.LocalGroupFixture.Probe]::ResultDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Results -and [ADAnalyzer.LocalGroupFixture.Probe]::EnumeratorDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Enumerators -and [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -and [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) ('Failure cleanup incomplete: '+$fault)
            if($fault -eq 'ProjectionAndCleanup'){
                Assert-LocalGroup ($caught.Exception.ToString() -match 'fixture member projection failure') 'Cleanup hid the projection failure'
                $found=$false;$exception=$caught.Exception
                while($null -ne $exception){if($exception.Data.Contains('ADAnalyzerCleanupErrors')){$found=$true};$exception=$exception.InnerException}
                Assert-LocalGroup $found 'Secondary cleanup diagnostics missing'
            }
        }
    }elseif($Mode -eq 'Validation'){
        foreach($computers in @(@(' '),@('fixture-one',''))){
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');$caught=$false;try{$null=Get-LocalGroupMember -ComputerName $computers}catch{$caught=$true}
            Assert-LocalGroup ($caught -and [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0) 'Invalid host list reached authentication'
        }
    }elseif($Mode -eq 'Cli'){
        $entry=ConvertTo-LocalGroupFixtureBlock $ast
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');$caught=$false;try{& $entry | Out-Null}catch{$caught=$true}
        Assert-LocalGroup ($caught -and [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0) 'CLI without selectors reached authentication'
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('');$rows=@(& $entry -ComputerName fixture-one)
        Assert-LocalGroup ($rows.Count -eq 2 -and [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 1) 'Explicit CLI failed'
    }else{throw 'Unknown local group fixture mode'}
}
'PASS local group contract '+$ScriptName+' '+$Mode
