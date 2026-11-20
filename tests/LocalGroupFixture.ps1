param(
    [string]$RepositoryRoot,
    [ValidateSet('Get-LocalGroup.ps1', 'Get-LocalGroup copy.ps1')][string]$ScriptName,
    [ValidateSet('Inert', 'Success', 'Name', 'Pipeline', 'Failures', 'Validation', 'Cli', 'Direct', 'Runspace')][string]$Mode
)
$ErrorActionPreference = 'Stop'
$env:COMPUTERNAME = 'fixture-local'
$fixtureTypes = @'
using System;
using System.Collections;
using System.Collections.Generic;
namespace ADAnalyzer.LocalGroupFixture {
 public enum ContextType {Machine}
 public enum IdentityType {SamAccountName,Sid}
 public static class Probe {
  public static string Fault="",FaultHost="",ActiveHost="";public static bool Empty,CredentialsCorrect;public static int Contexts,ContextDisposals,Groups,GroupDisposals,Results,ResultDisposals,Enumerators,EnumeratorDisposals,Retrieved,MemberDisposals,BorrowedDisposals,Prompts,Arity;
  public static List<string> Events=new List<string>();
  public static void Reset(string fault){Fault=fault;FaultHost=ActiveHost="";Empty=false;CredentialsCorrect=false;Contexts=ContextDisposals=Groups=GroupDisposals=Results=ResultDisposals=Enumerators=EnumeratorDisposals=Retrieved=MemberDisposals=BorrowedDisposals=Prompts=Arity=0;Events.Clear();}
  public static bool Bad(string stage){return (FaultHost=="" || ActiveHost==FaultHost) && (Fault==stage || (Fault=="ProjectionAndCleanup" && (stage=="Projection" || stage.EndsWith("Dispose"))));}
 }
 public class PrincipalContext:IDisposable {
  bool disposed,borrowed;string name;
  PrincipalContext(string label){name=label;borrowed=true;}
  public static PrincipalContext Borrowed(){return new PrincipalContext("CONTOSO");}
  void Initialize(ContextType type,string host,int arity){if(type!=ContextType.Machine || !host.StartsWith("fixture-"))throw new Exception("Unexpected machine target");Probe.ActiveHost=host;Probe.Arity=arity;if(Probe.Bad("Constructor"))throw new Exception("fixture constructor failure");name=host;Probe.Contexts++;}
  public PrincipalContext(ContextType type,string host){Initialize(type,host,2);}
  public PrincipalContext(ContextType type,string host,string user,string password){Initialize(type,host,4);Probe.CredentialsCorrect=user=="fixture-user" && password=="fixture-only";}
  public string Name {get{if(disposed)throw new ObjectDisposedException("context");if(borrowed){Probe.Events.Add("get.Context.Name");if(Probe.Bad("ContextProjection"))throw new Exception("fixture context projection failure");}return name;}}
  public void Dispose(){disposed=true;if(borrowed){Probe.BorrowedDisposals++;return;}Probe.ContextDisposals++;Probe.Events.Add("context.dispose");if(Probe.Bad("ContextDispose"))throw new Exception("fixture context cleanup failure");}
 }
 public class Principal:IDisposable {
  bool disposed;int number;PrincipalContext context;
  public Principal(int index){number=index;context=PrincipalContext.Borrowed();}
  void Check(){if(disposed)throw new ObjectDisposedException("member");if(Probe.Bad("Projection"))throw new Exception("fixture member projection failure");}
  public string SamAccountName {get{Probe.Events.Add("get.SamAccountName");Check();return number==0?"UserOne":"DirectGroup";}}
  public string Name {get{Probe.Events.Add("get.Name");Check();if(Probe.Bad("NameProjection"))throw new Exception("fixture name projection failure");if(Probe.Bad("NameMissing"))return null;return number==0?"Display One":"Display Group";}}
  public PrincipalContext Context {get{Probe.Events.Add("get.Context");Check();return Probe.Bad("NullContext")?null:context;}}
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
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $fixtureTypes -ErrorAction Stop

function Assert-LocalGroup($Value, [string]$Message) {
    if (-not $Value) {
        throw $Message
    }
}

function Read-LocalGroupFixtureAst([string]$Path) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    Assert-LocalGroup ($errors.Count -eq 0) ('Local-group source did not parse: ' + $Path)
    return $ast
}

function ConvertTo-LocalGroupFixtureSource([string]$Path) {
    $ast = Read-LocalGroupFixtureAst $Path
    $source = $ast.Extent.Text
    $offset = $ast.Extent.StartOffset
    $typeNames = @('PrincipalContext', 'GroupPrincipal', 'ContextType', 'IdentityType')
    $seen = @{}
    $nodes = @($ast.FindAll({
                param($node)

                $node -is [Management.Automation.Language.TypeExpressionAst] -or
                    ($node -is [Management.Automation.Language.StringConstantExpressionAst] -and
                        $node.Parent -is [Management.Automation.Language.ConvertExpressionAst] -and
                        $node.Parent.Type.TypeName.FullName -ieq 'type' -and
                        [object]::ReferenceEquals($node, $node.Parent.Child))
            }, $true) | Sort-Object -Property { $_.Extent.StartOffset } -Descending)
    foreach ($node in $nodes) {
        $isStatic = $node -is [Management.Automation.Language.TypeExpressionAst]
        $name = if ($isStatic) {
            $node.TypeName.FullName
        }
        else {
            $node.Value
        }
        $name = $name -replace '^System\.DirectoryServices\.AccountManagement\.', ''
        if ($name -notin $typeNames) {
            continue
        }
        $seen[$name] = $true
        $fakeType = 'ADAnalyzer.LocalGroupFixture.' + $name
        $replacement = if ($isStatic) {
            '[' + $fakeType + ']'
        }
        else {
            "'" + $fakeType + "'"
        }
        $start = $node.Extent.StartOffset - $offset
        $length = $node.Extent.EndOffset - $node.Extent.StartOffset
        $source = $source.Remove($start, $length).Insert($start, $replacement)
    }
    foreach ($name in $typeNames) {
        Assert-LocalGroup ($seen.ContainsKey($name)) ('Missing isolated type mapping for ' + $name + ' in ' + $Path)
    }
    Assert-LocalGroup ($source -notmatch '(?i)System\.DirectoryServices\.AccountManagement\.' -and
        $source -notmatch '(?i)\\Add-Type\b') ('Unsafe framework reference in transformed source: ' + $Path)
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseInput($source, $Path, [ref]$tokens, [ref]$errors)
    Assert-LocalGroup ($errors.Count -eq 0) ('Isolated local-group source did not parse: ' + $Path)
    return $source
}

function New-LocalGroupFixturePackage([string]$Stage) {
    $names = @(
        'bin/ADLocalGroupReader.ps1'
        'etc/Get-LocalGroup.ps1'
        'etc/Get-LocalGroup copy.ps1'
    )
    foreach ($name in $names) {
        $path = Join-Path $Stage $name
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        $source = ConvertTo-LocalGroupFixtureSource (Join-Path $RepositoryRoot $name)
        [IO.File]::WriteAllText($path, $source, [Text.UTF8Encoding]::new($false))
    }
}

$script:FrameworkLoads = 0

function Add-Type {
    [CmdletBinding()]
    param($AssemblyName)

    Assert-LocalGroup ($AssemblyName -ceq 'System.DirectoryServices.AccountManagement') 'Unexpected framework dependency'
    $script:FrameworkLoads++
    if ($Mode -eq 'Inert') {
        throw 'Unexpected framework load during inert bootstrap'
    }
}

function Get-Credential {
    [ADAnalyzer.LocalGroupFixture.Probe]::Prompts++
    throw 'Unexpected credential prompt'
}

function New-Object {
    [CmdletBinding()]param(
        $TypeName,
        [object[]]$ArgumentList

    )
    Assert-LocalGroup ($TypeName -eq 'System.DirectoryServices.AccountManagement.PrincipalContext') 'Unexpected legacy object activation'
    [ADAnalyzer.LocalGroupFixture.PrincipalContext]::new($ArgumentList[0], $ArgumentList[1])
}

function Assert-LocalGroupInertSource($Ast) {
    $expectedLoader = '. (Join-Path -Path $PSScriptRoot -ChildPath ''../bin/ADLocalGroupReader.ps1'')'
    foreach ($statement in $Ast.EndBlock.Statements) {
        $safe = $statement -is [Management.Automation.Language.FunctionDefinitionAst] -or
            ($statement -is [Management.Automation.Language.PipelineAst] -and $statement.Extent.Text.Trim() -ceq $expectedLoader) -or
            ($statement -is [Management.Automation.Language.IfStatementAst] -and
                $statement.Extent.Text -match '^if\s*\(\s*\$MyInvocation\.InvocationName\s+-ne\s+''\.''')
        Assert-LocalGroup $safe 'Unsafe automatic startup prevented before source execution'
    }
}

function Assert-LocalGroupOwnedCleanup {
    Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -and
        [ADAnalyzer.LocalGroupFixture.Probe]::GroupDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Groups -and
        [ADAnalyzer.LocalGroupFixture.Probe]::ResultDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Results -and
        [ADAnalyzer.LocalGroupFixture.Probe]::EnumeratorDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Enumerators -and
        [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -and
        [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0 -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Prompts -eq 0) 'Resource ownership or prompt behavior changed'
}

function Get-LocalGroupFixtureFingerprint($Rows) {
    ConvertTo-Json -InputObject $Rows -Compress -Depth 5
}

function Get-LocalGroupFixtureFailure([scriptblock]$Operation, [int]$ExpectedRows = 0) {
    $emitted = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Operation | ForEach-Object { $emitted.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-LocalGroup ($null -ne $failure -and $emitted.Count -eq $ExpectedRows) 'Expected the failure with the original output cutoff'
    return $failure
}

function Invoke-LocalGroupNameConsumerCases([string]$Stage, [pscredential]$Credential) {
    $original = Join-Path $RepositoryRoot 'etc/Get-ComputerADSI.ps1'
    $consumer = Join-Path $Stage 'etc/Get-ComputerADSI.ps1'
    [IO.File]::Copy($original, $consumer)
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $startup = @(. $consumer)
    $names = @(Get-ComputerAdministratorName -ComputerName @('fixture-one', 'fixture-two') -Credential $Credential)
    Assert-LocalGroup ($startup.Count -eq 0 -and ($names -join '|') -ceq 'Display One|Display Group|Display One|Display Group' -and
        [ADAnalyzer.LocalGroupFixture.Probe]::CredentialsCorrect -and
        [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 2) 'The real name adapter lost the chosen members or credential'
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('MoveNextAfterFirst')
    [ADAnalyzer.LocalGroupFixture.Probe]::FaultHost = 'fixture-two'
    $failure = Get-LocalGroupFixtureFailure {
        Get-ComputerAdministratorName -ComputerName @('fixture-one', 'fixture-two') -Credential $Credential
    }
    Assert-LocalGroup ($failure.Exception.ToString() -match 'fixture iteration failure' -and
        [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 2) 'A later host did not reach the real name adapter'
    Assert-LocalGroupOwnedCleanup
}

function Invoke-LocalGroupDirectCases([string]$Stage) {
    $owner = [ADAnalyzerLocalGroupReader]::new()
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $start = $script:FrameworkLoads
    foreach ($invalid in @(
            @{
                Input = $null
                Error = 'Specify at least one computer.'
            }
            @{
                Input = [string[]]@()
                Error = 'Specify at least one computer.'
            }
            @{
                Input = @('fixture-one', ' ')
                Error = 'Computer names must be nonempty strings.'
            }
            @{
                Input = @('fixture-one', $null)
                Error = 'Computer names must be nonempty strings.'
            }
        )) {
        $failure = Get-LocalGroupFixtureFailure { $owner.Read($invalid.Input) }
        Assert-LocalGroup ($failure.Exception.GetBaseException().Message -ceq $invalid.Error) 'Direct validation changed its diagnostic'
    }
    $failure = Get-LocalGroupFixtureFailure {
        Set-StrictMode -Version Latest
        $owner.Read($null)
    }
    Assert-LocalGroup ($failure.Exception.GetBaseException().Message -ceq 'Specify at least one computer.') (
        'Strict-mode direct validation changed its diagnostic'
    )
    Assert-LocalGroup ($script:FrameworkLoads -eq $start -and [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0) (
        'Direct validation did not precede all framework access'
    )

    $computers = [string[]]@('fixture-one', 'fixture-two')
    $ordinary = $owner.Read($computers)
    Assert-LocalGroup ($ordinary -is [object[]] -and $ordinary.Count -eq 4 -and
        ($ordinary.Computer -join ',') -ceq 'fixture-one,fixture-one,fixture-two,fixture-two' -and
        ($ordinary[0].PSObject.Properties.Name -join ',') -ceq 'Computer,Domain,samaccountname' -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Arity -eq 2 -and $script:FrameworkLoads -eq $start + 1 -and
        ($computers -join ',') -ceq 'fixture-one,fixture-two') 'Direct default shape, selection order or input ownership changed'
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $native = @(Get-LocalGroupMember -ComputerName $computers)
    Assert-LocalGroup ((Get-LocalGroupFixtureFingerprint $ordinary) -ceq (Get-LocalGroupFixtureFingerprint $native)) 'Default direct/native results differ'

    $login = [pscredential]::new('fixture-user', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $withName = $owner.Read($computers, $login, $true)
    Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::Arity -eq 4 -and
        [ADAnalyzer.LocalGroupFixture.Probe]::CredentialsCorrect -and
        ($withName[0].PSObject.Properties.Name -join ',') -ceq 'Computer,Domain,samaccountname,Name' -and
        ($withName.Name -join '|') -ceq 'Display One|Display Group|Display One|Display Group') 'Optional Name or explicit credentials changed'
    $observed = [ADAnalyzer.LocalGroupFixture.Probe]::Events -join '|'
    $oneMember = 'get.Context|get.Context.Name|get.SamAccountName|get.Name|member.dispose'
    $oneHost = "$oneMember|$oneMember|enumerator.dispose|result.dispose|group.dispose|context.dispose"
    Assert-LocalGroup ($observed -ceq "$oneHost|$oneHost") 'Member getter or cleanup order changed'
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $nativeNames = @(Get-LocalGroupMember -ComputerName $computers -Credential $login -IncludeName)
    Assert-LocalGroup ((Get-LocalGroupFixtureFingerprint $withName) -ceq (Get-LocalGroupFixtureFingerprint $nativeNames)) 'Optional Name direct/native results differ'

    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('NameProjection')
    $withoutName = $owner.Read(@('fixture-one'), $login)
    Assert-LocalGroup ($withoutName.Count -eq 2 -and -not $withoutName[0].PSObject.Properties['Name'] -and
        -not [ADAnalyzer.LocalGroupFixture.Probe]::Events.Contains('get.Name')) 'Default reader eagerly read Name'
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('NullContext')
    $nullable = $owner.Read(@('fixture-one'), [pscredential]::Empty, $true)
    Assert-LocalGroup ($nullable.Count -eq 2 -and $null -eq $nullable[0].Domain -and $null -eq $nullable[1].Domain -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Arity -eq 2) 'A missing borrowed context became a fabricated domain'
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    [ADAnalyzer.LocalGroupFixture.Probe]::Empty = $true
    $empty = $owner.Read(@('fixture-one'))
    Assert-LocalGroup ($empty -is [object[]] -and $empty.Count -eq 0) 'Empty membership produced an invented row'
    Assert-LocalGroupOwnedCleanup

    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('MoveNextAfterFirst')
    [ADAnalyzer.LocalGroupFixture.Probe]::FaultHost = 'fixture-two'
    $failure = Get-LocalGroupFixtureFailure { $owner.Read($computers) }
    Assert-LocalGroup ($failure.Exception.ToString() -match 'fixture iteration failure' -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 2 -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -eq 3) 'Whole-call reader did not reach a late failing host'
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('MoveNextAfterFirst')
    [ADAnalyzer.LocalGroupFixture.Probe]::FaultHost = 'fixture-two'
    $null = Get-LocalGroupFixtureFailure { Get-LocalGroupMember -ComputerName $computers } 2
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $first = @(Get-LocalGroupMember -ComputerName $computers | Select-Object -First 1)
    Assert-LocalGroup ($first.Count -eq 1 -and $first[0].Computer -ceq 'fixture-one' -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 1 -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -eq 2) 'Native early cutoff failed to finish just the selected host'
    Assert-LocalGroupOwnedCleanup

    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('ProjectionAndCleanup')
    $failure = Get-LocalGroupFixtureFailure { $owner.Read(@('fixture-one')) }
    $messages = @()
    $exception = $failure.Exception
    while ($null -ne $exception) {
        if ($exception.Data.Contains('ADAnalyzerCleanupErrors')) {
            $messages = @($exception.Data['ADAnalyzerCleanupErrors'])
            break
        }
        $exception = $exception.InnerException
    }
    $events = [ADAnalyzer.LocalGroupFixture.Probe]::Events -join '|'
    Assert-LocalGroup ($failure.Exception.ToString() -match 'fixture member projection failure' -and
        $messages.Count -eq 5 -and $events -ceq 'get.Context|member.dispose|enumerator.dispose|result.dispose|group.dispose|context.dispose') (
        'Compound direct failure hid its cause or cleanup order'
    )
    Assert-LocalGroupOwnedCleanup
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $withName[0].Name = 'changed result only'
    $again = $owner.Read($computers, $null, $true)
    Assert-LocalGroup ((Get-LocalGroupFixtureFingerprint $again) -ceq (Get-LocalGroupFixtureFingerprint $nativeNames) -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Arity -eq 2 -and
        [Management.Automation.PSSerializer]::Serialize($owner) -cnotmatch 'fixture-only|fixture-user|PSCredential|PrincipalContext') (
        'Result mutation, credential or failed operation affected instance reuse'
    )
    Assert-LocalGroupOwnedCleanup
    Invoke-LocalGroupNameConsumerCases $Stage $login
}

function Invoke-LocalGroupRunspaceCases([string]$Entry) {
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $owner = [ADAnalyzerLocalGroupReader]::new()
    $expected = Get-LocalGroupFixtureFingerprint ($owner.Read(@('fixture-one'), [pscredential]::Empty, $true))
    Assert-LocalGroupOwnedCleanup
    $runner = [powershell]::Create()
    try {
        $body = @'
param([string]$Entry)
$ErrorActionPreference = 'Stop'
if ('ADAnalyzerLocalGroupReader' -as [type]) {
    throw 'Secondary runspace inherited a preloaded reader type'
}
if (-not ('ADAnalyzer.LocalGroupFixture.Probe' -as [type])) {
    throw 'Secondary runspace did not load the inert fixture types'
}
function Add-Type {
    [CmdletBinding()]
    param([string]$AssemblyName)

    if ($AssemblyName -cne 'System.DirectoryServices.AccountManagement') {
        throw 'Unexpected framework request in secondary runspace'
    }
    $script:fixtureFrameworkLoads++
}
function Get-Credential {
    throw 'Unexpected credential prompt in secondary runspace'
}
$script:fixtureFrameworkLoads = 0
[ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
$startup = @(. $Entry)
$owner = [ADAnalyzerLocalGroupReader]::new()
if ($startup.Count -ne 0 -or $script:fixtureFrameworkLoads -ne 0) {
    throw 'Loading or construction entered the framework seam'
}
foreach ($index in 1..2) {
    $rows = $owner.Read(@('fixture-one'), [pscredential]::Empty, $true)
    if ($rows.Count -ne 2 -or [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -ne $index -or
        [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -ne 0 -or $script:fixtureFrameworkLoads -ne $index) {
        throw 'Secondary runspace did not acquire and release each read independently'
    }
    ConvertTo-Json -InputObject $rows -Compress -Depth 5
}
'@
        $null = $runner.AddScript($body).AddArgument($Entry)
        $results = @($runner.Invoke())
        Assert-LocalGroup (-not $runner.HadErrors -and $results.Count -eq 2 -and
            [string]$results[0] -ceq $expected -and [string]$results[1] -ceq $expected) (
            'Secondary runspace did not reuse the selected reader: ' + ($runner.Streams.Error -join ' | ')
        )
    }
    finally {
        $runner.Dispose()
    }
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $actual = Get-LocalGroupFixtureFingerprint ($owner.Read(@('fixture-one'), [pscredential]::Empty, $true))
    Assert-LocalGroup ($actual -ceq $expected) 'Original reader did not survive secondary runspace disposal'
    Assert-LocalGroupOwnedCleanup
}

$path = Join-Path $RepositoryRoot ('etc/' + $ScriptName)
$ast = Read-LocalGroupFixtureAst $path
if ($Mode -eq 'Inert') {
    Assert-LocalGroupInertSource $ast
    $ownerPath = Join-Path $RepositoryRoot 'bin/ADLocalGroupReader.ps1'
    if ([IO.File]::Exists($ownerPath)) {
        $classAst = Read-LocalGroupFixtureAst $ownerPath
        $statements = @($classAst.EndBlock.Statements)
        Assert-LocalGroup ($statements.Count -eq 1 -and
            $statements[0] -is [Management.Automation.Language.TypeDefinitionAst] -and $statements[0].IsClass) (
            'Shared reader source contained executable startup statements'
        )
    }
    [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
    $computerName = @('caller-computer')
    $output = @(. $path)
    $owner = [ADAnalyzerLocalGroupReader]::new()
    $otherName = if ($ScriptName -ceq 'Get-LocalGroup.ps1') {
        'Get-LocalGroup copy.ps1'
    }
    else {
        'Get-LocalGroup.ps1'
    }
    $other = Join-Path $RepositoryRoot ('etc/' + $otherName)
    Assert-LocalGroupInertSource (Read-LocalGroupFixtureAst $other)
    $otherOutput = @(. $other)
    $otherOwner = [ADAnalyzerLocalGroupReader]::new()
    Assert-LocalGroup ($output.Count -eq 0 -and $otherOutput.Count -eq 0 -and $script:FrameworkLoads -eq 0 -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0 -and
        [ADAnalyzer.LocalGroupFixture.Probe]::Prompts -eq 0 -and
        [object]::ReferenceEquals($owner.GetType(), $otherOwner.GetType())) 'Dot loading or construction did work or changed the reader type'
    Assert-LocalGroup ($computerName[0] -eq 'caller-computer') 'Dot source changed caller input'
    'PASS local group contract ' + $ScriptName + ' ' + $Mode
    return
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ('ad-local-group-fixture-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($stage)
try {
    New-LocalGroupFixturePackage $stage
    $entry = Join-Path $stage ('etc/' + $ScriptName)
    $load = @(. $entry)
    Assert-LocalGroup ($load.Count -eq 0 -and $script:FrameworkLoads -eq 0) 'Staged wrapper loaded the framework'
    if ($Mode -eq 'Success') {
        foreach ($explicit in @($false, $true)) {
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
            $arguments = @{
                ComputerName = @('fixture-one')
            }
            if ($explicit) {
                $arguments.Credential = [pscredential]::new('fixture-user', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
            }
            $rows = @(Get-LocalGroupMember @arguments)
            Assert-LocalGroup ($rows.Count -eq 2 -and
                ($rows.Computer -join ',') -eq 'fixture-one,fixture-one' -and
                ($rows.Domain -join ',') -eq 'CONTOSO,CONTOSO' -and
                ($rows.samaccountname -join ',') -eq 'UserOne,DirectGroup') 'Detached direct member rows changed'
            Assert-LocalGroup (($rows[0].PSObject.Properties.Name -join ',') -ceq 'Computer,Domain,samaccountname') 'Member columns changed'
            Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -eq 2 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq 2 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) 'Member/borrowed context ownership failed'
            foreach ($name in @('ContextDisposals', 'GroupDisposals', 'ResultDisposals', 'EnumeratorDisposals')) {
                Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::$name -eq 1) ('Cleanup count failed ' + $name)
            }
            $arity = if ($explicit) {
                4
            }
            else {
                2
            }
            Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::Arity -eq $arity) 'Wrong credential constructor'
            if ($explicit) {
                Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::CredentialsCorrect) 'Credential identity changed'
            }
            $events = [ADAnalyzer.LocalGroupFixture.Probe]::Events
            Assert-LocalGroup ($events.IndexOf('enumerator.dispose') -lt $events.IndexOf('result.dispose') -and
                $events.IndexOf('result.dispose') -lt $events.IndexOf('group.dispose') -and
                $events.IndexOf('group.dispose') -lt $events.IndexOf('context.dispose')) 'Resource cleanup order changed'
        }
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
        [ADAnalyzer.LocalGroupFixture.Probe]::Empty = $true
        Assert-LocalGroup (@(Get-LocalGroupMember -ComputerName fixture-one).Count -eq 0) 'Empty group produced a fabricated row'
        Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ResultDisposals -eq 1 -and
            [ADAnalyzer.LocalGroupFixture.Probe]::EnumeratorDisposals -eq 1) 'Empty enumeration leaked resources'
    }
    elseif ($Mode -eq 'Name') {
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
        $rows = @(Get-LocalGroupMember -ComputerName fixture-one -IncludeName)
        Assert-LocalGroup (($rows.Name -join ',') -eq 'Display One,Display Group' -and
            ($rows.samaccountname -join ',') -eq 'UserOne,DirectGroup') 'Name projection assumed SAM identity'
        Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq 2 -and
            [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 1) 'Name projection leaked resources'
        foreach ($fault in @('NameProjection', 'NameMissing')) {
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset($fault)
            $emitted = [Collections.Generic.List[object]]::new()
            $caught = $null
            try {
                Get-LocalGroupMember -ComputerName fixture-one -IncludeName | ForEach-Object { $emitted.Add($_) }
            }
            catch {
                $caught = $_
            }
            Assert-LocalGroup ($null -ne $caught -and $emitted.Count -eq 0) 'Failed name projection emitted partial data'
            Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq 1 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 1 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::GroupDisposals -eq 1 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::ResultDisposals -eq 1 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::EnumeratorDisposals -eq 1 -and
                [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) 'Failed name projection cleanup failed'
        }
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('NameProjection')
        $rows = @(Get-LocalGroupMember -ComputerName fixture-one)
        Assert-LocalGroup ($rows.Count -eq 2 -and
            ($rows[0].PSObject.Properties.Name -join ',') -eq 'Computer,Domain,samaccountname') 'Default shape or optional getter behavior changed'
    }
    elseif ($Mode -eq 'Pipeline') {
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
        $rows = @(@('fixture-one', 'fixture-two') | Get-LocalGroupMember)
        Assert-LocalGroup ($rows.Count -eq 4 -and
            ($rows.Computer -join ',') -eq 'fixture-one,fixture-one,fixture-two,fixture-two') 'Pipeline host order changed'
        Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 2 -and
            [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq 4 -and
            [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) 'Pipeline resources leaked'
    }
    elseif ($Mode -eq 'Failures') {
        foreach ($fault in @('Constructor',
                'Lookup',
                'Missing',
                'GetMembers',
                'GetEnumerator',
                'MoveNext',
                'MoveNextAfterFirst',
                'Current',
                'Projection',
                'ContextProjection',
                'MemberDispose',
                'EnumeratorDispose',
                'ResultDispose',
                'GroupDispose',
                'ContextDispose',
                'ProjectionAndCleanup')) {
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset($fault)
            $emitted = [Collections.Generic.List[object]]::new()
            $caught = $null
            try {
                Get-LocalGroupMember -ComputerName fixture-one | ForEach-Object { $emitted.Add($_) }
            }
            catch {
                $caught = $_
            }
            Assert-LocalGroup ($null -ne $caught -and $emitted.Count -eq 0) ('Failure emitted partial host data: ' + $fault)
            Assert-LocalGroup ([ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -and
                [ADAnalyzer.LocalGroupFixture.Probe]::GroupDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Groups -and
                [ADAnalyzer.LocalGroupFixture.Probe]::ResultDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Results -and
                [ADAnalyzer.LocalGroupFixture.Probe]::EnumeratorDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Enumerators -and
                [ADAnalyzer.LocalGroupFixture.Probe]::MemberDisposals -eq [ADAnalyzer.LocalGroupFixture.Probe]::Retrieved -and
                [ADAnalyzer.LocalGroupFixture.Probe]::BorrowedDisposals -eq 0) ('Failure cleanup incomplete: ' + $fault)
            if ($fault -eq 'ProjectionAndCleanup') {
                Assert-LocalGroup ($caught.Exception.ToString() -match 'fixture member projection failure') 'Cleanup hid the projection failure'
                $found = $false
                $exception = $caught.Exception
                while ($null -ne $exception) {
                    if ($exception.Data.Contains('ADAnalyzerCleanupErrors')) {
                        $found = $true
                    }
                    $exception = $exception.InnerException
                }
                Assert-LocalGroup $found 'Secondary cleanup diagnostics missing'
            }
        }
    }
    elseif ($Mode -eq 'Validation') {
        foreach ($computers in @(@(' '), @('fixture-one', ''))) {
            [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
            $caught = $false
            try {
                $null = Get-LocalGroupMember -ComputerName $computers
            }
            catch {
                $caught = $true
            }
            Assert-LocalGroup ($caught -and [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0) 'Invalid host list reached authentication'
        }
    }
    elseif ($Mode -eq 'Cli') {
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
        $caught = $false
        try {
            & $entry | Out-Null
        }
        catch {
            $caught = $true
        }
        Assert-LocalGroup ($caught -and [ADAnalyzer.LocalGroupFixture.Probe]::Contexts -eq 0) 'CLI without selectors reached authentication'
        [ADAnalyzer.LocalGroupFixture.Probe]::Reset('')
        $rows = @(& $entry -ComputerName fixture-one)
        Assert-LocalGroup ($rows.Count -eq 2 -and [ADAnalyzer.LocalGroupFixture.Probe]::ContextDisposals -eq 1) 'Explicit CLI failed'
    }
    elseif ($Mode -eq 'Direct') {
        Invoke-LocalGroupDirectCases $stage
    }
    elseif ($Mode -eq 'Runspace') {
        Invoke-LocalGroupRunspaceCases $entry
    }
    else {
        throw 'Unknown local group fixture mode'
    }
}
finally {
    [IO.Directory]::Delete($stage, $true)
}
'PASS local group contract ' + $ScriptName + ' ' + $Mode
