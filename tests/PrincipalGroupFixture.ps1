using namespace ADAnalyzer.PrincipalFixture
param(
    [string]$RepositoryRoot,
    [ValidateSet('Get-ServerHPA.ps1', 'Get-ServerHPA copy.ps1')][string]$ScriptName,
    [ValidateSet('Inert', 'Success', 'Failures', 'Validation', 'Cli', 'Direct', 'Worker')][string]$Mode
)
$ErrorActionPreference = 'Stop'
$fixtureTypes = @'
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
  public string Name {get{Probe.Events.Add("get.Name");Check();return "Fixture Group";}}
  public string SamAccountName {get{Probe.Events.Add("get.SamAccountName");Check();return "FixtureGroup";}}
  public FixtureSid Sid {get{Probe.Events.Add("get.Sid");Check();return Probe.Fault=="NoSid"?null:new FixtureSid();}}
  public string Description {get{Probe.Events.Add("get.Description");Check();return "Detached fixture metadata";}}
  public static GroupPrincipal FindByIdentity(PrincipalContext context,IdentityType type,string identity) {
   if(context.Disposed || type!=IdentityType.SamAccountName || identity!="FixtureGroup")throw new Exception("Unexpected lookup contract");
   Probe.Events.Add("group.lookup");if(Probe.Fault=="Lookup" || Probe.Fault=="LookupContextDispose")throw new Exception("fixture lookup failure");
   if(Probe.Fault=="Missing")return null;Probe.Groups++;return new GroupPrincipal();
  }
  public void Dispose(){disposed=true;Probe.GroupDisposals++;Probe.Events.Add("group.dispose");if(Probe.Fault=="GroupDispose" || Probe.Fault=="BothDispose" || Probe.Fault=="ProjectionAndDispose")throw new Exception("fixture group cleanup failure");}
 }
}
'@
Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $fixtureTypes -ErrorAction Stop

function Assert-Principal($Value, [string]$Message) {
    if (-not $Value) {
        throw $Message
    }
}

function ConvertTo-PrincipalFixtureSource([string]$Path) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    Assert-Principal ($errors.Count -eq 0) ('Principal source did not parse: ' + $Path)
    $source = $Ast.Extent.Text
    $offset = $Ast.Extent.StartOffset
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
        $fakeType = 'ADAnalyzer.PrincipalFixture.' + $name
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
        Assert-Principal ($seen.ContainsKey($name)) ('Missing isolated type mapping for ' + $name + ' in ' + $Path)
    }
    Assert-Principal ($source -notmatch '(?i)System\.DirectoryServices\.AccountManagement\.' -and
        $source -notmatch '(?i)\\Add-Type\b') ('Unsafe framework reference in transformed source: ' + $Path)
    $null = [Management.Automation.Language.Parser]::ParseInput($source, $Path, [ref]$tokens, [ref]$errors)
    Assert-Principal ($errors.Count -eq 0) ('Isolated principal source did not parse: ' + $Path)
    return $source
}

function New-PrincipalFixturePackage([string]$Stage) {
    $names = @(
        'bin/ADPrincipalGroupReader.ps1'
        'etc/Get-ServerHPA.ps1'
        'etc/Get-ServerHPA copy.ps1'
    )
    foreach ($name in $names) {
        $path = Join-Path $Stage $name
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        $source = ConvertTo-PrincipalFixtureSource (Join-Path $RepositoryRoot $name)
        [IO.File]::WriteAllText($path, $source, [Text.UTF8Encoding]::new($false))
    }
}
$global:ADAnalyzerHpaFrameworkLoads = 0
$global:ADAnalyzerHpaFrameworkBlocked = $Mode -eq 'Inert'

function Add-Type {
    [CmdletBinding()]param([string]$AssemblyName)
    Assert-Principal ($AssemblyName -eq 'System.DirectoryServices.AccountManagement') 'Unexpected framework dependency'
    $global:ADAnalyzerHpaFrameworkLoads++
    if ($global:ADAnalyzerHpaFrameworkBlocked) {
        throw 'Unexpected framework load during inert bootstrap'
    }
}
$global:ADAnalyzerHpaPromptBlocked = $Mode -in 'Inert', 'Cli', 'Validation'

function Get-Credential {
    [ADAnalyzer.PrincipalFixture.Probe]::Prompts++
    if ($global:ADAnalyzerHpaPromptBlocked) {
        throw 'Unexpected credential prompt'
    }
    [pscredential]::new('fixture-user', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
}

function Assert-PrincipalSnapshot($Row, [bool]$HasSid = $true) {
    $expectedSid = $null
    if ($HasSid) {
        $expectedSid = 'S-1-5-32-544'
    }
    Assert-Principal ($Row -is [pscustomobject] -and
        ($Row.PSObject.Properties.Name -join ',') -ceq 'Computer,Name,SamAccountName,SID,Description' -and
        $Row.Computer -ceq 'fixture-host' -and $Row.Name -ceq 'Fixture Group' -and
        $Row.SamAccountName -ceq 'FixtureGroup' -and $Row.SID -ceq $expectedSid -and
        $Row.Description -ceq 'Detached fixture metadata') 'Expected one detached ordered host group snapshot'
}

function Assert-PrincipalLifecycle([int]$Arity) {
    $events = [ADAnalyzer.PrincipalFixture.Probe]::Events -join '|'
    $expected = 'context.create|group.lookup|get.Name|get.SamAccountName|get.Sid|get.Description|group.dispose|context.dispose'
    Assert-Principal ($events -ceq $expected -and [ADAnalyzer.PrincipalFixture.Probe]::Arity -eq $Arity -and
        [ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq 1 -and
        [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq 1 -and
        [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0) 'Principal getter order, constructor or resource ownership changed'
}

function Invoke-PrincipalDirectCases {
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
    $before = $global:ADAnalyzerHpaFrameworkLoads
    $owner = [ADAnalyzerPrincipalGroupReader]::new()
    foreach ($inputs in @(@('', 'FixtureGroup'), @('fixture-host', ' '))) {
        $failure = $null
        try {
            $null = $owner.Read($inputs[0], $inputs[1])
        }
        catch {
            $failure = $_
        }
        Assert-Principal ($null -ne $failure -and $failure.Exception.Message -match 'Specify a computer and group target') 'Direct validation did not stop before framework access'
    }
    Assert-Principal ($global:ADAnalyzerHpaFrameworkLoads -eq $before -and
        [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0) 'Construction or rejected input loaded the framework'

    $row = $owner.Read('fixture-host', 'FixtureGroup')
    Assert-PrincipalSnapshot $row
    Assert-PrincipalLifecycle 2
    Assert-Principal ($global:ADAnalyzerHpaFrameworkLoads -eq $before + 1) 'Explicit Read did not use the selected framework load seam'
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
    $native = @(Get-ServerHPA -Computer fixture-host -Target FixtureGroup)
    Assert-Principal ($native.Count -eq 1 -and
        (ConvertTo-Json -InputObject $native[0] -Compress) -ceq (ConvertTo-Json -InputObject $row -Compress)) 'Explicit reader and native command returned different snapshots'
    Assert-PrincipalLifecycle 2

    $credential = [pscredential]::new('fixture-user', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
    $explicit = $owner.Read('fixture-host', 'FixtureGroup', $credential)
    Assert-PrincipalSnapshot $explicit
    Assert-PrincipalLifecycle 4
    Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::CredentialsCorrect -and
        [Management.Automation.PSSerializer]::Serialize($owner) -cnotmatch 'fixture-user|fixture-only|PSCredential') 'Credentials changed or persisted in the reader'

    [ADAnalyzer.PrincipalFixture.Probe]::Reset('NoSid')
    $missingSid = $owner.Read('fixture-host', 'FixtureGroup', [pscredential]::Empty)
    Assert-PrincipalSnapshot $missingSid $false
    Assert-PrincipalLifecycle 2
    $explicit.Name = 'caller change'
    Assert-Principal ($missingSid.Name -ceq 'Fixture Group' -and $row.Name -ceq 'Fixture Group') 'Reader reused a mutable snapshot'

    [ADAnalyzer.PrincipalFixture.Probe]::Reset('ProjectionAndDispose')
    $emitted = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        $owner.Read('fixture-host', 'FixtureGroup') | ForEach-Object { $emitted.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-Principal ($null -ne $failure -and $emitted.Count -eq 0 -and
        $failure.Exception.Message -match 'fixture projection failure' -and
        [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq 1 -and
        [ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq 1) 'Compound failure lost the primary error or disposed resources incorrectly'
    $diagnostics = @()
    $exception = $failure.Exception
    while ($null -ne $exception) {
        if ($exception.Data.Contains('ADAnalyzerCleanupErrors')) {
            $diagnostics = @($exception.Data['ADAnalyzerCleanupErrors'])
            break
        }
        $exception = $exception.InnerException
    }
    Assert-Principal ($diagnostics.Count -eq 2 -and $diagnostics[0] -match 'fixture group cleanup failure' -and
        $diagnostics[1] -match 'fixture context cleanup failure') 'Secondary cleanup evidence or its order changed'
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
    Assert-PrincipalSnapshot ($owner.Read('fixture-host', 'FixtureGroup'))
    Assert-PrincipalLifecycle 2
}

function Invoke-PrincipalWorkerCases([string]$Stage, [string]$SelectedPath) {
    $planSource = Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1'
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($planSource, [ref]$tokens, [ref]$errors)
    Assert-Principal ($errors.Count -eq 0 -and $ast.Extent.Text -match 'MyInvocation\.InvocationName' -and
        $ast.Extent.Text -notmatch '(?i)System\.DirectoryServices\.AccountManagement') 'Unexpected connection startup in the worker source'
    $plan = Join-Path $Stage 'etc/Test-Runspace.ps1'
    [IO.File]::Copy($planSource, $plan)
    $startup = @(. $plan)
    Assert-Principal ($startup.Count -eq 0 -and
        $constant['HostGroupHelperPath'] -ceq (Join-Path $Stage 'etc/Get-ServerHPA.ps1')) 'Connection loader did not select its real sibling'
    $constant['HostGroupHelperPath'] = $SelectedPath
    $state = $null
    $runner = $null
    try {
        $state = Initialize-RunspacePool -MaxRunspaces 1
        $state.pool.Open()

        $startup = @(. $SelectedPath)
        Assert-Principal ($startup.Count -eq 0) 'Parent wrapper load was not inert'
        $parent = [ADAnalyzerPrincipalGroupReader]::new()
        [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
        Assert-PrincipalSnapshot ($parent.Read('fixture-host', 'FixtureGroup'))
        Assert-PrincipalLifecycle 2

        $runner = [powershell]::Create()
        $runner.RunspacePool = $state.pool
        $command = @'
param([pscredential]$Credential)
$ErrorActionPreference = 'Stop'
$global:ADAnalyzerHpaFrameworkLoads = 0
$global:ADAnalyzerHpaFrameworkBlocked = $false
$global:ADAnalyzerHpaPromptBlocked = $true
if ('ADAnalyzerPrincipalGroupReader' -as [type]) {
    throw 'Worker inherited a preloaded reader'
}
[ADAnalyzer.PrincipalFixture.Probe]::Reset('')
$borrowed = [pscustomobject]@{ Disposed = $false }
$borrowed | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
$rows = @(Connect-WindowsServer -context fixture-host -principal FixtureGroup -domain $borrowed -Credential $Credential)
if ($rows.Count -ne 1 -or $borrowed.Disposed -or $global:ADAnalyzerHpaFrameworkLoads -ne 1 -or
    (Test-Path -LiteralPath 'Function:Get-ServerHPA')) {
    throw 'Worker could not load its private named reader without leaking a dependency or disposing borrowed data'
}
$rows[0]
'@
        $credential = [pscredential]::new('fixture-user', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $null = $runner.AddScript($command).AddArgument($credential)
        $rows = @($runner.Invoke())
        Assert-Principal (-not $runner.HadErrors -and $rows.Count -eq 1) (
            'Fresh selected worker failed. State={0}, HadErrors={1}, Rows={2}, Errors={3}' -f
            $runner.InvocationStateInfo.State, $runner.HadErrors, $rows.Count, ($runner.Streams.Error -join ' | ')
        )
        Assert-PrincipalSnapshot $rows[0]
        Assert-PrincipalLifecycle 4
        Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::CredentialsCorrect) 'The selected worker did not forward the credential'
    }
    finally {
        if ($null -ne $runner) {
            $runner.Dispose()
        }
        if ($null -ne $state) {
            $state.pool.Dispose()
        }
    }
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
    Assert-PrincipalSnapshot ($parent.Read('fixture-host', 'FixtureGroup'))
    Assert-PrincipalLifecycle 2
}

$path = Join-Path $RepositoryRoot ('etc/' + $ScriptName)
if ($Mode -eq 'Inert') {
    [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
    $computer = 'caller-computer'
    $target = 'caller-target'
    $output = @(. $path)
    $owner = [ADAnalyzerPrincipalGroupReader]::new()
    $otherName = if ($ScriptName -ceq 'Get-ServerHPA.ps1') {
        'Get-ServerHPA copy.ps1'
    }
    else {
        'Get-ServerHPA.ps1'
    }
    $other = Join-Path $RepositoryRoot ('etc/' + $otherName)
    $alternateOutput = @(. $other)
    $alternateOwner = [ADAnalyzerPrincipalGroupReader]::new()
    Assert-Principal ($output.Count -eq 0 -and
        $alternateOutput.Count -eq 0 -and $global:ADAnalyzerHpaFrameworkLoads -eq 0 -and
        [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and
        [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0 -and
        [object]::ReferenceEquals($owner.GetType(), $alternateOwner.GetType())) 'Dot loading or construction loaded the framework, changed the type or emitted data'
    Assert-Principal ($computer -eq 'caller-computer' -and $target -eq 'caller-target') 'Dot sourcing changed caller inputs'
    'PASS host-group principal contract ' + $ScriptName + ' ' + $Mode
    return
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ('ad-principal-class-fixture-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($stage)
try {
    New-PrincipalFixturePackage $stage
    $entry = Join-Path $stage ('etc/' + $ScriptName)
    Assert-Principal ([ADAnalyzer.PrincipalFixture.PrincipalContext]::FixtureMarker) 'Fixture did not bind its isolated CLR contracts'
    if ($Mode -eq 'Worker') {
        Invoke-PrincipalWorkerCases $stage $entry
        'PASS host-group principal contract ' + $ScriptName + ' ' + $Mode
        return
    }

    $output = @(. $entry)
    Assert-Principal ($output.Count -eq 0 -and $global:ADAnalyzerHpaFrameworkLoads -eq 0) 'The staged wrapper was not inert'
    if ($Mode -eq 'Success') {
        foreach ($explicit in @($false, $true)) {
            [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
            $arguments = @{
                Computer = 'fixture-host'
                Target = 'FixtureGroup'
            }
            if ($explicit) {
                $arguments.Credential = [pscredential]::new('fixture-user', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
            }
            $rows = @(Get-ServerHPA @arguments)
            $name = $rows[0].Name
            Assert-Principal ($rows.Count -eq 1 -and
                $rows[0] -is [pscustomobject] -and
                $name -eq 'Fixture Group') 'Host-group result was not one detached record'
            Assert-Principal ($rows[0].Computer -eq 'fixture-host' -and
                $rows[0].Name -eq 'Fixture Group' -and
                $rows[0].SamAccountName -eq 'FixtureGroup' -and
                $rows[0].SID -eq 'S-1-5-32-544' -and
                $rows[0].Description -eq 'Detached fixture metadata') 'Detached metadata changed or was read after disposal'
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and
                [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 1 -and
                [ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq 1 -and
                [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq 1) 'Owned resources or prompt contract failed'
            $arity = if ($explicit) {
                4
            }
            else {
                2
            }
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::Arity -eq $arity) 'Wrong context constructor selected'
            if ($explicit) {
                Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::CredentialsCorrect) 'Explicit credential identity changed'
            }
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::Events.IndexOf('group.dispose') -lt [ADAnalyzer.PrincipalFixture.Probe]::Events.IndexOf('context.dispose')) 'Cleanup ownership order changed'
            foreach ($property in $rows[0].PSObject.Properties) {
                Assert-Principal ($property.Value -isnot [ADAnalyzer.PrincipalFixture.PrincipalContext] -and
                    $property.Value -isnot [ADAnalyzer.PrincipalFixture.GroupPrincipal]) 'A live or disposed principal reference escaped'
            }
        }
    }
    elseif ($Mode -eq 'Failures') {
        foreach ($fault in @('Constructor',
                'Lookup',
                'Missing',
                'Projection',
                'GroupDispose',
                'ContextDispose',
                'BothDispose',
                'ProjectionAndDispose',
                'LookupContextDispose')) {
            [ADAnalyzer.PrincipalFixture.Probe]::Reset($fault)
            $emitted = [Collections.Generic.List[object]]::new()
            $caught = $null
            try {
                Get-ServerHPA -Computer fixture-host -Target FixtureGroup | ForEach-Object { $emitted.Add($_) }
            }
            catch {
                $caught = $_
            }
            Assert-Principal ($null -ne $caught -and $emitted.Count -eq 0) ('Failure emitted success: ' + $fault)
            $expected = if ($fault -eq 'Missing') {
                'not found'
            }
            elseif ($fault -like 'Lookup*') {
                'fixture lookup failure'
            }
            elseif ($fault -like 'Projection*') {
                'fixture projection failure'
            }
            elseif ($fault -eq 'Constructor') {
                'fixture constructor failure'
            }
            elseif ($fault -eq 'ContextDispose') {
                'fixture context cleanup failure'
            }
            else {
                'fixture group cleanup failure'
            }
            Assert-Principal ($caught.Exception.Message -match [regex]::Escape($expected)) ('Primary failure was lost: ' + $fault)
            $contexts = if ($fault -eq 'Constructor') {
                0
            }
            else {
                1
            }
            $groups = if ($fault -in 'Constructor', 'Lookup', 'Missing', 'LookupContextDispose') {
                0
            }
            else {
                1
            }
            Assert-Principal ([ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq $contexts -and
                [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq $groups) ('Cleanup was incomplete: ' + $fault)
            if ($fault -in 'BothDispose', 'ProjectionAndDispose', 'LookupContextDispose') {
                $secondary = $false
                $exception = $caught.Exception
                while ($null -ne $exception) {
                    if ($exception.Data.Contains('ADAnalyzerCleanupErrors')) {
                        $secondary = $true
                    }
                    $exception = $exception.InnerException
                }
                Assert-Principal $secondary ('Secondary cleanup evidence was lost: ' + $fault)
            }
        }
    }
    elseif ($Mode -eq 'Validation') {
        foreach ($arguments in @(@{}, @{
                    Computer = ' '
                    Target = 'FixtureGroup'
                }, @{
                    Computer = 'fixture-host'
                    Target = ''
                })) {
            [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
            $caught = $false
            try {
                $null = Get-ServerHPA @arguments
            }
            catch {
                $caught = $true
            }
            Assert-Principal ($caught -and
                [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and
                [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0) 'Invalid inputs reached authentication'
        }
    }
    elseif ($Mode -eq 'Cli') {
        [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
        $caught = $false
        try {
            & $entry | Out-Null
        }
        catch {
            $caught = $true
        }
        Assert-Principal ($caught -and
            [ADAnalyzer.PrincipalFixture.Probe]::Prompts -eq 0 -and
            [ADAnalyzer.PrincipalFixture.Probe]::Contexts -eq 0) 'CLI without selectors reached authentication'
        [ADAnalyzer.PrincipalFixture.Probe]::Reset('')
        $rows = @(& $entry -Computer fixture-host -Target FixtureGroup)
        Assert-Principal ($rows.Count -eq 1 -and
            $rows[0].SID -eq 'S-1-5-32-544' -and
            [ADAnalyzer.PrincipalFixture.Probe]::ContextDisposals -eq 1 -and
            [ADAnalyzer.PrincipalFixture.Probe]::GroupDisposals -eq 1) 'Explicit CLI did not return detached metadata'
    }
    elseif ($Mode -eq 'Direct') {
        Invoke-PrincipalDirectCases
    }
    else {
        throw 'Unknown principal fixture mode'
    }
}
finally {
    [IO.Directory]::Delete($stage, $true)
}
'PASS host-group principal contract ' + $ScriptName + ' ' + $Mode
