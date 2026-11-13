param([string]$RepositoryRoot,[string]$Mode)
$ErrorActionPreference='Stop'
function Assert-Pool($Value,[string]$Message){if(-not $Value){throw $Message}}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1'),[ref]$tokens,[ref]$errors)
Assert-Pool ($errors.Count -eq 0) 'Runspace source did not parse'
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-RunspacePool'},$true)
$global:constant=@{Label='fixture-only';runspace=@{global=@{constant='fixture configuration';var='fixture state'}}}
$global:var=[hashtable]::Synchronized(@{Runs=0})
function Invoke-PoolFixtureWorker {$var['Runs']++;[pscustomobject]@{Label=$constant.Label;Runs=$var['Runs']}}
$originalProcessorVariable=$env:NUMBER_OF_PROCESSORS
Remove-Item Env:NUMBER_OF_PROCESSORS -ErrorAction SilentlyContinue
try{
    if($Mode -eq 'Failures'){
        Add-Type -TypeDefinition @'
using System;
namespace ADAnalyzer.PoolFixture {
 public static class Probe {public static string Fault="";public static int Created,Disposed,Calls;public static void Reset(string fault){Fault=fault;Created=Disposed=Calls=0;}}
 public class Pool : IDisposable {
  object threadOptions;TimeSpan cleanup;
  public object ThreadOptions {get{return threadOptions;}set{if(Probe.Fault=="Thread" || Probe.Fault=="Both")throw new Exception("fixture configuration thread failure");threadOptions=value;}}
  public TimeSpan CleanupInterval {get{return cleanup;}set{if(Probe.Fault=="Cleanup")throw new Exception("fixture configuration interval failure");cleanup=value;}}
  public void Dispose(){Probe.Disposed++;if(Probe.Fault=="Both")throw new Exception("fixture disposal failure");}
 }
 public static class Factory {
  public static Pool CreateRunspacePool(int minimum,int maximum,object initial,object host){Probe.Calls++;if(Probe.Fault=="Factory")throw new Exception("fixture factory failure");Probe.Created++;return new Pool();}
 }
}
'@
        $source=$function.Extent.Text;$offset=$function.Extent.StartOffset
        foreach($node in @($function.FindAll({param($n) $n -is [Management.Automation.Language.TypeExpressionAst] -and $n.TypeName.FullName -eq 'System.Management.Automation.Runspaces.RunspaceFactory'},$true) | Sort-Object {$_.Extent.StartOffset} -Descending)){
            $source=$source.Remove($node.Extent.StartOffset-$offset,$node.Extent.EndOffset-$node.Extent.StartOffset).Insert($node.Extent.StartOffset-$offset,'[ADAnalyzer.PoolFixture.Factory]')
        }
        Assert-Pool ($source -match 'ADAnalyzer.PoolFixture.Factory') 'Factory adapter did not bind'
        . ([scriptblock]::Create($source))
        foreach($fault in @('Factory','Thread','Cleanup','Both')){
            [ADAnalyzer.PoolFixture.Probe]::Reset($fault);$caught=$null;$emitted=[Collections.Generic.List[object]]::new()
            try{Initialize-RunspacePool -MaxRunspaces 2 | ForEach-Object {$emitted.Add($_)}}catch{$caught=$_}
            Assert-Pool ($null -ne $caught -and $emitted.Count -eq 0 -and [ADAnalyzer.PoolFixture.Probe]::Calls -eq 1) ('Initialization failure returned output '+$fault)
            Assert-Pool ([ADAnalyzer.PoolFixture.Probe]::Disposed -eq [ADAnalyzer.PoolFixture.Probe]::Created) ('Acquired pool not disposed exactly once '+$fault)
            if($fault -eq 'Both'){Assert-Pool ($caught.Exception.Message -match 'configuration' -and $caught.Exception.Data['ADAnalyzerCleanupErrors']) 'Secondary disposal erased primary configuration failure'}
        }
    }else{
        . ([scriptblock]::Create($function.Extent.Text))
        if($Mode -eq 'Invalid'){
            $global:PoolBodyEffects=0
            function Get-ChildItem {
                [CmdletBinding()]param($Path)
                $global:PoolBodyEffects++
                Microsoft.PowerShell.Management\Get-ChildItem -Path $Path
            }
            foreach($maximum in @(0,-1)){
                $caught=$false;try{$result=Initialize-RunspacePool -MaxRunspaces $maximum;if($result.pool){$result.pool.Dispose()}}catch{$caught=$true}
                Assert-Pool ($caught -and $global:PoolBodyEffects -eq 0) 'Invalid pool maximum entered function body'
            }
        }elseif($Mode -in @('Default','Explicit')){
            $state=$null;$runner=$null
            try{
                $state=if($Mode -eq 'Default'){Initialize-RunspacePool}else{Initialize-RunspacePool -MaxRunspaces 2}
                $maximum=if($Mode -eq 'Default'){[Environment]::ProcessorCount}else{2}
                Assert-Pool ($state -is [hashtable] -and $state.jobs -is [Collections.ArrayList] -and $state.init -is [Management.Automation.Runspaces.InitialSessionState]) 'Pool return contract changed'
                Assert-Pool ($state.pool.GetMinRunspaces() -eq 1 -and $state.pool.GetMaxRunspaces() -eq $maximum -and $state.pool.RunspacePoolStateInfo.State -eq 'BeforeOpen') 'Pool sizing or caller ownership changed'
                Assert-Pool ($state.pool.ThreadOptions -eq 'UseNewThread' -and $state.pool.CleanupInterval -eq [timespan]::FromMinutes(2)) 'Pool configuration changed'
                $state.pool.Open();$runner=[powershell]::Create();$runner.RunspacePool=$state.pool
                $null=$runner.AddScript('Invoke-PoolFixtureWorker')
                for($i=1;$i -le 2;$i++){
                    $rows=@($runner.Invoke())
                    Assert-Pool (-not $runner.HadErrors -and $rows.Count -eq 1 -and $rows[0].Label -eq 'fixture-only' -and $rows[0].Runs -eq $i -and $var['Runs'] -eq $i) 'Cloned worker lost function/configuration/shared state'
                }
            }finally{
                if($null -ne $runner){$runner.Dispose()}
                if($null -ne $state -and $null -ne $state.pool){$state.pool.Dispose()}
            }
            Assert-Pool ($state.pool.RunspacePoolStateInfo.State -eq 'Closed') 'Caller-owned pool did not close'
        }else{throw 'Unknown fixture mode'}
    }
}finally{
    if($null -ne $originalProcessorVariable){$env:NUMBER_OF_PROCESSORS=$originalProcessorVariable}
    else{Remove-Item Env:NUMBER_OF_PROCESSORS -ErrorAction SilentlyContinue}
}
'PASS pool contract '+$Mode
