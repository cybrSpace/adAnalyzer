[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
$script:Passed=0;$script:Failed=0
function Assert-Equal($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], received [$Actual]"}}
function Assert-True($Actual,[string]$Message){if(-not $Actual){throw $Message}}
function Assert-Throws([scriptblock]$Body){$failed=$false;try{& $Body > $null}catch{$failed=$true};if(-not $failed){throw 'Expected a terminating error'}}
function Invoke-Test([string]$Name,[scriptblock]$Body){try{& $Body;$script:Passed++;Write-Host "PASS $Name"}catch{$script:Failed++;Write-Host "FAIL $Name : $_";Write-Host $_.ScriptStackTrace}}
Add-Type -TypeDefinition @'
namespace Microsoft.ActiveDirectory.Management { public class ADPropertyValueCollection {} public class ADPartition {} public class ADEntity {} }
namespace Microsoft.ActiveDirectory.Management.Provider { public class ADDriveInfo {} }
'@
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('ad-entry-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -Path $temporary -ItemType Directory
try {
    Invoke-Test 'all package PowerShell files parse without syntax errors' {
        foreach($file in Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'bin') -File | Where-Object Extension -in '.ps1','.psm1') {
            $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
            if($errors.Count){throw ($file.Name+': '+($errors.Message -join '; '))}
        }
    }
    . (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
    $before=(Get-Location).Path
    $Credential='caller credential sentinel';$Operation='caller operation sentinel'
    . (Join-Path $RepositoryRoot 'bin/Start-ADAnalyzer.ps1')
    Invoke-Test 'dot sourcing the helper preserves caller credentials operation and location' {Assert-Equal $before (Get-Location).Path;Assert-Equal 'caller credential sentinel' $Credential;Assert-Equal 'caller operation sentinel' $Operation;Assert-True ([bool](Get-Command Start-ADAnalyzer)) 'Missing helper function'}
    $script:ScanCalls=0;$script:ApplyCalls=0;$script:Exports=0;$script:FailScan=$false;$script:FailExport=$false
    function Get-ADAnalyzerAssessment {
        param($Domain,$Server,$SearchBase,$Credential,$Profile,[switch]$IncludeAcl,[switch]$IncludeHostChecks,[switch]$SkipGpo)
        $script:ScanCalls++;$script:ScanArguments=$PSBoundParameters
        if($script:FailScan){throw 'fixture scan failure'}
        [pscustomobject]@{SchemaVersion=1;Target='actual.example.invalid';State='Complete';RunId='fixture';Findings=@();Checks=@();Objects=@();Coverage=@{Total=0}}
    }
    function Export-ADAnalyzerAssessment {
        [CmdletBinding(SupportsShouldProcess=$true)]param($Assessment,$Path,$Format)
        if($script:FailExport){throw 'fixture export failure'}
        if($PSCmdlet.ShouldProcess($Path,'fixture export')){$script:Exports++;$script:ExportTarget=$Assessment.Target}
    }
    function New-ADAnalyzerRemediationPlan {param($Assessment,$Profile) [pscustomobject]@{SchemaVersion=1;Target=$Assessment.Target;Actions=@();Summary=@{Proposed=0}}}
    function Invoke-ADAnalyzerRemediationPlan {
        [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]param($Plan,$Server,$Credential,$JournalPath)
        if($PSCmdlet.ShouldProcess($Server,'fixture apply')){$script:ApplyCalls++}
        [pscustomobject]@{State='Complete';Target=$Server}
    }
    function Undo-ADAnalyzerRemediation {
        [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]param($JournalPath,$Server,$Credential)
        if($PSCmdlet.ShouldProcess($Server,'fixture undo')){$script:ApplyCalls++}
    }
    Invoke-Test 'helper forwards explicit target and search-base without prompting' {
        $null=Start-ADAnalyzer -Operation assess -FQDN target.example.invalid -Server dc.example.invalid -SearchBase 'OU=People,DC=example,DC=invalid'
        Assert-Equal 'target.example.invalid' $script:ScanArguments.Domain;Assert-Equal 'dc.example.invalid' $script:ScanArguments.Server
        Assert-Equal 'OU=People,DC=example,DC=invalid' $script:ScanArguments.SearchBase
    }
    Invoke-Test 'discovered domain identity is preserved in returned and exported reports' {
        $result=Start-ADAnalyzer -Operation report -OutputPath (Join-Path $temporary 'report')
        Assert-Equal 'actual.example.invalid' $result.Target;Assert-Equal 'actual.example.invalid' $script:ExportTarget
    }
    Invoke-Test 'credential is forwarded by reference and collectors remain opt-in' {
        $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $null=Start-ADAnalyzer -Credential $credential -IncludeAcl -IncludeHostChecks -SkipGpo
        Assert-True ([object]::ReferenceEquals($credential,$script:ScanArguments.Credential)) 'Dropped credential'
        Assert-True $script:ScanArguments.IncludeAcl 'ACL option lost';Assert-True $script:ScanArguments.IncludeHostChecks 'Host option lost';Assert-True $script:ScanArguments.SkipGpo 'GPO option lost'
    }
    Invoke-Test 'scan failures escape the helper as terminating errors' {
        $script:FailScan=$true;try{Assert-Throws {Start-ADAnalyzer}}finally{$script:FailScan=$false}
    }
    Invoke-Test 'export failures escape the helper as terminating errors' {
        $script:FailExport=$true;try{Assert-Throws {Start-ADAnalyzer -OutputPath (Join-Path $temporary 'broken')}}finally{$script:FailExport=$false}
    }
    Invoke-Test 'plan and legacy remediate operations never apply mutations' {
        $before=$script:ApplyCalls
        foreach($operation in @('plan','remediate')){$plan=Start-ADAnalyzer -Operation $operation;Assert-Equal 'actual.example.invalid' $plan.Target;Assert-Equal 0 $plan.Actions.Count}
        Assert-Equal $before $script:ApplyCalls
    }
    Invoke-Test 'apply requires both an explicit plan and journal' {
        Assert-Throws {Start-ADAnalyzer -Operation apply -PlanPath 'fixture.json'}
        Assert-Throws {Start-ADAnalyzer -Operation apply -JournalPath 'fixture.json'}
    }
    Invoke-Test 'WhatIf never reaches the apply mutation' {
        $before=$script:ApplyCalls;$null=Start-ADAnalyzer -Operation apply -PlanPath 'fixture.json' -JournalPath 'journal.json' -Server dc.example.invalid -WhatIf
        Assert-Equal $before $script:ApplyCalls
    }
    Invoke-Test 'WhatIf never reaches the undo mutation' {
        $before=$script:ApplyCalls;$null=Start-ADAnalyzer -Operation undo -JournalPath 'journal.json' -Server dc.example.invalid -WhatIf
        Assert-Equal $before $script:ApplyCalls
    }
    Invoke-Test 'read-only WhatIf still collects while suppressing export writes' {
        $before=$script:Exports;$scan=$script:ScanCalls;$null=Start-ADAnalyzer -OutputPath (Join-Path $temporary 'preview') -WhatIf
        Assert-Equal ($scan+1) $script:ScanCalls;Assert-Equal $before $script:Exports
    }
    Invoke-Test 'profile validation rejects unknown settings and executable input formats' {
        Assert-Throws {Import-ADAnalyzerProfile -Profile @{Policy=@{MisspelledThreshold=6}}}
        Assert-Throws {Import-ADAnalyzerProfile -Path 'profile.ps1'}
        Assert-Throws {Import-ADAnalyzerProfile -Profile @{Analysis=@{IncludeAcl='false'}}}
    }
    Invoke-Test 'profile defaults and nested collections are isolated between runs' {
        $a=Get-ADAnalyzerDefaultProfile;$b=Get-ADAnalyzerDefaultProfile;$a.Policy.MinimumPasswordLength=99;$a.Policy.AllowedUserRightSids['one']=@('SID')
        Assert-Equal 12 $b.Policy.MinimumPasswordLength;Assert-Equal 0 $b.Policy.AllowedUserRightSids.Count
    }
    Invoke-Test 'custom value baselines reject secret identities in every profile collection without changing input' {
        foreach($section in @('RegistryRules','ExpectedGpoSettings','Host')){foreach($expected in @('unit7-secret',@('unit7-secret'),'',$null,$true)){
            $rule=@{Id='unit7-secret-label';Key='Software\Fixture';ValueName='dEfAuLtPaSsWoRd';Name='MACHINE\Software\Fixture\DefaultPassword';Expected=$expected}
            $inputProfile=if($section -eq 'Host'){@{Host=@{RegistryRules=@($rule)}}}else{@{$section=@($rule)}}
            $before=ConvertTo-Json -InputObject $inputProfile -Depth 20 -Compress
            $caught=$null;try{$null=Import-ADAnalyzerProfile -Profile $inputProfile}catch{$caught=$_}
            Assert-True ($null -ne $caught) 'Secret value baseline accepted'
            Assert-Equal 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.' $caught.Exception.Message
            Assert-True (([string]$caught.TargetObject) -notmatch 'unit7-secret') 'Secret rule leaked through error target'
            Assert-Equal $before (ConvertTo-Json -InputObject $inputProfile -Depth 20 -Compress)
        }}
    }
    Invoke-Test 'JSON and PSD1 custom secret baselines are rejected for all profile collections' {
        foreach($section in @('RegistryRules','ExpectedGpoSettings','Host')){
            $rule=@{ValueName='DefaultPassword';Expected='unit7-file-secret'}
            $inputProfile=if($section -eq 'Host'){@{Host=@{RegistryRules=@($rule)}}}else{@{$section=@($rule)}}
            $json=Join-Path $temporary 'secret-profile.json';$inputProfile | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $json
            $literal="@{ValueName='DefaultPassword';Expected='unit7-file-secret'}"
            $text=if($section -eq 'Host'){"@{Host=@{RegistryRules=@($literal)}}"}else{"@{$section=@($literal)}"}
            $psd1=Join-Path $temporary 'secret-profile.psd1';Set-Content -LiteralPath $psd1 -Value $text
            foreach($path in @($json,$psd1)){
                $caught=$null;try{$null=Import-ADAnalyzerProfile -Path $path}catch{$caught=$_}
                Assert-True ($null -ne $caught) 'Secret value file baseline accepted'
                Assert-Equal 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.' $caught.Exception.Message
            }
        }
    }
    Invoke-Test 'standalone profile loading rejects secret baselines and retains ordinary typed settings' {
        $fixture=Join-Path $temporary 'profile-only.ps1'
        Set-Content -LiteralPath $fixture -Value @'
param([string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'bin/ADProfile.ps1')
$profile=Import-ADAnalyzerProfile -Profile @{Policy=@{PasswordComplexity=$true;MinimumPasswordLength=14};RegistryRules=@(@{Key='Software\Password';ValueName='Enabled';Expected=0})}
if($profile.Policy.MinimumPasswordLength -ne 14 -or $profile.RegistryRules[0].Expected -isnot [int]){throw 'Ordinary typed baseline changed'}
$caught=$null
try{$null=Import-ADAnalyzerProfile -Profile @{ExpectedGpoSettings=@(@{Kind='SecurityOptions';Name='MACHINE\Software\Fixture\DefaultPassword';Expected='fixture-only'})}}catch{$caught=$_}
if($null -eq $caught -or $caught.Exception.Message -ne 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'){throw 'Standalone profile guard did not run'}
'@
        & (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -File $fixture -Root $RepositoryRoot
        Assert-Equal 0 $LASTEXITCODE
    }
    Invoke-Test 'profile conversion preserves sorted scalar collections and typed values' {
        $profile=Import-ADAnalyzerProfile -Profile @{Policy=@{ApprovedLocalAdminSids=@('S-1-5-32-545','S-1-5-32-544' | Sort-Object)}}
        Assert-True ($profile.Policy.ApprovedLocalAdminSids[0] -is [string]) 'Pipeline-wrapped string became a property dictionary'
        Assert-Equal 'S-1-5-32-544' $profile.Policy.ApprovedLocalAdminSids[0]
        Assert-Equal 2 $profile.Policy.ApprovedLocalAdminSids.Count
    }
    Invoke-Test 'JSON and restricted PSD1 overrides merge without discarding defaults' {
        $json=Join-Path $temporary 'profile.json';Set-Content -LiteralPath $json -Value '{"Name":"Fixture","Policy":{"MinimumPasswordLength":20}}'
        $psd1=Join-Path $temporary 'profile.psd1';Set-Content -LiteralPath $psd1 -Value "@{Name='Fixture';Policy=@{MinimumPasswordLength=20}}"
        foreach($path in @($json,$psd1)){$p=Import-ADAnalyzerProfile -Path $path;Assert-Equal 20 $p.Policy.MinimumPasswordLength;Assert-Equal 6 $p.Policy.LockoutThreshold}
    }
    Invoke-Test 'exceptions require ownership reason expiry and retain the original status' {
        Assert-Throws {Import-ADAnalyzerProfile -Profile @{Exceptions=@(@{RuleId='ONE';Target='*'})}}
        $profile=Import-ADAnalyzerProfile -Profile @{Exceptions=@(@{RuleId='ONE';Target='fixture';Owner='Ops';Reason='Temporary';Expires=[datetime]::UtcNow.AddDays(1).ToString('o')})}
        $check=New-ADAnalyzerCheck -RuleId ONE -Target fixture -Status Fail
        $result=$check | Set-ADAnalyzerCheckException -Profile $profile
        Assert-Equal Fail $result.Status;Assert-True $result.Suppressed 'Exception metadata missing'
    }
    Invoke-Test 'expired exceptions do not suppress findings' {
        $profile=Import-ADAnalyzerProfile -Profile @{Exceptions=@(@{RuleId='ONE';Target='fixture';Owner='Ops';Reason='Expired';Expires='2020-01-01T00:00:00Z'})}
        $check=New-ADAnalyzerCheck -RuleId ONE -Target fixture -Status Fail
        Assert-Equal $false ($check | Set-ADAnalyzerCheckException -Profile $profile).Suppressed
    }
    Invoke-Test 'check identities are stable and target-specific' {
        $a=New-ADAnalyzerCheck -RuleId ONE -Target fixture -Status Pass;$b=New-ADAnalyzerCheck -RuleId one -Target FIXTURE -Status Fail;$c=New-ADAnalyzerCheck -RuleId ONE -Target other -Status Pass
        Assert-Equal $a.CheckId $b.CheckId;Assert-True ($a.CheckId -ne $c.CheckId) 'Different targets collided'
    }
    Invoke-Test 'prerequisite CLI honors the same domain target argument' {
        function Get-ADAnalyzerPrerequisite {param($RepositoryRoot,$Server,$Credential,[switch]$Online,$Profile) [pscustomobject]@{Observed=$Server;Status='Pass'}}
        $result=Start-ADAnalyzer -Operation prerequisites -FQDN target.example.invalid -Online
        Assert-Equal target.example.invalid $result.Observed
    }
    $harness=Join-Path $temporary 'cli-harness.ps1'
    $harnessSource=@'
param([string]$State)
. '__PROFILE__'
$global:ADAnalyzerFixtureCliState=$State
function Get-ADAnalyzerAssessment {
    param($Domain,$Server,$SearchBase,$Credential,$Profile,[switch]$IncludeAcl,[switch]$IncludeHostChecks,[switch]$SkipGpo)
    if($global:ADAnalyzerFixtureCliState -eq 'Error'){throw 'fixture CLI collection failed'}
    $state=if($global:ADAnalyzerFixtureCliState -eq 'Partial'){'Partial'}else{'Complete'}
    $findings=if($global:ADAnalyzerFixtureCliState -eq 'Findings'){@([pscustomobject]@{Status='Fail';Suppressed=$false})}else{@()}
    [pscustomobject]@{RunId='fixture';Target=$Domain;State=$state;Coverage=@{};Findings=$findings}
}
& '__HELPER__' -Operation assess -Domain example.invalid -PassThru -FailOnFindings
exit $LASTEXITCODE
'@
    $harnessSource=$harnessSource.Replace('__PROFILE__',(Join-Path $RepositoryRoot 'bin/ADProfile.ps1').Replace("'","''")).Replace('__HELPER__',(Join-Path $RepositoryRoot 'bin/Start-ADAnalyzer.ps1').Replace("'","''"))
    Set-Content -LiteralPath $harness -Value $harnessSource -Encoding UTF8
    foreach($case in @(@{State='Complete';Code=0},@{State='Partial';Code=2},@{State='Error';Code=1},@{State='Findings';Code=3})) {
        Invoke-Test ('CLI process returns explicit exit status for '+$case.State) {
            $shell=(Get-Process -Id $PID).Path;$previous=$ErrorActionPreference
            try{$ErrorActionPreference='Continue';$null=& $shell -NoLogo -NoProfile -NonInteractive -File $harness -State $case.State 2>&1;$actual=$LASTEXITCODE}finally{$ErrorActionPreference=$previous}
            Assert-Equal $case.Code $actual
        }
    }
    Invoke-Test 'manifest exports only package commands and has no installed RSAT requirement' {
        $manifest=Import-PowerShellDataFile (Join-Path $RepositoryRoot 'ADEnvironment.psd1')
        Assert-Equal 0 @($manifest.RequiredModules | Where-Object { $null -ne $_ }).Count
        Assert-True ($manifest.NestedModules -contains 'lib/Microsoft.ActiveDirectory.Management.dll') 'Bundled AD module missing'
        foreach($name in @('Get-ADAnalyzerAssessment','Invoke-ADAnalyzerAssessment','New-ADAnalyzerRemediationPlan','Export-ADAnalyzerAssessment')){Assert-True ($manifest.FunctionsToExport -contains $name) "Missing public command $name"}
    }
}finally{Remove-Item -LiteralPath $temporary -Recurse -Force -WhatIf:$false -Confirm:$false}
Write-Host ("{0} entry-point/profile tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
