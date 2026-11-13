using namespace System.Collections
using namespace System.Collections.Specialized
param([string]$RepositoryRoot,[string]$WorkingDirectory,[string]$Mode)
$ErrorActionPreference='Stop'
Microsoft.PowerShell.Core\Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
. (Join-Path $RepositoryRoot 'bin/ADFile.ps1')
$null=[IO.Directory]::CreateDirectory($WorkingDirectory)
function Assert-Saml($Value,[string]$Message){if(-not $Value){throw $Message}}
$global:SamlProbe=@{Calls=[Collections.Generic.List[object]]::new();Sleeps=[Collections.Generic.List[int]]::new();Fault='';AuthStatus='SUCCESS';Token='fixture-session';Html='<form><input name="SAMLResponse" value="fixture&#x2b;assertion&#61;&#61;"><input name="RelayState" value="return&#43;state&#61;"></form>';Prompts=0}
$urls=@{auth='https://fixture.invalid/auth';logn='https://fixture.invalid/login';saml='https://fixture.invalid/saml';appl='https://fixture.invalid/acs';data='https://fixture.invalid/data'}
$config=@{limit=2;wait=0;RequestTimeoutSeconds=13}
$credential=[pscredential]::new('fixture-user',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
$global:SamlFixtureCredential=$credential
function Get-Credential {[CmdletBinding()]param($UserName,$Message) $global:SamlProbe.Prompts++;$global:SamlFixtureCredential}
function Start-Sleep {param([int]$Seconds) $global:SamlProbe.Sleeps.Add($Seconds)}
function Add-SamlCall([string]$Command,$Bound){
    $kind=if($Bound.Uri -eq $urls.auth){'Auth'}elseif($Bound.Uri -eq $urls.logn){'Login'}elseif($Bound.Uri -eq $urls.appl){'ACS'}else{'Get'}
    $row=[ordered]@{Kind=$kind;Command=$Command;Method=$Bound.Method;TimeoutSec=$Bound.TimeoutSec;OperationTimeoutSeconds=$Bound.OperationTimeoutSeconds;SslProtocol=$Bound.SslProtocol;Session=$Bound.WebSession;ErrorAction=$Bound.ErrorAction;PasswordPresent=$false;AssertionCorrect=$false;RelayCorrect=$false}
    $row.ProcessTls=[Net.ServicePointManager]::SecurityProtocol
    if($kind -eq 'Auth'){$parsed=$Bound.Body | ConvertFrom-Json;$row.PasswordPresent=-not [string]::IsNullOrEmpty([string]$parsed.password)}
    if($kind -eq 'ACS'){$row.AssertionCorrect=$Bound.Body.SAMLResponse -ceq 'fixture+assertion==';$row.RelayCorrect=$Bound.Body.RelayState -ceq 'return+state='}
    $global:SamlProbe.Calls.Add([pscustomobject]$row)
    if($global:SamlProbe.Fault -eq $kind -or ($global:SamlProbe.Fault -eq 'SecondGet' -and $kind -eq 'Get' -and @($global:SamlProbe.Calls | Where-Object Kind -eq Get).Count -eq 2)){throw ('fixture request failure '+$kind)}
    return $kind
}
function Invoke-RestMethod {
    [CmdletBinding()]param($Uri,$Method,$ContentType,$WebSession,$Body,[switch]$UseBasicParsing,$UserAgent,[Alias('ConnectionTimeoutSeconds')]$TimeoutSec,$OperationTimeoutSeconds,$SslProtocol)
    $kind=Add-SamlCall Rest $PSBoundParameters
    if($kind -eq 'Auth'){return [pscustomobject]@{Status=$global:SamlProbe.AuthStatus;SessionToken=$global:SamlProbe.Token}}
    if($kind -eq 'Login'){return [pscustomobject]@{InputFields=@([pscustomobject]@{Name='SAMLResponse';Value='fixture&#x2b;assertion&#61;&#61;'})}}
    [pscustomobject]@{status='Success'}
}
function Invoke-WebRequest {
    [CmdletBinding()]param($Uri,$Method,$ContentType,$WebSession,$Body,[switch]$UseBasicParsing,$UserAgent,[Alias('ConnectionTimeoutSeconds')]$TimeoutSec,$OperationTimeoutSeconds,$SslProtocol)
    $kind=Add-SamlCall Web $PSBoundParameters
    if($kind -eq 'Login'){return [pscustomobject]@{Content=$global:SamlProbe.Html}}
    [pscustomobject]@{Content='fixture complete';StatusCode=200}
}
$path=Join-Path $RepositoryRoot 'etc/Test-SAMLProtectedResponseTimes.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Assert-Saml ($errors.Count -eq 0) 'SAML source did not parse'
$inheritedTls=[Net.ServicePointManager]::SecurityProtocol
$originalTls=[Net.SecurityProtocolType]::SystemDefault
[Net.ServicePointManager]::SecurityProtocol=$originalTls
try{
    if($Mode -in @('Inert','Cli')){
        Assert-Saml ($ast.Extent.Text -match 'MyInvocation\.InvocationName') 'Old automatic authentication startup rejected'
        if($Mode -eq 'Inert'){$output=@(. $path);Assert-Saml ($output.Count -eq 0 -and $global:SamlProbe.Calls.Count -eq 0 -and $global:SamlProbe.Prompts -eq 0) 'Dot source authenticated/emitted data'}
        else{
            $savedPreference=$ErrorActionPreference
            try{$ErrorActionPreference='Continue';$fresh=@(& (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -File $path 2>&1);$freshExit=$LASTEXITCODE}finally{$ErrorActionPreference=$savedPreference}
            Assert-Saml ($freshExit -ne 0 -and ($fresh -join ' ') -match 'Specify ConfigPath') 'Fresh CLI did not reach explicit-config guard'
            $json=Join-Path $WorkingDirectory 'config.json';[IO.File]::WriteAllText($json,(@{Url=$urls;Config=$config} | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($true))
            $caught=$false;try{& $path | Out-Null}catch{$caught=$true};Assert-Saml ($caught -and $global:SamlProbe.Calls.Count -eq 0) 'CLI authenticated without explicit configuration'
            $csv=Join-Path $WorkingDirectory 'cli.csv';$rows=@(& $path -ConfigPath $json -Credential $credential -OutputPath $csv)
            Assert-Saml ($rows.Count -eq 2 -and @(Import-Csv -LiteralPath $csv).Count -eq 2 -and @($global:SamlProbe.Calls | Where-Object Kind -eq ACS).Count -eq 1) 'Explicit CLI workflow/export failed'
        }
    }else{
        $types=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.TypeDefinitionAst]},$true))
        $classSource='using namespace System.Collections'+[Environment]::NewLine+'using namespace System.Collections.Specialized'+[Environment]::NewLine+($types.Extent.Text -join [Environment]::NewLine)
        . ([scriptblock]::Create($classSource))
        if($Mode -eq 'Constructor'){
            $before=@{Url=$urls;Config=$config} | ConvertTo-Json -Depth 10 -Compress
            $target=[Target]::new($urls,$config)
            Assert-Saml ($target.Collection -is [Collections.ArrayList] -and $target.Collection.Count -eq 0) 'Actual collection constructor is broken'
            $target.Config.limit=1;$target.URL.auth='https://fixture.invalid/changed'
            Assert-Saml ((@{Url=$urls;Config=$config} | ConvertTo-Json -Depth 10 -Compress) -ceq $before) 'Constructor mutated caller tables'
        }elseif($Mode -eq 'Flow'){
            $target=[Target]::Initialize($urls,$config);$target.Analyze($urls.data)
            Assert-Saml (($global:SamlProbe.Calls.Kind -join ',') -ceq 'Auth,Login,ACS,Get,Get' -and $global:SamlProbe.Calls[1].Command -eq 'Web') 'Authentication/request order or repeated POST'
            Assert-Saml ($global:SamlProbe.Calls[0].PasswordPresent -and $global:SamlProbe.Calls[2].AssertionCorrect -and $global:SamlProbe.Calls[2].RelayCorrect -and $global:SamlProbe.Prompts -eq 1) 'Credential/form transport changed'
            Assert-Saml ($target.Collection.Count -eq 2 -and $global:SamlProbe.Sleeps.Count -eq 0) 'Measurement/zero delay changed'
        }elseif($Mode -eq 'Tokens'){
            foreach($spec in @(@{Status='MFA_REQUIRED';Token='fixture'},@{Status='SUCCESS';Token=''},@{Status='SUCCESS';Token=@('one','two')})){
                $global:SamlProbe.Calls.Clear();$global:SamlProbe.AuthStatus=$spec.Status;$global:SamlProbe.Token=$spec.Token;$caught=$false
                try{$null=[Target]::Initialize($urls,$config)}catch{$caught=$true}
                Assert-Saml ($caught -and $global:SamlProbe.Calls.Count -eq 1) 'Invalid auth evidence reached login'
            }
        }elseif($Mode -eq 'Parse'){
            Assert-Saml ([Target]::HttpsUrl([Uri]'https://fixture.invalid/path') -ceq 'https://fixture.invalid/path') 'HTTPS Uri input compatibility changed'
            foreach($html in @('<INPUT VALUE=''fixture&#43;assertion=='' NAME=''SAMLResponse''>', '<input value=fixture+assertion== name=SAMLResponse>', '<!--<input name=SAMLResponse value=wrong>--><script>"<input name=SAMLResponse value=wrong>"</script><style><input name=SAMLResponse value=wrong></style><textarea><input name=SAMLResponse value=wrong></textarea><input name=SAMLResponse value="fixture+assertion==">')){
                $form=[Target]::ReadSamlForm($html)
                Assert-Saml ($form.SAMLResponse -ceq 'fixture+assertion==') 'Form entity/attribute/raw-text parsing changed'
            }
            foreach($html in @('', '<input-custom name=SAMLResponse value=wrong>','<!--<input name=SAMLResponse value=wrong>', '<input name=SAMLResponse value="">','<input name=SAMLResponse value=one><input name=SAMLResponse value=two>','<input name=SAMLResponse name=other value=one>','<input name=SAMLResponse value=one value=two>','<template><input name=SAMLResponse value=one></template>')){
                $caught=$false;try{$null=[Target]::ReadSamlForm($html)}catch{$caught=$true};Assert-Saml $caught 'Ambiguous/missing/unsupported form was accepted'
            }
            $form=[Target]::ReadSamlForm($global:SamlProbe.Html);Assert-Saml ($form.RelayState -ceq 'return+state=') 'RelayState dropped or URI-decoded'
            $caught=$false;try{$null=[Target]::ReadSamlForm('<![CDATA[<input name=SAMLResponse value=wrong>]]>')}catch{$caught=$true};Assert-Saml $caught 'CDATA apparent input accepted'
            $caught=$false;try{$null=[Target]::ReadSamlForm('<div data="<input name=SAMLResponse value=decoy>')}catch{$caught=$true};Assert-Saml $caught 'Malformed outer attribute exposed apparent inner input'
            foreach($bad in @('<input! name=SAMLResponse value=wrong>','<input.foo name=SAMLResponse value=wrong>','<input_foo name=SAMLResponse value=wrong>',('<input'+[char]0x00A0+'name=SAMLResponse value=wrong>'),'<script><!-- </script><input name=SAMLResponse value=one> --></script><input name=SAMLResponse value=two>','<script><div data="</script><input name=SAMLResponse value=one>"></script><input name=SAMLResponse value=two>')){
                $caught=$false;try{$null=[Target]::ReadSamlForm($bad)}catch{$caught=$true};Assert-Saml $caught 'Tag boundary/raw-state ambiguity accepted'
            }
            $caught=$false;try{$null=[Target]::ReadSamlForm(('<input name'+[char]0x00A0+'=SAMLResponse value=wrong>'))}catch{$caught=$true};Assert-Saml $caught 'Non-HTML whitespace changed attribute identity'
            $form=[Target]::ReadSamlForm('<script></scripted><input name=SAMLResponse value=wrong></script><input name=SAMLResponse value=fixture+assertion==>')
            Assert-Saml ($form.SAMLResponse -ceq 'fixture+assertion==') 'Raw-text closing tag boundary changed'
        }elseif($Mode -eq 'Failures'){
            foreach($fault in @('Auth','Login','ACS')){
                $global:SamlProbe.Calls.Clear();$global:SamlProbe.Fault=$fault;$caught=$false
                try{$null=[Target]::Initialize($urls,$config)}catch{$caught=$true}
                $expected=if($fault -eq 'Auth'){1}elseif($fault -eq 'Login'){2}else{3}
                Assert-Saml ($caught -and $global:SamlProbe.Calls.Count -eq $expected -and [Net.ServicePointManager]::SecurityProtocol -eq $originalTls) ('Request replay/state leak after '+$fault)
            }
        }elseif($Mode -eq 'Timeouts'){
            $target=[Target]::Initialize($urls,$config);$target.Analyze($urls.data)
            foreach($call in $global:SamlProbe.Calls){
                Assert-Saml ($call.TimeoutSec -eq 13 -and $call.ErrorAction -eq 'Stop' -and [object]::ReferenceEquals($call.Session,$target.Session)) 'Missing timeout/error/session binding'
                $name=if($call.Command -eq 'Rest'){'Invoke-RestMethod'}else{'Invoke-WebRequest'}
                $native=Get-Command $name -CommandType Cmdlet
                if($native.Parameters.ContainsKey('OperationTimeoutSeconds')){Assert-Saml ($call.OperationTimeoutSeconds -eq 13) 'Missing operation timeout'}
                if($native.Parameters.ContainsKey('SslProtocol')){Assert-Saml ($call.SslProtocol -eq 'Tls12') 'Request did not pin TLS12'}else{Assert-Saml ($call.ProcessTls -eq [Net.SecurityProtocolType]::Tls12) 'Legacy request did not use TLS12'}
            }
            Assert-Saml ([Net.ServicePointManager]::SecurityProtocol -eq $originalTls) 'Request changed caller TLS policy'
        }elseif($Mode -eq 'Config'){
            foreach($bad in @(@{limit=0;wait=0},@{limit=$false;wait=0},@{limit=1;wait=-1},@{limit=1;wait=0;RequestTimeoutSeconds=0},@{limit=1;wait=0;RequestTimeoutSeconds=301})){
                $caught=$false;try{$null=[Target]::new($urls,$bad)}catch{$caught=$true};Assert-Saml ($caught -and $global:SamlProbe.Calls.Count -eq 0) 'Invalid config reached HTTP'
            }
            $badUrl=@{}+$urls;$badUrl.auth='http://fixture.invalid/auth';$caught=$false;try{$null=[Target]::Initialize($badUrl,$config)}catch{$caught=$true}
            Assert-Saml ($caught -and $global:SamlProbe.Calls.Count -eq 0 -and $global:SamlProbe.Prompts -eq 0) 'Insecure URL reached prompt/request'
        }elseif($Mode -eq 'Measure'){
            $cfg=@{limit=3;wait=2;RequestTimeoutSeconds=13};$target=[Target]::new($urls,$cfg);$target.Analyze($urls.data)
            Assert-Saml ($target.Collection.Count -eq 3 -and ($global:SamlProbe.Sleeps -join ',') -eq '2,2') 'Sample count/final sleep changed'
            foreach($row in $target.Collection){Assert-Saml ($row.status -eq 'Success' -and $row.seconds -ge 0 -and $row.timestamp) 'Timing row fabricated or incomplete'}
            $global:SamlProbe.Calls.Clear();$global:SamlProbe.Fault='SecondGet';$target=[Target]::new($urls,$config);$caught=$false
            try{$target.Analyze($urls.data)}catch{$caught=$true};Assert-Saml ($caught -and $target.Collection.Count -eq 1) 'Failed measurement produced row or hid failure'
        }elseif($Mode -eq 'Export'){
            $target=[Target]::new($urls,$config);$target.Analyze($urls.data);$csv=Join-Path $WorkingDirectory 'report.csv';$target.Export($csv)
            Assert-Saml (@(Import-Csv -LiteralPath $csv).Count -eq 2 -and ((Import-Csv -LiteralPath $csv | Select-Object -First 1).PSObject.Properties.Name -join ',') -ceq 'iteration,url,status,seconds,timestamp') 'CSV contract changed'
            [IO.File]::WriteAllText($csv,'previous');$global:SamlProbe.Fault='Get';$caught=$false
            try{$target.Analyze($urls.data);$target.Export($csv)}catch{$caught=$true};Assert-Saml ($caught -and [IO.File]::ReadAllText($csv) -ceq 'previous') 'Failed workflow replaced previous report'
        }else{throw 'Unknown fixture mode'}
    }
    Assert-Saml ([Net.ServicePointManager]::SecurityProtocol -eq $originalTls) 'Workflow left TLS policy changed'
}finally{
    if($null -ne (Get-Variable target -ErrorAction SilentlyContinue) -and $target.Session -is [IDisposable]){$target.Session.Dispose()}
    [Net.ServicePointManager]::SecurityProtocol=$inheritedTls
}
'PASS SAML contract '+$Mode
