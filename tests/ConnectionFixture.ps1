param([string]$RepositoryRoot,[string]$WorkingDirectory,[string]$Mode)
$ErrorActionPreference='Stop'
$global:ConnectionFixtureCalls=0
function Assert-Connection($Value,[string]$Message){if(-not $Value){throw $Message}}
function Get-Credential {throw 'Unexpected fixture credential prompt'}
$path=Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
Assert-Connection ($errors.Count -eq 0) 'Connection source did not parse'
$connect=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Connect-WindowsServer'},$true)
$unsafe=@($ast.EndBlock.Statements | Where-Object {$_ -isnot [Management.Automation.Language.FunctionDefinitionAst] -and $_.Extent.Text -match 'AccountManagement\.PrincipalContext'})
$guarded=$ast.Extent.Text -match 'MyInvocation\.InvocationName'
$null=[IO.Directory]::CreateDirectory($WorkingDirectory)
$copy=Join-Path $WorkingDirectory 'Test-Runspace.ps1';[IO.File]::Copy($path,$copy,$true)
$helper=Join-Path $WorkingDirectory 'Get-ServerHPA.ps1'
[IO.File]::WriteAllText($helper,@'
function Get-ServerHPA {
    [CmdletBinding()]param([string]$Computer,[string]$Target,[pscredential]$Credential=[pscredential]::Empty)
    $global:ConnectionFixtureCalls++
    $var['Calls']++
    $var['LastCredential']=$Credential
    if($Computer -eq 'error-host'){throw $var['Failure']}
    [pscustomobject]@{Computer=$Computer;Target=$Target;Marker='fixture-only';CredentialUser=$(if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$Credential.UserName}else{$null})}
}
'@)
if($unsafe.Count -or -not $guarded){
    # Never execute old domain-context construction or the hardcoded startup call.
    if($Mode -in @('Inert','Worker','Cli')){throw 'Unsafe original top-level connection startup rejected'}
    . ([scriptblock]::Create($connect.Extent.Text))
    $constant=@{HostGroupHelperPath=$helper};$var=[hashtable]::Synchronized(@{})
}else{
    $context='caller-context';$principal='caller-principal';$domain='caller-domain'
    $startup=@(. $copy)
    Assert-Connection ($startup.Count -eq 0 -and $context -ceq 'caller-context' -and $principal -ceq 'caller-principal' -and $domain -ceq 'caller-domain') 'Dot source performed work or changed caller inputs'
    Assert-Connection (-not $constant.domain.ContainsKey('context')) 'Dot source created a domain binding'
}
Assert-Connection ([IO.Path]::GetFullPath([string]$constant['HostGroupHelperPath']) -eq [IO.Path]::GetFullPath($helper)) 'Configured reader escaped the isolated fixture'
$var['Calls']=0;$var['Failure']=[InvalidOperationException]::new('original fixture delegation failure')
$borrowed=[pscustomobject]@{Disposed=$false};$borrowed | Add-Member ScriptMethod Dispose {$this.Disposed=$true}
if($Mode -eq 'Inert'){
    Assert-Connection ($var['Calls'] -eq 0 -and -not (Get-Command Get-ServerHPA -CommandType Function -ErrorAction SilentlyContinue)) 'Inert load read host metadata'
}elseif($Mode -in @('Delegate','Credentials')){
    $arguments=@{context='fixture-host';principal='fixture-group';domain=$borrowed}
    if($Mode -eq 'Credentials'){$credential=[pscredential]::new('fixture-user',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force));$arguments.Credential=$credential}
    $rows=@(Connect-WindowsServer @arguments)
    Assert-Connection ($rows.Count -eq 1 -and $rows[0].Computer -ceq 'fixture-host' -and $rows[0].Target -ceq 'fixture-group' -and $rows[0].Marker -ceq 'fixture-only' -and $var['Calls'] -eq 1 -and -not $borrowed.Disposed) 'Delegation/output/borrowed ownership failed'
    if($Mode -eq 'Credentials'){Assert-Connection ([object]::ReferenceEquals($var['LastCredential'],$credential) -and $rows[0].CredentialUser -ceq 'fixture-user') 'Explicit credential identity changed'}
    else{Assert-Connection ($var['LastCredential'] -eq [pscredential]::Empty -and $null -eq $rows[0].CredentialUser) 'Default identity changed'}
    Assert-Connection (-not (Get-Command Get-ServerHPA -CommandType Function -ErrorAction SilentlyContinue)) 'Private helper function leaked'
}elseif($Mode -eq 'Errors'){
    $caught=$null;try{Connect-WindowsServer -context error-host -principal fixture-group -domain $borrowed | Out-Null}catch{$caught=$_}
    Assert-Connection ($null -ne $caught -and [object]::ReferenceEquals($caught.Exception.GetBaseException(),$var['Failure']) -and -not $borrowed.Disposed) 'Delegated original error was replaced or borrowed input disposed'
    [IO.File]::Delete($helper);$before=$var['Calls'];$caught=$false
    try{Connect-WindowsServer -context fixture-host -principal fixture-group | Out-Null}catch{$caught=$true}
    Assert-Connection ($caught -and $var['Calls'] -eq $before) 'Missing dependency fabricated success/fell through'
}elseif($Mode -eq 'Worker'){
    Assert-Connection (-not (Get-Command Get-ServerHPA -CommandType Function -ErrorAction SilentlyContinue)) 'Worker test preloaded dependency'
    $state=$null;$runner=$null
    try{
        $state=Initialize-RunspacePool -MaxRunspaces 1;$state.pool.Open()
        $runner=[powershell]::Create();$runner.RunspacePool=$state.pool
        $null=$runner.AddScript("Connect-WindowsServer -context fixture-host -principal fixture-group")
        $rows=@($runner.Invoke())
        Assert-Connection (-not $runner.HadErrors -and $rows.Count -eq 1 -and $rows[0].Marker -ceq 'fixture-only' -and $rows[0].Computer -ceq 'fixture-host' -and $rows[0].Target -ceq 'fixture-group' -and $var['Calls'] -eq 1) 'Cloned connection lost its sibling dependency/configuration'
    }finally{if($null -ne $runner){$runner.Dispose()};if($null -ne $state){$state.pool.Dispose()}}
}elseif($Mode -eq 'Cli'){
    $caught=$false;try{& $copy | Out-Null}catch{$caught=$true}
    Assert-Connection ($caught -and $var['Calls'] -eq 0 -and $global:ConnectionFixtureCalls -eq 0) 'CLI ran without explicit host/group'
    $rows=@(& $copy -context fixture-host -principal fixture-group)
    Assert-Connection ($rows.Count -eq 1 -and $rows[0].Marker -ceq 'fixture-only' -and $rows[0].Computer -ceq 'fixture-host' -and $rows[0].Target -ceq 'fixture-group' -and $global:ConnectionFixtureCalls -eq 1) 'Explicit CLI did not delegate'
}else{throw 'Unknown fixture mode'}
'PASS connection contract '+$Mode
