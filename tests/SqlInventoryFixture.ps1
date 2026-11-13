param([string]$RepositoryRoot,[string]$WorkingDirectory,[string]$Mode)
$ErrorActionPreference='Stop'
$null=[IO.Directory]::CreateDirectory($WorkingDirectory)
$global:SqlProbe=@{Calls=[Collections.Generic.List[object]]::new();Fault='';Selection='All';Current=$WorkingDirectory;Drive='';Provider='FileSystem'}
function Assert-Sql($Value,[string]$Message){if(-not $Value){throw $Message}}
function Add-SqlCall([string]$Kind,$Bound){$copy=@{Kind=$Kind};foreach($key in $Bound.Keys){$copy[$key]=$Bound[$key]};$global:SqlProbe.Calls.Add([pscustomobject]$copy)}
function Import-Module {
    [CmdletBinding()]param($Name,$Scope)
    Add-SqlCall Import $PSBoundParameters
    Assert-Sql ([IO.Path]::GetFullPath($Name) -eq [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll')) -and $Scope -eq 'Local') 'AD import escaped bundle/call scope'
    if($global:SqlProbe.Fault -eq 'Import'){throw 'fixture import'}
}
function Get-ADRootDSE {
    [CmdletBinding()]param($Server,[pscredential]$Credential)
    Add-SqlCall Root $PSBoundParameters
    if($global:SqlProbe.Fault -eq 'Root'){throw 'fixture root'}
    [pscustomobject]@{DnsHostName='dc.fixture.invalid';DefaultNamingContext='DC=fixture,DC=invalid'}
}
function New-PSDrive {
    [CmdletBinding(SupportsShouldProcess=$true)]param($Name,$PSProvider,$Root,$Server,$Scope,[pscredential]$Credential)
    Add-SqlCall Drive $PSBoundParameters
    if($global:SqlProbe.Fault -eq 'Drive'){throw 'fixture drive'}
    $global:SqlProbe.Drive=$Name
    [pscustomobject]@{Name=$Name;Provider=[pscustomobject]@{Name=$(if($global:SqlProbe.Fault -eq 'Provider'){'FileSystem'}else{'ActiveDirectory'})}}
}
function Get-Location {[pscustomobject]@{Path=$global:SqlProbe.Current;Drive=[pscustomobject]@{Name=$(if($global:SqlProbe.Fault -eq 'Drift' -and $global:SqlProbe.Provider -eq 'ActiveDirectory'){'other-drive'}else{$global:SqlProbe.Drive})};Provider=[pscustomobject]@{Name=$global:SqlProbe.Provider}}}
function Set-Location {
    [CmdletBinding()]param($LiteralPath,$Path)
    $target=if($PSBoundParameters.ContainsKey('LiteralPath')){$LiteralPath}else{$Path}
    Add-SqlCall Location @{Target=[string]$target}
    if([string]$target -eq ($global:SqlProbe.Drive+':')){
        if($global:SqlProbe.Fault -eq 'Enter'){throw 'fixture enter'}
        $global:SqlProbe.Current=[string]$target;$global:SqlProbe.Provider='ActiveDirectory'
    }else{
        if($global:SqlProbe.Fault -in @('Restore','RestoreRemove')){throw 'fixture restore'}
        $global:SqlProbe.Current=[string]$target;$global:SqlProbe.Provider='FileSystem'
    }
}
function Remove-PSDrive {
    [CmdletBinding(SupportsShouldProcess=$true)]param($Name,$Scope,[switch]$Force)
    Add-SqlCall RemoveDrive $PSBoundParameters
    if($global:SqlProbe.Fault -in @('Remove','RestoreRemove')){throw 'fixture remove'}
}
function Get-ADComputer {
    [CmdletBinding()]param($Filter,$Properties,$SearchBase,$Server,[pscredential]$Credential)
    Add-SqlCall Computer $PSBoundParameters
    if($global:SqlProbe.Fault -eq 'Discovery'){throw 'fixture discovery'}
    if($global:SqlProbe.Fault -eq 'DiscoveryWrite'){Write-Error 'fixture discovery write';return}
    if($global:SqlProbe.Selection -eq 'None'){return}
    [pscustomobject]@{Name='sql-one';DNSHostName='sql-one.fixture.invalid';OperatingSystem='Windows Server 2022'}
    if($global:SqlProbe.Selection -eq 'One'){return}
    [pscustomobject]@{Name='empty-two';DNSHostName='empty-two.fixture.invalid';OperatingSystem='Windows Server 2019'}
    [pscustomobject]@{Name='linux-three';DNSHostName='linux-three.fixture.invalid';OperatingSystem='Linux'}
}
function New-CimSession {
    [CmdletBinding()]param($ComputerName,$OperationTimeoutSec,[pscredential]$Credential)
    Add-SqlCall Session $PSBoundParameters
    if($global:SqlProbe.Fault -eq 'Session'){throw 'fixture session'}
    [pscustomobject]@{ComputerName=$ComputerName}
}
function Get-CimInstance {
    [CmdletBinding()]param($ClassName,$Property,$CimSession,$OperationTimeoutSec)
    Add-SqlCall Query $PSBoundParameters
    if($global:SqlProbe.Fault -in @('Query','QueryCleanup')){throw 'fixture query'}
    if($global:SqlProbe.Fault -eq 'QueryWrite'){Write-Error 'fixture query write';return}
    if($global:SqlProbe.Fault -eq 'QueryPartial'){[pscustomobject]@{Name='MSSQLPartial';DisplayName='Partial';State='Running'};Write-Error 'fixture query partial';return}
    if($CimSession.ComputerName -like 'empty*'){[pscustomobject]@{Name='Other';DisplayName='Other service';State='Running'};return}
    foreach($state in @('Running','Stopped','Paused')){[pscustomobject]@{Name=('MSSQL'+$state);DisplayName=('SQL '+[char]0x00FC+', "quoted" '+$state);State=$state;Status=$state};if($global:SqlProbe.ServiceSelection -eq 'One'){break}}
}
function Remove-CimSession {
    [CmdletBinding()]param($CimSession)
    Add-SqlCall RemoveSession $PSBoundParameters
    if($global:SqlProbe.Fault -in @('Cleanup','QueryCleanup')){throw 'fixture cleanup'}
}
# Safe obsolete API/startup substitutes: the old source may only hit these mocks.
function Get-Service {[CmdletBinding()]param($ComputerName) foreach($state in @('Running','Stopped')){[pscustomobject]@{Name='SQL'+$state;DisplayName=$state;Status=$state}}}
function Export-Csv {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,$Path,[switch]$NoTypeInformation) process{throw 'Legacy startup export blocked'}}
$path=Join-Path $RepositoryRoot 'etc/Get-MSSQLServers.ps1'
$startupError=$null
try{$startup=@(. $path)}catch{$startupError=$_}
Remove-Item Function:Export-Csv
$startupCalls=$global:SqlProbe.Calls.Count;$global:SqlProbe.Calls.Clear()
function Invoke-SqlFixture([hashtable]$Extra=@{}){
    $params=@{SearchBase='OU=Servers,DC=fixture,DC=invalid'};foreach($key in $Extra.Keys){$params[$key]=$Extra[$key]}
    $values=@(Get-ADMSSQLServers @params)
    Assert-Sql ($values.Count -eq 1 -and $values[0].GetType().Name -eq 'Collection') 'Collection was enumerated, missing, or replaced'
    return ,$values[0]
}
if($Mode -eq 'Inert'){
    Assert-Sql ($null -eq $startupError -and $startup.Count -eq 0 -and $startupCalls -eq 0) 'Dot source performed startup queries/export'
}elseif($Mode -eq 'States'){
    $result=Invoke-SqlFixture
    Assert-Sql ($result.Count -eq 4) 'Default Windows Server filter or no-match row failed'
    Assert-Sql (($result[0].PSObject.Properties.Name -join ',') -ceq 'computer.Name,computer.Status,service.Name,service.DisplayName,service.Status,computer.Message') 'Six-column contract changed'
    foreach($state in @('Running','Stopped','Paused')){Assert-Sql (@($result | Where-Object {$_.'service.Status' -ceq $state -and $_.'computer.Status' -eq $true}).Count -eq 1) ('Lost literal state '+$state)}
    $empty=@($result | Where-Object {$_.'computer.Name' -eq 'empty-two'})
    Assert-Sql ($empty.Count -eq 1 -and $empty[0].'computer.Status' -eq $true -and $null -eq $empty[0].'service.Name') 'No-match became failure or vanished'
    Assert-Sql (@($global:SqlProbe.Calls | Where-Object Kind -eq Session).Count -eq 2 -and @($global:SqlProbe.Calls | Where-Object Kind -eq RemoveSession).Count -eq 2) 'Sessions leaked or nonserver probed'
    foreach($query in @($global:SqlProbe.Calls | Where-Object Kind -eq Query)){
        Assert-Sql (@($global:SqlProbe.Calls | Where-Object {$_.Kind -eq 'RemoveSession' -and [object]::ReferenceEquals($_.CimSession,$query.CimSession)}).Count -eq 1) 'Wrong CIM session was disposed'
    }
    $result.Finding('offline',$false,'actual fixture error')
    Assert-Sql ($result[-1].'computer.Status' -eq $false -and $result[-1].'computer.Message' -ceq 'actual fixture error') 'Finding discarded supplied error'
    $global:SqlProbe.Selection='One';$global:SqlProbe.ServiceSelection='One';$single=Invoke-SqlFixture
    Assert-Sql ($single.Count -eq 1 -and $single[0].'service.Status' -ceq 'Running') 'Single service changed the Collection return contract'
}elseif($Mode -eq 'Connections'){
    $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    $result=Invoke-SqlFixture @{Server='bootstrap.fixture.invalid';Credential=$credential;OperationTimeoutSeconds=17}
    $root=@($global:SqlProbe.Calls | Where-Object Kind -eq Root);$drive=@($global:SqlProbe.Calls | Where-Object Kind -eq Drive);$computer=@($global:SqlProbe.Calls | Where-Object Kind -eq Computer)
    Assert-Sql ($root.Count -eq 1 -and $root[0].Server -eq 'bootstrap.fixture.invalid' -and [object]::ReferenceEquals($root[0].Credential,$credential)) 'Bootstrap identity changed'
    Assert-Sql ($drive.Count -eq 1 -and $drive[0].Server -eq 'dc.fixture.invalid' -and $drive[0].Root -eq 'DC=fixture,DC=invalid' -and $drive[0].Scope -eq 'Local' -and $drive[0].PSProvider -eq 'ActiveDirectory' -and [object]::ReferenceEquals($drive[0].Credential,$credential)) 'Owned drive parameters changed'
    Assert-Sql ($computer.Count -eq 1 -and $computer[0].Server -eq 'dc.fixture.invalid' -and $computer[0].SearchBase -eq 'OU=Servers,DC=fixture,DC=invalid' -and -not $computer[0].PSObject.Properties['Credential'] -and $computer[0].Properties -contains 'OperatingSystem' -and $computer[0].Properties -contains 'DNSHostName') 'Drive query contract changed'
    Assert-Sql ($global:SqlProbe.Current -eq $WorkingDirectory -and @($global:SqlProbe.Calls | Where-Object Kind -eq RemoveDrive).Count -eq 1) 'Directory context was not restored/removed'
    $removed=@($global:SqlProbe.Calls | Where-Object Kind -eq RemoveDrive)[0]
    Assert-Sql ($removed.Name -ceq $drive[0].Name -and $removed.Scope -eq 'Local' -and $removed.Force) 'Wrong owned drive was removed'
    foreach($call in @($global:SqlProbe.Calls | Where-Object {$_.Kind -in @('Session','Query')})){
        Assert-Sql ($call.OperationTimeoutSec -eq 17 -and $call.ErrorAction -eq 'Stop') 'CIM operation bound missing'
        if($call.Kind -eq 'Session'){Assert-Sql ([object]::ReferenceEquals($call.Credential,$credential)) 'CIM credential changed'}
    }
    $order=@($global:SqlProbe.Calls.Kind);Assert-Sql ([array]::IndexOf($order,'RemoveDrive') -lt [array]::IndexOf($order,'Session')) 'Host probe ran before discovery cleanup'
}elseif($Mode -eq 'Direct'){
    $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    $result=Invoke-SqlFixture @{DirectoryConnection='Direct';Credential=$credential}
    Assert-Sql (@($global:SqlProbe.Calls | Where-Object Kind -in @('Drive','Location','RemoveDrive')).Count -eq 0) 'Direct mode created a drive'
    $computer=@($global:SqlProbe.Calls | Where-Object Kind -eq Computer)[0];Assert-Sql ([object]::ReferenceEquals($computer.Credential,$credential) -and $computer.Server -eq 'dc.fixture.invalid') 'Direct mode lost explicit identity'
    $global:SqlProbe.Calls.Clear();$result=Invoke-SqlFixture
    foreach($call in $global:SqlProbe.Calls){Assert-Sql (-not $call.PSObject.Properties['Credential']) 'Empty credential was rebound'}
}elseif($Mode -eq 'DiscoveryFailures'){
    $output=Join-Path $WorkingDirectory 'previous.csv'
    foreach($fault in @('Import','Root','Drive','Provider','Enter','Drift','Discovery','DiscoveryWrite','Restore','Remove','RestoreRemove')){
        $global:SqlProbe.Calls.Clear();$global:SqlProbe.Fault=$fault;$global:SqlProbe.Current=$WorkingDirectory;$global:SqlProbe.Provider='FileSystem'
        [IO.File]::WriteAllText($output,'previous');$emitted=[Collections.Generic.List[object]]::new();$caught=$false
        try{Get-ADMSSQLServers -OutputPath $output | ForEach-Object {$emitted.Add($_)}}catch{$caught=$true}
        Assert-Sql ($caught -and $emitted.Count -eq 0 -and [IO.File]::ReadAllText($output) -eq 'previous' -and @($global:SqlProbe.Calls | Where-Object Kind -eq Session).Count -eq 0) ('Discovery failure reached probe/export: '+$fault)
        if($fault -in @('Provider','Enter','Drift','Discovery','DiscoveryWrite','Restore','Remove','RestoreRemove')){Assert-Sql (@($global:SqlProbe.Calls | Where-Object Kind -eq RemoveDrive).Count -eq 1) ('Drive cleanup missing '+$fault)}
    }
}elseif($Mode -eq 'HostFailures'){
    $global:SqlProbe.Selection='One'
    foreach($fault in @('Session','Query','QueryWrite','QueryPartial','Cleanup','QueryCleanup')){
        $global:SqlProbe.Calls.Clear();$global:SqlProbe.Fault=$fault
        $result=Invoke-SqlFixture
        $success=$fault -eq 'Cleanup'
        Assert-Sql ($result.Count -eq $(if($success){3}else{1}) -and $result[0].'computer.Status' -eq $success -and $result[0].'computer.Message' -match 'fixture') ('Host evidence lost '+$fault)
        if($success){Assert-Sql ($result[1].'service.Status' -ceq 'Stopped') 'Cleanup discarded observation'}
        if($fault -eq 'QueryCleanup'){Assert-Sql ($result[0].'computer.Message' -match 'fixture query' -and $result[0].'computer.Message' -match 'fixture cleanup') 'Secondary cleanup evidence erased primary failure'}
        Assert-Sql (@($global:SqlProbe.Calls | Where-Object Kind -eq RemoveSession).Count -eq $(if($fault -eq 'Session'){0}else{1})) ('Session cleanup missing '+$fault)
    }
}elseif($Mode -eq 'Validation'){
    foreach($extra in @(@{Filter='['},@{OperationTimeoutSeconds=0},@{OperationTimeoutSeconds=301},@{DirectoryConnection='Other'})){
        $global:SqlProbe.Calls.Clear();$caught=$false;try{$null=Get-ADMSSQLServers @extra}catch{$caught=$true}
        Assert-Sql ($caught -and $global:SqlProbe.Calls.Count -eq 0) 'Invalid configuration reached dependencies'
    }
}elseif($Mode -eq 'Csv'){
    $output=Join-Path $WorkingDirectory 'folder[1]/sql[2].csv';$result=Invoke-SqlFixture @{OutputPath=$output};$csv=@(Import-Csv -LiteralPath $output)
    Assert-Sql ($csv.Count -eq 4 -and $csv[0].'service.Status' -ceq 'Running' -and $csv[1].'service.Status' -ceq 'Stopped' -and $csv[0].'service.DisplayName' -ceq ('SQL '+[char]0x00FC+', "quoted" Running')) 'CSV values changed'
    $global:SqlProbe.Selection='None';$empty=Invoke-SqlFixture;$empty.Export($output)
    Assert-Sql ($empty.Count -eq 0 -and @(Import-Csv -LiteralPath $output).Count -eq 0 -and [IO.File]::ReadAllText($output).Trim() -ceq '"computer.Name","computer.Status","service.Name","service.DisplayName","service.Status","computer.Message"') 'Empty export lost schema or retained rows'
}elseif($Mode -eq 'ExportFailures'){
    $output=Join-Path $WorkingDirectory 'previous.csv';$result=Invoke-SqlFixture;[IO.File]::WriteAllText($output,'previous')
    function ConvertTo-Csv {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[switch]$NoTypeInformation) process{Write-Error 'fixture serialization'}}
    $caught=$false;$preference=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';try{$result.Export($output)}catch{$caught=$true}}finally{$ErrorActionPreference=$preference;Remove-Item Function:ConvertTo-Csv}
    Assert-Sql ((Get-Command ConvertTo-Csv).CommandType -eq 'Cmdlet') 'Conversion mock leaked'
    Assert-Sql ($caught -and [IO.File]::ReadAllText($output) -eq 'previous') 'Serialization erased output'
    $directory=Join-Path $WorkingDirectory 'directory';$null=[IO.Directory]::CreateDirectory($directory);$caught=$false
    try{$result.Export($directory)}catch{$caught=$true};Assert-Sql ($caught -and [IO.Directory]::Exists($directory)) 'Write failure looked successful'
}elseif($Mode -eq 'WhatIf'){
    $output=Join-Path $WorkingDirectory 'preview/report.csv';$result=Invoke-SqlFixture @{OutputPath=$output;WhatIf=$true}
    Assert-Sql ($result.Count -eq 4 -and -not (Test-Path -LiteralPath $output)) 'WhatIf lost data or wrote output'
}elseif($Mode -eq 'Cli'){
    $global:SqlProbe.Calls.Clear();$caught=$false;try{& $path | Out-Null}catch{$caught=$true}
    Assert-Sql ($caught -and $global:SqlProbe.Calls.Count -eq 0) 'CLI ran without explicit discovery choice'
    $output=Join-Path $WorkingDirectory 'cli.csv';$values=@(& $path -SearchBase 'DC=fixture,DC=invalid' -OutputPath $output -Confirm:$false)
    Assert-Sql ($values.Count -eq 1 -and $values[0].Count -eq 4 -and @(Import-Csv -LiteralPath $output).Count -eq 4) 'Explicit CLI/collection failed'
}else{throw 'Unknown fixture mode'}
'PASS SQL inventory '+$Mode

