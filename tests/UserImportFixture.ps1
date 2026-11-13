param([string]$RepositoryRoot,[string]$WorkingDirectory,[string]$Mode)
$ErrorActionPreference='Stop'
$null=[IO.Directory]::CreateDirectory($WorkingDirectory)
Set-Location -LiteralPath $WorkingDirectory
function Assert-Import($Value,[string]$Message){if(-not $Value){throw $Message}}
$global:UserImportProbe=@{Calls=[Collections.Generic.List[object]]::new();Users=@{existing=$true};Fault='';Enables=0}
function Add-ImportCall([string]$Kind,$Bound){
    $copy=@{Kind=$Kind}
    foreach($key in $Bound.Keys){if($key -ne 'AccountPassword'){$copy[$key]=$Bound[$key]}}
    if($Bound.ContainsKey('AccountPassword')){$copy.PasswordPresent=$null -ne $Bound.AccountPassword -and $Bound.AccountPassword.Length -gt 0}
    $global:UserImportProbe.Calls.Add([pscustomobject]$copy)
}
function Import-Module {
    [CmdletBinding()]param($Name,$Scope)
    Add-ImportCall Import $PSBoundParameters
    Assert-Import ([IO.Path]::GetFullPath($Name) -eq [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll')) -and $Scope -eq 'Local') 'Unscoped/external import'
    if($global:UserImportProbe.Fault -eq 'Import'){Write-Error 'fixture import unavailable'}
}
function Get-ADRootDSE {
    [CmdletBinding()]param($Server,[pscredential]$Credential)
    Add-ImportCall Root $PSBoundParameters
    if($global:UserImportProbe.Fault -eq 'Root'){Write-Error 'fixture root unavailable';return}
    [pscustomobject]@{DefaultNamingContext='DC=fixture,DC=invalid'}
}
function Get-ADUser {
    [CmdletBinding()]param($LDAPFilter,$SearchBase,$Properties,$Server,[pscredential]$Credential)
    Add-ImportCall Lookup $PSBoundParameters
    Assert-Import ($SearchBase -eq 'DC=fixture,DC=invalid') 'Lookup inherited a narrow search base'
    if($global:UserImportProbe.Fault -eq 'LookupThrow'){throw 'fixture lookup unavailable'}
    if($global:UserImportProbe.Fault -eq 'LookupWrite'){Write-Error 'fixture lookup unavailable';return}
    $prefix='(sAMAccountName='
    Assert-Import ($LDAPFilter.StartsWith($prefix) -and $LDAPFilter.EndsWith(')')) 'Wrong lookup filter'
    $name=$LDAPFilter.Substring($prefix.Length,$LDAPFilter.Length-$prefix.Length-1).Replace('\2a','*').Replace('\28','(').Replace('\29',')').Replace('\00',[string][char]0).Replace('\5c','\')
    if($global:UserImportProbe.Users.ContainsKey($name)){[pscustomobject]@{SamAccountName=$name}}
}
function New-ADUser {
    [CmdletBinding()]param($Name,$SamAccountName,$GivenName,$Surname,$DisplayName,$Department,$EmployeeID,$UserPrincipalName,[Security.SecureString]$AccountPassword,[bool]$Enabled,[bool]$ChangePasswordAtLogon,$Path,[switch]$PassThru,$Server,[pscredential]$Credential)
    Add-ImportCall Create $PSBoundParameters
    Assert-Import ($Enabled -and $ChangePasswordAtLogon -and -not $PassThru -and $AccountPassword.Length -gt 0) 'Creation flags/password/output contract changed'
    if($global:UserImportProbe.Fault -eq 'CreateThrow'){throw 'fixture creation failed'}
    if($global:UserImportProbe.Fault -eq 'Partial'){$global:UserImportProbe.Users[$SamAccountName]=$true;Write-Error 'fixture partial creation';return}
    if($global:UserImportProbe.Fault -eq 'CreateWrite'){Write-Error 'fixture creation failed';return}
    $global:UserImportProbe.Users[$SamAccountName]=$true
}
function Enable-ADAccount {$global:UserImportProbe.Enables++;throw 'Redundant enable call'}
function Write-ImportCsv($Rows){
    $path=Join-Path $WorkingDirectory 'input[1].csv'
    $text=($Rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
    [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($true))
    return $path
}
function New-ImportRow([string]$Name){
    [pscustomobject]@{username=$Name;name=('Fixture '+[char]0x00FC+' '+$Name);password='synthetic-fixture-only';path='OU=Fixture,DC=fixture,DC=invalid';givenName='Given';surname='Surname';displayName='Display';department='';employeeID='00123';userPrincipalName=($Name+'@fixture.invalid')}
}
$path=Join-Path $RepositoryRoot 'etc/New-ADPASUser.ps1';$CsvPath='caller-csv';$Server='caller-server'
$startup=@(. $path)
Assert-Import ($startup.Count -eq 0 -and $global:UserImportProbe.Calls.Count -eq 0 -and $CsvPath -ceq 'caller-csv' -and $Server -ceq 'caller-server') 'Dot source performed work/changed caller inputs'
if($Mode -eq 'Inert'){}
elseif($Mode -eq 'DuplicateCreate'){
    $existing=New-ImportRow existing;$existing.name='';$existing.password='';$existing.path=''
    $csv=Write-ImportCsv @($existing,(New-ImportRow newuser))
    $output=@(New-ADPASUser -CsvPath $csv -Confirm:$false 3>&1)
    $created=@($global:UserImportProbe.Calls | Where-Object Kind -eq Create)
    Assert-Import ($created.Count -eq 1 -and $created[0].SamAccountName -ceq 'newuser' -and $created[0].Name -ceq ('Fixture '+[char]0x00FC+' newuser') -and $created[0].PasswordPresent -eq $true -and $created[0].EmployeeID -ceq '00123' -and -not $created[0].PSObject.Properties['Department']) 'Duplicate/attribute/password contract changed'
    Assert-Import (@($output | Where-Object {$_ -is [Management.Automation.WarningRecord]}).Count -eq 1 -and @($output | Where-Object {$_ -isnot [Management.Automation.WarningRecord]}).Count -eq 0) 'Duplicate warning failed or success payload leaked'
    $onlyUsername=Write-ImportCsv @([pscustomobject]@{username='existing'});$null=New-ADPASUser -CsvPath $onlyUsername -WarningAction SilentlyContinue
    Assert-Import (@($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 1) 'Existing user required creation-only columns'
}elseif($Mode -eq 'Idempotent'){
    $csv=Write-ImportCsv @((New-ImportRow newuser),(New-ImportRow newuser))
    $null=New-ADPASUser -CsvPath $csv -Confirm:$false -WarningAction SilentlyContinue
    $null=New-ADPASUser -CsvPath $csv -Confirm:$false -WarningAction SilentlyContinue
    Assert-Import (@($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 1) 'Duplicate batch/rerun created again'
}elseif($Mode -eq 'Connections'){
    $csv=Write-ImportCsv @((New-ImportRow newuser));$credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    $null=New-ADPASUser -CsvPath $csv -Server dc.fixture.invalid -Credential $credential -Confirm:$false
    foreach($call in @($global:UserImportProbe.Calls | Where-Object Kind -in @('Root','Lookup','Create'))){Assert-Import ($call.Server -eq 'dc.fixture.invalid' -and [object]::ReferenceEquals($call.Credential,$credential) -and $call.ErrorAction -eq 'Stop') 'Connection/error identity changed'}
    Assert-Import (@($global:UserImportProbe.Calls | Where-Object Kind -eq Root).Count -eq 1) 'Naming context not read once'
    $global:UserImportProbe.Calls.Clear();$global:UserImportProbe.Users=@{};$null=New-ADPASUser -CsvPath $csv -WarningAction SilentlyContinue
    foreach($call in $global:UserImportProbe.Calls){Assert-Import (-not $call.PSObject.Properties['Credential'] -and -not $call.PSObject.Properties['Server']) 'Empty connection was rebound'}
}elseif($Mode -eq 'LookupFailures'){
    $csv=Write-ImportCsv @((New-ImportRow newuser))
    foreach($fault in @('Import','Root','LookupThrow','LookupWrite')){foreach($preference in @('Continue','Stop')){
        $global:UserImportProbe.Calls.Clear();$global:UserImportProbe.Fault=$fault;$caught=$false;$saved=$ErrorActionPreference
        try{$ErrorActionPreference=$preference;try{New-ADPASUser -CsvPath $csv -Confirm:$false | Out-Null}catch{$caught=$true}}finally{$ErrorActionPreference=$saved}
        Assert-Import ($caught -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 0) ('Inconclusive lookup permitted create '+$fault+'/'+$preference)
    }}
}elseif($Mode -eq 'CreateFailures'){
    $csv=Write-ImportCsv @((New-ImportRow newuser),(New-ImportRow lateruser))
    foreach($fault in @('CreateThrow','CreateWrite','Partial')){
        $global:UserImportProbe.Calls.Clear();$global:UserImportProbe.Users=@{};$global:UserImportProbe.Fault=$fault;$caught=$false;$saved=$ErrorActionPreference
        try{$ErrorActionPreference='Continue';try{New-ADPASUser -CsvPath $csv -Confirm:$false | Out-Null}catch{$caught=$true}}finally{$ErrorActionPreference=$saved}
        Assert-Import ($caught -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 1 -and -not $global:UserImportProbe.Users.ContainsKey('lateruser')) 'Creation failure retried/enabled/continued'
        if($fault -eq 'Partial'){Assert-Import ($global:UserImportProbe.Users.ContainsKey('newuser')) 'Partial-persistence fixture did not execute'}
    }
}elseif($Mode -eq 'Validation'){
    foreach($row in @([pscustomobject]@{username=' '},[pscustomobject]@{username='newuser';name='';password='fixture';path='OU=Fixture,DC=fixture,DC=invalid'},[pscustomobject]@{username='newuser';name='Fixture';password='';path='OU=Fixture,DC=fixture,DC=invalid'},[pscustomobject]@{username='newuser';name='Fixture';password='fixture';path=''})){
        $global:UserImportProbe.Calls.Clear();$csv=Write-ImportCsv @($row);$caught=$false
        try{New-ADPASUser -CsvPath $csv -Confirm:$false | Out-Null}catch{$caught=$true}
        Assert-Import ($caught -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 0) 'Missing field reached create'
        if([string]::IsNullOrWhiteSpace($row.username)){Assert-Import ($global:UserImportProbe.Calls.Count -eq 0) 'Invalid username reached import/lookup'}
    }
    $global:UserImportProbe.Calls.Clear();$csv=Join-Path $WorkingDirectory 'empty.csv';[IO.File]::WriteAllText($csv,'"username"',[Text.UTF8Encoding]::new($true));$output=@(New-ADPASUser -CsvPath $csv)
    Assert-Import ($output.Count -eq 0 -and $global:UserImportProbe.Calls.Count -eq 0) 'Empty batch contacted AD'
}elseif($Mode -eq 'WhatIf'){
    $csv=Write-ImportCsv @((New-ImportRow newuser));$output=@(New-ADPASUser -CsvPath $csv -WhatIf)
    Assert-Import ($output.Count -eq 0 -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Lookup).Count -eq 1 -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 0) 'WhatIf created or skipped read/validation'
    $invalid=New-ImportRow newuser;$invalid.password='';$csv=Write-ImportCsv @($invalid);$caught=$false
    try{New-ADPASUser -CsvPath $csv -WhatIf | Out-Null}catch{$caught=$true}
    Assert-Import ($caught -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 0) 'WhatIf bypassed creation validation'
}elseif($Mode -eq 'Cli'){
    $caught=$false;try{& $path | Out-Null}catch{$caught=$true};Assert-Import ($caught -and $global:UserImportProbe.Calls.Count -eq 0) 'CLI ran without explicit CSV'
    $csv=Write-ImportCsv @((New-ImportRow newuser));$output=@(& $path -CsvPath $csv -Confirm:$false)
    Assert-Import ($output.Count -eq 0 -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 1) 'Explicit CLI failed'
}elseif($Mode -eq 'SpecialFilter'){
    $special='literal*(x)\name';$global:UserImportProbe.Users[$special]=$true;$row=New-ImportRow $special;$csv=Write-ImportCsv @($row)
    $null=New-ADPASUser -CsvPath $csv -WarningAction SilentlyContinue
    $lookup=@($global:UserImportProbe.Calls | Where-Object Kind -eq Lookup)
    Assert-Import ($lookup.Count -eq 1 -and $lookup[0].LDAPFilter -ceq '(sAMAccountName=literal\2a\28x\29\5cname)' -and @($global:UserImportProbe.Calls | Where-Object Kind -eq Create).Count -eq 0) 'SAM filter was not literal'
}else{throw 'Unknown fixture mode'}
Assert-Import ($global:UserImportProbe.Enables -eq 0) 'Redundant enable call occurred'
'PASS user import '+$Mode
