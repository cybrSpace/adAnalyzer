[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('CsvPath')][string]$CliCsvPath,
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty
)

function New-ADPASUser {
    <# .SYNOPSIS Creates absent CSV users; failures may leave an account and are not retried. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$CsvPath,[string]$Server,[pscredential]$Credential=[pscredential]::Empty)
    $ErrorActionPreference='Stop'
    if([string]::IsNullOrWhiteSpace($CsvPath)){throw 'Specify an explicit CsvPath.'}
    if($PSBoundParameters.ContainsKey('Server') -and [string]::IsNullOrWhiteSpace($Server)){throw 'Server must be nonempty when specified.'}
    $adUsers=@(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)
    if(-not $adUsers.Count){return}
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    foreach($user in $adUsers){
        if([string]::IsNullOrWhiteSpace([string]$user.username)){throw 'Each CSV row requires username.'}
        $null=$utf8.GetByteCount([string]$user.username)
    }
    $repository=Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $connection=@{ErrorAction='Stop'}
    if($Server){$connection.Server=$Server}
    if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$connection.Credential=$Credential}
    $roots=@(Get-ADRootDSE @connection)
    if($roots.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$roots[0].DefaultNamingContext)){throw 'The target default naming context is unavailable.'}
    $searchBase=[string]$roots[0].DefaultNamingContext
    foreach($user in $adUsers){
        $username=[string]$user.username
        $escaped=$username.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
        $existing=@(Get-ADUser -LDAPFilter ('(sAMAccountName='+$escaped+')') -SearchBase $searchBase -Properties SamAccountName @connection)
        if($existing.Count){
            Write-Warning ('User {0} already exists' -f $username)
            continue
        }
        foreach($field in @('name','path')){
            if([string]::IsNullOrWhiteSpace([string]$user.$field)){throw ('An absent user requires CSV field: '+$field)}
        }
        if([string]::IsNullOrEmpty([string]$user.password)){throw 'An absent user requires CSV field: password'}
        if(-not $PSCmdlet.ShouldProcess($username,'Create enabled AD user and require password change')){continue}
        $parameters=@{}+$connection+@{Name=[string]$user.name;SamAccountName=$username;Path=[string]$user.path;Enabled=$true;ChangePasswordAtLogon=$true}
        foreach($field in @('GivenName','Surname','DisplayName','Department','EmployeeID','UserPrincipalName')){
            if(-not [string]::IsNullOrEmpty([string]$user.$field)){$parameters[$field]=[string]$user.$field}
        }
        $password=$null
        try{
            $password=ConvertTo-SecureString ([string]$user.password) -AsPlainText -Force -ErrorAction Stop
            $parameters.AccountPassword=$password
            $null=New-ADUser @parameters
        }finally{if($null -ne $password){$password.Dispose()}}
    }
}
if($MyInvocation.InvocationName -ne '.'){
    $arguments=@{CsvPath=$CliCsvPath;Credential=$CliCredential;WhatIf=[bool]$WhatIfPreference}
    if($PSBoundParameters.ContainsKey('CliServer')){$arguments.Server=$CliServer}
    if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
    New-ADPASUser @arguments
}
