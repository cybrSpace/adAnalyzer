using namespace System.Collections
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('SearchBase')][string]$CliSearchBase,
    [Alias('Filter')][string]$CliFilter='Windows Server',
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('DirectoryConnection')][ValidateSet('PSDrive','Direct')][string]$CliDirectoryConnection='PSDrive',
    [Alias('OperationTimeoutSeconds')][ValidateRange(1,300)][int]$CliOperationTimeoutSeconds=30,
    [Alias('OutputPath')][string]$CliOutputPath
)
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/ADFile.ps1')

class Collection : ArrayList {
    [void]Export([string]$path) {
        $content=if($this.Count){($this | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine}
        else{'"computer.Name","computer.Status","service.Name","service.DisplayName","service.Status","computer.Message"'}
        $null=Write-ADAnalyzerFile -Path $path -Content $content
    }
    [void]Finding([string]$computer,[bool]$status,[string]$message) {
        $this.Add([pscustomobject][ordered]@{
            'computer.Name'=$computer;'computer.Status'=$status
            'service.Name'=$null;'service.DisplayName'=$null;'service.Status'=$null;'computer.Message'=$message
        }) > $null
    }
    [void]Finding([string]$computer,[string]$service,[string]$name,[string]$status) {
        $this.Finding($computer,$service,$name,$status,$null)
    }
    [void]Finding([string]$computer,[string]$service,[string]$name,[string]$status,[string]$message) {
        $this.Add([pscustomobject][ordered]@{
            'computer.Name'=$computer;'computer.Status'=$true
            'service.Name'=$service;'service.DisplayName'=$name
            'service.Status'=$(if([string]::IsNullOrEmpty($status)){$null}else{$status})
            'computer.Message'=$(if([string]::IsNullOrEmpty($message)){$null}else{$message})
        }) > $null
    }
}

function Get-ADMSSQLServers {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$SearchBase,[string]$Filter='Windows Server',[string]$Server,
        [pscredential]$Credential=[pscredential]::Empty,
        [ValidateSet('PSDrive','Direct')][string]$DirectoryConnection='PSDrive',
        [ValidateRange(1,300)][int]$OperationTimeoutSeconds=30,[string]$OutputPath
    )
    $ErrorActionPreference='Stop'
    $osPattern=[regex]::new($Filter,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach($field in @('SearchBase','Server')){
        if($PSBoundParameters.ContainsKey($field) -and [string]::IsNullOrWhiteSpace([string](Get-Variable $field -ValueOnly))){throw ($field+' cannot be empty.')}
    }
    $repository=Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $bootstrap=@{ErrorAction='Stop'}
    if($Server){$bootstrap.Server=$Server}
    if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$bootstrap.Credential=$Credential}
    $roots=@(Get-ADRootDSE @bootstrap)
    if($roots.Count -ne 1){throw 'RootDSE did not return one directory context.'}
    $pinnedServer=[string]$roots[0].DnsHostName;$domainRoot=[string]$roots[0].DefaultNamingContext
    if([string]::IsNullOrWhiteSpace($pinnedServer) -or [string]::IsNullOrWhiteSpace($domainRoot)){throw 'RootDSE returned an incomplete DC or naming context.'}
    $base=if($SearchBase){$SearchBase}else{$domainRoot}
    $query=@{Filter='Enabled -eq $true';Properties=@('Name','OperatingSystem','DNSHostName');SearchBase=$base;Server=$pinnedServer;ErrorAction='Stop'}
    $drive=$null;$previousLocation=$null;$failure=$null;$computers=@()
    $cleanupErrors=[Collections.Generic.List[object]]::new()
    try{
        if($DirectoryConnection -eq 'PSDrive'){
            $previousLocation=Get-Location
            $driveArguments=@{Name=('ADAnalyzerSql'+[guid]::NewGuid().ToString('N'));PSProvider='ActiveDirectory';Root=$domainRoot;Server=$pinnedServer;Scope='Local';ErrorAction='Stop';WhatIf=$false;Confirm=$false}
            if($bootstrap.ContainsKey('Credential')){$driveArguments.Credential=$Credential}
            $drive=New-PSDrive @driveArguments
            if($null -eq $drive -or $drive.Provider.Name -ne 'ActiveDirectory'){throw 'The owned AD provider drive was not established.'}
            Set-Location -LiteralPath ($drive.Name+':') -ErrorAction Stop
            $location=Get-Location
            if($location.Drive.Name -ne $drive.Name -or $location.Provider.Name -ne 'ActiveDirectory'){throw 'The owned AD drive is not the active directory context.'}
        }elseif($bootstrap.ContainsKey('Credential')){$query.Credential=$Credential}
        $records=@(Get-ADComputer @query)
        $computers=@(foreach($record in $records){
            if($osPattern.IsMatch([string]$record.OperatingSystem)){
                $computerName=[string]$record.Name
                $remoteName=if([string]::IsNullOrWhiteSpace([string]$record.DNSHostName)){$computerName}else{[string]$record.DNSHostName}
                if([string]::IsNullOrWhiteSpace($computerName) -or [string]::IsNullOrWhiteSpace($remoteName)){throw 'A selected server lacks a usable name.'}
                [pscustomobject]@{Name=$computerName;Target=$remoteName;OperatingSystem=[string]$record.OperatingSystem}
            }
        })
        $records=$null
    }catch{$failure=$_}
    finally{
        if($null -ne $drive){
            try{Set-Location -LiteralPath $previousLocation.Path -ErrorAction Stop}catch{$cleanupErrors.Add($_)}
            try{Remove-PSDrive -Name $drive.Name -Scope Local -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false}catch{$cleanupErrors.Add($_)}
        }
    }
    if($null -ne $failure){
        if($cleanupErrors.Count){$failure.Exception.Data['ADAnalyzerCleanupErrors']=@($cleanupErrors | ForEach-Object {$_.Exception.Message})}
        throw $failure
    }
    if($cleanupErrors.Count){
        $errorRecord=$cleanupErrors[0]
        if($cleanupErrors.Count -gt 1){$errorRecord.Exception.Data['ADAnalyzerCleanupErrors']=@($cleanupErrors | Select-Object -Skip 1 | ForEach-Object {$_.Exception.Message})}
        throw $errorRecord
    }
    $result=[Collection]::new()
    foreach($computer in $computers){
        $session=$null;$services=@();$hostFailure=$null;$cleanupFailure=$null
        try{
            $sessionArguments=@{ComputerName=$computer.Target;OperationTimeoutSec=$OperationTimeoutSeconds;ErrorAction='Stop'}
            if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$sessionArguments.Credential=$Credential}
            $session=New-CimSession @sessionArguments
            if($null -eq $session -or $session -is [array]){throw 'A single remote CIM session was not established.'}
            $services=@(Get-CimInstance -CimSession $session -ClassName Win32_Service -Property Name,DisplayName,State -OperationTimeoutSec $OperationTimeoutSeconds -ErrorAction Stop | Where-Object {[string]$_.Name -match 'SQL'})
        }catch{$hostFailure=$_}
        finally{
            if($null -ne $session){try{Remove-CimSession -CimSession $session -ErrorAction Stop}catch{$cleanupFailure=$_}}
        }
        $cleanupMessage=if($null -ne $cleanupFailure){'CIM cleanup: '+$cleanupFailure.Exception.GetType().FullName+': '+$cleanupFailure.Exception.Message}else{$null}
        if($null -ne $hostFailure){
            $message=$hostFailure.Exception.GetType().FullName+': '+$hostFailure.Exception.Message
            if($cleanupMessage){$message+='; '+$cleanupMessage}
            $result.Finding($computer.Name,$false,$message)
        }elseif($services.Count){
            foreach($service in $services){$result.Finding($computer.Name,[string]$service.Name,[string]$service.DisplayName,[string]$service.State,$cleanupMessage)}
        }else{
            $message='No SQL-named services found.'
            if($cleanupMessage){$message+='; '+$cleanupMessage}
            $result.Finding($computer.Name,$true,$message)
        }
    }
    if($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath,'Export SQL service inventory')){$result.Export($OutputPath)}
    return ,$result
}

if($MyInvocation.InvocationName -ne '.'){
    if([string]::IsNullOrWhiteSpace($CliSearchBase) -and [string]::IsNullOrWhiteSpace($CliServer)){throw 'Specify SearchBase or Server for directory discovery.'}
    $arguments=@{Filter=$CliFilter;Credential=$CliCredential;DirectoryConnection=$CliDirectoryConnection;OperationTimeoutSeconds=$CliOperationTimeoutSeconds;WhatIf=[bool]$WhatIfPreference}
    foreach($field in @('SearchBase','Server','OutputPath')){
        if($PSBoundParameters.ContainsKey('Cli'+$field)){$arguments[$field]=Get-Variable ('Cli'+$field) -ValueOnly}
    }
    if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
    Get-ADMSSQLServers @arguments
}
