using namespace System.DirectoryServices.AccountManagement
[CmdletBinding()]
param(
    [Alias('Computer','ComputerName')][string]$CliComputer,
    [Alias('Target')][string]$CliTarget,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty
)

function Get-ServerHPA {
    <# .SYNOPSIS Returns detached metadata for a selected host group without retaining principal resources. #>
    [CmdletBinding()]
    param(
        [Alias('ComputerName')][string]$Computer,[string]$Target,
        [pscredential]$Credential=[pscredential]::Empty
    )
    if([string]::IsNullOrWhiteSpace($Computer) -or [string]::IsNullOrWhiteSpace($Target)){throw 'Specify a computer and group target.'}
    $context=$null;$principal=$null;$snapshot=$null;$failure=$null
    $cleanupErrors=[Collections.Generic.List[object]]::new()
    try{
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){
            $context=[System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Machine,$Computer,$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }else{
            $context=[System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Machine,$Computer)
        }
        $principal=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$Target)
        if($null -eq $principal){throw 'The requested host group was not found.'}
        $metadata=@{};$principalType=$principal.GetType()
        foreach($name in @('Name','SamAccountName','Sid','Description')){
            $property=$principalType.GetProperty($name)
            if($null -eq $property){throw 'A required host group metadata getter is unavailable.'}
            $metadata[$name]=$property.GetValue($principal,$null)
        }
        $sid=$metadata.Sid
        $snapshot=[pscustomobject][ordered]@{
            Computer=$Computer;Name=$metadata.Name;SamAccountName=$metadata.SamAccountName
            SID=if($null -ne $sid){[string]$sid.Value}else{$null}
            Description=$metadata.Description
        }
    }catch{$failure=$_}
    finally{
        if($null -ne $principal){try{$principal.Dispose()}catch{$cleanupErrors.Add($_)}}
        if($null -ne $context){try{$context.Dispose()}catch{$cleanupErrors.Add($_)}}
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
    return $snapshot
}

if($MyInvocation.InvocationName -ne '.'){
    Get-ServerHPA -Computer $CliComputer -Target $CliTarget -Credential $CliCredential
}
