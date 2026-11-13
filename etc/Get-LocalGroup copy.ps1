using namespace System.DirectoryServices.AccountManagement
[CmdletBinding()]
param(
    [Alias('ComputerName','Computer')][string[]]$CliComputerName=@(),
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty
)

function Get-LocalGroupMember {
    <# .SYNOPSIS Returns detached direct local Administrators membership. #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('Computer')][string[]]$ComputerName=$env:COMPUTERNAME,
        [pscredential]$Credential=[pscredential]::Empty
    )
    begin {
        $frameworkLoaded=$false
        $getEnumerator=[Collections.IEnumerable].GetMethod('GetEnumerator')
        $moveNext=[Collections.IEnumerator].GetMethod('MoveNext')
        $current=[Collections.IEnumerator].GetProperty('Current')
        $dispose=[IDisposable].GetMethod('Dispose')
    }
    process {
        if(-not $ComputerName.Count){throw 'Specify at least one computer.'}
        foreach($computer in $ComputerName){if([string]::IsNullOrWhiteSpace($computer)){throw 'Computer names must be nonempty strings.'}}
        if(-not $frameworkLoaded){Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop;$frameworkLoaded=$true}
        foreach($computer in $ComputerName){
            $context=$null;$group=$null;$result=$null;$enumerator=$null;$failure=$null
            $rows=[Collections.Generic.List[object]]::new();$cleanupErrors=[Collections.Generic.List[object]]::new()
            try{
                if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){
                    $context=[System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Machine,$computer,$Credential.UserName,$Credential.GetNetworkCredential().Password)
                }else{
                    $context=[System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Machine,$computer)
                }
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context,[System.DirectoryServices.AccountManagement.IdentityType]::Sid,'S-1-5-32-544')
                if($null -eq $group){throw 'The local Administrators group was not found.'}
                $result=$group.GetMembers($false)
                if($null -eq $result){throw 'The group membership result is unavailable.'}
                $enumerator=$getEnumerator.Invoke($result,$null)
                if($null -eq $enumerator){throw 'The group membership enumerator is unavailable.'}
                while([bool]$moveNext.Invoke($enumerator,$null)){
                    $member=$null
                    try{
                        $member=$current.GetValue($enumerator,$null)
                        if($null -eq $member){throw 'A group membership record is unavailable.'}
                        $memberType=$member.GetType();$contextProperty=$memberType.GetProperty('Context');$samProperty=$memberType.GetProperty('SamAccountName')
                        if($null -eq $contextProperty -or $null -eq $samProperty){throw 'A required member metadata getter is unavailable.'}
                        $memberContext=$contextProperty.GetValue($member,$null);$domain=$null
                        if($null -ne $memberContext){
                            $nameProperty=$memberContext.GetType().GetProperty('Name')
                            if($null -eq $nameProperty){throw 'The member context name getter is unavailable.'}
                            $domain=$nameProperty.GetValue($memberContext,$null)
                        }
                        $sam=$samProperty.GetValue($member,$null)
                        $rows.Add([pscustomobject][ordered]@{Computer=$computer;Domain=$domain;samaccountname=$sam})
                    }finally{
                        if($null -ne $member){try{$null=$dispose.Invoke($member,$null)}catch{$cleanupErrors.Add($_)}}
                    }
                    if($cleanupErrors.Count){break}
                }
            }catch{$failure=$_}
            finally{
                if($enumerator -is [IDisposable]){try{$null=$dispose.Invoke($enumerator,$null)}catch{$cleanupErrors.Add($_)}}
                foreach($resource in @($result,$group,$context)){
                    if($null -ne $resource){try{$null=$dispose.Invoke($resource,$null)}catch{$cleanupErrors.Add($_)}}
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
            $rows
        }
    }
}

if($MyInvocation.InvocationName -ne '.'){
    if(-not $PSBoundParameters.ContainsKey('CliComputerName') -or -not $CliComputerName.Count){throw 'CLI execution requires explicit ComputerName inputs.'}
    Get-LocalGroupMember -ComputerName $CliComputerName -Credential $CliCredential
}
