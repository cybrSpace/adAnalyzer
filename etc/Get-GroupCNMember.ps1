[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('Array')][string[]]$CliArray=@(),
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('OutputPath')][string]$CliOutputPath
)

function Get-GroupCN {
    <# .SYNOPSIS Reads bounded membership inventories for exact CN/SAM selectors. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string[]]$Array=@(),[string]$Server,[pscredential]$Credential=[pscredential]::Empty,[string]$OutputPath)
    $ErrorActionPreference='Stop'
    if(-not $Array.Count){throw 'Specify at least one group selector.'}
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    foreach($item in $Array){
        if([string]::IsNullOrWhiteSpace($item)){throw 'Group selectors must be nonempty strings.'}
        $null=$utf8.GetByteCount($item)
    }
    $repository=Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $connection=@{ErrorAction='Stop'}
    if($Server){$connection.Server=$Server}
    if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$connection.Credential=$Credential}
    $objects=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    function Read-GroupCNObject {
        param([string]$DistinguishedName)
        if([string]::IsNullOrWhiteSpace($DistinguishedName)){throw 'A group member has no distinguished name.'}
        if($objects.ContainsKey($DistinguishedName)){return $objects[$DistinguishedName]}
        $found=@(Get-ADObject -Identity $DistinguishedName -Properties @('SamAccountName','ObjectClass','CN','Member') @connection)
        if($found.Count -ne 1){throw 'A member distinguished name did not resolve to exactly one record.'}
        $record=$found[0];$recordDn=[string]$record.DistinguishedName
        if([string]::IsNullOrWhiteSpace($recordDn) -or [string]::IsNullOrWhiteSpace([string]$record.ObjectClass)){throw 'A member record lacks required identity or class metadata.'}
        $objects[$DistinguishedName]=$record;$objects[$recordDn]=$record
        return $record
    }
    function Get-GroupCNMember {
        param([string]$GroupName,$Group)
        $rootDn=[string]$Group.DistinguishedName
        if([string]::IsNullOrWhiteSpace($rootDn)){throw 'A selected group has no distinguished name.'}
        $visited=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $pending=[Collections.Generic.Queue[object]]::new()
        $null=$visited.Add($rootDn);$pending.Enqueue($Group)
        while($pending.Count){
            $containing=$pending.Dequeue();$containingDn=[string]$containing.DistinguishedName
            $memberDns=@();if($null -ne $containing.Member){$memberDns=@($containing.Member)}
            if(-not $memberDns.Count){
                [pscustomobject][ordered]@{'group.DN'=$containingDn;'group.CN'=$GroupName;'member.SamAccountName'=$null;'member.objectClass'=$null}
                continue
            }
            foreach($memberDn in $memberDns){
                $member=Read-GroupCNObject -DistinguishedName ([string]$memberDn)
                [pscustomobject][ordered]@{'group.DN'=$containingDn;'group.CN'=$GroupName;'member.SamAccountName'=$member.SamAccountName;'member.objectClass'=$member.ObjectClass}
                if(@($member.ObjectClass) -icontains 'group'){
                    $nestedDn=[string]$member.DistinguishedName
                    if($visited.Add($nestedDn)){$pending.Enqueue($member)}
                }
            }
        }
    }
    $rows=@(foreach($item in $Array){
        $escaped=$item.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
        $filter='(|(CN={0})(sAMAccountName={0}))' -f $escaped
        $selected=@(Get-ADGroup -LDAPFilter $filter -Properties @('CN','Member') @connection)
        if(-not $selected.Count){throw ('No group matched selector: '+$item)}
        foreach($group in $selected){Get-GroupCNMember -GroupName $item -Group $group}
    })
    if($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath,'Export group membership inventory')){
        $content=($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
        . (Join-Path $repository 'bin/ADFile.ps1')
        $null=Write-ADAnalyzerFile -Path $OutputPath -Content $content
    }
    return $rows
}

if($MyInvocation.InvocationName -ne '.'){
    $arguments=@{Array=$CliArray;Credential=$CliCredential;WhatIf=[bool]$WhatIfPreference}
    if($CliServer){$arguments.Server=$CliServer}
    if($CliOutputPath){$arguments.OutputPath=$CliOutputPath}
    if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
    Get-GroupCN @arguments
}
