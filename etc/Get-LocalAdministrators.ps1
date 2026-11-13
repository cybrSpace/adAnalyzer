[CmdletBinding()]
param([Alias('Invoke')][switch]$CliInvoke)

function Resolve-LocalAdministratorsName {
    $sid=[System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $account=$sid.Translate([System.Security.Principal.NTAccount])
    $name=([string]$account.Value).Split('\')[-1]
    if([string]::IsNullOrWhiteSpace($name)){throw 'Administrators SID did not resolve to a local group name.'}
    return $name
}
function New-LocalAdminDirectoryEntry {
    param([string]$Path)
    return [System.DirectoryServices.DirectoryEntry]::new($Path)
}
function ConvertTo-LocalAdminSidEvidence {
    param($Value)
    if($null -eq $Value){return [pscustomobject]@{SID=$null;SidValid=$null}}
    try{
        $sid=if($Value -is [System.Security.Principal.SecurityIdentifier]){$Value}
        elseif($Value -is [byte[]]){[System.Security.Principal.SecurityIdentifier]::new($Value,0)}
        else{[System.Security.Principal.SecurityIdentifier]::new([string]$Value)}
        [pscustomobject]@{SID=$sid.Value;SidValid=$true}
    }catch{
        $cause=$_.Exception.GetBaseException()
        if($cause -isnot [ArgumentException]){throw}
        [pscustomobject]@{SID=$null;SidValid=$false}
    }
}
function Get-LocalAdministratorGroup {
    [CmdletBinding()]param()
    $ErrorActionPreference='Stop'
    $entry=$null;$failure=$null;$cleanup=$null;$rows=[Collections.Generic.List[object]]::new()
    try{
        $name=Resolve-LocalAdministratorsName
        $entry=New-LocalAdminDirectoryEntry -Path ('WinNT://./'+$name+',group')
        if($null -eq $entry){throw 'Local group binding returned no entry.'}
        foreach($member in $entry.Invoke('Members')){
            $item=[ordered]@{Name=$null;Domain=$null;Class=$null;SID=$null;SidValid=$null;Message=$null}
            $messages=[Collections.Generic.List[string]]::new();$memberPath=$null
            foreach($property in @('Name','AdsPath','Class')){
                try{
                    $value=$member.GetType().InvokeMember($property,[Reflection.BindingFlags]::GetProperty,$null,$member,$null)
                    if($property -eq 'AdsPath'){$memberPath=[string]$value}else{$item[$property]=[string]$value}
                }catch{$messages.Add($property+': '+$_.Exception.GetBaseException().Message)}
            }
            if($memberPath -match '^(?i)WinNT://(.+)$'){
                $parts=$Matches[1].Split('/')
                if($parts.Count -in @(2,3) -and @($parts | Where-Object {[string]::IsNullOrWhiteSpace($_)}).Count -eq 0){$item.Domain=$parts[$parts.Count-2]}
                else{$messages.Add('Unrecognized member WinNT path.')}
            }else{$messages.Add('Member WinNT authority is unavailable.')}
            try{
                $raw=$member.GetType().InvokeMember('Get',[Reflection.BindingFlags]::InvokeMethod,$null,$member,@('objectSID'))
                $evidence=ConvertTo-LocalAdminSidEvidence -Value $raw
                $item.SID=$evidence.SID;$item.SidValid=$evidence.SidValid
            }catch{$messages.Add('SID: '+$_.Exception.GetBaseException().Message)}
            if($messages.Count){$item.Message=$messages -join '; '}
            $rows.Add([pscustomobject]$item)
        }
    }catch{$failure=$_}
    finally{if($null -ne $entry){try{$entry.Dispose()}catch{$cleanup=$_}}}
    if($null -ne $failure){
        if($null -ne $cleanup){$failure.Exception.Data['ADAnalyzerCleanupErrors']=@($cleanup.Exception.GetBaseException().Message)}
        throw $failure
    }
    if($null -ne $cleanup){throw $cleanup}
    return $rows.ToArray()
}
function New-LocalAdminObject {
    param(
        $Domain,$Name,$Class,[string]$MachineName=[Environment]::MachineName,
        [string]$SID,[Nullable[bool]]$SidValid=$null,[Nullable[bool]]$EnabledEvidence=$null,[string]$Message
    )
    $kind='UnknownSID';$local=$false
    if($SidValid -eq $false){$kind='InvalidSID'}
    elseif($SidValid -eq $true){
        if($SID -like 'S-1-12-1-*'){$kind='EntraSID'}
        elseif($SID -like 'S-1-5-32-*'){$kind='BuiltinSID'}
        elseif($SID -like 'S-1-5-21-*'){
            if(-not [string]::IsNullOrWhiteSpace([string]$Domain) -and [string]::Equals([string]$Domain,$MachineName,[StringComparison]::OrdinalIgnoreCase)){$kind='MachineLocal';$local=$Class -in @('User','Group')}
            elseif(-not [string]::IsNullOrWhiteSpace([string]$Domain)){$kind='OtherAuthority'}
            else{$kind='UnresolvedSID'}
        }elseif($SID -in @('S-1-5-18','S-1-5-19','S-1-5-20')){$kind='WellKnownSID'}
        else{$kind='OtherSID'}
    }
    [pscustomobject][ordered]@{
        hostname=$MachineName;memberNetBIOS=$Domain;memberName=$Name;memberClass=$Class
        memberLocal=$local;memberLocalEnabled=$(if($local -and $Class -eq 'User'){$EnabledEvidence}else{$null})
        memberInvalid=$(if($null -eq $SidValid){$null}else{-not $SidValid})
        whenCollected=(Get-Date -Format 'yyyy/MM/dd HH:mm:ss')
        memberSID=$(if($SidValid -eq $true){$SID}else{$null});memberResolutionKind=$kind
        memberMessage=$(if($Message){$Message}else{$null})
    }
}
function Get-LocalAdministrators {
    [CmdletBinding()]param()
    $ErrorActionPreference='Stop'
    $machine=[Environment]::MachineName
    $members=@(Get-LocalAdministratorGroup)
    $rows=@(foreach($member in $members){
        $row=New-LocalAdminObject -Domain $member.Domain -Name $member.Name -Class $member.Class -MachineName $machine -SID $member.SID -SidValid $member.SidValid -Message $member.Message
        if($row.memberLocal -and $row.memberClass -eq 'User'){
            try{
                $users=@(Get-LocalUser -SID $row.memberSID -ErrorAction Stop)
                if($users.Count -ne 1){throw 'Local user SID did not resolve to exactly one account.'}
                $evidence=ConvertTo-LocalAdminSidEvidence -Value $users[0].SID
                if($evidence.SidValid -ne $true -or -not [string]::Equals($evidence.SID,$row.memberSID,[StringComparison]::OrdinalIgnoreCase) -or $users[0].Enabled -isnot [bool]){throw 'Local user enabled evidence does not match the exact SID.'}
                $row.memberLocalEnabled=$users[0].Enabled
            }catch{
                $message='Enabled: '+$_.Exception.GetBaseException().Message
                $row.memberMessage=if($row.memberMessage){$row.memberMessage+'; '+$message}else{$message}
            }
        }
        $row
    })
    return $rows
}
if($MyInvocation.InvocationName -ne '.'){
    if(-not $CliInvoke){throw 'Specify -Invoke to collect local Administrators.'}
    Get-LocalAdministrators
}
