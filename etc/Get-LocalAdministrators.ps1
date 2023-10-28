using namespace System.Collections
using namespace System.Collections.Specialized
function Get-LocalAdministratorGroup {

    $group = [ADSI]'WinNT://./administrators,group'

    $members = [ArrayList]@()

    $group.Invoke('Members') | ForEach-Object {
        
        $object = [ordered]@{
            'Name'   = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $($_), $null)
            'Domain' = $_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $($_), $null).Replace('WinNT://', '').Split('/')[0]
            'Class'  = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $($_), $null)
        }

        $members.Add([PSCustomObject]$object) > $null

    }

    return $members

}
function New-LocalAdminObject () {

    param ($domain, $name, $class ) 

    $object = [PSCustomObject]@{
        'hostname'           = [System.Net.DNS]::GetHostName()
        'memberNetBIOS'      = $domain
        'memberName'         = $name
        'memberClass'        = $class
        'memberLocal'        = $false
        'memberLocalEnabled' = $false
        'memberInvalid'      = $false
        'whenCollected'      = (Get-Date -f 'yyyy/MM/dd HH:mm:ss')
    }
    
    if ($name -match '^S-1-12-1') {

        $object.memberInvalid = $true

    }
    elseif ($class -eq 'Group' -or $domain -in @('NT Authority')) {

        $object.memberLocal = $true

    }
    elseif ($class -eq 'User' -and $domain -match $env:USERDOMAIN) {

        $object.memberLocal = $true

        try {

            $user = Get-LocalUser -Name $name -ErrorAction Stop

        }
        catch {

            $user = $null

        }

        if ($null -ne $user) {

            $object.memberLocalEnabled = $user.Enabled 

        }

    }

    return $object

}


try { 

    $members = Get-LocalAdministratorGroup

}
catch {

    $members = @()

}

$array = [ArrayList]@()

foreach ($member in $members) {

    $object = New-LocalAdminObject -domain $member.Domain -name $member.Name -class $member.Class
        
    $array.Add($object) > $null

}

$array | Format-Table -AutoSize
