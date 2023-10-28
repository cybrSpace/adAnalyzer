$filePath = '{0}.{1}.csv' -f '.\tmp\expport\AD-Servers', (Get-Date -Format 'yyyyMMdd')

$groups = @(

    'Desktop-Support-Z'

)

if (Test-Path -Path $filePath) {

    $filePath = $filePath -replace '.csv', ('.{0}.csv' -f (Get-Date -Format 'yyyyMMdd.HHmm'))
    
}

function Export-ComputerToCSV () {
    param (
        $group, $groupName, $member = $null
    )
    $object = [PSCustomObject]@{
        'group.DN'              = $group
        'group.CN'              = $groupName
        'member.SamAccountName' = $null
        'member.objectClass'    = $null
    } 
    if (-not $null -eq $member) {
        $object['member.SamAccountName'] = $member.samaccountname
        $object['member.objectClass'] = $member.objectclass
    }
    
    $object | Export-Csv -Path $filePath -Append -NoTypeInformation

}
function Get-GroupCNMember () {
    param (
        $groupName, $group
    )
    $members = Get-ADGroup -LDAPFilter ('(|(CN={0})(samaccountname={1}))' -f $item, $item) -pr cn, member | Select-Object -ExpandProperty member 

    if ($members.Count -eq 0) {

        Export-ComputerToCSV -groupName $groupName -group $group.distinguishedname

    }
    else {
        $members | ForEach-Object {

            Get-ADObject -Identity $_ -pr samaccountname, objectclass, cn | ForEach-Object {

                if ($_.objectClass -eq 'group') {

                    Export-ComputerToCSV -groupName $groupName -group $group.distinguishedname -member $_

                    Get-GroupCNMember -groupName $group.cn -group $group.distinguishedname

                }
                else {

                    Export-ComputerToCSV -groupName $item -group $group.distinguishedname -member $_

                }

            }   

        }
    }

}

function Get-GroupCN () {
    param (
        $array
    )

    foreach ($item in $array) {
        
        Get-ADGroup -LDAPFilter ('(|(CN={0})(samaccountname={1}))' -f $item, $item) -pr cn, member | ForEach-Object {

            $group = $_

            if ($group.Member.Count -eq 0) {

                Export-ComputerToCSV -groupName $item -group $group.distinguishedname

            }
            else {

                $group.Member | ForEach-Object {

                    $member = $_

                    Get-ADObject -Identity $member -pr samaccountname, objectclass, cn | ForEach-Object {

                        if ($_.objectClass -eq 'group') {

                            Get-GroupCNMember -groupName $group.cn -group $group.distinguishedname

                        }
                        else {

                            Export-ComputerToCSV -groupName $item -group $group.distinguishedname -member $_

                        }

                    }

                }

            }

        }

    }
}

Get-GroupCN -array $groups