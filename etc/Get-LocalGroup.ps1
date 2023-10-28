using namespace System.DirectoryServices.AccountManagement

[System.Reflection.Assembly]::LoadFrom('.\Microsoft.ActiveDirectory.Management.dll') | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices.AccountManagement') | Out-Null

function Get-LocalGroupMember {
    [CmdletBinding()]

    param (

        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]$computerName = $env:COMPUTERNAME

    )

    begin {

        $cType = [ContextType]::Machine

    }
    process {

        foreach ($computer in $computerName) {

            $context = [PrincipalContext]::($cType, $computer)
            $idType = [IdentityType]::SamAccountName
            $group = [GroupPrincipal]::FindByIdentity($context, $idType, 'Administrators')
            $group.Members | Select-Object @{n = 'Computer'; e = { $computer } }, @{N = 'Domain'; E = { $_.Context.Name } }, samaccountname 
        
        }

    }

}

Get-LocalGroupMember