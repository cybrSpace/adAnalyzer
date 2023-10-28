using namespace System.DirectoryServices.AccountManagement

[System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices.AccountManagement') | Out-Null

function Get-ServerHPA () {
    [CmdletBinding()]
    param (
        $computer, $target
    )

    try {


        $c = Get-Credential

        $context = [PrincipalContext]::New([ContextType]::Machine, $computer, $c.UserName, $c.GetNetworkCredential().Password)

        $principal = [GroupPrincipal]::FindByIdentity($context, [IdentityType]::SamAccountName, $target)

    }
    catch {

        throw '{0}({1})' -f 'serverHPA', $_.Exception.Message

    }
    finally {

        $principal.Dispose()

        $context.Dispose()

    }

    return $principal

}

Get-ServerHPA -computer $env:HOSTNAME -target 'Administrators'