[CmdletBinding()]
param(
    [Alias('ComputerName','Computer')][string[]]$CliTargetComputer=@(),
    [Alias('Credential')][pscredential]$CliTargetCredential=[pscredential]::Empty
)

function Get-ComputerAdministratorName {
    <# .SYNOPSIS Returns detached direct local Administrators member names using SID544. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$ComputerName,
        [pscredential]$Credential=[pscredential]::Empty
    )
    $ErrorActionPreference='Stop'
    $helper=Join-Path $PSScriptRoot 'Get-LocalGroup.ps1'
    & {
        param($MemberHelper,$Targets,$Login)
        . $MemberHelper
        $rows=@(Get-LocalGroupMember -ComputerName $Targets -Credential $Login -IncludeName)
        foreach($row in $rows){$row.Name}
    } $helper $ComputerName $Credential
}

if($MyInvocation.InvocationName -ne '.'){
    if(-not $PSBoundParameters.ContainsKey('CliTargetComputer') -or -not $CliTargetComputer.Count){throw 'CLI execution requires explicit ComputerName inputs.'}
    Get-ComputerAdministratorName -ComputerName $CliTargetComputer -Credential $CliTargetCredential
}
