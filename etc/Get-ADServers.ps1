[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('Identity','ComputerName','Servers')][string[]]$CliIdentity=@(),
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('OutputPath')][string]$CliOutputPath
)

function Get-ADServers {
    <# .SYNOPSIS Reads selected computer names and IPv4 addresses using the bundled AD library. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Alias('ComputerName','Servers')][string[]]$Identity=@(),
        [string]$Server,[pscredential]$Credential=[pscredential]::Empty,[string]$OutputPath
    )
    $ErrorActionPreference='Stop'
    if(-not $Identity.Count){throw 'Specify at least one computer identity.'}
    foreach($item in $Identity){if([string]::IsNullOrWhiteSpace($item)){throw 'Computer identities must be nonempty strings.'}}
    $repository=Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $connection=@{Properties=@('IPv4Address');ErrorAction='Stop'}
    if($Server){$connection.Server=$Server}
    if($null -ne $Credential -and $Credential -ne [pscredential]::Empty){$connection.Credential=$Credential}
    $rows=@(foreach($item in $Identity){
        $found=@(Get-ADComputer -Identity $item @connection)
        if($found.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$found[0].Name)){throw 'A computer identity did not resolve to exactly one named record.'}
        [pscustomobject][ordered]@{name=$found[0].Name;ipv4Address=$found[0].IPv4Address}
    })
    if($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath,'Export AD server inventory')){
        $content=($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
        . (Join-Path $repository 'bin/ADFile.ps1')
        $null=Write-ADAnalyzerFile -Path $OutputPath -Content $content
    }
    return $rows
}

if($MyInvocation.InvocationName -ne '.'){
    $arguments=@{Identity=$CliIdentity;Credential=$CliCredential;WhatIf=[bool]$WhatIfPreference}
    if($CliServer){$arguments.Server=$CliServer}
    if($CliOutputPath){$arguments.OutputPath=$CliOutputPath}
    if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
    Get-ADServers @arguments
}
