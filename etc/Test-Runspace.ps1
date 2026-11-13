[CmdletBinding()]
param(
    [Alias('context')][string]$CliContext,
    [Alias('principal')][string]$CliPrincipal,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty
)

$constant = @{

    'module'   = 'WindowsServerHPA'
    'HostGroupHelperPath' = (Join-Path $PSScriptRoot 'Get-ServerHPA.ps1')

    'property' = @{
        'skip'  = 3
        'limit' = 3
    }
    'runspace' = @{
        'mode'   = 'multi'
        'global' = @{
            'constant' = 'constant variable table for module'
            'var'      = 'cmdlet runtime variable'
        }
    }
    'target'   = @{
        'range'     = 30
        'filter'    = '^Windows'
        'principal' = 'Administrators'
        'member'    = @{
            'class'     = 'group'
            'exclusion' = @('Domain Admins')
        }
        'record'    = @{
            'exclusion' = @('set')
        }
    }
    'mapping'  = @{
        'legacy' = 'legacy'
        'new'    = 'new'
    }
    'domain'   = @{

        'name' = 'ad'
        'fqdn' = 'ad.cybr.pro'

    }
    'error'    = @{
        'bad.user' = @{
            'msg'   = 'invalid username or password'
            'value' = @(
                'The user name or password is incorrect.'
                'Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed.'
            )
        }
        'bad.host' = @{
            'msg'   = 'unable to connect'
            'value' = @('The network path was not found.')
        }
        'locked'   = @{
            'msg'   = 'account is locked'
            'value' = @('The referenced account is currently locked out and may not be logged on to.')
        }
        'denied'   = @{
            'msg'   = 'access denied'
            'value' = @('Access is denied.')
        }
    }

}

function Connect-WindowsServer {
    [CmdletBinding()]
    param([string]$context,[string]$principal,$domain,[pscredential]$Credential=[pscredential]::Empty)
    $ErrorActionPreference='Stop'
    # Pool workers clone function definitions, so use the absolute configured dependency path.
    $helperPath=[string]$constant['HostGroupHelperPath']
    if([string]::IsNullOrWhiteSpace($helperPath) -or -not [IO.File]::Exists($helperPath)){throw 'Host-group reader dependency is unavailable.'}
    . $helperPath
    Get-ServerHPA -Computer $context -Target $principal -Credential $Credential
}

function Format-WindowsServerException () {
    param (
        [Parameter(Mandatory = $true)]
        $value
    )
    switch ($constant['error'].Keys) { 

        'bad.user' {

            if ($value -match ('({0})' -f ($contains['error'][$_]['value'] -join '|'))) {

                $var['attempt']++

                if ($var['attempt'] -ge $constant['property']['limit']) {

                    throw 'exceeded invalid attempt limit'

                    break

                }
                else {

                    $message = $constant['error'][$_]['msg']

                }

            }

        }
        'locked' {

            if ($value -match ('({0})' -f ($constant['error'][$_]['value'] -join '|'))) {

                $var['attempt']++

                if ($var['attempt'] -ge $constant['property']['limit']) {

                    throw 'exceeded invalid attempt limit'

                    break

                }
                else {

                    $message = $constant['error'][$_]['msg']

                }

            }

        }
        default {

            if ($value -match ('({0})' -f ($constant['error'][$_]['value'] -join '|'))) {

                $message = $constant['error'][$_]['msg']

            }
            
        }

    }

    if ([String]::IsNullOrEmpty($message)) {

        $message = '{0} ({1})' -f 'unknown exception', $value

    }

    return '{0}({1})' -f 'server_exception', $message

}

function Invoke-Cmdlet {
    <# .SYNOPSIS Runs a block once, or retries it up to Max total attempts.
       .DESCRIPTION Retry safety belongs to the caller; this does not impose a deadline on the block. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][scriptblock]$sb,
        [switch]$retry,
        [ValidateRange(1,2147483647)][int]$max=3,
        [ValidateRange(0,300)][int]$DelaySeconds=1
    )
    $ErrorActionPreference='Stop'
    $attempts=if($retry){$max}else{1}
    for($attempt=1;$attempt -le $attempts;$attempt++){
        try{
            $output=@(Invoke-Command -ScriptBlock $sb -ErrorAction Stop)
            return $output
        }catch{
            if($attempt -ge $attempts){throw}
        }
        if($DelaySeconds){Start-Sleep -Seconds $DelaySeconds}
    }
}

function Initialize-RunspacePool {
    <# .SYNOPSIS Returns an unopened pool; the caller owns Open and Dispose. #>
    [CmdletBinding()]
    param([ValidateRange(1,2147483647)][int]$MaxRunspaces=[Environment]::ProcessorCount)
    $ErrorActionPreference='Stop'

    $r = @{}

    $r['jobs'] = [System.Collections.ArrayList]@()
    $r['init'] = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

    foreach ($fn in (Get-ChildItem function:)) {

        $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn.name, $fn.Definition)
        $r['init'].Commands.Add($entry)

    }

    foreach ($i in $constant['runspace']['global'].GetEnumerator() ) {

        $entry = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($i.name, ((Get-Variable -Name $i.name -ErrorAction stop).Value), $i.value)
        $r['init'].Variables.Add($entry)

    }

    $pool=$null
    try {
        $pool=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1,$MaxRunspaces,$r['init'],$host)
        $pool.ThreadOptions=[System.Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
        $pool.CleanupInterval=[timespan]::FromMinutes(2)
        $r['pool']=$pool
    } catch {
        $failure=$_
        if($null -ne $pool){
            try{$pool.Dispose()}catch{$failure.Exception.Data['ADAnalyzerCleanupErrors']=@($_.Exception.GetBaseException().Message)}
        }
        throw $failure
    }


    return $r

}

$var = [hashtable]::Synchronized(@{})
$tbl = [hashtable]::Synchronized(@{})

if($MyInvocation.InvocationName -ne '.'){
    if([string]::IsNullOrWhiteSpace($CliContext) -or [string]::IsNullOrWhiteSpace($CliPrincipal)){throw 'Specify context and principal for an explicit host-group read.'}
    Connect-WindowsServer -context $CliContext -principal $CliPrincipal -Credential $CliCredential
}
