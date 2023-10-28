$constant = @{

    'module'   = 'WindowsServerHPA'

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

$constant['domain']['context'] = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
    [System.DirectoryServices.AccountManagement.ContextType]::Domain, $constant['domain']['fqdn']
)

function Connect-WindowsServer () {

    param (

        $context, $principal, $domain

    )

    try {

        $r = @{}

        $r['context'] = New-System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Machine, $context
        )

        $r['principal'] = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(
            $r['context'], [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $principal
        )

        if ($null -eq $r['principal'].Members -or [String]::IsNullOrEmpty($r['principal'].Members.Count)) {

            $r['principal'] = New-Object System.DirectoryServices.DirectoryEntry(($r['principal'].GetUnderlyingObject()).Path)

        }

    }
    catch {

        throw $_.Exception.Message

    }

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

function Invoke-Cmdlet () {

    [CmdletBinding(DefaultParameterSetName = 'Target')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Invoke')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Retry')]
        [scriptblock]$sb,

        [Parameter(ParameterSetName = 'Retry')]
        [switch]$retry,
        [Parameter(Mandatory = $true, ParameterSetName = 'Retry')]
        [int]$max = 0
    )
    function Set-RetryDelay () {

        param (

            [alias('attempt')]
            $a = 0,
            [alias('previousDelay')]
            $pd = 0

        )

        return [math]::Ceiling((Get-Random -Minimum $pd -Maximum ((1 / 2) * ([math]::Pow(2, $a) - 1))))

    }

    $attempt = 0
    $pDelay = 0
    $return = $null

    do {

        ++$attempt
            
        try {
            $return = Invoke-Command -ScriptBlock $sb
            $exit = $true
        } 
        catch {

            if ($retry) {

                $exit = $false
                $pDelay = Set-RetryDelay -attempt $attempt -previousDelay $pDelay
                Start-Sleep

            }
            else {

                $exit = $true

            }

        }

    } until ($exit -eq $true -or $attempt -eq $max)

    if ($attempt -eq $max) {

        throw 'invoke_cmdlet_failed...({})' -f $error[0].Exception.Message

    }
    else {

        return $return

    }

}
function Initialize-RunspacePool () {

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

    #$r['pool'] = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $constant['runspace']['threads'], $r['init'], $host)
    #$r['pool'].ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread

    $r['pool'] = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS, $r['init'], $host)
    $r['pool'].ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
    $r['pool'].CleanupInterval = 2 * [timespan]::TicksPerMinute


    return $r

}

$var = [hashtable]::Synchronized(@{})
$tbl = [hashtable]::Synchronized(@{})

$srv = [ordered]@{
    'name' = 'srv1'
}
$tbl[$srv['name']] = $srv
Connect-WindowsServer -context $srv['name'] -principal $constant['target']['principal'] -domain $constant['domain']['context']