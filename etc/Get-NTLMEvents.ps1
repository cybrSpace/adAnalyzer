#requires -version 6.1

using namespace System.Collections
using namespace System.Collections.Specialized

$var = @{

    'user'   = [String]'ad\da-alipa'

    'server' = [ArrayList]@(
        'dc1', 
        'dc2'
    )
    'filter' = [Hashtable]@{
        
        'LogName'       = 'Security'
        'Id'            = '4624'
        'StartTime'     = (Get-Date).AddDays(-1)
        'LmPackageName' = 'NTLM V1'

    }

    'export' = [String]('{0}.{1}.csv' -f '.\tmp\NTLMEvents', (Get-Date -f 'yyyy.MM.dd.HHmm'))

}

class Target {

    $Location
    $Filter
    $Collection = [Collection]::New()

    Target([ArrayList]$server, [Hashtable]$filter) {

        $this.Location = $server
        $this.Filter = $filter

    }

    static [Target]Scan([ArrayList]$server, [Hashtable]$filter, [String]$user) {

        $c = (Get-Credential -UserName $user -Message 'Enter password for user: ' -ErrorAction Stop)
        
        $target = [Target]::New([ArrayList]$server, [Hashtable]$filter)

        foreach ($item in $target.Location) {

            # Exclude ANONYMOUS LOGON from results
            # [-] The logic of the NTLM Auditing is that it will log NTLMv2-level authentication when it finds NTLMv2 key material on the logon session
            # [-] It logs NTLMv1 in all other cases, which includes NTLMv1 and LM
            # [-] Therefore, our general recommendation is to ignore the event for security protocol usage information when the event is loggon for ANONYMOUS LOGON
            # [!] https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1

            Get-WinEvent -FilterHashtable $target.Filter -Credential $c -ComputerName $item | Where-Object { $_.Properties[5].Value -ne 'ANONYMOUS LOGON' } | ForEach-Object {

                $object = [Finding]::New($_.TimeCreated.ToString('g'), $item, $_.Properties)

                $target.Collection.Add([PSCustomObject]$object)

            }

        }

        return $target

    }

    [void]Export([String]$value) {

        $this.Collection.Export($value)

    }

    [Collection]Report() {

        return $this.Collection

    }

}
class Finding : OrderedDictionary {

    Finding ([String]$time, [String]$server, $value) : base([StringComparer]::OrdinalIgnoreCase) {

        $this['Server'] = $server
        $this['EventID'] = '4624'
        $this['LogName'] = 'Security'
        $this['Time'] = $time
        $this['UserName'] = $value[5].Value
        $this['WorkstationName'] = $value[11].Value
        $this['LogonType'] = $value[8].Value
        $this['ImpersonationLevel'] = $value[20].Value

        <#
        $this['AuthenticationPackageName'] = $value[9].Value
        $this['LmPackageName'] = $value[10].Value
        $this['KeyLength'] = $value[12].Value
        #> 

    }

}
class Collection : ArrayList {

    Collection() : base() {}

    [void]Export([String]$value) {

        try {

            if (Test-Path -Path $value) {

                Remove-Item -Path $value -Force -ErrorAction Stop

            }

        }
        catch {

            $value = $value -replace $value, ('.{0}.csv') -f (Get-Date -f 'ss')

        }

        try {

            if ($this.Count -gt 0) {

                $this | Export-Csv -Path $value -NoTypeInformation -ErrorAction Stop

            }

        }
        catch {

            throw ('{0}({1})' -f 'export', $_.Exception.Message)

        }

    }

}

try {

    $target = [Target]::Scan($var['server'], $var['filter'], $var['user'])

    $target.Report()

    $target.Export($var['export'])

}
catch {

    throw ('{0}({1})' -f 'error', $_.Exception.Message)


}

