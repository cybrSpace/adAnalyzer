using namespace System.Collections

$var = @{

    'filter'     = 'Windows Servers'

    'searchBase' = 'OU=Servers,DC=AD,DC=Cybr,DC=Pro'

    'path'       = ('{0}\{1}.{2}.csv') -f '.\tmp\export', 'msSQLServers', (Get-Date -Format 'yyyyMMdd.HHmm')

}

class Collection : ArrayList {

    Export([String]$path) {

        if ($this.count -eq 0) {

            throw 'collection is empty'

        }
        else {

            $this | Export-Csv -Path $path -NoTypeInformation

        }

    }

    Finding([String]$computer, [Boolean]$status, [String]$message) {

        $object = [ordered]@{

            'computer.Name'       = $computer
            'computer.Status'     = $false
            'service.Name'        = $null
            'service.DisplayName' = $null
            'service.Status'      = $null
            'computer.Message'    = $null

        }

        $this.Add([PSCustomObject]$object) > $null

    }
    Finding([String]$computer, [String]$service, [String]$name, [Boolean]$status) {

        $object = [ordered]@{

            'computer.Name'       = $computer
            'computer.Status'     = $true
            'service.Name'        = $service
            'service.DisplayName' = $name
            'service.Status'      = $status
            'computer.Message'    = $null

        }

        $this.Add([PSCustomObject]$object) > $null

    }

}
function Get-ADMSSQLServers () {

    param (

        [String]$searchBase,
        [String]$filter

    )

    $result = [Collection]::New()

    try {

        $servers = Get-ADComputer -Filter { enabled -eq $true } -Properties OperatingSystem -SearchBase $searchBase | Where-Object { $_.OperatingSystem -match $filter }

    }
    catch {

        $servers = $null

    }

    foreach ($server in $servers) {

        try {

            $services = Get-Service -ComputerName $server.Name | Where-Object { $_.Name -match 'SQL' }

            $services | ForEach-Object { $result.Finding( $server.name, $_.Name, $_.DisplayName, $_.Status) }

        }
        catch {

            $message = ('error({0})' -f $_.Exception.Message)

            $result.Finding($server.Name, $false, $message)

        }

    }

    return $result

}

try {

    $result = Get-ADMSSQLServers -searchBase $var['searchBase'] -filter $var['filter']

    $result | Format-Table -AutoSize

    $result.Export($var['path'])

}
catch {

    throw ('uncaughtException({0})' -f $_.Exception.Message)

}
