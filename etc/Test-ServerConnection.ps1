$ports = (445)

$servers = @('srv1')

$filePath = '{0}.{1}.csv' -f '.\tmp\expport\AD-Servers', (Get-Date -Format 'yyyyMMdd')

$servers = @(

    'srv1'

)

if (Test-Path -Path $filePath) {

    $filePath = $filePath -replace '.csv', ('.{0}.csv' -f (Get-Date -Format 'yyyyMMdd.HHmm'))

}

$results = [System.Collections.ArrayList]::new()

foreach ($name in $servers) {

    $ports | ForEach-Object {

        try {

            $r = Test-NetConnection -ComputerName $name -Port $_ -WarningAction SilentlyContinue -InformationLevel Detailed | Select-Object ComputerName, RemoteAddress, RemotePort, TcpTestSucceeded

        }
        catch { $r = $null }
        
        
        if ($null -ne $r) {

            $object = [ordered]@{
                'ComputerName'  = $name
                'RemoteAddress' = $r.RemoteAddress
                'RemotePort'    = $_
                'tcpTest'       = $r.TcpTestSucceeded
                'result'        = $true
            }

        }
        else {

            $object = [ordered]@{
                'ComputerName'  = $name
                'RemoteAddress' = $null
                'RemotePort'    = $_
                'tcpTest'       = $null
                'result'        = $false
            }

        }

        $results.Add($object) > $null

    }

}

$results | Export-Csv -Path $filePath -NoTypeInformation

$results | Format-Table -AutoSize