$filePath = '{0}.{1}.csv' -f '.\tmp\expport\AD-Servers', (Get-Date -Format 'yyyyMMdd')

$servers = @(

    'srv1'

)

if (Test-Path -Path $filePath) {

    $filePath = $filePath -replace '.csv', ('.{0}.csv' -f (Get-Date -Format 'yyyyMMdd.HHmm'))

}

$results = [System.Collections.ArrayList]::new()

foreach ($item in $servers) {

    try {

        $object = Get-ADComputer $item -pr ipv4Address | Select-Object name, ipv4Address

        $results.Add($object) > $null

    } 
    catch { }

}

$resuls | Export-Csv -Path $filePath -NoTypeInformation
