$var = @{

    'path' = '\\<path>\<to>\<gpo>\<xml>'
    'name' = '<GPO name>'
    'type' = 'xml'
    

}

$var['export'] = ('{0}\{1}.{2}.{3}') -f $var['path'], $var['name'].Replace(' ',''), (Get-Date -f 'yyyyMMdd.HHmm'), $var['type']

try {

    if (Test-Path -Path $var['export']) {

        Remove-Item -Path $var['export'] -ErrorAction Stop

    }
    
}
catch {

    $var['export'] = $var['export'] -replace $var['export'], ('.{0}.{1}') -f (Get-Date -f 'yyyy.MM.dd.HHmm'), $var['type']

}
finally {

   Get-GPOReport -Name $var['name'] -ReportType $var['type'] -Path $var['export'] -ErrorAction Stop
   Invoke-Item -Path $var['export']

}