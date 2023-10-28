$var = @{

    'author' = 'Allen Lipa'
    'company' = 'cybrPro'
    'name' = 'ADEnvironmentAnalyzer.psm1'
    'functions' = @('Get-ADEnvironment', 'Set-ADEnvironment')
    'modules' = (
        'ActiveDirectory', @{ModuleName = 'ActiveDirectory'; ModuleVersion = '1.0.0.0'}
    )
    'path' = '.\ADEnvironment.psd1'

}
if ($var['path'] -notmatch 'psd1$') {

    throw 'invalid path. extension must be set as psd1'
    
}
else {

    New-ModuleManifest -Path $var['path'] -Author $var['author'] -CompanyName $var['company'] -RootModule $var['name'] -FunctionsToExport $var['functions'] -requiredModules $var['modules']

}