param([string]$RepositoryRoot,[string]$WorkingDirectory,[string]$Mode)
$ErrorActionPreference='Stop'
$null=[IO.Directory]::CreateDirectory((Join-Path $WorkingDirectory 'tmp/expport'))
$global:ADAnalyzerServerFixture=@{Imports=[Collections.Generic.List[object]]::new();Queries=[Collections.Generic.List[object]]::new();Failure='';Bad='bad'}
function Assert-Server($Value,[string]$Message){if(-not $Value){throw $Message}}
function Import-Module {
    [CmdletBinding()]param($Name,$Scope)
    $expected=Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
    Assert-Server ([IO.Path]::GetFullPath($Name) -eq [IO.Path]::GetFullPath($expected)) 'An external AD module was requested'
    Assert-Server ($Scope -eq 'Local' -and $PSBoundParameters.ErrorAction -eq 'Stop') 'Import scope/error contract changed'
    $global:ADAnalyzerServerFixture.Imports.Add($Name)
}
function Get-ADComputer {
    [CmdletBinding()]param([Parameter(Position=0)]$Identity,[Alias('pr')]$Properties,$Server,[pscredential]$Credential)
    $copy=@{};foreach($key in $PSBoundParameters.Keys){$copy[$key]=$PSBoundParameters[$key]}
    $global:ADAnalyzerServerFixture.Queries.Add([pscustomobject]$copy)
    if($Identity -eq $global:ADAnalyzerServerFixture.Bad){
        switch($global:ADAnalyzerServerFixture.Failure){
            'Throw' {throw 'fixture lookup failure'}
            'WriteError' {Write-Error 'fixture nonterminating lookup failure';return}
            'Missing' {return}
            'Multiple' {[pscustomobject]@{Name='one'};[pscustomobject]@{Name='two'};return}
        }
    }
    $name=if($Identity -eq 'unicode'){'srv '+[char]0x00FC+', "quoted"'}else{[string]$Identity}
    if($Identity -eq 'no-address'){return [pscustomobject]@{Name=$name}}
    [pscustomobject]@{Name=$name;IPv4Address='192.0.2.10'}
}
$scriptPath=Join-Path $RepositoryRoot 'etc/Get-ADServers.ps1'
$location=(Get-Location).Path
try{
    Set-Location -LiteralPath $WorkingDirectory
    $servers=@('caller-server');$Server='caller-dc';$OutputPath='caller-output'
    . $scriptPath
    if($Mode -eq 'Inert'){
        Assert-Server ($global:ADAnalyzerServerFixture.Imports.Count -eq 0 -and $global:ADAnalyzerServerFixture.Queries.Count -eq 0) 'Dot sourcing performed directory work'
        Assert-Server ($servers.Count -eq 1 -and $servers[0] -eq 'caller-server' -and $Server -eq 'caller-dc' -and $OutputPath -eq 'caller-output') 'Dot sourcing changed caller inputs'
        Assert-Server (@(Get-ChildItem -LiteralPath $WorkingDirectory -Recurse -File).Count -eq 0) 'Dot sourcing wrote a file'
    }elseif($Mode -eq 'Validation'){
        foreach($identities in @(@(),@(''),@('first',' '))){
            $caught=$false;try{$null=Get-ADServers -Identity $identities}catch{$caught=$true}
            Assert-Server $caught 'Invalid selectors were accepted'
        }
        Assert-Server ($global:ADAnalyzerServerFixture.Imports.Count -eq 0 -and $global:ADAnalyzerServerFixture.Queries.Count -eq 0) 'Validation happened after effects'
    }elseif($Mode -eq 'Rows'){
        $rows=@(Get-ADServers -Identity @('second','first','second','no-address'))
        Assert-Server ($rows.Count -eq 4 -and ($rows.name -join ',') -eq 'second,first,second,no-address') 'Input order/duplicates changed'
        Assert-Server ($null -eq $rows[3].ipv4Address) 'Missing address became a query failure or fabricated value'
        Assert-Server ($global:ADAnalyzerServerFixture.Imports.Count -eq 1) 'Bundled import was not scoped to the inventory call'
        foreach($call in $global:ADAnalyzerServerFixture.Queries){
            Assert-Server (($call.Properties -join ',') -eq 'IPv4Address' -and $call.ErrorAction -eq 'Stop') 'Lookup projection/error contract changed'
            Assert-Server (-not $call.PSObject.Properties['Credential'] -and -not $call.PSObject.Properties['Server']) 'Default connection values were explicitly rebound'
        }
    }elseif($Mode -eq 'Credentials'){
        $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $null=Get-ADServers -Identity first -Credential ([pscredential]::Empty)
        $null=Get-ADServers -Identity first -Credential $null
        $null=Get-ADServers -Identity first -Credential $credential -Server dc.fixture.invalid
        $calls=$global:ADAnalyzerServerFixture.Queries
        Assert-Server (-not $calls[0].PSObject.Properties['Credential'] -and -not $calls[1].PSObject.Properties['Credential']) 'Empty credential was bound'
        Assert-Server ([object]::ReferenceEquals($calls[2].Credential,$credential) -and $calls[2].Server -eq 'dc.fixture.invalid') 'Explicit connection identity changed'
    }elseif($Mode -eq 'Csv'){
        $path=Join-Path $WorkingDirectory 'folder[1]/servers[2].csv'
        $rows=@(Get-ADServers -Identity @('unicode','no-address') -OutputPath $path)
        $csv=@(Import-Csv -LiteralPath $path)
        Assert-Server ($rows.Count -eq 2 -and $csv.Count -eq 2) 'Populated inventory was not exported'
        Assert-Server (($csv[0].PSObject.Properties.Name -join ',') -ceq 'name,ipv4Address') 'CSV columns changed'
        Assert-Server ($csv[0].name -ceq $rows[0].name -and $csv[0].ipv4Address -eq '192.0.2.10' -and [string]$csv[1].ipv4Address -eq '') 'CSV values changed'
    }elseif($Mode -eq 'QueryFailures'){
        $path=Join-Path $WorkingDirectory 'previous.csv';[IO.File]::WriteAllText($path,'previous report')
        foreach($failure in @('Throw','WriteError','Missing','Multiple')){
            $global:ADAnalyzerServerFixture.Failure=$failure;$emitted=[Collections.Generic.List[object]]::new();$caught=$false
            try{Get-ADServers -Identity @('first','bad') -OutputPath $path | ForEach-Object {$emitted.Add($_)}}catch{$caught=$true}
            Assert-Server ($caught -and $emitted.Count -eq 0 -and [IO.File]::ReadAllText($path) -eq 'previous report') 'Failed lookup emitted partial data or replaced prior output'
        }
    }elseif($Mode -eq 'ExportFailures'){
        $path=Join-Path $WorkingDirectory 'previous.csv';[IO.File]::WriteAllText($path,'previous report')
        function ConvertTo-Csv {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[switch]$NoTypeInformation) process{throw 'fixture conversion failure'}}
        $caught=$false;try{Get-ADServers -Identity first -OutputPath $path | Out-Null}catch{$caught=$true}
        Assert-Server ($caught -and [IO.File]::ReadAllText($path) -eq 'previous report') 'Conversion failure replaced prior output'
        Remove-Item Function:ConvertTo-Csv
        $directory=Join-Path $WorkingDirectory 'directory-destination';$null=[IO.Directory]::CreateDirectory($directory)
        $sentinel=Join-Path $directory 'sentinel';[IO.File]::WriteAllText($sentinel,'preserve')
        $caught=$false;try{Get-ADServers -Identity first -OutputPath $directory | Out-Null}catch{$caught=$true}
        Assert-Server ($caught -and [IO.File]::ReadAllText($sentinel) -eq 'preserve') 'Write failure lost existing data'
    }elseif($Mode -eq 'WhatIf'){
        $directory=Join-Path $WorkingDirectory 'preview';$rows=@(Get-ADServers -Identity first -OutputPath (Join-Path $directory 'servers.csv') -WhatIf)
        Assert-Server ($rows.Count -eq 1 -and -not (Test-Path -LiteralPath $directory)) 'WhatIf lost data or wrote output'
    }elseif($Mode -eq 'Cli'){
        $caught=$false;try{& $scriptPath | Out-Null}catch{$caught=$true}
        Assert-Server ($caught -and $global:ADAnalyzerServerFixture.Queries.Count -eq 0) 'Missing CLI input performed discovery'
        $path=Join-Path $WorkingDirectory 'cli.csv';$rows=@(& $scriptPath -Identity first -Server dc.fixture.invalid -OutputPath $path -Confirm:$false)
        Assert-Server ($rows.Count -eq 1 -and @(Import-Csv -LiteralPath $path).Count -eq 1) 'Explicit CLI did not export inventory'
    }else{throw 'Unknown fixture mode'}
    'PASS standalone AD server inventory '+$Mode
}finally{Set-Location -LiteralPath $location}
