param([string]$RepositoryRoot,[string]$WorkingDirectory,[string]$Mode)
$ErrorActionPreference='Stop';$null=[IO.Directory]::CreateDirectory((Join-Path $WorkingDirectory 'tmp/expport'))
$global:ADAnalyzerGroupFixture=@{Imports=[Collections.Generic.List[object]]::new();Calls=[Collections.Generic.List[object]]::new();Fault='';Bad='CN=Computer,DC=fixture,DC=invalid'}
function Assert-Group($Value,[string]$Message){if(-not $Value){throw $Message}}
$global:ADAnalyzerGroupObjects=@{}
foreach($spec in @(
    @{Name='RootA';Class='group';Members=@('Child','User')},@{Name='RootB';Class='group';Members=@('Child','Empty')},
    @{Name='Child';Class='group';Members=@('RootA','Computer')},@{Name='Empty';Class='group';Members=@()},
    @{Name='User';Class='user';Members=@()},@{Name='Computer';Class='computer';Members=@()}
)){
    $dn='CN='+$spec.Name+',DC=fixture,DC=invalid'
    $sam=if($spec.Name -eq 'User'){'user '+[char]0x00FC+', "quoted"'}else{$spec.Name}
    $global:ADAnalyzerGroupObjects[$dn]=[pscustomobject]@{DistinguishedName=$dn;CN=$spec.Name;SamAccountName=$sam;ObjectClass=$spec.Class;Member=@($spec.Members | ForEach-Object {'CN='+$_+',DC=fixture,DC=invalid'})}
}
function Import-Module {
    [CmdletBinding()]param($Name,$Scope)
    Assert-Group ([IO.Path]::GetFullPath($Name) -eq [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll')) -and $Scope -eq 'Local' -and $PSBoundParameters.ErrorAction -eq 'Stop') 'External or unscoped AD import'
    $global:ADAnalyzerGroupFixture.Imports.Add($Name)
}
function ConvertTo-FixtureFilter([string]$Value){$Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')}
function Get-ADGroup {
    [CmdletBinding()]param($LDAPFilter,$Identity,[Alias('pr')]$Properties,$Server,[pscredential]$Credential)
    $copy=@{};foreach($key in $PSBoundParameters.Keys){$copy[$key]=$PSBoundParameters[$key]};$copy.Command='Group';$global:ADAnalyzerGroupFixture.Calls.Add([pscustomobject]$copy)
    if($global:ADAnalyzerGroupFixture.Calls.Count -gt 40){throw 'Fixture query bound exceeded'}
    if($Identity){return $global:ADAnalyzerGroupObjects[[string]$Identity]}
    $special='a*(b)\'+[char]0
    foreach($selector in @('RootA','RootB','Empty','Both',$special,'Missing')){
        $escaped=ConvertTo-FixtureFilter $selector
        if($LDAPFilter -ieq ('(|(CN='+$escaped+')(samaccountname='+$escaped+'))')){
            if($selector -eq 'Both'){$global:ADAnalyzerGroupObjects['CN=RootA,DC=fixture,DC=invalid'];$global:ADAnalyzerGroupObjects['CN=Empty,DC=fixture,DC=invalid'];return}
            if($selector -eq 'Missing'){return}
            $name=if($selector -eq $special){'Empty'}else{$selector}
            return $global:ADAnalyzerGroupObjects['CN='+$name+',DC=fixture,DC=invalid']
        }
    }
    if($LDAPFilter -match 'Desktop-Support-Z'){return}
    throw 'Unexpected or unescaped LDAP selector'
}
function Get-ADObject {
    [CmdletBinding()]param($Identity,[Alias('pr')]$Properties,$Server,[pscredential]$Credential)
    $copy=@{};foreach($key in $PSBoundParameters.Keys){$copy[$key]=$PSBoundParameters[$key]};$copy.Command='Object';$global:ADAnalyzerGroupFixture.Calls.Add([pscustomobject]$copy)
    if($global:ADAnalyzerGroupFixture.Calls.Count -gt 40){throw 'Fixture query bound exceeded'}
    if($Identity -eq $global:ADAnalyzerGroupFixture.Bad){switch($global:ADAnalyzerGroupFixture.Fault){'Throw'{throw 'fixture member lookup failure'};'WriteError'{Write-Error 'fixture member read failure';return};'Missing'{return};'Multiple'{$global:ADAnalyzerGroupObjects[$Identity];$global:ADAnalyzerGroupObjects[$Identity];return}}}
    $global:ADAnalyzerGroupObjects[[string]$Identity]
}
$path=Join-Path $RepositoryRoot 'etc/Get-GroupCNMember.ps1';$location=(Get-Location).Path
try{
    Set-Location -LiteralPath $WorkingDirectory
    $groups=@('caller-group');$Server='caller-server';$OutputPath='caller-output'
    . $path
    if($Mode -eq 'Inert'){
        Assert-Group ($global:ADAnalyzerGroupFixture.Imports.Count -eq 0 -and $global:ADAnalyzerGroupFixture.Calls.Count -eq 0 -and $groups[0] -eq 'caller-group' -and $Server -eq 'caller-server' -and $OutputPath -eq 'caller-output') 'Dot source performed work or changed caller state'
        Assert-Group (@(Get-ChildItem -LiteralPath $WorkingDirectory -Recurse -File).Count -eq 0) 'Dot source wrote output'
    }elseif($Mode -eq 'Traversal'){
        $rows=@(Get-GroupCN -Array RootA)
        Assert-Group ($rows.Count -eq 4 -and @($rows | Where-Object {$_.'group.CN' -ne 'RootA'}).Count -eq 0) 'Root labels or direct edges changed'
        Assert-Group (@($rows | Where-Object {$_.'group.DN' -eq 'CN=Child,DC=fixture,DC=invalid' -and $_.'member.SamAccountName' -eq 'RootA' -and $_.'member.objectClass' -eq 'group'}).Count -eq 1) 'Cycle edge was lost'
        Assert-Group ($global:ADAnalyzerGroupFixture.Calls.Count -le 10) 'Traversal was not bounded by visited groups'
    }elseif($Mode -eq 'SharedRoots'){
        $rows=@(Get-GroupCN -Array @('RootA','RootB'))
        Assert-Group ($rows.Count -eq 11 -and @($rows | Where-Object {$_.'group.CN' -eq 'RootA'}).Count -eq 4 -and @($rows | Where-Object {$_.'group.CN' -eq 'RootB'}).Count -eq 7) 'Shared nested group was suppressed across roots'
        Assert-Group (@($rows | Where-Object {$_.'group.DN' -eq 'CN=Empty,DC=fixture,DC=invalid' -and $null -eq $_.'member.SamAccountName'}).Count -eq 1) 'Empty nested group marker lost'
    }elseif($Mode -eq 'Selection'){
        $rows=@(Get-GroupCN -Array Both)
        Assert-Group ($rows.Count -eq 5 -and @($rows | Where-Object {$_.'group.CN' -ne 'Both'}).Count -eq 0) 'Distinct root matches were rejected or mislabeled'
        foreach($selectors in @(@(),@(' '),@('RootA',''))){$before=$global:ADAnalyzerGroupFixture.Calls.Count;$caught=$false;try{$null=Get-GroupCN -Array $selectors}catch{$caught=$true};Assert-Group ($caught -and $global:ADAnalyzerGroupFixture.Calls.Count -eq $before) 'Invalid selectors reached lookup'}
    }elseif($Mode -eq 'SpecialFilter'){
        $rows=@(Get-GroupCN -Array ('a*(b)\'+[char]0))
        Assert-Group ($rows.Count -eq 1 -and $rows[0].'group.DN' -eq 'CN=Empty,DC=fixture,DC=invalid') 'Literal selector was not escaped exactly'
    }elseif($Mode -eq 'Connection'){
        $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $null=Get-GroupCN -Array RootA -Server dc.fixture.invalid -Credential $credential
        foreach($call in $global:ADAnalyzerGroupFixture.Calls){Assert-Group ($call.Server -eq 'dc.fixture.invalid' -and [object]::ReferenceEquals($call.Credential,$credential) -and $call.ErrorAction -eq 'Stop') 'Connection/error contract changed'}
        $global:ADAnalyzerGroupFixture.Calls.Clear();$null=Get-GroupCN -Array Empty -Credential ([pscredential]::Empty)
        foreach($call in $global:ADAnalyzerGroupFixture.Calls){Assert-Group (-not $call.PSObject.Properties['Credential'] -and -not $call.PSObject.Properties['Server']) 'Empty connection identity was rebound'}
    }elseif($Mode -eq 'QueryFailures'){
        $output=Join-Path $WorkingDirectory 'previous.csv';[IO.File]::WriteAllText($output,'previous report')
        foreach($fault in @('Throw','WriteError','Missing','Multiple')){
            $global:ADAnalyzerGroupFixture.Calls.Clear();$global:ADAnalyzerGroupFixture.Fault=$fault;$emitted=[Collections.Generic.List[object]]::new();$caught=$false
            try{Get-GroupCN -Array RootA -OutputPath $output | ForEach-Object {$emitted.Add($_)}}catch{$caught=$true}
            Assert-Group ($caught -and $emitted.Count -eq 0 -and [IO.File]::ReadAllText($output) -eq 'previous report') ('Failed member lookup overwrote/emitted partial inventory: '+$fault)
        }
        $caught=$false;try{$null=Get-GroupCN -Array Missing -OutputPath $output}catch{$caught=$true};Assert-Group ($caught -and [IO.File]::ReadAllText($output) -eq 'previous report') 'No-match lookup erased output'
    }elseif($Mode -eq 'Csv'){
        $output=Join-Path $WorkingDirectory 'folder[1]/groups[2].csv';$rows=@(Get-GroupCN -Array @('RootA','Empty') -OutputPath $output);$csv=@(Import-Csv -LiteralPath $output)
        Assert-Group ($rows.Count -eq 5 -and $csv.Count -eq 5 -and ($csv[0].PSObject.Properties.Name -join ',') -ceq 'group.DN,group.CN,member.SamAccountName,member.objectClass') 'CSV row/header contract changed'
        Assert-Group (@($csv | Where-Object {$_.'member.SamAccountName' -ceq ('user '+[char]0x00FC+', "quoted"')}).Count -eq 1) 'Unicode/quoted member changed'
    }elseif($Mode -eq 'ExportFailures'){
        $output=Join-Path $WorkingDirectory 'previous.csv';[IO.File]::WriteAllText($output,'previous report')
        function ConvertTo-Csv {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[switch]$NoTypeInformation) process{throw 'fixture conversion failure'}}
        $caught=$false;try{Get-GroupCN -Array RootA -OutputPath $output | Out-Null}catch{$caught=$true};Assert-Group ($caught -and [IO.File]::ReadAllText($output) -eq 'previous report') 'Conversion failure replaced output';Remove-Item Function:ConvertTo-Csv
        $directory=Join-Path $WorkingDirectory 'directory-destination';$null=[IO.Directory]::CreateDirectory($directory)
        $sentinel=Join-Path $directory 'sentinel';[IO.File]::WriteAllText($sentinel,'preserve')
        $caught=$false;try{Get-GroupCN -Array RootA -OutputPath $directory | Out-Null}catch{$caught=$true}
        Assert-Group ($caught -and [IO.File]::ReadAllText($sentinel) -eq 'preserve') 'Write failure lost existing data'
    }elseif($Mode -eq 'WhatIf'){
        $directory=Join-Path $WorkingDirectory 'preview';$rows=@(Get-GroupCN -Array RootA -OutputPath (Join-Path $directory 'groups.csv') -WhatIf)
        Assert-Group ($rows.Count -eq 4 -and -not (Test-Path -LiteralPath $directory)) 'WhatIf lost rows or wrote files'
    }elseif($Mode -eq 'Cli'){
        $caught=$false;try{& $path | Out-Null}catch{$caught=$true};Assert-Group ($caught -and $global:ADAnalyzerGroupFixture.Calls.Count -eq 0) 'Missing CLI selector triggered discovery'
        $output=Join-Path $WorkingDirectory 'cli.csv';$rows=@(& $path -Array Empty -OutputPath $output -Confirm:$false)
        Assert-Group ($rows.Count -eq 1 -and @(Import-Csv -LiteralPath $output).Count -eq 1) 'Explicit CLI failed'
    }else{throw 'Unknown fixture mode'}
    'PASS group inventory '+$Mode
}finally{Set-Location -LiteralPath $location}
