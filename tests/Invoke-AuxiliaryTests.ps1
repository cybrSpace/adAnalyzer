[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
foreach($file in @('ADProfile','ADGpo','ADPolicyAnalysis','ADOperations')){. (Join-Path $RepositoryRoot ('bin/'+$file+'.ps1'))}
$script:Passed=0;$script:Failed=0
$script:Temporary=Join-Path ([IO.Path]::GetTempPath()) ('ad-auxiliary-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -Path $script:Temporary -ItemType Directory
$script:LookupCalls=[Collections.Generic.List[object]]::new()
$script:ReportCalls=[Collections.Generic.List[object]]::new()
$script:Imports=[Collections.Generic.List[string]]::new()
$script:ExternalCalls=0
$script:Credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
function Assert-Equal($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], got [$Actual]"}}
function Assert-True($Value,[string]$Message='Assertion failed'){if(-not $Value){throw $Message}}
function Assert-Throws([scriptblock]$Body){
    $caught=$null;try{$null=& $Body}catch{$caught=$_}
    if($null -eq $caught){throw 'Expected a terminating failure'}
    return $caught
}
function Assert-NoSecret($Value){
    $json=if($Value -is [string]){$Value}else{ConvertTo-Json -InputObject $Value -Depth 100}
    Assert-True ($json -notmatch 'AUXILIARY_FIXTURE_SECRET_8|REDACTED') 'A secret value or masked placeholder escaped'
}
function Write-FixtureText([string]$Path,[string]$Content,[Text.Encoding]$Encoding=[Text.Encoding]::UTF8){
    $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path));[IO.File]::WriteAllText($Path,$Content,$Encoding)
}
function Get-BytesFingerprint([string]$Path){[Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))}
function New-AuxiliaryReport([string]$Name,[guid]$Id){
    $root=Join-Path $script:Temporary $Id.ToString('N')
    Write-FixtureText (Join-Path $root 'GPT.INI') ("[General]"+[Environment]::NewLine+'Version=65538')
    Write-FixtureText (Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf') @'
[Unicode]
Unicode=yes
[Group Membership]
*S-1-5-32-544__Members=*S-1-5-21-1-2-3-1101
*S-1-5-21-1-2-3-1200__Memberof=*S-1-5-32-544
'@ ([Text.Encoding]::Unicode)
    Write-FixtureText (Join-Path $root 'Machine/Preferences/Groups/Groups.xml') @'
<Groups>
 <Group uid="members" name="Configured administrators"><Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators"><Members><Member action="ADD" sid="S-1-5-21-1-2-3-1101"/><Member action="REMOVE" sid="S-1-5-21-1-2-3-1102"/></Members></Properties><Filters><FilterComputer name="fixture-host"/></Filters></Group>
 <Group uid="cleared"><Properties action="R" groupSid="S-1-5-32-544" groupName="Administrators" deleteAllUsers="1"><Members/></Properties></Group>
 <User uid="disabled-user" disabled="1"><Properties action="U" userName="fixture-local" cpassword="AUXILIARY_FIXTURE_SECRET_8" password=""/></User>
 <User uid="unassessed-user"><Properties action="U" userName="fixture-other"/></User>
</Groups>
'@
    $metadata=[pscustomobject]@{
        Id=$Id;DisplayName=$Name;Domain='example.invalid';Server='dc.example.invalid'
        Flags=0;Version=65538;WmiFilter='fixture-filter'
        Links=@([pscustomobject]@{SOMPath='OU=Fixture,DC=example,DC=invalid';Enabled=$true;Enforced=$false})
        CreationTime=[datetime]'2026-01-01T00:00:00Z';ModificationTime=[datetime]'2026-01-02T00:00:00Z'
    }
    [pscustomobject]@{Gpo=$metadata;Policy=Read-ADAnalyzerGpo -Path $root}
}
function Reset-AuxiliaryMocks {
    $script:LookupCalls.Clear();$script:ReportCalls.Clear();$script:Imports.Clear()
    $script:Candidates=@($script:ReportA.Gpo);$script:ReadFailureId='';$script:LookupFails=$false
    $script:ReportMap=@{([string]$script:ReportA.Gpo.Id)=$script:ReportA;([string]$script:ReportB.Gpo.Id)=$script:ReportB}
    $script:XmlResponse=ConvertTo-AnalyzerGpoXml -Gpo $script:ReportA.Gpo -Parsed $script:ReportA.Policy
}
function Invoke-AuxiliaryTest([string]$Name,[scriptblock]$Body){
    Reset-AuxiliaryMocks
    try{& $Body;$script:Passed++;Write-Host "PASS $Name"}
    catch{$script:Failed++;Write-Host "FAIL $Name : $_";Write-Host $_.ScriptStackTrace}
}
# No fixture may use native imports, AD/SYSVOL, GPMC, WMI discovery or GUI actions.
function Import-Module {
    [CmdletBinding()]param([Parameter(Position=0)]$Name,[switch]$Force,[switch]$Global,[string]$Scope,[switch]$PassThru)
    if([IO.Path]::GetFileName([string]$Name) -ne 'ADEnvironment.psd1'){throw 'Unexpected module import'}
    $script:Imports.Add([string]$Name)
}
function Get-ADAnalyzerGpo {
    [CmdletBinding()]param([switch]$All,[string]$Name,[guid]$Guid,[string]$Domain,[string]$Server,[pscredential]$Credential)
    $copy=@{};foreach($key in $PSBoundParameters.Keys){$copy[$key]=$PSBoundParameters[$key]}
    $script:LookupCalls.Add([pscustomobject]$copy)
    if($script:LookupFails){throw 'fixture directory enumeration failure'}
    $script:Candidates
}
function Get-ADAnalyzerGpoReport {
    [CmdletBinding()]param($Gpo,[pscredential]$Credential,[switch]$AsObject)
    $script:ReportCalls.Add([pscustomobject]@{Gpo=$Gpo;Credential=$Credential;AsObject=[bool]$AsObject})
    if([string]$Gpo.Id -eq $script:ReadFailureId){throw 'AUXILIARY_FIXTURE_SECRET_8'}
    if($AsObject){return $script:ReportMap[[string]$Gpo.Id]}
    return $script:XmlResponse
}
function Get-GPO {$script:ExternalCalls++;throw 'Installed GPO command must not run'}
function Get-GPOReport {$script:ExternalCalls++;throw 'Installed GPO report command must not run'}
function Get-WmiObject {$script:ExternalCalls++;throw 'WMI fallback must not run'}
function Invoke-Item {$script:ExternalCalls++;throw 'GUI must not open'}
function Get-ADRootDSE {$script:ExternalCalls++;throw 'Actual directory query must not run'}
function Get-ADDomain {$script:ExternalCalls++;throw 'Actual directory query must not run'}
function Get-ADObject {$script:ExternalCalls++;throw 'Actual directory query must not run'}
try {
    $script:ReportA=New-AuxiliaryReport -Name ('Fixture '+[char]0x00FC+' policy') -Id ([guid]'11111111-1111-1111-1111-111111111111')
    $script:ReportB=New-AuxiliaryReport -Name $script:ReportA.Gpo.DisplayName -Id ([guid]'22222222-2222-2222-2222-222222222222')
    . (Join-Path $RepositoryRoot 'etc/Get-GPOXML.ps1')
    . (Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1')
    Invoke-AuxiliaryTest 'dot sourcing both GPO tools is inert and preserves caller state' {
        $Domain='caller-domain';$Server='caller-server';$Name='caller-name'
        $Guid=[guid]'33333333-3333-3333-3333-333333333333';$Credential=$script:Credential;$location=(Get-Location).Path
        $output=@(. (Join-Path $RepositoryRoot 'etc/Get-GPOXML.ps1');. (Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1'))
        Assert-Equal 0 $output.Count;Assert-Equal $location (Get-Location).Path
        Assert-Equal 'caller-domain' $Domain;Assert-Equal 'caller-server' $Server;Assert-Equal 'caller-name' $Name
        Assert-Equal ([guid]'33333333-3333-3333-3333-333333333333') $Guid
        Assert-True ([object]::ReferenceEquals($Credential,$script:Credential)) 'Caller credential changed'
        Assert-Equal 0 $script:LookupCalls.Count;Assert-Equal 0 $script:ReportCalls.Count;Assert-Equal 0 $script:Imports.Count;Assert-Equal 0 $script:ExternalCalls
    }
    Invoke-AuxiliaryTest 'missing or conflicting live targets fail before import and collection' {
        $null=Assert-Throws {Get-ADAnalyzerGpoXml}
        $null=Assert-Throws {Get-ADAnalyzerGpoXml -Domain example.invalid}
        $null=Assert-Throws {Get-ADAnalyzerGpoXml -Domain example.invalid -Name one -Guid $script:ReportA.Gpo.Id}
        $null=Assert-Throws {Get-ADAnalyzerLocalAdminGpo}
        $null=Assert-Throws {Get-ADAnalyzerLocalAdminGpo -Domain example.invalid}
        $null=Assert-Throws {Get-ADAnalyzerLocalAdminGpo -Domain example.invalid -All -Name one}
        Assert-Equal 0 $script:Imports.Count;Assert-Equal 0 $script:LookupCalls.Count
    }
    Invoke-AuxiliaryTest 'offline XML uses supplied flags and canonical typed policy without native imports' {
        $provided=[pscustomobject]@{Gpo=$script:ReportA.Gpo.PSObject.Copy();Policy=$script:ReportA.Policy};$provided.Gpo.Flags=2
        $text=Get-ADAnalyzerGpoXml -InputObject $provided;$xml=[xml]$text
        Assert-Equal 'GPO' $xml.DocumentElement.LocalName
        Assert-Equal 'false' ([string]$xml.GPO.Computer.Enabled);Assert-Equal 'true' ([string]$xml.GPO.User.Enabled)
        Assert-True ($text -match 'Group Membership|Members|Memberof') 'Configured group policy disappeared'
        Assert-NoSecret $text
        Assert-Equal 0 $script:Imports.Count;Assert-Equal 0 $script:LookupCalls.Count;Assert-Equal 0 $script:ReportCalls.Count
    }
    Invoke-AuxiliaryTest 'raw offline XML and named registry payloads retain only secret presence' {
        $policy=[pscustomobject]@{
            SysvolVersion=0;Files=@();SecuritySettings=@();IniSettings=@()
            RegistrySettings=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='DefaultPassword';Type=1;Value='AUXILIARY_FIXTURE_SECRET_8';RawData=[byte[]]@(1,2,3)})
            XmlFiles=@([pscustomobject]@{Scope='Computer';Kind='Preferences';Path='Machine/Preferences/Groups/Groups.xml';Xml='<Groups><User uid="raw"><Properties cpassword="AUXILIARY_FIXTURE_SECRET_8"/></User></Groups>'})
        }
        $provided=[pscustomobject]@{Gpo=$script:ReportA.Gpo;Policy=$policy}
        $text=Get-ADAnalyzerGpoXml -InputObject $provided
        Assert-NoSecret $text;Assert-True ($text -match 'SecretPresent|cpasswordPresent') 'Presence indicator missing'
        Assert-True ($policy.XmlFiles[0].Xml -match 'AUXILIARY_FIXTURE_SECRET_8') 'Caller XML mutated'
        Assert-Equal 'AUXILIARY_FIXTURE_SECRET_8' $policy.RegistrySettings[0].Value
    }
    Invoke-AuxiliaryTest 'offline metadata is required rather than inventing GPO identity or flags' {
        foreach($tool in @('Get-ADAnalyzerGpoXml','Get-ADAnalyzerLocalAdminGpo')){foreach($field in @('Id','Flags')){
            $metadata=$script:ReportA.Gpo.PSObject.Copy();$metadata.PSObject.Properties.Remove($field)
            $provided=[pscustomobject]@{Gpo=$metadata;Policy=$script:ReportA.Policy};$null=Assert-Throws {& $tool -InputObject $provided}
        }
            $provided=[pscustomobject]@{Gpo=$script:ReportA.Gpo;Policy=$script:ReportA.Policy}
            $null=Assert-Throws {& $tool -InputObject $provided -Domain example.invalid}
        }
        Assert-Equal 0 $script:Imports.Count;Assert-Equal 0 $script:LookupCalls.Count
    }
    Invoke-AuxiliaryTest 'XML live name selection forwards target credential and package import' {
        $text=Get-ADAnalyzerGpoXml -Domain example.invalid -Server dc.example.invalid -Name 'Fixture policy' -Credential $script:Credential
        Assert-Equal 1 $script:Imports.Count;Assert-Equal 1 $script:LookupCalls.Count;Assert-Equal 1 $script:ReportCalls.Count
        Assert-Equal 'example.invalid' $script:LookupCalls[0].Domain;Assert-Equal 'dc.example.invalid' $script:LookupCalls[0].Server
        Assert-Equal 'Fixture policy' $script:LookupCalls[0].Name
        Assert-True ([object]::ReferenceEquals($script:Credential,$script:LookupCalls[0].Credential)) 'Lookup credential lost'
        Assert-True ([object]::ReferenceEquals($script:Credential,$script:ReportCalls[0].Credential)) 'Report credential lost'
        Assert-Equal $false $script:ReportCalls[0].AsObject;Assert-NoSecret $text
    }
    Invoke-AuxiliaryTest 'XML GUID and FQDN aliases preserve the selected identity' {
        $null=Get-ADAnalyzerGpoXml -FQDN example.invalid -Guid $script:ReportA.Gpo.Id
        Assert-Equal $script:ReportA.Gpo.Id $script:LookupCalls[0].Guid;Assert-Equal 'example.invalid' $script:LookupCalls[0].Domain
    }
    Invoke-AuxiliaryTest 'missing and ambiguous XML names never read or overwrite a report' {
        $path=Join-Path $script:Temporary 'ambiguous.xml';Write-FixtureText $path 'previous';$before=Get-BytesFingerprint $path
        foreach($selected in @(@(),@($script:ReportA.Gpo,$script:ReportB.Gpo))){
            $script:Candidates=$selected;$null=Assert-Throws {Get-ADAnalyzerGpoXml -Domain example.invalid -Name duplicate -OutputPath $path}
            Assert-Equal $before (Get-BytesFingerprint $path)
        }
        Assert-Equal 0 $script:ReportCalls.Count
    }
    Invoke-AuxiliaryTest 'local-admin inventory retains states membership operations targeting and metadata' {
        $rows=@(Get-ADAnalyzerLocalAdminGpo -InputObject $script:ReportA)
        foreach($status in @('Pass','Fail','Unknown','NotApplicable')){Assert-True (@($rows | Where-Object Status -eq $status).Count -gt 0) ('Missing '+$status+' rows')}
        $members=@($rows | Where-Object {$_.RuleId -eq 'GPO.Preferences.LocalUsersGroups' -and $_.Evidence.ConfiguredSetting.Uid -eq 'members'})[0]
        Assert-Equal 'U' $members.Evidence.ConfiguredSetting.Action;Assert-Equal 2 $members.Evidence.ConfiguredSetting.Members.Count
        Assert-Equal 'ADD' $members.Evidence.ConfiguredSetting.Members[0].Action;Assert-Equal 'REMOVE' $members.Evidence.ConfiguredSetting.Members[1].Action
        Assert-Equal $true $members.Evidence.ConfiguredSetting.Targeted;Assert-Equal ([string]$script:ReportA.Gpo.Id) $members.GpoId
        Assert-Equal 'Provided' $members.MetadataStatus;Assert-Equal $script:ReportA.Gpo.DisplayName $members.GpoName
        Assert-Equal 'OU=Fixture,DC=example,DC=invalid' $members.Evidence.Gpo.Links[0].SOMPath
        $restricted=@($rows | Where-Object RuleId -eq 'GPO.RestrictedGroups.LocalAdministrators')
        Assert-True (@($restricted | Where-Object {$_.Evidence.ConfiguredSetting.Mode -ieq 'Members'}).Count -gt 0) 'Members lost'
        Assert-True (@($restricted | Where-Object {$_.Evidence.ConfiguredSetting.Mode -ieq 'Memberof'}).Count -gt 0) 'MemberOf lost'
        $secret=@($rows | Where-Object RuleId -eq 'GPO.Preferences.CPassword')[0]
        Assert-Equal 'Fail' $secret.Status;Assert-Equal $true $secret.Evidence.ConfiguredSetting
        Assert-True ($secret.Evidence.RuleEvidence.Path -match 'Groups.xml') 'Secret location missing'
        Assert-NoSecret $rows;Assert-Equal 0 $script:Imports.Count;Assert-Equal 0 $script:LookupCalls.Count
    }
    Invoke-AuxiliaryTest 'empty policies remain explicit NotConfigured rather than an empty success report' {
        $empty=[pscustomobject]@{Gpo=$script:ReportA.Gpo;Policy=[pscustomobject]@{SecuritySettings=@();RegistrySettings=@();IniSettings=@();XmlFiles=@();Files=@();UnparsedFiles=@()}}
        $rows=@(Get-ADAnalyzerLocalAdminGpo -InputObject $empty)
        Assert-True (@($rows | Where-Object Status -eq NotConfigured).Count -ge 2) 'Absent group policy hidden'
    }
    Invoke-AuxiliaryTest 'local-admin CSV includes configured members and GUID metadata without secrets' {
        $path=Join-Path $script:Temporary 'inventory.csv';$rows=@(Get-ADAnalyzerLocalAdminGpo -InputObject $script:ReportA -OutputPath $path)
        Assert-True ($rows.Count -gt 0) 'Typed rows missing'
        $csv=@(Import-Csv -LiteralPath $path);$text=Get-Content -LiteralPath $path -Raw
        Assert-True ($text -match 'S-1-5-21-1-2-3-1101' -and $text -match '11111111-1111-1111-1111-111111111111') 'CSV lost evidence or GUID'
        Assert-True ($csv[0].PSObject.Properties.Name -contains 'Evidence') 'CSV evidence column missing';Assert-NoSecret $text
    }
    Invoke-AuxiliaryTest 'live all-policy inventory retains duplicate names and forwards every read credential' {
        $script:Candidates=@($script:ReportA.Gpo,$script:ReportB.Gpo)
        $rows=@(Get-ADAnalyzerLocalAdminGpo -FQDN example.invalid -Server dc.example.invalid -All -Credential $script:Credential)
        Assert-Equal $true $script:LookupCalls[0].All;Assert-Equal 'example.invalid' $script:LookupCalls[0].Domain
        Assert-Equal 'dc.example.invalid' $script:LookupCalls[0].Server;Assert-Equal 2 $script:ReportCalls.Count
        foreach($call in $script:ReportCalls){Assert-Equal $true $call.AsObject;Assert-True ([object]::ReferenceEquals($script:Credential,$call.Credential)) 'Read credential lost'}
        Assert-Equal 2 @($rows.GpoId | Select-Object -Unique).Count;Assert-Equal 1 @($rows.GpoName | Select-Object -Unique).Count;Assert-Equal 0 $script:ExternalCalls
    }
    Invoke-AuxiliaryTest 'read failures are explicit without export and preserve previous exports' {
        $script:Candidates=@($script:ReportA.Gpo,$script:ReportB.Gpo);$script:ReadFailureId=[string]$script:ReportB.Gpo.Id
        $rows=@(Get-ADAnalyzerLocalAdminGpo -Domain example.invalid -All -Credential $script:Credential)
        $failure=@($rows | Where-Object RuleId -eq GPO.READ)
        Assert-Equal 1 $failure.Count;Assert-Equal 'Unreadable' $failure[0].Status;Assert-Equal ([string]$script:ReportB.Gpo.Id) $failure[0].GpoId;Assert-NoSecret $rows
        $path=Join-Path $script:Temporary 'existing-inventory.csv';Write-FixtureText $path 'previous report';$before=Get-BytesFingerprint $path
        $null=Assert-Throws {Get-ADAnalyzerLocalAdminGpo -Domain example.invalid -All -OutputPath $path};Assert-Equal $before (Get-BytesFingerprint $path)
    }
    Invoke-AuxiliaryTest 'WhatIf reads provided policy but creates no export directory' {
        $directory=Join-Path $script:Temporary 'whatif-new'
        $xml=Get-ADAnalyzerGpoXml -InputObject $script:ReportA -OutputPath (Join-Path $directory 'policy.xml') -WhatIf
        $rows=@(Get-ADAnalyzerLocalAdminGpo -InputObject $script:ReportA -OutputPath (Join-Path $directory 'inventory.csv') -WhatIf)
        Assert-True ([bool]$xml -and $rows.Count -gt 0) 'Read results missing under WhatIf';Assert-Equal $false (Test-Path -LiteralPath $directory)
    }
    Invoke-AuxiliaryTest 'live XML declarations agree with actual UTF8 BOM encoding' {
        $word='M'+[char]0x00FC+'nchen'
        $script:XmlResponse='<?xml version="1.0" encoding="utf-16"?><GPO><Label>'+$word+'</Label><Properties cpassword="AUXILIARY_FIXTURE_SECRET_8"/></GPO>'
        $path=Join-Path $script:Temporary 'encoded.xml'
        $text=Get-ADAnalyzerGpoXml -Domain example.invalid -Guid $script:ReportA.Gpo.Id -OutputPath $path
        $bytes=[IO.File]::ReadAllBytes($path);Assert-Equal 'EF-BB-BF' ([BitConverter]::ToString($bytes[0..2]))
        $xml=[xml]::new();$xml.Load($path);Assert-Equal $word ([string]$xml.GPO.Label)
        Assert-True ($text -match 'encoding="utf-8"') 'XML declaration disagrees with file bytes';Assert-NoSecret ([IO.File]::ReadAllText($path))
    }
    Invoke-AuxiliaryTest 'DTD reports fail before replacing previous XML bytes' {
        $script:XmlResponse='<!DOCTYPE GPO [<!ENTITY fixture "value">]><GPO>&fixture;</GPO>'
        $path=Join-Path $script:Temporary 'dtd.xml';Write-FixtureText $path 'previous';$before=Get-BytesFingerprint $path
        $null=Assert-Throws {Get-ADAnalyzerGpoXml -Domain example.invalid -Name one -OutputPath $path};Assert-Equal $before (Get-BytesFingerprint $path)
    }
    Invoke-AuxiliaryTest 'shared writer resolves literal PSDrive paths and replaces complete files' {
        $directory=Join-Path $script:Temporary 'drive-root';$null=New-Item -Path $directory -ItemType Directory
        $driveName='Aux'+[guid]::NewGuid().ToString('N').Substring(0,12);$null=New-PSDrive -Name $driveName -PSProvider FileSystem -Root $directory -Scope Global
        try{
            $provided=$driveName+':/folder[1]/report[2].txt';$expected=Join-Path $directory 'folder[1]/report[2].txt'
            $null=Write-ADAnalyzerFile -Path $provided -Content 'first complete report';Assert-Equal 'first complete report' ([IO.File]::ReadAllText($expected))
            $null=Write-ADAnalyzerOperationFile -Path $provided -Content 'replacement complete report';Assert-Equal 'replacement complete report' ([IO.File]::ReadAllText($expected))
            Assert-Equal 0 @(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($expected)) -Force -Filter '.ad-analyzer-*.tmp').Count
        }finally{Remove-PSDrive -Name $driveName -Force}
        $null=Assert-Throws {Write-ADAnalyzerFile -Path 'Env:ADANALYZER_AUXILIARY_INVALID_PROVIDER' -Content 'not a file'}
    }
    Invoke-AuxiliaryTest 'failed replacement preserves destination data and removes staging files' {
        $directory=Join-Path $script:Temporary 'destination-is-directory';$null=New-Item -Path $directory -ItemType Directory
        $sentinel=Join-Path $directory 'sentinel.txt';Write-FixtureText $sentinel 'preserve me'
        $null=Assert-Throws {Write-ADAnalyzerFile -Path $directory -Content 'replacement'}
        Assert-Equal 'preserve me' ([IO.File]::ReadAllText($sentinel));Assert-Equal 0 @(Get-ChildItem -LiteralPath $script:Temporary -Force -Filter '.ad-analyzer-*.tmp').Count
    }
    Invoke-AuxiliaryTest 'provided record projection preserves known presence and leaves input unchanged' {
        foreach($case in @(@($true,''),@($true,$null),@($false,'AUXILIARY_FIXTURE_SECRET_8'))){
            $record=[pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='DefaultPassword';Type=1;Value=$case[1];SecretPresent=$case[0];Source='Machine/Registry.pol';KeyOnly=$false}
            $provided=[pscustomobject]@{Gpo=$script:ReportA.Gpo;Policy=[pscustomobject]@{Files=@();UnparsedFiles=@();SysvolVersion=1;RegistrySettings=@($record);SecuritySettings=@();IniSettings=@();XmlFiles=@()}}
            $before=ConvertTo-Json -InputObject $provided -Depth 50 -Compress
            $xml=[xml](Get-ADAnalyzerGpoXml -InputObject $provided)
            Assert-True ($xml.SelectNodes('//*[@SecretPresent="true"]|//*[local-name()="SecretPresent" and .="true"]').Count -gt 0) 'XML lost known presence'
            $rows=@(Get-ADAnalyzerLocalAdminGpo -InputObject $provided)
            $finding=@($rows | Where-Object RuleId -eq GPO.StoredSecret)[0]
            Assert-Equal $true $finding.Observed
            Assert-NoSecret $xml.OuterXml;Assert-NoSecret $rows
            $first=ConvertTo-ADAnalyzerSecretRecord $record;$second=ConvertTo-ADAnalyzerSecretRecord $first
            Assert-Equal $true $first.SecretPresent
            Assert-Equal (ConvertTo-Json -InputObject $first -Compress) (ConvertTo-Json -InputObject $second -Compress)
            Assert-Equal $before (ConvertTo-Json -InputObject $provided -Depth 50 -Compress)
        }
    }
    Invoke-AuxiliaryTest 'XML retains actual identity and Unicode metadata without fabricating optional fields' {
        $metadata=$script:ReportA.Gpo.PSObject.Copy()
        $metadata.PSObject.Properties.Remove('Domain');$metadata.PSObject.Properties.Remove('Server')
        $metadata.Flags=0
        $xml=[xml](Get-ADAnalyzerGpoXml -InputObject ([pscustomobject]@{Gpo=$metadata;Policy=$script:ReportA.Policy}))
        Assert-Equal ([string]$metadata.Id) ([string]$xml.GPO.Id)
        Assert-Equal $metadata.DisplayName ([string]$xml.GPO.DisplayName);Assert-Equal '0' ([string]$xml.GPO.Flags)
        Assert-Equal $null $xml.SelectSingleNode('/GPO/Domain');Assert-Equal $null $xml.SelectSingleNode('/GPO/Server')
        $live=[xml](Get-ADAnalyzerGpoXml -Domain example.invalid -Guid $script:ReportA.Gpo.Id)
        Assert-Equal ([string]$script:ReportA.Gpo.Id) ([string]$live.GPO.Id)
        Assert-Equal $script:ReportA.Gpo.DisplayName ([string]$live.GPO.DisplayName)
    }
    Invoke-AuxiliaryTest 'JSON report roundtrip preserves binary registry encoding and inventory identities' {
        $policy=$script:ReportA.Policy.PSObject.Copy()
        $policy.RegistrySettings=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='Bytes';Type=3;Value=[byte[]]@(1,2);Source='Machine/Registry.pol';KeyOnly=$false})
        $provided=[pscustomobject]@{Gpo=$script:ReportA.Gpo;Policy=$policy}
        $json=$provided | ConvertTo-Json -Depth 100 | ConvertFrom-Json
        $originalValue=$json.Policy.RegistrySettings[0].Value;$originalType=$originalValue.GetType()
        $before=ConvertTo-Json -InputObject $json -Depth 100 -Compress
        $native=[xml](Get-ADAnalyzerGpoXml -InputObject $provided);$roundtrip=[xml](Get-ADAnalyzerGpoXml -InputObject $json)
        Assert-Equal $originalType $json.Policy.RegistrySettings[0].Value.GetType()
        Assert-True ([object]::ReferenceEquals($originalValue,$json.Policy.RegistrySettings[0].Value)) 'XML replaced the caller binary array'
        $xpath='//Record[Name="HKLM\Software\Fixture\Bytes"]/Value'
        Assert-Equal 'AQI=' $native.SelectSingleNode($xpath).InnerText
        Assert-Equal $native.SelectSingleNode($xpath).InnerText $roundtrip.SelectSingleNode($xpath).InnerText
        $a=@(Get-ADAnalyzerLocalAdminGpo -InputObject $provided);$b=@(Get-ADAnalyzerLocalAdminGpo -InputObject $json)
        Assert-Equal ($a.CheckId -join ',') ($b.CheckId -join ',');Assert-NoSecret $b
        Assert-Equal $originalType $json.Policy.RegistrySettings[0].Value.GetType()
        Assert-True ([object]::ReferenceEquals($originalValue,$json.Policy.RegistrySettings[0].Value)) 'Inventory replaced the caller binary array'
        Assert-Equal $before (ConvertTo-Json -InputObject $json -Depth 100 -Compress)
    }
    Invoke-AuxiliaryTest 'unsupported dictionary rows and unreadable provided XML fail before replacing bytes' {
        foreach($policy in @(
            [pscustomobject]@{Files=@();RegistrySettings=@(@{Scope='Computer';ValueName='DefaultPassword';Value='AUXILIARY_FIXTURE_SECRET_8'});SecuritySettings=@();IniSettings=@();XmlFiles=@()}
            [pscustomobject]@{Files=@();RegistrySettings=@();SecuritySettings=@();IniSettings=@();XmlFiles=@([pscustomobject]@{Scope='Computer';Kind='Preferences';Path='bad.xml';Xml='<!DOCTYPE Groups [<!ENTITY secret "AUXILIARY_FIXTURE_SECRET_8">]><Groups>&secret;</Groups>'})}
        )){
            $provided=[pscustomobject]@{Gpo=$script:ReportA.Gpo;Policy=$policy}
            foreach($tool in @('Get-ADAnalyzerGpoXml','Get-ADAnalyzerLocalAdminGpo')){
                $path=Join-Path $script:Temporary 'invalid-provided.txt';Write-FixtureText $path 'previous report';$before=Get-BytesFingerprint $path
                $error=Assert-Throws {& $tool -InputObject $provided -OutputPath $path}
                Assert-Equal $before (Get-BytesFingerprint $path);Assert-NoSecret $error.Exception.Message
            }
        }
    }
    Invoke-AuxiliaryTest 'directory and CSV serialization failures preserve the previous destination' {
        $path=Join-Path $script:Temporary 'serialization.csv';Write-FixtureText $path 'previous report';$before=Get-BytesFingerprint $path
        $script:LookupFails=$true
        $null=Assert-Throws {Get-ADAnalyzerGpoXml -Domain example.invalid -Name one -OutputPath $path}
        Assert-Equal $before (Get-BytesFingerprint $path)
        function script:ConvertTo-Csv {[CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[switch]$NoTypeInformation) process{throw 'fixture serialization failure'}}
        try{
            $null=Assert-Throws {Get-ADAnalyzerLocalAdminGpo -InputObject $script:ReportA -OutputPath $path}
            Assert-Equal $before (Get-BytesFingerprint $path)
        }finally{Remove-Item Function:script:ConvertTo-Csv}
    }
    Invoke-AuxiliaryTest 'an empty all-policy selection exports explicit CSV headers and no fabricated rows' {
        $script:Candidates=@();$path=Join-Path $script:Temporary 'no-policies.csv'
        $rows=@(Get-ADAnalyzerLocalAdminGpo -Domain example.invalid -All -OutputPath $path)
        Assert-Equal 0 $rows.Count;Assert-Equal 0 @(Import-Csv -LiteralPath $path).Count
        Assert-True ((Get-Content -LiteralPath $path -Raw) -match '"RuleId","Target","Status","Severity","Evidence"') 'Empty CSV header missing'
        Assert-Equal 0 $script:ReportCalls.Count
    }
    Invoke-AuxiliaryTest 'clean live callers need only public module APIs and retain private helper scope' {
        $fixture=Join-Path $script:Temporary 'clean-public-api.ps1'
        Write-FixtureText $fixture @'
param([string]$Root)
$ErrorActionPreference='Stop'
$module=New-Module -Name ADAnalyzerPublicFixture -ArgumentList $Root -ScriptBlock {
    param($Root)
    foreach($file in @('ADProfile','ADGpo','ADPolicyAnalysis','ADOperations')){. (Join-Path $Root ('bin/'+$file+'.ps1'))}
    function Get-ADAnalyzerGpo {
        param($Domain,$Server,$Credential,$Name,[guid]$Guid,[switch]$All)
        [pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';DisplayName=$Name;Domain=$Domain;Server=$Server;Flags=0;Version=1;Links=@()}
    }
    function Get-ADAnalyzerGpoReport {
        param($Gpo,$Credential,[switch]$AsObject)
        if($Gpo.DisplayName -eq 'failure'){throw 'fixture read failure'}
        [pscustomobject]@{Gpo=$Gpo;Policy=[pscustomobject]@{Files=@();UnparsedFiles=@();SecuritySettings=@();RegistrySettings=@();IniSettings=@();XmlFiles=@();SysvolVersion=1}}
    }
    Export-ModuleMember -Function Get-ADAnalyzerGpo,Get-ADAnalyzerGpoReport,Test-ADAnalyzerGpoPolicy,Import-ADAnalyzerProfile,Export-ADAnalyzerAssessment
}
Microsoft.PowerShell.Core\Import-Module $module -Global
function Import-Module {
    [CmdletBinding()]param($Name)
    if([IO.Path]::GetFileName([string]$Name) -ne 'ADEnvironment.psd1'){throw 'Unexpected import'}
}
if(Get-Command New-ADAnalyzerCheck -ErrorAction SilentlyContinue){throw 'Private check helper leaked from fixture module'}
if(Get-Command ConvertTo-ADAnalyzerSafeData -ErrorAction SilentlyContinue){throw 'Private projection helper leaked from fixture module'}
. (Join-Path $Root 'etc/Get-LocalAdminGPO.ps1')
$rows=@(Get-ADAnalyzerLocalAdminGpo -Domain example.invalid -Name success)
if($rows.Count -lt 3 -or $rows[0].MetadataStatus -ne 'Collected'){throw 'Clean public live call failed'}
$failure=@(Get-ADAnalyzerLocalAdminGpo -Domain example.invalid -Name failure | Where-Object RuleId -eq GPO.READ)
if($failure.Count -ne 1 -or $failure[0].Status -ne 'Unreadable'){throw 'Clean read-error helper failed'}
if(Get-Command New-ADAnalyzerCheck -ErrorAction SilentlyContinue){throw 'Adapter check helper escaped its call'}
if(Get-Command ConvertTo-ADAnalyzerSafeData -ErrorAction SilentlyContinue){throw 'Adapter projection helper escaped its call'}
Write-Output 'PASS clean public API boundary'
'@
        $output=& (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -File $fixture -Root $RepositoryRoot
        Assert-Equal 0 $LASTEXITCODE
        Assert-True (($output -join ' ') -match 'PASS clean public API boundary') 'Clean child did not finish'
    }
    $legacyFixture=Join-Path $script:Temporary 'legacy-export-fixture.ps1'
    Write-FixtureText $legacyFixture @'
param([string]$Root,[string]$Script,[string]$Mode,[string]$Work)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'bin/ADFile.ps1')
$null=[IO.Directory]::CreateDirectory($Work);$path=Join-Path $Work 'report.csv'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Root ('etc/'+$Script)),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
$types=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.TypeDefinitionAst]},$true))
if($Mode -eq 'Export'){$types=@($types | Where-Object Name -eq Collection)}
if(-not $types.Count){throw 'Fixture class extraction failed'}
function Assert-Legacy($Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Fingerprint-Legacy {[System.Convert]::ToBase64String([IO.File]::ReadAllBytes($path))}
$body=if($Mode -eq 'Export'){
    {
        $row=if($Script -eq 'Get-NTLMEvents.ps1'){
            [pscustomobject]@{Server=('server '+[char]0x00FC+' "quoted"');EventID='4624';LogName='Security';Time='fixture';UserName='fixture';WorkstationName='work';LogonType=3;ImpersonationLevel=2}
        }else{[pscustomobject]@{iteration=1;url='https://fixture.invalid/a,"quoted"';status='Success';seconds=1.25;timestamp='2026-01-01 00:00:00Z'}}
        $collection=[Collection]::new();$null=$collection.Add($row)
        $collection.Export($path);$copy=@(Import-Csv -LiteralPath $path)
        Assert-Legacy ($copy.Count -eq 1) 'Populated CSV row count changed'
        foreach($property in $row.PSObject.Properties){Assert-Legacy ([string]$copy[0].($property.Name) -ceq [string]$property.Value) ('CSV value changed: '+$property.Name)}
        $preference=$ErrorActionPreference
        try{
            $ErrorActionPreference='Continue'
            function ConvertTo-Csv {
                [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[switch]$NoTypeInformation)
                process{if($script:ExportFaultMode -eq 'Terminating'){throw 'fixture conversion failure'};Write-Error 'fixture conversion failure'}
            }
            function Export-Csv {
                [CmdletBinding(SupportsShouldProcess=$true)]param([Parameter(ValueFromPipeline)]$InputObject,$Path,[switch]$NoTypeInformation,$Encoding,[switch]$Force)
                process{if($script:ExportFaultMode -eq 'Terminating'){throw 'fixture conversion failure'};Write-Error 'fixture conversion failure'}
            }
            foreach($script:ExportFaultMode in @('Terminating','NonTerminating')){
                [IO.File]::WriteAllText($path,('previous '+[char]0x03A9));$before=Fingerprint-Legacy
                $caught=$false;try{$collection.Export($path)}catch{$caught=$true}
                Assert-Legacy $caught 'Conversion failure was reported as success'
                Assert-Legacy ([IO.File]::Exists($path) -and (Fingerprint-Legacy) -ceq $before) 'Conversion failure destroyed previous bytes'
            }
        }finally{Remove-Item Function:ConvertTo-Csv,Function:Export-Csv;$ErrorActionPreference=$preference}
        $empty=[Collection]::new();$empty.Export($path)
        Assert-Legacy ([IO.File]::Exists($path) -and @(Import-Csv -LiteralPath $path).Count -eq 0) 'Empty export removed or retained stale rows'
        $headers=if($Script -eq 'Get-NTLMEvents.ps1'){'"Server","EventID","LogName","Time","UserName","WorkstationName","LogonType","ImpersonationLevel"'}else{'"iteration","url","status","seconds","timestamp"'}
        Assert-Legacy ([IO.File]::ReadAllText($path).Trim() -eq $headers) 'Empty CSV schema changed'
        if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
            [IO.File]::WriteAllText($path,'previous locked report');$before=Fingerprint-Legacy
            $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{$caught=$false;try{$collection.Export($path)}catch{$caught=$true}}finally{$held.Dispose()}
            Assert-Legacy ($caught -and (Fingerprint-Legacy) -ceq $before) 'Locked export failed to preserve its destination'
        }
        Assert-Legacy ([IO.Directory]::GetFiles($Work).Count -eq 1) 'Exporter silently renamed output or left a staging file'
    }.ToString()
}else{
    {
        $ErrorActionPreference='Continue'
        [IO.File]::WriteAllText($path,'previous query report');$before=Fingerprint-Legacy
        $script:QueryCalls=0
        function Get-Credential {
            [CmdletBinding()]param($UserName,$Message)
            [pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        }
        function Get-WinEvent {
            [CmdletBinding()]param($FilterHashtable,$Credential,$ComputerName)
            $script:QueryCalls++
            Write-Error 'fixture event query failure'
        }
        function Invoke-RestMethod {
            [CmdletBinding()]param($Uri,$Method,$WebSession,[switch]$UseBasicParsing,$UserAgent)
            $script:QueryCalls++
            Write-Error 'fixture measurement failure'
        }
        $caught=$false;$failureMessage=''
        try{
            if($Script -eq 'Get-NTLMEvents.ps1'){$target=[Target]::Scan([Collections.ArrayList]@('fixture-host'),@{},'fixture')}
            else{
                $target=[Target]::new(@{},@{limit=1;wait=0})
                # Supply a valid collection to isolate export/query behavior;
                # constructor finding C-013 is tested in its separate correction.
                $target.Collection=[Collection]::new();$target.Analyze('https://fixture.invalid/')
            }
            $target.Export($path)
        }catch{$caught=$true;$failureMessage=$_.Exception.Message}
        $marker=if($Script -eq 'Get-NTLMEvents.ps1'){'fixture event query failure'}else{'fixture measurement failure'}
        Assert-Legacy ($script:QueryCalls -eq 1 -and $failureMessage.Contains($marker)) 'Fixture did not reach and propagate the intended query failure'
        Assert-Legacy ($caught -and [IO.File]::Exists($path) -and (Fingerprint-Legacy) -ceq $before) 'Failed query reached export or changed prior bytes'
    }.ToString()
}
$source="using namespace System.Collections"+[Environment]::NewLine+"using namespace System.Collections.Specialized"+[Environment]::NewLine+($types.Extent.Text -join [Environment]::NewLine)+[Environment]::NewLine+$body
. ([scriptblock]::Create($source))
Write-Output ('PASS legacy '+$Script+' '+$Mode)
'@
    foreach($legacyScript in @('Get-NTLMEvents.ps1','Test-SAMLProtectedResponseTimes.ps1')){foreach($legacyMode in @('Export','Query')){
        Invoke-AuxiliaryTest ('legacy '+$legacyScript+' '+$legacyMode+' preserves reports on failures and supports empty data') {
            $work=Join-Path $script:Temporary ([guid]::NewGuid().ToString('N'))
            $output=& (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -File $legacyFixture -Root $RepositoryRoot -Script $legacyScript -Mode $legacyMode -Work $work
            Assert-Equal 0 $LASTEXITCODE
            Assert-True (($output -join ' ') -match 'PASS legacy') 'Legacy child fixture did not finish'
        }
    }}
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        Invoke-AuxiliaryTest 'Windows held destinations preserve bytes and clean failed staging files' {
            $path=Join-Path $script:Temporary 'held.txt';Write-FixtureText $path 'old report';$before=Get-BytesFingerprint $path
            $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{$null=Assert-Throws {Write-ADAnalyzerFile -Path $path -Content 'replacement'}}finally{$held.Dispose()}
            Assert-Equal $before (Get-BytesFingerprint $path);Assert-Equal 0 @(Get-ChildItem -LiteralPath $script:Temporary -Force -Filter '.ad-analyzer-*.tmp').Count
        }
    }
    Assert-Equal 0 $script:ExternalCalls
}finally{if(Test-Path -LiteralPath $script:Temporary){Remove-Item -LiteralPath $script:Temporary -Recurse -Force -ErrorAction SilentlyContinue}}
Write-Host ("{0} auxiliary tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
