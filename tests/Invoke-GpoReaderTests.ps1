[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
. (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
$script:Passed=0;$script:Failed=0
function Assert-Equal($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], got [$Actual]"}}
function Assert-True($Actual,[string]$Message){if(-not $Actual){throw $Message}}
function Assert-Throws([scriptblock]$Body){$threw=$false;try{& $Body > $null}catch{$threw=$true};if(-not $threw){throw 'Expected a terminating error'}}
function Test-Gpo([string]$Name,[scriptblock]$Body){try{& $Body;$script:Passed++;Write-Host "PASS $Name"}catch{$script:Failed++;Write-Host "FAIL $Name : $_";Write-Host $_.ScriptStackTrace}}
function Write-Text([string]$Path,[string]$Text,[Text.Encoding]$Encoding=[Text.Encoding]::UTF8){$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path));[IO.File]::WriteAllText($Path,$Text,$Encoding)}
function Write-Pol([string]$Path,[array]$Records){
    $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream=[IO.File]::Create($Path);$writer=[IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'));$writer.Write([uint32]1)
        foreach($row in $Records){
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Key+[char]0));$writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Name+[char]0));$writer.Write([uint16]59)
            $writer.Write([uint32]$row.Type);$writer.Write([uint16]59)
            $size=if($null -ne $row.Size){[uint32]$row.Size}else{[uint32]$row.Bytes.Length}
            $writer.Write($size);$writer.Write([uint16]59);$writer.Write([byte[]]$row.Bytes);$writer.Write([uint16]93)
        }
    }finally{$writer.Dispose();$stream.Dispose()}
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ad-gpo-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$policyRoot=Join-Path $temp 'offline'
$inf=Join-Path $policyRoot 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
$infText=@'
; UTF-16 security policy fixture
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 0
PasswordComplexity = 0
ClearTextPassword = 1
NewAdministratorName = "Renamed, Admin"
LSAAnonymousNameLookup = 1
[Kerberos Policy]
MaxTicketAge = 10
TicketValidateClient = 0
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-21-1-2-3-1100
SeDenyNetworkLogonRight =
[Registry Values]
MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,0
MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7,"LSARPC","custom,pipe"
MACHINE\Software\Fixture\Quoted=1,"a,b""c"
[Service General Setting]
ExampleService=2,"D:fixture"
'@
Write-Text $inf $infText ([Text.Encoding]::Unicode)
Write-Text (Join-Path $policyRoot 'GPT.INI') "[General]`r`nVersion=65538"
Write-Text (Join-Path $policyRoot 'root.bin') 'unparsed'
Write-Text (Join-Path $policyRoot 'Machine/Scripts/startup.cmd') '@echo fixture'
Write-Text (Join-Path $policyRoot 'Machine/Preferences/Drives/Drives.xml') '<Drives><Drive name="fixture &amp; drive" /></Drives>'
Write-Text (Join-Path $policyRoot 'User/Other.xml') '<Other><Setting value="0" /></Other>'
Write-Text (Join-Path $policyRoot 'User/Scripts/scripts.ini') "[Logon]`n0CmdLine=fixture.cmd"
$pol=Join-Path $policyRoot 'Machine/Registry.pol'
$records=@(
    @{Key='Software\Fixture';Name='String';Type=1;Bytes=[Text.Encoding]::Unicode.GetBytes("hello`0")}
    @{Key='Software\Fixture';Name='Expand';Type=2;Bytes=[Text.Encoding]::Unicode.GetBytes("%TEMP%`0")}
    @{Key='Software\Fixture';Name='Zero';Type=4;Bytes=[BitConverter]::GetBytes([uint32]0)}
    @{Key='Software\Fixture';Name='BigEndian';Type=5;Bytes=[byte[]]@(0,0,1,0)}
    @{Key='Software\Fixture';Name='Multi';Type=7;Bytes=[Text.Encoding]::Unicode.GetBytes("one`0two`0`0")}
    @{Key='Software\Fixture';Name='Qword';Type=11;Bytes=[BitConverter]::GetBytes([uint64]4294967296)}
    @{Key='Software\Fixture';Name='Binary';Type=3;Bytes=[byte[]]@(0,255,93,0)}
    @{Key='Software\Fixture';Name='**del.Obsolete';Type=0;Bytes=[byte[]]@()}
    @{Key='Software\Fixture';Name='';Type=0;Bytes=[byte[]]@()}
    @{Key='Software\Policies\Microsoft\Windows\System';Name='UserPolicyMode';Type=4;Bytes=[BitConverter]::GetBytes([uint32]2)}
)
Write-Pol $pol $records
try {
    $parsed=Read-ADAnalyzerGpo $policyRoot
    Test-Gpo 'UTF-16 INF preserves numeric zero and boolean false' {
        Assert-Equal 0 ($parsed.SecuritySettings | Where-Object Name -eq 'MinimumPasswordLength').Value
        $value=($parsed.SecuritySettings | Where-Object Name -eq 'PasswordComplexity').Value
        Assert-True ($value -is [bool] -and -not $value) 'Expected typed false'
        Assert-Equal $false ($parsed.SecuritySettings | Where-Object Name -eq 'TicketValidateClient').Value
        Assert-Equal 'Renamed, Admin' ($parsed.SecuritySettings | Where-Object Name -eq 'NewAdministratorName').Value
    }
    Test-Gpo 'privilege assignments preserve SID lists and empty assignments' {
        Assert-Equal 2 ($parsed.SecuritySettings | Where-Object Name -eq 'SeNetworkLogonRight').Value.Count
        Assert-Equal 0 @((($parsed.SecuritySettings | Where-Object Name -eq 'SeDenyNetworkLogonRight').Value)).Count
    }
    Test-Gpo 'quoted policy CSV preserves commas and escaped quotes' {
        $parts=Split-AnalyzerPolicyCsv '1,"a,b""c",0'
        Assert-Equal 3 $parts.Count;Assert-Equal 'a,b"c' $parts[1];Assert-Equal '0' $parts[2]
        Assert-Throws {Split-AnalyzerPolicyCsv '1,"unfinished'}
    }
    Test-Gpo 'security options preserve analyzer names and value types' {
        Assert-Equal $false ($parsed.SecuritySettings | Where-Object Name -eq 'Microsoft network server: Digitally sign communications (always)').Value
        Assert-Equal $true ($parsed.SecuritySettings | Where-Object Name -eq 'Network access: Allow anonymous SID/Name translation').Value
        Assert-Equal 'Elevate without prompting' ($parsed.SecuritySettings | Where-Object Name -like '*Behavior of the elevation prompt*').Value
        Assert-Equal 'Send NTLMv2 response only. Refuse LM & NTLM' ($parsed.SecuritySettings | Where-Object Name -eq 'Network security: LAN Manager authentication level').Value
        $pipes=@($parsed.SecuritySettings | Where-Object Name -eq 'Network access: Named Pipes that can be accessed anonymously')
        Assert-Equal 2 $pipes.Count;Assert-Equal 'custom,pipe' $pipes[1].Value
    }
    Test-Gpo 'Registry.pol decodes supported typed values and zero' {
        $rows=$parsed.RegistrySettings;Assert-Equal 10 $rows.Count
        Assert-Equal 'hello' ($rows | Where-Object ValueName -eq 'String').Value
        Assert-Equal '%TEMP%' ($rows | Where-Object ValueName -eq 'Expand').Value
        Assert-Equal 0 ($rows | Where-Object ValueName -eq 'Zero').Value
        Assert-Equal 256 ($rows | Where-Object ValueName -eq 'BigEndian').Value
        Assert-Equal 'one|two' (($rows | Where-Object ValueName -eq 'Multi').Value -join '|')
        Assert-Equal 4294967296 ($rows | Where-Object ValueName -eq 'Qword').Value
        Assert-Equal '00FF5D00' ([BitConverter]::ToString(($rows | Where-Object ValueName -eq 'Binary').Value).Replace('-',''))
    }
    Test-Gpo 'Registry.pol retains deletion directives and key-only entries' {
        $row=$parsed.RegistrySettings | Where-Object ValueName -eq '**del.Obsolete'
        Assert-True $row.DeletionDirective 'Deletion marker lost';Assert-Equal 0 $row.RawData.Length
        Assert-True ($parsed.RegistrySettings | Where-Object ValueName -eq '').KeyOnly 'Key-only entry lost'
    }
    Test-Gpo 'INI XML preferences and unsupported files remain visible' {
        Assert-Equal 65538 $parsed.SysvolVersion
        Assert-Equal 2 $parsed.XmlFiles.Count
        Assert-Equal 'Preferences' ($parsed.XmlFiles | Where-Object Path -like '*Drives.xml').Kind
        Assert-Equal 'fixture.cmd' ($parsed.IniSettings | Where-Object Name -eq '0CmdLine').Value
        Assert-Equal '2,"D:fixture"' ($parsed.IniSettings | Where-Object Name -eq 'ExampleService').Value
        Assert-Equal 2 $parsed.UnparsedFiles.Count
        Assert-Equal 'Metadata' ($parsed.Files | Where-Object Path -eq 'GPT.INI').Kind
    }
    Test-Gpo 'empty policy sides and empty Registry.pol are valid' {
        $empty=Join-Path $temp 'empty';$null=New-Item -ItemType Directory -Path $empty
        Assert-Equal 0 (Read-ADAnalyzerGpo $empty).Files.Count
        $emptyPol=Join-Path $empty 'Machine/Registry.pol';Write-Pol $emptyPol @()
        Assert-Equal 0 @(Read-AnalyzerRegistryPolicy $emptyPol Computer).Count
    }
    Test-Gpo 'missing root and file roots fail clearly' {
        Assert-Throws {Read-ADAnalyzerGpo (Join-Path $temp 'missing')}
        Assert-Throws {Read-ADAnalyzerGpo $pol}
    }
    foreach($case in @(
        @{Name='signature';Bytes=[byte[]]@(0,0,0,0,1,0,0,0)}
        @{Name='truncated header';Bytes=[byte[]]@(80,82,101,103)}
        @{Name='version';Bytes=[byte[]]@(80,82,101,103,2,0,0,0)}
        @{Name='truncated entry';Bytes=[byte[]]@(80,82,101,103,1,0,0,0,91,0)}
    )) {
        Test-Gpo ('Registry.pol rejects '+$case.Name) {
            $bad=Join-Path $temp 'bad.pol';[IO.File]::WriteAllBytes($bad,$case.Bytes)
            Assert-Throws {Read-AnalyzerRegistryPolicy $bad Computer}
        }
    }
    foreach($case in @(
        @{Name='oversized payload';Type=3;Bytes=[byte[]]@(1);Size=[uint32]::MaxValue}
        @{Name='odd UTF-16';Type=1;Bytes=[byte[]]@(1)}
        @{Name='invalid DWORD length';Type=4;Bytes=[byte[]]@(1,2)}
        @{Name='invalid QWORD length';Type=11;Bytes=[byte[]]@(1,2)}
    )) {
        Test-Gpo ('Registry.pol rejects '+$case.Name) {
            $bad=Join-Path $temp 'bad.pol';Write-Pol $bad @(@{Key='Software\Fixture';Name='Bad';Type=$case.Type;Bytes=$case.Bytes;Size=$case.Size})
            Assert-Throws {Read-AnalyzerRegistryPolicy $bad Computer}
        }
    }
    Test-Gpo 'XML parsing prohibits DTDs and rejects malformed documents' {
        $bad=Join-Path $temp 'unsafe.xml';Write-Text $bad '<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///unread">]><x>&leak;</x>'
        Assert-Throws {Read-AnalyzerPolicyXml $bad}
        Write-Text $bad '<broken>';Assert-Throws {Read-AnalyzerPolicyXml $bad}
    }
    $id=[guid]'11111111-1111-1111-1111-111111111111'
    $metadata=[pscustomobject]@{Id=$id;DisplayName='Fixture';Version=65538;Flags=0;Domain='example.invalid';Server='dc01.example.invalid';Links=@([pscustomobject]@{SOMPath='DC=example,DC=invalid';Enabled=$true;Enforced=$false})}
    Test-Gpo 'canonical XML preserves strings booleans SID status and raw records' {
        $xml=[xml](ConvertTo-AnalyzerGpoXml $metadata $parsed)
        Assert-Equal 'Renamed, Admin' ($xml.GPO.Computer.ExtensionData.Extension.Account | Where-Object Name -eq 'NewAdministratorName').SettingString
        Assert-Equal 'false' ($xml.GPO.Computer.ExtensionData.Extension.Account | Where-Object Name -eq 'PasswordComplexity').SettingBoolean
        $members=@(($xml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object Name -eq 'SeNetworkLogonRight').Member)
        Assert-Equal 'Administrators' $members[0].Name;Assert-Equal 'NotAttempted' $members[1].Resolution
        Assert-True ($xml.GPO.Computer.ExtensionData.Name -contains 'Registry') 'Registry records missing'
        Assert-True ($xml.GPO.Computer.ExtensionData.Name -contains 'Preferences') 'Preferences missing'
        Assert-True ($xml.GPO.Computer.ExtensionData.Name -contains 'Ini') 'Unsupported INI section missing'
        Assert-Equal 'false' $xml.GPO.VersionMismatch
    }
    # Directory mocks record every endpoint and credential; no network is used.
    $script:Queries=[Collections.ArrayList]::new()
    $credential=[pscredential]::new('EXAMPLE\reader',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    function Get-ADRootDSE {param($Server,$Credential,$ErrorAction)
        $null=$script:Queries.Add(@{Command='RootDSE';Server=$Server;Credential=$Credential})
        [pscustomobject]@{DnsHostName='dc01.example.invalid';ConfigurationNamingContext='CN=Configuration,DC=example,DC=invalid'}
    }
    function Get-ADDomain {param($Identity,$Server,$Credential,$ErrorAction)
        $null=$script:Queries.Add(@{Command='Domain';Identity=$Identity;Server=$Server;Credential=$Credential})
        [pscustomobject]@{DNSRoot='example.invalid';DistinguishedName='DC=example,DC=invalid'}
    }
    $script:PolicyObjects=@(0..3 | ForEach-Object {
        $guid=([guid]::Parse(('11111111-1111-1111-1111-{0:d12}' -f ($_+1)))).ToString('B')
        [pscustomobject]@{Name=$guid;DisplayName='Duplicate';DistinguishedName="CN=$guid,CN=Policies,CN=System,DC=example,DC=invalid";flags=$_;versionNumber=65538;gPCFileSysPath='\\untrusted.invalid\stolen';whenCreated=[datetime]'2020-01-01';whenChanged=[datetime]'2020-02-01'}
    })
    $script:SidLookupFails=$false
    function Get-ADObject {param($LDAPFilter,$Filter,$SearchBase,$Properties,$Server,$Credential,$ErrorAction)
        $null=$script:Queries.Add(@{Command='Object';Server=$Server;Credential=$Credential;Filter=$Filter;Base=$SearchBase})
        if($Filter){if($script:SidLookupFails){throw 'fixture lookup denied'};return [pscustomobject]@{sAMAccountName='PolicyReaders'}}
        if($LDAPFilter -eq '(objectClass=groupPolicyContainer)'){return $script:PolicyObjects}
        if($SearchBase -like 'CN=Sites,*'){return [pscustomobject]@{DistinguishedName='CN=Site,CN=Sites,CN=Configuration,DC=example,DC=invalid';gPLink=('[LDAP://{0};3]' -f $script:PolicyObjects[0].DistinguishedName)}}
        [pscustomobject]@{DistinguishedName='OU=People,DC=example,DC=invalid';gPLink=('[LDAP://{0};0]' -f $script:PolicyObjects[0].DistinguishedName)}
    }
    Test-Gpo 'metadata pins directory calls to the DC and forwards credentials' {
        $script:Queries.Clear();$gpos=@(Get-ADAnalyzerGpo -All -Domain 'example.invalid' -Server 'alias.example.invalid' -Credential $credential)
        Assert-Equal 4 $gpos.Count;Assert-Equal 'alias.example.invalid' $gpos[0].RequestedServer
        Assert-Equal 'dc01.example.invalid' $gpos[0].Server
        Assert-Equal 'example.invalid' ($script:Queries | Where-Object Command -eq Domain).Identity
        foreach($query in $script:Queries){Assert-True ([object]::ReferenceEquals($credential,$query.Credential)) 'Credential was dropped';if($query.Command -ne 'RootDSE'){Assert-Equal 'dc01.example.invalid' $query.Server}}
        Assert-Equal ('\\dc01.example.invalid\SYSVOL\example.invalid\Policies\'+$gpos[0].Id.ToString('B')) $gpos[0].PolicyPath
    }
    Test-Gpo 'selectors preserve duplicate names and unique GUID identity' {
        Assert-Equal 4 @(Get-ADAnalyzerGpo -Name Duplicate -Domain example.invalid).Count
        $gpo=@(Get-ADAnalyzerGpo -Guid $script:PolicyObjects[2].Name -Domain example.invalid)
        Assert-Equal 1 $gpo.Count;Assert-Equal 2 $gpo[0].Flags
    }
    Test-Gpo 'metadata flags and enabled enforced links survive XML conversion' {
        $gpos=@(Get-ADAnalyzerGpo -All -Domain example.invalid)
        Assert-Equal 'AllSettingsEnabled|UserSettingsDisabled|ComputerSettingsDisabled|AllSettingsDisabled' ($gpos.GPOStatus -join '|')
        Assert-Equal 2 $gpos[0].Links.Count
        Assert-Equal $false $gpos[0].Links[1].Enabled;Assert-Equal $true $gpos[0].Links[1].Enforced
        foreach($gpo in $gpos){$xml=[xml](ConvertTo-AnalyzerGpoXml $gpo $parsed);Assert-Equal ([string](($gpo.Flags -band 2) -eq 0)).ToLowerInvariant() $xml.GPO.Computer.Enabled;Assert-Equal ([string](($gpo.Flags -band 1) -eq 0)).ToLowerInvariant() $xml.GPO.User.Enabled}
    }
    # The drive mock maps the requested UNC to a local fixture. Real local
    # FileSystem drives exercise path resolution and owned-drive cleanup.
    $script:DriveEvents=[Collections.ArrayList]::new();$script:SmbRoot=Join-Path $temp 'sysvol'
    $copy=Join-Path $script:SmbRoot ('example.invalid/Policies/'+$id.ToString('B'))
    $null=[IO.Directory]::CreateDirectory($copy)
    Copy-Item -Path (Join-Path $policyRoot '*') -Destination $copy -Recurse
    function New-PSDrive {param($Name,$PSProvider,$Root,$Credential,$Scope,$ErrorAction,[switch]$WhatIf,[switch]$Confirm)
        $null=$script:DriveEvents.Add(@{Action='New';Name=$Name;Root=$Root;Credential=$Credential;Scope=$Scope})
        Microsoft.PowerShell.Management\New-PSDrive -Name $Name -PSProvider FileSystem -Root $script:SmbRoot -Scope Script
    }
    function Remove-PSDrive {param($Name,[switch]$Force,$ErrorAction,[switch]$WhatIf,[switch]$Confirm)
        $null=$script:DriveEvents.Add(@{Action='Remove';Name=$Name})
        Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Force
    }
    Test-Gpo 'credentialed SYSVOL reads use pinned host and remove owned drive' {
        $script:DriveEvents.Clear();$report=Get-ADAnalyzerGpoReport -Gpo $metadata -Credential $credential -AsObject
        Assert-Equal 65538 $report.Policy.SysvolVersion;Assert-Equal $false $report.VersionMismatch
        Assert-Equal 2 $script:DriveEvents.Count;Assert-Equal '\\dc01.example.invalid\SYSVOL' $script:DriveEvents[0].Root
        Assert-Equal 'Local' $script:DriveEvents[0].Scope
        Assert-True ([object]::ReferenceEquals($credential,$script:DriveEvents[0].Credential)) 'SMB credential missing'
        Assert-Equal $script:DriveEvents[0].Name $script:DriveEvents[1].Name
        Assert-True (-not (Get-PSDrive $script:DriveEvents[0].Name -ErrorAction SilentlyContinue)) 'Drive leaked'
    }
    Test-Gpo 'credentialed reports resolve custom SIDs with the same target and credential' {
        $script:Queries.Clear();$xml=[xml](Get-ADAnalyzerGpoReport -Gpo $metadata -Credential $credential)
        $member=($xml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object Name -eq SeNetworkLogonRight).Member[1]
        Assert-Equal 'PolicyReaders' $member.Name;Assert-Equal 'Resolved' $member.Resolution
        Assert-Equal 'dc01.example.invalid' $script:Queries[0].Server
        Assert-True ([object]::ReferenceEquals($credential,$script:Queries[0].Credential)) 'SID query credential missing'
        Assert-Equal "objectSid -eq 'S-1-5-21-1-2-3-1100'" $script:Queries[0].Filter
    }
    Test-Gpo 'failed SID lookup preserves the SID with an explicit status' {
        $script:SidLookupFails=$true
        try{$xml=[xml](Get-ADAnalyzerGpoReport -Gpo $metadata -Credential $credential -WarningAction SilentlyContinue)}finally{$script:SidLookupFails=$false}
        $member=($xml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object Name -eq SeNetworkLogonRight).Member[1]
        Assert-Equal 'LookupFailed' $member.Resolution;Assert-Equal 'S-1-5-21-1-2-3-1100' $member.SID
    }
    Test-Gpo 'directory SYSVOL version mismatch is returned and warned' {
        $metadata.Version=65539
        try{$report=Get-ADAnalyzerGpoReport -Gpo $metadata -Credential $credential -AsObject -WarningVariable warning -WarningAction SilentlyContinue;Assert-True $report.VersionMismatch 'Mismatch was lost';Assert-True ($warning.Count -gt 0) 'Mismatch warning missing'}finally{$metadata.Version=65538}
    }
    Test-Gpo 'SYSVOL drives are cleaned after a parser failure' {
        $script:DriveEvents.Clear();$bad=Join-Path $copy 'User/unsafe.xml';Write-Text $bad '<broken>'
        try{Assert-Throws {Get-ADAnalyzerGpoReport -Gpo $metadata -Credential $credential}}finally{Remove-Item -LiteralPath $bad}
        Assert-Equal 2 $script:DriveEvents.Count;Assert-Equal 'Remove' $script:DriveEvents[1].Action
        Assert-True (-not (Get-PSDrive $script:DriveEvents[0].Name -ErrorAction SilentlyContinue)) 'Failed report leaked drive'
    }
    Test-Gpo 'invalid metadata is rejected before creating a credentialed drive' {
        $script:DriveEvents.Clear();$metadata.Server='bad\host'
        try{Assert-Throws {Get-ADAnalyzerGpoReport -Gpo $metadata -Credential $credential}}finally{$metadata.Server='dc01.example.invalid'}
        Assert-Equal 0 $script:DriveEvents.Count
    }
    Test-Gpo 'empty multi-string remains an empty typed collection' {
        $emptyPol=Join-Path $temp 'empty-multi.pol'
        Write-Pol $emptyPol @(@{Key='Software\Fixture';Name='Multi';Type=7;Bytes=[byte[]]@(0,0,0,0)})
        $row=Read-AnalyzerRegistryPolicy $emptyPol User
        Assert-Equal 0 $row.Value.Count;Assert-True ($row.Value -is [string[]]) 'Expected an empty string array';Assert-Equal 'HKCU' $row.Hive
    }
    Test-Gpo 'access denied to a policy side is not treated as an absent side' {
        function script:Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction)
            if($LiteralPath -like '*Machine'){throw [UnauthorizedAccessException]::new('fixture access denied')}
            Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        }
        try{Assert-Throws {Read-ADAnalyzerGpo $policyRoot}}finally{Remove-Item Function:Get-Item}
    }
    Test-Gpo 'auxiliary templates and registry files are not treated as active policy' {
        Write-Text (Join-Path $policyRoot 'Machine/Scripts/GptTmpl.inf') "[System Access]`nMinimumPasswordLength=99"
        Write-Text (Join-Path $policyRoot 'Machine/Scripts/Registry.pol') 'not an active registry policy'
        $result=Read-ADAnalyzerGpo $policyRoot
        Assert-Equal 1 @($result.SecuritySettings | Where-Object Name -eq MinimumPasswordLength).Count
        Assert-Equal 0 ($result.SecuritySettings | Where-Object Name -eq MinimumPasswordLength).Value
        Assert-Equal $false ($result.IniSettings | Where-Object Value -eq 99).Analyzed
        Assert-True (@($result.UnparsedFiles | Where-Object Path -like '*Scripts*Registry.pol').Count -eq 1) 'Auxiliary binary was not inventoried'
    }
    Test-Gpo 'uncredentialed reports rebuild the trusted path without creating drives' {
        $reader=(Get-Command Read-ADAnalyzerGpo).ScriptBlock
        function script:Read-ADAnalyzerGpo {param($Path) $script:ReadPath=$Path;return $script:ParsedFixture}
        $script:ParsedFixture=$parsed;$script:DriveEvents.Clear()
        try {
            $null=Get-ADAnalyzerGpoReport -Gpo $metadata -AsObject
            Assert-Equal ('\\dc01.example.invalid\SYSVOL\example.invalid\Policies\'+$id.ToString('B')) $script:ReadPath
            Assert-Equal 0 $script:DriveEvents.Count
        } finally {Set-Item Function:script:Read-ADAnalyzerGpo $reader}
    }
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -WhatIf:$false -Confirm:$false
}
Write-Host ("{0} GPO-reader tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
