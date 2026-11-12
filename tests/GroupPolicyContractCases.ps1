Invoke-ClassTest 'misplaced INF entries survive canonical and legacy raw INI projection' {
    $r=Invoke-ClassScope @'
$root=Join-Path ([IO.Path]::GetTempPath()) ('ad-legacy-section-'+[guid]::NewGuid().ToString('N'))
try{
    $directory=Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit';$null=[IO.Directory]::CreateDirectory($directory)
    $path=Join-Path $directory 'GptTmpl.inf';[IO.File]::WriteAllText($path,"[Kerberos Policy]`nPasswordComplexity=1",[Text.Encoding]::Unicode)
    $policy=Read-ADAnalyzerGpo $root
    [xml]$xml=ConvertTo-AnalyzerGpoXml -Gpo ([pscustomobject]@{Id=[guid]::Empty;Flags=0}) -Parsed $policy
    $owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault()
    $extension=@($xml.GPO.Computer.ExtensionData | Where-Object Name -eq Ini)[0];$rows=$owner.GetRawExtension($extension)
    [pscustomobject]@{Count=$rows.Count;Extension=$rows[0].'cfg.extension';Name=$rows[0].'property.setting.name';Value=$rows[0].'property.setting.value'}
}finally{if([IO.Directory]::Exists($root)){[IO.Directory]::Delete($root,$true)}}
'@
    Assert-ClassEqual 1 $r.Count;Assert-ClassEqual Ini $r.Extension;Assert-ClassEqual '1' $r.Value
    Assert-ClassTrue ($r.Name.Replace('\','/') -eq 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf: [Kerberos Policy] PasswordComplexity') 'Legacy raw setting lost its source/section identity'
}
Invoke-ClassTest 'legacy GPO reports findings and exports retain boolean secret detection and location' {
    $r=Invoke-ClassScope @'
$previous=$script:FixturePolicyXml;$path=Join-Path ([IO.Path]::GetTempPath()) ('ad-secret-report-'+[guid]::NewGuid().ToString('N')+'.csv')
try{
    $security=@();$registry=@();$ini=@()
    foreach($present in @($true,$false)){
        foreach($kind in @('Account','SecurityOptions')){$security+=@([pscustomobject]@{Scope='Computer';Kind=$kind;Name='MACHINE\Software\Fixture\DefaultPassword';SecretPresent=$present;Source='Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'})}
        $registry+=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='DefaultPassword';SecretPresent=$present;Type=1;Source='Machine/Registry.pol'})
        $ini+=@([pscustomobject]@{Scope='User';Section='Fixture';Name='Password';SecretPresent=$present;Source='User/settings.ini';Analyzed=$false})
    }
    $security+=@([pscustomobject]@{Scope='Computer';Kind='Account';Name='MinimumPasswordLength';Value=16L;Source='Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'})
    $registry+=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='Enabled';Type=4;Value=0;Source='Machine/Registry.pol'})
    $policy=[pscustomobject]@{SecuritySettings=$security;RegistrySettings=$registry;IniSettings=$ini;XmlFiles=@();Files=@()}
    $xml=ConvertTo-AnalyzerGpoXml -Gpo ([pscustomobject]@{Id=[guid]::Empty;Flags=0;Links=@()}) -Parsed $policy
    $script:FixturePolicyXml=$xml
    $environment=Get-ADEnvironment -Class GroupPolicy -FQDN target.example.invalid
    $rows=@(foreach($group in $environment.GroupPolicy.Report.Values){foreach($row in $group){$row}})
    $before=ConvertTo-Json -InputObject $rows -Depth 50 -Compress
    $indicators=@($rows | Where-Object {$_.'property.setting.secretPresent' -is [bool]})
    $positive=@($indicators | Where-Object {$_.'property.setting.secretPresent'})
    $negative=@($indicators | Where-Object {-not $_.'property.setting.secretPresent'})
    $exposures=@($environment.GroupPolicy.Finding | Where-Object finding -eq 'Defect - Stored Secret')
    $aggregate=@($environment.Finding | ForEach-Object {$_.object | ConvertFrom-Json})
    $environment.GroupPolicy.Finding.ExportCSV($path);$csv=@(Import-Csv -LiteralPath $path)
    [pscustomobject]@{Rows=$rows.Count;Positive=$positive.Count;Negative=$negative.Count;Findings=$exposures.Count;NullValues=(@($indicators | Where-Object {$null -ne $_.'property.setting.value'}).Count -eq 0);SecuritySources=@($indicators | Where-Object {$_.'property.setting.source' -eq 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'}).Count;IniLocation=@($indicators | Where-Object {$_.'property.setting.name'.Replace('\','/') -like 'User/settings.ini:*'}).Count;NormalFlags=@($rows | Where-Object {$null -eq $_.'property.setting.secretPresent'}).Count;CsvFlags=(@($csv | Where-Object {$_.'property.setting.secretPresent' -eq 'True'}).Count);AggregateFlags=@($aggregate | Where-Object {$_.'property.setting.secretPresent' -is [bool] -and $_.'property.setting.secretPresent'}).Count;Unchanged=($before -ceq (ConvertTo-Json -InputObject $rows -Depth 50 -Compress));XmlUnchanged=($xml -ceq $script:FixturePolicyXml)}
}finally{$script:FixturePolicyXml=$previous;if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
'@
    Assert-ClassEqual 10 $r.Rows;Assert-ClassEqual 4 $r.Positive;Assert-ClassEqual 4 $r.Negative
    Assert-ClassEqual 4 $r.Findings;Assert-ClassEqual $true $r.NullValues;Assert-ClassEqual 4 $r.SecuritySources
    Assert-ClassEqual 2 $r.IniLocation;Assert-ClassEqual 2 $r.NormalFlags;Assert-ClassEqual 4 $r.CsvFlags;Assert-ClassEqual 4 $r.AggregateFlags
    Assert-ClassEqual $true $r.Unchanged;Assert-ClassEqual $true $r.XmlUnchanged
}
Invoke-ClassTest 'legacy presence markers suppress value nodes reject malformed flags and reset normal rows' {
    $r=Invoke-ClassScope @'
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['property.setting.secretPresent']=$true;$owner.Record['property.setting.source']='stale'
$xml=[xml]'<ExtensionData><Name>Registry</Name><Extension><Record><Name>HKLM\Fixture\DefaultPassword</Name><SecretPresent>true</SecretPresent><Value>unit13-never-retain</Value></Record><Record><Name>HKLM\Fixture\Password</Name><SecretPresent>unknown</SecretPresent><Value>unit13-never-retain</Value></Record><Record><Name>HKLM\Fixture\Enabled</Name><Value>0</Value></Record></Extension></ExtensionData>'
$before=$xml.OuterXml;$rows=$owner.GetRawExtension($xml.DocumentElement)
[pscustomobject]@{Count=$rows.Count;Present=$rows[0].'property.setting.secretPresent';Value=$rows[0].'property.setting.value';Invalid=$rows[1].'property.setting.valid';InvalidLabel=([GroupPolicyObject]::Analyze($rows[1]))[0].finding;NormalFlag=$rows[2].'property.setting.secretPresent';NormalSource=$rows[2].'property.setting.source';NormalValue=$rows[2].'property.setting.value';Safe=(($rows | ConvertTo-Json -Depth 30) -notmatch 'unit13-never-retain|REDACTED');Unchanged=($before -ceq $xml.OuterXml)}
'@
    Assert-ClassEqual 3 $r.Count;Assert-ClassEqual $true $r.Present;Assert-ClassEqual $null $r.Value
    Assert-ClassEqual $false $r.Invalid;Assert-ClassEqual 'Validate - Invalid stored policy value' $r.InvalidLabel
    Assert-ClassEqual $null $r.NormalFlag;Assert-ClassEqual $null $r.NormalSource;Assert-ClassEqual '0' $r.NormalValue
    Assert-ClassEqual $true $r.Safe;Assert-ClassEqual $true $r.Unchanged
}
Invoke-ClassTest 'wide password-policy records retain presence without copying tagged value nodes' {
    $r=Invoke-ClassScope @'
$null=[PasswordPolicy]::Initialize();$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.name']='Presence fixture'
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><Account><Name>DefaultPassword</Name><SecretPresent>true</SecretPresent><SettingString>unit13-wide-never-retain</SettingString></Account><Account><Name>Password</Name><SecretPresent>false</SecretPresent><SettingString>unit13-wide-never-retain</SettingString></Account><Account><Name>Credential</Name><SecretPresent>unknown</SecretPresent><SettingString>unit13-wide-never-retain</SettingString></Account><Account><Name>MinimumPasswordLength</Name><SettingNumber>16</SettingNumber></Account></Extension></ExtensionData>'
$rows=$owner.GetSecurityExtension($xml.DocumentElement);$wide=[PasswordPolicy]::GetInstance()['Presence fixture']
[pscustomobject]@{Present=$wide.'DefaultPassword.SecretPresent';Absent=$wide.'Password.SecretPresent';Invalid=$wide.'Credential.ValueValid';Neighbor=$wide.MinimumPasswordLength;Safe=(($wide | ConvertTo-Json -Depth 30) -notmatch 'unit13-wide-never-retain|REDACTED');FlatCount=$rows.Count}
'@
    Assert-ClassEqual $true $r.Present;Assert-ClassEqual $false $r.Absent;Assert-ClassEqual $false $r.Invalid
    Assert-ClassEqual 16 $r.Neighbor;Assert-ClassEqual $true $r.Safe;Assert-ClassEqual 4 $r.FlatCount
}
Invoke-ClassTest 'singleton GPO account settings retain zero and extension metadata' {
    $r=Invoke-ClassScope @'
$null=[PasswordPolicy]::Initialize()
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.name']='FixturePolicy'
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><Account><Name>MinimumPasswordLength</Name><SettingNumber>0</SettingNumber></Account></Extension></ExtensionData>'
$rows=$owner.GetSecurityExtension($xml.DocumentElement)
[pscustomobject]@{Count=$rows.Count;Name=$rows[0].'property.setting.name';Value=$rows[0].'property.setting.value';Extension=$rows[0].'cfg.extension';Policy=[PasswordPolicy]::GetInstance()['FixturePolicy'].MinimumPasswordLength}
'@
    Assert-ClassEqual 1 $r.Count
    Assert-ClassEqual 'MinimumPasswordLength' $r.Name
    Assert-ClassEqual 0 $r.Value
    Assert-ClassEqual 'Security' $r.Extension
    Assert-ClassEqual 0 $r.Policy
}

Invoke-ClassTest 'multiple GPO account settings retain false boolean values' {
    $r=Invoke-ClassScope @'
$null=[PasswordPolicy]::Initialize()
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.name']='FixturePolicy'
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><Account><Name>ClearTextPassword</Name><SettingBoolean>false</SettingBoolean></Account><Account><Name>MinimumPasswordLength</Name><SettingNumber>12</SettingNumber></Account></Extension></ExtensionData>'
$rows=$owner.GetSecurityExtension($xml.DocumentElement)
[pscustomobject]@{Count=$rows.Count;Value=$rows[0].'property.setting.value';Policy=[PasswordPolicy]::GetInstance()['FixturePolicy'].ClearTextPassword}
'@
    Assert-ClassEqual 2 $r.Count
    Assert-ClassEqual $false $r.Value
    Assert-ClassEqual $false $r.Policy
}

Invoke-ClassTest 'singleton GPO security options retain display names and false values' {
    $r=Invoke-ClassScope @'
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault()
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><SecurityOptions><Display><Name>Fixture option</Name><DisplayBoolean>false</DisplayBoolean></Display></SecurityOptions></Extension></ExtensionData>'
$rows=$owner.GetSecurityExtension($xml.DocumentElement)
[pscustomobject]@{Count=$rows.Count;Name=$rows[0].'property.setting.name';Value=$rows[0].'property.setting.value';Extension=$rows[0].'cfg.extension'}
'@
    Assert-ClassEqual 1 $r.Count
    Assert-ClassEqual 'Fixture option' $r.Name
    Assert-ClassEqual $false $r.Value
    Assert-ClassEqual 'Security' $r.Extension
}

Invoke-ClassTest 'singleton GPO user rights retain member names and SID fallback' {
    $r=Invoke-ClassScope @'
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault()
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><UserRightsAssignment><Name>SeNetworkLogonRight</Name><Member><Name>Fixture Operator</Name><SID>S-1-5-32-544</SID></Member><Member><SID>S-1-5-32-545</SID></Member></UserRightsAssignment></Extension></ExtensionData>'
$rows=$owner.GetSecurityExtension($xml.DocumentElement)
[pscustomobject]@{Count=$rows.Count;First=$rows[0].'property.setting.value';Second=$rows[1].'property.setting.value';Right=$rows[0].'property.setting.right';Sid=$rows[0].'property.setting.sid';Empty=$rows[0].'property.setting.empty'}
'@
    Assert-ClassEqual 2 $r.Count
    Assert-ClassEqual 'Fixture Operator' $r.First
    Assert-ClassEqual 'S-1-5-32-545' $r.Second
    Assert-ClassEqual 'SeNetworkLogonRight' $r.Right
    Assert-ClassEqual 'S-1-5-32-544' $r.Sid
    Assert-ClassEqual $false $r.Empty
}

Invoke-ClassTest 'legacy user-right approval follows exact SID identity across names and resolution states' {
    $r=Invoke-ClassScope @'
$script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile
$script:ADAnalyzerLegacyProfile.Policy.AllowedUserRightSids=@{SeDebugPrivilege=@('S-1-5-32-544')}
try {
    $owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.linked.ou']='Domain Controllers'
    $xml=[xml]'<ExtensionData><Name>Security</Name><Extension><UserRightsAssignment><Name>SeDebugPrivilege</Name><Member><Name>Administrateurs</Name><SID>S-1-5-32-544</SID></Member><Member><Name>NotAdministrators</Name><SID>S-1-5-21-1-2-3-1100</SID></Member><Member><Name>S-1-5-32-544</Name><SID>S-1-5-21-1-2-3-1100</SID></Member><Member><SID>S-1-5-32-544</SID><Resolution>LookupFailed</Resolution></Member></UserRightsAssignment></Extension></ExtensionData>'
    $rows=$owner.GetSecurityExtension($xml.DocumentElement)
    foreach($row in $rows){[pscustomobject]@{Display=$row.'property.setting.value';Labels=@([GroupPolicyObject]::Analyze($row) | ForEach-Object finding)}}
}finally{$script:ADAnalyzerLegacyProfile=$null}
'@
    Assert-ClassEqual 4 $r.Count
    Assert-ClassEqual 'Administrateurs' $r[0].Display
    Assert-ClassEqual 0 $r[0].Labels.Count
    Assert-ClassEqual 'Defect - Invalid UserRightsAssignment' $r[1].Labels[0]
    Assert-ClassEqual 'Defect - Invalid UserRightsAssignment' $r[2].Labels[0]
    Assert-ClassEqual 0 $r[3].Labels.Count
}

Invoke-ClassTest 'legacy user-right missing identity and malformed allowlists require validation' {
    $r=Invoke-ClassScope @'
$cases=@(
    @{Rights=@{};Sid='S-1-5-32-544';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-32-544')};Sid='';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-32-544')};Sid='S-1-bad';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=$null};Sid='S-1-5-32-544';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@{Sid='S-1-5-32-544'}};Sid='S-1-5-32-544';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@(@('S-1-5-32-544','S-1-5-32-545'), 'S-1-5-32-546')};Sid='S-1-5-32-544';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-*')};Sid='S-1-5-32-544';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-4294967296')};Sid='S-1-5-4294967296';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-281474976710656-1')};Sid='S-1-281474976710656-1';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-32-544')};Sid='S-1-5-4294967296';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-0xffffffffffff-4294967295')};Sid='S-1-0xffffffffffff-4294967295';Prefix=''}
    @{Rights=@{SeDebugPrivilege=@('S-1-4294967295-4294967295')};Sid='S-1-4294967295-4294967295';Prefix=''}
    @{Rights=@{SeDebugPrivilege=@('S-1-4294967296-1')};Sid='S-1-4294967296-1';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-32-544')};Sid=('S-1-5'+('-1'*16));Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-32-544')};Sid=('S-1-'+[char]0x0665+'-1');Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege=@('S-1-5-0544')};Sid='S-1-5-0544';Prefix='Validate -'}
    @{Rights=@{SeDebugPrivilege='S-1-5-32-544'};Sid='S-1-5-32-544';Prefix=''}
    @{Rights=@{SeDebugPrivilege=@()};Sid='S-1-5-32-544';Prefix='Defect -'}
)
try{
    foreach($case in $cases){
        $script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile;$script:ADAnalyzerLegacyProfile.Policy.AllowedUserRightSids=$case.Rights
        $row=[pscustomobject]@{'ext.property.name'='UserRightsAssignment';'gpo.linked.ou'='Domain Controllers';'property.setting.name'='Debug programs (SeDebugPrivilege)';'property.setting.value'='Administrators';'property.setting.right'='SeDebugPrivilege';'property.setting.sid'=$case.Sid;'property.setting.empty'=$false}
        $findings=[GroupPolicyObject]::Analyze($row)
        [pscustomobject]@{Expected=$case.Prefix;Count=$findings.Count;Label=($findings | Select-Object -First 1).finding}
    }
    $row.'property.setting.right'=$null
    [pscustomobject]@{Expected='Validate -';Count=([GroupPolicyObject]::Analyze($row)).Count;Label=([GroupPolicyObject]::Analyze($row))[0].finding}
}finally{$script:ADAnalyzerLegacyProfile=$null}
'@
    foreach($case in $r){
        if($case.Expected){Assert-ClassEqual 1 $case.Count;Assert-ClassTrue ($case.Label.StartsWith($case.Expected)) $case.Label}
        else{Assert-ClassEqual 0 $case.Count}
    }
}

Invoke-ClassTest 'legacy user-right empty assignment differs from a malformed Member and preserves scope' {
    $r=Invoke-ClassScope @'
$script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile
$script:ADAnalyzerLegacyProfile.Policy.AllowedUserRightSids=@{SeDebugPrivilege=@()}
try{
    $owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.linked.ou']='Domain Controllers'
    $xml=[xml]'<ExtensionData><Name>Security</Name><Extension><UserRightsAssignment><Name>SeDebugPrivilege</Name></UserRightsAssignment><UserRightsAssignment><Name>SeDebugPrivilege</Name><Member /></UserRightsAssignment></Extension></ExtensionData>'
    $rows=$owner.GetSecurityExtension($xml.DocumentElement)
    $result=[pscustomobject]@{Count=$rows.Count;Empty=$rows[0].'property.setting.empty';Malformed=$rows[1].'property.setting.empty';EmptyFindings=[GroupPolicyObject]::Analyze($rows[0]).Count;MalformedLabel=([GroupPolicyObject]::Analyze($rows[1]))[0].finding;OutsideFindings=0}
    $rows[1].'gpo.linked.ou'='Workstations';$result.OutsideFindings=[GroupPolicyObject]::Analyze($rows[1]).Count
    $result
}finally{$script:ADAnalyzerLegacyProfile=$null}
'@
    Assert-ClassEqual 2 $r.Count;Assert-ClassEqual $true $r.Empty;Assert-ClassEqual $false $r.Malformed
    Assert-ClassEqual 0 $r.EmptyFindings
    Assert-ClassTrue ($r.MalformedLabel -like 'Validate -*') $r.MalformedLabel
    Assert-ClassEqual 0 $r.OutsideFindings
}

Invoke-ClassTest 'empty GPO user-right assignments remain explicit records' {
    $r=Invoke-ClassScope @'
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault()
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><UserRightsAssignment><Name>SeNetworkLogonRight</Name></UserRightsAssignment></Extension></ExtensionData>'
$rows=$owner.GetSecurityExtension($xml.DocumentElement)
[pscustomobject]@{Count=$rows.Count;Value=$rows[0].'property.setting.value';Name=$rows[0].'property.setting.name'}
'@
    Assert-ClassEqual 1 $r.Count
    Assert-ClassEqual $null $r.Value
    Assert-ClassTrue ($r.Name -match 'SeNetworkLogonRight') 'Expected a named assignment record'
}

Invoke-ClassTest 'full GPO report pipeline produces configuration and password-policy findings' {
    $r=Invoke-ClassScope @'
$script:FixturePolicyXml='<GPO><ReadTime>2026-01-01T00:00:00</ReadTime><Computer><Enabled>true</Enabled><ExtensionData><Name>Security</Name><Extension><Account><Name>MinimumPasswordLength</Name><SettingNumber>0</SettingNumber></Account></Extension></ExtensionData></Computer><User><Enabled>true</Enabled></User></GPO>'
try {
    $environment=Get-ADEnvironment -Class GroupPolicy -FQDN 'target.example.invalid'
    [pscustomobject]@{Reports=$environment.GroupPolicy.Report.Count;Findings=$environment.GroupPolicy.Finding.Count;Policies=$environment.Domain.PasswordPolicy.Count;Aggregate=$environment.Finding.Count}
} finally {$script:FixturePolicyXml=$null}
'@
    Assert-ClassEqual 1 $r.Reports
    Assert-ClassTrue ($r.Findings -gt 0) 'Expected configured password-policy findings'
    Assert-ClassEqual 1 $r.Policies
    Assert-ClassTrue ($r.Aggregate -gt 0) 'Expected findings in the global aggregate'
}

Invoke-ClassTest 'self-contained XML feeds account security registry and preference records' {
    $r=Invoke-ClassScope @'
$null=[PasswordPolicy]::Initialize()
$gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';DisplayName='Fixture';Version=1;Flags=0;Links=@()}
$policy=[pscustomobject]@{
    SysvolVersion=1;Files=@();IniSettings=@()
    SecuritySettings=@(
        [pscustomobject]@{Scope='Computer';Kind='Account';Name='MinimumPasswordLength';Value=[long]0}
        [pscustomobject]@{Scope='Computer';Kind='Account';Name='NewAdministratorName';Value='Fixture Admin'}
        [pscustomobject]@{Scope='Computer';Kind='SecurityOptions';Name='Microsoft network server: Digitally sign communications (always)';Value=$false}
    )
    RegistrySettings=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Policies\Microsoft\Windows\System';ValueName='UserPolicyMode';Type=4;Value=2})
    XmlFiles=@([pscustomobject]@{Scope='Computer';Kind='Preferences';Path='Machine/Preferences/Drives.xml';Xml='<Drives />'})
}
$xml=[xml](ConvertTo-AnalyzerGpoXml $gpo $policy)
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.name']='Fixture';$owner.Record['gpo.id']=$gpo.Id.ToString()
$rows=[List]::new()
foreach($ext in $xml.GPO.Computer.ExtensionData){$rows.AddItem($owner.ExpandExtensionData($ext))}
$signing=$rows | Where-Object 'property.setting.name' -eq 'Microsoft network server: Digitally sign communications (always)'
[pscustomobject]@{Count=$rows.Count;Rename=($rows | Where-Object 'property.setting.name' -eq NewAdministratorName).'property.setting.value';SigningFindings=[GroupPolicyObject]::Analyze($signing).Count;Loopback=[GroupPolicyObject]::GetLoopback($xml.GPO.Computer.ExtensionData);Preference=($rows | Where-Object 'cfg.extension' -eq Preferences).'property.setting.value'}
'@
    Assert-ClassEqual 5 $r.Count
    Assert-ClassEqual 'Fixture Admin' $r.Rename
    Assert-ClassTrue ($r.SigningFindings -gt 0) 'Expected disabled-signing finding from self-contained XML'
    Assert-ClassEqual 'Enabled(Replace)' $r.Loopback
    Assert-ClassEqual '<Drives />' $r.Preference
}

Invoke-ClassTest 'unattempted SID lookup stays visible without an unresolvable defect' {
    $r=Invoke-ClassScope @'
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault()
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><UserRightsAssignment><Name>SeNetworkLogonRight</Name><Member><SID>S-1-5-21-1-2-3-1100</SID><Resolution>NotAttempted</Resolution></Member></UserRightsAssignment></Extension></ExtensionData>'
$row=$owner.GetSecurityExtension($xml.DocumentElement)[0]
[pscustomobject]@{Value=$row.'property.setting.value';Status=$row.'property.setting.parameter';Findings=[GroupPolicyObject]::Analyze($row).Count}
'@
    Assert-ClassEqual 'S-1-5-21-1-2-3-1100' $r.Value
    Assert-ClassEqual 'SID resolution: NotAttempted' $r.Status
    Assert-ClassEqual 0 $r.Findings
}

Invoke-ClassTest 'GPO and password policy tables retain duplicate display names by GUID' {
    $r=Invoke-ClassScope @'
$null=[PasswordPolicy]::Initialize();$table=[GroupPolicyTable]::SetDefault()
foreach($id in @('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222')) {
    $record=[GroupPolicyObject]::SetDefault();$record['gpo.name']='Duplicate';$record['gpo.id']=$id
    $xml=[xml]'<ExtensionData><Name>Security</Name><Extension><Account><Name>MinimumPasswordLength</Name><SettingNumber>0</SettingNumber></Account></Extension></ExtensionData>'
    $owner=[GroupPolicyObject]::SetDefault();$owner.Record=$record
    $rows=$owner.GetSecurityExtension($xml.DocumentElement);$table[$id]=$rows
}
[pscustomobject]@{Key=$table.Properties.Key;Reports=$table.Count;PasswordPolicies=[PasswordPolicy]::GetInstance().Count}
'@
    Assert-ClassEqual 'gpo.id' $r.Key
    Assert-ClassEqual 2 $r.Reports
    Assert-ClassEqual 2 $r.PasswordPolicies
}

Invoke-ClassTest 'credentialed environment forwards credentials to GPO collection and report reads' {
    $r=Invoke-ClassScope @'
$credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
$null=Get-ADEnvironment -Class GroupPolicy -FQDN 'target.example.invalid' -Credential $credential
[object]::ReferenceEquals($credential,$script:GpoQueryCredential) -and [object]::ReferenceEquals($credential,$script:GpoReportCredential)
'@
    Assert-ClassTrue $r 'Environment did not forward GPO credentials'
}

Invoke-ClassTest 'unreadable GPO files produce an explicit finding without dropping metadata' {
    $r=Invoke-ClassScope @'
$script:FailGpoRead=$true
try {
    $environment=Get-ADEnvironment -Class GroupPolicy -FQDN 'target.example.invalid' -WarningAction SilentlyContinue
    [pscustomobject]@{Policies=$environment.GroupPolicy.Data.Count;Reports=$environment.GroupPolicy.Report.Count;Error=($environment.GroupPolicy.Finding | Where-Object finding -eq 'Error - GPO report unreadable').ReadError}
}finally{$script:FailGpoRead=$false}
'@
    Assert-ClassEqual 1 $r.Policies
    Assert-ClassEqual 0 $r.Reports
    Assert-ClassEqual 'fixture unreadable SYSVOL' $r.Error
}

Invoke-ClassTest 'empty anonymous lists and required LDAP signing do not trigger false findings' {
    $r=Invoke-ClassScope @'
$count=0
foreach($name in @('Network access: Named Pipes that can be accessed anonymously','Network access: Shares that can be access anonymously','Network security: LDAP client signing requirements')) {
    $row=[pscustomobject]@{'ext.property.name'='SecurityOptions';'property.setting.name'=$name;'property.setting.value'=$(if($name -like '*LDAP*'){'Require signing'}else{''})}
    $count += [GroupPolicyObject]::Analyze($row).Count
}
$count
'@
    Assert-ClassEqual 0 $r
}

Invoke-ClassTest 'legacy account rules distinguish disabled lockout and administrator unlock' {
    $r=Invoke-ClassScope @'
$disabled=[pscustomobject]@{'ext.property.name'='Account';'property.setting.name'='LockoutBadCount';'property.setting.value'=0}
$manual=[pscustomobject]@{'ext.property.name'='Account';'property.setting.name'='LockoutDuration';'property.setting.value'=-1}
[pscustomobject]@{Disabled=[GroupPolicyObject]::Analyze($disabled).Count;Manual=[GroupPolicyObject]::Analyze($manual).Count}
'@
    Assert-ClassEqual 1 $r.Disabled
    Assert-ClassEqual 0 $r.Manual
}

Invoke-ClassTest 'legacy policy analysis honors configurable LM and LDAP requirements' {
    $r=Invoke-ClassScope @'
$lm=[pscustomobject]@{'ext.property.name'='SecurityOptions';'property.setting.name'='Network security: LAN Manager authentication level';'property.setting.value'='Send NTLMv2 response only'}
$ldap=[pscustomobject]@{'ext.property.name'='SecurityOptions';'property.setting.name'='Network security: LDAP client signing requirements';'property.setting.value'='Negotiate signing'}
$strict=[GroupPolicyObject]::Analyze($lm).Count
$script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile
$script:ADAnalyzerLegacyProfile.Policy.MinimumLmCompatibilityLevel=3;$script:ADAnalyzerLegacyProfile.Policy.RequireLdapClientSigning=$false
try{[pscustomobject]@{Strict=$strict;ConfiguredLm=[GroupPolicyObject]::Analyze($lm).Count;ConfiguredLdap=[GroupPolicyObject]::Analyze($ldap).Count}}finally{$script:ADAnalyzerLegacyProfile=$null}
'@
    Assert-ClassEqual 1 $r.Strict
    Assert-ClassEqual 0 $r.ConfiguredLm
    Assert-ClassEqual 0 $r.ConfiguredLdap
}

Invoke-ClassTest 'invalid flag metadata and raw values survive canonical flat and aggregate reports' {
    $results=Invoke-ClassScope @'
foreach($token in @('true','')){
    $null=[PasswordPolicy]::Initialize()
    $id='11111111-1111-1111-1111-111111111111'
    $gpo=[pscustomobject]@{Id=[guid]$id;Flags=0;Links=@();Version=1}
    $policy=[pscustomobject]@{SysvolVersion=1;Files=@();IniSettings=@();RegistrySettings=@();XmlFiles=@();SecuritySettings=@(
        [pscustomobject]@{Scope='Computer';Kind='Account';Name='PasswordComplexity';Value=$token;ValueValid=$false}
        [pscustomobject]@{Scope='Computer';Kind='Account';Name='MinimumPasswordLength';Value=16L}
        [pscustomobject]@{Scope='Computer';Kind='Account';Name='ClearTextPassword';Value=$false;ValueValid=$true}
        [pscustomobject]@{Scope='Computer';Kind='SecurityOptions';Name='Network access: Allow anonymous SID/Name translation';Value='';ValueValid=$false}
    )}
    $xml=[xml](ConvertTo-AnalyzerGpoXml -Gpo $gpo -Parsed $policy)
    $owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.name']='Flag fixture';$owner.Record['gpo.id']=$id
    $owner.Record['property.setting.valid']=$false
    $rows=[List]::new();foreach($extension in $xml.GPO.Computer.ExtensionData){$rows.AddItem($owner.ExpandExtensionData($extension))}
    $bad=$rows | Where-Object 'property.setting.name' -eq PasswordComplexity
    $neighbor=$rows | Where-Object 'property.setting.name' -eq MinimumPasswordLength
    $anonymous=$rows | Where-Object 'property.setting.name' -eq 'Network access: Allow anonymous SID/Name translation'
    $wide=[PasswordPolicy]::GetInstance()[$id]
    $flat=[System.Collections.Specialized.OrderedDictionary]::new();foreach($property in $bad.PSObject.Properties){$flat[$property.Name]=$property.Value}
    [pscustomobject]@{
        Expected=$token;Flat=$bad.'property.setting.value';Wide=$wide.PasswordComplexity;Valid=$bad.'property.setting.valid';WideValid=$wide.'PasswordComplexity.ValueValid'
        MarkerCount=$xml.SelectNodes('//ValueValid[.="false"]').Count
        Finding=([GroupPolicyObject]::Analyze($bad))[0].finding
        OtherFinding=([PasswordPolicyObject]::Analyze($flat))[0].finding
        Neighbor=$neighbor.'property.setting.value';NeighborValid=$neighbor.'property.setting.valid'
        EmptyType=($anonymous.'property.setting.value' -is [string]);EmptyValue=$anonymous.'property.setting.value'
        AnonymousFinding=([GroupPolicyObject]::Analyze($anonymous))[0].finding;GoodFlag=$wide.ClearTextPassword;GoodValid=$wide.'ClearTextPassword.ValueValid'
    }
}
'@
    foreach($r in $results){
        Assert-ClassEqual $r.Expected $r.Flat;Assert-ClassEqual $r.Expected $r.Wide
        Assert-ClassEqual $false $r.Valid;Assert-ClassEqual $false $r.WideValid;Assert-ClassEqual 2 $r.MarkerCount
        foreach($label in @($r.Finding,$r.OtherFinding,$r.AnonymousFinding)){Assert-ClassEqual 'Validate - Invalid stored policy value' $label}
        Assert-ClassEqual 16 $r.Neighbor;Assert-ClassEqual $null $r.NeighborValid
        Assert-ClassEqual $true $r.EmptyType;Assert-ClassEqual '' $r.EmptyValue
        Assert-ClassEqual $false $r.GoodFlag;Assert-ClassEqual $true $r.GoodValid
    }
}
Invoke-ClassTest 'unmarked duplicate values clear prior aggregate validity and CSV retains later validity columns' {
    $r=Invoke-ClassScope @'
$null=[PasswordPolicy]::Initialize()
$xml=[xml]'<ExtensionData><Name>Security</Name><Extension><Account><Name>PasswordComplexity</Name><SettingString>bad</SettingString><ValueValid>false</ValueValid></Account><Account><Name>PasswordComplexity</Name><SettingBoolean>true</SettingBoolean></Account></Extension></ExtensionData>'
$owner=[GroupPolicyObject]::SetDefault();$owner.Record=[GroupPolicyObject]::SetDefault();$owner.Record['gpo.name']='First';$owner.Record['gpo.id']='11111111-1111-1111-1111-111111111111'
$rows=$owner.GetSecurityExtension($xml.DocumentElement);$wide=[PasswordPolicy]::GetInstance()['11111111-1111-1111-1111-111111111111']
$first=[PasswordPolicyObject]::Initialize(@(([xml]'<Account><Name>MinimumPasswordLength</Name><SettingNumber>16</SettingNumber></Account>').DocumentElement),$owner.Record)
$invalid=[PasswordPolicyObject]::Initialize(@(([xml]'<Account><Name>PasswordComplexity</Name><SettingString>bad</SettingString><ValueValid>false</ValueValid></Account>').DocumentElement),$owner.Record)
$path=Join-Path ([IO.Path]::GetTempPath()) ('ad-validity-csv-'+[guid]::NewGuid().ToString('N')+'.csv')
try{
    [Export]::CSV(@([pscustomobject]$first,[pscustomobject]$invalid),$path);$csv=@(Import-Csv -LiteralPath $path)
    [pscustomobject]@{Value=$wide.PasswordComplexity;Valid=$wide.'PasswordComplexity.ValueValid';FirstValid=$rows[0].'property.setting.valid';SecondValid=$rows[1].'property.setting.valid';CsvRaw=$csv[1].PasswordComplexity;CsvValid=$csv[1].'PasswordComplexity.ValueValid'}
}finally{if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
'@
    Assert-ClassEqual $true $r.Value;Assert-ClassEqual $null $r.Valid
    Assert-ClassEqual $false $r.FirstValid;Assert-ClassEqual $null $r.SecondValid
    Assert-ClassEqual 'bad' $r.CsvRaw;Assert-ClassEqual 'False' $r.CsvValid
}
