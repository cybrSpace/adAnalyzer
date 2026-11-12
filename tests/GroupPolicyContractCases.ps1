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
[pscustomobject]@{Count=$rows.Count;First=$rows[0].'property.setting.value';Second=$rows[1].'property.setting.value'}
'@
    Assert-ClassEqual 2 $r.Count
    Assert-ClassEqual 'Fixture Operator' $r.First
    Assert-ClassEqual 'S-1-5-32-545' $r.Second
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
