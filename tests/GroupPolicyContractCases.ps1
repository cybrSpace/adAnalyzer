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
