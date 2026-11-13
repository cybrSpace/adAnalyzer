Invoke-ClassTest 'value normalization preserves scalar and collection attributes with exclusions' {
    $r=Invoke-ClassScope @'
$value=[ordered]@{Name='Alice';Number=0;Enabled=$false;Empty=@();Missing=$null;Single=@('one');Multiple=@('one','two');nTSecurityDescriptor='excluded'}
$n=[Format]::ValueCollection($value,@('nTSecurityDescriptor'))
[pscustomobject]@{Name=$n['Name'];Number=$n['Number'];Enabled=$n['Enabled'];EmptyIsNull=$null -eq $n['Empty'];MissingIsNull=$null -eq $n['Missing'];Single=$n['Single'];MultipleCount=$n['Multiple'].Count;Excluded=$n.Contains('nTSecurityDescriptor')}
'@
    Assert-ClassEqual 'Alice' $r.Name
    Assert-ClassEqual 0 $r.Number
    Assert-ClassEqual $false $r.Enabled
    Assert-ClassTrue $r.EmptyIsNull 'Empty collections should normalize to null'
    Assert-ClassTrue $r.MissingIsNull 'Null attributes should remain null'
    Assert-ClassEqual 'one' $r.Single
    Assert-ClassEqual 2 $r.MultipleCount
    Assert-ClassEqual $false $r.Excluded
}

Invoke-ClassTest 'value normalization also accepts property-based objects' {
    $r=Invoke-ClassScope @'
$n=[Format]::ValueCollection([pscustomobject]@{Name='Alice';Groups=@('one','two');Hidden='excluded'},@('Hidden'))
[pscustomobject]@{Name=$n['Name'];Count=$n['Groups'].Count;Hidden=$n.Contains('Hidden')}
'@
    Assert-ClassEqual 'Alice' $r.Name
    Assert-ClassEqual 2 $r.Count
    Assert-ClassEqual $false $r.Hidden
}
Invoke-ClassTest 'legacy normalization preserves native metadata and only boolean secret presence' {
    $r=Invoke-ClassScope @'
$source=[ordered]@{SID=[pscustomobject]@{Value='S-1-5-21-1-2-3-1001'};WhenChanged=[datetime]::UtcNow;Password='unit3-secret';PasswordPresent=$false;apiKey=@();Xml='<Properties name="DefaultPassword" value="unit3-xml-secret"/>';PasswordHistorySize=12;Members=@('one','two')}
$n=[Format]::ValueCollection($source,@())
$opposite=[Format]::ValueCollection([ordered]@{PasswordPresent=$false;Password='unit3-secret'},@())
[pscustomobject]@{Presence=$n.PasswordPresent;OtherOrder=$opposite.PasswordPresent;Empty=$n.apiKeyPresent;HasValue=$n.Contains('Password');HasUnqueried=$n.Contains('userPasswordPresent');NativeSID=[object]::ReferenceEquals($n.SID,$source.SID);NativeDate=$n.WhenChanged -is [datetime];Xml=$n.Xml;Threshold=$n.PasswordHistorySize;Members=$n.Members.Count;Original=$source.Password;OriginalFlag=$source.PasswordPresent}
'@
    Assert-ClassEqual $true $r.Presence;Assert-ClassEqual $true $r.OtherOrder;Assert-ClassEqual $false $r.Empty
    Assert-ClassEqual $false $r.HasValue;Assert-ClassEqual $false $r.HasUnqueried
    Assert-ClassTrue ($r.NativeSID -and $r.NativeDate) 'Native metadata types changed'
    Assert-ClassTrue ($r.Xml -notmatch 'unit3-xml-secret|REDACTED') 'XML secret retained'
    Assert-ClassEqual 12 $r.Threshold;Assert-ClassEqual 2 $r.Members
    Assert-ClassEqual 'unit3-secret' $r.Original;Assert-ClassEqual $false $r.OriginalFlag
}

Invoke-ClassTest 'value normalization handles AD attribute value collections' {
    $r=Invoke-ClassScope @'
$values=[Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]::new()
$null=$values.Add('first');$null=$values.Add('second')
$n=[Format]::ValueCollection([ordered]@{memberOf=$values},@())
$n['memberOf'] -join ','
'@
    Assert-ClassEqual 'first,second' $r
}

Invoke-ClassTest 'date normalization handles every declared date name and null timestamps' {
    $r=Invoke-ClassScope @'
$count=0
foreach($field in [DateAttributes].GetEnumNames()) {
    $suffix=switch($field){'passwordlastset'{'pwdlastset'} 'lastlogondate'{'lastlogon'} default{$field}}
    $n=[Format]::DateAttributes($field,$null)
    if($null -ne $n[('days.'+$suffix)] -or $n[('range.'+$suffix)] -ne 'never'){throw $field}
    $count++
}
$count
'@
    Assert-ClassEqual 4 $r
}

Invoke-ClassTest 'date normalization uses explicit names and correct age bands' {
    $r=Invoke-ClassScope @'
$count=0
foreach($pair in @(@(7,'<= 7 days'),@(10,'8 - 14 days'),@(20,'15 - 30 days'),@(45,'31 - 60 days'),@(75,'61 - 90 days'),@(105,'91 - 120 days'),@(135,'121 - 150 days'),@(165,'151 - 180 days'),@(200,'> 180 days'))) {
    $n=[Format]::DateAttributes('passwordlastset',[datetime]::Now.AddDays(-$pair[0]))
    if($n['range.pwdlastset'] -ne $pair[1]){throw ('Invalid band: '+$pair[0])}
    $count++
}
$count
'@
    Assert-ClassEqual 9 $r
}

Invoke-ClassTest 'distinguished names retain separate parent levels and escaped commas' {
    $r=Invoke-ClassScope @'
$n=[Format]::DistinguishedName('CN=Alice,OU=People,OU=HQ,DC=example,DC=test')
$e=[Format]::DistinguishedName('CN=Alice,OU=People\, West,OU=HQ,DC=example,DC=test')
$s=[Format]::DistinguishedName('CN=Alice,DC=example')
[pscustomobject]@{L0=$n['orgUnit.L0'];L1=$n['orgUnit.L1'];L2=$n['orgUnit.L2'];Escaped=$e['orgUnit.L0'];Short=$s['orgUnit.L0'];Missing=$null -eq $s['orgUnit.L1']}
'@
    Assert-ClassEqual 'People' $r.L0
    Assert-ClassEqual 'HQ' $r.L1
    Assert-ClassEqual 'example' $r.L2
    Assert-ClassEqual 'People, West' $r.Escaped
    Assert-ClassEqual 'example' $r.Short
    Assert-ClassTrue $r.Missing 'Missing levels should be null'
}

Invoke-ClassTest 'property metadata excludes unsupported fields and resets names' {
    $r=Invoke-ClassScope @'
$p=[Property]::new();$p.SetPropertyNames(@('samaccountname','nTSecurityDescriptor','WriteErrorStream'));$first=$p.GetNames() -join ',';$p.SetPropertyNames(@('name'))
[pscustomobject]@{First=$first;Second=$p.GetNames() -join ','}
'@
    Assert-ClassEqual 'samaccountname' $r.First
    Assert-ClassEqual 'name' $r.Second
}

Invoke-ClassTest 'ordered rows retain requested column order and missing cells' {
    $r=Invoke-ClassScope @'
$row=[Format]::OrderedProperties([ordered]@{Name='Alice';Unused='excluded'},@('Missing','Name'))
[pscustomobject]@{Keys=$row.Keys -join ',';Missing=$null -eq $row['Missing'];Name=$row['Name'];Extra=$row.Contains('Unused')}
'@
    Assert-ClassEqual 'Missing,Name' $r.Keys
    Assert-ClassTrue $r.Missing 'Missing attributes should have null cells'
    Assert-ClassEqual 'Alice' $r.Name
    Assert-ClassEqual $false $r.Extra
}

Invoke-ClassTest 'user objects normalize a single UAC flag and whenChanged' {
    $r=Invoke-ClassScope @'
$null=[DomainData]::Initialize();[DomainData]::GetInstance().WellKnownSID=@{}
$null=[ObjectData]::Initialize();[ObjectData]::GetInstance().Data=[Table]::new()
$record=[UserObject]::Initialize($script:UserRecord)
[pscustomobject]@{FlagType=$record['userAccountControl'].GetType().Name;Flags=$record['userAccountControl'] -join ',';DatePresent=$record.Contains('days.whenChanged');ChangedDays=$record['days.whenChanged'];AccountType=$record['acctType']}
'@
    Assert-ClassEqual 'ArrayList' $r.FlagType
    Assert-ClassEqual 'NORMAL_ACCOUNT' $r.Flags
    Assert-ClassTrue $r.DatePresent 'whenChanged must be normalized'
    Assert-ClassTrue ($r.ChangedDays -ge 5) 'whenChanged age must be retained'
    Assert-ClassEqual 'unknown' $r.AccountType
}

Invoke-ClassTest 'nested group findings retain their source record' {
    $r=Invoke-ClassScope @'
$value=[ordered]@{samaccountname='FixtureGroup';managedBy='CN=Owner';memberOf=@('CN=Parent');members=@('CN=Alice');'orgUnit.L0'='Groups'}
$item=@([GroupObject]::Analyze($value) | Where-Object {$_.finding -eq 'Defect - Nested Group'})
[pscustomobject]@{Count=$item.Count;Source=$item[0].samaccountname}
'@
    Assert-ClassEqual 1 $r.Count
    Assert-ClassEqual 'FixtureGroup' $r.Source
}

Invoke-ClassTest 'legacy user data report and CSV retain empty single and multiple direct memberships' {
    $count=Invoke-ClassScope @'
$savedMembers=$script:UserRecord.memberOf;$count=0
$path=Join-Path ([IO.Path]::GetTempPath()) ('ad-membership-'+[guid]::NewGuid().ToString('N')+'.csv')
try {
    foreach($members in @(@(),@($script:GroupRecord.distinguishedName),@($script:GroupRecord.distinguishedName,'CN=Other,DC=example,DC=invalid'))){
        $script:UserRecord.memberOf=$members
        $before=ConvertTo-Json -InputObject $script:UserRecord -Depth 10 -Compress
        $e=Get-ADEnvironment -Class User -FQDN target.example.invalid
        $data=$e.User.Data['adoe'];$report=$e.User.Report['adoe']
        if(($data.memberOf -join ';') -ne ($members -join ';')){throw 'Data membership changed'}
        if(-not $report.Contains('memberOf') -or ($report.memberOf -join ';') -ne ($members -join ';')){throw 'Report membership lost'}
        $e.User.Report.ExportCSV($path);$csv=@(Import-Csv -LiteralPath $path)
        if($csv.Count -ne 1 -or $csv[0].memberOf -ne ($members -join ';')){throw 'CSV membership lost'}
        if(($report.memberOf -join ';') -ne ($members -join ';')){throw 'Export mutated report'}
        if((ConvertTo-Json -InputObject $script:UserRecord -Depth 10 -Compress) -ne $before){throw 'Source user mutated'}
        if($report.privilegeResolution -ne 'Unknown' -or $report.protectedUser -ne $false){throw 'Privilege/protection resolution changed'}
        $count++
    }
} finally {$script:UserRecord.memberOf=$savedMembers;if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force};[ADEnvironment]::Close()}
$count
'@
    Assert-ClassEqual 3 $count
}
