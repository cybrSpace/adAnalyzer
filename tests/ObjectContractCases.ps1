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
