Invoke-ClassTest 'legacy user inactivity follows configured thresholds and known creation grace' {
    $results=Invoke-ClassScope @'
$saved=$script:ADAnalyzerLegacyProfile
try{
    foreach($case in @(
        @{Limit=20;Logon=19;Created=200;Expected=0},@{Limit=20;Logon=20;Created=20;Expected=1},
        @{Limit=20;Logon=30;Created=19;Expected=0},@{Limit=90;Logon=80;Created=200;Expected=0},
        @{Limit=90;Logon=90;Created=90;Expected=1},@{Limit=20;Logon=$null;Never=$true;Created=20;Expected=1},
        @{Limit=20;Logon=30;Created=200;Disabled=$true;Expected=0},@{Limit=20;Logon=30;Created=200;Protected=$true;Expected=0},
        @{Limit=0;Logon=0;Created=$null;Expected=0},@{Limit=0;Logon=0;Created=0;Expected=1}
    )){
        $script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile;$script:ADAnalyzerLegacyProfile.Policy.UserInactivityDays=$case.Limit
        $row=[ordered]@{enabled=(-not $case.Disabled);WellKnownSID=[bool]$case.Protected;acctType='personal';passwordNeverExpires=$false;'days.lastlogon'=$case.Logon;'range.lastlogon'=$(if($case.Never){'never'}else{'known'});'days.whenCreated'=$case.Created;'days.whenChanged'=0;'days.pwdLastSet'=0;'range.pwdLastSet'='known'}
        $before=ConvertTo-Json -InputObject $row -Depth 20 -Compress
        $labels=@([UserObject]::Analyze($row) | ForEach-Object finding)
        [pscustomobject]@{Expected=$case.Expected;Actual=@($labels | Where-Object {$_ -eq 'Defect - User Inactivity'}).Count;Unchanged=($before -ceq (ConvertTo-Json -InputObject $row -Depth 20 -Compress))}
    }
}finally{$script:ADAnalyzerLegacyProfile=$saved}
'@
    foreach($r in $results){Assert-ClassEqual $r.Expected $r.Actual;Assert-ClassEqual $true $r.Unchanged}
}

Invoke-ClassTest 'legacy computer inactivity uses the profile for both independent signals' {
    $results=Invoke-ClassScope @'
$saved=$script:ADAnalyzerLegacyProfile
try{
    foreach($signal in @('lastlogon','pwdLastSet')){foreach($case in @(
        @{Limit=20;Age=19;Created=200;Expected=0},@{Limit=20;Age=20;Created=20;Expected=1},
        @{Limit=20;Age=30;Created=19;Expected=0},@{Limit=90;Age=80;Created=200;Expected=0},
        @{Limit=90;Age=90;Created=90;Expected=1},@{Limit=20;Age=$null;Never=$true;Created=20;Expected=1},
        @{Limit=0;Age=0;Created=$null;Expected=0},@{Limit=0;Age=0;Created=0;Expected=1}
    )){
        $script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile;$script:ADAnalyzerLegacyProfile.Policy.ComputerInactivityDays=$case.Limit
        $row=[ordered]@{enabled=$true;'days.lastlogon'=-1;'range.lastlogon'='future';'days.pwdLastSet'=-1;'range.pwdLastSet'='future';'days.whenCreated'=$case.Created;'days.whenChanged'=0;OperatingSystem=''}
        $row['days.'+$signal]=$case.Age;$row['range.'+$signal]=if($case.Never){'never'}else{'known'}
        [pscustomobject]@{Expected=$case.Expected;Actual=@([ComputerObject]::Analyze($row) | Where-Object finding -eq 'Defect - Computer Inactivity').Count}
    }}
    $script:ADAnalyzerLegacyProfile.Policy.ComputerInactivityDays=20
    $row=[ordered]@{enabled=$true;'days.lastlogon'=$null;'range.lastlogon'='never';'days.pwdLastSet'=$null;'range.pwdLastSet'='never';'days.whenCreated'=20;OperatingSystem=''}
    [pscustomobject]@{Expected=2;Actual=@([ComputerObject]::Analyze($row) | Where-Object finding -eq 'Defect - Computer Inactivity').Count}
}finally{$script:ADAnalyzerLegacyProfile=$saved}
'@
    foreach($r in $results){Assert-ClassEqual $r.Expected $r.Actual}
}

Invoke-ClassTest 'legacy personal password milestones are relative to configured age and never invent dates' {
    $results=Invoke-ClassScope @'
$saved=$script:ADAnalyzerLegacyProfile
try{
    $cases=@()
    foreach($limit in @(30,120)){foreach($remaining in @(1,2,7,21)){$cases+=@(@{Limit=$limit;Age=($limit-$remaining);Warning=('Warning - Personal Password Expiration - '+$remaining+' Days');Defect=0})};$cases+=@(@{Limit=$limit;Age=$limit;Warning=$null;Defect=1})}
    $cases+=@(
        @{Limit=120;Age=89;Warning=$null;Defect=0},@{Limit=90;Age=89;Warning='Warning - Personal Password Expiration - 1 Days';Defect=0},
        @{Limit=1;Age=0;Warning='Warning - Personal Password Expiration - 1 Days';Defect=0},
        @{Limit=1;Age=$null;Never=$true;Warning=$null;Defect=1},@{Limit=1;Age=-1;Warning=$null;Defect=0},
        @{Limit=0;Age=100;Warning=$null;Defect=0},@{Limit=120;Age=120;Created=30;Warning=$null;Defect=0},@{Limit=120;Age=120;Created=31;Warning=$null;Defect=1}
    )
    foreach($case in $cases){
        $script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile;$script:ADAnalyzerLegacyProfile.Policy.UserPasswordAgeDays=$case.Limit
        $row=[ordered]@{enabled=$true;acctType='personal';passwordNeverExpires=$false;WellKnownSID=$false;'days.pwdLastSet'=$case.Age;'range.pwdLastSet'=$(if($case.Never){'never'}else{'known'});'days.whenCreated'=$(if($case.ContainsKey('Created')){$case.Created}else{200});'days.lastlogon'=0;'range.lastlogon'='known'}
        $labels=@([UserObject]::Analyze($row) | ForEach-Object finding)
        [pscustomobject]@{ExpectedWarning=[string]$case.Warning;Warning=(@($labels | Where-Object {$_ -like 'Warning - Personal Password Expiration*'}) -join '|');ExpectedDefect=$case.Defect;Defect=@($labels | Where-Object {$_ -eq 'Defect - Personal Password Age'}).Count}
    }
}finally{$script:ADAnalyzerLegacyProfile=$saved}
'@
    foreach($r in $results){Assert-ClassEqual $r.ExpectedWarning $r.Warning;Assert-ClassEqual $r.ExpectedDefect $r.Defect}
}

Invoke-ClassTest 'legacy service warnings use configured windows and preserve default bucket labels' {
    $results=Invoke-ClassScope @'
$saved=$script:ADAnalyzerLegacyProfile
try{
    $cases=@(
        @{Limit=120;Age=29;Bucket=$null;Defect=0},@{Limit=120;Age=30;Bucket=30;Defect=0},
        @{Limit=120;Age=59;Bucket=30;Defect=0},@{Limit=120;Age=60;Bucket=60;Defect=0},
        @{Limit=120;Age=89;Bucket=60;Defect=0},@{Limit=120;Age=90;Bucket=90;Defect=0},
        @{Limit=120;Age=119;Bucket=90;Defect=0},@{Limit=120;Age=120;Bucket=$null;Defect=1},
        @{Limit=10;Age=0;Bucket=0;Defect=0},@{Limit=10;Age=9;Bucket=0;Defect=0},@{Limit=10;Age=10;Bucket=$null;Defect=1},
        @{Limit=365;Age=275;Bucket=275;Defect=0},@{Limit=365;Age=305;Bucket=305;Defect=0},@{Limit=365;Age=335;Bucket=335;Defect=0},
        @{Limit=10;Age=$null;Never=$true;Bucket=$null;Defect=1},@{Limit=10;Age=-1;Bucket=$null;Defect=0},@{Limit=0;Age=100;Bucket=$null;Defect=0},@{Limit=120;Age=120;Created=30;Bucket=$null;Defect=0},@{Limit=120;Age=120;Created=31;Bucket=$null;Defect=1}
    )
    foreach($case in $cases){
        $script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile;$script:ADAnalyzerLegacyProfile.Policy.ServicePasswordAgeDays=$case.Limit
        $row=[ordered]@{enabled=$true;acctType='non-personal';passwordNeverExpires=$true;WellKnownSID=$false;'days.pwdLastSet'=$case.Age;'range.pwdLastSet'=$(if($case.Never){'never'}else{'known'});'days.whenCreated'=$(if($case.ContainsKey('Created')){$case.Created}else{200});'days.lastlogon'=0;'range.lastlogon'='known'}
        $labels=@([UserObject]::Analyze($row) | ForEach-Object finding)
        [pscustomobject]@{ExpectedWarning=$(if($null -ne $case.Bucket){'Warning - Non-Personal Password Expiration - '+$case.Bucket+' Days'}else{''});Warning=(@($labels | Where-Object {$_ -like 'Warning - Non-Personal Password Expiration*'}) -join '|');ExpectedDefect=$case.Defect;Defect=@($labels | Where-Object {$_ -eq 'Defect - Non-Personal Password Age'}).Count}
    }
}finally{$script:ADAnalyzerLegacyProfile=$saved}
'@
    foreach($r in $results){Assert-ClassEqual $r.ExpectedWarning $r.Warning;Assert-ClassEqual $r.ExpectedDefect $r.Defect}
}

Invoke-ClassTest 'legacy password-policy class honors stricter and looser length and history profiles' {
    $results=Invoke-ClassScope @'
$saved=$script:ADAnalyzerLegacyProfile
try{
    foreach($setting in @('MinimumPasswordLength','PasswordHistorySize')){foreach($limit in @(4,20)){foreach($value in @(($limit-1),$limit)){
        $script:ADAnalyzerLegacyProfile=Get-ADAnalyzerDefaultProfile;$script:ADAnalyzerLegacyProfile.Policy[$setting]=$limit
        $row=[ordered]@{'ext.property.name'='Account';'property.setting.name'=$setting;'property.setting.value'=$value}
        [pscustomobject]@{Expected=$(if($value -lt $limit){1}else{0});Actual=@([PasswordPolicyObject]::Analyze($row)).Count}
        $row['property.setting.valid']=$false
        [pscustomobject]@{Expected=1;Actual=@([PasswordPolicyObject]::Analyze($row) | Where-Object finding -eq 'Validate - Invalid stored policy value').Count}
    }}}
}finally{$script:ADAnalyzerLegacyProfile=$saved}
'@
    foreach($r in $results){Assert-ClassEqual $r.Expected $r.Actual}
}

Invoke-ClassTest 'public legacy profile controls actual user inactivity findings without mutating fixtures' {
    $r=Invoke-ClassScope @'
$saved=$script:UserRecord
try{
    $script:UserRecord=[ordered]@{};foreach($key in $saved.Keys){$script:UserRecord[$key]=$saved[$key]}
    $script:UserRecord.lastlogondate=[datetime]::Now.AddDays(-80.25);$script:UserRecord.whenCreated=[datetime]::Now.AddDays(-200.25)
    $before=ConvertTo-Json -InputObject $script:UserRecord -Depth 30 -Compress
    $profile=Get-ADAnalyzerDefaultProfile;$profile.Policy.UserInactivityDays=90
    $a=Get-ADEnvironment -Class User -FQDN target.example.invalid -Profile $profile
    $profile.Policy.UserInactivityDays=20
    $b=Get-ADEnvironment -Class User -FQDN target.example.invalid -Profile $profile
    [pscustomobject]@{Loose=@($a.User.Finding | Where-Object finding -eq 'Defect - User Inactivity').Count;Strict=@($b.User.Finding | Where-Object finding -eq 'Defect - User Inactivity').Count;Unchanged=($before -ceq (ConvertTo-Json -InputObject $script:UserRecord -Depth 30 -Compress))}
}finally{$script:UserRecord=$saved}
'@
    Assert-ClassEqual 0 $r.Loose;Assert-ClassEqual 1 $r.Strict;Assert-ClassEqual $true $r.Unchanged
}
