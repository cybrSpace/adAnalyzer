[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
foreach($name in @('ADProfile','ADGpo','ADPolicyAnalysis','ADDirectoryAnalysis','ADHostAnalysis','ADOperations','ADAssessment')){. (Join-Path $RepositoryRoot ('bin/'+$name+'.ps1'))}
$script:Passed=0;$script:Failed=0
function Assert-Equal($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], got [$Actual]"}}
function Assert-True($Actual,[string]$Message){if(-not $Actual){throw $Message}}
function Assert-Throws([scriptblock]$Body){$failed=$false;try{& $Body > $null}catch{$failed=$true};if(-not $failed){throw 'Expected a terminating error'}}
function Test-Assessment([string]$Name,[scriptblock]$Body){try{& $Body;$script:Passed++;Write-Host "PASS $Name"}catch{$script:Failed++;Write-Host "FAIL $Name : $_";Write-Host $_.ScriptStackTrace}}
function New-AssessmentFixture([string]$Domain='example.invalid') {
    $dn='DC='+($Domain.Replace('.',',DC='));$coverage=@{}
    foreach($key in @('Domain','Users','Groups','Computers','Trusts','DefaultPasswordPolicy','FineGrainedPasswordPolicies','ResultantPasswordPolicies','ServiceAccounts','OptionalFeatures')){$coverage[$key]='Collected'}
    $coverage.Acl='NotConfigured';$coverage.Hosts='NotConfigured'
    [pscustomobject]@{
        Domain=[pscustomobject]@{DNSRoot=$Domain;DistinguishedName=$dn;SID='S-1-5-21-1-2-3';MachineAccountQuota=0;OptionalFeatures=@([pscustomobject]@{FeatureGUID='766ddcd8-acd0-445e-f3b9-a7f9b6744f2a';EnabledScopes=@($dn)})}
        Server=('dc.'+$Domain);Users=@();Groups=@();Computers=@();ServiceAccounts=@();Objects=@();Trusts=@();DomainControllers=@()
        PasswordPolicies=[pscustomobject]@{Default=$null;FineGrained=@();Resultant=@()};Acl=[pscustomobject]@{Entries=@()};Hosts=@();Errors=@();Coverage=$coverage
    }
}
function New-PolicyFixture {
    [pscustomobject]@{Path='fixture';SysvolVersion=1;SecuritySettings=@();RegistrySettings=@();XmlFiles=@();IniSettings=@();Files=@();UnparsedFiles=@()}
}
function Write-AssessmentPol([string]$Path,[array]$Records){
    $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    $stream=[IO.File]::Create($Path);$writer=[IO.BinaryWriter]::new($stream)
    try{
        $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'));$writer.Write([uint32]1)
        foreach($row in $Records){
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Key+[char]0));$writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($row.Name+[char]0));$writer.Write([uint16]59)
            $writer.Write([uint32]$row.Type);$writer.Write([uint16]59)
            $writer.Write([uint32]$row.Bytes.Length);$writer.Write([uint16]59);$writer.Write([byte[]]$row.Bytes);$writer.Write([uint16]93)
        }
    }finally{$writer.Dispose();$stream.Dispose()}
}
function New-RegistryIdentityFixture([string]$Name,[switch]$Deleted){
    $root=Join-Path $temp $Name;$templates=Join-Path $root 'templates'
    $null=[IO.Directory]::CreateDirectory((Join-Path $templates 'en-US'))
    [IO.File]::WriteAllText((Join-Path $templates 'fixture.admx'),'<policyDefinitions><policyNamespaces><target prefix="f" namespace="Fixture.Policies"/></policyNamespaces><policies><policy name="EnabledPolicy" class="Both" displayName="$(string.Title)" key="Software\Fixture" valueName="Enabled"><enabledValue><decimal value="1"/></enabledValue><disabledValue><delete/></disabledValue></policy></policies></policyDefinitions>')
    [IO.File]::WriteAllText((Join-Path $templates 'en-US/fixture.adml'),'<policyDefinitionResources><resources><stringTable><string id="Title">Fixture title</string></stringTable></resources></policyDefinitionResources>')
    foreach($side in @('Machine','User')){
        $rows=@(@{Key='Software\Fixture';Name='Enabled';Type=4;Bytes=[BitConverter]::GetBytes([uint32]0)},@{Key='Software\Fixture';Name='Enabled';Type=4;Bytes=[BitConverter]::GetBytes([uint32]1)})
        if($Deleted){$rows+=@{Key='Software\Fixture';Name='**del.Enabled';Type=1;Bytes=[byte[]]@()}}
        $rows+=@{Key='Software\Fixture';Name='DefaultPassword';Type=1;Bytes=[Text.Encoding]::Unicode.GetBytes("REGISTRY_IDENTITY_FIXTURE_SECRET`0")}
        if($side -eq 'Machine'){$rows+=@{Key='Software\Microsoft\Windows\CurrentVersion\Policies\System';Name='EnableLUA';Type=4;Bytes=[BitConverter]::GetBytes([uint32]1)}}
        Write-AssessmentPol (Join-Path $root ($side+'/Registry.pol')) $rows
    }
    [IO.File]::WriteAllText((Join-Path $root 'GPT.INI'),"[General]`nVersion=1")
    $policy=Read-ADAnalyzerGpo $root
    $profile=@{Analysis=@{TemplatePath=$templates};RegistryRules=@(@{Id='FixtureEnabled';Hive='HKLM';Key='Software\Fixture';ValueName='Enabled';Expected=1;Type=4})}
    [pscustomobject]@{Root=$root;Policy=$policy;Profile=$profile;Gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Version=1;Flags=0;Links=@()}}
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ad-assessment-'+[guid]::NewGuid().ToString('N'));$null=New-Item -Path $temp -ItemType Directory
try {
    Test-Assessment 'logical GPO paths are canonical and comparisons survive physical separator differences' {
        $root=Join-Path $temp 'logical-source';$null=[IO.Directory]::CreateDirectory((Join-Path $root 'Machine'));$null=[IO.Directory]::CreateDirectory((Join-Path $root 'User'))
        $script:LogicalSourceRoot=(Get-Item -LiteralPath $root).FullName
        $script:LogicalReads=[Collections.Generic.List[string]]::new()
        $script:LogicalFiles=@('Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf','Machine/Extra.ini','Machine/Preferences/Groups/Groups.xml','Machine/Scripts/unsupported.cmd')
        $ini=(Get-Command Read-AnalyzerPolicyIni).ScriptBlock;$xml=(Get-Command Read-AnalyzerPolicyXml).ScriptBlock
        $listing=Get-Command Get-ChildItem
        try{
            function script:Get-ChildItem {
                param($LiteralPath,[switch]$Recurse,[switch]$File,[switch]$Force,$ErrorAction)
                if($LiteralPath -eq (Join-Path $script:LogicalSourceRoot 'Machine')){foreach($path in $script:LogicalFiles){
                    [pscustomobject]@{FullName=$script:LogicalSourceRoot+$script:LogicalSeparator+$path.Replace('/',$script:LogicalSeparator);Name=($path.Split('/')[-1]);Extension=[IO.Path]::GetExtension($path);Length=100}
                }}
            }
            function script:Read-AnalyzerPolicyIni {
                param($Path)
                $script:LogicalReads.Add($Path)
                if($Path -like '*GptTmpl.inf'){return [ordered]@{'System Access'=[ordered]@{MinimumPasswordLength='16'}}}
                return [ordered]@{Fixture=[ordered]@{Setting='value'}}
            }
            function script:Read-AnalyzerPolicyXml {
                param($Path)
                $script:LogicalReads.Add($Path)
                return [xml]'<Groups><Group uid="stable"><Properties action="U" groupSid="S-1-5-32-544"/></Group></Groups>'
            }
            $results=@()
            foreach($separator in @([string][char]92,'/')){
                $script:LogicalSeparator=$separator;$script:LogicalReads.Clear()
                $policy=Read-ADAnalyzerGpo $root
                Assert-Equal $script:LogicalSourceRoot $policy.Path
                foreach($path in @($policy.SecuritySettings.Source)+@($policy.IniSettings.Source)+@($policy.XmlFiles.Path)+@($policy.Files.Path)+@($policy.UnparsedFiles.Path)){
                    Assert-True (-not $path.Contains([string][char]92)) ('Noncanonical logical path '+$path)
                    Assert-True (-not [IO.Path]::IsPathRooted($path)) 'Physical root escaped into logical metadata'
                }
                Assert-Equal 3 $script:LogicalReads.Count
                foreach($path in $script:LogicalReads){
                    Assert-True ($path.StartsWith($script:LogicalSourceRoot+$separator,[StringComparison]::Ordinal)) 'File I/O path was normalized'
                    Assert-True ($path.Contains($separator+'Machine'+$separator)) 'Original file I/O path was replaced'
                }
                $gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Flags=0;Links=@()}
                $results+=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$policy})
            }
            $changes=@((Compare-ADAnalyzerAssessment $results[0] $results[1]).Changes | Where-Object RuleId -like 'GPO.*')
            Assert-True ($changes.Count -gt 5) 'Policy paths were not assessed'
            Assert-Equal 0 @($changes | Where-Object Change -ne Unchanged).Count
            Assert-Equal (ConvertTo-Json -InputObject $results[0].Data.Policies -Depth 100 -Compress) (ConvertTo-Json -InputObject $results[1].Data.Policies -Depth 100 -Compress)
        }finally{
            Set-Item Function:script:Read-AnalyzerPolicyIni $ini;Set-Item Function:script:Read-AnalyzerPolicyXml $xml
            if($listing -is [Management.Automation.FunctionInfo]){Set-Item Function:script:Get-ChildItem $listing.ScriptBlock}else{Remove-Item Function:Get-ChildItem}
            Assert-Equal $listing.CommandType (Get-Command Get-ChildItem).CommandType
        }
    }
    Test-Assessment 'native GPO files retain canonical logical paths and original bytes' {
        $root=Join-Path $temp 'native-logical-source';$files=@{
            'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'="[System Access]`nMinimumPasswordLength=16"
            'Machine/Extra.ini'="[Fixture]`nSetting=value"
            'Machine/Preferences/Groups/Groups.xml'='<Groups><Group uid="stable"><Properties action="U" groupSid="S-1-5-32-544"/></Group></Groups>'
            'Machine/Scripts/unsupported.cmd'='fixture content'
        }
        $bytes=@{}
        foreach($relative in $files.Keys){$path=Join-Path $root $relative;$null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path));[IO.File]::WriteAllText($path,$files[$relative]);$bytes[$path]=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))}
        $policy=Read-ADAnalyzerGpo $root
        foreach($path in @($policy.SecuritySettings.Source)+@($policy.IniSettings.Source)+@($policy.XmlFiles.Path)+@($policy.Files.Path)+@($policy.UnparsedFiles.Path)){Assert-True (-not $path.Contains([string][char]92)) 'Native logical path was not canonical'}
        Assert-Equal 1 $policy.SecuritySettings.Count;Assert-Equal 2 $policy.IniSettings.Count;Assert-Equal 1 $policy.XmlFiles.Count;Assert-Equal 1 $policy.UnparsedFiles.Count
        foreach($path in $bytes.Keys){Assert-Equal $bytes[$path] ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)))}
    }
    Test-Assessment 'registry template metadata uses final effective writes in each hive without altering raw inventory' {
        foreach($deleted in @($false,$true)){
            $fixture=New-RegistryIdentityFixture ('registry-effective-'+$deleted) -Deleted:$deleted
            $before=ConvertTo-Json -InputObject $fixture.Policy -Depth 100 -Compress
            $bytes=@{};foreach($file in Get-ChildItem -LiteralPath $fixture.Root -Recurse -File){$bytes[$file.FullName]=[Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))}
            $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @($fixture) -Profile $fixture.Profile
            $metadata=@($result.Checks | Where-Object {$_.RuleId -eq 'GPO.TEMPLATE_METADATA' -and $_.Observed.ValueName -eq 'Enabled'})
            Assert-Equal 2 $metadata.Count;Assert-Equal 'HKCU,HKLM' (($metadata.Observed.Hive | Sort-Object) -join ',')
            foreach($check in $metadata){
                Assert-Equal Pass $check.Status
                if($deleted){Assert-Equal Disabled $check.Observed.State;Assert-Equal $true $check.Observed.Deleted}
                else{Assert-Equal Enabled $check.Observed.State;Assert-Equal 1 $check.Observed.Value;Assert-Equal $false $check.Observed.Deleted}
            }
            Assert-Equal 0 @($result.Checks | Group-Object CheckId | Where-Object Count -gt 1).Count
            Assert-Equal $before (ConvertTo-Json -InputObject $fixture.Policy -Depth 100 -Compress)
            foreach($path in $bytes.Keys){Assert-Equal $bytes[$path] ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)))}
            Assert-True ((ConvertTo-Json -InputObject $result -Depth 100) -notmatch 'REGISTRY_IDENTITY_FIXTURE_SECRET|REDACTED') 'Secret escaped metadata assessment'
        }
    }
    Test-Assessment 'identical GPO registry policies at different roots retain unchanged check identities' {
        $a=New-RegistryIdentityFixture 'registry-root-a';$b=New-RegistryIdentityFixture 'registry-root-b'
        $before=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @($a) -Profile $a.Profile
        $after=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @($b) -Profile $b.Profile
        $changes=@((Compare-ADAnalyzerAssessment $before $after).Changes | Where-Object RuleId -like 'GPO.*')
        Assert-True ($changes.Count -gt 5) 'Registry assessment paths were not exercised'
        Assert-Equal 0 @($changes | Where-Object Change -ne Unchanged).Count
        foreach($pattern in @('GPO.SECURITY.*','GPO.EXPECTED.*','GPO.STOREDSECRET','GPO.TEMPLATE_METADATA')){Assert-True (@($changes | Where-Object RuleId -like $pattern).Count -gt 0) ('Missing assessment path '+$pattern)}
        foreach($rule in @('GPO.Security.SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA','GPO.Expected.FixtureEnabled')){
            $checks=@($after.Checks | Where-Object RuleId -eq $rule)
            Assert-Equal 1 $checks.Count;Assert-Equal Pass $checks[0].Status
            Assert-Equal 'Machine/Registry.pol' $checks[0].Evidence.Path
        }
        Assert-Equal 0 @($after.Checks | Where-Object {$_.RuleId -eq 'GPO.StoredSecret' -and $_.Observed -ne $true}).Count
    }
    Test-Assessment 'offline assessment reports explicit coverage without directory calls' {
        $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture)
        Assert-True ($result.Checks.Count -gt 0) 'No checks returned'
        Assert-Equal $result.Checks.Count $result.Coverage.Total
        Assert-Equal 'Pass' ($result.Checks | Where-Object RuleId -eq DOMAIN.MACHINE_ACCOUNT_QUOTA).Status
        Assert-Equal 'NotConfigured' ($result.Checks | Where-Object RuleId -eq COLLECTION.ACL).Status
        Assert-Equal 1 $result.SchemaVersion
    }
    Test-Assessment 'unreadable collectors produce partial coverage and preserve errors' {
        $data=New-AssessmentFixture;$data.Coverage.Users='Unreadable';$data.Errors=@([pscustomobject]@{Collection='Users';Message='fixture access denied'})
        $result=Invoke-ADAnalyzerAssessment -DirectoryData $data
        Assert-Equal Partial $result.State
        Assert-Equal Unreadable ($result.Checks | Where-Object RuleId -eq COLLECTION.USERS).Status
        Assert-Equal 'fixture access denied' $result.Errors[0].Message
    }
    Test-Assessment 'missing domain metadata cannot produce a complete live assessment' {
        $data=New-AssessmentFixture;$data.Domain=$null;$data.Coverage.Domain='Unreadable'
        $result=Invoke-ADAnalyzerAssessment -DirectoryData $data -Target example.invalid
        Assert-Equal Failed $result.State
    }
    Test-Assessment 'exceptions preserve failed evidence with owned expiring suppression metadata' {
        $data=New-AssessmentFixture;$data.Domain.MachineAccountQuota=10
        $profile=@{Exceptions=@(@{RuleId='DOMAIN.MACHINE_ACCOUNT_QUOTA';Target=$data.Domain.DistinguishedName;Owner='Ops';Reason='Lab migration';Expires=[datetime]::UtcNow.AddDays(1).ToString('o')})}
        $result=Invoke-ADAnalyzerAssessment -DirectoryData $data -Profile $profile
        $check=$result.Checks | Where-Object RuleId -eq DOMAIN.MACHINE_ACCOUNT_QUOTA
        Assert-Equal Fail $check.Status;Assert-True $check.Suppressed 'Owned exception not applied';Assert-Equal Ops $check.Exception.Owner
    }
    Test-Assessment 'separate snapshots do not share nested evidence or configuration' {
        $data=New-AssessmentFixture;$a=Invoke-ADAnalyzerAssessment -DirectoryData $data;$b=Invoke-ADAnalyzerAssessment -DirectoryData $data
        $a.Data.Directory.Domain.MachineAccountQuota=99;$a.Configuration.Policy.MinimumPasswordLength=99
        Assert-Equal 0 $b.Data.Directory.Domain.MachineAccountQuota;Assert-Equal 12 $b.Configuration.Policy.MinimumPasswordLength
        Assert-Equal 0 $data.Domain.MachineAccountQuota
    }
    Test-Assessment 'assessment boundary retains only credential and XML secret presence' {
        $data=New-AssessmentFixture;$data | Add-Member -NotePropertyName Credential -NotePropertyValue ([pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-password' -AsPlainText -Force)))
        $policy=New-PolicyFixture;$policy.XmlFiles=@([pscustomobject]@{Scope='Computer';Kind='Preferences';Path='Machine/Preferences/Groups.xml';Xml='<Groups><User uid="fixture" cpassword="fixture-secret" /></Groups>'})
        $gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Flags=0;Version=1;Links=@()}
        $result=Invoke-ADAnalyzerAssessment -DirectoryData $data -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$policy;Error=$null})
        $json=ConvertTo-Json -InputObject $result -Depth 100
        Assert-True ($json -notmatch 'fixture-secret|fixture-password') 'Secret crossed assessment boundary'
        Assert-Equal Fail ($result.Checks | Where-Object RuleId -eq GPO.Preferences.CPassword).Status
    }
    Test-Assessment 'SYSVOL version mismatch and policy read errors remain explicit' {
        $policy=New-PolicyFixture;$policy.SysvolVersion=2
        $gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Flags=0;Version=1;Links=@()}
        $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$policy;Error=$null})
        Assert-Equal Fail ($result.Checks | Where-Object RuleId -eq GPO.VERSION_CONSISTENCY).Status
        $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$null;Error='fixture SYSVOL denied'})
        Assert-Equal Unreadable ($result.Checks | Where-Object RuleId -eq GPO.READ).Status;Assert-Equal Partial $result.State
    }
    Test-Assessment 'named XML secrets remain boolean findings through assessment and all exports' {
        $policy=New-PolicyFixture;$policy.XmlFiles=@([pscustomobject]@{Scope='Computer';Kind='Preferences';Path='Machine/Preferences/Registry.xml';Xml='<RegistrySettings><Registry uid="one"><Properties name="DefaultPassword" value="unit2-assessment-secret"/></Registry></RegistrySettings>'})
        $gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Flags=0;Version=1;Links=@()}
        $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$policy;Error=$null})
        $finding=$result.Findings | Where-Object RuleId -eq GPO.StoredSecret
        Assert-Equal Fail $finding.Status;Assert-Equal $true $finding.Observed;Assert-Equal $true $finding.Evidence.SecretPresent
        Assert-True (($result | ConvertTo-Json -Depth 100) -notmatch 'unit2-assessment-secret|REDACTED') 'Assessment retained a named XML secret'
        foreach($path in @(Export-ADAnalyzerAssessment -Assessment $result -Path (Join-Path $temp 'named-secret') -Format All -Confirm:$false)){
            Assert-True ((Get-Content -LiteralPath $path -Raw) -notmatch 'unit2-assessment-secret|REDACTED') 'Export retained a named XML secret'
        }
    }
    Test-Assessment 'missing policy versions remain unknown' {
        $policy=New-PolicyFixture;$policy.SysvolVersion=$null
        $gpo=[pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Flags=0;Version=1;Links=@()}
        $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$policy;Error=$null})
        Assert-Equal Unknown ($result.Checks | Where-Object RuleId -eq GPO.VERSION_CONSISTENCY).Status
    }
    Test-Assessment 'failed GPO reads and skipped GPO collection cannot resolve stored failures' {
        $collector=(Get-Command Get-ADAnalyzerDirectoryData).ScriptBlock
        $gpos=(Get-Command Get-ADAnalyzerGpo).ScriptBlock;$report=(Get-Command Get-ADAnalyzerGpoReport).ScriptBlock
        $script:ComparisonReadFails=$false
        function script:Get-ADRootDSE {param($Server,$Credential,$ErrorAction) [pscustomobject]@{DnsHostName='dc.example.invalid'}}
        function script:Get-ADAnalyzerDirectoryData {param($Context,$Profile) New-AssessmentFixture}
        function script:Get-ADAnalyzerGpo {param([switch]$All,$Domain,$Server,$Credential) [pscustomobject]@{Id=[guid]'11111111-1111-1111-1111-111111111111';Flags=0;Version=1;Links=@()}}
        function script:Get-ADAnalyzerGpoReport {
            param($Gpo,$Credential,[switch]$AsObject)
            if($script:ComparisonReadFails){throw 'fixture GPO read denied'}
            $policy=New-PolicyFixture;$policy.SecuritySettings=@([pscustomobject]@{Scope='Computer';Kind='Account';Name='MinimumPasswordLength';Value=0;Source='Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'})
            [pscustomobject]@{Policy=$policy}
        }
        try{
            $before=Get-ADAnalyzerAssessment -Domain example.invalid
            Assert-True (@($before.Checks | Where-Object {$_.RuleId -like 'GPO.*' -and $_.Status -eq 'Fail'}).Count -gt 0) 'Missing failing GPO baseline'
            $script:ComparisonReadFails=$true;$failed=Get-ADAnalyzerAssessment -Domain example.invalid
            Assert-Equal Partial $failed.State
            $skipped=Get-ADAnalyzerAssessment -Domain example.invalid -SkipGpo
            Assert-Equal Complete $skipped.State
            foreach($after in @($failed,$skipped)){
                $changes=@((Compare-ADAnalyzerAssessment $before $after).Changes | Where-Object {$_.RuleId -like 'GPO.*' -and $_.Reason -eq 'NotObservedInDifference'})
                Assert-True ($changes.Count -gt 0) 'Missing explicit unobserved policy checks'
                Assert-Equal 0 @($changes | Where-Object Change -ne Changed).Count
                Assert-Equal 0 @((Compare-ADAnalyzerAssessment $before $after).Changes | Where-Object {$_.RuleId -like 'GPO.*' -and $_.Change -eq 'Resolved'}).Count
            }
        }finally{
            Set-Item Function:script:Get-ADAnalyzerDirectoryData $collector;Set-Item Function:script:Get-ADAnalyzerGpo $gpos;Set-Item Function:script:Get-ADAnalyzerGpoReport $report
            Remove-Item Function:Get-ADRootDSE;$script:ComparisonReadFails=$false
        }
    }
    Test-Assessment 'SCT-style extracted GPO backup becomes typed baseline expectations' {
        $path=Join-Path $temp 'baseline/DomainSysvol/GPO';$machine=Join-Path $path 'Machine/Microsoft/Windows NT/SecEdit';$null=New-Item -Path $machine -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $path 'GPT.INI') -Value "[General]`nVersion=1"
        Set-Content -LiteralPath (Join-Path $machine 'GptTmpl.inf') -Value "[System Access]`nMinimumPasswordLength=16`nPasswordComplexity=1"
        $profile=Import-ADAnalyzerBaseline -GpoPath $path -Name Fixture -Version '2026.11'
        Assert-Equal Fixture $profile.Name;Assert-Equal '2026.11' $profile.Version;Assert-Equal 2 $profile.ExpectedGpoSettings.Count
        $parsed=Read-ADAnalyzerGpo $path;$gpo=[pscustomobject]@{Id=[guid]::Empty;Flags=0;Version=1;Links=@()}
        $checks=@(Test-ADAnalyzerGpoPolicy -Gpo $gpo -Policy $parsed -Profile $profile | Where-Object RuleId -like 'GPO.Expected.*')
        Assert-Equal 2 $checks.Count;Assert-Equal 0 @($checks | Where-Object Status -ne Pass).Count
        $again=Import-ADAnalyzerBaseline -GpoPath $path -Name Fixture -Version '2026.11'
        Assert-Equal ($profile.ExpectedGpoSettings.Id -join '|') ($again.ExpectedGpoSettings.Id -join '|')
    }
    Test-Assessment 'misplaced account-template entries are excluded from baselines and leave explicit coverage' {
        $root=Join-Path $temp 'section-baseline';$directory=Join-Path $root 'Machine/Microsoft/Windows NT/SecEdit';$null=[IO.Directory]::CreateDirectory($directory)
        [IO.File]::WriteAllText((Join-Path $root 'GPT.INI'),"[General]`nVersion=1")
        [IO.File]::WriteAllText((Join-Path $directory 'GptTmpl.inf'),"[System Access]`nMinimumPasswordLength=16`nTicketValidateClient=1`n[Kerberos Policy]`nPasswordComplexity=1`nMaxTicketAge=10",[Text.Encoding]::Unicode)
        $profile=Import-ADAnalyzerBaseline -GpoPath $root -Version section
        Assert-Equal 2 @($profile.ExpectedGpoSettings).Count
        Assert-Equal 0 @($profile.ExpectedGpoSettings | Where-Object {$_.Name -in 'TicketValidateClient','PasswordComplexity'}).Count
        $gpo=[pscustomobject]@{Id=[guid]::Empty;Flags=0;Version=1;Links=@()};$policy=Read-ADAnalyzerGpo $root
        $result=Invoke-ADAnalyzerAssessment -DirectoryData (New-AssessmentFixture) -GpoData @([pscustomobject]@{Gpo=$gpo;Policy=$policy;Error=$null}) -Profile $profile
        Assert-Equal 'Unknown' ($result.Checks | Where-Object RuleId -eq GPO.Coverage.UnsupportedInfSettings).Status
        Assert-Equal 'Partial' $result.State
        Assert-Equal 'NotConfigured' ($result.Checks | Where-Object RuleId -eq GPO.Account.PasswordComplexity).Status
        Assert-Equal 0 @($result.Checks | Where-Object {$_.RuleId -like 'GPO.Expected.*' -and $_.Status -ne 'Pass'}).Count
    }
    Test-Assessment 'conflicting baseline inputs are rejected without silently overwriting' {
        $a=Join-Path $temp 'baseline/DomainSysvol/GPO';$b=Join-Path $temp 'conflict';$null=New-Item -Path (Join-Path $b 'Machine/Microsoft/Windows NT/SecEdit') -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $b 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf') -Value "[System Access]`nMinimumPasswordLength=8"
        Assert-Throws {Import-ADAnalyzerBaseline -GpoPath @($a,$b) -Version one}
    }
    Test-Assessment 'baseline omits stored secret values instead of accepting them as expectations' {
        $reader=(Get-Item Function:Read-ADAnalyzerGpo).ScriptBlock
        $script:BaselinePolicy=New-PolicyFixture;$script:BaselinePolicy.Files=@([pscustomobject]@{Path='Machine/Registry.pol'})
        $script:BaselinePolicy.RegistrySettings=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='DefaultPassword';SecretPresent=$true;Type=1;Source='Machine/Registry.pol';KeyOnly=$false})
        $script:BaselinePolicy.SecuritySettings=@([pscustomobject]@{Scope='Computer';Kind='SecurityOptions';Name='MACHINE\Software\Fixture\DefaultPassword';SecretPresent=$true;Source='Machine/GptTmpl.inf'})
        function script:Read-ADAnalyzerGpo {param($Path) $script:BaselinePolicy}
        try{$profile=Import-ADAnalyzerBaseline -GpoPath fixture -Version one;Assert-Equal 0 $profile.RegistryRules.Count;Assert-Equal 0 $profile.ExpectedGpoSettings.Count}finally{Set-Item Function:script:Read-ADAnalyzerGpo $reader}
    }
    Test-Assessment 'invalid marked policy values cannot become baseline expectations' {
        $reader=(Get-Command Read-ADAnalyzerGpo).ScriptBlock
        function script:Read-ADAnalyzerGpo {param($Path)
            $policy=New-PolicyFixture;$policy.Files=@([pscustomobject]@{Path='Machine/GptTmpl.inf'})
            $policy.SecuritySettings=@([pscustomobject]@{Scope='Computer';Kind='Account';Name='PasswordComplexity';Value='true';ValueValid=$false;Source='Machine/GptTmpl.inf'})
            $policy
        }
        try{Assert-Throws {Import-ADAnalyzerBaseline -GpoPath fixture -Version one}}finally{Set-Item Function:script:Read-ADAnalyzerGpo $reader}
    }
    Test-Assessment 'baseline replay uses final writes and omits deleted registry values' {
        $reader=(Get-Command Read-ADAnalyzerGpo).ScriptBlock
        $script:BaselinePolicy=New-PolicyFixture;$script:BaselinePolicy.Files=@([pscustomobject]@{Path='Machine/Registry.pol'})
        $script:BaselinePolicy.RegistrySettings=@(
            [pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='X';Type=4;Value=0;KeyOnly=$false;DeletionDirective=$false}
            [pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='X';Type=4;Value=1;KeyOnly=$false;DeletionDirective=$false}
            [pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='Y';Type=4;Value=1;KeyOnly=$false;DeletionDirective=$false}
            [pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='**del.Y';Type=0;Value='';KeyOnly=$false;DeletionDirective=$true}
        )
        function script:Read-ADAnalyzerGpo {param($Path) $script:BaselinePolicy}
        try{$profile=Import-ADAnalyzerBaseline -GpoPath fixture -Version one;Assert-Equal 1 $profile.RegistryRules.Count;Assert-Equal X $profile.RegistryRules[0].ValueName;Assert-Equal 1 $profile.RegistryRules[0].Expected}finally{Set-Item Function:script:Read-ADAnalyzerGpo $reader}
    }
    Test-Assessment 'cross-policy registry type conflicts are not hidden by equal decoded values' {
        $reader=(Get-Command Read-ADAnalyzerGpo).ScriptBlock
        function script:Read-ADAnalyzerGpo {param($Path)
            $policy=New-PolicyFixture;$policy.Files=@([pscustomobject]@{Path='Machine/Registry.pol'})
            $policy.RegistrySettings=@([pscustomobject]@{Scope='Computer';Hive='HKLM';Key='Software\Fixture';ValueName='X';Type=$(if($Path -eq 'a'){4}else{5});Value=0;KeyOnly=$false;DeletionDirective=$false});$policy
        }
        try{Assert-Throws {Import-ADAnalyzerBaseline -GpoPath a,b -Version one}}finally{Set-Item Function:script:Read-ADAnalyzerGpo $reader}
    }
    Test-Assessment 'multi-string security baseline values aggregate into one set expectation' {
        $reader=(Get-Command Read-ADAnalyzerGpo).ScriptBlock
        $script:BaselinePolicy=New-PolicyFixture;$script:BaselinePolicy.Files=@([pscustomobject]@{Path='Machine/GptTmpl.inf'})
        $script:BaselinePolicy.SecuritySettings=@('LSARPC','NETLOGON','SAMR' | ForEach-Object {[pscustomobject]@{Scope='Computer';Kind='SecurityOptions';Name='Network access: Named Pipes that can be accessed anonymously';Value=$_;Source='Machine/GptTmpl.inf'}})
        function script:Read-ADAnalyzerGpo {param($Path) $script:BaselinePolicy}
        try {
            $profile=Import-ADAnalyzerBaseline -GpoPath fixture -Version one
            Assert-Equal 1 $profile.ExpectedGpoSettings.Count;Assert-True $profile.ExpectedGpoSettings[0].Aggregate 'Missing set semantics';Assert-Equal 3 $profile.ExpectedGpoSettings[0].Expected.Count
            $gpo=[pscustomobject]@{Id=[guid]::Empty;Flags=0;Links=@()}
            $checks=@(Test-ADAnalyzerGpoPolicy -Gpo $gpo -Policy $script:BaselinePolicy -Profile $profile | Where-Object RuleId -like GPO.Expected.*)
            Assert-Equal 1 $checks.Count;Assert-Equal Pass $checks[0].Status
        } finally {Set-Item Function:script:Read-ADAnalyzerGpo $reader}
    }
    Test-Assessment 'live orchestration pins each independent context to its returned DC' {
        $collector=(Get-Command Get-ADAnalyzerDirectoryData).ScriptBlock
        $script:Contexts=[Collections.ArrayList]::new();$script:RootQueries=[Collections.ArrayList]::new()
        function script:Get-ADRootDSE {param($Server,$Credential,$ErrorAction)
            $null=$script:RootQueries.Add(@{Server=$Server;Credential=$Credential})
            [pscustomobject]@{DnsHostName=$Server.Replace('alias.','dc.')}
        }
        function script:Get-ADAnalyzerDirectoryData {param($Context,$Profile)
            $null=$script:Contexts.Add($Context);New-AssessmentFixture $Context.Domain
        }
        $credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        try {
            $a=Get-ADAnalyzerAssessment -Domain a.invalid -Server alias.a.invalid -Credential $credential -SkipGpo -IncludeAcl
            $b=Get-ADAnalyzerAssessment -Domain b.invalid -Server alias.b.invalid -Credential $credential -SkipGpo -IncludeHostChecks
            Assert-Equal dc.a.invalid $a.Context.Server;Assert-Equal dc.b.invalid $b.Context.Server
            Assert-Equal a.invalid $a.Target;Assert-Equal b.invalid $b.Target
            Assert-True ([object]::ReferenceEquals($credential,$script:Contexts[0].Credential)) 'Credential lost'
            Assert-True $script:Contexts[0].IncludeAcl 'ACL option lost';Assert-True $script:Contexts[1].IncludeHostChecks 'Host option lost'
            Assert-True ($null -eq $a.Context.PSObject.Properties['Credential']) 'Credential included in public context'
        } finally {Set-Item Function:script:Get-ADAnalyzerDirectoryData $collector;Remove-Item Function:Get-ADRootDSE}
    }
    Test-Assessment 'prerequisite check detects missing package DLL without invoking RSAT install' {
        $checks=@(Get-ADAnalyzerPrerequisite -RepositoryRoot $temp)
        Assert-Equal Fail ($checks | Where-Object RuleId -eq PACKAGE.BUNDLED_AD).Status
    }
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -WhatIf:$false -Confirm:$false}
Write-Host ("{0} assessment-integration tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
