[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
. (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
. (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
$script:Passed=0;$script:Failed=0
$script:Temporary=Join-Path ([IO.Path]::GetTempPath()) ('ad-operations-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -Path $script:Temporary -ItemType Directory
function Assert-Equal($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], received [$Actual]"}}
function Assert-True($Value,[string]$Message='Assertion failed'){if(-not $Value){throw $Message}}
function Assert-Throws([scriptblock]$Body){$thrown=$false;try{& $Body}catch{$thrown=$true};if(-not $thrown){throw 'Expected a terminating failure'}}
function Reset-Fixture {
    $script:Reads=0;$script:GroupReads=0;$script:Disables=0;$script:Enables=0
    $script:FreshPrivileged=$false;$script:FreshAccountType='User';$script:Unresolved=@();$script:FailMutation=$false
    $script:SeenCredential=$null;$script:SeenServer=$null;$script:SeenIdentity=$null
    $script:Current=[pscustomobject][ordered]@{
        ObjectGuid='11111111-1111-1111-1111-111111111111';SID='S-1-5-21-10-20-30-1101'
        DistinguishedName='CN=Fixture User,OU=People,DC=example,DC=invalid';SamAccountName='fixture'
        ObjectClass='User';AccountType='User';Enabled=$true;UserAccountControl=512
        WhenChanged=[datetime]'2026-01-01T00:00:00Z';AdminCount=0;ProtectedFromAccidentalDeletion=$false
        Privileged=$false;PrivilegeResolutionStatus='Complete';IsCriticalSystemObject=$false;IsDomainController=$false
        MemberOf=@();PrimaryGroupID=513;SafetyMetadataStatus='Collected'
        SIDHistory=@();WhenCreated=[datetime]::UtcNow.AddDays(-365);lastLogonTimestamp=[datetime]::UtcNow.AddDays(-100).ToFileTimeUtc();lastLogon=0
    }
    $script:Profile=Get-ADAnalyzerDefaultProfile
    $script:Profile.Remediation.AllowDisable=$true
    $script:Profile.Remediation.ApprovedObjectGuids=@($script:Current.ObjectGuid)
    $script:Assessment=[pscustomobject]@{
        SchemaVersion=1;RunId='run-fixture';Timestamp='2026-01-01T00:00:00Z';Target='example.invalid'
        Objects=@($script:Current);Findings=@([pscustomobject]@{RuleId='ACCOUNT.INACTIVE';Status='Fail';Target=$script:Current.DistinguishedName;ObjectGuid=$script:Current.ObjectGuid;SID=$script:Current.SID;Evidence=@{DaysInactive=90};Suppressed=$false})
    }
    $script:Journal=Join-Path $script:Temporary ([guid]::NewGuid().ToString('N')+'.json')
}
function Invoke-Test([string]$Name,[scriptblock]$Body){Reset-Fixture;try{& $Body;$script:Passed++;Write-Host "PASS $Name"}catch{$script:Failed++;Write-Host "FAIL $Name : $_"}}
function Get-ADObject {
    [CmdletBinding()]param($Identity,$Properties,$Server,$Credential)
    $script:Reads++;$script:SeenIdentity=$Identity;$script:SeenServer=$Server;$script:SeenCredential=$Credential
    if([string]$Identity -ne $script:Current.ObjectGuid){throw 'Fixture query was not bound to the approved GUID'}
    return $script:Current
}
function Get-ADGroup {
    [CmdletBinding()]param($Filter,$Properties,$Server,$Credential)
    $script:GroupReads++;$script:SeenServer=$Server;$script:SeenCredential=$Credential
    [pscustomobject]@{SID='S-1-5-21-10-20-30-512';Members=@();MemberOf=@();PrimaryGroupToken=512}
}
function Resolve-ADAnalyzerMembership {
    param($Object,$Groups,$DomainSid,$PrivilegedSids)
    [pscustomobject]@{IsPrivileged=$script:FreshPrivileged;Unresolved=$script:Unresolved;DirectSids=@();EffectiveSids=@();PrivilegedSids=@();Cycles=@()}
}
function Get-ADAnalyzerAccountType {
    param($Object,$Profile,$Membership)
    [pscustomobject]@{Type=$script:FreshAccountType;Conflicting=$false;InvalidRules=@();Evidence=@()}
}
function Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess=$true)]param($Identity,$Server,$Credential)
    if(-not (Test-Path -LiteralPath $script:Journal)){throw 'No durable journal before mutation'}
    $persisted=Get-Content -LiteralPath $script:Journal -Raw|ConvertFrom-Json
    if($persisted.Entries[-1].Status -ne 'Prepared'){throw 'Mutation intent was not journaled'}
    if($script:FailMutation){throw 'Fixture mutation failure'}
    $script:Disables++;$script:Current.Enabled=$false;$script:Current.UserAccountControl=514
    $script:Current.WhenChanged=$script:Current.WhenChanged.AddSeconds(1)
    $script:SeenCredential=$Credential;$script:SeenServer=$Server
}
function Enable-ADAccount {
    [CmdletBinding(SupportsShouldProcess=$true)]param($Identity,$Server,$Credential)
    $persisted=Get-Content -LiteralPath $script:Journal -Raw|ConvertFrom-Json
    if($persisted.Entries[-1].Undo.Status -ne 'Prepared'){throw 'Undo intent was not journaled'}
    $script:Enables++;$script:Current.Enabled=$true;$script:Current.UserAccountControl=512
    $script:Current.WhenChanged=$script:Current.WhenChanged.AddSeconds(1)
    $script:SeenCredential=$Credential;$script:SeenServer=$Server
}
function New-FixturePlan {New-ADAnalyzerRemediationPlan -Assessment $script:Assessment -Profile $script:Profile}
function Apply-FixturePlan {param($Plan=(New-FixturePlan));Invoke-ADAnalyzerRemediationPlan -Plan $Plan -Server dc.example.invalid -JournalPath $script:Journal -Confirm:$false}
function Test-ConcurrentJournal([string]$Operation){
    $plan=New-FixturePlan
    if($Operation -eq 'Undo'){$null=Apply-FixturePlan $plan}
    $directory=Join-Path $script:Temporary ([guid]::NewGuid().ToString('N'));$null=New-Item -Path $directory -ItemType Directory
    $script:Current | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $directory 'state.json') -Encoding UTF8
    $plan | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath (Join-Path $directory 'plan.json') -Encoding UTF8
    $engine=(Get-Process -Id $PID).Path;$fixture=Join-Path $RepositoryRoot 'tests/JournalConcurrencyFixture.ps1';$processes=@()
    function Wait-ConcurrentStage($Process,[string]$File){
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while(-not $Process.HasExited -and -not (Test-Path -LiteralPath $File)){
            if($watch.Elapsed.TotalSeconds -gt 20){throw 'Concurrent fixture timed out'}
            Start-Sleep -Milliseconds 25
        }
    }
    try{
        foreach($role in @('First','Second')){
            $arguments='-NoLogo -NoProfile -NonInteractive -File "{0}" -RepositoryRoot "{1}" -Coordination "{2}" -JournalPath "{3}" -Role {4} -Operation {5}' -f $fixture,$RepositoryRoot,$directory,$script:Journal,$role,$Operation
            $process=Start-Process -FilePath $engine -ArgumentList $arguments -PassThru -RedirectStandardOutput (Join-Path $directory ($role+'.out')) -RedirectStandardError (Join-Path $directory ($role+'.err'))
            $processes+=,$process
            Wait-ConcurrentStage $process (Join-Path $directory ($role+'-ready'))
            if($role -eq 'First' -and $process.HasExited){throw (Get-Content -LiteralPath (Join-Path $directory 'First.err') -Raw)}
        }
        Set-Content -LiteralPath (Join-Path $directory 'First-release') -Value release
        Assert-True ($processes[0].WaitForExit(20000)) 'First writer did not complete'
        $processes[0].WaitForExit()
        Set-Content -LiteralPath (Join-Path $directory 'Second-release') -Value release
        Assert-True ($processes[1].WaitForExit(20000)) 'Second writer did not complete'
        $processes[1].WaitForExit()
        Assert-Equal 0 $processes[0].ExitCode
        Assert-True ($processes[1].ExitCode -ne 0) 'Competing writer unexpectedly completed'
        $journal=Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        $expected=if($Operation -eq 'Undo'){'Undone'}else{'Succeeded'}
        Assert-Equal 1 @($journal.Entries | Where-Object Status -eq $expected).Count
        Assert-Equal 1 @(Get-Content -LiteralPath (Join-Path $directory 'mutations.txt')).Count
        Assert-True ((Get-Content -LiteralPath (Join-Path $directory 'Second.err') -Raw) -match 'journal.*lock') 'Competing writer did not fail at the journal lease'
        Assert-Equal $false (Test-Path -LiteralPath (Join-Path $directory 'Second-reads.txt'))
    }finally{
        foreach($process in $processes){if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(5000)};$process.Dispose()}
    }
}

try {
    Invoke-Test 'safe projection is a deep copy and preserves policy thresholds' {
        $value=[pscustomobject]@{Members=@('one','two');PasswordComplexity=$true;MaximumPasswordAge=90;Nested=@{Password='fixture-secret';Credential=[pscredential]::New('fixture',(ConvertTo-SecureString 'secret' -AsPlainText -Force))}}
        $safe=ConvertTo-ADAnalyzerSafeData $value
        $safe.Members[0]='changed'
        Assert-Equal 'one' $value.Members[0]
        Assert-Equal $true $safe.Nested.PasswordPresent
        Assert-Equal $null $safe.Nested.PSObject.Properties['Password']
        Assert-Equal $true $safe.Nested.CredentialPresent
        Assert-Equal $true $safe.PasswordComplexity
        Assert-Equal 90 $safe.MaximumPasswordAge
    }
    Invoke-Test 'safe projection preserves empty and singleton array contracts' {
        $safe=ConvertTo-ADAnalyzerSafeData ([pscustomobject]@{Empty=@();One=@('one');Objects=@([pscustomobject]@{Name='one'})})
        Assert-True ($safe.Empty -is [array]);Assert-Equal 0 $safe.Empty.Count
        Assert-True ($safe.One -is [array]);Assert-Equal 1 $safe.One.Count
        Assert-True ($safe.Objects -is [array]);Assert-Equal 1 $safe.Objects.Count
    }
    Invoke-Test 'JSON HTML and CSV exports retain only secret presence and escape HTML' {
        $script:Assessment | Add-Member NoteProperty Xml '<Properties cpassword="unique-fixture-secret"><password>nested-secret</password></Properties>'
        $script:Assessment.Target='<script>fixture</script>'
        $script:Assessment.Findings[0].Evidence=@{ManagedPassword='another-fixture-secret';Xml=$script:Assessment.Xml}
        $prefix=Join-Path $script:Temporary 'assessment'
        $paths=@(Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path $prefix -Format All -Confirm:$false)
        Assert-Equal 3 $paths.Count
        foreach($path in $paths){$text=Get-Content -LiteralPath $path -Raw;Assert-True ($text -notmatch 'unique-fixture-secret|nested-secret|another-fixture-secret|\[REDACTED\]')}
        $html=Get-Content -LiteralPath ($prefix+'.html') -Raw
        Assert-True ($html -notmatch '<script>');Assert-True ($html -match '&lt;script&gt;')
        Assert-True ($script:Assessment.Xml -match 'unique-fixture-secret') 'Projection mutated the source XML'
        Assert-True ($html -match '<th>Expected</th>' -and $html -match '<th>Observed</th>' -and $html -match 'Collection coverage' -and $html -match 'View evidence') 'Readable report structure is missing'
    }
    Invoke-Test 'tagged secret evidence becomes a boolean without hiding policy values' {
        $value=@{Evidence=@{Name='cpassword';Value='tagged-secret'};PasswordHistorySize=12;EvidenceXml='<x ns:cpassword=''attribute-secret'' />'}
        $safe=ConvertTo-ADAnalyzerSafeData $value
        Assert-Equal $true $safe.Evidence.SecretPresent;Assert-Equal $null $safe.Evidence.PSObject.Properties['Value'];Assert-Equal 12 $safe.PasswordHistorySize
        Assert-True ($safe.EvidenceXml -notmatch 'attribute-secret')
        $native=ConvertTo-ADAnalyzerSafeData @{unicodePwd='native-secret';'msLAPS-EncryptedPassword'=[byte[]]@(1,2,3);ManagedPasswordIntervalInDays=30;Record=@{Name='registry';ValueName='cpassword';Expected='expected-secret';Value='value-secret'}}
        Assert-Equal $true $native.unicodePwdPresent;Assert-Equal $true $native.'msLAPS-EncryptedPasswordPresent'
        Assert-Equal 30 $native.ManagedPasswordIntervalInDays;Assert-Equal $true $native.Record.SecretPresent;Assert-Equal $null $native.Record.PSObject.Properties['Expected'];Assert-Equal $null $native.Record.PSObject.Properties['Value']
    }
    Invoke-Test 'presence is boolean for empty values and independent of expected text and property order' {
        foreach($record in @(@{Name='cpassword';Value='';Expected='no secret'},[ordered]@{Name='password';SecretPresent=$false;Value=''},[ordered]@{Name='password';Value='';SecretPresent=$false})){
            $safe=ConvertTo-ADAnalyzerSafeData $record
            Assert-Equal $false $safe.SecretPresent
            Assert-Equal $null $safe.PSObject.Properties['Expected']
        }
        $empty=ConvertTo-ADAnalyzerSafeData @{Password='';Credential=[pscredential]::Empty}
        Assert-Equal $false $empty.PasswordPresent;Assert-Equal $false $empty.CredentialPresent
    }
    Invoke-Test 'XML presence projection handles nested containers and is idempotent' {
        $xml='<Credentials><Credential userName="u" password="nested-secret" /></Credentials>'
        $safe=ConvertTo-ADAnalyzerSafeData $xml
        Assert-True ($safe -match '<CredentialsPresent>true</CredentialsPresent>') $safe
        Assert-True ($safe -notmatch 'nested-secret|REDACTED') $safe
        Assert-Equal $safe (ConvertTo-ADAnalyzerSafeData $safe)
        $safe=ConvertTo-ADAnalyzerSafeData '<Item cpasswordPresent="false" cpassword="value" password="" />'
        Assert-True ($safe -match 'cpasswordPresent="true"' -and $safe -match 'passwordPresent="false"') $safe
    }
    Invoke-Test 'empty snapshots compare deterministically' {
        $comparison=Compare-ADAnalyzerAssessment @{SchemaVersion=1;Findings=@()} @{SchemaVersion=1;Findings=@()}
        Assert-Equal 0 @($comparison.Changes).Count
    }
    Invoke-Test 'concurrent apply preserves the successful journal and blocks the stale writer before AD reads' {Test-ConcurrentJournal Apply}
    Invoke-Test 'concurrent undo preserves the successful undo and blocks the stale writer before AD reads' {Test-ConcurrentJournal Undo}
    Invoke-Test 'relative export paths follow PowerShell location rather than the process directory' {
        $location=Get-Location;$dotnet=[Environment]::CurrentDirectory
        $processDirectory=Join-Path $script:Temporary 'process-export';$psDirectory=Join-Path $script:Temporary 'powershell-export'
        $null=New-Item -Path $processDirectory,$psDirectory -ItemType Directory
        try{
            [Environment]::CurrentDirectory=$processDirectory;Set-Location -LiteralPath $psDirectory
            $path=Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path 'report.json' -Confirm:$false
            Assert-Equal (Join-Path $psDirectory 'report.json') $path
            Assert-Equal $true (Test-Path -LiteralPath (Join-Path $psDirectory 'report.json'))
            Assert-Equal $false (Test-Path -LiteralPath (Join-Path $processDirectory 'report.json'))
            Assert-Throws {Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path 'Env:\ADAnalyzerTestOutput' -Confirm:$false}
        }finally{Set-Location -LiteralPath $location.Path;[Environment]::CurrentDirectory=$dotnet}
    }
    Invoke-Test 'relative journal reads writes undo and ownership bind one path and preserve unrelated files' {
        $location=Get-Location;$dotnet=[Environment]::CurrentDirectory
        $processDirectory=Join-Path $script:Temporary 'process-journal';$psDirectory=Join-Path $script:Temporary 'powershell-journal'
        $null=New-Item -Path $processDirectory,$psDirectory -ItemType Directory
        $other=Join-Path $processDirectory 'journal.json';[IO.File]::WriteAllText($other,'unrelated journal bytes')
        try{
            [Environment]::CurrentDirectory=$processDirectory;Set-Location -LiteralPath $psDirectory
            $script:Journal='journal.json';$plan=New-FixturePlan
            $null=Apply-FixturePlan $plan
            $null=Undo-ADAnalyzerRemediation -JournalPath 'journal.json' -Server dc.example.invalid -Confirm:$false
            Assert-Equal $true $script:Current.Enabled
            Assert-Equal 'unrelated journal bytes' ([IO.File]::ReadAllText($other))
            Assert-Equal $false (Test-Path -LiteralPath ($other+'.lock'))
            Assert-Equal Undone (Get-Content -LiteralPath (Join-Path $psDirectory 'journal.json') -Raw | ConvertFrom-Json).Entries[0].Status
            $lease=Enter-ADAnalyzerJournalLease (Join-Path $psDirectory 'journal.json')
            try{
                $before=$script:Reads
                $message='';try{$null=Apply-FixturePlan $plan}catch{$message=$_.Exception.Message}
                Assert-True ($message -match 'journal.*lock') 'Relative and absolute paths did not contend for the same ownership'
                Assert-Equal $before $script:Reads
            }finally{$lease.Dispose()}
        }finally{Set-Location -LiteralPath $location.Path;[Environment]::CurrentDirectory=$dotnet}
    }
    Invoke-Test 'journal ownership is released after a failed mutation and a successful retry' {
        $plan=New-FixturePlan;$script:FailMutation=$true
        Assert-Throws {Apply-FixturePlan $plan}
        $lease=[IO.File]::Open(($script:Journal+'.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$lease.Dispose()
        $script:FailMutation=$false;$null=Apply-FixturePlan $plan
        $lease=[IO.File]::Open(($script:Journal+'.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$lease.Dispose()
        Assert-Equal 1 $script:Disables
    }
    Invoke-Test 'early result selection preserves successful evidence and releases journal ownership' {
        $plan=New-FixturePlan;$second=$plan.Actions[0] | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $second.ActionId=[guid]::NewGuid().ToString('D');$second.ObjectGuid='22222222-2222-2222-2222-222222222222';$second.Preconditions.ObjectGuid=$second.ObjectGuid
        $plan.Actions=@($plan.Actions[0],$second);$plan.Remediation.ApprovedObjectGuids+=,$second.ObjectGuid
        $result=Invoke-ADAnalyzerRemediationPlan -Plan $plan -Server dc.example.invalid -JournalPath $script:Journal -Confirm:$false | Select-Object -First 1
        Assert-Equal Succeeded $result.Status;Assert-Equal 1 $script:Disables
        $journal=Get-Content -LiteralPath $script:Journal -Raw | ConvertFrom-Json
        Assert-Equal Succeeded $journal.Entries[0].Status
        $lease=[IO.File]::Open(($script:Journal+'.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$lease.Dispose()
    }
    Invoke-Test 'named XML secret payloads become idempotent boolean presence without losing normal settings' {
        $fixtures=@(
            @('<Registry><Properties name="DefaultPassword" value="unit2-secret"/><Properties name="PasswordComplexity" value="0"/></Registry>',$true),
            @('<Setting ValueName="HKLM\Software\Fixture\DefaultPassword" Data="unit2-secret"/>',$true),
            @('<p:Setting xmlns:p="urn:fixture" p:AttributeName="PASSWORD"><p:Value>unit2-secret</p:Value></p:Setting>',$true),
            @('<Setting><Name>DefaultPassword</Name><Value>unit2-secret</Value></Setting>',$true),
            @('<Setting name="DefaultPassword"><![CDATA[unit2-secret]]></Setting>',$true),
            @('<Setting name="DefaultPassword">unit2-secret</Setting>',$true),
            @('<Setting name="DefaultPassword" value="" Expected="unit2-expected"/>',$false),
            @('<Setting><Name>DefaultPassword</Name><Value/></Setting>',$false),
            @('<Setting name="DefaultPassword" SecretPresent="true" value=""/>',$true),
            @('<Setting name="DefaultPassword" SecretPresent="false" value="unit2-secret"/>',$true)
        )
        foreach($fixture in $fixtures){
            $source=[xml]$fixture[0];$original=$source.OuterXml
            $safe=ConvertTo-ADAnalyzerSafeData $source
            Assert-True ($safe -notmatch 'unit2-secret|unit2-expected|REDACTED') $safe
            $projected=[xml]$safe;$flag=@($projected.SelectNodes('//@*') | Where-Object LocalName -eq SecretPresent)[0]
            Assert-Equal ([string]$fixture[1]).ToLowerInvariant() $flag.Value
            Assert-Equal $safe (ConvertTo-ADAnalyzerSafeData $safe)
            Assert-Equal $original $source.OuterXml
        }
        $normal=ConvertTo-ADAnalyzerSafeData '<Settings><Setting name="PasswordComplexity" value="0"/><Setting name="ClearTextPassword" value="false"/><Setting name="ManagedPasswordIntervalInDays" value="30"/></Settings>'
        Assert-True ($normal -match 'value="0"' -and $normal -match 'value="false"' -and $normal -match 'value="30"' -and $normal -notmatch 'SecretPresent') $normal
        $fragment=ConvertTo-ADAnalyzerSafeData 'prefix <Properties name="DefaultPassword" value="unit2-secret"/> suffix'
        Assert-True ($fragment -notmatch 'unit2-secret|REDACTED' -and $fragment -match 'SecretPresent="true"' -and $fragment.StartsWith('prefix ') -and $fragment.EndsWith(' suffix')) $fragment
        Assert-Equal $fragment (ConvertTo-ADAnalyzerSafeData $fragment)
        Assert-Equal 'passwordPresent="true"' (ConvertTo-ADAnalyzerSafeData 'password="unit2-secret"')
        $mixed=ConvertTo-ADAnalyzerSafeData 'password="unit2-secret" <Other/>'
        Assert-True ($mixed -notmatch 'unit2-secret' -and $mixed -match 'passwordPresent="true"') $mixed
        Assert-Equal 'Password age > 90' (ConvertTo-ADAnalyzerSafeData 'Password age > 90')
    }
    Invoke-Test 'comparison preserves evidence sequences where order is meaningful' {
        $old=@{SchemaVersion=1;Findings=@(@{RuleId='precedence';Target='a';Evidence=@{PolicySequence=@('first','second')}})}
        $new=@{SchemaVersion=1;Findings=@(@{RuleId='precedence';Target='a';Evidence=@{PolicySequence=@('second','first')}})}
        Assert-Equal 1 (Compare-ADAnalyzerAssessment $old $new).Summary.Changed
    }
    Invoke-Test 'export WhatIf has no filesystem effects' {
        $path=Join-Path $script:Temporary 'not-created/assessment.json'
        $null=Export-ADAnalyzerAssessment -Assessment $script:Assessment -Path $path -WhatIf
        Assert-Equal $false (Test-Path -LiteralPath (Split-Path -Parent $path))
    }
    Invoke-Test 'comparison returns stable four-state changes and ignores timestamp/order noise' {
        $old=[pscustomobject]@{SchemaVersion=1;RunId='old';Findings=@(
            [pscustomobject]@{RuleId='same';Target='a';Timestamp='old';Evidence=@{Members=@('one','two');Count=2}},
            [pscustomobject]@{RuleId='changed';Target='b';Evidence=@{Value=1}},
            [pscustomobject]@{RuleId='resolved';Target='c';Evidence=@{Value=1}})}
        $new=[pscustomobject]@{SchemaVersion=1;RunId='new';Findings=@(
            [pscustomobject]@{RuleId='same';Target='a';Timestamp='new';Evidence=@{Count=2;Members=@('two','one')}},
            [pscustomobject]@{RuleId='changed';Target='b';Evidence=@{Value=2}},
            [pscustomobject]@{RuleId='new';Target='d';Evidence=@{Value=1}})}
        $comparison=Compare-ADAnalyzerAssessment $old $new
        Assert-Equal 1 $comparison.Summary.Unchanged;Assert-Equal 1 $comparison.Summary.Changed
        Assert-Equal 1 $comparison.Summary.Resolved;Assert-Equal 1 $comparison.Summary.New
    }
    Invoke-Test 'comparison reads saved snapshots and accepts legacy inactivity rule labels' {
        $legacy=@{Findings=@(@{Finding='Defect - User Inactivity';Target='a';Evidence=@{Days=90}})}
        $path=Join-Path $script:Temporary 'legacy.json';$legacy|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $path
        $comparison=Compare-ADAnalyzerAssessment $path $legacy
        Assert-Equal 1 $comparison.Summary.Unchanged
        Assert-Throws {Compare-ADAnalyzerAssessment @{SchemaVersion=2;Findings=@()} $legacy}
    }
    Invoke-Test 'default remediation profile never proposes a write' {
        $plan=New-ADAnalyzerRemediationPlan -Assessment $script:Assessment
        Assert-Equal 0 @($plan.Actions).Count;Assert-Equal 'RemediationDisabled' $plan.Excluded[0].Reason
        Assert-Equal 0 $script:Reads
    }
    Invoke-Test 'only explicitly approved Fail inactivity findings become DisableAccount actions' {
        $plan=New-FixturePlan
        Assert-Equal 1 @($plan.Actions).Count;Assert-Equal 'DisableAccount' $plan.Actions[0].Action
        Assert-Equal $true $plan.Actions[0].Preconditions.Enabled
        Assert-Equal $script:Current.SID $plan.Actions[0].Preconditions.SID
        $script:Assessment.Findings[0].Status='Unknown'
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
        $script:Assessment.Findings[0].Status='Fail';$script:Profile.Remediation.ApprovedObjectGuids=@()
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    Invoke-Test 'suppressed findings and unrelated rules cannot create actions' {
        $script:Assessment.Findings[0].Suppressed=$true
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
        $script:Assessment.Findings[0].Suppressed=$false;$script:Assessment.Findings[0].RuleId='PASSWORD.AGE'
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    foreach($case in @(
        @('ObjectClass','Group'),@('SID','S-1-5-21-10-20-30-500'),@('SID','S-1-5-21-10-20-30-501'),@('SID','S-1-5-21-10-20-30-502'),
        @('AdminCount',1),@('ProtectedFromAccidentalDeletion',$true),@('Privileged',$true),@('IsCriticalSystemObject',$true),
        @('IsDomainController',$true),@('UserAccountControl',8192),@('PrimaryGroupID',516),@('PrimaryGroupID',521),
        @('AccountType','Service'),@('AccountType','Unknown'),@('PrivilegeResolutionStatus','Unknown'),@('WhenChanged',$null),
        @('SafetyMetadataStatus','Unknown'),@('UserAccountControl',$null),@('PrimaryGroupID',$null),@('ProtectedFromAccidentalDeletion',$null)
    )) {
        $field=$case[0];$value=$case[1]
        Invoke-Test ('planner excludes '+$field+'='+$value) {
            $script:Current.$field=$value
            Assert-Equal 0 @((New-FixturePlan).Actions).Count
        }
    }
    Invoke-Test 'critical exclusions survive opt-in service/privileged settings' {
        $script:Profile.Remediation.IncludeServiceAccounts=$true;$script:Profile.Remediation.IncludePrivilegedAccounts=$true
        $script:Current.AdminCount=1
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    Invoke-Test 'explicit object and OU exclusions are enforced' {
        $script:Profile.Remediation.ExcludedObjectGuids=@($script:Current.ObjectGuid)
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
        $script:Profile.Remediation.ExcludedObjectGuids=@();$script:Profile.Remediation.ExcludedOUs=@('OU=People,DC=example,DC=invalid')
        Assert-Equal 0 @((New-FixturePlan).Actions).Count
    }
    Invoke-Test 'maximum action count is enforced without replacing explicit approvals' {
        $second=$script:Current|ConvertTo-Json|ConvertFrom-Json
        $second.ObjectGuid='22222222-2222-2222-2222-222222222222';$second.SID='S-1-5-21-10-20-30-1102'
        $second.DistinguishedName='CN=Second,OU=People,DC=example,DC=invalid'
        $script:Assessment.Objects+=,$second
        $script:Assessment.Findings+=,[pscustomobject]@{RuleId='ACCOUNT.INACTIVE';Status='Fail';Target=$second.DistinguishedName;ObjectGuid=$second.ObjectGuid}
        $script:Profile.Remediation.ApprovedObjectGuids+=,$second.ObjectGuid;$script:Profile.Remediation.MaximumActions=1
        $plan=New-FixturePlan
        Assert-Equal 1 @($plan.Actions).Count;Assert-Equal 'MaximumActionsReached' $plan.Excluded[0].Reason
    }
    Invoke-Test 'plan execution WhatIf performs no query mutation or journal write' {
        $null=Invoke-ADAnalyzerRemediationPlan -Plan (New-FixturePlan) -Server dc.example.invalid -JournalPath $script:Journal -WhatIf
        Assert-Equal 0 $script:Reads;Assert-Equal 0 $script:GroupReads;Assert-Equal 0 $script:Disables
        Assert-Equal $false (Test-Path -LiteralPath $script:Journal)
        Assert-Equal $false (Test-Path -LiteralPath ($script:Journal+'.lock'))
    }
    Invoke-Test 'reviewed server context cannot be silently changed at execution' {
        $script:Assessment|Add-Member NoteProperty Context ([pscustomobject]@{Server='reviewed.example.invalid';Domain='example.invalid'})
        $plan=New-FixturePlan
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Reads;Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'execution journals intent before disabling and binds server credential GUID' {
        $credential=[pscredential]::New('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        $result=Invoke-ADAnalyzerRemediationPlan -Plan (New-FixturePlan) -Server dc.example.invalid -Credential $credential -JournalPath $script:Journal -Confirm:$false
        Assert-Equal 'Succeeded' $result.Status;Assert-Equal 1 $script:Disables
        Assert-Equal 'dc.example.invalid' $script:SeenServer;Assert-Equal $credential $script:SeenCredential
        Assert-True ($script:SeenIdentity -is [guid]);Assert-Equal $false $script:Current.Enabled
        $journal=Get-Content -LiteralPath $script:Journal -Raw|ConvertFrom-Json
        Assert-Equal $true $journal.Entries[0].Before.Enabled;Assert-Equal $false $journal.Entries[0].After.Enabled
        Assert-True ((Get-Content -LiteralPath $script:Journal -Raw) -notmatch 'fixture-only')
    }
    Invoke-Test 'failed journal persistence prevents the mutation' {
        $plan=New-FixturePlan;$script:Journal=$script:Temporary
        Assert-Throws {Apply-FixturePlan $plan}
        Assert-Equal 0 $script:Disables
    }
    foreach($case in @(@('SID','S-1-5-21-10-20-30-9999'),@('DistinguishedName','CN=Replaced,DC=example,DC=invalid'),@('Enabled',$false),@('WhenChanged',[datetime]'2026-01-02T00:00:00Z'))) {
        $field=$case[0];$value=$case[1]
        Invoke-Test ('execution rejects changed precondition '+$field) {
            $plan=New-FixturePlan;$script:Current.$field=$value
            Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Disables
        }
    }
    Invoke-Test 'fresh membership race is detected even without a user whenChanged change' {
        $plan=New-FixturePlan;$script:FreshPrivileged=$true
        Assert-Throws {Apply-FixturePlan $plan}
        Assert-Equal 1 $script:GroupReads;Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'unresolved fresh membership fails closed' {
        $script:Unresolved=@('CN=UnreadableGroup,DC=example,DC=invalid')
        Assert-Throws {Apply-FixturePlan};Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'missing fresh privilege resolver fails closed' {
        $isolated=[powershell]::Create()
        try {
            $source=". '"+(Join-Path $RepositoryRoot 'bin/ADOperations.ps1').Replace("'","''")+"'; Assert-ADAnalyzerOperationPrivilege -Object @{} -Action @{} -Plan @{} -Connection @{}"
            $message=''
            try{$null=$isolated.AddScript($source).Invoke()}catch{$message=$_.Exception.ToString()}
            $message+=($isolated.Streams.Error|Out-String)
            Assert-True ($message -match 'privilege resolver is unavailable')
        } finally {$isolated.Dispose()}
    }
    foreach($classification in @('Unknown','Service')) {
        Invoke-Test ('fresh classification change to '+$classification+' is blocked') {
            $plan=New-FixturePlan;$script:FreshAccountType=$classification
            Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Disables
        }
    }
    Invoke-Test 'fresh adminCount protection cannot be bypassed by stale evidence' {
        $plan=New-FixturePlan;$script:Current.AdminCount=1
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'unsupported deletion and duplicate object actions are rejected before reads' {
        $plan=New-FixturePlan;$plan.Actions[0].Action='Delete'
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Reads
        $plan=New-FixturePlan;$plan.Actions=@($plan.Actions[0],$plan.Actions[0])
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Reads
    }
    Invoke-Test 'failed AD mutation has failure evidence and cannot be automatically undone' {
        $script:FailMutation=$true
        Assert-Throws {Apply-FixturePlan}
        $journal=Get-Content -LiteralPath $script:Journal -Raw|ConvertFrom-Json
        Assert-Equal 'Failed' $journal.Entries[0].Status
        Assert-True ($journal.Entries[0].Message -match 'Fixture mutation failure')
        $null=Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false
        Assert-Equal 0 $script:Enables
    }
    Invoke-Test 'undo only enables a successful unchanged journaled disable' {
        $null=Apply-FixturePlan
        $result=Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false
        Assert-Equal 'Undone' $result.Status;Assert-Equal 1 $script:Enables;Assert-Equal $true $script:Current.Enabled
        $null=Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false
        Assert-Equal 1 $script:Enables
    }
    Invoke-Test 'undo WhatIf performs no read mutation or journal update' {
        $null=Apply-FixturePlan;$script:Reads=0
        $before=Get-Content -LiteralPath $script:Journal -Raw
        $lease=[IO.File]::Open(($script:Journal+'.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try{$null=Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -WhatIf}finally{$lease.Dispose()}
        Assert-Equal 0 $script:Reads;Assert-Equal 0 $script:Enables
        Assert-Equal $before (Get-Content -LiteralPath $script:Journal -Raw)
    }
    Invoke-Test 'undo rejects concurrent state changes and new privileged membership' {
        $null=Apply-FixturePlan;$script:Current.WhenChanged=$script:Current.WhenChanged.AddSeconds(30)
        Assert-Throws {Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false}
        Assert-Equal 0 $script:Enables
    }
    Invoke-Test 'undo rejects new privileged membership without a user timestamp change' {
        $null=Apply-FixturePlan;$script:FreshPrivileged=$true
        Assert-Throws {Undo-ADAnalyzerRemediation -JournalPath $script:Journal -Server dc.example.invalid -Confirm:$false}
        Assert-Equal 0 $script:Enables
        $journal=Get-Content -LiteralPath $script:Journal -Raw|ConvertFrom-Json
        Assert-Equal 'Rejected' $journal.Entries[0].Undo.Status
    }
    Invoke-Test 'passing checks still report configured drift when findings are empty' {
        $a=[pscustomobject]@{SchemaVersion=1;Findings=@();Checks=@([pscustomobject]@{RuleId='Fixture';Target='one';Status='Pass';Observed=4})}
        $b=[pscustomobject]@{SchemaVersion=1;Findings=@();Checks=@([pscustomobject]@{RuleId='Fixture';Target='one';Status='Pass';Observed=5})}
        $comparison=Compare-ADAnalyzerAssessment -Reference $a -Difference $b
        Assert-Equal 1 @($comparison.Changes | Where-Object Change -eq Changed).Count
    }
    Invoke-Test 'check status transitions distinguish a resolved finding from unknown coverage' {
        $a=[pscustomobject]@{Checks=@([pscustomobject]@{RuleId='Fixture';Target='one';Status='Fail';Observed=4})}
        $b=[pscustomobject]@{Checks=@([pscustomobject]@{RuleId='Fixture';Target='one';Status='Pass';Observed=5})}
        Assert-Equal Resolved (Compare-ADAnalyzerAssessment $a $b).Changes[0].Change
        $b.Checks[0].Status='Unknown'
        Assert-Equal Changed (Compare-ADAnalyzerAssessment $a $b).Changes[0].Change
    }
    Invoke-Test 'different targets or collection scopes cannot imply resolved findings' {
        $a=[pscustomobject]@{Target='a.invalid';Checks=@();Context=[pscustomobject]@{SearchBase='OU=People'}}
        $b=[pscustomobject]@{Target='b.invalid';Checks=@();Context=[pscustomobject]@{SearchBase='OU=People'}}
        Assert-Throws {Compare-ADAnalyzerAssessment $a $b}
        $b.Target='a.invalid';$b.Context.SearchBase='OU=Other';Assert-Throws {Compare-ADAnalyzerAssessment $a $b}
    }
    Invoke-Test 'SIDHistory requires manual review even when a GUID was approved' {
        $script:Current.SIDHistory=@('S-1-5-21-10-20-30-512')
        $plan=New-FixturePlan;Assert-Equal 0 $plan.Actions.Count;Assert-Equal SidHistoryRequiresReview $plan.Excluded[0].Reason
    }
    Invoke-Test 'fresh SIDHistory cannot bypass the approved snapshot' {
        $plan=New-FixturePlan;$script:Current.SIDHistory=@('S-1-5-21-10-20-30-512')
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'fresh local activity blocks disable even without a whenChanged update' {
        $plan=New-FixturePlan;$script:Current.lastLogon=[datetime]::UtcNow.AddMinutes(-1).ToFileTimeUtc()
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'missing fresh activity and creation evidence blocks disable' {
        $plan=New-FixturePlan;$script:Current.lastLogon=0;$script:Current.lastLogonTimestamp=0;$script:Current.WhenCreated=$null
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Disables
    }
    Invoke-Test 'reviewed DC binding rejects a different server before querying' {
        $script:Assessment | Add-Member NoteProperty Context ([pscustomobject]@{Server='reviewed.example.invalid';Domain='example.invalid'})
        $plan=New-FixturePlan
        Assert-Throws {Apply-FixturePlan $plan};Assert-Equal 0 $script:Reads
    }
}
finally {Remove-Item -LiteralPath $script:Temporary -Recurse -Force -WhatIf:$false -Confirm:$false}
Write-Host ("{0} operations tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
