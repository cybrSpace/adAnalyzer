# Assessment projections and explicit, reversible remediation. No AD query is
# performed by the exporter, comparer, or planner.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
. (Join-Path $PSScriptRoot 'ADFile.ps1')
function Get-ADAnalyzerOperationValue {
    param([AllowNull()]$Object,[string[]]$Names,[AllowNull()]$Default=$null)
    if($null -eq $Object){return $Default}
    foreach($name in $Names) {
        if($Object -is [Collections.IDictionary]) {
            if($Object.Contains($name)){return $Object[$name]}
        } else {
            $property=$Object.PSObject.Properties[$name]
            if($null -ne $property){return $property.Value}
        }
    }
    return $Default
}

function Get-ADAnalyzerOperationSecretNames {
    Get-ADAnalyzerSecretNames
}
function Protect-ADAnalyzerSecretText {
    param([string]$Text)
    ConvertTo-ADAnalyzerSecretIndicatorText $Text
}

function ConvertTo-ADAnalyzerSafeData {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][AllowNull()]$InputObject,[int]$Depth=0)
    process {
        if($null -eq $InputObject){return $null}
        if($Depth -gt 40){return '[Depth limit]'}
        if($InputObject -is [pscredential] -or $InputObject -is [Security.SecureString]){return [pscustomobject]@{SecretPresent=(Test-ADAnalyzerSecretPresence $InputObject)}}
        if($InputObject -is [string]){return Protect-ADAnalyzerSecretText $InputObject}
        if($InputObject -is [datetime]){return $InputObject.ToUniversalTime().ToString('o')}
        if($InputObject -is [datetimeoffset]){return $InputObject.ToUniversalTime().ToString('o')}
        if($InputObject -is [guid]){return $InputObject.ToString('D')}
        if($InputObject -is [ValueType]){return $InputObject}
        if($InputObject -is [Xml.XmlNode]){return Protect-ADAnalyzerSecretText $InputObject.OuterXml}
        if($InputObject -is [Collections.IEnumerable] -and $InputObject -isnot [Collections.IDictionary] -and $InputObject -isnot [pscustomobject]) {
            $items=[Collections.ArrayList]::new()
            foreach($item in $InputObject){$null=$items.Add((ConvertTo-ADAnalyzerSafeData -InputObject $item -Depth ($Depth+1)))}
            return ,$items.ToArray()
        }
        $result=[ordered]@{}
        $properties=if($InputObject -is [Collections.IDictionary]){@($InputObject.Keys)}else{@($InputObject.PSObject.Properties.Name)}
        $taggedSecret=$false
        foreach($labelName in @('Name','Attribute','AttributeName','Property','PropertyName','SettingName','ValueName')) {
            if(Test-ADAnalyzerSecretName ([string](Get-ADAnalyzerOperationValue $InputObject @($labelName)))){$taggedSecret=$true}
        }
        $present=$false;$hasPresence=$false
        foreach($name in $properties) {
            if($InputObject -is [Collections.IDictionary]){$value=$InputObject[$name]}else{$value=$InputObject.PSObject.Properties[$name].Value}
            if(Test-ADAnalyzerSecretName ([string]$name)){$result[[string]$name+'Present']=Test-ADAnalyzerSecretPresence $value}
            elseif($taggedSecret -and [string]$name -in @('Value','Observed','Expected','Data','Bytes','RawData')) {
                if($name -ne 'Expected'){$indicator=if($name -eq 'Observed' -and $value -is [bool]){$value}else{Test-ADAnalyzerSecretPresence $value};$present=$present -or $indicator;$hasPresence=$true}
            } elseif($taggedSecret -and $name -eq 'SecretPresent') {
                if($value -is [bool]){$present=$present -or $value;$hasPresence=$true}
            } else {
                $result[[string]$name]=ConvertTo-ADAnalyzerSafeData -InputObject $value -Depth ($Depth+1)
            }
        }
        if($taggedSecret -and $hasPresence){$result['SecretPresent']=$present}
        return [pscustomobject]$result
    }
}

function Read-ADAnalyzerOperationDocument {
    param([Parameter(Mandatory)]$InputObject,[string]$Kind='Assessment')
    if($InputObject -is [string]) {
        if(-not (Test-Path -LiteralPath $InputObject -PathType Leaf)){throw "$Kind file does not exist"}
        $InputObject=Microsoft.PowerShell.Management\Get-Content -LiteralPath $InputObject -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    if($null -eq $InputObject -or $InputObject -is [ValueType] -or $InputObject -is [string]){throw "$Kind must be a structured object or JSON file"}
    $version=Get-ADAnalyzerOperationValue $InputObject @('SchemaVersion')
    if($null -ne $version -and [string]$version -notmatch '^1(?:\.|$)'){throw "Unsupported $Kind SchemaVersion"}
    return $InputObject
}

function Resolve-ADAnalyzerOperationFilePath {
    param([Parameter(Mandatory)][string]$Path)
    Resolve-ADAnalyzerFilePath $Path
}
function Write-ADAnalyzerOperationFile {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    Write-ADAnalyzerFile -Path $Path -Content $Content
}

function ConvertTo-ADAnalyzerOperationHtmlValue {
    param([AllowNull()]$Value)
    if($null -eq $Value){return ''}
    if($Value -is [string] -or $Value -is [ValueType]){return [Net.WebUtility]::HtmlEncode([string]$Value)}
    return [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $Value -Depth 100 -Compress))
}
function ConvertTo-ADAnalyzerAssessmentHtml {
    param([Parameter(Mandatory)]$Assessment)
    $checks=@(Get-ADAnalyzerOperationValue $Assessment @('Checks','Findings') @() | Where-Object {$null -ne $_})
    $errors=@(Get-ADAnalyzerOperationValue $Assessment @('Errors') @() | Where-Object {$null -ne $_})
    $counts=@{}
    foreach($status in @('Pass','Fail','Unknown','Unreadable','Invalid','NotConfigured','NotApplicable')){$counts[$status]=@($checks | Where-Object Status -eq $status).Count}
    $state=if(-not $checks.Count){'No checks collected'}elseif($errors.Count -or $counts.Unknown -or $counts.Unreadable -or $counts.Invalid){'Incomplete evidence: review unknowns and collection errors'}elseif($counts.Fail){'Failed checks require review'}else{'No failed checks recorded'}
    $target=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('Target'))
    $profile=Get-ADAnalyzerOperationValue $Assessment @('Profile')
    $profileName=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Name') 'Unspecified')
    $profileVersion=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Version') '')
    $runId=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('RunId'))
    $timestamp=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('Timestamp'))
    $recordedState=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('State') 'Unspecified')
    $html=[Text.StringBuilder]::new()
    $null=$html.Append('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AD Analyzer assessment</title><style>body{font:15px system-ui,sans-serif;color:#1e293b;background:#f8fafc;max-width:1450px;margin:2rem auto;padding:0 1.2rem}h1{font-size:2rem;margin-bottom:.3rem}h2{margin-top:2rem}p{line-height:1.5}.meta{color:#475569}.state{border-left:4px solid #2563eb;padding:.8rem 1rem;background:white}.cards{display:flex;flex-wrap:wrap;gap:.6rem;margin:1.2rem 0}.card{background:white;border:1px solid #cbd5e1;border-radius:.4rem;padding:.6rem 1rem}.card b{font-size:1.4rem;display:block}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;background:white;font-size:.9rem}th,td{border:1px solid #cbd5e1;text-align:left;vertical-align:top;padding:.6rem;overflow-wrap:anywhere}th{background:#e2e8f0}.fail{color:#9f1239;font-weight:700}.pass{color:#166534}.unknown{color:#92400e}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:1rem}details{margin:.4rem 0}summary{cursor:pointer;color:#1d4ed8}.muted{color:#64748b}</style></head><body>')
    $null=$html.Append('<h1>Active Directory assessment</h1><p class="meta">Target: <strong>'+ $target +'</strong><br>Profile: '+$profileName+' '+$profileVersion+'<br>State: '+$recordedState+'<br>Run: '+$runId+'<br>Collected: '+$timestamp+'</p>')
    $null=$html.Append('<p class="state">'+[Net.WebUtility]::HtmlEncode($state)+'. Findings are evidence for review, not authorization to change directory objects.</p><div class="cards">')
    foreach($status in @('Pass','Fail','Unknown','Unreadable','Invalid','NotConfigured','NotApplicable')){$null=$html.Append('<div class="card"><b>'+[string]$counts[$status]+'</b>'+[Net.WebUtility]::HtmlEncode($status)+'</div>')}
    $null=$html.Append('</div><h2>Collection coverage</h2><div class="table"><table><thead><tr><th>Source or capability</th><th>Collection state / evidence</th></tr></thead><tbody>')
    $data=Get-ADAnalyzerOperationValue $Assessment @('Data')
    $directory=Get-ADAnalyzerOperationValue $data @('Directory')
    $coverage=Get-ADAnalyzerOperationValue $directory @('Coverage') (Get-ADAnalyzerOperationValue $Assessment @('Coverage'))
    $names=if($coverage -is [Collections.IDictionary]){@($coverage.Keys)}elseif($coverage){@($coverage.PSObject.Properties.Name)}else{@()}
    foreach($name in @($names | Sort-Object)){$null=$html.Append('<tr><td>'+[Net.WebUtility]::HtmlEncode([string]$name)+'</td><td>'+(ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $coverage @([string]$name)))+'</td></tr>')}
    if(-not $names.Count){$null=$html.Append('<tr><td colspan="2" class="muted">Coverage was not recorded.</td></tr>')}
    $null=$html.Append('</tbody></table></div><h2>Checks and findings</h2><div class="table"><table><thead><tr><th>Rule</th><th>Target</th><th>Status</th><th>Severity</th><th>Expected</th><th>Observed</th><th>Evidence</th></tr></thead><tbody>')
    foreach($check in $checks) {
        $status=[string](Get-ADAnalyzerOperationValue $check @('Status'))
        $statusClass=if($status -eq 'Fail'){'fail'}elseif($status -eq 'Pass'){'pass'}else{'unknown'}
        $statusLabel=$status+$(if([bool](Get-ADAnalyzerOperationValue $check @('Suppressed') $false)){' (suppressed)'}else{''})
        $evidence=[Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject (Get-ADAnalyzerOperationValue $check @('Evidence')) -Depth 100))
        $message=ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Message'))
        $null=$html.Append('<tr><td>'+(ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('RuleId','Finding')))+'</td><td>'+(ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Target','DistinguishedName','SID')))+'</td><td class="'+$statusClass+'">'+[Net.WebUtility]::HtmlEncode($statusLabel)+'</td><td>'+(ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Severity')))+'</td><td>'+(ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Expected')))+'</td><td>'+(ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Observed','Actual')))+'</td><td>'+$message+'<details><summary>View evidence</summary><pre>'+$evidence+'</pre></details></td></tr>')
    }
    if(-not $checks.Count){$null=$html.Append('<tr><td colspan="7" class="muted">No check results are present in this snapshot.</td></tr>')}
    $null=$html.Append('</tbody></table></div>')
    if($errors.Count){$null=$html.Append('<h2>Collection errors</h2><pre>'+[Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $errors -Depth 100))+'</pre>')}
    $null=$html.Append('<details><summary>Full assessment snapshot (secret presence only)</summary><pre>'+[Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $Assessment -Depth 100))+'</pre></details><p class="muted">Standalone report. No external scripts, fonts, or resources are loaded.</p></body></html>')
    return $html.ToString()
}

function Export-ADAnalyzerAssessment {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory)]$Assessment,[Parameter(Mandatory)][string]$Path,[ValidateSet('Json','Html','Csv','All')][string]$Format='Json')
    $document=Read-ADAnalyzerOperationDocument $Assessment
    $safe=ConvertTo-ADAnalyzerSafeData -InputObject $document
    $findings=@(Get-ADAnalyzerOperationValue $safe @('Findings','Checks') @())
    $formats=if($Format -eq 'All'){@('Json','Html','Csv')}else{@($Format)}
    foreach($item in $formats) {
        $outputPath=if($Format -eq 'All'){$Path.TrimEnd('.')+'.'+$item.ToLowerInvariant()}else{$Path}
        if(-not $PSCmdlet.ShouldProcess($outputPath,'Export assessment projection')){continue}
        switch($item) {
            'Json' {$content=ConvertTo-Json -InputObject $safe -Depth 100}
            'Html' {
                $content=ConvertTo-ADAnalyzerAssessmentHtml $safe
            }
            'Csv' {
                $rows=@(foreach($finding in $findings){[pscustomobject][ordered]@{
                    RuleId=Get-ADAnalyzerOperationValue $finding @('RuleId','Finding')
                    Target=Get-ADAnalyzerOperationValue $finding @('Target','DistinguishedName','SID')
                    Status=Get-ADAnalyzerOperationValue $finding @('Status')
                    Severity=Get-ADAnalyzerOperationValue $finding @('Severity')
                    Evidence=ConvertTo-Json -InputObject (Get-ADAnalyzerOperationValue $finding @('Evidence','Observed')) -Depth 100 -Compress
                }})
                $content=if($rows.Count){($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine}else{'"RuleId","Target","Status","Severity","Evidence"'}
            }
        }
        Write-ADAnalyzerOperationFile -Path $outputPath -Content $content
    }
}

function ConvertTo-ADAnalyzerComparableValue {
    param([AllowNull()]$Value,[string]$Field='')
    if($null -eq $Value){return $null}
    if($Value -is [string] -or $Value -is [ValueType]){return $Value}
    if($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary] -and $Value -isnot [pscustomobject]) {
        $items=@(foreach($item in $Value){ConvertTo-ADAnalyzerComparableValue $item $Field})
        if($Field -eq '' -or $Field -in @('Members','MemberOf','TransitiveGroups','EffectiveSids','DirectSids','PrivilegedSids','Unresolved','Cycles','SIDHistory','ServicePrincipalNames')) {
            return ,@(foreach($serialized in @($items | ForEach-Object {ConvertTo-Json -InputObject $_ -Depth 100 -Compress} | Sort-Object)){$serialized})
        }
        return ,$items
    }
    $output=[ordered]@{}
    $names=if($Value -is [Collections.IDictionary]){@($Value.Keys)}else{@($Value.PSObject.Properties.Name)}
    foreach($name in @($names | Sort-Object)) {
        if($name -in @('Timestamp','CollectedAt','ObservedAt','RunId','ScanId','StartedAt','CompletedAt','Duration','Elapsed','CheckId')){continue}
        if($Value -is [Collections.IDictionary]){$child=$Value[$name]}else{$child=$Value.PSObject.Properties[$name].Value}
        $output[[string]$name]=ConvertTo-ADAnalyzerComparableValue -Value $child -Field ([string]$name)
    }
    return [pscustomobject]$output
}

function Compare-ADAnalyzerAssessment {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Reference,[Parameter(Mandatory)]$Difference)
    $before=Read-ADAnalyzerOperationDocument $Reference
    $after=Read-ADAnalyzerOperationDocument $Difference
    $oldTarget=[string](Get-ADAnalyzerOperationValue $before @('Target'));$newTarget=[string](Get-ADAnalyzerOperationValue $after @('Target'))
    if($oldTarget -and $newTarget -and $oldTarget -ine $newTarget){throw 'Cannot compare different directory targets as configuration drift'}
    $oldScope=[string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $before @('Context')) @('SearchBase'))
    $newScope=[string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $after @('Context')) @('SearchBase'))
    if($oldScope -ine $newScope){throw 'Cannot compare different search-base scopes as configuration drift'}
    $maps=@(@{},@{})
    foreach($pair in @(@($before,0),@($after,1))) {
        $rows=@(Get-ADAnalyzerOperationValue $pair[0] @('Checks','Findings') @())
        foreach($row in $rows) {
            if($null -eq $row){continue}
            $rule=[string](Get-ADAnalyzerOperationValue $row @('RuleId'))
            if(-not $rule){
                $legacy=[string](Get-ADAnalyzerOperationValue $row @('Finding'))
                $rule=switch($legacy){'Defect - User Inactivity'{'ACCOUNT.INACTIVE'};'Defect - Computer Inactivity'{'COMPUTER.INACTIVE'};default{if($legacy){'LEGACY.'+$legacy}else{throw 'A snapshot finding is missing RuleId'}}}
            }
            $target=[string](Get-ADAnalyzerOperationValue $row @('Target','DistinguishedName','ObjectGuid','SID'))
            if(-not $target){throw 'A snapshot finding is missing its stable target'}
            $key=$rule.ToUpperInvariant()+[char]0+$target.ToUpperInvariant()
            if(-not $maps[$pair[1]].ContainsKey($key)){$maps[$pair[1]][$key]=[Collections.ArrayList]::new()}
            $null=$maps[$pair[1]][$key].Add((ConvertTo-ADAnalyzerSafeData -InputObject $row))
        }
    }
    $changes=@(foreach($key in @(@($maps[0].Keys)+@($maps[1].Keys) | Sort-Object -Unique)) {
        $old=@(if($maps[0].ContainsKey($key)){$maps[0][$key]});$new=@(if($maps[1].ContainsKey($key)){$maps[1][$key]});$status='Unchanged';$reason=$null
        if(-not $maps[0].ContainsKey($key)){$status='New'}
        elseif(-not $maps[1].ContainsKey($key)){$status='Changed';$reason='NotObservedInDifference'}
        else {
            $oldJson=ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $old) -Depth 100 -Compress
            $newJson=ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $new) -Depth 100 -Compress
            if($oldJson -cne $newJson){$status='Changed'}
            $oldFail=@($old | Where-Object Status -in 'Fail','Invalid').Count -gt 0
            $newFail=@($new | Where-Object Status -in 'Fail','Invalid').Count -gt 0
            $oldGood=@($old | Where-Object Status -notin 'Pass','NotApplicable').Count -eq 0
            $newGood=@($new | Where-Object Status -notin 'Pass','NotApplicable').Count -eq 0
            if($oldFail -and $newGood){$status='Resolved'}elseif($oldGood -and $newFail){$status='New'}
        }
        $sample=if($new.Count -and $null -ne $new[0]){$new[0]}else{$old[0]}
        [pscustomobject]@{RuleId=$key.Split([char]0)[0];Target=Get-ADAnalyzerOperationValue $sample @('Target','DistinguishedName','ObjectGuid','SID');Change=$status;Reason=$reason;Reference=$old;Difference=$new}
    })
    [pscustomobject][ordered]@{SchemaVersion=1;ComparisonType='ADAnalyzerAssessmentComparison';ReferenceRunId=Get-ADAnalyzerOperationValue $before @('RunId');DifferenceRunId=Get-ADAnalyzerOperationValue $after @('RunId');Timestamp=[datetimeoffset]::UtcNow.ToString('o');Changes=$changes;Summary=[pscustomobject]@{New=@($changes|Where-Object Change -eq 'New').Count;Resolved=@($changes|Where-Object Change -eq 'Resolved').Count;Changed=@($changes|Where-Object Change -eq 'Changed').Count;Unchanged=@($changes|Where-Object Change -eq 'Unchanged').Count}}
}

function ConvertTo-ADAnalyzerOperationGuid {
    param($Value)
    $guid=[guid]::Empty
    if(-not [guid]::TryParse([string]$Value,[ref]$guid) -or $guid -eq [guid]::Empty){return $null}
    return $guid.ToString('D')
}
function ConvertTo-ADAnalyzerOperationTime {
    param($Value)
    if($Value -is [datetime]){return $Value.ToUniversalTime().ToString('o')}
    if($Value -is [datetimeoffset]){return $Value.UtcDateTime.ToString('o')}
    $time=[datetimeoffset]::MinValue
    if(-not [datetimeoffset]::TryParse([string]$Value,[ref]$time)){return $null}
    return $time.UtcDateTime.ToString('o')
}
function Get-ADAnalyzerOperationSid {
    param($Object)
    $sid=Get-ADAnalyzerOperationValue $Object @('SID','ObjectSid')
    if($sid -and $sid -isnot [string]){$sid=Get-ADAnalyzerOperationValue $sid @('Value') ([string]$sid)}
    return [string]$sid
}
function Get-ADAnalyzerOperationState {
    param([Parameter(Mandatory)]$Object)
    $enabled=Get-ADAnalyzerOperationValue $Object @('Enabled')
    if($null -eq $enabled){$uac=Get-ADAnalyzerOperationValue $Object @('UserAccountControl');if($null -ne $uac){$enabled=([long]$uac -band 2) -eq 0}}
    [pscustomobject][ordered]@{
        ObjectGuid=ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $Object @('ObjectGuid'))
        SID=Get-ADAnalyzerOperationSid $Object
        DistinguishedName=[string](Get-ADAnalyzerOperationValue $Object @('DistinguishedName','DN'))
        Enabled=$enabled
        WhenChanged=ConvertTo-ADAnalyzerOperationTime (Get-ADAnalyzerOperationValue $Object @('WhenChanged'))
    }
}
function Get-ADAnalyzerOperationKind {
    param($Object)
    $classes=@(Get-ADAnalyzerOperationValue $Object @('ObjectClass','Class'))
    if($classes -contains 'computer'){return 'Computer'}
    if($classes -contains 'group'){return 'Group'}
    if($classes -contains 'user'){return 'User'}
    return 'Unknown'
}
function Get-ADAnalyzerOperationExclusion {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)]$Settings)
    $state=Get-ADAnalyzerOperationState $Object
    if(-not $state.ObjectGuid -or $state.SID -notmatch '^S-\d+(?:-\d+)+$' -or -not $state.DistinguishedName -or -not $state.WhenChanged){return 'MissingIdentityOrPreconditions'}
    if($state.Enabled -isnot [bool] -or -not $state.Enabled){return 'AccountNotEnabled'}
    $kind=Get-ADAnalyzerOperationKind $Object
    if($kind -notin @('User','Computer')){return 'UnsupportedObjectClass'}
    $metadata=[string](Get-ADAnalyzerOperationValue $Object @('SafetyMetadataStatus'))
    if($metadata -ne 'Collected'){return 'MissingSafetyEvidence'}
    foreach($name in @('ProtectedFromAccidentalDeletion','IsDomainController')) {
        if((Get-ADAnalyzerOperationValue $Object @($name)) -isnot [bool]){return 'MissingSafetyEvidence'}
    }
    $critical=Get-ADAnalyzerOperationValue $Object @('IsCriticalSystemObject')
    if($null -ne $critical -and $critical -isnot [bool]){return 'MissingSafetyEvidence'}
    if($null -eq (Get-ADAnalyzerOperationValue $Object @('UserAccountControl')) -or $null -eq (Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID'))){return 'MissingSafetyEvidence'}
    if($state.SID -match '^S-1-5-32-' -or $state.SID -match '^S-1-5-21-(?:\d+-){3}(500|501|502)$' -or [bool](Get-ADAnalyzerOperationValue $Object @('WellKnownSID') $false)){return 'WellKnownAccount'}
    $uac=Get-ADAnalyzerOperationValue $Object @('UserAccountControl') 0
    $primary=Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID') 0
    if([bool](Get-ADAnalyzerOperationValue $Object @('IsDomainController') $false) -or ([long]$uac -band 8192) -ne 0 -or [int]$primary -in @(516,521)){return 'DomainController'}
    if([int](Get-ADAnalyzerOperationValue $Object @('AdminCount') 0) -ne 0){return 'AdminCountProtected'}
    if(@(Get-ADAnalyzerOperationValue $Object @('SIDHistory') @() | Where-Object {$null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_)}).Count){return 'SidHistoryRequiresReview'}
    foreach($name in @('ProtectedFromAccidentalDeletion','ProtectedUser','Protected','IsCriticalSystemObject')) {
        if([bool](Get-ADAnalyzerOperationValue $Object @($name) $false)){return 'ProtectedOrCriticalObject'}
    }
    $membership=Get-ADAnalyzerOperationValue $Object @('Membership')
    $effective=@(Get-ADAnalyzerOperationValue $Object @('TransitiveGroups','EffectiveSids') @())+@(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
    if(@($effective | Where-Object {$_ -match '^S-1-5-21-(?:\d+-){3}525$'}).Count){return 'ProtectedOrCriticalObject'}
    if([string](Get-ADAnalyzerOperationValue $Object @('PrivilegeResolutionStatus','MembershipResolutionStatus')) -ne 'Complete'){return 'PrivilegeResolutionIncomplete'}
    $privileged=Get-ADAnalyzerOperationValue $Object @('Privileged','IsPrivileged')
    if($privileged -isnot [bool]){return 'PrivilegeResolutionIncomplete'}
    if($privileged -and -not $Settings.IncludePrivilegedAccounts){return 'PrivilegedAccount'}
    if($kind -eq 'User') {
        $accountType=[string](Get-ADAnalyzerOperationValue $Object @('AccountType'))
        if($accountType -in @('Unknown','') -or $accountType -notin @('User','Personal','Human','Service','Non-Personal','gMSA','ManagedServiceAccount')){return 'UnknownAccountClassification'}
        if($accountType -in @('Service','Non-Personal','gMSA','ManagedServiceAccount') -and -not $Settings.IncludeServiceAccounts){return 'ServiceAccount'}
    }
    foreach($excluded in @($Settings.ExcludedObjectGuids)) {
        if((ConvertTo-ADAnalyzerOperationGuid $excluded) -eq $state.ObjectGuid){return 'ExplicitObjectExclusion'}
    }
    foreach($ou in @($Settings.ExcludedOUs)) {
        if($ou -and ($state.DistinguishedName.Equals([string]$ou,[StringComparison]::OrdinalIgnoreCase) -or $state.DistinguishedName.EndsWith(','+[string]$ou,[StringComparison]::OrdinalIgnoreCase))){return 'ExcludedOrganizationalUnit'}
    }
    return $null
}

function New-ADAnalyzerRemediationPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Assessment,[AllowNull()]$Profile)
    $assessmentObject=Read-ADAnalyzerOperationDocument $Assessment
    $configuration=Import-ADAnalyzerProfile -Profile $Profile
    $settings=$configuration.Remediation
    $data=Get-ADAnalyzerOperationValue $assessmentObject @('Data')
    $directory=Get-ADAnalyzerOperationValue $data @('Directory')
    $domain=Get-ADAnalyzerOperationValue $directory @('Domain')
    $domainSid=[string](Get-ADAnalyzerOperationValue $domain @('SID','DomainSID'))
    $rootDomainSid=[string](Get-ADAnalyzerOperationValue $domain @('RootDomainSID'))
    $privilegeContextMissing=$false
    $privileged=@(Get-ADAnalyzerOperationValue $domain @('PrivilegedSids') @() | Where-Object {$null -ne $_})
    foreach($sid in @($configuration.Policy.PrivilegedSids)) {
        if(([string]$sid).Contains('{DomainSid}') -and -not $domainSid){$privilegeContextMissing=$true}
        if(([string]$sid).Contains('{RootDomainSid}') -and -not $rootDomainSid){$privilegeContextMissing=$true}
        $expanded=([string]$sid).Replace('{DomainSid}',$domainSid).Replace('{RootDomainSid}',$rootDomainSid)
        if($expanded -and $expanded -match '^S-\d-'){$privileged+=,$expanded}
    }
    $objects=@{}
    foreach($object in @(Get-ADAnalyzerOperationValue $assessmentObject @('Objects') @())) {
        if($null -eq $object){continue}
        $guid=ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $object @('ObjectGuid'))
        if($guid){$objects[$guid]=$object}
    }
    $approved=@(foreach($value in @($settings.ApprovedObjectGuids)){ConvertTo-ADAnalyzerOperationGuid $value})
    $actions=[Collections.ArrayList]::new();$excluded=[Collections.ArrayList]::new();$seen=@{}
    foreach($finding in @(Get-ADAnalyzerOperationValue $assessmentObject @('Findings') @())) {
        if($null -eq $finding){continue}
        $rule=[string](Get-ADAnalyzerOperationValue $finding @('RuleId'))
        if($rule -notin @('ACCOUNT.INACTIVE','COMPUTER.INACTIVE') -or [string](Get-ADAnalyzerOperationValue $finding @('Status')) -ne 'Fail'){continue}
        $guid=ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $finding @('ObjectGuid'))
        $reason=$null
        if(-not $settings.AllowDisable){$reason='RemediationDisabled'}
        elseif($privilegeContextMissing){$reason='PrivilegedPolicyContextMissing'}
        elseif([bool](Get-ADAnalyzerOperationValue $finding @('Suppressed') $false)){$reason='SuppressedFinding'}
        elseif(-not $guid -or -not $objects.ContainsKey($guid)){$reason='MissingObjectEvidence'}
        elseif($guid -notin $approved){$reason='ObjectNotExplicitlyApproved'}
        elseif(($rule -eq 'ACCOUNT.INACTIVE' -and (Get-ADAnalyzerOperationKind $objects[$guid]) -ne 'User') -or ($rule -eq 'COMPUTER.INACTIVE' -and (Get-ADAnalyzerOperationKind $objects[$guid]) -ne 'Computer')){$reason='RuleObjectClassMismatch'}
        else {$reason=Get-ADAnalyzerOperationExclusion $objects[$guid] $settings}
        if(-not $reason -and $actions.Count -ge $settings.MaximumActions){$reason='MaximumActionsReached'}
        if($reason){$null=$excluded.Add([pscustomobject]@{RuleId=$rule;ObjectGuid=$guid;Target=Get-ADAnalyzerOperationValue $finding @('Target');Reason=$reason});continue}
        if($seen.ContainsKey($guid)){continue};$seen[$guid]=$true
        $object=$objects[$guid];$state=Get-ADAnalyzerOperationState $object
        $null=$actions.Add([pscustomobject][ordered]@{
            ActionId=[guid]::NewGuid().ToString('D');Action='DisableAccount';RuleId=$rule
            ObjectGuid=$state.ObjectGuid;SID=$state.SID;DistinguishedName=$state.DistinguishedName
            ObjectClass=Get-ADAnalyzerOperationKind $object
            AccountType=Get-ADAnalyzerOperationValue $object @('AccountType')
            InactivityDays=$(if((Get-ADAnalyzerOperationKind $object) -eq 'Computer'){$configuration.Policy.ComputerInactivityDays}else{$configuration.Policy.UserInactivityDays})
            Preconditions=$state
        })
    }
    [pscustomobject][ordered]@{
        SchemaVersion=1;PlanType='ADAnalyzerRemediationPlan';PlanId=[guid]::NewGuid().ToString('D')
        CreatedAt=[datetimeoffset]::UtcNow.ToString('o');AssessmentRunId=Get-ADAnalyzerOperationValue $assessmentObject @('RunId')
        Target=Get-ADAnalyzerOperationValue $assessmentObject @('Target')
        Context=ConvertTo-ADAnalyzerSafeData (Get-ADAnalyzerOperationValue $assessmentObject @('Context'))
        Remediation=ConvertTo-ADAnalyzerSafeData $settings
        AccountClassification=ConvertTo-ADAnalyzerSafeData $configuration.AccountClassification
        PrivilegedSids=@($privileged | Select-Object -Unique);Actions=$actions.ToArray();Excluded=$excluded.ToArray()
    }
}

function Get-ADAnalyzerOperationConnection {
    param([string]$Server,[pscredential]$Credential)
    if($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'A DNS or NetBIOS Server is required'}
    $connection=@{Server=$Server;ErrorAction='Stop'}
    if($Credential -and $Credential -ne [pscredential]::Empty){$connection.Credential=$Credential}
    return $connection
}
function Get-ADAnalyzerOperationCurrentObject {
    param([string]$ObjectGuid,[hashtable]$Connection,$Plan)
    $properties=@('objectGUID','objectSid','distinguishedName','userAccountControl','whenChanged','whenCreated','lastLogonTimestamp','lastLogon','sIDHistory','adminCount','isCriticalSystemObject','ProtectedFromAccidentalDeletion','memberOf','primaryGroupID','sAMAccountName')
    foreach($rule in @($Plan.AccountClassification.AttributeRules)) {
        if($null -eq $rule){continue}
        $attribute=[string](Get-ADAnalyzerOperationValue $rule @('Attribute'))
        if(-not (Get-Command Test-ADAnalyzerClassificationAttribute -ErrorAction SilentlyContinue) -or -not (Test-ADAnalyzerClassificationAttribute $attribute)){throw 'Classification attribute cannot be safely re-queried'}
        $properties+=,$attribute
    }
    return Get-ADObject -Identity ([guid]$ObjectGuid) -Properties $properties @Connection
}
function Assert-ADAnalyzerOperationPreconditions {
    param($Expected,$Actual,[bool]$Enabled)
    $current=Get-ADAnalyzerOperationState $Actual
    foreach($name in @('ObjectGuid','SID','DistinguishedName','WhenChanged')) {
        $wanted=Get-ADAnalyzerOperationValue $Expected @($name)
        if($name -eq 'WhenChanged'){$wanted=ConvertTo-ADAnalyzerOperationTime $wanted}
        if($name -eq 'ObjectGuid'){$wanted=ConvertTo-ADAnalyzerOperationGuid $wanted}
        if(-not $wanted -or [string]$wanted -ine [string]$current.$name){throw "Remediation precondition failed: $name changed or is missing"}
    }
    if($Expected.Enabled -isnot [bool] -or $Expected.Enabled -ne $Enabled -or $current.Enabled -isnot [bool] -or $current.Enabled -ne $Enabled){throw 'Remediation precondition failed: Enabled changed or is missing'}
    return $current
}
function Assert-ADAnalyzerOperationPrivilege {
    param($Object,$Action,$Plan,[hashtable]$Connection)
    if(-not (Get-Command Resolve-ADAnalyzerMembership -ErrorAction SilentlyContinue)){throw 'Fresh privilege resolver is unavailable; remediation is blocked'}
    if((Get-ADAnalyzerOperationKind $Object) -ne $Action.ObjectClass){throw 'Current object class differs from the approved action'}
    $groups=@(Get-ADGroup -Filter * -Properties members,memberOf,primaryGroupToken,SID @Connection)
    $sid=Get-ADAnalyzerOperationSid $Object
    if($sid -notmatch '^(S-1-5-21-\d+-\d+-\d+)-\d+$'){throw 'A domain SID is required for fresh privilege resolution'}
    $domainSid=$Matches[1]
    $privileged=@($Plan.PrivilegedSids)+@('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-32-552')
    foreach($group in $groups){$groupSid=Get-ADAnalyzerOperationSid $group;if($groupSid -match '^S-1-5-21-(?:\d+-){3}(512|516|518|519|520|521|526|527)$'){$privileged+=,$groupSid}}
    $membership=Resolve-ADAnalyzerMembership -Object $Object -Groups $groups -DomainSid $domainSid -PrivilegedSids @($privileged | Select-Object -Unique)
    if($null -eq $membership -or @(Get-ADAnalyzerOperationValue $membership @('Unresolved') @() | Where-Object {$null -ne $_}).Count -gt 0){throw 'Fresh privilege resolution is incomplete; remediation is blocked'}
    $isPrivileged=Get-ADAnalyzerOperationValue $membership @('IsPrivileged')
    if($isPrivileged -isnot [bool]){throw 'Fresh privilege resolution did not return a definite result'}
    $state=Get-ADAnalyzerOperationState $Object
    $safe=@{ObjectGuid=$state.ObjectGuid;SID=$state.SID;DistinguishedName=$state.DistinguishedName;WhenChanged=$state.WhenChanged;Enabled=$true
        Privileged=$isPrivileged;PrivilegeResolutionStatus='Complete';AccountType=$Action.AccountType;ObjectClass=$Action.ObjectClass}
    foreach($name in @('AdminCount','ProtectedFromAccidentalDeletion','ProtectedUser','Protected','IsCriticalSystemObject','IsDomainController','UserAccountControl','PrimaryGroupID','WellKnownSID','SIDHistory')) {
        $safe[$name]=Get-ADAnalyzerOperationValue $Object @($name)
    }
    # These optional schema attributes were explicitly requested by our successful
    # query; an unset value differs from a missing or unreadable ACL-derived fact.
    if($null -eq $safe.AdminCount){$safe.AdminCount=0}
    if($null -eq $safe.IsCriticalSystemObject){$safe.IsCriticalSystemObject=$false}
    $safe.SafetyMetadataStatus='Collected'
    $safe.TransitiveGroups=@(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
    $safe.IsDomainController=([long]$safe.UserAccountControl -band 8192) -ne 0 -or [int]$safe.PrimaryGroupID -in @(516,521)
    if($Action.ObjectClass -eq 'User') {
        if(-not (Get-Command Get-ADAnalyzerAccountType -ErrorAction SilentlyContinue)){throw 'Fresh account classification is unavailable; remediation is blocked'}
        $classificationObject=@{DistinguishedName=$state.DistinguishedName;MemberOf=Get-ADAnalyzerOperationValue $Object @('MemberOf') @();DirectoryObjectClass=[string](Get-ADAnalyzerOperationValue $Object @('ObjectClass'))}
        foreach($rule in @($Plan.AccountClassification.AttributeRules)) {
            if($null -ne $rule){$attribute=[string](Get-ADAnalyzerOperationValue $rule @('Attribute'));$classificationObject[$attribute]=Get-ADAnalyzerOperationValue $Object @($attribute)}
        }
        $classificationProfile=@{AccountClassification=ConvertTo-ADAnalyzerHashtable $Plan.AccountClassification}
        $classification=Get-ADAnalyzerAccountType -Object ([pscustomobject]$classificationObject) -Profile $classificationProfile -Membership $membership
        $safe.AccountType=[string](Get-ADAnalyzerOperationValue $classification @('Type') 'Unknown')
        if($safe.AccountType -notin @('User','Service')){throw 'Fresh account classification is unknown or conflicting'}
    }
    $reason=Get-ADAnalyzerOperationExclusion $safe $Plan.Remediation
    if($reason){throw "Fresh object safety check failed: $reason"}
}

function Assert-ADAnalyzerOperationInactivity {
    param($Object,$Action)
    $days=0L
    if(-not [long]::TryParse([string]$Action.InactivityDays,[ref]$days) -or $days -lt 0){throw 'The reviewed action is missing its inactivity threshold'}
    $dates=[Collections.Generic.List[datetime]]::new()
    foreach($name in @('lastLogonTimestamp','lastLogon','LastLogonDate')) {
        $value=Get-ADAnalyzerOperationValue $Object @($name)
        if($null -eq $value -or [string]$value -eq '0'){continue}
        $fileTime=0L
        try {
            if([long]::TryParse([string]$value,[ref]$fileTime)){$dates.Add([datetime]::FromFileTimeUtc($fileTime))}
            else{$dates.Add([datetime]::Parse((ConvertTo-ADAnalyzerOperationTime $value),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime())}
        } catch {throw 'Fresh activity metadata could not be interpreted'}
    }
    if($dates.Count){$latest=$dates.ToArray() | Sort-Object -Descending | Select-Object -First 1}
    else {
        $created=Get-ADAnalyzerOperationValue $Object @('WhenCreated')
        if($null -eq $created){throw 'Fresh inactivity evidence is unavailable'}
        try{$latest=[datetime]::Parse((ConvertTo-ADAnalyzerOperationTime $created),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()}catch{throw 'Fresh creation metadata could not be interpreted'}
    }
    if(([datetime]::UtcNow-$latest).TotalDays -lt $days){throw 'Fresh activity no longer satisfies the reviewed inactivity rule'}
    # This checks known activity on the pinned DC and its replicated timestamp;
    # it is not an authoritative all-DC lastLogon sweep.
}

function Enter-ADAnalyzerJournalLease {
    param([Parameter(Mandatory)][string]$Path)
    $full=Resolve-ADAnalyzerOperationFilePath $Path
    if(Test-Path -LiteralPath $full -PathType Container){throw 'JournalPath must name a file'}
    $directory=[IO.Path]::GetDirectoryName($full)
    if(-not [IO.Directory]::Exists($directory)){$null=[IO.Directory]::CreateDirectory($directory)}
    try {
        # Keep the marker: unlinking after close can race the next owner.
        return [IO.File]::Open(($full+'.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    }catch{
        throw [IO.IOException]::new(('Unable to acquire journal lock for '+$full+'. Another run may be active or the filesystem may be unavailable.'),$_.Exception)
    }
}

function Get-ADAnalyzerOperationJournal {
    param($Plan,[string]$Server,[string]$Path)
    if(Test-Path -LiteralPath $Path) {
        if(Test-Path -LiteralPath $Path -PathType Container){throw 'JournalPath must name a file'}
        $journal=Read-ADAnalyzerOperationDocument $Path 'Journal'
        if($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.PlanId -ne $Plan.PlanId -or $journal.Server -ine $Server){throw 'Existing journal belongs to a different plan or server'}
        return $journal
    }
    [pscustomobject][ordered]@{
        SchemaVersion=1;JournalType='ADAnalyzerRemediationJournal';JournalId=[guid]::NewGuid().ToString('D')
        PlanId=$Plan.PlanId;Server=$Server;CreatedAt=[datetimeoffset]::UtcNow.ToString('o');UpdatedAt=$null
        Remediation=ConvertTo-ADAnalyzerSafeData $Plan.Remediation;PrivilegedSids=@($Plan.PrivilegedSids)
        AccountClassification=ConvertTo-ADAnalyzerSafeData $Plan.AccountClassification;Entries=@()
    }
}
function Save-ADAnalyzerOperationJournal {
    param($Journal,[string]$Path)
    $Journal.UpdatedAt=[datetimeoffset]::UtcNow.ToString('o')
    $json=ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerSafeData $Journal) -Depth 100
    $null=Write-ADAnalyzerOperationFile -Path $Path -Content $json
}
function Assert-ADAnalyzerOperationPlan {
    param($Plan)
    if($Plan.PlanType -ne 'ADAnalyzerRemediationPlan' -or -not (ConvertTo-ADAnalyzerOperationGuid $Plan.PlanId)){throw 'Only an explicit ADAnalyzer remediation plan may be executed'}
    if($Plan.Remediation.AllowDisable -isnot [bool] -or -not $Plan.Remediation.AllowDisable){throw 'The plan does not enable account disabling'}
    foreach($name in @('IncludeServiceAccounts','IncludePrivilegedAccounts')){if($Plan.Remediation.$name -isnot [bool]){throw "Invalid plan boolean setting: $name"}}
    $limit=0
    if(-not [int]::TryParse([string]$Plan.Remediation.MaximumActions,[ref]$limit) -or $limit -lt 1 -or $limit -gt 1000 -or @($Plan.Actions).Count -gt $limit){throw 'Invalid remediation action limit'}
    $approved=@(foreach($value in @($Plan.Remediation.ApprovedObjectGuids)){ConvertTo-ADAnalyzerOperationGuid $value})
    $seen=@{}
    foreach($action in @($Plan.Actions)) {
        if($null -eq $action){continue}
        $guid=ConvertTo-ADAnalyzerOperationGuid $action.ObjectGuid
        if($action.Action -ne 'DisableAccount' -or -not $guid -or $guid -notin $approved -or $action.Preconditions.ObjectGuid -ne $guid -or -not (ConvertTo-ADAnalyzerOperationGuid $action.ActionId)){throw 'Plan includes an unsupported, unapproved, or unbound action'}
        if(($action.RuleId -eq 'ACCOUNT.INACTIVE' -and $action.ObjectClass -ne 'User') -or ($action.RuleId -eq 'COMPUTER.INACTIVE' -and $action.ObjectClass -ne 'Computer') -or $action.RuleId -notin @('ACCOUNT.INACTIVE','COMPUTER.INACTIVE')){throw 'Plan rule and object class do not match'}
        $days=0L;if(-not [long]::TryParse([string]$action.InactivityDays,[ref]$days) -or $days -lt 0){throw 'Plan action is missing its reviewed inactivity threshold'}
        if($seen.ContainsKey($guid)){throw 'Plan contains duplicate object actions'};$seen[$guid]=$true
    }
}

function Invoke-ADAnalyzerRemediationPlan {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param([Parameter(Mandatory)]$Plan,[Parameter(Mandatory)][string]$Server,[pscredential]$Credential=[pscredential]::Empty,[Parameter(Mandatory)][string]$JournalPath)
    $planObject=Read-ADAnalyzerOperationDocument $Plan 'Plan'
    Assert-ADAnalyzerOperationPlan $planObject
    $JournalPath=Resolve-ADAnalyzerOperationFilePath $JournalPath
    $connection=Get-ADAnalyzerOperationConnection $Server $Credential
    $reviewedServer=[string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $planObject @('Context')) @('Server'))
    if($reviewedServer -and $reviewedServer -ine $Server){throw 'Server differs from the DC recorded in the reviewed assessment'}
    $journal=$null;$lease=$null
    try {
    foreach($action in @($planObject.Actions)) {
        if($null -eq $action){continue}
        if(-not $PSCmdlet.ShouldProcess($action.DistinguishedName,'Disable account from explicit reviewed plan')) {
            [pscustomobject]@{ActionId=$action.ActionId;ObjectGuid=$action.ObjectGuid;Status='Skipped';JournalPath=$null}
            continue
        }
        if($null -eq $journal){$lease=Enter-ADAnalyzerJournalLease $JournalPath;$journal=Get-ADAnalyzerOperationJournal $planObject $Server $JournalPath}
        if(@($journal.Entries | Where-Object {$_.ActionId -eq $action.ActionId -and $_.Status -in @('Succeeded','Undone')}).Count){throw 'This plan action has already been applied; create a fresh assessment and plan'}
        $entry=[pscustomobject][ordered]@{
            EntryId=[guid]::NewGuid().ToString('D');ActionId=$action.ActionId;Action='DisableAccount'
            ObjectGuid=$action.ObjectGuid;SID=$action.SID;DistinguishedName=$action.DistinguishedName
            ObjectClass=$action.ObjectClass;AccountType=$action.AccountType;InactivityDays=$action.InactivityDays;Timestamp=[datetimeoffset]::UtcNow.ToString('o')
            Status='Rejected';Before=$null;After=$null;Message=$null;Undo=$null
        }
        $added=$false
        try {
            $current=Get-ADAnalyzerOperationCurrentObject $action.ObjectGuid $connection $planObject
            $entry.Before=Assert-ADAnalyzerOperationPreconditions $action.Preconditions $current $true
            Assert-ADAnalyzerOperationPrivilege $current $action $planObject $connection
            Assert-ADAnalyzerOperationInactivity $current $action
            $entry.Status='Prepared'
            $journal.Entries=@($journal.Entries)+@($entry);$added=$true
            # Durable intent precedes the mutation. A failed journal write aborts.
            Save-ADAnalyzerOperationJournal $journal $JournalPath
            Disable-ADAccount -Identity ([guid]$action.ObjectGuid) @connection -WhatIf:$false -Confirm:$false
            $after=Get-ADAnalyzerOperationCurrentObject $action.ObjectGuid $connection $planObject
            $entry.After=Get-ADAnalyzerOperationState $after
            if($entry.After.ObjectGuid -ne $entry.Before.ObjectGuid -or $entry.After.SID -ne $entry.Before.SID -or $entry.After.DistinguishedName -ine $entry.Before.DistinguishedName -or $entry.After.Enabled -isnot [bool] -or $entry.After.Enabled -or -not $entry.After.WhenChanged){throw 'Unable to verify the account disable result'}
            $entry.Status='Succeeded'
            Save-ADAnalyzerOperationJournal $journal $JournalPath
        }
        catch {
            $failure=$_
            $entry.Status=if($entry.Status -eq 'Rejected'){'Rejected'}else{'Failed'}
            $entry.Message=$failure.Exception.Message
            if(-not $added){$journal.Entries=@($journal.Entries)+@($entry)}
            try {Save-ADAnalyzerOperationJournal $journal $JournalPath}
            catch {throw ('Journal persistence failed; no further changes were attempted. Inspect the durable journal before retrying. '+$failure.Exception.Message+'; '+$_.Exception.Message)}
            throw $failure
        }
        ConvertTo-ADAnalyzerSafeData $entry
    }
    }finally{if($null -ne $lease){$lease.Dispose()}}
}

function Undo-ADAnalyzerRemediation {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param([Parameter(Mandatory)][string]$JournalPath,[Parameter(Mandatory)][string]$Server,[pscredential]$Credential=[pscredential]::Empty)
    $JournalPath=Resolve-ADAnalyzerOperationFilePath $JournalPath
    $journal=Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
    if($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server){throw 'Journal type/server does not match this undo request'}
    $connection=Get-ADAnalyzerOperationConnection $Server $Credential
    $lease=$null
    try {
    foreach($candidate in @($journal.Entries | Where-Object {$_.Action -eq 'DisableAccount' -and $_.Status -eq 'Succeeded'})) {
        if(-not $PSCmdlet.ShouldProcess($candidate.DistinguishedName,'Undo a journaled account disable')) {
            [pscustomobject]@{EntryId=$candidate.EntryId;ObjectGuid=$candidate.ObjectGuid;Status='Skipped'}
            continue
        }
        if($null -eq $lease){
            $lease=Enter-ADAnalyzerJournalLease $JournalPath
            $journal=Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
            if($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server){throw 'Journal type/server does not match this undo request'}
            $plan=[pscustomobject]@{Remediation=$journal.Remediation;PrivilegedSids=$journal.PrivilegedSids;AccountClassification=$journal.AccountClassification}
        }
        $matching=@($journal.Entries | Where-Object {$_.EntryId -eq $candidate.EntryId})
        if(-not $candidate.EntryId -or $matching.Count -ne 1){throw 'Journal entry identity is missing or ambiguous'}
        $entry=$matching[0]
        if($entry.Action -ne 'DisableAccount' -or $entry.Status -ne 'Succeeded'){continue}
        try {
            if($entry.Before.Enabled -ne $true -or $entry.After.Enabled -ne $false){throw 'Journal does not contain a reversible enabled-to-disabled transition'}
            $approved=@(foreach($value in @($journal.Remediation.ApprovedObjectGuids)){ConvertTo-ADAnalyzerOperationGuid $value})
            if($entry.ObjectGuid -notin $approved -or $entry.ObjectGuid -ne $entry.Before.ObjectGuid -or $entry.ObjectGuid -ne $entry.After.ObjectGuid -or $entry.SID -ne $entry.Before.SID -or $entry.SID -ne $entry.After.SID){throw 'Journal entry identity is not bound to an approved reversible action'}
            $current=Get-ADAnalyzerOperationCurrentObject $entry.ObjectGuid $connection $plan
            $state=Assert-ADAnalyzerOperationPreconditions $entry.After $current $false
            Assert-ADAnalyzerOperationPrivilege $current $entry $plan $connection
            $entry.Undo=[pscustomobject]@{Timestamp=[datetimeoffset]::UtcNow.ToString('o');Status='Prepared';Before=$state;After=$null;Message=$null}
            Save-ADAnalyzerOperationJournal $journal $JournalPath
            Enable-ADAccount -Identity ([guid]$entry.ObjectGuid) @connection -WhatIf:$false -Confirm:$false
            $after=Get-ADAnalyzerOperationCurrentObject $entry.ObjectGuid $connection $plan
            $entry.Undo.After=Get-ADAnalyzerOperationState $after
            if($entry.Undo.After.ObjectGuid -ne $entry.Before.ObjectGuid -or $entry.Undo.After.SID -ne $entry.Before.SID -or $entry.Undo.After.DistinguishedName -ine $entry.Before.DistinguishedName -or $entry.Undo.After.Enabled -isnot [bool] -or -not $entry.Undo.After.Enabled){throw 'Unable to verify the account enable result'}
            $entry.Undo.Status='Succeeded';$entry.Status='Undone'
            Save-ADAnalyzerOperationJournal $journal $JournalPath
        }
        catch {
            $failure=$_
            if($entry.Undo){$entry.Undo.Status='Failed';$entry.Undo.Message=$failure.Exception.Message}
            else{$entry.Undo=[pscustomobject]@{Timestamp=[datetimeoffset]::UtcNow.ToString('o');Status='Rejected';Before=$null;After=$null;Message=$failure.Exception.Message}}
            try {Save-ADAnalyzerOperationJournal $journal $JournalPath}
            catch {throw ('Undo journal persistence failed; no further changes were attempted. '+$failure.Exception.Message+'; '+$_.Exception.Message)}
            throw $failure
        }
        ConvertTo-ADAnalyzerSafeData $entry
    }
    }finally{if($null -ne $lease){$lease.Dispose()}}
}
