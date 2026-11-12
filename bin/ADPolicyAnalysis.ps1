# Offline policy assessment. Directory transport and changes belong to the caller.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
function Get-ADAnalyzerPolicyValue {
    param($Object,[string]$Name,$Default=$null)
    if($null -eq $Object){return $Default}
    if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]}}
    elseif($null -ne $Object.PSObject.Properties[$Name]){return $Object.$Name}
    return $Default
}

function Get-ADAnalyzerPolicyProfileValue {
    param([hashtable]$Profile,[string]$Name,$Default)
    Get-ADAnalyzerPolicyValue (Get-ADAnalyzerPolicyValue $Profile Policy @{}) $Name $Default
}

function Get-ADAnalyzerXmlAttribute {
    param([Xml.XmlNode]$Node,[string]$Name,[string]$Default='')
    if($Node){foreach($attribute in @($Node.Attributes)){if($attribute.LocalName -ieq $Name){return $attribute.Value}}}
    return $Default
}

function Get-ADAnalyzerPresencePolicyXml {
    param([Xml.XmlNode]$Node)
    if(-not $Node){return $null}
    return (ConvertTo-ADAnalyzerSecretIndicatorXml $Node).OuterXml
}

function Get-ADAnalyzerPolicyXmlPath {
    param([Xml.XmlNode]$Node)
    $parts=@()
    while($Node -and $Node.NodeType -eq [Xml.XmlNodeType]::Element){
        $uid=Get-ADAnalyzerXmlAttribute $Node uid
        if($uid){$parts=@($Node.LocalName+'#'+$uid)+$parts;break}
        $position=1;$sibling=$Node.PreviousSibling
        while($sibling){if($sibling.NodeType -eq [Xml.XmlNodeType]::Element -and $sibling.LocalName -eq $Node.LocalName){$position++};$sibling=$sibling.PreviousSibling}
        $parts=@($Node.LocalName+'['+$position+']')+$parts;$Node=$Node.ParentNode
    }
    return $parts -join '/'
}

function Get-ADAnalyzerPolicyApplicability {
    param($Gpo,[string]$Scope,[hashtable]$Profile,[switch]$Targeted,[switch]$Disabled)
    $flags=Get-ADAnalyzerPolicyValue $Gpo Flags 0
    $bit=if($Scope -eq 'User'){1}else{2}
    if($Disabled -or ([int]$flags -band $bit)){return 'NotApplicable'}
    $links=@(Get-ADAnalyzerPolicyValue $Gpo Links @())
    if($links.Count -gt 0 -and @($links | Where-Object Enabled).Count -eq 0){return 'NotApplicable'}
    if($Targeted){return 'Unknown'}
    if(Get-ADAnalyzerPolicyValue $Gpo WmiFilter ''){return 'Unknown'}
    $analysis=Get-ADAnalyzerPolicyValue $Profile Analysis @{}
    if(Get-ADAnalyzerPolicyValue $analysis AssumeGpoApplicable $false){return 'Applicable'}
    return 'Unknown'
}

function ConvertTo-ADAnalyzerPolicyNumber {
    param($Value)
    if($Value -is [bool] -or $Value -is [array] -or $null -eq $Value){return [pscustomobject]@{Valid=$false;Value=$null}}
    $number=0L
    $valid=[long]::TryParse([string]$Value,[Globalization.NumberStyles]::Integer,[Globalization.CultureInfo]::InvariantCulture,[ref]$number)
    [pscustomobject]@{Valid=$valid;Value=$number}
}

function ConvertTo-ADAnalyzerPolicyBoolean {
    param($Value)
    if($Value -is [bool]){return [pscustomobject]@{Valid=$true;Value=$Value}}
    if($null -ne $Value -and $Value -isnot [array]){
        switch -Regex ([string]$Value) {
            '^(?i:true|1)$' {return [pscustomobject]@{Valid=$true;Value=$true}}
            '^(?i:false|0)$' {return [pscustomobject]@{Valid=$true;Value=$false}}
        }
    }
    [pscustomobject]@{Valid=$false;Value=$null}
}

function ConvertFrom-ADAnalyzerPolicyPrincipal {
    param([string]$Value)
    $token=$Value.Trim().TrimStart('*')
    $sid=$null;$valid=$true
    if($token -match '^S-\d+(-\d+)+$'){$sid=$token}
    elseif($Value.StartsWith('*') -or $token -match '^S-\d'){$valid=$false}
    [pscustomobject]@{Sid=$sid;Name=$(if(-not $sid){$token}else{$null});Valid=$valid}
}

function ConvertFrom-ADAnalyzerRestrictedGroups {
    [CmdletBinding()]
    param([object[]]$IniSettings)
    foreach($setting in @($IniSettings | Where-Object {$_.Section -ieq 'Group Membership'})){
        $match=[regex]::Match([string]$setting.Name,'^(?<group>.+)__(?<mode>Members|Memberof)$',[Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $valid=$match.Success;$group=$null;$members=@();$errorText=$null
        try {
            if($valid){
                $group=ConvertFrom-ADAnalyzerPolicyPrincipal $match.Groups['group'].Value
                $valid=$group.Valid
                if(-not [string]::IsNullOrWhiteSpace([string]$setting.Value)){
                    $members=@(Split-AnalyzerPolicyCsv ([string]$setting.Value) | ForEach-Object {$_} | ForEach-Object {ConvertFrom-ADAnalyzerPolicyPrincipal $_})
                    if(@($members | Where-Object {-not $_.Valid}).Count){$valid=$false}
                }
            }
        }catch{$valid=$false;$errorText='Malformed group membership value'}
        [pscustomobject]@{Scope=$setting.Scope;Source=$setting.Source;GroupSid=$group.Sid;GroupName=$group.Name;Mode=$match.Groups['mode'].Value;Members=$members;Valid=$valid;Error=$errorText;SettingName=$setting.Name}
    }
}

function Get-ADAnalyzerPolicyXmlRecords {
    param([object[]]$XmlFiles)
    foreach($file in @($XmlFiles)){
        try {
            $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
            $text=[IO.StringReader]::new([string]$file.Xml);$reader=[Xml.XmlReader]::Create($text,$settings)
            try{$doc=[xml]::new();$doc.XmlResolver=$null;$doc.Load($reader)}finally{$reader.Dispose();$text.Dispose()}
            [pscustomobject]@{File=$file;Document=$doc;Valid=$true}
        }catch{[pscustomobject]@{File=$file;Document=$null;Valid=$false}}
    }
}

function ConvertFrom-ADAnalyzerLocalUsersGroups {
    [CmdletBinding()]
    param([object[]]$XmlFiles)
    foreach($record in @(Get-ADAnalyzerPolicyXmlRecords $XmlFiles)){
        if(-not $record.Valid){continue}
        if($record.Document.DocumentElement.LocalName -ine 'Groups'){continue}
        foreach($item in @($record.Document.DocumentElement.ChildNodes | Where-Object {$_.NodeType -eq [Xml.XmlNodeType]::Element -and $_.LocalName -in 'Group','User'})){
            $properties=$item.SelectSingleNode('./*[local-name()="Properties"]')
            $members=@()
            foreach($member in @($(if($properties){$properties.SelectNodes('./*[local-name()="Members"]/*[local-name()="Member"]')}))){
                $sid=Get-ADAnalyzerXmlAttribute $member sid
                $principal=ConvertFrom-ADAnalyzerPolicyPrincipal $(if($sid){$sid}else{Get-ADAnalyzerXmlAttribute $member name})
                $members+= [pscustomobject]@{Sid=$principal.Sid;Name=$principal.Name;Valid=$principal.Valid;Action=(Get-ADAnalyzerXmlAttribute $member action).ToUpperInvariant()}
            }
            $action=(Get-ADAnalyzerXmlAttribute $properties action).ToUpperInvariant()
            $filters=$item.SelectSingleNode('./*[local-name()="Filters"]')
            $disabled=Get-ADAnalyzerXmlAttribute $item disabled '0'
            $targetSid=Get-ADAnalyzerXmlAttribute $properties groupSid
            if($item.LocalName -eq 'User'){$targetSid=Get-ADAnalyzerXmlAttribute $properties userSid (Get-ADAnalyzerXmlAttribute $properties sid)}
            $targetName=Get-ADAnalyzerXmlAttribute $properties $(if($item.LocalName -eq 'Group'){'groupName'}else{'userName'})
            $sidValid=-not $targetSid -or $targetSid -match '^S-\d+(-\d+)+$'
            [pscustomobject]@{Scope=$record.File.Scope;Source=$record.File.Path;Kind=$item.LocalName;Uid=(Get-ADAnalyzerXmlAttribute $item uid);Name=$targetName;Sid=$targetSid;Action=$action;Disabled=($disabled -in '1','true');AccountDisabled=(Get-ADAnalyzerXmlAttribute $properties disabled);PasswordNeverExpires=(Get-ADAnalyzerXmlAttribute $properties neverExpires);Targeted=($null -ne $filters -and $filters.HasChildNodes);Filters=(Get-ADAnalyzerPresencePolicyXml $filters);DeleteAllUsers=(Get-ADAnalyzerXmlAttribute $properties deleteAllUsers '0') -in '1','true';DeleteAllGroups=(Get-ADAnalyzerXmlAttribute $properties deleteAllGroups '0') -in '1','true';RemovePolicy=(Get-ADAnalyzerXmlAttribute $item removePolicy '0') -in '1','true';Members=$members;Valid=($null -ne $properties -and $sidValid -and $disabled -in '0','1','true','false' -and $action -in 'C','U','R','D' -and @($members | Where-Object {-not $_.Valid -or $_.Action -notin 'ADD','REMOVE'}).Count -eq 0)}
        }
    }
}

function Get-ADAnalyzerEffectiveRegistryRecords {
    param([object[]]$RegistrySettings)
    $state=@{}
    foreach($row in @($RegistrySettings)){
        $base=([string]$row.Hive+'\'+([string]$row.Key).TrimEnd('\')+'\')
        $name=[string]$row.ValueName
        if($name -match '^\*\*del\.(.*)$'){$state[$base+$Matches[1]]=[pscustomobject]@{Hive=$row.Hive;Key=$row.Key;ValueName=$Matches[1];Value=$null;Type=$row.Type;Scope=$row.Scope;Source=$row.Source;Deleted=$true};continue}
        if($name -ieq '**DeleteValues'){
            $data=if($row.Value -is [byte[]]){[Text.Encoding]::Unicode.GetString($row.Value).TrimEnd([char]0)}else{[string]$row.Value}
            foreach($entry in @($data -split ';' | Where-Object {$_})){$state[$base+$entry]=[pscustomobject]@{Hive=$row.Hive;Key=$row.Key;ValueName=$entry;Value=$null;Type=$row.Type;Scope=$row.Scope;Source=$row.Source;Deleted=$true}}
            continue
        }
        if($name -ieq '**DelVals'){
            foreach($key in @($state.Keys | Where-Object {$state[$_].Hive -ieq $row.Hive -and $state[$_].Key -ieq $row.Key})){if($null -ne $state[$key].PSObject.Properties['Value']){$state[$key].Value=$null};if($null -ne $state[$key].PSObject.Properties['SecretPresent']){$state[$key].SecretPresent=$false};$state[$key].Deleted=$true}
            continue
        }
        if($name -ieq '**DeleteKeys'){
            $data=if($row.Value -is [byte[]]){[Text.Encoding]::Unicode.GetString($row.Value).TrimEnd([char]0)}else{[string]$row.Value}
            foreach($entry in @($data -split ';' | Where-Object {$_})){
                $prefix=$base+$entry.TrimEnd('\')+'\'
                foreach($key in @($state.Keys | Where-Object {$_.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)})){if($null -ne $state[$key].PSObject.Properties['Value']){$state[$key].Value=$null};if($null -ne $state[$key].PSObject.Properties['SecretPresent']){$state[$key].SecretPresent=$false};$state[$key].Deleted=$true}
            }
            continue
        }
        if($name.StartsWith('**')){continue}
        if(-not $row.KeyOnly){$copy=[ordered]@{};foreach($property in $row.PSObject.Properties){$copy[$property.Name]=$property.Value};$copy.Deleted=$false;$state[$base+$name]=[pscustomobject]$copy}
    }
    $state.Values
}

function Get-ADAnalyzerSecuritySpecifications {
    param([hashtable]$Profile)
    $definitions=@(
        ,@('RequireSecuritySignature','SYSTEM\CurrentControlSet\Services\LanManServer\Parameters','Microsoft network server: Digitally sign communications (always)',$true)
        ,@('EnableSecuritySignature','SYSTEM\CurrentControlSet\Services\LanManServer\Parameters','Microsoft network server: Digitally sign communications (if client agrees)',$true)
        ,@('RequireSecuritySignature','SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters','Microsoft network client: Digitally sign communications (always)',$true)
        ,@('EnableSecuritySignature','SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters','Microsoft network client: Digitally sign communications (if server agrees)',$true)
        ,@('EnablePlainTextPassword','SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters','Microsoft network client: Send unencrypted password to third-party SMB servers',$false)
        ,@('RequireSignOrSeal','SYSTEM\CurrentControlSet\Services\NetLogon\Parameters','Domain member: Digitally encrypt or sign secure channel data (always)',$true)
        ,@('SealSecureChannel','SYSTEM\CurrentControlSet\Services\NetLogon\Parameters','Domain member: Digitally encrypt secure channel data (when possible)',$true)
        ,@('EveryoneIncludesAnonymous','SYSTEM\CurrentControlSet\Control\Lsa','Network access: Let Everyone permissions apply to anonymous users',$false)
        ,@('RestrictAnonymousSAM','SYSTEM\CurrentControlSet\Control\Lsa','Network access: Do not allow anonymous enumeration of SAM accounts',$true)
        ,@('RestrictAnonymous','SYSTEM\CurrentControlSet\Control\Lsa','Network access: Do not allow anonymous enumeration of SAM accounts and shares',$true)
        ,@('RestrictNullSessAccess','SYSTEM\CurrentControlSet\Services\LanManServer\Parameters','Network access: Restrict anonymous access to Named Pipes and Shares',$true)
        ,@('FilterAdministratorToken','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','User Account Control: Admin Approval Mode for the Built-in Administrator account',$true)
        ,@('EnableUIADesktopToggle','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop',$false)
        ,@('EnableInstallerDetection','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','User Account Control: Detect application installations and prompt for elevation',$true)
        ,@('EnableLUA','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','User Account Control: Run all administrators in Admin Approval Mode',$true)
    )
    foreach($definition in $definitions){[pscustomobject]@{Id=$definition[1]+'\'+$definition[0];Key=$definition[1];ValueName=$definition[0];Name=$definition[2];Kind='Boolean';Type=4;Expected=$definition[3]}}
    @(
        [pscustomobject]@{Id='Lsa.LmCompatibilityLevel';Key='SYSTEM\CurrentControlSet\Control\Lsa';ValueName='LmCompatibilityLevel';Name='Network security: LAN Manager authentication level';Kind='Lm';Type=4;Expected=(Get-ADAnalyzerPolicyProfileValue $Profile MinimumLmCompatibilityLevel 5)}
        [pscustomobject]@{Id='NTDS.LDAPServerIntegrity';Key='SYSTEM\CurrentControlSet\Services\NTDS\Parameters';ValueName='LDAPServerIntegrity';Name='Domain controller: LDAP server signing requirements';Kind='LdapServer';Type=4;Expected=$(if(Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapServerSigning $true){2}else{'Any valid value'})}
        [pscustomobject]@{Id='LDAP.LDAPClientIntegrity';Key='SYSTEM\CurrentControlSet\Services\LDAP';ValueName='LDAPClientIntegrity';Name='Network security: LDAP client signing requirements';Kind='LdapClient';Type=4;Expected=$(if(Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapClientSigning $true){2}else{'Any valid value'})}
        [pscustomobject]@{Id='UAC.ConsentPromptBehaviorAdmin';Key='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';ValueName='ConsentPromptBehaviorAdmin';Name='User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode';Kind='UacPrompt';Type=4;Expected='Prompt (1-5)'}
        [pscustomobject]@{Id='Server.NullSessionPipes';Key='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters';ValueName='NullSessionPipes';Name='Network access: Named Pipes that can be accessed anonymously';Kind='Pipes';Type=7;Expected=@(Get-ADAnalyzerPolicyProfileValue $Profile AllowedAnonymousPipes @('LSARPC','NETLOGON','SAMR'))}
        [pscustomobject]@{Id='Server.NullSessionShares';Key='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters';ValueName='NullSessionShares';Name='Network access: Shares that can be access anonymously';Kind='Shares';Type=7;Expected=@()}
        [pscustomobject]@{Id='LSAAnonymousNameLookup';Key=$null;ValueName=$null;Name='Network access: Allow anonymous SID/Name translation';Kind='Boolean';Type=$null;Expected=$false}
    )
}

function Test-ADAnalyzerPolicyComparison {
    param($Observed,$Expected,[string]$Operator='Equals')
    switch($Operator){
        {$_ -in 'Equals','Equal','eq','NotEquals','ne'} {
            $left=@($Observed);$right=@($Expected);$equal=$left.Count -eq $right.Count
            if($equal -and $left.Count){$equal=@(Compare-Object -ReferenceObject $left -DifferenceObject $right).Count -eq 0}
            if($Operator -in 'NotEquals','ne'){return -not $equal};return $equal
        }
        'In' {return @($Expected) -contains $Observed}
        'NotIn' {return @($Expected) -notcontains $Observed}
        {$_ -in 'Minimum','AtLeast','ge'} {$number=ConvertTo-ADAnalyzerPolicyNumber $Observed;if(-not $number.Valid){throw 'A numeric value is required'};return $number.Value -ge [long]$Expected}
        {$_ -in 'Maximum','AtMost','le'} {$number=ConvertTo-ADAnalyzerPolicyNumber $Observed;if(-not $number.Valid){throw 'A numeric value is required'};return $number.Value -le [long]$Expected}
        default {throw 'Unsupported comparison operator'}
    }
}

function Test-ADAnalyzerGpoPolicy {
    <# .SYNOPSIS Assesses stored GPO content without querying a domain or calculating RSoP.
       .DESCRIPTION RegistryRules entries use Id, Hive, Key, ValueName, Operator, Expected and Severity.
       ExpectedGpoSettings use Kind (Account/SecurityOptions/Registry), Name, Operator and Expected.
       Unknown applicability is preserved; a configured-risk finding is not proof that a target applies it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Gpo,[Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][hashtable]$Profile)
    Assert-ADAnalyzerValueBaseline -Profile $Profile
    $identity=[string](Get-ADAnalyzerPolicyValue $Gpo Id (Get-ADAnalyzerPolicyValue $Gpo DisplayName 'offline'))
    $target='GPO:'+ $identity
    $xmlRecords=@(Get-ADAnalyzerPolicyXmlRecords $Policy.XmlFiles)
    $secretCount=0;$xmlErrors=0
    foreach($xmlRecord in $xmlRecords){
        if(-not $xmlRecord.Valid){$xmlErrors++;New-ADAnalyzerCheck -RuleId 'GPO.Xml.Readable' -Status Unreadable -Severity Medium -Category PolicyCoverage -Target ($target+'/'+$xmlRecord.File.Path) -Observed 'Unreadable XML' -Expected 'Well-formed XML without DTDs' -Evidence @{Path=$xmlRecord.File.Path} -Message 'XML could not be parsed; its content was not included in the assessment.' -Applicability Unknown;continue}
        foreach($attribute in @($xmlRecord.Document.SelectNodes('//@*') | Where-Object {($_.LocalName -ieq 'cpassword' -and -not [string]::IsNullOrEmpty($_.Value)) -or ($_.LocalName -ieq 'cpasswordPresent' -and $_.Value -ieq 'true')})){
            $secretCount++;$item=$attribute.OwnerElement.ParentNode
            $safe=[ordered]@{Path=$xmlRecord.File.Path;ItemUid=(Get-ADAnalyzerXmlAttribute $item uid);ItemName=(Get-ADAnalyzerXmlAttribute $item name);Account=(Get-ADAnalyzerXmlAttribute $attribute.OwnerElement userName);SecretPresent=$true}
            $attributePath=(Get-ADAnalyzerPolicyXmlPath $attribute.OwnerElement)+'/@cpassword'
            $safe['Attribute']='cpassword';$safe['ItemPath']=$attributePath
            New-ADAnalyzerCheck -RuleId 'GPO.Preferences.CPassword' -Status Fail -Severity Critical -Category CredentialExposure -Target ($target+'/'+$xmlRecord.File.Path+'/'+$attributePath) -Observed $true -Expected $false -Evidence $safe -Message 'A recoverable preference credential remains in stored policy. Remove the exposed credential and rotate the affected password; only its presence is reported.' -Applicability Configured
        }
        $presenceDocument=ConvertTo-ADAnalyzerSecretIndicatorXml $xmlRecord.Document
        foreach($record in @($presenceDocument.SelectNodes('//*[@SecretPresent]'))){
            $name=Get-ADAnalyzerXmlSecretName $record
            if(-not $name){continue}
            $present=$record.GetAttribute('SecretPresent') -ieq 'true'
            $itemPath=Get-ADAnalyzerPolicyXmlPath $record
            $location=('{0}/{1}/{2}' -f $xmlRecord.File.Scope,$xmlRecord.File.Path,$itemPath)
            New-ADAnalyzerCheck -RuleId 'GPO.StoredSecret' -Status $(if($present){'Fail'}else{'Pass'}) -Severity Critical -Category CredentialExposure -Target ($target+'/'+$location) -Observed $present -Expected $false -Evidence @{SecretPresent=$present;Path=$xmlRecord.File.Path;Scope=$xmlRecord.File.Scope;ItemPath=$itemPath;SettingName=$name} -Message 'Only the presence of a named XML secret is reported; its value is omitted.' -Applicability Configured
        }
    }
    if(-not $secretCount){New-ADAnalyzerCheck -RuleId 'GPO.Preferences.CPassword' -Status $(if($xmlErrors){'Unknown'}else{'Pass'}) -Severity Critical -Category CredentialExposure -Target ($target+'/cpassword') -Observed $(if($xmlErrors){$null}else{$false}) -Expected $false -Evidence @{SecretPresent=$(if($xmlErrors){$null}else{$false});UnreadableXmlFiles=$xmlErrors} -Message 'Assessed XML contains no nonempty cpassword attribute; unreadable files prevent a complete conclusion.' -Applicability Configured}

    $storedSecrets=@(
        foreach($row in @(Get-ADAnalyzerEffectiveRegistryRecords $Policy.RegistrySettings)){
            if(-not $row.Deleted -and (Test-ADAnalyzerSecretName $row.ValueName)){$row}
        }
        foreach($row in @($Policy.IniSettings)){
            if(-not $row.Analyzed -and (Test-ADAnalyzerSecretName $row.Name)){$row}
        }
        foreach($row in @($Policy.SecuritySettings)){
            if(Test-ADAnalyzerSecretName $row.Name){$row}
        }
    )
    foreach($row in $storedSecrets){
        $name=[string](Get-ADAnalyzerPolicyValue $row ValueName (Get-ADAnalyzerPolicyValue $row Name 'secret'))
        $present=Get-ADAnalyzerPolicyValue $row SecretPresent $null
        if($null -eq $present){$present=Test-ADAnalyzerSecretPresence (Get-ADAnalyzerPolicyValue $row Value)}
        $location=('{0}/{1}/{2}/{3}' -f $row.Scope,$row.Source,(Get-ADAnalyzerPolicyValue $row Key (Get-ADAnalyzerPolicyValue $row Section '')),$name)
        New-ADAnalyzerCheck -RuleId 'GPO.StoredSecret' -Status $(if($present){'Fail'}else{'Pass'}) -Severity Critical -Category CredentialExposure -Target ($target+'/'+$location) -Observed ([bool]$present) -Expected $false -Evidence @{SecretPresent=[bool]$present;Path=$row.Source;Scope=$row.Scope;SettingName=$name} -Message 'Only the presence of a stored secret is reported; its value is omitted.' -Applicability Configured
    }

    $accountRules=@(
        ,@('MinimumPasswordLength','MinimumPasswordLength',12,'Minimum',0,65536)
        ,@('MinimumPasswordAge','MinimumPasswordAgeDays',1,'Minimum',0,999)
        ,@('PasswordHistorySize','PasswordHistorySize',10,'Minimum',0,65536)
        ,@('MaximumPasswordAge','MaximumPasswordAgeDays',90,'Age',-1,999)
        ,@('LockoutBadCount','LockoutThreshold',6,'Threshold',0,65536)
        ,@('LockoutDuration','LockoutDurationMinutes',30,'Duration',-1,99999)
        ,@('ResetLockoutCount','ResetLockoutMinutes',30,'Minimum',-4294967296,4294967296)
        ,@('PasswordComplexity','PasswordComplexity',$true,'Boolean',0,1)
        ,@('ClearTextPassword','AllowReversibleEncryption',$false,'Boolean',0,1)
    )
    foreach($rule in $accountRules){
        $rows=@($Policy.SecuritySettings | Where-Object {$_.Kind -eq 'Account' -and $_.Name -eq $rule[0]})
        $expected=Get-ADAnalyzerPolicyProfileValue $Profile $rule[1] $rule[2]
        if(-not $rows.Count){New-ADAnalyzerCheck -RuleId ('GPO.Account.'+$rule[0]) -Status NotConfigured -Severity High -Category AccountPolicy -Target ($target+'/Account/'+$rule[0]) -Observed $null -Expected $expected -Evidence $null -Message 'This setting is absent from this GPO; inherited or effective policy has not been determined.' -Applicability Unknown;continue}
        foreach($row in $rows){
            $valid=$true;$pass=$false;$semantic=$null
            if($rule[3] -eq 'Boolean'){$value=ConvertTo-ADAnalyzerPolicyBoolean $row.Value;$valid=$value.Valid;$pass=$value.Value -eq $expected}
            else{
                $value=ConvertTo-ADAnalyzerPolicyNumber $row.Value;$valid=$value.Valid -and $value.Value -ge $rule[4] -and $value.Value -le $rule[5]
                if($valid){switch($rule[3]){
                    'Minimum' {$pass=$value.Value -ge [long]$expected}
                    'Age' {$valid=$value.Value -eq -1 -or $value.Value -ge 1;if($value.Value -eq -1){$semantic='NeverExpires';$pass=[bool](Get-ADAnalyzerPolicyProfileValue $Profile AllowPasswordNeverExpires $false)}else{$pass=$value.Value -le [long]$expected}}
                    'Threshold' {if($value.Value -eq 0){$semantic='LockoutDisabled';$pass=[long]$expected -eq 0}else{$pass=[long]$expected -gt 0 -and $value.Value -le [long]$expected}}
                    'Duration' {$valid=$value.Value -eq -1 -or $value.Value -ge 1;if($value.Value -eq -1){$semantic='AdministratorUnlockRequired';$pass=$true}else{$pass=$value.Value -ge [long]$expected}}
                }}
            }
            $status=if(-not $valid){'Invalid'}elseif($pass){'Pass'}else{'Fail'}
            New-ADAnalyzerCheck -RuleId ('GPO.Account.'+$rule[0]) -Status $status -Severity High -Category AccountPolicy -Target ($target+'/'+$row.Scope+'/'+$row.Source+'/Account/'+$rule[0]) -Observed $row.Value -Expected $expected -Evidence @{Scope=$row.Scope;Path=$row.Source;Semantic=$semantic} -Message 'Stored account policy was compared with the profile. Applicability and inheritance remain separate.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $row.Scope $Profile)
        }
    }

    $registry=@(Get-ADAnalyzerEffectiveRegistryRecords $Policy.RegistrySettings)
    foreach($spec in @(Get-ADAnalyzerSecuritySpecifications $Profile)){
        $rows=@()
        foreach($raw in @($registry | Where-Object {$_.Hive -ieq 'HKLM' -and $_.Key -ieq $spec.Key -and $_.ValueName -ieq $spec.ValueName})){$rows+=[pscustomobject]@{Scope=$raw.Scope;Source=$raw.Source;Value=$raw.Value;Type=$raw.Type;Raw=$true;Deleted=$raw.Deleted}}
        foreach($setting in @($Policy.SecuritySettings | Where-Object {$_.Kind -eq 'SecurityOptions' -and $_.Name -eq $spec.Name})){
            $type=$null;$rawValue=$setting.Value;$raw=$false
            foreach($ini in @($Policy.IniSettings | Where-Object {$_.Section -eq 'Registry Values' -and $_.Scope -eq $setting.Scope -and $_.Source -eq $setting.Source -and ($_.Name -replace '^(?i)MACHINE\\','') -ieq ($spec.Key+'\'+$spec.ValueName)})){
                try{$parts=Split-AnalyzerPolicyCsv $ini.Value;$type=[int]$parts[0];$rawValue=if($type -eq 7){,$parts[1..($parts.Count-1)]}else{$parts[1..($parts.Count-1)] -join ','};$raw=$true}catch{$type=-1}
            }
            $rows+=[pscustomobject]@{Scope=$setting.Scope;Source=$setting.Source;Value=$rawValue;Type=$type;Raw=$raw;Deleted=$false}
        }
        if(-not $rows.Count){New-ADAnalyzerCheck -RuleId ('GPO.Security.'+$spec.Id) -Status NotConfigured -Severity High -Category SecurityOptions -Target ($target+'/Security/'+$spec.Id) -Observed $null -Expected $spec.Expected -Evidence @{Name=$spec.Name} -Message 'This GPO does not configure this supported baseline setting.' -Applicability Unknown;continue}
        $ordinal=0
        foreach($row in $rows){
            $ordinal++;$status='Unknown';$valid=$true;$pass=$false;$observed=$row.Value
            if($row.Deleted){$status='NotConfigured'}
            elseif($null -ne $row.Type -and $null -ne $spec.Type -and $row.Type -ne $spec.Type){$status='Invalid'}
            else{
                if($spec.Kind -eq 'Boolean'){$value=ConvertTo-ADAnalyzerPolicyBoolean $row.Value;$valid=$value.Valid;$pass=$value.Value -eq $spec.Expected}
                elseif($spec.Kind -in 'Pipes','Shares'){$values=@($row.Value | Where-Object {-not [string]::IsNullOrEmpty([string]$_)});$pass=@($values | Where-Object {@($spec.Expected) -notcontains $_}).Count -eq 0}
                else{
                    $number=ConvertTo-ADAnalyzerPolicyNumber $row.Value
                    if($row.Raw){
                        $max=if($spec.Kind -eq 'Lm' -or $spec.Kind -eq 'UacPrompt'){5}else{2};$valid=$number.Valid -and $number.Value -ge 0 -and $number.Value -le $max
                        if($valid){switch($spec.Kind){'Lm'{$pass=$number.Value -ge [long]$spec.Expected};'LdapClient'{$pass=$spec.Expected -ne 2 -or $number.Value -eq 2};'LdapServer'{$valid=$number.Value -in 0,1,2;$pass=$spec.Expected -ne 2 -or $number.Value -eq 2};'UacPrompt'{$pass=$number.Value -gt 0}}}
                    } else {
                        switch($spec.Kind){
                            'Lm'{$levels=@('Send LM & NTLM responses','Send LM & NTLM - use NTLMv2 session security if negotiated','Send NTLM response only','Send NTLMv2 response only','Send NTLMv2 response only. Refuse LM','Send NTLMv2 response only. Refuse LM & NTLM');$index=[array]::IndexOf($levels,[string]$row.Value);if([string]$row.Value -eq 'Send NTLMv2 responses only. Refuse LM & NTLM'){$index=5};$valid=$index -ge 0;$pass=$index -ge [long]$spec.Expected}
                            'LdapClient'{$valid=$row.Value -in 'None','Negotiate signing','Require signing';$pass=$spec.Expected -ne 2 -or $row.Value -eq 'Require signing'}
                            'LdapServer'{$valid=$row.Value -in 'None','Require signature','Require signing';$pass=$spec.Expected -ne 2 -or $row.Value -in 'Require signature','Require signing'}
                            'UacPrompt'{$valid=$row.Value -in 'Elevate without prompting','Prompt for credentials on the secure desktop','Prompt for consent on the secure desktop','Prompt for credentials','Prompt for consent','Prompt for consent for non-Windows binaries';$pass=$valid -and $row.Value -ne 'Elevate without prompting'}
                        }
                    }
                }
                $status=if(-not $valid){'Invalid'}elseif($pass){'Pass'}else{'Fail'}
            }
            New-ADAnalyzerCheck -RuleId ('GPO.Security.'+$spec.Id) -Status $status -Severity High -Category SecurityOptions -Target ($target+'/'+$row.Scope+'/'+$row.Source+'/Security/'+$spec.Id+'/'+$ordinal) -Observed $observed -Expected $spec.Expected -Evidence @{Name=$spec.Name;RegistryType=$row.Type;Path=$row.Source;Deleted=$row.Deleted} -Message 'Stored security policy was validated and compared with the profile; this is not a calculation of effective policy.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $row.Scope $Profile)
        }
    }

    $approved=@(Get-ADAnalyzerPolicyProfileValue $Profile ApprovedLocalAdminSids @('S-1-5-32-544'))
    $restricted=@(ConvertFrom-ADAnalyzerRestrictedGroups $Policy.IniSettings)
    foreach($group in $restricted){
        $candidates=@();$privileged=$group.GroupSid -eq 'S-1-5-32-544' -or $group.GroupName -ieq 'Administrators'
        if($group.Mode -ieq 'Memberof'){$privileged=@($group.Members | Where-Object {$_.Sid -eq 'S-1-5-32-544' -or $_.Name -ieq 'Administrators'}).Count -gt 0;$candidates=@([pscustomobject]@{Sid=$group.GroupSid;Name=$group.GroupName})}else{$candidates=@($group.Members)}
        $unknown=@($candidates | Where-Object {-not $_.Sid}).Count -gt 0
        $bad=@($candidates | Where-Object {$_.Sid -and $approved -notcontains $_.Sid})
        $status=if(-not $group.Valid){'Invalid'}elseif(-not $privileged){'NotApplicable'}elseif($bad.Count){'Fail'}elseif($unknown){'Unknown'}else{'Pass'}
        New-ADAnalyzerCheck -RuleId 'GPO.RestrictedGroups.LocalAdministrators' -Status $status -Severity High -Category RestrictedGroups -Target ($target+'/'+$group.Scope+'/'+$group.Source+'/'+$group.SettingName) -Observed $group -Expected $approved -Evidence @{Path=$group.Source;Mode=$group.Mode} -Message 'Members replaces the configured membership; MemberOf requires inclusion. Names without a SID cannot be approved by the SID allowlist.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $group.Scope $Profile)
    }
    if(-not $restricted.Count){New-ADAnalyzerCheck -RuleId 'GPO.RestrictedGroups.LocalAdministrators' -Status NotConfigured -Severity High -Category RestrictedGroups -Target ($target+'/RestrictedGroups') -Observed $null -Expected $approved -Evidence $null -Message 'No Restricted Groups configuration was found in this GPO.' -Applicability Unknown}
    $local=@(ConvertFrom-ADAnalyzerLocalUsersGroups $Policy.XmlFiles);$index=0
    foreach($item in $local){
        $index++;$privileged=$item.Sid -eq 'S-1-5-32-544' -or $item.Name -ieq 'Administrators'
        $additions=@($item.Members | Where-Object Action -eq 'ADD');$unknown=@($additions | Where-Object {-not $_.Sid}).Count -gt 0
        $bad=@($additions | Where-Object {$_.Sid -and $approved -notcontains $_.Sid})
        $status=if(-not $item.Valid){'Invalid'}elseif($item.Disabled -or $item.Action -eq 'D'){'NotApplicable'}elseif($item.Kind -ne 'Group' -or -not $privileged){'Unknown'}elseif($bad.Count){'Fail'}elseif($unknown){'Unknown'}else{'Pass'}
        New-ADAnalyzerCheck -RuleId 'GPO.Preferences.LocalUsersGroups' -Status $status -Severity High -Category LocalUsersGroups -Target ($target+'/'+$item.Scope+'/'+$item.Source+'/'+$item.Uid+'/'+$index) -Observed $item -Expected $approved -Evidence @{Path=$item.Source;Targeting=$item.Targeted;Disabled=$item.Disabled;Action=$item.Action} -Message 'Preference actions and member additions/removals are preserved. Targeting filters have not been evaluated, and an update is not a complete effective membership inventory.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $item.Scope $Profile -Targeted:$item.Targeted -Disabled:$item.Disabled)
    }
    if(-not $local.Count){New-ADAnalyzerCheck -RuleId 'GPO.Preferences.LocalUsersGroups' -Status NotConfigured -Severity High -Category LocalUsersGroups -Target ($target+'/LocalUsersGroups') -Observed $null -Expected $approved -Evidence $null -Message 'No Local Users and Groups preference was found in this GPO.' -Applicability Unknown}

    $rights=Get-ADAnalyzerPolicyProfileValue $Profile AllowedUserRightSids @{}
    foreach($right in @($Policy.SecuritySettings | Where-Object Kind -eq 'UserRightsAssignment')){
        $principals=@($right.Value | ForEach-Object {ConvertFrom-ADAnalyzerPolicyPrincipal ([string]$_)})
        $hasAllowlist=$rights -is [Collections.IDictionary] -and $rights.Contains($right.Name)
        $expected=$null;if($hasAllowlist){$expected=@($rights[$right.Name])}
        $status=if(@($principals | Where-Object {-not $_.Valid}).Count){'Invalid'}elseif(-not $hasAllowlist -or @($principals | Where-Object {-not $_.Sid}).Count){'Unknown'}elseif(@($principals | Where-Object {@($expected) -notcontains $_.Sid}).Count){'Fail'}else{'Pass'}
        New-ADAnalyzerCheck -RuleId ('GPO.UserRights.'+$right.Name) -Status $status -Severity High -Category UserRightsAssignment -Target ($target+'/'+$right.Scope+'/'+$right.Source+'/'+$right.Name) -Observed $principals -Expected $expected -Evidence @{Path=$right.Source;Right=$right.Name} -Message 'User rights are compared with exact approved SIDs, never principal-name substrings. An unspecified allowlist is Unknown.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $right.Scope $Profile)
    }
    if($rights -is [Collections.IDictionary]){foreach($name in $rights.Keys){if(-not @($Policy.SecuritySettings | Where-Object {$_.Kind -eq 'UserRightsAssignment' -and $_.Name -eq $name}).Count){New-ADAnalyzerCheck -RuleId ('GPO.UserRights.'+$name) -Status NotConfigured -Severity High -Category UserRightsAssignment -Target ($target+'/UserRights/'+$name) -Observed $null -Expected $rights[$name] -Evidence $null -Message 'This configured baseline right is absent from this GPO.' -Applicability Unknown}}}

    foreach($rule in @(Get-ADAnalyzerPolicyValue $Profile RegistryRules @()) + @(Get-ADAnalyzerPolicyValue $Profile ExpectedGpoSettings @())){
        $kind=Get-ADAnalyzerPolicyValue $rule Kind 'Registry';$name=Get-ADAnalyzerPolicyValue $rule Name ''; $id=Get-ADAnalyzerPolicyValue $rule RuleId (Get-ADAnalyzerPolicyValue $rule Id ($kind+'.'+$name+'.'+$rule.Key+'.'+$rule.ValueName))
        $severity=Get-ADAnalyzerPolicyValue $rule Severity 'Medium';$expected=$rule.Expected;$operator=Get-ADAnalyzerPolicyValue $rule Operator 'Equals'
        $matches=@(if($kind -eq 'Registry'){$registry | Where-Object {$_.Hive -ieq (Get-ADAnalyzerPolicyValue $rule Hive 'HKLM') -and $_.Key -ieq $rule.Key -and $_.ValueName -ieq $rule.ValueName -and -not $_.Deleted}}else{$Policy.SecuritySettings | Where-Object {$_.Kind -eq $kind -and $_.Name -eq $name}})
        $scope=Get-ADAnalyzerPolicyValue $rule Scope ''
        if($scope){$matches=@($matches | Where-Object {$_.Scope -ieq $scope})}
        if(-not $matches.Count){New-ADAnalyzerCheck -RuleId ('GPO.Expected.'+$id) -Status NotConfigured -Severity $severity -Category PolicyBaseline -Target ($target+'/Expected/'+$id+'/'+$scope) -Observed $null -Expected $expected -Evidence @{Kind=$kind;Name=$name;Scope=$scope} -Message 'The expected setting is not configured in the requested GPO scope; effective policy remains unknown.' -Applicability Unknown;continue}
        $expectedType=Get-ADAnalyzerPolicyValue $rule Type $null
        $typeAliases=@{REG_NONE=0;REG_SZ=1;REG_EXPAND_SZ=2;REG_BINARY=3;REG_DWORD=4;REG_DWORD_BIG_ENDIAN=5;REG_MULTI_SZ=7;REG_QWORD=11}
        if($null -ne $expectedType -and $typeAliases.ContainsKey([string]$expectedType)){$expectedType=$typeAliases[[string]$expectedType]}
        if(Get-ADAnalyzerPolicyValue $rule Aggregate $false) {
            foreach($group in @($matches | Group-Object Scope,Source)) {
                $sample=$group.Group[0];$observed=@($group.Group | ForEach-Object { $_.Value })
                $checkTarget=$target+'/Expected/'+$id+'/Aggregate/'+$sample.Scope+'/'+([string]$sample.Source).Replace('\','/')
                try {
                    if($kind -eq 'Registry' -and $null -ne $expectedType) {
                        $declared=ConvertTo-ADAnalyzerPolicyNumber $expectedType
                        foreach($record in $group.Group) {$actual=ConvertTo-ADAnalyzerPolicyNumber $record.Type;if(-not $declared.Valid -or -not $actual.Valid -or $declared.Value -ne $actual.Value){throw 'The registry data type does not match the baseline'}}
                    }
                    $status=if(Test-ADAnalyzerPolicyComparison $observed $expected $operator){'Pass'}else{'Fail'}
                } catch {$status='Invalid'}
                New-ADAnalyzerCheck -RuleId ('GPO.Expected.'+$id) -Status $status -Severity $severity -Category PolicyBaseline -Target $checkTarget -Observed $observed -Expected $expected -Evidence @{Path=$sample.Source;Scope=$sample.Scope;Operator=$operator;Aggregate=$true;ExpectedRegistryType=$expectedType} -Message 'The complete configured value collection was compared as a set within its source and scope.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $sample.Scope $Profile)
            }
            continue
        }
        $identities=@{};$occurrences=@{}
        foreach($row in $matches){
            $settingIdentity=if($kind -eq 'Registry'){[string]$row.Hive+'/'+$row.Key+'/'+$row.ValueName}else{$kind+'/'+$row.Name}
            $rowIdentity=([string]$row.Source).Replace('\','/')+'/'+$row.Scope+'/'+$settingIdentity
            if(-not $identities.ContainsKey($rowIdentity)){$identities[$rowIdentity]=0};$identities[$rowIdentity]++
        }
        foreach($row in $matches){
            $settingIdentity=if($kind -eq 'Registry'){[string]$row.Hive+'/'+$row.Key+'/'+$row.ValueName}else{$kind+'/'+$row.Name}
            $rowIdentity=([string]$row.Source).Replace('\','/')+'/'+$row.Scope+'/'+$settingIdentity
            if(-not $occurrences.ContainsKey($rowIdentity)){$occurrences[$rowIdentity]=0};$occurrences[$rowIdentity]++
            $checkTarget=$target+'/Expected/'+$id+'/'+$rowIdentity
            if($identities[$rowIdentity] -gt 1){$checkTarget+='/duplicate/'+$occurrences[$rowIdentity]}
            try{
                if($kind -eq 'Registry' -and $null -ne $expectedType){
                    $declared=ConvertTo-ADAnalyzerPolicyNumber $expectedType;$actual=ConvertTo-ADAnalyzerPolicyNumber $row.Type
                    if(-not $declared.Valid -or -not $actual.Valid -or $declared.Value -ne $actual.Value){throw 'The registry data type does not match the baseline'}
                }
                $pass=Test-ADAnalyzerPolicyComparison $row.Value $expected $operator;$status=if($pass){'Pass'}else{'Fail'}
            }catch{$status='Invalid'}
            New-ADAnalyzerCheck -RuleId ('GPO.Expected.'+$id) -Status $status -Severity $severity -Category PolicyBaseline -Target $checkTarget -Observed $row.Value -Expected $expected -Evidence @{Path=$row.Source;Scope=$row.Scope;Operator=$operator;RegistryType=$row.Type;ExpectedRegistryType=$expectedType} -Message 'Stored setting scope, registry type when specified, and value were assessed against the configured baseline rule.' -Applicability (Get-ADAnalyzerPolicyApplicability $Gpo $row.Scope $Profile)
        }
    }
    if(@($Policy.UnparsedFiles).Count){New-ADAnalyzerCheck -RuleId 'GPO.Coverage.UnsupportedFiles' -Status Unknown -Severity Information -Category PolicyCoverage -Target ($target+'/UnsupportedFiles') -Observed @($Policy.UnparsedFiles | Select-Object Scope,Path,Kind) -Expected 'Supported parsed content' -Evidence $null -Message 'Unsupported files remain inventoried; their policy behavior was not assessed.' -Applicability Unknown}
}

function Get-ADAnalyzerAdmxValue {
    param([Xml.XmlNode]$Node)
    if(-not $Node){return [pscustomobject]@{Valid=$false;Value=$null;Deleted=$false}}
    $value=$Node.SelectSingleNode('./*[1]')
    if(-not $value){return [pscustomobject]@{Valid=$false;Value=$null;Deleted=$false}}
    switch($value.LocalName){
        'decimal' {$n=ConvertTo-ADAnalyzerPolicyNumber (Get-ADAnalyzerXmlAttribute $value value);return [pscustomobject]@{Valid=$n.Valid;Value=$n.Value;Deleted=$false}}
        'longDecimal' {$n=ConvertTo-ADAnalyzerPolicyNumber (Get-ADAnalyzerXmlAttribute $value value);return [pscustomobject]@{Valid=$n.Valid;Value=$n.Value;Deleted=$false}}
        'string' {return [pscustomobject]@{Valid=$true;Value=$value.InnerText;Deleted=$false}}
        'delete' {return [pscustomobject]@{Valid=$true;Value=$null;Deleted=$true}}
    }
    [pscustomobject]@{Valid=$false;Value=$null;Deleted=$false}
}

function Resolve-ADAnalyzerRegistryPolicy {
    <# .SYNOPSIS Adds optional offline ADMX/ADML metadata while preserving raw policy records.
       .DESCRIPTION Supports policy enabled/disabled values and boolean, enum and list elements.
       Complex multi-key definitions retain explicit Unknown state; no template is required for parsing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistrySettings,[string]$TemplatePath,[string]$Language='en-US')
    $definitions=@();$errors=@();$templateMissing=-not $TemplatePath -or -not (Test-Path -LiteralPath $TemplatePath -PathType Container)
    if(-not $templateMissing){
        foreach($file in @(Get-ChildItem -LiteralPath $TemplatePath -Filter '*.admx' -File -ErrorAction Stop)){
            try {
                $xml=Read-AnalyzerPolicyXml $file.FullName;$resources=@{};$languageMissing=$false
                $resourcePath=Join-Path (Join-Path $TemplatePath $Language) ($file.BaseName+'.adml')
                if(Test-Path -LiteralPath $resourcePath -PathType Leaf){$adml=Read-AnalyzerPolicyXml $resourcePath;foreach($resource in @($adml.SelectNodes('//*[local-name()="stringTable"]/*[local-name()="string"]'))){$resources[(Get-ADAnalyzerXmlAttribute $resource id)]=$resource.InnerText}}else{$languageMissing=$true}
                $namespace=Get-ADAnalyzerXmlAttribute ($xml.SelectSingleNode('//*[local-name()="policyNamespaces"]/*[local-name()="target"]')) namespace
                foreach($policy in @($xml.SelectNodes('//*[local-name()="policies"]/*[local-name()="policy"]'))){
                    $key=Get-ADAnalyzerXmlAttribute $policy key;$valueName=Get-ADAnalyzerXmlAttribute $policy valueName;$name=Get-ADAnalyzerXmlAttribute $policy name;$display=Get-ADAnalyzerXmlAttribute $policy displayName
                    if($display -match '^\$\(string\.(.+)\)$'){if($resources.ContainsKey($Matches[1])){$display=$resources[$Matches[1]]}else{$languageMissing=$true;$display=$name}}
                    $common=@{PolicyId=$name;PolicyNamespace=$namespace;DisplayName=$display;Class=(Get-ADAnalyzerXmlAttribute $policy class);Template=$file.Name;LanguageMissing=$languageMissing;Resources=$resources}
                    if($valueName){$definitions+=[pscustomobject]@{Common=$common;Kind='Policy';Key=$key;ValueName=$valueName;ElementId=$null;Node=$policy}}
                    foreach($element in @($policy.SelectNodes('./*[local-name()="elements"]/*'))){$elementKey=Get-ADAnalyzerXmlAttribute $element key $key;$elementName=Get-ADAnalyzerXmlAttribute $element valueName;$definitions+=[pscustomobject]@{Common=$common;Kind=$element.LocalName;Key=$elementKey;ValueName=$elementName;ElementId=(Get-ADAnalyzerXmlAttribute $element id);Node=$element}}
                    foreach($list in @($policy.SelectNodes('./*[local-name()="enabledList" or local-name()="disabledList"]'))){foreach($item in @($list.SelectNodes('./*[local-name()="item"]'))){$definitions+=[pscustomobject]@{Common=$common;Kind='PolicyValueList';Key=(Get-ADAnalyzerXmlAttribute $item key $key);ValueName=(Get-ADAnalyzerXmlAttribute $item valueName);ElementId=$null;Node=$item}}}
                }
            }catch{$errors+=$file.Name}
        }
    }
    foreach($row in @($RegistrySettings)){
        if(Test-ADAnalyzerSecretName $row.ValueName){
            $safe=ConvertTo-ADAnalyzerSecretRecord $row
            $safe | Add-Member NoteProperty MetadataStatus 'PresenceOnly' -Force
            $safe | Add-Member NoteProperty State 'Unknown' -Force
            $safe
            continue
        }
        $class=if($row.Hive -ieq 'HKCU'){'User'}else{'Machine'}
        $matches=@($definitions | Where-Object {$_.Common.Class -in $class,'Both' -and $_.Key -ieq $row.Key -and ($_.ValueName -ieq $row.ValueName -or ($_.Kind -eq 'list' -and ([string]$row.ValueName).StartsWith((Get-ADAnalyzerXmlAttribute $_.Node valuePrefix),[StringComparison]::OrdinalIgnoreCase)))})
        $status=if($templateMissing){'TemplateNotFound'}elseif(-not $matches.Count -and $errors.Count){'InvalidTemplate'}elseif(-not $matches.Count){'NoMatch'}elseif($matches.Count -gt 1){'Ambiguous'}else{'Resolved'}
        $definition=$null;$state='Unknown';$options=@()
        if($matches.Count -eq 1){
            $definition=$matches[0];if($definition.Common.LanguageMissing){$status='LanguageResourceMissing'}
            switch($definition.Kind){
                'Policy' {foreach($pair in @(@('enabledValue','Enabled'),@('disabledValue','Disabled'))){$value=Get-ADAnalyzerAdmxValue ($definition.Node.SelectSingleNode('./*[local-name()="'+$pair[0]+'"]'));if($value.Valid -and (($value.Deleted -and $row.Deleted) -or (-not $value.Deleted -and $row.Value -eq $value.Value))){$state=$pair[1]}}}
                'boolean' {foreach($pair in @(@('trueValue','True'),@('falseValue','False'))){$value=Get-ADAnalyzerAdmxValue ($definition.Node.SelectSingleNode('./*[local-name()="'+$pair[0]+'"]'));if($value.Valid -and $row.Value -eq $value.Value){$state=$pair[1]}}}
                'enum' {foreach($item in @($definition.Node.SelectNodes('./*[local-name()="item"]'))){$value=Get-ADAnalyzerAdmxValue ($item.SelectSingleNode('./*[local-name()="value"]'));$label=Get-ADAnalyzerXmlAttribute $item displayName;if($label -match '^\$\(string\.(.+)\)$'){if($definition.Common.Resources.ContainsKey($Matches[1])){$label=$definition.Common.Resources[$Matches[1]]}else{$status='LanguageResourceMissing'}};$options+=[pscustomobject]@{Label=$label;Value=$value.Value};if($value.Valid -and $row.Value -eq $value.Value){$state='Configured'}}}
                'list' {$state='Configured'}
                'PolicyValueList' {$state='Unknown'}
                default {$status='UnsupportedDefinition'}
            }
        }
        [pscustomobject]@{Scope=$row.Scope;Hive=$row.Hive;Key=$row.Key;ValueName=$row.ValueName;Type=$row.Type;Value=$row.Value;RawData=$row.RawData;Source=$row.Source;KeyOnly=$row.KeyOnly;DeletionDirective=$row.DeletionDirective;Deleted=$row.Deleted;MetadataStatus=$status;State=$state;PolicyId=$definition.Common.PolicyId;PolicyNamespace=$definition.Common.PolicyNamespace;DisplayName=$definition.Common.DisplayName;DefinitionType=$definition.Kind;ElementId=$definition.ElementId;Options=$options;TemplateErrors=$errors}
    }
}
