# Package-owned GPO collection. No GroupPolicy module or GPMC COM objects.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
function Read-AnalyzerPolicyIni {
    param([Parameter(Mandatory)][string]$Path)
    $sections=[ordered]@{}; $section=''
    $reader=[IO.StreamReader]::new($Path,[Text.Encoding]::UTF8,$true)
    try {
        while($null -ne ($line=$reader.ReadLine())) {
            $line=$line.Trim()
            if(-not $line -or $line.StartsWith(';')){continue}
            if($line -match '^\[(.+)\]$'){$section=$Matches[1];if(-not $sections.Contains($section)){$sections[$section]=[ordered]@{}};continue}
            $split=$line.IndexOf('=')
            if($split -gt 0 -and $section){$sections[$section][$line.Substring(0,$split).Trim()]=$line.Substring($split+1).Trim()}
        }
    } finally {$reader.Dispose()}
    return $sections
}

function Split-AnalyzerPolicyCsv {
    param([string]$Value)
    $items=[Collections.Generic.List[string]]::new();$part=[Text.StringBuilder]::new();$quoted=$false
    for($i=0;$i -lt $Value.Length;$i++) {
        $c=$Value[$i]
        if($c -eq '"') {
            if($quoted -and $i+1 -lt $Value.Length -and $Value[$i+1] -eq '"'){$null=$part.Append('"');$i++}
            else {$quoted=-not $quoted}
        } elseif($c -eq ',' -and -not $quoted){$items.Add($part.ToString().Trim());$null=$part.Clear()}
        else {$null=$part.Append($c)}
    }
    if($quoted){throw 'Unterminated quoted policy value'}
    $items.Add($part.ToString().Trim());return ,$items.ToArray()
}

function Read-AnalyzerRegistryPolicy {
    param([Parameter(Mandatory)][string]$Path,[ValidateSet('Computer','User')][string]$Scope)
    $stream=[IO.File]::OpenRead($Path);$reader=[IO.BinaryReader]::new($stream,[Text.Encoding]::Unicode)
    try {
        if([Text.Encoding]::ASCII.GetString($reader.ReadBytes(4)) -ne 'PReg' -or $reader.ReadUInt32() -ne 1){throw 'Invalid Registry.pol header/version'}
        while($stream.Position -lt $stream.Length) {
            if($reader.ReadUInt16() -ne 91){throw 'Invalid Registry.pol opening delimiter'}
            $strings=@()
            foreach($field in @('key','value')) {
                $text=[Text.StringBuilder]::new()
                while(($c=$reader.ReadUInt16()) -ne 0){$null=$text.Append([char]$c)}
                if($reader.ReadUInt16() -ne 59){throw "Invalid Registry.pol $field delimiter"}
                $strings+= $text.ToString()
            }
            $type=$reader.ReadUInt32();if($reader.ReadUInt16() -ne 59){throw 'Invalid Registry.pol type delimiter'}
            $size=$reader.ReadUInt32();if($reader.ReadUInt16() -ne 59){throw 'Invalid Registry.pol size delimiter'}
            if($size -gt [int]::MaxValue -or $size -gt ($stream.Length-$stream.Position-2)){throw 'Invalid Registry.pol data length'}
            $bytes=$reader.ReadBytes([int]$size)
            if($reader.ReadUInt16() -ne 93){throw 'Invalid Registry.pol closing delimiter'}
            $value=if($size -eq 0){,[byte[]]@()}else{switch($type) {
                {$_ -in 1,2} {if($size%2){throw 'Invalid UTF-16 registry value'};[Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)}
                4 {if($size -ne 4){throw 'Invalid DWORD length'};[BitConverter]::ToUInt32($bytes,0)}
                5 {if($size -ne 4){throw 'Invalid big-endian DWORD length'};$copy=[byte[]]$bytes.Clone();[Array]::Reverse($copy);[BitConverter]::ToUInt32($copy,0)}
                7 {if($size%2){throw 'Invalid multi-string length'};$decoded=[Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0);if($decoded){,$decoded.Split([char]0)}else{,[string[]]@()}}
                11 {if($size -ne 8){throw 'Invalid QWORD length'};[BitConverter]::ToUInt64($bytes,0)}
                default {,$bytes}
            }}
            ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{Scope=$Scope;Hive=$(if($Scope -eq 'Computer'){'HKLM'}else{'HKCU'});Key=$strings[0];ValueName=$strings[1];Type=$type;Value=$value;RawData=$bytes;KeyOnly=($size -eq 0 -and $strings[1] -eq '');DeletionDirective=$strings[1].StartsWith('**');Source=$Path})
        }
    } catch {throw "Unable to parse '$Path': $($_.Exception.Message)"}
    finally {$reader.Dispose();$stream.Dispose()}
}

function Read-AnalyzerPolicyXml {
    param([string]$Path)
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create($Path,$settings)
    try {$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.Load($reader);return $xml}
    finally {$reader.Dispose()}
}

function ConvertTo-AnalyzerSecurityOption {
    param([string]$Name,$Value)
    # Keep unknown registry settings verbatim. These names match the analyzer's
    # existing security-option contract; raw INF values remain in IniSettings.
    $key=$Name -replace '^(?i)MACHINE\\',''
    $booleanNames=@{
        'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'='Microsoft network server: Digitally sign communications (always)'
        'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature'='Microsoft network server: Digitally sign communications (if client agrees)'
        'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature'='Microsoft network client: Digitally sign communications (always)'
        'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\EnableSecuritySignature'='Microsoft network client: Digitally sign communications (if server agrees)'
        'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword'='Microsoft network client: Send unencrypted password to third-party SMB servers'
        'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\RequireSignOrSeal'='Domain member: Digitally encrypt or sign secure channel data (always)'
        'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\SealSecureChannel'='Domain member: Digitally encrypt secure channel data (when possible)'
        'SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'='Network access: Let Everyone permissions apply to anonymous users'
        'SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'='Network access: Do not allow anonymous enumeration of SAM accounts'
        'SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous'='Network access: Do not allow anonymous enumeration of SAM accounts and shares'
        'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess'='Network access: Restrict anonymous access to Named Pipes and Shares'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken'='User Account Control: Admin Approval Mode for the Built-in Administrator account'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle'='User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection'='User Account Control: Detect application installations and prompt for elevation'
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'='User Account Control: Run all administrators in Admin Approval Mode'
    }
    if($booleanNames.ContainsKey($key)) {$Name=$booleanNames[$key];$Value=[bool][uint32]$Value}
    else {
        switch($key) {
            'SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' {
                $Name='Network security: LAN Manager authentication level'
                $levels=@('Send LM & NTLM responses','Send LM & NTLM - use NTLMv2 session security if negotiated','Send NTLM response only','Send NTLMv2 response only','Send NTLMv2 response only. Refuse LM','Send NTLMv2 response only. Refuse LM & NTLM')
                if([int]$Value -ge 0 -and [int]$Value -lt $levels.Count){$Value=$levels[[int]$Value]}
            }
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin' {
                $Name='User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
                $levels=@('Elevate without prompting','Prompt for credentials on the secure desktop','Prompt for consent on the secure desktop','Prompt for credentials','Prompt for consent','Prompt for consent for non-Windows binaries')
                if([int]$Value -ge 0 -and [int]$Value -lt $levels.Count){$Value=$levels[[int]$Value]}
            }
            'SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity' {$Name='Domain controller: LDAP server signing requirements';if($Value -eq 2){$Value='Require signature'}else{$Value='None'}}
            'SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity' {$Name='Network security: LDAP client signing requirements';$levels=@('None','Negotiate signing','Require signing');if([int]$Value -ge 0 -and [int]$Value -lt 3){$Value=$levels[[int]$Value]}}
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes' {$Name='Network access: Named Pipes that can be accessed anonymously'}
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares' {$Name='Network access: Shares that can be access anonymously'}
        }
    }
    foreach($entry in @($Value)) {[pscustomobject]@{Name=$Name;Value=$entry}}
}

function Read-ADAnalyzerGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $root=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if(-not $root.PSIsContainer){throw 'GPO path must be a directory'}
    $security=[Collections.ArrayList]::new();$registry=[Collections.ArrayList]::new();$xmlFiles=[Collections.ArrayList]::new();$files=[Collections.ArrayList]::new();$iniSettings=[Collections.ArrayList]::new();$sysvolVersion=$null
    foreach($file in Get-ChildItem -LiteralPath $root.FullName -File -Force -ErrorAction Stop) {
        $kind='Unparsed'
        if($file.Name -ieq 'GPT.INI') {
            $kind='Metadata';$ini=Read-AnalyzerPolicyIni $file.FullName
            if($ini.Contains('General') -and $ini['General'].Contains('Version')){$sysvolVersion=[uint32]$ini['General']['Version']}
        }
        $null=$files.Add([pscustomobject]@{Scope='Gpo';Path=$file.Name;Kind=$kind;Length=$file.Length})
    }
    foreach($pair in @(@('Computer','Machine'),@('User','User'))) {
        $scope=$pair[0];$side=Join-Path $root.FullName $pair[1]
        try {$null=Get-Item -LiteralPath $side -Force -ErrorAction Stop}
        catch [System.Management.Automation.ItemNotFoundException] {continue}
        foreach($file in Get-ChildItem -LiteralPath $side -Recurse -File -Force -ErrorAction Stop) {
            $relative=$file.FullName.Substring($root.FullName.TrimEnd('\','/').Length+1)
            $normalized=$relative.Replace('\','/')
            $securityTemplate=$normalized -ieq ('{0}/Microsoft/Windows NT/SecEdit/GptTmpl.inf' -f $pair[1])
            $kind='Unparsed'
            if($file.Extension -in '.ini','.inf') {
                $kind='Ini';$ini=Read-AnalyzerPolicyIni $file.FullName
                foreach($section in $ini.Keys) {
                    foreach($entry in $ini[$section].GetEnumerator()) {
                        $iniValue=$entry.Value
                        if($section -eq 'Registry Values' -and (Test-ADAnalyzerSecretName $entry.Key)){
                            $parts=Split-AnalyzerPolicyCsv $entry.Value
                            $iniValue=if($parts.Count -ge 2){$parts[1..($parts.Count-1)] -join ','}else{''}
                        }
                        $null=$iniSettings.Add((ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{Scope=$scope;Section=$section;Name=$entry.Key;Value=$iniValue;Source=$relative;Analyzed=($securityTemplate -and $section -in 'System Access','Kerberos Policy','Privilege Rights','Registry Values')})))
                    }
                }
                if(-not $securityTemplate) {$null=$files.Add([pscustomobject]@{Scope=$scope;Path=$relative;Kind=$kind;Length=$file.Length});continue}
                $kind='SecurityTemplate'
                foreach($section in @('System Access','Kerberos Policy')) {
                    if(-not $ini.Contains($section)){continue}
                    foreach($entry in $ini[$section].GetEnumerator()) {
                        $value=$entry.Value
                        if($value -match '^-?\d+$'){$value=[long]$value}
                        if($entry.Key -in 'PasswordComplexity','ClearTextPassword','RequireLogonToChangePassword','ForceLogoffWhenHourExpire','TicketValidateClient'){$value=[bool][int]$value}
                        if($entry.Key -eq 'LSAAnonymousNameLookup') {
                            $null=$security.Add([pscustomobject]@{Scope=$scope;Kind='SecurityOptions';Name='Network access: Allow anonymous SID/Name translation';Value=[bool][int]$value;Source=$relative})
                        } else {
                            if($value -is [string] -and $value.StartsWith('"')){$value=(Split-AnalyzerPolicyCsv $value)[0]}
                            $null=$security.Add([pscustomobject]@{Scope=$scope;Kind='Account';Name=$entry.Key;Value=$value;Source=$relative})
                        }
                    }
                }
                if($ini.Contains('Privilege Rights')) {
                    foreach($entry in $ini['Privilege Rights'].GetEnumerator()) {
                        $members=if($entry.Value){Split-AnalyzerPolicyCsv $entry.Value}else{@()}
                        $null=$security.Add([pscustomobject]@{Scope=$scope;Kind='UserRightsAssignment';Name=$entry.Key;Value=$members;Source=$relative})
                    }
                }
                if($ini.Contains('Registry Values')) {
                    foreach($entry in $ini['Registry Values'].GetEnumerator()) {
                        $parts=Split-AnalyzerPolicyCsv $entry.Value
                        if($parts.Count -lt 2){throw "Invalid registry setting in $relative"}
                        $value=if($parts[0] -eq '7'){,$parts[1..($parts.Count-1)]}else{$parts[1..($parts.Count-1)] -join ','}
                        if($parts[0] -eq '4' -and $value -match '^\d+$'){$value=[uint32]$value}
                        foreach($option in ConvertTo-AnalyzerSecurityOption $entry.Key $value) {
                            $null=$security.Add([pscustomobject]@{Scope=$scope;Kind='SecurityOptions';Name=$option.Name;Value=$option.Value;Source=$relative})
                        }
                    }
                }
            } elseif($normalized -ieq ('{0}/Registry.pol' -f $pair[1])) {
                $kind='RegistryPolicy';foreach($item in @(Read-AnalyzerRegistryPolicy $file.FullName $scope)){$null=$registry.Add($item)}
            } elseif($file.Extension -ieq '.xml') {
                $kind='Xml';$xml=Read-AnalyzerPolicyXml $file.FullName
                $xmlKind=if($relative -match '(^|[\\/])Preferences[\\/]'){'Preferences'}else{'Xml'}
                $null=$xmlFiles.Add([pscustomobject]@{Scope=$scope;Kind=$xmlKind;Path=$relative;Xml=(ConvertTo-ADAnalyzerSecretIndicatorXml $xml).OuterXml})
            }
            $null=$files.Add([pscustomobject]@{Scope=$scope;Path=$relative;Kind=$kind;Length=$file.Length})
        }
    }
    [pscustomobject]@{Path=$root.FullName;SysvolVersion=$sysvolVersion;SecuritySettings=@($security | ForEach-Object {ConvertTo-ADAnalyzerSecretRecord $_});RegistrySettings=$registry.ToArray();XmlFiles=$xmlFiles.ToArray();IniSettings=$iniSettings.ToArray();Files=$files.ToArray();UnparsedFiles=@($files | Where-Object Kind -eq 'Unparsed')}
}

function ConvertTo-ADAnalyzerProvidedGpoPolicy {
    # Prefetched input uses the package DTO contract, including safe XML and
    # typed registry values. Copy before projecting so caller data stays intact.
    param([Parameter(Mandatory)]$Policy)
    foreach($field in @('SecuritySettings','RegistrySettings','IniSettings','XmlFiles','Files','UnparsedFiles')){foreach($record in @($Policy.$field)){
        if($null -ne $record -and ($record -is [Collections.IDictionary] -or $record -is [string] -or $record -is [ValueType] -or $record -isnot [pscustomobject])){
            throw 'InputObject policy records must use package report objects or JSON objects.'
        }
    }}
    $xmlFiles=@(foreach($record in @($Policy.XmlFiles)){
        if($null -eq $record){continue}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
        $text=[IO.StringReader]::new([string]$record.Xml);$reader=$null
        try{
            $reader=[Xml.XmlReader]::Create($text,$settings);$document=[xml]::new();$document.XmlResolver=$null;$document.Load($reader)
            $safe=ConvertTo-ADAnalyzerSecretIndicatorXml $document
        }catch{throw 'Provided policy XML is unreadable.'}
        finally{if($null -ne $reader){$reader.Dispose()};$text.Dispose()}
        [pscustomobject]@{Scope=$record.Scope;Kind=$record.Kind;Path=$record.Path;Xml=$safe.OuterXml}
    })
    [pscustomobject]@{
        Path=$Policy.Path;SysvolVersion=$Policy.SysvolVersion;Files=@($Policy.Files);UnparsedFiles=@($Policy.UnparsedFiles)
        SecuritySettings=@($Policy.SecuritySettings | Where-Object {$null -ne $_} | ForEach-Object {ConvertTo-ADAnalyzerSecretRecord $_})
        RegistrySettings=@($Policy.RegistrySettings | Where-Object {$null -ne $_} | ForEach-Object {
            $record=ConvertTo-ADAnalyzerSecretRecord $_
            if($record.Type -notin @(1,2,4,5,7,11) -and $record.Value -is [array]){$record.Value=[byte[]]$record.Value}
            $record
        })
        IniSettings=@($Policy.IniSettings | Where-Object {$null -ne $_} | ForEach-Object {ConvertTo-ADAnalyzerSecretRecord $_})
        XmlFiles=$xmlFiles
    }
}

function Get-ADAnalyzerGpo {
    [CmdletBinding(DefaultParameterSetName='All')]
    param([Parameter(ParameterSetName='All')][switch]$All,[Parameter(Mandatory,ParameterSetName='Guid')][guid]$Guid,[Parameter(Mandatory,ParameterSetName='Name')][string]$Name,[Parameter(Mandatory)][string]$Domain,[string]$Server=$Domain,[pscredential]$Credential=[pscredential]::Empty)
    if($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Server must be a DNS or NetBIOS host name'}
    $connection=@{Server=$Server;ErrorAction='Stop'}
    if($Credential -and $Credential -ne [pscredential]::Empty){$connection.Credential=$Credential}
    $requestedServer=$Server
    $rootDse=Get-ADRootDSE @connection
    if($rootDse.DnsHostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'The directory server did not return a valid DC host name'}
    $Server=[string]$rootDse.DnsHostName;$connection.Server=$Server
    $domainInfo=Get-ADDomain -Identity $Domain @connection
    $dns=[string]$domainInfo.DNSRoot
    if($dns -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Invalid domain DNS name'}
    $base='CN=Policies,CN=System,'+$domainInfo.DistinguishedName
    $objects=@(Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase $base -Properties displayName,gPCFileSysPath,flags,whenCreated,whenChanged,versionNumber,gPCWQLFilter,gPCMachineExtensionNames,gPCUserExtensionNames @connection)
    $links=@(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $domainInfo.DistinguishedName -Properties gPLink,gPOptions,distinguishedName @connection)
    if($rootDse.ConfigurationNamingContext){$links+=@(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase ('CN=Sites,'+$rootDse.ConfigurationNamingContext) -Properties gPLink,gPOptions,distinguishedName @connection)}
    foreach($object in $objects) {
        $id=[guid]([string]$object.Name).Trim('{}')
        if($PSCmdlet.ParameterSetName -eq 'Guid' -and $id -ne $Guid){continue}
        if($PSCmdlet.ParameterSetName -eq 'Name' -and $object.displayName -ine $Name){continue}
        $policyLinks=[Collections.ArrayList]::new()
        foreach($container in $links) {
            $storedIndex=0
            foreach($match in [regex]::Matches([string]$container.gPLink,'(?i)\[LDAP://(?<dn>[^;]+);(?<flags>\d+)\]')) {
                if($match.Groups['dn'].Value -ieq $object.DistinguishedName) {
                    $options=[int]$match.Groups['flags'].Value
                    $null=$policyLinks.Add([pscustomobject]@{SOMPath=$container.DistinguishedName;Enabled=($options -band 1) -eq 0;Enforced=($options -band 2) -ne 0;StoredLinkIndex=$storedIndex;BlockInheritance=([int]$container.gPOptions -band 1) -ne 0})
                }
                $storedIndex++
            }
        }
        $flags=[int]$object.flags
        [pscustomobject]@{Id=$id;DisplayName=$object.displayName;CreationTime=$object.whenCreated;ModificationTime=$object.whenChanged;GPOStatus=@('AllSettingsEnabled','UserSettingsDisabled','ComputerSettingsDisabled','AllSettingsDisabled')[$flags -band 3];Flags=$flags;Version=$object.versionNumber;Domain=$dns;Server=$Server;RequestedServer=$requestedServer;DistinguishedName=$object.DistinguishedName;DirectoryFilePath=$object.gPCFileSysPath;PolicyPath=('\\{0}\SYSVOL\{1}\Policies\{2}' -f $Server,$dns,$id.ToString('B'));Links=$policyLinks.ToArray();WmiFilter=$object.gPCWQLFilter;MachineExtensions=$object.gPCMachineExtensionNames;UserExtensions=$object.gPCUserExtensionNames}
    }
}

function Add-AnalyzerGpoXmlNode {
    param([xml]$Document,[Xml.XmlNode]$Parent,[string]$Name,$Value)
    $node=$Document.CreateElement($Name)
    if($null -ne $Value){$node.InnerText=[string]$Value}
    $null=$Parent.AppendChild($node);return $node
}

function ConvertTo-AnalyzerGpoXml {
    param($Gpo,$Parsed,[hashtable]$SidNames=@{},[hashtable]$SidStatus=@{})
    $known=@{'S-1-5-32-544'='Administrators';'S-1-5-32-545'='Users';'S-1-5-32-546'='Guests';'S-1-5-32-551'='Backup Operators';'S-1-1-0'='Everyone';'S-1-5-11'='Authenticated Users';'S-1-5-18'='SYSTEM';'S-1-5-19'='LOCAL SERVICE';'S-1-5-20'='NETWORK SERVICE'}
    foreach($key in $SidNames.Keys){$known[$key]=$SidNames[$key]}
    $doc=[xml]::new();$doc.XmlResolver=$null;$g=$doc.CreateElement('GPO');$null=$doc.AppendChild($g)
    $null=Add-AnalyzerGpoXmlNode $doc $g 'ReadTime' ([datetime]::UtcNow.ToString('o'))
    $null=Add-AnalyzerGpoXmlNode $doc $g 'DirectoryVersion' $Gpo.Version
    $null=Add-AnalyzerGpoXmlNode $doc $g 'SysvolVersion' $Parsed.SysvolVersion
    $null=Add-AnalyzerGpoXmlNode $doc $g 'VersionMismatch' ([string]($null -ne $Parsed.SysvolVersion -and $null -ne $Gpo.Version -and $Parsed.SysvolVersion -ne ([long]$Gpo.Version -band [long]4294967295))).ToLowerInvariant()
    foreach($link in @($Gpo.Links)) {$l=Add-AnalyzerGpoXmlNode $doc $g 'LinksTo';$null=Add-AnalyzerGpoXmlNode $doc $l 'SOMPath' $link.SOMPath;$null=Add-AnalyzerGpoXmlNode $doc $l 'Enabled' ([string]$link.Enabled).ToLowerInvariant();$null=Add-AnalyzerGpoXmlNode $doc $l 'NoOverride' ([string]$link.Enforced).ToLowerInvariant()}
    foreach($scope in @('Computer','User')) {
        $side=Add-AnalyzerGpoXmlNode $doc $g $scope
        $bit=if($scope -eq 'Computer'){2}else{1}
        $null=Add-AnalyzerGpoXmlNode $doc $side 'Enabled' ([string](($Gpo.Flags -band $bit) -eq 0)).ToLowerInvariant()
        $settings=@($Parsed.SecuritySettings | Where-Object Scope -eq $scope)
        if($settings.Count) {
            $ext=Add-AnalyzerGpoXmlNode $doc $side 'ExtensionData';$null=Add-AnalyzerGpoXmlNode $doc $ext 'Name' 'Security';$body=Add-AnalyzerGpoXmlNode $doc $ext 'Extension'
            foreach($setting in $settings) {
                $node=Add-AnalyzerGpoXmlNode $doc $body $setting.Kind
                if($null -ne $setting.PSObject.Properties['SecretPresent']){
                    $null=Add-AnalyzerGpoXmlNode $doc $node 'Name' $setting.Name
                    $null=Add-AnalyzerGpoXmlNode $doc $node 'SecretPresent' ([string]$setting.SecretPresent).ToLowerInvariant()
                    continue
                }
                if($setting.Kind -eq 'SecurityOptions') {
                    $display=Add-AnalyzerGpoXmlNode $doc $node 'Display';$null=Add-AnalyzerGpoXmlNode $doc $display 'Name' $setting.Name
                    if($setting.Value -is [bool]){$null=Add-AnalyzerGpoXmlNode $doc $display 'DisplayBoolean' ([string]$setting.Value).ToLowerInvariant()}else{$null=Add-AnalyzerGpoXmlNode $doc $display 'DisplayString' $setting.Value}
                }
                else {
                    $null=Add-AnalyzerGpoXmlNode $doc $node 'Name' $setting.Name
                    if($setting.Kind -eq 'Account') {
                        if($setting.Value -is [bool]){$null=Add-AnalyzerGpoXmlNode $doc $node 'SettingBoolean' ([string]$setting.Value).ToLowerInvariant()}
                        elseif($setting.Value -is [long]){$null=Add-AnalyzerGpoXmlNode $doc $node 'SettingNumber' $setting.Value}
                        else{$null=Add-AnalyzerGpoXmlNode $doc $node 'SettingString' $setting.Value}
                    } else {
                        foreach($entry in @($setting.Value)) {
                            $member=Add-AnalyzerGpoXmlNode $doc $node 'Member';$token=([string]$entry).TrimStart('*')
                            if($token -match '^S-\d-') {
                                $null=Add-AnalyzerGpoXmlNode $doc $member 'SID' $token
                                $status='NotAttempted'
                                if($known.ContainsKey($token)){$null=Add-AnalyzerGpoXmlNode $doc $member 'Name' $known[$token];$status='Resolved'}elseif($SidStatus.ContainsKey($token)){$status=$SidStatus[$token]}
                                $null=Add-AnalyzerGpoXmlNode $doc $member 'Resolution' $status
                            } else {$null=Add-AnalyzerGpoXmlNode $doc $member 'Name' $token}
                        }
                    }
                }
            }
        }
        foreach($kind in @('Registry','Preferences','Xml','Ini')) {
            # Wrap the complete conditional: Windows PowerShell 5.1 does not
            # provide Count on a singleton PSCustomObject after pipeline unwrap.
            $rows=@(
                if($kind -eq 'Registry'){$Parsed.RegistrySettings | Where-Object Scope -eq $scope}
                elseif($kind -eq 'Ini'){$Parsed.IniSettings | Where-Object { $_.Scope -eq $scope -and -not $_.Analyzed }}
                else{$Parsed.XmlFiles | Where-Object { $_.Scope -eq $scope -and $_.Kind -eq $kind }}
            )
            if(-not $rows.Count){continue}
            $ext=Add-AnalyzerGpoXmlNode $doc $side 'ExtensionData';$null=Add-AnalyzerGpoXmlNode $doc $ext 'Name' $kind;$body=Add-AnalyzerGpoXmlNode $doc $ext 'Extension'
            foreach($row in $rows) {
                $record=Add-AnalyzerGpoXmlNode $doc $body 'Record'
                if($kind -eq 'Registry') {$label='{0}\{1}\{2}' -f $row.Hive,$row.Key,$row.ValueName;$value=if($row.Value -is [byte[]]){[System.Convert]::ToBase64String($row.Value)}elseif($row.Value -is [array]){ConvertTo-Json -InputObject $row.Value -Compress}else{[string]$row.Value};$null=Add-AnalyzerGpoXmlNode $doc $record 'Type' $row.Type}
                elseif($kind -eq 'Ini') {$label='{0}: [{1}] {2}' -f $row.Source,$row.Section,$row.Name;$value=$row.Value}
                else {$label=$row.Path;$value=$row.Xml}
                $null=Add-AnalyzerGpoXmlNode $doc $record 'Name' $label
                if($null -ne $row.PSObject.Properties['SecretPresent']){$null=Add-AnalyzerGpoXmlNode $doc $record 'SecretPresent' ([string]$row.SecretPresent).ToLowerInvariant()}
                else{$null=Add-AnalyzerGpoXmlNode $doc $record 'Value' $value}
            }
        }
    }
    $inventory=Add-AnalyzerGpoXmlNode $doc $g 'FileInventory'
    foreach($file in $Parsed.Files){$node=Add-AnalyzerGpoXmlNode $doc $inventory 'File';$node.SetAttribute('Kind',$file.Kind);$node.InnerText=$file.Path}
    return $doc.OuterXml
}

function Get-ADAnalyzerGpoReport {
    [CmdletBinding(DefaultParameterSetName='Gpo')]
    param([Parameter(Mandatory,ParameterSetName='Gpo')]$Gpo,[Parameter(Mandatory,ParameterSetName='Guid')][guid]$Guid,[Parameter(Mandatory,ParameterSetName='Guid')][string]$Domain,[Parameter(ParameterSetName='Guid')][string]$Server=$Domain,[pscredential]$Credential=[pscredential]::Empty,[switch]$AsObject,[hashtable]$SidNames=@{})
    if($PSCmdlet.ParameterSetName -eq 'Guid'){$Gpo=@(Get-ADAnalyzerGpo -Guid $Guid -Domain $Domain -Server $Server -Credential $Credential);if($Gpo.Count -ne 1){throw 'GPO was not found or was ambiguous'};$Gpo=$Gpo[0]}
    # Rebuild from validated metadata; never authenticate to gPCFileSysPath hosts.
    if($Gpo.Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or $Gpo.Domain -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Invalid GPO server/domain'}
    $id=[guid]$Gpo.Id;$drive=$null
    try {
        if($Credential -and $Credential -ne [pscredential]::Empty) {
            $drive=New-PSDrive -Name ('ADGpo'+[guid]::NewGuid().ToString('N')) -PSProvider FileSystem -Root ('\\{0}\SYSVOL' -f $Gpo.Server) -Credential $Credential -Scope Local -ErrorAction Stop -WhatIf:$false -Confirm:$false
            $path=Join-Path ($drive.Name+':\') ('{0}\Policies\{1}' -f $Gpo.Domain,$id.ToString('B'))
        } else {$path='\\{0}\SYSVOL\{1}\Policies\{2}' -f $Gpo.Server,$Gpo.Domain,$id.ToString('B')}
        $parsed=Read-ADAnalyzerGpo -Path $path
        $mismatch=$null -ne $parsed.SysvolVersion -and $null -ne $Gpo.Version -and $parsed.SysvolVersion -ne ([long]$Gpo.Version -band [long]4294967295)
        if($mismatch){Write-Warning ('GPO {0} directory and SYSVOL versions differ; the policy may be updating or replicating' -f $Gpo.Id)}
        if($AsObject){[pscustomobject]@{Gpo=$Gpo;Policy=$parsed;VersionMismatch=$mismatch}}
        else {
            $names=if($null -ne $SidNames){$SidNames.Clone()}else{@{}};$status=@{}
            $connection=@{Server=$Gpo.Server;ErrorAction='Stop'}
            if($Credential -and $Credential -ne [pscredential]::Empty){$connection.Credential=$Credential}
            $tokens=@($parsed.SecuritySettings | Where-Object Kind -eq 'UserRightsAssignment' | ForEach-Object { $_.Value } | ForEach-Object { ([string]$_).TrimStart('*') } | Where-Object { $_ -match '^S-1-5-21-(\d+-){3}\d+$' } | Select-Object -Unique)
            foreach($token in $tokens) {
                if($names.ContainsKey($token)){continue}
                try {
                    $matches=@(Get-ADObject -Filter "objectSid -eq '$token'" -Properties sAMAccountName @connection)
                    if($matches.Count -eq 1 -and $matches[0].sAMAccountName){$names[$token]=[string]$matches[0].sAMAccountName;$status[$token]='Resolved'}else{$status[$token]='NotFound'}
                } catch {$status[$token]='LookupFailed';Write-Warning "Unable to resolve policy SID $token on $($Gpo.Server): $($_.Exception.Message)"}
            }
            ConvertTo-AnalyzerGpoXml $Gpo $parsed $names $status
        }
    } finally {if($drive){Remove-PSDrive -Name $drive.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false}}
}
