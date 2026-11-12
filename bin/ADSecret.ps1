# Secret-bearing source fields are represented by boolean presence indicators.
# No secret value or masked stand-in is retained in returned evidence.
function Get-ADAnalyzerSecretNames {
    'cpassword|password|defaultpassword|managedpassword|msDS-ManagedPassword|msDS-ManagedPasswordId|credential|credentials|securepassword|plaintextpassword|passwordhash|nthash|lmhash|accesstoken|refreshtoken|privatekey|secret|unicodePwd|userPassword|dBCSPwd|ntPwdHistory|lmPwdHistory|supplementalCredentials|msLAPS-Password|msLAPS-EncryptedPassword|msLAPS-EncryptedPasswordHistory|msLAPS-EncryptedDSRMPassword|msLAPS-EncryptedDSRMPasswordHistory|ms-Mcs-AdmPwd|apiKey|clientSecret|bearerToken|sessionToken'
}
function Test-ADAnalyzerSecretName {
    param([string]$Name)
    $leaf=($Name -split '[\\/]')[-1]
    $leaf -match ('(?i)^(?:'+(Get-ADAnalyzerSecretNames)+')$')
}
function Assert-ADAnalyzerValueBaseline {
    param([hashtable]$Profile)
    if($null -eq $Profile){return}
    $collections=@(
        [pscustomobject]@{Rules=$Profile.RegistryRules;Registry=$false}
        [pscustomobject]@{Rules=$Profile.ExpectedGpoSettings;Registry=$false}
        [pscustomobject]@{Rules=$Profile.Host.RegistryRules;Registry=$true}
    )
    foreach($collection in $collections){foreach($rule in @($collection.Rules)){
        if($null -eq $rule){continue}
        $kind='Registry'
        if($rule -is [Collections.IDictionary]){if($rule.Contains('Kind')){$kind=$rule['Kind']}}
        elseif($null -ne $rule.PSObject.Properties['Kind']){$kind=$rule.Kind}
        # A registry key named Password can contain ordinary values such as Enabled.
        # Evaluate the actual value/setting name before using a full-key fallback.
        $identity=if($collection.Registry -or $kind -eq 'Registry'){
            if($rule.ValueName){$rule.ValueName}elseif($rule.Name){$rule.Name}else{$rule.Key}
        }else{
            if($rule.Name){$rule.Name}elseif($rule.ValueName){$rule.ValueName}else{$rule.Key}
        }
        if(Test-ADAnalyzerSecretName ([string]$identity)){
            throw 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'
        }
    }}
}
function Test-ADAnalyzerSecretPresence {
    param([AllowNull()]$Value)
    if($null -eq $Value){return $false}
    if($Value -is [pscredential]){return $null -ne $Value.Password -and $Value.Password.Length -gt 0}
    if($Value -is [Security.SecureString]){return $Value.Length -gt 0}
    if($Value -is [string]){return $Value.Length -gt 0}
    if($Value -is [Collections.ICollection]){return $Value.Count -gt 0}
    return $true
}
function ConvertTo-ADAnalyzerSecretRecord {
    param([Parameter(Mandatory)]$Record)
    $secret=$false
    foreach($label in @('Name','ValueName','Attribute','PropertyName')){
        if(Test-ADAnalyzerSecretName ([string]$Record.$label)){$secret=$true}
    }
    if(-not $secret){return $Record}
    $result=[ordered]@{};$present=$false
    if($Record.SecretPresent -is [bool]){$present=$Record.SecretPresent}
    foreach($property in $Record.PSObject.Properties){
        if($property.Name -in @('Value','RawData','Data','Bytes')){
            if($property.Name -eq 'Value'){$present=Test-ADAnalyzerSecretPresence $property.Value}
        }else{$result[$property.Name]=$property.Value}
    }
    $result['SecretPresent']=$present
    [pscustomobject]$result
}
function Get-ADAnalyzerXmlSecretName {
    param([Xml.XmlNode]$Node)
    if(-not $Node){return ''}
    $labels=@('Name','ValueName','Attribute','AttributeName','Property','PropertyName','SettingName')
    foreach($attribute in @($Node.Attributes)){
        if($attribute.LocalName -in $labels -and (Test-ADAnalyzerSecretName $attribute.Value)){return $attribute.Value}
    }
    foreach($child in @($Node.SelectNodes('./*'))){
        if($child.LocalName -in $labels -and (Test-ADAnalyzerSecretName $child.InnerText)){return $child.InnerText}
    }
    return ''
}
function ConvertTo-ADAnalyzerSecretIndicatorXml {
    param([Parameter(Mandatory)][Xml.XmlNode]$Node)
    $copy=$Node.CloneNode($true)
    $document=if($copy -is [xml]){$copy}else{$copy.OwnerDocument}
    foreach($attribute in @($copy.SelectNodes('.//@*') | Where-Object {Test-ADAnalyzerSecretName $_.LocalName})) {
        $owner=$attribute.OwnerElement;$name=$attribute.LocalName+'Present';$present=Test-ADAnalyzerSecretPresence $attribute.Value
        $present=$present -or $owner.GetAttribute($name) -ieq 'true'
        $null=$owner.Attributes.Remove($attribute);$owner.SetAttribute($name,([string]$present).ToLowerInvariant())
    }
    # GPP registry and other named-value records use generic payload fields,
    # e.g. <Properties name="DefaultPassword" value="..."/>.
    foreach($record in @($copy.SelectNodes('descendant-or-self::*'))){
        if(-not (Get-ADAnalyzerXmlSecretName $record)){continue}
        $payloadNames=@('Value','Data','RawData','Bytes','Observed','Expected')
        $labelNames=@('Name','ValueName','Attribute','AttributeName','Property','PropertyName','SettingName')
        $present=$false;$hasPayload=$false;$hasFlag=$false
        foreach($attribute in @($record.Attributes)){
            if($attribute.LocalName -ieq 'SecretPresent'){
                $present=$present -or $attribute.Value -ieq 'true';$hasFlag=$true
                $null=$record.Attributes.Remove($attribute)
            }elseif($attribute.LocalName -in $payloadNames){
                $hasPayload=$true
                if($attribute.LocalName -ine 'Expected'){$present=$present -or (Test-ADAnalyzerSecretPresence $attribute.Value)}
                $null=$record.Attributes.Remove($attribute)
            }elseif($attribute.LocalName -like '*Present' -and $attribute.Value -ieq 'true'){
                $present=$true
            }
        }
        foreach($child in @($record.ChildNodes)){
            if($child.NodeType -eq [Xml.XmlNodeType]::Element){
                if($child.LocalName -ieq 'SecretPresent'){
                    $present=$present -or $child.InnerText -ieq 'true';$hasFlag=$true
                    $null=$record.RemoveChild($child)
                }elseif($child.LocalName -in $payloadNames){
                    $hasPayload=$true
                    if($child.LocalName -ine 'Expected'){$present=$present -or (Test-ADAnalyzerSecretPresence $child.InnerText)}
                    $null=$record.RemoveChild($child)
                }
            }elseif($child.NodeType -in @([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::CDATA)){
                $hasPayload=$true;$present=$present -or (Test-ADAnalyzerSecretPresence $child.Value)
                $null=$record.RemoveChild($child)
            }
        }
        # A wrapper can share its nested item's display name. Do not invent a
        # second empty credential record for a wrapper with no own payload.
        $nested=@($record.SelectNodes('./*') | Where-Object {$_.LocalName -notin $labelNames})
        if($hasPayload -or $hasFlag -or -not $nested.Count){
            $record.SetAttribute('SecretPresent',([string]$present).ToLowerInvariant())
            if(-not $record.HasChildNodes){$record.IsEmpty=$true}
        }
    }
    foreach($element in @($copy.SelectNodes('descendant-or-self::*') | Where-Object {Test-ADAnalyzerSecretName $_.LocalName})) {
        $present=if($element.HasAttribute('SecretPresent')){$element.GetAttribute('SecretPresent') -ieq 'true'}elseif($element.HasAttribute('value')){Test-ADAnalyzerSecretPresence $element.GetAttribute('value')}else{Test-ADAnalyzerSecretPresence $element.InnerText}
        if(@($element.SelectNodes('descendant-or-self::*/@*') | Where-Object {$_.LocalName -like '*Present' -and $_.Value -eq 'true'}).Count -or @($element.SelectNodes('.//*') | Where-Object {$_.LocalName -like '*Present' -and $_.InnerText -eq 'true'}).Count){$present=$true}
        $flag=$document.CreateElement($element.LocalName+'Present');$flag.InnerText=([string]$present).ToLowerInvariant()
        if($element.ParentNode){$null=$element.ParentNode.ReplaceChild($flag,$element)}else{$copy=$flag}
    }
    return $copy
}
function ConvertTo-ADAnalyzerSecretIndicatorText {
    param([string]$Text)
    $names=Get-ADAnalyzerSecretNames
    if($Text -notmatch ('(?i)(?:'+$names+')')){return $Text}
    # Use a non-resolving parser for complete XML and a narrow text projection
    # for fragments/diagnostic strings. Neither path expands external entities.
    foreach($fragment in @($false,$true)){
        try {
            $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
            $xmlText=if($fragment){'<ADAnalyzerFragment>'+$Text+'</ADAnalyzerFragment>'}else{$Text}
            $stringReader=[IO.StringReader]::new($xmlText);$reader=[Xml.XmlReader]::Create($stringReader,$settings)
            try{
                $document=[xml]::new();$document.XmlResolver=$null;$document.Load($reader)
                $safe=ConvertTo-ADAnalyzerSecretIndicatorXml $document
                if(-not $fragment){return $safe.OuterXml}
                if(@($safe.DocumentElement.SelectNodes('./*')).Count){$Text=$safe.DocumentElement.InnerXml}
                # Plain text must not be XML-escaped, and quoted assignments
                # around a fragment still need the direct-secret projection.
                break
            }finally{$reader.Dispose();$stringReader.Dispose()}
        }catch{
            # A second, safely wrapped parse covers XML fragments. Unparseable
            # text then uses the narrow direct-secret projection below.
        }
    }
    $name='(?<name>(?:[A-Za-z_][\w.-]*:)?(?:'+$names+'))'
    $attribute='(?is)(?<![\w:.-])'+$name+'\s*=\s*(?<quote>["''])(?<value>.*?)\k<quote>'
    $safe=[regex]::Replace($Text,$attribute,{param($m) $m.Groups['name'].Value+'Present='+$m.Groups['quote'].Value+([string]($m.Groups['value'].Value.Length -gt 0)).ToLowerInvariant()+$m.Groups['quote'].Value})
    $element='(?is)<'+$name+'(?:\s[^>]*)?>(?<value>.*?)</\k<name>\s*>'
    return [regex]::Replace($safe,$element,{param($m) '<'+$m.Groups['name'].Value+'Present>'+([string]($m.Groups['value'].Value.Length -gt 0)).ToLowerInvariant()+'</'+$m.Groups['name'].Value+'Present>'})
}
