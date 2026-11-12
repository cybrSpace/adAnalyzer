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
function ConvertTo-ADAnalyzerSecretIndicatorXml {
    param([Parameter(Mandatory)][Xml.XmlNode]$Node)
    $copy=$Node.CloneNode($true)
    $document=if($copy -is [xml]){$copy}else{$copy.OwnerDocument}
    foreach($attribute in @($copy.SelectNodes('.//@*') | Where-Object {Test-ADAnalyzerSecretName $_.LocalName})) {
        $owner=$attribute.OwnerElement;$name=$attribute.LocalName+'Present';$present=Test-ADAnalyzerSecretPresence $attribute.Value
        $present=$present -or $owner.GetAttribute($name) -ieq 'true'
        $null=$owner.Attributes.Remove($attribute);$owner.SetAttribute($name,([string]$present).ToLowerInvariant())
    }
    foreach($element in @($copy.SelectNodes('descendant-or-self::*') | Where-Object {Test-ADAnalyzerSecretName $_.LocalName})) {
        $present=if($element.HasAttribute('value')){Test-ADAnalyzerSecretPresence $element.GetAttribute('value')}else{Test-ADAnalyzerSecretPresence $element.InnerText}
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
    try {
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
        $stringReader=[IO.StringReader]::new($Text);$reader=[Xml.XmlReader]::Create($stringReader,$settings)
        try{$document=[xml]::new();$document.XmlResolver=$null;$document.Load($reader);return (ConvertTo-ADAnalyzerSecretIndicatorXml $document).OuterXml}
        finally{$reader.Dispose();$stringReader.Dispose()}
    } catch {
        $name='(?<name>(?:[A-Za-z_][\w.-]*:)?(?:'+$names+'))'
        $attribute='(?is)(?<![\w:.-])'+$name+'\s*=\s*(?<quote>["''])(?<value>.*?)\k<quote>'
        $safe=[regex]::Replace($Text,$attribute,{param($m) $m.Groups['name'].Value+'Present='+$m.Groups['quote'].Value+([string]($m.Groups['value'].Value.Length -gt 0)).ToLowerInvariant()+$m.Groups['quote'].Value})
        $element='(?is)<'+$name+'(?:\s[^>]*)?>(?<value>.*?)</\k<name>\s*>'
        $safe=[regex]::Replace($safe,$element,{param($m) '<'+$m.Groups['name'].Value+'Present>'+([string]($m.Groups['value'].Value.Length -gt 0)).ToLowerInvariant()+'</'+$m.Groups['name'].Value+'Present>'})
        return $safe
    }
}
