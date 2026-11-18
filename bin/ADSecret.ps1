# Secret-bearing source fields are represented by boolean presence indicators.
# No secret value or masked stand-in is retained in returned evidence.
class ADAnalyzerSecretIndicator {
    ADAnalyzerSecretIndicator() {
    }

    [string] GetNamePattern() {
        return 'cpassword|password|defaultpassword|managedpassword|msDS-ManagedPassword|msDS-ManagedPasswordId|credential|credentials|securepassword|plaintextpassword|passwordhash|nthash|lmhash|accesstoken|refreshtoken|privatekey|secret|unicodePwd|userPassword|dBCSPwd|ntPwdHistory|lmPwdHistory|supplementalCredentials|msLAPS-Password|msLAPS-EncryptedPassword|msLAPS-EncryptedPasswordHistory|msLAPS-EncryptedDSRMPassword|msLAPS-EncryptedDSRMPasswordHistory|ms-Mcs-AdmPwd|apiKey|clientSecret|bearerToken|sessionToken'
    }

    [bool] IsSecretName([string]$Name) {
        $leaf = ($Name -split '[\\/]')[-1]
        return $leaf -match ('(?i)^(?:' + ($this.GetNamePattern()) + ')$')
    }

    [bool] IsPresent([object]$Value) {
        if ($null -eq $Value) {
            return $false
        }
        if ($Value -is [pscredential]) {
            $password = $Value.PSBase.Password
            return $null -ne $password -and $password.PSBase.Length -gt 0
        }
        if ($Value -is [Security.SecureString]) {
            return $Value.PSBase.Length -gt 0
        }
        if ($Value -is [string]) {
            return $Value.PSBase.Length -gt 0
        }
        if ($Value -is [Collections.ICollection]) {
            return [Collections.ICollection].GetProperty('Count').GetValue($Value, $null) -gt 0
        }
        return $true
    }

    [void] AssertValueBaseline([hashtable]$Profile) {
        if ($null -eq $Profile) {
            return
        }
        $collections = @(
            [pscustomobject]@{
                Rules = $Profile.RegistryRules
                Registry = $false
            }
            [pscustomobject]@{
                Rules = $Profile.ExpectedGpoSettings
                Registry = $false
            }
            [pscustomobject]@{
                Rules = $Profile.Host.RegistryRules
                Registry = $true
            }
        )
        foreach ($collection in $collections) {
            foreach ($rule in @($collection.Rules)) {
                if ($null -eq $rule) {
                    continue
                }
                foreach ($field in @('Kind', 'Name', 'Key', 'ValueName')) {
                    if ($null -ne $rule.$field -and $rule.$field -isnot [string]) {
                        throw 'Custom value baseline identity fields must be strings or null.'
                    }
                }
                $kind = 'Registry'
                if ($rule -is [Collections.IDictionary]) {
                    if (([Collections.IDictionary]$rule).Contains('Kind')) {
                        $kind = $rule['Kind']
                    }
                }
                elseif ($null -ne $rule.PSObject.Properties['Kind']) {
                    $kind = $rule.Kind
                }
                # A registry key named Password can contain ordinary values such as Enabled.
                # Evaluate the actual value/setting name before using a full-key fallback.
                $identities = if ($collection.Registry -or $kind -eq 'Registry') {
                    if ($rule.ValueName) {
                        @($rule.ValueName)
                    }
                    else {
                        @($rule.Name, $rule.Key)
                    }
                }
                else {
                    if ($rule.Name) {
                        $rule.Name
                    }
                    elseif ($rule.ValueName) {
                        $rule.ValueName
                    }
                    else {
                        $rule.Key
                    }
                }
                foreach ($identity in @($identities)) {
                    if ($this.IsSecretName(([string]$identity))) {
                        throw 'Value baselines for secret-bearing settings are not supported. Use secret-presence checks.'
                    }
                }
            }
        }
    }

    [object] ProjectRecord([object]$Record) {
        if ($null -eq $Record) {
            throw [ArgumentNullException]::new('Record')
        }
        $inputFrame = @{ Record = $Record }
        $secret = $false
        foreach ($label in @('Name', 'ValueName', 'Attribute', 'PropertyName')) {
            if ((Test-ADAnalyzerOptionalSecretRecordMember $inputFrame $label) -and
                $this.IsSecretName(([string]$Record.$label))) {
                $secret = $true
            }
        }
        if (-not $secret) {
            return $Record
        }
        $result = [ordered]@{}
        $present = $false
        if ((Test-ADAnalyzerOptionalSecretRecordMember $inputFrame 'SecretPresent') -and
            $Record.SecretPresent -is [bool]) {
            $present = $Record.SecretPresent
        }
        foreach ($property in $Record.PSObject.Properties) {
            if ($property.Name -in @('Value', 'RawData', 'Data', 'Bytes')) {
                if ($property.Name -eq 'Value') {
                    $present = $present -or ($this.IsPresent($property.Value))
                }
            }
            else {
                $result[$property.Name] = $property.Value
            }
        }
        $result['SecretPresent'] = $present
        return [pscustomobject]$result
    }

    [string] FindXmlSecretName([Xml.XmlNode]$Node) {
        if (-not $Node) {
            return ''
        }
        $labels = @('Name', 'ValueName', 'Attribute', 'AttributeName', 'Property', 'PropertyName', 'SettingName')
        foreach ($attribute in @($Node.PSBase.Attributes)) {
            if ($attribute.PSBase.LocalName -in $labels -and ($this.IsSecretName($attribute.PSBase.Value))) {
                return $attribute.PSBase.Value
            }
        }
        foreach ($child in @($Node.SelectNodes('./*'))) {
            if ($child.PSBase.LocalName -in $labels -and ($this.IsSecretName($child.PSBase.InnerText))) {
                return $child.PSBase.InnerText
            }
        }
        return ''
    }

    [Xml.XmlNode] ProjectXml([Xml.XmlNode]$Node) {
        if ($null -eq $Node) {
            throw [ArgumentNullException]::new('Node')
        }
        if ($Node.PSBase.NodeType -notin @(
                [Xml.XmlNodeType]::Document,
                [Xml.XmlNodeType]::Element
            )) {
            throw [ArgumentException]::new('XML projection supports Document and Element nodes only.', 'Node')
        }
        $sourceDocument = if ($Node -is [xml]) {
            $Node
        }
        else {
            $Node.PSBase.OwnerDocument
        }
        if ($null -ne $sourceDocument -and
            $null -ne $sourceDocument.PSBase.DocumentType) {
            throw [IO.InvalidDataException]::new('DTD declarations are not supported in secret-presence projection.')
        }
        $copy = $Node.CloneNode($true)
        if ($Node -is [xml] -and $null -ne $Node.PSBase.DocumentElement) {
            $rootReader = [Xml.XmlNodeReader]::new($Node.PSBase.DocumentElement.CloneNode($true))
            try {
                $rootCopy = $copy.ReadNode($rootReader)
                $null = $copy.ReplaceChild($rootCopy, $copy.PSBase.DocumentElement)
            }
            finally {
                $rootReader.Dispose()
            }
        }
        $document = if ($copy -is [xml]) {
            $copy
        }
        else {
            $copy.PSBase.OwnerDocument
        }
        foreach ($attribute in @(
                $copy.SelectNodes('.//@*') | Where-Object {
                    $this.IsSecretName($_.PSBase.LocalName)
                }
            )) {
            $owner = $attribute.PSBase.OwnerElement
            $name = $attribute.PSBase.LocalName + 'Present'
            $present = $this.IsPresent($attribute.PSBase.Value)
            $present = $present -or $owner.GetAttribute($name) -ieq 'true'
            $null = $owner.PSBase.Attributes.Remove($attribute)
            $owner.SetAttribute($name, ([string]$present).ToLowerInvariant())
        }
        # GPP registry and other named-value records use generic payload fields,
        # e.g. <Properties name="DefaultPassword" value="..."/>.
        foreach ($record in @($copy.SelectNodes('descendant-or-self::*'))) {
            if (-not ($this.FindXmlSecretName($record))) {
                continue
            }
            $payloadNames = @('Value', 'Data', 'RawData', 'Bytes', 'Observed', 'Expected')
            $labelNames = @(
                'Name',
                'ValueName',
                'Attribute',
                'AttributeName',
                'Property',
                'PropertyName',
                'SettingName'
            )
            $present = $false
            $hasPayload = $false
            $hasFlag = $false
            foreach ($attribute in @($record.PSBase.Attributes)) {
                if ($attribute.PSBase.LocalName -ieq 'SecretPresent') {
                    $present = $present -or $attribute.PSBase.Value -ieq 'true'
                    $hasFlag = $true
                    $null = $record.PSBase.Attributes.Remove($attribute)
                }
                elseif ($attribute.PSBase.LocalName -in $payloadNames) {
                    $hasPayload = $true
                    if ($attribute.PSBase.LocalName -ine 'Expected') {
                        $present = $present -or ($this.IsPresent($attribute.PSBase.Value))
                    }
                    $null = $record.PSBase.Attributes.Remove($attribute)
                }
                elseif ($attribute.PSBase.LocalName -like '*Present' -and $attribute.PSBase.Value -ieq 'true') {
                    $present = $true
                }
            }
            foreach ($child in @($record.PSBase.ChildNodes)) {
                if ($child.PSBase.NodeType -eq [Xml.XmlNodeType]::Element) {
                    if ($child.PSBase.LocalName -ieq 'SecretPresent') {
                        $present = $present -or $child.PSBase.InnerText -ieq 'true'
                        $hasFlag = $true
                        $null = $record.RemoveChild($child)
                    }
                    elseif ($child.PSBase.LocalName -in $payloadNames) {
                        $hasPayload = $true
                        if ($child.PSBase.LocalName -ine 'Expected') {
                            $present = $present -or ($this.IsPresent($child.PSBase.InnerText))
                        }
                        $null = $record.RemoveChild($child)
                    }
                }
                elseif ($child.PSBase.NodeType -in @([Xml.XmlNodeType]::Text, [Xml.XmlNodeType]::CDATA)) {
                    $hasPayload = $true
                    $present = $present -or ($this.IsPresent($child.PSBase.Value))
                    $null = $record.RemoveChild($child)
                }
            }
            # A wrapper can share its nested item's display name. Do not invent a
            # second empty credential record for a wrapper with no own payload.
            $nested = @(
                $record.SelectNodes('./*') | Where-Object {
                    $_.PSBase.LocalName -notin $labelNames
                }
            )
            if ($hasPayload -or $hasFlag -or -not $nested.Count) {
                $record.SetAttribute('SecretPresent', ([string]$present).ToLowerInvariant())
                if (-not $record.PSBase.HasChildNodes) {
                    $record.PSBase.IsEmpty = $true
                }
            }
        }
        foreach ($element in @(
                $copy.SelectNodes('descendant-or-self::*') | Where-Object {
                    $this.IsSecretName($_.PSBase.LocalName)
                }
            )) {
            $present = if ($element.HasAttribute('SecretPresent')) {
                $element.GetAttribute('SecretPresent') -ieq 'true'
            }
            elseif ($element.HasAttribute('value')) {
                $this.IsPresent($element.GetAttribute('value'))
            }
            else {
                $this.IsPresent($element.PSBase.InnerText)
            }
            if (@(
                    $element.SelectNodes('descendant-or-self::*/@*') | Where-Object {
                        $_.PSBase.LocalName -like '*Present' -and
                        $_.PSBase.Value -eq 'true'
                    }
                ).Count -or
                @(
                    $element.SelectNodes('.//*') | Where-Object {
                        $_.PSBase.LocalName -like '*Present' -and
                        $_.PSBase.InnerText -eq 'true'
                    }
                ).Count) {
                $present = $true
            }
            $flag = $document.CreateElement($element.PSBase.LocalName + 'Present')
            $flag.PSBase.InnerText = ([string]$present).ToLowerInvariant()
            if ($element.PSBase.ParentNode) {
                $null = $element.PSBase.ParentNode.ReplaceChild($flag, $element)
            }
            else {
                $copy = $flag
            }
        }
        if ($copy -is [Xml.XmlElement]) {
            $detachedDocument = [xml]::new()
            $detachedDocument.PreserveWhitespace = $true
            $detachedDocument.XmlResolver = $null
            $reader = [Xml.XmlNodeReader]::new($copy)
            try {
                return $detachedDocument.ReadNode($reader)
            }
            finally {
                $reader.Dispose()
            }
        }
        return $copy
    }

    [string] ProjectText([string]$Text) {
        $names = $this.GetNamePattern()
        $hasSecretName = $Text -match ('(?i)(?:' + $names + ')')
        $hasDtdMarkup = $Text -match '(?i)<!DOCTYPE\b'
        if (-not $hasSecretName -and -not $hasDtdMarkup) {
            return $Text
        }
        # Use a non-resolving parser for complete XML and a narrow text projection
        # for fragments/diagnostic strings. Neither path expands external entities.
        $parsed = $false
        foreach ($fragment in @($false, $true)) {
            try {
                $settings = [Xml.XmlReaderSettings]::new()
                $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
                $settings.XmlResolver = $null
                $xmlText = if ($fragment) {
                    '<ADAnalyzerFragment>' + $Text + '</ADAnalyzerFragment>'
                }
                else {
                    $Text
                }
                $stringReader = [IO.StringReader]::new($xmlText)
                $reader = [Xml.XmlReader]::Create($stringReader, $settings)
                try {
                    $document = [xml]::new()
                    $document.XmlResolver = $null
                    $document.Load($reader)
                    $safe = $this.ProjectXml($document)
                    $parsed = $true
                    if (-not $hasSecretName) {
                        return $Text
                    }
                    if (-not $fragment) {
                        return $safe.PSBase.OuterXml
                    }
                    if (@($safe.PSBase.DocumentElement.SelectNodes('./*')).Count) {
                        $Text = $safe.PSBase.DocumentElement.PSBase.InnerXml
                    }
                    # Plain text must not be XML-escaped, and quoted assignments
                    # around a fragment still need the direct-secret projection.
                    break
                }
                finally {
                    $reader.Dispose()
                    $stringReader.Dispose()
                }
            }
            catch {
                # A second, safely wrapped parse covers XML fragments. Unparseable
                # text then uses the narrow direct-secret projection below.
            }
        }
        if ($hasDtdMarkup -and -not $parsed) {
            throw [IO.InvalidDataException]::new('DTD declarations are not supported in secret-presence projection.')
        }
        $name = '(?<name>(?:[A-Za-z_][\w.-]*:)?(?:' + $names + '))'
        $attribute = '(?is)(?<![\w:.-])' + $name + '\s*=\s*(?<quote>["''])(?<value>.*?)\k<quote>'
        $safe = [regex]::Replace(
            $Text,
            $attribute,
            {
                param($m)
                $m.Groups['name'].Value + 'Present=' + $m.Groups['quote'].Value +
                    ([string]($m.Groups['value'].Value.Length -gt 0)).ToLowerInvariant() +
                    $m.Groups['quote'].Value
            }
        )
        $element = '(?is)<' + $name + '(?:\s[^>]*)?>(?<value>.*?)</\k<name>\s*>'
        return [regex]::Replace(
            $safe,
            $element,
            {
                param($m)
                '<' + $m.Groups['name'].Value + 'Present>' +
                    ([string]($m.Groups['value'].Value.Length -gt 0)).ToLowerInvariant() +
                    '</' + $m.Groups['name'].Value + 'Present>'
            }
        )
    }

}

function Test-ADAnalyzerOptionalSecretRecordMember {
    param(
        [hashtable]$InputFrame,
        [string]$Name
    )

    $record = $InputFrame.Record
    # Dynamic objects can resolve members that PSObject does not list.
    if ($record.PSObject.BaseObject -is [System.Dynamic.IDynamicMetaObjectProvider]) {
        return $true
    }
    if ($record -is [Collections.IDictionary]) {
        $type = $record.GetType()
        $isGenericDictionary = $type.IsGenericType -and
            $type.GetGenericTypeDefinition() -eq [Collections.Generic.Dictionary[string, object]].GetGenericTypeDefinition()
        if ($type -notin [hashtable], [Collections.Specialized.OrderedDictionary] -and
            -not $isGenericDictionary) {
            # Keep custom dictionary lookup in the native member access.
            return $true
        }
        if (([Collections.IDictionary]$record).Contains($Name)) {
            return $true
        }
    }
    elseif ($record -is [Collections.IEnumerable] -and $record -isnot [string]) {
        # Keep PowerShell's member-access enumeration for these records.
        return $true
    }
    return $null -ne $record.PSObject.Properties[$Name]
}

function Get-ADAnalyzerSecretNames {
    return [ADAnalyzerSecretIndicator]::new().GetNamePattern()
}

function Test-ADAnalyzerSecretName {
    param([string]$Name)
    return [ADAnalyzerSecretIndicator]::new().IsSecretName($Name)
}

function Assert-ADAnalyzerValueBaseline {
    param([hashtable]$Profile)
    return [ADAnalyzerSecretIndicator]::new().AssertValueBaseline($Profile)
}

function Test-ADAnalyzerSecretPresence {
    param([AllowNull()]$Value)
    return [ADAnalyzerSecretIndicator]::new().IsPresent($Value)
}

function ConvertTo-ADAnalyzerSecretRecord {
    param([Parameter(Mandatory)]$Record)
    return [ADAnalyzerSecretIndicator]::new().ProjectRecord($Record)
}

function Get-ADAnalyzerXmlSecretName {
    param([Xml.XmlNode]$Node)
    return [ADAnalyzerSecretIndicator]::new().FindXmlSecretName($Node)
}

function ConvertTo-ADAnalyzerSecretIndicatorXml {
    param([Parameter(Mandatory)][Xml.XmlNode]$Node)
    return [ADAnalyzerSecretIndicator]::new().ProjectXml($Node)
}

function ConvertTo-ADAnalyzerSecretIndicatorText {
    param([string]$Text)
    return [ADAnalyzerSecretIndicator]::new().ProjectText($Text)
}
