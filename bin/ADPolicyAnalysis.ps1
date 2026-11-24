# Offline policy assessment. Directory transport and changes belong to the caller.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')

. (Join-Path $PSScriptRoot 'ADPolicyValueSemantics.ps1')

function Get-ADAnalyzerPolicyProfileValue {
    param(
        [hashtable]$Profile,
        [string]$Name,
        $Default

    )
    Get-ADAnalyzerPolicyValue (Get-ADAnalyzerPolicyValue $Profile Policy @{}) $Name $Default
}

function Test-ADAnalyzerPolicyValueValid {
    param($Record)
    $marker = Get-ADAnalyzerPolicyValue $Record ValueValid $null
    return (New-ADAnalyzerPolicyValueSemantics).AcceptValidityMarker($marker)
}

function Get-ADAnalyzerXmlAttribute {
    param(
        [Xml.XmlNode]$Node,
        [string]$Name,
        [string]$Default = ''

    )
    if ($Node) {
        foreach ($attribute in @($Node.PSBase.Attributes)) {
            if ($attribute.PSBase.LocalName -ieq $Name) {
                return $attribute.PSBase.Value
            }
        }
    }
    return $Default
}

function Get-ADAnalyzerPresencePolicyXml {
    param([Xml.XmlNode]$Node)
    if (-not $Node) {
        return $null
    }
    return (ConvertTo-ADAnalyzerSecretIndicatorXml $Node).PSBase.OuterXml
}

class ADAnalyzerGpoPolicyRecordParser {
    ADAnalyzerGpoPolicyRecordParser() {
    }

    [string] GetXmlPath([Xml.XmlNode]$Node) {
        $parts = @()
        while ($Node -and $Node.PSBase.NodeType -eq [Xml.XmlNodeType]::Element) {
            $uid = Get-ADAnalyzerXmlAttribute $Node uid
            if ($uid) {
                $parts = @($Node.PSBase.LocalName + '#' + $uid) + $parts
                break
            }
            $position = 1
            $sibling = $Node.PSBase.PreviousSibling
            while ($sibling) {
                if ($sibling.PSBase.NodeType -eq [Xml.XmlNodeType]::Element -and $sibling.PSBase.LocalName -eq $Node.PSBase.LocalName) {
                    $position++
                }
                $sibling = $sibling.PSBase.PreviousSibling
            }
            $parts = @($Node.PSBase.LocalName + '[' + $position + ']') + $parts
            $Node = $Node.PSBase.ParentNode
        }
        return $parts -join '/'
    }

    [string[]] ResolveIdentities([string[]]$Targets) {
        $counts = $this.NewIdentityIndex()
        $seen = $this.NewIdentityIndex()
        foreach ($identity in $Targets) {
            $counts[$identity] = $this.NextIdentityOrdinal($counts[$identity])
        }

        $results = [Collections.Generic.List[string]]::new()
        foreach ($identity in $Targets) {
            if ($this.IsUniqueIdentity($counts[$identity])) {
                $results.Add($identity)
                continue
            }
            $seen[$identity] = $this.NextIdentityOrdinal($seen[$identity])
            $results.Add($this.DuplicateIdentity($identity, $seen[$identity]))
        }
        return $results.ToArray()
    }

    hidden [Collections.Generic.Dictionary[string, int]] NewIdentityIndex() {
        return [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    }

    hidden [int] NextIdentityOrdinal([object]$Current) {
        if ($null -eq $Current) {
            return 1
        }
        return $Current + 1
    }

    hidden [bool] IsUniqueIdentity([object]$Count) {
        return $Count -eq 1
    }

    hidden [string] DuplicateIdentity([string]$Identity, [int]$Occurrence) {
        return $Identity + '/duplicate/' + $Occurrence.ToString([Globalization.CultureInfo]::InvariantCulture)
    }

    [bool] IsSecurityTemplateSource([string]$Scope, [string]$Source) {
        $relative = ([string]$Source).Replace('\', '/')
        return ($Scope -ieq 'Computer' -and $relative -ieq 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf') -or
        ($Scope -ieq 'User' -and $relative -ieq 'User/Microsoft/Windows NT/SecEdit/GptTmpl.inf')
    }

    [object[]] ParseRestrictedGroups([object[]]$IniSettings) {
        $parser = $this
        $selected = @($IniSettings | Where-Object {
            $parser.IsRestrictedGroupSection($_.Section) -and $parser.IsSecurityTemplateSource($_.Scope, $_.Source)
        })
        $results = [Collections.Generic.List[object]]::new()
        foreach ($setting in $selected) {
            $match = $this.MatchRestrictedGroup([string]$setting.Name)
            $results.Add($this.ParseRestrictedGroupRecord(@{
                Setting = $setting
                Match = $match
            }))
        }
        return $results.ToArray()
    }

    hidden [bool] IsRestrictedGroupSection([object]$Section) {
        return $Section -ieq 'Group Membership'
    }

    hidden [Text.RegularExpressions.Match] MatchRestrictedGroup([string]$Name) {
        return [regex]::Match($Name,
            '^(?<group>.+)__(?<mode>Members|Memberof)$',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }

    hidden [pscustomobject] ParseRestrictedGroupRecord([hashtable]$InputFrame) {
        $setting = $InputFrame.Setting
        $match = $InputFrame.Match
        $values = New-ADAnalyzerPolicyValueSemantics
        $valid = $match.Success
        $group = $null
        $members = @()
        $errorText = $null
        try {
            if ($valid) {
                $group = $values.ParsePrincipal($match.Groups['group'].Value)
                $valid = $group.Valid
                if (-not [string]::IsNullOrWhiteSpace([string]$setting.Value)) {
                    $members = @(
                        Split-AnalyzerPolicyCsv ([string]$setting.Value) | ForEach-Object {
                            $_
                        } | ForEach-Object {
                            $values.ParsePrincipal($_)
                        }
                    )
                    if (@($members | Where-Object { -not $_.Valid }).Count) {
                        $valid = $false
                    }
                }
            }
        }
        catch {
            $valid = $false
            $errorText = 'Malformed group membership value'
        }
        return [pscustomobject]@{
            Scope = $setting.Scope
            Source = $setting.Source
            GroupSid = $group.Sid
            GroupName = $group.Name
            Mode = $match.Groups['mode'].Value
            Members = $members
            Valid = $valid
            Error = $errorText
            SettingName = $setting.Name
        }
    }

    hidden [object[]] ReadXmlRecords([object[]]$XmlFiles) {
        $records = [Collections.Generic.List[object]]::new()
        foreach ($file in @($XmlFiles)) {
            $record = $null
            try {
                $record = $this.ReadXmlText(@{
                    File = $file
                    Text = [string]$file.Xml
                })
            }
            catch {
                $record = $this.InvalidXmlRecord(@{
                    File = $file
                })
            }
            $records.Add($record)
        }
        return $records.ToArray()
    }

    hidden [pscustomobject] ReadXmlText([hashtable]$InputFrame) {
        try {
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $text = [IO.StringReader]::new($InputFrame.Text)
            $reader = [Xml.XmlReader]::Create($text, $settings)
            $doc = $null
            try {
                $doc = [xml]::new()
                $doc.XmlResolver = $null
                $doc.Load($reader)
            }
            finally {
                $reader.Dispose()
                $text.Dispose()
            }
            return [pscustomobject]@{
                File = $InputFrame.File
                Document = $doc
                Valid = $true
            }
        }
        catch {
            return $this.InvalidXmlRecord($InputFrame)
        }
    }

    hidden [pscustomobject] InvalidXmlRecord([hashtable]$InputFrame) {
        return [pscustomobject]@{
            File = $InputFrame.File
            Document = $null
            Valid = $false
        }
    }

    [object[]] ParseLocalUsersGroups([object[]]$XmlFiles) {
        # All file reads precede group traversal, including invalid records.
        $records = $this.ReadXmlRecords($XmlFiles)
        $results = [Collections.Generic.List[object]]::new()
        foreach ($record in $records) {
            foreach ($item in $this.SelectLocalGroupItems(@{
                        Record = $record
                    })) {
                $results.Add($this.ParseLocalGroupItem(@{
                    Record = $record
                    Item = $item
                }))
            }
        }
        return $results.ToArray()
    }

    hidden [object[]] SelectLocalGroupItems([hashtable]$InputFrame) {
        $record = $InputFrame.Record
        if (-not $record.Valid) {
            return @()
        }
        $root = $record.Document.PSBase.DocumentElement
        if ($root.PSBase.LocalName -ine 'Groups') {
            return @()
        }
        return @($root.PSBase.ChildNodes | Where-Object {
            $_.PSBase.NodeType -eq [Xml.XmlNodeType]::Element -and
                $_.PSBase.LocalName -in 'Group', 'User'
        })
    }

    hidden [pscustomobject] ParseLocalGroupItem([hashtable]$InputFrame) {
        $record = $InputFrame.Record
        $item = $InputFrame.Item
        $values = New-ADAnalyzerPolicyValueSemantics

        $properties = $item.SelectSingleNode('./*[local-name()="Properties"]')
        $members = @()
        foreach ($member in @($(if ($properties) {
                        $properties.SelectNodes('./*[local-name()="Members"]/*[local-name()="Member"]')
                    }))) {
            $sid = Get-ADAnalyzerXmlAttribute $member sid
            $principal = $values.ParsePrincipal($(if ($sid) {
                    $sid
                }
                else {
                    Get-ADAnalyzerXmlAttribute $member name
                }))
            if ($sid -and -not $values.IsSid($sid)) {
                $principal.Valid = $false
            }
            $members += [pscustomobject]@{
                Sid = $principal.Sid
                Name = $principal.Name
                Valid = $principal.Valid
                Action = (Get-ADAnalyzerXmlAttribute $member action).ToUpperInvariant()
            }
        }
        $action = (Get-ADAnalyzerXmlAttribute $properties action).ToUpperInvariant()
        $filters = $item.SelectSingleNode('./*[local-name()="Filters"]')
        $disabled = Get-ADAnalyzerXmlAttribute $item disabled '0'
        $targetSid = Get-ADAnalyzerXmlAttribute $properties groupSid
        if ($item.PSBase.LocalName -eq 'User') {
            $targetSid = Get-ADAnalyzerXmlAttribute $properties userSid (Get-ADAnalyzerXmlAttribute $properties sid)
        }
        $targetName = Get-ADAnalyzerXmlAttribute $properties $(if ($item.PSBase.LocalName -eq 'Group') {
                'groupName'
            }
            else {
                'userName'
            })
        $sidValid = -not $targetSid -or $values.IsSid($targetSid)
        $result = [pscustomobject]@{
            Scope = $record.File.Scope
            Source = $record.File.Path
            Kind = $item.PSBase.LocalName
            Uid = (Get-ADAnalyzerXmlAttribute $item uid)
            ItemPath = $this.GetXmlPath($item)
            Name = $targetName
            Sid = $targetSid
            Action = $action
            Disabled = ($disabled -in '1', 'true')
            AccountDisabled = (Get-ADAnalyzerXmlAttribute $properties disabled)
            PasswordNeverExpires = (Get-ADAnalyzerXmlAttribute $properties neverExpires)
            Targeted = ($null -ne $filters -and $filters.PSBase.HasChildNodes)
            Filters = (Get-ADAnalyzerPresencePolicyXml $filters)
            DeleteAllUsers = (Get-ADAnalyzerXmlAttribute $properties deleteAllUsers '0') -in '1', 'true'
            DeleteAllGroups = (Get-ADAnalyzerXmlAttribute $properties deleteAllGroups '0') -in '1', 'true'
            RemovePolicy = (Get-ADAnalyzerXmlAttribute $item removePolicy '0') -in '1', 'true'
            Members = $members
            Valid = ($null -ne $properties -and
                $sidValid -and
                $disabled -in '0',
                '1',
                'true',
                'false' -and
                $action -in 'C',
                'U',
                'R',
                'D' -and
                @($members | Where-Object { -not $_.Valid -or
                        $_.Action -notin 'ADD',
                        'REMOVE' }).Count -eq 0)
        }
        return $result
    }
}

function Get-ADAnalyzerPolicyXmlPath {
    param([Xml.XmlNode]$Node)
    return [ADAnalyzerGpoPolicyRecordParser]::new().GetXmlPath($Node)
}

function Join-ADAnalyzerPolicyIdentity {
    param([string[]]$Parts)
    $result = [Text.StringBuilder]::new()
    foreach ($part in $Parts) {
        $text = [string]$part
        $null = $result.Append($text.Length.ToString([Globalization.CultureInfo]::InvariantCulture)).Append(':').Append($text)
    }
    $result.ToString()
}

function Resolve-ADAnalyzerPolicyIdentityCollisions {
    param([string[]]$Targets)
    $parser = [ADAnalyzerGpoPolicyRecordParser]::new()
    $counts = $parser.NewIdentityIndex()
    $seen = $parser.NewIdentityIndex()

    # Native indexing retains the original handling of null identity elements.
    foreach ($identity in $Targets) {
        $counts[$identity] = $parser.NextIdentityOrdinal($counts[$identity])
    }
    foreach ($identity in $Targets) {
        if ($parser.IsUniqueIdentity($counts[$identity])) {
            $identity
            continue
        }
        $seen[$identity] = $parser.NextIdentityOrdinal($seen[$identity])
        $parser.DuplicateIdentity($identity, $seen[$identity])
    }
}

function Get-ADAnalyzerPolicyApplicability {
    param(
        $Gpo,
        [string]$Scope,
        [hashtable]$Profile,
        [switch]$Targeted,
        [switch]$Disabled

    )
    $evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
    $flags = Get-ADAnalyzerPolicyValue $Gpo Flags 0
    # Keep the short-circuited cast in command scope for native errors.
    if ($Disabled -or $evaluator.IsScopeDisabled([int]$flags, $Scope)) {
        return 'NotApplicable'
    }

    $links = @(Get-ADAnalyzerPolicyValue $Gpo Links @())
    if ($links.Count -gt 0 -and
        $evaluator.NoEnabledLinks(@($links | Where-Object Enabled).Count)) {
        return 'NotApplicable'
    }
    if ($Targeted -or $evaluator.HasUnresolvedFilter((Get-ADAnalyzerPolicyValue $Gpo WmiFilter ''))) {
        return 'Unknown'
    }

    $analysis = Get-ADAnalyzerPolicyValue $Profile Analysis @{}
    # A native truthiness error under Continue keeps the default outcome.
    $assumed = $false
    if (Get-ADAnalyzerPolicyValue $analysis AssumeGpoApplicable $false) {
        $assumed = $true
    }
    return $evaluator.FromAssumption($assumed)
}

function ConvertTo-ADAnalyzerPolicyNumber {
    param($Value)
    $semantics = New-ADAnalyzerPolicyValueSemantics
    if (-not $semantics.CanParseNumber($Value)) {
        return $semantics.MakeResult(@{
            Valid = $false
            Value = $null
        })
    }

    # Keep the native string conversion and assignment in command scope.
    $number = 0L
    $valid = $semantics.ParseNumberText([string]$Value, [ref]$number)
    $semantics.MakeResult(@{
        Valid = $valid
        Value = $number
    })
}

function ConvertTo-ADAnalyzerPolicyBoolean {
    param($Value)
    $semantics = New-ADAnalyzerPolicyValueSemantics
    if ($semantics.IsBoolean($Value)) {
        return $semantics.MakeResult(@{
            Valid = $true
            Value = $Value
        })
    }
    if ($semantics.CanParseBooleanText($Value)) {
        $parsed = $null
        $parsed = $semantics.ParseBooleanText([string]$Value)
        if ($null -ne $parsed) {
            return $parsed
        }
    }
    $semantics.MakeResult(@{
        Valid = $false
        Value = $null
    })
}

function Test-ADAnalyzerPolicySid {
    param($Value)
    return (New-ADAnalyzerPolicyValueSemantics).IsSid($Value)
}

function Test-ADAnalyzerPolicySidList {
    param($Value)
    $semantics = New-ADAnalyzerPolicyValueSemantics
    if (-not $semantics.CanValidateSidList($Value)) {
        return $false
    }

    # Keep native enumeration and its continuation behavior in command scope.
    foreach ($sid in $Value) {
        if (-not $semantics.IsSid($sid)) {
            return $false
        }
    }
    return $true
}

function ConvertFrom-ADAnalyzerPolicyPrincipal {
    param([string]$Value)
    return (New-ADAnalyzerPolicyValueSemantics).ParsePrincipal($Value)
}

function Test-ADAnalyzerSecurityTemplateSource {
    param(
        [string]$Scope,
        [string]$Source

    )
    return [ADAnalyzerGpoPolicyRecordParser]::new().IsSecurityTemplateSource($Scope, $Source)
}

function ConvertFrom-ADAnalyzerRestrictedGroups {
    [CmdletBinding()]
    param([object[]]$IniSettings)
    $parser = [ADAnalyzerGpoPolicyRecordParser]::new()
    $selected = @($IniSettings | Where-Object {
        $parser.IsRestrictedGroupSection($_.Section) -and
        (Test-ADAnalyzerSecurityTemplateSource -Scope $_.Scope -Source $_.Source)
    })
    foreach ($setting in $selected) {
        # Conversion and assignment retain their native command-scope continuation.
        $match = $parser.MatchRestrictedGroup([string]$setting.Name)
        $parser.ParseRestrictedGroupRecord(@{
            Setting = $setting
            Match = $match
        })
    }
}

function Get-ADAnalyzerPolicyXmlRecords {
    param([object[]]$XmlFiles)
    $parser = [ADAnalyzerGpoPolicyRecordParser]::new()
    foreach ($file in @($XmlFiles)) {
        try {
            $parser.ReadXmlText(@{
                File = $file
                Text = [string]$file.Xml
            })
        }
        catch {
            $parser.InvalidXmlRecord(@{
                File = $file
            })
        }
    }
}

function ConvertFrom-ADAnalyzerLocalUsersGroups {
    [CmdletBinding()]
    param([object[]]$XmlFiles)
    $parser = [ADAnalyzerGpoPolicyRecordParser]::new()
    foreach ($record in @(Get-ADAnalyzerPolicyXmlRecords $XmlFiles)) {
        # Emit each item before reading metadata for the next file item.
        foreach ($item in $parser.SelectLocalGroupItems(@{
                    Record = $record
                })) {
            $parser.ParseLocalGroupItem(@{
                Record = $record
                Item = $item
            })
        }
    }
}

class ADAnalyzerRegistryPolicyReplay {
    ADAnalyzerRegistryPolicyReplay() {
    }

    [object[]] Replay([object[]]$RegistrySettings) {
        $state = $this.NewState()
        $replay = $this
        foreach ($row in @($RegistrySettings)) {
            $keyPath = $this.NormalizeKey([string]$row.Key)
            $name = [string]$row.ValueName
            $singleDeletion = $name -match $this.NamedDeletionPattern()
            $action = $this.GetAction($name, $singleDeletion)
            if ($action -eq 'DeleteValue') {
                $this.PutNamedDeletion($state, @{
                    Hive = $row.Hive
                    Key = $row.Key
                    ValueName = $Matches[1]
                    Type = $row.Type
                    Scope = $row.Scope
                    Source = $row.Source
                }, (Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $Matches[1])))
                continue
            }

            if ($action -in 'DeleteValues', 'DeleteKeys') {
                $data = if ($row.Value -is [byte[]]) {
                    $this.TrimDecodedPayload([Text.Encoding]::Unicode.GetString($row.Value))
                }
                else {
                    [string]$row.Value
                }
                foreach ($entry in $this.SplitPayload($data)) {
                    if ($action -eq 'DeleteValues') {
                        $this.PutNamedDeletion($state, @{
                            Hive = $row.Hive
                            Key = $row.Key
                            ValueName = $entry
                            Type = $row.Type
                            Scope = $row.Scope
                            Source = $row.Source
                        }, (Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $entry)))
                    }
                    else {
                        $targetKey = $this.GetSubtreeRoot($keyPath, $entry)
                        $prefix = $this.GetDescendantPrefix($targetKey)
                        $keys = @($state.Keys | Where-Object {
                            $replay.Matches(@{
                                Left = $state[$_].Hive
                                Right = $row.Hive
                            }) -and (
                                $replay.Matches(@{
                                    Left = $state[$_].Key
                                    Right = $targetKey
                                }) -or
                                $replay.StartsWithPrefix([string]$state[$_].Key, $prefix)
                            )
                        })
                        $this.MarkDeleted($state, $keys)
                    }
                }
                continue
            }

            if ($action -eq 'DelVals') {
                $keys = @($state.Keys | Where-Object {
                    $replay.Matches(@{
                        Left = $state[$_].Hive
                        Right = $row.Hive
                    }) -and
                    $replay.Matches(@{
                        Left = $state[$_].Key
                        Right = $row.Key
                    })
                })
                $this.MarkDeleted($state, $keys)
                continue
            }

            if ($action -eq 'Write' -and $this.CanWrite(@{
                        KeyOnly = $row.KeyOnly
                    })) {
                $copy = [ordered]@{}
                foreach ($property in $row.PSObject.Properties) {
                    $copy[$property.Name] = $property.Value
                }
                $this.PutRecord($state, $this.CreateWriteRecord($copy),
                    (Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $name)))
            }
        }
        return @($state.Values)
    }

    hidden [hashtable] NewState() {
        return @{}
    }

    hidden [string] NormalizeKey([string]$Key) {
        return $Key.TrimEnd('\')
    }

    hidden [string] NamedDeletionPattern() {
        return '^\*\*del\.(.*)$'
    }

    hidden [string] GetAction([string]$Name, [bool]$SingleDeletion) {
        if ($SingleDeletion) {
            return 'DeleteValue'
        }
        if ($Name -ieq '**DeleteValues') {
            return 'DeleteValues'
        }
        if ($Name -ieq '**DelVals') {
            return 'DelVals'
        }
        if ($Name -ieq '**DeleteKeys') {
            return 'DeleteKeys'
        }
        if ($Name.StartsWith('**')) {
            return 'Ignore'
        }
        return 'Write'
    }

    hidden [string] TrimDecodedPayload([string]$Text) {
        return $Text.TrimEnd([char]0)
    }

    hidden [string[]] SplitPayload([string]$Payload) {
        return @($Payload -split ';' | Where-Object { $_ })
    }

    hidden [string] GetSubtreeRoot([string]$Key, [string]$Entry) {
        return $Key + '\' + $Entry.TrimEnd('\')
    }

    hidden [string] GetDescendantPrefix([string]$Root) {
        return $Root + '\'
    }

    hidden [bool] Matches([hashtable]$Operands) {
        return $Operands.Left -ieq $Operands.Right
    }

    hidden [bool] StartsWithPrefix([string]$Key, [string]$Prefix) {
        return $Key.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)
    }

    hidden [bool] CanWrite([hashtable]$InputFrame) {
        return -not $InputFrame.KeyOnly
    }

    hidden [void] PutNamedDeletion([hashtable]$State, [hashtable]$Fields, [string]$Identity) {
        $record = [pscustomobject]@{
            Hive = $Fields.Hive
            Key = $Fields.Key
            ValueName = $Fields.ValueName
            Value = $null
            Type = $Fields.Type
            Scope = $Fields.Scope
            Source = $Fields.Source
            Deleted = $true
        }
        $this.PutRecord($State, $record, $Identity)
    }

    hidden [pscustomobject] CreateWriteRecord([Collections.Specialized.OrderedDictionary]$Fields) {
        $Fields.Deleted = $false
        return [pscustomobject]$Fields
    }

    hidden [void] PutRecord([hashtable]$State, [pscustomobject]$Record, [string]$Identity) {
        $State[$Identity] = $Record
    }

    hidden [void] MarkDeleted([hashtable]$State, [string[]]$Keys) {
        foreach ($key in $Keys) {
            if ($null -ne $State[$key].PSObject.Properties['Value']) {
                $State[$key].Value = $null
            }
            if ($null -ne $State[$key].PSObject.Properties['SecretPresent']) {
                $State[$key].SecretPresent = $false
            }
            $State[$key].Deleted = $true
        }
    }
}

function Get-ADAnalyzerEffectiveRegistryRecords {
    param([object[]]$RegistrySettings)
    $replay = [ADAnalyzerRegistryPolicyReplay]::new()
    $state = $replay.NewState()
    foreach ($row in @($RegistrySettings)) {
        # Preserve native conversion errors without reusing a previous row.
        $keyPath = $null
        $name = $null
        $keyPath = $replay.NormalizeKey([string]$row.Key)
        $name = [string]$row.ValueName
        if ($null -eq $keyPath -or $null -eq $name) {
            continue
        }

        # Capture the regular expression match in the command scope.
        $singleDeletion = $name -match $replay.NamedDeletionPattern()
        $action = $replay.GetAction($name, $singleDeletion)
        if ($action -eq 'DeleteValue') {
            $replay.PutNamedDeletion($state, @{
                Hive = $row.Hive
                Key = $row.Key
                ValueName = $Matches[1]
                Type = $row.Type
                Scope = $row.Scope
                Source = $row.Source
            }, (Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $Matches[1])))
            continue
        }

        if ($action -in 'DeleteValues', 'DeleteKeys') {
            $data = $null
            $data = if ($row.Value -is [byte[]]) {
                $replay.TrimDecodedPayload([Text.Encoding]::Unicode.GetString($row.Value))
            }
            else {
                [string]$row.Value
            }
            foreach ($entry in $replay.SplitPayload($data)) {
                if ($action -eq 'DeleteValues') {
                    $replay.PutNamedDeletion($state, @{
                        Hive = $row.Hive
                        Key = $row.Key
                        ValueName = $entry
                        Type = $row.Type
                        Scope = $row.Scope
                        Source = $row.Source
                    }, (Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $entry)))
                }
                else {
                    # Native filtering retains one observation per candidate and its own errors.
                    $targetKey = $replay.GetSubtreeRoot($keyPath, $entry)
                    $prefix = $replay.GetDescendantPrefix($targetKey)
                    $keys = @($state.Keys | Where-Object {
                        $replay.Matches(@{
                            Left = $state[$_].Hive
                            Right = $row.Hive
                        }) -and (
                            $replay.Matches(@{
                                Left = $state[$_].Key
                                Right = $targetKey
                            }) -or
                            $replay.StartsWithPrefix([string]$state[$_].Key, $prefix)
                        )
                    })
                    $replay.MarkDeleted($state, $keys)
                }
            }
            continue
        }

        if ($action -eq 'DelVals') {
            $keys = @($state.Keys | Where-Object {
                $replay.Matches(@{
                    Left = $state[$_].Hive
                    Right = $row.Hive
                }) -and
                $replay.Matches(@{
                    Left = $state[$_].Key
                    Right = $row.Key
                })
            })
            $replay.MarkDeleted($state, $keys)
            continue
        }

        if ($action -eq 'Write' -and $replay.CanWrite(@{
                    KeyOnly = $row.KeyOnly
                })) {
            $copy = [ordered]@{}
            foreach ($property in $row.PSObject.Properties) {
                $copy[$property.Name] = $property.Value
            }
            $replay.PutRecord($state, $replay.CreateWriteRecord($copy),
                (Join-ADAnalyzerPolicyIdentity @($row.Hive, $keyPath, $name)))
        }
    }
    $state.Values
}

function Get-ADAnalyzerSecuritySpecifications {
    param([hashtable]$Profile)
    $evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
    # Emit the fixed rows before reading any profile settings.
    $evaluator.FixedSecuritySpecifications()

    $defaults = $evaluator.GetSecuritySpecificationDefaults()
    $evaluator.ConfiguredSecuritySpecifications(@{
        MinimumLm = (Get-ADAnalyzerPolicyProfileValue $Profile MinimumLmCompatibilityLevel $defaults.MinimumLm)
        ServerSigning = $(if (Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapServerSigning $defaults.LdapSigning) {
                $true
            }
            else {
                $false
            })
        ClientSigning = $(if (Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapClientSigning $defaults.LdapSigning) {
                $true
            }
            else {
                $false
            })
        AnonymousPipes = @(Get-ADAnalyzerPolicyProfileValue $Profile AllowedAnonymousPipes $defaults.AnonymousPipes)
    })
}

function Test-ADAnalyzerPolicyComparison {
    param(
        $Observed,
        $Expected,
        [string]$Operator = 'Equals'

    )

    $semantics = New-ADAnalyzerPolicyValueSemantics
    $kind = $semantics.ResolveOperator($Operator)
    switch ($kind) {
        { $_ -in 'Equals', 'NotEquals' } {
            $left = @($Observed)
            $right = @($Expected)
            $comparison = $semantics.PrepareEquality($left, $right)
            $differences = 0
            if ($comparison.CompareMembers) {
                # Compare-Object reports native binding and comparison errors here.
                $differences = @(Compare-Object -ReferenceObject $left -DifferenceObject $right).Count
            }
            return $semantics.FinishEquality($kind, $comparison.CountsMatch, $differences)
        }
        { $_ -in 'In', 'NotIn' } {
            return $semantics.CompareMembership($kind, @{
                Observed = $Observed
                Expected = $Expected
            })
        }
        { $_ -in 'Minimum', 'Maximum' } {
            $number = ConvertTo-ADAnalyzerPolicyNumber $Observed
            if (-not $semantics.HasNumericValue($number)) {
                throw 'A numeric value is required'
            }
            return $semantics.CompareBound($kind, $number.Value, [long]$Expected)
        }
        default {
            throw 'Unsupported comparison operator'
        }
    }
}

class ADAnalyzerGpoPolicyEvaluator {
    ADAnalyzerGpoPolicyEvaluator() {
    }

    [string] GetApplicability([object]$Gpo, [string]$Scope, [hashtable]$Profile) {
        return $this.GetApplicability($Gpo, $Scope, $Profile, $false, $false)
    }

    [string] GetApplicability(
        [object]$Gpo,
        [string]$Scope,
        [hashtable]$Profile,
        [bool]$Targeted,
        [bool]$Disabled
    ) {
        $flags = Get-ADAnalyzerPolicyValue $Gpo Flags 0
        if ($Disabled -or $this.IsScopeDisabled([int]$flags, $Scope)) {
            return 'NotApplicable'
        }

        $links = @(Get-ADAnalyzerPolicyValue $Gpo Links @())
        if ($links.Count -gt 0 -and
            $this.NoEnabledLinks(@($links | Where-Object Enabled).Count)) {
            return 'NotApplicable'
        }
        if ($Targeted -or $this.HasUnresolvedFilter((Get-ADAnalyzerPolicyValue $Gpo WmiFilter ''))) {
            return 'Unknown'
        }

        $analysis = Get-ADAnalyzerPolicyValue $Profile Analysis @{}
        return $this.FromAssumption((Get-ADAnalyzerPolicyValue $analysis AssumeGpoApplicable $false))
    }

    hidden [bool] IsScopeDisabled([int]$Flags, [string]$Scope) {
        $bit = 2
        if ($Scope -eq 'User') {
            $bit = 1
        }
        return [bool]($Flags -band $bit)
    }

    hidden [bool] NoEnabledLinks([int]$EnabledCount) {
        return $EnabledCount -eq 0
    }

    hidden [bool] HasUnresolvedFilter([object]$Filter) {
        return [bool]$Filter
    }

    hidden [string] FromAssumption([object]$Assumption) {
        if ($Assumption) {
            return 'Applicable'
        }
        return 'Unknown'
    }

    [object[]] GetSecuritySpecifications([hashtable]$Profile) {
        $fixed = $this.FixedSecuritySpecifications()
        $defaults = $this.GetSecuritySpecificationDefaults()
        $fields = @{
            MinimumLm = (Get-ADAnalyzerPolicyProfileValue $Profile MinimumLmCompatibilityLevel $defaults.MinimumLm)
            ServerSigning = $(if (Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapServerSigning $defaults.LdapSigning) {
                    $true
                }
                else {
                    $false
                })
            ClientSigning = $(if (Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapClientSigning $defaults.LdapSigning) {
                    $true
                }
                else {
                    $false
                })
            AnonymousPipes = @(Get-ADAnalyzerPolicyProfileValue $Profile AllowedAnonymousPipes $defaults.AnonymousPipes)
        }
        return @($fixed + $this.ConfiguredSecuritySpecifications($fields))
    }

    hidden [hashtable] GetSecuritySpecificationDefaults() {
        return @{
            MinimumLm = 5
            LdapSigning = $true
            AnonymousPipes = @('LSARPC', 'NETLOGON', 'SAMR')
        }
    }

    hidden [object[]] FixedSecuritySpecifications() {
        $definitions = @(
            ,
            @('RequireSecuritySignature',
                'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
                'Microsoft network server: Digitally sign communications (always)',
                $true)
            ,
            @('EnableSecuritySignature',
                'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
                'Microsoft network server: Digitally sign communications (if client agrees)',
                $true)
            ,
            @('RequireSecuritySignature',
                'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
                'Microsoft network client: Digitally sign communications (always)',
                $true)
            ,
            @('EnableSecuritySignature',
                'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
                'Microsoft network client: Digitally sign communications (if server agrees)',
                $true)
            ,
            @('EnablePlainTextPassword',
                'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
                'Microsoft network client: Send unencrypted password to third-party SMB servers',
                $false)
            ,
            @('RequireSignOrSeal',
                'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters',
                'Domain member: Digitally encrypt or sign secure channel data (always)',
                $true)
            ,
            @('SealSecureChannel',
                'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters',
                'Domain member: Digitally encrypt secure channel data (when possible)',
                $true)
            ,
            @('EveryoneIncludesAnonymous',
                'SYSTEM\CurrentControlSet\Control\Lsa',
                'Network access: Let Everyone permissions apply to anonymous users',
                $false)
            ,
            @('RestrictAnonymousSAM',
                'SYSTEM\CurrentControlSet\Control\Lsa',
                'Network access: Do not allow anonymous enumeration of SAM accounts',
                $true)
            ,
            @('RestrictAnonymous',
                'SYSTEM\CurrentControlSet\Control\Lsa',
                'Network access: Do not allow anonymous enumeration of SAM accounts and shares',
                $true)
            ,
            @('RestrictNullSessAccess',
                'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
                'Network access: Restrict anonymous access to Named Pipes and Shares',
                $true)
            ,
            @('FilterAdministratorToken',
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'User Account Control: Admin Approval Mode for the Built-in Administrator account',
                $true)
            ,
            @('EnableUIADesktopToggle',
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop',
                $false)
            ,
            @('EnableInstallerDetection',
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'User Account Control: Detect application installations and prompt for elevation',
                $true)
            ,
            @('EnableLUA',
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'User Account Control: Run all administrators in Admin Approval Mode',
                $true)
        )
        return @(
            foreach ($definition in $definitions) {
                [pscustomobject]@{
                    Id = $definition[1] + '\' + $definition[0]
                    Key = $definition[1]
                    ValueName = $definition[0]
                    Name = $definition[2]
                    Kind = 'Boolean'
                    Type = 4
                    Expected = $definition[3]
                }
            }
        )
    }

    hidden [object[]] ConfiguredSecuritySpecifications([hashtable]$Fields) {
        $serverExpected = $null
        if ($null -ne $Fields.ServerSigning) {
            $serverExpected = $this.GetLdapSigningExpectation($Fields.ServerSigning)
        }
        $clientExpected = $null
        if ($null -ne $Fields.ClientSigning) {
            $clientExpected = $this.GetLdapSigningExpectation($Fields.ClientSigning)
        }

        return @(
            [pscustomobject]@{
                Id = 'Lsa.LmCompatibilityLevel'
                Key = 'SYSTEM\CurrentControlSet\Control\Lsa'
                ValueName = 'LmCompatibilityLevel'
                Name = 'Network security: LAN Manager authentication level'
                Kind = 'Lm'
                Type = 4
                Expected = $Fields.MinimumLm
            }
            [pscustomobject]@{
                Id = 'NTDS.LDAPServerIntegrity'
                Key = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                ValueName = 'LDAPServerIntegrity'
                Name = 'Domain controller: LDAP server signing requirements'
                Kind = 'LdapServer'
                Type = 4
                Expected = $serverExpected
            }
            [pscustomobject]@{
                Id = 'LDAP.LDAPClientIntegrity'
                Key = 'SYSTEM\CurrentControlSet\Services\LDAP'
                ValueName = 'LDAPClientIntegrity'
                Name = 'Network security: LDAP client signing requirements'
                Kind = 'LdapClient'
                Type = 4
                Expected = $clientExpected
            }
            [pscustomobject]@{
                Id = 'UAC.ConsentPromptBehaviorAdmin'
                Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                ValueName = 'ConsentPromptBehaviorAdmin'
                Name = 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
                Kind = 'UacPrompt'
                Type = 4
                Expected = 'Prompt (1-5)'
            }
            [pscustomobject]@{
                Id = 'Server.NullSessionPipes'
                Key = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
                ValueName = 'NullSessionPipes'
                Name = 'Network access: Named Pipes that can be accessed anonymously'
                Kind = 'Pipes'
                Type = 7
                Expected = $Fields.AnonymousPipes
            }
            [pscustomobject]@{
                Id = 'Server.NullSessionShares'
                Key = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
                ValueName = 'NullSessionShares'
                Name = 'Network access: Shares that can be access anonymously'
                Kind = 'Shares'
                Type = 7
                Expected = @()
            }
            [pscustomobject]@{
                Id = 'LSAAnonymousNameLookup'
                Key = $null
                ValueName = $null
                Name = 'Network access: Allow anonymous SID/Name translation'
                Kind = 'Boolean'
                Type = $null
                Expected = $false
            }
        )
    }

    hidden [object] GetLdapSigningExpectation([bool]$Required) {
        if ($Required) {
            return 2
        }
        return 'Any valid value'
    }

    [object[]] Evaluate([object]$Gpo, [object]$Policy, [hashtable]$Profile) {
        return $this.EvaluateCore($Gpo, $Policy, $Profile, $null, 'Stop')
    }

    hidden [void] EvaluateForCommand(
        [object]$Gpo,
        [object]$Policy,
        [hashtable]$Profile,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        $null = $this.EvaluateCore($Gpo, $Policy, $Profile, $CommandContext, $ErrorPreference)
    }

    hidden [object[]] EvaluateCore(
        [object]$Gpo,
        [object]$Policy,
        [hashtable]$Profile,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        if ($null -eq $Gpo -or $null -eq $Policy -or $null -eq $Profile) {
            throw 'Gpo, Policy and Profile are required.'
        }
        Assert-ADAnalyzerValueBaseline -Profile $Profile
        $identity = [string](Get-ADAnalyzerPolicyValue $Gpo Id (Get-ADAnalyzerPolicyValue $Gpo DisplayName 'offline'))
        $state = @{
            Gpo = $Gpo
            Policy = $Policy
            Profile = $Profile
            Target = 'GPO:' + $identity
            Registry = @()
            Checks = [Collections.Generic.List[object]]::new()
            CommandContext = $CommandContext
            ErrorPreference = $ErrorPreference
        }
        $this.EvaluateCredentials($state)
        $this.EvaluateAccount($state)
        $this.EvaluateSecurity($state)
        $this.EvaluateMembershipAndRights($state)
        $this.EvaluateCustomBaseline($state)
        $this.EvaluateCoverage($state)
        return $state.Checks.ToArray()
    }

    hidden [void] Emit([hashtable]$State, [Collections.IDictionary]$Parameters) {
        $ErrorActionPreference = if ($State.ErrorPreference -eq 'Stop') {
            'Stop'
        }
        else {
            'Continue'
        }
        $arguments = @{}
        foreach ($name in $Parameters.Keys) {
            $arguments[$name] = $Parameters[$name]
        }
        if ($State.ErrorPreference -eq 'Ignore') {
            $arguments.ErrorAction = 'Ignore'
        }
        foreach ($check in @(New-ADAnalyzerCheck @arguments 2>&1)) {
            if ($check -is [Management.Automation.ErrorRecord]) {
                if ($null -eq $State.CommandContext) {
                    throw $check
                }
                $State.CommandContext.WriteError($check)
            }
            elseif ($null -ne $State.CommandContext) {
                $State.CommandContext.WriteObject($check)
            }
            else {
                $State.Checks.Add($check)
            }
        }
    }

    hidden [int] CountMissingXml([object]$Policy, [object[]]$XmlRecords) {
        $expected = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
        $missing = 0
        foreach ($file in @(Get-ADAnalyzerPolicyValue $Policy Files)) {
            $kind = Get-ADAnalyzerPolicyValue $file Kind
            if ($kind -isnot [string] -or $kind -ine 'Xml') {
                continue
            }

            $missing++
            $scope = Get-ADAnalyzerPolicyValue $file Scope
            $path = Get-ADAnalyzerPolicyValue $file Path
            if ($scope -isnot [string] -or [string]::IsNullOrEmpty($scope) -or
                $path -isnot [string] -or [string]::IsNullOrEmpty($path)) {
                continue
            }

            # The reader puts the same logical scope and relative path in both lists.
            $identity = Join-ADAnalyzerPolicyIdentity @($scope, $path)
            $expected[$identity] = 1 + $expected[$identity]
        }
        if (-not $expected.Count) {
            return $missing
        }

        foreach ($record in $XmlRecords) {
            $scope = Get-ADAnalyzerPolicyValue $record.File Scope
            $path = Get-ADAnalyzerPolicyValue $record.File Path
            if ($scope -isnot [string] -or $path -isnot [string]) {
                continue
            }

            $identity = Join-ADAnalyzerPolicyIdentity @($scope, $path)
            if ($expected.ContainsKey($identity)) {
                $missing--
                $expected[$identity]--
                if (-not $expected[$identity]) {
                    $null = $expected.Remove($identity)
                    if (-not $expected.Count) {
                        break
                    }
                }
            }
        }
        return $missing
    }

    hidden [void] EvaluateCredentials([hashtable]$state) {
        $Gpo = $state.Gpo
        $Policy = $state.Policy
        $Profile = $state.Profile
        $target = $state.Target
        $xmlRecords = @(Get-ADAnalyzerPolicyXmlRecords $Policy.XmlFiles)
        $secretCount = 0
        $xmlErrors = 0
        $xmlSecretChecks = [Collections.Generic.List[object]]::new()
        foreach ($xmlRecord in $xmlRecords) {
            if (-not $xmlRecord.Valid) {
                $xmlErrors++
                $this.Emit($state, @{
                    RuleId = 'GPO.Xml.Readable'
                    Status = 'Unreadable'
                    Severity = 'Medium'
                    Category = 'PolicyCoverage'
                    Target = ($target + '/' + $xmlRecord.File.Path)
                    Observed = 'Unreadable XML'
                    Expected = 'Well-formed XML without DTDs'
                    Evidence = @{
                        Path = $xmlRecord.File.Path
                    }
                    Message = 'XML could not be parsed; its content was not included in the assessment.'
                    Applicability = 'Unknown'
                })
                continue
            }
            $credentialOwners = [Collections.Generic.HashSet[Xml.XmlElement]]::new()
            foreach ($attribute in @($xmlRecord.Document.SelectNodes('//@*') | Where-Object { ($_.PSBase.LocalName -ieq 'cpassword' -and
                            -not [string]::IsNullOrEmpty($_.PSBase.Value)) -or
                        ($_.PSBase.LocalName -ieq 'cpasswordPresent' -and
                        $_.PSBase.Value -ieq 'true') })) {
                if (-not $credentialOwners.Add($attribute.PSBase.OwnerElement)) {
                    continue
                }
                $secretCount++
                $item = $attribute.PSBase.OwnerElement.PSBase.ParentNode
                $safe = [ordered]@{
                    Path = $xmlRecord.File.Path
                    ItemUid = (Get-ADAnalyzerXmlAttribute $item uid)
                    ItemName = (Get-ADAnalyzerXmlAttribute $item name)
                    Account = (Get-ADAnalyzerXmlAttribute $attribute.PSBase.OwnerElement userName)
                    SecretPresent = $true
                }
                $attributePath = (Get-ADAnalyzerPolicyXmlPath $attribute.PSBase.OwnerElement) + '/@cpassword'
                $safe['Attribute'] = 'cpassword'
                $safe['ItemPath'] = $attributePath
                $xmlSecretChecks.Add(@{
                        RuleId = 'GPO.Preferences.CPassword'
                        Status = 'Fail'
                        Severity = 'Critical'
                        Category = 'CredentialExposure'
                        Target = (Join-ADAnalyzerPolicyIdentity @($target, $xmlRecord.File.Scope, $xmlRecord.File.Path, $attributePath))
                        Observed = $true
                        Expected = $false
                        Evidence = $safe
                        Message = 'A recoverable preference credential remains in stored policy. Remove the exposed credential and rotate the affected password; only its presence is reported.'
                        Applicability = 'Configured'
                    })
            }
            $presenceDocument = ConvertTo-ADAnalyzerSecretIndicatorXml $xmlRecord.Document
            foreach ($record in @($presenceDocument.SelectNodes('//*[@SecretPresent]'))) {
                $name = Get-ADAnalyzerXmlSecretName $record
                if (-not $name) {
                    continue
                }
                $present = $record.GetAttribute('SecretPresent') -ieq 'true'
                $itemPath = Get-ADAnalyzerPolicyXmlPath $record
                $location = Join-ADAnalyzerPolicyIdentity @($target, $xmlRecord.File.Scope, $xmlRecord.File.Path, $itemPath)
                $xmlSecretChecks.Add(@{
                        RuleId = 'GPO.StoredSecret'
                        Status = $(if ($present) {
                                'Fail'
                            }
                            else {
                                'Pass'
                            })
                        Severity = 'Critical'
                        Category = 'CredentialExposure'
                        Target = $location
                        Observed = $present
                        Expected = $false
                        Evidence = @{
                            SecretPresent = $present
                            Path = $xmlRecord.File.Path
                            Scope = $xmlRecord.File.Scope
                            ItemPath = $itemPath
                            SettingName = $name
                        }
                        Message = 'Only the presence of a named XML secret is reported; its value is omitted.'
                        Applicability = 'Configured'
                    })
            }
        }
        foreach ($family in @($xmlSecretChecks | Group-Object RuleId)) {
            $targets = @(Resolve-ADAnalyzerPolicyIdentityCollisions @($family.Group | ForEach-Object { $_.Target }))
            for ($index = 0; $index -lt $family.Group.Count; $index++) {
                $arguments = $family.Group[$index]
                $arguments.Target = $targets[$index]
                $this.Emit($state, $arguments)
            }
        }
        $missingXml = $this.CountMissingXml($Policy, $xmlRecords)
        if (-not $secretCount) {
            $status = 'Pass'
            $present = $false
            if ($xmlErrors -or $missingXml) {
                $status = 'Unknown'
                $present = $null
            }
            $message = 'Assessed XML contains no nonempty cpassword attribute; unreadable files prevent a complete conclusion.'
            if ($missingXml) {
                $message = 'Credential presence cannot be determined because inventoried XML content is missing.'
            }

            $this.Emit($state, @{
                RuleId = 'GPO.Preferences.CPassword'
                Status = $status
                Severity = 'Critical'
                Category = 'CredentialExposure'
                Target = ($target + '/cpassword')
                Observed = $present
                Expected = $false
                Evidence = @{
                    SecretPresent = $present
                    UnreadableXmlFiles = $xmlErrors
                }
                Message = $message
                Applicability = 'Configured'
            })
        }
        if ($missingXml) {
            $this.Emit($state, @{
                RuleId = 'GPO.Coverage.MissingXml'
                Status = 'Unknown'
                Severity = 'Medium'
                Category = 'PolicyCoverage'
                Target = ($target + '/MissingXml')
                Observed = $missingXml
                Expected = 0
                Evidence = $null
                Message = 'The GPO inventory lists XML files without matching content for assessment.'
                Applicability = 'Unknown'
            })
        }

        $storedSecrets = @(
            foreach ($row in @(Get-ADAnalyzerEffectiveRegistryRecords $Policy.RegistrySettings)) {
                if (-not $row.Deleted -and (Test-ADAnalyzerSecretName $row.ValueName)) {
                    $row
                }
            }
            foreach ($row in @($Policy.IniSettings)) {
                if (-not $row.Analyzed -and (Test-ADAnalyzerSecretName $row.Name)) {
                    $row
                }
            }
            foreach ($row in @($Policy.SecuritySettings)) {
                if (Test-ADAnalyzerSecretName $row.Name) {
                    $row
                }
            }
        )
        foreach ($row in $storedSecrets) {
            $name = [string](Get-ADAnalyzerPolicyValue $row ValueName (Get-ADAnalyzerPolicyValue $row Name 'secret'))
            $present = Get-ADAnalyzerPolicyValue $row SecretPresent $null
            if ($null -eq $present) {
                $present = Test-ADAnalyzerSecretPresence (Get-ADAnalyzerPolicyValue $row Value)
            }
            $location = ('{0}/{1}/{2}/{3}' -f $row.Scope,
                $row.Source,
                (Get-ADAnalyzerPolicyValue $row Key (Get-ADAnalyzerPolicyValue $row Section '')),
                $name)
            $this.Emit($state, @{
                RuleId = 'GPO.StoredSecret'
                Status = $(if ($present) {
                        'Fail'
                    }
                    else {
                        'Pass'
                    })
                Severity = 'Critical'
                Category = 'CredentialExposure'
                Target = ($target + '/' + $location)
                Observed = ([bool]$present)
                Expected = $false
                Evidence = @{
                    SecretPresent = [bool]$present
                    Path = $row.Source
                    Scope = $row.Scope
                    SettingName = $name
                }
                Message = 'Only the presence of a stored secret is reported; its value is omitted.'
                Applicability = 'Configured'
            })
        }
    }

    hidden [void] EvaluateAccount([hashtable]$state) {
        $Gpo = $state.Gpo
        $Policy = $state.Policy
        $Profile = $state.Profile
        $target = $state.Target
        $accountRules = @(
            , @('MinimumPasswordLength', 'MinimumPasswordLength', 12, 'Minimum', 0, 65536)
            , @('MinimumPasswordAge', 'MinimumPasswordAgeDays', 1, 'Minimum', 0, 999)
            , @('PasswordHistorySize', 'PasswordHistorySize', 10, 'Minimum', 0, 65536)
            , @('MaximumPasswordAge', 'MaximumPasswordAgeDays', 90, 'Age', -1, 999)
            , @('LockoutBadCount', 'LockoutThreshold', 6, 'Threshold', 0, 65536)
            , @('LockoutDuration', 'LockoutDurationMinutes', 30, 'Duration', -1, 99999)
            , @('ResetLockoutCount', 'ResetLockoutMinutes', 30, 'Minimum', -4294967296, 4294967296)
            , @('PasswordComplexity', 'PasswordComplexity', $true, 'Boolean', 0, 1)
            , @('ClearTextPassword', 'AllowReversibleEncryption', $false, 'Boolean', 0, 1)
        )
        foreach ($rule in $accountRules) {
            $rows = @($Policy.SecuritySettings | Where-Object { $_.Kind -eq 'Account' -and $_.Name -eq $rule[0] })
            $expected = Get-ADAnalyzerPolicyProfileValue $Profile $rule[1] $rule[2]
            if (-not $rows.Count) {
                $this.Emit($state, @{
                    RuleId = ('GPO.Account.' + $rule[0])
                    Status = 'NotConfigured'
                    Severity = 'High'
                    Category = 'AccountPolicy'
                    Target = ($target + '/Account/' + $rule[0])
                    Observed = $null
                    Expected = $expected
                    Evidence = $null
                    Message = 'This setting is absent from this GPO; inherited or effective policy has not been determined.'
                    Applicability = 'Unknown'
                })
                continue
            }
            foreach ($row in $rows) {
                $valid = $true
                $pass = $false
                $semantic = $null
                if (-not (Test-ADAnalyzerPolicyValueValid $row)) {
                    $valid = $false
                }
                elseif ($rule[3] -eq 'Boolean') {
                    $value = ConvertTo-ADAnalyzerPolicyBoolean $row.Value
                    $valid = $value.Valid
                    $pass = $value.Value -eq $expected
                }
                else {
                    $value = ConvertTo-ADAnalyzerPolicyNumber $row.Value
                    $valid = $value.Valid -and $value.Value -ge $rule[4] -and $value.Value -le $rule[5]
                    if ($valid) {
                        switch ($rule[3]) {
                            'Minimum' {
                                $pass = $value.Value -ge [long]$expected
                            }
                            'Age' {
                                $valid = $value.Value -eq -1 -or $value.Value -ge 1
                                if ($value.Value -eq -1) {
                                    $semantic = 'NeverExpires'
                                    $pass = [bool](Get-ADAnalyzerPolicyProfileValue $Profile AllowPasswordNeverExpires $false)
                                }
                                else {
                                    $pass = $value.Value -le [long]$expected
                                }
                            }
                            'Threshold' {
                                if ($value.Value -eq 0) {
                                    $semantic = 'LockoutDisabled'
                                    $pass = [long]$expected -eq 0
                                }
                                else {
                                    $pass = [long]$expected -gt 0 -and $value.Value -le [long]$expected
                                }
                            }
                            'Duration' {
                                $valid = $value.Value -eq -1 -or $value.Value -ge 1
                                if ($value.Value -eq -1) {
                                    $semantic = 'AdministratorUnlockRequired'
                                    $pass = $true
                                }
                                else {
                                    $pass = $value.Value -ge [long]$expected
                                }
                            }
                        }
                    }
                }
                $status = if (-not $valid) {
                    'Invalid'
                }
                elseif ($pass) {
                    'Pass'
                }
                else {
                    'Fail'
                }
                $this.Emit($state, @{
                    RuleId = ('GPO.Account.' + $rule[0])
                    Status = $status
                    Severity = 'High'
                    Category = 'AccountPolicy'
                    Target = ($target + '/' + $row.Scope + '/' + $row.Source + '/Account/' + $rule[0])
                    Observed = $row.Value
                    Expected = $expected
                    Evidence = @{
                        Scope = $row.Scope
                        Path = $row.Source
                        Semantic = $semantic
                    }
                    Message = 'Stored account policy was compared with the profile. Applicability and inheritance remain separate.'
                    Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $row.Scope $Profile)
                })
            }
        }
    }

    hidden [void] EvaluateSecurity([hashtable]$state) {
        $Gpo = $state.Gpo
        $Policy = $state.Policy
        $Profile = $state.Profile
        $target = $state.Target
        $registry = @(Get-ADAnalyzerEffectiveRegistryRecords $Policy.RegistrySettings)
        $state.Registry = $registry
        foreach ($spec in @(Get-ADAnalyzerSecuritySpecifications $Profile)) {
            $rows = @()
            foreach ($raw in @($registry | Where-Object { $_.Hive -ieq 'HKLM' -and
                        $_.Key -ieq $spec.Key -and
                        $_.ValueName -ieq $spec.ValueName })) {
                $rows += [pscustomobject]@{
                    Scope = $raw.Scope
                    Source = $raw.Source
                    Value = $raw.Value
                    Type = $raw.Type
                    Raw = $true
                    Deleted = $raw.Deleted
                }
            }
            foreach ($setting in @($Policy.SecuritySettings | Where-Object { $_.Kind -eq 'SecurityOptions' -and $_.Name -eq $spec.Name })) {
                $type = $null
                $rawValue = $setting.Value
                $raw = $false
                foreach ($ini in @($Policy.IniSettings | Where-Object { $_.Section -eq 'Registry Values' -and
                            $_.Scope -eq $setting.Scope -and
                            $_.Source -eq $setting.Source -and
                            ($_.Name -replace '^(?i)MACHINE\\',
                            '') -ieq ($spec.Key + '\' + $spec.ValueName) })) {
                    try {
                        $parts = Split-AnalyzerPolicyCsv $ini.Value
                        $type = [int]$parts[0]
                        $rawValue = if ($type -eq 7) {
                            , $parts[1..($parts.Count - 1)]
                        }
                        else {
                            $parts[1..($parts.Count - 1)] -join ','
                        }
                        $raw = $true
                    }
                    catch {
                        $type = -1
                    }
                }
                $rows += [pscustomobject]@{
                    Scope = $setting.Scope
                    Source = $setting.Source
                    Value = $rawValue
                    Type = $type
                    Raw = $raw
                    Deleted = $false
                    ValueValid = (Get-ADAnalyzerPolicyValue $setting ValueValid $null)
                }
            }
            if (-not $rows.Count) {
                $this.Emit($state, @{
                    RuleId = ('GPO.Security.' + $spec.Id)
                    Status = 'NotConfigured'
                    Severity = 'High'
                    Category = 'SecurityOptions'
                    Target = ($target + '/Security/' + $spec.Id)
                    Observed = $null
                    Expected = $spec.Expected
                    Evidence = @{
                        Name = $spec.Name
                    }
                    Message = 'This GPO does not configure this supported baseline setting.'
                    Applicability = 'Unknown'
                })
                continue
            }
            $sourceTargets = @(foreach ($row in $rows) {
                    $target + '/' + $row.Scope + '/' + ([string]$row.Source).Replace('\', '/') + '/Security/' + $spec.Id
                })
            $rowTargets = @(Resolve-ADAnalyzerPolicyIdentityCollisions -Targets $sourceTargets)
            $rowIndex = 0
            foreach ($row in $rows) {
                $checkTarget = $rowTargets[$rowIndex]
                $rowIndex++
                $status = 'Unknown'
                $valid = $true
                $pass = $false
                $observed = $row.Value
                if (-not (Test-ADAnalyzerPolicyValueValid $row)) {
                    $status = 'Invalid'
                }
                elseif ($row.Deleted) {
                    $status = 'NotConfigured'
                }
                elseif ($null -ne $row.Type -and $null -ne $spec.Type -and $row.Type -ne $spec.Type) {
                    $status = 'Invalid'
                }
                else {
                    if ($spec.Kind -eq 'Boolean') {
                        $value = ConvertTo-ADAnalyzerPolicyBoolean $row.Value
                        $valid = $value.Valid
                        $pass = $value.Value -eq $spec.Expected
                    }
                    elseif ($spec.Kind -in 'Pipes', 'Shares') {
                        $values = @($row.Value | Where-Object { -not [string]::IsNullOrEmpty([string]$_) })
                        $pass = @($values | Where-Object { @($spec.Expected) -notcontains $_ }).Count -eq 0
                    }
                    else {
                        $number = ConvertTo-ADAnalyzerPolicyNumber $row.Value
                        if ($row.Raw) {
                            $max = if ($spec.Kind -eq 'Lm' -or $spec.Kind -eq 'UacPrompt') {
                                5
                            }
                            else {
                                2
                            }
                            $valid = $number.Valid -and $number.Value -ge 0 -and $number.Value -le $max
                            if ($valid) {
                                switch ($spec.Kind) {
                                    'Lm' {
                                        $pass = $number.Value -ge [long]$spec.Expected
                                    }
                                    'LdapClient' {
                                        $pass = $spec.Expected -ne 2 -or $number.Value -eq 2
                                    }
                                    'LdapServer' {
                                        $valid = $number.Value -in 0, 1, 2
                                        $pass = $spec.Expected -ne 2 -or $number.Value -eq 2
                                    }
                                    'UacPrompt' {
                                        $pass = $number.Value -gt 0
                                    }
                                }
                            }
                        }
                        else {
                            switch ($spec.Kind) {
                                'Lm' {
                                    $levels = @('Send LM & NTLM responses',
                                        'Send LM & NTLM - use NTLMv2 session security if negotiated',
                                        'Send NTLM response only',
                                        'Send NTLMv2 response only',
                                        'Send NTLMv2 response only. Refuse LM',
                                        'Send NTLMv2 response only. Refuse LM & NTLM')
                                    $index = [array]::IndexOf($levels, [string]$row.Value)
                                    if ([string]$row.Value -eq 'Send NTLMv2 responses only. Refuse LM & NTLM') {
                                        $index = 5
                                    }
                                    $valid = $index -ge 0
                                    $pass = $index -ge [long]$spec.Expected
                                }
                                'LdapClient' {
                                    $valid = $row.Value -in 'None', 'Negotiate signing', 'Require signing'
                                    $pass = $spec.Expected -ne 2 -or $row.Value -eq 'Require signing'
                                }
                                'LdapServer' {
                                    $valid = $row.Value -in 'None', 'Require signature', 'Require signing'
                                    $pass = $spec.Expected -ne 2 -or $row.Value -in 'Require signature', 'Require signing'
                                }
                                'UacPrompt' {
                                    $valid = $row.Value -in 'Elevate without prompting',
                                    'Prompt for credentials on the secure desktop',
                                    'Prompt for consent on the secure desktop',
                                    'Prompt for credentials',
                                    'Prompt for consent',
                                    'Prompt for consent for non-Windows binaries'
                                    $pass = $valid -and $row.Value -ne 'Elevate without prompting'
                                }
                            }
                        }
                    }
                    $status = if (-not $valid) {
                        'Invalid'
                    }
                    elseif ($pass) {
                        'Pass'
                    }
                    else {
                        'Fail'
                    }
                }
                $this.Emit($state, @{
                    RuleId = ('GPO.Security.' + $spec.Id)
                    Status = $status
                    Severity = 'High'
                    Category = 'SecurityOptions'
                    Target = $checkTarget
                    Observed = $observed
                    Expected = $spec.Expected
                    Evidence = @{
                        Name = $spec.Name
                        RegistryType = $row.Type
                        Path = $row.Source
                        Deleted = $row.Deleted
                    }
                    Message = 'Stored security policy was validated and compared with the profile; this is not a calculation of effective policy.'
                    Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $row.Scope $Profile)
                })
            }
        }
    }

    hidden [void] EvaluateMembershipAndRights([hashtable]$state) {
        $Gpo = $state.Gpo
        $Policy = $state.Policy
        $Profile = $state.Profile
        $target = $state.Target
        $policySection = Get-ADAnalyzerPolicyValue $Profile Policy @{}
        $approvedValue = @('S-1-5-32-544')
        if ($policySection -is [Collections.IDictionary] -and
            ([Collections.IDictionary]$policySection).Contains('ApprovedLocalAdminSids')) {
            $approvedValue = $policySection['ApprovedLocalAdminSids']
        }
        elseif ($null -ne $policySection -and $null -ne $policySection.PSObject.Properties['ApprovedLocalAdminSids']) {
            $approvedValue = $policySection.PSObject.Properties['ApprovedLocalAdminSids'].Value
        }
        $approvedValid = Test-ADAnalyzerPolicySidList $approvedValue
        $approved = @($approvedValue)
        $restricted = @(ConvertFrom-ADAnalyzerRestrictedGroups $Policy.IniSettings)
        foreach ($group in $restricted) {
            $candidates = @()
            $privileged = $group.GroupSid -eq 'S-1-5-32-544' -or $group.GroupName -ieq 'Administrators'
            if ($group.Mode -ieq 'Memberof') {
                $privileged = @($group.Members | Where-Object { $_.Sid -eq 'S-1-5-32-544' -or $_.Name -ieq 'Administrators' }).Count -gt 0
                $candidates = @([pscustomobject]@{
                        Sid = $group.GroupSid
                        Name = $group.GroupName
                    })
            }
            else {
                $candidates = @($group.Members)
            }
            $unknown = @($candidates | Where-Object { -not $_.Sid }).Count -gt 0
            $bad = @($candidates | Where-Object { $_.Sid -and $approved -notcontains $_.Sid })
            $status = if (-not $group.Valid -or -not $approvedValid) {
                'Invalid'
            }
            elseif (-not $privileged) {
                'NotApplicable'
            }
            elseif ($bad.Count) {
                'Fail'
            }
            elseif ($unknown) {
                'Unknown'
            }
            else {
                'Pass'
            }
            $this.Emit($state, @{
                RuleId = 'GPO.RestrictedGroups.LocalAdministrators'
                Status = $status
                Severity = 'High'
                Category = 'RestrictedGroups'
                Target = ($target + '/' + $group.Scope + '/' + $group.Source + '/' + $group.SettingName)
                Observed = $group
                Expected = $approved
                Evidence = @{
                    Path = $group.Source
                    Mode = $group.Mode
                }
                Message = 'Members replaces the configured membership; MemberOf requires inclusion. Names without a SID cannot be approved by the SID allowlist.'
                Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $group.Scope $Profile)
            })
        }
        if (-not $restricted.Count) {
            $this.Emit($state, @{
                RuleId = 'GPO.RestrictedGroups.LocalAdministrators'
                Status = 'NotConfigured'
                Severity = 'High'
                Category = 'RestrictedGroups'
                Target = ($target + '/RestrictedGroups')
                Observed = $null
                Expected = $approved
                Evidence = $null
                Message = 'No Restricted Groups configuration was found in this GPO.'
                Applicability = 'Unknown'
            })
        }
        $local = @(ConvertFrom-ADAnalyzerLocalUsersGroups $Policy.XmlFiles)
        $itemIdentities = @(foreach ($item in $local) {
                $kind = if ($item.Uid) {
                    'Uid'
                }
                else {
                    'Path'
                }
                $identity = if ($item.Uid) {
                    $item.Uid
                }
                else {
                    $item.ItemPath
                }
                $target + '/LocalUsersGroups/' + (Join-ADAnalyzerPolicyIdentity `
                        -Parts @($item.Scope,
                        ([string]$item.Source).Replace('\',
                            '/'),
                        $kind,
                        $identity))
            })
        $itemTargets = @(Resolve-ADAnalyzerPolicyIdentityCollisions -Targets $itemIdentities)
        $itemIndex = 0
        foreach ($item in $local) {
            $checkTarget = $itemTargets[$itemIndex]
            $itemIndex++
            $privileged = $item.Sid -eq 'S-1-5-32-544' -or $item.Name -ieq 'Administrators'
            $additions = @($item.Members | Where-Object Action -eq 'ADD')
            $unknown = @($additions | Where-Object { -not $_.Sid }).Count -gt 0
            $bad = @($additions | Where-Object { $_.Sid -and $approved -notcontains $_.Sid })
            $status = if (-not $item.Valid -or -not $approvedValid) {
                'Invalid'
            }
            elseif ($item.Disabled -or $item.Action -eq 'D') {
                'NotApplicable'
            }
            elseif ($item.Kind -ne 'Group' -or -not $privileged) {
                'Unknown'
            }
            elseif ($bad.Count) {
                'Fail'
            }
            elseif ($unknown) {
                'Unknown'
            }
            else {
                'Pass'
            }
            $this.Emit($state, @{
                RuleId = 'GPO.Preferences.LocalUsersGroups'
                Status = $status
                Severity = 'High'
                Category = 'LocalUsersGroups'
                Target = $checkTarget
                Observed = $item
                Expected = $approved
                Evidence = @{
                    Path = $item.Source
                    Targeting = $item.Targeted
                    Disabled = $item.Disabled
                    Action = $item.Action
                }
                Message = 'Preference actions and member additions/removals are preserved. Targeting filters have not been evaluated, and an update is not a complete effective membership inventory.'
                Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $item.Scope $Profile `
                        -Targeted:$item.Targeted `
                        -Disabled:$item.Disabled)
            })
        }
        if (-not $local.Count) {
            $this.Emit($state, @{
                RuleId = 'GPO.Preferences.LocalUsersGroups'
                Status = 'NotConfigured'
                Severity = 'High'
                Category = 'LocalUsersGroups'
                Target = ($target + '/LocalUsersGroups')
                Observed = $null
                Expected = $approved
                Evidence = $null
                Message = 'No Local Users and Groups preference was found in this GPO.'
                Applicability = 'Unknown'
            })
        }

        $rights = Get-ADAnalyzerPolicyProfileValue $Profile AllowedUserRightSids @{}
        foreach ($right in @($Policy.SecuritySettings | Where-Object Kind -eq 'UserRightsAssignment')) {
            $principals = @($right.Value | ForEach-Object { ConvertFrom-ADAnalyzerPolicyPrincipal ([string]$_) })
            $hasAllowlist = $rights -is [Collections.IDictionary] -and
                ([Collections.IDictionary]$rights).Contains($right.Name)
            $expected = $null
            $allowlistValid = $false
            if ($hasAllowlist) {
                $allowlistValid = Test-ADAnalyzerPolicySidList $rights[$right.Name]
                $expected = @($rights[$right.Name])
            }
            $status = if (@($principals | Where-Object { -not $_.Valid }).Count -or ($hasAllowlist -and -not $allowlistValid)) {
                'Invalid'
            }
            elseif (-not $hasAllowlist -or @($principals | Where-Object { -not $_.Sid }).Count) {
                'Unknown'
            }
            elseif (@($principals | Where-Object { @($expected) -notcontains $_.Sid }).Count) {
                'Fail'
            }
            else {
                'Pass'
            }
            $this.Emit($state, @{
                RuleId = ('GPO.UserRights.' + $right.Name)
                Status = $status
                Severity = 'High'
                Category = 'UserRightsAssignment'
                Target = ($target + '/' + $right.Scope + '/' + $right.Source + '/' + $right.Name)
                Observed = $principals
                Expected = $expected
                Evidence = @{
                    Path = $right.Source
                    Right = $right.Name
                }
                Message = 'User rights are compared with exact approved SIDs, never principal-name substrings. An unspecified allowlist is Unknown.'
                Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $right.Scope $Profile)
            })
        }
        if ($rights -is [Collections.IDictionary]) {
            foreach ($name in ([Collections.IDictionary].GetProperty('Keys')).GetValue($rights, $null)) {
                if (-not @($Policy.SecuritySettings | Where-Object { $_.Kind -eq 'UserRightsAssignment' -and $_.Name -eq $name }).Count) {
                    $this.Emit($state, @{
                        RuleId = ('GPO.UserRights.' + $name)
                        Status = 'NotConfigured'
                        Severity = 'High'
                        Category = 'UserRightsAssignment'
                        Target = ($target + '/UserRights/' + $name)
                        Observed = $null
                        Expected = $rights[$name]
                        Evidence = $null
                        Message = 'This configured baseline right is absent from this GPO.'
                        Applicability = 'Unknown'
                    })
                }
            }
        }
    }

    hidden [hashtable] RecordAggregateRegistrySelector([object]$Sample) {
        # The replayed row identifies the actual selection without reading the rule again.
        $hive = $Sample.Hive
        $key = $Sample.Key
        $name = $Sample.ValueName
        $path = $Sample.Source
        $scope = $Sample.Scope
        if ($key -isnot [string] -or $key.Length -eq 0 -or $name -isnot [string] -or
            $hive -isnot [string] -or $path -isnot [string] -or $scope -isnot [string] -or
            -not (($scope -eq 'Computer' -and $path -eq 'Machine/Registry.pol' -and $hive -eq 'HKLM') -or
                ($scope -eq 'User' -and $path -eq 'User/Registry.pol' -and $hive -eq 'HKCU'))) {
            return $null
        }

        # Keep these literal strings outside the JSON reader's date coercion.
        $recordedKey = ':' + $key
        $recordedName = ':' + $name
        $secretType = 'ADAnalyzerSecretIndicator' -as [type]
        $secretIndicator = $secretType::new()
        try {
            if ($secretIndicator.ProjectText($key) -cne $key -or $secretIndicator.ProjectText($name) -cne $name -or
                $secretIndicator.ProjectText($recordedKey) -cne $recordedKey -or
                $secretIndicator.ProjectText($recordedName) -cne $recordedName) {
                return $null
            }
        }
        catch [IO.InvalidDataException] {
            return $null
        }
        return @{
            Hive = $hive
            Key = $recordedKey
            ValueName = $recordedName
        }
    }

    hidden [void] EvaluateCustomBaseline([hashtable]$state) {
        $Gpo = $state.Gpo
        $Policy = $state.Policy
        $Profile = $state.Profile
        $target = $state.Target
        $registry = $state.Registry
        foreach ($rule in @(Get-ADAnalyzerPolicyValue $Profile RegistryRules @()) + @(Get-ADAnalyzerPolicyValue $Profile ExpectedGpoSettings @())) {
            $kind = Get-ADAnalyzerPolicyValue $rule Kind 'Registry'
            $name = Get-ADAnalyzerPolicyValue $rule Name ''
            $id = Get-ADAnalyzerPolicyValue $rule RuleId (Get-ADAnalyzerPolicyValue $rule Id ($kind + '.' + $name + '.' + $rule.Key + '.' + $rule.ValueName))
            $severity = Get-ADAnalyzerPolicyValue $rule Severity 'Medium'
            $expected = $rule.Expected
            $operator = Get-ADAnalyzerPolicyValue $rule Operator 'Equals'
            $matches = @(if ($kind -eq 'Registry') {
                    $registry | Where-Object { $_.Hive -ieq (Get-ADAnalyzerPolicyValue $rule Hive 'HKLM') -and
                        $_.Key -ieq $rule.Key -and
                        $_.ValueName -ieq $rule.ValueName -and
                        -not $_.Deleted }
                }
                else {
                    $Policy.SecuritySettings | Where-Object { $_.Kind -eq $kind -and $_.Name -eq $name }
                })
            $scope = Get-ADAnalyzerPolicyValue $rule Scope ''
            if ($scope) {
                $matches = @($matches | Where-Object { $_.Scope -ieq $scope })
            }
            if (-not $matches.Count) {
                $this.Emit($state, @{
                    RuleId = ('GPO.Expected.' + $id)
                    Status = 'NotConfigured'
                    Severity = $severity
                    Category = 'PolicyBaseline'
                    Target = ($target + '/Expected/' + $id + '/' + $scope)
                    Observed = $null
                    Expected = $expected
                    Evidence = @{
                        Kind = $kind
                        Name = $name
                        Scope = $scope
                    }
                    Message = 'The expected setting is not configured in the requested GPO scope; effective policy remains unknown.'
                    Applicability = 'Unknown'
                })
                continue
            }
            $expectedType = Get-ADAnalyzerPolicyValue $rule Type $null
            $typeAliases = @{
                REG_NONE = 0
                REG_SZ = 1
                REG_EXPAND_SZ = 2
                REG_BINARY = 3
                REG_DWORD = 4
                REG_DWORD_BIG_ENDIAN = 5
                REG_MULTI_SZ = 7
                REG_QWORD = 11
            }
            if ($null -ne $expectedType -and $typeAliases.ContainsKey([string]$expectedType)) {
                $expectedType = $typeAliases[[string]$expectedType]
            }
            if (Get-ADAnalyzerPolicyValue $rule Aggregate $false) {
                foreach ($group in @($matches | Group-Object Scope, Source)) {
                    $sample = $group.Group[0]
                    $observed = @($group.Group | ForEach-Object { $_.Value })
                    $checkTarget = $target + '/Expected/' + $id + '/Aggregate/' + $sample.Scope + '/' + ([string]$sample.Source).Replace('\',
                        '/')
                    try {
                        if (@($group.Group | Where-Object { -not (Test-ADAnalyzerPolicyValueValid $_) }).Count) {
                            throw 'The stored value is invalid'
                        }
                        if ($kind -eq 'Registry' -and $null -ne $expectedType) {
                            $declared = ConvertTo-ADAnalyzerPolicyNumber $expectedType
                            foreach ($record in $group.Group) {
                                $actual = ConvertTo-ADAnalyzerPolicyNumber $record.Type
                                if (-not $declared.Valid -or -not $actual.Valid -or $declared.Value -ne $actual.Value) {
                                    throw 'The registry data type does not match the baseline'
                                }
                            }
                        }
                        $status = if (Test-ADAnalyzerPolicyComparison $observed $expected $operator) {
                            'Pass'
                        }
                        else {
                            'Fail'
                        }
                    }
                    catch {
                        $status = 'Invalid'
                    }
                    $evidence = @{
                        Path = $sample.Source
                        Scope = $sample.Scope
                        Operator = $operator
                        Aggregate = $true
                        ExpectedRegistryType = $expectedType
                    }
                    if ($kind -eq 'Registry') {
                        $selector = $this.RecordAggregateRegistrySelector($sample)
                        if ($null -ne $selector) {
                            $evidence.RegistrySelector = $selector
                        }
                    }
                    $this.Emit($state, @{
                        RuleId = ('GPO.Expected.' + $id)
                        Status = $status
                        Severity = $severity
                        Category = 'PolicyBaseline'
                        Target = $checkTarget
                        Observed = $observed
                        Expected = $expected
                        Evidence = $evidence
                        Message = 'The complete configured value collection was compared as a set within its source and scope.'
                        Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $sample.Scope $Profile)
                    })
                }
                continue
            }
            $identities = @{}
            $occurrences = @{}
            foreach ($row in $matches) {
                $settingIdentity = if ($kind -eq 'Registry') {
                    [string]$row.Hive + '/' + $row.Key + '/' + $row.ValueName
                }
                else {
                    $kind + '/' + $row.Name
                }
                $rowIdentity = ([string]$row.Source).Replace('\', '/') + '/' + $row.Scope + '/' + $settingIdentity
                if (-not $identities.ContainsKey($rowIdentity)) {
                    $identities[$rowIdentity] = 0
                }
                $identities[$rowIdentity]++
            }
            foreach ($row in $matches) {
                $settingIdentity = if ($kind -eq 'Registry') {
                    [string]$row.Hive + '/' + $row.Key + '/' + $row.ValueName
                }
                else {
                    $kind + '/' + $row.Name
                }
                $rowIdentity = ([string]$row.Source).Replace('\', '/') + '/' + $row.Scope + '/' + $settingIdentity
                if (-not $occurrences.ContainsKey($rowIdentity)) {
                    $occurrences[$rowIdentity] = 0
                }
                $occurrences[$rowIdentity]++
                $checkTarget = $target + '/Expected/' + $id + '/' + $rowIdentity
                if ($identities[$rowIdentity] -gt 1) {
                    $checkTarget += '/duplicate/' + $occurrences[$rowIdentity]
                }
                try {
                    if (-not (Test-ADAnalyzerPolicyValueValid $row)) {
                        throw 'The stored value is invalid'
                    }
                    if ($kind -eq 'Registry' -and $null -ne $expectedType) {
                        $declared = ConvertTo-ADAnalyzerPolicyNumber $expectedType
                        $actual = ConvertTo-ADAnalyzerPolicyNumber $row.Type
                        if (-not $declared.Valid -or -not $actual.Valid -or $declared.Value -ne $actual.Value) {
                            throw 'The registry data type does not match the baseline'
                        }
                    }
                    $pass = Test-ADAnalyzerPolicyComparison $row.Value $expected $operator
                    $status = if ($pass) {
                        'Pass'
                    }
                    else {
                        'Fail'
                    }
                }
                catch {
                    $status = 'Invalid'
                }
                $this.Emit($state, @{
                    RuleId = ('GPO.Expected.' + $id)
                    Status = $status
                    Severity = $severity
                    Category = 'PolicyBaseline'
                    Target = $checkTarget
                    Observed = $row.Value
                    Expected = $expected
                    Evidence = @{
                        Path = $row.Source
                        Scope = $row.Scope
                        Operator = $operator
                        RegistryType = $row.Type
                        ExpectedRegistryType = $expectedType
                    }
                    Message = 'Stored setting scope, registry type when specified, and value were assessed against the configured baseline rule.'
                    Applicability = (Get-ADAnalyzerPolicyApplicability $Gpo $row.Scope $Profile)
                })
            }
        }
    }

    hidden [void] EvaluateCoverage([hashtable]$state) {
        $Gpo = $state.Gpo
        $Policy = $state.Policy
        $Profile = $state.Profile
        $target = $state.Target
        $unsupportedInf = @($Policy.IniSettings | Where-Object {
                $_.Analyzed -is [bool] -and -not $_.Analyzed -and $_.Section -in 'System Access', 'Kerberos Policy' -and
                (Test-ADAnalyzerSecurityTemplateSource -Scope $_.Scope -Source $_.Source)
            })
        if ($unsupportedInf.Count) {
            $this.Emit($state, @{
                RuleId = 'GPO.Coverage.UnsupportedInfSettings'
                Status = 'Unknown'
                Severity = 'Information'
                Category = 'PolicyCoverage'
                Target = ($target + '/UnsupportedInfSettings')
                Observed = @($unsupportedInf | Select-Object Scope,
                    Source,
                    Section,
                    Name)
                Expected = 'Known setting in its authoritative section'
                Evidence = $null
                Message = 'Unknown or misplaced account-template entries remain inventoried; their policy behavior was not assessed.'
                Applicability = 'Unknown'
            })
        }
        if (@($Policy.UnparsedFiles).Count) {
            $this.Emit($state, @{
                RuleId = 'GPO.Coverage.UnsupportedFiles'
                Status = 'Unknown'
                Severity = 'Information'
                Category = 'PolicyCoverage'
                Target = ($target + '/UnsupportedFiles')
                Observed = @($Policy.UnparsedFiles | Select-Object Scope,
                    Path,
                    Kind)
                Expected = 'Supported parsed content'
                Evidence = $null
                Message = 'Unsupported files remain inventoried; their policy behavior was not assessed.'
                Applicability = 'Unknown'
            })
        }
    }
}

function Test-ADAnalyzerGpoPolicy {
    <# .SYNOPSIS Assesses stored GPO content without querying a domain or calculating RSoP.
       .DESCRIPTION RegistryRules entries use Id, Hive, Key, ValueName, Operator, Expected and Severity.
       ExpectedGpoSettings use Kind (Account/SecurityOptions/Registry), Name, Operator and Expected.
       Unknown applicability is preserved; a configured-risk finding is not proof that a target applies it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Gpo,
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][hashtable]$Profile

    )
    $evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
    $preference = if ($PSBoundParameters.ContainsKey('ErrorAction')) {
        $PSBoundParameters.ErrorAction
    }
    else {
        $ErrorActionPreference
    }
    $evaluator.EvaluateForCommand($Gpo, $Policy, $Profile, $PSCmdlet, $preference)
}

class ADAnalyzerAdmxResolver {
    ADAnalyzerAdmxResolver() {
    }

    [pscustomobject] ReadValue([Xml.XmlNode]$Node) {
        if (-not $Node) {
            return [pscustomobject]@{
                Valid = $false
                Value = $null
                Deleted = $false
            }
        }
        $value = $Node.SelectSingleNode('./*[1]')
        if (-not $value) {
            return [pscustomobject]@{
                Valid = $false
                Value = $null
                Deleted = $false
            }
        }
        switch ($value.PSBase.LocalName) {
            'decimal' {
                $n = (New-ADAnalyzerPolicyValueSemantics).ParseNumber((Get-ADAnalyzerXmlAttribute $value value))
                return [pscustomobject]@{
                    Valid = $n.Valid
                    Value = $n.Value
                    Deleted = $false
                }
            }
            'longDecimal' {
                $n = (New-ADAnalyzerPolicyValueSemantics).ParseNumber((Get-ADAnalyzerXmlAttribute $value value))
                return [pscustomobject]@{
                    Valid = $n.Valid
                    Value = $n.Value
                    Deleted = $false
                }
            }
            'string' {
                return [pscustomobject]@{
                    Valid = $true
                    Value = $value.PSBase.InnerText
                    Deleted = $false
                }
            }
            'delete' {
                return [pscustomobject]@{
                    Valid = $true
                    Value = $null
                    Deleted = $true
                }
            }
        }
        return [pscustomobject]@{
            Valid = $false
            Value = $null
            Deleted = $false
        }
    }

    [object[]] Resolve([object[]]$RegistrySettings) {
        return $this.Resolve($RegistrySettings, '', 'en-US')
    }

    [object[]] Resolve([object[]]$RegistrySettings, [string]$TemplatePath) {
        return $this.Resolve($RegistrySettings, $TemplatePath, 'en-US')
    }

    [object[]] Resolve([object[]]$RegistrySettings, [string]$TemplatePath, [string]$Language) {
        if ($null -eq $RegistrySettings -or $RegistrySettings -contains $null) {
            throw [ArgumentException]::new('Registry records must be supplied and cannot contain null entries.', 'RegistrySettings')
        }

        $catalogue = $this.LoadCatalogue($TemplatePath, $Language)
        $results = [Collections.Generic.List[object]]::new()
        foreach ($row in $RegistrySettings) {
            $selection = $this.SelectResolution(@{
                    Record = $row
                }, $catalogue)
            if ($null -ne $selection.PresenceRecord) {
                $results.Add($selection.PresenceRecord)
                continue
            }

            $results.Add($this.BuildRecord(@{
                Scope = $row.Scope
                Hive = $row.Hive
                Key = $row.Key
                ValueName = $row.ValueName
                Type = $row.Type
                Value = $row.Value
                RawData = $(if (Test-ADAnalyzerAdmxOptionalField $row RawData) {
                    , $row.RawData
                }
                else {
                    $null
                })
                Source = $row.Source
                KeyOnly = $(if (Test-ADAnalyzerAdmxOptionalField $row KeyOnly) {
                    , $row.KeyOnly
                }
                else {
                    $null
                })
                DeletionDirective = $(if (Test-ADAnalyzerAdmxOptionalField $row DeletionDirective) {
                    , $row.DeletionDirective
                }
                else {
                    $null
                })
                Deleted = $(if (Test-ADAnalyzerAdmxOptionalField $row Deleted) {
                    , $row.Deleted
                }
                else {
                    $null
                })
            }, $selection))
        }
        return $results.ToArray()
    }

    hidden [hashtable] LoadCatalogue([string]$TemplatePath, [string]$Language) {
        $templateMissing = -not $TemplatePath -or -not (Test-Path -LiteralPath $TemplatePath -PathType Container)
        $files = @()
        if (-not $templateMissing) {
            $files = @(Get-ChildItem -LiteralPath $TemplatePath -Filter '*.admx' -File -ErrorAction Stop)
        }
        return $this.BuildCatalogue($TemplatePath, $Language, $templateMissing, $files)
    }

    hidden [hashtable] BuildCatalogue(
        [string]$TemplatePath,
        [string]$Language,
        [bool]$TemplateMissing,
        [object[]]$Files
    ) {
        $definitions = @()
        $errors = @()
        $unresolvedDefinition = @{
            Common = @{
                PolicyId = $null
                PolicyNamespace = $null
                DisplayName = $null
            }
            Kind = $null
            ElementId = $null
        }
        if (-not $TemplateMissing) {
            foreach ($file in $Files) {
                try {
                    $xml = Read-AnalyzerPolicyXml $file.FullName
                    $resources = @{}
                    $resourceFileMissing = $false
                    $resourcePath = Join-Path (Join-Path $TemplatePath $Language) ($file.BaseName + '.adml')
                    if (Test-Path -LiteralPath $resourcePath -PathType Leaf) {
                        $adml = Read-AnalyzerPolicyXml $resourcePath
                        foreach ($resource in @($adml.SelectNodes('//*[local-name()="stringTable"]/*[local-name()="string"]'))) {
                            $resources[(Get-ADAnalyzerXmlAttribute $resource id)] = $resource.PSBase.InnerText
                        }
                    }
                    else {
                        $resourceFileMissing = $true
                    }
                    $namespace = Get-ADAnalyzerXmlAttribute ($xml.SelectSingleNode('//*[local-name()="policyNamespaces"]/*[local-name()="target"]')) namespace
                    foreach ($policy in @($xml.SelectNodes('//*[local-name()="policies"]/*[local-name()="policy"]'))) {
                        $languageMissing = $resourceFileMissing
                        $key = Get-ADAnalyzerXmlAttribute $policy key
                        $valueName = Get-ADAnalyzerXmlAttribute $policy valueName
                        $name = Get-ADAnalyzerXmlAttribute $policy name
                        $display = Get-ADAnalyzerXmlAttribute $policy displayName
                        if ($display -match '^\$\(string\.(.+)\)$') {
                            if ($resources.ContainsKey($Matches[1])) {
                                $display = $resources[$Matches[1]]
                            }
                            else {
                                $languageMissing = $true
                                $display = $name
                            }
                        }
                        $common = @{
                            PolicyId = $name
                            PolicyNamespace = $namespace
                            DisplayName = $display
                            Class = (Get-ADAnalyzerXmlAttribute $policy class)
                            Template = $file.Name
                            LanguageMissing = $languageMissing
                            Resources = $resources
                        }
                        if ($valueName) {
                            $definitions += [pscustomobject]@{
                                Common = $common
                                Kind = 'Policy'
                                Key = $key
                                ValueName = $valueName
                                ElementId = $null
                                Node = $policy
                            }
                        }
                        foreach ($element in @($policy.SelectNodes('./*[local-name()="elements"]/*'))) {
                            $elementKey = Get-ADAnalyzerXmlAttribute $element key $key
                            $elementName = Get-ADAnalyzerXmlAttribute $element valueName
                            $definitions += [pscustomobject]@{
                                Common = $common
                                Kind = $element.PSBase.LocalName
                                Key = $elementKey
                                ValueName = $elementName
                                ElementId = (Get-ADAnalyzerXmlAttribute $element id)
                                Node = $element
                            }
                        }
                        foreach ($list in @($policy.SelectNodes('./*[local-name()="enabledList" or local-name()="disabledList"]'))) {
                            foreach ($item in @($list.SelectNodes('./*[local-name()="item"]'))) {
                                $definitions += [pscustomobject]@{
                                    Common = $common
                                    Kind = 'PolicyValueList'
                                    Key = (Get-ADAnalyzerXmlAttribute $item key $key)
                                    ValueName = (Get-ADAnalyzerXmlAttribute $item valueName)
                                    ElementId = $null
                                    Node = $item
                                }
                            }
                        }
                    }
                }
                catch {
                    $errors += $file.Name
                }
            }
        }
        return @{
            Definitions = $definitions
            Errors = $errors
            TemplateMissing = $TemplateMissing
            UnresolvedDefinition = $unresolvedDefinition
        }
    }

    hidden [hashtable] SelectResolution([hashtable]$InputFrame, [hashtable]$Catalogue) {
        $row = $InputFrame.Record
        $definitions = $Catalogue.Definitions
        $errors = $Catalogue.Errors
        $templateMissing = $Catalogue.TemplateMissing
        $unresolvedDefinition = $Catalogue.UnresolvedDefinition

        if (Test-ADAnalyzerSecretName $row.ValueName) {
            $safe = ConvertTo-ADAnalyzerSecretRecord $row
            $safe | Add-Member NoteProperty MetadataStatus 'PresenceOnly' -Force
            $safe | Add-Member NoteProperty State 'Unknown' -Force
            return @{
                PresenceRecord = $safe
            }
        }
        $class = if ($row.Hive -ieq 'HKCU') {
            'User'
        }
        else {
            'Machine'
        }
        $matches = @($definitions | Where-Object { $_.Common.Class -in $class,
                'Both' -and
                $_.Key -ieq $row.Key -and
                ($_.ValueName -ieq $row.ValueName -or
                ($_.Kind -eq 'list' -and
                ([string]$row.ValueName).StartsWith((Get-ADAnalyzerXmlAttribute $_.Node valuePrefix),
                    [StringComparison]::OrdinalIgnoreCase))) })
        $status = if ($templateMissing) {
            'TemplateNotFound'
        }
        elseif (-not $matches.Count -and $errors.Count) {
            'InvalidTemplate'
        }
        elseif (-not $matches.Count) {
            'NoMatch'
        }
        elseif ($matches.Count -gt 1) {
            'Ambiguous'
        }
        else {
            'Resolved'
        }
        $definition = $null
        $state = 'Unknown'
        $options = @()
        if ($matches.Count -eq 1) {
            $definition = $matches[0]
            if ($definition.Common.LanguageMissing) {
                $status = 'LanguageResourceMissing'
            }
            switch ($definition.Kind) {
                'Policy' {
                    foreach ($pair in @(@('enabledValue', 'Enabled'), @('disabledValue', 'Disabled'))) {
                        $value = $this.ReadValue($definition.Node.SelectSingleNode('./*[local-name()="' + $pair[0] + '"]'))
                        if ($value.Valid -and
                            (($value.Deleted -and
                                (Test-ADAnalyzerAdmxOptionalField $row Deleted) -and
                                $row.Deleted) -or
                            (-not $value.Deleted -and
                            $row.Value -eq $value.Value))) {
                            $state = $pair[1]
                        }
                    }
                }
                'boolean' {
                    foreach ($pair in @(@('trueValue', 'True'), @('falseValue', 'False'))) {
                        $value = $this.ReadValue($definition.Node.SelectSingleNode('./*[local-name()="' + $pair[0] + '"]'))
                        if ($value.Valid -and $row.Value -eq $value.Value) {
                            $state = $pair[1]
                        }
                    }
                }
                'enum' {
                    foreach ($item in @($definition.Node.SelectNodes('./*[local-name()="item"]'))) {
                        $value = $this.ReadValue($item.SelectSingleNode('./*[local-name()="value"]'))
                        $label = Get-ADAnalyzerXmlAttribute $item displayName
                        if ($label -match '^\$\(string\.(.+)\)$') {
                            if ($definition.Common.Resources.ContainsKey($Matches[1])) {
                                $label = $definition.Common.Resources[$Matches[1]]
                            }
                            else {
                                $status = 'LanguageResourceMissing'
                            }
                        }
                        $options += [pscustomobject]@{
                            Label = $label
                            Value = $value.Value
                        }
                        if ($value.Valid -and $row.Value -eq $value.Value) {
                            $state = 'Configured'
                        }
                    }
                }
                'list' {
                    $state = 'Configured'
                }
                'PolicyValueList' {
                    $state = 'Unknown'
                }
                default {
                    $status = 'UnsupportedDefinition'
                }
            }
        }
        $reportDefinition = $definition
        if ($null -eq $reportDefinition) {
            $reportDefinition = $unresolvedDefinition
        }
        return @{
            PresenceRecord = $null
            Status = $status
            State = $state
            Definition = $reportDefinition
            Options = $options
            Errors = $errors
        }
    }

    hidden [pscustomobject] BuildRecord([hashtable]$Raw, [hashtable]$Selection) {
        return [pscustomobject]@{
            Scope = $Raw.Scope
            Hive = $Raw.Hive
            Key = $Raw.Key
            ValueName = $Raw.ValueName
            Type = $Raw.Type
            Value = $Raw.Value
            RawData = $Raw.RawData
            Source = $Raw.Source
            KeyOnly = $Raw.KeyOnly
            DeletionDirective = $Raw.DeletionDirective
            Deleted = $Raw.Deleted
            MetadataStatus = $Selection.Status
            State = $Selection.State
            PolicyId = $Selection.Definition.Common.PolicyId
            PolicyNamespace = $Selection.Definition.Common.PolicyNamespace
            DisplayName = $Selection.Definition.Common.DisplayName
            DefinitionType = $Selection.Definition.Kind
            ElementId = $Selection.Definition.ElementId
            Options = $Selection.Options
            TemplateErrors = $Selection.Errors
        }
    }
}

function Get-ADAnalyzerAdmxValue {
    param([Xml.XmlNode]$Node)
    return [ADAnalyzerAdmxResolver]::new().ReadValue($Node)
}

function Test-ADAnalyzerAdmxOptionalField {
    param(
        $Record,
        [string]$Name
    )
    if ($Record -is [Collections.IDictionary]) {
        $type = $Record.GetType()
        $isGenericDictionary = $type.IsGenericType -and
            $type.GetGenericTypeDefinition() -eq [Collections.Generic.Dictionary[string, object]].GetGenericTypeDefinition()
        if ($type -notin [hashtable], [Collections.Specialized.OrderedDictionary] -and
            -not $isGenericDictionary) {
            # Let PowerShell perform the only lookup on custom dictionary implementations.
            return $true
        }
        if (([Collections.IDictionary]$Record).Contains($Name)) {
            return $true
        }
    }
    elseif ($Record -is [Collections.IEnumerable] -and $Record -isnot [string]) {
        # Let PowerShell enumerate members of collection-shaped records.
        return $true
    }
    return $null -ne $Record.PSObject.Properties[$Name]
}

function Resolve-ADAnalyzerRegistryPolicy {
    <# .SYNOPSIS Adds optional offline ADMX/ADML metadata while preserving raw policy records.
       .DESCRIPTION Supports policy enabled/disabled values and boolean, enum and list elements.
       Complex multi-key definitions retain explicit Unknown state; no template is required for parsing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistrySettings,
        [string]$TemplatePath,
        [string]$Language = 'en-US'

    )
    $resolver = [ADAnalyzerAdmxResolver]::new()
    $templateMissing = -not $TemplatePath -or -not (Test-Path -LiteralPath $TemplatePath -PathType Container)
    $files = @()
    if (-not $templateMissing) {
        $files = @(Get-ChildItem -LiteralPath $TemplatePath -Filter '*.admx' -File -ErrorAction Stop)
    }
    $catalogue = $null
    $catalogue = $resolver.BuildCatalogue($TemplatePath, $Language, $templateMissing, $files)
    if ($null -eq $catalogue) {
        return
    }

    foreach ($row in @($RegistrySettings)) {
        $selection = $null
        $selection = $resolver.SelectResolution(@{
                Record = $row
            }, $catalogue)
        if ($null -eq $selection) {
            continue
        }
        if ($null -ne $selection.PresenceRecord) {
            $selection.PresenceRecord
            continue
        }

        # Observe source properties in their original native row scope.
        $resolver.BuildRecord(@{
            Scope = $row.Scope
            Hive = $row.Hive
            Key = $row.Key
            ValueName = $row.ValueName
            Type = $row.Type
            Value = $row.Value
            RawData = $(if (Test-ADAnalyzerAdmxOptionalField $row RawData) {
                , $row.RawData
            }
            else {
                $null
            })
            Source = $row.Source
            KeyOnly = $(if (Test-ADAnalyzerAdmxOptionalField $row KeyOnly) {
                , $row.KeyOnly
            }
            else {
                $null
            })
            DeletionDirective = $(if (Test-ADAnalyzerAdmxOptionalField $row DeletionDirective) {
                , $row.DeletionDirective
            }
            else {
                $null
            })
            Deleted = $(if (Test-ADAnalyzerAdmxOptionalField $row Deleted) {
                , $row.Deleted
            }
            else {
                $null
            })
        }, $selection)
    }
}
