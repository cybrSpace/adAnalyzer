# Package-owned GPO collection. No GroupPolicy module or GPMC COM objects.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')

class ADAnalyzerGpoReader {
    ADAnalyzerGpoReader() {
    }

    hidden [void] ValidatePath([string]$Path) {
        if ([string]::IsNullOrEmpty($Path)) {
            throw 'Path is required.'
        }
    }

    hidden [Collections.Specialized.OrderedDictionary] ReadIni([string]$Path) {
        $this.ValidatePath($Path)
        $sections = [ordered]@{}
        $section = ''
        $reader = [IO.StreamReader]::new($Path, [Text.Encoding]::UTF8, $true)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                $line = $line.Trim()
                if (-not $line -or $line.StartsWith(';')) {
                    continue
                }
                if ($line -match '^\[(.+)\]$') {
                    $section = $Matches[1]
                    if (-not $sections.Contains($section)) {
                        $sections[$section] = [ordered]@{}
                    }
                    continue
                }
                $split = $line.IndexOf('=')
                if ($split -gt 0 -and $section) {
                    $sections[$section][$line.Substring(0, $split).Trim()] = $line.Substring($split + 1).Trim()
                }
            }
        }
        finally {
            $reader.Dispose()
        }
        return $sections
    }

    hidden [string[]] SplitCsv([string]$Value) {
        $items = [Collections.Generic.List[string]]::new()
        $part = [Text.StringBuilder]::new()
        $quoted = $false
        for ($i = 0; $i -lt $Value.Length; $i++) {
            $c = $Value[$i]
            if ($c -eq '"') {
                if ($quoted -and $i + 1 -lt $Value.Length -and $Value[$i + 1] -eq '"') {
                    $null = $part.Append('"')
                    $i++
                }
                else {
                    $quoted = -not $quoted
                }
            }
            elseif ($c -eq ',' -and -not $quoted) {
                $items.Add($part.ToString().Trim())
                $null = $part.Clear()
            }
            else {
                $null = $part.Append($c)
            }
        }
        if ($quoted) {
            throw 'Unterminated quoted policy value'
        }
        $items.Add($part.ToString().Trim())
        return $items.ToArray()
    }

    [object[]] ReadRegistryPolicy([string]$Path) {
        return $this.ReadRegistryPolicyCore($Path, '', $null)
    }

    [object[]] ReadRegistryPolicy([string]$Path, [string]$Scope) {
        if ($Scope -notin 'Computer', 'User') {
            throw 'Scope must be Computer or User.'
        }
        return $this.ReadRegistryPolicyCore($Path, $Scope, $null)
    }

    hidden [object[]] ReadRegistryPolicyCore(
        [string]$Path,
        [string]$Scope,
        [Management.Automation.PSCmdlet]$CommandContext
    ) {
        $this.ValidatePath($Path)
        if ($Scope -and $Scope -notin 'Computer', 'User') {
            throw 'Scope must be Computer or User.'
        }
        $records = [Collections.Generic.List[object]]::new()
        $stream = [IO.File]::OpenRead($Path)
        $reader = [IO.BinaryReader]::new($stream, [Text.Encoding]::Unicode)
        try {
            if ([Text.Encoding]::ASCII.GetString($reader.ReadBytes(4)) -ne 'PReg' -or $reader.ReadUInt32() -ne 1) {
                throw 'Invalid Registry.pol header/version'
            }
            while ($stream.Position -lt $stream.Length) {
                if ($reader.ReadUInt16() -ne 91) {
                    throw 'Invalid Registry.pol opening delimiter'
                }
                $strings = @()
                foreach ($field in @('key', 'value')) {
                    $text = [Text.StringBuilder]::new()
                    while (($c = $reader.ReadUInt16()) -ne 0) {
                        $null = $text.Append([char]$c)
                    }
                    if ($reader.ReadUInt16() -ne 59) {
                        throw "Invalid Registry.pol $field delimiter"
                    }
                    $strings += $text.ToString()
                }
                $type = $reader.ReadUInt32()
                if ($reader.ReadUInt16() -ne 59) {
                    throw 'Invalid Registry.pol type delimiter'
                }
                $size = $reader.ReadUInt32()
                if ($reader.ReadUInt16() -ne 59) {
                    throw 'Invalid Registry.pol size delimiter'
                }
                if ($size -gt [int]::MaxValue -or $size -gt ($stream.Length - $stream.Position - 2)) {
                    throw 'Invalid Registry.pol data length'
                }
                $bytes = $reader.ReadBytes([int]$size)
                if ($reader.ReadUInt16() -ne 93) {
                    throw 'Invalid Registry.pol closing delimiter'
                }
                $value = if ($size -eq 0) {
                    , [byte[]]@()
                }
                else {
                    switch ($type) {
                        { $_ -in 1, 2 } {
                            if ($size % 2) {
                                throw 'Invalid UTF-16 registry value'
                            }
                            [Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)
                        }
                        4 {
                            if ($size -ne 4) {
                                throw 'Invalid DWORD length'
                            }
                            [BitConverter]::ToUInt32($bytes, 0)
                        }
                        5 {
                            if ($size -ne 4) {
                                throw 'Invalid big-endian DWORD length'
                            }
                            $copy = [byte[]]$bytes.Clone()
                            [Array]::Reverse($copy)
                            [BitConverter]::ToUInt32($copy, 0)
                        }
                        7 {
                            if ($size % 2) {
                                throw 'Invalid multi-string length'
                            }
                            $decoded = [Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)
                            if ($decoded) {
                                , $decoded.Split([char]0)
                            }
                            else {
                                , [string[]]@()
                            }
                        }
                        11 {
                            if ($size -ne 8) {
                                throw 'Invalid QWORD length'
                            }
                            [BitConverter]::ToUInt64($bytes, 0)
                        }
                        default {
                            , $bytes
                        }
                    }
                }
                $record = ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{
                        Scope = $Scope
                        Hive = $(if ($Scope -eq 'Computer') {
                                'HKLM'
                            }
                            else {
                                'HKCU'
                            })
                        Key = $strings[0]
                        ValueName = $strings[1]
                        Type = $type
                        Value = $value
                        RawData = $bytes
                        KeyOnly = ($size -eq 0 -and ($strings[1] -eq '' -or ($type -in 4, 5, 11 -and -not $strings[1].StartsWith('**'))))
                        DeletionDirective = $strings[1].StartsWith('**')
                        Source = $Path
                    })
                if ($null -ne $CommandContext) {
                    $CommandContext.WriteObject($record)
                }
                else {
                    $records.Add($record)
                }
            }
        }
        catch {
            throw "Unable to parse '$Path': $($_.Exception.Message)"
        }
        finally {
            $reader.Dispose()
            $stream.Dispose()
        }
        return $records.ToArray()
    }

    hidden [Xml.XmlDocument] ReadXml([string]$Path) {
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [Xml.XmlReader]::Create($Path, $settings)
        try {
            $xml = [Xml.XmlDocument]::new()
            $xml.XmlResolver = $null
            $xml.Load($reader)
            return $xml
        }
        finally {
            $reader.Dispose()
        }
    }

    hidden [object[]] ConvertSecurityOption([string]$Name, [object]$Value) {
        # Keep unknown registry settings verbatim. These names match the analyzer's
        # existing security-option contract; raw INF values remain in IniSettings.
        $key = $Name -replace '^(?i)MACHINE\\', ''
        $booleanNames = @{
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature' = 'Microsoft network server: Digitally sign communications (always)'
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature' = 'Microsoft network server: Digitally sign communications (if client agrees)'
            'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature' = 'Microsoft network client: Digitally sign communications (always)'
            'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\EnableSecuritySignature' = 'Microsoft network client: Digitally sign communications (if server agrees)'
            'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters\EnablePlainTextPassword' = 'Microsoft network client: Send unencrypted password to third-party SMB servers'
            'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\RequireSignOrSeal' = 'Domain member: Digitally encrypt or sign secure channel data (always)'
            'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\SealSecureChannel' = 'Domain member: Digitally encrypt secure channel data (when possible)'
            'SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous' = 'Network access: Let Everyone permissions apply to anonymous users'
            'SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM' = 'Network access: Do not allow anonymous enumeration of SAM accounts'
            'SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous' = 'Network access: Do not allow anonymous enumeration of SAM accounts and shares'
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess' = 'Network access: Restrict anonymous access to Named Pipes and Shares'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken' = 'User Account Control: Admin Approval Mode for the Built-in Administrator account'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle' = 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection' = 'User Account Control: Detect application installations and prompt for elevation'
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA' = 'User Account Control: Run all administrators in Admin Approval Mode'
        }
        if ($booleanNames.ContainsKey($key)) {
            $Name = $booleanNames[$key]
            $Value = [bool][uint32]$Value
        }
        else {
            switch ($key) {
                'SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' {
                    $Name = 'Network security: LAN Manager authentication level'
                    $levels = @('Send LM & NTLM responses',
                        'Send LM & NTLM - use NTLMv2 session security if negotiated',
                        'Send NTLM response only',
                        'Send NTLMv2 response only',
                        'Send NTLMv2 response only. Refuse LM',
                        'Send NTLMv2 response only. Refuse LM & NTLM')
                    if ([int]$Value -ge 0 -and [int]$Value -lt $levels.Count) {
                        $Value = $levels[[int]$Value]
                    }
                }
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin' {
                    $Name = 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
                    $levels = @('Elevate without prompting',
                        'Prompt for credentials on the secure desktop',
                        'Prompt for consent on the secure desktop',
                        'Prompt for credentials',
                        'Prompt for consent',
                        'Prompt for consent for non-Windows binaries')
                    if ([int]$Value -ge 0 -and [int]$Value -lt $levels.Count) {
                        $Value = $levels[[int]$Value]
                    }
                }
                'SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity' {
                    $Name = 'Domain controller: LDAP server signing requirements'
                    if ($Value -eq 2) {
                        $Value = 'Require signature'
                    }
                    else {
                        $Value = 'None'
                    }
                }
                'SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity' {
                    $Name = 'Network security: LDAP client signing requirements'
                    $levels = @('None', 'Negotiate signing', 'Require signing')
                    if ([int]$Value -ge 0 -and [int]$Value -lt 3) {
                        $Value = $levels[[int]$Value]
                    }
                }
                'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes' {
                    $Name = 'Network access: Named Pipes that can be accessed anonymously'
                }
                'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares' {
                    $Name = 'Network access: Shares that can be access anonymously'
                }
            }
        }
        return @(foreach ($entry in @($Value)) {
            [pscustomobject]@{
                Name = $Name
                Value = $entry
            }
        })
    }

    hidden [object] ConvertInfFlag([string]$Name, [string]$RawValue) {
        # MS-GPSB flag domains are numeric and are not uniformly limited to 0/1.
        $domains = @{
            PasswordComplexity = @(10, 65536)
            ClearTextPassword = @(10, 65536)
            LSAAnonymousNameLookup = @(1, 9)
            TicketValidateClient = @(5, 99999)
            ForceLogoffWhenHourExpire = @(10, 9999999999)
        }
        if (-not $domains.ContainsKey($Name)) {
            return $null
        }
        [uint64]$number = 0
        $domain = $domains[$Name]
        $pattern = '^[0-9]{1,' + $domain[0] + '}$'
        $valid = $RawValue -cmatch $pattern -and [uint64]::TryParse($RawValue, [ref]$number) -and $number -le $domain[1]
        return [pscustomobject]@{
            Value = $(if ($valid) {
                    $number -ne 0
                }
                else {
                    $RawValue
                })
            ValueValid = [bool]$valid
        }
    }

    [object] Read([string]$Path) {
        return $this.ReadCore($Path, $null, $null)
    }

    hidden [object] ReadForCommand(
        [string]$Path,
        [Management.Automation.CommandInfo]$IniReader,
        [Management.Automation.CommandInfo]$XmlReader
    ) {
        return $this.ReadCore($Path, $IniReader, $XmlReader)
    }

    hidden [object] ReadCore(
        [string]$Path,
        [Management.Automation.CommandInfo]$IniReader,
        [Management.Automation.CommandInfo]$XmlReader
    ) {
        $this.ValidatePath($Path)
        $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $root.PSIsContainer) {
            throw 'GPO path must be a directory'
        }
        $security = [Collections.ArrayList]::new()
        $registry = [Collections.ArrayList]::new()
        $xmlFiles = [Collections.ArrayList]::new()
        $files = [Collections.ArrayList]::new()
        $iniSettings = [Collections.ArrayList]::new()
        $sysvolVersion = $null
        # MS-GPSB assigns these keys to distinct client-side stores by section.
        $accountKeys = @{
            'System Access' = @('MinimumPasswordAge',
                'MaximumPasswordAge',
                'MinimumPasswordLength',
                'PasswordComplexity',
                'PasswordHistorySize',
                'ClearTextPassword',
                'RequireLogonToChangePassword',
                'LockoutBadCount',
                'ResetLockoutCount',
                'LockoutDuration',
                'ForceLogoffWhenHourExpire',
                'LSAAnonymousNameLookup',
                'EnableAdminAccount',
                'EnableGuestAccount',
                'NewAdministratorName',
                'NewGuestName')
            'Kerberos Policy' = @('MaxTicketAge', 'MaxRenewAge', 'MaxServiceAge', 'MaxClockSkew', 'TicketValidateClient')
        }
        foreach ($file in Get-ChildItem -LiteralPath $root.FullName -File -Force -ErrorAction Stop) {
            $kind = 'Unparsed'
            if ($file.Name -ieq 'GPT.INI') {
                $kind = 'Metadata'
                $ini = if ($IniReader) {
                    & $IniReader $file.FullName
                }
                else {
                    $this.ReadIni($file.FullName)
                }
                if ($ini.Contains('General') -and $ini['General'].Contains('Version')) {
                    $sysvolVersion = [uint32]$ini['General']['Version']
                }
            }
            $null = $files.Add([pscustomobject]@{
                    Scope = 'Gpo'
                    Path = $file.Name
                    Kind = $kind
                    Length = $file.Length
                })
        }
        foreach ($pair in @(@('Computer', 'Machine'), @('User', 'User'))) {
            $scope = $pair[0]
            $side = Join-Path $root.FullName $pair[1]
            try {
                $sideItem = Get-Item -LiteralPath $side -Force -ErrorAction Stop
            }
            catch [System.Management.Automation.ItemNotFoundException] {
                continue
            }
            if ($null -eq $sideItem) {
                continue
            }
            foreach ($file in Get-ChildItem -LiteralPath $side -Recurse -File -Force -ErrorAction Stop) {
                $relative = $file.FullName.Substring($root.FullName.TrimEnd('\', '/').Length + 1)
                $normalized = $relative.Replace('\', '/')
                $relative = $normalized
                $securityTemplate = $normalized -ieq ('{0}/Microsoft/Windows NT/SecEdit/GptTmpl.inf' -f $pair[1])
                $kind = 'Unparsed'
                if ($file.Extension -in '.ini', '.inf') {
                    $kind = 'Ini'
                    $ini = if ($IniReader) {
                        & $IniReader $file.FullName
                    }
                    else {
                        $this.ReadIni($file.FullName)
                    }
                    foreach ($section in ([Collections.IDictionary].GetProperty('Keys')).GetValue($ini, $null)) {
                        foreach ($entry in $ini[$section].GetEnumerator()) {
                            $iniValue = $entry.Value
                            if ($section -eq 'Registry Values' -and (Test-ADAnalyzerSecretName $entry.Key)) {
                                $parts = $this.SplitCsv($entry.Value)
                                $iniValue = if ($parts.Count -ge 2) {
                                    $parts[1..($parts.Count - 1)] -join ','
                                }
                                else {
                                    ''
                                }
                            }
                            $analyzed = $securityTemplate -and
                            (($section -in 'Privilege Rights',
                                'Registry Values') -or
                            ($accountKeys.ContainsKey($section) -and
                            $entry.Key -in $accountKeys[$section]))
                            $null = $iniSettings.Add((ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{
                                            Scope = $scope
                                            Section = $section
                                            Name = $entry.Key
                                            Value = $iniValue
                                            Source = $relative
                                            Analyzed = $analyzed
                                        })))
                        }
                    }
                    if (-not $securityTemplate) {
                        $null = $files.Add([pscustomobject]@{
                                Scope = $scope
                                Path = $relative
                                Kind = $kind
                                Length = $file.Length
                            })
                        continue
                    }
                    $kind = 'SecurityTemplate'
                    foreach ($section in @('System Access', 'Kerberos Policy')) {
                        if (-not $ini.Contains($section)) {
                            continue
                        }
                        foreach ($entry in $ini[$section].GetEnumerator()) {
                            if ($entry.Key -notin $accountKeys[$section]) {
                                continue
                            }
                            $flag = $this.ConvertInfFlag($entry.Key, $entry.Value)
                            $value = $entry.Value
                            if ($null -ne $flag) {
                                $value = $flag.Value
                            }
                            elseif ($entry.Key -ne 'RequireLogonToChangePassword') {
                                if ($value -match '^-?\d+$') {
                                    $value = [long]$value
                                }
                                if ($value -is [string] -and $value.StartsWith('"')) {
                                    $value = ($this.SplitCsv($value))[0]
                                }
                            }
                            $name = $entry.Key
                            $settingKind = 'Account'
                            if ($entry.Key -eq 'LSAAnonymousNameLookup') {
                                $name = 'Network access: Allow anonymous SID/Name translation'
                                $settingKind = 'SecurityOptions'
                            }
                            $record = [ordered]@{
                                Scope = $scope
                                Kind = $settingKind
                                Name = $name
                                Value = $value
                                Source = $relative
                            }
                            if ($null -ne $flag) {
                                $record.ValueValid = $flag.ValueValid
                            }
                            $null = $security.Add([pscustomobject]$record)
                        }
                    }
                    if ($ini.Contains('Privilege Rights')) {
                        foreach ($entry in $ini['Privilege Rights'].GetEnumerator()) {
                            $members = if ($entry.Value) {
                                , $this.SplitCsv($entry.Value)
                            }
                            else {
                                @()
                            }
                            $null = $security.Add([pscustomobject]@{
                                    Scope = $scope
                                    Kind = 'UserRightsAssignment'
                                    Name = $entry.Key
                                    Value = $members
                                    Source = $relative
                                })
                        }
                    }
                    if ($ini.Contains('Registry Values')) {
                        foreach ($entry in $ini['Registry Values'].GetEnumerator()) {
                            $parts = $this.SplitCsv($entry.Value)
                            if ($parts.Count -lt 2) {
                                throw "Invalid registry setting in $relative"
                            }
                            $value = if ($parts[0] -eq '7') {
                                , $parts[1..($parts.Count - 1)]
                            }
                            else {
                                $parts[1..($parts.Count - 1)] -join ','
                            }
                            if ($parts[0] -eq '4' -and $value -match '^\d+$') {
                                $value = [uint32]$value
                            }
                            foreach ($option in $this.ConvertSecurityOption($entry.Key, $value)) {
                                $null = $security.Add([pscustomobject]@{
                                        Scope = $scope
                                        Kind = 'SecurityOptions'
                                        Name = $option.Name
                                        Value = $option.Value
                                        Source = $relative
                                    })
                            }
                        }
                    }
                }
                elseif ($normalized -ieq ('{0}/Registry.pol' -f $pair[1])) {
                    $kind = 'RegistryPolicy'
                    foreach ($item in $this.ReadRegistryPolicy($file.FullName, $scope)) {
                        $item.Source = $pair[1] + '/Registry.pol'
                        $null = $registry.Add($item)
                    }
                }
                elseif ($file.Extension -ieq '.xml') {
                    $kind = 'Xml'
                    $xml = if ($XmlReader) {
                        & $XmlReader $file.FullName
                    }
                    else {
                        $this.ReadXml($file.FullName)
                    }
                    $xmlKind = if ($relative -match '(^|[\\/])Preferences[\\/]') {
                        'Preferences'
                    }
                    else {
                        'Xml'
                    }
                    $null = $xmlFiles.Add([pscustomobject]@{
                            Scope = $scope
                            Kind = $xmlKind
                            Path = $relative
                            Xml = (ConvertTo-ADAnalyzerSecretIndicatorXml $xml).PSBase.OuterXml
                        })
                }
                $null = $files.Add([pscustomobject]@{
                        Scope = $scope
                        Path = $relative
                        Kind = $kind
                        Length = $file.Length
                    })
            }
        }
        return [pscustomobject]@{
            Path = $root.FullName
            SysvolVersion = $sysvolVersion
            SecuritySettings = @($security | ForEach-Object { ConvertTo-ADAnalyzerSecretRecord $_ })
            RegistrySettings = $registry.ToArray()
            XmlFiles = $xmlFiles.ToArray()
            IniSettings = $iniSettings.ToArray()
            Files = $files.ToArray()
            UnparsedFiles = @($files | Where-Object Kind -eq 'Unparsed')
        }
    }

}

function Read-AnalyzerPolicyIni {
    param([Parameter(Mandatory)][string]$Path)
    return [ADAnalyzerGpoReader]::new().ReadIni($Path)
}

function Split-AnalyzerPolicyCsv {
    param([string]$Value)
    return , ([ADAnalyzerGpoReader]::new().SplitCsv($Value))
}

function Read-AnalyzerRegistryPolicy {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Computer', 'User')][string]$Scope

    )
    $reader = [ADAnalyzerGpoReader]::new()
    $null = $reader.ReadRegistryPolicyCore($Path, $Scope, $PSCmdlet)
}

function Read-AnalyzerPolicyXml {
    param([string]$Path)
    return [ADAnalyzerGpoReader]::new().ReadXml($Path)
}

function ConvertTo-AnalyzerSecurityOption {
    param(
        [string]$Name,
        $Value

    )
    return [ADAnalyzerGpoReader]::new().ConvertSecurityOption($Name, $Value)
}

function ConvertFrom-ADAnalyzerInfFlag {
    param(
        [string]$Name,
        [AllowEmptyString()][string]$RawValue

    )
    return [ADAnalyzerGpoReader]::new().ConvertInfFlag($Name, $RawValue)
}

function Read-ADAnalyzerGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $reader = [ADAnalyzerGpoReader]::new()
    return $reader.ReadForCommand(
        $Path,
        (Get-Command Read-AnalyzerPolicyIni),
        (Get-Command Read-AnalyzerPolicyXml)
    )
}

class ADAnalyzerGpoSourceNormalizer {
    ADAnalyzerGpoSourceNormalizer() {
    }

    [pscustomobject] Normalize([object]$Policy) {
        if ($null -eq $Policy) {
            throw [ArgumentNullException]::new('Policy')
        }

        $ErrorActionPreference = 'Stop'
        $normalizer = $this
        foreach ($field in $normalizer.RecordCollections()) {
            foreach ($record in @($Policy.$field)) {
                if ($normalizer.IsUnsupportedRecord(@{ Record = $record })) {
                    throw 'InputObject policy records must use package report objects or JSON objects.'
                }
            }
        }
        $xmlFiles = @(foreach ($record in @($Policy.XmlFiles)) {
                if ($null -eq $record) {
                    continue
                }
                $settings = $normalizer.NewXmlSettings()
                $text = [IO.StringReader]::new([string]$record.Xml)
                $reader = $null
                try {
                    $reader = [Xml.XmlReader]::Create($text, $settings)
                    $document = $normalizer.NewXmlDocument()
                    $document.Load($reader)
                    $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $document
                }
                catch {
                    throw 'Provided policy XML is unreadable.'
                }
                finally {
                    if ($null -ne $reader) {
                        $reader.Dispose()
                    }
                    $text.Dispose()
                }
                $normalizer.BuildXmlFile(@{
                    Scope = $record.Scope
                    Kind = $record.Kind
                    Path = $record.Path
                    Xml = $safe.PSBase.OuterXml
                })
            })
        return $this.BuildPolicy(@{
            Path = $Policy.Path
            SysvolVersion = $Policy.SysvolVersion
            Files = @($Policy.Files)
            UnparsedFiles = @($Policy.UnparsedFiles)
            SecuritySettings = @(
                $Policy.SecuritySettings | Where-Object {
                    $null -ne $_
                } | ForEach-Object {
                    ConvertTo-ADAnalyzerSecretRecord $_
                }
            )
            RegistrySettings = @(
                $Policy.RegistrySettings | Where-Object {
                    $null -ne $_
                } | ForEach-Object {
                    $record = ConvertTo-ADAnalyzerSecretRecord $_.PSObject.Copy()
                    if ($normalizer.RequiresBinaryConversion(@{ Type = $record.Type }) -and
                        ($null -ne $record.PSObject.Properties['Value'] -or
                            $null -eq $record.PSObject.Properties['SecretPresent']) -and
                        $record.Value -is [array]) {
                        $record.Value = [byte[]]$record.Value
                    }
                    $record
                }
            )
            IniSettings = @(
                $Policy.IniSettings | Where-Object {
                    $null -ne $_
                } | ForEach-Object {
                    ConvertTo-ADAnalyzerSecretRecord $_
                }
            )
            XmlFiles = $xmlFiles
        })
    }

    hidden [string[]] RecordCollections() {
        return @('SecuritySettings', 'RegistrySettings', 'IniSettings', 'XmlFiles', 'Files', 'UnparsedFiles')
    }

    hidden [bool] IsUnsupportedRecord([hashtable]$InputFrame) {
        $record = $InputFrame.Record
        return $null -ne $record -and
            ($record -is [Collections.IDictionary] -or
                $record -is [string] -or
                $record -is [ValueType] -or
                $record -isnot [pscustomobject])
    }

    hidden [Xml.XmlReaderSettings] NewXmlSettings() {
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        return $settings
    }

    hidden [xml] NewXmlDocument() {
        $document = [xml]::new()
        $document.XmlResolver = $null
        return $document
    }

    hidden [bool] RequiresBinaryConversion([hashtable]$InputFrame) {
        return $InputFrame.Type -notin @(1, 2, 4, 5, 7, 11)
    }

    hidden [pscustomobject] BuildXmlFile([hashtable]$Fields) {
        return [pscustomobject]@{
            Scope = $Fields.Scope
            Kind = $Fields.Kind
            Path = $Fields.Path
            Xml = $Fields.Xml
        }
    }

    hidden [pscustomobject] BuildPolicy([hashtable]$Fields) {
        return [pscustomobject]@{
            Path = $Fields.Path
            SysvolVersion = $Fields.SysvolVersion
            Files = $Fields.Files
            UnparsedFiles = $Fields.UnparsedFiles
            SecuritySettings = $Fields.SecuritySettings
            RegistrySettings = $Fields.RegistrySettings
            IniSettings = $Fields.IniSettings
            XmlFiles = $Fields.XmlFiles
        }
    }
}

function ConvertTo-ADAnalyzerProvidedGpoPolicy {
    # Prefetched input uses the package DTO contract, including safe XML and
    # typed registry values. Copy before projecting so caller data stays intact.
    param([Parameter(Mandatory)]$Policy)

    $normalizer = [ADAnalyzerGpoSourceNormalizer]::new()
    # Keep native XML, property observations, and binary casts in command scope.
    foreach ($field in $normalizer.RecordCollections()) {
        foreach ($record in @($Policy.$field)) {
            if ($normalizer.IsUnsupportedRecord(@{ Record = $record })) {
                throw 'InputObject policy records must use package report objects or JSON objects.'
            }
        }
    }
    $xmlFiles = @(foreach ($record in @($Policy.XmlFiles)) {
            if ($null -eq $record) {
                continue
            }
            $settings = $normalizer.NewXmlSettings()
            $text = [IO.StringReader]::new([string]$record.Xml)
            $reader = $null
            try {
                $reader = [Xml.XmlReader]::Create($text, $settings)
                $document = $normalizer.NewXmlDocument()
                $document.Load($reader)
                $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $document
            }
            catch {
                throw 'Provided policy XML is unreadable.'
            }
            finally {
                if ($null -ne $reader) {
                    $reader.Dispose()
                }
                $text.Dispose()
            }
            $normalizer.BuildXmlFile(@{
                Scope = $record.Scope
                Kind = $record.Kind
                Path = $record.Path
                Xml = $safe.PSBase.OuterXml
            })
        })
    $normalizer.BuildPolicy(@{
        Path = $Policy.Path
        SysvolVersion = $Policy.SysvolVersion
        Files = @($Policy.Files)
        UnparsedFiles = @($Policy.UnparsedFiles)
        SecuritySettings = @(
            $Policy.SecuritySettings | Where-Object {
                $null -ne $_
            } | ForEach-Object {
                ConvertTo-ADAnalyzerSecretRecord $_
            }
        )
        RegistrySettings = @(
            $Policy.RegistrySettings | Where-Object {
                $null -ne $_
            } | ForEach-Object {
                $record = ConvertTo-ADAnalyzerSecretRecord $_.PSObject.Copy()
                if ($normalizer.RequiresBinaryConversion(@{ Type = $record.Type }) -and
                    ($null -ne $record.PSObject.Properties['Value'] -or
                        $null -eq $record.PSObject.Properties['SecretPresent']) -and
                    $record.Value -is [array]) {
                    $record.Value = [byte[]]$record.Value
                }
                $record
            }
        )
        IniSettings = @(
            $Policy.IniSettings | Where-Object {
                $null -ne $_
            } | ForEach-Object {
                ConvertTo-ADAnalyzerSecretRecord $_
            }
        )
        XmlFiles = $xmlFiles
    })
}

class ADAnalyzerGpoCatalog {
    ADAnalyzerGpoCatalog() {
    }

    [object[]] GetAll([string]$Domain) {
        return $this.GetAll($Domain, $Domain, [pscredential]::Empty)
    }

    [object[]] GetAll([string]$Domain, [string]$Server) {
        return $this.GetAll($Domain, $Server, [pscredential]::Empty)
    }

    [object[]] GetAll([string]$Domain, [string]$Server, [pscredential]$Credential) {
        return $this.Discover($Domain, $Server, $Credential, 'All', [guid]::Empty, '')
    }

    [object[]] FindById([guid]$Guid, [string]$Domain) {
        return $this.FindById($Guid, $Domain, $Domain, [pscredential]::Empty)
    }

    [object[]] FindById([guid]$Guid, [string]$Domain, [string]$Server) {
        return $this.FindById($Guid, $Domain, $Server, [pscredential]::Empty)
    }

    [object[]] FindById([guid]$Guid, [string]$Domain, [string]$Server, [pscredential]$Credential) {
        return $this.Discover($Domain, $Server, $Credential, 'Guid', $Guid, '')
    }

    [object[]] FindByName([string]$Name, [string]$Domain) {
        return $this.FindByName($Name, $Domain, $Domain, [pscredential]::Empty)
    }

    [object[]] FindByName([string]$Name, [string]$Domain, [string]$Server) {
        return $this.FindByName($Name, $Domain, $Server, [pscredential]::Empty)
    }

    [object[]] FindByName([string]$Name, [string]$Domain, [string]$Server, [pscredential]$Credential) {
        return $this.Discover($Domain, $Server, $Credential, 'Name', [guid]::Empty, $Name)
    }

    hidden [bool] IsHostName([hashtable]$Observed) {
        return -not ($Observed.Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$')
    }

    hidden [hashtable] NewConnection([string]$Server, [pscredential]$Credential) {
        $connection = @{
            Server = $Server
            ErrorAction = 'Stop'
        }
        if ($Credential -and $Credential -ne [pscredential]::Empty) {
            $connection.Credential = $Credential
        }
        return $connection
    }

    hidden [hashtable] QueryDefinitions() {
        return @{
            PolicyBasePrefix = 'CN=Policies,CN=System,'
            SiteBasePrefix = 'CN=Sites,'
            LinkPattern = '(?i)\[LDAP://(?<dn>[^;]+);(?<flags>\d+)\]'
            Policies = @{
                LDAPFilter = '(objectClass=groupPolicyContainer)'
                Properties = @(
                    'displayName'
                    'gPCFileSysPath'
                    'flags'
                    'whenCreated'
                    'whenChanged'
                    'versionNumber'
                    'gPCWQLFilter'
                    'gPCMachineExtensionNames'
                    'gPCUserExtensionNames'
                )
            }
            Links = @{
                LDAPFilter = '(gPLink=*)'
                Properties = @('gPLink', 'gPOptions', 'distinguishedName')
            }
        }
    }

    hidden [bool] RejectGuid([guid]$Observed, [guid]$Requested) {
        return $Observed -ne $Requested
    }

    hidden [bool] RejectName([hashtable]$Observed, [string]$Requested) {
        return $Observed.Name -ine $Requested
    }

    hidden [pscustomobject] BuildLink([hashtable]$Observed) {
        return [pscustomobject]@{
            SOMPath = $Observed.SOMPath
            Enabled = ($Observed.Options -band 1) -eq 0
            Enforced = ($Observed.Options -band 2) -ne 0
            StoredLinkIndex = $Observed.Index
            BlockInheritance = ($Observed.InheritanceOptions -band 1) -ne 0
        }
    }

    hidden [pscustomobject] BuildPolicy([hashtable]$Observed) {
        $statusNames = @(
            'AllSettingsEnabled'
            'UserSettingsDisabled'
            'ComputerSettingsDisabled'
            'AllSettingsDisabled'
        )
        return [pscustomobject]@{
            Id = $Observed.Id
            DisplayName = $Observed.DisplayName
            CreationTime = $Observed.CreationTime
            ModificationTime = $Observed.ModificationTime
            GPOStatus = $statusNames[$Observed.Flags -band 3]
            Flags = $Observed.Flags
            Version = $Observed.Version
            Domain = $Observed.Domain
            Server = $Observed.Server
            RequestedServer = $Observed.RequestedServer
            DistinguishedName = $Observed.DistinguishedName
            DirectoryFilePath = $Observed.DirectoryFilePath
            PolicyPath = ('\\{0}\SYSVOL\{1}\Policies\{2}' -f $Observed.Server, $Observed.Domain, $Observed.Id.ToString('B'))
            Links = $Observed.Links
            WmiFilter = $Observed.WmiFilter
            MachineExtensions = $Observed.MachineExtensions
            UserExtensions = $Observed.UserExtensions
        }
    }

    hidden [object[]] Discover(
        [string]$Domain, [string]$Server, [pscredential]$Credential,
        [string]$Selection, [guid]$Guid, [string]$Name
    ) {
        $ErrorActionPreference = 'Stop'
        $catalog = $this
        if (-not $catalog.IsHostName(@{ Value = $Server })) {
            throw 'Server must be a DNS or NetBIOS host name'
        }
        if ([string]::IsNullOrWhiteSpace($Domain)) {
            throw [ArgumentException]::new('Domain must be supplied.', 'Domain')
        }
        if ($Selection -eq 'Guid' -and $Guid -eq [guid]::Empty) {
            throw [ArgumentException]::new('GPO GUID must be supplied.', 'Guid')
        }
        if ($Selection -eq 'Name' -and [string]::IsNullOrWhiteSpace($Name)) {
            throw [ArgumentException]::new('GPO name must be supplied.', 'Name')
        }

        $providerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        $cmdlets = $provider.ExportedCmdlets
        $rootCommand = $cmdlets['Get-ADRootDSE']
        $domainCommand = $cmdlets['Get-ADDomain']
        $objectCommand = $cmdlets['Get-ADObject']
        if ($null -eq $rootCommand -or $null -eq $domainCommand -or $null -eq $objectCommand) {
            throw 'Bundled AD assembly does not provide the required catalog commands'
        }

        $connection = $catalog.NewConnection($Server, $Credential)
        $requestedServer = $Server
        $rootDse = & $rootCommand @connection
        if (-not $catalog.IsHostName(@{ Value = $rootDse.DnsHostName })) {
            throw 'The directory server did not return a valid DC host name'
        }
        $Server = [string]$rootDse.DnsHostName
        if (-not $catalog.IsHostName(@{ Value = $Server })) {
            throw 'The directory server did not return a valid DC host name'
        }
        $connection.Server = $Server
        $domainInfo = & $domainCommand -Identity $Domain @connection
        $dns = [string]$domainInfo.DNSRoot
        if (-not $catalog.IsHostName(@{ Value = $dns })) {
            throw 'Invalid domain DNS name'
        }

        $queries = $catalog.QueryDefinitions()
        $policyQuery = $queries.Policies
        $linkQuery = $queries.Links
        $linkPattern = $queries.LinkPattern
        $base = $queries.PolicyBasePrefix + $domainInfo.DistinguishedName
        $objects = @(& $objectCommand -SearchBase $base @policyQuery @connection)
        $links = @(& $objectCommand -SearchBase $domainInfo.DistinguishedName @linkQuery @connection)
        if ($rootDse.ConfigurationNamingContext) {
            $links += @(& $objectCommand -SearchBase ($queries.SiteBasePrefix + $rootDse.ConfigurationNamingContext) @linkQuery @connection)
        }

        $policies = [Collections.Generic.List[object]]::new()
        # Reuse matches only after reading the current text from this container.
        $lastLinkText = $null
        $lastLinkMatches = $null
        foreach ($object in $objects) {
            $id = [guid]([string]$object.Name).Trim('{}')
            if ($selection -eq 'Guid' -and $catalog.RejectGuid($id, $Guid)) {
                continue
            }
            if ($selection -eq 'Name' -and $catalog.RejectName(@{ Name = $object.displayName }, $Name)) {
                continue
            }

            $policyLinks = [Collections.ArrayList]::new()
            $containerIndex = -1
            foreach ($container in $links) {
                $containerIndex++
                $storedIndex = 0
                $linkText = $null
                $linkText = [string]$container.gPLink
                if ($null -eq $linkText) {
                    continue
                }
                if ($null -eq $lastLinkMatches) {
                    $lastLinkMatches = [object[]]::new($links.Count)
                    $lastLinkText = [string[]]::new($links.Count)
                }
                if ($null -eq $lastLinkMatches[$containerIndex] -or
                    -not [string]::Equals($lastLinkText[$containerIndex], $linkText, [StringComparison]::Ordinal)) {
                    $lastLinkMatches[$containerIndex] = [regex]::Matches($linkText, $linkPattern)
                    $lastLinkText[$containerIndex] = $linkText
                }
                foreach ($match in $lastLinkMatches[$containerIndex]) {
                    if ($match.Groups['dn'].Value -ieq $object.DistinguishedName) {
                        $options = [int]$match.Groups['flags'].Value
                        $null = $policyLinks.Add($catalog.BuildLink(@{
                                SOMPath = $container.DistinguishedName
                                Options = $options
                                Index = $storedIndex
                                InheritanceOptions = ([int]$container.gPOptions)
                            }))
                    }
                    $storedIndex++
                }
            }

            $flags = [int]$object.flags
            $policies.Add($catalog.BuildPolicy(@{
                    Id = $id
                    DisplayName = $object.displayName
                    CreationTime = $object.whenCreated
                    ModificationTime = $object.whenChanged
                    Flags = $flags
                    Version = $object.versionNumber
                    Domain = $dns
                    Server = $Server
                    RequestedServer = $requestedServer
                    DistinguishedName = $object.DistinguishedName
                    DirectoryFilePath = $object.gPCFileSysPath
                    Links = $policyLinks.ToArray()
                    WmiFilter = $object.gPCWQLFilter
                    MachineExtensions = $object.gPCMachineExtensionNames
                    UserExtensions = $object.gPCUserExtensionNames
                }))
        }
        return $policies.ToArray()
    }
}

function Get-ADAnalyzerGpo {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(ParameterSetName = 'All')][switch]$All,
        [Parameter(Mandatory, ParameterSetName = 'Guid')][guid]$Guid,
        [Parameter(Mandatory, ParameterSetName = 'Name')][string]$Name,
        [Parameter(Mandatory)][string]$Domain,
        [string]$Server = $Domain,
        [pscredential]$Credential = [pscredential]::Empty

    )
    $catalog = [ADAnalyzerGpoCatalog]::new()
    $selection = $PSCmdlet.ParameterSetName
    if (-not $catalog.IsHostName(@{ Value = $Server })) {
        throw 'Server must be a DNS or NetBIOS host name'
    }

    # Keep provider calls and raw reads in native scope for command error capture.
    $connection = $catalog.NewConnection($Server, $Credential)
    $requestedServer = $Server
    $rootDse = Get-ADRootDSE @connection
    if (-not $catalog.IsHostName(@{ Value = $rootDse.DnsHostName })) {
        throw 'The directory server did not return a valid DC host name'
    }
    $Server = [string]$rootDse.DnsHostName
    $connection.Server = $Server
    $domainInfo = Get-ADDomain -Identity $Domain @connection
    $dns = [string]$domainInfo.DNSRoot
    if (-not $catalog.IsHostName(@{ Value = $dns })) {
        throw 'Invalid domain DNS name'
    }

    $queries = $catalog.QueryDefinitions()
    $policyQuery = $queries.Policies
    $linkQuery = $queries.Links
    $linkPattern = $queries.LinkPattern
    $base = $queries.PolicyBasePrefix + $domainInfo.DistinguishedName
    $objects = @(Get-ADObject -SearchBase $base @policyQuery @connection)
    $links = @(Get-ADObject -SearchBase $domainInfo.DistinguishedName @linkQuery @connection)
    if ($rootDse.ConfigurationNamingContext) {
        $links += @(Get-ADObject -SearchBase ($queries.SiteBasePrefix + $rootDse.ConfigurationNamingContext) @linkQuery @connection)
    }

    # Keep the original link getter and conversion in this native scope.
    $lastLinkText = $null
    $lastLinkMatches = $null
    foreach ($object in $objects) {
        # A failed native cast under Continue leaves the variable unchanged.
        $id = $null
        $id = [guid]([string]$object.Name).Trim('{}')
        if ($null -eq $id) {
            continue
        }
        if ($selection -eq 'Guid' -and $catalog.RejectGuid($id, $Guid)) {
            continue
        }
        if ($selection -eq 'Name' -and $catalog.RejectName(@{ Name = $object.displayName }, $Name)) {
            continue
        }

        $policyLinks = [Collections.ArrayList]::new()
        $containerIndex = -1
        foreach ($container in $links) {
            $containerIndex++
            $storedIndex = 0
            $linkText = $null
            $linkText = [string]$container.gPLink
            if ($null -eq $linkText) {
                continue
            }
            if ($null -eq $lastLinkMatches) {
                $lastLinkMatches = [object[]]::new($links.Count)
                $lastLinkText = [string[]]::new($links.Count)
            }
            if ($null -eq $lastLinkMatches[$containerIndex] -or
                -not [string]::Equals($lastLinkText[$containerIndex], $linkText, [StringComparison]::Ordinal)) {
                $lastLinkMatches[$containerIndex] = [regex]::Matches($linkText, $linkPattern)
                $lastLinkText[$containerIndex] = $linkText
            }
            foreach ($match in $lastLinkMatches[$containerIndex]) {
                if ($match.Groups['dn'].Value -ieq $object.DistinguishedName) {
                    $options = $null
                    $options = [int]$match.Groups['flags'].Value
                    if ($null -ne $options) {
                        $null = $policyLinks.Add($catalog.BuildLink(@{
                                SOMPath = $container.DistinguishedName
                                Options = $options
                                Index = $storedIndex
                                InheritanceOptions = ([int]$container.gPOptions)
                            }))
                    }
                }
                $storedIndex++
            }
        }

        $flags = $null
        $flags = [int]$object.flags
        if ($null -eq $flags) {
            continue
        }

        $catalog.BuildPolicy(@{
                Id = $id
                DisplayName = $object.displayName
                CreationTime = $object.whenCreated
                ModificationTime = $object.whenChanged
                Flags = $flags
                Version = $object.versionNumber
                Domain = $dns
                Server = $Server
                RequestedServer = $requestedServer
                DistinguishedName = $object.DistinguishedName
                DirectoryFilePath = $object.gPCFileSysPath
                Links = $policyLinks.ToArray()
                WmiFilter = $object.gPCWQLFilter
                MachineExtensions = $object.gPCMachineExtensionNames
                UserExtensions = $object.gPCUserExtensionNames
            })
    }
}

class ADAnalyzerGpoXmlWriter {
    ADAnalyzerGpoXmlWriter() {
    }

    [string] Render([object]$Gpo, [object]$Policy) {
        return $this.Render($Gpo, $Policy, @{}, @{})
    }

    [string] Render([object]$Gpo, [object]$Policy, [hashtable]$SidNames, [hashtable]$SidStatus) {
        $writer = $this
        $Parsed = $Policy
        $appendSourceNode = {
            param([xml]$Document, [Xml.XmlNode]$Parent, [string]$Name, $Value)

            $node = [ADAnalyzerGpoXmlWriter]::PrepareNode($Document, $Name)
            if ($null -ne $Value) {
                [ADAnalyzerGpoXmlWriter]::SetText($node, [string]$Value)
            }
            [ADAnalyzerGpoXmlWriter]::AttachNode($Parent, $node)
            return $node
        }
        $observeSource = $this.SourceObservationSteps()
        return & $observeSource $true
    }

    hidden [hashtable] NewSidNames() {
        return @{
            'S-1-5-32-544' = 'Administrators'
            'S-1-5-32-545' = 'Users'
            'S-1-5-32-546' = 'Guests'
            'S-1-5-32-551' = 'Backup Operators'
            'S-1-1-0' = 'Everyone'
            'S-1-5-11' = 'Authenticated Users'
            'S-1-5-18' = 'SYSTEM'
            'S-1-5-19' = 'LOCAL SERVICE'
            'S-1-5-20' = 'NETWORK SERVICE'
        }
    }

    hidden [xml] StartDocument() {
        $document = [xml]::new()
        $document.XmlResolver = $null
        $root = $document.CreateElement('GPO')
        $null = $document.AppendChild($root)
        $null = $this.Append($root, 'ReadTime', [datetime]::UtcNow.ToString('o'))
        return $document
    }

    hidden static [Xml.XmlElement] PrepareNode([xml]$Document, [string]$Name) {
        return $Document.CreateElement($Name)
    }

    hidden static [void] SetText([Xml.XmlNode]$Node, [string]$Text) {
        $Node.PSBase.InnerText = $Text
    }

    hidden static [void] AttachNode([Xml.XmlNode]$Parent, [Xml.XmlNode]$Node) {
        $null = $Parent.AppendChild($Node)
    }

    hidden [Xml.XmlElement] Append([Xml.XmlNode]$Parent, [string]$Name, [object]$Value) {
        $node = [ADAnalyzerGpoXmlWriter]::PrepareNode($Parent.OwnerDocument, $Name)
        if ($null -ne $Value) {
            [ADAnalyzerGpoXmlWriter]::SetText($node, [string]$Value)
        }
        [ADAnalyzerGpoXmlWriter]::AttachNode($Parent, $node)
        return $node
    }

    hidden [void] AppendBoolean([Xml.XmlNode]$Parent, [string]$Name, [bool]$Value) {
        $null = $this.Append($Parent, $Name, ([string]$Value).ToLowerInvariant())
    }

    hidden [bool] VersionsDiffer([hashtable]$Observed, [long]$DirectoryVersion) {
        return $Observed.SysvolVersion -ne ($DirectoryVersion -band [long]4294967295)
    }

    hidden [int] ScopeDisabledBit([string]$Scope) {
        if ($Scope -eq 'Computer') {
            return 2
        }
        return 1
    }

    hidden [Xml.XmlElement] OpenExtension([Xml.XmlNode]$ScopeNode, [string]$Name) {
        $section = $this.Append($ScopeNode, 'ExtensionData', $null)
        $null = $this.Append($section, 'Name', $Name)
        return $this.Append($section, 'Extension', $null)
    }

    hidden [string] SecurityValueTag([string]$Kind, [bool]$Boolean, [bool]$Number) {
        if ($Kind -eq 'SecurityOptions') {
            if ($Boolean) {
                return 'DisplayBoolean'
            }
            return 'DisplayString'
        }
        if ($Boolean) {
            return 'SettingBoolean'
        }
        if ($Number) {
            return 'SettingNumber'
        }
        return 'SettingString'
    }

    hidden [bool] WriteMemberIdentity([Xml.XmlElement]$Member, [object]$Token) {
        if ($Token -match '^S-\d-') {
            $null = $this.Append($Member, 'SID', $Token)
            return $true
        }
        $null = $this.Append($Member, 'Name', $Token)
        return $false
    }

    hidden [pscustomobject] ResolveMember([string]$Token, [hashtable]$Names, [hashtable]$Observed) {
        if ($Names.ContainsKey($Token)) {
            return [pscustomobject]@{
                Named = $true
                Name = $Names[$Token]
                Status = 'Resolved'
            }
        }
        $status = 'NotAttempted'
        if ($Observed.HasStatus) {
            $status = $Observed.Status
        }
        return [pscustomobject]@{
            Named = $false
            Name = $null
            Status = $status
        }
    }

    hidden [bool] HasValueOrIsOrdinary([hashtable]$InputFrame) {
        $record = $InputFrame.Record
        return $null -ne $record.PSObject.Properties['Value'] -or
            $null -eq $record.PSObject.Properties['SecretPresent']
    }

    hidden [string] ExtensionValueTag([bool]$HasPresence) {
        if ($HasPresence) {
            return 'SecretPresent'
        }
        return 'Value'
    }

    hidden [string] Serialize([xml]$Document) {
        return $Document.PSBase.OuterXml
    }

    hidden [object] ProjectEmbeddedXml([object]$Value) {
        $text = $null
        $reader = $null
        try {
            $source = [string]$Value
            if ([string]::IsNullOrWhiteSpace($source)) {
                return $Value
            }

            $normalizer = [ADAnalyzerGpoSourceNormalizer]::new()
            $text = [IO.StringReader]::new($source)
            $reader = [Xml.XmlReader]::Create($text, $normalizer.NewXmlSettings())
            $document = $normalizer.NewXmlDocument()
            $document.PreserveWhitespace = $true
            $document.Load($reader)
            $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $document
            $projected = $safe.PSBase.OuterXml
            if ($projected -ceq $document.PSBase.OuterXml) {
                return $Value
            }
            return $projected
        }
        catch {
            throw 'Provided policy XML is unreadable.'
        }
        finally {
            if ($null -ne $reader) {
                $reader.Dispose()
            }
            if ($null -ne $text) {
                $text.Dispose()
            }
        }
    }

    hidden [scriptblock] SourceObservationSteps() {
        # Run raw reads and conversions in the caller's PowerShell frame. A
        # command under Continue can still return its DOM after a bad row.
        return {
            param([bool]$ProjectSecretInput)

            $known = $writer.NewSidNames()
            foreach ($key in ([Collections.IDictionary].GetProperty('Keys')).GetValue($SidNames, $null)) {
                $known[$key] = $SidNames[$key]
            }
            $doc = $writer.StartDocument()
            $g = $doc.PSBase.DocumentElement
            $null = & $appendSourceNode $doc $g 'DirectoryVersion' $Gpo.Version
            $null = & $appendSourceNode $doc $g 'SysvolVersion' $Parsed.SysvolVersion
            $writer.AppendBoolean($g, 'VersionMismatch', ($null -ne $Parsed.SysvolVersion -and
                        $null -ne $Gpo.Version -and
                        $writer.VersionsDiffer(@{ SysvolVersion = $Parsed.SysvolVersion }, [long]$Gpo.Version)))

            foreach ($link in @($Gpo.Links)) {
                $l = $writer.Append($g, 'LinksTo', $null)
                $null = & $appendSourceNode $doc $l 'SOMPath' $link.SOMPath
                $null = & $appendSourceNode $doc $l 'Enabled' ([string]$link.Enabled).ToLowerInvariant()
                $null = & $appendSourceNode $doc $l 'NoOverride' ([string]$link.Enforced).ToLowerInvariant()
            }

            foreach ($scope in @('Computer', 'User')) {
                $side = $writer.Append($g, $scope, $null)
                $bit = $writer.ScopeDisabledBit($scope)
                $writer.AppendBoolean($side, 'Enabled', (($Gpo.Flags -band $bit) -eq 0))

                $settings = @($Parsed.SecuritySettings | Where-Object Scope -eq $scope)
                if ($settings.Count) {
                    $body = $writer.OpenExtension($side, 'Security')
                    foreach ($setting in $settings) {
                        if ($ProjectSecretInput) {
                            $setting = ConvertTo-ADAnalyzerSecretRecord -Record $setting
                        }
                        # A failed native assignment under Continue can leave an earlier value.
                        $node = $null
                        $node = & $appendSourceNode $doc $body $setting.Kind
                        if ($null -eq $node) {
                            continue
                        }

                        if ($null -ne $setting.PSObject.Properties['ValueValid'] -and $null -ne $setting.ValueValid) {
                            $valid = $setting.ValueValid -is [bool] -and $setting.ValueValid
                            $writer.AppendBoolean($node, 'ValueValid', $valid)
                        }

                        if ($null -ne $setting.PSObject.Properties['SecretPresent']) {
                            $null = & $appendSourceNode $doc $node 'Name' $setting.Name
                            $null = & $appendSourceNode $doc $node 'SecretPresent' ([string]$setting.SecretPresent).ToLowerInvariant()
                            $canReadSource = -not $ProjectSecretInput -or
                                (Test-ADAnalyzerOptionalSecretRecordMember @{ Record = $setting } 'Source')
                            if ($canReadSource -and $setting.Source) {
                                $null = & $appendSourceNode $doc $node 'Source' $setting.Source
                            }
                            continue
                        }

                        if ($setting.Kind -eq 'SecurityOptions') {
                            $display = $writer.Append($node, 'Display', $null)
                            $null = & $appendSourceNode $doc $display 'Name' $setting.Name
                            if ($setting.Value -is [bool]) {
                                $tag = $writer.SecurityValueTag('SecurityOptions', $true, $false)
                                $null = & $appendSourceNode $doc $display $tag ([string]$setting.Value).ToLowerInvariant()
                            }
                            else {
                                $tag = $writer.SecurityValueTag('SecurityOptions', $false, $false)
                                $null = & $appendSourceNode $doc $display $tag $setting.Value
                            }
                        }
                        else {
                            $null = & $appendSourceNode $doc $node 'Name' $setting.Name
                            if ($setting.Kind -eq 'Account') {
                                if ($setting.Value -is [bool]) {
                                    $tag = $writer.SecurityValueTag('Account', $true, $false)
                                    $null = & $appendSourceNode $doc $node $tag ([string]$setting.Value).ToLowerInvariant()
                                }
                                elseif ($setting.Value -is [long]) {
                                    $tag = $writer.SecurityValueTag('Account', $false, $true)
                                    $null = & $appendSourceNode $doc $node $tag $setting.Value
                                }
                                else {
                                    $tag = $writer.SecurityValueTag('Account', $false, $false)
                                    $null = & $appendSourceNode $doc $node $tag $setting.Value
                                }
                            }
                            else {
                                foreach ($entry in @($setting.Value)) {
                                    $member = $writer.Append($node, 'Member', $null)
                                    $token = $null
                                    $token = ([string]$entry).TrimStart('*')
                                    if ($writer.WriteMemberIdentity($member, $token)) {
                                        $observed = @{
                                            HasStatus = $false
                                            Status = $null
                                        }
                                        if (-not $known.ContainsKey($token) -and $SidStatus.ContainsKey($token)) {
                                            $observed.HasStatus = $true
                                            $observed.Status = $SidStatus[$token]
                                        }
                                        $resolution = $writer.ResolveMember($token, $known, $observed)
                                        if ($resolution.Named) {
                                            $null = & $appendSourceNode $doc $member 'Name' $resolution.Name
                                        }
                                        $null = & $appendSourceNode $doc $member 'Resolution' $resolution.Status
                                    }
                                }
                            }
                        }
                    }
                }

                foreach ($kind in @('Registry', 'Preferences', 'Xml', 'Ini')) {
                    # Windows PowerShell 5.1 unwraps a singleton PSCustomObject.
                    $rows = @(
                        if ($kind -eq 'Registry') {
                            $Parsed.RegistrySettings | Where-Object Scope -eq $scope
                        }
                        elseif ($kind -eq 'Ini') {
                            $Parsed.IniSettings | Where-Object { $_.Scope -eq $scope -and -not $_.Analyzed }
                        }
                        else {
                            $Parsed.XmlFiles | Where-Object { $_.Scope -eq $scope -and $_.Kind -eq $kind }
                        }
                    )
                    if (-not $rows.Count) {
                        continue
                    }

                    $body = $writer.OpenExtension($side, $kind)
                    foreach ($row in $rows) {
                        if ($ProjectSecretInput -and $kind -in 'Registry', 'Ini') {
                            $row = ConvertTo-ADAnalyzerSecretRecord -Record $row
                        }
                        # A failed native read must leave this record's field empty.
                        $label = $null
                        $value = $null
                        $record = $writer.Append($body, 'Record', $null)
                        if ($kind -eq 'Registry') {
                            $label = '{0}\{1}\{2}' -f $row.Hive, $row.Key, $row.ValueName
                            $value = if (-not $writer.HasValueOrIsOrdinary(@{ Record = $row })) {
                                $null
                            }
                            elseif ($row.Value -is [byte[]]) {
                                [System.Convert]::ToBase64String($row.Value)
                            }
                            elseif ($row.Value -is [array]) {
                                ConvertTo-Json -InputObject $row.Value -Compress
                            }
                            else {
                                [string]$row.Value
                            }
                            $null = & $appendSourceNode $doc $record 'Type' $row.Type
                        }
                        elseif ($kind -eq 'Ini') {
                            $label = '{0}: [{1}] {2}' -f $row.Source, $row.Section, $row.Name
                            $value = if ($writer.HasValueOrIsOrdinary(@{ Record = $row })) {
                                $row.Value
                            }
                        }
                        else {
                            $label = $row.Path
                            if ($ProjectSecretInput) {
                                $value = $writer.ProjectEmbeddedXml($row.Xml)
                            }
                            else {
                                $value = $row.Xml
                            }
                        }

                        $null = & $appendSourceNode $doc $record 'Name' $label
                        $hasPresence = $null -ne $row.PSObject.Properties['SecretPresent']
                        $tag = $writer.ExtensionValueTag($hasPresence)
                        if ($hasPresence) {
                            $null = & $appendSourceNode $doc $record $tag ([string]$row.SecretPresent).ToLowerInvariant()
                        }
                        else {
                            $null = & $appendSourceNode $doc $record $tag $value
                        }
                    }
                }
            }

            $inventory = $writer.Append($g, 'FileInventory', $null)
            foreach ($file in $Parsed.Files) {
                $node = $writer.Append($inventory, 'File', $null)
                $node.SetAttribute('Kind', $file.Kind)
                $node.PSBase.InnerText = $file.Path
            }
            return $writer.Serialize($doc)
        }
    }
}

function Add-AnalyzerGpoXmlNode {
    param(
        [xml]$Document,
        [Xml.XmlNode]$Parent,
        [string]$Name,
        $Value

    )
    $node = [ADAnalyzerGpoXmlWriter]::PrepareNode($Document, $Name)
    if ($null -ne $Value) {
        [ADAnalyzerGpoXmlWriter]::SetText($node, [string]$Value)
    }
    [ADAnalyzerGpoXmlWriter]::AttachNode($Parent, $node)
    return $node
}

function ConvertTo-AnalyzerGpoXml {
    param(
        $Gpo,
        $Parsed,
        [hashtable]$SidNames = @{},
        [hashtable]$SidStatus = @{}

    )
    $writer = [ADAnalyzerGpoXmlWriter]::new()
    $appendSourceNode = 'Add-AnalyzerGpoXmlNode'
    $observeSource = $writer.SourceObservationSteps()
    & $observeSource $false
}

function Get-ADAnalyzerGpoReport {
    [CmdletBinding(DefaultParameterSetName = 'Gpo')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Gpo')]$Gpo,
        [Parameter(Mandatory, ParameterSetName = 'Guid')][guid]$Guid,
        [Parameter(Mandatory, ParameterSetName = 'Guid')][string]$Domain,
        [Parameter(ParameterSetName = 'Guid')][string]$Server = $Domain,
        [pscredential]$Credential = [pscredential]::Empty,
        [switch]$AsObject,
        [hashtable]$SidNames = @{}

    )
    if ($PSCmdlet.ParameterSetName -eq 'Guid') {
        $Gpo = @(Get-ADAnalyzerGpo -Guid $Guid -Domain $Domain -Server $Server -Credential $Credential)
        if ($Gpo.Count -ne 1) {
            throw 'GPO was not found or was ambiguous'
        }
        $Gpo = $Gpo[0]
    }
    # Use only the single validated target for SYSVOL and directory lookups.
    $hostPattern = '\A[A-Za-z0-9][A-Za-z0-9._-]*\z'
    if (($reportServer = $Gpo.Server) -isnot [string] -or
        $reportServer -notmatch $hostPattern -or
        ($reportDomain = $Gpo.Domain) -isnot [string] -or
        $reportDomain -notmatch $hostPattern) {
        throw 'Invalid GPO server/domain'
    }
    $id = [guid]$Gpo.Id
    $drive = $null
    $completed = $false
    try {
        if ($Credential -and $Credential -ne [pscredential]::Empty) {
            $drive = New-PSDrive `
                -Name ('ADGpo' + [guid]::NewGuid().ToString('N')) `
                -PSProvider FileSystem `
                -Root ('\\{0}\SYSVOL' -f $reportServer) `
                -Credential $Credential `
                -Scope Local `
                -ErrorAction Stop `
                -WhatIf:$false `
                -Confirm:$false
            $path = Join-Path ($drive.Name + ':\') ('{0}\Policies\{1}' -f $reportDomain, $id.ToString('B'))
        }
        else {
            $path = '\\{0}\SYSVOL\{1}\Policies\{2}' -f $reportServer, $reportDomain, $id.ToString('B')
        }
        $parsed = Read-ADAnalyzerGpo -Path $path
        $mismatch = $null -ne $parsed.SysvolVersion -and
        $null -ne $Gpo.Version -and
        $parsed.SysvolVersion -ne ([long]$Gpo.Version -band [long]4294967295)
        if ($mismatch) {
            Write-Warning ('GPO {0} directory and SYSVOL versions differ; the policy may be updating or replicating' -f $Gpo.Id)
        }
        if ($AsObject) {
            [pscustomobject]@{
                Gpo = $Gpo
                Policy = $parsed
                VersionMismatch = $mismatch
            }
        }
        else {
            $names = if ($null -ne $SidNames) {
                $SidNames.Clone()
            }
            else {
                @{}
            }
            $status = @{}
            $connection = @{
                Server = $reportServer
                ErrorAction = 'Stop'
            }
            if ($Credential -and $Credential -ne [pscredential]::Empty) {
                $connection.Credential = $Credential
            }
            $tokens = @($parsed.SecuritySettings | Where-Object Kind `
                    -eq 'UserRightsAssignment' | ForEach-Object { $_.Value } | ForEach-Object { ([string]$_).TrimStart('*') } | Where-Object { $_ -match '^S-1-5-21-(\d+-){3}\d+$' } | Select-Object `
                    -Unique)
            foreach ($token in $tokens) {
                if ($names.ContainsKey($token)) {
                    continue
                }
                try {
                    $matches = @(Get-ADObject -Filter "objectSid -eq '$token'" -Properties sAMAccountName @connection)
                    if ($matches.Count -eq 1 -and $matches[0].sAMAccountName) {
                        $names[$token] = [string]$matches[0].sAMAccountName
                        $status[$token] = 'Resolved'
                    }
                    else {
                        $status[$token] = 'NotFound'
                    }
                }
                catch {
                    $status[$token] = 'LookupFailed'
                    Write-Warning "Unable to resolve policy SID $token on ${reportServer}: $($_.Exception.Message)"
                }
            }
            ConvertTo-AnalyzerGpoXml $Gpo $parsed $names $status
        }
        $completed = $true
    }
    finally {
        if ($drive -and $completed) {
            Remove-PSDrive -Name $drive.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
        }
        elseif ($drive) {
            try {
                Remove-PSDrive -Name $drive.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
            }
            catch {
                # Retain any pending error and the native cleanup diagnostic.
            }
        }
    }
}
