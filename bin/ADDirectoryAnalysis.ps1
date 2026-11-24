# Read-only directory assessment. No managed password values are requested.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
. (Join-Path $PSScriptRoot 'ADAccountControl.ps1')

# Hidden PowerShell fields serialize; the private .NET capsule has no properties.
if (-not ('ADAnalyzer.InternalState' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'ADConfiguration.cs') -ErrorAction Stop
}

function Get-ADAnalyzerDirectoryField {
    param(
        $InputObject,
        [string]$Name,
        $Default = $null

    )
    if ($null -eq $InputObject) {
        return $Default
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if (([Collections.IDictionary]$InputObject).Contains($Name)) {
            return $InputObject[$Name]
        }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }
    return $Default
}

function Get-ADAnalyzerDirectoryObservationField {
    param($Record, [string]$Name)

    # Preserve the original shape and the caller's PowerShell error scope.
    if ($null -eq $Record) {
        return $null
    }
    if ($Record -is [Collections.IDictionary]) {
        if (([Collections.IDictionary]$Record).Contains($Name)) {
            return , ($Record[$Name])
        }
        return $null
    }

    $property = $Record.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return , $property.Value
    }
    return $null
}

function ConvertTo-ADAnalyzerSid {
    param($Value)
    if ($null -eq $Value) {
        return $null
    }
    $sid = Get-ADAnalyzerDirectoryField $Value 'Value'
    if ($null -ne $sid) {
        return [string]$sid
    }
    return [string]$Value
}

function ConvertTo-ADAnalyzerDirectoryDate {
    param(
        $Value,
        [switch]$FileTime

    )
    if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) {
        return $null
    }
    try {
        if ($FileTime) {
            if ([long]$Value -le 0) {
                return $null
            }
            return [datetime]::FromFileTimeUtc([long]$Value)
        }
        return ([datetime]$Value).ToUniversalTime()
    }
    catch {
        return $null
    }
}

function Get-ADAnalyzerDirectoryTarget {
    param($Object)
    foreach ($name in @('DistinguishedName', 'SID', 'ObjectGuid', 'SamAccountName', 'Name')) {
        $value = Get-ADAnalyzerDirectoryField $Object $name
        if ($null -ne $value -and -not [string]::IsNullOrEmpty([string]$value)) {
            return [string]$value
        }
    }
    return 'Unknown'
}

function Test-ADAnalyzerClassificationAttribute {
    param([string]$Name)
    $Name -match '^[A-Za-z][A-Za-z0-9-]*$' -and -not (Test-ADAnalyzerSecretName $Name)
}

class ADAnalyzerMembershipIndexBuilder {
    [object] Build([object[]]$Groups) {
        $byDn = @{}
        $bySid = @{}
        foreach ($group in $Groups) {
            $dn = [string](Get-ADAnalyzerDirectoryField $group 'DistinguishedName')
            $sid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $group 'SID' (Get-ADAnalyzerDirectoryField $group 'objectSid'))
            if ($dn) {
                $byDn[$dn] = $group
            }
            if ($sid) {
                $bySid[$sid] = $group
            }
        }
        return [pscustomobject]@{
            ByDn = $byDn
            BySid = $bySid
        }
    }
}

class ADAnalyzerMembershipGraph {
    hidden [object]$State

    ADAnalyzerMembershipGraph() {
        $this.Initialize(@())
    }

    ADAnalyzerMembershipGraph([object[]]$Groups) {
        $this.Initialize($Groups)
    }

    hidden [void] Initialize([object[]]$Groups) {
        $snapshots = [Collections.Generic.List[object]]::new()
        foreach ($group in $Groups) {
            $parents = [Collections.Generic.List[string]]::new()
            foreach ($parent in @(Get-ADAnalyzerDirectoryField $group 'MemberOf' @())) {
                if ($parent) {
                    $parents.Add([string]$parent)
                }
            }

            $snapshots.Add([pscustomobject]@{
                    DistinguishedName = [string](Get-ADAnalyzerDirectoryField $group 'DistinguishedName')
                    SID = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $group 'SID' (Get-ADAnalyzerDirectoryField $group 'objectSid'))
                    MemberOf = $parents.ToArray()
                })
        }

        $builder = [ADAnalyzerMembershipIndexBuilder]::new()
        $index = $builder.Build($snapshots.ToArray())
        $this.State = [Activator]::CreateInstance(
            ('ADAnalyzer.InternalState' -as [type]),
            [object[]]@($index)
        )
    }

    # Compatibility indexes deliberately preserve the original group references.
    static [object] BuildIndex([object[]]$Groups) {
        $builder = [ADAnalyzerMembershipIndexBuilder]::new()
        return $builder.Build($Groups)
    }

    [object] Resolve([object]$Object) {
        return $this.Resolve($Object, '', @())
    }

    [object] Resolve([object]$Object, [string]$DomainSid) {
        return $this.Resolve($Object, $DomainSid, @())
    }

    [object] Resolve([object]$Object, [string]$DomainSid, [string[]]$PrivilegedSids) {
        return $this.ResolveUsingIndex($Object, $this.State.GetValue(), $DomainSid, $PrivilegedSids)
    }

    hidden [object] ResolveUsingIndex(
        [object]$Object,
        [object]$GroupIndex,
        [string]$DomainSid,
        [string[]]$PrivilegedSids
    ) {
        $byDn = $GroupIndex.ByDn
        $bySid = $GroupIndex.BySid
        $stack = [Collections.Generic.Stack[object]]::new()
        $direct = [System.Collections.Generic.List[string]]::new()
        $effective = [System.Collections.Generic.List[string]]::new()
        $unresolved = [System.Collections.Generic.List[string]]::new()
        $cycles = [System.Collections.Generic.List[string]]::new()
        $cycleSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $colors = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($parent in @(Get-ADAnalyzerDirectoryField $Object 'MemberOf' @())) {
            if ($parent) {
                $direct.Add([string]$parent)
            }
        }
        $primary = Get-ADAnalyzerDirectoryField $Object 'PrimaryGroupID'
        if ($null -ne $primary) {
            $objectSid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $Object 'SID' (Get-ADAnalyzerDirectoryField $Object 'objectSid'))
            $sidRoot = if ($objectSid -match '^S-\d-\d+(?:-\d+)+-\d+$') {
                $objectSid -replace '-\d+$', ''
            }
            else {
                $DomainSid
            }
            if ($sidRoot) {
                $identity = '{0}-{1}' -f $sidRoot, $primary
                $direct.Add($identity)
            }
            else {
                $unresolved.Add('PrimaryGroupID:' + $primary)
            }
        }
        for ($i = $direct.Count - 1; $i -ge 0; $i--) {
            $stack.Push([pscustomobject]@{
                    Identity = $direct[$i]
                    Exit = $false
                })
        }
        while ($stack.Count) {
            $item = $stack.Pop()
            if ($item.Exit) {
                $colors[$item.Canonical] = 2
                continue
            }
            $identity = [string]$item.Identity
            $group = if ($byDn.ContainsKey($identity)) {
                $byDn[$identity]
            }
            elseif ($bySid.ContainsKey($identity)) {
                $bySid[$identity]
            }
            else {
                $null
            }
            $sid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $group 'SID' (Get-ADAnalyzerDirectoryField $group 'objectSid'))
            $canonical = if ($sid) {
                $sid
            }
            else {
                $identity
            }
            if ($colors.ContainsKey($canonical)) {
                # Gray nodes are active ancestors; black nodes are complete.
                if ($colors[$canonical] -eq 1 -and $cycleSet.Add($canonical)) {
                    $cycles.Add($canonical)
                }
                continue
            }
            $colors[$canonical] = 1
            if ($null -eq $group) {
                if ($identity -match '^S-\d-') {
                    $effective.Add($identity)
                }
                $unresolved.Add($identity)
                $colors[$canonical] = 2
                continue
            }
            if ($sid) {
                $effective.Add($sid)
            }
            if (-not $sid) {
                $unresolved.Add($identity + ':SID')
            }
            $stack.Push([pscustomobject]@{
                    Canonical = $canonical
                    Exit = $true
                })
            $parents = @(Get-ADAnalyzerDirectoryField $group 'MemberOf' @())
            for ($i = $parents.Count - 1; $i -ge 0; $i--) {
                if ($parents[$i]) {
                    $stack.Push([pscustomobject]@{
                            Identity = [string]$parents[$i]
                            Exit = $false
                        })
                }
            }
        }
        $privileged = @($effective | Where-Object { $_ -in $PrivilegedSids })
        return [pscustomobject]@{
            DirectSids = @(
                $direct.ToArray() |
                    ForEach-Object {
                        if ($byDn.ContainsKey($_)) {
                            ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $byDn[$_] 'SID' (Get-ADAnalyzerDirectoryField $byDn[$_] 'objectSid'))
                        }
                        else {
                            $_
                        }
                    } |
                    Where-Object { $_ } |
                    Select-Object -Unique
            )
            EffectiveSids = $effective.ToArray()
            PrivilegedSids = $privileged
            IsPrivileged = $privileged.Count -gt 0
            Unresolved = @($unresolved.ToArray() | Select-Object -Unique)
            Cycles = @($cycles.ToArray() | Select-Object -Unique)
            ResolutionStatus = if ($unresolved.Count) {
                'Unknown'
            }
            else {
                'Complete'
            }
        }
    }
}

function New-ADAnalyzerMembershipIndex {
    param([object[]]$Groups = @())

    $builder = [ADAnalyzerMembershipIndexBuilder]::new()
    $builder.Build($Groups)
}

function Resolve-ADAnalyzerMembership {
    [CmdletBinding()]
    param(
        $Object,
        [object[]]$Groups = @(),
        [string]$DomainSid,
        [string[]]$PrivilegedSids = @(),
        $GroupIndex

    )

    if ($null -eq $GroupIndex) {
        $GroupIndex = New-ADAnalyzerMembershipIndex -Groups $Groups
    }

    $graph = [ADAnalyzerMembershipGraph]::new()
    $graph.ResolveUsingIndex($Object, $GroupIndex, $DomainSid, $PrivilegedSids)
}

class ADAnalyzerAccountClassifier {
    ADAnalyzerAccountClassifier() {
    }

    [object] Classify([object]$Object) {
        return $this.Classify($Object, $null, $null)
    }

    [object] Classify([object]$Object, [hashtable]$Profile) {
        return $this.Classify($Object, $Profile, $null)
    }

    [object] Classify(
        [object]$Object,
        [hashtable]$Profile,
        [object]$Membership
    ) {
        return $this.ClassifyObserved($Object, $Profile, $Membership, $null)
    }

    hidden [object] ClassifyObserved(
        [object]$Object,
        [hashtable]$Profile,
        [object]$Membership,
        [hashtable]$RawAttributes
    ) {
        $classification = Get-ADAnalyzerDirectoryField $Profile 'AccountClassification' @{}
        $evidence = [System.Collections.Generic.List[object]]::new()
        $invalidRules = [System.Collections.Generic.List[string]]::new()
        $objectClass = [string](Get-ADAnalyzerDirectoryField $Object 'DirectoryObjectClass')
        if ($objectClass -in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) {
            $evidence.Add([pscustomobject]@{
                    Type = 'Service'
                    Source = 'DirectoryObjectClass'
                    Value = $objectClass
                })
        }
        $dn = [string](Get-ADAnalyzerDirectoryField $Object 'DistinguishedName')
        foreach ($type in @('User', 'Service')) {
            foreach ($ou in @(Get-ADAnalyzerDirectoryField $classification ($type + 'OUs') @())) {
                if ($ou -and ($dn -ieq $ou -or $dn.EndsWith(',' + $ou, [StringComparison]::OrdinalIgnoreCase))) {
                    $evidence.Add([pscustomobject]@{
                            Type = $type
                            Source = 'OU'
                            Value = [string]$ou
                        })
                }
            }
            $identities = @(Get-ADAnalyzerDirectoryField $Object 'MemberOf' @())
            if ($Membership) {
                $identities += @($Membership.EffectiveSids)
            }
            foreach ($group in @(Get-ADAnalyzerDirectoryField $classification ($type + 'Groups') @())) {
                if ($group -and $group -in $identities) {
                    $evidence.Add([pscustomobject]@{
                            Type = $type
                            Source = 'Group'
                            Value = [string]$group
                        })
                }
            }
        }
        foreach ($rule in @(Get-ADAnalyzerDirectoryField $classification 'AttributeRules' @())) {
            $attribute = [string](Get-ADAnalyzerDirectoryField $rule 'Attribute')
            $type = [string](Get-ADAnalyzerDirectoryField $rule 'Type')
            if (-not $attribute -or $type -notin @('User', 'Service')) {
                continue
            }
            if (-not (Test-ADAnalyzerClassificationAttribute $attribute)) {
                $invalidRules.Add($attribute)
                continue
            }
            if ($null -ne $RawAttributes -and $RawAttributes.ContainsKey($attribute)) {
                $actual = Get-ADAnalyzerDirectoryField $RawAttributes $attribute
            }
            else {
                $actual = Get-ADAnalyzerDirectoryField $Object $attribute
            }
            $expected = Get-ADAnalyzerDirectoryField $rule 'Value'
            $matchType = Get-ADAnalyzerDirectoryField $rule 'Match' 'Equals'
            $matched = $false
            if ($matchType -eq 'Regex') {
                try {
                    $matched = [string]$actual -match [string]$expected
                }
                catch {
                    $matched = $false
                    $invalidRules.Add($attribute + ':Regex')
                }
            }
            else {
                $matched = $null -ne $actual -and [string]$actual -ieq [string]$expected
            }
            if ($matched) {
                $evidence.Add([pscustomobject]@{
                        Type = $type
                        Source = ('Attribute:' + $attribute)
                        Value = $actual
                    })
            }
        }
        $types = [Collections.Generic.List[string]]::new()
        foreach ($entry in $evidence) {
            if ($entry.Type -notin $types) {
                $types.Add($entry.Type)
            }
        }
        return [pscustomobject]@{
            Type = if ($types.Count -eq 1 -and -not $invalidRules.Count) {
                $types[0]
            }
            else {
                'Unknown'
            }
            Evidence = $evidence.ToArray()
            Conflicting = $types.Count -gt 1
            InvalidRules = $invalidRules.ToArray()
        }
    }
}

function Get-ADAnalyzerAccountType {
    [CmdletBinding()]
    param(
        $Object,
        [hashtable]$Profile,
        $Membership

    )
    $classifier = [ADAnalyzerAccountClassifier]::new()
    $classifier.Classify($Object, $Profile, $Membership)
}

function Invoke-ADAnalyzerDirectoryQuery {
    param(
        [string]$Command,
        [hashtable]$Parameters,
        [string]$Key,
        $Coverage,
        $Errors,
        [string]$Target,
        [string]$ExpectedDrive,
        [string]$ConnectionError

    )
    try {
        if ($ConnectionError) {
            throw $ConnectionError
        }
        if ($ExpectedDrive -and (Get-Location).Drive.Name -ne $ExpectedDrive) {
            $Coverage['DirectoryConnection'] = 'Unreadable'
            throw 'The owned AD PSDrive is no longer the active directory context'
        }
        $items = @(& $Command @Parameters -ErrorAction Stop)
        $Coverage[$Key] = 'Collected'
        return $items
    }
    catch {
        $Coverage[$Key] = 'Unreadable'
        $Errors.Add([pscustomobject]@{
                Collector = $Key
                Target = $Target
                Status = 'Unreadable'
                Message = $_.Exception.Message
                ExceptionType = $_.Exception.GetType().FullName
            }) > $null
    }
}

class ADAnalyzerDirectoryObjectProjector {
    ADAnalyzerDirectoryObjectProjector() {
    }

    [object] Project([object]$Record, [string]$Kind) {
        return $this.Project($Record, $Kind, @())
    }

    [object] Project([object]$Record, [string]$Kind, [string[]]$AdditionalProperties) {
        $ErrorActionPreference = 'Stop'
        $result = $this.BeginObject($Kind)
        foreach ($name in $this.StandardProperties()) {
            if ($Kind -eq 'User' -and $name -eq 'UserAccountControl') {
                $result[$name] = Get-ADAnalyzerDirectoryObservationField $Record $name
            }
            else {
                $result[$name] = Get-ADAnalyzerDirectoryField $Record $name
            }
        }
        $result['SID'] = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $Record 'SID')
        foreach ($name in @('BuildNumber', 'EsuStatus', 'EsuValidUntil') + $AdditionalProperties) {
            if (-not (Test-ADAnalyzerClassificationAttribute $name)) {
                continue
            }
            if ($name -notin 'ObjectClass', 'SID') {
                if ($Kind -eq 'User' -and $name -eq 'UserAccountControl') {
                    $result[$name] = Get-ADAnalyzerDirectoryObservationField $Record $name
                }
                else {
                    $result[$name] = Get-ADAnalyzerDirectoryField $Record $name
                }
                continue
            }
            $null = Get-ADAnalyzerDirectoryField $Record $name
        }
        $result['ObjectGuid'] = if ($result['ObjectGuid']) {
            [string]$result['ObjectGuid']
        }
        else {
            $null
        }
        $result['DirectoryObjectClass'] = [string](Get-ADAnalyzerDirectoryField $Record 'ObjectClass')
        foreach ($name in @('WhenChanged', 'WhenCreated', 'LastLogonDate', 'PasswordLastSet')) {
            $result[$name] = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record $name)
        }
        $result['PasswordNeverExpires'] = Get-ADAnalyzerDirectoryObservationField $Record 'PasswordNeverExpires'
        $result['SIDHistory'] = @(Get-ADAnalyzerDirectoryField $Record 'SIDHistory' @() | ForEach-Object { ConvertTo-ADAnalyzerSid $_ })
        $resultantDn = @(Get-ADAnalyzerDirectoryField $Record 'msDS-ResultantPSO' @())
        $result['ResultantPasswordPolicyDN'] = $this.ResultantPolicyDn($resultantDn)
        $result['AllowedToDelegateTo'] = @(Get-ADAnalyzerDirectoryField $Record 'msDS-AllowedToDelegateTo' @())
        $result['SupportedEncryptionTypes'] = Get-ADAnalyzerDirectoryField $Record 'msDS-SupportedEncryptionTypes'
        $result['Protected'] = if ($null -eq $result['ProtectedFromAccidentalDeletion']) {
            $null
        }
        else {
            [bool]$result['ProtectedFromAccidentalDeletion']
        }
        $projectedControl = $result['UserAccountControl']
        if ($Kind -eq 'User') {
            # Preserve the legacy cast and error scope without discarding the raw User observation.
            $projectedControl = $($projectedControl)
        }
        $uac = if ($null -ne $projectedControl) {
            [long]$projectedControl
        }
        else {
            0
        }
        $result['IsDomainController'] = $Kind -eq 'Computer' -and $this.HasControllerRole(@{
                UserAccountControl = $uac
                PrimaryGroupID = $result['PrimaryGroupID']
            })
        $descriptor = Get-ADAnalyzerDirectoryField $Record 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $result['ResourceBasedDelegation'] = @($this.ProjectAces($descriptor, [string]$result['DistinguishedName'], 'RBCD'))
        $result['LapsExpiration'] = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record 'msLAPS-PasswordExpirationTime') `
            -FileTime
        $result['LegacyLapsExpiration'] = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record 'ms-Mcs-AdmPwdExpirationTime') `
            -FileTime
        return $this.FinishObject($result, $null)
    }

    [object[]] ProjectAces([object]$Descriptor, [string]$Target, [string]$TargetType) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Descriptor) {
            return @()
        }
        if ($Descriptor -is [byte[]]) {
            $security = [System.DirectoryServices.ActiveDirectorySecurity]::new()
            $security.SetSecurityDescriptorBinaryForm($Descriptor)
            $Descriptor = $security
        }
        $access = if ($Descriptor.PSObject.Methods['GetAccessRules']) {
            $Descriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        }
        else {
            Get-ADAnalyzerDirectoryField $Descriptor 'Access' @()
        }
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($ace in $access) {
            $rows.Add($this.CreateAce(@{
                Target = $Target
                TargetType = $TargetType
                IdentitySid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $ace 'IdentityReference' (Get-ADAnalyzerDirectoryField $ace 'IdentitySid'))
                Rights = [string](Get-ADAnalyzerDirectoryField $ace 'ActiveDirectoryRights' (Get-ADAnalyzerDirectoryField $ace 'Rights'))
                AccessControlType = [string](Get-ADAnalyzerDirectoryField $ace 'AccessControlType')
                ObjectType = [string](Get-ADAnalyzerDirectoryField $ace 'ObjectType')
                InheritedObjectType = [string](Get-ADAnalyzerDirectoryField $ace 'InheritedObjectType')
                IsInherited = [bool](Get-ADAnalyzerDirectoryField $ace 'IsInherited' $false)
                PropagationFlags = [string](Get-ADAnalyzerDirectoryField $ace 'PropagationFlags' 'None')
                InheritanceType = [string](Get-ADAnalyzerDirectoryField $ace 'InheritanceType' 'None')
            }))
        }
        return $rows.ToArray()
    }

    hidden [string[]] StandardProperties() {
        return @(
            'ObjectGuid'
            'DistinguishedName'
            'SamAccountName'
            'Name'
            'Enabled'
            'AdminCount'
            'PrimaryGroupID'
            'IsCriticalSystemObject'
            'ProtectedFromAccidentalDeletion'
            'ServicePrincipalNames'
            'MemberOf'
            'Members'
            'ManagedBy'
            'DNSHostName'
            'OperatingSystem'
            'OperatingSystemVersion'
            'UserAccountControl'
            'TrustedForDelegation'
            'PrincipalsAllowedToDelegateToAccount'
            'PrincipalsAllowedToRetrieveManagedPassword'
            'ManagedPasswordIntervalInDays'
            'Description'
        )
    }

    hidden [Collections.Specialized.OrderedDictionary] BeginObject([string]$Kind) {
        return [ordered]@{
            ObjectClass = $Kind
        }
    }

    hidden [object] ResultantPolicyDn([object[]]$Candidates) {
        if ($Candidates.Count -eq 1 -and
            $Candidates[0] -is [string] -and
            -not [string]::IsNullOrWhiteSpace($Candidates[0])) {
            return $Candidates[0]
        }
        return $null
    }

    hidden [bool] HasControllerRole([hashtable]$Observed) {
        return ($Observed.UserAccountControl -band 8192) -ne 0 -or $Observed.PrimaryGroupID -in @(516, 521)
    }

    hidden [object] FinishObject(
        [Collections.Specialized.OrderedDictionary]$Result,
        [hashtable]$RawAttributes
    ) {
        if ($null -ne $RawAttributes) {
            $Result['_ClassificationAttributes'] = $RawAttributes
        }
        return [pscustomobject]$Result
    }

    hidden [object] CreateAce([hashtable]$Observed) {
        return [pscustomobject]@{
            Target = $Observed.Target
            TargetType = $Observed.TargetType
            IdentitySid = $Observed.IdentitySid
            Rights = $Observed.Rights
            AccessControlType = $Observed.AccessControlType
            ObjectType = $Observed.ObjectType
            InheritedObjectType = $Observed.InheritedObjectType
            IsInherited = $Observed.IsInherited
            PropagationFlags = $Observed.PropagationFlags
            InheritanceType = $Observed.InheritanceType
        }
    }
}

function Get-ADAnalyzerSecurityAces {
    param(
        $Descriptor,
        [string]$Target,
        [string]$TargetType

    )
    # Native observations and conversions keep the caller's error scope.
    $projector = [ADAnalyzerDirectoryObjectProjector]::new()
    if ($null -eq $Descriptor) {
        return
    }
    if ($Descriptor -is [byte[]]) {
        $security = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $security.SetSecurityDescriptorBinaryForm($Descriptor)
        $Descriptor = $security
    }
    $access = if ($Descriptor.PSObject.Methods['GetAccessRules']) {
        $Descriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    }
    else {
        Get-ADAnalyzerDirectoryField $Descriptor 'Access' @()
    }
    foreach ($ace in $access) {
        $projector.CreateAce(@{
            Target = $Target
            TargetType = $TargetType
            IdentitySid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $ace 'IdentityReference' (Get-ADAnalyzerDirectoryField $ace 'IdentitySid'))
            Rights = [string](Get-ADAnalyzerDirectoryField $ace 'ActiveDirectoryRights' (Get-ADAnalyzerDirectoryField $ace 'Rights'))
            AccessControlType = [string](Get-ADAnalyzerDirectoryField $ace 'AccessControlType')
            ObjectType = [string](Get-ADAnalyzerDirectoryField $ace 'ObjectType')
            InheritedObjectType = [string](Get-ADAnalyzerDirectoryField $ace 'InheritedObjectType')
            IsInherited = [bool](Get-ADAnalyzerDirectoryField $ace 'IsInherited' $false)
            PropagationFlags = [string](Get-ADAnalyzerDirectoryField $ace 'PropagationFlags' 'None')
            InheritanceType = [string](Get-ADAnalyzerDirectoryField $ace 'InheritanceType' 'None')
        })
    }
}

function ConvertTo-ADAnalyzerDirectoryObject {
    param(
        $Record,
        [string]$Kind,
        [string[]]$AdditionalProperties = @(),
        [switch]$PreserveClassificationInput

    )
    # Native observations and conversions keep the caller's error scope.
    $projector = [ADAnalyzerDirectoryObjectProjector]::new()
    $result = $projector.BeginObject($Kind)
    foreach ($name in $projector.StandardProperties()) {
        if ($Kind -eq 'User' -and $name -eq 'UserAccountControl') {
            $result[$name] = Get-ADAnalyzerDirectoryObservationField $Record $name
        }
        else {
            $result[$name] = Get-ADAnalyzerDirectoryField $Record $name
        }
    }
    $result['SID'] = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $Record 'SID')
    $rawAttributes = $null
    foreach ($name in @('BuildNumber', 'EsuStatus', 'EsuValidUntil') + $AdditionalProperties) {
        if (-not (Test-ADAnalyzerClassificationAttribute $name)) {
            continue
        }
        if ($name -notin 'ObjectClass', 'SID') {
            if ($Kind -eq 'User' -and $name -eq 'UserAccountControl') {
                $result[$name] = Get-ADAnalyzerDirectoryObservationField $Record $name
            }
            else {
                $result[$name] = Get-ADAnalyzerDirectoryField $Record $name
            }
            continue
        }
        if ($PreserveClassificationInput) {
            if ($null -eq $rawAttributes) {
                $rawAttributes = @{}
            }
            $rawAttributes[$name] = Get-ADAnalyzerDirectoryField $Record $name
        }
        else {
            $null = Get-ADAnalyzerDirectoryField $Record $name
        }
    }
    $result['ObjectGuid'] = if ($result['ObjectGuid']) {
        [string]$result['ObjectGuid']
    }
    else {
        $null
    }
    $result['DirectoryObjectClass'] = [string](Get-ADAnalyzerDirectoryField $Record 'ObjectClass')
    foreach ($name in @('WhenChanged', 'WhenCreated', 'LastLogonDate', 'PasswordLastSet')) {
        $result[$name] = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record $name)
    }
    $result['PasswordNeverExpires'] = Get-ADAnalyzerDirectoryObservationField $Record 'PasswordNeverExpires'
    $result['SIDHistory'] = @(Get-ADAnalyzerDirectoryField $Record 'SIDHistory' @() | ForEach-Object { ConvertTo-ADAnalyzerSid $_ })
    $resultantDn = @(Get-ADAnalyzerDirectoryField $Record 'msDS-ResultantPSO' @())
    $result['ResultantPasswordPolicyDN'] = $projector.ResultantPolicyDn($resultantDn)
    $result['AllowedToDelegateTo'] = @(Get-ADAnalyzerDirectoryField $Record 'msDS-AllowedToDelegateTo' @())
    $result['SupportedEncryptionTypes'] = Get-ADAnalyzerDirectoryField $Record 'msDS-SupportedEncryptionTypes'
    $result['Protected'] = if ($null -eq $result['ProtectedFromAccidentalDeletion']) {
        $null
    }
    else {
        [bool]$result['ProtectedFromAccidentalDeletion']
    }
    $projectedControl = $result['UserAccountControl']
    if ($Kind -eq 'User') {
        # Preserve the legacy cast and error scope without discarding the raw User observation.
        $projectedControl = $($projectedControl)
    }
    $uac = if ($null -ne $projectedControl) {
        [long]$projectedControl
    }
    else {
        0
    }
    $result['IsDomainController'] = $Kind -eq 'Computer' -and $projector.HasControllerRole(@{
            UserAccountControl = $uac
            PrimaryGroupID = $result['PrimaryGroupID']
        })
    $result['ResourceBasedDelegation'] = @(Get-ADAnalyzerSecurityAces (Get-ADAnalyzerDirectoryField $Record 'msDS-AllowedToActOnBehalfOfOtherIdentity') ([string]$result['DistinguishedName']) 'RBCD')
    $result['LapsExpiration'] = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record 'msLAPS-PasswordExpirationTime') `
        -FileTime
    $result['LegacyLapsExpiration'] = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $Record 'ms-Mcs-AdmPwdExpirationTime') `
        -FileTime
    $projector.FinishObject($result, $rawAttributes)
}

class ADAnalyzerHostCollectionTiming {
    hidden [uint32] $OperationTimeoutSeconds
    hidden [Diagnostics.Stopwatch] $Clock
    hidden [string] $Phase
    hidden [string] $Operation
    hidden [string] $LocalCleanup = 'NotAttempted'
    hidden [Collections.Generic.List[object]] $TimedOutOperations

    ADAnalyzerHostCollectionTiming([uint32]$OperationTimeoutSeconds) {
        $this.OperationTimeoutSeconds = $OperationTimeoutSeconds
        $this.Clock = [Diagnostics.Stopwatch]::new()
    }

    hidden [void] StartOperation([string]$Phase, [string]$Operation) {
        $this.Phase = $Phase
        $this.Operation = $Operation
        $this.Clock.Restart()
    }

    hidden [void] CompleteOperation() {
        $this.Clock.Reset()
    }

    hidden [bool] IsTimeout([Management.Automation.ErrorRecord]$Failure) {
        if ($Failure.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::OperationTimeout) {
            return $true
        }
        for ($cause = $Failure.Exception; $null -ne $cause; $cause = $cause.InnerException) {
            if ($cause -is [TimeoutException]) {
                return $true
            }
        }
        return $false
    }

    hidden [void] RecordFailure([Management.Automation.ErrorRecord]$Failure) {
        if (-not $this.Clock.IsRunning) {
            return
        }
        $this.Clock.Stop()
        if (-not $this.IsTimeout($Failure)) {
            return
        }
        if ($null -eq $this.TimedOutOperations) {
            $this.TimedOutOperations = [Collections.Generic.List[object]]::new()
        }
        $this.TimedOutOperations.Add([pscustomobject][ordered]@{
                Phase = $this.Phase
                Operation = $this.Operation
                Elapsed = $this.Clock.ElapsedMilliseconds
            })
    }

    hidden [bool] HasTimeouts() {
        return $null -ne $this.TimedOutOperations
    }

    hidden [void] RecordCleanup([bool]$ReportedErrors) {
        $this.LocalCleanup = if ($ReportedErrors) {
            'ReportedFailure'
        }
        else {
            'Completed'
        }
    }

    hidden [void] AddToReport([Collections.Specialized.OrderedDictionary]$Report) {
        if ($this.HasTimeouts()) {
            $Report['CollectionTiming'] = [pscustomobject][ordered]@{
                OperationTimeoutSeconds = $this.OperationTimeoutSeconds
                TimedOutOperations = $this.TimedOutOperations.ToArray()
                LocalCleanup = $this.LocalCleanup
                RemoteSettlement = 'Unknown'
            }
        }
    }
}

class ADAnalyzerHostCollector {
    ADAnalyzerHostCollector() {
    }

    [pscustomobject] Collect([string[]]$ComputerNames) {
        return $this.Collect($ComputerNames, [pscredential]::Empty, 30, $null)
    }

    [pscustomobject] Collect(
        [string[]]$ComputerNames,
        [pscredential]$Credential,
        [uint32]$TimeoutSeconds,
        [hashtable]$Profile
    ) {
        if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 3600) {
            throw [ArgumentOutOfRangeException]::new('TimeoutSeconds')
        }

        $profileType = [type]'ADAnalyzerProfile'
        $configuration = $profileType::new($Profile).ToHashtable()
        $plan = $this.CreatePlan($configuration)
        $hosts = [Collections.Generic.List[object]]::new()
        $errors = [Collections.Generic.List[object]]::new()
        foreach ($computer in $this.SelectComputers($ComputerNames)) {
            $hosts.Add($this.CollectHost($computer, $Credential, $TimeoutSeconds, $plan, $errors))
        }
        return [pscustomobject][ordered]@{
            Hosts = $hosts.ToArray()
            Errors = $errors.ToArray()
        }
    }

    hidden [string[]] SelectComputers([string[]]$ComputerNames) {
        return @($ComputerNames | Where-Object { $_ } | Select-Object -Unique)
    }

    hidden [pscustomobject] CreatePlan([hashtable]$Configuration) {
        $serviceNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $serviceFilters = [Collections.Generic.List[string]]::new()
        foreach ($name in @('Spooler', 'W32Time') + @($Configuration.Host.Services | ForEach-Object Name)) {
            if ($serviceNames.Add($name)) {
                $escaped = $name.Replace('\', '\\').Replace("'", "\'").Replace('"', '\"')
                $serviceFilters.Add("Name='$escaped'")
            }
        }

        $queries = @(
            @{
                Key = 'Services'
                ClassName = 'Win32_Service'
                Filter = ($serviceFilters -join ' OR ')
            },
            @{
                Key = 'OperatingSystem'
                ClassName = 'Win32_OperatingSystem'
            },
            @{
                Key = 'Patches'
                ClassName = 'Win32_QuickFixEngineering'
            },
            @{
                Key = 'Dns'
                ClassName = 'Win32_NetworkAdapterConfiguration'
                Filter = 'IPEnabled=True'
            },
            @{
                Key = 'Smb'
                ClassName = 'MSFT_SmbServerConfiguration'
                Namespace = 'root/Microsoft/Windows/SMB'
            }
        )
        $settings = [Collections.Generic.List[hashtable]]::new()
        $settings.Add(@{
                Path = 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
                Name = 'NtpServer'
                Method = 'GetStringValue'
                Type = 1
            })
        $settings.Add(@{
                Path = 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
                Name = 'Type'
                Method = 'GetStringValue'
                Type = 1
            })
        $settings.Add(@{
                Path = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
                Name = 'SMB1'
                Method = 'GetDWORDValue'
                Type = 4
            })
        foreach ($version in @('TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')) {
            foreach ($side in @('Client', 'Server')) {
                $settings.Add(@{
                        Path = ('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' + $version + '\' + $side)
                        Name = 'Enabled'
                        Method = 'GetDWORDValue'
                        Type = 4
                    })
            }
        }

        $seenSettings = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($setting in $settings) {
            $null = $seenSettings.Add($setting.Path + [char]0 + $setting.Name)
        }
        foreach ($rule in @($Configuration.Host.RegistryRules)) {
            if ($seenSettings.Add($rule.Key + [char]0 + $rule.ValueName)) {
                $settings.Add(@{
                        Path = $rule.Key
                        Name = $rule.ValueName
                        Type = $rule['Type']
                        Method = $null
                    })
            }
        }
        return [pscustomobject]@{
            Queries = $queries
            RegistrySettings = $settings.ToArray()
        }
    }

    hidden [Collections.Specialized.OrderedDictionary] CreateReport([string]$ComputerName) {
        return [ordered]@{
            ComputerName = $ComputerName
            Status = 'Unknown'
            Services = @()
            OperatingSystem = $null
            Patches = @()
            Dns = @()
            Smb = $null
            Registry = @()
            AuditPolicy = [pscustomobject]@{
                Status = 'Unknown'
                Reason = 'Effective audit policy is not available from this CIM inventory'
            }
            Certificates = [pscustomobject]@{
                Status = 'Unknown'
                Reason = 'Certificate validation requires explicit endpoints and trust policy'
            }
        }
    }

    hidden [hashtable] SessionArguments([string]$ComputerName, [pscredential]$Credential, [uint32]$TimeoutSeconds) {
        $parameters = @{
            ComputerName = $ComputerName
            OperationTimeoutSec = $TimeoutSeconds
            ErrorAction = 'Stop'
        }
        if ($null -ne $Credential -and $Credential -ne [pscredential]::Empty) {
            $parameters.Credential = $Credential
        }
        return $parameters
    }

    hidden [hashtable] QueryArguments([object]$Session, [hashtable]$Query, [uint32]$TimeoutSeconds) {
        $parameters = @{
            CimSession = $Session
            ClassName = $Query.ClassName
            OperationTimeoutSec = $TimeoutSeconds
            ErrorAction = 'Stop'
        }
        if ($Query.ContainsKey('Filter')) {
            $parameters.Filter = $Query.Filter
        }
        if ($Query.ContainsKey('Namespace')) {
            $parameters.Namespace = $Query.Namespace
        }
        return $parameters
    }

    hidden [hashtable] RegistryArguments(
        [object]$Session,
        [hashtable]$Setting,
        [string]$Method,
        [uint32]$TimeoutSeconds
    ) {
        $providerArguments = @{
            hDefKey = [uint32]2147483650
            sSubKeyName = $Setting.Path
        }
        if ($Method -ne 'EnumValues') {
            $providerArguments.sValueName = $Setting.Name
        }
        return @{
            CimSession = $Session
            Namespace = 'root/default'
            ClassName = 'StdRegProv'
            MethodName = $Method
            Arguments = $providerArguments
            OperationTimeoutSec = $TimeoutSeconds
            ErrorAction = 'Stop'
        }
    }

    hidden [hashtable] RegistryMetadataArguments(
        [hashtable]$TypeCache,
        [object]$Session,
        [hashtable]$Setting,
        [uint32]$TimeoutSeconds
    ) {
        if ($TypeCache.ContainsKey($Setting.Path)) {
            return $null
        }
        return $this.RegistryArguments($Session, $Setting, 'EnumValues', $TimeoutSeconds)
    }

    hidden [int] FindRegistryValue([object[]]$Names, [int]$TypeCount, [string]$Name) {
        for ($index = 0; $index -lt $Names.Count; $index++) {
            if ($Names[$index] -ieq $Name -and $index -lt $TypeCount) {
                return $index
            }
        }
        return -1
    }

    hidden [string] RegistryMethod([int]$Type) {
        switch ($Type) {
            1 {
                return 'GetStringValue'
            }
            2 {
                return 'GetExpandedStringValue'
            }
            3 {
                return 'GetBinaryValue'
            }
            4 {
                return 'GetDWORDValue'
            }
            7 {
                return 'GetMultiStringValue'
            }
            11 {
                return 'GetQWORDValue'
            }
        }
        return ''
    }

    hidden [bool] CanUseDeclaredRegistryType([hashtable]$Setting) {
        # StdRegProv can omit the metadata arrays when only the default value exists.
        return $Setting.Name -eq '' -and $null -ne $Setting.Type
    }

    hidden [string] RegistryValueProperty([object]$Type) {
        if ($Type -in 1, 2, 7) {
            return 'sValue'
        }
        return 'uValue'
    }

    hidden [bool] RegistryReturnCodeIs([object]$Value, [uint32]$Expected) {
        if ($Value -isnot [ValueType] -or $Value -is [Enum] -or [type]::GetTypeCode($Value.GetType()) -notin @(
                [TypeCode]::SByte,
                [TypeCode]::Byte,
                [TypeCode]::Int16,
                [TypeCode]::UInt16,
                [TypeCode]::Int32,
                [TypeCode]::UInt32,
                [TypeCode]::Int64,
                [TypeCode]::UInt64
            )) {
            return $false
        }
        return [decimal]$Value -eq $Expected
    }

    hidden [pscustomobject] RegistryObservation(
        [hashtable]$Setting,
        [object]$Type,
        [object]$Result
    ) {
        $returnCode = Get-ADAnalyzerDirectoryObservationField $Result 'ReturnValue'
        $status = 'Unknown'
        $value = $null
        if ($this.RegistryReturnCodeIs($returnCode, 0)) {
            $property = $this.RegistryValueProperty($Type)
            if ($Type -in 4, 11) {
                # DWORD and QWORD getters return their data separately from the status code.
                $value = Get-ADAnalyzerDirectoryObservationField $Result $property
                if ($null -ne $value) {
                    $status = 'Observed'
                }
            }
            else {
                $value = $Result.$property
                $status = 'Observed'
            }
        }
        return [pscustomobject]@{
            Path = $Setting.Path
            Name = $Setting.Name
            Type = $Type
            Status = $status
            Value = $value
            ReturnValue = $returnCode
        }
    }

    hidden [pscustomobject] RegistryFailure([hashtable]$Setting, [object]$Type, [string]$Message) {
        return [pscustomobject]@{
            Path = $Setting.Path
            Name = $Setting.Name
            Type = $Type
            Status = 'Unknown'
            Value = $null
            Message = $Message
        }
    }

    hidden [pscustomobject] CollectorFailure([string]$Collector, [string]$ComputerName, [string]$Message) {
        return [pscustomobject]@{
            Collector = $Collector
            Target = $ComputerName
            Status = 'Unknown'
            Message = $Message
        }
    }

    hidden [void] RecordCleanupFailures(
        [object]$Errors,
        [string]$ComputerName,
        [Management.Automation.ErrorRecord[]]$CleanupErrors
    ) {
        if ($null -eq $Errors) {
            return
        }

        foreach ($cleanupError in $CleanupErrors) {
            $failure = $this.CollectorFailure('Host.Cleanup', $ComputerName, $cleanupError.Exception.Message)
            [void]$Errors.Add($failure)
        }
    }

    hidden [void] CompleteReport(
        [Collections.Specialized.OrderedDictionary]$Report,
        [object[]]$Registry,
        [bool]$HasErrors
    ) {
        $Report['Registry'] = $Registry
        $Report['Status'] = if ($HasErrors) {
            'Partial'
        }
        else {
            'Observed'
        }
    }

    hidden [pscustomobject] CollectHost(
        [string]$ComputerName,
        [pscredential]$Credential,
        [uint32]$TimeoutSeconds,
        [pscustomobject]$Plan,
        [Collections.Generic.List[object]]$Errors
    ) {
        $session = $null
        $initialErrorCount = $Errors.Count
        $report = $this.CreateReport($ComputerName)
        $timing = [ADAnalyzerHostCollectionTiming]::new($TimeoutSeconds)
        try {
            $arguments = $this.SessionArguments($ComputerName, $Credential, $TimeoutSeconds)
            $timing.StartOperation('Session', 'New-CimSession')
            $session = New-CimSession @arguments
            $timing.CompleteOperation()
            foreach ($query in $Plan.Queries) {
                try {
                    $arguments = $this.QueryArguments($session, $query, $TimeoutSeconds)
                    $timing.StartOperation('Query', $query.ClassName)
                    $report[$query.Key] = @(Get-CimInstance @arguments)
                    $timing.CompleteOperation()
                }
                catch {
                    $timing.RecordFailure($_)
                    $Errors.Add($this.CollectorFailure(('Host.' + $query.Key), $ComputerName, $_.Exception.Message))
                }
            }
            $registry = $this.CollectRegistry($session, $Plan.RegistrySettings, $TimeoutSeconds, $timing)
            $this.CompleteReport($report, $registry, ($Errors.Count -gt $initialErrorCount -or $timing.HasTimeouts()))
        }
        catch {
            $timing.RecordFailure($_)
            $Errors.Add($this.CollectorFailure('Host', $ComputerName, $_.Exception.Message))
        }
        finally {
            if ($null -ne $session) {
                $cleanupErrors = $null
                Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue -ErrorVariable cleanupErrors
                $timing.RecordCleanup([bool]$cleanupErrors)
                if ($cleanupErrors) {
                    $this.RecordCleanupFailures($Errors, $ComputerName, $cleanupErrors)
                }
            }
        }
        $timing.AddToReport($report)
        return [pscustomobject]$report
    }

    hidden [object[]] CollectRegistry([object]$Session, [hashtable[]]$Settings, [uint32]$TimeoutSeconds) {
        $timing = [ADAnalyzerHostCollectionTiming]::new($TimeoutSeconds)
        return $this.CollectRegistry($Session, $Settings, $TimeoutSeconds, $timing)
    }

    hidden [object[]] CollectRegistry(
        [object]$Session,
        [hashtable[]]$Settings,
        [uint32]$TimeoutSeconds,
        [ADAnalyzerHostCollectionTiming]$Timing
    ) {
        $registry = [Collections.Generic.List[object]]::new()
        $typeCache = @{}
        foreach ($setting in $Settings) {
            $type = $setting.Type
            $method = $setting.Method
            try {
                if (-not $method) {
                    $arguments = $this.RegistryMetadataArguments($typeCache, $Session, $setting, $TimeoutSeconds)
                    if ($null -ne $arguments) {
                        $Timing.StartOperation('Registry', 'EnumValues')
                        $typeCache[$setting.Path] = Invoke-CimMethod @arguments
                        $Timing.CompleteOperation()
                    }
                    $metadata = $typeCache[$setting.Path]
                    $metadataCode = Get-ADAnalyzerDirectoryObservationField $metadata 'ReturnValue'
                    if (-not $this.RegistryReturnCodeIs($metadataCode, 0)) {
                        throw 'Registry value type metadata is unavailable'
                    }
                    $names = @($metadata.sNames)
                    $types = @($metadata.Types)
                    $index = $this.FindRegistryValue($names, $types.Count, $setting.Name)
                    if ($index -ge 0) {
                        $type = [int]$types[$index]
                    }
                    elseif (-not $this.CanUseDeclaredRegistryType($setting)) {
                        throw 'Registry value type is unavailable'
                    }
                    $method = $this.RegistryMethod([int]$type)
                    if (-not $method) {
                        throw 'Registry value type is unsupported'
                    }
                }

                $arguments = $this.RegistryArguments($Session, $setting, $method, $TimeoutSeconds)
                $Timing.StartOperation('Registry', $method)
                $value = Invoke-CimMethod @arguments
                $Timing.CompleteOperation()
                $registry.Add($this.RegistryObservation($setting, $type, $value))
            }
            catch {
                $Timing.RecordFailure($_)
                $registry.Add($this.RegistryFailure($setting, $type, $_.Exception.Message))
            }
        }
        return $registry.ToArray()
    }
}

function Get-ADAnalyzerHostData {
    param(
        [string[]]$ComputerNames,
        [pscredential]$Credential = [pscredential]::Empty,
        $Errors,
        [ValidateRange(1, 3600)][uint32]$TimeoutSeconds = 30,
        [hashtable]$Profile

    )
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $collector = [ADAnalyzerHostCollector]::new()
    $plan = $collector.CreatePlan($configuration)

    # Keep the native command sites and foreach scope for streaming and diagnostics.
    foreach ($computer in $collector.SelectComputers($ComputerNames)) {
        $session = $null
        $initialErrorCount = $Errors.Count
        $data = $collector.CreateReport($computer)
        $timing = [ADAnalyzerHostCollectionTiming]::new($TimeoutSeconds)
        try {
            $arguments = $collector.SessionArguments($computer, $Credential, $TimeoutSeconds)
            $timing.StartOperation('Session', 'New-CimSession')
            $session = New-CimSession @arguments
            $timing.CompleteOperation()
            foreach ($query in $plan.Queries) {
                try {
                    $splat = $collector.QueryArguments($session, $query, $TimeoutSeconds)
                    $timing.StartOperation('Query', $query.ClassName)
                    $data[$query.Key] = @(Get-CimInstance @splat)
                    $timing.CompleteOperation()
                }
                catch {
                    $timing.RecordFailure($_)
                    $Errors.Add($collector.CollectorFailure(('Host.' + $query.Key), $computer, $_.Exception.Message)) > $null
                }
            }

            $registry = [Collections.Generic.List[object]]::new()
            $typeCache = @{}
            foreach ($setting in $plan.RegistrySettings) {
                $type = $setting.Type
                $method = $setting.Method
                try {
                    if (-not $method) {
                        $splat = $collector.RegistryMetadataArguments($typeCache, $session, $setting, $TimeoutSeconds)
                        if ($null -ne $splat) {
                            $timing.StartOperation('Registry', 'EnumValues')
                            $typeCache[$setting.Path] = Invoke-CimMethod @splat
                            $timing.CompleteOperation()
                        }
                        $metadata = $typeCache[$setting.Path]
                        $metadataCode = Get-ADAnalyzerDirectoryObservationField $metadata 'ReturnValue'
                        if (-not $collector.RegistryReturnCodeIs($metadataCode, 0)) {
                            throw 'Registry value type metadata is unavailable'
                        }
                        $names = @($metadata.sNames)
                        $types = @($metadata.Types)
                        $index = $collector.FindRegistryValue($names, $types.Count, $setting.Name)
                        if ($index -ge 0) {
                            $type = [int]$types[$index]
                        }
                        elseif (-not $collector.CanUseDeclaredRegistryType($setting)) {
                            throw 'Registry value type is unavailable'
                        }
                        $method = $collector.RegistryMethod([int]$type)
                        if (-not $method) {
                            throw 'Registry value type is unsupported'
                        }
                    }

                    $splat = $collector.RegistryArguments($session, $setting, $method, $TimeoutSeconds)
                    $timing.StartOperation('Registry', $method)
                    $value = Invoke-CimMethod @splat
                    $timing.CompleteOperation()
                    $registry.Add($collector.RegistryObservation($setting, $type, $value))
                }
                catch {
                    $timing.RecordFailure($_)
                    $registry.Add($collector.RegistryFailure($setting, $type, $_.Exception.Message))
                }
            }
            $collector.CompleteReport($data, $registry.ToArray(), ($Errors.Count -gt $initialErrorCount -or $timing.HasTimeouts()))
        }
        catch {
            $timing.RecordFailure($_)
            $Errors.Add($collector.CollectorFailure('Host', $computer, $_.Exception.Message)) > $null
        }
        finally {
            if ($null -ne $session) {
                $cleanupErrors = $null
                Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue -ErrorVariable cleanupErrors
                $timing.RecordCleanup([bool]$cleanupErrors)
                if ($cleanupErrors) {
                    $collector.RecordCleanupFailures($Errors, $computer, $cleanupErrors)
                }
            }
        }
        $timing.AddToReport($data)
        [pscustomobject]$data
    }
}

class ADAnalyzerDirectoryCollector {
    ADAnalyzerDirectoryCollector() {
    }

    [object] Collect([object]$Context, [hashtable]$Profile) {
        $ErrorActionPreference = 'Stop'
        $collector = $this
        $connectionMode = $collector.ResolveMode(
            (Get-ADAnalyzerDirectoryField (Get-ADAnalyzerDirectoryField $Profile 'Analysis' @{}) 'DirectoryConnection' 'PSDrive')
        )
        if (-not $connectionMode) {
            throw 'Analysis.DirectoryConnection must be PSDrive or Direct'
        }
        $server = [string](Get-ADAnalyzerDirectoryField $Context 'Server')
        if ([string]::IsNullOrWhiteSpace($server)) {
            $server = [string](Get-ADAnalyzerDirectoryField $Context 'Domain')
        }
        if ([string]::IsNullOrWhiteSpace($server)) {
            throw 'Context.Server or Context.Domain is required'
        }
        $credential = Get-ADAnalyzerDirectoryField $Context 'Credential'
        $common = @{
            Server = $server
        }
        if ($null -ne $credential -and $credential -ne [pscredential]::Empty) {
            $common['Credential'] = $credential
        }
        $observation = Get-ADAnalyzerDirectoryObservation
        $providerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        $capabilities = $provider.ExportedCmdlets
        foreach ($name in $collector.RequiredCommands()) {
            if (-not $capabilities -or $capabilities[$name] -isnot [Management.Automation.CommandInfo]) {
                throw ('The bundled Active Directory provider did not export ' + $name)
            }
        }

        $coverage = [ordered]@{}
        $errors = [System.Collections.Generic.List[object]]::new()
        $expectedDrive = $null
        $connectionError = $null
        $query = {
            param(
                $Command,
                $Arguments,
                $Key
            )

            $splat = @{} + $common + $Arguments
            $collector.ObserveQuery(
                $capabilities[$Command],
                $splat,
                $Key,
                $coverage,
                $errors,
                $server,
                $expectedDrive,
                $connectionError
            )
        }
        $root = @(& $query 'Get-ADRootDSE' @{} 'RootDSE') | Select-Object -First 1
        $domainIdentity = [string](Get-ADAnalyzerDirectoryField $Context 'Domain')
        if ([string]::IsNullOrWhiteSpace($domainIdentity)) {
            $domainIdentity = [string](Get-ADAnalyzerDirectoryField $root 'DefaultNamingContext' $server)
        }
        $domain = @(& $query 'Get-ADDomain' @{
                Identity = $domainIdentity
            } 'Domain') | Select-Object -First 1
        $domainDn = [string](Get-ADAnalyzerDirectoryField $domain 'DistinguishedName' (Get-ADAnalyzerDirectoryField $root 'DefaultNamingContext'))
        $domainSid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $domain 'DomainSID')

        $drive = $null
        $previousLocation = $null
        $primaryError = $null
        $restorationError = $null
        $removalError = $null
        $result = $null
        $connectionStatus = 'Direct'
        $coverage['DirectoryConnection'] = 'NotConfigured'
        . $observation
        if ($null -ne $primaryError) {
            if ($null -ne $restorationError) {
                $primaryError.Exception.Data['ADAnalyzerLocationRestorationError'] = $restorationError.Exception.Message
            }
            if ($null -ne $removalError) {
                $primaryError.Exception.Data['ADAnalyzerDriveRemovalError'] = $removalError.Exception.Message
            }
            throw $primaryError
        }
        if ($null -ne $restorationError) {
            if ($null -ne $removalError) {
                $restorationError.Exception.Data['ADAnalyzerDriveRemovalError'] = $removalError.Exception.Message
            }
            throw $restorationError
        }
        if ($null -ne $removalError) {
            throw $removalError
        }
        return $result
    }

    hidden [object[]] ObserveQuery(
        [Management.Automation.CommandInfo]$Capability,
        [hashtable]$Parameters,
        [string]$Key,
        [System.Collections.IDictionary]$Coverage,
        [System.Collections.Generic.List[object]]$Errors,
        [string]$Server,
        [string]$ExpectedDrive,
        [string]$ConnectionError
    ) {
        try {
            if ($ConnectionError) {
                throw $ConnectionError
            }
            if ($ExpectedDrive -and (Get-Location).Drive.Name -ne $ExpectedDrive) {
                $Coverage['DirectoryConnection'] = 'Unreadable'
                throw 'The owned AD PSDrive is no longer the active directory context'
            }
            $items = @(& $Capability @Parameters -ErrorAction Stop)
            $Coverage[$Key] = 'Collected'
            return $items
        }
        catch {
            $Coverage[$Key] = 'Unreadable'
            $Errors.Add([pscustomobject]@{
                    Collector = $Key
                    Target = $Server
                    Status = 'Unreadable'
                    Message = $_.Exception.Message
                    ExceptionType = $_.Exception.GetType().FullName
                })
            return @()
        }
    }

    hidden [string[]] RequiredCommands() {
        return @(
            'Get-ADRootDSE'
            'Get-ADDomain'
            'Get-ADForest'
            'Get-ADObject'
            'Get-ADUser'
            'Get-ADComputer'
            'Get-ADGroup'
            'Get-ADTrust'
            'Get-ADDomainController'
            'Get-ADServiceAccount'
            'Get-ADDefaultDomainPasswordPolicy'
            'Get-ADFineGrainedPasswordPolicy'
            'Get-ADOptionalFeature'
            'Get-ADUserResultantPasswordPolicy'
            'Get-ADOrganizationalUnit'
        )
    }

    hidden [string] ResolveMode([object]$Mode) {
        if ($Mode -isnot [string] -or $Mode -notin 'PSDrive', 'Direct') {
            return ''
        }
        if ($Mode -ieq 'PSDrive') {
            return 'PSDrive'
        }
        return 'Direct'
    }

    hidden [hashtable] CreateDriveParameters(
        [string]$Name,
        [string]$Root,
        [hashtable]$Connection
    ) {
        $parameters = @{
            Name = $Name
            PSProvider = 'ActiveDirectory'
            Root = $Root
            Server = $Connection.Server
            Scope = 'Local'
            ErrorAction = 'Stop'
            WhatIf = $false
            Confirm = $false
        }
        if ($Connection.ContainsKey('Credential')) {
            $parameters.Credential = $Connection.Credential
        }
        return $parameters
    }

    hidden [object] FeatureSchemaRequest([string]$SchemaDn, [System.Collections.IDictionary]$Coverage) {
        if (-not $SchemaDn) {
            $Coverage['FeatureSchema'] = 'Unreadable'
            return $null
        }
        # Query only schema names and GUIDs. Never request managed-password values.
        $featureNames = @(
            'msLAPS-PasswordExpirationTime'
            'ms-Mcs-AdmPwdExpirationTime'
            'msLAPS-Password'
            'msLAPS-EncryptedPassword'
            'ms-Mcs-AdmPwd'
            'msDS-AllowedToActOnBehalfOfOtherIdentity'
            'msDS-GroupMSAMembership'
            'msDS-ResultantPSO'
        )
        $clauses = ($featureNames | ForEach-Object { '(lDAPDisplayName=' + $_ + ')' }) -join ''
        return [pscustomobject]@{
            Command = 'Get-ADObject'
            Key = 'FeatureSchema'
            Arguments = @{
                SearchBase = $SchemaDn
                LDAPFilter = ('(|' + $clauses + ')')
                Properties = @('lDAPDisplayName', 'schemaIDGUID')
            }
        }
    }

    hidden [object] ForestRootRequest([string]$ForestRoot, [object]$DomainDns) {
        if (-not $ForestRoot -or $ForestRoot -ieq $DomainDns) {
            return $null
        }
        return [pscustomobject]@{
            Command = 'Get-ADDomain'
            Key = 'ForestRootDomain'
            Arguments = @{
                Identity = $ForestRoot
            }
        }
    }

    hidden [object] AccountPlan(
        [string]$SearchBase,
        [string]$DomainDn,
        [object[]]$Available,
        [hashtable]$Profile,
        [System.Collections.IDictionary]$Coverage,
        [System.Collections.Generic.List[object]]$Errors,
        [string]$Server
    ) {
        $userProperties = @(
            'ObjectGuid'
            'SID'
            'SIDHistory'
            'SamAccountName'
            'Enabled'
            'WhenChanged'
            'WhenCreated'
            'LastLogonDate'
            'PasswordLastSet'
            'PasswordNeverExpires'
            'AdminCount'
            'IsCriticalSystemObject'
            'MemberOf'
            'PrimaryGroupID'
            'ServicePrincipalNames'
            'UserAccountControl'
            'ProtectedFromAccidentalDeletion'
            'msDS-AllowedToDelegateTo'
            'msDS-SupportedEncryptionTypes'
            'Description'
        )
        $computerProperties = @(
            'ObjectGuid'
            'SID'
            'SIDHistory'
            'SamAccountName'
            'Enabled'
            'WhenChanged'
            'WhenCreated'
            'LastLogonDate'
            'PasswordLastSet'
            'AdminCount'
            'MemberOf'
            'PrimaryGroupID'
            'UserAccountControl'
            'ServicePrincipalNames'
            'TrustedForDelegation'
            'IsCriticalSystemObject'
            'ProtectedFromAccidentalDeletion'
            'OperatingSystem'
            'OperatingSystemVersion'
            'DNSHostName'
            'msDS-AllowedToDelegateTo'
            'msDS-SupportedEncryptionTypes'
        )
        $classificationAttributes = @()
        $classification = Get-ADAnalyzerDirectoryField $Profile 'AccountClassification' @{}
        foreach ($rule in @(Get-ADAnalyzerDirectoryField $classification 'AttributeRules' @())) {
            $attribute = [string](Get-ADAnalyzerDirectoryField $rule 'Attribute')
            if (Test-ADAnalyzerClassificationAttribute $attribute) {
                $classificationAttributes += $attribute
            }
            else {
                $Errors.Add([pscustomobject]@{
                        Collector = 'AccountClassification'
                        Target = $Server
                        Status = 'Invalid'
                        Message = ('Unsafe or invalid classification attribute: ' + $attribute)
                    })
            }
        }
        $classificationAttributes = @($classificationAttributes | Select-Object -Unique)
        $userProperties = @($userProperties + $classificationAttributes | Select-Object -Unique)
        $resultantPsoAvailable = $Coverage['FeatureSchema'] -eq 'Collected' -and 'msDS-ResultantPSO' -in $Available
        if ($resultantPsoAvailable) {
            $userProperties += 'msDS-ResultantPSO'
        }
        $computerProperties = @($computerProperties + $classificationAttributes | Select-Object -Unique)
        foreach ($attribute in @(
                'msLAPS-PasswordExpirationTime'
                'ms-Mcs-AdmPwdExpirationTime'
                'msDS-AllowedToActOnBehalfOfOtherIdentity'
            )) {
            if ($attribute -in $Available) {
                $computerProperties += $attribute
                if ($attribute -eq 'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                    $userProperties += $attribute
                }
            }
        }
        $userArgs = @{
            Filter = '*'
            Properties = $userProperties
        }
        $computerArgs = @{
            Filter = '*'
            Properties = $computerProperties
        }
        if ($SearchBase) {
            $userArgs.SearchBase = $SearchBase
            $computerArgs.SearchBase = $SearchBase
        }

        # Membership needs domain-wide groups even when account scanning is OU-scoped.
        $groupArgs = @{
            Filter = '*'
            Properties = @(
                'SID'
                'ObjectGuid'
                'MemberOf'
                'Members'
                'PrimaryGroupID'
                'AdminCount'
                'ProtectedFromAccidentalDeletion'
                'ManagedBy'
            )
        }
        $serviceArgs = @{
            Filter = '*'
            Properties = @(
                'SID'
                'ObjectGuid'
                'SIDHistory'
                'Enabled'
                'AdminCount'
                'IsCriticalSystemObject'
                'UserAccountControl'
                'MemberOf'
                'PrimaryGroupID'
                'ServicePrincipalNames'
                'PrincipalsAllowedToRetrieveManagedPassword'
                'ManagedPasswordIntervalInDays'
                'DNSHostName'
                'msDS-SupportedEncryptionTypes'
                'WhenChanged'
                'WhenCreated'
                'ProtectedFromAccidentalDeletion'
            )
        }
        $serviceArgs.Properties = @($serviceArgs.Properties + $classificationAttributes | Select-Object -Unique)
        if ($DomainDn) {
            $groupArgs.SearchBase = $DomainDn
            $serviceArgs.SearchBase = $DomainDn
        }
        return [pscustomobject]@{
            UserArguments = $userArgs
            ComputerArguments = $computerArgs
            GroupArguments = $groupArgs
            TrustArguments = @{
                Filter = '*'
                Properties = @(
                    'SIDFilteringForestAware'
                    'SIDFilteringQuarantined'
                    'SelectiveAuthentication'
                    'TGTDelegation'
                    'ForestTransitive'
                    'IntraForest'
                    'Direction'
                    'TrustType'
                    'Source'
                    'Target'
                )
            }
            ControllerArguments = @{
                Filter = '*'
            }
            ServiceArguments = $serviceArgs
            AdditionalProperties = $classificationAttributes
            PreserveClassificationInput = 'ObjectClass' -in $classificationAttributes -or 'SID' -in $classificationAttributes
            ResultantPsoAvailable = $resultantPsoAvailable
        }
    }

    hidden [object] DomainPolicyPlan([string]$DomainDn, [System.Collections.IDictionary]$Coverage) {
        if (-not $DomainDn) {
            foreach ($key in @('DomainSettings', 'DefaultPasswordPolicy', 'FineGrainedPasswordPolicies', 'OptionalFeatures')) {
                $Coverage[$key] = 'Unreadable'
            }
            return $null
        }
        return [pscustomobject]@{
            SettingsArguments = @{
                Identity = $DomainDn
                Properties = @('ms-DS-MachineAccountQuota', 'msDS-Behavior-Version')
            }
            DefaultArguments = @{
                Identity = $DomainDn
            }
            FineGrainedArguments = @{
                Filter = '*'
                Properties = @(
                    'AppliesTo'
                    'Precedence'
                    'MinPasswordLength'
                    'PasswordHistoryCount'
                    'ComplexityEnabled'
                    'ReversibleEncryptionEnabled'
                    'MaxPasswordAge'
                    'MinPasswordAge'
                    'LockoutThreshold'
                    'LockoutDuration'
                    'LockoutObservationWindow'
                )
            }
            OptionalArguments = @{
                Filter = '*'
                Properties = @('EnabledScopes', 'FeatureGUID')
            }
        }
    }

    hidden [object] ClassifyAccounts(
        [object[]]$Users,
        [object[]]$Computers,
        [object[]]$Services,
        [object[]]$Groups,
        [string]$DomainSid,
        [string]$RootDomainSid,
        [hashtable]$Profile,
        [System.Collections.IDictionary]$Coverage,
        [bool]$PreserveClassificationInput
    ) {
        $serviceIds = @($services | ForEach-Object { if ($_.SID) {
                    $_.SID
                }
                else {
                    $_.DistinguishedName
                } })
        $computers = @($computers | Where-Object { $(if ($_.SID) {
                        $_.SID
                    }
                    else {
                        $_.DistinguishedName
                    }) -notin $serviceIds })
        $policy = Get-ADAnalyzerDirectoryField $Profile 'Policy' @{}
        $privilegedSids = @(Get-ADAnalyzerPrivilegedSids -DomainSid $domainSid -RootDomainSid $rootDomainSid -Profile $Profile)
        foreach ($sid in @(Get-ADAnalyzerDirectoryField $policy 'PrivilegedSids' @())) {
            $expanded = ([string]$sid).Replace('{DomainSid}', [string]$domainSid).Replace('{RootDomainSid}', [string]$rootDomainSid)
            if ($expanded) {
                $privilegedSids += $expanded
            }
        }
        $membershipGraph = [ADAnalyzerMembershipGraph]::new($groups)
        $accountClassifier = [ADAnalyzerAccountClassifier]::new()
        foreach ($object in @($users) + @($computers) + @($services)) {
            $rawAttributes = $null
            if ($preserveClassificationInput) {
                $rawAttributes = Get-ADAnalyzerDirectoryField $object '_ClassificationAttributes'
                $object.PSObject.Properties.Remove('_ClassificationAttributes')
            }
            $sourceKey = if ($object.ObjectClass -eq 'User') {
                'Users'
            }
            elseif ($object.ObjectClass -eq 'Computer') {
                'Computers'
            }
            else {
                'ServiceAccounts'
            }
            $safetyStatus = 'Unknown'
            if ($coverage[$sourceKey] -eq 'Collected') {
                # Unset optional schema flags have defined defaults only after an explicit successful query.
                if ($null -eq $object.AdminCount) {
                    $object.AdminCount = 0
                }
                if ($null -eq $object.IsCriticalSystemObject) {
                    $object.IsCriticalSystemObject = $false
                }
                if ($object.SID -and
                    $null -ne $object.UserAccountControl -and
                    $null -ne $object.PrimaryGroupID -and
                    $null -ne $object.ProtectedFromAccidentalDeletion) {
                    $safetyStatus = 'Collected'
                }
            }
            $object | Add-Member NoteProperty SafetyMetadataStatus $safetyStatus -Force
            $membership = $membershipGraph.Resolve($object, $domainSid, $privilegedSids)
            $type = $accountClassifier.ClassifyObserved($object, $Profile, $membership, $rawAttributes)
            $object | Add-Member NoteProperty TransitiveGroups $membership.EffectiveSids -Force
            $object | Add-Member NoteProperty Membership $membership -Force
            $object | Add-Member NoteProperty Privileged $membership.IsPrivileged -Force
            $complete = $coverage['Groups'] -eq 'Collected' -and
            $membership.ResolutionStatus -eq 'Complete' -and
            $object.SID -and
            $null -ne $object.PrimaryGroupID
            $object | Add-Member NoteProperty PrivilegeResolutionStatus $(if ($complete) {
                    'Complete'
                }
                else {
                    'Unknown'
                }) -Force
            $object | Add-Member NoteProperty AccountType $type.Type -Force
            $object | Add-Member NoteProperty AccountClassification $type -Force
            $object | Add-Member NoteProperty DelegationSchemaStatus $coverage['FeatureSchema'] -Force
        }
        return [pscustomobject]@{
            Computers = $computers
            PrivilegedSids = $privilegedSids
        }
    }

    hidden [Collections.Generic.Dictionary[string, object]] BuildResultantPolicyIndex(
        [bool]$ResultantPsoAvailable,
        [Collections.IDictionary]$Coverage,
        [object[]]$FineGrained
    ) {
        $index = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        if (-not $ResultantPsoAvailable -or $Coverage['FineGrainedPasswordPolicies'] -ne 'Collected') {
            return $index
        }

        $requiredFields = @(
            'MinPasswordLength'
            'PasswordHistoryCount'
            'ComplexityEnabled'
            'ReversibleEncryptionEnabled'
            'LockoutThreshold'
            'LockoutDuration'
            'LockoutObservationWindow'
            'MinPasswordAge'
            'MaxPasswordAge'
        )
        foreach ($pso in $FineGrained) {
            $dn = Get-ADAnalyzerDirectoryField $pso 'DistinguishedName'
            if ($dn -isnot [string] -or [string]::IsNullOrWhiteSpace($dn)) {
                continue
            }
            if ($index.ContainsKey($dn)) {
                $index[$dn].Count++
                continue
            }
            $complete = $true
            foreach ($field in $requiredFields) {
                if ($null -eq (Get-ADAnalyzerDirectoryField $pso $field)) {
                    $complete = $false
                    break
                }
            }
            $index[$dn] = [pscustomobject]@{
                Policy = $pso
                Count = 1
                Complete = $complete
            }
        }
        return $index
    }

    hidden [pscustomobject] PlanResultantPolicy(
        [object]$User,
        [Collections.Generic.Dictionary[string, object]]$Index,
        [Collections.IDictionary]$Coverage
    ) {
        $key = 'ResultantPasswordPolicy:' + $User.DistinguishedName
        # Only a positive server-computed association can select cached policy.
        # An absent attribute can also mean unreadable and requires the dedicated query.
        $dn = $User.ResultantPasswordPolicyDN
        if ($dn -and $Index.ContainsKey($dn) -and $Index[$dn].Count -eq 1 -and $Index[$dn].Complete) {
            $Coverage[$key] = 'Collected'
            return [pscustomobject]@{
                Key = $key
                Arguments = $null
                CachedPolicy = $Index[$dn].Policy
            }
        }
        return [pscustomobject]@{
            Key = $key
            Arguments = @{
                Identity = $User.DistinguishedName
            }
            CachedPolicy = $null
        }
    }

    hidden [pscustomobject] CreateResultantPolicyRecord(
        [object]$Target,
        [object]$Effective,
        [object]$DefaultPolicy,
        [object]$Status
    ) {
        return [pscustomobject]@{
            Target = $Target
            Policy = if ($Effective) {
                $Effective
            }
            else {
                $DefaultPolicy
            }
            Source = if ($Effective) {
                'FineGrained'
            }
            else {
                'DefaultDomain'
            }
            Status = $Status
        }
    }

    hidden [void] CompleteResultantPolicyCoverage(
        [Collections.IDictionary]$Coverage,
        [Collections.Generic.List[object]]$Resultant
    ) {
        $Coverage['ResultantPasswordPolicies'] = if (@($Resultant | Where-Object Status -ne 'Collected').Count) {
            'Partial'
        }
        elseif ($Coverage['Users'] -eq 'Collected') {
            'Collected'
        }
        else {
            'Unreadable'
        }
    }

    hidden [pscustomobject] PlanAcl(
        [bool]$IncludeAcl,
        [string]$DomainDn,
        [string]$SchemaDn,
        [string]$SearchBase
    ) {
        $plan = [pscustomobject]@{
            IncludeAcl = $IncludeAcl
            Enabled = [bool]($IncludeAcl -and $DomainDn)
            GuidMap = @{}
            Entries = [Collections.Generic.List[object]]::new()
            Observations = [Collections.Generic.List[object]]::new()
            Targets = [Collections.Generic.List[object]]::new()
            SchemaArguments = $null
            OuArguments = $null
            GpoArguments = $null
        }
        if ($plan.Enabled) {
            if ($SchemaDn) {
                $plan.SchemaArguments = @{
                    SearchBase = $SchemaDn
                    LDAPFilter = '(|(objectClass=attributeSchema)(objectClass=classSchema))'
                    Properties = @('lDAPDisplayName', 'schemaIDGUID')
                }
            }
            $plan.OuArguments = @{
                Filter = '*'
                SearchBase = if ($SearchBase) {
                    $SearchBase
                }
                else {
                    $DomainDn
                }
            }
            $plan.GpoArguments = @{
                SearchBase = ('CN=Policies,CN=System,' + $DomainDn)
                LDAPFilter = '(objectClass=groupPolicyContainer)'
                Properties = @('displayName')
            }
        }
        return $plan
    }

    hidden [hashtable] PlanAclExtendedRights([string]$ConfigurationDn) {
        if (-not $ConfigurationDn) {
            return $null
        }
        return @{
            SearchBase = ('CN=Extended-Rights,' + $ConfigurationDn)
            LDAPFilter = '(objectClass=controlAccessRight)'
            Properties = @('rightsGuid', 'displayName')
        }
    }

    hidden [void] AddAclGuidLabel([hashtable]$GuidMap, [string]$Key, [string]$Label) {
        $GuidMap[$Key] = $Label
    }

    hidden [pscustomobject] CreateAclSchemaError([string]$SchemaDn) {
        return [pscustomobject]@{
            Collector = 'AclSchema'
            Target = $SchemaDn
            Status = 'Unknown'
            Message = 'Unparseable schema GUID'
        }
    }

    hidden [void] AddAclBaseTargets([Collections.Generic.List[object]]$Targets, [string]$DomainDn) {
        $this.AddAclTarget($Targets, $DomainDn, 'DomainRoot')
        $this.AddAclTarget($Targets, ('CN=AdminSDHolder,CN=System,' + $DomainDn), 'AdminSDHolder')
    }

    hidden [void] AddAclTarget([Collections.Generic.List[object]]$Targets, [string]$Dn, [string]$Kind) {
        $Targets.Add([pscustomobject]@{
                DN = $Dn
                Type = $Kind
            })
    }

    hidden [pscustomobject] PlanAclDescriptor([pscustomobject]$Target) {
        return [pscustomobject]@{
            Key = ('Acl:' + $Target.DN)
            Arguments = @{
                Identity = $Target.DN
                Properties = @('nTSecurityDescriptor')
            }
        }
    }

    hidden [object] AclDescriptorStatus([object]$Status, [object]$Descriptor) {
        if ($Status -eq 'Collected' -and $null -eq $Descriptor) {
            return 'Unreadable'
        }
        return $Status
    }

    hidden [pscustomobject] CreateAclReadError([object]$Target, [string]$Message) {
        return [pscustomobject]@{
            Collector = 'Acl'
            Target = $Target
            Status = 'Unreadable'
            Message = $Message
        }
    }

    hidden [void] AddAclObservation(
        [Collections.Generic.List[object]]$Observations,
        [pscustomobject]$Target,
        [object]$Status
    ) {
        $Observations.Add([pscustomobject]@{
                Target = $Target.DN
                Type = $Target.Type
                Status = $Status
            })
    }

    hidden [void] CompleteAclCoverage([Collections.IDictionary]$Coverage, [pscustomobject]$Plan) {
        $Coverage['Acl'] = if ($Plan.Enabled) {
            if ($Coverage['AclOUs'] -eq 'Unreadable' -or
                @($Plan.Observations | Where-Object Status -ne 'Collected').Count) {
                'Partial'
            }
            else {
                'Collected'
            }
        }
        elseif ($Plan.IncludeAcl) {
            'Unreadable'
        }
        else {
            'NotConfigured'
        }
    }

    hidden [pscustomobject] CreateAclSnapshot(
        [Collections.Generic.List[object]]$Observations,
        [Collections.Generic.List[object]]$Entries,
        [hashtable]$GuidMap
    ) {
        return [pscustomobject]@{
            Targets = $Observations.ToArray()
            Entries = $Entries.ToArray()
            GuidMap = $GuidMap
            EffectiveAccessCalculated = $false
        }
    }

    hidden [object] PlanHosts([object]$Context, [object]$Analysis, [object[]]$Controllers) {
        $fallback = Get-ADAnalyzerDirectoryField $Analysis 'IncludeHostChecks' $false
        if (-not [bool](Get-ADAnalyzerDirectoryField $Context 'IncludeHostChecks' $fallback)) {
            return $null
        }
        return [pscustomobject]@{
            Names = @($Controllers | ForEach-Object { [string](Get-ADAnalyzerDirectoryField $_ 'HostName') })
            TimeoutSeconds = Get-ADAnalyzerDirectoryField $Analysis 'HostTimeoutSeconds' 30
        }
    }

    hidden [void] CompleteHostCoverage(
        [System.Collections.IDictionary]$Coverage,
        [object[]]$Hosts,
        [bool]$Enabled
    ) {
        if (-not $Enabled) {
            $Coverage['Hosts'] = 'NotConfigured'
            return
        }
        if (-not $Hosts.Count) {
            $Coverage['Hosts'] = 'Unreadable'
            return
        }

        $status = 'Collected'
        $hostCollector = [ADAnalyzerHostCollector]::new()
        :scanHosts foreach ($hostRecord in $Hosts) {
            if ($hostRecord.Status -ne 'Observed') {
                $status = 'Partial'
                break scanHosts
            }

            $registry = $hostRecord.PSObject.Properties['Registry']
            if ($null -eq $registry) {
                continue
            }
            foreach ($record in $registry.Value) {
                if ($null -eq $record -or $record.Status -ne 'Unknown') {
                    continue
                }

                $members = $record.PSObject.Properties
                $returnCode = $members['ReturnValue']
                if ($null -ne $returnCode) {
                    # Win32 code 2 is the established missing-value observation.
                    if ($hostCollector.RegistryReturnCodeIs($returnCode.Value, 2)) {
                        continue
                    }
                }
                elseif ($null -eq $members['Message']) {
                    continue
                }

                $status = 'Partial'
                break scanHosts
            }
        }

        $Coverage['Hosts'] = $status
    }

    hidden [object] DescribeUsersObservation(
        [string]$RequestedSearchBase,
        [string]$SearchBase,
        [string]$Server,
        [object]$RootDse,
        [string]$Mode,
        [Collections.IDictionary]$Coverage
    ) {
        if ([string]::IsNullOrWhiteSpace($RequestedSearchBase)) {
            return $null
        }

        $observedAt = $null
        $status = 'Unreadable'
        if ($Coverage['Users'] -eq 'Collected') {
            $status = 'Completed'
            $observedAt = [datetime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        elseif ($Mode -eq 'PSDrive' -and $Coverage['DirectoryConnection'] -ne 'Collected') {
            $status = 'Unobserved'
        }

        $controller = $null
        $ErrorActionPreference = 'Stop'
        try {
            $reportedServer = Get-ADAnalyzerDirectoryObservationField $RootDse 'DnsHostName'
            if ($reportedServer -is [string] -and
                [string]::Equals($reportedServer, $Server, [StringComparison]::OrdinalIgnoreCase)) {
                $controller = $Server
            }
        }
        catch {
            # A missing controller witness does not change the query outcome.
            $controller = $null
        }
        return [pscustomobject][ordered]@{
            Version = 1
            RequestedSearchBase = $RequestedSearchBase
            SearchBase = $SearchBase
            Server = $controller
            Mode = $Mode
            ObservedAt = $observedAt
            Status = $status
        }
    }

    hidden [object] CreateSnapshot([hashtable]$Observations) {
        $connectionStatus = $Observations.ConnectionStatus
        if ($Observations.ConnectionMode -eq 'PSDrive' -and $Observations.Coverage['DirectoryConnection'] -ne 'Collected') {
            $connectionStatus = 'Unreadable'
        }
        $snapshot = [ordered]@{
            Server = $Observations.Server
            Domain = [pscustomobject]@{
                DistinguishedName = $Observations.DomainDn
                DNSRoot = Get-ADAnalyzerDirectoryField $Observations.Domain 'DNSRoot'
                SID = $Observations.DomainSid
                RootDomainSID = $Observations.RootDomainSid
                DomainMode = Get-ADAnalyzerDirectoryField $Observations.Domain 'DomainMode'
                ForestMode = Get-ADAnalyzerDirectoryField $Observations.Forest 'ForestMode'
                MachineAccountQuota = Get-ADAnalyzerDirectoryField $Observations.Settings 'ms-DS-MachineAccountQuota'
                OptionalFeatures = $Observations.OptionalFeatures
                FeatureSchema = $Observations.FeatureSchema
                PrivilegedSids = @($Observations.PrivilegedSids | Select-Object -Unique)
            }
            Users = $Observations.Users
            Groups = $Observations.Groups
            Computers = $Observations.Computers
            ServiceAccounts = $Observations.ServiceAccounts
            DirectoryConnection = [pscustomobject]@{
                Mode = $Observations.ConnectionMode
                Server = $Observations.Server
                Status = $connectionStatus
            }
            Objects = @($Observations.Users) + @($Observations.Computers) + @($Observations.ServiceAccounts)
            Trusts = $Observations.Trusts
            PasswordPolicies = [pscustomobject]@{
                Default = $Observations.DefaultPolicy
                FineGrained = $Observations.FineGrained
                Resultant = $Observations.Resultant.ToArray()
            }
            DomainControllers = $Observations.Controllers
            Acl = $Observations.Acl
            Hosts = $Observations.Hosts
            Errors = $Observations.Errors.ToArray()
            Coverage = $Observations.Coverage
        }
        if ($null -ne $Observations.UsersObservation) {
            $snapshot['UsersObservation'] = $Observations.UsersObservation
        }
        return [pscustomobject]$snapshot
    }
}

# Dot-source the observation in the caller that owns the local drive. Keep
# preflight throws and terminal rethrows in the entry point's native scope.
function Get-ADAnalyzerDirectoryObservation {
    return {
        try {
            if ($connectionMode -eq 'PSDrive') {
                try {
                    $previousLocation = Get-Location
                    $driveName = 'ADAnalyzerData' + [guid]::NewGuid().ToString('N')
                    $driveArguments = $collector.CreateDriveParameters($driveName, $domainDn, $common)
                    $drive = New-PSDrive @driveArguments
                    if ($drive.Provider.Name -ne 'ActiveDirectory') {
                        throw 'The requested AD PSDrive provider was not established'
                    }
                    Set-Location -LiteralPath ($drive.Name + ':') -ErrorAction Stop
                    $expectedDrive = $drive.Name
                    $null = $common.Remove('Credential')
                    $connectionStatus = 'Connected'
                    $coverage['DirectoryConnection'] = 'Collected'
                }
                catch {
                    $connectionStatus = 'Unreadable'
                    $coverage['DirectoryConnection'] = 'Unreadable'
                    $connectionError = 'AD PSDrive connection is unavailable: ' + $_.Exception.Message
                    $errors.Add([pscustomobject]@{
                            Collector = 'DirectoryConnection'
                            Target = $server
                            Status = 'Unreadable'
                            Message = $_.Exception.Message
                            ExceptionType = $_.Exception.GetType().FullName
                        }) > $null
                }
            }
            $forest = @(& $query 'Get-ADForest' @{} 'Forest') | Select-Object -First 1
            $rootDomainSid = $domainSid
            $forestRoot = [string](Get-ADAnalyzerDirectoryField $forest 'RootDomain')
            if ($forestRoot) {
                $request = $collector.ForestRootRequest($forestRoot, (Get-ADAnalyzerDirectoryField $domain 'DNSRoot'))
                if ($null -ne $request) {
                    $rootDomain = @(& $query $request.Command $request.Arguments $request.Key) | Select-Object -First 1
                    $rootDomainSid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $rootDomain 'DomainSID')
                }
            }

            $schema = @()
            $schemaDn = [string](Get-ADAnalyzerDirectoryField $root 'SchemaNamingContext')
            $request = $collector.FeatureSchemaRequest($schemaDn, $coverage)
            if ($null -ne $request) {
                $schema = @(& $query $request.Command $request.Arguments $request.Key)
            }
            $available = @($schema | ForEach-Object { [string](Get-ADAnalyzerDirectoryField $_ 'lDAPDisplayName') })
            $requestedSearchBase = [string](Get-ADAnalyzerDirectoryField $Context 'SearchBase')
            $searchBase = $requestedSearchBase
            if ([string]::IsNullOrWhiteSpace($searchBase)) {
                $searchBase = $domainDn
            }

            $accountPlan = $collector.AccountPlan($searchBase, $domainDn, $available, $Profile, $coverage, $errors, $server)
            $rawUsers = @(& $query 'Get-ADUser' $accountPlan.UserArguments 'Users')
            $usersObservation = $collector.DescribeUsersObservation(
                $requestedSearchBase,
                $accountPlan.UserArguments.SearchBase,
                $server,
                $root,
                $connectionMode,
                $coverage
            )
            $rawComputers = @(& $query 'Get-ADComputer' $accountPlan.ComputerArguments 'Computers')
            $groups = @(& $query 'Get-ADGroup' $accountPlan.GroupArguments 'Groups')
            $trusts = @(& $query 'Get-ADTrust' $accountPlan.TrustArguments 'Trusts')
            $controllers = @(& $query 'Get-ADDomainController' $accountPlan.ControllerArguments 'DomainControllers')
            $rawServices = @(& $query 'Get-ADServiceAccount' $accountPlan.ServiceArguments 'ServiceAccounts')

            $settings = $null
            $optional = @()
            $defaultPolicy = $null
            $fineGrained = @()
            $resultant = [System.Collections.Generic.List[object]]::new()
            $policyPlan = $collector.DomainPolicyPlan($domainDn, $coverage)
            if ($null -ne $policyPlan) {
                $settings = @(& $query 'Get-ADObject' $policyPlan.SettingsArguments 'DomainSettings') | Select-Object -First 1
                $defaultPolicy = @(& $query 'Get-ADDefaultDomainPasswordPolicy' $policyPlan.DefaultArguments 'DefaultPasswordPolicy') |
                    Select-Object -First 1
                if ($null -eq $defaultPolicy -and $coverage['DefaultPasswordPolicy'] -eq 'Collected') {
                    $coverage['DefaultPasswordPolicy'] = 'Unreadable'
                }
                $fineGrained = @(& $query 'Get-ADFineGrainedPasswordPolicy' $policyPlan.FineGrainedArguments 'FineGrainedPasswordPolicies')
                $optional = @(& $query 'Get-ADOptionalFeature' $policyPlan.OptionalArguments 'OptionalFeatures')
            }

            $projection = @{
                AdditionalProperties = $accountPlan.AdditionalProperties
                PreserveClassificationInput = $accountPlan.PreserveClassificationInput
            }
            $users = @($rawUsers | ForEach-Object { ConvertTo-ADAnalyzerDirectoryObject $_ 'User' @projection })
            $computers = @($rawComputers | ForEach-Object { ConvertTo-ADAnalyzerDirectoryObject $_ 'Computer' @projection })
            $services = @($rawServices | ForEach-Object { ConvertTo-ADAnalyzerDirectoryObject $_ 'ServiceAccount' @projection })
            $classified = $collector.ClassifyAccounts(
                $users, $computers, $services, $groups, $domainSid, $rootDomainSid, $Profile, $coverage,
                $accountPlan.PreserveClassificationInput
            )
            $computers = $classified.Computers
            $privilegedSids = $classified.PrivilegedSids
            $resultantPsoAvailable = $accountPlan.ResultantPsoAvailable

            $psoIndex = $collector.BuildResultantPolicyIndex($resultantPsoAvailable, $coverage, $fineGrained)
            foreach ($user in $users) {
                $policyPlan = $collector.PlanResultantPolicy($user, $psoIndex, $coverage)
                $effective = $policyPlan.CachedPolicy
                if ($null -ne $policyPlan.Arguments) {
                    $effective = @(& $query 'Get-ADUserResultantPasswordPolicy' $policyPlan.Arguments $policyPlan.Key) |
                        Select-Object -First 1
                }
                if ($null -eq $effective -and $null -eq $defaultPolicy -and
                    $coverage[$policyPlan.Key] -eq 'Collected') {
                    $coverage[$policyPlan.Key] = 'Unreadable'
                }

                $resultant.Add($collector.CreateResultantPolicyRecord(
                        $user.DistinguishedName, $effective, $defaultPolicy, $coverage[$policyPlan.Key]
                    ))
            }
            $collector.CompleteResultantPolicyCoverage($coverage, $resultant)

            $analysis = Get-ADAnalyzerDirectoryField $Profile 'Analysis' @{}
            $includeAcl = [bool](Get-ADAnalyzerDirectoryField $Context 'IncludeAcl' (Get-ADAnalyzerDirectoryField $analysis 'IncludeAcl' $false))
            $aclPlan = $collector.PlanAcl($includeAcl, $domainDn, $schemaDn, $searchBase)
            $aces = $aclPlan.Entries
            $aclTargets = $aclPlan.Observations
            $guidMap = $aclPlan.GuidMap
            if ($aclPlan.Enabled) {
                if ($null -ne $aclPlan.SchemaArguments) {
                    foreach ($entry in @(& $query 'Get-ADObject' $aclPlan.SchemaArguments 'AclSchema')) {
                        $guid = Get-ADAnalyzerDirectoryField $entry 'schemaIDGUID'
                        if ($guid) {
                            try {
                                $label = [string](Get-ADAnalyzerDirectoryField $entry 'lDAPDisplayName')
                                $key = ([guid]$guid).ToString()
                                $collector.AddAclGuidLabel($guidMap, $key, $label)
                            }
                            catch {
                                $errors.Add($collector.CreateAclSchemaError($schemaDn))
                            }
                        }
                    }
                }

                $configDn = [string](Get-ADAnalyzerDirectoryField $root 'ConfigurationNamingContext')
                $rightsArguments = $collector.PlanAclExtendedRights($configDn)
                if ($null -ne $rightsArguments) {
                    foreach ($right in @(& $query 'Get-ADObject' $rightsArguments 'ExtendedRights')) {
                        $label = [string](Get-ADAnalyzerDirectoryField $right 'displayName')
                        $key = [string](Get-ADAnalyzerDirectoryField $right 'rightsGuid')
                        $collector.AddAclGuidLabel($guidMap, $key, $label)
                    }
                }

                $targets = $aclPlan.Targets
                $collector.AddAclBaseTargets($targets, $domainDn)
                foreach ($ou in @(& $query 'Get-ADOrganizationalUnit' $aclPlan.OuArguments 'AclOUs')) {
                    $dn = [string](Get-ADAnalyzerDirectoryField $ou 'DistinguishedName')
                    $collector.AddAclTarget($targets, $dn, 'OU')
                }
                foreach ($gpo in @(& $query 'Get-ADObject' $aclPlan.GpoArguments 'AclGPOs')) {
                    $dn = [string](Get-ADAnalyzerDirectoryField $gpo 'DistinguishedName')
                    $collector.AddAclTarget($targets, $dn, 'GPO')
                }
                foreach ($target in $targets) {
                    $descriptorPlan = $collector.PlanAclDescriptor($target)
                    $record = @(& $query 'Get-ADObject' $descriptorPlan.Arguments $descriptorPlan.Key) |
                        Select-Object -First 1
                    $descriptor = Get-ADAnalyzerDirectoryField $record 'nTSecurityDescriptor'
                    $status = $collector.AclDescriptorStatus($coverage[$descriptorPlan.Key], $descriptor)
                    try {
                        foreach ($ace in @(Get-ADAnalyzerSecurityAces $descriptor $target.DN $target.Type)) {
                            $ace | Add-Member NoteProperty ObjectTypeName (Get-ADAnalyzerDirectoryField $guidMap $ace.ObjectType $ace.ObjectType)
                            $aces.Add($ace)
                        }
                    }
                    catch {
                        $status = 'Unreadable'
                        $errors.Add($collector.CreateAclReadError($target.DN, $_.Exception.Message))
                    }
                    $collector.AddAclObservation($aclTargets, $target, $status)
                }
            }
            $collector.CompleteAclCoverage($coverage, $aclPlan)

            $hosts = @()
            $hostPlan = $collector.PlanHosts($Context, $analysis, $controllers)
            if ($null -ne $hostPlan) {
                if ($null -eq $capabilities) {
                    $hostArguments = @{
                        ComputerNames = $hostPlan.Names
                        Credential = $credential
                        Errors = $errors
                        TimeoutSeconds = $hostPlan.TimeoutSeconds
                        Profile = $Profile
                    }
                    $hosts = @(Get-ADAnalyzerHostData @hostArguments)
                }
                else {
                    $hostCollector = [ADAnalyzerHostCollector]::new()
                    $hostResults = $hostCollector.Collect($hostPlan.Names, $credential, $hostPlan.TimeoutSeconds, $Profile)
                    $hosts = $hostResults.Hosts
                    foreach ($failure in $hostResults.Errors) {
                        $errors.Add($failure)
                    }
                }
            }
            $collector.CompleteHostCoverage($coverage, $hosts, ($null -ne $hostPlan))
            $result = $collector.CreateSnapshot(@{
                    Server = $server
                    Domain = $domain
                    DomainDn = $domainDn
                    DomainSid = $domainSid
                    RootDomainSid = $rootDomainSid
                    Forest = $forest
                    Settings = $settings
                    OptionalFeatures = $optional
                    FeatureSchema = $available
                    PrivilegedSids = $privilegedSids
                    Users = $users
                    Groups = $groups
                    Computers = $computers
                    ServiceAccounts = $services
                    ConnectionMode = $connectionMode
                    ConnectionStatus = $connectionStatus
                    Trusts = $trusts
                    DefaultPolicy = $defaultPolicy
                    FineGrained = $fineGrained
                    Resultant = $resultant
                    Controllers = $controllers
                    Acl = $collector.CreateAclSnapshot($aclTargets, $aces, $guidMap)
                    Hosts = $hosts
                    Errors = $errors
                    Coverage = $coverage
                    UsersObservation = $usersObservation
                })
        }
        catch {
            $primaryError = $_
        }
        finally {
            if ($null -ne $drive) {
                try {
                    Set-Location -LiteralPath $previousLocation.Path -ErrorAction Stop
                }
                catch {
                    $restorationError = $_
                }
                try {
                    Remove-PSDrive -Name $drive.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
                }
                catch {
                    $removalError = $_
                }
            }
        }
    }
}

function Get-ADAnalyzerDirectoryData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][hashtable]$Profile

    )
    $collector = [ADAnalyzerDirectoryCollector]::new()
    $connectionMode = $collector.ResolveMode(
        (Get-ADAnalyzerDirectoryField (Get-ADAnalyzerDirectoryField $Profile 'Analysis' @{}) 'DirectoryConnection' 'PSDrive')
    )
    if (-not $connectionMode) {
        throw 'Analysis.DirectoryConnection must be PSDrive or Direct'
    }
    $server = [string](Get-ADAnalyzerDirectoryField $Context 'Server')
    if ([string]::IsNullOrWhiteSpace($server)) {
        $server = [string](Get-ADAnalyzerDirectoryField $Context 'Domain')
    }
    if ([string]::IsNullOrWhiteSpace($server)) {
        throw 'Context.Server or Context.Domain is required'
    }
    $credential = Get-ADAnalyzerDirectoryField $Context 'Credential'
    $common = @{
        Server = $server
    }
    if ($null -ne $credential -and $credential -ne [pscredential]::Empty) {
        $common['Credential'] = $credential
    }
    $capabilities = $null
    $coverage = [ordered]@{}
    $errors = [System.Collections.Generic.List[object]]::new()
    $expectedDrive = $null
    $connectionError = $null
    $query = { param(
            $Command,
            $Arguments,
            $Key

        ) $splat = @{} + $common + $Arguments
        @(Invoke-ADAnalyzerDirectoryQuery $Command $splat $Key $coverage $errors $server `
                -ExpectedDrive $expectedDrive `
                -ConnectionError $connectionError) }
    $root = @(& $query 'Get-ADRootDSE' @{} 'RootDSE') | Select-Object -First 1
    $domainIdentity = [string](Get-ADAnalyzerDirectoryField $Context 'Domain')
    if ([string]::IsNullOrWhiteSpace($domainIdentity)) {
        $domainIdentity = [string](Get-ADAnalyzerDirectoryField $root 'DefaultNamingContext' $server)
    }
    $domain = @(& $query 'Get-ADDomain' @{
            Identity = $domainIdentity
        } 'Domain') | Select-Object -First 1
    $domainDn = [string](Get-ADAnalyzerDirectoryField $domain 'DistinguishedName' (Get-ADAnalyzerDirectoryField $root 'DefaultNamingContext'))
    $domainSid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $domain 'DomainSID')
    $drive = $null
    $previousLocation = $null
    $primaryError = $null
    $restorationError = $null
    $removalError = $null
    $result = $null
    $connectionStatus = 'Direct'
    $coverage['DirectoryConnection'] = 'NotConfigured'
    $observation = Get-ADAnalyzerDirectoryObservation
    . $observation
    if ($null -ne $primaryError) {
        if ($null -ne $restorationError) {
            $primaryError.Exception.Data['ADAnalyzerLocationRestorationError'] = $restorationError.Exception.Message
        }
        if ($null -ne $removalError) {
            $primaryError.Exception.Data['ADAnalyzerDriveRemovalError'] = $removalError.Exception.Message
        }
        throw $primaryError
    }
    if ($null -ne $restorationError) {
        if ($null -ne $removalError) {
            $restorationError.Exception.Data['ADAnalyzerDriveRemovalError'] = $removalError.Exception.Message
        }
        throw $restorationError
    }
    if ($null -ne $removalError) {
        throw $removalError
    }
    $result
}

function Add-ADAnalyzerDirectoryCheck {
    param(
        [string]$RuleId,
        [string]$Status,
        [string]$Severity,
        [string]$Category,
        [string]$Target,
        $Observed,
        $Expected,
        $Evidence,
        [string]$Message,
        $Object,
        [string]$Applicability = 'Unknown'

    )
    $splat = @{
        RuleId = $RuleId
        Status = $Status
        Severity = $Severity
        Category = $Category
        Target = $Target
        Observed = $Observed
        Expected = $Expected
        Evidence = $Evidence
        Message = $Message
        Applicability = $Applicability
    }
    if ($null -ne $Object) {
        $splat['Object'] = $Object
    }
    New-ADAnalyzerCheck @splat
}

function Test-ADAnalyzerOperatingSystemProfile {
    param(
        $Object,
        [object[]]$Entries = @(),
        [datetimeoffset]$ReferenceTime = [datetimeoffset]::UtcNow

    )
    $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
    return $evaluator.EvaluateOperatingSystem($Object, $Entries, $ReferenceTime)
}

class ADAnalyzerDirectoryPolicyEvaluator {
    ADAnalyzerDirectoryPolicyEvaluator() {
    }

    [pscustomobject] EvaluateOperatingSystem([object]$Object, [object[]]$Entries) {
        return $this.EvaluateOperatingSystem($Object, $Entries, [datetimeoffset]::UtcNow)
    }

    [pscustomobject] EvaluateOperatingSystem(
        [object]$Object,
        [object[]]$Entries,
        [datetimeoffset]$ReferenceTime
    ) {
        $name = [string](Get-ADAnalyzerDirectoryField $Object 'OperatingSystem')
        $version = [string](Get-ADAnalyzerDirectoryField $Object 'OperatingSystemVersion')
        $build = Get-ADAnalyzerDirectoryField $Object 'BuildNumber'
        if ($null -eq $build -and $version -match '\((\d+)\)') {
            $parsedBuild = $null
            if ([Management.Automation.LanguagePrimitives]::TryConvertTo($Matches[1], [long], [ref]$parsedBuild)) {
                $build = $parsedBuild
            }
        }
        if ($null -eq $build) {
            $parsed = $null
            if ([version]::TryParse($version, [ref]$parsed) -and $parsed.Build -ge 0) {
                $build = $parsed.Build
            }
        }
        $esu = Get-ADAnalyzerDirectoryField $Object 'EsuStatus'
        $esuUntil = Get-ADAnalyzerDirectoryField $Object 'EsuValidUntil'
        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $Entries) {
            $nameOnly = $entry -is [string]
            $pattern = if ($nameOnly) {
                $entry
            }
            else {
                [string](Get-ADAnalyzerDirectoryField $entry 'Name')
            }
            if (-not $nameOnly -and -not $pattern) {
                $results.Add([pscustomobject]@{
                        Status = 'Invalid'
                        Reason = 'OS profile entry requires Name'
                        Entry = $entry
                    })
                continue
            }
            try {
                if ($name -notlike $pattern) {
                    continue
                }
            }
            catch {
                $results.Add([pscustomobject]@{
                        Status = 'Invalid'
                        Reason = 'Invalid OS Name wildcard'
                        Entry = $entry
                    })
                continue
            }
            if ($nameOnly) {
                $results.Add([pscustomobject]@{
                        Status = 'Unknown'
                        Reason = 'A name-only allowlist is not lifecycle/build support evidence'
                        Entry = $entry
                    })
                continue
            }
            $versionPattern = Get-ADAnalyzerDirectoryField $entry 'VersionPattern'
            $minimum = Get-ADAnalyzerDirectoryField $entry 'MinimumBuild'
            $maximum = Get-ADAnalyzerDirectoryField $entry 'MaximumBuild'
            $until = Get-ADAnalyzerDirectoryField $entry 'SupportedUntil'
            $requireEsu = Get-ADAnalyzerDirectoryField $entry 'RequireEsu'
            $status = 'Pass'
            $reason = 'Explicit profile version/build/lifecycle metadata matches'
            $deadline = [datetimeoffset]::MinValue
            $deadlineValid = $null -ne $until -and [datetimeoffset]::TryParse([string]$until, [ref]$deadline)
            if ($null -ne $until -and -not $deadlineValid) {
                $status = 'Invalid'
                $reason = 'Invalid SupportedUntil timestamp'
            }
            elseif ($versionPattern -and $version -and $null -ne $build) {
                try {
                    if ($version -notmatch [string]$versionPattern) {
                        $status = 'Fail'
                        $reason = 'Operating-system version differs from the explicit profile'
                    }
                }
                catch {
                    $status = 'Invalid'
                    $reason = 'Invalid OS VersionPattern'
                }
            }
            $buildAvailable = $null -ne $build
            $invalidObservedBuild = $false
            if ($status -eq 'Pass' -and $buildAvailable -and ($null -ne $minimum -or $null -ne $maximum)) {
                $number = $null
                $minimumBuild = $null
                $maximumBuild = $null
                if (-not [Management.Automation.LanguagePrimitives]::TryConvertTo($build, [long], [ref]$number)) {
                    $buildAvailable = $false
                    $invalidObservedBuild = $true
                }
                elseif ($null -ne $minimum -and
                    -not [Management.Automation.LanguagePrimitives]::TryConvertTo($minimum, [long], [ref]$minimumBuild)) {
                    $status = 'Invalid'
                    $reason = 'Invalid OS MinimumBuild'
                }
                elseif ($null -ne $minimum -and $number -lt $minimumBuild) {
                    $status = 'Fail'
                    $reason = 'Build lies outside the configured range'
                }
                elseif ($null -ne $maximum -and
                    -not [Management.Automation.LanguagePrimitives]::TryConvertTo($maximum, [long], [ref]$maximumBuild)) {
                    $status = 'Invalid'
                    $reason = 'Invalid OS MaximumBuild'
                }
                elseif ($null -ne $maximum -and $number -gt $maximumBuild) {
                    $status = 'Fail'
                    $reason = 'Build lies outside the configured range'
                }
            }
            if ($status -eq 'Pass' -and $deadlineValid -and $deadline -lt $ReferenceTime -and $requireEsu -eq $false) {
                $status = 'Fail'
                $reason = 'Configured support lifecycle has expired'
            }
            if ($status -eq 'Pass' -and
                (-not $buildAvailable -or
                $null -eq $minimum -or
                -not $versionPattern -or
                -not $version -or
                -not $deadlineValid -or
                $null -eq $requireEsu)) {
                $status = 'Unknown'
                $reason = if ($invalidObservedBuild) {
                    'Observed OS build number is invalid'
                }
                else {
                    'Build, version, lifecycle or ESU applicability metadata is missing'
                }
            }
            if ($status -eq 'Pass' -and $requireEsu) {
                $expiry = [datetimeoffset]::MinValue
                if ($null -eq $esu -or $null -eq $esuUntil -or -not [datetimeoffset]::TryParse([string]$esuUntil, [ref]$expiry)) {
                    $status = 'Unknown'
                    $reason = 'Required ESU enrollment/expiry evidence is missing'
                }
                elseif ($esu -ne 'Active' -or $expiry -lt $ReferenceTime) {
                    $status = 'Fail'
                    $reason = 'Required ESU evidence is inactive or expired'
                }
            }
            $results.Add([pscustomobject]@{
                    Status = $status
                    Reason = $reason
                    Entry = $entry
                })
        }
        $status = if (-not $Entries.Count) {
            'NotConfigured'
        }
        elseif (-not $name) {
            'Unknown'
        }
        elseif (@($results | Where-Object Status -eq 'Invalid').Count) {
            'Invalid'
        }
        elseif (@($results | Where-Object Status -eq 'Pass').Count) {
            'Pass'
        }
        elseif (@($results | Where-Object Status -eq 'Unknown').Count) {
            'Unknown'
        }
        else {
            'Fail'
        }
        return [pscustomobject]@{
            Status = $status
            Observed = [pscustomobject]@{
                Name = $name
                Version = $version
                Build = $build
                EsuStatus = $esu
                EsuValidUntil = $esuUntil
            }
            Expected = $Entries
            Evidence = @{
                Matches = $results.ToArray()
                ReferenceTime = $ReferenceTime.ToString('o')
                LifecycleInferred = $false
            }
        }
    }

    [object[]] Evaluate([object]$Data, [hashtable]$Profile) {
        return $this.EvaluateCore($Data, $Profile, $null, 'Stop')
    }

    hidden [object[]] EvaluateForCommand(
        [object]$Data,
        [hashtable]$Profile,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        return $this.EvaluateCore($Data, $Profile, $CommandContext, $ErrorPreference)
    }

    hidden [object[]] EvaluateCore(
        [object]$Data,
        [hashtable]$Profile,
        [Management.Automation.PSCmdlet]$CommandContext,
        [Management.Automation.ActionPreference]$ErrorPreference
    ) {
        if ($null -eq $Data) {
            throw [ArgumentNullException]::new('Data')
        }
        if ($null -eq $Profile) {
            throw [ArgumentNullException]::new('Profile')
        }

        $policy = Get-ADAnalyzerDirectoryField $Profile 'Policy' @{}
        $domain = Get-ADAnalyzerDirectoryField $Data 'Domain'
        $domainTarget = Get-ADAnalyzerDirectoryTarget $domain
        $coverage = Get-ADAnalyzerDirectoryField $Data 'Coverage' @{}
        $evaluation = @{
            Data = $Data
            Profile = $Profile
            Policy = $policy
            Domain = $domain
            DomainTarget = $domainTarget
            Coverage = $coverage
            Checks = [Collections.Generic.List[object]]::new()
            CommandContext = $CommandContext
            ErrorPreference = $ErrorPreference
        }

        $this.EvaluateDomain($evaluation)
        $this.EvaluateAccounts($evaluation)
        $this.EvaluateTrustsAndAcl($evaluation)
        $this.EvaluatePasswordPolicies($evaluation)
        $this.EvaluateHostEvidence($evaluation)
        return $evaluation.Checks.ToArray()
    }

    hidden [void] Emit([hashtable]$Evaluation, [Collections.IDictionary]$Specification) {
        $arguments = @{
            Applicability = 'Unknown'
        }
        foreach ($name in $Specification.Keys) {
            $arguments[$name] = $Specification[$name]
        }

        # Preserve the string coercions/defaults of the compatibility check helper.
        foreach ($name in @('RuleId', 'Status', 'Severity', 'Category', 'Target', 'Message', 'Applicability')) {
            $arguments[$name] = [string]$arguments[$name]
        }
        if ($null -eq $arguments.Object) {
            $arguments.Remove('Object')
        }

        $ErrorActionPreference = if ($null -ne $Evaluation.CommandContext -and
            $Evaluation.ErrorPreference -ne 'Stop') {
            'Continue'
        }
        else {
            'Stop'
        }
        if ($Evaluation.ErrorPreference -eq 'Ignore') {
            # Windows PowerShell 5.1 accepts Ignore as a parameter, not a preference.
            $arguments.ErrorAction = 'Ignore'
        }

        foreach ($item in @(New-ADAnalyzerCheck @arguments 2>&1)) {
            if ($item -is [Management.Automation.ErrorRecord]) {
                if ($null -eq $Evaluation.CommandContext) {
                    throw $item
                }
                $Evaluation.CommandContext.WriteError($item)
            }
            elseif ($null -ne $Evaluation.CommandContext) {
                $Evaluation.CommandContext.WriteObject($item)
            }
            else {
                $Evaluation.Checks.Add($item)
            }
        }
    }

    hidden [void] EvaluateDomain([hashtable]$Evaluation) {
        $Data = $Evaluation.Data
        $Profile = $Evaluation.Profile
        $policy = $Evaluation.Policy
        $domain = $Evaluation.Domain
        $domainTarget = $Evaluation.DomainTarget
        $coverage = $Evaluation.Coverage

        foreach ($key in @('Domain',
                'Users',
                'Groups',
                'Computers',
                'Trusts',
                'DefaultPasswordPolicy',
                'FineGrainedPasswordPolicies',
                'ResultantPasswordPolicies',
                'ServiceAccounts',
                'Acl',
                'Hosts')) {
            $state = [string](Get-ADAnalyzerDirectoryField $coverage $key 'Unreadable')
            if ($state -ne 'Collected') {
                $status = if ($state -eq 'NotConfigured') {
                    'NotConfigured'
                }
                elseif ($state -eq 'Unreadable') {
                    'Unreadable'
                }
                else {
                    'Unknown'
                }
                $this.Emit($Evaluation, @{
                    RuleId = ('COLLECTION.' + $key.ToUpperInvariant())
                    Status = $status
                    Severity = 'Information'
                    Category = 'Coverage'
                    Target = $domainTarget
                    Observed = $state
                    Expected = 'Collected'
                    Evidence = @()
                    Message = ('Collection coverage: ' + $key)
                    Object = $null
                })
            }
        }
        $quota = Get-ADAnalyzerDirectoryField $domain 'MachineAccountQuota'
        $expectedQuota = Get-ADAnalyzerDirectoryField $policy 'MachineAccountQuota' 0
        $status = if ($null -eq $quota) {
            'Unknown'
        }
        elseif ([long]$quota -gt [long]$expectedQuota) {
            'Fail'
        }
        else {
            'Pass'
        }
        $this.Emit($Evaluation, @{
            RuleId = 'DOMAIN.MACHINE_ACCOUNT_QUOTA'
            Status = $status
            Severity = 'High'
            Category = 'Domain'
            Target = $domainTarget
            Observed = $quota
            Expected = $expectedQuota
            Evidence = @()
            Message = 'Configured quota; join rights may also be delegated through directory ACLs.'
            Object = $null
            Applicability = 'Configured'
        })
        $recycle = @(Get-ADAnalyzerDirectoryField $domain 'OptionalFeatures' @() | Where-Object { [string](Get-ADAnalyzerDirectoryField $_ 'FeatureGUID') -eq '766ddcd8-acd0-445e-f3b9-a7f9b6744f2a' })
        $recycleStatus = if ((Get-ADAnalyzerDirectoryField $coverage 'OptionalFeatures') -ne 'Collected') {
            'Unknown'
        }
        elseif (-not $recycle.Count) {
            'Unknown'
        }
        elseif (@(Get-ADAnalyzerDirectoryField $recycle[0] 'EnabledScopes' @()).Count) {
            'Pass'
        }
        else {
            'Fail'
        }
        $this.Emit($Evaluation, @{
            RuleId = 'DOMAIN.RECYCLE_BIN'
            Status = $recycleStatus
            Severity = 'Medium'
            Category = 'Domain'
            Target = $domainTarget
            Observed = @($recycle | ForEach-Object { Get-ADAnalyzerDirectoryField $_ 'EnabledScopes' })
            Expected = 'Recycle Bin optional feature enabled'
            Evidence = @()
            Message = 'This check observes optional-feature configuration and does not enable it.'
            Object = $null
            Applicability = 'Configured'
        })
    }

    hidden [hashtable] GetScopedUserEvidence([object]$Data) {
        $observation = Get-ADAnalyzerDirectoryObservationField $Data 'UsersObservation'
        $version = Get-ADAnalyzerDirectoryObservationField $observation 'Version'
        $outcome = Get-ADAnalyzerDirectoryObservationField $observation 'Status'
        $scope = Get-ADAnalyzerDirectoryObservationField $observation 'SearchBase'
        $requestedScope = Get-ADAnalyzerDirectoryObservationField $observation 'RequestedSearchBase'
        $coverage = Get-ADAnalyzerDirectoryObservationField $Data 'Coverage'
        $usersCoverage = Get-ADAnalyzerDirectoryObservationField $coverage 'Users'
        $users = Get-ADAnalyzerDirectoryObservationField $Data 'Users'
        if (($version -isnot [int] -and $version -isnot [long]) -or $version -ne 1 -or
            $outcome -isnot [string] -or $outcome -cne 'Completed' -or
            $usersCoverage -isnot [string] -or $usersCoverage -cne 'Collected' -or
            $scope -isnot [string] -or [string]::IsNullOrWhiteSpace($scope) -or
            $requestedScope -isnot [string] -or -not $scope.Equals($requestedScope, [StringComparison]::OrdinalIgnoreCase) -or
            $users -isnot [Collections.IList]) {
            return $null
        }

        $controller = Get-ADAnalyzerDirectoryObservationField $observation 'Server'
        $directoryServer = Get-ADAnalyzerDirectoryObservationField $Data 'Server'
        $connection = Get-ADAnalyzerDirectoryObservationField $Data 'DirectoryConnection'
        $connectionServer = Get-ADAnalyzerDirectoryObservationField $connection 'Server'
        if ($controller -isnot [string] -or [string]::IsNullOrWhiteSpace($controller) -or
            $directoryServer -isnot [string] -or $connectionServer -isnot [string] -or
            -not $controller.Equals($directoryServer, [StringComparison]::OrdinalIgnoreCase) -or
            -not $controller.Equals($connectionServer, [StringComparison]::OrdinalIgnoreCase)) {
            return @{ ControllerCorroborated = $false }
        }

        $index = [Collections.Generic.Dictionary[guid, object]]::new()
        foreach ($user in $users) {
            $identity = ConvertTo-ADAnalyzerDirectorySubjectGuid (Get-ADAnalyzerDirectoryObservationField $user 'ObjectGuid')
            if ($identity -eq [guid]::Empty) {
                continue
            }
            if ($index.ContainsKey($identity)) {
                $index[$identity] = $null
                continue
            }
            $index.Add($identity, $user)
        }
        return @{
            ControllerCorroborated = $true
            Scope = $scope
            Users = $index
        }
    }

    hidden [object] FindScopedUser([object]$Object, [hashtable]$Evidence) {
        if ($null -eq $Evidence -or -not $Evidence.ControllerCorroborated) {
            return $null
        }
        $identity = ConvertTo-ADAnalyzerDirectorySubjectGuid (Get-ADAnalyzerDirectoryObservationField $Object 'ObjectGuid')
        $user = $null
        if ($identity -eq [guid]::Empty -or -not $Evidence.Users.TryGetValue($identity, [ref]$user) -or $null -eq $user) {
            return $null
        }

        $dn = Get-ADAnalyzerDirectoryObservationField $Object 'DistinguishedName'
        $userDn = Get-ADAnalyzerDirectoryObservationField $user 'DistinguishedName'
        $kind = Get-ADAnalyzerDirectoryObservationField $user 'ObjectClass'
        if ($kind -is [string] -and $kind -ieq 'User' -and $dn -is [string] -and $userDn -is [string] -and
            $dn.Equals($userDn, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-ADAnalyzerDirectorySubjectInScope $dn $Evidence.Scope)) {
            return $user
        }
        return $null
    }

    hidden [void] EvaluateAccounts([hashtable]$Evaluation) {
        $Data = $Evaluation.Data
        $Profile = $Evaluation.Profile
        $policy = $Evaluation.Policy
        $domain = $Evaluation.Domain
        $domainTarget = $Evaluation.DomainTarget
        $coverage = $Evaluation.Coverage
        $scopedUsers = if ($Data -is [Collections.IDictionary]) {
            ([Collections.IDictionary]$Data).Contains('UsersObservation')
        }
        else {
            $null -ne $Data -and $null -ne $Data.PSObject.Properties['UsersObservation']
        }
        $scopedEvidence = $null
        if ($scopedUsers) {
            $scopedEvidence = $this.GetScopedUserEvidence($Data)
        }
        $controllerUncorroborated = $null -ne $scopedEvidence -and -not $scopedEvidence.ControllerCorroborated

        $allObjects = @(Get-ADAnalyzerDirectoryField $Data 'Objects' @())
        if (-not $allObjects.Count) {
            $allObjects = @(Get-ADAnalyzerDirectoryField $Data 'Users' @()) + @(Get-ADAnalyzerDirectoryField $Data 'Computers' @()) + @(Get-ADAnalyzerDirectoryField $Data 'ServiceAccounts' @())
        }
        $groups = @(Get-ADAnalyzerDirectoryField $Data 'Groups' @())
        $sidLookup = @{}
        $spns = @{}
        $membershipGraph = [ADAnalyzerMembershipGraph]::new($groups)
        foreach ($object in $allObjects + $groups) {
            $sid = ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $object 'SID')
            if ($sid) {
                $sidLookup[$sid] = $object
            }
        }
        foreach ($object in $allObjects) {
            $target = Get-ADAnalyzerDirectoryTarget $object
            $kind = [string](Get-ADAnalyzerDirectoryField $object 'ObjectClass')
            $scopedUser = $scopedUsers -and $kind -eq 'User'
            $scopedControl = $null
            $recordedEnabled = $null
            $classification = [string](Get-ADAnalyzerDirectoryField $object 'AccountType' 'Unknown')
            if ($kind -in @('User', 'ServiceAccount')) {
                $classificationEvidence = Get-ADAnalyzerDirectoryField $object 'AccountClassification'
                $classificationStatus = if (@(Get-ADAnalyzerDirectoryField $classificationEvidence 'InvalidRules' @()).Count) {
                    'Invalid'
                }
                elseif ($classification -eq 'Unknown') {
                    'Unknown'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = 'ACCOUNT.CLASSIFICATION'
                    Status = $classificationStatus
                    Severity = 'Information'
                    Category = 'Account'
                    Target = $target
                    Observed = $classification
                    Expected = 'Explicit User or Service classification'
                    Evidence = $classificationEvidence
                    Message = 'No username-based classification is used.'
                    Object = $object
                })
            }
            if ($kind -in @('User', 'Computer')) {
                $inactiveKey = if ($kind -eq 'Computer') {
                    'ComputerInactivityDays'
                }
                else {
                    'UserInactivityDays'
                }
                $inactiveDays = Get-ADAnalyzerDirectoryField $policy $inactiveKey 60
                $last = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $object 'LastLogonDate')
                $created = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $object 'WhenCreated')
                $age = if ($last) {
                    [math]::Floor(([datetime]::UtcNow - $last).TotalDays)
                }
                elseif ($created) {
                    [math]::Floor(([datetime]::UtcNow - $created).TotalDays)
                }
                else {
                    $null
                }
                $enabled = if ($scopedUser) {
                    $recordedEnabled = Get-ADAnalyzerDirectoryObservationField $object 'Enabled'
                    $recordedEnabled
                }
                else {
                    Get-ADAnalyzerDirectoryField $object 'Enabled'
                }
                $status = if ($null -eq $enabled -or $null -eq $age) {
                    'Unknown'
                }
                elseif (-not $enabled) {
                    'NotApplicable'
                }
                elseif ($age -ge $inactiveDays) {
                    'Fail'
                }
                else {
                    'Pass'
                }
                $rule = if ($kind -eq 'Computer') {
                    'COMPUTER.INACTIVE'
                }
                else {
                    'ACCOUNT.INACTIVE'
                }
                $this.Emit($Evaluation, @{
                    RuleId = $rule
                    Status = $status
                    Severity = 'Medium'
                    Category = 'Account'
                    Target = $target
                    Observed = $age
                    Expected = $inactiveDays
                    Evidence = @{
                                LastLogonDate = $last
                                WhenCreated = $created
                                Signal = 'Replicated LastLogonDate, or creation age when no logon is recorded'
                                Approximate = $true
                            }
                    Message = 'Inactivity is a signal, not authorization to disable this object.'
                    Object = $object
                    Applicability = 'Applicable'
                })
            }
            if ($kind -eq 'User') {
                $passwordDate = ConvertTo-ADAnalyzerDirectoryDate (Get-ADAnalyzerDirectoryField $object 'PasswordLastSet')
                $maxAge = if ($classification -eq 'User') {
                    Get-ADAnalyzerDirectoryField $policy 'UserPasswordAgeDays'
                }
                elseif ($classification -eq 'Service') {
                    Get-ADAnalyzerDirectoryField $policy 'ServicePasswordAgeDays'
                }
                else {
                    $null
                }
                $passwordAge = if ($passwordDate) {
                    [math]::Floor(([datetime]::UtcNow - $passwordDate).TotalDays)
                }
                else {
                    $null
                }
                $status = if ($null -eq $maxAge -or $classification -eq 'Unknown' -or $null -eq $passwordAge) {
                    'Unknown'
                }
                elseif ($maxAge -eq 0) {
                    'NotConfigured'
                }
                elseif ($passwordAge -gt $maxAge) {
                    'Fail'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = 'ACCOUNT.PASSWORD_AGE'
                    Status = $status
                    Severity = 'Medium'
                    Category = 'Account'
                    Target = $target
                    Observed = $passwordAge
                    Expected = $maxAge
                    Evidence = @{
                                AccountType = $classification
                                PasswordStrengthEvaluated = $false
                            }
                    Message = 'Account age policy is profile-controlled and is not a password-strength test.'
                    Object = $object
                    Applicability = 'Configured'
                })
                $never = Get-ADAnalyzerDirectoryObservationField $object 'PasswordNeverExpires'
                $allowed = Get-ADAnalyzerDirectoryField $policy 'AllowPasswordNeverExpires'
                $expirationMessage = 'Exceptions and account purpose require explicit profile decisions.'
                $disabled = $false
                if ($scopedUser) {
                    if ($controllerUncorroborated) {
                        $expirationMessage = 'The Users query did not corroborate the selected directory controller. Recheck the account using a confirmed controller.'
                    }
                    $observation = @{
                        Value = Get-ADAnalyzerDirectoryObservationField $object 'UserAccountControl'
                        Enabled = $recordedEnabled
                        ExpirationFlag = $never
                    }
                    $scopedControl = Get-ADAnalyzerAccountControlObservation @observation
                    $user = $this.FindScopedUser($object, $scopedEvidence)
                    $subjectControl = $null
                    if ($null -ne $user) {
                        $subjectControl = $scopedControl
                        if (-not [object]::ReferenceEquals($user, $object)) {
                            $observed = @{
                                Value = Get-ADAnalyzerDirectoryObservationField $user 'UserAccountControl'
                                Enabled = Get-ADAnalyzerDirectoryObservationField $user 'Enabled'
                                ExpirationFlag = Get-ADAnalyzerDirectoryObservationField $user 'PasswordNeverExpires'
                            }
                            $subjectControl = Get-ADAnalyzerAccountControlObservation @observed
                        }
                    }
                    $never = $null
                    if ($null -ne $subjectControl -and $subjectControl.Consistent) {
                        $never = $subjectControl.PasswordNeverExpires
                        $disabled = -not $subjectControl.Enabled
                    }
                }
                $status = if ($disabled) {
                    'NotApplicable'
                }
                elseif ($never -isnot [bool] -or $null -eq $allowed) {
                    'Unknown'
                }
                elseif ($never -and -not $allowed) {
                    'Fail'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = 'ACCOUNT.PASSWORD_NEVER_EXPIRES'
                    Status = $status
                    Severity = 'Medium'
                    Category = 'Account'
                    Target = $target
                    Observed = $never
                    Expected = $allowed
                    Evidence = @()
                    Message = $expirationMessage
                    Object = $object
                    Applicability = 'Configured'
                })
            }
            $uac = if ($scopedUser) {
                if ($null -ne $scopedControl) {
                    $scopedControl.Flags
                }
            }
            else {
                Get-ADAnalyzerDirectoryField $object 'UserAccountControl'
            }
            $unconstrained = Get-ADAnalyzerDirectoryField $object 'TrustedForDelegation'
            if ($null -ne $uac) {
                $unconstrained = ([long]$uac -band 524288) -ne 0
            }
            $protocol = if ($null -ne $uac) {
                ([long]$uac -band 16777216) -ne 0
            }
            else {
                $null
            }
            $targets = @(Get-ADAnalyzerDirectoryField $object 'AllowedToDelegateTo' @())
            $approved = @(@(Get-ADAnalyzerDirectoryField $Profile 'ApprovedDelegationTargets' @()) + @(Get-ADAnalyzerDirectoryField $policy 'ApprovedDelegationTargets' @()) | Select-Object `
                    -Unique)
            $unapproved = @($targets | Where-Object { $_ -notin $approved })
            $rbcd = @(Get-ADAnalyzerDirectoryField $object 'ResourceBasedDelegation' @() | Where-Object { $_.AccessControlType -eq 'Allow' })
            $unapprovedRbcd = @($rbcd | Where-Object { $_.IdentitySid -notin $approved })
            $delegationStatus = if ($unconstrained -or $protocol -or $unapproved.Count -or $unapprovedRbcd.Count) {
                'Fail'
            }
            elseif ($null -eq $unconstrained -and $null -eq $protocol) {
                'Unknown'
            }
            elseif ((Get-ADAnalyzerDirectoryField $object 'DelegationSchemaStatus') -ne 'Collected') {
                'Unknown'
            }
            else {
                'Pass'
            }
            $this.Emit($Evaluation, @{
                RuleId = 'DELEGATION.EXPOSURE'
                Status = $delegationStatus
                Severity = 'High'
                Category = 'Delegation'
                Target = $target
                Observed = @{
                        Unconstrained = $unconstrained
                        ProtocolTransition = $protocol
                        ConstrainedTargets = $targets
                        ResourceBasedPrincipals = $rbcd
                    }
                Expected = $approved
                Evidence = @{
                        EffectiveAccessCalculated = $false
                    }
                Message = 'Review delegation configuration; ACEs do not constitute a complete effective-access calculation.'
                Object = $object
                Applicability = 'Configured'
            })
            if ($null -ne $uac) {
                foreach ($flag in @(@{
                            Rule = 'ACCOUNT.PASSWORD_NOT_REQUIRED'
                            Mask = 32
                        }, @{
                            Rule = 'KERBEROS.PREAUTH_NOT_REQUIRED'
                            Mask = 4194304
                        }, @{
                            Rule = 'KERBEROS.DES_ONLY'
                            Mask = 2097152
                        }, @{
                            Rule = 'ACCOUNT.REVERSIBLE_ENCRYPTION'
                            Mask = 128
                        })) {
                    $set = ([long]$uac -band $flag.Mask) -ne 0
                    $allowed = $flag.Rule -eq 'ACCOUNT.REVERSIBLE_ENCRYPTION' -and
                    (Get-ADAnalyzerDirectoryField $policy 'AllowReversibleEncryption' $false)
                    $this.Emit($Evaluation, @{
                        RuleId = $flag.Rule
                        Status = $(if ($set -and -not $allowed) {
                                            'Fail'
                                        }
                                        else {
                                            'Pass'
                                        })
                        Severity = 'High'
                        Category = 'Account'
                        Target = $target
                        Observed = $set
                        Expected = $allowed
                        Evidence = @{
                                        UserAccountControl = $uac
                                    }
                        Message = 'Configured account-control flag.'
                        Object = $object
                        Applicability = 'Configured'
                    })
                }
            }
            $enc = Get-ADAnalyzerDirectoryField $object 'SupportedEncryptionTypes'
            $encStatus = if ($null -eq $enc -or [long]$enc -eq 0) {
                'Unknown'
            }
            elseif (([long]$enc -band 24) -eq 0) {
                'Fail'
            }
            else {
                'Pass'
            }
            $this.Emit($Evaluation, @{
                RuleId = 'KERBEROS.ENCRYPTION_METADATA'
                Status = $encStatus
                Severity = 'Medium'
                Category = 'Kerberos'
                Target = $target
                Observed = $enc
                Expected = 'AES flags in explicit supported-encryption metadata'
                Evidence = @{
                        PasswordStrengthEvaluated = $false
                    }
                Message = 'Missing or zero metadata can inherit domain behavior and does not prove weak keys.'
                Object = $object
                Applicability = 'Configured'
            })
            foreach ($spn in @(Get-ADAnalyzerDirectoryField $object 'ServicePrincipalNames' @())) {
                if (-not $spn) {
                    continue
                }
                $key = ([string]$spn).ToLowerInvariant()
                if (-not $spns.ContainsKey($key)) {
                    $spns[$key] = [System.Collections.Generic.List[object]]::new()
                }
                $spns[$key].Add($object)
            }
            $history = @(Get-ADAnalyzerDirectoryField $object 'SIDHistory' @())
            if ($history.Count) {
                $privileged = @(Get-ADAnalyzerDirectoryField $domain 'PrivilegedSids' @())
                $knownPrivileged = [System.Collections.Generic.List[string]]::new()
                $unresolved = [System.Collections.Generic.List[string]]::new()
                foreach ($sid in $history) {
                    if ($sid -in $privileged) {
                        $knownPrivileged.Add([string]$sid)
                    }
                    elseif ($sidLookup.ContainsKey([string]$sid)) {
                        $historical = $sidLookup[[string]$sid]
                        $membership = $membershipGraph.Resolve($historical, $domain.SID, $privileged)
                        if ($membership.IsPrivileged -or (Get-ADAnalyzerDirectoryField $historical 'Privileged' $false)) {
                            $knownPrivileged.Add([string]$sid)
                        }
                        elseif ($membership.ResolutionStatus -ne 'Complete') {
                            $unresolved.Add([string]$sid)
                        }
                    }
                    else {
                        $unresolved.Add([string]$sid)
                    }
                }
                $status = if ($knownPrivileged.Count) {
                    'Fail'
                }
                elseif ($unresolved.Count) {
                    'Unknown'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = 'SIDHISTORY.PRIVILEGED'
                    Status = $status
                    Severity = 'High'
                    Category = 'Identity'
                    Target = $target
                    Observed = $history
                    Expected = 'No privileged historical SIDs'
                    Evidence = @{
                                Privileged = $knownPrivileged.ToArray()
                                Unresolved = $unresolved.ToArray()
                            }
                    Message = 'Unresolved historical SIDs are not declared invalid.'
                    Object = $object
                    Applicability = 'Configured'
                })
            }
            if ($kind -eq 'Computer') {
                $schema = @(Get-ADAnalyzerDirectoryField $domain 'FeatureSchema' @())
                $lapsKnown = 'msLAPS-PasswordExpirationTime' -in $schema -or 'ms-Mcs-AdmPwdExpirationTime' -in $schema
                $expiry = Get-ADAnalyzerDirectoryField $object 'LapsExpiration'
                if ($null -eq $expiry) {
                    $expiry = Get-ADAnalyzerDirectoryField $object 'LegacyLapsExpiration'
                }
                $require = Get-ADAnalyzerDirectoryField $policy 'RequireLaps'
                $status = if ($null -eq $require) {
                    'NotConfigured'
                }
                elseif (-not $require -or (Get-ADAnalyzerDirectoryField $object 'IsDomainController' $false)) {
                    'NotApplicable'
                }
                elseif (-not $lapsKnown -or $null -eq $expiry) {
                    'Unknown'
                }
                elseif ([datetime]$expiry -lt [datetime]::UtcNow) {
                    'Fail'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = 'LAPS.ROTATION_METADATA'
                    Status = $status
                    Severity = 'Medium'
                    Category = 'LAPS'
                    Target = $target
                    Observed = $expiry
                    Expected = 'Present, unexpired LAPS rotation metadata'
                    Evidence = @{
                                SecretValuesRead = $false
                                SchemaAvailable = $lapsKnown
                                DomainControllerRequiresSeparateDsrmAssessment = $object.IsDomainController
                            }
                    Message = 'Metadata is not proof of effective retrieval permissions or successful rotation.'
                    Object = $object
                    Applicability = 'Configured'
                })
                $osResult = $this.EvaluateOperatingSystem(
                    $object,
                    @(Get-ADAnalyzerDirectoryField $policy 'SupportedOperatingSystems' @())
                )
                $this.Emit($Evaluation, @{
                    RuleId = 'COMPUTER.OS_POLICY'
                    Status = $osResult.Status
                    Severity = 'Medium'
                    Category = 'Host'
                    Target = $target
                    Observed = $osResult.Observed
                    Expected = $osResult.Expected
                    Evidence = $osResult.Evidence
                    Message = 'Support requires explicit version/build/lifecycle metadata and ESU evidence when required.'
                    Object = $object
                    Applicability = 'Configured'
                })
            }
            if ($classification -eq 'Service') {
                $required = Get-ADAnalyzerDirectoryField $policy 'RequireGmsaForServiceAccounts' $false
                $managed = $object.DirectoryObjectClass -in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')
                $this.Emit($Evaluation, @{
                    RuleId = 'SERVICE_ACCOUNT.MANAGED_IDENTITY'
                    Status = $(if (-not $required) {
                                    'NotApplicable'
                                }
                                elseif ($managed) {
                                    'Pass'
                                }
                                else {
                                    'Fail'
                                })
                    Severity = 'Medium'
                    Category = 'ServiceAccount'
                    Target = $target
                    Observed = $object.DirectoryObjectClass
                    Expected = 'Managed service account when required by profile'
                    Evidence = @{
                                RetrievalPrincipals = Get-ADAnalyzerDirectoryField $object 'PrincipalsAllowedToRetrieveManagedPassword'
                                IntervalDays = Get-ADAnalyzerDirectoryField $object 'ManagedPasswordIntervalInDays'
                                SecretValuesRead = $false
                            }
                    Message = 'Managed-account configuration metadata; managed password values are never read.'
                    Object = $object
                    Applicability = 'Configured'
                })
                if ($managed) {
                    $principals = @(Get-ADAnalyzerDirectoryField $object 'PrincipalsAllowedToRetrieveManagedPassword' @() | ForEach-Object { ConvertTo-ADAnalyzerSid (Get-ADAnalyzerDirectoryField $_ 'SID' $_) })
                    $approvedReaders = @(Get-ADAnalyzerDirectoryField $policy 'ApprovedGmsaReaderSids' @())
                    $unresolvedReaders = @($principals | Where-Object { $_ -notmatch '^S-\d-' })
                    $readerStatus = if (-not $approvedReaders.Count) {
                        'NotConfigured'
                    }
                    elseif (-not $principals.Count -or $unresolvedReaders.Count) {
                        'Unknown'
                    }
                    elseif (@($principals | Where-Object { $_ -notin $approvedReaders }).Count) {
                        'Fail'
                    }
                    else {
                        'Pass'
                    }
                    $this.Emit($Evaluation, @{
                        RuleId = 'GMSA.RETRIEVAL_PRINCIPALS'
                        Status = $readerStatus
                        Severity = 'High'
                        Category = 'ServiceAccount'
                        Target = $target
                        Observed = $principals
                        Expected = $approvedReaders
                        Evidence = @{
                                        Unresolved = $unresolvedReaders
                                        EffectiveAccessCalculated = $false
                                        SecretValuesRead = $false
                                    }
                        Message = 'Configured retrieval-principal metadata; nested tokens and deny precedence are not an effective-access calculation.'
                        Object = $object
                        Applicability = 'Configured'
                    })
                }
            }
        }
        foreach ($key in ([Collections.IDictionary].GetProperty('Keys')).GetValue($spns, $null)) {
            $owners = @($spns[$key] | ForEach-Object { Get-ADAnalyzerDirectoryTarget $_ } | Select-Object -Unique)
            if ($owners.Count -gt 1) {
                $this.Emit($Evaluation, @{
                    RuleId = 'SPN.DUPLICATE'
                    Status = 'Fail'
                    Severity = 'High'
                    Category = 'Kerberos'
                    Target = $key
                    Observed = $owners
                    Expected = 'One owner per SPN in the collected scope'
                    Evidence = @{
                                Scope = $Data.Server
                            }
                    Message = 'Duplicate SPN owners require review, without inferring password strength.'
                    Object = $null
                    Applicability = 'Configured'
                })
            }
        }
    }

    hidden [void] EvaluateTrustsAndAcl([hashtable]$Evaluation) {
        $Data = $Evaluation.Data
        $Profile = $Evaluation.Profile
        $policy = $Evaluation.Policy
        $domain = $Evaluation.Domain
        $domainTarget = $Evaluation.DomainTarget
        $coverage = $Evaluation.Coverage

        foreach ($trust in @(Get-ADAnalyzerDirectoryField $Data 'Trusts' @())) {
            $intraForest = Get-ADAnalyzerDirectoryObservationField $trust 'IntraForest'
            $forestTrust = Get-ADAnalyzerDirectoryObservationField $trust 'ForestTransitive'
            $filtering = $null
            if ($forestTrust -is [bool]) {
                $flagName = if ($forestTrust) {
                    'SIDFilteringForestAware'
                }
                else {
                    'SIDFilteringQuarantined'
                }
                $filtering = Get-ADAnalyzerDirectoryObservationField $trust $flagName
            }

            $status = if ($intraForest -is [bool] -and $intraForest) {
                'NotApplicable'
            }
            elseif ($intraForest -isnot [bool] -or $forestTrust -isnot [bool] -or $filtering -isnot [bool]) {
                'Unknown'
            }
            elseif ($filtering) {
                'Pass'
            }
            else {
                'Fail'
            }
            $this.Emit($Evaluation, @{
                RuleId = 'TRUST.SID_FILTERING'
                Status = $status
                Severity = 'High'
                Category = 'Trust'
                Target = ([string](Get-ADAnalyzerDirectoryField $trust 'Target' (Get-ADAnalyzerDirectoryField $trust 'Name')))
                Observed = $filtering
                Expected = $true
                Evidence = @{
                        IntraForest = $intraForest
                        Direction = Get-ADAnalyzerDirectoryField $trust 'Direction'
                        Type = Get-ADAnalyzerDirectoryField $trust 'TrustType'
                        SelectiveAuthentication = Get-ADAnalyzerDirectoryField $trust 'SelectiveAuthentication'
                        TGTDelegation = Get-ADAnalyzerDirectoryField $trust 'TGTDelegation'
                    }
                Message = 'Boundary SID filtering is not applied to normal intra-forest parent/child trusts.'
                Object = $null
                Applicability = 'Configured'
            })
        }
        $acl = Get-ADAnalyzerDirectoryField $Data 'Acl'
        $approvedReplication = @(@(Get-ADAnalyzerDirectoryField $Profile 'ApprovedReplicationSids' @()) + @(Get-ADAnalyzerDirectoryField $policy 'ApprovedReplicationSids' @()) | Select-Object `
                -Unique)
        if ($domain.SID) {
            $approvedReplication += ($domain.SID + '-516')
        }
        $approvedReplication += 'S-1-5-9'
        if (Get-ADAnalyzerDirectoryField $policy 'IncludeAdministrativeReplicationRoles' $true) {
            $approvedReplication += @('S-1-5-18', 'S-1-5-32-544')
            if ($domain.SID) {
                $approvedReplication += ($domain.SID + '-512')
            }
            if ($domain.RootDomainSID) {
                $approvedReplication += ($domain.RootDomainSID + '-519')
            }
        }
        $replication = @{}
        $seenAces = @{}
        foreach ($ace in @(Get-ADAnalyzerDirectoryField $acl 'Entries' @())) {
            if ($ace.AccessControlType -ne 'Allow' -or -not $ace.IdentitySid) {
                continue
            }
            $aceKey = (@($ace.Target,
                    $ace.IdentitySid,
                    $ace.ObjectType,
                    $ace.Rights,
                    $ace.InheritedObjectType,
                    [string]$ace.IsInherited,
                    [string]$ace.PropagationFlags,
                    [string]$ace.InheritanceType) -join '|')
            if ($seenAces.ContainsKey($aceKey)) {
                continue
            }
            $seenAces[$aceKey] = $true
            if ($ace.TargetType -eq 'DomainRoot' -and [string]$ace.PropagationFlags -notmatch 'InheritOnly') {
                if (-not $replication.ContainsKey($ace.IdentitySid)) {
                    $replication[$ace.IdentitySid] = @{
                        Changes = $false
                        All = $false
                        Evidence = [System.Collections.Generic.List[object]]::new()
                    }
                }
                $grant = $replication[$ace.IdentitySid]
                $allRights = $ace.Rights -match 'GenericAll' -or
                ($ace.Rights -match 'ExtendedRight' -and
                (!$ace.ObjectType -or
                $ace.ObjectType -eq ([guid]::Empty).ToString()))
                if ($allRights -or ($ace.Rights -match 'ExtendedRight' -and $ace.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')) {
                    $grant.Changes = $true
                }
                if ($allRights -or ($ace.Rights -match 'ExtendedRight' -and $ace.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) {
                    $grant.All = $true
                }
                $grant.Evidence.Add($ace)
            }
            if ($ace.Rights -match 'GenericAll|WriteDacl|WriteOwner' -and $ace.IdentitySid -notin @($domain.PrivilegedSids)) {
                $this.Emit($Evaluation, @{
                    RuleId = 'ACL.DELEGATED_CONTROL'
                    Status = 'Fail'
                    Severity = 'High'
                    Category = 'ACL'
                    Target = $aceKey
                    Observed = $ace
                    Expected = @{
                                ApprovedPrivilegedSids = $domain.PrivilegedSids
                            }
                    Evidence = @{
                                EffectiveAccessCalculated = $false
                            }
                    Message = 'Potential broad delegated control; ACE order, deny rules and token semantics still require review.'
                    Object = $null
                    Applicability = 'Configured'
                })
            }
            if ($ace.ObjectTypeName -in @('msLAPS-Password',
                    'msLAPS-EncryptedPassword',
                    'msLAPS-EncryptedPasswordHistory',
                    'msLAPS-EncryptedDSRMPassword',
                    'ms-Mcs-AdmPwd') -and
                $ace.Rights -match 'ReadProperty|ExtendedRight|GenericRead|GenericAll') {
                $approvedReaders = @(Get-ADAnalyzerDirectoryField $policy 'ApprovedLapsReaderSids' @())
                $readerStatus = if (-not $approvedReaders.Count) {
                    'NotConfigured'
                }
                elseif ($ace.IdentitySid -in $approvedReaders) {
                    'Pass'
                }
                else {
                    'Fail'
                }
                $this.Emit($Evaluation, @{
                    RuleId = 'LAPS.ATTRIBUTE_READ_ACL'
                    Status = $readerStatus
                    Severity = 'High'
                    Category = 'ACL'
                    Target = $aceKey
                    Observed = $ace
                    Expected = $approvedReaders
                    Evidence = @{
                                EffectiveAccessCalculated = $false
                                ConfidentialAttributeAccessCalculated = $false
                                DecryptionPermissionsCalculated = $false
                            }
                    Message = 'An allow ACE references LAPS data; this does not establish plaintext retrieval or effective access.'
                    Object = $null
                    Applicability = 'Configured'
                })
            }
        }
        foreach ($sid in ([Collections.IDictionary].GetProperty('Keys')).GetValue($replication, $null)) {
            $grant = $replication[$sid]
            if ($grant.Changes -and $grant.All) {
                $this.Emit($Evaluation, @{
                    RuleId = 'ACL.REPLICATION_RIGHTS'
                    Status = $(if ($sid -in $approvedReplication) {
                                    'Pass'
                                }
                                else {
                                    'Fail'
                                })
                    Severity = 'Critical'
                    Category = 'ACL'
                    Target = ($domainTarget + '|SID=' + $sid)
                    Observed = $sid
                    Expected = $approvedReplication
                    Evidence = @{
                                Aces = $grant.Evidence.ToArray()
                                EffectiveAccessCalculated = $false
                            }
                    Message = 'Direct allow ACEs expose replication capabilities; this is not complete effective access.'
                    Object = $null
                    Applicability = 'Configured'
                })
            }
        }
    }

    hidden [void] EvaluatePasswordPolicies([hashtable]$Evaluation) {
        $Data = $Evaluation.Data
        $Profile = $Evaluation.Profile
        $policy = $Evaluation.Policy
        $domain = $Evaluation.Domain
        $domainTarget = $Evaluation.DomainTarget
        $coverage = $Evaluation.Coverage

        $effective = Get-ADAnalyzerDirectoryField (Get-ADAnalyzerDirectoryField $Data 'PasswordPolicies') 'Resultant' @()
        foreach ($entry in @($effective)) {
            $password = $entry.Policy
            foreach ($spec in @(
                    @{
                        Rule = 'PASSWORD.MIN_LENGTH'
                        Field = 'MinPasswordLength'
                        Profile = 'MinimumPasswordLength'
                        Mode = 'Minimum'
                    },
                    @{
                        Rule = 'PASSWORD.LOCKOUT_THRESHOLD'
                        Field = 'LockoutThreshold'
                        Profile = 'LockoutThreshold'
                        Mode = 'MaximumNonzero'
                    },
                    @{
                        Rule = 'PASSWORD.HISTORY'
                        Field = 'PasswordHistoryCount'
                        Profile = 'PasswordHistorySize'
                        Mode = 'Minimum'
                    },
                    @{
                        Rule = 'PASSWORD.COMPLEXITY'
                        Field = 'ComplexityEnabled'
                        Profile = 'PasswordComplexity'
                        Mode = 'Equal'
                    },
                    @{
                        Rule = 'PASSWORD.REVERSIBLE_ENCRYPTION'
                        Field = 'ReversibleEncryptionEnabled'
                        Profile = 'AllowReversibleEncryption'
                        Mode = 'Allow'
                    }
                )) {
                $expected = Get-ADAnalyzerDirectoryField $policy $spec.Profile
                $actual = Get-ADAnalyzerDirectoryField $password $spec.Field
                $status = if ($null -eq $expected -or ($spec.Mode -eq 'MaximumNonzero' -and $expected -eq 0)) {
                    'NotConfigured'
                }
                elseif ($entry.Status -ne 'Collected' -or $null -eq $actual) {
                    'Unknown'
                }
                elseif ($spec.Mode -eq 'Minimum' -and $actual -lt $expected) {
                    'Fail'
                }
                elseif ($spec.Mode -eq 'MaximumNonzero' -and ($actual -eq 0 -or $actual -gt $expected)) {
                    'Fail'
                }
                elseif ($spec.Mode -eq 'Equal' -and $actual -ne $expected) {
                    'Fail'
                }
                elseif ($spec.Mode -eq 'Allow' -and $actual -and -not $expected) {
                    'Fail'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = $spec.Rule
                    Status = $status
                    Severity = 'Medium'
                    Category = 'PasswordPolicy'
                    Target = $entry.Target
                    Observed = $actual
                    Expected = $expected
                    Evidence = @{
                                PolicySource = $entry.Source
                                PolicyDN = Get-ADAnalyzerDirectoryField $password 'DistinguishedName'
                            }
                    Message = 'Effective/default policy metadata; actual password content is not inspected.'
                    Object = $null
                    Applicability = 'Applicable'
                })
            }
            foreach ($spec in @(
                    @{
                        Rule = 'PASSWORD.LOCKOUT_DURATION'
                        Field = 'LockoutDuration'
                        Profile = 'LockoutDurationMinutes'
                        Unit = 'Minutes'
                        Zero = 'Unlimited'
                    },
                    @{
                        Rule = 'PASSWORD.LOCKOUT_RESET'
                        Field = 'LockoutObservationWindow'
                        Profile = 'ResetLockoutMinutes'
                        Unit = 'Minutes'
                        Zero = 'Normal'
                    },
                    @{
                        Rule = 'PASSWORD.MIN_AGE'
                        Field = 'MinPasswordAge'
                        Profile = 'MinimumPasswordAgeDays'
                        Unit = 'Days'
                        Zero = 'Normal'
                    },
                    @{
                        Rule = 'PASSWORD.MAX_AGE'
                        Field = 'MaxPasswordAge'
                        Profile = 'MaximumPasswordAgeDays'
                        Unit = 'Days'
                        Zero = 'Never'
                    }
                )) {
                $expected = Get-ADAnalyzerDirectoryField $policy $spec.Profile
                $raw = Get-ADAnalyzerDirectoryField $password $spec.Field
                $actual = $null
                if ($null -ne $raw) {
                    try {
                        $span = [timespan]$raw
                        $actual = if ($spec.Unit -eq 'Days') {
                            $span.TotalDays
                        }
                        else {
                            $span.TotalMinutes
                        }
                    }
                    catch {
                    }
                }
                $allowNever = Get-ADAnalyzerDirectoryField $policy 'AllowPasswordNeverExpires' $false
                $status = if ($null -eq $expected) {
                    'NotConfigured'
                }
                elseif ($entry.Status -ne 'Collected' -or $null -eq $actual) {
                    'Unknown'
                }
                elseif ($spec.Zero -eq 'Unlimited' -and $actual -eq 0) {
                    'Pass'
                }
                elseif ($spec.Zero -eq 'Never' -and $actual -eq 0 -and $allowNever) {
                    'Pass'
                }
                elseif ($spec.Zero -eq 'Never' -and $expected -eq 0) {
                    'NotConfigured'
                }
                elseif ($spec.Zero -eq 'Never' -and ($actual -eq 0 -or $actual -gt $expected)) {
                    'Fail'
                }
                elseif ($spec.Zero -ne 'Never' -and $actual -lt $expected) {
                    'Fail'
                }
                else {
                    'Pass'
                }
                $this.Emit($Evaluation, @{
                    RuleId = $spec.Rule
                    Status = $status
                    Severity = 'Medium'
                    Category = 'PasswordPolicy'
                    Target = $entry.Target
                    Observed = $actual
                    Expected = $expected
                    Evidence = @{
                                PolicySource = $entry.Source
                                ZeroSemantics = $spec.Zero
                                AllowPasswordNeverExpires = $allowNever
                            }
                    Message = 'Durations use explicit zero-value semantics.'
                    Object = $null
                    Applicability = 'Applicable'
                })
            }
        }
    }

    hidden [void] EvaluateHostEvidence([hashtable]$Evaluation) {
        $Data = $Evaluation.Data
        $Profile = $Evaluation.Profile
        $policy = $Evaluation.Policy
        $domain = $Evaluation.Domain
        $domainTarget = $Evaluation.DomainTarget
        $coverage = $Evaluation.Coverage

        foreach ($hostRecord in @(Get-ADAnalyzerDirectoryField $Data 'Hosts' @())) {
            $this.Emit($Evaluation, @{
                RuleId = 'HOST.OBSERVATIONS'
                Status = 'Unknown'
                Severity = 'Information'
                Category = 'Host'
                Target = $hostRecord.ComputerName
                Observed = $hostRecord
                Expected = 'Explicit host baseline and effective-state validation'
                Evidence = @{
                        ObservedOnly = $true
                    }
                Message = 'CIM and registry observations are not implied effective compliance.'
                Object = $null
                Applicability = 'Unknown'
            })
        }
    }
}

function Test-ADAnalyzerDirectoryPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Data,
        [Parameter(Mandatory = $true)][hashtable]$Profile

    )
    $evaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
    $preference = if ($PSBoundParameters.ContainsKey('ErrorAction')) {
        $PSBoundParameters.ErrorAction
    }
    else {
        $ErrorActionPreference
    }

    $evaluator.EvaluateForCommand($Data, $Profile, $PSCmdlet, $preference)
}
