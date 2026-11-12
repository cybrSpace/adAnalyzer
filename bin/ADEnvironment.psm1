using namespace System.Xml
using namespace System.Collections
using namespace System.Collections.Specialized
using namespace System.Management.Automation

. (Join-Path $PSScriptRoot 'ADGpo.ps1')
. (Join-Path $PSScriptRoot 'ADProfile.ps1')
. (Join-Path $PSScriptRoot 'ADPolicyAnalysis.ps1')
. (Join-Path $PSScriptRoot 'ADDirectoryAnalysis.ps1')
. (Join-Path $PSScriptRoot 'ADHostAnalysis.ps1')
. (Join-Path $PSScriptRoot 'ADOperations.ps1')
. (Join-Path $PSScriptRoot 'ADAssessment.ps1')
. (Join-Path $PSScriptRoot 'Start-ADAnalyzer.ps1')

######################################################################################################################################################################################################################################################
#region Enumeration

Enum DateAttributes {

    passwordlastset
    lastlogondate
    whenChanged
    whenCreated

}

Enum ObjectClasses {

    user
    group
    computer
    GroupPolicy

}

Enum EnvironmentObjects {

    UserObject
    ComputerObject
    GroupObject
    GroupPolicyObject
    PasswordPolicyObject

}

Enum GPOConfiguration {
    
    Computer
    User

}

Enum GPOExtensionType {

    Security
    Registry
    Preferences
    Xml
    Ini

}

Enum GPOExtensionProperty {

    Account
    SecurityOptions
    UserRightsAssignment

}


#endregion Enumeration
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Classes
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Helper

Class Convert {

    static [boolean] ToBoolean([string]$value) {

        $object = $false

        switch ($value) {

            'y' { $object = $true }
            'yes' { $object = $true }
            'true' { $object = $true }
            't' { $object = $true }
            1 { $object = $true }

            'n' { $object = $false }
            'no' { $object = $false }
            'false' { $object = $false }
            'f' { $object = $false }
            0 { $object = $false }

            default { $object = $false }

        }

        return $object

    }

    static [PSCustomObject]ToExport([PSCustomObject]$object) {

        $projection = ConvertTo-ADAnalyzerSafeData -InputObject $object
        foreach ($item in $projection.PSObject.Properties) {

            switch ($item.Value) {

                { $item.Value -is [Array] -or $item.Value -is [ArrayList] } { $projection.($item.Name) = $item.Value -join ';' }

            }

        }

        return $projection

    }

    static [OrderedDictionary]ToOrderedDictionary($value) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        if ($null -eq $value) { return $object }

        if ($value -is [OrderedDictionary] -or $value -is [Hashtable] -or $value.GetType().Name -in ([EnvironmentObjects].GetEnumNames())) {
            $value.Keys | ForEach-Object { $object[$_] = $value[$_] }
        }
        elseif ($value -is [PSCustomObject]) {
            $value.PSObject.Properties | ForEach-Object { $object[$_.Name] = $_.Value }
        }

        return $object

    }

}
class Format {

    static [OrderedDictionary]DateAttributes([String]$name, $value) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        switch ($name) {

            'lastlogondate' { $name = 'lastlogon' }
            'passwordlastset' { $name = 'pwdlastset' }

            default { }

        }
        if ([String]::IsNullOrEmpty($name)) { return $null }
        if ($null -eq $value -or [String]::IsNullOrEmpty([String]$value)) {
            $object[('days.{0}' -f $name)] = $null
        }
        else {
            $object[('days.{0}' -f $name)] = [math]::Floor(([datetime]::Now - (Get-Date $value)).TotalDays)
        }

        switch ($object[('days.{0}' -f $name)]) {

            { $null -eq $_ } { $object['range.{0}' -f $name] = 'never' }

            { $_ -gt 180 } { $object['range.{0}' -f $name] = '> 180 days' }

            { $_ -le 180 -and $_ -gt 150 } { $object['range.{0}' -f $name] = '151 - 180 days' }
            { $_ -le 150 -and $_ -gt 120 } { $object['range.{0}' -f $name] = '121 - 150 days' }
            { $_ -le 120 -and $_ -gt 90 } { $object['range.{0}' -f $name] = '91 - 120 days' }
            { $_ -le 90 -and $_ -gt 60 } { $object['range.{0}' -f $name] = '61 - 90 days' }
            { $_ -le 60 -and $_ -gt 30 } { $object['range.{0}' -f $name] = '31 - 60 days' }
            { $_ -le 30 -and $_ -gt 14 } { $object['range.{0}' -f $name] = '15 - 30 days' }
            { $_ -le 14 -and $_ -gt 7 } { $object['range.{0}' -f $name] = '8 - 14 days' }

            { $null -ne $_ -and $_ -le 7 } { $object['range.{0}' -f $name] = '<= 7 days' }
            
        }

        return $object

    }

    static [OrderedDictionary]DistinguishedName([String]$value) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        $parts = @([regex]::Matches($value, '(?:\\.|[^,])+') | ForEach-Object { $_.Value.Trim() } | Where-Object { $_ -match '^(?:CN|OU|DC)=' })
        for ($index = 0; $index -lt 3; $index++) {
            $name = 'orgUnit.L{0}' -f $index
            $object[$name] = $null
            if ($parts.Count -gt ($index + 1)) {
                $object[$name] = ($parts[$index + 1] -replace '^(?:CN|OU|DC)=', '') -replace '\\([,+"\\<>;=#])', '$1'
            }
        }

        return $object

    }

    static [OrderedDictionary]ValueCollection($value, [Array]$exclude) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)
        if ($null -eq $value) { return $object }
        $entries = if ($value.PSObject.Methods['GetEnumerator']) { $value.GetEnumerator() } else { $value.PSObject.Properties }
        foreach ($entry in $entries) {
            $key = if ($entry.PSObject.Properties['Key']) { $entry.Key } else { $entry.Name }
            if ($key -in $exclude) { continue }
            $item = $entry.Value
            if ($item -is [System.Collections.IEnumerable] -and $item -isnot [String] -and $item -isnot [System.Collections.IDictionary]) {
                $items = @($item)
                if ($items.Count -eq 0) { $item = $null }
                elseif ($items.Count -eq 1) { $item = $items[0] }
                else { $item = [ArrayList]$items }
            }
            $keyName = [string]$key
            if ((Test-ADAnalyzerSecretName $keyName) -or $item -is [pscredential] -or $item -is [Security.SecureString]) {
                $flag = $keyName + 'Present'
                $present = Test-ADAnalyzerSecretPresence $item
                if ($object.Contains($flag) -and $object[$flag] -is [bool]) { $present = $present -or $object[$flag] }
                $object[$flag] = [bool]$present
                continue
            }
            if ($keyName.EndsWith('Present', [StringComparison]::OrdinalIgnoreCase) -and (Test-ADAnalyzerSecretName ($keyName.Substring(0, $keyName.Length - 7)))) {
                $recorded = $false
                if (-not [bool]::TryParse([string]$item, [ref]$recorded)) { $recorded = Test-ADAnalyzerSecretPresence $item }
                if ($object.Contains($keyName) -and $object[$keyName] -is [bool]) { $recorded = $recorded -or $object[$keyName] }
                $object[$keyName] = [bool]$recorded
                continue
            }
            if ($item -is [string]) { $item = ConvertTo-ADAnalyzerSecretIndicatorText $item }
            elseif ($item -is [ArrayList]) {
                for ($index = 0; $index -lt $item.Count; $index++) {
                    if ($item[$index] -is [string]) { $item[$index] = ConvertTo-ADAnalyzerSecretIndicatorText $item[$index] }
                }
            }
            $object[$key] = $item
        }
        return $object

    }

    static [OrderedDictionary]OrderedProperties($value, $list) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $list) { $object[$name] = $value[$name] }
        return $object

    }

}
class Export {

    static [void]CSV($array, $value) {

        try {

            $list = [ArrayList]::New()

            $array | ForEach-Object { 
                
                if ($_ -is [List] -or $_ -is [ArrayList]) {

                    $item = $_

                    $item | ForEach-Object { if ($null -ne $_) { $list.Add([Convert]::ToExport($_)) > $null } }

                }
                else {

                    if ($null -ne $_) { $list.Add([Convert]::ToExport([PSCustomObject]$_)) > $null }

                }
            
            }

            $columns = [ArrayList]::New()
            $seen = [System.Collections.Generic.HashSet[string]]::New([StringComparer]::OrdinalIgnoreCase)
            foreach ($record in $list) {
                foreach ($property in $record.PSObject.Properties) {
                    if ($seen.Add($property.Name)) { $null = $columns.Add($property.Name) }
                }
            }
            $rows = [ArrayList]::New()
            foreach ($record in $list) {
                $row = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)
                foreach ($column in $columns) {
                    $property = $record.PSObject.Properties[$column]
                    $row[$column] = if ($null -ne $property) { $property.Value } else { $null }
                }
                $null = $rows.Add([PSCustomObject]$row)
            }
            $content = if ($rows.Count) { ($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine } else { '' }
            $null = Write-ADAnalyzerFile -Path $value -Content $content

        }
        catch {

            throw '{0}({1})' -f 'exporting_data', $_.Exception.Message

        }

    }

}

#endregion Helper
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Base

class Data {

    [String]$Name
    [Table]$Data
    [Table]$Report
    [Finding]$Finding

    [void]GetData() {}
    [void]GetReport() {}
    [void]GetFinding() {}

    [void]Analyze() {

        $this.GetData()
        $this.GetReport()
        $this.GetFinding()

    }
    [void]SetFinding() {}

    [void]SyncFindings() {

        if ($null -ne $this.Finding -and $this.Finding.Count -gt 0) {

            [FindingData]::Add($this.Name, $this.Finding)

        }

    }

}
class Property {

    [String]$Key

    [Array]$List = [Array]@()
    [Array]$Exclude = @(
        'WriteDebugStream', 'WriteErrorStream', 'WriteInformationStream', 'WriteVerboseStream', 'WriteWarningStream'
        'PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount'

        # TODO: Write helpers to enable these properties
        # do not enable this NTSecurityDescriptor!! 10x resource usage

        'nTSecurityDescriptor', 'msExchMailboxSecurityDescriptor', 'logonHours'

    )

    [void]SetKey([String]$value) { $this.Key = $value }
    [void]SetList([Array]$value) { $this.List = $value }

    [void]AddPropertyName($value) {

        $this.Names[$value] = $null

    }

    [void]SetPropertyNames($value) {

        try {         
            $this.Names.Clear()
            $value | Where-Object { $_ -notin $this.Exclude } | ForEach-Object { $this.Names[$_] = $null }
        }
        catch {
            throw '{0}({1})' -f 'exception_setting_propertyNames', $_.Exception.Message
        }

    }

    [ArrayList]GetNames() { return $this.Names.Keys }

    hidden [OrderedDictionary]$Names = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

}
class Process {

    static [Boolean]$WhatIf
    static [Boolean]$Confirm

    static [void]Close() {

        [Process]::WhatIf = $null
        [Process]::Confirm = $null

    }   
    static [void]Initialize([Boolean]$WhatIf, [Boolean]$Confirm) {

        [Process]::WhatIf = $WhatIf
        [Process]::Confirm = $Confirm

    }

}
class Table : Hashtable {

    [Property]$Properties = [Property]::New()

    Table() : base([StringComparer]::OrdinalIgnoreCase) {}

    [void]FormatData() {

        $table = @{}

        $key = $this.Properties.Key

        $list = $this.Values.Keys | Sort-Object -Unique | Where-Object { $_ -notin $this.Properties.Exclude } 

        $this.Values | ForEach-Object {

            $object = [Format]::OrderedProperties($_, $list)

            $table[$object.($key)] = $object

        }

        $this.Properties.SetPropertyNames($list)

        $table.GetEnumerator() | ForEach-Object { $this[$_.Name] = $_.Value }

    }
    [void]ExportCSV([String]$value) {

        [Export]::CSV($this.Values, $value)

    }

}
class List : ArrayList {

    [void]AddItem([ArrayList]$value) {

        if ($value.Count -eq 1) {
            $this.AddRange([ArrayList]@($value)) > $null
        }
        elseif ($value.Count -gt 1) {
            $this.AddRange($value)
        }

    }
    [void]ExportCSV([String]$value) {
        [Export]::CSV($this, $value)
    }

}
class Finding : List {

    [void]AddFinding($value, $item) {

        $object = [Convert]::ToOrderedDictionary($value)

        $object['finding'] = $item

        $this.Add([PSCustomObject]$object) > $null

    }
    [void]UpdateFinding($value, $item) {

        if ($null -ne $item) {

            $object = [Convert]::ToOrderedDictionary($value)

            @('action', 'result', 'message') | ForEach-Object { $object[$_] = $item[$_] }

            $this.Add([PSCustomObject]$object) > $null

        }

    }
    
    static [Object]Delete($value) {
        throw [NotSupportedException]::new('Unplanned deletion is disabled. Use a reviewed remediation plan; deletion is not an automatic action.')
    }
    static [Object]Disable($value) {
        throw [NotSupportedException]::new('Unplanned mutation is disabled. Use Invoke-ADAnalyzerRemediationPlan with a journal.')
    }

    static [OrderedDictionary]Remediate([Object]$value, [String]$item) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        $object['action'] = $item
        $object['result'] = $false
        $object['message'] = $null

        try {

            switch ($object['action']) {

                'delete' { $object['result'] = [Finding]::Delete($value) }
                'disable' { $object['result'] = [Finding]::Disable($value) }

            }   

        }
        catch { 

            $object['result'] = $false

            $object['message'] = '{0}({1})' -f 'findingRemediation', $_.Exception.Message  

        }

        return $object

    }

}

#endregion Base
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Domain

class DomainData : Data {

    DomainData() { $this.Name = 'Domain' }

    [String]$FQDN
    [String]$DomainSID
    [String]$RootDomainSID

    [Hashtable]$WellKnownSID

    [PSCustomObject]$Containers
    [PSCustomObject]$Identifiers
    [PSCustomObject]$fsmoRoles
    [PSCustomObject]$PasswordPolicy
    [PSCustomObject]$OptionalFeatures

    static [DomainData]$Instance

    static [DomainData]Initialize() {

        [DomainData]::Instance = [DomainData]::New()

        return [DomainData]::Instance

    }
    static [DomainData]GetInstance() {

        if ($null -eq [DomainData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [DomainData]::Instance

        }

    }
    static [void]Close() {

        [PasswordPolicy]::Close()
        [DomainData]::Instance = $null

    }
    [Hashtable]GetWellKnownSID() {

        if ([String]::IsNullOrEmpty($this.DomainSID) -or [String]::IsNullOrEmpty($this.RootDomainSID)) {

            throw '{0}({1})' -f 'wellKnownSid', 'domain data is not properly initialized'

        }

        return [Hashtable]@{

            ('S-1-5-32-544')                          = 'Administrators'
            ('s-1-5-32-545')                          = 'Users'
            ('s-1-5-32-546')                          = 'Guests'
            ('s-1-5-32-547')                          = 'Power Users'
            ('s-1-5-32-548')                          = 'Account Operators'
            ('s-1-5-32-549')                          = 'Server Operators'
            ('s-1-5-32-550')                          = 'Print Operators'
            ('s-1-5-32-551')                          = 'Backup Operators'
            ('s-1-5-32-552')                          = 'Replicators'

            ('s-1-5-32-581')                          = 'System Managed Accounts Group'

            ('{0}-{1}' -f $this.DomainSID, '500')     = 'Administrator'
            ('{0}-{1}' -f $this.DomainSID, '501')     = 'Guest'
            ('{0}-{1}' -f $this.DomainSID, '502')     = 'KRBTGT'
            ('{0}-{1}' -f $this.DomainSID, '503')     = 'DefaultAccount'

            ('{0}-{1}' -f $this.DomainSID, '512')     = 'Domain Admins'
            ('{0}-{1}' -f $this.DomainSID, '513')     = 'Domain Users'
            ('{0}-{1}' -f $this.DomainSID, '514')     = 'Domain Guests'
            ('{0}-{1}' -f $this.DomainSID, '515')     = 'Domain Computers'
            ('{0}-{1}' -f $this.DomainSID, '516')     = 'Domain Controllers'
            ('{0}-{1}' -f $this.DomainSID, '517')     = 'Cert Publishers'
            ('{0}-{1}' -f $this.DomainSID, '520')     = 'Group Policy Creator Owners'
            ('{0}-{1}' -f $this.DomainSID, '526')     = 'Key Admins'
            ('{0}-{1}' -f $this.DomainSID, '527')     = 'Enterprise Key Admins'
            ('{0}-{1}' -f $this.DomainSID, '553')     = 'RAS and IAS Servers'

            ('{0}-{1}' -f $this.RootDomainSID, '518') = 'Schema Admins'
            ('{0}-{1}' -f $this.RootDomainSID, '519') = 'Enterprise Admins'
            ('{0}-{1}' -f $this.RootDomainSID, '521') = 'Read-only Domain Controllers'
            ('{0}-{1}' -f $this.RootDomainSID, '571') = 'Allowed RODC Password Replication Group'   

        }

    }
    [PSCustomObject]GetDomainControllers([Microsoft.ActiveDirectory.Management.ADPartition]$domain) {

        return [PSCustomObject]@{

            Computer         = $domain.ComputersContainer
            DomainController = $domain.DomainControllersContainer
            DeletedObject    = $domain.DeletedObjectsContainer
            ForeignSecurity  = $domain.ForeignSecurityPrincipalsContainer
            User             = $domain.UsersContainer

        }

    }
    [PSCustomObject]GetDomainIdentifiers([Microsoft.ActiveDirectory.Management.ADPartition]$domain) {

        return [PSCustomObject]@{

            dnsRoot     = $domain.dnsRoot
            Name        = $domain.Name
            NetBIOSName = $domain.NetBIOSName

        }

    }
    [PSCustomObject]GetDomainFSMORoles([Microsoft.ActiveDirectory.Management.ADPartition]$domain, [Microsoft.ActiveDirectory.Management.ADEntity]$forest) {

        return [PSCustomObject]@{

            DomainNamingMaster   = $forest.DomainNamingMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            PDCEmulator          = $domain.PDCEmulator
            RIDMaster            = $domain.RIDMaster
            SchemaMaster         = $forest.SchemaMaster

        }

    }

    [PSCustomObject]GetOptionalFeatures([String]$value) {

        $table = [Table]::New()

        $table.Properties.SetKey('Name')

        try {

            Get-ADOptionalFeature -Filter * -Properties ('Name', 'DistinguishedName', 'EnabledScopes') -Server $value -ErrorAction Stop | ForEach-Object {

                $object = [ordered]@{

                    Name               = $_.Name.Replace('Feature', '').Trim()
                    Enabled            = $_.EnabledScopes.Count -gt 0
                    RequiredDomainMode = $_.RequiredDomainMode
                    RequiredForestMode = $_.RequiredForestMode
                    distinguishedName  = $_.distinguishedName

                }

                $table[$object.($table.Properties.Key)] = [PSCustomObject]$object

            }

        }
        catch { throw '{0}({1})' -f 'optionalFeatureCollection', $_.Exception.Message }

        return $table

    }

    [void]GetData() {

        try {

            $domain = Get-ADDomain -Server ([ADTarget]::FQDN) -ErrorAction Stop

            $this.FQDN = ([ADTarget]::FQDN)

            $this.DomainSID = $domain.DomainSID

        }
        catch { throw '{0}({1})' -f 'domainCollection', $_.Exception.Message }

        try {

            $forest = Get-ADForest -Server ([ADTarget]::FQDN) -ErrorAction Stop

            if ($forest.RootDomain -eq $domain.Name) {
                $this.RootDomainSID = $this.DomainSID
            }
            else {
                $this.RootDomainSID = (Get-ADDomain -Server $forest.RootDomain).DomainSID
            }

        }
        catch { throw '{0}({1})' -f 'forestCollection', $_.Exception.Message }

        $this.WellKnownSID = $this.GetWellKnownSID()

        $this.Containers = $this.GetDomainControllers($domain)
        $this.Identifiers = $this.GetDomainIdentifiers($domain)
        $this.fsmoRoles = $this.GetDomainFSMORoles($domain, $forest)

        $this.PasswordPolicy = [PasswordPolicy]::Initialize()

        $this.OptionalFeatures = $this.GetOptionalFeatures([ADTarget]::FQDN)

    }

}
class ObjectData : Data {

    ObjectData () { $this.Name = 'Object' }
    hidden [object]$MembershipIndex

    static [ObjectData]$Instance

    static [ObjectData]Initialize() {

        [ObjectData]::Instance = [ObjectData]::New()

        return [ObjectData]::Instance

    }
    static [ObjectData]GetInstance() {

        if ($null -eq [ObjectData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [ObjectData]::Instance

        }

    }
    static [void]Close() {

        [ObjectData]::Instance = $null

    }

    [void]GetData() {
        
        try {

            $table = [Table]::New()

            $table.Properties.SetKey('DistinguishedName')

            Get-ADObject -Filter { objectClass -eq 'user' -or objectClass -eq 'group' -or objectClass -eq 'computer' } -Properties samaccountname,objectSid,memberOf,primaryGroupID,objectClass,objectGUID -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
                $table[$_.($table.Properties.Key)] = [Format]::ValueCollection($_, $table.Properties.Exclude)
            }

            $table.FormatData()

        }
        catch { throw '{0}({1})' -f 'objectCollection', $_.Exception.Message }

        $this.Data = $table
        $this.MembershipIndex = New-ADAnalyzerMembershipIndex -Groups @($table.Values)

    }

}
class FindingData : Finding {

    static [FindingData]$Instance

    static [FindingData]Initialize() {

        [FindingData]::Instance = [FindingData]::New()

        return [FindingData]::Instance

    }
    static [FindingData]GetInstance() {

        if ($null -eq [FindingData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [FindingData]::Instance

        }

    }

    static [void]Close() {

        [FindingData]::Instance = $null

    }
    static [void]Add([String]$value, [Finding]$list) {

        foreach ($item in $list) {

            # Windows PowerShell 5.1 serializes BigInteger as its CLR metadata.
            # Project flat finding fields without changing the live record.
            $jsonRecord = [ordered]@{}
            foreach ($property in $item.PSObject.Properties) {
                $field = $property.Value
                if ($field -is [bigint]) {
                    if ($field -ge [long]::MinValue -and $field -le [long]::MaxValue) { $field = [long]$field }
                    elseif ($field -ge 0 -and $field -le [uint64]::MaxValue) { $field = [uint64]$field }
                    else { $field = $field.ToString([Globalization.CultureInfo]::InvariantCulture) }
                }
                $jsonRecord[$property.Name] = $field
            }
            $object = [ordered]@{
                'class'   = $value
                'finding' = $item.'finding'
                'object'  = ([PSCustomObject]$jsonRecord | ConvertTo-Json)
            }

            [FindingData]::GetInstance().Add([PSCustomObject]$object) > $null

        }

    }

}

#endregion Domain
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Password Policy
class PasswordPolicy : Table {

    static [PasswordPolicy]$Instance

    static [PasswordPolicy]Initialize() {

        [PasswordPolicy]::Instance = [PasswordPolicy]::New()

        return [PasswordPolicy]::Instance

    }
    static [PasswordPolicy]GetInstance() {

        if ($null -eq [PasswordPolicy]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [PasswordPolicy]::Instance

        }

    }
    static [void]Close() {

        [PasswordPolicy]::Instance = $null

    }

}
class PasswordPolicyObject : OrderedDictionary {

    [Property]$Properties = [Property]::New()

    static [PasswordPolicyObject]SetDefault() {

        $object = [PasswordPolicyObject]::New()

        $object.SetDefaultProperties()

        return $object

    }
    static [PasswordPolicyObject]Initialize([Array]$value, [OrderedDictionary]$obj) {

        $object = [PasswordPolicyObject]::SetDefault()

        $object.Properties.List | ForEach-Object { $object[$_] = $null }

        $object['policyName'] = $obj['gpo.name']
        $object['policyId'] = $obj['gpo.id']

        $object['linked'] = $obj['gpo.linked']
        $object['linkedOU'] = $obj['gpo.linked.OU']

        $object['configuration'] = $obj['cfg.class']
        $object['configurationEnabled'] = $obj['cfg.enabled']

        foreach ($item in $value) {
            $presenceKey = [string]$item.Name + '.SecretPresent'
            $presenceNode = $item.SelectSingleNode('./*[local-name()="SecretPresent"]')
            if ($null -ne $presenceNode) {
                if ($object.Contains([string]$item.Name)) { $object.Remove([string]$item.Name) }
                $present = $false
                $valid = [bool]::TryParse($presenceNode.InnerText, [ref]$present)
                $object[$presenceKey] = if ($valid) { $present } else { $null }
                $validityKey = [string]$item.Name + '.ValueValid'
                $validityNode = $item.SelectSingleNode('./*[local-name()="ValueValid"]')
                $object[$validityKey] = if (-not $valid) { $false } elseif ($null -ne $validityNode) { [System.Convert]::ToBoolean($validityNode.InnerText) } else { $null }
                continue
            }
            if ($object.Contains($presenceKey)) { $object[$presenceKey] = $null }
            if ($null -ne $item.SettingNumber) {
                $object[$item.Name] = [bigint]$item.SettingNumber
            }
            elseif ($null -ne $item.SettingBoolean) {
                $object[$item.Name] = [Convert]::ToBoolean($item.SettingBoolean)
            }
            elseif ($null -ne $item.SelectSingleNode('./*[local-name()="SettingString"]')) {
                $object[$item.Name] = $item.SelectSingleNode('./*[local-name()="SettingString"]').InnerText
            }
            $validityKey = [string]$item.Name + '.ValueValid'
            $validityNode = $item.SelectSingleNode('./*[local-name()="ValueValid"]')
            if ($null -ne $validityNode) { $object[$validityKey] = [System.Convert]::ToBoolean($validityNode.InnerText) }
            elseif ($object.Contains($validityKey)) { $object[$validityKey] = $null }
        }

        return $object

    }
    static [Finding]Analyze([OrderedDictionary]$value) {

        $list = [Finding]::New()
        $policy = (Get-ADAnalyzerLegacyProfile).Policy
        if ($value.'property.setting.valid' -is [bool] -and -not $value.'property.setting.valid') {
            $list.AddFinding($value, 'Validate - Invalid stored policy value')
            return $list
        }

        if ($value.'property.setting.secretPresent' -is [bool]) {
            if ($value.'property.setting.secretPresent') { $list.AddFinding($value, 'Defect - Stored Secret') }
            return $list
        }

        if ($value.'ext.property.name' -eq 'Account') {

            switch ($value.'property.setting.name') {

                # Reference : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b40db09-d95d-40a6-8467-32aedec8140c

                # Lockout
                { $_ -eq 'LockoutBadCount' -and ($policy.LockoutThreshold -gt 0 -and ($value.'property.setting.value' -eq 0 -or $value.'property.setting.value' -gt $policy.LockoutThreshold)) } { $list.AddFinding($value, 'Defect - Invalid Password Attempt Limit') }
                { $_ -eq 'LockoutDuration' -and $value.'property.setting.value' -ne -1 -and $value.'property.setting.value' -lt $policy.LockoutDurationMinutes } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }
                { $_ -eq 'ResetLockoutCount' -and $value.'property.setting.value' -lt $policy.ResetLockoutMinutes } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }
                
                # Password
                { $_ -eq 'ClearTextPassword' -and $value.'property.setting.value' -eq $true } { $list.AddFinding($value, 'Defect - Reversible Encryption Enabled') }
                { $_ -eq 'MaximumPasswordAge' -and (($value.'property.setting.value' -eq -1 -and -not $policy.AllowPasswordNeverExpires) -or $value.'property.setting.value' -gt $policy.MaximumPasswordAgeDays) } { $list.AddFinding($value, 'Defect - Max Password Age') }
                { $_ -eq 'MinimumPasswordAge' -and $value.'property.setting.value' -lt $policy.MinimumPasswordAgeDays } { $list.AddFinding($value, 'Defect - Minimum Password Age') }
                { $_ -eq 'MinimumPasswordLength' -and $value.'property.setting.value' -lt $policy.MinimumPasswordLength } { $list.AddFinding($value, 'Defect - Minimum Password Length') }
                { $_ -eq 'PasswordHistorySize' -and $value.'property.setting.value' -lt $policy.PasswordHistorySize } { $list.AddFinding($value, 'Defect - Password History') }
                { $_ -eq 'PasswordComplexity' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Password Complexity') }

            }

        }

        return $list

    }
    [void]UpdateInstance() {

        $key = if ($this['policyId']) { $this['policyId'] } else { $this['policyName'] }
        [PasswordPolicy]::GetInstance()[$key] = [PSCustomObject]$this

    }

    [void]SetDefaultProperties() {

        $this.Properties.SetKey('policyName')

        $this.Properties.SetList(
            @(

                'policyId', 'policyName', 'linked', 'linkedOU', 'configuration', 'configurationEnabled'
                'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount'
                'ClearTextPassword', 'MaximumPasswordAge', 'MinimumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'ResetLockoutCount'
                'MaxClockSkew', 'MaxRenewAge', 'MaxServiceAge', 'MaxTicketAge', 'MaxTicketAgeForRenew', 'TicketValidateClient'
                'ForceLogoffWhenHourExpire', 'RequireLogonToChangePassword'
                'PasswordComplexity.ValueValid', 'ClearTextPassword.ValueValid', 'TicketValidateClient.ValueValid', 'ForceLogoffWhenHourExpire.ValueValid'

            )
        )

    }
}

#endregion Password Policy
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region User

class UserData : Data {

    UserData () { $this.Name = 'User' }

    static [UserData]$Instance

    static [UserData]Initialize() {

        [UserData]::Instance = [UserData]::New()

        return [UserData]::Instance

    }
    static [UserData]GetInstance() {

        if ($null -eq [UserData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [UserData]::Instance

        }

    }
    static [void]Close() {

        [UserData]::Instance = $null

    }
    
    [void]GetData() {

        try {

            $table = [UserTable]::SetDefault()

            $properties = @($table.Properties.List) + @('primaryGroupID','objectGUID','objectClass')
            $profile = Get-ADAnalyzerLegacyProfile
            foreach ($rule in @($profile.AccountClassification.AttributeRules)) {
                $attribute = [string]$rule.Attribute
                if (-not (Test-ADAnalyzerClassificationAttribute $attribute)) { throw 'Invalid or secret-valued classification attribute' }
                $properties += $attribute
            }
            $properties = @($properties | Select-Object -Unique)
            Get-ADUser -Filter * -Properties $properties -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
                $table[$_.($table.Properties.Key)] = [Format]::ValueCollection($_, $table.Properties.Exclude)
            }

            $table.FormatData()

        }
        catch { 
            
            throw '{0}({1})' -f 'userCollection', $_.Exception.Message 
        
        }
        finally {

            $this.Data = $table


        }

    }
    [void]GetReport() {

        $table = [UserTable]::SetDefault()

        $this.Data.Values | ForEach-Object { $table[$_.($table.Properties.Key)] = [UserObject]::Initialize($_) }

        $this.Report = $table

    }
    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Report.Values | ForEach-Object { $array.AddItem([UserObject]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()

    }

    [void]SetFinding() {

        $array = [Finding]::New()

        try {

            $this.Finding | ForEach-Object { $array.UpdateFinding($_, [UserObject]::Remediate($_)) }

        }
        catch { 

            throw '{0}({1})' -f 'setFinding', $_.Exception.Message 

        }
        finally { 

            $this.Finding = $array 

        }

    }

}
class UserTable : Table {

    UserTable() : base() {} 

    static [UserTable]SetDefault() {

        $object = [UserTable]::New()

        $object.SetDefaultProperties()

        return $object

    }

    [void]SetDefaultProperties() {

        $object = [UserObject]::SetDefault()

        $this.Properties.SetKey($object.Properties.Key)
        $this.Properties.SetList($object.Properties.List)

    }

}
class UserObject : OrderedDictionary {

    [Property]$Properties = [Property]::New()

    UserObject() : base([StringComparer]::OrdinalIgnoreCase) { }

    static [Hashtable]$Action = [Hashtable]@{

        'Defect - User Inactivity'    = 'Disable'
        'Defect - Disabled > 30 days' = 'Delete'

    }

    static [String]GetAccountType([OrderedDictionary]$value) {

        $classification = Get-ADAnalyzerAccountType -Object $value -Profile (Get-ADAnalyzerLegacyProfile)
        switch ($classification.Type) {
            'User' { return 'personal' }
            'Service' { return 'non-personal' }
        }
        return 'unknown'
    }
    static [ArrayList]GetUserAccountControl([int]$value) { 

        $object = [ArrayList]::New()

        switch ($value) {

            # Reference : https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties

            { ($value -bor 0x0001) -eq $value } { $object.Add('SCRIPT') > $null }
            { ($value -bor 0x0002) -eq $value } { $object.Add('Disabled') > $null }
            { ($value -bor 0x0008) -eq $value } { $object.Add('HOMEDIR_REQUIRED') > $null }
            { ($value -bor 0x0010) -eq $value } { $object.Add('LOCKOUT') > $null }
            { ($value -bor 0x0020) -eq $value } { $object.Add('PASSWD_NOTREQD') > $null }
            { ($value -bor 0x0040) -eq $value } { $object.Add('PASSWD_CANT_CHANGE') > $null }
            { ($value -bor 0x0080) -eq $value } { $object.Add('ENCRYPTED_TEXT_PWD_ALLOWED') > $null }
            { ($value -bor 0x0100) -eq $value } { $object.Add('TEMP_DUPLICATE_ACCOUNT') > $null }
            { ($value -bor 0x0200) -eq $value } { $object.Add('NORMAL_ACCOUNT') > $null }
            { ($value -bor 0x0800) -eq $value } { $object.Add('INTERDOMAIN_TRUST_ACCOUNT') > $null }
            { ($value -bor 0x1000) -eq $value } { $object.Add('WORKSTATION_TRUST_ACCOUNT') > $null }
            { ($value -bor 0x2000) -eq $value } { $object.Add('SERVER_TRUST_ACCOUNT') > $null }
            { ($value -bor 0x10000) -eq $value } { $object.Add('DONT_EXPIRE_PASSWORD') > $null }
            { ($value -bor 0x20000) -eq $value } { $object.Add('MNS_LOGON_ACCOUNT') > $null }
            { ($value -bor 0x40000) -eq $value } { $object.Add('SMARTCARD_REQUIRED') > $null }
            { ($value -bor 0x80000) -eq $value } { $object.Add('TRUSTED_FOR_DELEGATION') > $null }
            { ($value -bor 0x100000) -eq $value } { $object.Add('NOT_DELEGATED') > $null }
            { ($value -bor 0x200000) -eq $value } { $object.Add('USE_DES_KEY_ONLY') > $null }
            { ($value -bor 0x400000) -eq $value } { $object.Add('DONT_REQ_PREAUTH') > $null }
            { ($value -bor 0x800000) -eq $value } { $object.Add('PASSWORD_EXPIRED') > $null }
            { ($value -bor 0x1000000) -eq $value } { $object.Add('TRUSTED_TO_AUTH_FOR_DELEGATION') > $null }
            { ($value -bor 0x04000000) -eq $value } { $object.Add('PARTIAL_SECRETS_ACCOUNT') > $null }

        }

        return $object

    }
    static [Boolean]IsProtectedUser($value) {

        if ($value -match '^CN=Protected Users,CN=Users') {

            return $true

        }
        else {

            return $false

        }

    }
    static [UserObject]SetDefault() {

        $object = [UserObject]::New()

        $object.SetDefaultProperties()

        return $object

    }
    static [UserObject]Initialize([OrderedDictionary]$value) {

        $object = [UserObject]::SetDefault()

        switch ($object.Properties.List) {

            'distinguishedName' {

                $object[$_] = $value.($_)

                $item = [Format]::DistinguishedName($value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            { $_ -in ([DateAttributes].GetEnumNames()) } {

                $object[$_] = $value.($_)

                $item = [Format]::DateAttributes($_, $value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            'userAccountControl' { 
                
                $item = [UserObject]::GetUserAccountControl($value.($_))

                if ($item.Count -eq 1) {

                    $object[$_] = [ArrayList]@($item)

                }
                else {

                    $object[$_] = $item

                }

            }
            'userPrincipalName' {

                $object[$_] = $value.($_)

                $object['acctType'] = [UserObject]::GetAccountType($value)

            }
            'memberOf' {

                $profile = Get-ADAnalyzerLegacyProfile
                $domainSid = [DomainData]::GetInstance().DomainSID
                $privilegedSids = @(Get-ADAnalyzerPrivilegedSids -DomainSid $domainSid -RootDomainSid ([DomainData]::GetInstance().RootDomainSID) -Profile $profile)
                $membership = Resolve-ADAnalyzerMembership -Object $value -GroupIndex ([ObjectData]::GetInstance().MembershipIndex) -DomainSid $domainSid -PrivilegedSids $privilegedSids
                $object['privilegedGroup'] = if ($membership.IsPrivileged) { $membership.PrivilegedSids } else { $null }
                $object['protectedUser'] = $membership.EffectiveSids -contains ($domainSid + '-525')
                $object['privilegeResolution'] = if (@($membership.Unresolved).Count) { 'Unknown' } else { 'Complete' }

            }
            'SID' {

                if ([DomainData]::GetInstance().WellKnownSID.ContainsKey($value.($_).Value)) {
                    $object['WellKnownSID'] = $true
                }
                else {
                    $object['WellKnownSID'] = $false
                }

                $object[$_] = $value.($_).Value

            }
            default { $object[$_] = $value[$_] }

        }

        return $object

    }

    static [Finding]Analyze([OrderedDictionary]$value) {

        $list = [Finding]::New()
        $policy = (Get-ADAnalyzerLegacyProfile).Policy

        # TODO : get source data to pull HR details for termination findings

        $personalRemaining = $null
        $serviceRemaining = $null
        if ($null -ne $value.'days.pwdLastSet' -and $value.'days.pwdLastSet' -ge 0) {
            if ($policy.UserPasswordAgeDays -gt 0) { $personalRemaining = $policy.UserPasswordAgeDays - $value.'days.pwdLastSet' }
            if ($policy.ServicePasswordAgeDays -gt 0) { $serviceRemaining = $policy.ServicePasswordAgeDays - $value.'days.pwdLastSet' }
        }

        if (-not $value.enabled -and -not $value.WellKnownSID -and $value.'days.whenChanged' -ge 30) {

            $list.AddFinding($value, 'Defect - Disabled > 30 days')

        }
        else {

            switch ($value) {

                # Personal milestones are days remaining under the profile.
                { $value.enabled -and $value.acctType -eq 'personal' -and $null -ne $personalRemaining -and $personalRemaining -eq 1 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 1 Days') }
                { $value.enabled -and $value.acctType -eq 'personal' -and $null -ne $personalRemaining -and $personalRemaining -eq 2 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 2 Days') }
                { $value.enabled -and $value.acctType -eq 'personal' -and $null -ne $personalRemaining -and $personalRemaining -eq 7 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 7 Days') }
                { $value.enabled -and $value.acctType -eq 'personal' -and $null -ne $personalRemaining -and $personalRemaining -eq 21 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 21 Days') }

                # Service labels retain the lower elapsed-age boundary.
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $null -ne $serviceRemaining -and $serviceRemaining -gt 0 -and $serviceRemaining -le 30 } { $list.AddFinding($value, ('Warning - Non-Personal Password Expiration - {0} Days' -f [math]::Max(0, ($policy.ServicePasswordAgeDays - 30)))) }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $null -ne $serviceRemaining -and $serviceRemaining -gt 30 -and $serviceRemaining -le 60 } { $list.AddFinding($value, ('Warning - Non-Personal Password Expiration - {0} Days' -f [math]::Max(0, ($policy.ServicePasswordAgeDays - 60)))) }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $null -ne $serviceRemaining -and $serviceRemaining -gt 60 -and $serviceRemaining -le 90 } { $list.AddFinding($value, ('Warning - Non-Personal Password Expiration - {0} Days' -f [math]::Max(0, ($policy.ServicePasswordAgeDays - 90)))) }
                
                # Password Age Defects
                { $value.enabled -and $value.acctType -eq 'personal' -and $policy.UserPasswordAgeDays -gt 0 -and ($value.'days.pwdLastSet' -ge $policy.UserPasswordAgeDays -or $value.'range.pwdLastSet' -eq 'never') -and $value.'days.whenCreated' -gt 30 } { $list.AddFinding($value, 'Defect - Personal Password Age') }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $policy.ServicePasswordAgeDays -gt 0 -and ($value.'days.pwdLastSet' -ge $policy.ServicePasswordAgeDays -or $value.'range.pwdLastSet' -eq 'never') -and $value.'days.whenCreated' -gt 30 } { $list.AddFinding($value, 'Defect - Non-Personal Password Age') }

                # Require known creation age before applying the profile grace.
                { $value.enabled -and -not $value.WellKnownSID -and ($value.'days.lastlogon' -ge $policy.UserInactivityDays -or $value.'range.lastlogon' -eq 'never') -and $null -ne $value.'days.whenCreated' -and [int]$value.'days.whenCreated' -ge $policy.UserInactivityDays } { $list.AddFinding($value, 'Defect - User Inactivity') }

            }

            switch ($value) {

                # Personal Password Never Expires - Personal User Passwords must expire automatically
                { $value.enabled -and $value.acctType -eq 'personal' -and $value.'passwordNeverExpires' -eq $true } { $list.AddFinding($value, 'Defect - Personal Password Never Expires') }
                
                # Non-Personal Password Automatically Expires - Non-Personal User Passwords should not expire automatically. Will disrupt service accounts. 
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $value.'passwordNeverExpires' -eq $false } { $list.AddFinding($value, 'Defect - Non-Personal Password Set to Expire') }

                # Unsecure Account Attributes
                { $value.AllowedReversiblePasswordEncryption -eq $true } { $list.AddFinding($value, 'Defect - Reversible Encryption Enabled') }
                { $value.userAccountControl -contains 'USE_DES_KEY_ONLY' } { $list.AddFinding($value, 'Defect - DES Encryption Enabled') }
                { $value.userAccountControl -contains 'PASSWD_NOTREQD' } { $list.AddFinding($value, 'Defect - Password Not Required') }
                { $value.userAccountControl -contains 'DONT_REQ_PREAUTH' -or $value.userAccountControl -contains 'DONT_REQUIRE_PREAUTH' } { $list.AddFinding($value, 'Defect - Kerberos PreAuth Not Required') }
                { $value.userAccountControl -contains 'TRUSTED_TO_AUTH_FOR_DELEGATION' } { $list.AddFinding($value, 'Defect - Trusted Account Delegation Enabled') }
                { $value.userAccountControl -contains 'TRUSTED_FOR_DELEGATION' } { $list.AddFinding($value, 'Defect - Trusted For Delegation Enabled') }

                # Protected User
                { $value.enabled -and $value.acctType -eq 'personal' -and -not [String]::IsNullOrEmpty($value.'privilegedGroup') } { $list.AddFinding($value, 'Defect - Personal Privileged Group Membership') }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and -not [String]::IsNullOrEmpty($value.'privilegedGroup') } { $list.AddFinding($value, 'Validate - Non-Personal Privileged Group Membership') }
                { $value.adminCount -eq 1 -and -not $value.WellKnownSID -and [String]::IsNullOrEmpty($value.'privilegedGroup') } { $list.AddFinding($value, 'Defect - Protected User Not in Privileged Group') }

                # Warnings
                { $value.CannotChangePassword } { $list.AddFinding($value, 'Warning - User Cannot Change Password') }
                { $value.acctType -eq 'personal' -and -not [String]::IsNullOrEmpty($value.ServicePrincipalNames) } { $list.AddFinding($value, 'Defect - Personal Service Principal Names') }
                { $value.acctType -eq 'non-personal' -and -not [String]::IsNullOrEmpty($value.ServicePrincipalNames) } { $list.AddFinding($value, 'Validate - Non-Personal Service Principal Names') }
                { $value.enabled -and $value.'range.pwdLastSet' -eq 'never' -and $value.'days.whenCreated' -gt 30 } { $list.AddFinding($value, 'Warning - User Must Change Password at Next Logon') }
                { $value.enabled -and -not [String]::IsNullOrEmpty($value.'SIDHistory') } { $list.AddFinding($value, 'Warning - SID History Defined') }

                # Informational
                { $value.ProtectedFromAccidentalDeletion } { $list.AddFinding($value, 'Validate - User Protected from Accidental Deletion') }

            }

        }

        return $list

    }

    static [OrderedDictionary]Remediate([Object]$value) {

        $object = $null 

        if (-not $value.'WellKnownSID' -and [UserObject]::Action.Contains($value.'finding')) {

            $object = [Finding]::Remediate($value, [UserObject]::Action[$value.'finding'])

        }

        return $object

    }

    [void]SetDefaultProperties() {

        $this.Properties.SetKey('samaccountname')
        $this.Properties.SetList(

            @(  
                'samaccountname', 'name', 'surName', 'givenName', 'userPrincipalName', 'distinguishedName'
                'enabled', 'passwordlastset', 'lastlogondate', 'whenChanged', 'whenCreated', 'description'

                'userAccountControl', 'AllowedReversiblePasswordEncryption', 'DoesNotRequirePreAuth', 'PasswordNeverExpires' 
                'KerberosEncryptionType', 'adminCount', 'CannotChangePassword', 'ProtectedFromAccidentalDeletion'
                'PrincipalsAllowedToDelegateToAccount', 'SmartcardLogonRequired', 'ServicePrincipalNames', 'sidHistory', 'memberOf', 'SID'
            )

        )

    }

}

#endregion User
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Group
class GroupData : Data {

    GroupData () { $this.Name = 'Group' }

    static [GroupData]$Instance

    static [GroupData]Initialize() {

        [GroupData]::Instance = [GroupData]::New()

        return [GroupData]::Instance

    }
    static [GroupData]GetInstance() {

        if ($null -eq [GroupData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [GroupData]::Instance

        }

    }
    static [void]Close() {

        [GroupData]::Instance = $null

    }
    [void]GetData() {

        try {

            $table = [GroupTable]::SetDefault()

            Get-ADGroup -Filter * -Properties @($table.Properties.List) -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
                $table[$_.($table.Properties.Key)] = [Format]::ValueCollection($_, $table.Properties.Exclude)
            }

            $table.FormatData()

            $this.Data = $table 

        }
        catch { 
            
            throw '{0}({1})' -f 'groupCollection', $_.Exception.Message 
        
        }

    }

    [void]GetReport() {

        $table = [GroupTable]::SetDefault()

        $this.Data.Values | ForEach-Object { $table[$_.($table.Properties.Key)] = [GroupObject]::Initialize($_) }

        $this.Report = $table

    }

    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Report.Values | ForEach-Object { $array.AddItem([GroupObject]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()

    }

    [ArrayList]LookupGroupMembers($value) {

        $array = [ArrayList]::New()

        foreach ($item in $value) {

            if ([ADCollection]::Get('object').Data.ContainsKey($item)) {

                $array.add([ADCollection]::Get('object').Data[$item]['samaccountname']) > $null

            }

        }

        return $array

    }

}
class GroupTable : Table {

    GroupTable() : base() {} 

    static [GroupTable]SetDefault() {

        $object = [GroupTable]::New()

        $object.SetDefaultProperties()

        return $object

    }

    [void]SetDefaultProperties() {

        $object = [GroupObject]::SetDefault()

        $this.Properties.SetKey($object.Properties.Key)
        $this.Properties.SetList($object.Properties.List)

    }


}
class GroupObject : OrderedDictionary {

    [Property]$Properties = [Property]::New()

    GroupObject() : base([StringComparer]::OrdinalIgnoreCase) { }

    static [GroupObject]SetDefault() {

        $object = [GroupObject]::New()

        $object.SetDefaultProperties()

        return $object

    }
    static [GroupObject]Initialize([OrderedDictionary]$value) {

        $object = [GroupObject]::SetDefault()

        switch ($object.Properties.List) {

            'distinguishedName' {

                $object[$_] = $value.($_)

                $item = [Format]::DistinguishedName($value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            'samaccountname' {

                $object[$_] = $value.($_)
                $privilegedSids = @(Get-ADAnalyzerPrivilegedSids -DomainSid ([DomainData]::GetInstance().DomainSID) -RootDomainSid ([DomainData]::GetInstance().RootDomainSID) -Profile (Get-ADAnalyzerLegacyProfile))
                $object['privilegedGroup'] = $privilegedSids -contains (Get-ADAnalyzerSidValue $value.SID)

            }
            { $_ -in ([DateAttributes].GetEnumNames()) } {

                $object[$_] = $value.($_)

                $item = [Format]::DateAttributes($_, $value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            'members' {

                $object[$_] = $value.($_)

                $array = [ArrayList]::New()

                $value.($_) | Where-Object { $_ -match 'CN=ForeignSecurityPrincipals' } | ForEach-Object {

                    $array.Add($_) > $null

                }

                if ($array.Count -gt 0) {
                    $object['foreignSecurityPrincipalMembers'] = $array
                }
                else {
                    $object['foreignSecurityPrincipalMembers'] = $null
                }

            }
            'SID' {

                if ([DomainData]::GetInstance().WellKnownSID.ContainsKey($value.($_).Value)) {
                    $object['WellKnownSID'] = $true
                }
                else {
                    $object['WellKnownSID'] = $false
                }

                $object[$_] = $value.($_).Value

            }

            default { $object[$_] = $value[$_] }

        }

        return $object

    }
    static [Finding]Analyze([OrderedDictionary]$value) {

        $list = [Finding]::New()
        $policy = (Get-ADAnalyzerLegacyProfile).Policy
        
        switch ($value) {

            # defect
            { [String]::IsNullOrEmpty($value.'managedBy') } { $list.AddFinding($value, 'Defect - Unidentified Owner') }
            { $value.privilegedGroup -and -not [String]::IsNullOrEmpty($value.'foreignSecurityPrincipalMembers') } { $list.AddFinding($value, 'Defect - Privileged Group w/ ForeignSecurityPrincipal(s)') }
            { -not [String]::IsNullOrEmpty($value.'members') -and $value.SID -in @('S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551') } { $list.AddFinding($value, 'Defect - Privileged Builtin Group w/ Members') }
            { -not [string]::IsNullOrEmpty($value.'memberOf') -and $value.'orgUnit.L0' -notin @('Builtin') } { $list.AddFinding($value, 'Defect - Nested Group') }

            # warning
            { [String]::IsNullOrEmpty($value.'members') -and $value.'orgUnit.L0' -notin @('Builtin') } { $list.AddFinding($value, 'Warning - Empty Group') }

        }

        return $list

    }

    [void]SetDefaultProperties() {

        $this.Properties.SetKey('samaccountname')
        $this.Properties.SetList(

            @(  
                'samaccountname', 'name', 'groupCategory', 'groupScope', 'distinguishedName'
                'description', 'ProtectedFromAccidentalDeletion', 'isCriticalSystemObject'
                'managedBy', 'whenChanged', 'whenCreated', 'members', 'memberOf', 'SID'
            )

        )

    }

    static [ArrayList]ADPrivilegedGroups() {

        return [ArrayList]@(
            'Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'DNSAdmins', 'DHCP Administrators'
            'Backup Operators', 'Account Operators', 'Print Operators', 'Server Operators', 'Domain Controllers'
            'Enterprise Key Admins', 'Organization Management', 'RTCDomainServerAdmins', 'Enterprise Domain Controllers'
            'Cert Publishers', 'Exchange Recipient Administrators', 'Replicator', 'Read-Only Domain Controllers'
        )

    }

}
#endregion Group
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Computer
class ComputerData : Data {

    ComputerData () { $this.Name = 'Computer' }

    static [ComputerData]$Instance

    static [ComputerData]Initialize() {

        [ComputerData]::Instance = [ComputerData]::New()

        return [ComputerData]::Instance

    }
    static [ComputerData]GetInstance() {

        if ($null -eq [ComputerData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [ComputerData]::Instance

        }

    }

    static [void]Close() {

        [ComputerData]::Instance = $null

    }

    [void]GetData() {

        try {

            $table = [ComputerTable]::SetDefault()

            $list = [ArrayList]@(

                'samaccountname', 'name', 'distinguishedName', 'enabled', 'IPv4Address'
                'passwordlastset', 'lastlogondate', 'whenChanged', 'whenCreated'
                'isCriticalSystemObject', 'OperatingSystem', 'OperatingSystemVersion'
                'TrustedForDelegation'

            )

            Get-ADComputer -Filter * -Properties $list -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
                $table[$_.($table.Properties.Key)] = [Format]::ValueCollection($_, $table.Properties.Exclude)
            }

        }
        catch { 
            
            throw '{0}({1})' -f 'computerCollection', $_.Exception.Message 
        
        }
        finally { 
            
            $this.Data = $table 
        
        }

    }
    [void]GetReport() {

        $table = [ComputerTable]::SetDefault()

        $this.Data.Values | ForEach-Object { $table[$_.($table.Properties.Key)] = [ComputerObject]::Initialize($_) }

        $this.Report = $table

    }
    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Report.Values | ForEach-Object { $array.AddItem([ComputerObject]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()

    }

    [void]SetFinding() {

        $array = [Finding]::New()

        try {

            $this.Finding | ForEach-Object { $array.UpdateFinding($_, [ComputerObject]::Remediate($_)) }

        }
        catch { 

            throw '{0}({1})' -f 'setFinding', $_.Exception.Message 

        }
        finally { 

            $this.Finding = $array 

        }

    }

}
class ComputerTable : Table {

    ComputerTable() {} 

    static [ComputerTable]SetDefault() {

        $object = [ComputerTable]::New()

        $object.SetDefaultProperties()

        return $object

    }

    [void]SetDefaultProperties() {

        $object = [ComputerObject]::SetDefault()

        $this.Properties.SetKey($object.Properties.Key)
        $this.Properties.SetList($object.Properties.List)

    }

}
class ComputerObject : OrderedDictionary {

    [ComputerObject]$Computer

    [Property]$Properties = [Property]::New()

    ComputerObject() : base([StringComparer]::OrdinalIgnoreCase) { }

    static [Hashtable]$Action = [Hashtable]@{

        'Defect - Computer Inactivity' = 'Disable'
        'Defect - Disabled > 30 days'  = 'Delete'

    }

    static [ComputerObject]SetDefault() {

        $object = [ComputerObject]::New()

        $object.SetDefaultProperties()

        return $object

    }
    static [ComputerObject]Initialize([OrderedDictionary]$value) {

        $object = [ComputerObject]::SetDefault()

        switch ($object.Properties.List) {

            'distinguishedName' {

                $object[$_] = $value.($_)

                $item = [Format]::DistinguishedName($value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            { $_ -in ([DateAttributes].GetEnumNames()) } {

                $object[$_] = $value.($_)

                $item = [Format]::DateAttributes($_, $value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            'SID' {

                if ([DomainData]::GetInstance().WellKnownSID.ContainsKey($value.($_).Value)) {

                    $object['WellKnownSID'] = $true

                }
                else {

                    $object['WellKnownSID'] = $false

                }

                $object[$_] = $value.($_).Value

            }
            default { $object[$_] = $value[$_] }

        }

        return $object

    }

    static [Finding]Analyze([OrderedDictionary]$value) {

        $list = [Finding]::New()
        $policy = (Get-ADAnalyzerLegacyProfile).Policy

        if (-not $value.enabled -and $value.'days.whenChanged' -ge 30) {

            $list.AddFinding($value, 'Defect - Disabled > 30 days')

        }
        else {

            switch ($value) {

                # last logon activity
                { $value.enabled -and ($value.'days.lastlogon' -ge $policy.ComputerInactivityDays -or $value.'range.lastlogon' -eq 'never') -and $null -ne $value.'days.whenCreated' -and [int]$value.'days.whenCreated' -ge $policy.ComputerInactivityDays } { $list.AddFinding($value, 'Defect - Computer Inactivity') }

                # password age inactivity
                { $value.enabled -and ($value.'days.pwdLastSet' -ge $policy.ComputerInactivityDays -or $value.'range.pwdLastSet' -eq 'never') -and $null -ne $value.'days.whenCreated' -and [int]$value.'days.whenCreated' -ge $policy.ComputerInactivityDays } { $list.AddFinding($value, 'Defect - Computer Inactivity') }

                # operating system
                { $value.enabled -and -not [String]::IsNullOrEmpty($value.'OperatingSystem') } { $list.AddFinding($value, 'Unknown - Operating System Lifecycle Requires Versioned Profile') }

            }

        }

        return $list

    }

    static [OrderedDictionary]Remediate([Object]$value) {

        $object = $null 

        if (-not $value.'WellKnownSID' -and [ComputerObject]::Action.Contains($value.'finding')) {

            $object = [Finding]::Remediate($value, [ComputerObject]::Action[$value.'finding'])

        }

        return $object

    }

    [void]SetDefaultProperties() {

        $this.Properties.SetKey('samaccountname')
        $this.Properties.SetList(

            @(

                'samaccountname', 'name', 'distinguishedName', 'enabled', 'IPv4Address'
                'passwordlastset', 'lastlogondate', 'whenChanged', 'whenCreated'
                'isCriticalSystemObject', 'OperatingSystem', 'OperatingSystemVersion'
                'TrustedForDelegation', 'SID'

            )

        )

    }

}
#endregion Computer
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Group Policy
class GroupPolicyData : Data {

    GroupPolicyData () { $this.Name = 'GroupPolicy' }

    static [GroupPolicyData]$Instance

    static [GroupPolicyData]Initialize() {

        [GroupPolicyData]::Instance = [GroupPolicyData]::New()

        return [GroupPolicyData]::Instance

    }
    static [GroupPolicyData]GetInstance() {

        if ($null -eq [GroupPolicyData]::Instance) {

            throw '{0}({1})' -f 'instanceException', 'class instance has not been initialized'

        }
        else {

            return [GroupPolicyData]::Instance

        }

    }
    
    static [void]Close() {

        [GroupPolicyData]::Instance = $null

    }
    [void]GetData() {

        try {

            $table = [GroupPolicyTable]::SetDefault()

            $table.Properties.SetKey('Id')

            $list = [ArrayList]@('DisplayName', 'CreationTime', 'ModificationTime', 'GPOStatus', 'id', 'ReadError')

            $value = @{

                'domain'      = ([ADTarget]::FQDN)
                'server'      = ([ADTarget]::FQDN)
                'ErrorAction' = 'Stop'

            }

            $credential = [ADEnvironment]::GetEnvironment().Credential
            if ($null -ne $credential -and $credential -ne [PSCredential]::Empty) { $value['Credential'] = $credential }

            Get-ADAnalyzerGpo -All @value | ForEach-Object {

                $obj = $_

                $object = [OrderedDictionary]::New([System.StringComparer]::OrdinalIgnoreCase)

                $list | ForEach-Object { $object[$_] = $obj.($_) }

                try {

                    $item = @{

                        'Gpo'        = $obj
                        'SidNames'   = [DomainData]::GetInstance().WellKnownSID

                    }

                    if ($null -ne $credential -and $credential -ne [PSCredential]::Empty) { $item['Credential'] = $credential }

                    $object['xml'] = [xml]( Get-ADAnalyzerGpoReport @item )

                }
                catch {

                    $object['xml'] = $null
                    $object['ReadError'] = $_.Exception.Message
                    Write-Warning ('Unable to read GPO {0}: {1}' -f $obj.Id, $_.Exception.Message)

                }
                
                $table[$_.($table.Properties.Key)] = $object

            }

            $list.Add('xml') > $null

            $table.Properties.SetPropertyNames($list)

            $this.Data = $table

        }
        catch { throw '{0}({1})' -f 'groupPolicyCollection', $_.Exception.Message }

    }
    [void]GetReport() {

        $table = [GroupPolicyTable]::SetDefault()

        $this.Data.Values | ForEach-Object { 

            if ($null -eq $_['xml']) { return }
            
            $object = [GroupPolicyObject]::Initialize($_) 

            if ($null -ne $object.Configuration) {

                $table[$object.($object.Properties.Key)] = $object.Configuration

            }
        
        }

        $this.Report = $table

    }
    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Data.Values | Where-Object { $_['ReadError'] } | ForEach-Object { $array.AddFinding($_, 'Error - GPO report unreadable') }

        $this.Report.Values | ForEach-Object { 
            
            $item = $_ 

            $item | ForEach-Object { $array.AddItem([GroupPolicyObject]::Analyze($_)) } 
        
        }

        $this.Finding = $array

        $this.SyncFindings()

    }

}
class GroupPolicyTable : Table {

    GroupPolicyTable() {} 

    static [GroupPolicyTable]SetDefault() {

        $object = [GroupPolicyTable]::New()

        $object.SetDefaultProperties()

        return $object

    }

    [void]SetDefaultProperties() {

        $object = [GroupPolicyObject]::SetDefault()

        $this.Properties.SetKey($object.Properties.Key)
        $this.Properties.SetList($object.Properties.List)

    }

}
class GroupPolicyObject : OrderedDictionary {

    [GroupPolicyObject]$Data
    [GroupPolicyObject]$Record
    [List]$Configuration

    [Property]$Properties = [Property]::New()

    GroupPolicyObject() : base([StringComparer]::OrdinalIgnoreCase) { }

    static [String]GetLink($value) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        if ([String]::IsNullOrEmpty($value)) {

            return $null

        }
        else {

            foreach ($item in $value) {

                if ($item.SOMPath -eq [ADTarget]::FQDN) {

                    $object[$item.SOMPath] = $item.Enabled

                }
                else {

                    $object[($item.SOMPath.Replace([ADTarget]::FQDN, ''))] = $item.Enabled

                }

            }

        }

        return ($object | ConvertTo-Json)

    }
    static [String]GetLoopback($value) {

        $object = $null

        if ($value.Name -contains 'Registry' -and $value.Extension.Policy.Name -contains 'Configure user Group Policy Loopback Processing Mode') {

            $item = $value.Extension.Policy | Where-Object { $_.Name -eq 'Configure user Group Policy loopback processing mode' }

            $object = ('{0}({1})' -f $item.DropDownList.State, $item.DropDown)

        }

        if ($null -eq $object) {
            foreach ($extension in @($value | Where-Object Name -eq 'Registry')) {
                foreach ($record in @($extension.Extension.Record)) {
                    if ($record.Name -ieq 'HKLM\Software\Policies\Microsoft\Windows\System\UserPolicyMode') {
                        switch ([String]$record.Value) {
                            '0' { $object = 'Disabled' }
                            '1' { $object = 'Enabled(Merge)' }
                            '2' { $object = 'Enabled(Replace)' }
                        }
                    }
                }
            }
        }
        return $object

    }

    static [Hashtable]UserRightsAssignment() {

        return [Hashtable]@{

            # Reference : https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment

            'SeTrustedCredManAccessPrivilege'           = 'Access Credential Manager as a trusted caller'
            'SeNetworkLogonRight'                       = 'Access this computer from the network'
            'SeTcbPrivilege'                            = 'Act as part of the operating system'
            'SeMachineAccountPrivilege'                 = 'Add workstations to domain'
            'SeIncreaseQuotaPrivilege'                  = 'Adjust memory quotas for a process'
            'SeInteractiveLogonRight'                   = 'Allow log on locally'
            'SeRemoteInteractiveLogonRight'             = 'Allow log on through Remote Desktop Services'
            'SeBackupPrivilege'                         = 'Back up files and directories'
            'SeChangeNotifyPrivilege'                   = 'Bypass traverse checking'
            'SeSystemtimePrivilege'                     = 'Change the system time'
            'SeTimeZonePrivilege'                       = 'Change the time zone'
            'SeCreatePagefilePrivilege'                 = 'Create a pagefile'
            'SeCreateTokenPrivilege'                    = 'Create a token object'
            'SeCreateGlobalPrivilege'                   = 'Create global objects'
            'SeCreatePermanentPrivilege'                = 'Create permanent shared objects'
            'SeCreateSymbolicLinkPrivilege'             = 'Create symbolic links'
            'SeDebugPrivilege'                          = 'Debug programs'
            'SeDenyNetworkLogonRight'                   = 'Deny access to this computer from the network'
            'SeDenyBatchLogonRight'                     = 'Deny log on as a batch job'
            'SeDenyServiceLogonRight'                   = 'Deny log on as a service'
            'SeDenyInteractiveLogonRight'               = 'Deny log on locally'
            'SeDenyRemoteInteractiveLogonRight'         = 'Deny log on through Remote Desktop Services'
            'SeEnableDelegationPrivilege'               = 'Enable computer and user accounts to be trusted for delegation'
            'SeRemoteShutdownPrivilege'                 = 'Force shutdown from a remote system'
            'SeAuditPrivilege'                          = 'Generate security audits'
            'SeImpersonatePrivilege'                    = 'Impersonate a client after authentication'
            'SeIncreaseWorkingSetPrivilege'             = 'Increase a process working set'
            'SeIncreaseBasePriorityPrivilege'           = 'Increase scheduling priority'
            'SeLoadDriverPrivilege'                     = 'Load and unload device drivers'
            'SeLockMemoryPrivilege'                     = 'Lock pages in memory'
            'SeBatchLogonRight'                         = 'Log on as a batch job'
            'SeServiceLogonRight'                       = 'Log on as a service'
            'SeSecurityPrivilege'                       = 'Manage auditing and security log'
            'SeRelabelPrivilege'                        = 'Modify an object label'
            'SeSystemEnvironmentPrivilege'              = 'Modify firmware environment values'
            'SeDelegateSessionUserImpersonatePrivilege' = 'Obtain an impersonation token for another user in the same session'
            'SeManageVolumePrivilege'                   = 'Perform volume maintenance tasks'
            'SeProfileSingleProcessPrivilege'           = 'Profile single process'
            'SeSystemProfilePrivilege'                  = 'Profile system performance'
            'SeUndockPrivilege'                         = 'Remove computer from docking station'
            'SeAssignPrimaryTokenPrivilege'             = 'Replace a process level token'
            'SeRestorePrivilege'                        = 'Restore files and directories'
            'SeShutdownPrivilege'                       = 'Shut down the system'
            'SeSyncAgentPrivilege'                      = 'Synchronize directory service data'
            'SeTakeOwnershipPrivilege'                  = 'Take ownership of files or other objects'

        }

    }
    static [GroupPolicyObject]ImportData([OrderedDictionary]$value) {

        $object = [GroupPolicyObject]::SetDefault()

        $object.Data = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        $value.GetEnumerator() | ForEach-Object { $object.Data[$_.Name] = $_.Value }

        return $object

    }
    static [GroupPolicyObject]ImportRecord([OrderedDictionary]$value) {

        $object = [GroupPolicyObject]::SetDefault()

        $object.Record = [OrderedDictionary]::New()

        $value.GetEnumerator() | ForEach-Object { $object.Record[$_.Name] = $_.Value }

        return $object

    }
    static [GroupPolicyObject]SetDefault() {

        $object = [GroupPolicyObject]::New()

        $object.SetDefaultProperties()

        return $object

    }
    static [GroupPolicyObject]Initialize([OrderedDictionary]$value) {

        $object = [GroupPolicyObject]::ImportData($value)

        $object.NewRecordItem()
        $object.GetConfiguration()

        $object[$object.Properties.Key] = $object.Record.($object.Properties.Key)

        return $object

    }

    static [Finding]Analyze([PSCustomObject]$value) {

        $list = [Finding]::New()
        $policy = (Get-ADAnalyzerLegacyProfile).Policy
        if ($value.'property.setting.valid' -is [bool] -and -not $value.'property.setting.valid') {
            $list.AddFinding($value, 'Validate - Invalid stored policy value')
            return $list
        }

        if ($value.'property.setting.secretPresent' -is [bool]) {
            if ($value.'property.setting.secretPresent') { $list.AddFinding($value, 'Defect - Stored Secret') }
            return $list
        }

        if ($value.'ext.property.name' -eq 'Account') {

            switch ($value.'property.setting.name') {

                # Password
                { $_ -eq 'MaximumPasswordAge' -and (([bigint]$value.'property.setting.value' -eq -1 -and -not $policy.AllowPasswordNeverExpires) -or [bigint]$value.'property.setting.value' -gt $policy.MaximumPasswordAgeDays) } { $list.AddFinding($value, 'Defect - Max Password Age') }
                { $_ -eq 'MinimumPasswordAge' -and $value.'property.setting.value' -lt $policy.MinimumPasswordAgeDays } { $list.AddFinding($value, 'Defect - Minimum Password Age') }
                { $_ -eq 'MinimumPasswordLength' -and [bigint]$value.'property.setting.value' -lt $policy.MinimumPasswordLength } { $list.AddFinding($value, 'Defect - Minimum Password Length') }
                { $_ -eq 'PasswordComplexity' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Password Complexity Disabled') }
                { $_ -eq 'PasswordHistorySize' -and [bigint]$value.'property.setting.value' -lt $policy.PasswordHistorySize } { $list.AddFinding($value, 'Defect - Password History') }
                { $_ -eq 'ClearTextPassword' -and $value.'property.setting.value' -eq $true } { $list.AddFinding($value, 'Defect - ClearText Password') }

                # Lockout
                { $_ -eq 'LockoutBadCount' -and ($policy.LockoutThreshold -gt 0 -and ($value.'property.setting.value' -eq 0 -or $value.'property.setting.value' -gt $policy.LockoutThreshold)) } { $list.AddFinding($value, 'Defect - Invalid Password Attempt Limit') }
                { $_ -eq 'LockoutDuration' -and $value.'property.setting.value' -ne -1 -and $value.'property.setting.value' -lt $policy.LockoutDurationMinutes } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }
                { $_ -eq 'ResetLockoutCount' -and $value.'property.setting.value' -lt $policy.ResetLockoutMinutes } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }

            }

        }
        elseif ($value.'ext.property.name' -eq 'SecurityOptions') {

            switch ($value.'property.setting.name') {

                # TODO : Add 'Network access: Shares that can be access anonymously' to the list

                # NTLM Settings
                { $_ -eq 'Network security: LAN Manager authentication level' -and (Get-ADAnalyzerLmLevel $value.'property.setting.value') -lt $policy.MinimumLmCompatibilityLevel } { $list.AddFinding($value, 'Defect - LAN Manager Authentication Level (LmCompatibilityLevel)') }

                # (Server) Digitally Sign Communications
                { $_ -eq 'Microsoft network server: Digitally sign communications (if client agrees)' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Digital Signing Disabled') }
                { $_ -eq 'Microsoft network server: Digitally sign communications (always)' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Digital Signing Disabled') }

                # Send Unencrypted Password
                { $_ -eq 'Microsoft network client: Send unencrypted password to third-party SMB servers' -and ($value.'property.setting.value' -eq $true -or [String]::IsNullOrEmpty($value.'property.setting.value')) } { $list.AddFinding($value, 'Defect - Unencrypted Password w/ 3rd Party SMB') }

                # Send Anonymous SID/Name Translation
                { $_ -eq 'Network access: Allow anonymous SID/Name translation' -and ($value.'property.setting.value' -eq $true -or [String]::IsNullOrEmpty($value.'property.setting.value')) } { $list.AddFinding($value, 'Defect - Anonymous SID/Name Translation') }

                # Send Everyone Permissions Apply to Anonymous Users
                { $_ -eq 'Network access: Let Everyone permissions apply to anonymous users' -and $value.'property.setting.value' -eq $true } { $list.AddFinding($value, 'Defect - Everyone Permissions Apply to Anonymous Users') }

                # Send Named Pipes Null Session
                { $_ -eq 'Network access: Named Pipes that can be accessed anonymously' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') -and $value.'property.setting.value' -notin $policy.AllowedAnonymousPipes } { $list.AddFinding($value, 'Defect - Named Pipes Allow Anonymous (Null) Session') }

                # Shares that can be access anonymously
                { $_ -eq 'Network access: Shares that can be access anonymously' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Shares Allow Anonymous (Null) Session') }

                # Named Pipes Allow Anonymous (Null) Session
                { $_ -eq 'Network access: Restrict anonymous access to Named Pipes and Shares' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Named Pipes Allow Anonymous (Null) Session') }

                # Send Anonymous Enumeration of SAM Accounts
                { $_ -eq 'Network access: Do not allow anonymous enumeration of SAM accounts' -and ($value.'property.setting.value' -eq $false -or [String]::IsNullOrEmpty($value.'property.setting.value')) } { $list.AddFinding($value, 'Defect - Anonymous Enumeration of SAM Accounts') }
                { $_ -eq 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' -and ($value.'property.setting.value' -eq $false -or [String]::IsNullOrEmpty($value.'property.setting.value')) } { $list.AddFinding($value, 'Defect - Anonymous Enumeration of SAM Accounts') }
                
                # (Client) Digitally Sign Communications
                { $_ -eq 'Microsoft network client: Digitally sign communications (if server agrees)' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Digital Signing Disabled') }
                { $_ -eq 'Microsoft network client: Digitally sign communications (always)' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Digital Signing Disabled') }

                # (Domain Member) Digitally Sign Communications
                { $_ -eq 'Domain member: Digitally encrypt or sign secure channel data (always)' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Secure Channel Encryption Disabled') }
                { $_ -eq 'Domain member: Digitally encrypt secure channel data (when possible)' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Secure Channel Encryption Disabled') }

                # (Domain Controller) LDAP Server Signing Requirements
                { $_ -eq 'Domain controller: LDAP server signing requirements' -and $policy.RequireLdapServerSigning -and $value.'property.setting.value' -notin @('Require signature') } { $list.AddFinding($value, 'Defect - LDAP Signing Not Required') }
                { $_ -eq 'Network security: LDAP client signing requirements' -and $policy.RequireLdapClientSigning -and $value.'property.setting.value' -ne 'Require signing' } { $list.AddFinding($value, 'Defect - LDAP Signing Not Required') }

                # User Account Control
                { $_ -eq 'User Account Control: Admin Approval Mode for the Built-in Administrator account' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Invalid User Account Control') }
                { $_ -eq 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' -and $value.'property.setting.value' -eq $true } { $list.AddFinding($value, 'Defect - Invalid User Account Control') }
                { $_ -eq 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' -and $value.'property.setting.value' -in @('Elevate without prompting') } { $list.AddFinding($value, 'Defect - Invalid User Account Control') }
                { $_ -eq 'User Account Control: Detect application installations and prompt for elevation' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Invalid User Account Control') }
                { $_ -eq 'User Account Control: Run all administrators in Admin Approval Mode' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Invalid User Account Control') }

            }
            
        }
        elseif ($value.'ext.property.name' -eq 'UserRightsAssignment') {

            if ($value.'gpo.linked.ou' -match 'Domain Controllers') {
                $right = [string]$value.'property.setting.right'
                $rights = $policy.AllowedUserRightSids
                if ([string]::IsNullOrWhiteSpace($right) -or $rights -isnot [Collections.IDictionary] -or -not $rights.Contains($right)) {
                    $list.AddFinding($value, 'Validate - UserRightsAssignment Allowlist Not Configured')
                }
                else {
                    $approved = $rights[$right]
                    $valid = $null -ne $approved -and ($approved -is [string] -or $approved -is [Collections.IList])
                    foreach ($sid in @($approved)) {
                        if (-not [GroupPolicyObject]::IsUserRightSid($sid)) { $valid = $false }
                    }
                    if (-not $valid) {
                        $list.AddFinding($value, 'Validate - Invalid UserRightsAssignment Allowlist')
                    }
                    elseif ($value.'property.setting.empty' -ne $true) {
                        $memberSid = [string]$value.'property.setting.sid'
                        if (-not [GroupPolicyObject]::IsUserRightSid($memberSid)) {
                            $list.AddFinding($value, 'Validate - UserRightsAssignment SID Required')
                        }
                        elseif (@($approved) -notcontains $memberSid) {
                            $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment')
                        }
                    }
                }
            }

        }

        return $list

    }

    hidden static [bool]IsUserRightSid([object]$value) {
        if ($value -isnot [string] -or $value -notmatch '^S-1-(?:0|[1-9][0-9]{0,9}|0x[0-9a-f]{12})(?:-(?:0|[1-9][0-9]{0,9})){1,15}$') { return $false }
        $parts = $value.Split('-')
        [uint64]$authority = 0
        if ($parts[2].StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            if (-not [uint64]::TryParse($parts[2].Substring(2), [Globalization.NumberStyles]::AllowHexSpecifier, [Globalization.CultureInfo]::InvariantCulture, [ref]$authority) -or $authority -lt 4294967296) { return $false }
        }
        elseif (-not [uint64]::TryParse($parts[2], [ref]$authority) -or $authority -gt 4294967295) { return $false }
        for ($index = 3; $index -lt $parts.Count; $index++) {
            [uint32]$subauthority = 0
            if (-not [uint32]::TryParse($parts[$index], [ref]$subauthority)) { return $false }
        }
        return $true
    }

    static [bool]SetSecretPresence([OrderedDictionary]$record, [XmlElement]$value) {
        $record['property.setting.secretPresent'] = $null
        $record['property.setting.source'] = $null
        $marker = $value.SelectSingleNode('./*[local-name()="SecretPresent"]')
        if ($null -eq $marker) { return $false }
        $record['property.setting.value'] = $null
        $present = $false
        if ([bool]::TryParse($marker.InnerText, [ref]$present)) { $record['property.setting.secretPresent'] = $present }
        else { $record['property.setting.valid'] = $false }
        $source = $value.SelectSingleNode('./*[local-name()="Source"]')
        if ($null -ne $source) { $record['property.setting.source'] = $source.InnerText }
        return $true
    }

    [List]GetAccountSettings([XmlElement]$value, [GPOExtensionProperty]$name) {

        $array = [List]::New()

        try {

            foreach ($item in @($value.Extension.($name))) {

                $object = [GroupPolicyObject]::ImportRecord($this.Record)

                $object.Record['ext.property.name'] = $name
                $object.Record['ext.property.type'] = $item.type

                $object.Record['property.setting.name'] = $item.name
                $object.Record['property.setting.valid'] = $null
                $validityNode = $item.SelectSingleNode('./*[local-name()="ValueValid"]')
                if ($null -ne $validityNode) { $object.Record['property.setting.valid'] = [System.Convert]::ToBoolean($validityNode.InnerText) }

                if (-not [GroupPolicyObject]::SetSecretPresence($object.Record, $item)) { switch ($item) {

                    { $item.SettingNumber } { $object.Record['property.setting.value'] = [bigint]$item.SettingNumber }
                    { $item.SettingBoolean } { $object.Record['property.setting.value'] = [Convert]::ToBoolean($item.SettingBoolean) }
                    { $null -ne $item.SelectSingleNode('./*[local-name()="SettingString"]') } { $object.Record['property.setting.value'] = $item.SelectSingleNode('./*[local-name()="SettingString"]').InnerText }

                } }

                $array.Add([PSCustomObject]$object.Record) > $null

            }

        }
        catch { throw '{0}({1})' -f 'Account', $_.Exception.Message }

        try {

            [PasswordPolicyObject]::Initialize($value.Extension.($name), $this.Record).UpdateInstance()

        }
        catch { throw '{0}({1})' -f 'PasswordPolicy', $_.Exception.Message }

        return $array

    }
    [List]GetSecurityOptions([XmlElement]$value, [GPOExtensionProperty]$name) {

        $array = [List]::New()

        try {

            foreach ($item in @($value.Extension.($name))) {

                if (-not [String]::IsNullOrEmpty($item.Display) -or $null -ne $item.SelectSingleNode('./*[local-name()="SecretPresent"]')) {

                    $object = [GroupPolicyObject]::ImportRecord($this.Record)

                    $object.Record['ext.property.name'] = $name
                    $object.Record['ext.property.type'] = $null

                    $object.Record['property.setting.name'] = if ($item.Display.Name) { $item.Display.Name } else { [string]$item.Name }
                    $object.Record['property.setting.valid'] = $null
                    $validityNode = $item.SelectSingleNode('./*[local-name()="ValueValid"]')
                    if ($null -ne $validityNode) { $object.Record['property.setting.valid'] = [System.Convert]::ToBoolean($validityNode.InnerText) }

                    if (-not [GroupPolicyObject]::SetSecretPresence($object.Record, $item)) { switch ($item) {

                        { $null -ne $item.SelectSingleNode('./*[local-name()="Display"]/*[local-name()="DisplayString"]') } { $object.Record['property.setting.value'] = $item.SelectSingleNode('./*[local-name()="Display"]/*[local-name()="DisplayString"]').InnerText }
                        { $item.Display.DisplayBoolean } { $object.Record['property.setting.value'] = [Convert]::ToBoolean($item.Display.DisplayBoolean) }

                    } }

                    $array.Add([PSCustomObject]$object.Record) > $null

                }

            }

        }
        catch { throw '{0}({1})' -f 'SecurityOptions', $_.Exception.Message }

        return $array

    }
    [List]GetUserRightsAssignment([XmlElement]$value, [GPOExtensionProperty]$name) {

        $array = [List]::New()

        try {

            $table = [GroupPolicyObject]::UserRightsAssignment()

            foreach ($list in @($value.Extension.($name))) {

                $rightNode = $list.SelectSingleNode('./*[local-name()="Name"]')
                $right = if ($null -ne $rightNode) { $rightNode.InnerText.Trim() } else { '' }
                $members = $list.SelectNodes('./*[local-name()="Member"]')
                if ($members.Count -eq 0) {

                    $object = [GroupPolicyObject]::ImportRecord($this.Record)

                    $object.Record['ext.property.name'] = $name
                    $object.Record['ext.property.type'] = $null

                    $object.Record['property.setting.name'] = ('{0} ({1})' -f $table[$right], $right)
                    $object.Record['property.setting.right'] = $right
                    $object.Record['property.setting.empty'] = $true

                    $array.add([PSCustomObject]$object.Record) > $null

                }
                else {

                    foreach ($item in $members) {

                        $object = [GroupPolicyObject]::ImportRecord($this.Record)

                        $object.Record['ext.property.name'] = $name
                        $object.Record['ext.property.type'] = $null

                        $object.Record['property.setting.name'] = ('{0} ({1})' -f $table[$right], $right)
                        $object.Record['property.setting.right'] = $right
                        $object.Record['property.setting.empty'] = $false
                        $object.Record['property.setting.value'] = $item

                        $nameNode = $item.SelectSingleNode('./*[local-name()="Name"]')
                        $sidNode = $item.SelectSingleNode('./*[local-name()="SID"]')
                        $memberName = if ($null -ne $nameNode) { $nameNode.InnerText } else { $null }
                        $memberSID = if ($null -ne $sidNode) { $sidNode.InnerText.Trim() } else { $null }
                        $object.Record['property.setting.sid'] = $memberSID
                        $object.Record['property.setting.value'] = if (-not [String]::IsNullOrEmpty($memberName)) { $memberName } else { $memberSID }
                        $resolutionNode = $item.SelectSingleNode('./*[local-name()="Resolution"]')
                        if ($null -ne $resolutionNode) { $object.Record['property.setting.parameter'] = 'SID resolution: ' + $resolutionNode.InnerText }
                        
                        $array.add([PSCustomObject]$object.Record) > $null

                    }

                }

            }

        }
        catch { throw '{0}({1})' -f 'UserRightsAssignment', $_.Exception.Message } 

        return $array

    }

    [List]GetSecurityExtension([XmlElement]$value) {

        $array = [List]::New()

        $this.Record['cfg.extension'] = $value.Name

        try {

            foreach ($item in $value.Extension.PSObject.Properties.Name | Where-Object { $null -ne ($_ -as [GPOExtensionProperty]) }) {

                switch ($item) {
                    ([GPOExtensionProperty]::Account) { $array.AddItem($this.GetAccountSettings($value, $item)) }
                    ([GPOExtensionProperty]::SecurityOptions) { $array.AddItem($this.GetSecurityOptions($value, $item)) }
                    ([GPOExtensionProperty]::UserRightsAssignment) { $array.AddItem($this.GetUserRightsAssignment($value, $item)) }

                }

            }

        }
        catch { throw '{0}({1})' -f 'SecurityExtension', $_.Exception.Message }

        return $array

    }
    [List]ExpandExtensionData([XmlElement]$value) {

        $array = [List]::New()

        try {

            foreach ($item in $value | Where-Object { $null -ne ($_.name -as [GPOExtensionType]) }) {

                switch ($item.name) {

                    ([GPOExtensionType]::Security) { $array.AddItem($this.GetSecurityExtension($item)) }
                    ([GPOExtensionType]::Registry) { $array.AddItem($this.GetRawExtension($item)) }
                    ([GPOExtensionType]::Preferences) { $array.AddItem($this.GetRawExtension($item)) }
                    ([GPOExtensionType]::Xml) { $array.AddItem($this.GetRawExtension($item)) }
                    ([GPOExtensionType]::Ini) { $array.AddItem($this.GetRawExtension($item)) }

                }

            }

        }
        catch { throw '{0}({1})' -f 'ExtensionData', $_.Exception.Message }

        return $array

    }

    [List]GetRawExtension([XmlElement]$value) {
        $array = [List]::New()
        foreach ($item in @($value.Extension.Record)) {
            $object = [GroupPolicyObject]::ImportRecord($this.Record)
            $object.Record['cfg.extension'] = [String]$value.Name
            $object.Record['ext.property.name'] = [String]$value.Name
            $object.Record['ext.property.type'] = [String]$item.Type
            $object.Record['property.setting.name'] = [String]$item.Name
            $object.Record['property.setting.valid'] = $null
            if (-not [GroupPolicyObject]::SetSecretPresence($object.Record, $item)) { $object.Record['property.setting.value'] = [String]$item.Value }
            $array.Add([PSCustomObject]$object.Record) > $null
        }
        return $array
    }

    [void]NewRecordItem() {

        $this.Record = [GroupPolicyObject]::SetDefault()

        switch ($this.Record.Properties.List) {

            'gpo.id' { $this.Record[$_] = [String]$this.Data.Id }
            'gpo.name' { $this.Record[$_] = $this.Data.DisplayName }
            'gpo.created' { $this.Record[$_] = (Get-Date $this.Data.CreationTime -f 'yyyy/MM/dd HH:mm') }
            'gpo.modified' { $this.Record[$_] = (Get-Date $this.Data.ModificationTime -f 'yyyy/MM/dd HH:mm') }
            'gpo.status' { $this.Record[$_] = $this.Data.Gpostatus }
            'gpo.read' { $this.Record[$_] = (Get-Date $this.Data.xml.GPO.ReadTime -f 'yyyy/MM/dd HH:mm') }
            'gpo.linked' { $this.Record[$_] = (-not [String]::IsNullOrEmpty($this.Data.xml.GPO.LinksTo)) }
            'gpo.linked.ou' { $this.Record[$_] = [GroupPolicyObject]::GetLink($this.Data.xml.GPO.LinksTo) }
            
            default { $this.Record[$_] = $null }

        }

    }
    [void]GetConfiguration() {

        $array = [List]::New()

        try {

            foreach ($item in [GPOConfiguration].GetEnumNames() | Where-Object { $null -ne $this.Data['xml'].GPO.($_).ExtensionData }) {

                $this.Record['cfg.class'] = $item
                $this.Record['cfg.enabled'] = $this.Data['xml'].GPO.($item).Enabled

                $this.Record['cfg.loopback'] = [GroupPolicyObject]::GetLoopback($this.Data['xml'].GPO.($item).ExtensionData)

                $this.Data['xml'].GPO.($item).ExtensionData | ForEach-Object {

                    $array.AddItem($this.ExpandExtensionData($_))

                }

                if ($array.Count -gt 0) {
                    $this.Configuration = $array
                }
                else {
                    $this.Configuration = $null
                }

            }

        }
        catch { throw '{0}({1})' -f 'gpoConfiguration', $_.Exception.Message }

    }
    [void]SetDefaultProperties() {

        $this.Properties.SetKey('gpo.id')
        $this.Properties.SetList(

            @(
                'gpo.id', 'gpo.name', 'gpo.created', 'gpo.modified', 'gpo.read', 'gpo.status', 'gpo.linked', 'gpo.linked.ou'
                'cfg.class', 'cfg.enabled', 'cfg.loopback', 'cfg.extension'
                'ext.property.name', 'ext.property.enabled', 'ext.property.type'
                'property.setting.name', 'property.setting.value', 'property.setting.parameter'
                'ext.property.parameter', 'ext.property.filter'
                'property.setting.right', 'property.setting.sid', 'property.setting.empty'
                'property.setting.valid', 'property.setting.secretPresent', 'property.setting.source'
            )

        )

    }

}
#endregion Group Policy
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Classes

#endregion Classes
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Environment
class ADTarget {

    static [String]$FQDN
    static [ADDiagnostic]$Diagnostic
    hidden static [String]$ConnectionDrive
    hidden static [String]$PreviousLocation

    hidden [Microsoft.ActiveDirectory.Management.Provider.ADDriveInfo]$Connection

    ADTarget() {

        [ADTarget]::FQDN = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

    }
    ADTarget([String]$value) {

        [ADTarget]::FQDN = $value

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

    }
    ADTarget([PSCredential]$item) {

        [ADTarget]::FQDN = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

        $this.Connect($item)

    }
    ADTarget([String]$value, [PSCredential]$item) {

        [ADTarget]::FQDN = $value

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

        $this.Connect($item)

    }
    static [void]Close() {

        [ADTarget]::Disconnect()

        [ADTarget]::FQDN = $null

        [ADTarget]::Diagnostic = $null

        [ADDiagnostic]::Close()

    }
    static [void]Disconnect() {

        if (-not [String]::IsNullOrEmpty([ADTarget]::ConnectionDrive)) {
            $restorationError = $null
            $removalError = $null
            try { Set-Location -LiteralPath ([ADTarget]::PreviousLocation) -ErrorAction Stop }
            catch { $restorationError = $_ }
            try { Remove-PSDrive -Name ([ADTarget]::ConnectionDrive) -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false }
            catch { $removalError = $_ }
            if ($null -eq $removalError) {
                [ADTarget]::ConnectionDrive = $null
                [ADTarget]::PreviousLocation = $null
            }
            if ($null -ne $restorationError) {
                if ($null -ne $removalError) { $restorationError.Exception.Data['ADAnalyzerDriveRemovalError'] = $removalError.Exception.Message }
                throw $restorationError
            }
            if ($null -ne $removalError) { throw $removalError }
        }

    }

    [void]Connect([PSCredential]$value) {

        $object = $null

try {

            $item = Get-ADDomain -Server ([ADTarget]::FQDN) -Credential $value

            [ADTarget]::Disconnect()
            $driveName = $item.NetBiosName
            if (Get-PSDrive | Where-Object { $_.Name -eq $driveName }) {
                $driveName = '{0}-ADAnalyzer-{1}' -f $driveName, [guid]::NewGuid().ToString('N')
            }
            [ADTarget]::PreviousLocation = (Get-Location).Path
            $object = New-PSDrive -Server ([ADTarget]::FQDN) -Name $driveName -PSProvider ActiveDirectory -Root $item.DistinguishedName -Credential $value -Scope Script -ErrorAction Stop -WhatIf:$false -Confirm:$false
            [ADTarget]::ConnectionDrive = $object.Name

            Set-Location -Path ('{0}:' -f $object.Name) -ErrorAction Stop

        }
        catch { 
            
            throw '{0}({1})' -f 'targetConnection', 'domain connection failed' 
        
        }
        finally {

            $this.Connection = $object

        }

    }
    [void]Connect([String]$fqdn, [PSCredential]$value) {

        $object = $null

try {

            $item = Get-ADDomain -Server $fqdn -Credential $value

            [ADTarget]::Disconnect()
            $driveName = $item.NetBiosName
            if (Get-PSDrive | Where-Object { $_.Name -eq $driveName }) {
                $driveName = '{0}-ADAnalyzer-{1}' -f $driveName, [guid]::NewGuid().ToString('N')
            }
            [ADTarget]::PreviousLocation = (Get-Location).Path
            $object = New-PSDrive -Server $fqdn -Name $driveName -PSProvider ActiveDirectory -Root $item.DistinguishedName -Credential $value -Scope Script -ErrorAction Stop -WhatIf:$false -Confirm:$false
            [ADTarget]::ConnectionDrive = $object.Name

            Set-Location -Path ('{0}:' -f $object.Name) -ErrorAction Stop

        }
        catch { 
            
            throw '{0}({1})' -f 'targetConnection', 'domain connection failed' 
        
        }
        finally {

            $this.Connection = $object

        }

    }

}
class ADCollection {

    static [ArrayList]$List
    static [OrderedDictionary]$Data

    static [void]Add([String]$value) {

        $object = (New-Object -TypeName $('{0}Data' -f $value))::Initialize()

        [ADCollection]::Data[$value] = $object

    }

    static [Object]Get([String]$value) {

        if ([ADCollection]::Data.Contains($value)) {

            return [ADCollection]::Data[$value]

        }
        else {

            return $null

        }

    }

    static [OrderedDictionary]Initialize([ArrayList]$list) {

        [ADCollection]::List = $list

        [ADCollection]::Data = [OrderedDictionary]::New([System.StringComparer]::OrdinalIgnoreCase)

        $array = [ArrayList]@('Domain', 'Object')

        $array.AddRange($list) > $null

        $array | ForEach-Object { [ADCollection]::Add($_) }

        return [ADCollection]::Data

    }

    static [void]Close() {

        if ($null -ne [ADCollection]::Data -and [ADCollection]::Data.Count -gt 0) {

            [ADCollection]::Data.Keys | ForEach-Object { [ADCollection]::Data[$_]::Close() }

        }

        [ADCollection]::Data = $null
        [ADCollection]::List = $null

    }

}
class ADEnvironment : ADTarget {

    hidden [Data]$Object
    hidden [ArrayList]$Class
    hidden [OrderedDictionary]$Collection
    hidden [PSCredential]$Credential

    [UserData]$User
    [GroupData]$Group
    [DomainData]$Domain
    [ComputerData]$Computer
    [GroupPolicyData]$GroupPolicy

    [FindingData]$Finding

    ADEnvironment() : base() {}
    ADEnvironment([String]$value) : base([String]$value) {}
    ADEnvironment([PSCredential]$item) : base([PSCredential]$item) {}
    ADEnvironment([String]$value, [PSCredential]$item) : base([String]$value, [PSCredential]$item) {}

    static [ADEnvironment]$Instance

    static [ADEnvironment]Initialize() {

        $environment = [ADEnvironment]::New()

        $environment.Class = [ObjectClasses].GetEnumNames()

        $environment.Collection = [ADCollection]::Initialize($environment.Class)

        $environment.Collection.Keys | ForEach-Object { $environment.($_) = [ADCollection]::Get($_) }

        $environment.Finding = [FindingData]::Initialize()

        [ADEnvironment]::Instance = $environment

        return [ADEnvironment]::Instance

    }
    static [ADEnvironment]Initialize([ArrayList]$list) {

        $environment = [ADEnvironment]::New()

        $environment.Class = $list

        $environment.Collection = [ADCollection]::Initialize($environment.Class)

        $environment.Collection.Keys | ForEach-Object { $environment.($_) = [ADCollection]::Get($_) }

        $environment.Finding = [FindingData]::Initialize()

        [ADEnvironment]::Instance = $environment

        return [ADEnvironment]::Instance

    }
    static [ADEnvironment]Initialize([PSCredential]$item, [ArrayList]$list) {

        $environment = [ADEnvironment]::New($item)

        $environment.Class = $list

        $environment.Credential = $item

        $environment.Collection = [ADCollection]::Initialize($environment.Class)

        $environment.Collection.Keys | ForEach-Object { $environment.($_) = [ADCollection]::Get($_) }

        $environment.Finding = [FindingData]::Initialize()

        [ADEnvironment]::Instance = $environment

        return [ADEnvironment]::Instance

    }
    static [ADEnvironment]Initialize([String]$value, [ArrayList]$list) {

        $environment = [ADEnvironment]::New($value)
        $environment.Class = $list
        $environment.Collection = [ADCollection]::Initialize($environment.Class)
        $environment.Collection.Keys | ForEach-Object { $environment.($_) = [ADCollection]::Get($_) }
        $environment.Finding = [FindingData]::Initialize()
        [ADEnvironment]::Instance = $environment
        return [ADEnvironment]::Instance

    }
    static [ADEnvironment]Initialize([String]$value, [PSCredential]$item, [ArrayList]$list) {

        $environment = [ADEnvironment]::New($value, $item)

        $environment.Class = $list

        $environment.Credential = $item

        $environment.Collection = [ADCollection]::Initialize($environment.Class)

        $environment.Collection.Keys | ForEach-Object { $environment.($_) = [ADCollection]::Get($_) }

        $environment.Finding = [FindingData]::Initialize()

        [ADEnvironment]::Instance = $environment

        return [ADEnvironment]::Instance

    }

    static [ADEnvironment]GetEnvironment() {

        if ($null -eq [ADEnvironment]::Instance) {

            throw '{0}({1})' -f 'environmentInstance', 'environment not initialized'

        }
        else {

            return [ADEnvironment]::Instance

        }

    }

    static [void]Close() {

        [ADTarget]::Close()
        [ADCollection]::Close()
        [FindingData]::Close()
        [ADEnvironment]::Instance = $null

    }

    [void]Analyze() {

        try {

            if (-not [Object]::ReferenceEquals($this, [ADEnvironment]::Instance)) {
                throw 'This legacy environment is not current. Use Get-ADAnalyzerAssessment for independent snapshots.'
            }
            [ADTarget]::Diagnostic['StopWatch'].Start()

            $this.Collection.Keys | ForEach-Object { $this.($_).Analyze() }

        }
        catch {

            throw '{0}({1})' -f 'analyze', $_.Exception.Message

        }
        finally {

            [ADTarget]::Diagnostic['StopWatch'].Stop()

        }

    }
    [void]Remediate() {
        throw [NotSupportedException]::new('Legacy automatic remediation is disabled. Use New-ADAnalyzerRemediationPlan and Invoke-ADAnalyzerRemediationPlan.')
    }

}
class ADDiagnostic : Hashtable {

    ADDiagnostic() : base([StringComparer]::OrdinalIgnoreCase) { $this.AddStopWatch() }

    static [ADDiagnostic]$Instance

    static [ADDiagnostic]Initialize() {

        [ADDiagnostic]::Instance = [ADDiagnostic]::New()

        return [ADDiagnostic]::Instance

    }
    static [ADDiagnostic]GetInstance() {

        if ($null -eq [ADDiagnostic]::Instance) {

            throw '{0}({1})' -f 'diagnosticInstance', 'diagnostic not initialized'

        }
        else {

            return [ADDiagnostic]::Instance

        }

    }

    static [void]Close() {

        [ADDiagnostic]::Instance = $null

    }

    [void]AddStopWatch() {

        $this['StopWatch'] = [System.Diagnostics.Stopwatch]::New()

    }

}
#endregion Environment
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Cmdlets
function Get-ADEnvironment () {
    <#
    .SYNOPSIS
        Analyzes and reports AD Environment details including domain configuration & object data
    .DESCRIPTION
        Generates Active Directory environment report required for the assessment of AD security, hygiene, & compliance posture
    .PARAMETER help
        Toggles help switch to display cmdlet details
    .Example
        Get-ADEnvironment -Analyze user, group, computer, groupPolicy
    #>

    [CmdletBinding(DefaultParameterSetName = 'Help')]
    param (

        [Parameter(ParameterSetName = 'Help')]
        [Switch]$Help,

        [Parameter(ParameterSetName = 'Target')]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
        [String]$FQDN,

        [Parameter(ParameterSetName = 'Target')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Alias('Analyze', 'Report')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Target')]
        [ValidateSet('User', 'Group', 'Computer', 'GroupPolicy')]
        [String[]]$Class = @('User', 'Group', 'Computer', 'GroupPolicy'),

        [Parameter(ParameterSetName = 'Target')][string]$ProfilePath,
        [Parameter(ParameterSetName = 'Target')][hashtable]$Profile

    )

    try {

        $var = $PSCmdlet.MyInvocation.BoundParameters
        if ($ProfilePath -and $null -ne $Profile) { throw 'Specify ProfilePath or Profile, not both' }
        $script:ADAnalyzerLegacyProfile = if ($ProfilePath) { Import-ADAnalyzerProfile -Path $ProfilePath } else { Import-ADAnalyzerProfile -Profile $Profile }

    }
    catch { throw '{0}({1})' -f 'error', 'unable to evaluate parameters' }

    try {

        Write-Verbose -Message ('[ {0} ] {1} {2} : {3}' -f '$', 'Analysis', 'Started', (Get-Date -Format 'MM.dd @ HH:mm:ss'))

        if ($var.ContainsKey('Analyze') -or $var.ContainsKey('Report') -or $var.ContainsKey('Class')) {

            if ($Credential -ne [PSCredential]::Empty -and [String]::IsNullOrEmpty($FQDN)) {

                $adEnvironment = [ADEnvironment]::Initialize($Credential, $Class)

            }
            elseif ($Credential -ne [PSCredential]::Empty -and -not [String]::IsNullOrEmpty($FQDN)) {

                $adEnvironment = [ADEnvironment]::Initialize($FQDN, $Credential, $Class)

            }
            elseif (-not [String]::IsNullOrEmpty($FQDN)) {

                $adEnvironment = [ADEnvironment]::Initialize($FQDN, $Class)

            }
            else {

                $adEnvironment = [ADEnvironment]::Initialize($Class)

            }

            $adEnvironment.Analyze()

            return $adEnvironment

        }
        else { Get-Help -Name 'Get-ADEnvironment' -Detailed; return }

    }
    catch { 
        
        throw '{0}({1})' -f 'get', $_.Exception.Message 
    
    }
    finally {

        [ADEnvironment]::Close()
        $script:ADAnalyzerLegacyProfile = $null
        
        Write-Verbose -Message ('[ {0} ] {1} {2} : {3}' -f '$', 'Analysis', 'Completed', (Get-Date -Format 'MM.dd @ HH:mm:ss'))

    }


}
function Set-ADEnvironment {
    <#
    .SYNOPSIS
    Creates an inert remediation plan, or applies an explicitly supplied plan.
    .DESCRIPTION
    Automatic disable/delete by finding label is retired. Apply requires a plan,
    journal, stable identity/state preconditions, and per-object ShouldProcess.
    #>
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param(
        [Alias('Domain')][string]$FQDN,[pscredential]$Credential=[pscredential]::Empty,
        [Alias('Remediate','Fix')][ValidateSet('User','Computer')][string[]]$Class=@('User','Computer'),
        $Plan,[string]$JournalPath,[switch]$Apply,[string]$ProfilePath,$Profile
    )
    if($Apply) {
        if(-not $Plan -or -not $JournalPath){throw 'Apply requires Plan and JournalPath'}
        $arguments=@{Plan=$Plan;Server=$FQDN;Credential=$Credential;JournalPath=$JournalPath;WhatIf=[bool]$WhatIfPreference}
        if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
        return Invoke-ADAnalyzerRemediationPlan @arguments
    }
    if($ProfilePath -and $null -ne $Profile){throw 'Specify ProfilePath or Profile, not both'}
    if($Plan){return $Plan}
    $configuration=if($ProfilePath){Import-ADAnalyzerProfile -Path $ProfilePath}else{Import-ADAnalyzerProfile -Profile $Profile}
    $arguments=@{Credential=$Credential;Profile=$configuration;SkipGpo=$true}
    if($FQDN){$arguments.Domain=$FQDN}
    $assessment=Get-ADAnalyzerAssessment @arguments
    $allowed=@()
    if($Class -contains 'User'){$allowed+='ACCOUNT.INACTIVE'}
    if($Class -contains 'Computer'){$allowed+='COMPUTER.INACTIVE'}
    $assessment.Findings=@($assessment.Findings | Where-Object RuleId -in $allowed)
    New-ADAnalyzerRemediationPlan -Assessment $assessment -Profile $configuration
}

#endregion Cmdlets
######################################################################################################################################################################################################################################################


######################################################################################################################################################################################################################################################
#endregion Classes
######################################################################################################################################################################################################################################################
