using namespace System.Xml
using namespace System.Collections
using namespace System.Collections.Specialized
using namespace System.Management.Automation

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

        foreach ($item in $object.PSObject.Properties) {

            switch ($item.Value) {

                { $item.Value.Count -gt 1 } { $object.($item.Name) = $item.Value -join ';' }
                { $item.Value -is [ArrayList] } { $object.($item.Name) = $item.Value -join ';' }
                { $item.Value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection] } { $object.($item.Name) = $item.Value -join ';' }
                { $item.Value -is [System.DirectoryServices.ActiveDirectorySecurity] } { $object.($item.Name) = $item.Value | ConvertTo-Json }

            }

        }

        return $object

    }

    static [OrderedDictionary]ToOrderedDictionary($value) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

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

    static [OrderedDictionary]DateAttributes($value) {

        $name = $null

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        switch ($_) {

            'lastlogondate' { $name = 'lastlogon' }
            'passwordlastset' { $name = 'pwdlastset' }

            default { $name = $_ }

        }
        if ([String]::IsNullOrEmpty($name)) { return $null } {
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
            { $_ -le 120 -and $_ -gt 90 } { $object['range.{0}' -f $name] = '121 - 150 days' }
            { $_ -le 90 -and $_ -gt 60 } { $object['range.{0}' -f $name] = '121 - 150 days' }
            { $_ -le 60 -and $_ -gt 30 } { $object['range.{0}' -f $name] = '121 - 150 days' }
            { $_ -le 30 -and $_ -gt 14 } { $object['range.{0}' -f $name] = '121 - 150 days' }
            { $_ -le 14 -and $_ -gt 7 } { $object['range.{0}' -f $name] = '121 - 150 days' }

            { $null -ne $_ -and $_ -le 7 } { $object['range.{0}' -f $name] = '<= 7 days' }
            
        }

        return $object

    }

    static [OrderedDictionary]DistinguishedName($value, $list) {

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        $object['orgUnit.L0'] = ($value.Split(',') | Where-Object { $_ -match '(?:CN=|OU=|DC=)' })[1].Replace('(OU=|CN=|DC=', '')
        $object['orgUnit.L0'] = ($value.Split(',') | Where-Object { $_ -match '(?:CN=|OU=|DC=)' })[2].Replace('(OU=|CN=|DC=', '')
        $object['orgUnit.L0'] = ($value.Split(',') | Where-Object { $_ -match '(?:CN=|OU=|DC=)' })[3].Replace('(OU=|CN=|DC=', '')

        return $object

    }

    static [OrderedDictionary]ValueCollection($value) { 

        $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        $value.GetEnumerator() | Where-Object { $_.Key -notin $list } | ForEach-Object { 
            
            $item = $null

            if ($value[$_.Key].Count -eq 0) {                   
                $item = $null   
            }
            elseif ($value[$_.Key].Count -eq 1) {    
                $item = $value[$_.Key][0]    
            }
            elseif ($value[$_.Key].Count -gt 1) {
                $item = [ArrayList]@($value[$_.Key])
            }
            else {    
                $item = $value[$_.Key]     
            }

            $object[$_.Key] = $item
        
        }

        return $object

    }

    static [OrderedDictionary]OrderedProperties($value, $list) {

        $list | Where-Object { -not $value.ContainsKey($_) } | ForEach-Object { $value[$_] = $null }

        return $value

    }

}
class Export {

    static [void]CSV($array, $value) {

        try {

            if (Test-Path $value) { 
                Remove-Item $value -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false 
            }

        }
        catch {

            $value = $value.Replace('.csv', ('_{0}.csv' -f (Get-Date -Format 'yyyy.MM.dd.HHmm')))

        }

        try {

            $list = [ArrayList]::New()

            $array | ForEach-Object { 
                
                if ($_ -is [List] -or $_ -is [ArrayList]) {

                    $item = $_

                    $item | ForEach-Object { $list.Add([Convert]::ToExport($_)) > $null }

                }
                else {

                    $list.Add([Convert]::ToExport([PSCustomObject]$_)) > $null

                }
            
            }

            $list | Export-Csv -Path $value -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false

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

    [String]$name
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

        if (-not [String]::IsNullOrEmpty($this.Finding)) {

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
            $value | Where-Object { $_.Name -notin $this.Exclude } | ForEach-Object { $this.Names[$_] = $null }
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

        if ($WhatIf) { [Process]::WhatIf = $true }

        if ($Confirm) { 
            [Process]::Confirm = $true 
        }
        else { 
            [Process]::Confirm = $true 
        }

    }

}
class Table : Hashtable {

    [Property]$Property = [Property]::New()

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

        try { 

            if ($PSCmdlet.ShouldProcess($value.samaccountname, 'delete')) {

                $item = $value.description

                switch ($item) {

                    { [String]::IsNullOrEmpty($_) } { $item = '{0} | {1} | {2}' -f (Get-Date).ToShortDateString(), 'Delete', $value.'finding' }
                    { -not [String]::IsNullOrEmpty($_) } { $item = '{0} | {1} | {2} | {3}' -f $item, (Get-Date).ToShortDateString(), 'Delete', $value.'finding' }

                }

                if ([DomainData]::GetInstance().WellKnownSID.ContainsKey($value.SID)) { 

                    throw 'WellKnownSID'

                }
                else {

                    if (-not [String]::IsNullOrEmpty($value.adminCount) -and $value.adminCount -eq 1) {
                        Set-ADObject -Identity $value.DistinguishedName -Replace @{ description = $item; $value.adminCount = 0 } -ErrorAction Stop
                    }
                    else {
                        Set-ADObject -Identity $value.distinguishedName -Replace @{ description = $item } -ErrorAction Stop
                    }

                    Remove-ADObject -Identity $value.distinguishedName -Recursive -Confirm:$false -ErrorAction Stop

                }

            }

            if ([Process]::WhatIf) { 

                return 'WhatIf' 

            }
            else {

                return $true

            }

        }
        catch { throw '{0}({1})' -f 'delete', $_.Exception.Message }

    }
    static [Object]Disable($value) {

        try {

            if ($PSCmdlet.ShouldProcess($value.samaccountname, 'Disable')) {

                $item = $value.description

                switch ($item) { 

                    { [String]::IsNullOrEmpty($_) } { $item = '{0} | {1} | {2}' -f (Get-Date).ToShortDateString(), 'Disable', $value.'finding' }
                    { -not [String]::IsNullOrEmpty($_) } { $item = '{0} | {1} | {2} | {3}' -f $item, (Get-Date).ToShortDateString(), 'Disable', $value.'finding' }

                }

                if ([DomainData]::GetInstance().WellKnownSID.ContainsKey($value.SID)) {

                    throw 'WellKnownSID'

                }
                else {

                    if (-not [String]::IsNullOrEmpty($value.adminCount) -and $value.adminCount -eq 1) {
                        Set-ADObject -Identity $value.DistinguishedName -Replace @{ description = $item; $value.adminCount = 0 } -ErrorAction Stop
                    }
                    else {
                        Set-ADObject -Identity $value.distinguishedName -Replace @{ description = $item } -ErrorAction Stop
                    }

                    Disable-ADAccount -Identity $value.samaccountname -ErrorAction Stop

                }

            }

            if ([Process]::WhatIf) { 

                return 'WhatIf' 

            }
            else {

                return $true

            }

        }
        catch { throw '{0}({1})' -f 'disable', $_.Exception.Message }

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

        [DomainData]::Instance.PasswordPolicy = $null

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

        $table = [Hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $table.Properties.SetKey('Name')

        try {

            Get-ADOptionalFeature -Filter * -Properties ('Name', 'DistinguishedName', 'EnabledScopes') -Server $value -ErrorAction Stop | ForEach-Object {

                $object = [OrderedDictionary]@{

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

    [String]$Name
    [String]$Data

    ObjectData () { $this.Name = 'Object' }

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

            Get-ADObject -Filter { objectClass -eq 'user' -or objectClass -eq 'group' -or objectClass -eq 'computer' } -Properties samaccountname -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
                $table[$_.($table.Properties.Key)] = [Format]::ValueCollection($_, $table.Properties.Exclude)
            }

            $table.FormatData()

        }
        catch { throw '{0}({1})' -f 'objectCollection', $_.Exception.Message }

        $this.Data = $table

    }

}
class FindingData : Data {

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

            $object = [ordered]@{
                'class'   = $value
                'finding' = $item.'finding'
                'object'  = ($item | ConvertTo-Json)
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

        $object['linked'] = $obj['gpo.linked']
        $object['linkedOU'] = $obj['gpo.linked.OU']

        $object['configuration'] = $obj['cfg.class']
        $object['configurationEnabled'] = $obj['cfg.enabled']

        foreach ($item in $value.GetEnumerator()) { 

            switch ($item.Value) {

                # { $item.SettingString } { $object[$item.Name] = $item.SettingString }

                { $item.SettingNumber } { $object[$item.Name] = $item.SettingNumber }
                { $item.SettingBoolean } { $object[$item.Name] = $item.SettingBoolean }

            }

        }

        return $object

    }
    static [Finding]Analyze([OrderedDictionary]$value) {

        $list = [Finding]::New()

        if ($value.'ext.property.name' -eq 'Account') {

            switch ($value.'property.setting.name') {

                # Reference : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b40db09-d95d-40a6-8467-32aedec8140c

                # Lockout
                { $_ -eq 'LockoutBadCount' -and $value.'property.setting.value' -gt 6 } { $list.AddFinding($value, 'Defect - Invalid Password Attempt Limit') }
                { $_ -eq 'LockoutDuration' -and $value.'property.setting.value' -lt 30 } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }
                { $_ -eq 'ResetLockoutCount' -and $value.'property.setting.value' -lt 30 } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }
                
                # Password
                { $_ -eq 'ClearTextPassword' -and $value.'property.setting.value' -eq $true } { $list.AddFinding($value, 'Defect - Reversible Encryption Enabled') }
                { $_ -eq 'MaximumPasswordAge' -and $value.'property.setting.value' -gt 90 } { $list.AddFinding($value, 'Defect - Max Password Age') }
                { $_ -eq 'MinimumPasswordAge' -and $value.'property.setting.value' -lt 1 } { $list.AddFinding($value, 'Defect - Minimum Password Age') }
                { $_ -eq 'MinimumPasswordLength' -and $value.'property.setting.value' -lt 12 } { $list.AddFinding($value, 'Defect - Minimum Password Length') }
                { $_ -eq 'PasswordHistorySize' -and $value.'property.setting.value' -lt 10 } { $list.AddFinding($value, 'Defect - Password History') }
                { $_ -eq 'PasswordComplexity' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Password Complexity') }

            }

        }

        return $list

    }
    [void]UpdateInstance() {

        [PasswordPolicy]::GetInstance()[($this['policyName'])] = [PSCustomObject]$this

    }

    [void]SetDefaultProperties() {

        $this.Properties.SetKey('policyName')

        $this.Properties.SetList(
            @(

                'policyName', 'linked', 'linkedOU', 'configuration', 'configurationEnabled'
                'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount'
                'ClearTextPassword', 'MaximumPasswordAge', 'MinimumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'ResetLockoutCount'
                'MaxClockSkew', 'MaxRenewAge', 'MaxServiceAge', 'MaxTicketAge', 'MaxTicketAgeForRenew', 'TicketValidateClient'

            )
        )

    }
}

#endregion Password Policy
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region User

class UserData : Data {

    [String]$Name
    [String]$Data
    [String]$Report
    [String]$Finding

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

            Get-ADUser -Filter * -Properties * -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
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

        $this.Report.Values | ForEach-Object { $array.AddItem([UserData]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()

    }

    [void]SetFinding() {

        $array = [Finding]::New()

        try {

            $this.Finding | ForEach-Object { $array.UpdateFinding([Finding]::Remediate($_, 'disable')) }

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

        $string = 'unknown'

        if ([String]::IsNullOrEmpty($value['givenName'])) {
            $string = 'non-personal'
        }
        else {

            # NOTE : Logic to identify if user is a personal or non-personal / human account
            # NOTE : currently set to use first letter of first name and last name to match samaccountname

            if (('{0}{1}' -f ($value['givenName'].ToCharArray())[0], $value['surName']).Split(' ')[0] -match "^$($value['samaccountname'])$") {
                $string = 'personal'
            }
            else {
                $string = 'non-personal'
            }

        }

        return $string
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

                $item = [Format]::DateAttributes($value.($_))

                $item.GetEnumerator() | ForEach-Object { $object[$_.Name] = $_.Value }

            }
            'userAccountControl' { 
                
                $item = [UserObject]::GetUserAccountControl($value.($_))

                if ($item.Count -eq 1) {

                    object[$_] = [ArrayList]@($item)

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

                $array = [ArrayList]::New()

                $value.($_) | Where-Object { $_ -match ('^CN=({0})' -f ([GroupObject]::ADPrivilegedGroups() -join '|')) } | ForEach-Object {

                    if ([ObjectData]::GetInstance().Data.Contains($_)) {
                        $array.Add([ObjectData]::GetInstance().Data[$_]['samaccountname']) > $null
                    }
                    else {
                        $array.Add($_) > $null
                    }

                }

                if ($array.Count -gt 0) {
                    $object['privilegedGroup'] = $array
                }
                else {
                    $object['privilegedGroup'] = $null
                }

                if ([UserObject]::IsProtectedUser($value.($_))) {
                    $object['protectedUser'] = $true
                }
                else {
                    $object['protectedUser'] = $false
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

        # TODO : get source data to pull HR details for termination findings

        if (-not $value.enabled -and -not $value.WellKnownSID -and $value.'days.whenChanged' -ge 30) {

            $list.AddFinding($value, 'Defect - Disabled > 30 days')

        }
        else {

            switch ($value) {

                # Personal Password Age Warning (>90d - Quarterly Rotation)
                { $value.enabled -and $value.acctType -eq 'personal' -and $value.'days.pwdLastSet' -eq 89 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 1 Days') }
                { $value.enabled -and $value.acctType -eq 'personal' -and $value.'days.pwdLastSet' -eq 88 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 2 Days') }
                { $value.enabled -and $value.acctType -eq 'personal' -and $value.'days.pwdLastSet' -eq 83 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 7 Days') }
                { $value.enabled -and $value.acctType -eq 'personal' -and $value.'days.pwdLastSet' -eq 69 } { $list.AddFinding($value, 'Warning - Personal Password Expiration - 21 Days') }

                # Non-Personal Password Age Warning (>365d - Annual Rotation)
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $value.'days.pwdLastSet' -ge 335 -and $value.'days.pwdLastSet' -lt 365 } { $list.AddFinding($value, 'Warning - Non-Personal Password Expiration - 335 Days') }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $value.'days.pwdLastSet' -ge 305 -and $value.'days.pwdLastSet' -lt 335 } { $list.AddFinding($value, 'Warning - Non-Personal Password Expiration - 305 Days') }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and $value.'days.pwdLastSet' -ge 275 -and $value.'days.pwdLastSet' -lt 305 } { $list.AddFinding($value, 'Warning - Non-Personal Password Expiration - 275 Days') }
                
                # Password Age Defects
                { $value.enabled -and $value.acctType -eq 'personal' -and ($value.'days.pwdLastSet' -ge 90 -or $value.'range.pwdLastSet' -eq 'never') -and $value.'days.whenCreated' -gt 30 } { $list.AddFinding($value, 'Defect - Personal Password Age') }
                { $value.enabled -and $value.acctType -eq 'non-personal' -and ($value.'days.pwdLastSet' -ge 365 -or $value.'range.pwdLastSet' -eq 'never') -and $value.'days.whenCreated' -gt 30 } { $list.AddFinding($value, 'Defect - Non-Personal Password Age') }

                # Inactivity (>60d)
                { $value.enabled -and -not $value.WellKnownSID -and ($value.'days.lastlogon' -ge 60 -or $value.'range.lastlogon' -eq 'never') -and [int]$value.'days.whenCreated' -ge 60 } { $list.AddFinding($value, 'Defect - User Inactivity') }

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
                'enabled', 'passwordlastset', 'lastlogondate', 'whenChangec', 'whenCreated', 'description'

                'userAccountControl', 'AllowedReversiblePasswordEncryption', 'DoesNoteRequirePreAuth', 'PasswordNeverExpires' 
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

    [String]$Name
    [GroupTable]$Data
    [GroupTable]$Report
    [Finding]$Finding

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

            Get-ADGroup -Filter * -Properties * -Server ([ADTarget]::FQDN) -ErrorAction Stop | ForEach-Object {
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

        $this.Report.Values | ForEach-Object { $array.AddItem([GroupData]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()

    }

    [ArrayList]LookupGroupMembers($value) {

        $array = [ArrayList]::New()

        foreach ($item in $value) {

            if ([ADCollection]::Get('object').Contains($item)) {

                $array.add($this.Data[$item]['samaccountname']) > $null

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

                if ($value.($_) -in [GroupObject]::ADPrivilegedGroups()) {

                    $object['privilegedGroup'] = $true

                }
                else {

                    $object['privilegedGroup'] = $false

                }

            }
            { $_ -in ([DateAttributes].GetEnumNames()) } {

                $object[$_] = $value.($_)

                $item = [Format]::DateAttributes($value.($_))

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
        
        switch ($value) {

            # defect
            { [String]::IsNullOrEmpty($value.'managedBy') } { $list.AddFinding($value, 'Defect - Unidentified Owner') }
            { $value.samaccountname -in [GroupObject]::ADPrivilegedGroups() -and -not [String]::IsNullOrEmpty($value.'foreignSecurityPrincipalMembers') } { $list.AddFinding($value, 'Defect - Privileged Group w/ ForeignSecurityPrincipal(s)') }
            { -not [String]::IsNullOrEmpty($value.'members') -and $value.'samaccountname' -in @('Account Operators', 'Backup Operators', 'Print Operators', 'Server Operators') } { $list.AddFinding($value, 'Defect - Privileged Builtin Group w/ Members') }
            { -not [string]::IsNullOrEmpty($value.'memberOf') -and $value.'orgUnit.L0' -notin @('Builtin') } { $list.AddFinding('Defect - Nested Group') }

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

    [String]$Name
    [ComputerTable]$Data
    [ComputerTable]$Report
    [Finding]$Finding

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

        $this.Report.Values | ForEach-Object { $array.AddItem([ComputerData]::Analyze($_)) }

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

                $item = [Format]::DateAttributes($value.($_))

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

        if (-not $value.enabled -and $value.'days.whenChanged' -ge 30) {

            $list.AddFinding($value, 'Defect - Disabled > 30 days')

        }
        else {

            switch ($value) {

                # last logon activity
                { $value.enabled -and ($value.'days.lastlogon' -ge 60 -or $value.'range.lastlogon' -eq 'never') -and [int]$value.'days.whenCreated' -ge 60 } { $list.AddFinding($value, 'Defect - Computer Inactivity') }

                # password age inactivity
                { $value.enabled -and ($value.'days.pwdLastSet' -ge 60 -or $value.'range.pwdLastSet' -eq 'never') -and [int]$value.'days.whenCreated' -ge 60 } { $list.AddFinding($value, 'Defect - Computer Inactivity') }

                # operating system
                { $value.enabled -and $value.'OperatingSystem' -match '^Windows' -and $value.'OperatingSystem' -notmatch '^Windows (10|11|Server (20[1-2]{1}[0-9]{1}))' } { $list.AddFinding($value, 'Defect - Unsupported Operating System') }

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

    [String]$Name
    [GroupPolicyTable]$Data
    [GroupPolicyTable]$Report
    [Finding]$Finding

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

            $table.Properties.SetKey('DisplayName')

            $list = [ArrayList]@('DisplayName', 'CreationTime', 'ModificationTime', 'GPOStatus', 'id')

            $value = @{

                'domain'      = ([ADTarget]::FQDN)
                'server'      = ([ADTarget]::FQDN)
                'ErrorAction' = 'Stop'

            }

            Get-GPO -All @value | Select-Object -Property $list | ForEach-Object {

                $obj = $_

                $object = [OrderedDictionary]::New([System.StringComparer]::OrdinalIgnoreCase)

                $list | ForEach-Object { $object[$_] = $obj.($_) }

                try {

                    $item = @{

                        'guid'       = $_.Id
                        'reporttype' = 'xml'
                        'server'     = ([ADTarget]::FQDN)
                        'domain'     = ([ADTarget]::FQDN)

                    }

                    $object['xml'] = [xml]( Get-GPOReport @item )

                }
                catch {

                    $object['xml'] = $null

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
            
            $object = [GroupPolicyObject]::Initialize($_) 

            if ($null -ne $object.Configuration) {

                $table[$object.($object.Properties.Key)] = $object.Configuration

            }
        
        }

        $this.Report = $table

    }
    [void]GetFinding() {

        $array = [Finding]::New()

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

        if ($value.'ext.property.name' -eq 'Account') {

            switch ($value.'property.setting.name') {

                # Password
                { $_ -eq 'MaximumPasswordAge' -and [bigint]$value.'property.setting.value' -gt 90 } { $list.AddFinding($value, 'Defect - Max Password Age') }
                { $_ -eq 'MinimumPasswordAge' -and $value.'property.setting.value' -lt 1 } { $list.AddFinding($value, 'Defect - Minimum Password Age') }
                { $_ -eq 'MinimumPasswordLength' -and [bigint]$value.'property.setting.value' -lt 12 } { $list.AddFinding($value, 'Defect - Minimum Password Length') }
                { $_ -eq 'PasswordComplexity' -and $value.'property.setting.value' -eq $false } { $list.AddFinding($value, 'Defect - Password Complexity Disabled') }
                { $_ -eq 'PasswordHistorySize' -and [bigint]$value.'property.setting.value' -lt 10 } { $list.AddFinding($value, 'Defect - Password History') }
                { $_ -eq 'ClearTextPassword' -and $value.'property.setting.value' -eq $true } { $list.AddFinding($value, 'Defect - ClearText Password') }

                # Lockout
                { $_ -eq 'LockoutBadCount' -and $value.'property.setting.value' -gt 6 } { $list.AddFinding($value, 'Defect - Invalid Password Attempt Limit') }
                { $_ -eq 'LockoutDuration' -and $value.'property.setting.value' -lt 30 } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }
                { $_ -eq 'ResetLockoutCount' -and $value.'property.setting.value' -lt 30 } { $list.AddFinding($value, 'Defect - Invalid Password Lockout Duration') }

            }

        }
        elseif ($value.'ext.property.name' -eq 'SecurityOptions') {

            switch ($value.'property.setting.name') {

                # TODO : Add 'Network access: Shares that can be access anonymously' to the list

                # NTLM Settings
                { $_ -eq 'Network security: LAN Manager authentication level' -and $value.'property.setting.value' -notin @('Send NTLMv2 responses only. Refuse LM & NTLM', 'Send NTLMv2 response only') } { $list.AddFinding($value, 'Defect - LAN Manager Authentication Level (LmCompatibilityLevel)') }

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
                { $_ -eq 'Network access: Named Pipes that can be accessed anonymously' -and $value.'property.setting.value' -notin @('LSARPC', 'NETLOGON', 'SAMR') } { $list.AddFinding($value, 'Defect - Named Pipes Allow Anonymous (Null) Session') }

                # Shares that can be access anonymously
                { $_ -eq 'Network access: Shares that can be access anonymously' -and $value.'property.setting.value' -notin @() } { $list.AddFinding($value, 'Defect - Shares Allow Anonymous (Null) Session') }

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
                { $_ -eq 'Domain controller: LDAP server signing requirements' -and $value.'property.setting.value' -notin @('Require signature') } { $list.AddFinding($value, 'Defect - LDAP Signing Not Required') }
                { $_ -eq 'Network security: LDAP client signing requirements' -and $value.'property.setting.value' -notin @('') } { $list.AddFinding($value, 'Defect - LDAP Signing Not Required') }

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

                switch ($value.'property.setting.name') {

                    { $_ -match 'Access Credential Manager as a trusted caller' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Access this computer from the network' -and $value.'property.setting.value' -notmatch '(Administrators|Authenticated Users|Domain Admins)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Act as part of the operating system' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Add workstations to domain' -and $value.'property.setting.value' -notmatch '(Administrators|Authenticated Users)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Adjust memory quotas for a process' -and $value.'property.setting.value' -notmatch '(Administrators|LOCAL SERVICE|NETWORK SERVICE)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Allow log on locally' -and $value.'property.setting.value' -notmatch '(Domain Admins|Enterprise Admins|Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Allow log on through Remote Desktop Services' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Back up files and directories' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    # Hardened (Requires thorough testing) { $_ -match 'Bypass traverse checking' -and $value.'property.setting.value' -notmatch '(Administrators|Authenticated Users|Local Service|Network Service)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Bypass traverse checking' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Change the system time' -and $value.'property.setting.value' -notmatch '(Administrators|LOCAL SERVICE)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Change the time zone' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Create a pagefile' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Create a token object' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Create global objects' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Create permanent shared objects' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Create symbolic links' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Debug programs' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Deny access to this computer from the network' -and $value.'property.setting.value' -notmatch '(Guests|ANONYMOUS LOGON)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Deny log on as a batch job' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Deny log on as a service' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Deny log on locally' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Deny log on through Remote Desktop Services' -and $value.'property.setting.value' -notmatch '(Guests)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Enable computer and user accounts to be trusted for delegation' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Force shutdown from a remote system' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Generate security audits' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Impersonate a client after authentication' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Increase a process working set' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Increase scheduling priority' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Load and unload device drivers' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Lock pages in memory' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Log on as a batch job' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Log on as a service' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Manage auditing and security log' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Modify an object label' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Modify firmware environment values' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Obtain an impersonation token for another user in the same session' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Perform volume maintenance tasks' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Profile single process' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Profile system performance' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Remove computer from docking station' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Replace a process level token' -and $value.'property.setting.value' -notmatch '(Network Service|Local Service)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Restore files and directories' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Shut down the system' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Synchronize directory service data' -and -not [String]::IsNullOrEmpty($value.'property.setting.value') } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }
                    { $_ -match 'Take ownership of files or other objects' -and $value.'property.setting.value' -notmatch '(Administrators)' } { $list.AddFinding($value, 'Defect - Invalid UserRightsAssignment') }

                }

            }

            switch ($value.'property.setting.name') {

                { $value.'property.setting.value' -match '^S-1-5' } { $list.AddFinding($value, 'Defect - Unresolvable UserRightsAssignment') }

            }

        }

        return $list

    }

    [List]GetAccountSettings([XmlElement]$value, [GPOExtensionProperty]$name) {

        $array = [List]::New()

        try {

            foreach ($item in $value.Extension.($name).GetEnumerator() | Select-Object -Property *) {

                $object = [GroupPolicyObject]::ImportRecord($this.Record)

                $object.Record['ext.property.name'] = $name
                $object.Record['ext.property.type'] = $item.type

                $object.Record['property.setting.name'] = $item.name

                switch ($item) {

                    { $item.SettingNumber } { $object.Record['property.setting.value'] = [bigint]$item.SettingNumber }
                    { $item.SettingBoolean } { $object.Record['property.setting.value'] = [Convert]::ToBoolean($item.SettingBoolean) }

                }

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

            foreach ($item in $value.Extension.($name).GetEnumerator() | Select-Object -Property *) {

                if (-not [String]::IsNullOrEmpty($item.Display)) {

                    $object = [GroupPolicyObject]::ImportRecord($this.Record)

                    $object.Record['ext.property.name'] = $name
                    $object.Record['ext.property.type'] = $null

                    $object.Record['property.setting.name'] = $item.Display.Name

                    switch ($item) {

                        { $item.Display.DisplayString } { $object.Record['property.setting.value'] = $item.Display.DisplayString }
                        { $item.Display.DisplayBoolean } { $object.Record['property.setting.value'] = [Convert]::ToBoolean($item.Display.DisplayBoolean) }

                    }

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

            foreach ($list in $value.Extension.($name).GetEnumerator() | Select-Object -Property *) {

                if ([String]::IsNullOrEmpty($list.Member)) {

                    $object = [GroupPolicyObject]::ImportRecord($this.Record)

                    $object.Record['ext.property.name'] = $name
                    $object.Record['ext.property.type'] = $null

                    $object.Record['property.setting.name'] = ('{0} ({1})' -f $table[$list.Name], $list.Name)

                    $array.add([PSCustomObject]$object.Record) > $null

                }
                else {

                    foreach ($item in $list.Member) {

                        $object = [GroupPolicyObject]::ImportRecord($this.Record)

                        $object.Record['ext.property.name'] = $name
                        $object.Record['ext.property.type'] = $null

                        $object.Record['property.setting.name'] = ('{0} ({1})' -f $table[$list.Name], $list.Name)
                        $object.Record['property.setting.value'] = $item

                        if (-not [String]::IsNullOrEmpty($item.Name.'#text')) {

                            $object.Record['property.setting.value'] = $item.Name.'#text'

                        }
                        else {

                            $object.Record['property.setting.value'] = $item.SID.'#text'
                            
                        }
                        
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

        $object = [GroupPolicyObject]::ImportRecord($this.Record)

        $object.Record['cfg.extension'] = $value.Name

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

                }

            }

        }
        catch { throw '{0}({1})' -f 'ExtensionData', $_.Exception.Message }

        return $array

    }

    [void]NewRecordItem() {

        $this.Record = [GroupPolicyObject]::SetDefault()

        switch ($this.Record.Properties.List) {

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

        $this.Properties.SetKey('gpo.name')
        $this.Properties.SetList(

            @(
                'gpo.name', 'gpo.created', 'gpo.modified', 'gpo.read', 'gpo.status', 'gpo.linked', 'gpo.linked.ou'
                'cfg.class', 'cfg.enabled', 'cfg.loopback', 'cfg.extension'
                'ext.property.name', 'ext.property.enabled', 'ext.property.type'
                'property.setting.name', 'property.setting.value', 'property.setting.parameter'
                'ext.property.parameter', 'ext.property.filter'
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
    static [String]$Diagnostic

    hidden [Microsoft.ActiveDirectory.Management.Provider.ADDriveInfo]$Connection

    ADTarget() {

        [ADTarget]::FQDN = (Get-WmiObject -Class Win32_ComputerSystem).Domain

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

    }
    ADTarget([String]$value) {

        [ADTarget]::FQDN = $value

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

    }
    ADTarget([PSCredential]$item) {

        [ADTarget]::FQDN = (Get-WmiObject -Class Win32_ComputerSystem).Domain

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

        $this.Connect($item)

    }
    ADTarget([String]$value, [PSCredential]$item) {

        [ADTarget]::FQDN = $value

        [ADTarget]::Diagnostic = [ADDiagnostic]::Initialize()

        $this.Connect($item)

    }
    static [void]Close() {

        Set-Location -Path ($env:USERPROFILE)

        [ADTarget]::Disconnect()

        [ADTarget]::FQDN = $null

        [ADTarget]::Diagnostic = $null

        [ADTarget]::Instance = $null

    }
    static [void]Disconnect() {

        try {

            Set-Location -Path ($env:USERPROFILE)

            $item = ([ADTarget]::FQDN.SPlit('.')[0])

            Get-PSDrive | Where-Object { $_.Name -eq $item } | ForEach-Object {

                Set-Location -Path ($env:USERPROFILE) -ErrorAction Stop
                Remove-PSDrive -Name ($_) -ErrorAction Stop -WhatIf:$false -Confirm:$false

            }

        }
        catch { }

    }

    [void]Connect([PSCredential]$value) {

        $object = $null

        try {

            Test-ComputerSecureChannel -Server ([ADTarget]::FQDN) -Credential $value -WhatIf:$false -Confirm:$false

        }
        catch { throw '{0}({1})' -f 'targetConnection', 'unable to establish secure connection' }

        try {

            $item = Get-ADDomain -Server ([ADTarget]::FQDN) -Credential $value

            Get-PSDrive | Where-Object { $_.Name -eq $item.NetBiosName } | ForEach-Object {

                Set-Location -Path ($env:USERPROFILE) -ErrorAction Stop
                Remove-PSDrive -Name ($_) -ErrorAction Stop -WhatIf:$false -Confirm:$false

            }

            $object = New-PSDrive -Server ([ADTarget]::FQDN) -Name $item.NetBiosName -PSProvider ActiveDirectory -Root $item.DistinguishedName -Credential $value -ErrorAction Stop -WhatIf:$false -Confirm:$false

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

            Test-ComputerSecureChannel -Server $fqdn -Credential $value -WhatIf:$false -Confirm:$false

        }
        catch { throw '{0}({1})' -f 'targetConnection', 'unable to establish secure connection' }

        try {

            $item = Get-ADDomain -Server $fqdn -Credential $value

            Get-PSDrive | Where-Object { $_.Name -eq $item.NetBiosName } | ForEach-Object {

                Set-Location -Path ($env:USERPROFILE) -ErrorAction Stop
                Remove-PSDrive -Name ($_) -ErrorAction Stop -WhatIf:$false -Confirm:$false

            }

            $object = New-PSDrive -Server $fqdn -Name $item.NetBiosName -PSProvider ActiveDirectory -Root $item.DistinguishedName -Credential $value -ErrorAction Stop -WhatIf:$false -Confirm:$false

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

        if ([ADCollection]::Data.Count -gt 0) {

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
        [ADEnvironment]::Instance = $null

    }

    [void]Analyze() {

        try {

            [ADTarget]::Diagnostic['StopWatch']::StartNew()

            $this.Collection.Keys | ForEach-Object { $this.($_).Analyze() }

        }
        catch {

            throw '{0}({1})' -f 'analyze', $_.Exception.Message

        }
        finally {

            [ADTarget]::Diagnostic['StopWatch']::Stop()

        }

    }
    [void]Remediate() {

        try {

            [DomainData]::Instance = $this.Domain
            [ADDiagnostic]::Initialize()
            [ADDiagnostic]::GetInstance()['StopWatch'].Start()

            if ($null -ne $this.Credential) {

                $this.Connect($this.Domain.FQDN, $this.Credential)

            }

            $this.Collection.Keys | Where-Object { $_ -in $this.Class } | ForEach-Object { $this.($_).SetFinding() }

        }
        catch {

            throw '{0}({1})' -f 'remediate', $_.Exception.Message

        }
        finally {

            [DomainData]::Instance = $null
            [ADDiagnostic]::GetInstance()['StopWatch'].Stop()

        }

    }

}
class ADDiagnostic : Hashtable {

    ADDiagnostic() : base([StringComparer]::OrdinalIgnoreCase) { $this.AddStopWatch }

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
        [ValidateScript(
            {
                if (Test-ComputerSecureChannel -Server $PSItem -WhatIf:$false -Confirm:$false) {
                    $true
                }
                else {
                    $false
                }
            }
        )]
        [String]$FQDN,

        [Parameter(ParameterSetName = 'Target')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Alias('Analyze', 'Report')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Target')]
        [ValidateSet('User', 'Group', 'Computer', 'GroupPolicy')]
        [ArrayList]$Class = @('User', 'Group', 'Computer', 'GroupPolicy')

    )

    try {

        $var = $PSCmdlet.MyInvocation.BoundParameters

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
            else {

                $adEnvironment = [ADEnvironment]::Initialize($Class)

            }

            $adEnvironment.Analyze()

            return $adEnvironment

        }
        else { Get-Help -Name 'Get-ADEnvironment' -Detailed; exit }

    }
    catch { 
        
        throw '{0}({1})' -f 'get', $_.Exception.Message 
    
    }
    finally {

        [ADEnvironment]::Close()
        
        Write-Verbose -Message ('[ {0} ] {1} {2} : {3}' -f '$', 'Analysis', 'Completed', (Get-Date -Format 'MM.dd @ HH:mm:ss'))

    }


}
function Set-ADEnvironment () {
    <#
    .SYNOPSIS
        Remediates AD Environment findings related to the hygiene and compliance of AD objects
    .DESCRIPTION
        Executes corrective actions against Active Directory objects to remediate findings
    .PARAMETER help
        Toggles help switch to display cmdlet details
    .Example
        Get-ADEnvironment -Remediate user, computer
    #>

    [CmdletBinding(DefaultParameterSetName = 'Help', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (

        [Parameter(ParameterSetName = 'Help')]
        [Switch]$Help,

        [Parameter(ParameterSetName = 'Target')]
        [ValidateScript(
            {
                if (Test-ComputerSecureChannel -Server $PSItem -WhatIf:$false ) {
                    $true
                }
                else {
                    $false
                }
            }
        )]
        [String]$FQDN,

        [Parameter(ParameterSetName = 'Target')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Alias('Remediate', 'Fix')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Target')]
        [ValidateSet('user', 'computer')]
        [ArrayList]$Class = @('user', 'computer')

    )

    try {

        $var = $PSCmdlet.MyInvocation.BoundParameters

        if ($var['Confirm'] -eq $true) {

            $ConfirmPreference = 'High'

        }

        if ($var.ContainsKey('WhatIf') -and $var.ContainsKey('Confirm')) {

            [Process]::Initialize($var['WhatIf'], $var['Confirm'])

        }
        elseif ($var.ContainsKey('Confirm')) {

            [Process]::Initialize($WhatIfPreference.IsPresent, $var['Confirm'])

        }
        else {

            [Process]::Initialize($WhatIfPreference.IsPresent, $ConfirmPreference)

        }

    }
    catch { throw '{0}({1})' -f 'error', 'unable to evaluate parameters' }

    try {

        if ($var.ContainsKey('Remediate') -or $var.ContainsKey('Class')) {

            $value = $null
        
            Write-Information -MessageData ''

            Write-Verbose -Message ('[ {0} ] {1} {2} : {3}' -f '$', 'Remediation', 'Started', (Get-Date -Format 'MM.dd @ HH:mm:ss'))

            switch ($var.Keys) {

                'Class' { $value = ($var['Class'] -join '; ') }
                'Remediate' { $value = ($var['Remediate'] -join '; ') }

            }

            if ($PSCmdlet.ShouldProcess($value, 'Remediate AD Environment Findings')) {

                # NOTE : [Process] class sets the WhatIfPreference and Confirm variables
                # NOTE : Empty ShouldProcess to trigger prompt

            }

            if ($Credential -ne [PSCredential]::Empty -and [String]::IsNullOrEmpty($FQDN)) {

                $splat = @{

                    'analyze'    = $Class
                    'credential' = $Credential

                }

            }
            elseif ($Credential -ne [PSCredential]::Empty -and -not [String]::IsNullOrEmpty($FQDN)) {

                $splat = @{

                    'fqdn'       = $FQDN
                    'analyze'    = $Class
                    'credential' = $Credential

                }

            }
            else {

                $splat = @{

                    'analyze' = $Class

                }

            }

            $adEnvironment = Get-ADEnvironment @splat

            $adEnvironment.Remediate()

            return $adEnvironment

        }
        else { Get-Help -Name 'Set-ADEnvironment' -Detailed; exit }

    }
    catch { 
        
        throw '{0}({1})' -f 'set', $_.Exception.Message 
    
    }
    finally {

        [Process]::Close()
        [ADEnvironment]::Close()
        
        Write-Verbose -Message ('[ {0} ] {1} {2} : {3}' -f '$', 'Remediation', 'Completed', (Get-Date -Format 'MM.dd @ HH:mm:ss'))

    }

}

#endregion Cmdlets
######################################################################################################################################################################################################################################################


######################################################################################################################################################################################################################################################
#endregion Classes
######################################################################################################################################################################################################################################################
