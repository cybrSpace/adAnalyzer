[CmdletBinding()]
param([Alias('Invoke')][switch]$CliInvoke)

class ADAnalyzerLocalAdministratorInventory {
    ADAnalyzerLocalAdministratorInventory() {
    }

    [object[]] Read() {
        $ErrorActionPreference = 'Stop'
        $machine = [Environment]::MachineName
        $members = $this.ReadGroup()
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($member in $members) {
            $row = $this.BuildRow(
                $member.Domain, $member.Name, $member.Class, $machine,
                $member.SID, $member.SidValid, $null, $member.Message
            )
            if ($this.NeedsLocalUser($row)) {
                try {
                    $users = @(Get-LocalUser -SID $row.memberSID -ErrorAction Stop)
                    if ($users.Count -ne 1) {
                        throw 'Local user SID did not resolve to exactly one account.'
                    }
                    $evidence = $this.NormalizeSid($users[0].SID)
                    if (-not $this.MatchesSid($evidence, $row.memberSID) -or $users[0].Enabled -isnot [bool]) {
                        throw 'Local user enabled evidence does not match the exact SID.'
                    }
                    $row.memberLocalEnabled = $users[0].Enabled
                }
                catch {
                    $row.memberMessage = $this.AppendEnabledFailure($row.memberMessage, $_.Exception)
                }
            }
            $rows.Add($row)
        }
        return $rows.ToArray()
    }

    [object] Project([Collections.IDictionary]$Member, [string]$MachineName) {
        if ($null -eq $Member) {
            throw [ArgumentNullException]::new('Member')
        }
        if ([string]::IsNullOrWhiteSpace($MachineName)) {
            throw [ArgumentException]::new('Specify a machine authority.', 'MachineName')
        }

        $metadata = @{}
        foreach ($field in @('Domain', 'Name', 'Class', 'SID', 'Message')) {
            $value = $Member[$field]
            if ($null -ne $value -and $value -isnot [string]) {
                throw [ArgumentException]::new("$field must be a string when supplied.", 'Member')
            }
            $metadata[$field] = $value
        }
        foreach ($field in @('SidValid', 'EnabledEvidence')) {
            $value = $Member[$field]
            if ($null -ne $value -and $value -isnot [bool]) {
                throw [ArgumentException]::new("$field must be a Boolean when supplied.", 'Member')
            }
            $metadata[$field] = $value
        }

        return $this.BuildRow(
            $metadata.Domain, $metadata.Name, $metadata.Class, $MachineName,
            $metadata.SID, $metadata.SidValid, $metadata.EnabledEvidence, $metadata.Message
        )
    }

    hidden [object[]] ReadGroup() {
        $entry = $null
        $failure = $null
        $cleanup = $null
        $rows = [Collections.Generic.List[object]]::new()
        try {
            $name = Resolve-LocalAdministratorsName
            $entry = New-LocalAdminDirectoryEntry -Path ('WinNT://./' + $name + ',group')
            if ($null -eq $entry) {
                throw 'Local group binding returned no entry.'
            }
            foreach ($member in $entry.Invoke('Members')) {
                $rows.Add($this.ReadMember($member))
            }
        }
        catch {
            $failure = $_
        }
        finally {
            if ($null -ne $entry) {
                try {
                    $entry.Dispose()
                }
                catch {
                    $cleanup = $_
                }
            }
        }
        if ($null -ne $failure) {
            if ($null -ne $cleanup) {
                $failure.Exception.Data['ADAnalyzerCleanupErrors'] = @($cleanup.Exception.GetBaseException().Message)
            }
            throw $failure
        }
        if ($null -ne $cleanup) {
            throw $cleanup
        }
        return $rows.ToArray()
    }

    hidden [object] ReadMember([object]$Member) {
        $item = $this.NewMember()
        $messages = [Collections.Generic.List[string]]::new()
        $memberPath = $null
        foreach ($property in @('Name', 'AdsPath', 'Class')) {
            try {
                $value = $Member.GetType().InvokeMember(
                    $property, [Reflection.BindingFlags]::GetProperty, $null, $Member, $null
                )
                if ($property -eq 'AdsPath') {
                    $memberPath = [string]$value
                }
                else {
                    $item[$property] = [string]$value
                }
            }
            catch {
                $messages.Add($property + ': ' + $_.Exception.GetBaseException().Message)
            }
        }
        $this.SetAuthority($item, $memberPath, $messages)
        try {
            $raw = $Member.GetType().InvokeMember(
                'Get', [Reflection.BindingFlags]::InvokeMethod, $null, $Member, @('objectSID')
            )
            $evidence = $this.NormalizeSid($raw)
            $item.SID = $evidence.SID
            $item.SidValid = $evidence.SidValid
        }
        catch {
            $messages.Add('SID: ' + $_.Exception.GetBaseException().Message)
        }
        return $this.FinishMember($item, $messages)
    }

    hidden [object] NormalizeSid([object]$Value) {
        if ($null -eq $Value) {
            return $this.SidEvidence($null, $null)
        }
        try {
            $sid = if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
                $Value
            }
            elseif ($Value -is [byte[]]) {
                [System.Security.Principal.SecurityIdentifier]::new($Value, 0)
            }
            else {
                [System.Security.Principal.SecurityIdentifier]::new([string]$Value)
            }
            return $this.SidEvidence($sid.Value, $true)
        }
        catch {
            if ($_.Exception.GetBaseException() -isnot [ArgumentException]) {
                throw
            }
            return $this.SidEvidence($null, $false)
        }
    }

    hidden [object] SidEvidence([object]$Value, [Nullable[bool]]$Valid) {
        return [pscustomobject]@{
            SID = $Value
            SidValid = $Valid
        }
    }

    hidden [Collections.Specialized.OrderedDictionary] NewMember() {
        return [ordered]@{
            Name = $null
            Domain = $null
            Class = $null
            SID = $null
            SidValid = $null
            Message = $null
        }
    }

    hidden [void] SetAuthority(
        [Collections.Specialized.OrderedDictionary]$Item,
        [string]$MemberPath,
        [Collections.Generic.List[string]]$Messages
    ) {
        if ($MemberPath -match '^(?i)WinNT://(.+)$') {
            $parts = $Matches[1].Split('/')
            if ($parts.Count -in @(2, 3) -and
                @($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
                $Item.Domain = $parts[$parts.Count - 2]
            }
            else {
                $Messages.Add('Unrecognized member WinNT path.')
            }
        }
        else {
            $Messages.Add('Member WinNT authority is unavailable.')
        }
    }

    hidden [object] FinishMember(
        [Collections.Specialized.OrderedDictionary]$Item,
        [Collections.Generic.List[string]]$Messages
    ) {
        if ($Messages.Count) {
            $Item.Message = $Messages -join '; '
        }
        return [pscustomobject]$Item
    }

    hidden [object] BuildRow(
        [object]$Domain,
        [object]$Name,
        [object]$Class,
        [string]$MachineName,
        [string]$SID,
        [Nullable[bool]]$SidValid,
        [Nullable[bool]]$EnabledEvidence,
        [string]$Message
    ) {
        $kind = 'UnknownSID'
        $local = $false
        if ($SidValid -eq $false) {
            $kind = 'InvalidSID'
        }
        elseif ($SidValid -eq $true) {
            if ($SID -like 'S-1-12-1-*') {
                $kind = 'EntraSID'
            }
            elseif ($SID -like 'S-1-5-32-*') {
                $kind = 'BuiltinSID'
            }
            elseif ($SID -like 'S-1-5-21-*') {
                if (-not [string]::IsNullOrWhiteSpace([string]$Domain) -and
                    [string]::Equals([string]$Domain, $MachineName, [StringComparison]::OrdinalIgnoreCase)) {
                    $kind = 'MachineLocal'
                    $local = $Class -in @('User', 'Group')
                }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$Domain)) {
                    $kind = 'OtherAuthority'
                }
                else {
                    $kind = 'UnresolvedSID'
                }
            }
            elseif ($SID -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) {
                $kind = 'WellKnownSID'
            }
            else {
                $kind = 'OtherSID'
            }
        }

        $enabled = if ($local -and $Class -eq 'User') {
            $EnabledEvidence
        }
        $invalid = if ($null -ne $SidValid) {
            -not $SidValid
        }
        $memberSid = if ($SidValid -eq $true) {
            $SID
        }
        $memberMessage = if ($Message) {
            $Message
        }
        return [pscustomobject][ordered]@{
            hostname = $MachineName
            memberNetBIOS = $Domain
            memberName = $Name
            memberClass = $Class
            memberLocal = $local
            memberLocalEnabled = $enabled
            memberInvalid = $invalid
            whenCollected = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss')
            memberSID = $memberSid
            memberResolutionKind = $kind
            memberMessage = $memberMessage
        }
    }

    hidden [bool] NeedsLocalUser([object]$Row) {
        return $Row.memberLocal -and $Row.memberClass -eq 'User'
    }

    hidden [bool] MatchesSid([object]$Evidence, [string]$Expected) {
        return $Evidence.SidValid -eq $true -and
            [string]::Equals($Evidence.SID, $Expected, [StringComparison]::OrdinalIgnoreCase)
    }

    hidden [string] AppendEnabledFailure([string]$Message, [Exception]$Failure) {
        $detail = 'Enabled: ' + $Failure.GetBaseException().Message
        if ($Message) {
            return $Message + '; ' + $detail
        }
        return $detail
    }
}

function Resolve-LocalAdministratorsName {
    $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $account = $sid.Translate([System.Security.Principal.NTAccount])
    $name = ([string]$account.Value).Split('\')[-1]
    if ([string]::IsNullOrWhiteSpace($name)) {
        throw 'Administrators SID did not resolve to a local group name.'
    }
    return $name
}

function New-LocalAdminDirectoryEntry {
    param([string]$Path)
    return [System.DirectoryServices.DirectoryEntry]::new($Path)
}

function ConvertTo-LocalAdminSidEvidence {
    param($Value)
    $inventory = [ADAnalyzerLocalAdministratorInventory]::new()
    if ($null -eq $Value) {
        return $inventory.SidEvidence($null, $null)
    }
    try {
        $sid = if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
            $Value
        }
        elseif ($Value -is [byte[]]) {
            [System.Security.Principal.SecurityIdentifier]::new($Value, 0)
        }
        else {
            [System.Security.Principal.SecurityIdentifier]::new([string]$Value)
        }
        $inventory.SidEvidence($sid.Value, $true)
    }
    catch {
        $cause = $_.Exception.GetBaseException()
        if ($cause -isnot [ArgumentException]) {
            throw
        }
        $inventory.SidEvidence($null, $false)
    }
}

function Get-LocalAdministratorGroup {
    [CmdletBinding()]param()
    $ErrorActionPreference = 'Stop'
    $inventory = [ADAnalyzerLocalAdministratorInventory]::new()
    $entry = $null
    $failure = $null
    $cleanup = $null
    $rows = [Collections.Generic.List[object]]::new()
    try {
        $name = Resolve-LocalAdministratorsName
        $entry = New-LocalAdminDirectoryEntry -Path ('WinNT://./' + $name + ',group')
        if ($null -eq $entry) {
            throw 'Local group binding returned no entry.'
        }
        foreach ($member in $entry.Invoke('Members')) {
            $item = $inventory.NewMember()
            $messages = [Collections.Generic.List[string]]::new()
            $memberPath = $null
            foreach ($property in @('Name', 'AdsPath', 'Class')) {
                try {
                    $value = $member.GetType().InvokeMember($property, [Reflection.BindingFlags]::GetProperty, $null, $member, $null)
                    if ($property -eq 'AdsPath') {
                        $memberPath = [string]$value
                    }
                    else {
                        $item[$property] = [string]$value
                    }
                }
                catch {
                    $messages.Add($property + ': ' + $_.Exception.GetBaseException().Message)
                }
            }
            $inventory.SetAuthority($item, $memberPath, $messages)
            try {
                $raw = $member.GetType().InvokeMember('Get', [Reflection.BindingFlags]::InvokeMethod, $null, $member, @('objectSID'))
                $evidence = ConvertTo-LocalAdminSidEvidence -Value $raw
                $item.SID = $evidence.SID
                $item.SidValid = $evidence.SidValid
            }
            catch {
                $messages.Add('SID: ' + $_.Exception.GetBaseException().Message)
            }
            $rows.Add($inventory.FinishMember($item, $messages))
        }
    }
    catch {
        $failure = $_
    }
    finally {
        if ($null -ne $entry) {
            try {
                $entry.Dispose()
            }
            catch {
                $cleanup = $_
            }
        }
    }
    if ($null -ne $failure) {
        if ($null -ne $cleanup) {
            $failure.Exception.Data['ADAnalyzerCleanupErrors'] = @($cleanup.Exception.GetBaseException().Message)
        }
        throw $failure
    }
    if ($null -ne $cleanup) {
        throw $cleanup
    }
    return $rows.ToArray()
}

function New-LocalAdminObject {
    param(
        $Domain,
        $Name,
        $Class,
        [string]$MachineName = [Environment]::MachineName,
        [string]$SID,
        [Nullable[bool]]$SidValid = $null,
        [Nullable[bool]]$EnabledEvidence = $null,
        [string]$Message

    )
    $inventory = [ADAnalyzerLocalAdministratorInventory]::new()
    return $inventory.BuildRow($Domain, $Name, $Class, $MachineName, $SID, $SidValid, $EnabledEvidence, $Message)
}

function Get-LocalAdministrators {
    [CmdletBinding()]param()
    $ErrorActionPreference = 'Stop'
    $inventory = [ADAnalyzerLocalAdministratorInventory]::new()
    $machine = [Environment]::MachineName
    $members = @(Get-LocalAdministratorGroup)
    $rows = @(foreach ($member in $members) {
            $row = New-LocalAdminObject `
                -Domain $member.Domain `
                -Name $member.Name `
                -Class $member.Class `
                -MachineName $machine `
                -SID $member.SID `
                -SidValid $member.SidValid `
                -Message $member.Message
            if ($inventory.NeedsLocalUser($row)) {
                try {
                    $users = @(Get-LocalUser -SID $row.memberSID -ErrorAction Stop)
                    if ($users.Count -ne 1) {
                        throw 'Local user SID did not resolve to exactly one account.'
                    }
                    $evidence = ConvertTo-LocalAdminSidEvidence -Value $users[0].SID
                    if (-not $inventory.MatchesSid($evidence, $row.memberSID) -or
                        $users[0].Enabled -isnot [bool]) {
                        throw 'Local user enabled evidence does not match the exact SID.'
                    }
                    $row.memberLocalEnabled = $users[0].Enabled
                }
                catch {
                    $row.memberMessage = $inventory.AppendEnabledFailure($row.memberMessage, $_.Exception)
                }
            }
            $row
        })
    return $rows
}
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $CliInvoke) {
        throw 'Specify -Invoke to collect local Administrators.'
    }
    Get-LocalAdministrators
}
