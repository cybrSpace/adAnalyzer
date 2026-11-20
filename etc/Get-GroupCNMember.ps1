[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('Array')][string[]]$CliArray = @(),
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty,
    [Alias('OutputPath')][string]$CliOutputPath
)

class ADAnalyzerGroupInventory {
    ADAnalyzerGroupInventory() {
    }

    [object[]] Collect([string[]]$Selectors) {
        return $this.Collect($Selectors, '', [pscredential]::Empty)
    }

    [object[]] Collect([string[]]$Selectors, [string]$Server) {
        return $this.Collect($Selectors, $Server, [pscredential]::Empty)
    }

    [object[]] Collect([string[]]$Selectors, [string]$Server, [pscredential]$Credential) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Selectors -or -not $Selectors.Count) {
            throw 'Specify at least one group selector.'
        }
        $selectorsCopy = [string[]]$Selectors.Clone()
        $utf8 = $this.StrictUtf8()
        foreach ($selector in $selectorsCopy) {
            if ($this.BlankName($selector)) {
                throw 'Group selectors must be nonempty strings.'
            }
            $null = $utf8.GetByteCount($selector)
        }

        $repository = Split-Path -Parent $PSScriptRoot
        $path = Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $path -Scope Local -PassThru -ErrorAction Stop
        if ($null -eq $provider -or $null -eq $provider.ExportedCmdlets -or
            $provider.ExportedCmdlets['Get-ADGroup'] -isnot [Management.Automation.CommandInfo] -or
            $provider.ExportedCmdlets['Get-ADObject'] -isnot [Management.Automation.CommandInfo]) {
            throw 'Bundled AD assembly does not provide the required group inventory commands.'
        }
        $readGroup = $provider.ExportedCmdlets['Get-ADGroup']
        $readObject = $provider.ExportedCmdlets['Get-ADObject']
        $connection = $this.Connection($Server, $Credential)
        $objects = $this.NewObjectCache()
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($selector in $selectorsCopy) {
            $filter = $this.SelectorFilter($selector)
            $selected = @(& $readGroup -LDAPFilter $filter -Properties @('CN', 'Member') @connection)
            if (-not $selected.Count) {
                throw ('No group matched selector: ' + $selector)
            }
            foreach ($group in $selected) {
                $this.WalkRoot($selector, $group, $objects, $readObject, $connection, $rows)
            }
        }
        return $rows.ToArray()
    }

    [object[]] Export([string[]]$Selectors, [string]$Path) {
        return $this.Export($Selectors, $Path, '', [pscredential]::Empty, $false)
    }

    [object[]] Export([string[]]$Selectors, [string]$Path, [bool]$DryRun) {
        return $this.Export($Selectors, $Path, '', [pscredential]::Empty, $DryRun)
    }

    [object[]] Export([string[]]$Selectors, [string]$Path, [string]$Server, [pscredential]$Credential) {
        return $this.Export($Selectors, $Path, $Server, $Credential, $false)
    }

    [object[]] Export(
        [string[]]$Selectors,
        [string]$Path,
        [string]$Server,
        [pscredential]$Credential,
        [bool]$DryRun
    ) {
        $ErrorActionPreference = 'Stop'
        if ([string]::IsNullOrEmpty($Path)) {
            throw 'A group inventory output path is required.'
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADFile.ps1')
        $destination = Resolve-ADAnalyzerFilePath $Path
        $rows = $this.Collect($Selectors, $Server, $Credential)
        if (-not $DryRun) {
            $content = ($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
            $null = Write-ADAnalyzerFile -Path $destination -Content $content
        }
        return $rows
    }

    hidden [void] WalkRoot(
        [string]$GroupName,
        [object]$Group,
        [Collections.Generic.Dictionary[string, object]]$Objects,
        [Management.Automation.CommandInfo]$ReadObject,
        [hashtable]$Connection,
        [Collections.Generic.List[object]]$Rows
    ) {
        $rootDn = [string]$Group.DistinguishedName
        if ($this.BlankName($rootDn)) {
            throw 'A selected group has no distinguished name.'
        }
        $walk = $this.StartWalk($rootDn, $Group)
        $pending = $walk.Pending
        while ($pending.Count) {
            $containing = $pending.Dequeue()
            $containingDn = [string]$containing.DistinguishedName
            $memberDns = @()
            if ($null -ne $containing.Member) {
                $memberDns = @($containing.Member)
            }
            if (-not $memberDns.Count) {
                $Rows.Add($this.Row($containingDn, $GroupName, $null, $null))
                continue
            }
            foreach ($memberDn in $memberDns) {
                $member = $this.ReadMember([string]$memberDn, $Objects, $ReadObject, $Connection)
                $Rows.Add($this.Row($containingDn, $GroupName, $member.SamAccountName, $member.ObjectClass))
                if ($this.IsNestedGroup($member.ObjectClass)) {
                    $this.QueueNested($walk, ([string]$member.DistinguishedName), $member)
                }
            }
        }
    }

    hidden [object] ReadMember(
        [string]$DistinguishedName,
        [Collections.Generic.Dictionary[string, object]]$Objects,
        [Management.Automation.CommandInfo]$ReadObject,
        [hashtable]$Connection
    ) {
        if ($this.BlankName($DistinguishedName)) {
            throw 'A group member has no distinguished name.'
        }
        if ($Objects.ContainsKey($DistinguishedName)) {
            return $Objects[$DistinguishedName]
        }
        $properties = @('SamAccountName', 'ObjectClass', 'CN', 'Member')
        $found = @(& $ReadObject -Identity $DistinguishedName -Properties $properties @Connection)
        if ($found.Count -ne 1) {
            throw 'A member distinguished name did not resolve to exactly one record.'
        }
        $record = $found[0]
        $recordDn = [string]$record.DistinguishedName
        if ($this.BlankName($recordDn) -or $this.BlankName([string]$record.ObjectClass)) {
            throw 'A member record lacks required identity or class metadata.'
        }
        $this.Remember($Objects, $DistinguishedName, $recordDn, $record)
        return $record
    }

    hidden [Text.UTF8Encoding] StrictUtf8() {
        return [Text.UTF8Encoding]::new($false, $true)
    }

    hidden [bool] BlankName([string]$Value) {
        return [string]::IsNullOrWhiteSpace($Value)
    }

    hidden [string] SelectorFilter([string]$Selector) {
        $escaped = $Selector.Replace('\', '\5c')
        $escaped = $escaped.Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
        $escaped = $escaped.Replace([string][char]0, '\00')
        return '(|(CN={0})(sAMAccountName={0}))' -f $escaped
    }

    hidden [hashtable] Connection([string]$Server, [pscredential]$Credential) {
        $connection = @{
            ErrorAction = 'Stop'
        }
        if ($Server) {
            $connection.Server = $Server
        }
        if ($null -ne $Credential -and $Credential -ne [pscredential]::Empty) {
            $connection.Credential = $Credential
        }
        return $connection
    }

    hidden [Collections.Generic.Dictionary[string, object]] NewObjectCache() {
        return [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    }

    hidden [void] Remember(
        [Collections.Generic.Dictionary[string, object]]$Objects,
        [string]$RequestedDn,
        [string]$RecordDn,
        [object]$Record
    ) {
        $Objects[$RequestedDn] = $Record
        $Objects[$RecordDn] = $Record
    }

    hidden [hashtable] StartWalk([string]$RootDn, [object]$Group) {
        $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $pending = [Collections.Generic.Queue[object]]::new()
        $null = $visited.Add($RootDn)
        $pending.Enqueue($Group)
        return @{
            Visited = $visited
            Pending = $pending
        }
    }

    hidden [bool] IsNestedGroup([object]$ObjectClass) {
        return @($ObjectClass) -icontains 'group'
    }

    hidden [void] QueueNested([hashtable]$Walk, [string]$DistinguishedName, [object]$Member) {
        if ($Walk.Visited.Add($DistinguishedName)) {
            $Walk.Pending.Enqueue($Member)
        }
    }

    hidden [object] Row([string]$ContainingDn, [string]$RootName, [object]$AccountName, [object]$ObjectClass) {
        return [pscustomobject][ordered]@{
            'group.DN' = $ContainingDn
            'group.CN' = $RootName
            'member.SamAccountName' = $AccountName
            'member.objectClass' = $ObjectClass
        }
    }
}

function Get-GroupCN {
    <# .SYNOPSIS Reads bounded membership inventories for exact CN/SAM selectors. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$Array = @(),
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [string]$OutputPath

    )
    $ErrorActionPreference = 'Stop'
    $inventory = [ADAnalyzerGroupInventory]::new()
    if (-not $Array.Count) {
        throw 'Specify at least one group selector.'
    }
    $utf8 = $inventory.StrictUtf8()
    foreach ($item in $Array) {
        if ($inventory.BlankName($item)) {
            throw 'Group selectors must be nonempty strings.'
        }
        $null = $utf8.GetByteCount($item)
    }
    $repository = Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $connection = $inventory.Connection($Server, $Credential)
    $objects = $inventory.NewObjectCache()

    function Read-GroupCNObject {
        param([string]$DistinguishedName)
        if ($inventory.BlankName($DistinguishedName)) {
            throw 'A group member has no distinguished name.'
        }
        if ($objects.ContainsKey($DistinguishedName)) {
            return $objects[$DistinguishedName]
        }
        $found = @(Get-ADObject -Identity $DistinguishedName -Properties @('SamAccountName', 'ObjectClass', 'CN', 'Member') @connection)
        if ($found.Count -ne 1) {
            throw 'A member distinguished name did not resolve to exactly one record.'
        }
        $record = $found[0]
        $recordDn = [string]$record.DistinguishedName
        if ($inventory.BlankName($recordDn) -or $inventory.BlankName([string]$record.ObjectClass)) {
            throw 'A member record lacks required identity or class metadata.'
        }
        $inventory.Remember($objects, $DistinguishedName, $recordDn, $record)
        return $record
    }

    function Get-GroupCNMember {
        param(
            [string]$GroupName,
            $Group

        )
        $rootDn = [string]$Group.DistinguishedName
        if ($inventory.BlankName($rootDn)) {
            throw 'A selected group has no distinguished name.'
        }
        $walk = $inventory.StartWalk($rootDn, $Group)
        $pending = $walk.Pending
        while ($pending.Count) {
            $containing = $pending.Dequeue()
            $containingDn = [string]$containing.DistinguishedName
            $memberDns = @()
            if ($null -ne $containing.Member) {
                $memberDns = @($containing.Member)
            }
            if (-not $memberDns.Count) {
                $inventory.Row($containingDn, $GroupName, $null, $null)
                continue
            }
            foreach ($memberDn in $memberDns) {
                $member = Read-GroupCNObject -DistinguishedName ([string]$memberDn)
                $inventory.Row($containingDn, $GroupName, $member.SamAccountName, $member.ObjectClass)
                if ($inventory.IsNestedGroup($member.ObjectClass)) {
                    $nestedDn = [string]$member.DistinguishedName
                    $inventory.QueueNested($walk, $nestedDn, $member)
                }
            }
        }
    }
    $rows = @(foreach ($item in $Array) {
            $filter = $inventory.SelectorFilter($item)
            $selected = @(Get-ADGroup -LDAPFilter $filter -Properties @('CN', 'Member') @connection)
            if (-not $selected.Count) {
                throw ('No group matched selector: ' + $item)
            }
            foreach ($group in $selected) {
                Get-GroupCNMember -GroupName $item -Group $group
            }
        })
    if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Export group membership inventory')) {
        $content = ($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
        . (Join-Path $repository 'bin/ADFile.ps1')
        $null = Write-ADAnalyzerFile -Path $OutputPath -Content $content
    }
    return $rows
}

if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{
        Array = $CliArray
        Credential = $CliCredential
        WhatIf = [bool]$WhatIfPreference
    }
    if ($CliServer) {
        $arguments.Server = $CliServer
    }
    if ($CliOutputPath) {
        $arguments.OutputPath = $CliOutputPath
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $arguments.Confirm = $PSBoundParameters.Confirm
    }
    Get-GroupCN @arguments
}
