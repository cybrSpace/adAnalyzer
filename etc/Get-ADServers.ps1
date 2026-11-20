[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('Identity', 'ComputerName', 'Servers')][string[]]$CliIdentity = @(),
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty,
    [Alias('OutputPath')][string]$CliOutputPath
)

class ADAnalyzerServerInventory {
    ADAnalyzerServerInventory() {
    }

    [object[]] Collect([string[]]$Identity) {
        return $this.Collect($Identity, '', [pscredential]::Empty)
    }

    [object[]] Collect([string[]]$Identity, [string]$Server) {
        return $this.Collect($Identity, $Server, [pscredential]::Empty)
    }

    [object[]] Collect([string[]]$Identity, [string]$Server, [pscredential]$Credential) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Identity -or -not $Identity.Count) {
            throw 'Specify at least one computer identity.'
        }
        $identities = [string[]]$Identity.Clone()
        foreach ($item in $identities) {
            if ($this.BlankName($item)) {
                throw 'Computer identities must be nonempty strings.'
            }
        }

        $repository = Split-Path -Parent $PSScriptRoot
        $path = Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $path -Scope Local -PassThru -ErrorAction Stop
        if ($null -eq $provider -or $null -eq $provider.ExportedCmdlets -or
            $provider.ExportedCmdlets['Get-ADComputer'] -isnot [Management.Automation.CommandInfo]) {
            throw 'Bundled AD assembly does not provide Get-ADComputer'
        }
        $query = $provider.ExportedCmdlets['Get-ADComputer']
        $connection = $this.Connection($Server, $Credential)
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($item in $identities) {
            $found = @(& $query -Identity $item @connection)
            if ($found.Count -ne 1 -or $this.BlankName([string]$found[0].Name)) {
                throw 'A computer identity did not resolve to exactly one named record.'
            }
            $rows.Add($this.Row($found[0].Name, $found[0].IPv4Address))
        }
        return $rows.ToArray()
    }

    [object[]] Export([string[]]$Identity, [string]$Path) {
        return $this.Export($Identity, $Path, '', [pscredential]::Empty, $false)
    }

    [object[]] Export([string[]]$Identity, [string]$Path, [bool]$DryRun) {
        return $this.Export($Identity, $Path, '', [pscredential]::Empty, $DryRun)
    }

    [object[]] Export([string[]]$Identity, [string]$Path, [string]$Server, [pscredential]$Credential) {
        return $this.Export($Identity, $Path, $Server, $Credential, $false)
    }

    [object[]] Export(
        [string[]]$Identity,
        [string]$Path,
        [string]$Server,
        [pscredential]$Credential,
        [bool]$DryRun
    ) {
        $ErrorActionPreference = 'Stop'
        if ([string]::IsNullOrEmpty($Path)) {
            throw 'A server inventory output path is required.'
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADFile.ps1')
        $destination = Resolve-ADAnalyzerFilePath $Path
        $rows = $this.Collect($Identity, $Server, $Credential)
        if (-not $DryRun) {
            $content = ($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
            $null = Write-ADAnalyzerFile -Path $destination -Content $content
        }
        return $rows
    }

    hidden [bool] BlankName([string]$Value) {
        return [string]::IsNullOrWhiteSpace($Value)
    }

    hidden [hashtable] Connection([string]$Server, [pscredential]$Credential) {
        $connection = @{
            Properties = @('IPv4Address')
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

    hidden [object] Row([object]$Name, [object]$Address) {
        return [pscustomobject][ordered]@{
            name = $Name
            ipv4Address = $Address
        }
    }
}

function Get-ADServers {
    <# .SYNOPSIS Reads selected computer names and IPv4 addresses using the bundled AD library. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Alias('ComputerName', 'Servers')][string[]]$Identity = @(),
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [string]$OutputPath

    )
    $ErrorActionPreference = 'Stop'
    $inventory = [ADAnalyzerServerInventory]::new()
    if (-not $Identity.Count) {
        throw 'Specify at least one computer identity.'
    }
    foreach ($item in $Identity) {
        if ($inventory.BlankName($item)) {
            throw 'Computer identities must be nonempty strings.'
        }
    }
    $repository = Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $connection = $inventory.Connection($Server, $Credential)
    $rows = @(foreach ($item in $Identity) {
            $found = @(Get-ADComputer -Identity $item @connection)
            if ($found.Count -ne 1 -or $inventory.BlankName([string]$found[0].Name)) {
                throw 'A computer identity did not resolve to exactly one named record.'
            }
            $inventory.Row($found[0].Name, $found[0].IPv4Address)
        })
    if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Export AD server inventory')) {
        $content = ($rows | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
        . (Join-Path $repository 'bin/ADFile.ps1')
        $null = Write-ADAnalyzerFile -Path $OutputPath -Content $content
    }
    return $rows
}

if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{
        Identity = $CliIdentity
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
    Get-ADServers @arguments
}
