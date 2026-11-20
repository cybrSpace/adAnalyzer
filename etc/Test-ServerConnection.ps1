[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('ComputerName')][string[]]$CliComputerName = @(),
    [Alias('Port')][int[]]$CliPort = @(445),
    [Alias('OutputPath')][string]$CliOutputPath
)

class ADAnalyzerConnectionScan {
    hidden [string[]]$ComputerIdentities
    hidden [int[]]$PortNumbers

    ADAnalyzerConnectionScan([string[]]$ComputerName, [int[]]$Port) {
        $this.ComputerIdentities = @($ComputerName)
        $this.PortNumbers = @($Port)
        $this.Validate()
    }

    hidden [void] Validate() {
        if (-not $this.ComputerIdentities.Count -or -not $this.PortNumbers.Count) {
            throw 'Specify at least one computer and one TCP port.'
        }
        foreach ($computer in $this.ComputerIdentities) {
            if ([string]::IsNullOrWhiteSpace($computer)) {
                throw 'Computer names must be nonempty strings.'
            }
        }
        foreach ($port in $this.PortNumbers) {
            if ($port -lt 1 -or $port -gt 65535) {
                throw 'TCP ports must be between 1 and 65535.'
            }
        }
    }

    [object[]] Collect([Management.Automation.CommandInfo]$Probe) {
        $ErrorActionPreference = 'Stop'
        $this.Validate()
        if ($null -eq $Probe) {
            throw 'A connection probe is required.'
        }

        $collectedRows = [Collections.Generic.List[object]]::new()
        foreach ($computer in $this.ComputerIdentities) {
            foreach ($port in $this.PortNumbers) {
                $address = $null
                $tcpSucceeded = $null
                $completed = $false
                $probeArguments = @{
                    ComputerName = $computer
                    Port = $port
                    WarningAction = 'SilentlyContinue'
                    InformationLevel = 'Detailed'
                    ErrorAction = 'Stop'
                }
                try {
                    $observed = @(& $Probe @probeArguments)
                    if ($observed.Count -ne 1 -or $observed[0].TcpTestSucceeded -isnot [bool]) {
                        throw 'A connection probe must return one boolean TCP result.'
                    }
                    $address = $observed[0].RemoteAddress
                    $tcpSucceeded = $observed[0].TcpTestSucceeded
                    $completed = $true
                }
                catch {
                    $address = $null
                    $tcpSucceeded = $null
                }
                $collectedRows.Add([pscustomobject][ordered]@{
                        ComputerName = $computer
                        RemoteAddress = $address
                        RemotePort = $port
                        tcpTest = $tcpSucceeded
                        result = $completed
                    })
            }
        }
        return $collectedRows.ToArray()
    }

    [string] ToCsv([object[]]$Rows) {
        $ErrorActionPreference = 'Stop'
        if (-not $Rows.Count) {
            return '"ComputerName","RemoteAddress","RemotePort","tcpTest","result"'
        }
        $columns = @(
            'ComputerName'
            'RemoteAddress'
            'RemotePort'
            'tcpTest'
            'result'
        )
        $content = $Rows |
            Select-Object -Property $columns -ErrorAction Stop |
            ConvertTo-Csv -NoTypeInformation -ErrorAction Stop
        return $content -join [Environment]::NewLine
    }
}

function Test-ServerConnection {
    <# .SYNOPSIS Collects explicit TCP probes and optionally writes their five-column CSV report. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$ComputerName = @(),
        [int[]]$Port = @(445),
        [string]$OutputPath

    )

    $ErrorActionPreference = 'Stop'
    $scan = [ADAnalyzerConnectionScan]::new($ComputerName, $Port)
    $probe = Get-Command Test-NetConnection -ErrorAction Stop
    $rows = @($scan.Collect($probe))
    if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Export TCP connection results')) {
        $content = $scan.ToCsv($rows)
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADFile.ps1')
        $null = Write-ADAnalyzerFile -Path $OutputPath -Content $content
    }
    return $rows
}

if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{
        ComputerName = $CliComputerName
        Port = $CliPort
        WhatIf = [bool]$WhatIfPreference
    }
    if ($CliOutputPath) {
        $arguments.OutputPath = $CliOutputPath
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $arguments.Confirm = $PSBoundParameters.Confirm
    }
    Test-ServerConnection @arguments
}
