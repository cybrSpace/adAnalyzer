#requires -version 5.1

using namespace System.Collections
using namespace System.Collections.Specialized

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('ComputerName')][string[]]$CliComputerName = @(),
    [Alias('StartTime')][Nullable[datetime]]$CliStartTime,
    [Alias('Credential')][pscredential]$CliCredential,
    [Alias('OutputPath')][string]$CliOutputPath
)

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/ADFile.ps1')

class Target {

    $Location
    $Filter
    $Collection = [Collection]::New()

    Target([ArrayList]$server, [Hashtable]$filter) {

        $this.Location = $server
        $this.Filter = $filter
    }

    static [Target]Scan([ArrayList]$server, [Hashtable]$filter, [String]$user) {

        if ($global:PSVersionTable.PSVersion.Major -lt 6) {
            $standardKeys = @(
                'LogName', 'ProviderName', 'Path', 'Keywords', 'ID',
                'Level', 'StartTime', 'EndTime', 'UserID', 'Data'
            )
            if (@($filter.Keys | Where-Object { $_ -notin $standardKeys }).Count) {
                throw 'Legacy named EventData filters require PowerShell 6 or later. Use the DateTime/PSCredential Scan overload on Windows PowerShell 5.1.'
            }
        }

        $c = (Get-Credential -UserName $user -Message 'Enter password for user: ' -ErrorAction Stop)

        $target = [Target]::New([ArrayList]$server, [Hashtable]$filter)

        foreach ($item in $target.Location) {

            # Exclude ANONYMOUS LOGON from results
            # [-] The logic of the NTLM Auditing is that it will log NTLMv2-level authentication when it finds NTLMv2 key material on the logon session
            # [-] It logs NTLMv1 in all other cases, which includes NTLMv1 and LM
            # [-] Therefore, our general recommendation is to ignore the event for security protocol usage information when the event is loggon for ANONYMOUS LOGON
            # [!] https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1

            Get-WinEvent `
                -FilterHashtable $target.Filter `
                -Credential $c `
                -ComputerName $item `
                -ErrorAction Stop | Where-Object { $_.Properties[5].Value -ne 'ANONYMOUS LOGON' } | ForEach-Object {

                $object = [Finding]::New($_.TimeCreated.ToString('g'), $item, $_.Properties)

                $target.Collection.Add([PSCustomObject]$object)
            }
        }

        return $target
    }

    static [Target] Scan([ArrayList]$server, [datetime]$startTime, [pscredential]$credential) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $server -or $server.Count -eq 0) {
            throw [ArgumentException]::new('Specify at least one computer.', 'server')
        }
        if ($startTime -eq [datetime]::MinValue) {
            throw [ArgumentException]::new('Specify a start time.', 'startTime')
        }

        $ownedServers = [ArrayList]::new()
        foreach ($computer in $server) {
            if ($computer -isnot [string] -or [string]::IsNullOrWhiteSpace($computer)) {
                throw [ArgumentException]::new('Computer names must be nonempty strings.', 'server')
            }
            $null = $ownedServers.Add([string]$computer)
        }

        $startUtc = $startTime.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $xpath = "*[System[(EventID=4624) and TimeCreated[@SystemTime >= '$startUtc']] and EventData[Data[@Name='LmPackageName']='NTLM V1']]"
        $queryFilter = @{
            LogName = 'Security'
            Id = '4624'
            StartTime = $startTime
            LmPackageName = 'NTLM V1'
        }
        $scanTarget = [Target]::new($ownedServers, $queryFilter)
        $queryArguments = @{
            LogName = 'Security'
            FilterXPath = $xpath
            ErrorAction = 'Stop'
        }
        if ($null -ne $credential -and $credential -ne [pscredential]::Empty) {
            $queryArguments.Credential = $credential
        }

        foreach ($computer in $ownedServers) {
            $queryArguments.ComputerName = $computer
            Get-WinEvent @queryArguments | ForEach-Object {
                $eventRecord = $_
                $recordFailure = $null
                try {
                    if ($eventRecord.Properties[5].Value -ne 'ANONYMOUS LOGON') {
                        $finding = [Finding]::new(
                            $eventRecord.TimeCreated.ToString('g'),
                            $computer,
                            $eventRecord.Properties
                        )
                        $null = $scanTarget.Collection.Add([pscustomobject]$finding)
                    }
                }
                catch {
                    $recordFailure = $_
                }
                finally {
                    if ($eventRecord -is [IDisposable]) {
                        try {
                            $eventRecord.Dispose()
                        }
                        catch {
                            if ($null -eq $recordFailure) {
                                throw
                            }
                            $recordFailure.Exception.Data['CleanupErrors'] = $_.Exception.Message
                        }
                    }
                }
                if ($null -ne $recordFailure) {
                    throw $recordFailure
                }
            }
        }

        return $scanTarget
    }

    [void]Export([String]$value) {

        $this.Collection.Export($value)
    }

    [Collection]Report() {

        return $this.Collection
    }
}

class Finding : OrderedDictionary {

    Finding ([String]$time, [String]$server, $value) : base([StringComparer]::OrdinalIgnoreCase) {

        $this['Server'] = $server
        $this['EventID'] = '4624'
        $this['LogName'] = 'Security'
        $this['Time'] = $time
        $this['UserName'] = $value[5].Value
        $this['WorkstationName'] = $value[11].Value
        $this['LogonType'] = $value[8].Value
        $this['ImpersonationLevel'] = $value[20].Value

        <#
        $this['AuthenticationPackageName'] = $value[9].Value
        $this['LmPackageName'] = $value[10].Value
        $this['KeyLength'] = $value[12].Value
        #>
    }
}

class Collection : ArrayList {

    Collection() : base() {
    }

    [void]Export([String]$value) {
        try {
            $content = if ($this.Count) {
                ($this | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
            }
            else {
                '"Server","EventID","LogName","Time","UserName","WorkstationName","LogonType","ImpersonationLevel"'
            }
            $null = Write-ADAnalyzerFile -Path $value -Content $content
        }
        catch {
            throw ('{0}({1})' -f 'export', $_.Exception.Message)
        }
    }
}

function Get-ADAnalyzerNtlmEvents {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ComputerName,
        [Nullable[datetime]]$StartTime,
        [pscredential]$Credential,
        [string]$OutputPath
    )

    $since = if ($PSBoundParameters.ContainsKey('StartTime')) {
        if ($null -eq $StartTime) {
            throw 'StartTime must not be null.'
        }
        [datetime]$StartTime
    }
    else {
        (Get-Date).AddDays(-1)
    }

    $scan = [Target]::Scan([ArrayList]$ComputerName, $since, $Credential)
    if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Export NTLM event CSV')) {
        $scan.Export($OutputPath)
    }
    $scan.Report()
}

if ($MyInvocation.InvocationName -ne '.') {
    $invokeArguments = @{
        ComputerName = $CliComputerName
    }
    foreach ($parameter in @('StartTime', 'Credential', 'OutputPath')) {
        if ($PSBoundParameters.ContainsKey('Cli' + $parameter)) {
            $invokeArguments[$parameter] = $PSBoundParameters['Cli' + $parameter]
        }
    }
    foreach ($parameter in @('WhatIf', 'Confirm', 'ErrorAction')) {
        if ($PSBoundParameters.ContainsKey($parameter)) {
            $invokeArguments[$parameter] = $PSBoundParameters[$parameter]
        }
    }

    Get-ADAnalyzerNtlmEvents @invokeArguments
}
