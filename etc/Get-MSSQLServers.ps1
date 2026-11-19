using namespace System.Collections
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('SearchBase')][string]$CliSearchBase,
    [Alias('Filter')][string]$CliFilter = 'Windows Server',
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty,
    [Alias('DirectoryConnection')][ValidateSet('PSDrive', 'Direct')][string]$CliDirectoryConnection = 'PSDrive',
    [Alias('OperationTimeoutSeconds')][ValidateRange(1, 300)][int]$CliOperationTimeoutSeconds = 30,
    [Alias('OutputPath')][string]$CliOutputPath
)
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/ADFile.ps1')

class Collection : ArrayList {
    [void]Export([string]$path) {
        $content = if ($this.Count) {
            ($this | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine
        }
        else {
            '"computer.Name","computer.Status","service.Name","service.DisplayName","service.Status","computer.Message"'
        }
        $null = Write-ADAnalyzerFile -Path $path -Content $content
    }
    [void]Finding([string]$computer, [bool]$status, [string]$message) {
        $this.Add([pscustomobject][ordered]@{
                'computer.Name' = $computer
                'computer.Status' = $status
                'service.Name' = $null
                'service.DisplayName' = $null
                'service.Status' = $null
                'computer.Message' = $message
            }) > $null
    }
    [void]Finding([string]$computer, [string]$service, [string]$name, [string]$status) {
        $this.Finding($computer, $service, $name, $status, $null)
    }
    [void]Finding([string]$computer, [string]$service, [string]$name, [string]$status, [string]$message) {
        $this.Add([pscustomobject][ordered]@{
                'computer.Name' = $computer
                'computer.Status' = $true
                'service.Name' = $service
                'service.DisplayName' = $name
                'service.Status' = $(if ([string]::IsNullOrEmpty($status)) {
                        $null
                    }
                    else {
                        $status
                    })
                'computer.Message' = $(if ([string]::IsNullOrEmpty($message)) {
                        $null
                    }
                    else {
                        $message
                    })
            }) > $null
    }
}

class ADAnalyzerSqlServiceInventory {
    ADAnalyzerSqlServiceInventory() {
    }

    [Collection] Read() {
        return $this.Read(@{})
    }

    [Collection] Read([hashtable]$Options) {
        $ErrorActionPreference = 'Stop'
        $request = $this.Request($Options)
        $computers = $this.Discover($request)
        $results = [Collection]::new()
        foreach ($computer in $computers) {
            $this.ReadServices($results, $computer, $request.OperationTimeoutSeconds, $request.Credential)
        }
        return $results
    }

    hidden [hashtable] Request([hashtable]$Options) {
        if ($null -eq $Options) {
            $Options = @{}
        }
        $values = @{
            SearchBase = $null
            Filter = 'Windows Server'
            Server = $null
            Credential = [pscredential]::Empty
            DirectoryConnection = 'PSDrive'
            OperationTimeoutSeconds = 30
        }
        $supplied = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($field in $Options.get_Keys()) {
            if ($field -isnot [string] -or -not $values.ContainsKey($field)) {
                throw [ArgumentException]::new('Unknown SQL inventory option.', 'Options')
            }
            if (-not $supplied.Add($field)) {
                throw [ArgumentException]::new('Specify each SQL inventory option once.', 'Options')
            }
            $values[$field] = $Options[$field]
        }

        $timeout = [int]$values.OperationTimeoutSeconds
        if ($timeout -lt 1 -or $timeout -gt 300) {
            throw [ArgumentOutOfRangeException]::new('OperationTimeoutSeconds')
        }
        $connection = [string]$values.DirectoryConnection
        if ($connection -notin @('PSDrive', 'Direct')) {
            throw [ArgumentException]::new('Specify PSDrive or Direct.', 'DirectoryConnection')
        }

        $pattern = [regex]::new([string]$values.Filter, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($field in @('SearchBase', 'Server')) {
            if ($supplied.Contains($field) -and $this.IsBlankTarget([string]$values[$field])) {
                throw ($field + ' cannot be empty.')
            }
        }
        return @{
            SearchBase = [string]$values.SearchBase
            Pattern = $pattern
            Server = [string]$values.Server
            Credential = [pscredential]$values.Credential
            DirectoryConnection = $connection
            OperationTimeoutSeconds = $timeout
        }
    }

    hidden [object[]] Discover([hashtable]$Request) {
        $repository = Split-Path -Parent $PSScriptRoot
        $providerPath = Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll'
        $modules = @(
            Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        )
        if ($modules.Count -ne 1) {
            throw 'The bundled Active Directory provider did not load once.'
        }
        $rootDse = $modules[0].ExportedCmdlets['Get-ADRootDSE']
        $computerQuery = $modules[0].ExportedCmdlets['Get-ADComputer']
        if ($rootDse -isnot [Management.Automation.CommandInfo] -or
            $computerQuery -isnot [Management.Automation.CommandInfo]) {
            throw 'The bundled Active Directory query commands are unavailable.'
        }

        $credential = $Request.Credential
        $bootstrap = $this.BootstrapArguments($Request.Server, $credential)
        $roots = @(& $rootDse @bootstrap)
        if ($roots.Count -ne 1) {
            throw 'RootDSE did not return one directory context.'
        }
        $pinnedServer = [string]$roots[0].DnsHostName
        $domainRoot = [string]$roots[0].DefaultNamingContext
        if ($this.IsBlankTarget($pinnedServer) -or $this.IsBlankTarget($domainRoot)) {
            throw 'RootDSE returned an incomplete DC or naming context.'
        }
        $query = $this.QueryArguments($Request.SearchBase, $domainRoot, $pinnedServer)
        $drive = $null
        $previousLocation = $null
        $failure = $null
        $computers = [Collections.Generic.List[object]]::new()
        $cleanupErrors = [Collections.Generic.List[object]]::new()
        try {
            if ($Request.DirectoryConnection -eq 'PSDrive') {
                $previousLocation = Get-Location
                $driveArguments = $this.DriveArguments($domainRoot, $pinnedServer, $credential)
                $drive = New-PSDrive @driveArguments
                if ($null -eq $drive -or $drive.Provider.Name -ne 'ActiveDirectory') {
                    throw 'The owned AD provider drive was not established.'
                }

                Set-Location -LiteralPath ($drive.Name + ':') -ErrorAction Stop
                $location = Get-Location
                if ($location.Drive.Name -ne $drive.Name -or $location.Provider.Name -ne 'ActiveDirectory') {
                    throw 'The owned AD drive is not the active directory context.'
                }
            }
            elseif ($bootstrap.ContainsKey('Credential')) {
                $query.Credential = $credential
            }

            $records = @(& $computerQuery @query)
            foreach ($record in $records) {
                if ($Request.Pattern.IsMatch([string]$record.OperatingSystem)) {
                    $name = [string]$record.Name
                    $target = if ($this.IsBlankTarget([string]$record.DNSHostName)) {
                        $name
                    }
                    else {
                        [string]$record.DNSHostName
                    }
                    if ($this.IsBlankTarget($name) -or $this.IsBlankTarget($target)) {
                        throw 'A selected server lacks a usable name.'
                    }
                    $computers.Add($this.ComputerRow($name, $target, [string]$record.OperatingSystem))
                }
            }
        }
        catch {
            $failure = $_
        }
        finally {
            if ($null -ne $drive) {
                try {
                    Set-Location -LiteralPath $previousLocation.Path -ErrorAction Stop
                }
                catch {
                    $cleanupErrors.Add($_)
                }
                try {
                    Remove-PSDrive -Name $drive.Name -Scope Local -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
                }
                catch {
                    $cleanupErrors.Add($_)
                }
            }
        }
        if ($null -ne $failure) {
            $this.RecordCleanup($failure, $cleanupErrors, 0)
            throw $failure
        }
        if ($cleanupErrors.Count) {
            $failure = $cleanupErrors[0]
            $this.RecordCleanup($failure, $cleanupErrors, 1)
            throw $failure
        }
        return $computers.ToArray()
    }

    hidden [void] ReadServices(
        [Collection]$Results,
        [object]$Computer,
        [int]$OperationTimeoutSeconds,
        [pscredential]$Credential
    ) {
        $session = $null
        $services = @()
        $hostFailure = $null
        $cleanupFailure = $null
        try {
            $sessionArguments = $this.SessionArguments($Computer.Target, $OperationTimeoutSeconds, $Credential)
            $session = New-CimSession @sessionArguments
            if ($null -eq $session -or $session -is [array]) {
                throw 'A single remote CIM session was not established.'
            }
            $serviceArguments = @{
                CimSession = $session
                ClassName = 'Win32_Service'
                Property = @('Name', 'DisplayName', 'State')
                OperationTimeoutSec = $OperationTimeoutSeconds
                ErrorAction = 'Stop'
            }
            $services = @(Get-CimInstance @serviceArguments | Where-Object { [string]$_.Name -match 'SQL' })
        }
        catch {
            $hostFailure = $_
        }
        finally {
            if ($null -ne $session) {
                try {
                    Remove-CimSession -CimSession $session -ErrorAction Stop
                }
                catch {
                    $cleanupFailure = $_
                }
            }
        }
        $messages = $this.HostMessages($hostFailure, $cleanupFailure)
        if ($null -ne $hostFailure) {
            $Results.Finding($Computer.Name, $false, $messages.Failed)
        }
        elseif ($services.Count) {
            foreach ($service in $services) {
                $Results.Finding(
                    $Computer.Name, [string]$service.Name, [string]$service.DisplayName,
                    [string]$service.State, $messages.Cleanup
                )
            }
        }
        else {
            $Results.Finding($Computer.Name, $true, $messages.Empty)
        }
    }

    hidden [bool] IsBlankTarget([string]$Value) {
        return [string]::IsNullOrWhiteSpace($Value)
    }

    hidden [bool] UsesCredential([pscredential]$Credential) {
        return $null -ne $Credential -and $Credential -ne [pscredential]::Empty
    }

    hidden [hashtable] BootstrapArguments([string]$Server, [pscredential]$Credential) {
        $arguments = @{
            ErrorAction = 'Stop'
        }
        if ($Server) {
            $arguments.Server = $Server
        }
        if ($this.UsesCredential($Credential)) {
            $arguments.Credential = $Credential
        }
        return $arguments
    }

    hidden [hashtable] QueryArguments([string]$SearchBase, [string]$DomainRoot, [string]$Server) {
        $base = if ($SearchBase) {
            $SearchBase
        }
        else {
            $DomainRoot
        }
        return @{
            Filter = 'Enabled -eq $true'
            Properties = @('Name', 'OperatingSystem', 'DNSHostName')
            SearchBase = $base
            Server = $Server
            ErrorAction = 'Stop'
        }
    }

    hidden [hashtable] DriveArguments([string]$DomainRoot, [string]$Server, [pscredential]$Credential) {
        $arguments = @{
            Name = 'ADAnalyzerSql' + [guid]::NewGuid().ToString('N')
            PSProvider = 'ActiveDirectory'
            Root = $DomainRoot
            Server = $Server
            Scope = 'Local'
            ErrorAction = 'Stop'
            WhatIf = $false
            Confirm = $false
        }
        if ($this.UsesCredential($Credential)) {
            $arguments.Credential = $Credential
        }
        return $arguments
    }

    hidden [object] ComputerRow([string]$Name, [string]$Target, [string]$OperatingSystem) {
        return [pscustomobject]@{
            Name = $Name
            Target = $Target
            OperatingSystem = $OperatingSystem
        }
    }

    hidden [hashtable] SessionArguments([string]$Target, [int]$Timeout, [pscredential]$Credential) {
        $arguments = @{
            ComputerName = $Target
            OperationTimeoutSec = $Timeout
            ErrorAction = 'Stop'
        }
        if ($this.UsesCredential($Credential)) {
            $arguments.Credential = $Credential
        }
        return $arguments
    }

    hidden [hashtable] HostMessages(
        [Management.Automation.ErrorRecord]$Failure,
        [Management.Automation.ErrorRecord]$Cleanup
    ) {
        $cleanupMessage = $null
        $failureMessage = $null
        $emptyMessage = 'No SQL-named services found.'
        if ($null -ne $Cleanup) {
            $cleanupMessage = 'CIM cleanup: ' + $Cleanup.Exception.GetType().FullName + ': ' + $Cleanup.Exception.Message
            $emptyMessage += '; ' + $cleanupMessage
        }
        if ($null -ne $Failure) {
            $failureMessage = $Failure.Exception.GetType().FullName + ': ' + $Failure.Exception.Message
            if ($cleanupMessage) {
                $failureMessage += '; ' + $cleanupMessage
            }
        }
        return @{
            Cleanup = $cleanupMessage
            Failed = $failureMessage
            Empty = $emptyMessage
        }
    }

    hidden [void] RecordCleanup(
        [Management.Automation.ErrorRecord]$Primary,
        [Collections.Generic.List[object]]$Errors,
        [int]$Start
    ) {
        if ($Start -lt $Errors.Count) {
            $messages = [Collections.Generic.List[object]]::new()
            for ($index = $Start; $index -lt $Errors.Count; $index++) {
                $messages.Add($Errors[$index].Exception.Message)
            }
            $Primary.Exception.Data['ADAnalyzerCleanupErrors'] = $messages.ToArray()
        }
    }
}

function Get-ADMSSQLServers {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$SearchBase,
        [string]$Filter = 'Windows Server',
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [ValidateSet('PSDrive', 'Direct')][string]$DirectoryConnection = 'PSDrive',
        [ValidateRange(1, 300)][int]$OperationTimeoutSeconds = 30,
        [string]$OutputPath

    )
    $ErrorActionPreference = 'Stop'
    $inventory = [ADAnalyzerSqlServiceInventory]::new()
    $osPattern = [regex]::new($Filter, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($field in @('SearchBase', 'Server')) {
        if ($PSBoundParameters.ContainsKey($field) -and [string]::IsNullOrWhiteSpace([string](Get-Variable $field -ValueOnly))) {
            throw ($field + ' cannot be empty.')
        }
    }
    $repository = Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $bootstrap = $inventory.BootstrapArguments($Server, $Credential)
    $roots = @(Get-ADRootDSE @bootstrap)
    if ($roots.Count -ne 1) {
        throw 'RootDSE did not return one directory context.'
    }
    $pinnedServer = [string]$roots[0].DnsHostName
    $domainRoot = [string]$roots[0].DefaultNamingContext
    if ([string]::IsNullOrWhiteSpace($pinnedServer) -or [string]::IsNullOrWhiteSpace($domainRoot)) {
        throw 'RootDSE returned an incomplete DC or naming context.'
    }
    $query = $inventory.QueryArguments($SearchBase, $domainRoot, $pinnedServer)
    $drive = $null
    $previousLocation = $null
    $failure = $null
    $computers = @()
    $cleanupErrors = [Collections.Generic.List[object]]::new()
    try {
        if ($DirectoryConnection -eq 'PSDrive') {
            $previousLocation = Get-Location
            $driveArguments = $inventory.DriveArguments($domainRoot, $pinnedServer, $Credential)
            $drive = New-PSDrive @driveArguments
            if ($null -eq $drive -or $drive.Provider.Name -ne 'ActiveDirectory') {
                throw 'The owned AD provider drive was not established.'
            }
            Set-Location -LiteralPath ($drive.Name + ':') -ErrorAction Stop
            $location = Get-Location
            if ($location.Drive.Name -ne $drive.Name -or $location.Provider.Name -ne 'ActiveDirectory') {
                throw 'The owned AD drive is not the active directory context.'
            }
        }
        elseif ($bootstrap.ContainsKey('Credential')) {
            $query.Credential = $Credential
        }
        $records = @(Get-ADComputer @query)
        $computers = @(foreach ($record in $records) {
                if ($osPattern.IsMatch([string]$record.OperatingSystem)) {
                    $computerName = [string]$record.Name
                    $remoteName = if ([string]::IsNullOrWhiteSpace([string]$record.DNSHostName)) {
                        $computerName
                    }
                    else {
                        [string]$record.DNSHostName
                    }
                    if ([string]::IsNullOrWhiteSpace($computerName) -or [string]::IsNullOrWhiteSpace($remoteName)) {
                        throw 'A selected server lacks a usable name.'
                    }
                    $inventory.ComputerRow($computerName, $remoteName, [string]$record.OperatingSystem)
                }
            })
        $records = $null
    }
    catch {
        $failure = $_
    }
    finally {
        if ($null -ne $drive) {
            try {
                Set-Location -LiteralPath $previousLocation.Path -ErrorAction Stop
            }
            catch {
                $cleanupErrors.Add($_)
            }
            try {
                Remove-PSDrive -Name $drive.Name -Scope Local -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
            }
            catch {
                $cleanupErrors.Add($_)
            }
        }
    }
    if ($null -ne $failure) {
        if ($cleanupErrors.Count) {
            $failure.Exception.Data['ADAnalyzerCleanupErrors'] = @($cleanupErrors | ForEach-Object { $_.Exception.Message })
        }
        throw $failure
    }
    if ($cleanupErrors.Count) {
        $errorRecord = $cleanupErrors[0]
        if ($cleanupErrors.Count -gt 1) {
            $errorRecord.Exception.Data['ADAnalyzerCleanupErrors'] = @($cleanupErrors | Select-Object `
                    -Skip 1 | ForEach-Object { $_.Exception.Message })
        }
        throw $errorRecord
    }
    $result = [Collection]::new()
    foreach ($computer in $computers) {
        $session = $null
        $services = @()
        $hostFailure = $null
        $cleanupFailure = $null
        try {
            $sessionArguments = $inventory.SessionArguments($computer.Target, $OperationTimeoutSeconds, $Credential)
            $session = New-CimSession @sessionArguments
            if ($null -eq $session -or $session -is [array]) {
                throw 'A single remote CIM session was not established.'
            }
            $services = @(Get-CimInstance `
                    -CimSession $session `
                    -ClassName Win32_Service `
                    -Property Name,
                DisplayName,
                State `
                    -OperationTimeoutSec $OperationTimeoutSeconds `
                    -ErrorAction Stop | Where-Object { [string]$_.Name -match 'SQL' })
        }
        catch {
            $hostFailure = $_
        }
        finally {
            if ($null -ne $session) {
                try {
                    Remove-CimSession -CimSession $session -ErrorAction Stop
                }
                catch {
                    $cleanupFailure = $_
                }
            }
        }
        $messages = $inventory.HostMessages($hostFailure, $cleanupFailure)
        if ($null -ne $hostFailure) {
            $result.Finding($computer.Name, $false, $messages.Failed)
        }
        elseif ($services.Count) {
            foreach ($service in $services) {
                $result.Finding($computer.Name,
                    [string]$service.Name,
                    [string]$service.DisplayName,
                    [string]$service.State,
                    $messages.Cleanup)
            }
        }
        else {
            $result.Finding($computer.Name, $true, $messages.Empty)
        }
    }
    if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Export SQL service inventory')) {
        $result.Export($OutputPath)
    }
    return , $result
}

if ($MyInvocation.InvocationName -ne '.') {
    if ([string]::IsNullOrWhiteSpace($CliSearchBase) -and [string]::IsNullOrWhiteSpace($CliServer)) {
        throw 'Specify SearchBase or Server for directory discovery.'
    }
    $arguments = @{
        Filter = $CliFilter
        Credential = $CliCredential
        DirectoryConnection = $CliDirectoryConnection
        OperationTimeoutSeconds = $CliOperationTimeoutSeconds
        WhatIf = [bool]$WhatIfPreference
    }
    foreach ($field in @('SearchBase', 'Server', 'OutputPath')) {
        if ($PSBoundParameters.ContainsKey('Cli' + $field)) {
            $arguments[$field] = Get-Variable ('Cli' + $field) -ValueOnly
        }
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $arguments.Confirm = $PSBoundParameters.Confirm
    }
    Get-ADMSSQLServers @arguments
}
