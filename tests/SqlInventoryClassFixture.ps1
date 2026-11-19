[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Construction', 'Validation', 'Discovery', 'Inventory', 'Failures')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:Passed = 0
$script:Unexpected = 0
$script:Enabled = $false
$script:Trace = [Collections.Generic.List[string]]::new()
$script:Dll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Bootstrap = 'alias.fixture.invalid'
$script:Pinned = 'dc.fixture.invalid'
$script:Domain = 'DC=fixture,DC=invalid'
$script:Search = 'OU=Servers,DC=fixture,DC=invalid'
$script:Credential = [pscredential]::new('FIXTURE\sql-inventory', [Security.SecureString]::new())
$script:DriveName = $null
$script:Session = $null
$script:Fault = ''
$script:Selection = 'Many'
$script:Header = 'computer.Name,computer.Status,service.Name,service.DisplayName,service.Status,computer.Message'

function Assert-SqlClass($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-SqlClass([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('Failed SQL inventory class fixture: ' + $Name)
        throw
    }
}

function Stop-SqlClassExternal {
    $script:Unexpected++
    throw 'Unexpected live, ambient or premature dependency call'
}

function Get-SqlClassFailure([scriptblock]$Body, [string]$Pattern = '.+') {
    $rows = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-SqlClass ($null -ne $failure -and $rows.Count -eq 0 -and $failure.Exception.Message -match $Pattern) (
        'Expected a terminal failure with no results: ' + $Pattern
    )
    return $failure
}

function Reset-SqlClass([string]$Route = 'PSDrive', [bool]$Explicit = $false, [string]$Fault = '', [string]$Selection = 'Many') {
    $script:Trace.Clear()
    $script:Route = $Route
    $script:Fault = $Fault
    $script:Selection = $Selection
    $script:UseCredential = $Explicit
    $script:ExpectedBootstrap = $null
    $script:ExpectedSearch = $script:Domain
    $script:ExpectedTimeout = 30
    if ($Explicit) {
        $script:ExpectedBootstrap = $script:Bootstrap
        $script:ExpectedSearch = $script:Search
        $script:ExpectedTimeout = 17
    }
}

function Assert-SqlClassCredential($Bound, [bool]$Expected) {
    Assert-SqlClass ($Bound.ContainsKey('Credential') -eq $Expected) 'Credential binding presence changed'
    if ($Expected) {
        Assert-SqlClass ([object]::ReferenceEquals($Bound['Credential'], $script:Credential)) 'Credential identity changed'
    }
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru, [switch]$Global)

    if (-not $script:Enabled) {
        Stop-SqlClassExternal
    }
    Assert-SqlClass ($Name -ceq $script:Dll -and [IO.Path]::IsPathRooted($Name) -and
        $Scope -ceq 'Local' -and $PassThru -and -not $Global -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'The exact local bundled DLL request changed'
    $script:Trace.Add('Import')
    $commands = @{
        'Get-ADRootDSE' = Get-Command Invoke-SqlClassRoot -CommandType Function
        'Get-ADComputer' = Get-Command Invoke-SqlClassComputer -CommandType Function
    }
    $exports = $commands.Clone()
    if ($script:Fault -eq 'MissingRoot') {
        $exports.Remove('Get-ADRootDSE')
    }
    if ($script:Fault -eq 'BadComputer') {
        $exports['Get-ADComputer'] = 'Invoke-SqlClassComputer'
    }
    $provider = [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $exports
        ExportedCommands = $commands
    }
    $provider
    if ($script:Fault -eq 'MultipleModules') {
        $provider
    }
}

function Get-ADRootDSE { Stop-SqlClassExternal }
function Get-ADComputer { Stop-SqlClassExternal }
function Get-Service { Stop-SqlClassExternal }
function Get-ADMSSQLServers { Stop-SqlClassExternal }
function Invoke-Command { Stop-SqlClassExternal }

function Invoke-SqlClassRoot {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    if (-not $script:Enabled) {
        Stop-SqlClassExternal
    }
    $script:Trace.Add('Root')
    Assert-SqlClass ($PSBoundParameters['ErrorAction'] -eq 'Stop' -and
        $PSBoundParameters.ContainsKey('Server') -eq [bool]$script:ExpectedBootstrap -and
        $PSBoundParameters['Server'] -ceq $script:ExpectedBootstrap) 'Bootstrap server/default binding changed'
    Assert-SqlClassCredential $PSBoundParameters $script:UseCredential
    if ($script:Fault -eq 'EmptyRoot') {
        return
    }
    [pscustomobject]@{
        DnsHostName = $script:Pinned
        DefaultNamingContext = $script:Domain
    }
}

function New-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [string]$PSProvider, [string]$Root, [string]$Server, [string]$Scope,
        [pscredential]$Credential, [switch]$WhatIf, [switch]$Confirm)

    if (-not $script:Enabled -or $script:Route -ne 'PSDrive') {
        Stop-SqlClassExternal
    }
    Assert-SqlClass ($null -eq $script:DriveName -and $Name -cmatch '^ADAnalyzerSql[0-9a-f]{32}$' -and
        $PSProvider -ceq 'ActiveDirectory' -and $Root -ceq $script:Domain -and $Server -ceq $script:Pinned -and
        $Scope -ceq 'Local' -and $PSBoundParameters['ErrorAction'] -eq 'Stop' -and -not $WhatIf -and -not $Confirm) (
        'Invalid selected-controller drive request'
    )
    Assert-SqlClassCredential $PSBoundParameters $script:UseCredential
    $surrogate = @{
        Name = $Name
        PSProvider = 'FileSystem'
        Root = $script:OwnedRoot
        Scope = '1'
        ErrorAction = 'Stop'
        WhatIf = $false
        Confirm = $false
    }
    $actual = Microsoft.PowerShell.Management\New-PSDrive @surrogate
    $script:DriveName = $actual.Name
    $script:LastDrive = $actual.Name
    $script:Trace.Add('Drive')
    [pscustomobject]@{
        Name = $actual.Name
        Provider = [pscustomobject]@{ Name = 'ActiveDirectory' }
    }
}

function Get-Location {
    if (-not $script:Enabled -or $script:Route -ne 'PSDrive') {
        Stop-SqlClassExternal
    }
    $script:Trace.Add('GetLocation')
    $location = Microsoft.PowerShell.Management\Get-Location
    if ($script:DriveName -and $location.Drive.Name -ceq $script:DriveName) {
        return [pscustomobject]@{
            Path = $location.Path
            Drive = $location.Drive
            Provider = [pscustomobject]@{ Name = 'ActiveDirectory' }
        }
    }
    return $location
}

function Set-Location {
    [CmdletBinding()]
    param([string]$LiteralPath)

    if (-not $script:Enabled -or $script:Route -ne 'PSDrive') {
        Stop-SqlClassExternal
    }
    $enter = $LiteralPath -ceq ($script:DriveName + ':')
    Assert-SqlClass (($enter -or $LiteralPath -ceq $script:BorrowedPath) -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Directory location escaped the owned and caller drives'
    Microsoft.PowerShell.Management\Set-Location @PSBoundParameters
    if ($enter) {
        $script:Trace.Add('Enter')
    }
    else {
        $script:Trace.Add('Restore')
        if ($script:Fault -eq 'DiscoveryCleanup') {
            throw 'Fixture borrowed location restore fault'
        }
    }
}

function Remove-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)

    if (-not $script:Enabled -or $script:Route -ne 'PSDrive') {
        Stop-SqlClassExternal
    }
    Assert-SqlClass ($Name -ceq $script:DriveName -and $Scope -ceq 'Local' -and
        $Force -and -not $WhatIf -and -not $Confirm -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Wrong drive cleanup'
    $actual = Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -Scope '1' -ErrorAction Stop
    Assert-SqlClass ($actual.Root -ceq $script:OwnedRoot -and $actual.Provider.Name -ceq 'FileSystem') 'The drive did not survive in its real owner scope'
    Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Scope '1' -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
    $script:DriveName = $null
    $script:Trace.Add('RemoveDrive')
    if ($script:Fault -in 'RemoveDrive', 'DiscoveryCleanup') {
        throw 'Fixture owned drive removal fault'
    }
}

function Invoke-SqlClassComputer {
    [CmdletBinding()]
    param([string]$Filter, [string[]]$Properties, [string]$SearchBase, [string]$Server, [pscredential]$Credential)

    $script:Trace.Add('Computer')
    Assert-SqlClass ($PSBoundParameters['ErrorAction'] -eq 'Stop' -and $Filter -ceq 'Enabled -eq $true' -and
        ($Properties -join ',') -ceq 'Name,OperatingSystem,DNSHostName' -and
        $SearchBase -ceq $script:ExpectedSearch -and $Server -ceq $script:Pinned) 'Pinned directory query changed'
    Assert-SqlClassCredential $PSBoundParameters ($script:Route -eq 'Direct' -and $script:UseCredential)
    $location = Microsoft.PowerShell.Management\Get-Location
    if ($script:Route -eq 'PSDrive') {
        Assert-SqlClass ($location.Drive.Name -ceq $script:DriveName -and
            [IO.File]::ReadAllText((Join-Path $location.ProviderPath 'scope-witness')) -ceq 'fixture-owned-drive') (
            'Packaged command did not execute in the actual temporary drive'
        )
    }
    else {
        Assert-SqlClass ($location.Path -ceq $script:BorrowedPath -and $null -eq $script:DriveName) 'Direct query changed the caller location'
    }
    if ($script:Fault -eq 'DiscoveryCleanup') {
        throw 'Fixture discovery fault'
    }
    if ($script:Selection -eq 'None') {
        return
    }
    [pscustomobject]@{
        Name = 'sql-one'
        DNSHostName = 'sql-one.fixture.invalid'
        OperatingSystem = 'Windows Server 2022'
    }
    if ($script:Selection -ne 'One') {
        [pscustomobject]@{
            Name = 'empty-two'
            DNSHostName = ''
            OperatingSystem = 'Windows Server 2019'
        }
        [pscustomobject]@{
            Name = 'linux-three'
            DNSHostName = 'linux-three.fixture.invalid'
            OperatingSystem = 'Linux'
        }
    }
}

function New-CimSession {
    [CmdletBinding()]
    param([string]$ComputerName, [int]$OperationTimeoutSec, [pscredential]$Credential)

    if (-not $script:Enabled) {
        Stop-SqlClassExternal
    }
    Assert-SqlClass ($null -eq $script:DriveName -and $null -eq $script:Session -and
        (Microsoft.PowerShell.Management\Get-Location).Path -ceq $script:BorrowedPath -and
        $ComputerName -in 'sql-one.fixture.invalid', 'empty-two', 'linux-three.fixture.invalid' -and
        $OperationTimeoutSec -eq $script:ExpectedTimeout -and $PSBoundParameters['ErrorAction'] -eq 'Stop') (
        'CIM session opened before directory cleanup or changed target/timeout'
    )
    Assert-SqlClassCredential $PSBoundParameters $script:UseCredential
    $script:Trace.Add('Session:' + $ComputerName)
    $script:Session = [pscustomobject]@{
        ComputerName = $ComputerName
    }
    return $script:Session
}

function New-SqlClassService([string]$State) {
    $service = [pscustomobject]@{
        Name = 'MSSQL' + $State
        Display = 'SQL ' + [char]0x00FC + ', "quoted" ' + $State
        FixtureState = $State
    }
    $service | Add-Member -MemberType ScriptProperty -Name DisplayName -Value {
        if ($null -ne $script:Session) {
            Stop-SqlClassExternal
        }
        $script:Trace.Add('Project:' + $this.FixtureState)
        return $this.Display
    }
    $service | Add-Member -MemberType ScriptProperty -Name State -Value {
        if ($null -ne $script:Session) {
            Stop-SqlClassExternal
        }
        return $this.FixtureState
    }
    return $service
}

function Get-CimInstance {
    [CmdletBinding()]
    param([object]$CimSession, [string]$ClassName, [string[]]$Property, [int]$OperationTimeoutSec)

    Assert-SqlClass ($null -ne $script:Session -and [object]::ReferenceEquals($CimSession, $script:Session) -and
        $ClassName -ceq 'Win32_Service' -and ($Property -join ',') -ceq 'Name,DisplayName,State' -and
        $OperationTimeoutSec -eq $script:ExpectedTimeout -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'CIM query escaped its owned session'
    $target = $CimSession.ComputerName
    $script:Trace.Add('Query:' + $target)
    if ($target -ne 'sql-one.fixture.invalid') {
        [pscustomobject]@{
            Name = 'Other'
            DisplayName = 'Unselected service'
            State = 'Running'
        }
        return
    }
    if ($script:Fault -eq 'QueryCleanup') {
        New-SqlClassService 'Partial'
        throw 'Fixture CIM partial query fault'
    }
    New-SqlClassService 'Running'
    if ($script:Selection -ne 'One') {
        New-SqlClassService 'Stopped'
        New-SqlClassService 'Paused'
    }
}

function Remove-CimSession {
    [CmdletBinding()]
    param([object]$CimSession)

    Assert-SqlClass ($null -ne $script:Session -and [object]::ReferenceEquals($CimSession, $script:Session) -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Cleanup attempted to dispose a foreign session'
    $target = $CimSession.ComputerName
    $script:Trace.Add('RemoveSession:' + $target)
    $script:Session = $null
    if ($target -eq 'sql-one.fixture.invalid' -and $script:Fault -in 'QueryCleanup', 'Cleanup') {
        throw 'Fixture CIM cleanup fault'
    }
}

function Assert-SqlClassRestored {
    Assert-SqlClass ($null -eq $script:Session -and $null -eq $script:DriveName -and
        (Microsoft.PowerShell.Management\Get-Location).Path -ceq $script:BorrowedPath -and
        (Microsoft.PowerShell.Management\Get-PSDrive -Name $script:BorrowedName -ErrorAction Stop).Root -ceq $script:BorrowedRoot) (
        'Original caller location or borrowed drive changed'
    )
    if ($script:LastDrive) {
        $names = @(Microsoft.PowerShell.Management\Get-PSDrive | ForEach-Object Name)
        Assert-SqlClass ($script:LastDrive -notin $names) 'Owned temporary drive leaked into the caller'
    }
}

function Assert-SqlClassCollection($Result, [int]$Expected) {
    Assert-SqlClass ($null -ne $Result -and $Result.GetType().Name -ceq 'Collection' -and
        $Result.Count -eq $Expected -and $null -ne $Result.PSObject.Methods['Export']) 'Read replaced or unwrapped the Collection'
    foreach ($row in $Result) {
        Assert-SqlClass (($row.PSObject.Properties.Name -join ',') -ceq $script:Header) 'Ordered six-column row schema changed'
    }
}

function Get-SqlClassExplicitOptions([string]$Route = 'PSDrive') {
    @{
        Server = $script:Bootstrap
        SearchBase = $script:Search
        Credential = $script:Credential
        OperationTimeoutSeconds = 17
        DirectoryConnection = $Route
    }
}

function Invoke-SqlClassConstructionCases {
    Test-SqlClass 'literal via the real standalone entrypoint has no startup work' {
        Assert-SqlClass ($startup.Count -eq 0 -and $owner.GetType().Name -ceq 'ADAnalyzerSqlServiceInventory' -and
            (Microsoft.PowerShell.Management\Get-Location).Path -ceq $script:BorrowedPath -and
            $script:Trace.Count -eq 0 -and [IO.Directory]::GetFiles($script:BorrowedRoot).Count -eq 0) (
            'Load or construction performed I/O'
        )
    }
    Test-SqlClass 'detached local scope releases its real temporary drive' {
        $ephemeral = & {
            $name = 'SqlPriorScope' + [guid]::NewGuid().ToString('N')
            $drive = Microsoft.PowerShell.Management\New-PSDrive -Name $name -PSProvider FileSystem -Root $script:OwnedRoot
            Assert-SqlClass ([IO.File]::ReadAllText((Join-Path $drive.Root 'scope-witness')) -ceq 'fixture-owned-drive') 'Local drive negative control did not mount'
            $drive.Name
        }
        $names = @(Microsoft.PowerShell.Management\Get-PSDrive | ForEach-Object Name)
        Assert-SqlClass ($ephemeral -notin $names) 'Local drive fixture failed to distinguish an operation-local scope'
        Assert-SqlClassRestored
    }
}

function Invoke-SqlClassValidationCases {
    Test-SqlClass 'invalid regex precedes explicit blank discovery validation' {
        $failure = Get-SqlClassFailure {
            $owner.Read(@{
                Filter = '['
                Server = ' '
            })
        }
        Assert-SqlClass ($failure.Exception.GetBaseException() -is [ArgumentException] -and
            $failure.Exception.ToString() -notmatch 'Server cannot be empty') 'Invalid regex handling changed'
    }
    Test-SqlClass 'bound blank server and search base fail before dependencies' {
        foreach ($field in 'Server', 'SearchBase') {
            foreach ($value in '', ' ', $null) {
                $options = @{}
                $options[$field] = $value
                $null = Get-SqlClassFailure { $owner.Read($options) } ($field + ' cannot be empty')
            }
        }
        $caseSensitive = [hashtable]::new([StringComparer]::Ordinal)
        $caseSensitive.Add('server', ' ')
        $null = Get-SqlClassFailure { $owner.Read($caseSensitive) } 'Server cannot be empty'
    }
    Test-SqlClass 'unknown keys cannot shadow option validation' {
        foreach ($field in 'OutputPath', 'Keys') {
            $options = @{}
            $options[$field] = 'unsupported fixture'
            $null = Get-SqlClassFailure { $owner.Read($options) }
        }
        $caseSensitive = [hashtable]::new([StringComparer]::Ordinal)
        $caseSensitive.Add('Server', $script:Bootstrap)
        $caseSensitive.Add('server', $script:Pinned)
        $null = Get-SqlClassFailure { $owner.Read($caseSensitive) } '(?i)Specify each SQL inventory option once'
    }
    Test-SqlClass 'range and unsupported transport reject before any work' {
        foreach ($value in 0, 301) {
            $null = Get-SqlClassFailure { $owner.Read(@{ OperationTimeoutSeconds = $value }) }
        }
        $null = Get-SqlClassFailure { $owner.Read(@{ DirectoryConnection = 'Other' }) }
    }
    Assert-SqlClass ($script:Trace.Count -eq 0 -and $script:Unexpected -eq 0) 'Rejected options reached an external seam'
}

function Invoke-SqlClassDiscoveryCases {
    $script:Enabled = $true
    $drivePrefix = 'Import|Root|GetLocation|Drive|Enter|GetLocation|Computer|Restore|RemoveDrive'
    Test-SqlClass 'ambient Read uses a genuine operation-local drive and restores the borrowed drive' {
        Reset-SqlClass
        $result = $owner.Read()
        Assert-SqlClassCollection $result 4
        Assert-SqlClass (($script:Trace -join '|').StartsWith($drivePrefix + '|Session:', [StringComparison]::Ordinal) -and
            $script:Trace.Contains('Session:empty-two') -and -not $script:Trace.Contains('Session:linux-three.fixture.invalid')) (
            'Default discovery, DNS fallback or host probe order changed'
        )
        Assert-SqlClassRestored
    }
    Test-SqlClass 'explicit credentials pin the owned drive and CIM to the selected scope' {
        Reset-SqlClass -Explicit $true
        $options = Get-SqlClassExplicitOptions
        $result = $owner.Read($options)
        Assert-SqlClassCollection $result 4
        Assert-SqlClass (($script:Trace -join '|').StartsWith($drivePrefix + '|Session:', [StringComparison]::Ordinal) -and
            $options.Count -eq 5 -and $options.Server -ceq $script:Bootstrap -and $options.SearchBase -ceq $script:Search -and
            $options.OperationTimeoutSeconds -eq 17 -and $options.DirectoryConnection -ceq 'PSDrive' -and
            [object]::ReferenceEquals($options.Credential, $script:Credential)) 'Discovery mutated the supplied connection settings'
        Assert-SqlClassRestored
    }
    Test-SqlClass 'explicit direct pins compute queries and has no location or drive effects' {
        Reset-SqlClass -Route Direct -Explicit $true
        $options = [hashtable]::new([StringComparer]::Ordinal)
        $supplied = Get-SqlClassExplicitOptions 'dIrEcT'
        foreach ($key in $supplied.Keys) {
            $options.Add($key.ToLowerInvariant(), $supplied[$key])
        }
        $result = $owner.Read($options)
        Assert-SqlClassCollection $result 4
        Assert-SqlClass (($script:Trace -join '|').StartsWith('Import|Root|Computer|Session:', [StringComparison]::Ordinal) -and
            'Drive' -notin $script:Trace -and 'GetLocation' -notin $script:Trace -and 'RemoveDrive' -notin $script:Trace) (
            'Direct acquired a location or changed discovery order'
        )
        Assert-SqlClassRestored
    }
}

function Invoke-SqlClassInventoryCases {
    $script:Enabled = $true
    Test-SqlClass 'many rows preserve order, literal states and projection after session removal' {
        Reset-SqlClass -Route Direct
        $result = $owner.Read(@{ DirectoryConnection = 'Direct' })
        Assert-SqlClassCollection $result 4
        Assert-SqlClass (($result.'computer.Name' -join '|') -ceq 'sql-one|sql-one|sql-one|empty-two' -and
            ($result.'service.Status' -join '|') -ceq 'Running|Stopped|Paused|' -and
            @($result | Where-Object { $_.'computer.Status' -isnot [bool] -or -not $_.'computer.Status' }).Count -eq 0 -and
            $null -eq $result[3].'service.Name' -and $result[3].'computer.Message' -ceq 'No SQL-named services found.') (
            'Many result rows lost schema or meaning'
        )
        $tail = @($script:Trace | Select-Object -Skip 3) -join '|'
        $expected = 'Session:sql-one.fixture.invalid|Query:sql-one.fixture.invalid|RemoveSession:sql-one.fixture.invalid|Project:Running|Project:Stopped|Project:Paused|Session:empty-two|Query:empty-two|RemoveSession:empty-two'
        Assert-SqlClass ($tail -ceq $expected) 'Detached service fields were observed before removing the original session'
    }
    Test-SqlClass 'empty and singleton remain single Collections and export literal CSV explicitly' {
        $output = Join-Path $script:Temporary 'reports [explicit]/services [saved].csv'
        Reset-SqlClass -Selection None
        $empty = $owner.Read($null)
        Assert-SqlClassCollection $empty 0
        Assert-SqlClass (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($output))) 'Read wrote a report or folder before Export'
        $empty.Export($output)
        Assert-SqlClass (@(Import-Csv -LiteralPath $output).Count -eq 0 -and
            [IO.File]::ReadAllText($output).Trim() -ceq ('"' + $script:Header.Replace(',', '","') + '"')) 'Empty CSV lost its schema'
        Reset-SqlClass -Route Direct -Selection One
        $one = $owner.Read(@{ DirectoryConnection = 'Direct' })
        Assert-SqlClassCollection $one 1
        $one.Export($output)
        $csv = @(Import-Csv -LiteralPath $output)
        Assert-SqlClass ($csv.Count -eq 1 -and $csv[0].'service.DisplayName' -ceq ('SQL ' + [char]0x00FC + ', "quoted" Running') -and
            $csv[0].'service.Status' -ceq 'Running') 'Literal overwrite lost the only row or CSV escaping'
        Assert-SqlClassRestored
    }
    Test-SqlClass 'explicit empty OS filter includes all and keeps an empty credential omitted' {
        Reset-SqlClass -Route Direct
        $result = $owner.Read(@{
                DirectoryConnection = 'Direct'
                Credential = [pscredential]::Empty
                Filter = ''
            })
        Assert-SqlClassCollection $result 5
        Assert-SqlClass ($result[4].'computer.Name' -ceq 'linux-three' -and
            $script:Trace.Contains('Session:linux-three.fixture.invalid')) 'Explicit empty regex was replaced by the default selection'
        Assert-SqlClassRestored
    }
    Test-SqlClass 'reused and independent inventories do not retain caller options or mutable rows' {
        Reset-SqlClass -Route Direct -Explicit $true
        $configured = $owner.Read((Get-SqlClassExplicitOptions Direct))
        $configured[0].'service.Name' = 'changed result only'
        $other = [ADAnalyzerSqlServiceInventory]::new()
        foreach ($instance in $owner, $other) {
            Reset-SqlClass -Route Direct
            $next = $instance.Read(@{ DirectoryConnection = 'Direct' })
            Assert-SqlClassCollection $next 4
            Assert-SqlClass ($next[0].'service.Name' -ceq 'MSSQLRunning' -and
                [Management.Automation.PSSerializer]::Serialize($instance) -cnotmatch 'PSCredential|fixture.invalid|changed result only') (
                'Instance retained credentials, selected state or changes to previous rows'
            )
        }
        Assert-SqlClassRestored
    }
}

function Invoke-SqlClassFailureCases {
    $script:Enabled = $true
    Test-SqlClass 'missing or malformed packaged export never falls back to ambient queries' {
        foreach ($fault in 'MissingRoot', 'BadComputer', 'MultipleModules') {
            Reset-SqlClass -Route Direct -Fault $fault
            $null = Get-SqlClassFailure { $owner.Read(@{ DirectoryConnection = 'Direct' }) } '(?i)bundled'
            Assert-SqlClass (($script:Trace -join '|') -ceq 'Import') 'Provider rejection reached directory work'
        }
        Reset-SqlClass -Route Direct -Fault EmptyRoot
        $null = Get-SqlClassFailure { $owner.Read(@{ DirectoryConnection = 'Direct' }) } '(?i)one directory context'
        Assert-SqlClass (($script:Trace -join '|') -ceq 'Import|Root') 'RootDSE rejection reached discovery'
    }
    Test-SqlClass 'discovery keeps both cleanup observations and stops before CIM output' {
        Reset-SqlClass -Fault DiscoveryCleanup
        $failure = Get-SqlClassFailure { $owner.Read() } 'Fixture discovery fault'
        $messages = @()
        $exception = $failure.Exception
        while ($null -ne $exception) {
            if ($exception.Data.Contains('ADAnalyzerCleanupErrors')) {
                $messages = @($exception.Data['ADAnalyzerCleanupErrors'])
                break
            }
            $exception = $exception.InnerException
        }
        Assert-SqlClass ($messages.Count -eq 2 -and $messages[0] -match 'restore fault' -and $messages[1] -match 'removal fault' -and
            ($script:Trace -join '|') -ceq 'Import|Root|GetLocation|Drive|Enter|GetLocation|Computer|Restore|RemoveDrive') (
            'Discovery failure displaced primary cause, lost cleanup order or crossed into host effects'
        )
        Assert-SqlClassRestored
        Reset-SqlClass -Fault RemoveDrive
        $null = Get-SqlClassFailure { $owner.Read() } 'Fixture owned drive removal fault'
        Assert-SqlClass (@($script:Trace | Where-Object { $_ -like 'Session:*' }).Count -eq 0) 'Cleanup-only discovery failure reached host work'
        Assert-SqlClassRestored
    }
    Test-SqlClass 'partial query and cleanup faults return one failed host plus later hosts' {
        Reset-SqlClass -Route Direct -Fault QueryCleanup
        $result = $owner.Read(@{ DirectoryConnection = 'Direct' })
        Assert-SqlClassCollection $result 2
        $message = $result[0].'computer.Message'
        Assert-SqlClass ($result[0].'computer.Status' -is [bool] -and -not $result[0].'computer.Status' -and
            $null -eq $result[0].'service.Name' -and $message -match 'partial query fault.*CIM cleanup:.*cleanup fault' -and
            $result[1].'computer.Name' -ceq 'empty-two' -and $result[1].'computer.Status' -eq $true -and
            'RemoveSession:sql-one.fixture.invalid' -in $script:Trace -and 'RemoveSession:empty-two' -in $script:Trace) (
            'Partial query delivered service success or lost cleanup and subsequent host'
        )
        Assert-SqlClassRestored
    }
    Test-SqlClass 'cleanup-only host failure retains successful service states and later hosts' {
        Reset-SqlClass -Route Direct -Fault Cleanup
        $result = $owner.Read(@{ DirectoryConnection = 'Direct' })
        Assert-SqlClassCollection $result 4
        Assert-SqlClass (@($result | Where-Object { $_.'computer.Status' -eq $true -and
                    $_.'service.Status' -in 'Running', 'Stopped', 'Paused' -and $_.'computer.Message' -match 'CIM cleanup:.*cleanup fault' }).Count -eq 3 -and
            $result[3].'computer.Name' -ceq 'empty-two') 'Cleanup-only fault erased observed SQL states or subsequent host'
        Assert-SqlClassRestored
    }
}

$initialLocation = (Microsoft.PowerShell.Management\Get-Location).Path
$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-sql-inventory-' + [guid]::NewGuid().ToString('N'))
$script:BorrowedRoot = Join-Path $script:Temporary 'borrowed'
$script:OwnedRoot = Join-Path $script:Temporary 'owned'
$null = [IO.Directory]::CreateDirectory($script:BorrowedRoot)
$null = [IO.Directory]::CreateDirectory($script:OwnedRoot)
[IO.File]::WriteAllText((Join-Path $script:OwnedRoot 'scope-witness'), 'fixture-owned-drive')
$script:BorrowedName = 'SqlCaller' + [guid]::NewGuid().ToString('N')
$borrowed = $null
try {
    $borrowed = Microsoft.PowerShell.Management\New-PSDrive -Name $script:BorrowedName -PSProvider FileSystem -Root $script:BorrowedRoot
    Microsoft.PowerShell.Management\Set-Location -LiteralPath ($script:BorrowedName + ':')
    $script:BorrowedPath = (Microsoft.PowerShell.Management\Get-Location).Path
    $startup = @(. (Join-Path $RepositoryRoot 'etc/Get-MSSQLServers.ps1'))
    $owner = [ADAnalyzerSqlServiceInventory]::new()
    Assert-SqlClass ($startup.Count -eq 0 -and $script:Trace.Count -eq 0 -and $script:Unexpected -eq 0) 'Standalone entry or constructor entered a dependency seam'
    function Get-ADMSSQLServers { Stop-SqlClassExternal }
    switch ($Mode) {
        'Construction' { Invoke-SqlClassConstructionCases }
        'Validation' { Invoke-SqlClassValidationCases }
        'Discovery' { Invoke-SqlClassDiscoveryCases }
        'Inventory' { Invoke-SqlClassInventoryCases }
        'Failures' { Invoke-SqlClassFailureCases }
    }
    Assert-SqlClass ($script:Unexpected -eq 0) 'An error report concealed an out-of-scope effect'
    'PASS SQL inventory class {0} {1}' -f $Mode, $script:Passed
}
finally {
    Microsoft.PowerShell.Management\Set-Location -LiteralPath $initialLocation
    if ($null -ne $borrowed) {
        Microsoft.PowerShell.Management\Remove-PSDrive -Name $borrowed.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
    }
    [IO.Directory]::Delete($script:Temporary, $true)
}
