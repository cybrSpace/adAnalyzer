[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Construction', 'Collect', 'Export', 'Isolation')]
    [string]$Mode,
    [switch]$RunspaceWorker
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:Passed = 0
$script:ForeignCalls = 0
$script:Route = 'Blocked'
$script:ProviderShape = 'Valid'
$script:Imports = [Collections.Generic.List[bool]]::new()
$script:Queries = [Collections.Generic.List[object]]::new()
$script:Dll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Credential = [pscredential]::new('FIXTURE\server-inventory', [Security.SecureString]::new())
$script:FixtureServer = 'dc.fixture.invalid'
$script:Failure = $null

function Assert-ServerClass($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-ServerClass([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('Failed AD server inventory class fixture: ' + $Name)
        throw
    }
}

function Assert-ServerClassFailure([scriptblock]$Body, [string]$Pattern = '.+') {
    $output = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Body | ForEach-Object { $output.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-ServerClass ($null -ne $failure -and $output.Count -eq 0) 'Expected a failure with no partial rows.'
    Assert-ServerClass ($failure.Exception.Message -match $Pattern) ('Unexpected failure: ' + $failure.Exception.Message)
}

function Reset-ServerClassTrace {
    $script:Imports.Clear()
    $script:Queries.Clear()
}

function Get-ServerClassJson($Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 12 -Compress
}

function Deny-ServerClassExternal {
    $script:ForeignCalls++
    throw 'Unexpected live or ambient provider operation.'
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru, [switch]$Global)

    if ($script:Route -eq 'Blocked') {
        Deny-ServerClassExternal
    }
    Assert-ServerClass ([IO.Path]::IsPathRooted($Name) -and $Name -ceq $script:Dll -and $Scope -ceq 'Local' -and
        -not $Global -and $PSBoundParameters['ErrorAction'] -eq 'Stop' -and
        $PassThru.IsPresent -eq ($script:Route -eq 'Direct')) 'The selected provider metadata, scope or import binding changed.'
    $script:Imports.Add($PassThru.IsPresent)
    if (-not $PassThru) {
        return
    }
    if ($script:ProviderShape -eq 'Throw') {
        throw [IO.FileLoadException]::new('Fixture packaged module load failed.')
    }

    $lookup = Get-Command Invoke-FixtureComputerLookup -CommandType Function
    $exports = @{}
    switch ($script:ProviderShape) {
        'Valid' {
            $exports['Get-ADComputer'] = $lookup
        }
        'NonCommand' {
            $exports['Get-ADComputer'] = 'Invoke-FixtureComputerLookup'
        }
    }
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $exports
        ExportedCommands = @{ 'Get-ADComputer' = $lookup }
    }
}

function Get-ADComputer {
    [CmdletBinding()]
    param([string]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($script:Route -ne 'Native') {
        Deny-ServerClassExternal
    }
    Invoke-ServerClassObservation $PSBoundParameters
}

function Invoke-FixtureComputerLookup {
    [CmdletBinding()]
    param([string]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($script:Route -ne 'Direct') {
        Deny-ServerClassExternal
    }
    Invoke-ServerClassObservation $PSBoundParameters
}

function Invoke-ServerClassObservation($Bound) {
    Assert-ServerClass (($Bound['Properties'] -join ',') -ceq 'IPv4Address' -and
        $Bound['ErrorAction'] -eq 'Stop') 'The computer lookup projection or error behavior changed.'
    $identity = $Bound['Identity']
    $script:Queries.Add([pscustomobject]@{
        Identity = $identity
        HasServer = $Bound.ContainsKey('Server')
        Server = $Bound['Server']
        HasCredential = $Bound.ContainsKey('Credential')
        Credential = $Bound['Credential']
    })
    if ($identity -eq 'bad') {
        switch ($script:Failure) {
            'Throw' { throw 'fixture stopping lookup failure' }
            'WriteError' {
                Write-Error 'fixture nonterminating lookup failure' -ErrorAction Stop
            }
            'Missing' { return }
            'Duplicate' {
                [pscustomobject]@{ Name = 'one'; IPv4Address = $null }
                [pscustomobject]@{ Name = 'two'; IPv4Address = $null }
                return
            }
            'Unnamed' {
                return [pscustomobject]@{ Name = ' '; IPv4Address = $null }
            }
            'MissingName' {
                return [pscustomobject]@{ IPv4Address = '192.0.2.10' }
            }
        }
    }

    if ($identity -eq 'no-address') {
        return [pscustomobject]@{ Name = $identity }
    }
    $name = $identity
    if ($identity -eq 'unicode') {
        $name = 'srv ' + [char]0x00FC + ', "quoted"'
    }
    [pscustomobject]@{
        Name = $name
        IPv4Address = '192.0.2.10'
        UnrelatedField = 'must not be returned'
    }
}

function Get-ADObject { Deny-ServerClassExternal }
function Get-ADDomain { Deny-ServerClassExternal }
function New-PSDrive { Deny-ServerClassExternal }
function Invoke-Command { Deny-ServerClassExternal }
function Invoke-RestMethod { Deny-ServerClassExternal }

function Assert-ServerClassQueries([string[]]$Identities, [string]$Server, [pscredential]$Credential) {
    $actual = @($script:Queries | ForEach-Object Identity)
    Assert-ServerClass ($script:Imports.Count -eq 1 -and $actual.Count -eq $Identities.Count -and
        ($actual -join '|') -ceq ($Identities -join '|')) 'Query and provider order changed.'
    $hasServer = [bool]$Server
    $expectedServer = $null
    if ($hasServer) {
        $expectedServer = $Server
    }
    foreach ($query in $script:Queries) {
        Assert-ServerClass ($query.HasServer -eq $hasServer -and $query.Server -ceq $expectedServer -and
            $query.HasCredential -eq [bool]$Credential) 'Connection defaults were rebound.'
        if ($Credential) {
            Assert-ServerClass ([object]::ReferenceEquals($query.Credential, $Credential)) 'Explicit credential identity changed.'
        }
    }
}

function Invoke-ServerConstructionCases {
    Test-ServerClass 'standalone dot source and constructor leave caller state unchanged' {
        Assert-ServerClass ($loaded.Count -eq 0 -and $owner.GetType().Name -ceq 'ADAnalyzerServerInventory' -and
            $script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0 -and
            $Server -ceq 'caller-server' -and $OutputPath -ceq 'caller-path' -and
            ($Identity -join ',') -ceq 'caller-identity' -and
            $null -eq (Get-Command Write-ADAnalyzerFile -CommandType Function -ListImported -ErrorAction SilentlyContinue)) 'Standalone initialization changed caller state.'
    }
    Test-ServerClass 'standalone owners coexist without initializing the provider' {
        $spurious = @(
            . (Join-Path $RepositoryRoot 'etc/Get-GPOXML.ps1')
            . (Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1')
        )
        $xml = [ADAnalyzerGpoXmlInventory]::new()
        $local = [ADAnalyzerLocalAdminPolicyInventory]::new()
        Assert-ServerClass ($spurious.Count -eq 0 -and $null -ne $xml -and $null -ne $local -and
            $script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0) 'Standalones collided or began initialization.'
    }
}

function Invoke-ServerCollectionCases {
    Test-ServerClass 'all identities validate before any provider effect' {
        Assert-ServerClassFailure { $owner.Collect($null) } '(?i)at least one'
        Assert-ServerClassFailure { $owner.Collect([string[]]@()) } '(?i)at least one'
        Assert-ServerClassFailure { $owner.Collect(@('first', ' ')) } '(?i)nonempty'
        Assert-ServerClassFailure { $owner.Collect(@('first', $null)) } '(?i)nonempty'
        Assert-ServerClass ($script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0) 'Failed selectors reached the provider.'
    }
    Test-ServerClass 'ordered rows and nullable addresses match the same-engine native command' {
        $identities = [string[]]@('second', 'first', 'second', 'no-address')
        $script:Route = 'Native'
        $legacy = @(Get-ADServers -Identity $identities)
        Assert-ServerClassQueries $identities '' $null
        Reset-ServerClassTrace
        $script:Route = 'Direct'
        $rows = $owner.Collect($identities)
        Assert-ServerClassQueries $identities '' $null
        Assert-ServerClass ($rows -is [object[]] -and $rows.Count -eq 4 -and
            ($rows.name -join ',') -ceq 'second,first,second,no-address' -and
            ($rows[0].PSObject.Properties.Name -join ',') -ceq 'name,ipv4Address' -and
            $null -eq $rows[3].ipv4Address -and (Get-ServerClassJson $rows) -ceq (Get-ServerClassJson $legacy)) (
            'Ordered result names, schema or nullable IPv4 changed.'
        )
        Assert-ServerClass (($identities -join ',') -ceq 'second,first,second,no-address') 'Collect changed caller inputs.'
    }
    Test-ServerClass 'optional server and credential binding survives reused connection overloads' {
        Reset-ServerClassTrace
        $null = $owner.Collect(@('first'), $script:FixtureServer)
        Assert-ServerClassQueries @('first') $script:FixtureServer $null
        foreach ($omitted in $null, [pscredential]::Empty) {
            Reset-ServerClassTrace
            $null = $owner.Collect(@('first'), '', $omitted)
            Assert-ServerClassQueries @('first') '' $null
        }
        Reset-ServerClassTrace
        $null = $owner.Collect(@('first'), $script:FixtureServer, $script:Credential)
        Assert-ServerClassQueries @('first') $script:FixtureServer $script:Credential
        Reset-ServerClassTrace
        $null = $owner.Collect(@('first'))
        Assert-ServerClassQueries @('first') '' $null
    }
    Test-ServerClass 'invalid provider metadata never falls back or invokes a plain command name' {
        foreach ($shape in 'Missing', 'NonCommand', 'Throw') {
            Reset-ServerClassTrace
            $script:ProviderShape = $shape
            Assert-ServerClassFailure { $owner.Collect(@('first')) }
            Assert-ServerClass ($script:Imports.Count -eq 1 -and $script:Queries.Count -eq 0) 'Invalid module metadata triggered a lookup.'
        }
        $script:ProviderShape = 'Valid'
    }
    Test-ServerClass 'late lookup failure exposes no earlier rows and a later call recovers' {
        foreach ($failure in 'Throw', 'WriteError', 'Missing', 'Duplicate', 'Unnamed', 'MissingName') {
            Reset-ServerClassTrace
            $script:Failure = $failure
            Assert-ServerClassFailure { $owner.Collect(@('first', 'bad', 'unreached')) }
            Assert-ServerClassQueries @('first', 'bad') '' $null
        }
        Reset-ServerClassTrace
        $script:Failure = $null
        $result = $owner.Collect(@('first'))
        Assert-ServerClassQueries @('first') '' $null
        Assert-ServerClass ($result.Count -eq 1 -and $result[0].name -ceq 'first') 'A failed operation affected reuse.'
    }
}

function Invoke-ServerExportCases {
    Test-ServerClass 'literal CSV is identical to the native export with quoted Unicode and a blank IPv4' {
        $ids = @('unicode', 'no-address')
        $path = Join-Path $script:Temporary 'folder [direct]/servers [literal].csv'
        $nativePath = Join-Path $script:Temporary 'native.csv'
        $script:Route = 'Direct'
        $rows = $owner.Export($ids, $path, $script:FixtureServer, $script:Credential)
        Assert-ServerClassQueries $ids $script:FixtureServer $script:Credential
        Reset-ServerClassTrace
        $script:Route = 'Native'
        $nativeArguments = @{
            Identity = $ids
            Server = $script:FixtureServer
            Credential = $script:Credential
            OutputPath = $nativePath
            Confirm = $false
        }
        $native = @(Get-ADServers @nativeArguments)
        Assert-ServerClassQueries $ids $script:FixtureServer $script:Credential
        $csv = @(Import-Csv -LiteralPath $path)
        Assert-ServerClass ($rows -is [object[]] -and $rows.Count -eq 2 -and $csv.Count -eq 2 -and
            ($csv[0].PSObject.Properties.Name -join ',') -ceq 'name,ipv4Address' -and
            $csv[0].name -ceq ('srv ' + [char]0x00FC + ', "quoted"') -and
            $csv[0].ipv4Address -ceq '192.0.2.10' -and [string]$csv[1].ipv4Address -ceq '' -and
            (Get-ServerClassJson $rows) -ceq (Get-ServerClassJson $native) -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($nativePath))) (
            'CSV serialization, quoting, returned rows or nullable values differ.'
        )
    }
    Test-ServerClass 'dry-run reads both connection overloads and does not render or write' {
        $script:Route = 'Direct'
        function ConvertTo-Csv { Deny-ServerClassExternal }
        $directory = Join-Path $script:Temporary 'dry folder'
        $path = Join-Path $directory 'planned.csv'
        $prior = Join-Path $script:Temporary 'dry previous.csv'
        [IO.File]::WriteAllText($prior, 'old data')
        Reset-ServerClassTrace
        $selected = $owner.Export(@('first'), $prior, $script:FixtureServer, $script:Credential, $true)
        Assert-ServerClassQueries @('first') $script:FixtureServer $script:Credential
        Reset-ServerClassTrace
        $ambient = $owner.Export(@('first'), $path, $true)
        Assert-ServerClassQueries @('first') '' $null
        Assert-ServerClass ($selected.Count -eq 1 -and $ambient.Count -eq 1 -and
            (Get-ServerClassJson $selected) -ceq (Get-ServerClassJson $ambient) -and
            [IO.File]::ReadAllText($prior) -ceq 'old data' -and -not [IO.Directory]::Exists($directory)) 'Dry run lost rows or changed files.'
    }
    Test-ServerClass 'bad path fails before any collection even during dry-run' {
        Reset-ServerClassTrace
        $script:Route = 'Blocked'
        foreach ($dryRun in $true, $false) {
            Assert-ServerClassFailure { $owner.Export(@('first'), '', $dryRun) } '(?i)output path'
            Assert-ServerClassFailure { $owner.Export(@('first'), 'Variable:ServerInventoryFixtureOutput', $dryRun) } '(?i)FileSystem'
        }
        Assert-ServerClass ($script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0 -and
            $null -eq (Get-Variable -Name ServerInventoryFixtureOutput -ErrorAction SilentlyContinue)) 'Path validation leaked effects.'
        $script:Route = 'Direct'
    }
    Test-ServerClass 'late query failure preserves previous bytes without emitting rows' {
        $path = Join-Path $script:Temporary 'previous lookup.csv'
        [IO.File]::WriteAllText($path, 'prior lookup report')
        $previous = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        foreach ($failure in 'Throw', 'WriteError', 'Missing', 'Duplicate', 'Unnamed') {
            Reset-ServerClassTrace
            $script:Failure = $failure
            Assert-ServerClassFailure { $owner.Export(@('first', 'bad', 'unreached'), $path) }
            Assert-ServerClassQueries @('first', 'bad') '' $null
            Assert-ServerClass ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $previous) 'Failed query replaced previous bytes.'
        }
        $script:Failure = $null
    }
    Test-ServerClass 'serializer failure happens after lookup and leaves the previous file' {
        $path = Join-Path $script:Temporary 'previous serialization.csv'
        [IO.File]::WriteAllText($path, 'prior serialization report')
        function ConvertTo-Csv {
            [CmdletBinding()]
            param([Parameter(ValueFromPipeline)]$InputObject, [switch]$NoTypeInformation)

            process {
                throw 'Fixture CSV serialization failed.'
            }
        }
        Reset-ServerClassTrace
        Assert-ServerClassFailure { $owner.Export(@('first'), $path) } 'Fixture CSV serialization failed'
        Assert-ServerClassQueries @('first') '' $null
        Assert-ServerClass ([IO.File]::ReadAllText($path) -ceq 'prior serialization report') 'Serializer failure replaced the previous file.'
    }
    Test-ServerClass 'failed filesystem promotion cleans staging and emits no rows' {
        $path = Join-Path $script:Temporary 'existing directory.csv'
        $null = [IO.Directory]::CreateDirectory($path)
        $marker = Join-Path $path 'retain'
        [IO.File]::WriteAllText($marker, 'existing data')
        Reset-ServerClassTrace
        Assert-ServerClassFailure { $owner.Export(@('first'), $path) }
        Assert-ServerClassQueries @('first') '' $null
        Assert-ServerClass ([IO.File]::ReadAllText($marker) -ceq 'existing data' -and
            [IO.Directory]::GetFiles($script:Temporary, '.ad-analyzer-*.tmp').Count -eq 0) 'File promotion lost data or left a staged file.'
    }
}

function Invoke-ServerIsolationCases {
    $script:Route = 'Direct'
    $expected = Get-ServerClassJson ($owner.Collect(@('first', 'no-address')))
    if ($RunspaceWorker) {
        Assert-ServerClassQueries @('first', 'no-address') '' $null
        $expected
        return
    }
    Test-ServerClass 'independent objects and reused collections do not retain dependency state' {
        Reset-ServerClassTrace
        $first = $owner.Collect(@('first', 'no-address'), $script:FixtureServer, $script:Credential)
        Assert-ServerClassQueries @('first', 'no-address') $script:FixtureServer $script:Credential
        $first[0].name = 'changed result only'
        $other = [ADAnalyzerServerInventory]::new()
        foreach ($instance in $owner, $other) {
            Reset-ServerClassTrace
            $rows = $instance.Collect(@('first', 'no-address'))
            Assert-ServerClassQueries @('first', 'no-address') '' $null
            Assert-ServerClass ((Get-ServerClassJson $rows) -ceq $expected -and
                [Management.Automation.PSSerializer]::Serialize($instance) -cnotmatch 'FIXTURE\\server-inventory|PSCredential') (
                'Credential, mutable results or lookup state leaked across calls.'
            )
        }
    }
    Test-ServerClass 'separate runspace loading and disposal preserve the original owner' {
        $shell = [powershell]::Create()
        try {
            $worker = @'
param($Fixture, $Root)
& $Fixture -RepositoryRoot $Root -Mode Isolation -RunspaceWorker
'@
            $bound = $shell.AddScript($worker).AddArgument($PSCommandPath).AddArgument($RepositoryRoot)
            $rows = @($bound.Invoke())
            Assert-ServerClass (-not $shell.HadErrors -and $rows.Count -eq 1 -and
                [string]$rows[0] -ceq $expected) ('Separate runspace failed: ' + ($shell.Streams.Error -join ' | '))
        }
        finally {
            $shell.Dispose()
        }
        Reset-ServerClassTrace
        $result = $owner.Collect(@('first', 'no-address'))
        Assert-ServerClassQueries @('first', 'no-address') '' $null
        Assert-ServerClass ((Get-ServerClassJson $result) -ceq $expected) 'Reuse failed after another runspace was disposed.'
    }
}

$originalLocation = (Get-Location).Path
$Server = 'caller-server'
$OutputPath = 'caller-path'
$Identity = @('caller-identity')
$loaded = @(. (Join-Path $RepositoryRoot 'etc/Get-ADServers.ps1'))
$owner = [ADAnalyzerServerInventory]::new()
Assert-ServerClass ($loaded.Count -eq 0 -and $script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0) 'Loading or construction had effects.'

$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-server-inventory-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Temporary)
try {
    switch ($Mode) {
        'Construction' { Invoke-ServerConstructionCases }
        'Collect' { Invoke-ServerCollectionCases }
        'Export' { Invoke-ServerExportCases }
        'Isolation' { Invoke-ServerIsolationCases }
    }
    Assert-ServerClass ($script:ForeignCalls -eq 0 -and (Get-Location).Path -ceq $originalLocation) 'The fixture crossed an external boundary or changed location.'
    if (-not $RunspaceWorker) {
        'PASS AD server inventory class {0} {1}' -f $Mode, $script:Passed
    }
}
finally {
    [IO.Directory]::Delete($script:Temporary, $true)
}
