[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Construction', 'Traversal', 'Failures', 'Export', 'Isolation')]
    [string]$Mode,
    [switch]$RunspaceWorker
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:Passed = 0
$script:ForeignCalls = 0
$script:Route = 'Blocked'
$script:ProviderShape = 'Valid'
$script:Imports = 0
$script:Trace = [Collections.Generic.List[object]]::new()
$script:ChildSamReads = 0
$script:Dll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:FixtureServer = 'dc.fixture.invalid'
$script:Credential = [pscredential]::new('FIXTURE\group-inventory', [Security.SecureString]::new())
$script:ExpectedServer = ''
$script:ExpectedCredential = $null
$script:Fault = ''
$script:Marker = 'user ' + [char]0x00FC + ', "quoted"'
$script:Suffix = ',DC=fixture,DC=invalid'
$script:RootA = 'CN=RootA' + $script:Suffix
$script:RootB = 'CN=RootB' + $script:Suffix
$script:Child = 'CN=Child' + $script:Suffix
$script:ChildAlias = 'CN=Child alias' + $script:Suffix
$script:Empty = 'CN=Empty' + $script:Suffix
$script:Leaf = 'CN=Leaf' + $script:Suffix
$script:After = 'CN=After' + $script:Suffix
$script:Special = 'literal ' + [char]0x00FC + '*(x)\' + [char]0
$script:SpecialFilter = '(|(CN=literal ' + [char]0x00FC + '\2a\28x\29\5c\00)(sAMAccountName=literal ' + [char]0x00FC + '\2a\28x\29\5c\00))'

function Assert-GroupInventory($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-GroupInventoryCase([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('Failed AD group inventory class fixture: ' + $Name)
        throw
    }
}

function Assert-GroupInventoryFailure([scriptblock]$Body, [string]$Pattern = '.+', [type]$Cause) {
    $output = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Body | ForEach-Object { $output.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-GroupInventory ($null -ne $failure -and $output.Count -eq 0) 'Expected a failure with no partial rows.'
    Assert-GroupInventory ($failure.Exception.Message -match $Pattern) ('Unexpected failure: ' + $failure.Exception.Message)
    if ($Cause) {
        Assert-GroupInventory ($Cause.IsAssignableFrom($failure.Exception.GetBaseException().GetType())) 'The original failure type was lost.'
    }
}

function Reset-GroupInventoryTrace([string]$Server = '', [pscredential]$Credential) {
    $script:Imports = 0
    $script:Trace.Clear()
    $script:ChildSamReads = 0
    $script:ExpectedServer = $Server
    $script:ExpectedCredential = $Credential
}

function Get-GroupInventoryJson($Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 15 -Compress
}

function New-GroupInventoryRecord([string]$Dn, [string]$Sam, [string]$Class, [object[]]$Members = @()) {
    [pscustomobject]@{
        DistinguishedName = $Dn
        CN = $Sam
        SamAccountName = $Sam
        ObjectClass = $Class
        Member = $Members
    }
}

$script:SelectedA = New-GroupInventoryRecord $script:RootA 'Selected RootA' group @(
    $script:ChildAlias
    $script:Child.ToLowerInvariant()
    $script:Empty
    $script:Leaf
)
$script:SelectedB = New-GroupInventoryRecord $script:RootB 'Selected RootB' group @($script:Child, $script:ChildAlias)
$script:ResolvedA = New-GroupInventoryRecord $script:RootA 'Resolved RootA' group @($script:After)
$script:ChildRow = New-GroupInventoryRecord $script:Child '' group @($script:RootA.ToUpperInvariant(), $script:After)
$script:ChildRow.PSObject.Properties.Remove('SamAccountName')
$script:ChildRow | Add-Member -MemberType ScriptProperty -Name SamAccountName -Value {
    $script:ChildSamReads++
    'Child observation ' + $script:ChildSamReads
}
$script:EmptyRow = New-GroupInventoryRecord $script:Empty 'Empty' group
$script:LeafRow = New-GroupInventoryRecord $script:Leaf $script:Marker user
$script:AfterRow = New-GroupInventoryRecord $script:After 'After' computer

function Deny-GroupInventoryExternal {
    $script:ForeignCalls++
    throw 'Unexpected live or ambient provider operation.'
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru, [switch]$Global)

    if ($script:Route -eq 'Blocked') {
        Deny-GroupInventoryExternal
    }
    Assert-GroupInventory ($Name -ceq $script:Dll -and [IO.Path]::IsPathRooted($Name) -and
        $Scope -ceq 'Local' -and -not $Global -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop' -and
        $PassThru.IsPresent -eq ($script:Route -eq 'Direct')) 'Wrong bundled import path, scope or error binding.'
    $script:Imports++
    if (-not $PassThru) {
        return
    }
    $commands = @{
        'Get-ADGroup' = Get-Command Invoke-GroupInventoryFakeGroup -CommandType Function
        'Get-ADObject' = Get-Command Invoke-GroupInventoryFakeObject -CommandType Function
    }
    $exports = $commands.Clone()
    switch ($script:ProviderShape) {
        'MissingGroup' { $exports.Remove('Get-ADGroup') }
        'MissingObject' { $exports.Remove('Get-ADObject') }
        'StringObject' { $exports['Get-ADObject'] = 'Invoke-GroupInventoryFakeObject' }
    }
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $exports
        ExportedCommands = $commands
    }
}

function Get-ADGroup {
    [CmdletBinding()]
    param([string]$LDAPFilter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($script:Route -ne 'Native') {
        Deny-GroupInventoryExternal
    }
    Invoke-GroupInventoryMatch $PSBoundParameters
}

function Get-ADObject {
    [CmdletBinding()]
    param([string]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($script:Route -ne 'Native') {
        Deny-GroupInventoryExternal
    }
    Invoke-GroupInventoryMember $PSBoundParameters
}

function Invoke-GroupInventoryFakeGroup {
    [CmdletBinding()]
    param([string]$LDAPFilter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($script:Route -ne 'Direct') {
        Deny-GroupInventoryExternal
    }
    Invoke-GroupInventoryMatch $PSBoundParameters
}

function Invoke-GroupInventoryFakeObject {
    [CmdletBinding()]
    param([string]$Identity, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($script:Route -ne 'Direct') {
        Deny-GroupInventoryExternal
    }
    Invoke-GroupInventoryMember $PSBoundParameters
}

function Add-GroupInventoryTrace([string]$Step, [string]$Requested, [string]$Properties, $Bound) {
    Assert-GroupInventory ($script:Trace.Count -lt 40 -and ($Bound['Properties'] -join ',') -ceq $Properties -and
        $Bound['ErrorAction'] -eq 'Stop') 'Query exceeded the bound or changed projected properties.'
    Assert-GroupInventory ($Bound.ContainsKey('Server') -eq [bool]$script:ExpectedServer -and
        $Bound.ContainsKey('Credential') -eq [bool]$script:ExpectedCredential) 'An omitted connection was explicitly rebound.'
    if ($script:ExpectedServer) {
        Assert-GroupInventory ($Bound['Server'] -ceq $script:ExpectedServer) 'Selected server changed.'
    }
    if ($script:ExpectedCredential) {
        Assert-GroupInventory ([object]::ReferenceEquals($Bound['Credential'], $script:ExpectedCredential)) 'Selected credential identity changed.'
    }
    $script:Trace.Add([pscustomobject]@{
        Step = $Step
        Requested = $Requested
    })
}

function Invoke-GroupInventoryMatch($Bound) {
    $filter = $Bound['LDAPFilter']
    Add-GroupInventoryTrace Group $filter 'CN,Member' $Bound
    if ($filter -ceq $script:SpecialFilter) {
        return $script:EmptyRow
    }
    foreach ($name in 'RootA', 'RootB', 'Empty', 'Both', 'Missing', 'BadRoot', 'BadMember') {
        if ($filter -cne ('(|(CN={0})(sAMAccountName={0}))' -f $name)) {
            continue
        }
        switch ($name) {
            'RootA' { return $script:SelectedA }
            'RootB' { return $script:SelectedB }
            'Empty' { return $script:EmptyRow }
            'Both' {
                $script:SelectedA
                $script:EmptyRow
                $script:SelectedA
                return
            }
            'Missing' { return }
            'BadRoot' {
                return New-GroupInventoryRecord '' fixture group
            }
            'BadMember' {
                return New-GroupInventoryRecord $script:RootA fixture group @(' ')
            }
        }
    }
    throw 'Unexpected literal selector filter.'
}

function Invoke-GroupInventoryMember($Bound) {
    $dn = $Bound['Identity']
    Add-GroupInventoryTrace Object $dn 'SamAccountName,ObjectClass,CN,Member' $Bound
    if ($dn -ieq $script:After) {
        switch ($script:Fault) {
            'Throw' { throw 'Fixture member lookup failed.' }
            'WriteError' { Write-Error 'Fixture member observation failed.' -ErrorAction Stop }
            'Missing' { return }
            'Duplicate' {
                $script:AfterRow
                $script:AfterRow
                return
            }
            'BlankDN' {
                return New-GroupInventoryRecord '' After computer
            }
            'BlankClass' {
                return New-GroupInventoryRecord $script:After After ''
            }
        }
        return $script:AfterRow
    }
    switch ($dn) {
        $script:ChildAlias { return $script:ChildRow }
        $script:Child { return $script:ChildRow }
        $script:RootA { return $script:ResolvedA }
        $script:Empty { return $script:EmptyRow }
        $script:Leaf { return $script:LeafRow }
        default { throw 'Unexpected fixture object lookup.' }
    }
}

function Get-GroupInventoryRequests([string]$Step) {
    $script:Trace | Where-Object Step -eq $Step | ForEach-Object Requested
}

function Assert-GroupInventoryGraph([object[]]$Rows) {
    Assert-GroupInventory ($Rows.Count -eq 12 -and ($Rows[0].PSObject.Properties.Name -join ',') -ceq
        'group.DN,group.CN,member.SamAccountName,member.objectClass') 'Inventory length or ordered schema changed.'
    $groups = @($Rows | ForEach-Object { $_.'group.DN' }) -join '|'
    $expectedGroups = @(
        $script:RootA
        $script:RootA
        $script:RootA
        $script:RootA
        $script:Child
        $script:Child
        $script:Empty
        $script:RootB
        $script:RootB
        $script:Child
        $script:Child
        $script:RootA
    ) -join '|'
    Assert-GroupInventory ($groups -ceq $expectedGroups -and
        ($Rows.'group.CN' -join '|') -ceq 'RootA|RootA|RootA|RootA|RootA|RootA|RootA|RootB|RootB|RootB|RootB|RootB') 'Breadth-first order, containing DN or root labels changed.'
    Assert-GroupInventory ($Rows[4].'member.SamAccountName' -ceq 'Resolved RootA' -and
        $Rows[9].'member.SamAccountName' -ceq 'Resolved RootA' -and
        $null -eq $Rows[6].'member.SamAccountName' -and $null -eq $Rows[6].'member.objectClass') 'Cycle or empty edge observation changed.'
    $reads = @($Rows | Where-Object { $_.'member.SamAccountName' -clike 'Child observation *' } |
        ForEach-Object { $_.'member.SamAccountName' })
    Assert-GroupInventory (($reads -join '|') -ceq 'Child observation 1|Child observation 2|Child observation 3|Child observation 4' -and
        $script:ChildSamReads -eq 4) 'The alias cache used projected data instead of re-reading the shared record.'
    $objectQueries = @(
        $script:ChildAlias
        $script:Empty
        $script:Leaf
        $script:RootA.ToUpperInvariant()
        $script:After
    ) -join '|'
    Assert-GroupInventory ((@(Get-GroupInventoryRequests Object) -join '|') -ceq $objectQueries -and $script:Imports -eq 1) (
        'Shared cache lost requested/canonical aliases, treated cases differently or seeded from selected roots.'
    )
}

function Invoke-GroupInventoryConstructionCases {
    Test-GroupInventoryCase 'literal standalone construction is inert' {
        Assert-GroupInventory ($owner.GetType().Name -ceq 'ADAnalyzerGroupInventory' -and $loaded.Count -eq 0 -and
            $script:Imports -eq 0 -and $script:Trace.Count -eq 0 -and
            $Server -ceq 'caller-server' -and $OutputPath -ceq 'caller-path' -and
            ($Array -join ',') -ceq 'caller-group' -and
            $null -eq (Get-Command Read-GroupCNObject -CommandType Function -ListImported -ErrorAction SilentlyContinue) -and
            $null -eq (Get-Command Write-ADAnalyzerFile -CommandType Function -ListImported -ErrorAction SilentlyContinue)) (
            'Construction initialized a dependency or changed caller state.'
        )
    }
    Test-GroupInventoryCase 'standalone group and server inventory types can coexist' {
        $serverLoad = @(. (Join-Path $RepositoryRoot 'etc/Get-ADServers.ps1'))
        $other = [ADAnalyzerServerInventory]::new()
        Assert-GroupInventory ($serverLoad.Count -eq 0 -and $other.GetType().Name -ceq 'ADAnalyzerServerInventory' -and
            $script:Imports -eq 0 -and $script:Trace.Count -eq 0) 'Coexistence initialized a dependency.'
    }
}

function Invoke-GroupInventoryTraversalCases {
    Test-GroupInventoryCase 'shared nested graph preserves BFS and exact native row and request order' {
        $selectors = [string[]]@('RootA', 'RootB')
        $script:Route = 'Native'
        $legacy = @(Get-GroupCN -Array $selectors)
        Assert-GroupInventoryGraph $legacy
        $trace = Get-GroupInventoryJson ($script:Trace.ToArray())
        $script:Route = 'Direct'
        Reset-GroupInventoryTrace
        $rows = $owner.Collect($selectors)
        Assert-GroupInventoryGraph $rows
        Assert-GroupInventory ($rows -is [object[]] -and (Get-GroupInventoryJson $rows) -ceq (Get-GroupInventoryJson $legacy) -and
            (Get-GroupInventoryJson ($script:Trace.ToArray())) -ceq $trace -and
            ($selectors -join ',') -ceq 'RootA,RootB') 'Direct and native graph projections or order differ.'
    }
    Test-GroupInventoryCase 'duplicate matches and repeated selector input retain separate root visits' {
        Reset-GroupInventoryTrace
        $rows = $owner.Collect(@('Both', 'Empty'))
        Assert-GroupInventory ($rows.Count -eq 16 -and $rows[0].'group.DN' -ceq $script:RootA -and
            $rows[6].'group.DN' -ceq $script:Empty -and $rows[7].'group.DN' -ceq $script:Empty -and
            $rows[8].'group.DN' -ceq $script:RootA -and $rows[15].'group.DN' -ceq $script:Empty -and
            (($rows.'group.CN' | Select-Object -Unique) -join '|') -ceq 'Both|Empty' -and
            @(Get-GroupInventoryRequests Object).Count -eq 5 -and $script:ChildSamReads -eq 4) (
            'Duplicate matched roots or empty records were collapsed.'
        )
        Reset-GroupInventoryTrace
        $duplicate = $owner.Collect(@('Empty', 'Empty'))
        Assert-GroupInventory ($duplicate.Count -eq 2 -and @(Get-GroupInventoryRequests Group).Count -eq 2) 'Duplicate selector input was deduplicated.'
    }
    Test-GroupInventoryCase 'selector literal escapes LDAP metacharacters and preserves Unicode and the input label' {
        Reset-GroupInventoryTrace
        $rows = $owner.Collect(@($script:Special))
        Assert-GroupInventory ((@(Get-GroupInventoryRequests Group) -join '|') -ceq $script:SpecialFilter -and
            @(Get-GroupInventoryRequests Object).Count -eq 0 -and $rows.Count -eq 1 -and
            $rows[0].'group.CN' -ceq $script:Special -and $rows[0].'group.DN' -ceq $script:Empty) 'Exact literal selector or original label changed.'
    }
    Test-GroupInventoryCase 'explicit connection is reused for both package commands and does not persist' {
        Reset-GroupInventoryTrace $script:FixtureServer $script:Credential
        $rows = $owner.Collect(@('RootA'), $script:FixtureServer, $script:Credential)
        Assert-GroupInventory ($rows.Count -eq 7 -and $script:Imports -eq 1 -and $script:Trace.Count -eq 6) 'Explicit qualified inputs were not read.'
        Reset-GroupInventoryTrace $script:FixtureServer
        $null = $owner.Collect(@('Empty'), $script:FixtureServer)
        Assert-GroupInventory ($script:Trace.Count -eq 1) 'Server-only overload did not query.'
        foreach ($emptyCredential in $null, [pscredential]::Empty) {
            Reset-GroupInventoryTrace
            $null = $owner.Collect(@('Empty'), '', $emptyCredential)
            Assert-GroupInventory ($script:Trace.Count -eq 1) 'Empty connection overload did not query.'
        }
    }
    Test-GroupInventoryCase 'authority-selected root record is not overwritten by its fetched data' {
        Reset-GroupInventoryTrace
        $rows = $owner.Collect(@('RootA', 'RootA'))
        Assert-GroupInventory ($rows.Count -eq 14 -and $rows[4].'member.SamAccountName' -ceq 'Resolved RootA' -and
            $rows[11].'member.SamAccountName' -ceq 'Resolved RootA' -and
            @(Get-GroupInventoryRequests Group).Count -eq 2 -and @(Get-GroupInventoryRequests Object).Count -eq 5) (
            'Cached fetched root data replaced a separately selected root or a visited set leaked.'
        )
    }
}

function Invoke-GroupInventoryFailureCases {
    Test-GroupInventoryCase 'all selectors including invalid UTF-8 fail before provider work' {
        Assert-GroupInventoryFailure { $owner.Collect($null) } '(?i)at least one'
        Assert-GroupInventoryFailure { $owner.Collect([string[]]@()) } '(?i)at least one'
        Assert-GroupInventoryFailure { $owner.Collect(@('RootA', ' ')) } '(?i)nonempty'
        Assert-GroupInventoryFailure { $owner.Collect(@('RootA', $null)) } '(?i)nonempty'
        $unpaired = [string][char]0xD800
        Assert-GroupInventoryFailure { $owner.Collect(@('RootA', $unpaired)) } '.+' ([Text.EncoderFallbackException])
        Assert-GroupInventory ($script:Imports -eq 0 -and $script:Trace.Count -eq 0 -and
            $script:ForeignCalls -eq 0) 'Invalid selectors reached a provider.'
    }
    Test-GroupInventoryCase 'both exact exports must be genuine host CommandInfo before any query' {
        $script:Route = 'Direct'
        foreach ($shape in 'MissingGroup', 'MissingObject', 'StringObject') {
            Reset-GroupInventoryTrace
            $script:ProviderShape = $shape
            Assert-GroupInventoryFailure { $owner.Collect(@('RootA')) }
            Assert-GroupInventory ($script:Imports -eq 1 -and $script:Trace.Count -eq 0) 'Missing metadata triggered a query.'
        }
        $script:ProviderShape = 'Valid'
    }
    Test-GroupInventoryCase 'missing roots, malformed metadata and late lookups fail without partial output' {
        Reset-GroupInventoryTrace
        Assert-GroupInventoryFailure { $owner.Collect(@('RootA', 'Missing')) } 'No group matched selector'
        Assert-GroupInventory (@(Get-GroupInventoryRequests Group).Count -eq 2) 'Both selectors were not evaluated before failure.'
        Reset-GroupInventoryTrace
        Assert-GroupInventoryFailure { $owner.Collect(@('BadRoot')) } '(?i)group has no distinguished name'
        Assert-GroupInventoryFailure { $owner.Collect(@('BadMember')) } '(?i)member has no distinguished name'
        Assert-GroupInventory (@(Get-GroupInventoryRequests Object).Count -eq 0) 'Blank distinguished names reached member lookup.'
        foreach ($fault in 'Throw', 'WriteError', 'Missing', 'Duplicate', 'BlankDN', 'BlankClass') {
            Reset-GroupInventoryTrace
            $script:Fault = $fault
            Assert-GroupInventoryFailure { $owner.Collect(@('RootA', 'RootB')) }
            $requests = @(Get-GroupInventoryRequests Object)
            Assert-GroupInventory ($requests.Count -eq 5 -and $requests[4] -ceq $script:After -and
                @(Get-GroupInventoryRequests Group).Count -eq 1) 'Failure did not stop after the intended late lookup.'
        }
        Reset-GroupInventoryTrace
        $script:Fault = ''
        Assert-GroupInventory ($owner.Collect(@('RootA')).Count -eq 7) 'A failed inventory contaminated a later call.'
    }
}

function Invoke-GroupInventoryExportCases {
    Test-GroupInventoryCase 'literal CSV preserves native bytes, order, quoting and fields' {
        $path = Join-Path $script:Temp 'folder [direct]/groups [one].csv'
        $nativePath = Join-Path $script:Temp 'native.csv'
        $selectors = @('RootA', 'Empty')
        Reset-GroupInventoryTrace $script:FixtureServer $script:Credential
        $script:Route = 'Direct'
        $rows = $owner.Export($selectors, $path, $script:FixtureServer, $script:Credential)
        Reset-GroupInventoryTrace $script:FixtureServer $script:Credential
        $script:Route = 'Native'
        $nativeArgs = @{
            Array = $selectors
            Server = $script:FixtureServer
            Credential = $script:Credential
            OutputPath = $nativePath
            Confirm = $false
        }
        $native = @(Get-GroupCN @nativeArgs)
        $csv = @(Import-Csv -LiteralPath $path)
        Assert-GroupInventory ($rows.Count -eq 8 -and $csv.Count -eq 8 -and
            ($csv[0].PSObject.Properties.Name -join ',') -ceq 'group.DN,group.CN,member.SamAccountName,member.objectClass' -and
            $csv[3].'member.SamAccountName' -ceq $script:Marker -and [string]$csv[7].'member.SamAccountName' -ceq '' -and
            (Get-GroupInventoryJson $rows) -ceq (Get-GroupInventoryJson $native) -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($nativePath))) (
            'CSV data, schema or exact serialized bytes diverged.'
        )
    }
    Test-GroupInventoryCase 'dry-run reads validation results but never serializes, writes or creates directories' {
        $script:Route = 'Direct'
        function ConvertTo-Csv { Deny-GroupInventoryExternal }
        $folder = Join-Path $script:Temp 'dry folder'
        $oldPath = Join-Path $script:Temp 'previous dry.csv'
        [IO.File]::WriteAllText($oldPath, 'old dry report')
        Reset-GroupInventoryTrace
        $ordinary = $owner.Export(@('RootA'), (Join-Path $folder 'planned.csv'), $true)
        Assert-GroupInventory ($ordinary.Count -eq 7 -and $script:Trace.Count -eq 6 -and
            -not [IO.Directory]::Exists($folder)) 'Dry-run lost rows or created a destination.'
        Reset-GroupInventoryTrace $script:FixtureServer $script:Credential
        $selected = $owner.Export(@('RootA'), $oldPath, $script:FixtureServer, $script:Credential, $true)
        Assert-GroupInventory ((Get-GroupInventoryJson $ordinary) -ceq (Get-GroupInventoryJson $selected) -and
            $script:Trace.Count -eq 6 -and [IO.File]::ReadAllText($oldPath) -ceq 'old dry report') 'Credentialed dry-run changed output.'
    }
    Test-GroupInventoryCase 'empty and unsupported paths fail before provider work' {
        Reset-GroupInventoryTrace
        $script:Route = 'Blocked'
        foreach ($dry in $false, $true) {
            Assert-GroupInventoryFailure { $owner.Export(@('RootA'), '', $dry) } '(?i)path'
            Assert-GroupInventoryFailure { $owner.Export(@('RootA'), 'Variable:GroupInventoryTestOutput', $dry) } '(?i)FileSystem'
        }
        Assert-GroupInventory ($script:Imports -eq 0 -and $script:Trace.Count -eq 0 -and $script:ForeignCalls -eq 0) 'Path validation reached the provider.'
        $script:Route = 'Direct'
    }
    Test-GroupInventoryCase 'lookup and rendering failures keep previous bytes and emit no rows' {
        $path = Join-Path $script:Temp 'prior [literal].csv'
        [IO.File]::WriteAllText($path, 'previous report')
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        Reset-GroupInventoryTrace
        $script:Fault = 'Throw'
        Assert-GroupInventoryFailure { $owner.Export(@('RootA'), $path) } 'Fixture member lookup failed'
        Assert-GroupInventory ($script:Trace.Count -eq 6 -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $before) 'Late lookup replaced previous bytes.'
        $script:Fault = ''
        Reset-GroupInventoryTrace
        function ConvertTo-Csv {
            [CmdletBinding()]
            param([Parameter(ValueFromPipeline)]$InputObject, [switch]$NoTypeInformation)

            process {
                throw 'Fixture group CSV conversion failed.'
            }
        }
        Assert-GroupInventoryFailure { $owner.Export(@('RootA'), $path) } 'Fixture group CSV conversion failed'
        Assert-GroupInventory ($script:Trace.Count -eq 6 -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $before) 'Serialization failure replaced previous bytes.'
    }
    Test-GroupInventoryCase 'failed atomic promotion preserves local data and cleans staging' {
        $folder = Join-Path $script:Temp 'directory [existing].csv'
        $null = [IO.Directory]::CreateDirectory($folder)
        $marker = Join-Path $folder 'retain'
        [IO.File]::WriteAllText($marker, 'retain')
        Reset-GroupInventoryTrace
        Assert-GroupInventoryFailure { $owner.Export(@('RootA'), $folder) }
        Assert-GroupInventory ($script:Trace.Count -eq 6 -and [IO.File]::ReadAllText($marker) -ceq 'retain' -and
            [IO.Directory]::GetFiles($script:Temp, '.ad-analyzer-*.tmp').Count -eq 0) 'Failed promotion changed files or left staging.'
    }
}

function Invoke-GroupInventoryIsolationCases {
    $script:Route = 'Direct'
    $expected = Get-GroupInventoryJson ($owner.Collect(@('RootA', 'RootB')))
    if ($RunspaceWorker) {
        Assert-GroupInventory ($script:Imports -eq 1 -and @(Get-GroupInventoryRequests Object).Count -eq 5) (
            'Fresh runspace did not independently acquire and traverse the provider.'
        )
        $expected
        return
    }
    Test-GroupInventoryCase 'fresh calls and instances do not retain raw object, credentials or mutable projections' {
        Reset-GroupInventoryTrace $script:FixtureServer $script:Credential
        $rows = $owner.Collect(@('RootA', 'RootB'), $script:FixtureServer, $script:Credential)
        Assert-GroupInventoryGraph $rows
        $rows[0].'member.SamAccountName' = 'mutated result only'
        $other = [ADAnalyzerGroupInventory]::new()
        $script:ResolvedA.SamAccountName = 'Changed provider observation'
        foreach ($instance in $other, $owner) {
            Reset-GroupInventoryTrace
            $actual = $instance.Collect(@('RootA', 'RootB'))
            Assert-GroupInventory ($actual.Count -eq 12 -and $actual[4].'member.SamAccountName' -ceq 'Changed provider observation' -and
                $actual[0].'member.SamAccountName' -ceq 'Child observation 1' -and
                @(Get-GroupInventoryRequests Object).Count -eq 5 -and
                [Management.Automation.PSSerializer]::Serialize($instance) -cnotmatch 'FIXTURE\\group-inventory|PSCredential') (
                'Cache entries, credentials or modified result rows persisted across calls.'
            )
        }
        $script:ResolvedA.SamAccountName = 'Resolved RootA'
    }
    Test-GroupInventoryCase 'secondary runspace disposal leaves the original isolated graph usable' {
        $shell = [powershell]::Create()
        try {
            $worker = @'
param($Fixture, $Root)
& $Fixture -RepositoryRoot $Root -Mode Isolation -RunspaceWorker
'@
            $call = $shell.AddScript($worker).AddArgument($PSCommandPath).AddArgument($RepositoryRoot)
            $rows = @($call.Invoke())
            Assert-GroupInventory (-not $shell.HadErrors -and $rows.Count -eq 1 -and
                [string]$rows[0] -ceq $expected) ('Secondary runspace failed: ' + ($shell.Streams.Error -join ' | '))
        }
        finally {
            $shell.Dispose()
        }
        Reset-GroupInventoryTrace
        $result = $owner.Collect(@('RootA', 'RootB'))
        Assert-GroupInventoryGraph $result
        Assert-GroupInventory ((Get-GroupInventoryJson $result) -ceq $expected) 'Original owner failed after another runspace was disposed.'
    }
}

$initialLocation = (Get-Location).Path
$Server = 'caller-server'
$OutputPath = 'caller-path'
$Array = @('caller-group')
$loaded = @(. (Join-Path $RepositoryRoot 'etc/Get-GroupCNMember.ps1'))
$owner = [ADAnalyzerGroupInventory]::new()
Assert-GroupInventory ($loaded.Count -eq 0 -and $script:Imports -eq 0 -and $script:Trace.Count -eq 0) 'Load or constructor performed work.'

$script:Temp = Join-Path ([IO.Path]::GetTempPath()) ('ad-group-inventory-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Temp)
try {
    switch ($Mode) {
        'Construction' { Invoke-GroupInventoryConstructionCases }
        'Traversal' { Invoke-GroupInventoryTraversalCases }
        'Failures' { Invoke-GroupInventoryFailureCases }
        'Export' { Invoke-GroupInventoryExportCases }
        'Isolation' { Invoke-GroupInventoryIsolationCases }
    }
    Assert-GroupInventory ($script:ForeignCalls -eq 0 -and (Get-Location).Path -ceq $initialLocation) 'Fixture crossed its external boundary or changed location.'
    if (-not $RunspaceWorker) {
        'PASS AD group inventory class {0} {1}' -f $Mode, $script:Passed
    }
}
finally {
    [IO.Directory]::Delete($script:Temp, $true)
}
