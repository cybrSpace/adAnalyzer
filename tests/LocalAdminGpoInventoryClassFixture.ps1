[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Construction', 'Analysis', 'Export', 'Isolation', 'Collection')]
    [string]$Mode,
    [switch]$RunspaceWorker,
    [string]$SharedPolicyPath,
    [string]$SharedProfilePath
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$entry = Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1'
$script:Passed = 0
$script:ForeignCalls = 0
$script:ProviderAllowed = $false
$script:Trace = [Collections.Generic.List[object]]::new()
$script:OwnedDrives = @{}
$script:DomainName = 'inventory.fixture.invalid'
$script:DomainDn = 'DC=inventory,DC=fixture,DC=invalid'
$script:RequestedServer = 'alias.' + $script:DomainName
$script:PinnedServer = 'dc.' + $script:DomainName
$script:SysvolRoot = '\\{0}\SYSVOL' -f $script:PinnedServer
$script:ProviderDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Credential = [pscredential]::new('FIXTURE\inventory', [Security.SecureString]::new())
$script:Secret = 'U145_TEST_ONLY_MARKER'
$script:Ids = @(
    [guid]'11111111-1111-4111-8111-111111111111'
    [guid]'22222222-2222-4222-8222-222222222222'
    [guid]'33333333-3333-4333-8333-333333333333'
)

function Assert-Inventory($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-InventoryJson($Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 42 -Compress
}

function Test-InventoryFixture([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('Failed local-admin GPO inventory fixture: ' + $Name)
        throw
    }
}

function Assert-InventoryThrows([scriptblock]$Operation, [string]$Pattern = '.+') {
    $failure = $null
    try {
        & $Operation | Out-Null
    }
    catch {
        $failure = $_
    }
    Assert-Inventory ($null -ne $failure) 'The operation unexpectedly succeeded.'
    Assert-Inventory ($failure.Exception.Message -match $Pattern) ('Unexpected failure: ' + $failure.Exception.Message)
}

function Write-InventoryText([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function New-InventoryPolicy([string]$Root, [bool]$WithSecret) {
    $groups = Join-Path $Root 'Machine/Preferences/Groups'
    $null = [IO.Directory]::CreateDirectory($groups)
    Write-InventoryText (Join-Path $Root 'GPT.INI') ("[General]" + [Environment]::NewLine + 'Version=1')
    $xml = '<Groups><Group uid="fixture-group"><Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators"><Members><Member action="ADD" sid="S-1-5-18"/></Members></Properties></Group>'
    if ($WithSecret) {
        $xml += '<User uid="fixture-user"><Properties action="U" cpassword="' + $script:Secret + '"/></User>'
    }
    Write-InventoryText (Join-Path $groups 'Groups.xml') ($xml + '</Groups>')
}

function New-InventoryMetadata([int]$Index = 0) {
    [pscustomobject][ordered]@{
        Id = $script:Ids[$Index]
        DisplayName = 'Inventory fixture ' + $Index
        Domain = $script:DomainName
        Server = $script:PinnedServer
        Flags = 0
        Version = 1
        Links = @(
            [pscustomobject]@{
                SOMPath = 'OU=Fixture,' + $script:DomainDn
                Enabled = $true
                Enforced = $false
                StoredLinkIndex = 0
                BlockInheritance = $false
            }
        )
        WmiFilter = $null
    }
}

function New-InventoryPacket([string]$Root, [int]$Index = 0) {
    . (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
    $readerType = [type]'ADAnalyzerGpoReader'
    $reader = $readerType::new()
    [pscustomobject][ordered]@{
        Gpo = New-InventoryMetadata $Index
        Policy = $reader.Read($Root)
        VersionMismatch = $false
    }
}

function Get-InventoryDependencies {
    $definitions = [ordered]@{}
    foreach ($name in 'Read-ADAnalyzerGpo', 'Test-ADAnalyzerGpoPolicy', 'New-ADAnalyzerCheck', 'ConvertTo-ADAnalyzerSafeData') {
        $command = Get-Command -Name $name -CommandType Function -ListImported -ErrorAction SilentlyContinue
        if ($command) {
            $definitions[$name] = $command.ScriptBlock
        }
    }
    foreach ($name in 'ADAnalyzerGpoReader', 'ADAnalyzerGpoSourceNormalizer', 'ADAnalyzerProfile',
        'ADAnalyzerGpoPolicyEvaluator', 'ADAnalyzerEvidenceProjector', 'ADAnalyzerAssessmentReport') {
        $type = $name -as [type]
        if ($type) {
            $definitions[$name] = $type
        }
    }
    return $definitions
}

function Assert-InventoryDependencies($Expected) {
    $actual = Get-InventoryDependencies
    Assert-Inventory ($actual.Count -eq $Expected.Count) 'Unexpected definitions reached the caller.'
    foreach ($name in $Expected.Keys) {
        Assert-Inventory ([object]::ReferenceEquals($Expected[$name], $actual[$name])) ('Replaced caller definition: ' + $name)
    }
}

function Deny-InventoryExternalCall {
    $script:ForeignCalls++
    throw 'Unexpected provider, network or compatibility command.'
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru, [switch]$Global)

    if (-not $script:ProviderAllowed) {
        Deny-InventoryExternalCall
    }
    Assert-Inventory ($Name -ceq $script:ProviderDll -and $Scope -ceq 'Local' -and $PassThru -and -not $Global -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'The catalog did not use the exact local packaged provider.'
    $script:Trace.Add([pscustomobject]@{ Step = 'Import' })
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = @{
            'Get-ADRootDSE' = Get-Command Invoke-InventoryMockRootDse -CommandType Function
            'Get-ADDomain' = Get-Command Invoke-InventoryMockDomain -CommandType Function
            'Get-ADObject' = Get-Command Invoke-InventoryMockObject -CommandType Function
        }
    }
}

function Get-ADRootDSE { Deny-InventoryExternalCall }
function Get-ADDomain { Deny-InventoryExternalCall }
function Get-ADObject { Deny-InventoryExternalCall }
function Get-ADAnalyzerGpo { Deny-InventoryExternalCall }
function Get-ADAnalyzerGpoReport { Deny-InventoryExternalCall }
function Get-GPO { Deny-InventoryExternalCall }
function Get-GPOReport { Deny-InventoryExternalCall }
function Invoke-WebRequest { Deny-InventoryExternalCall }
function Invoke-RestMethod { Deny-InventoryExternalCall }
function Invoke-Command { Deny-InventoryExternalCall }

function Add-InventoryQuery([string]$Step, [Collections.Generic.IDictionary[string, object]]$Bound) {
    Assert-Inventory ($script:ProviderAllowed -and $Bound['ErrorAction'] -eq 'Stop') 'Unexpected provider query behavior.'
    $script:Trace.Add([pscustomobject]@{
        Step = $Step
        Server = $Bound['Server']
        CredentialPresent = $Bound.ContainsKey('Credential')
        Credential = $Bound['Credential']
        Identity = $Bound['Identity']
        SearchBase = $Bound['SearchBase']
        LDAPFilter = $Bound['LDAPFilter']
    })
}

function Invoke-InventoryMockRootDse {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Add-InventoryQuery RootDse $PSBoundParameters
    [pscustomobject]@{
        DnsHostName = $script:PinnedServer
        ConfigurationNamingContext = $null
    }
}

function Invoke-InventoryMockDomain {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [string]$Identity)

    Add-InventoryQuery Domain $PSBoundParameters
    [pscustomobject]@{
        DNSRoot = $script:DomainName
        DistinguishedName = $script:DomainDn
    }
}

function Invoke-InventoryMockObject {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [string]$SearchBase, [string]$LDAPFilter, [string[]]$Properties)

    if ($LDAPFilter -ceq '(gPLink=*)') {
        Add-InventoryQuery Links $PSBoundParameters
        return
    }
    Assert-Inventory ($LDAPFilter -ceq '(objectClass=groupPolicyContainer)') 'Unexpected catalog filter.'
    Add-InventoryQuery Policies $PSBoundParameters
    for ($index = 0; $index -lt $script:Ids.Count; $index++) {
        $id = $script:Ids[$index].ToString('B')
        $display = if ($index -eq 0) {
            'Unique fixture'
        }
        else {
            'Duplicate fixture'
        }
        [pscustomobject]@{
            Name = $id
            DisplayName = $display
            DistinguishedName = "CN=$id,CN=Policies,CN=System,$script:DomainDn"
            Flags = 0
            VersionNumber = 1
            gPCFileSysPath = '\\unused.fixture.invalid\stored-only'
            WhenCreated = [datetime]'2020-01-01'
            WhenChanged = [datetime]'2020-02-01'
            gPCWQLFilter = $null
            gPCMachineExtensionNames = $null
            gPCUserExtensionNames = $null
        }
    }
}

function New-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [string]$PSProvider, [string]$Root, [string]$Scope,
        [pscredential]$Credential, [switch]$WhatIf, [switch]$Confirm)

    if (-not $script:ProviderAllowed) {
        Deny-InventoryExternalCall
    }
    Assert-Inventory ($Name -cmatch '^ADGpo[0-9a-f]{32}$' -and $PSProvider -ceq 'FileSystem' -and
        $Scope -ceq 'Local' -and $Root -ceq $script:SysvolRoot -and -not $WhatIf -and -not $Confirm -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop' -and $script:OwnedDrives.Count -eq 0 -and
        [object]::ReferenceEquals($Credential, $script:Credential)) 'SYSVOL selection or credential scope changed.'
    $mount = @{
        Name = $Name
        PSProvider = 'FileSystem'
        Root = $script:LocalSysvol
        Scope = '1'
        ErrorAction = 'Stop'
        WhatIf = $false
        Confirm = $false
    }
    $drive = Microsoft.PowerShell.Management\New-PSDrive @mount
    $script:OwnedDrives[$Name] = $true
    $script:Trace.Add([pscustomobject]@{ Step = 'Mount' })
    return $drive
}

function Remove-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)

    $owned = Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -Scope '1' -ErrorAction Stop
    Assert-Inventory ($script:OwnedDrives.ContainsKey($Name) -and $owned.Root -ceq $script:LocalSysvol -and
        $Force -and -not $WhatIf -and -not $Confirm -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Wrong SYSVOL lease cleanup.'
    Microsoft.PowerShell.Management\Remove-PSDrive -Scope '1' @PSBoundParameters
    $script:OwnedDrives.Remove($Name)
    $script:Trace.Add([pscustomobject]@{ Step = 'Remove' })
}

function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)

    if ($LiteralPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        if (-not $script:ProviderAllowed) {
            Deny-InventoryExternalCall
        }
        foreach ($id in $script:Ids) {
            $relative = '{0}\Policies\{1}' -f $script:DomainName, $id.ToString('B')
            if ($LiteralPath -ceq ($script:SysvolRoot + '\' + $relative)) {
                $script:Trace.Add([pscustomobject]@{
                    Step = 'ReadAmbient'
                    Id = $id
                })
                $local = Join-Path $script:LocalSysvol ($relative.Replace('\', '/'))
                return Microsoft.PowerShell.Management\Get-Item -LiteralPath $local -Force -ErrorAction Stop
            }
        }
        Deny-InventoryExternalCall
    }
    foreach ($name in $script:OwnedDrives.Keys) {
        if ($LiteralPath.StartsWith($name + ':', [StringComparison]::OrdinalIgnoreCase) -and $LiteralPath.EndsWith('}')) {
            $id = [guid]($LiteralPath.Substring($LiteralPath.LastIndexOf('{')))
            $script:Trace.Add([pscustomobject]@{
                Step = 'ReadOwned'
                Id = $id
            })
        }
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}

function Assert-InventoryTrace([string]$Steps, [string]$InitialServer, [bool]$WithCredential) {
    $actual = @($script:Trace | ForEach-Object Step) -join ','
    Assert-Inventory ($actual -ceq $Steps) ('Unexpected catalog or SYSVOL order: ' + $actual)
    Assert-Inventory ($script:Trace[1].Server -ceq $InitialServer -and
        $script:Trace[2].Identity -ceq $script:DomainName -and
        $script:Trace[3].SearchBase -ceq ('CN=Policies,CN=System,' + $script:DomainDn) -and
        $script:Trace[4].SearchBase -ceq $script:DomainDn) 'Catalog request selection changed.'
    for ($index = 1; $index -le 4; $index++) {
        $event = $script:Trace[$index]
        Assert-Inventory ($event.CredentialPresent -eq $WithCredential) 'Credential binding presence changed.'
        if ($WithCredential) {
            Assert-Inventory ([object]::ReferenceEquals($event.Credential, $script:Credential)) 'Credential identity changed.'
        }
        if ($index -gt 1) {
            Assert-Inventory ($event.Server -ceq $script:PinnedServer) 'A query lost the selected DC.'
        }
    }
    Assert-Inventory ($script:OwnedDrives.Count -eq 0) 'A SYSVOL drive remained owned after return.'
}

function Invoke-InventoryConstructionCases {
    Test-InventoryFixture 'owner-only constructor has no package dependencies' {
        Assert-Inventory ($before.Count -eq 0 -and $null -eq $beforeClr -and
            $owner.GetType().Name -ceq 'ADAnalyzerLocalAdminPolicyInventory') 'The fresh process already had package state.'
    }
    Test-InventoryFixture 'both standalone scripts can be dot-loaded without initialization' {
        $xmlLoaded = @(. (Join-Path $RepositoryRoot 'etc/Get-GPOXML.ps1'))
        Assert-Inventory ($xmlLoaded.Count -eq 0 -and
            $null -ne (Get-Command Get-ADAnalyzerGpoXml -CommandType Function)) 'The other standalone GPO script did not load inertly.'
        Assert-InventoryDependencies $before
    }
    Test-InventoryFixture 'explicit empty analysis preserves the caller scope' {
        $empty = $owner.AnalyzeProvided([object[]]@())
        Assert-Inventory ($empty -is [object[]] -and $empty.Count -eq 0) 'Expected an empty result array.'
        Assert-InventoryDependencies $before
    }
}

function Invoke-InventoryAnalysisCases {
    $root = Join-Path $script:Temporary 'policy [one]'
    New-InventoryPolicy $root $true
    $packet = New-InventoryPacket $root
    $packetJson = Get-InventoryJson $packet
    Test-InventoryFixture 'real policy produces native ordered inventory and presence-only rows' {
        $native = @(Get-ADAnalyzerLocalAdminGpo -InputObject @($packet))
        $direct = $owner.AnalyzeProvided(@($packet))
        Assert-Inventory ($direct -is [object[]] -and $direct.Count -ge 3 -and
            (Get-InventoryJson $direct) -ceq (Get-InventoryJson $native)) 'Stored policy inventory differs from the command.'
        $group = @($direct | Where-Object { $_.Evidence.ConfiguredSetting.Uid -ceq 'fixture-group' })
        Assert-Inventory ($group.Count -eq 1 -and $group[0].Evidence.ConfiguredSetting.Members[0].Sid -ceq 'S-1-5-18' -and
            $group[0].MetadataStatus -ceq 'Provided' -and $group[0].GpoId -ceq $packet.Gpo.Id.ToString('D')) (
            'Configured membership or GPO identity was lost.'
        )
        $secret = @($direct | Where-Object RuleId -eq 'GPO.Preferences.CPassword')
        Assert-Inventory ($secret.Count -eq 1 -and $secret[0].Status -ceq 'Fail' -and
            $secret[0].Evidence.ConfiguredSetting -is [bool] -and $secret[0].Evidence.ConfiguredSetting -and
            (Get-InventoryJson $direct) -cnotmatch $script:Secret) 'Expected only the credential presence result.'
    }
    Test-InventoryFixture 'JSON package round-trip retains inventory' {
        $decoded = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $packetJson
        Assert-Inventory ((Get-InventoryJson ($owner.AnalyzeProvided(@($decoded)))) -ceq
            (Get-InventoryJson ($owner.AnalyzeProvided(@($packet))))) 'JSON report normalization changed the results.'
    }
    Test-InventoryFixture 'strict healthy and unreadable packets coexist' {
        Set-StrictMode -Version Latest
        $unreadable = [pscustomobject]@{
            Gpo = New-InventoryMetadata 1
            Policy = $null
            ReadError = $true
        }
        $rows = $owner.AnalyzeProvided(@($packet, $unreadable))
        $last = $rows[$rows.Count - 1]
        Assert-Inventory ($last.RuleId -ceq 'GPO.READ' -and $last.Status -ceq 'Unreadable' -and
            $null -eq $last.Evidence.RuleEvidence.ErrorType -and
            @($rows | Where-Object GpoName -eq $packet.Gpo.DisplayName).Count -ge 3) 'Strict optional read metadata discarded results.'
    }
    Test-InventoryFixture 'null and malformed required inputs fail locally' {
        Assert-InventoryThrows { $owner.AnalyzeProvided($null) }
        $bad = New-InventoryPacket $root
        $bad.Gpo.Id = 'not-a-guid'
        Assert-InventoryThrows { $owner.AnalyzeProvided(@($bad)) } '(?i)identity|guid'
        foreach ($flags in -1, 4, 'bad') {
            $bad = New-InventoryPacket $root
            $bad.Gpo.Flags = $flags
            Assert-InventoryThrows { $owner.AnalyzeProvided(@($bad)) } '(?i)flags'
        }
    }
    Test-InventoryFixture 'late required packet fault emits no partial inventory' {
        Set-StrictMode -Version Latest
        $bad = [pscustomobject]@{
            Gpo = New-InventoryMetadata 1
            ReadError = $false
        }
        $received = [Collections.Generic.List[object]]::new()
        Assert-InventoryThrows {
            $owner.AnalyzeProvided(@($packet, $bad)) | ForEach-Object { $received.Add($_) }
        } '(?i)policy'
        Assert-Inventory ($received.Count -eq 0) 'Rows escaped before the late required failure.'
    }
    Test-InventoryFixture 'literal profile changes the same applicability as the command' {
        $path = Join-Path $script:Temporary 'profile [one].json'
        Write-InventoryText $path '{"Analysis":{"AssumeGpoApplicable":true}}'
        $beforeProfile = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $native = @(Get-ADAnalyzerLocalAdminGpo -InputObject @($packet) -ProfilePath $path)
        $rows = $owner.AnalyzeProvided(@($packet), $path)
        $ordinary = $owner.AnalyzeProvided(@($packet))
        Assert-Inventory ((Get-InventoryJson $rows) -ceq (Get-InventoryJson $native) -and
            (Get-InventoryJson $rows) -cne (Get-InventoryJson $ordinary) -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $beforeProfile) 'Explicit profile was ignored or modified.'
        Write-InventoryText $path '$'
        Assert-InventoryThrows { $owner.AnalyzeProvided(@($packet), $path) }
    }
    Test-InventoryFixture 'results cannot mutate packet, sibling metadata, or later results' {
        $rows = $owner.AnalyzeProvided(@($packet))
        $expected = Get-InventoryJson $rows
        $rows[0].Evidence.Gpo.Links[0].SOMPath = 'changed result only'
        Assert-Inventory ((Get-InventoryJson $packet) -ceq $packetJson -and
            $rows[1].Evidence.Gpo.Links[0].SOMPath -ceq ('OU=Fixture,' + $script:DomainDn) -and
            (Get-InventoryJson ($owner.AnalyzeProvided(@($packet)))) -ceq $expected) 'Returned evidence was aliased.'
    }
}

function Invoke-InventoryExportCases {
    $root = Join-Path $script:Temporary 'policy'
    New-InventoryPolicy $root $false
    $packet = New-InventoryPacket $root
    $rows = $owner.AnalyzeProvided(@($packet))
    Test-InventoryFixture 'all formats produce safe output with original order' {
        $path = Join-Path $script:Temporary 'report [literal]'
        $rows[0].Evidence | Add-Member -NotePropertyName Password -NotePropertyValue $script:Secret
        $paths = $owner.Export($rows, 'fixture target', $path, 'All')
        Assert-Inventory ($paths -is [string[]] -and
            ($paths -join '|') -ceq ("$path.json|$path.html|$path.csv")) 'Output paths or format order changed.'
        foreach ($created in $paths) {
            $text = [IO.File]::ReadAllText($created)
            Assert-Inventory ($text.Length -gt 0 -and $text -cnotmatch $script:Secret) 'An output was empty or exposed the marker.'
        }
        $snapshot = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($paths[0]))
        Assert-Inventory ($snapshot.SchemaVersion -eq 1 -and $snapshot.Target -ceq 'fixture target' -and
            $snapshot.State -ceq 'Complete' -and $snapshot.Coverage.Total -eq $rows.Count -and
            $snapshot.Checks.Count -eq $rows.Count -and $snapshot.Findings.Count -eq $rows.Count -and
            $snapshot.Findings[0].Evidence.PasswordPresent -is [bool] -and $snapshot.Findings[0].Evidence.PasswordPresent) (
            'The serialized assessment envelope lost presence or completeness.'
        )
        Assert-Inventory ($rows[0].Evidence.Password -ceq $script:Secret) 'Export changed the caller rows.'
    }
    Test-InventoryFixture 'dry-run reports no paths and does not create folders' {
        $directory = Join-Path $script:Temporary 'dry-run'
        $paths = $owner.Export($rows, 'fixture target', (Join-Path $directory 'report'), 'All', $true)
        Assert-Inventory ($paths -is [string[]] -and $paths.Count -eq 0 -and
            -not [IO.Directory]::Exists($directory)) 'Dry run reported or created files.'
    }
    Test-InventoryFixture 'unreadable blocks normal and dry-run export while preserving bytes' {
        $path = Join-Path $script:Temporary 'previous.json'
        Write-InventoryText $path 'prior report'
        $unreadable = [pscustomobject]@{
            Gpo = New-InventoryMetadata 1
            Policy = $null
            ReadError = $true
        }
        $mixed = $owner.AnalyzeProvided(@($packet, $unreadable))
        foreach ($dryRun in $false, $true) {
            Assert-InventoryThrows { $owner.Export($mixed, 'fixture target', $path, 'Json', $dryRun) } '(?i)incomplete|unreadable'
        }
        Assert-Inventory ([IO.File]::ReadAllText($path) -ceq 'prior report') 'Unreadable inventory replaced the previous report.'
    }
    Test-InventoryFixture 'unknown rows retain a Partial snapshot' {
        $partial = $owner.AnalyzeProvided(@($packet))
        $partial[0].Status = 'Unknown'
        $path = Join-Path $script:Temporary 'partial.json'
        $null = $owner.Export($partial, 'partial fixture', $path, 'Json')
        $snapshot = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($path))
        Assert-Inventory ($snapshot.State -ceq 'Partial' -and $snapshot.Checks[0].Status -ceq 'Unknown') 'Partial inventory was misclassified.'
    }
    Test-InventoryFixture 'empty CSV retains the exact headers' {
        $path = Join-Path $script:Temporary 'empty.csv'
        $null = $owner.Export([object[]]@(), 'empty fixture', $path, 'Csv')
        Assert-Inventory ([IO.File]::ReadAllText($path).Trim() -ceq '"RuleId","Target","Status","Severity","Evidence"') (
            'Empty inventory lost CSV headers.'
        )
    }
}

function Invoke-InventoryIsolationCases {
    $root = $SharedPolicyPath
    $profilePath = $SharedProfilePath
    if (-not $RunspaceWorker) {
        $root = Join-Path $script:Temporary 'policy'
        New-InventoryPolicy $root $false
        $profilePath = Join-Path $script:Temporary 'profile [isolation].json'
        Write-InventoryText $profilePath '{"Analysis":{"AssumeGpoApplicable":true}}'
    }
    $packet = New-InventoryPacket $root
    $expected = Get-InventoryJson ($owner.AnalyzeProvided(@($packet)))
    $expectedWithProfile = Get-InventoryJson ($owner.AnalyzeProvided(@($packet), $profilePath))
    Assert-InventoryDependencies $before
    if ($RunspaceWorker) {
        $expected
        $expectedWithProfile
        return
    }
    Test-InventoryFixture 'reuse and independent instances are stateless' {
        function Get-ADAnalyzerLocalAdminGpo { Deny-InventoryExternalCall }
        $ownerResult = $owner.AnalyzeProvided(@($packet))
        $ownerResult[0].Status = 'mutated'
        $other = [ADAnalyzerLocalAdminPolicyInventory]::new()
        Assert-Inventory ((Get-InventoryJson ($owner.AnalyzeProvided(@($packet)))) -ceq $expected -and
            (Get-InventoryJson ($other.AnalyzeProvided(@($packet)))) -ceq $expected) 'Inventory instances accumulated state.'
        Assert-InventoryDependencies $before
    }
    Test-InventoryFixture 'preloaded package definitions keep their references' {
        . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
        $preloaded = Get-InventoryDependencies
        Assert-Inventory ($preloaded.Count -eq 10) 'Preloaded caller test did not load the intended definitions.'
        Assert-Inventory ((Get-InventoryJson ($owner.AnalyzeProvided(@($packet)))) -ceq $expected) 'Preloading changed inventory results.'
        Assert-InventoryDependencies $preloaded
    }
    Test-InventoryFixture 'reuse survives loading and disposing a secondary runspace' {
        $shell = [powershell]::Create()
        try {
            $body = @'
param($Fixture, $Root, $LocalPolicy, $LocalProfile)
& $Fixture -RepositoryRoot $Root -Mode Isolation -RunspaceWorker -SharedPolicyPath $LocalPolicy -SharedProfilePath $LocalProfile
'@
            $invocation = $shell.AddScript($body).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).AddArgument($root)
            $null = $invocation.AddArgument($profilePath)
            $returned = @($invocation.Invoke())
            Assert-Inventory (-not $shell.HadErrors -and $returned.Count -eq 2 -and
                [string]$returned[0] -ceq $expected -and [string]$returned[1] -ceq $expectedWithProfile) (
                'Secondary runspace failed: ' + ($shell.Streams.Error -join ' | ')
            )
        }
        finally {
            $shell.Dispose()
        }
        Assert-Inventory ((Get-InventoryJson ($owner.AnalyzeProvided(@($packet)))) -ceq $expected -and
            (Get-InventoryJson ($owner.AnalyzeProvided(@($packet), $profilePath))) -ceq $expectedWithProfile) (
            'The original instance failed after runspace disposal.'
        )
        Assert-InventoryDependencies $before
    }
}

function Invoke-InventoryCollectionCases {
    $script:LocalSysvol = Join-Path $script:Temporary 'local-sysvol'
    foreach ($index in 0, 2) {
        $leaf = '{0}/Policies/{1}' -f $script:DomainName, $script:Ids[$index].ToString('B')
        New-InventoryPolicy (Join-Path $script:LocalSysvol $leaf) $false
    }
    $profilePath = Join-Path $script:Temporary 'late [profile].json'
    $catalogTrace = 'Import,RootDse,Domain,Policies,Links'
    Test-InventoryFixture 'invalid selection is rejected before provider access' {
        foreach ($selection in @(
                @{ Name = 'Unique fixture' }
                @{ Domain = $script:DomainName }
                @{ Domain = $script:DomainName; Name = 'Unique fixture'; All = $true }
                @{ Domain = $script:DomainName; Name = ' ' }
                @{ Domain = $script:DomainName; Guid = 'not-a-guid' }
                @{ Domain = $script:DomainName; All = 'true' }
                @{ Domain = $script:DomainName; All = $false }
                @{ Domain = $script:DomainName; All = $true; Keys = @() }
            )) {
            Assert-InventoryThrows { $owner.Collect($selection) }
        }
        Assert-Inventory ($script:Trace.Count -eq 0 -and $script:ForeignCalls -eq 0) 'Invalid input reached an external boundary.'
    }
    $script:ProviderAllowed = $true
    Test-InventoryFixture 'explicit name collection pins the server and owns the credentialed SYSVOL drive' {
        $script:Trace.Clear()
        $selection = @{
            Domain = $script:DomainName
            Server = $script:RequestedServer
            Name = 'Unique fixture'
        }
        $saved = Get-InventoryJson $selection
        $rows = $owner.Collect($selection, $script:Credential)
        Assert-InventoryTrace ($catalogTrace + ',Mount,ReadOwned,Remove') $script:RequestedServer $true
        Assert-Inventory ($rows.Count -ge 3 -and
            @($rows | Where-Object { $_.MetadataStatus -cne 'Collected' -or $_.GpoId -cne $script:Ids[0].ToString('D') }).Count -eq 0 -and
            $rows[0].Evidence.Gpo.Server -ceq $script:PinnedServer -and
            (Get-InventoryJson $selection) -ceq $saved) 'Direct name collection lost catalog identity or mutated its selection.'
    }
    Test-InventoryFixture 'guid selection uses the domain default and ambient authentication' {
        $script:Trace.Clear()
        $rows = $owner.Collect(@{ Domain = $script:DomainName; Guid = $script:Ids[2] })
        Assert-InventoryTrace ($catalogTrace + ',ReadAmbient') $script:DomainName $false
        Assert-Inventory ($rows.Count -ge 3 -and $rows[0].GpoId -ceq $script:Ids[2].ToString('D') -and
            $script:Trace[5].Id -eq $script:Ids[2]) 'GUID selection returned the wrong policy.'
    }
    Test-InventoryFixture 'all retains ordinal healthy siblings and recovers a missing SYSVOL policy' {
        $script:Trace.Clear()
        $rows = $owner.Collect(@{ Domain = $script:DomainName; All = $true }, $script:Credential)
        Assert-InventoryTrace ($catalogTrace + ',Mount,ReadOwned,Remove,Mount,ReadOwned,Remove,Mount,ReadOwned,Remove') $script:DomainName $true
        $issues = @($rows | Where-Object RuleId -eq 'GPO.READ')
        $gpos = @($rows | ForEach-Object GpoId | Select-Object -Unique)
        Assert-Inventory ($issues.Count -eq 1 -and $issues[0].GpoId -ceq $script:Ids[1].ToString('D') -and
            $issues[0].Status -ceq 'Unreadable' -and
            $issues[0].Evidence.RuleEvidence.ErrorType -ceq 'System.Management.Automation.ItemNotFoundException' -and
            ($gpos -join '|') -ceq ($script:Ids -join '|')) 'Failed policy did not produce honest ordered recovery evidence.'
    }
    Test-InventoryFixture 'missing or ambiguous name never reads SYSVOL' {
        foreach ($name in 'No such fixture', 'Duplicate fixture') {
            $script:Trace.Clear()
            Assert-InventoryThrows {
                $owner.Collect(@{ Domain = $script:DomainName; Name = $name }, $script:Credential)
            } '(?i)not found|ambiguous'
            Assert-InventoryTrace $catalogTrace $script:DomainName $true
        }
    }
    Test-InventoryFixture 'profile validation follows scoped acquisition and successful cleanup' {
        $script:Trace.Clear()
        Write-InventoryText $profilePath '$'
        $selection = @{ Domain = $script:DomainName; Name = 'Unique fixture' }
        Assert-InventoryThrows { $owner.Collect($selection, $script:Credential, $profilePath) }
        Assert-InventoryTrace ($catalogTrace + ',Mount,ReadOwned,Remove') $script:DomainName $true
        Write-InventoryText $profilePath '{"Analysis":{"AssumeGpoApplicable":true}}'
        $script:Trace.Clear()
        $next = $owner.Collect($selection, $script:Credential, $profilePath)
        Assert-InventoryTrace ($catalogTrace + ',Mount,ReadOwned,Remove') $script:DomainName $true
        Assert-Inventory ($next.Count -ge 3) 'Profile failure affected a subsequent valid collection.'
    }
}

$originalLocation = (Get-Location).Path
$before = Get-InventoryDependencies
$beforeClr = 'ADAnalyzer.ConfigurationState' -as [type]
$loaded = @(. $entry)
$owner = [ADAnalyzerLocalAdminPolicyInventory]::new()
Assert-Inventory ($loaded.Count -eq 0 -and $script:ForeignCalls -eq 0 -and $script:Trace.Count -eq 0 -and
    (Get-Location).Path -ceq $originalLocation) 'Dot loading or construction was not inert.'
Assert-InventoryDependencies $before
Assert-Inventory ([object]::ReferenceEquals($beforeClr, ('ADAnalyzer.ConfigurationState' -as [type]))) (
    'Dot loading or construction initialized profile dependencies.'
)

$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-local-inventory-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Temporary)
try {
    switch ($Mode) {
        'Construction' { Invoke-InventoryConstructionCases }
        'Analysis' { Invoke-InventoryAnalysisCases }
        'Export' { Invoke-InventoryExportCases }
        'Isolation' { Invoke-InventoryIsolationCases }
        'Collection' { Invoke-InventoryCollectionCases }
    }
    Assert-Inventory ($script:ForeignCalls -eq 0 -and $script:OwnedDrives.Count -eq 0 -and
        (Get-Location).Path -ceq $originalLocation) 'A fixture crossed an external boundary or leaked location or ownership.'
    if (-not $RunspaceWorker) {
        'PASS local-admin GPO inventory class {0} {1}' -f $Mode, $script:Passed
    }
}
finally {
    [IO.Directory]::Delete($script:Temporary, $true)
}
