[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Construction', 'OtherFirst', 'Render', 'Export', 'Isolation', 'Collection')]
    [string]$Mode,
    [switch]$RunspaceWorker,
    [string]$SharedPolicyPath
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:Passed = 0
$script:Unexpected = 0
$script:PermitProvider = $false
$script:Events = [Collections.Generic.List[string]]::new()
$script:Mount = $null
$script:DomainName = 'xml.fixture.invalid'
$script:DomainDn = 'DC=xml,DC=fixture,DC=invalid'
$script:Alias = 'alias.' + $script:DomainName
$script:Pinned = 'dc.' + $script:DomainName
$script:Share = '\\{0}\SYSVOL' -f $script:Pinned
$script:Dll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Credential = [pscredential]::new('FIXTURE\xml', [Security.SecureString]::new())
$script:FixtureDisplayName = 'XML fixture <A & "B">'
$script:Marker = 'U146_TEST_ONLY_PRESENT'
$script:Ids = @(
    [guid]'11111111-1111-4111-8111-111111111111'
    [guid]'22222222-2222-4222-8222-222222222222'
    [guid]'33333333-3333-4333-8333-333333333333'
)

function Assert-XmlInventory($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-XmlInventory([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('Failed GPO XML inventory fixture: ' + $Name)
        throw
    }
}

function Assert-XmlInventoryFailure([scriptblock]$Body, [string]$Pattern = '.+') {
    $rows = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-XmlInventory ($null -ne $failure -and $rows.Count -eq 0) 'Expected a failure with no output.'
    Assert-XmlInventory ($failure.Exception.Message -match $Pattern) ('Unexpected failure: ' + $failure.Exception.Message)
}

function Get-XmlFingerprint([string]$Text) {
    Assert-XmlInventory ($Text -cmatch '^<\?xml version="1\.0" encoding="utf-8"\?>') 'Canonical UTF-8 XML declaration is required.'
    $document = [xml]$Text
    $time = $document.SelectSingleNode('/GPO/ReadTime')
    $parsed = [datetimeoffset]::MinValue
    Assert-XmlInventory ($null -ne $time -and [datetimeoffset]::TryParse($time.InnerText, [ref]$parsed)) 'Missing canonical GPO read time.'
    return $Text -replace '(?<=<ReadTime>)[^<]*(?=</ReadTime>)', 'fixture-time'
}

function Get-XmlFixtureJson($Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 35 -Compress
}

function Write-XmlFixtureText([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Get-FixtureGroupsXml {
    '<Groups><Group uid="fixture-group"><Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators" cpassword="' +
        $script:Marker + '"><Members><Member action="ADD" sid="S-1-5-18"/></Members></Properties></Group></Groups>'
}

function New-XmlPolicy([string]$Root) {
    $groups = Join-Path $Root 'Machine/Preferences/Groups'
    $null = [IO.Directory]::CreateDirectory($groups)
    Write-XmlFixtureText (Join-Path $Root 'GPT.INI') ("[General]" + [Environment]::NewLine + 'Version=1')
    Write-XmlFixtureText (Join-Path $groups 'Groups.xml') (Get-FixtureGroupsXml)
}

function New-XmlPacket([string]$Root) {
    . (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
    $readerType = [type]'ADAnalyzerGpoReader'
    $policy = $readerType::new().Read($Root)
    $policy.XmlFiles[0].Xml = Get-FixtureGroupsXml
    $policy.RegistrySettings = @(
        [pscustomobject]@{
            Scope = 'Computer'
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Bytes'
            Type = 3
            Value = [byte[]]@(1, 2)
            Source = 'Machine/Registry.pol'
            KeyOnly = $false
        }
    )
    [pscustomobject]@{
        Gpo = [pscustomobject][ordered]@{
            Id = $script:Ids[0]
            DisplayName = $script:FixtureDisplayName
            Domain = $script:DomainName
            Server = $script:Pinned
            Flags = 0
            Version = 1
            Links = @()
            WmiFilter = $null
        }
        Policy = $policy
        VersionMismatch = $false
    }
}

function Assert-XmlPresence([string]$Text) {
    Assert-XmlInventory (-not $Text.Contains($script:Marker) -and
        -not $Text.Contains([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:Marker)))) 'Raw marker leaked into XML.'
    $document = [xml]$Text
    $cell = $document.SelectSingleNode("//ExtensionData[Name='Preferences']/Extension/Record/Value")
    Assert-XmlInventory ($null -ne $cell) 'The parsed Preferences record is absent.'
    $properties = ([xml]($cell.InnerText)).SelectSingleNode('/Groups/Group/Properties')
    Assert-XmlInventory ($null -ne $properties -and -not $properties.HasAttribute('cpassword') -and
        $properties.GetAttribute('cpasswordPresent') -ceq 'true') 'XML credential evidence was not Boolean presence only.'
}

function Get-XmlDependencies {
    $loaded = [ordered]@{}
    foreach ($name in 'Read-ADAnalyzerGpo', 'ConvertTo-AnalyzerGpoXml', 'Write-ADAnalyzerFile') {
        $command = Get-Command -Name $name -CommandType Function -ListImported -ErrorAction SilentlyContinue
        if ($command) {
            $loaded[$name] = $command.ScriptBlock
        }
    }
    foreach ($name in 'ADAnalyzerGpoReader', 'ADAnalyzerGpoSourceNormalizer', 'ADAnalyzerGpoXmlWriter', 'ADAnalyzerGpoReportService') {
        $type = $name -as [type]
        if ($type) {
            $loaded[$name] = $type
        }
    }
    return $loaded
}

function Assert-XmlDependencies($Expected) {
    $actual = Get-XmlDependencies
    Assert-XmlInventory ($Expected.Count -eq $actual.Count) 'Package helper definitions leaked into the caller.'
    foreach ($name in $Expected.Keys) {
        Assert-XmlInventory ([object]::ReferenceEquals($Expected[$name], $actual[$name])) ('Caller definition changed: ' + $name)
    }
}

function Deny-XmlExternalCall {
    $script:Unexpected++
    throw 'Unexpected provider or external command.'
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru, [switch]$Global)

    if (-not $script:PermitProvider) {
        Deny-XmlExternalCall
    }
    Assert-XmlInventory ($Name -ceq $script:Dll -and $Scope -ceq 'Local' -and $PassThru -and -not $Global -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Directory operation did not request the exact bundled commands locally.'
    $script:Events.Add('Import')
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = @{
            'Get-ADRootDSE' = Get-Command Invoke-XmlFixtureRoot -CommandType Function
            'Get-ADDomain' = Get-Command Invoke-XmlFixtureDomain -CommandType Function
            'Get-ADObject' = Get-Command Invoke-XmlFixtureObject -CommandType Function
        }
    }
}

function Get-ADRootDSE { Deny-XmlExternalCall }
function Get-ADDomain { Deny-XmlExternalCall }
function Get-ADObject { Deny-XmlExternalCall }
function Get-ADAnalyzerGpo { Deny-XmlExternalCall }
function Get-ADAnalyzerGpoReport { Deny-XmlExternalCall }
function Get-GPO { Deny-XmlExternalCall }
function Get-GPOReport { Deny-XmlExternalCall }
function Invoke-WebRequest { Deny-XmlExternalCall }
function Invoke-RestMethod { Deny-XmlExternalCall }
function Invoke-Command { Deny-XmlExternalCall }

function Assert-XmlQuery([string]$Step, [string]$Server, $Bound) {
    Assert-XmlInventory ($script:PermitProvider -and $Bound['ErrorAction'] -eq 'Stop' -and
        $Bound['Server'] -ceq $Server -and $Bound.ContainsKey('Credential') -eq $script:ExplicitCredential) 'Provider command lost its server or binding.'
    if ($script:ExplicitCredential) {
        Assert-XmlInventory ([object]::ReferenceEquals($script:Credential, $Bound['Credential'])) 'Provider command lost credential identity.'
    }
    $script:Events.Add($Step)
}

function Invoke-XmlFixtureRoot {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Assert-XmlQuery Root $script:InitialServer $PSBoundParameters
    [pscustomobject]@{ DnsHostName = $script:Pinned; ConfigurationNamingContext = $null }
}

function Invoke-XmlFixtureDomain {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [string]$Identity)

    Assert-XmlQuery Domain $script:Pinned $PSBoundParameters
    Assert-XmlInventory ($Identity -ceq $script:DomainName) 'Wrong catalog domain.'
    [pscustomobject]@{ DNSRoot = $script:DomainName; DistinguishedName = $script:DomainDn }
}

function Invoke-XmlFixtureObject {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential, [string]$SearchBase, [string]$LDAPFilter, [string[]]$Properties)

    if ($LDAPFilter -ceq '(gPLink=*)') {
        Assert-XmlQuery Links $script:Pinned $PSBoundParameters
        Assert-XmlInventory ($SearchBase -ceq $script:DomainDn) 'Wrong link scope.'
        return
    }
    Assert-XmlQuery Policies $script:Pinned $PSBoundParameters
    Assert-XmlInventory ($LDAPFilter -ceq '(objectClass=groupPolicyContainer)' -and
        $SearchBase -ceq ('CN=Policies,CN=System,' + $script:DomainDn)) 'Wrong policy scope.'
    for ($index = 0; $index -lt $script:Ids.Count; $index++) {
        $id = $script:Ids[$index].ToString('B')
        $label = if ($index -eq 0) {
            $script:FixtureDisplayName
        }
        else {
            'Duplicate fixture'
        }
        [pscustomobject]@{
            Name = $id
            DisplayName = $label
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

    if (-not $script:PermitProvider) {
        Deny-XmlExternalCall
    }
    Assert-XmlInventory ($script:ExplicitCredential -and $null -eq $script:Mount -and
        $Name -cmatch '^ADGpo[0-9a-f]{32}$' -and $Root -ceq $script:Share -and
        $PSProvider -ceq 'FileSystem' -and $Scope -ceq 'Local' -and -not $WhatIf -and -not $Confirm -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop' -and
        [object]::ReferenceEquals($Credential, $script:Credential)) 'Unexpected SYSVOL lease.'
    $arguments = @{
        Name = $Name
        PSProvider = 'FileSystem'
        Root = $script:Sysvol
        Scope = '1'
        ErrorAction = 'Stop'
        WhatIf = $false
        Confirm = $false
    }
    $drive = Microsoft.PowerShell.Management\New-PSDrive @arguments
    $script:Mount = $Name
    $script:Events.Add('Mount')
    return $drive
}

function Remove-PSDrive {
    [CmdletBinding()]
    param([string]$Name, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)

    $drive = Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -Scope '1' -ErrorAction Stop
    Assert-XmlInventory ($Name -ceq $script:Mount -and $drive.Root -ceq $script:Sysvol -and
        $Force -and -not $WhatIf -and -not $Confirm -and $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Invalid SYSVOL cleanup.'
    Microsoft.PowerShell.Management\Remove-PSDrive -Scope '1' @PSBoundParameters
    $script:Mount = $null
    $script:Events.Add('Remove')
}

function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)

    if ($LiteralPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        if (-not $script:PermitProvider -or $script:ExplicitCredential) {
            Deny-XmlExternalCall
        }
        $relative = '{0}\Policies\{1}' -f $script:DomainName, $script:Ids[0].ToString('B')
        if ($LiteralPath -cne ($script:Share + '\' + $relative)) {
            Deny-XmlExternalCall
        }
        $script:Events.Add('AmbientRead')
        $local = Join-Path $script:Sysvol ($relative.Replace('\', '/'))
        return Microsoft.PowerShell.Management\Get-Item -LiteralPath $local -Force -ErrorAction Stop
    }
    if ($script:Mount -and $LiteralPath.StartsWith($script:Mount + ':', [StringComparison]::OrdinalIgnoreCase) -and $LiteralPath.EndsWith('}')) {
        $script:Events.Add('MountedRead')
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}

function Invoke-XmlConstructionCases {
    Test-XmlInventory 'owner script and literal construction leave package state untouched' {
        Assert-XmlInventory ($initial.Count -eq 0 -and $owner.GetType().Name -ceq 'ADAnalyzerGpoXmlInventory' -and
            $loads.Count -eq 0 -and $script:Unexpected -eq 0 -and $script:Events.Count -eq 0) 'Standalone bootstrap was not inert.'
        Assert-XmlDependencies $initial
    }
    Test-XmlInventory 'both standalone owners coexist in this load order' {
        if ($Mode -eq 'Construction') {
            $otherLoads = @(. (Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1'))
            Assert-XmlInventory ($otherLoads.Count -eq 0) 'Local-admin script emitted output while loading.'
        }
        $otherOwner = [ADAnalyzerLocalAdminPolicyInventory]::new()
        Assert-XmlInventory ($otherOwner.GetType().Name -ceq 'ADAnalyzerLocalAdminPolicyInventory' -and
            (Get-Command Get-ADAnalyzerGpoXml -CommandType Function) -and
            (Get-Command Get-ADAnalyzerLocalAdminGpo -CommandType Function)) 'The standalone scripts collided.'
        Assert-XmlDependencies $initial
        $packet = New-XmlPacket $policyPath
        Assert-XmlPresence ($owner.RenderProvided($packet))
        Assert-XmlInventory ($otherOwner.AnalyzeProvided(@($packet)).Count -gt 0) 'The second owner could not operate in the same scope.'
        Assert-XmlDependencies $initial
    }
}

function Invoke-XmlRenderCases {
    $packet = New-XmlPacket $policyPath
    Test-XmlInventory 'real local policy yields the same canonical XML as the command and script' {
        $text = $owner.RenderProvided($packet)
        $native = Get-ADAnalyzerGpoXml -InputObject $packet
        $scriptOutput = & (Join-Path $RepositoryRoot 'etc/Get-GPOXML.ps1') -InputObject $packet
        $expected = Get-XmlFingerprint $text
        Assert-XmlInventory ($text -is [string] -and (Get-XmlFingerprint $native) -ceq $expected -and
            (Get-XmlFingerprint $scriptOutput) -ceq $expected) 'Direct, command and script XML differ.'
        $document = [xml]$text
        Assert-XmlInventory ($document.DocumentElement.LocalName -ceq 'GPO' -and
            $document.DocumentElement.SelectSingleNode('Id').InnerText -ceq $script:Ids[0].ToString('D') -and
            $document.DocumentElement.SelectSingleNode('DisplayName').InnerText -ceq $script:FixtureDisplayName -and
            $document.DocumentElement.SelectSingleNode('Flags').InnerText -ceq '0' -and
            $document.DocumentElement.SelectSingleNode('Server').InnerText -ceq $script:Pinned -and
            $text.Contains('&lt;A &amp; "B"&gt;')) 'Decoded metadata or escaping changed.'
    }
    Test-XmlInventory 'JSON report round-trip preserves the typed registry byte value and its input' {
        $json = Get-XmlFixtureJson $packet
        $decoded = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $json
        $originalArray = $decoded.Policy.RegistrySettings[0].Value
        $expectedInput = Get-XmlFixtureJson $decoded
        $text = $owner.RenderProvided($decoded)
        $output = [xml]$text
        $value = $output.SelectSingleNode('//Record[Name="HKLM\Software\Fixture\Bytes"]/Value')
        Assert-XmlInventory ($null -ne $value -and $value.InnerText -ceq 'AQI=' -and
            (Get-XmlFingerprint $text) -ceq (Get-XmlFingerprint ($owner.RenderProvided($packet))) -and
            (Get-XmlFixtureJson $decoded) -ceq $expectedInput -and
            [object]::ReferenceEquals($originalArray, $decoded.Policy.RegistrySettings[0].Value)) 'Binary round-trip or input ownership changed.'
    }
    Test-XmlInventory 'optional offline names stay absent and numeric zero survives' {
        $optional = New-XmlPacket $policyPath
        $optional.Gpo.PSObject.Properties.Remove('Domain')
        $optional.Gpo.PSObject.Properties.Remove('Server')
        $document = [xml]($owner.RenderProvided($optional))
        Assert-XmlInventory ($null -eq $document.SelectSingleNode('/GPO/Domain') -and
            $null -eq $document.SelectSingleNode('/GPO/Server') -and
            $document.SelectSingleNode('/GPO/Flags').InnerText -ceq '0') 'Offline metadata was invented or zero Flags was lost.'
    }
    Test-XmlInventory 'required report, identity, policy and flags validation stops locally' {
        Assert-XmlInventoryFailure { $owner.RenderProvided($null) }
        Assert-XmlInventoryFailure { $owner.RenderProvided([pscustomobject]@{ Gpo = $packet.Gpo; Policy = $null }) } '(?i)Gpo and Policy'
        $bad = New-XmlPacket $policyPath
        foreach ($invalid in -1, 4, 'bad') {
            $bad.Gpo.Flags = $invalid
            Assert-XmlInventoryFailure { $owner.RenderProvided($bad) } '(?i)flags'
        }
        $bad.Gpo.Flags = 0
        $bad.Gpo.Id = 'invalid'
        Assert-XmlInventoryFailure { $owner.RenderProvided($bad) } '(?i)GPO Id'
    }
    Test-XmlInventory 'provided XML normalizes Boolean presence and rejects an inert document type' {
        $initialInput = Get-XmlFixtureJson $packet
        Assert-XmlPresence ($owner.RenderProvided($packet))
        Assert-XmlInventory ((Get-XmlFixtureJson $packet) -ceq $initialInput -and
            $packet.Policy.XmlFiles[0].Xml.Contains($script:Marker)) 'Safe rendering mutated the provided packet.'
        $unreadable = New-XmlPacket $policyPath
        $unreadable.Policy.XmlFiles[0].Xml = '<!DOCTYPE Groups []><Groups/>'
        Assert-XmlInventoryFailure { $owner.RenderProvided($unreadable) } '(?i)XML is unreadable'
    }
}

function Invoke-XmlExportCases {
    $packet = New-XmlPacket $policyPath
    Test-XmlInventory 'literal file writes one safe XML string and exact UTF-8 bytes' {
        $path = Join-Path $script:Temporary 'saved [literal].xml'
        $text = $owner.ExportProvided($packet, $path)
        Assert-XmlInventory ($text -is [string] -and [IO.File]::ReadAllText($path) -ceq $text -and
            (Get-XmlFingerprint $text) -ceq (Get-XmlFingerprint ($owner.RenderProvided($packet)))) 'Return string and file differ.'
        $bytes = [IO.File]::ReadAllBytes($path)
        $expected = [Text.UTF8Encoding]::new($true).GetPreamble() + [Text.Encoding]::UTF8.GetBytes($text)
        Assert-XmlInventory ([Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String($expected)) 'The XML file lost its UTF-8 BOM or exact content.'
        Assert-XmlPresence $text
    }
    Test-XmlInventory 'explicit dry-run validates and returns XML without creating folders' {
        $folder = Join-Path $script:Temporary 'dry fixture'
        $target = Join-Path $folder 'planned.xml'
        $actual = $owner.ExportProvided($packet, $target, $true)
        Assert-XmlInventory ((Get-XmlFingerprint $actual) -ceq (Get-XmlFingerprint ($owner.RenderProvided($packet))) -and
            -not [IO.Directory]::Exists($folder)) 'Dry run created a path or changed XML.'
    }
    Test-XmlInventory 'FileSystem and nonempty path validation applies even on dry-run' {
        foreach ($dryRun in $true, $false) {
            Assert-XmlInventoryFailure { $owner.ExportProvided($packet, '', $dryRun) } '(?i)path'
            Assert-XmlInventoryFailure { $owner.ExportProvided($packet, 'Variable:XmlFixtureOutput', $dryRun) } '(?i)FileSystem'
        }
        Assert-XmlInventory ($null -eq (Get-Variable -Name XmlFixtureOutput -ErrorAction SilentlyContinue)) 'A provider path created a variable.'
    }
    Test-XmlInventory 'failed render leaves prior literal XML intact' {
        $path = Join-Path $script:Temporary 'previous [literal].xml'
        Write-XmlFixtureText $path 'previous XML'
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $bad = New-XmlPacket $policyPath
        $bad.Policy.XmlFiles[0].Xml = '<unclosed>'
        Assert-XmlInventoryFailure { $owner.ExportProvided($bad, $path) } '(?i)XML is unreadable'
        Assert-XmlInventory ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $before) 'Rejected XML replaced previous bytes.'
    }
    Test-XmlInventory 'failed filesystem promotion returns no XML and cleans staging' {
        $path = Join-Path $script:Temporary 'directory [not file].xml'
        $null = [IO.Directory]::CreateDirectory($path)
        Write-XmlFixtureText (Join-Path $path 'keep') 'keep'
        Assert-XmlInventoryFailure { $owner.ExportProvided($packet, $path) }
        Assert-XmlInventory ([IO.File]::ReadAllText((Join-Path $path 'keep')) -ceq 'keep' -and
            [IO.Directory]::GetFiles($script:Temporary, '.ad-analyzer-*.tmp').Count -eq 0) 'Failed promotion changed the destination or left residue.'
    }
}

function Invoke-XmlIsolationCases {
    $packet = New-XmlPacket $policyPath
    $expected = Get-XmlFingerprint ($owner.RenderProvided($packet))
    Assert-XmlDependencies $initial
    if ($RunspaceWorker) {
        $expected
        return
    }
    Test-XmlInventory 'independent owners preserve preloaded provider and writer definitions' {
        . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
        $preloaded = Get-XmlDependencies
        Assert-XmlInventory ($preloaded.Count -eq 7) 'The preloaded route did not contain the expected definitions.'
        function Get-ADAnalyzerGpoXml { Deny-XmlExternalCall }
        $other = [ADAnalyzerGpoXmlInventory]::new()
        Assert-XmlInventory ((Get-XmlFingerprint ($owner.RenderProvided($packet))) -ceq $expected -and
            (Get-XmlFingerprint ($other.RenderProvided($packet))) -ceq $expected) 'Preload, reuse or independent construction changed XML.'
        Assert-XmlDependencies $preloaded
    }
    Test-XmlInventory 'fresh runspace and post-disposal reuse preserve XML and caller scope' {
        $shell = [powershell]::Create()
        try {
            $body = @'
param($Fixture, $Root, $Policy)
& $Fixture -RepositoryRoot $Root -Mode Isolation -RunspaceWorker -SharedPolicyPath $Policy
'@
            $call = $shell.AddScript($body).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).AddArgument($policyPath)
            $rows = @($call.Invoke())
            Assert-XmlInventory (-not $shell.HadErrors -and $rows.Count -eq 1 -and
                [string]$rows[0] -ceq $expected) ('Secondary runspace failed: ' + ($shell.Streams.Error -join ' | '))
        }
        finally {
            $shell.Dispose()
        }
        Assert-XmlInventory ((Get-XmlFingerprint ($owner.RenderProvided($packet))) -ceq $expected) 'Reuse failed after a secondary runspace was disposed.'
        Assert-XmlDependencies $initial
    }
}

function Assert-XmlEvents([string]$Expected) {
    $actual = $script:Events -join ','
    Assert-XmlInventory ($actual -ceq $Expected -and $null -eq $script:Mount) ('Unexpected query or SYSVOL order: ' + $actual)
}

function Invoke-XmlCollectionCases {
    $script:Sysvol = Join-Path $script:Temporary 'sysvol'
    $leaf = '{0}/Policies/{1}' -f $script:DomainName, $script:Ids[0].ToString('B')
    New-XmlPolicy (Join-Path $script:Sysvol $leaf)
    $catalog = 'Import,Root,Domain,Policies,Links'
    $owned = $catalog + ',Mount,MountedRead,Remove'
    $ambient = $catalog + ',AmbientRead'
    $selection = @{
        Domain = $script:DomainName
        Server = $script:Alias
        Name = $script:FixtureDisplayName
    }
    Test-XmlInventory 'invalid configuration stops before package and SYSVOL access' {
        foreach ($invalid in @(
                $null
                @{ Name = $script:FixtureDisplayName }
                @{ Domain = $script:DomainName }
                @{ Domain = $script:DomainName; Name = ' ' }
                @{ Domain = $script:DomainName; Guid = 'invalid' }
                @{ Domain = $script:DomainName; Name = $script:FixtureDisplayName; Guid = $script:Ids[0] }
                @{ Domain = $script:DomainName; Name = $script:FixtureDisplayName; Keys = @() }
            )) {
            Assert-XmlInventoryFailure { $owner.Collect($invalid) }
        }
        Assert-XmlInventory ($script:Events.Count -eq 0 -and $script:Unexpected -eq 0) 'Invalid input reached an external boundary.'
    }
    $script:PermitProvider = $true
    Test-XmlInventory 'explicit name and credential pin SYSVOL through an owned disposable lease' {
        $script:Events.Clear()
        $script:ExplicitCredential = $true
        $script:InitialServer = $script:Alias
        $saved = Get-XmlFixtureJson $selection
        $text = $owner.Collect($selection, $script:Credential)
        Assert-XmlEvents $owned
        Assert-XmlPresence $text
        $document = [xml]$text
        Assert-XmlInventory ($document.SelectSingleNode('/GPO/Server').InnerText -ceq $script:Pinned -and
            $document.SelectSingleNode('/GPO/Id').InnerText -ceq $script:Ids[0].ToString('D') -and
            $document.SelectSingleNode('/GPO/DisplayName').InnerText -ceq $script:FixtureDisplayName -and
            (Get-XmlFixtureJson $selection) -ceq $saved) 'Collected GPO metadata or selection identity was lost.'
    }
    Test-XmlInventory 'GUID with omitted server uses domain and ambient credentials' {
        $script:Events.Clear()
        $script:ExplicitCredential = $false
        $script:InitialServer = $script:DomainName
        $text = $owner.Collect(@{ Domain = $script:DomainName; Guid = $script:Ids[0] })
        Assert-XmlEvents $ambient
        Assert-XmlPresence $text
        Assert-XmlInventory ((([xml]$text).SelectSingleNode('/GPO/Id').InnerText) -ceq $script:Ids[0].ToString('D')) 'GUID returned a different policy.'
    }
    Test-XmlInventory 'missing and ambiguous names stop before reading policy' {
        $script:ExplicitCredential = $false
        $script:InitialServer = $script:DomainName
        foreach ($name in 'Missing fixture', 'Duplicate fixture') {
            $script:Events.Clear()
            Assert-XmlInventoryFailure { $owner.Collect(@{ Domain = $script:DomainName; Name = $name }) } '(?i)not found|ambiguous'
            Assert-XmlEvents $catalog
        }
    }
    Test-XmlInventory 'selected export validates paths before collection and dry-run creates no files' {
        $script:Events.Clear()
        $script:ExplicitCredential = $true
        $script:InitialServer = $script:Alias
        Assert-XmlInventoryFailure { $owner.ExportSelected($selection, '', $script:Credential) } '(?i)path'
        Assert-XmlInventoryFailure {
            $owner.ExportSelected($selection, 'Variable:XmlFixtureOutput', $script:Credential, $true)
        } '(?i)FileSystem'
        Assert-XmlEvents ''
        $directory = Join-Path $script:Temporary 'selected dry'
        $path = Join-Path $directory 'planned.xml'
        $text = $owner.ExportSelected($selection, $path, $script:Credential, $true)
        Assert-XmlEvents $owned
        Assert-XmlPresence $text
        Assert-XmlInventory (-not [IO.Directory]::Exists($directory)) 'Selected dry run created a directory.'
    }
    Test-XmlInventory 'selected export writes exact returned XML and keeps ambient semantics' {
        $script:Events.Clear()
        $script:ExplicitCredential = $false
        $script:InitialServer = $script:DomainName
        $path = Join-Path $script:Temporary 'selected [saved].xml'
        $text = $owner.ExportSelected(@{ Domain = $script:DomainName; Guid = $script:Ids[0] }, $path)
        Assert-XmlEvents $ambient
        Assert-XmlPresence $text
        $null = Get-XmlFingerprint $text
        Assert-XmlInventory ([IO.File]::ReadAllText($path) -ceq $text) 'Selected XML file and return string differ.'
    }
}

$location = (Get-Location).Path
$initial = Get-XmlDependencies
$initialClrType = 'ADAnalyzer.ConfigurationState' -as [type]
$otherLoads = @()
if ($Mode -eq 'OtherFirst') {
    $otherLoads = @(. (Join-Path $RepositoryRoot 'etc/Get-LocalAdminGPO.ps1'))
}
$loads = @(. (Join-Path $RepositoryRoot 'etc/Get-GPOXML.ps1'))
$owner = [ADAnalyzerGpoXmlInventory]::new()
Assert-XmlInventory ($loads.Count -eq 0 -and $otherLoads.Count -eq 0 -and
    $script:Events.Count -eq 0 -and $script:Unexpected -eq 0 -and (Get-Location).Path -ceq $location -and
    [object]::ReferenceEquals($initialClrType, ('ADAnalyzer.ConfigurationState' -as [type]))) 'Loading or construction had effects.'
Assert-XmlDependencies $initial

$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-gpo-xml-inventory-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Temporary)
try {
    $policyPath = $SharedPolicyPath
    if (-not $RunspaceWorker -and $Mode -ne 'Collection') {
        $policyPath = Join-Path $script:Temporary 'source [policy]'
        New-XmlPolicy $policyPath
    }
    switch ($Mode) {
        'Construction' { Invoke-XmlConstructionCases }
        'OtherFirst' { Invoke-XmlConstructionCases }
        'Render' { Invoke-XmlRenderCases }
        'Export' { Invoke-XmlExportCases }
        'Isolation' { Invoke-XmlIsolationCases }
        'Collection' { Invoke-XmlCollectionCases }
    }
    Assert-XmlInventory ($script:Unexpected -eq 0 -and $null -eq $script:Mount -and
        (Get-Location).Path -ceq $location) 'The fixture crossed an external boundary or leaked scope.'
    if (-not $RunspaceWorker) {
        'PASS GPO XML inventory class {0} {1}' -f $Mode, $script:Passed
    }
}
finally {
    [IO.Directory]::Delete($script:Temporary, $true)
}
