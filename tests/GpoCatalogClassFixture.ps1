[CmdletBinding()]
param(
    [ValidateSet('Contracts', 'Direct', 'Standalone')][string]$Case = 'Contracts',
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

# Exact native catalog command from c4cc306, before class ownership.
$script:CatalogOracle = @'
function Get-ADAnalyzerGpo {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param(
        [Parameter(ParameterSetName = 'All')][switch]$All,
        [Parameter(Mandatory, ParameterSetName = 'Guid')][guid]$Guid,
        [Parameter(Mandatory, ParameterSetName = 'Name')][string]$Name,
        [Parameter(Mandatory)][string]$Domain,
        [string]$Server = $Domain,
        [pscredential]$Credential = [pscredential]::Empty

    )
    if ($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Server must be a DNS or NetBIOS host name'
    }
    $connection = @{
        Server = $Server
        ErrorAction = 'Stop'
    }
    if ($Credential -and $Credential -ne [pscredential]::Empty) {
        $connection.Credential = $Credential
    }
    $requestedServer = $Server
    $rootDse = Get-ADRootDSE @connection
    if ($rootDse.DnsHostName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'The directory server did not return a valid DC host name'
    }
    $Server = [string]$rootDse.DnsHostName
    $connection.Server = $Server
    $domainInfo = Get-ADDomain -Identity $Domain @connection
    $dns = [string]$domainInfo.DNSRoot
    if ($dns -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'Invalid domain DNS name'
    }
    $base = 'CN=Policies,CN=System,' + $domainInfo.DistinguishedName
    $objects = @(Get-ADObject `
            -LDAPFilter '(objectClass=groupPolicyContainer)' `
            -SearchBase $base `
            -Properties displayName,
        gPCFileSysPath,
        flags,
        whenCreated,
        whenChanged,
        versionNumber,
        gPCWQLFilter,
        gPCMachineExtensionNames,
        gPCUserExtensionNames @connection)
    $links = @(Get-ADObject `
            -LDAPFilter '(gPLink=*)' `
            -SearchBase $domainInfo.DistinguishedName `
            -Properties gPLink,
        gPOptions,
        distinguishedName @connection)
    if ($rootDse.ConfigurationNamingContext) {
        $links += @(Get-ADObject `
                -LDAPFilter '(gPLink=*)' `
                -SearchBase ('CN=Sites,' + $rootDse.ConfigurationNamingContext) `
                -Properties gPLink,
            gPOptions,
            distinguishedName @connection)
    }
    foreach ($object in $objects) {
        # A failed native cast under Continue leaves the variable unchanged.
        $id = $null
        $id = [guid]([string]$object.Name).Trim('{}')
        if ($null -eq $id) {
            continue
        }
        if ($PSCmdlet.ParameterSetName -eq 'Guid' -and $id -ne $Guid) {
            continue
        }
        if ($PSCmdlet.ParameterSetName -eq 'Name' -and $object.displayName -ine $Name) {
            continue
        }
        $policyLinks = [Collections.ArrayList]::new()
        foreach ($container in $links) {
            $storedIndex = 0
            foreach ($match in [regex]::Matches([string]$container.gPLink, '(?i)\[LDAP://(?<dn>[^;]+);(?<flags>\d+)\]')) {
                if ($match.Groups['dn'].Value -ieq $object.DistinguishedName) {
                    $options = $null
                    $options = [int]$match.Groups['flags'].Value
                    if ($null -ne $options) {
                        $null = $policyLinks.Add([pscustomobject]@{
                                SOMPath = $container.DistinguishedName
                                Enabled = ($options -band 1) -eq 0
                                Enforced = ($options -band 2) -ne 0
                                StoredLinkIndex = $storedIndex
                                BlockInheritance = ([int]$container.gPOptions -band 1) -ne 0
                            })
                    }
                }
                $storedIndex++
            }
        }
        $flags = $null
        $flags = [int]$object.flags
        if ($null -eq $flags) {
            continue
        }
        [pscustomobject]@{
            Id = $id
            DisplayName = $object.displayName
            CreationTime = $object.whenCreated
            ModificationTime = $object.whenChanged
            GPOStatus = @('AllSettingsEnabled', 'UserSettingsDisabled', 'ComputerSettingsDisabled', 'AllSettingsDisabled')[$flags -band 3]
            Flags = $flags
            Version = $object.versionNumber
            Domain = $dns
            Server = $Server
            RequestedServer = $requestedServer
            DistinguishedName = $object.DistinguishedName
            DirectoryFilePath = $object.gPCFileSysPath
            PolicyPath = ('\\{0}\SYSVOL\{1}\Policies\{2}' -f $Server, $dns, $id.ToString('B'))
            Links = $policyLinks.ToArray()
            WmiFilter = $object.gPCWQLFilter
            MachineExtensions = $object.gPCMachineExtensionNames
            UserExtensions = $object.gPCUserExtensionNames
        }
    }
}
'@

function Assert-CatalogBehavior($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function ConvertTo-CatalogFixtureJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 22 -Compress
}

$script:DomainName = 'catalog.fixture.invalid'
$script:DomainDn = 'DC=catalog,DC=fixture,DC=invalid'
$script:ConfigDn = "CN=Configuration,$script:DomainDn"
$script:Alias = 'alias.catalog.fixture.invalid'
$script:Pinned = 'dc.catalog.fixture.invalid'
$script:Credential = [pscredential]::new('CATALOG\fixture',
    (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
$script:Exports = @{}
$script:ExpectedDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Imports = [Collections.Generic.List[string]]::new()
$script:Queries = [Collections.Generic.List[object]]::new()
$script:Reads = [Collections.Generic.List[string]]::new()
$script:ImportAllowed = $false
$script:CatalogFault = 'None'
$script:BlockAmbient = $true

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru)

    Assert-CatalogBehavior $script:ImportAllowed 'Loading or invalid input tried to acquire a directory provider.'
    Assert-CatalogBehavior (
        [IO.Path]::IsPathRooted($Name) -and $Name -ceq $script:ExpectedDll -and
        $Scope -ceq 'Local' -and $PassThru -and $PSBoundParameters['ErrorAction'] -eq 'Stop'
    ) 'Direct import did not explicitly bind the package path, local scope and stopping behavior.'
    $script:Imports.Add($Name)
    if ($script:CatalogFault -eq 'ProviderImport') {
        throw [IO.FileLoadException]::new('Fixture package import failed.')
    }
    $commands = $script:Exports.Clone()
    if ($script:CatalogFault -eq 'MissingExport') {
        $commands.Remove('Get-ADObject')
    }
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $commands
    }
}

function New-CatalogFixturePolicy([string]$Suffix, [string]$Label, [int]$Flags) {
    $id = [guid]("11111111-1111-1111-1111-11111111111$Suffix")
    [pscustomobject]@{
        Name = $id.ToString('B')
        DisplayName = $Label
        DistinguishedName = "CN=$($id.ToString('B')),CN=Policies,CN=System,$script:DomainDn"
        Flags = $Flags
        VersionNumber = [long]65538
        gPCFileSysPath = '\\stored-only.fixture.invalid\evidence'
        WhenCreated = [datetime]'2020-01-01'
        WhenChanged = [datetime]'2020-02-01'
        gPCWQLFilter = 'fixture-filter'
        gPCMachineExtensionNames = 'fixture-machine'
        gPCUserExtensionNames = 'fixture-user'
    }
}

function Add-CatalogFixtureGetters([object]$Object, [string]$Tag, [string[]]$Names) {
    $Object | Add-Member -NotePropertyName FixtureValues -NotePropertyValue @{}
    foreach ($name in $Names) {
        $Object.FixtureValues[$name] = $Object.PSObject.Properties[$name].Value
        $Object.PSObject.Properties.Remove($name)
        $body = '$script:Reads.Add(''{0}.{1}''); $this.FixtureValues[''{1}'']' -f $Tag, $name
        $Object | Add-Member -MemberType ScriptProperty -Name $name -Value ([scriptblock]::Create($body))
    }
}

function New-CatalogFixtureInput([string]$Fault, [bool]$Trace) {
    $first = New-CatalogFixturePolicy 1 Duplicate 0
    $middle = New-CatalogFixturePolicy 2 Duplicate 3
    $tail = New-CatalogFixturePolicy 3 Tail 2
    $root = [pscustomobject]@{
        DnsHostName = $script:Pinned
        ConfigurationNamingContext = $script:ConfigDn
    }
    $domain = [pscustomobject]@{
        DNSRoot = $script:DomainName
        DistinguishedName = $script:DomainDn
    }
    $linkOptions = '1'
    switch ($Fault) {
        'BadGuid' {
            $middle.Name = 'invalid-guid'
        }
        'BadFlags' {
            $middle.Flags = 'invalid-flags'
        }
        'BadLinkOptions' {
            $linkOptions = '9999999999999999999'
        }
        'BadSelected' {
            $root.DnsHostName = 'invalid/path'
        }
        'MultipleSelected' {
            $root.DnsHostName = @($script:Pinned, 'other.catalog.fixture.invalid')
        }
        'BadDomain' {
            $domain.DNSRoot = 'invalid/domain'
        }
        'NoSites' {
            $root.ConfigurationNamingContext = $null
        }
        'MissingSites' {
            $root.PSObject.Properties.Remove('ConfigurationNamingContext')
        }
    }

    $domainLink = [pscustomobject]@{
        DistinguishedName = "OU=People,$script:DomainDn"
        gPLink = '[LDAP://{0};2] [ldap://{1};0] [LDAP://{2};{3}] [LDAP://{1};3] [LDAP://{2};1]' -f
            $tail.DistinguishedName, $first.DistinguishedName.ToLowerInvariant(), $middle.DistinguishedName, $linkOptions
        gPOptions = 1
    }
    $siteLink = [pscustomobject]@{
        DistinguishedName = "CN=Fixture,CN=Sites,$script:ConfigDn"
        gPLink = '[LDAP://{0};3]' -f $first.DistinguishedName
        gPOptions = 0
    }
    if ($Fault -eq 'MissingOptions') {
        $domainLink.PSObject.Properties.Remove('gPOptions')
    }
    if ($Trace) {
        Add-CatalogFixtureGetters $root Root @('DnsHostName', 'ConfigurationNamingContext')
        Add-CatalogFixtureGetters $domain Domain @('DNSRoot', 'DistinguishedName')
        Add-CatalogFixtureGetters $domainLink DomainLink @('gPLink', 'DistinguishedName', 'gPOptions')
        Add-CatalogFixtureGetters $siteLink SiteLink @('gPLink', 'DistinguishedName', 'gPOptions')
        $fields = @(
            'Name', 'DisplayName', 'DistinguishedName', 'Flags', 'VersionNumber', 'gPCFileSysPath',
            'WhenCreated', 'WhenChanged', 'gPCWQLFilter', 'gPCMachineExtensionNames', 'gPCUserExtensionNames'
        )
        Add-CatalogFixtureGetters $first First $fields
        Add-CatalogFixtureGetters $middle Middle $fields
        Add-CatalogFixtureGetters $tail Tail $fields
    }
    if ($Fault -eq 'ChangedSelected') {
        $root.PSObject.Properties.Remove('DnsHostName')
        $root | Add-Member -MemberType ScriptProperty -Name DnsHostName -Value {
            $script:Reads.Add('Root.DnsHostName')
            $dnsReads = @($script:Reads | Where-Object { $_ -ceq 'Root.DnsHostName' })
            if ($dnsReads.Count -gt 1) {
                return 'invalid/path'
            }
            return $this.FixtureValues['DnsHostName']
        }
    }
    [pscustomobject]@{
        Root = $root
        Domain = $domain
        Rows = @($first, $middle, $tail)
        DomainLink = $domainLink
        SiteLink = $siteLink
    }
}

function Add-CatalogFixtureQuery([string]$Stage, [Collections.IDictionary]$Bound) {
    $script:Queries.Add([pscustomobject]@{
        Stage = $Stage
        Server = $Bound['Server']
        Action = [string]$Bound['ErrorAction']
        Identity = $Bound['Identity']
        Base = $Bound['SearchBase']
        Filter = $Bound['LDAPFilter']
        Properties = @($Bound['Properties']) -join ','
        CredentialBound = $Bound.ContainsKey('Credential')
        SameCredential = [object]::ReferenceEquals($Bound['Credential'], $script:Credential)
    })
    if ($script:CatalogFault -eq ('Provider' + $Stage)) {
        Write-Error -Message 'Fixture directory query failed.' -ErrorId ('Fixture.' + $Stage) -ErrorAction $Bound['ErrorAction']
    }
}

function Invoke-CatalogFixtureRoot {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Add-CatalogFixtureQuery RootDSE $PSBoundParameters
    $script:CatalogInput.Root
}

function Invoke-CatalogFixtureDomain {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server, [pscredential]$Credential)

    Add-CatalogFixtureQuery Domain $PSBoundParameters
    $script:CatalogInput.Domain
}

function Invoke-CatalogFixtureObjects {
    [CmdletBinding()]
    param([string]$LDAPFilter, [string]$SearchBase, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    if ($LDAPFilter -ceq '(objectClass=groupPolicyContainer)') {
        Add-CatalogFixtureQuery Policies $PSBoundParameters
        Write-Verbose 'Fixture listing GPO containers.'
        return $script:CatalogInput.Rows
    }
    if ($SearchBase -like 'CN=Sites,*') {
        Add-CatalogFixtureQuery Sites $PSBoundParameters
        return $script:CatalogInput.SiteLink
    }
    Add-CatalogFixtureQuery Links $PSBoundParameters
    if ($script:CatalogFault -ne 'ProviderLinks') {
        Write-Warning 'Fixture listing domain links.'
    }
    $script:CatalogInput.DomainLink
}

function Get-ADRootDSE {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Assert-CatalogBehavior (-not $script:BlockAmbient) 'Direct lookup used the ambient directory RootDSE command.'
    Invoke-CatalogFixtureRoot @PSBoundParameters
}

function Get-ADDomain {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-CatalogBehavior (-not $script:BlockAmbient) 'Direct lookup used the ambient directory domain command.'
    Invoke-CatalogFixtureDomain @PSBoundParameters
}

function Get-ADObject {
    [CmdletBinding()]
    param([string]$LDAPFilter, [string]$SearchBase, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-CatalogBehavior (-not $script:BlockAmbient) 'Direct lookup used the ambient directory object command.'
    Invoke-CatalogFixtureObjects @PSBoundParameters
}

if ($Case -eq 'Direct') {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
}
Assert-CatalogBehavior ($script:Imports.Count -eq 0) 'The catalog loader imported a provider.'
$script:BlockAmbient = $false

$script:Exports = @{
    'Get-ADRootDSE' = Get-Command Invoke-CatalogFixtureRoot -CommandType Function
    'Get-ADDomain' = Get-Command Invoke-CatalogFixtureDomain -CommandType Function
    'Get-ADObject' = Get-Command Invoke-CatalogFixtureObjects -CommandType Function
    'Get-ADUser' = Get-Command Get-ADObject -CommandType Function
}

function Start-CatalogFixture([string]$Fault, [bool]$Trace = $true) {
    $script:CatalogFault = $Fault
    $script:CatalogInput = New-CatalogFixtureInput $Fault $Trace
    $before = ConvertTo-CatalogFixtureJson $script:CatalogInput
    $script:Queries.Clear()
    $script:Reads.Clear()
    $script:Imports.Clear()
    $before
}

function Read-CatalogFixtureSignal($Item) {
    if ($Item -is [Management.Automation.ErrorRecord]) {
        $command = $null
        if ($Item.InvocationInfo -and $Item.InvocationInfo.MyCommand) {
            $command = $Item.InvocationInfo.MyCommand.Name
        }
        return [ordered]@{
            Type = 'Error'
            Exception = $Item.Exception.GetType().FullName
            Cause = $Item.Exception.GetBaseException().GetType().FullName
            Id = $Item.FullyQualifiedErrorId
            Category = [string]$Item.CategoryInfo.Category
            Message = $Item.Exception.GetBaseException().Message
            Command = $command
        }
    }
    if ($Item -is [Management.Automation.IContainsErrorRecord]) {
        $signal = Read-CatalogFixtureSignal $Item.ErrorRecord
        $signal.Wrapper = $Item.GetType().FullName
        return $signal
    }
    if ($Item -is [Management.Automation.VerboseRecord] -or $Item -is [Management.Automation.WarningRecord]) {
        return [ordered]@{
            Type = $Item.GetType().Name
            Message = $Item.Message
        }
    }
    return [ordered]@{
        Type = 'Row'
        Value = $Item
    }
}

function Assert-CatalogFixtureBinding {
    $source = $script:CatalogOracle.Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
    Assert-CatalogBehavior ($hash -ieq 'aaa19cf41876edd8c073d7cd077d2cbb585b685548bdc96532e20de6aba33145') 'The exact native oracle changed.'
    $tokens = $null
    $errors = $null
    $oracle = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    $command = Get-Command Get-ADAnalyzerGpo -CommandType Function
    $actual = $command.ScriptBlock.Ast
    if ($actual -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $actual = $actual.Body
    }
    $frozen = $oracle.EndBlock.Statements[0].Body.ParamBlock.Extent.Text.Replace("`r`n", "`n")
    Assert-CatalogBehavior (
        $errors.Count -eq 0 -and $command.CmdletBinding -and $command.DefaultParameterSet -ceq 'All' -and
        $actual.ParamBlock.Extent.Text.Replace("`r`n", "`n") -ceq $frozen
    ) 'The advanced command changed its native parameter binding.'
}

function Invoke-CatalogNativeFixture(
    [bool]$Frozen, [string]$Fault, [string]$Mode, [string]$Preference, [int]$Arity = 1
) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:CatalogOracle))
    }
    $before = Start-CatalogFixture $Fault ($Fault -notin 'MissingOptions', 'MissingSites')
    Set-StrictMode -Version Latest
    $captured = @()
    $splat = @{
        Domain = $script:DomainName
        ErrorVariable = 'captured'
        Verbose = $true
    }
    switch ($Mode) {
        'All' {
            $splat.All = $true
        }
        'FalseAll' {
            $splat.All = $false
        }
        'Guid' {
            $splat.Guid = '11111111-1111-1111-1111-111111111112'
        }
        'Name' {
            $splat.Name = 'dUpLiCaTe'
        }
        'MissingName' {
            $splat.Name = 'No matching fixture'
        }
    }
    if ($Arity -ge 2) {
        $splat.Server = $script:Alias
    }
    if ($Arity -eq 3) {
        $splat.Credential = $script:Credential
    }
    if ($Fault -eq 'BadRequested') {
        $splat.Server = 'invalid/path'
    }
    if ($Fault -eq 'EmptyCredential') {
        $splat.Credential = [pscredential]::Empty
    }

    $ErrorActionPreference = 'Continue'
    if ($Preference -ne 'InheritedContinue') {
        $splat.ErrorAction = 'Continue'
    }
    if ($Preference -eq 'CaughtStop') {
        $splat.ErrorAction = 'Stop'
    }
    $caught = $null
    $items = @(
        if ($Preference -like 'Caught*') {
            try {
                Get-ADAnalyzerGpo @splat 4>&1 3>&1 2>&1
            }
            catch {
                $caught = Read-CatalogFixtureSignal $_
            }
        }
        else {
            Get-ADAnalyzerGpo @splat 4>&1 3>&1 2>&1
        }
    )
    $ErrorActionPreference = 'Stop'
    $reads = $script:Reads.ToArray()
    [pscustomobject]@{
        Stream = @($items | ForEach-Object { Read-CatalogFixtureSignal $_ })
        ErrorVariable = @($captured | ForEach-Object { Read-CatalogFixtureSignal $_ })
        Caught = $caught
        Queries = $script:Queries.ToArray()
        Reads = $reads
        SourceUnchanged = $before -ceq (ConvertTo-CatalogFixtureJson $script:CatalogInput)
    }
}

function Invoke-CatalogMethod([object]$Service, [string]$Mode, [int]$Arity) {
    $domain = $script:DomainName
    $server = $script:Alias
    $credential = $script:Credential
    switch ($Mode) {
        'All' {
            switch ($Arity) {
                1 {
                    return $Service.GetAll($domain)
                }
                2 {
                    return $Service.GetAll($domain, $server)
                }
                3 {
                    return $Service.GetAll($domain, $server, $credential)
                }
            }
        }
        'Guid' {
            $id = [guid]'11111111-1111-1111-1111-111111111112'
            switch ($Arity) {
                1 {
                    return $Service.FindById($id, $domain)
                }
                2 {
                    return $Service.FindById($id, $domain, $server)
                }
                3 {
                    return $Service.FindById($id, $domain, $server, $credential)
                }
            }
        }
        'Name' {
            switch ($Arity) {
                1 {
                    return $Service.FindByName('dUpLiCaTe', $domain)
                }
                2 {
                    return $Service.FindByName('dUpLiCaTe', $domain, $server)
                }
                3 {
                    return $Service.FindByName('dUpLiCaTe', $domain, $server, $credential)
                }
            }
        }
    }
    throw 'Unknown catalog fixture request.'
}

function Assert-CatalogFixtureFailure([scriptblock]$Operation, [string]$MessagePattern) {
    $items = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Operation | ForEach-Object { $items.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-CatalogBehavior ($null -ne $failure -and $items.Count -eq 0 -and
        $failure.Exception.GetBaseException().Message -match $MessagePattern
    ) "Direct operation did not stop with a useful cause matching '$MessagePattern' and zero results."
}

function Assert-CatalogFixtureNativeWitness($Observation) {
    $witness = @($Observation.Stream | Where-Object Type -in 'Row', 'Error')
    Assert-CatalogBehavior ($witness.Count -eq 3 -and
        $witness[0].Type -ceq 'Row' -and $witness[0].Value.DisplayName -ceq 'Duplicate' -and
        $witness[1].Type -ceq 'Error' -and $witness[1].Id -match 'InvalidCast' -and
        $witness[2].Type -ceq 'Row' -and $witness[2].Value.DisplayName -ceq 'Tail' -and
        @($Observation.ErrorVariable | Where-Object Id -match 'InvalidCast').Count -gt 0
    ) 'The native witness did not exercise an ordered per-row error, valid neighbors and ErrorVariable.'
}

if ($Case -eq 'Contracts') {
    Assert-CatalogFixtureBinding
    $count = 1
    $scenarios = @(
        ,@('None', 'Default', 'InheritedContinue', 1)
        ,@('None', 'All', 'ExplicitContinue', 3)
        ,@('None', 'FalseAll', 'InheritedContinue', 1)
        ,@('None', 'Guid', 'ExplicitContinue', 2)
        ,@('None', 'Name', 'ExplicitContinue', 1)
        ,@('None', 'MissingName', 'ExplicitContinue', 1)
        ,@('EmptyCredential', 'All', 'ExplicitContinue', 2)
        ,@('NoSites', 'All', 'ExplicitContinue', 1)
        ,@('BadGuid', 'All', 'InheritedContinue', 1)
        ,@('BadGuid', 'All', 'CaughtContinue', 1)
        ,@('BadFlags', 'All', 'ExplicitContinue', 1)
        ,@('BadFlags', 'Name', 'CaughtStop', 1)
        ,@('BadLinkOptions', 'All', 'InheritedContinue', 1)
        ,@('BadLinkOptions', 'Guid', 'CaughtContinue', 1)
        ,@('MissingOptions', 'All', 'ExplicitContinue', 1)
        ,@('MissingSites', 'All', 'ExplicitContinue', 1)
        ,@('BadRequested', 'All', 'CaughtStop', 1)
        ,@('BadSelected', 'All', 'CaughtStop', 1)
        ,@('BadDomain', 'All', 'CaughtStop', 1)
        ,@('ProviderRootDSE', 'All', 'CaughtContinue', 1)
        ,@('ProviderDomain', 'All', 'CaughtStop', 1)
        ,@('ProviderPolicies', 'All', 'CaughtStop', 1)
        ,@('ProviderLinks', 'All', 'CaughtContinue', 1)
        ,@('ProviderSites', 'All', 'CaughtStop', 1)
    )
    foreach ($scenario in $scenarios) {
        $expected = Invoke-CatalogNativeFixture $true @scenario
        $actual = Invoke-CatalogNativeFixture $false @scenario
        $context = $scenario -join '/'
        if ($context -eq 'BadGuid/All/InheritedContinue/1') {
            Assert-CatalogFixtureNativeWitness $expected
        }
        if ($scenario[0] -in 'BadFlags', 'ProviderDomain' -and $scenario[2] -ceq 'CaughtStop') {
            Assert-CatalogBehavior ($null -ne $expected.Caught -and $expected.ErrorVariable.Count -gt 0) "Frozen $context did not exercise caller-visible caught errors."
        }
        Assert-CatalogBehavior ($expected.SourceUnchanged -and $actual.SourceUnchanged -and
            (ConvertTo-CatalogFixtureJson $actual) -ceq (ConvertTo-CatalogFixtureJson $expected)
        ) "The native catalog changed stream, error capture, order, binding or observations for $context."
        $count++
    }
    Write-Output "PASS GPO catalog class Contracts $count"
    exit
}

$catalog = [ADAnalyzerGpoCatalog]::new()
Assert-CatalogBehavior ($catalog.GetType().Name -ceq 'ADAnalyzerGpoCatalog' -and
    $script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0
) 'Literal catalog construction did not remain inert.'
$count = 1
$baselines = @{}
foreach ($mode in @('All', 'Guid', 'Name')) {
    foreach ($arity in 1..3) {
        $baselines["$mode/$arity"] = Invoke-CatalogNativeFixture $true None $mode ExplicitContinue $arity
    }
}
$noSite = Invoke-CatalogNativeFixture $true NoSites All ExplicitContinue
function Get-ADAnalyzerGpo {
    throw 'Direct lookup called the compatibility command.'
}
$script:BlockAmbient = $true
$PSModuleAutoLoadingPreference = 'None'
$WarningPreference = 'SilentlyContinue'
$script:Queries.Clear()

Assert-CatalogFixtureFailure { $catalog.GetAll($script:DomainName, 'invalid/path') } 'DNS|host'
Assert-CatalogFixtureFailure { $catalog.GetAll('', $script:Alias) } 'domain'
Assert-CatalogFixtureFailure { $catalog.FindById([guid]::Empty, $script:DomainName) } 'GUID|ID'
Assert-CatalogFixtureFailure { $catalog.FindByName(' ', $script:DomainName) } 'name'
Assert-CatalogBehavior ($script:Imports.Count -eq 0 -and $script:Queries.Count -eq 0) 'Invalid catalog inputs did not reject before provider access.'
$count += 4

$script:ImportAllowed = $true
foreach ($mode in @('All', 'Guid', 'Name')) {
    foreach ($arity in 1..3) {
        $key = "$mode/$arity"
        $expected = $baselines[$key]
        $expectedRows = @($expected.Stream | Where-Object Type -eq 'Row' | ForEach-Object Value)
        $before = Start-CatalogFixture None
        $rows = @(Invoke-CatalogMethod $catalog $mode $arity)
        $observedGetterOrder = $script:Reads.ToArray()
        Assert-CatalogBehavior (
            $script:Imports.Count -eq 1 -and $expected.SourceUnchanged -and
            (ConvertTo-CatalogFixtureJson $rows) -ceq (ConvertTo-CatalogFixtureJson $expectedRows) -and
            (ConvertTo-CatalogFixtureJson $script:Queries.ToArray()) -ceq (ConvertTo-CatalogFixtureJson $expected.Queries) -and
            ($observedGetterOrder -join '|') -ceq ($expected.Reads -join '|') -and
            $before -ceq (ConvertTo-CatalogFixtureJson $script:CatalogInput)
        ) "Direct $key changed row, link, getter, input, credential or query behavior."
        Assert-CatalogBehavior ($rows[0].Id -is [guid] -and $rows[0].CreationTime -is [datetime] -and
            $rows[0].Version -is [long] -and $rows[0].Flags -is [int] -and
            $rows[0].Links[0].StoredLinkIndex -is [int] -and $rows[0].Links[0].Enabled -is [bool]
        ) "Direct $key changed native result types."
        $count++
    }
}

$null = Start-CatalogFixture NoSites
$rows = @($catalog.GetAll($script:DomainName))
$expectedRows = @($noSite.Stream | Where-Object Type -eq 'Row' | ForEach-Object Value)
Assert-CatalogBehavior ($script:Queries.Count -eq 4 -and
    (ConvertTo-CatalogFixtureJson $rows) -ceq (ConvertTo-CatalogFixtureJson $expectedRows)
) 'Unavailable site context changed domain results or caused a site lookup.'
$count++

$null = Start-CatalogFixture None
$unmatchedId = @($catalog.FindById([guid]'99999999-9999-9999-9999-999999999999', $script:DomainName))
$unmatchedName = @($catalog.FindByName('Missing fixture', $script:DomainName))
Assert-CatalogBehavior ($unmatchedId.Count -eq 0 -and $unmatchedName.Count -eq 0 -and
    $script:Imports.Count -eq 2
) 'Valid searches without matches did not return an empty result.'
$count++

foreach ($spec in @(
        ,@('ProviderImport', 'Fixture package import failed', 0)
        ,@('MissingExport', 'Get-ADObject|export|cmdlet|command', 0)
        ,@('BadSelected', 'valid DC host name', 1)
        ,@('MultipleSelected', 'valid DC host name', 1)
        ,@('ChangedSelected', 'valid DC host name', 1)
        ,@('BadDomain', 'Invalid domain DNS name', 2)
        ,@('ProviderDomain', 'Fixture directory query failed', 2)
        ,@('BadGuid', 'guid|[fF]ormat', 5)
    )) {
    $null = Start-CatalogFixture $spec[0]
    Assert-CatalogFixtureFailure { $catalog.GetAll($script:DomainName) } $spec[1]
    Assert-CatalogBehavior ($script:Imports.Count -eq 1 -and $script:Queries.Count -eq $spec[2]) "Direct $($spec[0]) continued collecting after failure."
    $count++
}

$null = Start-CatalogFixture None
$first = @($catalog.GetAll($script:DomainName, $script:Alias, $script:Credential))
$first[0].DisplayName = 'Caller changed its result'
$first[0].Links[0].Enabled = $false
$script:Queries.Clear()
$again = @($catalog.GetAll($script:DomainName))
$other = [ADAnalyzerGpoCatalog]::new()
$fresh = @($other.GetAll($script:DomainName))
$fields = $catalog.GetType().GetFields([Reflection.BindingFlags]'Instance,Public,NonPublic')
$retained = @(
    foreach ($field in $fields) {
        $value = $field.GetValue($catalog)
        if ($value -is [pscredential] -or $value -is [Management.Automation.CommandInfo] -or
            $value -is [Management.Automation.PSModuleInfo]) {
            $field.Name
        }
    }
)
Assert-CatalogBehavior ($retained.Count -eq 0 -and
    @($script:Queries | Where-Object CredentialBound).Count -eq 0 -and
    $again[0].DisplayName -ceq 'Duplicate' -and $again[0].Links[0].Enabled -and
    (ConvertTo-CatalogFixtureJson $again) -ceq (ConvertTo-CatalogFixtureJson $fresh)
) 'Reusing the catalog retained a credential or capability, or returned aliased results.'
$count++

if ($Case -eq 'Direct') {
    $exe = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoLogo'
        '-NoProfile'
        '-NonInteractive'
        '-File'
        $PSCommandPath
        '-Case'
        'Standalone'
        '-RepositoryRoot'
        $RepositoryRoot
    )
    $lines = @(& $exe @arguments 2>&1)
    Assert-CatalogBehavior ($LASTEXITCODE -eq 0 -and $lines.Count -eq 1 -and
        $lines[0] -ceq "PASS GPO catalog class Standalone $count"
    ) 'The standalone loader failed the direct catalog matrix.'
    $count++
}
Write-Output "PASS GPO catalog class $Case $count"
