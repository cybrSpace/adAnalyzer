[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Regression', 'Controls')][string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')

function Import-Module {
    throw 'Catalog fixtures may use only the isolated directory commands.'
}

$script:DomainName = 'example.invalid'
$script:RequestedServer = 'alias.example.invalid'
$script:SelectedServer = 'dc.example.invalid'
$script:DomainDn = 'DC=example,DC=invalid'
$script:ConfigDn = 'CN=Configuration,' + $script:DomainDn
$script:Ids = @{
    First = [guid]'11111111-1111-1111-1111-111111111111'
    Subject = [guid]'22222222-2222-2222-2222-222222222222'
    Tail = [guid]'33333333-3333-3333-3333-333333333333'
}
$script:FixtureCredential = [pscredential]::new(
    'EXAMPLE\fixture', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force)
)
$script:Queries = [Collections.Generic.List[object]]::new()

function Assert-Catalog($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-SourcePolicy([string]$Key, [string]$DisplayName, [int]$Flags) {
    $name = $script:Ids[$Key].ToString('B')
    return [pscustomobject]@{
        Name = $name
        DisplayName = $DisplayName
        DistinguishedName = "CN=$name,CN=Policies,CN=System,$script:DomainDn"
        Flags = $Flags
        VersionNumber = [long]65538
        gPCFileSysPath = '\\evidence-only.invalid\fixture'
        WhenCreated = [datetime]'2020-01-01'
        WhenChanged = [datetime]'2020-02-01'
        gPCWQLFilter = 'fixture-filter'
        gPCMachineExtensionNames = 'fixture-machine'
        gPCUserExtensionNames = 'fixture-user'
    }
}

function New-CatalogInput([string]$Fault, [string]$Position) {
    $first = New-SourcePolicy 'First' 'Duplicate' 0
    $subject = New-SourcePolicy 'Subject' 'Duplicate' 3
    $tail = New-SourcePolicy 'Tail' 'Tail' 2
    switch ($Fault) {
        'BadGuid' {
            $subject.Name = 'not-a-guid'
        }
        'BadFlags' {
            $subject.Flags = 'not-a-number'
        }
        'MissingGuid' {
            $subject.PSObject.Properties.Remove('Name')
        }
        'MissingFlags' {
            $subject.PSObject.Properties.Remove('Flags')
        }
        'NullFlags' {
            $subject.Flags = $null
        }
    }

    $optionText = if ($Fault -eq 'BadLinkOptions') {
        '9999999999999999999'
    }
    else {
        '1'
    }
    $domainLink = [pscustomobject]@{
        DistinguishedName = "OU=People,$script:DomainDn"
        gPLink = '[LDAP://{0};2] [ldap://{1};0] [LDAP://{2};{3}] [LDAP://{1};3] [LDAP://{2};1]' -f
            $tail.DistinguishedName, $first.DistinguishedName.ToLowerInvariant(), $subject.DistinguishedName, $optionText
        gPOptions = 1
    }
    $root = [pscustomobject]@{
        DnsHostName = $script:SelectedServer
        ConfigurationNamingContext = $script:ConfigDn
    }
    switch ($Fault) {
        'MissingOptions' {
            $domainLink.PSObject.Properties.Remove('gPOptions')
        }
        'NullOptions' {
            $domainLink.gPOptions = $null
        }
        'BadOptions' {
            $domainLink.gPOptions = 'not-a-number'
        }
        'MissingLink' {
            $domainLink.PSObject.Properties.Remove('gPLink')
        }
        'NullLink' {
            $domainLink.gPLink = $null
        }
        'MissingSites' {
            $root.PSObject.Properties.Remove('ConfigurationNamingContext')
        }
        'NoSites' {
            $root.ConfigurationNamingContext = $null
        }
    }
    $rows = @(
        switch ($Position) {
            'First' {
                $subject
                $first
                $tail
            }
            'Middle' {
                $first
                $subject
                $tail
            }
            'Sole' {
                $subject
            }
        }
    )
    return [pscustomobject]@{
        Root = $root
        Rows = $rows
        DomainLink = $domainLink
        SiteLink = [pscustomobject]@{
            DistinguishedName = "CN=Fixture,CN=Sites,$script:ConfigDn"
            gPLink = '[LDAP://{0};3]' -f $first.DistinguishedName
            gPOptions = 0
        }
    }
}

function Add-Query([string]$Command, [hashtable]$Bound) {
    $script:Queries.Add([pscustomobject]@{
        Command = $Command
        Server = $Bound['Server']
        ErrorAction = [string]$Bound['ErrorAction']
        CredentialBound = $Bound.ContainsKey('Credential')
        SameCredential = [object]::ReferenceEquals($Bound['Credential'], $script:FixtureCredential)
        Identity = $Bound['Identity']
        Filter = $Bound['LDAPFilter']
        Base = $Bound['SearchBase']
        Properties = @($Bound['Properties']) -join ','
    })
}

function Get-ADRootDSE {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)
    Add-Query 'RootDSE' $PSBoundParameters
    $script:CatalogInput.Root
}

function Get-ADDomain {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server, [pscredential]$Credential)
    Add-Query 'Domain' $PSBoundParameters
    [pscustomobject]@{
        DNSRoot = $script:DomainName
        DistinguishedName = $script:DomainDn
    }
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        [string]$LDAPFilter,
        [string]$SearchBase,
        [string[]]$Properties,
        [string]$Server,
        [pscredential]$Credential
    )
    Add-Query 'Object' $PSBoundParameters
    if ($LDAPFilter -eq '(objectClass=groupPolicyContainer)') {
        $script:CatalogInput.Rows
    }
    elseif ($SearchBase -like 'CN=Sites,*') {
        $script:CatalogInput.SiteLink
    }
    else {
        $script:CatalogInput.DomainLink
    }
}

function Get-ConversionDiagnostic {
    [CmdletBinding()]
    param([string]$Fault)
    switch ($Fault) {
        'BadGuid' {
            $id = [guid]([string]'not-a-guid').Trim('{}')
        }
        'BadLinkOptions' {
            $options = [int]'9999999999999999999'
        }
        default {
            $flags = [int]'not-a-number'
        }
    }
}

function Get-NativeErrorId([string]$Fault) {
    $ErrorActionPreference = 'Continue'
    $items = @(Get-ConversionDiagnostic -Fault $Fault 2>&1)
    $ErrorActionPreference = 'Stop'
    Assert-Catalog (
        $items.Count -eq 1 -and $items[0] -is [Management.Automation.ErrorRecord]
    ) 'The native diagnostic oracle did not emit one ErrorRecord.'
    return ($items[0].FullyQualifiedErrorId -split ',', 2)[0]
}

function Invoke-CatalogScenario(
    [string]$Fault,
    [string]$Position,
    [string]$Preference,
    [string]$Select,
    [bool]$Strict
) {
    if ($Strict) {
        Set-StrictMode -Version Latest
    }
    else {
        Set-StrictMode -Off
    }
    $script:CatalogInput = New-CatalogInput $Fault $Position
    $before = ConvertTo-Json -InputObject $script:CatalogInput -Depth 12 -Compress
    $script:Queries.Clear()
    $arguments = @{ Domain = $script:DomainName }
    switch ($Fault) {
        'ExplicitConnection' {
            $arguments.Server = $script:RequestedServer
            $arguments.Credential = $script:FixtureCredential
        }
        'EmptyCredential' {
            $arguments.Server = $script:RequestedServer
            $arguments.Credential = [pscredential]::Empty
        }
    }
    switch ($Select) {
        'All' {
            $arguments.All = $true
        }
        'FalseAll' {
            $arguments.All = $false
        }
        'Name' {
            $arguments.Name = 'dUPLICATE'
        }
        'NoMatch' {
            $arguments.Name = 'Missing'
        }
        'Guid' {
            $arguments.Guid = $script:Ids.Subject.ToString('B')
        }
        'GuidPrior' {
            $arguments.Guid = $script:Ids.First.ToString('B')
        }
    }
    if ($Preference -ne 'InheritedContinue') {
        $arguments.ErrorAction = if ($Preference -eq 'CaughtStop') {
            'Stop'
        }
        else {
            'Continue'
        }
    }

    # The ordinary modes must exercise Continue without an enclosing try.
    $ErrorActionPreference = 'Continue'
    $caught = $null
    $output = @(
        if ($Preference -like 'Caught*') {
            try {
                Get-ADAnalyzerGpo @arguments 2>&1
            }
            catch {
                $caught = $_
                $_
            }
        }
        else {
            Get-ADAnalyzerGpo @arguments 2>&1
        }
    )
    $ErrorActionPreference = 'Stop'

    return [pscustomobject]@{
        Output = $output
        Caught = $caught
        Queries = $script:Queries.ToArray()
        SourceUnchanged = $before -ceq (ConvertTo-Json -InputObject $script:CatalogInput -Depth 12 -Compress)
    }
}

function Assert-Queries([object[]]$Queries, [string]$Fault) {
    $withSites = $Fault -notin 'NoSites', 'MissingSites'
    $requested = if ($Fault -in 'ExplicitConnection', 'EmptyCredential') {
        $script:RequestedServer
    }
    else {
        $script:DomainName
    }
    $explicitCredential = $Fault -eq 'ExplicitConnection'
    $expected = @(
        , @('RootDSE', $requested, '', '', '', '')
        , @('Domain', $script:SelectedServer, $script:DomainName, '', '', '')
        , @('Object', $script:SelectedServer, '', '(objectClass=groupPolicyContainer)',
            "CN=Policies,CN=System,$script:DomainDn",
            'displayName,gPCFileSysPath,flags,whenCreated,whenChanged,versionNumber,gPCWQLFilter,gPCMachineExtensionNames,gPCUserExtensionNames')
        , @('Object', $script:SelectedServer, '', '(gPLink=*)', $script:DomainDn, 'gPLink,gPOptions,distinguishedName')
        if ($withSites) {
            , @('Object', $script:SelectedServer, '', '(gPLink=*)', "CN=Sites,$script:ConfigDn", 'gPLink,gPOptions,distinguishedName')
        }
    )
    Assert-Catalog ($Queries.Count -eq $expected.Count) 'Catalog changed the number of directory queries.'
    for ($index = 0; $index -lt $expected.Count; $index++) {
        $actual = $Queries[$index]
        $arguments = @($actual.Command, $actual.Server, $actual.Identity, $actual.Filter, $actual.Base, $actual.Properties)
        Assert-Catalog (
            ($arguments -join '|') -ceq ($expected[$index] -join '|') -and
            $actual.ErrorAction -ceq 'Stop' -and
            $actual.CredentialBound -eq $explicitCredential -and
            $actual.SameCredential -eq $explicitCredential
        ) 'Catalog changed native query binding, DC pinning, operation order or credentials.'
    }
}

function Get-ExpectedPolicyKeys(
    [string]$Fault, [string]$Position, [string]$Preference, [string]$Select, [bool]$Strict
) {
    if ($Preference -like 'Caught*') {
        return 'First'
    }
    $omit = $Fault -in 'BadGuid', 'BadFlags', 'MissingGuid' -or ($Fault -eq 'MissingFlags' -and $Strict)
    $keys = switch ($Position) {
        'First' {
            'Subject'
            'First'
            'Tail'
        }
        'Middle' {
            'First'
            'Subject'
            'Tail'
        }
        'Sole' {
            'Subject'
        }
    }
    foreach ($key in @($keys)) {
        if (($omit -and $key -eq 'Subject') -or $Select -eq 'NoMatch') {
            continue
        }
        if (($Select -eq 'Guid' -and $key -ne 'Subject') -or
            ($Select -eq 'GuidPrior' -and $key -ne 'First') -or
            ($Select -eq 'Name' -and $key -eq 'Tail')) {
            continue
        }
        $key
    }
}

function Assert-CatalogRow([object]$Row, [string]$Key, [string]$Fault, [bool]$Strict) {
    $id = $script:Ids[$Key]
    $dn = "CN=$($id.ToString('B')),CN=Policies,CN=System,$script:DomainDn"
    $requested = if ($Fault -in 'ExplicitConnection', 'EmptyCredential') {
        $script:RequestedServer
    }
    else {
        $script:DomainName
    }
    $status = @{
        First = @(0, 'AllSettingsEnabled')
        Subject = @(3, 'AllSettingsDisabled')
        Tail = @(2, 'ComputerSettingsDisabled')
    }
    if ($Fault -in 'NullFlags', 'MissingFlags') {
        $status.Subject = @(0, 'AllSettingsEnabled')
    }
    $expectedDisplayName = if ($Key -eq 'Tail') {
        'Tail'
    }
    else {
        'Duplicate'
    }
    Assert-Catalog (
        $Row.Id -is [guid] -and $Row.Id -eq $id -and
        $Row.DistinguishedName -ceq $dn -and
        $Row.PolicyPath -ceq ('\\{0}\SYSVOL\{1}\Policies\{2}' -f $script:SelectedServer, $script:DomainName, $id.ToString('B')) -and
        $Row.RequestedServer -ceq $requested -and $Row.Server -ceq $script:SelectedServer -and
        $Row.Domain -ceq $script:DomainName -and $Row.DisplayName -ceq $expectedDisplayName
    ) 'A catalog row inherited another policy identity or changed its own provenance.'
    Assert-Catalog (
        $Row.Flags -is [int] -and $Row.Flags -eq $status[$Key][0] -and
        $Row.GPOStatus -ceq $status[$Key][1] -and $Row.Version -is [long] -and $Row.Version -eq 65538 -and
        $Row.CreationTime -eq [datetime]'2020-01-01' -and $Row.ModificationTime -eq [datetime]'2020-02-01' -and
        $Row.DirectoryFilePath -ceq '\\evidence-only.invalid\fixture' -and $Row.WmiFilter -ceq 'fixture-filter' -and
        $Row.MachineExtensions -ceq 'fixture-machine' -and $Row.UserExtensions -ceq 'fixture-user'
    ) 'Catalog changed flags, status or metadata outside the discarded data.'

    $domainLinks = $Fault -notin 'MissingLink', 'NullLink', 'BadOptions' -and
        -not ($Strict -and $Fault -eq 'MissingOptions')
    $block = $Fault -notin 'NullOptions', 'MissingOptions'
    $links = @(
        if ($domainLinks) {
            switch ($Key) {
                'First' {
                    "Domain/1/True/False/$block"
                    "Domain/3/False/True/$block"
                }
                'Subject' {
                    if ($Fault -ne 'BadLinkOptions') {
                        "Domain/2/False/False/$block"
                    }
                    "Domain/4/False/False/$block"
                }
                'Tail' {
                    "Domain/0/True/True/$block"
                }
            }
        }
        if ($Key -eq 'First' -and $Fault -notin 'NoSites', 'MissingSites') {
            'Site/0/False/True/False'
        }
    )
    $observed = @($Row.Links | ForEach-Object {
            Assert-Catalog (
                $_.StoredLinkIndex -is [int] -and $_.Enabled -is [bool] -and
                $_.Enforced -is [bool] -and $_.BlockInheritance -is [bool]
            ) 'Catalog returned an invalid link DTO type.'
            $scope = if ($_.SOMPath -ceq "OU=People,$script:DomainDn") {
                'Domain'
            }
            elseif ($_.SOMPath -ceq "CN=Fixture,CN=Sites,$script:ConfigDn") {
                'Site'
            }
            else {
                'Unexpected'
            }
            '{0}/{1}/{2}/{3}/{4}' -f $scope, $_.StoredLinkIndex, $_.Enabled, $_.Enforced, $_.BlockInheritance
        })
    Assert-Catalog (
        ($observed -join '|') -ceq ($links -join '|')
    ) 'Catalog retained a malformed link or changed valid link order, stored index or flags.'
}

function Assert-Scenario([object]$Scenario, [object]$Actual) {
    $fault = $Scenario.Fault
    $preference = $Scenario.Preference
    $strict = $Scenario.Strict
    Assert-Queries $actual.Queries $fault
    Assert-Catalog $actual.SourceUnchanged 'Catalog changed its provider source objects.'

    $expectedKeys = @(Get-ExpectedPolicyKeys $fault $Scenario.Position $preference $Scenario.Select $strict)
    $rows = @($actual.Output | Where-Object { $_ -isnot [Management.Automation.ErrorRecord] })
    $errors = @($actual.Output | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
    $errorCount = 0
    $errorId = $null
    if ($fault -in 'BadGuid', 'BadFlags', 'BadLinkOptions' -or ($fault -eq 'MissingGuid' -and -not $strict)) {
        $oracle = if ($fault -eq 'MissingGuid') {
            'BadGuid'
        }
        else {
            $fault
        }
        $errorId = $script:NativeErrorIds[$oracle]
        $errorCount = 1
    }
    elseif ($strict -and $fault -in 'MissingGuid', 'MissingFlags', 'MissingOptions', 'MissingLink', 'MissingSites') {
        $errorId = 'PropertyNotFoundStrict'
        $errorCount = switch ($fault) {
            'MissingOptions' {
                5
            }
            'MissingLink' {
                3
            }
            default {
                1
            }
        }
    }
    elseif ($fault -eq 'BadOptions') {
        $errorId = $script:NativeErrorIds['BadFlags']
        $errorCount = 5
    }
    Assert-Catalog ($errors.Count -eq $errorCount) 'Catalog changed the number of native errors.'
    foreach ($errorRecord in $errors) {
        Assert-Catalog (
            ($errorRecord.FullyQualifiedErrorId -split ',', 2)[0] -ceq $errorId
        ) 'Catalog changed the underlying native diagnostic.'
    }
    if ($preference -like 'Caught*') {
        Assert-Catalog (
            $null -ne $actual.Caught -and
            $actual.Caught.FullyQualifiedErrorId -ceq ($errorId + ',Get-ADAnalyzerGpo')
        ) 'A caught native failure lost its public command context.'
    }
    if ($errorCount -eq 1) {
        $errorIndex = if ($Scenario.Position -eq 'Middle' -and $fault -ne 'MissingSites') {
            1
        }
        else {
            0
        }
        if ($Scenario.Select -eq 'Guid') {
            $errorIndex = 0
        }
        Assert-Catalog (
            $actual.Output[$errorIndex] -is [Management.Automation.ErrorRecord]
        ) 'Catalog reordered its primary native error relative to valid rows.'
    }

    Assert-Catalog ($rows.Count -eq $expectedKeys.Count) 'Catalog emitted a borrowed GPO row or dropped a valid neighbor.'
    for ($index = 0; $index -lt $rows.Count; $index++) {
        Assert-Catalog ($null -ne $rows[$index].PSObject.Properties['Id']) 'Catalog emitted an unexpected result object.'
        Assert-CatalogRow $rows[$index] $expectedKeys[$index] $fault $strict
    }
}

function New-Scenario(
    [string]$Fault,
    [string]$Position = 'Middle',
    [string]$Preference = 'ExplicitContinue',
    [string]$Select = 'All',
    [bool]$Strict = $false
) {
    return [pscustomobject]@{
        Fault = $Fault
        Position = $Position
        Preference = $Preference
        Select = $Select
        Strict = $Strict
    }
}

$scenarios = @(
    if ($Case -eq 'Regression') {
        foreach ($fault in @('BadGuid', 'BadFlags', 'BadLinkOptions')) {
            foreach ($position in @('First', 'Middle', 'Sole')) {
                New-Scenario $fault $position 'InheritedContinue'
                New-Scenario $fault $position 'ExplicitContinue'
            }
        }
        New-Scenario -Fault 'BadGuid' -Select 'GuidPrior'
        New-Scenario -Fault 'BadGuid' -Select 'Name'
        New-Scenario -Fault 'BadFlags' -Select 'Guid'
        New-Scenario -Fault 'BadLinkOptions' -Select 'Guid'
        New-Scenario -Fault 'MissingGuid' -Strict $true
        New-Scenario -Fault 'MissingFlags' -Strict $true
    }
    else {
        foreach ($selector in @('Default', 'All', 'FalseAll', 'Name', 'Guid', 'NoMatch')) {
            New-Scenario -Fault 'None' -Select $selector
        }
        New-Scenario -Fault 'ExplicitConnection'
        New-Scenario -Fault 'EmptyCredential'
        foreach ($fault in @('BadGuid', 'BadFlags', 'BadLinkOptions')) {
            New-Scenario -Fault $fault -Preference 'CaughtContinue'
            New-Scenario -Fault $fault -Preference 'CaughtStop'
        }
        foreach ($fault in @(
                'NullFlags', 'MissingOptions', 'NullOptions', 'BadOptions',
                'MissingLink', 'NullLink', 'MissingSites', 'NoSites'
            )) {
            New-Scenario -Fault $fault
            New-Scenario -Fault $fault -Strict $true
        }
        New-Scenario -Fault 'MissingFlags'
    }
)
$script:NativeErrorIds = @{
    BadGuid = Get-NativeErrorId 'BadGuid'
    BadFlags = Get-NativeErrorId 'BadFlags'
    BadLinkOptions = Get-NativeErrorId 'BadLinkOptions'
}
$mismatches = [Collections.Generic.List[string]]::new()
foreach ($scenario in $scenarios) {
    $actual = Invoke-CatalogScenario $scenario.Fault $scenario.Position $scenario.Preference $scenario.Select $scenario.Strict
    try {
        Assert-Scenario $scenario $actual
    }
    catch {
        $mismatches.Add(('{0}/{1}/{2}/{3}/Strict={4} - {5}' -f
            $scenario.Fault, $scenario.Position, $scenario.Preference, $scenario.Select, $scenario.Strict, $_.Exception.Message))
    }
}
if ($mismatches.Count) {
    throw ("{0} of {1} catalog row isolation cases failed.{2}{3}" -f
        $mismatches.Count, $scenarios.Count, [Environment]::NewLine, ($mismatches -join [Environment]::NewLine))
}
Write-Output ("PASS GPO catalog row isolation {0} {1}" -f $Case, $scenarios.Count)
