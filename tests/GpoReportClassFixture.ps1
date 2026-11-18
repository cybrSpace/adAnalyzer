[CmdletBinding()]
param(
    [ValidateSet('Contracts', 'Direct', 'Standalone')][string]$Case = 'Contracts',
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

# Exact native report command from accepted U-111, before class ownership.
$script:ReportOracle = @'
function Get-ADAnalyzerGpoReport {
    [CmdletBinding(DefaultParameterSetName = 'Gpo')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Gpo')]$Gpo,
        [Parameter(Mandatory, ParameterSetName = 'Guid')][guid]$Guid,
        [Parameter(Mandatory, ParameterSetName = 'Guid')][string]$Domain,
        [Parameter(ParameterSetName = 'Guid')][string]$Server = $Domain,
        [pscredential]$Credential = [pscredential]::Empty,
        [switch]$AsObject,
        [hashtable]$SidNames = @{}

    )
    if ($PSCmdlet.ParameterSetName -eq 'Guid') {
        $Gpo = @(Get-ADAnalyzerGpo -Guid $Guid -Domain $Domain -Server $Server -Credential $Credential)
        if ($Gpo.Count -ne 1) {
            throw 'GPO was not found or was ambiguous'
        }
        $Gpo = $Gpo[0]
    }
    # Use only the single validated target for SYSVOL and directory lookups.
    $hostPattern = '\A[A-Za-z0-9][A-Za-z0-9._-]*\z'
    if (($reportServer = $Gpo.Server) -isnot [string] -or
        $reportServer -notmatch $hostPattern -or
        ($reportDomain = $Gpo.Domain) -isnot [string] -or
        $reportDomain -notmatch $hostPattern) {
        throw 'Invalid GPO server/domain'
    }
    $id = [guid]$Gpo.Id
    $drive = $null
    $completed = $false
    try {
        if ($Credential -and $Credential -ne [pscredential]::Empty) {
            $drive = New-PSDrive `
                -Name ('ADGpo' + [guid]::NewGuid().ToString('N')) `
                -PSProvider FileSystem `
                -Root ('\\{0}\SYSVOL' -f $reportServer) `
                -Credential $Credential `
                -Scope Local `
                -ErrorAction Stop `
                -WhatIf:$false `
                -Confirm:$false
            $path = Join-Path ($drive.Name + ':\') ('{0}\Policies\{1}' -f $reportDomain, $id.ToString('B'))
        }
        else {
            $path = '\\{0}\SYSVOL\{1}\Policies\{2}' -f $reportServer, $reportDomain, $id.ToString('B')
        }
        $parsed = Read-ADAnalyzerGpo -Path $path
        $mismatch = $null -ne $parsed.SysvolVersion -and
        $null -ne $Gpo.Version -and
        $parsed.SysvolVersion -ne ([long]$Gpo.Version -band [long]4294967295)
        if ($mismatch) {
            Write-Warning ('GPO {0} directory and SYSVOL versions differ; the policy may be updating or replicating' -f $Gpo.Id)
        }
        if ($AsObject) {
            [pscustomobject]@{
                Gpo = $Gpo
                Policy = $parsed
                VersionMismatch = $mismatch
            }
        }
        else {
            $names = if ($null -ne $SidNames) {
                $SidNames.Clone()
            }
            else {
                @{}
            }
            $status = @{}
            $connection = @{
                Server = $reportServer
                ErrorAction = 'Stop'
            }
            if ($Credential -and $Credential -ne [pscredential]::Empty) {
                $connection.Credential = $Credential
            }
            $tokens = @($parsed.SecuritySettings | Where-Object Kind `
                    -eq 'UserRightsAssignment' | ForEach-Object { $_.Value } | ForEach-Object { ([string]$_).TrimStart('*') } | Where-Object { $_ -match '^S-1-5-21-(\d+-){3}\d+$' } | Select-Object `
                    -Unique)
            foreach ($token in $tokens) {
                if ($names.ContainsKey($token)) {
                    continue
                }
                try {
                    $matches = @(Get-ADObject -Filter "objectSid -eq '$token'" -Properties sAMAccountName @connection)
                    if ($matches.Count -eq 1 -and $matches[0].sAMAccountName) {
                        $names[$token] = [string]$matches[0].sAMAccountName
                        $status[$token] = 'Resolved'
                    }
                    else {
                        $status[$token] = 'NotFound'
                    }
                }
                catch {
                    $status[$token] = 'LookupFailed'
                    Write-Warning "Unable to resolve policy SID $token on ${reportServer}: $($_.Exception.Message)"
                }
            }
            ConvertTo-AnalyzerGpoXml $Gpo $parsed $names $status
        }
        $completed = $true
    }
    finally {
        if ($drive -and $completed) {
            Remove-PSDrive -Name $drive.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
        }
        elseif ($drive) {
            try {
                Remove-PSDrive -Name $drive.Name -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
            }
            catch {
                # Retain any pending error and the native cleanup diagnostic.
            }
        }
    }
}
'@

function Assert-GpoReportClass($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Import-Module {
    throw 'Report loading or construction tried to acquire a directory provider.'
}

if ($Case -eq 'Direct') {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')
}

function Assert-GpoReportBinding {
    $source = $script:ReportOracle.Replace("`r`n", "`n")
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = [BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($source))).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
    Assert-GpoReportClass ($hash -ieq '84f1f89043d559d6fabce348fea994a12ab6f043501022810911b0a5a710930f') 'The frozen report command changed.'
    $tokens = $null
    $errors = $null
    $parsed = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    $command = Get-Command Get-ADAnalyzerGpoReport -CommandType Function
    $actual = $command.ScriptBlock.Ast
    if ($actual -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $actual = $actual.Body
    }
    Assert-GpoReportClass ($errors.Count -eq 0 -and $command.CmdletBinding -and
        $command.DefaultParameterSet -ceq 'Gpo' -and
        $actual.ParamBlock.Extent.Text.Replace("`r`n", "`n") -ceq
        $parsed.EndBlock.Statements[0].Body.ParamBlock.Extent.Text.Replace("`r`n", "`n")
    ) 'The compatibility report command changed native binding.'
}

$script:ReportId = [guid]'22222222-2222-2222-2222-222222222222'
$script:ReportDomain = 'report.fixture.invalid'
$script:ReportAlias = 'alias.report.fixture.invalid'
$script:ReportServer = 'dc.report.fixture.invalid'
$script:DomainDn = 'DC=report,DC=fixture,DC=invalid'
$script:RequestedServer = $script:ReportDomain
$script:ReportCredential = [pscredential]::new('REPORT\fixture',
    (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
$script:ExpectedCredential = [pscredential]::Empty
$script:ExpectedDll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:Events = [Collections.Generic.List[string]]::new()
$script:NativeDrive = $null
$script:Mode = 'Normal'
$script:BundledOnly = $false
$script:ReportMarker = 'inert-report-presence-fixture'

function Assert-ReportProvider([object]$Credential, [string]$Action) {
    if ($script:ExpectedCredential -eq [pscredential]::Empty) {
        Assert-GpoReportClass ($null -eq $Credential) 'An ambient directory query acquired explicit credentials.'
    }
    else {
        Assert-GpoReportClass ([object]::ReferenceEquals($Credential, $script:ExpectedCredential)) 'The report lost the selected credential reference.'
    }
    Assert-GpoReportClass ($Action -ceq 'Stop') 'A report provider query failed to bind ErrorAction Stop.'
}

function Invoke-ReportFixtureRoot {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Assert-ReportProvider $Credential ([string]$PSBoundParameters['ErrorAction'])
    Assert-GpoReportClass ($Server -ceq $script:RequestedServer) 'RootDSE used the wrong requested directory endpoint.'
    $script:Events.Add('Root')
    [pscustomobject]@{
        DnsHostName = $script:ReportServer
        ConfigurationNamingContext = $null
    }
}

function Invoke-ReportFixtureDomain {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-ReportProvider $Credential ([string]$PSBoundParameters['ErrorAction'])
    Assert-GpoReportClass ($Identity -ceq $script:ReportDomain -and $Server -ceq $script:ReportServer) (
        'Catalog domain query lost the selected endpoint or identity.'
    )
    $script:Events.Add('Domain')
    [pscustomobject]@{
        DNSRoot = $script:ReportDomain
        DistinguishedName = $script:DomainDn
    }
}

function Invoke-ReportFixtureObjects {
    [CmdletBinding()]
    param(
        [string]$LDAPFilter,
        [string]$Filter,
        [string]$SearchBase,
        [string[]]$Properties,
        [string]$Server,
        [pscredential]$Credential
    )

    Assert-ReportProvider $Credential ([string]$PSBoundParameters['ErrorAction'])
    Assert-GpoReportClass ($Server -ceq $script:ReportServer) 'A catalog or SID query lost its selected directory endpoint.'
    if ($LDAPFilter -eq '(objectClass=groupPolicyContainer)') {
        Assert-GpoReportClass ($SearchBase -ceq "CN=Policies,CN=System,$script:DomainDn") 'Catalog policy base changed.'
        $script:Events.Add('Policies')
        if ($script:Mode -eq 'Missing') {
            return
        }
        if ($script:Mode -eq 'Duplicate') {
            $script:SourceRow
        }
        return $script:SourceRow
    }
    if ($LDAPFilter -eq '(gPLink=*)') {
        Assert-GpoReportClass ($SearchBase -ceq $script:DomainDn) 'Catalog link base changed.'
        $script:Events.Add('Links')
        return
    }

    Assert-GpoReportClass ($Properties.Count -eq 1 -and $Properties[0] -ceq 'sAMAccountName' -and
        $Filter -cmatch "^objectSid -eq 'S-1-5-21-1-2-3-(?<Member>100[1-6])'$"
    ) 'SID query did not use the exact observed identity and field.'
    $member = $Matches.Member
    $script:Events.Add('Sid' + $member)
    switch ($member) {
        '1001' {
            [pscustomobject]@{ sAMAccountName = 'Resolved fixture member' }
        }
        '1002' {
            return
        }
        '1003' {
            [pscustomobject]@{ sAMAccountName = 'Ambiguous one' }
            [pscustomobject]@{ sAMAccountName = 'Ambiguous two' }
        }
        '1004' {
            [pscustomobject]@{ sAMAccountName = '' }
        }
        '1005' {
            throw [UnauthorizedAccessException]::new('Fixture SID lookup denied.')
        }
        '1006' {
            [pscustomobject]@{ sAMAccountName = 'Directory fixture member' }
        }
    }
}

function Get-ADRootDSE {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Assert-GpoReportClass (-not $script:BundledOnly) 'Direct report queried ambient RootDSE.'
    Invoke-ReportFixtureRoot @PSBoundParameters
}

function Get-ADDomain {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server, [pscredential]$Credential)

    Assert-GpoReportClass (-not $script:BundledOnly) 'Direct report queried the ambient domain command.'
    Invoke-ReportFixtureDomain @PSBoundParameters
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        [string]$LDAPFilter,
        [string]$Filter,
        [string]$SearchBase,
        [string[]]$Properties,
        [string]$Server,
        [pscredential]$Credential
    )

    Assert-GpoReportClass (-not $script:BundledOnly) 'Direct report queried the ambient object command.'
    Invoke-ReportFixtureObjects @PSBoundParameters
}

function New-PSDrive {
    param(
        [string]$Name, [string]$PSProvider, [string]$Root, [pscredential]$Credential,
        [string]$Scope, [string]$ErrorAction, [switch]$WhatIf, [switch]$Confirm
    )

    Assert-GpoReportClass ($null -eq $script:NativeDrive -and $Name -cmatch '^ADGpo[0-9a-f]{32}$' -and
        $PSProvider -ceq 'FileSystem' -and $Scope -ceq 'Local' -and -not $WhatIf -and -not $Confirm -and
        $Root -ceq $script:TrustedRoot -and [object]::ReferenceEquals($Credential, $script:ReportCredential) -and
        $ErrorAction -ceq 'Stop'
    ) 'The report mounted a drive outside the proved connection contract.'
    $script:Events.Add('Mount')
    $script:NativeDrive = Microsoft.PowerShell.Management\New-PSDrive -Name $Name -PSProvider FileSystem `
        -Root $script:TempRoot -Scope '1' -ErrorAction Stop -WhatIf:$false -Confirm:$false
    $script:NativeDrive
}

function Remove-PSDrive {
    param([string]$Name, [switch]$Force, [string]$ErrorAction, [switch]$WhatIf, [switch]$Confirm)

    $owned = Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -Scope '1' -ErrorAction Stop
    Assert-GpoReportClass ($null -ne $script:NativeDrive -and $Name -ceq $script:NativeDrive.Name -and
        $owned.Root -ceq $script:TempRoot -and $Force -and $ErrorAction -ceq 'Stop' -and -not $WhatIf -and -not $Confirm
    ) 'The report did not remove its own local drive with the original flags.'
    $script:Events.Add('Remove')
    Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Scope '1' -Force -ErrorAction Stop -WhatIf:$false -Confirm:$false
    if ($script:Mode -in 'CleanupOnly', 'PrimaryCleanup') {
        throw [UnauthorizedAccessException]::new('Fixture cleanup denied after removal.')
    }
}

function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)

    if ($LiteralPath.StartsWith('\\', [StringComparison]::Ordinal)) {
        Assert-GpoReportClass ($LiteralPath -ceq $script:TrustedUnc) 'The report attempted a different UNC location.'
        $script:Events.Add('ReadUNC')
        $PSBoundParameters['LiteralPath'] = $script:PolicyPath
    }
    elseif ($script:NativeDrive -and $LiteralPath.StartsWith($script:NativeDrive.Name + ':', [StringComparison]::OrdinalIgnoreCase)) {
        $script:Events.Add('Read')
        $item = Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
        Assert-GpoReportClass ($item.FullName -ceq $script:PolicyPath) 'The reader used the wrong location within the scoped temporary drive.'
        return $item
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}

function Reset-ReportFixture(
    [string]$Mode = 'Normal',
    [pscredential]$Credential = [pscredential]::Empty,
    [string]$Requested = $script:ReportDomain
) {
    $script:Mode = $Mode
    $script:ExpectedCredential = $Credential
    $script:RequestedServer = $Requested
    $script:Events.Clear()
    $script:NativeDrive = $null
    $script:ReportGpo.Version = 64
    $script:SourceRow.versionNumber = 64
    if ($Mode -eq 'WarningStop') {
        $script:ReportGpo.Version = 65
    }
    if ($Mode -eq 'SignedVersion') {
        $script:ReportGpo.Version = -1
    }

    $fixtureVersion = '64'
    if ($Mode -eq 'SignedVersion') {
        $fixtureVersion = '4294967295'
    }
    [IO.File]::WriteAllText((Join-Path $script:PolicyPath 'GPT.INI'), "[General]`nVersion=$fixtureVersion")
    if ($Mode -eq 'AbsentStoredVersion') {
        [IO.File]::WriteAllText((Join-Path $script:PolicyPath 'GPT.INI'), '[General]')
    }
    if ($Mode -in 'PrimaryOnly', 'PrimaryCleanup') {
        [IO.File]::WriteAllBytes($script:RegistryPath, [byte[]]@(1, 2, 3))
    }
    elseif ([IO.File]::Exists($script:RegistryPath)) {
        [IO.File]::Delete($script:RegistryPath)
    }
}

function Test-FixtureDriveGone {
    if ($null -eq $script:NativeDrive) {
        return $true
    }
    return $null -eq (Microsoft.PowerShell.Management\Get-PSDrive -Name $script:NativeDrive.Name -ErrorAction SilentlyContinue)
}

function ConvertTo-ReportFixtureJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 18 -Compress
}

function Get-ReportFixtureDiagnostic($Record) {
    if ($null -eq $Record) {
        return
    }
    if ($Record -isnot [Management.Automation.ErrorRecord] -and $Record -is [Management.Automation.IContainsErrorRecord]) {
        $Record = $Record.ErrorRecord
    }
    if ($Record -isnot [Management.Automation.ErrorRecord]) {
        return [pscustomobject]@{ Type = $Record.GetType().FullName }
    }
    $cause = $Record.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Type = $Record.Exception.GetType().FullName
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Get-ReportFixtureXml([string]$Value) {
    $Value -replace '(?<=<ReadTime>)[^<]*(?=</ReadTime>)', 'fixture-time'
}

function Get-ReportFixtureSignal($Value) {
    if ($Value -is [Management.Automation.ErrorRecord]) {
        return [pscustomobject]@{
            Kind = 'Error'
            Record = Get-ReportFixtureDiagnostic $Value
        }
    }
    if ($Value -is [Management.Automation.WarningRecord]) {
        return [pscustomobject]@{
            Kind = 'Warning'
            Record = $Value.Message
        }
    }
    if ($Value -is [string]) {
        return [pscustomobject]@{
            Kind = 'Xml'
            Record = Get-ReportFixtureXml $Value
        }
    }
    return [pscustomobject]@{
        Kind = 'Object'
        Record = $Value
    }
}

function New-ReportFixtureInput {
    $script:TrustedRoot = '\\{0}\SYSVOL' -f $script:ReportServer
    $script:TrustedUnc = '{0}\{1}\Policies\{2}' -f $script:TrustedRoot, $script:ReportDomain, $script:ReportId.ToString('B')
    $script:TempRoot = [IO.Path]::GetFullPath(
        (Join-Path ([IO.Path]::GetTempPath()) ('gpo-report-class-' + [guid]::NewGuid().ToString('N'))))
    $relative = '{0}/Policies/{1}' -f $script:ReportDomain, $script:ReportId.ToString('B')
    $script:PolicyPath = [IO.Path]::GetFullPath((Join-Path $script:TempRoot $relative))
    $machine = Join-Path $script:PolicyPath 'Machine'
    $security = Join-Path $machine 'Microsoft/Windows NT/SecEdit'
    $preferences = Join-Path $machine 'Preferences'
    $script:RegistryPath = Join-Path $machine 'Registry.pol'
    $null = [IO.Directory]::CreateDirectory($security)
    $null = [IO.Directory]::CreateDirectory($preferences)
    $template = @'
[Unicode]
Unicode=yes
[Privilege Rights]
SeNetworkLogonRight=*S-1-5-32-544,*S-1-5-21-1-2-3-1001,*S-1-5-21-1-2-3-1001,*S-1-5-21-1-2-3-1002,*S-1-5-21-1-2-3-1003,*S-1-5-21-1-2-3-1004,*S-1-5-21-1-2-3-1005,*S-1-5-21-1-2-3-1006
'@
    [IO.File]::WriteAllText((Join-Path $security 'GptTmpl.inf'), $template, [Text.Encoding]::Unicode)
    [IO.File]::WriteAllText((Join-Path $preferences 'Fixture.xml'),
        "<Fixture><Properties cpassword='$script:ReportMarker' /></Fixture>")
    $script:ReportGpo = [pscustomobject]@{
        Id = $script:ReportId
        Domain = $script:ReportDomain
        Server = $script:ReportServer
        RequestedServer = $script:ReportAlias
        DirectoryFilePath = '\\ignored.fixture.invalid\ignored'
        PolicyPath = '\\ignored.fixture.invalid\ignored'
        Version = 64
        Flags = 0
        Links = @()
    }
    $script:SourceRow = [pscustomobject]@{
        Name = $script:ReportId.ToString('B')
        displayName = 'Fixture policy'
        DistinguishedName = "CN=$($script:ReportId.ToString('B')),CN=Policies,CN=System,$script:DomainDn"
        gPCFileSysPath = $script:ReportGpo.DirectoryFilePath
        flags = 0
        whenCreated = [datetime]'2020-01-01'
        whenChanged = [datetime]'2020-02-01'
        versionNumber = 64
        gPCWQLFilter = $null
        gPCMachineExtensionNames = $null
        gPCUserExtensionNames = $null
    }
}

function New-ReportFixtureRequest(
    [string]$Name, [bool]$ById = $false, [bool]$Xml = $false,
    [bool]$Explicit = $false, [bool]$Credential = $false,
    [string]$Mode = 'Normal', [bool]$Names = $false
) {
    [pscustomobject]@{
        Name = $Name
        ById = $ById
        Xml = $Xml
        Explicit = $Explicit
        Credential = $Credential
        Mode = $Mode
        Names = $Names
    }
}

function Reset-ReportFixtureRequest($Request) {
    $credential = [pscredential]::Empty
    if ($Request.Credential) {
        $credential = $script:ReportCredential
    }
    $requested = $script:ReportDomain
    if ($Request.Explicit) {
        $requested = $script:ReportAlias
    }
    Reset-ReportFixture $Request.Mode $credential $requested
}

function New-ReportSidNames([bool]$Supplied) {
    # Member 1006 is never looked up, except when the invocation has no map.
    $map = @{}
    if ($Supplied) {
        $map['S-1-5-21-1-2-3-1006'] = 'Supplied fixture member'
    }
    $map
}

function Invoke-ReportCommandFixture($Request, [bool]$Frozen) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:ReportOracle))
    }
    Reset-ReportFixtureRequest $Request
    $observedErrors = @()
    $names = New-ReportSidNames $Request.Names
    if ($Request.Mode -eq 'CloneFailure') {
        $names = [GpoReportFixtureFaultingSidMap]::new()
    }
    $before = ConvertTo-ReportFixtureJson $names
    $splat = @{
        AsObject = -not $Request.Xml
        SidNames = $names
        ErrorVariable = 'observedErrors'
        ErrorAction = 'Stop'
    }
    if ($Request.ById) {
        $splat.Guid = $script:ReportId
        $splat.Domain = $script:ReportDomain
        if ($Request.Explicit) {
            $splat.Server = $script:ReportAlias
        }
    }
    else {
        $splat.Gpo = $script:ReportGpo
    }
    if ($Request.Credential) {
        $splat.Credential = $script:ReportCredential
    }
    if ($Request.Mode -eq 'WarningStop') {
        $splat.WarningAction = 'Stop'
    }
    $signals = [Collections.Generic.List[object]]::new()
    $caught = $null
    try {
        Get-ADAnalyzerGpoReport @splat 3>&1 2>&1 | ForEach-Object {
            $signals.Add((Get-ReportFixtureSignal $_))
        }
    }
    catch {
        $caught = Get-ReportFixtureDiagnostic $_
    }
    return [pscustomobject]@{
        Stream = $signals.ToArray()
        Caught = $caught
        ErrorVariable = @($observedErrors | ForEach-Object { Get-ReportFixtureDiagnostic $_ })
        Events = $script:Events.ToArray()
        MapUnchanged = $before -ceq (ConvertTo-ReportFixtureJson $names)
        OwnedDriveGone = Test-FixtureDriveGone
    }
}

function Invoke-ReportDirectRequest($Service, $Request, [hashtable]$Names) {
    if (-not $Request.ById) {
        if ($Request.Xml) {
            if ($Request.Names) {
                return $Service.RenderXml($script:ReportGpo, $script:ExpectedCredential, $Names)
            }
            if ($Request.Credential) {
                return $Service.RenderXml($script:ReportGpo, $script:ExpectedCredential)
            }
            return $Service.RenderXml($script:ReportGpo)
        }
        if ($Request.Credential) {
            return $Service.Read($script:ReportGpo, $script:ExpectedCredential)
        }
        return $Service.Read($script:ReportGpo)
    }
    if ($Request.Xml) {
        if ($Request.Names) {
            return $Service.RenderXmlById($script:ReportId, $script:ReportDomain, $script:RequestedServer, $script:ExpectedCredential, $Names)
        }
        if ($Request.Credential) {
            return $Service.RenderXmlById($script:ReportId, $script:ReportDomain, $script:RequestedServer, $script:ExpectedCredential)
        }
        if ($Request.Explicit) {
            return $Service.RenderXmlById($script:ReportId, $script:ReportDomain, $script:RequestedServer)
        }
        return $Service.RenderXmlById($script:ReportId, $script:ReportDomain)
    }
    if ($Request.Credential) {
        return $Service.ReadById($script:ReportId, $script:ReportDomain, $script:RequestedServer, $script:ExpectedCredential)
    }
    if ($Request.Explicit) {
        return $Service.ReadById($script:ReportId, $script:ReportDomain, $script:RequestedServer)
    }
    return $Service.ReadById($script:ReportId, $script:ReportDomain)
}

function Invoke-ReportDirectFixture($Service, $Request) {
    Reset-ReportFixtureRequest $Request
    $names = New-ReportSidNames $Request.Names
    $before = ConvertTo-ReportFixtureJson $names
    $beforeMetadata = ConvertTo-ReportFixtureJson $script:ReportGpo
    $signals = [Collections.Generic.List[object]]::new()
    $caught = $null
    $Error.Clear()
    if ($Request.Mode -eq 'WarningStop') {
        $WarningPreference = 'Stop'
    }
    try {
        Invoke-ReportDirectRequest $Service $Request $names 3>&1 2>&1 | ForEach-Object {
            $signals.Add((Get-ReportFixtureSignal $_))
        }
    }
    catch {
        $caught = Get-ReportFixtureDiagnostic $_
    }
    [pscustomobject]@{
        Stream = $signals.ToArray()
        Caught = $caught
        Diagnostics = @($Error | ForEach-Object { Get-ReportFixtureDiagnostic $_ })
        Events = $script:Events.ToArray()
        MapUnchanged = $before -ceq (ConvertTo-ReportFixtureJson $names)
        MetadataUnchanged = $beforeMetadata -ceq (ConvertTo-ReportFixtureJson $script:ReportGpo)
        OwnedDriveGone = Test-FixtureDriveGone
    }
}

function Assert-ReportFixturePresence([string]$Text) {
    $markerBytes = [Text.Encoding]::UTF8.GetBytes($script:ReportMarker)
    $encoded = [Convert]::ToBase64String($markerBytes)
    $document = [xml]$Text
    $preference = $document.SelectSingleNode("//ExtensionData[Name='Preferences']/Extension/Record/Value")
    Assert-GpoReportClass ($null -ne $preference -and -not $Text.Contains($script:ReportMarker) -and
        -not $Text.Contains($encoded)
    ) 'A synthetic stored preference did not render as presence-only.'
    $xml = [xml]$preference.InnerText
    Assert-GpoReportClass ($null -ne $xml.SelectSingleNode("//Properties[@cpasswordPresent='true']") -and
        $null -eq $xml.SelectSingleNode('//@cpassword')
    ) 'The preference indicator lost its Boolean-only meaning.'
}

$requests = @(
    New-ReportFixtureRequest 'Read'
    New-ReportFixtureRequest 'ReadCredential' -Credential $true
    New-ReportFixtureRequest 'ReadId' -ById $true
    New-ReportFixtureRequest 'ReadIdServer' -ById $true -Explicit $true
    New-ReportFixtureRequest 'ReadIdCredential' -ById $true -Explicit $true -Credential $true
    New-ReportFixtureRequest 'Render' -Xml $true
    New-ReportFixtureRequest 'RenderCredential' -Xml $true -Credential $true
    New-ReportFixtureRequest 'RenderNames' -Xml $true -Credential $true -Names $true
    New-ReportFixtureRequest 'RenderId' -ById $true -Xml $true
    New-ReportFixtureRequest 'RenderIdServer' -ById $true -Xml $true -Explicit $true
    New-ReportFixtureRequest 'RenderIdCredential' -ById $true -Xml $true -Explicit $true -Credential $true
    New-ReportFixtureRequest 'RenderIdNames' -ById $true -Xml $true -Explicit $true -Credential $true -Names $true
    New-ReportFixtureRequest 'SignedVersion' -Credential $true -Mode SignedVersion
    New-ReportFixtureRequest 'AbsentStoredVersion' -Credential $true -Mode AbsentStoredVersion
)
$failures = @(
    New-ReportFixtureRequest 'MissingById' -ById $true -Explicit $true -Credential $true -Mode Missing
    New-ReportFixtureRequest 'DuplicateById' -ById $true -Explicit $true -Credential $true -Mode Duplicate
    New-ReportFixtureRequest 'CleanupOnly' -Credential $true -Mode CleanupOnly
    New-ReportFixtureRequest 'PrimaryOnly' -Credential $true -Mode PrimaryOnly
    New-ReportFixtureRequest 'PrimaryCleanup' -Credential $true -Mode PrimaryCleanup
    New-ReportFixtureRequest 'WarningStop' -Credential $true -Mode WarningStop
)
if ($Case -eq 'Contracts') {
    Add-Type @'
public sealed class GpoReportFixtureFaultingSidMap : System.Collections.Hashtable
{
    public override object Clone()
    {
        throw new System.InvalidOperationException("Fixture SID map clone failed.");
    }
}
'@
    $failures += New-ReportFixtureRequest 'CloneFailure' -Xml $true -Credential $true -Mode CloneFailure
}

function Assert-ReportFixtureSuccess($Observed, $Request) {
    $items = @($Observed.Stream | Where-Object Kind -in 'Object', 'Xml')
    Assert-GpoReportClass ($null -eq $Observed.Caught -and $items.Count -eq 1 -and
        $Observed.MapUnchanged -and $Observed.OwnedDriveGone
    ) "Report $($Request.Name) did not yield an isolated successful result."
    if (-not $Request.Xml) {
        $result = $items[0].Record
        Assert-GpoReportClass ($result.PSObject.Properties.Name -join '|' -ceq 'Gpo|Policy|VersionMismatch' -and
            $result.VersionMismatch -is [bool] -and -not $result.VersionMismatch -and
            $result.Gpo.Id -is [guid] -and $result.Gpo.Server -ceq $script:ReportServer -and
            @($Observed.Events | Where-Object { $_ -like 'Sid*' }).Count -eq 0 -and
            $result.Policy.XmlFiles.Count -eq 1 -and -not $result.Policy.XmlFiles[0].Xml.Contains($script:ReportMarker)
        ) "Report $($Request.Name) changed its object shape, mismatch or presence-only policy."
        if (-not $Request.ById) {
            Assert-GpoReportClass ([object]::ReferenceEquals($result.Gpo, $script:ReportGpo)) 'Supplied GPO metadata lost its original reference.'
        }
        if ($Request.Mode -eq 'SignedVersion') {
            Assert-GpoReportClass ($result.Gpo.Version -eq -1 -and
                $result.Policy.SysvolVersion -eq [long]4294967295
            ) 'The signed directory version did not match the real unsigned stored version.'
        }
        if ($Request.Mode -eq 'AbsentStoredVersion') {
            Assert-GpoReportClass ($null -eq $result.Policy.SysvolVersion) 'The fixture supplied an unexpected stored version.'
        }
        return
    }
    Assert-ReportFixturePresence $items[0].Record
    $document = [xml]$items[0].Record
    $members = @($document.SelectNodes('//Member[SID]'))
    $sites = 'Resolved|Resolved|Resolved|NotFound|NotFound|NotFound|LookupFailed|Resolved'
    Assert-GpoReportClass (($members | ForEach-Object { $_.SelectSingleNode('Resolution').InnerText }) -join '|' -ceq $sites -and
        @($Observed.Events | Where-Object { $_ -ceq 'Sid1001' }).Count -eq 1 -and
        @($Observed.Events | Where-Object { $_ -ceq 'Sid1006' }).Count -eq [int](-not $Request.Names)
    ) "Report $($Request.Name) changed the ordered, deduplicated SID results."
    if ($Request.Names) {
        $finalName = $members[-1].SelectSingleNode('Name')
        Assert-GpoReportClass ($finalName.InnerText -ceq 'Supplied fixture member') 'A supplied SID mapping did not take precedence.'
    }
}

$reportService = $null
if ($Case -ne 'Contracts') {
    $reportService = [ADAnalyzerGpoReportService]::new()
    Assert-GpoReportClass ($reportService.GetType().Name -ceq 'ADAnalyzerGpoReportService' -and
        $script:Events.Count -eq 0
    ) 'Literal report service construction did not remain inert.'
}
else {
    Assert-GpoReportBinding
}

$script:TempRoot = $null
$count = 1
try {
    New-ReportFixtureInput
    if ($Case -eq 'Contracts') {
        foreach ($request in $requests + $failures) {
            $expected = Invoke-ReportCommandFixture $request $true
            $actual = Invoke-ReportCommandFixture $request $false
            Assert-GpoReportClass (
                (ConvertTo-ReportFixtureJson $expected) -ceq (ConvertTo-ReportFixtureJson $actual)
            ) "Native report $($request.Name) changed its stream, typed diagnostics or connection events."
            if ($request.Mode -in 'Normal', 'SignedVersion', 'AbsentStoredVersion') {
                Assert-ReportFixtureSuccess $actual $request
            }
            else {
                Assert-GpoReportClass ($null -ne $actual.Caught -or
                    @($actual.Stream | Where-Object Kind -eq 'Error').Count -gt 0
                ) "Frozen $($request.Name) failed to exercise a native report error."
                if ($request.Mode -eq 'CloneFailure') {
                    Assert-GpoReportClass ($actual.Caught.Cause -ceq 'System.InvalidOperationException' -and
                        $actual.Caught.Message -ceq 'Fixture SID map clone failed.' -and
                        @($actual.ErrorVariable | Where-Object Cause -eq $actual.Caught.Cause).Count -gt 0 -and
                        ($actual.Events -join '|') -ceq 'Mount|Read|Remove'
                    ) 'The native SID map clone diagnostic was not captured from the mounted report.'
                }
            }
            $count++
        }
    }
    else {
        $expectedReports = @{}
        foreach ($request in $requests + $failures) {
            $expectedReports[$request.Name] = Invoke-ReportCommandFixture $request $true
        }
        $script:ReportExports = @{
            'Get-ADRootDSE' = Get-Command Invoke-ReportFixtureRoot -CommandType Function
            'Get-ADDomain' = Get-Command Invoke-ReportFixtureDomain -CommandType Function
            'Get-ADObject' = Get-Command Invoke-ReportFixtureObjects -CommandType Function
        }

        function Import-Module {
            [CmdletBinding()]
            param([string]$Name, [string]$Scope, [switch]$PassThru)

            Assert-GpoReportClass ([IO.Path]::IsPathRooted($Name) -and $Name -ceq $script:ExpectedDll -and
                $Scope -ceq 'Local' -and $PassThru -and $PSBoundParameters['ErrorAction'] -ceq 'Stop'
            ) 'Direct report acquired a provider outside the bundled local contract.'
            $script:Events.Add('Import')
            if ($script:Mode -eq 'ImportUnavailable') {
                throw [IO.FileLoadException]::new('Fixture bundled provider unavailable.')
            }
            [pscustomobject]@{
                Path = $Name
                ExportedCmdlets = $script:ReportExports
            }
        }
        function Get-ADAnalyzerGpoReport {
            throw 'The report class called its compatibility command.'
        }
        function Get-ADAnalyzerGpo {
            throw 'Direct report used the compatibility catalog.'
        }
        function Read-ADAnalyzerGpo {
            throw 'Direct report used the compatibility reader.'
        }
        function ConvertTo-AnalyzerGpoXml {
            throw 'Direct report used the compatibility writer.'
        }
        $script:BundledOnly = $true
        $PSModuleAutoLoadingPreference = 'None'

        foreach ($request in $requests) {
            $actual = Invoke-ReportDirectFixture $reportService $request
            Assert-ReportFixtureSuccess $actual $request
            $expected = $expectedReports[$request.Name]
            Assert-GpoReportClass ($actual.MetadataUnchanged -and
                (ConvertTo-ReportFixtureJson $actual.Stream) -ceq (ConvertTo-ReportFixtureJson $expected.Stream) -and
                (@($actual.Events | Where-Object { $_ -ne 'Import' }) -join '|') -ceq ($expected.Events -join '|')
            ) "Direct report $($request.Name) changed its result, warning order or provider binding."
            $imports = @($actual.Events | Where-Object { $_ -ceq 'Import' }).Count
            if ($request.ById) {
                Assert-GpoReportClass ($actual.Events[0] -ceq 'Import' -and $imports -ge 1 -and $imports -le 2) (
                    'GUID discovery did not use an operation-local provider acquisition.'
                )
            }
            elseif ($request.Xml) {
                Assert-GpoReportClass ($imports -eq 1) 'The first unresolved XML SID did not lazily acquire one bundled provider.'
            }
            else {
                Assert-GpoReportClass ($imports -eq 0) 'Supplied object-mode metadata acquired a directory provider.'
            }
            $count++
        }

        foreach ($request in $failures) {
            $actual = Invoke-ReportDirectFixture $reportService $request
            $expected = $expectedReports[$request.Name]
            Assert-GpoReportClass ($null -ne $actual.Caught -and
                $actual.Caught.Cause -ceq $expected.Caught.Cause -and $actual.Caught.Message -ceq $expected.Caught.Message -and
                @($actual.Stream | Where-Object Kind -in 'Object', 'Xml').Count -eq 0 -and
                (@($actual.Events | Where-Object { $_ -ne 'Import' }) -join '|') -ceq ($expected.Events -join '|') -and
                $actual.OwnedDriveGone
            ) "Direct report $($request.Name) lost its primary cause or leaked a partial report or drive."
            if ($request.Mode -eq 'PrimaryCleanup') {
                $cleanupCauses = @($actual.Diagnostics | Where-Object Cause -like '*UnauthorizedAccessException')
                Assert-GpoReportClass ($cleanupCauses.Count -gt 0) 'Direct report lost the secondary native cleanup cause.'
            }
            $count++
        }

        foreach ($invalid in @('Metadata', 'Domain', 'Id', 'Server')) {
            Reset-ReportFixture
            $caught = $null
            $bad = $script:ReportGpo.PSObject.Copy()
            $emitted = @()
            try {
                switch ($invalid) {
                    'Metadata' {
                        $bad.Server = @($script:ReportServer)
                        $emitted = @($reportService.Read($bad, $script:ReportCredential))
                    }
                    'Domain' {
                        $emitted = @($reportService.RenderXmlById($script:ReportId, ' ', $script:ReportAlias, $script:ReportCredential))
                    }
                    'Id' {
                        $emitted = @($reportService.ReadById([guid]::Empty, $script:ReportDomain))
                    }
                    'Server' {
                        $serverWithNewline = $script:ReportAlias + [char]10
                        $emitted = @($reportService.ReadById($script:ReportId, $script:ReportDomain, $serverWithNewline))
                    }
                }
            }
            catch {
                $caught = $_
            }
            Assert-GpoReportClass ($null -ne $caught -and $emitted.Count -eq 0 -and $script:Events.Count -eq 0) (
                "Invalid $invalid did not reject before provider work."
            )
            $count++
        }

        Reset-ReportFixture
        $allNames = @{}
        foreach ($index in 1001..1006) {
            $allNames["S-1-5-21-1-2-3-$index"] = 'Supplied fixture member'
        }
        $unchangedNames = ConvertTo-ReportFixtureJson $allNames
        $allSupplied = $reportService.RenderXml($script:ReportGpo, [pscredential]::Empty, $allNames)
        Assert-ReportFixturePresence $allSupplied
        Assert-GpoReportClass (($script:Events -join '|') -ceq 'ReadUNC' -and
            $unchangedNames -ceq (ConvertTo-ReportFixtureJson $allNames)
        ) 'A fully supplied SID map caused directory access or was mutated.'
        $count++

        $unavailableRequest = New-ReportFixtureRequest 'ImportUnavailable' -Xml $true -Names $true -Mode ImportUnavailable
        $unavailable = Invoke-ReportDirectFixture $reportService $unavailableRequest
        $document = [xml]($unavailable.Stream | Where-Object Kind -eq 'Xml' | Select-Object -First 1).Record
        Assert-GpoReportClass ($null -eq $unavailable.Caught -and $unavailable.MapUnchanged -and
            ($unavailable.Events -join '|') -ceq 'ReadUNC|Import' -and
            @($unavailable.Stream | Where-Object Kind -eq 'Warning').Count -eq 5 -and
            $document.SelectNodes("//Member[Resolution='LookupFailed']").Count -eq 6 -and
            $null -ne $document.SelectSingleNode("//Member[SID='S-1-5-21-1-2-3-1006' and Name='Supplied fixture member']")
        ) 'Provider acquisition failure lost per-SID evidence or retried within one render.'
        $count++

        Reset-ReportFixture
        $next = [ADAnalyzerGpoReportService]::new()
        $first = $reportService.Read($script:ReportGpo)
        $first.Policy.XmlFiles[0].Xml = '<CallerEdit />'
        $again = $reportService.Read($script:ReportGpo)
        $independent = $next.Read($script:ReportGpo)
        $retained = @(
            foreach ($field in $next.GetType().GetFields([Reflection.BindingFlags]'Public,NonPublic,Instance')) {
                $value = $field.GetValue($reportService)
                if ($value -is [pscredential] -or $value -is [Management.Automation.CommandInfo] -or
                    $value -is [Management.Automation.PSModuleInfo]) {
                    $field.Name
                }
            }
        )
        Assert-GpoReportClass (($script:Events -join '|') -ceq 'ReadUNC|ReadUNC|ReadUNC' -and
            $retained.Count -eq 0 -and
            $again.Policy.XmlFiles[0].Xml -cne $first.Policy.XmlFiles[0].Xml -and
            (ConvertTo-ReportFixtureJson $again) -ceq (ConvertTo-ReportFixtureJson $independent)
        ) 'Repeated or independent report service calls retained state.'
        $count++
    }
}
finally {
    if ([IO.Directory]::Exists($script:TempRoot)) {
        [IO.Directory]::Delete($script:TempRoot, $true)
    }
}

if ($Case -eq 'Direct') {
    $exe = (Get-Process -Id $PID).Path
    $parameters = @(
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
    $output = @(& $exe @parameters 2>&1)
    Assert-GpoReportClass ($LASTEXITCODE -eq 0 -and $output.Count -eq 1 -and
        $output[0] -ceq "PASS GPO report class Standalone $count"
    ) 'Fresh standalone GPO report direct checks failed.'
    $count++
}
Write-Output "PASS GPO report class $Case $count"
