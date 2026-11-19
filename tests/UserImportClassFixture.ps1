[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Construction', 'Preview', 'Guards', 'Apply')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:Passed = 0
$script:Unexpected = 0
$script:AllowProvider = $false
$script:AllowCreate = $false
$script:Trace = [Collections.Generic.List[string]]::new()
$script:Creations = [Collections.Generic.List[object]]::new()
$script:Converted = [Collections.Generic.List[Security.SecureString]]::new()
$script:Accounts = @{}
$script:RootDomain = 'DC=fixture,DC=invalid'
$script:Domain = $script:RootDomain
$script:Destination = 'OU=Fixture,DC=fixture,DC=invalid'
$script:ServerName = 'alias.fixture.invalid'
$script:Credential = [pscredential]::new('FIXTURE\pas-inventory', [Security.SecureString]::new())
$script:ExpectedServer = $null
$script:ExpectedCredential = $null
$script:Dll = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'))
$script:FirstMarker = 'PAS_SYNTHETIC_INPUT_ALPHA'
$script:SecondMarker = 'PAS_SYNTHETIC_INPUT_BETA'
$script:Fault = ''
$script:CreateTarget = $null
$script:ExpectedMarker = $null

function Assert-PasClass($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-PasClass([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('Failed PAS import class fixture: ' + $Name)
        throw
    }
}

function Stop-PasClassExternal {
    $script:Unexpected++
    throw 'Unexpected live, ambient or premature dependency call'
}

function Get-PasClassFailure([scriptblock]$Body, [string]$Pattern = '.+') {
    $rows = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Body | ForEach-Object { $rows.Add($_) }
    }
    catch {
        $failure = $_
    }
    Assert-PasClass ($null -ne $failure -and $rows.Count -eq 0 -and $failure.Exception.Message -match $Pattern) (
        'Expected a terminal failure matching ' + $Pattern
    )
    return $failure
}

function Assert-PasClassSafe($Value) {
    $json = Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 25 -Compress
    $xml = [Management.Automation.PSSerializer]::Serialize($Value)
    Assert-PasClass ($json -cnotmatch 'PAS_SYNTHETIC_INPUT_|PSCredential|SecureString' -and
        $xml -cnotmatch 'PAS_SYNTHETIC_INPUT_|PSCredential|SecureString') 'Public result retained a supplied password or credential'
}

function Get-PasClassJson($Value) {
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 25 -Compress
}

function Reset-PasClassTrace {
    $script:Trace.Clear()
    $script:Creations.Clear()
    $script:Converted.Clear()
    $script:AllowCreate = $false
    $script:CreateTarget = $null
    $script:ExpectedMarker = $null
    $script:Fault = ''
    $script:RootDomain = $script:Domain
}

function Assert-PasNoWrite {
    Assert-PasClass ($script:Creations.Count -eq 0 -and $script:Converted.Count -eq 0 -and
        'Convert' -notin $script:Trace -and @($script:Trace | Where-Object { $_ -like 'Create:*' }).Count -eq 0 -and
        $script:Unexpected -eq 0) 'A read-only or rejected action reached a write or secret conversion'
}

function Assert-PasClassDisposed([Security.SecureString]$Value) {
    $failure = $null
    try {
        $copy = $Value.Copy()
        $copy.Dispose()
    }
    catch {
        $failure = $_
    }
    Assert-PasClass ($null -ne $failure -and $failure.Exception.GetBaseException() -is [ObjectDisposedException]) (
        'Converted fixture password remained usable after the create attempt'
    )
}

function New-PasClassCsvRow([string]$Username, [string]$Marker = '') {
    [pscustomobject][ordered]@{
        username = $Username
        name = 'Fixture ' + [char]0x00FC + ' ' + $Username
        password = $Marker
        path = $script:Destination
        givenName = 'Fixture given'
        surname = 'Fixture surname'
        displayName = 'Fixture display'
        department = ''
        employeeID = '00123'
        userPrincipalName = $Username + '@fixture.invalid'
    }
}

function Write-PasClassCsv([string]$Path, [object[]]$Rows) {
    $text = ($Rows | Microsoft.PowerShell.Utility\ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($true))
}

function New-PasClassSource {
    $first = New-PasClassCsvRow 'alpha' $script:FirstMarker
    $saved = New-PasClassCsvRow 'existing'
    $saved.name = ''
    $saved.path = ''
    $second = New-PasClassCsvRow 'beta' $script:SecondMarker
    $script:Accounts = @{
        existing = $true
    }
    Write-PasClassCsv $csv @($first, $saved, $second)
    return @($first, $saved, $second)
}

function Get-PasClassAction($Plan, [string]$Username) {
    $found = @($Plan.Actions | Where-Object Username -ceq $Username)
    Assert-PasClass ($found.Count -eq 1) 'Expected one planned action for the fixture name'
    return $found[0]
}

function Assert-PasConnection($Bound) {
    Assert-PasClass ($Bound['ErrorAction'] -eq 'Stop' -and
        $Bound.ContainsKey('Server') -eq [bool]$script:ExpectedServer -and
        $Bound['Server'] -ceq $script:ExpectedServer -and
        $Bound.ContainsKey('Credential') -eq [bool]$script:ExpectedCredential) 'Ambient or explicit connection binding changed'
    if ($script:ExpectedCredential) {
        Assert-PasClass ([object]::ReferenceEquals($Bound['Credential'], $script:ExpectedCredential)) 'Explicit credential identity changed'
    }
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Scope, [switch]$PassThru, [switch]$Global)

    if (-not $script:AllowProvider) {
        Stop-PasClassExternal
    }
    Assert-PasClass ($Name -ceq $script:Dll -and [IO.Path]::IsPathRooted($Name) -and
        $Scope -ceq 'Local' -and $PassThru -and -not $Global -and
        $PSBoundParameters['ErrorAction'] -eq 'Stop') 'Direct route did not acquire the exact bundled capability locally'
    $script:Trace.Add('Import')
    $commands = @{
        'Get-ADRootDSE' = Get-Command Invoke-PasClassRoot -CommandType Function
        'Get-ADUser' = Get-Command Invoke-PasClassLookup -CommandType Function
        'New-ADUser' = Get-Command Invoke-PasClassCreate -CommandType Function
    }
    $exports = $commands.Clone()
    if ($script:Fault -eq 'MissingLookup') {
        $exports.Remove('Get-ADUser')
    }
    elseif ($script:Fault -eq 'StringRoot') {
        $exports['Get-ADRootDSE'] = 'Invoke-PasClassRoot'
    }
    elseif ($script:Fault -eq 'StringCreate') {
        $exports['New-ADUser'] = 'Invoke-PasClassCreate'
    }
    [pscustomobject]@{
        Path = $Name
        ExportedCmdlets = $exports
        ExportedCommands = $commands
    }
}

function Get-ADRootDSE { Stop-PasClassExternal }
function Get-ADUser { Stop-PasClassExternal }
function New-ADUser { Stop-PasClassExternal }
function Enable-ADAccount { Stop-PasClassExternal }
function Get-Credential { Stop-PasClassExternal }
function Invoke-Command { Stop-PasClassExternal }

function Invoke-PasClassRoot {
    [CmdletBinding()]
    param([string]$Server, [pscredential]$Credential)

    Assert-PasConnection $PSBoundParameters
    $script:Trace.Add('Root')
    if ($script:Fault -eq 'EmptyRoot') {
        return
    }
    [pscustomobject]@{
        DnsHostName = 'different-reply.fixture.invalid'
        DefaultNamingContext = $script:RootDomain
    }
}

function Invoke-PasClassLookup {
    [CmdletBinding()]
    param([string]$LDAPFilter, [string]$SearchBase, [string[]]$Properties, [string]$Server, [pscredential]$Credential)

    Assert-PasConnection $PSBoundParameters
    $prefix = '(sAMAccountName='
    Assert-PasClass ($SearchBase -ceq $script:RootDomain -and ($Properties -join ',') -ceq 'SamAccountName' -and
        $LDAPFilter.StartsWith($prefix, [StringComparison]::Ordinal) -and $LDAPFilter.EndsWith(')')) (
        'Lookup escaped the selected exact account and naming context'
    )
    $encoded = $LDAPFilter.Substring($prefix.Length, $LDAPFilter.Length - $prefix.Length - 1)
    $name = $encoded.Replace('\2a', '*').Replace('\28', '(').Replace('\29', ')').Replace('\00', [string][char]0).Replace('\5c', '\')
    $script:Trace.Add('Lookup:' + $name)
    if ($script:Fault -eq 'Lookup') {
        throw 'Fixture exact lookup failed'
    }
    if ($script:Fault -eq 'MultipleLookup') {
        $match = [pscustomobject]@{
            SamAccountName = $name
        }
        $match
        $match
        return
    }
    if ($script:Accounts.ContainsKey($name)) {
        [pscustomobject]@{
            SamAccountName = $name
        }
    }
}

function Invoke-PasConstructionCases {
    Test-PasClass 'literal construction uses the inert standalone entrypoint' {
        Assert-PasClass ($startup.Count -eq 0 -and $owner.GetType().Name -ceq 'ADAnalyzerPasUserImporter' -and
            $script:Trace.Count -eq 0 -and (Get-Location).Path -ceq $script:Temporary -and
            -not [IO.File]::Exists($csv)) 'Loading or constructing read input or touched the provider'
    }
    Test-PasClass 'independent constructors retain no effectful state' {
        $second = [ADAnalyzerPasUserImporter]::new()
        Assert-PasClass (-not [object]::ReferenceEquals($owner, $second) -and $script:Trace.Count -eq 0) 'Constructors reused mutable state'
        Assert-PasClassSafe $owner
        Assert-PasClassSafe $second
        Assert-PasNoWrite
    }
}

function Invoke-PasPreviewCases {
    $script:AllowProvider = $true
    Test-PasClass 'ambient preview is complete, ordered, read-only and presence only' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $plan = $owner.Preview($csv)
        Assert-PasClass ($plan -is [pscustomobject] -and $plan.SchemaVersion -eq 1 -and
            $plan.CsvPath -ceq $csv -and [string]::IsNullOrEmpty($plan.Server) -and
            $plan.NamingContext -ceq $script:Domain -and -not [string]::IsNullOrWhiteSpace($plan.Fingerprint) -and
            ($plan.Actions.Username -join '|') -ceq 'alpha|existing|beta' -and
            ($plan.Actions.Status -join '|') -ceq 'Pending|Existing|Pending') 'Ambient plan changed scope, order or reviewed status'
        $alpha = Get-PasClassAction $plan 'alpha'
        $beta = Get-PasClassAction $plan 'beta'
        $saved = Get-PasClassAction $plan 'existing'
        Assert-PasClass ($alpha.ActionId -is [string] -and $beta.ActionId -is [string] -and
            $alpha.ActionId -cne $beta.ActionId -and $alpha.RowNumber -lt $beta.RowNumber -and
            $alpha.PasswordPresent -is [bool] -and $alpha.PasswordPresent -and
            $saved.PasswordPresent -is [bool] -and -not $saved.PasswordPresent -and
            $null -eq $alpha.PSObject.Properties['Password'] -and
            $alpha.Name -ceq ('Fixture ' + [char]0x00FC + ' alpha') -and $alpha.Path -ceq $script:Destination) (
            'Preview lost reviewed fields or exposed the synthetic password'
        )
        Assert-PasClass (($script:Trace -join '|') -ceq 'Import|Root|Lookup:alpha|Lookup:existing|Lookup:beta') 'Preview did not complete ordered lookups'
        Assert-PasClassSafe $plan
        Assert-PasNoWrite
    }
    Test-PasClass 'explicit preview keeps target and credential without sharing either in state' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $script:ExpectedServer = $script:ServerName
        $script:ExpectedCredential = $script:Credential
        $options = @{
            Server = $script:ServerName
            Credential = $script:Credential
        }
        $plan = $owner.Preview($csv, $options)
        $alpha = Get-PasClassAction $plan 'alpha'
        Assert-PasClass ($plan.Server -ceq $script:ServerName -and $plan.NamingContext -ceq $script:Domain -and
            $alpha.Fields.EmployeeID -ceq '00123' -and [string]::IsNullOrEmpty([string]$alpha.Fields.Department) -and
            $options.Count -eq 2 -and [object]::ReferenceEquals($options.Credential, $script:Credential)) 'Selected server or optional reviewed fields changed'
        Assert-PasClassSafe $plan
        Assert-PasClassSafe $owner
        $script:ExpectedServer = $null
        $script:ExpectedCredential = $null
        $ordinary = $owner.Preview($csv, @{ Credential = [pscredential]::Empty })
        Assert-PasClass ([string]::IsNullOrEmpty($ordinary.Server) -and
            $ordinary.Fingerprint -cne $plan.Fingerprint) 'Ambient preview reused the explicit target'
        Assert-PasNoWrite
    }
    Test-PasClass 'reused preview returns stable identities and independent action values' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $first = $owner.Preview($csv)
        $expected = Get-PasClassJson $first
        $first.Actions[0].Name = 'changed result only'
        $other = [ADAnalyzerPasUserImporter]::new()
        $again = $owner.Preview($csv)
        $independent = $other.Preview($csv)
        Assert-PasClass ((Get-PasClassJson $again) -ceq $expected -and
            (Get-PasClassJson $independent) -ceq $expected) 'Preview retained mutable results or nondeterministic identity'
        $pending = Get-PasClassAction $again 'alpha'
        $script:Accounts['alpha'] = $true
        $different = $owner.Preview($csv)
        $observed = Get-PasClassAction $different 'alpha'
        Assert-PasClass ($pending.Status -ceq 'Pending' -and $observed.Status -ceq 'Existing' -and
            $observed.RowNumber -eq $pending.RowNumber -and $observed.ActionId -cne $pending.ActionId -and
            $different.Fingerprint -cne $again.Fingerprint) 'Action identity did not bind its reviewed status'
        Assert-PasNoWrite
    }
    Test-PasClass 'malformed package capabilities and missing RootDSE stop before action work' {
        $null = New-PasClassSource
        foreach ($fault in 'MissingLookup', 'StringRoot', 'EmptyRoot') {
            Reset-PasClassTrace
            $script:Fault = $fault
            $null = Get-PasClassFailure { $owner.Preview($csv) }
            $wanted = 'Import'
            if ($fault -eq 'EmptyRoot') {
                $wanted = 'Import|Root'
            }
            Assert-PasClass (($script:Trace -join '|') -ceq $wanted) 'Broken metadata reached action observation'
            Assert-PasNoWrite
        }
        Reset-PasClassTrace
        $script:AllowProvider = $false
        $header = New-PasClassCsvRow 'alpha' | Microsoft.PowerShell.Utility\ConvertTo-Csv -NoTypeInformation | Select-Object -First 1
        [IO.File]::WriteAllText($csv, $header, [Text.UTF8Encoding]::new($true))
        $empty = $owner.Preview($csv)
        Assert-PasClass ($empty.Actions.Count -eq 0 -and $script:Trace.Count -eq 0) 'Header-only CSV acquired a directory capability'
        Assert-PasNoWrite
    }
}

function Invoke-PasGuardCases {
    Test-PasClass 'invalid CSV and connection options fail before acquisition' {
        Reset-PasClassTrace
        $null = Get-PasClassFailure { $owner.Preview(' ') }
        $null = Get-PasClassFailure { $owner.Preview((Join-Path $script:Temporary 'missing.csv')) }
        $PasFixtureCsv = 'unrelated diagnostic'
        $null = Get-PasClassFailure { $owner.Preview('Variable:PasFixtureCsv') } '(?i)file system'
        $null = New-PasClassSource
        foreach ($key in 'Keys', 'OutputPath', 'WhatIf') {
            $extra = @{}
            $extra[$key] = 'unexpected'
            $null = Get-PasClassFailure { $owner.Preview($csv, $extra) }
        }
        $blank = [hashtable]::new([StringComparer]::Ordinal)
        $blank.Add('server', ' ')
        $null = Get-PasClassFailure { $owner.Preview($csv, $blank) } '(?i)server'
        $duplicate = [hashtable]::new([StringComparer]::Ordinal)
        $duplicate.Add('Server', $script:ServerName)
        $duplicate.Add('server', 'different.fixture.invalid')
        $null = Get-PasClassFailure { $owner.Preview($csv, $duplicate) } '(?i)option once'
        $data = @(New-PasClassSource)
        $data[2].username = ' '
        Write-PasClassCsv $csv $data
        $null = Get-PasClassFailure { $owner.Preview($csv) } '(?i)username'
        Assert-PasClass ($script:Trace.Count -eq 0) 'Invalid input imported the bundled provider'
        Assert-PasNoWrite
    }
    $script:AllowProvider = $true
    Test-PasClass 'empty, unknown, duplicate or existing action approval authorizes no work' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $plan = $owner.Preview($csv)
        $alpha = (Get-PasClassAction $plan 'alpha').ActionId
        $existing = (Get-PasClassAction $plan 'existing').ActionId
        $script:Trace.Clear()
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, $null) }
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, [string[]]@()) }
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @('f' * 64)) }
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($alpha, $alpha)) }
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($existing)) }
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($alpha, $null)) } '(?i)approved action ID'
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($alpha, '')) } '(?i)approved action ID'
        $null = Get-PasClassFailure {
            $WhatIfPreference = $true
            $owner.Apply($csv, $plan, @($alpha))
        } 'Use Preview'
        Assert-PasClass ($script:Trace.Count -eq 0) 'Invalid or dry approval attempted provider work'
        $script:Fault = 'StringCreate'
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($alpha)) } '(?i)bundled'
        Assert-PasClass (($script:Trace -join '|') -ceq 'Import') 'Unusable creation metadata reached lookup'
        Assert-PasNoWrite

        Reset-PasClassTrace
        $rows = @(New-PasClassSource)
        $rows[2].username = 'AlPhA'
        Write-PasClassCsv $csv $rows
        $duplicates = $owner.Preview($csv)
        $ids = @($duplicates.Actions | Where-Object Username -eq 'alpha' | ForEach-Object ActionId)
        Assert-PasClass ($ids.Count -eq 2 -and $ids[0] -cne $ids[1]) 'Distinct CSV rows did not get distinct action identities'
        $script:Trace.Clear()
        $parkedCsv = Join-Path $script:Temporary 'parked [review].csv'
        [IO.File]::Move($csv, $parkedCsv)
        try {
            $null = Get-PasClassFailure { $owner.Apply($csv, $duplicates, $ids) } 'Approve at most one pending action per account'
            Assert-PasClass ($script:Trace.Count -eq 0) 'Equivalent username approvals reached provider acquisition'
        }
        finally {
            [IO.File]::Move($parkedCsv, $csv)
        }
        Assert-PasNoWrite
    }
    Test-PasClass 'modified plan or stale literal input is rejected without conversion' {
        Reset-PasClassTrace
        $rows = @(New-PasClassSource)
        $plan = $owner.Preview($csv)
        $requested = (Get-PasClassAction $plan 'alpha').ActionId
        $plan.Actions[0].Name = 'changed reviewed action'
        $script:Trace.Clear()
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested)) }
        Assert-PasClass ($script:Trace.Count -eq 0) 'Tampered plan reached provider acquisition'
        $plan = $owner.Preview($csv)
        $activeGetter = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject (Get-PasClassJson $plan)
        $activeGetter.PSObject.Properties.Remove('Fingerprint')
        $script:PlanGetterReads = 0
        $activeGetter | Add-Member -MemberType ScriptProperty -Name Fingerprint -Value {
            $script:PlanGetterReads++
            'f' * 64
        }
        $script:Trace.Clear()
        $null = Get-PasClassFailure { $owner.Apply($csv, $activeGetter, @($requested)) } '(?i)valid reviewed PAS importer plan'
        Assert-PasClass ($script:PlanGetterReads -eq 0 -and $script:Trace.Count -eq 0) 'Review read a script property or acquired a provider'
        $rows[0].employeeID = '98765'
        Write-PasClassCsv $csv $rows
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested)) }
        $rows[0].employeeID = '00123'
        $other = Join-Path $script:Temporary 'different [source].csv'
        Write-PasClassCsv $other $rows
        $null = Get-PasClassFailure { $owner.Apply($other, $plan, @($requested)) }
        $rows[0].password = ''
        Write-PasClassCsv $csv $rows
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested)) }
        Assert-PasNoWrite
    }
    Test-PasClass 'target drift or a failed current lookup never reaches creation' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $plan = $owner.Preview($csv)
        $requested = (Get-PasClassAction $plan 'alpha').ActionId
        $script:Trace.Clear()
        $changedTarget = @{
            Server = $script:ServerName
        }
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested), $changedTarget) } '(?i)server has changed'
        Assert-PasClass ($script:Trace.Count -eq 0) 'Changed explicit server reached provider acquisition'
        $script:RootDomain = 'DC=another,DC=invalid'
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested)) }
        Assert-PasNoWrite
        Reset-PasClassTrace
        $script:Fault = 'Lookup'
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested)) } 'Fixture exact lookup failed'
        Assert-PasNoWrite
        Reset-PasClassTrace
        $script:Fault = 'MultipleLookup'
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($requested)) } '(?i)multiple users'
        Assert-PasNoWrite
    }
}

function ConvertTo-SecureString {
    [CmdletBinding()]
    param([string]$String, [switch]$AsPlainText, [switch]$Force)

    if (-not $script:AllowCreate) {
        Stop-PasClassExternal
    }
    Assert-PasClass ($AsPlainText -and $Force -and $PSBoundParameters['ErrorAction'] -eq 'Stop' -and
        $String -ceq $script:ExpectedMarker) 'Approved attempt did not use current synthetic input at the last possible moment'
    $script:Trace.Add('Convert')
    $password = [Security.SecureString]::new()
    $password.AppendChar([char]'X')
    $script:Converted.Add($password)
    return $password
}

function Invoke-PasClassCreate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name,
        [string]$SamAccountName,
        [string]$Path,
        [string]$GivenName,
        [string]$Surname,
        [string]$DisplayName,
        [string]$Department,
        [string]$EmployeeID,
        [string]$UserPrincipalName,
        [Security.SecureString]$AccountPassword,
        [bool]$Enabled,
        [bool]$ChangePasswordAtLogon,
        [switch]$PassThru,
        [string]$Server,
        [pscredential]$Credential
    )

    if (-not $script:AllowCreate) {
        Stop-PasClassExternal
    }
    Assert-PasConnection $PSBoundParameters
    Assert-PasClass ($SamAccountName -ceq $script:CreateTarget -and
        $Name -ceq ('Fixture ' + [char]0x00FC + ' ' + $SamAccountName) -and
        $Path -ceq $script:Destination -and $Enabled -and $ChangePasswordAtLogon -and -not $PassThru -and
        $PSBoundParameters.ContainsKey('Confirm') -and -not [bool]$PSBoundParameters['Confirm'] -and
        $GivenName -ceq 'Fixture given' -and $Surname -ceq 'Fixture surname' -and $DisplayName -ceq 'Fixture display' -and
        $EmployeeID -ceq '00123' -and $UserPrincipalName -ceq ($SamAccountName + '@fixture.invalid') -and
        -not $PSBoundParameters.ContainsKey('Department') -and $AccountPassword.Length -eq 1 -and
        [object]::ReferenceEquals($script:Converted[$script:Converted.Count - 1], $AccountPassword)) 'Synthetic creation request changed the reviewed fields or scope'
    $script:Trace.Add('Create:' + $SamAccountName)
    $script:Creations.Add([pscustomobject]@{
        Username = $SamAccountName
        PasswordPresent = $true
    })
    $script:Accounts[$SamAccountName] = $true
    if ($script:Fault -eq 'Partial') {
        throw 'Fixture provider reports an uncertain creation'
    }
}

function Enable-PasClassAttempt([string]$Username, [string]$Marker) {
    $script:AllowCreate = $true
    $script:CreateTarget = $Username
    $script:ExpectedMarker = $Marker
}

function Assert-PasClassCreated($Rows, [string]$Username) {
    Assert-PasClass ($Rows -is [object[]] -and $Rows.Count -eq 1 -and
        $Rows[0].Username -ceq $Username -and $Rows[0].Status -ceq 'Created' -and
        $script:Creations.Count -eq 1 -and $script:Creations[0].Username -ceq $Username -and
        $script:Converted.Count -eq 1 -and $script:Trace.IndexOf('Lookup:' + $Username) -lt $script:Trace.IndexOf('Convert') -and
        $script:Trace.IndexOf('Convert') + 1 -eq $script:Trace.IndexOf('Create:' + $Username)) (
        'Approved create did not bind one exact recheck, one conversion and one attempt'
    )
    Assert-PasClassSafe $Rows
    Assert-PasClassDisposed $script:Converted[0]
}

function Invoke-PasApplyCases {
    $script:AllowProvider = $true
    Test-PasClass 'selected approval creates only a freshly checked row on the explicit connection' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $script:ExpectedServer = $script:ServerName
        $script:ExpectedCredential = $script:Credential
        $options = @{
            Server = $script:ServerName
            Credential = $script:Credential
        }
        $plan = $owner.Preview($csv, $options)
        $before = Get-PasClassJson $plan
        $reviewed = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $before
        $beta = (Get-PasClassAction $plan 'beta').ActionId
        Reset-PasClassTrace
        Enable-PasClassAttempt 'beta' $script:SecondMarker
        $result = $owner.Apply($csv, $reviewed, @($beta), $options)
        Assert-PasClassCreated $result 'beta'
        Assert-PasClass ((Get-PasClassJson $plan) -ceq $before -and $script:Accounts['beta'] -and
            -not $script:Accounts.ContainsKey('alpha') -and [object]::ReferenceEquals($options.Credential, $script:Credential)) (
            'Approval changed the supplied plan/options or another pending account'
        )
        $script:ExpectedServer = $null
        $script:ExpectedCredential = $null
        Assert-PasClassSafe $owner
    }
    Test-PasClass 'a newly existing approved account is never converted or created again' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $plan = $owner.Preview($csv)
        $id = (Get-PasClassAction $plan 'alpha').ActionId
        $script:Accounts['alpha'] = $true
        Reset-PasClassTrace
        $result = $owner.Apply($csv, $plan, @($id))
        Assert-PasClass ($result -is [object[]] -and $result.Count -eq 1 -and $result[0].Username -ceq 'alpha' -and
            $result[0].Status -ceq 'Existing' -and $script:Trace.Contains('Lookup:alpha')) 'Existing user lost the exact current check or safe result'
        Assert-PasClassSafe $result
        Assert-PasNoWrite
    }
    Test-PasClass 'unchanged password presence accepts only the current synthetic password' {
        Reset-PasClassTrace
        $rows = @(New-PasClassSource)
        $plan = $owner.Preview($csv)
        $id = (Get-PasClassAction $plan 'alpha').ActionId
        $rotated = 'PAS_SYNTHETIC_INPUT_ROTATED'
        $rows[0].password = $rotated
        Write-PasClassCsv $csv $rows
        Reset-PasClassTrace
        Enable-PasClassAttempt 'alpha' $rotated
        $result = $owner.Apply($csv, $plan, @($id))
        Assert-PasClassCreated $result 'alpha'
        Assert-PasClassSafe $plan
    }
    Test-PasClass 'uncertain provider failure disposes the password and stops before later approvals' {
        Reset-PasClassTrace
        $null = New-PasClassSource
        $plan = $owner.Preview($csv)
        $alpha = (Get-PasClassAction $plan 'alpha').ActionId
        $beta = (Get-PasClassAction $plan 'beta').ActionId
        Reset-PasClassTrace
        Enable-PasClassAttempt 'alpha' $script:FirstMarker
        $script:Fault = 'Partial'
        $null = Get-PasClassFailure { $owner.Apply($csv, $plan, @($alpha, $beta)) } 'Fixture provider reports an uncertain creation'
        Assert-PasClass ($script:Creations.Count -eq 1 -and $script:Converted.Count -eq 1 -and
            $script:Accounts['alpha'] -and -not $script:Accounts.ContainsKey('beta')) 'Terminal attempt retried, fabricated success or continued'
        Assert-PasClassDisposed $script:Converted[0]
        Reset-PasClassTrace
        $again = $owner.Apply($csv, $plan, @($alpha))
        Assert-PasClass ($again.Count -eq 1 -and $again[0].Status -ceq 'Existing') 'A later reviewed call did not re-observe the uncertain account'
        Assert-PasNoWrite
        Reset-PasClassTrace
        $rows = @(New-PasClassSource)
        $rows[2].username = 'AlPhA'
        Write-PasClassCsv $csv $rows
        $duplicates = $owner.Preview($csv)
        $selected = Get-PasClassAction $duplicates 'alpha'
        Reset-PasClassTrace
        Enable-PasClassAttempt 'alpha' $script:FirstMarker
        $onlyOnce = $owner.Apply($csv, $duplicates, @($selected.ActionId))
        Assert-PasClassCreated $onlyOnce 'alpha'
        Assert-PasClass ($onlyOnce[0].ActionId -ceq $selected.ActionId) 'One selected duplicate row lost its exact action identity'
    }
}

$initialLocation = (Get-Location).Path
$script:Temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-pas-class-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Temporary)
try {
    Set-Location -LiteralPath $script:Temporary
    $csv = Join-Path $script:Temporary 'literal [review].csv'
    $startup = @(. (Join-Path $RepositoryRoot 'etc/New-ADPASUser.ps1'))
    $owner = [ADAnalyzerPasUserImporter]::new()
    Assert-PasClass ($startup.Count -eq 0 -and $script:Trace.Count -eq 0 -and $script:Unexpected -eq 0) 'Standalone entry or constructor entered a dependency seam'
    function New-ADPASUser { Stop-PasClassExternal }
    switch ($Mode) {
        'Construction' {
            Invoke-PasConstructionCases
        }
        'Preview' {
            Invoke-PasPreviewCases
        }
        'Guards' {
            Invoke-PasGuardCases
        }
        'Apply' {
            Invoke-PasApplyCases
        }
    }
    Assert-PasClass ($script:Unexpected -eq 0 -and (Get-Location).Path -ceq $script:Temporary) 'Unexpected effect was hidden or location was changed'
    'PASS PAS user import class {0} {1}' -f $Mode, $script:Passed
}
finally {
    Set-Location -LiteralPath $initialLocation
    [IO.Directory]::Delete($script:Temporary, $true)
}
