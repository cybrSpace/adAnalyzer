[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$script:Passed = 0
$script:Forbidden = [Collections.Generic.List[string]]::new()
$script:AuthorityReads = 0
$script:AuthorityDirectory = $null
$script:Account = [guid]'aabbccdd-1234-4567-89ab-123456789abc'
$script:Attempt = [guid]'12345678-2345-4567-89ab-abcdef012345'
$script:Created = [datetimeoffset]::Parse('2000-01-02T03:04:05+00:00', [Globalization.CultureInfo]::InvariantCulture)
$script:Secret = 'RESERVATION_INSPECTION_SECRET_6ac21f'
$script:Utf8 = [Text.UTF8Encoding]::new($false, $true)
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-reservation-inspection-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($temporary)

function Assert-Inspection($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Inspection([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:Passed++
    }
    catch {
        Write-Host ('FAIL remediation reservation inspection: ' + $Name)
        throw
    }
}

function Assert-InspectionFailure([scriptblock]$Body, [string]$Pattern = '.+') {
    $rows = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        & $Body | ForEach-Object {
            $rows.Add($_)
        }
    }
    catch {
        $failure = $_
    }
    Assert-Inspection ($null -ne $failure -and $rows.Count -eq 0) 'Expected an inspection failure without output.'
    Assert-Inspection ($failure.Exception.Message -match $Pattern) 'The inspection failed for an unexpected reason.'
    Assert-Inspection ($failure.ToString() -notmatch [regex]::Escape($script:Secret)) 'An inspection diagnostic exposed fixture content.'
}

function Set-InspectionTraps {
    foreach ($name in @('Import-Module', 'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE', 'Get-ADDomain',
            'Disable-ADAccount', 'Enable-ADAccount', 'Set-ADObject', 'Invoke-Command', 'New-PSDrive',
            'Enter-ADAnalyzerJournalLease', 'Save-ADAnalyzerOperationJournal')) {
        Set-Item -LiteralPath ('Function:script:' + $name) -Value {
            $script:Forbidden.Add($MyInvocation.MyCommand.Name)
            throw 'The inspection fixture reached an external or mutating boundary.'
        }
    }
}

function Get-InspectionSnapshot([string]$Root) {
    $entries = [Collections.Generic.List[string]]::new()
    foreach ($directory in [IO.Directory]::GetDirectories($Root, '*', [IO.SearchOption]::AllDirectories)) {
        $entries.Add('D:' + $directory.Substring($Root.Length))
    }
    foreach ($file in [IO.Directory]::GetFiles($Root, '*', [IO.SearchOption]::AllDirectories)) {
        $entries.Add('F:' + $file.Substring($Root.Length) + ':' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($file)))
    }
    return (($entries.ToArray() | Sort-Object) -join "`n")
}

function New-InspectionRecord([string]$Operation = 'Apply') {
    return "Status=Uncertain`nAttemptId=$($script:Attempt.ToString('D'))`nAccount=$($script:Account.ToString('D'))`nOperation=$Operation`nCreatedUtc=$($script:Created.ToString('o', [Globalization.CultureInfo]::InvariantCulture))`nLastConfirmedStep=AccountReserved`n"
}

function Read-Inspection([guid]$Identity = $script:Account) {
    $direct = @($script:First.Inspect($Identity))
    $captured = @()
    $warnings = @()
    $information = @()
    $parameters = @{
        ObjectGuid = $Identity
        ErrorVariable = '+captured'
        WarningVariable = '+warnings'
        InformationVariable = '+information'
    }
    $native = @(Get-ADAnalyzerRemediationReservation @parameters)
    Assert-Inspection ($direct.Count -eq 1 -and $native.Count -eq 1) 'Inspection changed output cardinality.'
    Assert-Inspection ($captured.Count -eq 0 -and $warnings.Count -eq 0 -and $information.Count -eq 0) 'A normal observation emitted diagnostics.'
    $expectedFields = 'ObjectGuid,Status,AttemptId,Operation,CreatedUtc,LastConfirmedStep'
    Assert-Inspection (
        ($direct[0].PSObject.Properties.Name -join ',') -ceq $expectedFields -and
        ($native[0].PSObject.Properties.Name -join ',') -ceq $expectedFields
    ) 'The observation exposed an unexpected field.'
    foreach ($field in $expectedFields.Split(',')) {
        $objectValue = $direct[0].$field
        $commandValue = $native[0].$field
        if ($null -eq $objectValue) {
            Assert-Inspection ($null -eq $commandValue) ('The command returned an unexpected value for ' + $field)
        }
        else {
            Assert-Inspection (
                $null -ne $commandValue -and $objectValue.GetType() -eq $commandValue.GetType() -and
                $objectValue -ceq $commandValue
            ) ('The command and object observations differ for ' + $field)
        }
    }
    $json = ConvertTo-Json -InputObject $direct[0] -Depth 5 -Compress
    Assert-Inspection ($json -notmatch [regex]::Escape($script:Secret) -and $json -notmatch 'Status=Uncertain|AttemptId=|RawRecord|CanRetry') 'The observation exposed content or implied permission.'
    Assert-Inspection ($direct[0].ObjectGuid -is [guid] -and $direct[0].ObjectGuid -eq $Identity) 'The observation lost its canonical account identity.'
    if ($direct[0].Status -cne 'Held') {
        foreach ($field in 'AttemptId', 'Operation', 'CreatedUtc', 'LastConfirmedStep') {
            Assert-Inspection ($null -eq $direct[0].$field) 'An unvalidated record exposed partial metadata.'
        }
    }
    return $direct[0]
}

try {
    Set-InspectionTraps
    $script:AllowCompilation = $false
    function script:Add-Type {
        [CmdletBinding()]
        param([string]$Path)

        if (-not $script:AllowCompilation) {
            $script:Forbidden.Add('Add-Type')
            throw 'Construction attempted to compile journal support.'
        }
        $expectedPath = Join-Path $RepositoryRoot 'bin/ADJournalLease.cs'
        Assert-Inspection ([IO.Path]::GetFullPath($Path) -ceq $expectedPath) 'Unexpected fixture compilation target.'
        Microsoft.PowerShell.Utility\Add-Type @PSBoundParameters
    }
    $hadReservationType = $null -ne ('ADAnalyzer.AccountEffectReservation' -as [type])
    $location = (Get-Location).Path
    $loaded = @(. (Join-Path $RepositoryRoot 'bin/ADOperations.ps1'))
    Set-InspectionTraps

    function Get-ADAnalyzerRemediationAuthorityDirectory {
        $script:AuthorityReads++
        if ([string]::IsNullOrEmpty($script:AuthorityDirectory) -or -not [IO.Directory]::Exists($script:AuthorityDirectory)) {
            throw 'The fixture authority is unavailable.'
        }
        return $script:AuthorityDirectory
    }

    Test-Inspection 'fresh standalone construction is inert' {
        $script:First = [ADAnalyzerRemediationReservationInspector]::new()
        $script:Second = [ADAnalyzerRemediationReservationInspector]::new()
        Assert-Inspection (-not $hadReservationType -and $null -eq ('ADAnalyzer.AccountEffectReservation' -as [type])) 'The fresh constructor loaded reservation support.'
        Assert-Inspection ($loaded.Count -eq 0 -and $script:AuthorityReads -eq 0 -and $script:Forbidden.Count -eq 0) 'Loading or construction performed work.'
        Assert-Inspection ((Get-Location).Path -ceq $location -and [IO.Directory]::GetFileSystemEntries($temporary).Count -eq 0) 'Construction changed location or files.'
        Assert-Inspection (-not [object]::ReferenceEquals($script:First, $script:Second)) 'Construction shared an inspector instance.'
    }
    $script:AllowCompilation = $true
    $script:AuthorityDirectory = Join-Path $temporary 'authority [literal]'
    $null = [IO.Directory]::CreateDirectory($script:AuthorityDirectory)
    $path = Join-Path $script:AuthorityDirectory ($script:Account.ToString('N') + '.hold')

    Test-Inspection 'a missing local record is an observation without artifacts' {
        $before = Get-InspectionSnapshot $temporary
        Assert-Inspection ((Read-Inspection).Status -ceq 'NotObserved') 'A missing record was not reported as NotObserved.'
        Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Missing inspection created an artifact.'
    }

    Test-Inspection 'valid Apply and Undo records retain typed evidence and GUID aliases' {
        foreach ($operation in 'Apply', 'Undo') {
            [IO.File]::WriteAllText($path, (New-InspectionRecord $operation), $script:Utf8)
            $before = Get-InspectionSnapshot $temporary
            $held = Read-Inspection
            Assert-Inspection ($held.Status -ceq 'Held' -and $held.AttemptId -is [guid] -and $held.AttemptId -eq $script:Attempt) 'Held lost typed attempt evidence.'
            Assert-Inspection ($held.Operation -ceq $operation -and $held.CreatedUtc -is [datetimeoffset] -and $held.CreatedUtc -eq $script:Created -and $held.CreatedUtc.Offset -eq [timespan]::Zero) 'Held lost its operation or UTC time.'
            Assert-Inspection ($held.LastConfirmedStep -ceq 'AccountReserved') 'Held invented a later confirmed step.'
            foreach ($form in 'D', 'N', 'B') {
                $alias = Get-ADAnalyzerRemediationReservation -ObjectGuid $script:Account.ToString($form).ToUpperInvariant()
                Assert-Inspection ($alias.Status -ceq 'Held' -and $alias.AttemptId -eq $script:Attempt) 'A GUID representation selected another record.'
            }
            Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Held inspection changed stored evidence.'
        }
    }

    Test-Inspection 'malformed secret-bearing and oversized records stay opaque' {
        $valid = New-InspectionRecord
        $invalid = @(
            [pscustomobject]@{ Bytes = [byte[]]@() }
            [pscustomobject]@{ Bytes = [byte[]]@(0xc3, 0x28) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes(('x' * 1025)) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.Replace($script:Attempt.ToString('D'), $script:Secret)) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.Replace($script:Attempt.ToString('D'), [guid]::Empty.ToString('D'))) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.Replace($script:Account.ToString('D'), 'bbbbbbbb-1111-4111-8111-111111111111')) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.Replace('Operation=Apply', ('Operation=' + $script:Secret))) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.Replace('+00:00', '+01:00')) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.Replace('LastConfirmedStep=AccountReserved', ('LastConfirmedStep=' + $script:Secret))) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid + 'Password=' + $script:Secret) }
            [pscustomobject]@{ Bytes = $script:Utf8.GetBytes($valid.TrimEnd([char]10)) }
        )
        foreach ($record in $invalid) {
            [IO.File]::WriteAllBytes($path, $record.Bytes)
            $before = Get-InspectionSnapshot $temporary
            Assert-Inspection ((Read-Inspection).Status -ceq 'Indeterminate') 'An invalid record was treated as absent or trusted.'
            Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Inspection modified malformed evidence.'
        }
    }

    Test-Inspection 'nonregular occupancy and active file sharing preserve evidence' {
        [IO.File]::Delete($path)
        $null = [IO.Directory]::CreateDirectory($path)
        [IO.File]::WriteAllText((Join-Path $path 'canary'), $script:Secret, $script:Utf8)
        $before = Get-InspectionSnapshot $temporary
        Assert-Inspection ((Read-Inspection).Status -ceq 'Indeterminate') 'Directory occupancy was treated as absent.'
        Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Inspection changed directory occupancy.'
        [IO.Directory]::Delete($path, $true)
        [IO.File]::WriteAllText($path, (New-InspectionRecord), $script:Utf8)
        $before = Get-InspectionSnapshot $temporary
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            Assert-Inspection ((Read-Inspection).Status -ceq 'Indeterminate') 'An unreadable active record was treated as absent.'
        }
        finally {
            $stream.Dispose()
        }
        Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Inspection changed an exclusively held record.'
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            Assert-Inspection ((Read-Inspection).Status -ceq 'Held') 'Compatible active sharing prevented observation.'
        }
        finally {
            $stream.Dispose()
        }
        Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Inspection changed a shared active record.'
    }

    Test-Inspection 'independent and reused inspectors detach results without releasing holds' {
        $before = Get-InspectionSnapshot $temporary
        $changed = $script:First.Inspect($script:Account)
        $changed.Status = 'fixture changed result'
        $changed.AttemptId = [guid]::Empty
        $fresh = $script:Second.Inspect($script:Account)
        Assert-Inspection ($fresh.Status -ceq 'Held' -and $fresh.AttemptId -eq $script:Attempt) 'Instances shared returned observation state.'
        Assert-Inspection ((Read-Inspection).Status -ceq 'Held') 'Reuse retained a mutated observation.'
        $type = 'ADAnalyzer.AccountEffectReservation' -as [type]
        Assert-InspectionFailure { $type::Acquire($script:AuthorityDirectory, $script:Account, $false) } 'Uncertain'
        Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Inspection released or rewrote the runtime reservation.'
        [IO.File]::Delete($path)
        Assert-Inspection ((Read-Inspection).Status -ceq 'NotObserved') 'A reused inspector cached the old hold.'
        [IO.File]::WriteAllText($path, (New-InspectionRecord 'Undo'), $script:Utf8)
        Assert-Inspection ((Read-Inspection).Operation -ceq 'Undo') 'A reused inspector cached old evidence.'
        Assert-Inspection ((ConvertTo-Json -InputObject $script:First -Compress) -cnotmatch 'AttemptId|AuthorityDirectory|AccountReserved') 'The inspector retained operation data.'
    }

    Test-Inspection 'invalid input and internal boundaries cannot select another scope' {
        $reads = $script:AuthorityReads
        $before = Get-InspectionSnapshot $temporary
        Assert-InspectionFailure { $script:First.Inspect([guid]::Empty) } 'canonical account GUID'
        Assert-InspectionFailure { Get-ADAnalyzerRemediationReservation -ObjectGuid ([guid]::Empty) } 'canonical account GUID'
        Assert-InspectionFailure { Get-ADAnalyzerRemediationReservation -ObjectGuid 'not a GUID' }
        $command = Get-Command Get-ADAnalyzerRemediationReservation -CommandType Function
        foreach ($name in 'Server', 'Domain', 'Credential', 'JournalPath', 'Path', 'AuthorityDirectory', 'Clear', 'WhatIf', 'Confirm') {
            Assert-Inspection (-not $command.Parameters.ContainsKey($name)) 'The inspection command exposed an alternate scope or effect switch.'
            $arguments = @{ ObjectGuid = $script:Account }
            $arguments[$name] = 'fixture-only'
            Assert-InspectionFailure { Get-ADAnalyzerRemediationReservation @arguments }
        }
        $type = 'ADAnalyzer.AccountEffectReservation' -as [type]
        Assert-InspectionFailure { $type::Inspect($script:AuthorityDirectory, [guid]::Empty) } 'canonical account GUID'
        Assert-InspectionFailure { $type::Inspect('relative-inspection-fixture', $script:Account) } 'absolute path'
        Assert-Inspection ($script:AuthorityReads -eq $reads) 'Invalid input reached the authority resolver.'
        Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Invalid inspection changed local evidence.'
    }

    Test-Inspection 'an unavailable authority throws without inventing absence' {
        $directory = $script:AuthorityDirectory
        $script:AuthorityDirectory = Join-Path $temporary 'not provisioned'
        $before = Get-InspectionSnapshot $temporary
        try {
            Assert-InspectionFailure { $script:First.Inspect($script:Account) } 'fixture authority is unavailable'
            Assert-InspectionFailure { Get-ADAnalyzerRemediationReservation -ObjectGuid $script:Account } 'fixture authority is unavailable'
            Assert-Inspection ((Get-InspectionSnapshot $temporary) -ceq $before) 'Inspection initialized an unavailable authority.'
        }
        finally {
            $script:AuthorityDirectory = $directory
        }
    }
    Assert-Inspection ($script:Forbidden.Count -eq 0) 'Inspection used a provider, journal lease or mutating command.'
}
finally {
    [IO.Directory]::Delete($temporary, $true)
}
Write-Output ('PASS remediation reservation inspection ' + $script:Passed)
