[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [string]$DeniedDirectory
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core' -or
    -not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::OSX
    )) {
    throw 'The case-alias fixture requires macOS PowerShell.'
}

$repository = [IO.Path]::GetFullPath($RepositoryRoot)
. (Join-Path $repository 'bin/ADProfile.ps1')
. (Join-Path $repository 'bin/ADOperations.ps1')
. (Join-Path $repository 'bin/Start-ADAnalyzer.ps1')

$script:Forbidden = [Collections.Generic.List[string]]::new()
$script:CollectorCalls = 0
foreach ($name in @(
        'Import-Module', 'Get-ADObject', 'Get-ADGroup', 'Get-ADRootDSE', 'Get-ADDomain',
        'Get-GPO', 'Invoke-Command', 'New-PSDrive', 'New-CimSession', 'Get-CimInstance',
        'Invoke-CimMethod', 'Disable-ADAccount', 'Enable-ADAccount'
    )) {
    Set-Item -LiteralPath ('Function:script:' + $name) -Value {
        $script:Forbidden.Add($MyInvocation.MyCommand.Name)
        throw 'The report fixture reached a forbidden integration.'
    }
}

if ($DeniedDirectory) {
    function Write-ADAnalyzerOperationFile {
        Write-Host 'UNEXPECTED_METADATA_WRITER'
        throw 'The metadata fixture reached the report writer.'
    }

    # This child deliberately invokes the command outside any try or trap.
    # A caller's try can cause statement-terminating method errors to propagate.
    $ErrorActionPreference = 'Continue'
    $ErrorView = 'NormalView'
    $document = [pscustomobject]@{
        SchemaVersion = 1
        Checks = @()
    }
    $arguments = @{
        Assessment = $document
        Format = 'Json'
        Path = [IO.Path]::Combine($DeniedDirectory, 'saved.json')
        ComparisonReferencePath = [IO.Path]::Combine($DeniedDirectory, 'Saved.JSON')
        Confirm = $false
        ErrorAction = 'Continue'
    }
    Write-Output 'METADATA_EXPORT_STARTED'
    Export-ADAnalyzerAssessment @arguments
    Write-Output 'UNEXPECTED_METADATA_CONTINUATION'
    exit 2
}

function Get-ADAnalyzerAssessment {
    [CmdletBinding()]
    param(
        [pscredential]$Credential,
        $Profile,
        [switch]$IncludeAcl,
        [switch]$IncludeHostChecks,
        [switch]$SkipGpo
    )

    if ($IncludeAcl -or $IncludeHostChecks -or -not $SkipGpo -or
        ($Credential -and $Credential -ne [pscredential]::Empty)) {
        throw 'The report fixture collection received unexpected options.'
    }
    $script:CollectorCalls++
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        Target = 'report-case.fixture.invalid'
        RunId = 'synthetic-difference'
        Checks = @()
        Findings = @()
    }
}

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Bytes([string]$Path) {
    if ([IO.File]::Exists($Path)) {
        return [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))
    }
    return $null
}

function Get-FileIdentityPair([string]$Source, [string]$Destination) {
    $results = @(& '/usr/bin/stat' '-f' '%d:%i' '--' $Source $Destination)
    Assert-Fixture (
        $LASTEXITCODE -eq 0 -and $results.Count -eq 2 -and
        $results[0] -match '^[0-9]+:[0-9]+$' -and $results[1] -match '^[0-9]+:[0-9]+$'
    ) 'The independent stat oracle could not identify both fixture files.'
    return $results
}

function Test-CaseAliasing([string]$Root) {
    $source = [IO.Path]::Combine($Root, 'Case-Calibration')
    $variant = [IO.Path]::Combine($Root, 'case-calibration')
    [IO.File]::WriteAllBytes($source, [byte[]]@(17, 19))
    if ([IO.File]::Exists($variant)) {
        $identities = @(Get-FileIdentityPair $source $variant)
        Assert-Fixture ($identities[0] -ceq $identities[1]) 'Case calibration found an unexpected existing file.'
        return $true
    }

    $handle = [IO.FileStream]::new(
        $variant, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $handle.WriteByte(23)
    }
    finally {
        $handle.Dispose()
    }
    $identities = @(Get-FileIdentityPair $source $variant)
    Assert-Fixture ($identities[0] -cne $identities[1]) 'Case calibration could not establish separate files.'
    return $false
}

function Test-UnavailableIdentityStopsNativeExport([string]$Root) {
    $denied = [IO.Path]::Combine($Root, 'metadata-denied')
    $null = [IO.Directory]::CreateDirectory($denied)
    $reference = [IO.Path]::Combine($denied, 'Saved.JSON')
    [IO.File]::WriteAllBytes($reference, [byte[]]@(33, 67, 11))
    $before = Get-Bytes $reference
    $errorFile = [IO.Path]::Combine($Root, 'metadata-child.stderr')
    $engine = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoLogo'
        '-NoProfile'
        '-NonInteractive'
        '-File'
        $PSCommandPath
        '-RepositoryRoot'
        $repository
        '-DeniedDirectory'
        $denied
    )
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        & '/bin/chmod' 000 $denied
        Assert-Fixture ($LASTEXITCODE -eq 0) 'Could not establish disposable metadata denial.'
        $output = @(& $engine @arguments 2> $errorFile)
        $exitCode = $LASTEXITCODE
    }
    finally {
        & '/bin/chmod' 700 $denied
        Assert-Fixture ($LASTEXITCODE -eq 0) 'Could not restore disposable metadata fixture permissions.'
    }

    $diagnostic = [IO.File]::ReadAllText($errorFile)
    $normalized = ($diagnostic -replace '(?m)^\s*\|\s*', '') -replace '\s+', ' '
    $message = 'Could not verify the saved report destination identity.'
    Assert-Fixture (
        $exitCode -eq 1 -and $normalized.Contains($message) -and
        -not $normalized.Contains('Saved.JSON') -and
        $output.Count -eq 1 -and $output[0] -ceq 'METADATA_EXPORT_STARTED'
    ) ('Native Continue did not stop before publication on the expected metadata error. ' +
        'Child output: ' + ($output -join ' ') + ' Child diagnostic: ' + $normalized)
    Assert-Fixture (
        (Get-Bytes $reference) -ceq $before -and [IO.Directory]::GetFileSystemEntries($denied).Count -eq 1
    ) 'Failed native publication changed its existing reference or left an unexpected artifact.'
    Write-Output 'PASS portable report metadata denial before native writer'
}

function Invoke-FixtureExport(
    [string]$Route,
    [string]$Source,
    [string]$OutputPath,
    [string]$Format,
    [bool]$Preview,
    [bool]$CreateOnly = $false
) {
    if ($Route -ceq 'Class') {
        $report = [ADAnalyzerAssessmentReport]::new()
        if ($CreateOnly) {
            return $report.WriteNew($Source, $OutputPath, $Preview)
        }
        return $report.Write($Source, $OutputPath, $Format, $Preview)
    }
    if ($Route -ceq 'CLI') {
        return Start-ADAnalyzer -Operation report -ReferencePath $Source -OutputPath $OutputPath -SkipGpo -WhatIf:$Preview
    }
    $arguments = @{
        Assessment = $Source
        Path = $OutputPath
        Format = $Format
        WhatIf = $Preview
        Confirm = $false
        ErrorAction = 'Stop'
    }
    if ($CreateOnly) {
        $arguments.CreateOnly = $true
    }
    Export-ADAnalyzerAssessment @arguments
}

$root = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(), ('ad-report-case-alias-' + [guid]::NewGuid().ToString('N'))
)
$null = [IO.Directory]::CreateDirectory($root)
$sourceBytes = [Text.UTF8Encoding]::new($false).GetBytes(
    '{"SchemaVersion":1,"Target":"report-case.fixture.invalid","RunId":"selected-source","Checks":[],"Findings":[]}'
)
$expectedSource = [Convert]::ToBase64String($sourceBytes)
$existingBytes = [byte[]]@(8, 0, 127, 255)
$expectedExisting = [Convert]::ToBase64String($existingBytes)
$failures = [Collections.Generic.List[string]]::new()
$executed = 0
$createOnlyExecuted = 0

try {
    $caseAliases = Test-CaseAliasing $root
    if ($caseAliases) {
        $mode = 'Alias'
        Write-Output 'The fixture volume aliases case variants. Case-sensitive volume qualification was not run.'
    }
    else {
        $mode = 'DistinctCase'
        Write-Output 'The fixture volume distinguishes case variants. Existing case aliases were unavailable.'
    }

    $cases = @(
        @{
            Name = 'native-literal'
            Route = 'Native'
            Alias = $true
        },
        @{
            Name = 'native-qualified'
            Route = 'Native'
            Alias = $true
            Qualified = $true
        },
        @{
            Name = 'class-literal'
            Route = 'Class'
            Alias = $true
        },
        @{
            Name = 'class-qualified'
            Route = 'Class'
            Alias = $true
            Qualified = $true
        },
        @{
            Name = 'native-all'
            Route = 'Native'
            Alias = $true
            All = $true
        },
        @{
            Name = 'class-all'
            Route = 'Class'
            Alias = $true
            All = $true
        },
        @{
            Name = 'cli-literal'
            Route = 'CLI'
            Alias = $true
            All = $true
        },
        @{
            Name = 'cli-qualified'
            Route = 'CLI'
            Alias = $true
            All = $true
            Qualified = $true
        },
        @{
            Name = 'native-distinct'
            Route = 'Native'
        },
        @{
            Name = 'class-distinct'
            Route = 'Class'
        },
        @{
            Name = 'cli-distinct'
            Route = 'CLI'
            All = $true
        }
    )

    foreach ($case in $cases) {
        $directory = [IO.Path]::Combine($root, $case.Name)
        $null = [IO.Directory]::CreateDirectory($directory)
        $extension = if ($case.All) { 'html' } else { 'json' }
        $format = if ($case.All) { 'All' } else { 'Json' }
        $stem = if ($case.Alias) { 'selected [literal]' } else { 'unrelated [literal]' }
        $source = [IO.Path]::Combine($directory, ('SELECTED [literal].' + $extension.ToUpperInvariant()))
        $prefix = [IO.Path]::Combine($directory, $stem)
        $destination = $prefix + '.' + $extension
        $outputPath = if ($case.All) { $prefix } else { $destination }
        if ($case.Qualified) {
            $outputPath = 'FileSystem::' + $outputPath
        }

        [IO.File]::WriteAllBytes($source, $sourceBytes)
        $sameFile = $case.Alias -and $caseAliases
        if (-not $sameFile) {
            [IO.File]::WriteAllBytes($destination, $existingBytes)
        }
        $identities = @(Get-FileIdentityPair $source $destination)
        Assert-Fixture (
            ($identities[0] -ceq $identities[1]) -eq $sameFile
        ) 'The scenario did not establish the expected physical file identities.'

        $sibling = $null
        $absent = $null
        if ($case.All) {
            $sibling = $prefix + '.json'
            $absent = $prefix + '.csv'
            [IO.File]::WriteAllBytes($sibling, $existingBytes)
        }

        $destinationBefore = Get-Bytes $destination
        $previewRows = @(Invoke-FixtureExport $case.Route $source $outputPath $format $true)
        if ($case.Route -ceq 'CLI') {
            Assert-Fixture (
                $previewRows.Count -eq 1 -and $previewRows[0].Comparison.ReferenceRunId -ceq 'selected-source'
            ) 'The CLI preview did not use the real saved comparison.'
        }
        else {
            Assert-Fixture ($previewRows.Count -eq 0) 'A report preview returned published paths.'
        }
        Assert-Fixture (
            (Get-Bytes $source) -ceq $expectedSource -and (Get-Bytes $destination) -ceq $destinationBefore
        ) 'A preview changed or published a file.'
        if ($case.All) {
            Assert-Fixture (
                (Get-Bytes $sibling) -ceq $expectedExisting -and -not [IO.File]::Exists($absent)
            ) 'An All preview changed a report sibling.'
        }

        if ($case.Alias -and -not $case.All) {
            $createOnlyPreview = @(Invoke-FixtureExport $case.Route $source $outputPath $format $true $true)
            Assert-Fixture ($createOnlyPreview.Count -eq 0) 'Create-only preview returned published paths.'
            $createOnlyFailure = $null
            $createOnlyRows = [Collections.Generic.List[object]]::new()
            try {
                Invoke-FixtureExport $case.Route $source $outputPath $format $false $true | ForEach-Object {
                    $createOnlyRows.Add($_)
                }
            }
            catch {
                $createOnlyFailure = $_.Exception.GetBaseException().Message
            }
            Assert-Fixture (
                $createOnlyFailure -ceq 'The report destination already exists.' -and
                $createOnlyRows.Count -eq 0 -and (Get-Bytes $source) -ceq $expectedSource -and
                (Get-Bytes $destination) -ceq $destinationBefore -and
                @([IO.Directory]::GetFiles($directory, '.ad-analyzer-*.tmp')).Count -eq 0
            ) 'Create-only changed the established collision outcome or wrote a file.'
            $createOnlyExecuted++
        }

        $rows = [Collections.Generic.List[object]]::new()
        $failure = $null
        try {
            Invoke-FixtureExport $case.Route $source $outputPath $format $false | ForEach-Object {
                $rows.Add($_)
            }
        }
        catch {
            $failure = $_.Exception.GetBaseException().Message
        }

        $sourcePreserved = (Get-Bytes $source) -ceq $expectedSource
        $destinationPreserved = (Get-Bytes $destination) -ceq $destinationBefore
        $siblingPreserved = $null -eq $sibling -or (Get-Bytes $sibling) -ceq $expectedExisting
        $absentPreserved = $null -eq $absent -or -not [IO.File]::Exists($absent)
        $staging = @([IO.Directory]::GetFiles($directory, '.ad-analyzer-*.tmp')).Count
        $expectedFailure = if ($case.Route -ceq 'CLI') {
            'A report destination matches the saved comparison reference.'
        }
        else {
            'A report destination matches the saved assessment source.'
        }

        if ($sameFile) {
            $passed = $failure -ceq $expectedFailure -and $rows.Count -eq 0 -and
                $sourcePreserved -and $destinationPreserved -and $siblingPreserved -and $absentPreserved -and $staging -eq 0
        }
        elseif ($case.Route -ceq 'CLI') {
            $passed = $null -eq $failure -and $rows.Count -eq 1 -and $sourcePreserved -and
                -not $destinationPreserved -and -not $siblingPreserved -and -not $absentPreserved -and $staging -eq 0
            if ($passed) {
                $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($sibling))
                $passed = $rows[0].Comparison.ReferenceRunId -ceq 'selected-source' -and
                    $saved.Comparison.ReferenceRunId -ceq 'selected-source'
            }
        }
        else {
            $passed = $null -eq $failure -and $rows.Count -eq 1 -and $sourcePreserved -and
                -not $destinationPreserved -and $rows[0] -ceq $destination -and $staging -eq 0
            if ($passed) {
                $saved = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($destination))
                $passed = $saved.RunId -ceq 'selected-source'
            }
        }

        if (-not $passed) {
            $failures.Add($case.Name)
        }
        $executed++
        [pscustomobject][ordered]@{
            Case = $case.Name
            SameFile = [bool]$sameFile
            SourceDeviceAndInode = $identities[0]
            DestinationDeviceAndInode = $identities[1]
            PreviewPreserved = $true
            Passed = $passed
            SourcePreserved = $sourcePreserved
            DestinationPreserved = $destinationPreserved
            SiblingPreserved = $siblingPreserved
            AbsentPreserved = $absentPreserved
            OutputCount = $rows.Count
            StagedCount = $staging
            Diagnostic = $failure
        } | ConvertTo-Json -Compress
    }
    Test-UnavailableIdentityStopsNativeExport $root
}
finally {
    [IO.Directory]::Delete($root, $true)
}

Assert-Fixture (
    $executed -eq 11 -and $createOnlyExecuted -eq 4
) 'The fixture did not execute every registered case.'
Assert-Fixture (
    $script:CollectorCalls -eq 6 -and $script:Forbidden.Count -eq 0
) 'The fixture did not isolate collection or reached a forbidden operation.'
Write-Output (
    "Report case mode: $mode, cases: $executed, failed: $($failures.Count), " +
    "create-only controls: $createOnlyExecuted, forbidden effects: $($script:Forbidden.Count)"
)
if ($failures.Count -gt 0) {
    Write-Output ('Protection failures: ' + ($failures -join ', '))
    exit 1
}
Write-Output ('PASS portable report case ' + $mode + ' ' + $executed)
