[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Regression', 'Controls', 'Targets', 'Observe')][string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [string]$Scenario,
    [ValidateSet('Caught', 'Uncaught')][string]$Capture = 'Caught',
    [switch]$First,
    [switch]$Ambient,
    [switch]$StopOnError,
    [switch]$StrictMetadata
)

$ErrorActionPreference = 'Stop'

function Assert-ReportFixture($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function ConvertTo-ErrorObservation([object]$Value) {
    $record = if ($Value -is [Management.Automation.ErrorRecord]) {
        $Value
    }
    elseif ($Value -is [Management.Automation.IContainsErrorRecord]) {
        $Value.ErrorRecord
    }
    if ($null -eq $record) {
        return [pscustomobject]@{ StoredType = $Value.GetType().FullName; IsTyped = $false }
    }
    $cause = $record.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $record.FullyQualifiedErrorId
        Category = [string]$record.CategoryInfo.Category
        Type = $cause.GetType().FullName
        Message = $cause.Message
        DataKeys = @($record.Exception.Data.Keys | Sort-Object) -join '|'
        StoredType = $Value.GetType().FullName
        IsTyped = $true
    }
}

if ($Case -eq 'Observe') {
    . (Join-Path $RepositoryRoot 'bin/ADGpo.ps1')

    $script:Events = [Collections.Generic.List[object]]::new()
    $script:TargetAttempts = [Collections.Generic.List[string]]::new()
    $script:TargetReads = [Collections.Generic.List[string]]::new()
    $script:TargetReadCounts = @{
        Server = 0
        Domain = 0
    }
    $script:DriveName = $null
    $script:PolicyId = [guid]'5c07cdaf-63cd-4203-87dd-4083d09a8d03'
    $script:Domain = 'report.fixture.invalid'
    $script:Pinned = 'dc-selected.fixture.invalid'
    $script:Requested = 'dc-alias.fixture.invalid'
    $script:TrustedRoot = '\\' + $script:Pinned + '\SYSVOL'
    $script:UncPolicy = $script:TrustedRoot + '\' + $script:Domain + '\Policies\' + $script:PolicyId.ToString('B')
    $script:TempRoot = Join-Path ([IO.Path]::GetTempPath()) ('gpo-report-fixture-' + [guid]::NewGuid().ToString('N'))
    $script:FixturePath = Join-Path (Join-Path (Join-Path $script:TempRoot $script:Domain) 'Policies') $script:PolicyId.ToString('B')
    $script:Credential = [pscredential]::new('fixture\reader', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
    $script:ExpectAmbientCredential = $Scenario -in @(
        'DefaultCredential'
        'EmptyCredential'
        'TargetUncredentialedObject'
        'TargetUncredentialedXml'
    )

    function Read-TargetFixtureValue([string]$Field, [string]$Initial, [string]$Later) {
        $script:TargetReads.Add($Field)
        $script:TargetReadCounts[$Field]++
        if ($script:TargetReadCounts[$Field] -eq 1) {
            return $Initial
        }
        return $Later
    }

    function Import-Module {
        throw 'GPO report fixture may use only its isolated directory commands.'
    }

    function Get-ADAnalyzerGpo {
        param([guid]$Guid, [string]$Domain, [string]$Server, [pscredential]$Credential)
        Assert-ReportFixture (
            $Guid -eq $script:PolicyId -and $Domain -ceq $script:Domain -and
            $Server -ceq $script:Requested -and [object]::ReferenceEquals($Credential, $script:Credential)
        ) 'GUID discovery dropped the requested DC, domain, identity or credential.'
        $script:Events.Add('Find')
        if ($Scenario -eq 'GuidAmbiguous') {
            $script:Metadata
        }
        $script:Metadata
    }

    function New-PSDrive {
        param(
            [string]$Name, [string]$PSProvider, [string]$Root,
            [pscredential]$Credential, [string]$Scope, [string]$ErrorAction,
            [switch]$WhatIf, [switch]$Confirm
        )
        $script:TargetAttempts.Add('Mount')
        Assert-ReportFixture (
            $Root -ceq $script:TrustedRoot -and $Scope -ceq 'Local' -and
            $PSProvider -ceq 'FileSystem' -and $Name -cmatch '^ADGpo[0-9a-f]{32}$' -and
            $ErrorAction -ceq 'Stop' -and -not $WhatIf -and -not $Confirm -and
            [object]::ReferenceEquals($Credential, $script:Credential)
        ) 'Mount did not preserve selected DC, local scope, credential or explicit flags.'
        $script:DriveName = $Name
        $script:Events.Add('Mount')
        if ($Scenario -eq 'MountFailure') {
            throw [IO.IOException]::new('Fixture mount failed.')
        }
        Microsoft.PowerShell.Management\New-PSDrive -Name $Name -PSProvider FileSystem -Root $script:TempRoot -Scope '1' -ErrorAction Stop -WhatIf:$false -Confirm:$false
    }

    function Remove-PSDrive {
        param([string]$Name, [switch]$Force, [string]$ErrorAction, [switch]$WhatIf, [switch]$Confirm)
        Assert-ReportFixture (
            $Name -ceq $script:DriveName -and $Force -and $ErrorAction -ceq 'Stop' -and -not $WhatIf -and -not $Confirm
        ) 'Unmount did not use the acquired drive or explicit flags.'
        $drive = Microsoft.PowerShell.Management\Get-PSDrive -Name $Name -Scope '1' -ErrorAction Stop
        Assert-ReportFixture ($null -ne $drive -and $drive.Root -ceq $script:TempRoot) 'Unmount could not see the owned disposable drive.'
        $script:Events.Add('Unmount')
        if ($Scenario -cmatch 'CleanupFailure$' -and $Scenario -ne 'NativeCleanupFailure') {
            throw [UnauthorizedAccessException]::new('Fixture cleanup failed.')
        }
        if ($Scenario -eq 'NativeCleanupFailure') {
            Write-Error -Message 'Fixture native cleanup failed.' -ErrorAction $ErrorAction
        }
        Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Force -Scope '1' -ErrorAction Stop -WhatIf:$false -Confirm:$false
        if ($Scenario -cmatch 'NativeDriveNotFound$') {
            Microsoft.PowerShell.Management\Remove-PSDrive -Name $Name -Force -Scope '1' -ErrorAction Stop -WhatIf:$false -Confirm:$false
        }
    }

    function Read-ADAnalyzerGpo {
        param([string]$Path)
        $script:TargetAttempts.Add('Read')
        if ($script:ExpectAmbientCredential) {
            Assert-ReportFixture ($Path -ceq $script:UncPolicy) 'Credential-free read used an unexpected path.'
            $script:Events.Add('ReadUNC')
        }
        else {
            Assert-ReportFixture ($Path -like ($script:DriveName + ':*')) 'Reader did not use its owned drive.'
            $actual = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -ErrorAction Stop
            Assert-ReportFixture ($actual.FullName -ceq $script:FixturePath) 'Reader did not reach the isolated policy folder.'
            $script:Events.Add('Read')
        }

        if ($Scenario -in 'ReadFailure', 'ReadAndCleanupFailure', 'ReadAndNativeDriveNotFound') {
            throw [IO.InvalidDataException]::new('Fixture policy read failed.')
        }
        if ($Scenario -in 'NativeReadFailure', 'NativeReadAndCleanupFailure') {
            return [FixtureNativeReportRead]::Fail()
        }
        if ($Scenario -in 'ReadNonterminating', 'ReadNonterminatingAndCleanupFailure') {
            Write-Error -Message 'Fixture nonterminating read diagnostic.' -ErrorAction Continue
        }
        return $script:Policy
    }

    function Get-ADObject {
        [CmdletBinding()]
        param([string]$Filter, [string[]]$Properties, [string]$Server, [pscredential]$Credential)
        $script:TargetAttempts.Add('Sid')
        $expectedCredential = if ($script:ExpectAmbientCredential) {
            -not $PSBoundParameters.ContainsKey('Credential')
        }
        else {
            [object]::ReferenceEquals($Credential, $script:Credential)
        }
        Assert-ReportFixture (
            $Server -ceq $script:Pinned -and ($Properties -join ',') -ceq 'sAMAccountName' -and
            $ErrorActionPreference -eq 'Stop' -and $expectedCredential -and
            $Filter -cmatch "^objectSid -eq '(?<Sid>S-1-5-21-1-2-3-\d+)'$"
        ) 'SID lookup lost pinned transport or native binding.'
        $sid = $Matches.Sid
        $script:Events.Add('Sid:' + $sid)
        switch ($sid) {
            'S-1-5-21-1-2-3-1001' {
                [pscustomobject]@{ sAMAccountName = 'Resolved fixture' }
            }
            'S-1-5-21-1-2-3-1002' {
                return
            }
            'S-1-5-21-1-2-3-1003' {
                throw [UnauthorizedAccessException]::new('Fixture SID lookup failed.')
            }
            default {
                throw 'Unexpected fixture SID.'
            }
        }
    }

    if ($Scenario -like 'NativeRead*') {
        Add-Type @'
using System.IO;
public static class FixtureNativeReportRead
{
    public static object Fail()
    {
        throw new InvalidDataException("Fixture native policy read failed.");
    }
}
'@
    }

    function ConvertTo-Emission([object]$Value) {
        if ($Value -is [Management.Automation.ErrorRecord]) {
            return [pscustomobject]@{ Kind = 'Error'; Diagnostic = ConvertTo-ErrorObservation $Value }
        }
        if ($Value -is [Management.Automation.WarningRecord]) {
            return [pscustomobject]@{ Kind = 'Warning'; Message = $Value.Message }
        }
        if ($Value -is [string]) {
            $doc = [xml]$Value
            $resolutions = @($doc.SelectNodes('//Member/Resolution') | ForEach-Object { $_.PSBase.InnerText })
            return [pscustomobject]@{ Kind = 'Xml'; Resolutions = $resolutions; Mismatch = $doc.GPO.VersionMismatch }
        }
        return [pscustomobject]@{
            Kind = 'Object'
            Fields = @($Value.PSObject.Properties.Name) -join '|'
            Mismatch = $Value.VersionMismatch
            SameMetadata = [object]::ReferenceEquals($Value.Gpo, $script:Metadata)
            SamePolicy = [object]::ReferenceEquals($Value.Policy, $script:Policy)
        }
    }

    function Observe-Report {
        $script:Metadata = [pscustomobject]@{
            Id = $script:PolicyId
            Domain = $script:Domain
            Server = $script:Pinned
            RequestedServer = $script:Requested
            DirectoryFilePath = '\\ignored.fixture.invalid\path'
            PolicyPath = '\\ignored.fixture.invalid\path'
            Version = 65538
            Flags = 0
            Links = @()
        }
        $script:Policy = [pscustomobject]@{
            SysvolVersion = 65538
            SecuritySettings = @(
                [pscustomobject]@{
                    Scope = 'Computer'
                    Kind = 'UserRightsAssignment'
                    Name = 'Fixture right'
                    Value = @(
                        '*S-1-5-32-544'
                        '*S-1-5-21-1-2-3-1001'
                        '*S-1-5-21-1-2-3-1001'
                        '*S-1-5-21-1-2-3-1002'
                        '*S-1-5-21-1-2-3-1003'
                        '*S-1-5-21-1-2-3-1004'
                    )
                }
            )
            RegistrySettings = @()
            IniSettings = @()
            XmlFiles = @()
            Files = @()
        }
        $names = @{ 'S-1-5-21-1-2-3-1004' = 'Supplied mapping' }
        $capturedErrors = @()
        $arguments = @{
            Gpo = $script:Metadata
            Credential = $script:Credential
            AsObject = $true
            SidNames = $names
            ErrorVariable = 'capturedErrors'
        }
        switch ($Scenario) {
            'DefaultCredential' {
                $arguments.Remove('Credential')
            }
            'EmptyCredential' {
                $arguments.Credential = [pscredential]::Empty
            }
            'MismatchedVersion' {
                $script:Metadata.Version = 65539
            }
            { $_ -in 'WarningsStop', 'WarningsStopAndCleanupFailure' } {
                $script:Metadata.Version = 65539
                $arguments.WarningAction = 'Stop'
            }
            { $_ -in 'BadVersion', 'BadVersionAndCleanupFailure' } {
                $script:Metadata.Version = 'invalid-version'
            }
            'UnsignedVersion' {
                $script:Metadata.Version = -1
                $script:Policy.SysvolVersion = [long]4294967295
            }
            'AbsentStoredVersion' {
                $script:Policy.SysvolVersion = $null
            }
            'InvalidMetadata' {
                $script:Metadata.Server = 'invalid/path'
            }
            'XmlWithSidOutcomes' {
                $arguments.AsObject = $false
                $script:Metadata.Version = 65539
            }
            { $_ -in 'GuidPinned', 'GuidAmbiguous', 'TargetGuid' } {
                $arguments.Remove('Gpo')
                $arguments.Guid = $script:PolicyId
                $arguments.Domain = $script:Domain
                $arguments.Server = $script:Requested
            }
        }
        if ($Scenario -like 'Target*') {
            $script:Metadata.PSObject.Properties.Remove('Server')
            $script:Metadata | Add-Member ScriptProperty Server {
                Read-TargetFixtureValue 'Server' $script:Pinned 'other-server.fixture.invalid'
            }
            $script:Metadata.PSObject.Properties.Remove('Domain')
            $script:Metadata | Add-Member ScriptProperty Domain {
                Read-TargetFixtureValue 'Domain' $script:Domain 'other-domain.fixture.invalid'
            }

            if ($Scenario -match '\ATargetBad(?<Field>Server|Domain)(?<Shape>.+)\z') {
                $field = $Matches.Field
                $shape = $Matches.Shape
                $script:Metadata.PSObject.Properties.Remove($field)
                if ($shape -ne 'Missing') {
                    $value = switch ($shape) {
                        'Null' {
                            $null
                        }
                        'Single' {
                            , @('scalar-shape.fixture.invalid')
                        }
                        'Multiple' {
                            , @('first.fixture.invalid', 'second.fixture.invalid')
                        }
                        'Newline' {
                            "scalar-shape.fixture.invalid`n"
                        }
                        'Number' {
                            123
                        }
                        'Syntax' {
                            'invalid fixture value'
                        }
                    }
                    $script:Metadata | Add-Member -MemberType NoteProperty -Name $field -Value $value
                }
            }
            else {
                if ($Scenario -eq 'TargetUncredentialedObject') {
                    $arguments.Remove('Credential')
                }
                if ($Scenario -eq 'TargetUncredentialedXml') {
                    $arguments.Credential = [pscredential]::Empty
                }
                if ($Scenario -in 'TargetMountedXml', 'TargetUncredentialedXml') {
                    $arguments.AsObject = $false
                }
            }
        }
        if ($Ambient) {
            $WhatIfPreference = $true
            $ConfirmPreference = 'Low'
        }
        if ($StopOnError) {
            $arguments.ErrorAction = 'Stop'
        }

        $Error.Clear()
        try {
            throw 'Fixture unrelated prior error.'
        }
        catch {
            # Distinguish a seeded diagnostic from a failure in the current operation.
        }
        $emissions = [Collections.Generic.List[object]]::new()
        $continued = $false
        $caught = $null
        $ErrorActionPreference = 'Continue'
        if ($StrictMetadata) {
            Set-StrictMode -Version Latest
        }

        # This outer finally serializes observations without catching an uncaught report failure.
        try {
            if ($Capture -eq 'Caught') {
                try {
                    if ($First) {
                        Get-ADAnalyzerGpoReport @arguments 3>&1 2>&1 |
                            Select-Object -First 1 | ForEach-Object { $emissions.Add($_) }
                    }
                    else {
                        Get-ADAnalyzerGpoReport @arguments 3>&1 2>&1 | ForEach-Object { $emissions.Add($_) }
                    }
                }
                catch {
                    $caught = ConvertTo-ErrorObservation $_
                    $emissions.Add($_)
                }
            }
            elseif ($First) {
                Get-ADAnalyzerGpoReport @arguments 3>&1 2>&1 |
                    Select-Object -First 1 | ForEach-Object { $emissions.Add($_) }
            }
            else {
                Get-ADAnalyzerGpoReport @arguments 3>&1 2>&1 | ForEach-Object { $emissions.Add($_) }
            }
            $continued = $true
        }
        finally {
            $history = @($Error | ForEach-Object { ConvertTo-ErrorObservation $_ })
            $variable = @($capturedErrors | ForEach-Object { ConvertTo-ErrorObservation $_ })
            $items = @($emissions | ForEach-Object { ConvertTo-Emission $_ })
            $visible = $false
            if ($script:DriveName) {
                $visible = $null -ne (Microsoft.PowerShell.Management\Get-PSDrive -Name $script:DriveName -ErrorAction SilentlyContinue)
            }
            $observation = [pscustomobject]@{
                Continued = $continued
                Caught = $caught
                Items = $items
                Events = $script:Events.ToArray()
                ErrorHistory = $history
                ErrorVariable = $variable
                DriveVisible = $visible
                SidMapIntact = $names.Count -eq 1 -and $names['S-1-5-21-1-2-3-1004'] -ceq 'Supplied mapping'
            }
            if ($Scenario -like 'Target*') {
                $observation | Add-Member -MemberType NoteProperty -Name TargetAttempts -Value $script:TargetAttempts.ToArray()
                $observation | Add-Member -MemberType NoteProperty -Name TargetReads -Value $script:TargetReads.ToArray()
            }
            Write-Output ('OBSERVATION ' + (ConvertTo-Json -InputObject $observation -Depth 12 -Compress))
        }
    }

    $null = [IO.Directory]::CreateDirectory($script:FixturePath)
    try {
        Observe-Report
    }
    finally {
        [IO.Directory]::Delete($script:TempRoot, $true)
    }
    exit
}

function Invoke-ReportChild(
    [string]$Name, [string]$Mode, [bool]$TakeFirst = $false, [bool]$Preferences = $false, [bool]$ActionStop = $false,
    [bool]$Strict = $false
) {
    $exe = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Observe', '-RepositoryRoot', $RepositoryRoot, '-Scenario', $Name, '-Capture', $Mode
    )
    if ($TakeFirst) {
        $arguments += '-First'
    }
    if ($Preferences) {
        $arguments += '-Ambient'
    }
    if ($ActionStop) {
        $arguments += '-StopOnError'
    }
    if ($Strict) {
        $arguments += '-StrictMetadata'
    }
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $lines = @(& $exe @arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $records = @($lines | Where-Object { [string]$_ -clike 'OBSERVATION *' })
    Assert-ReportFixture ($records.Count -eq 1) 'The fresh process did not provide one typed observation box.'
    $observation = ConvertFrom-Json -InputObject ([string]$records[0]).Substring('OBSERVATION '.Length)
    [pscustomobject]@{
        ExitCode = $exitCode
        Status = $observation
        Diagnostics = @($lines | Where-Object { [string]$_ -cnotlike 'OBSERVATION *' }) -join [Environment]::NewLine
    }
}

function Assert-BaseObservation([object]$Observation, [string]$Events, [string]$Kinds, [bool]$Continued, [bool]$ExitFailed) {
    $status = $Observation.Status
    Assert-ReportFixture (
        ($status.Events -join '|') -ceq $Events -and -not $status.DriveVisible -and $status.SidMapIntact
    ) 'The operation changed observed connection, ownership, cleanup or SID-map behavior.'
    Assert-ReportFixture (
        (@($status.Items | ForEach-Object Kind) -join '|') -ceq $Kinds -and
        $status.Continued -eq $Continued -and ($Observation.ExitCode -ne 0) -eq $ExitFailed
    ) 'The operation changed result, stream order or native termination.'
    foreach ($item in @($status.Items | Where-Object Kind -eq 'Object')) {
        Assert-ReportFixture (
            $item.Fields -ceq 'Gpo|Policy|VersionMismatch' -and $item.SameMetadata -and $item.SamePolicy
        ) 'AsObject changed its shape or source reference.'
    }
}

function Get-Primary([object]$Observation, [string]$Mode) {
    if ($Mode -eq 'Caught') {
        return $Observation.Status.Caught
    }
    return @($Observation.Status.ErrorHistory)[0]
}

function Assert-NativeCapture([object]$Observation, [string]$TypeMatch) {
    foreach ($records in @($Observation.Status.ErrorVariable, $Observation.Status.ErrorHistory)) {
        Assert-ReportFixture (
            @($records | Where-Object { $_.IsTyped -and $_.Id -and $_.Type -like $TypeMatch }).Count -gt 0
        ) 'A native typed diagnostic was absent from an error capture.'
    }
}

function Format-ReportHostDiagnostic([string]$Text) {
    $plain = $Text -replace '\x1b\[[0-?]*[ -/]*[@-~]', ''
    $unwrapped = $plain -replace '(?m)^[ \t]*\|[ \t]*', ''
    return ($unwrapped -replace '\s+', ' ').Trim()
}

function Test-CompetingFailures(
    [string]$Fault, [string]$Only, [string]$Mode, [bool]$Preferences, [string]$CleanupType
) {
    $control = Invoke-ReportChild $Only $Mode $false $Preferences
    $actual = Invoke-ReportChild $Fault $Mode $false $Preferences
    $expected = Get-Primary $control $Mode
    $primary = Get-Primary $actual $Mode
    Assert-ReportFixture (
        $null -ne $expected -and $expected.IsTyped -and
        $null -ne $primary -and $primary.IsTyped -and $primary.Type -ceq $expected.Type -and
        $primary.Id -ceq $expected.Id -and $primary.Category -ceq $expected.Category -and
        $primary.Message -ceq $expected.Message -and $primary.DataKeys -ceq $expected.DataKeys
    ) 'The cleanup error displaced or altered the primary native diagnostic.'
    Assert-NativeCapture $actual $CleanupType
    Assert-NativeCapture $actual $expected.Type
    Assert-ReportFixture (
        @($actual.Status.ErrorHistory | Where-Object Message -ceq 'Fixture unrelated prior error.').Count -gt 0
    ) 'The report changed unrelated native error history.'
    $expectedKinds = @($control.Status.Items | ForEach-Object Kind) -join '|'
    Assert-BaseObservation $actual 'Mount|Read|Unmount' $expectedKinds $control.Status.Continued ($control.ExitCode -ne 0)
    if ($Mode -eq 'Uncaught') {
        $controlText = Format-ReportHostDiagnostic $control.Diagnostics
        $actualText = Format-ReportHostDiagnostic $actual.Diagnostics
        Assert-ReportFixture (
            $control.ExitCode -ne 0 -and -not $control.Status.Continued -and
            -not [string]::IsNullOrWhiteSpace($expected.Message) -and
            $controlText -match '\p{L}' -and
            -not $controlText.Contains('Fixture cleanup failed.')
        ) 'The single-failure reference did not surface a terminal host diagnostic.'
        Assert-ReportFixture (
            $actualText -ceq $controlText -and
            -not $actualText.Contains('Fixture cleanup failed.')
        ) 'The uncaught host did not preserve its single-failure diagnostic.'
    }
}

function New-Control(
    [string]$Name, [string]$Mode, [string]$Events, [string]$Kinds,
    [string]$Primary = '', [bool]$TakeFirst = $false, [bool]$Preferences = $false, [bool]$ActionStop = $false
) {
    [pscustomobject]@{
        Name = $Name
        Mode = $Mode
        Events = $Events
        Kinds = $Kinds
        Primary = $Primary
        First = $TakeFirst
        Ambient = $Preferences
        Stop = $ActionStop
    }
}

function Test-ReportControl([object]$Spec) {
    $actual = Invoke-ReportChild $Spec.Name $Spec.Mode $Spec.First $Spec.Ambient $Spec.Stop
    $terminated = $Spec.Mode -eq 'Uncaught' -and $Spec.Primary -ne ''
    Assert-BaseObservation $actual $Spec.Events $Spec.Kinds (-not $terminated) $terminated
    if ($Spec.Primary) {
        $primary = Get-Primary $actual $Spec.Mode
        Assert-ReportFixture (
            $null -ne $primary -and $primary.IsTyped -and $primary.Type -like $Spec.Primary
        ) 'The report changed its native primary error type.'
    }
    if ($Spec.First -and $Spec.Name -like '*CleanupFailure') {
        Assert-NativeCapture $actual '*UnauthorizedAccessException'
    }
    if ($Spec.Name -eq 'XmlWithSidOutcomes') {
        $xml = @($actual.Status.Items | Where-Object Kind -eq 'Xml')[0]
        Assert-ReportFixture (
            $xml.Mismatch -ceq 'true' -and
            ($xml.Resolutions -join '|') -ceq 'Resolved|Resolved|Resolved|NotFound|LookupFailed|Resolved'
        ) 'The XML report changed version evidence or SID resolution outcomes.'
    }
    if ($Spec.Name -in 'UnsignedVersion', 'AbsentStoredVersion') {
        Assert-ReportFixture (-not $actual.Status.Items[0].Mismatch) 'Version comparison changed an accepted boundary.'
    }
}

function Test-ReportTargetSuccess([object]$Spec) {
    $actual = Invoke-ReportChild $Spec.Name $Spec.Mode
    $status = $actual.Status
    Assert-ReportFixture (($status.TargetReads -join '|') -ceq 'Server|Domain') 'The accepted target fields were not each read exactly once in order.'
    Assert-BaseObservation $actual $Spec.Events $Spec.Kinds $true $false
    if ($Spec.Kinds -eq 'Warning|Xml') {
        Assert-ReportFixture (
            $status.Items[0].Message -ceq 'Unable to resolve policy SID S-1-5-21-1-2-3-1003 on dc-selected.fixture.invalid: Fixture SID lookup failed.' -and
            $status.Items[1].Mismatch -ceq 'false' -and
            ($status.Items[1].Resolutions -join '|') -ceq 'Resolved|Resolved|Resolved|NotFound|LookupFailed|Resolved'
        ) 'The XML report did not retain its selected warning host, version check or SID resolution outcomes.'
    }
}

function Test-ReportTargetRejection([string]$Name, [string]$Field, [bool]$Strict = $false) {
    $actual = Invoke-ReportChild -Name $Name -Mode Caught -Strict $Strict
    $status = $actual.Status
    Assert-ReportFixture (@($status.TargetAttempts).Count -eq 0) 'Invalid target metadata reached a mount, policy reader or SID lookup.'
    $expectedReads = if ($Field -eq 'Server') {
        ''
    }
    else {
        'Server'
    }
    Assert-ReportFixture (($status.TargetReads -join '|') -ceq $expectedReads) 'Target validation reordered reads or read Domain after rejecting Server.'
    Assert-BaseObservation $actual '' 'Error' $true $false
    Assert-ReportFixture ($null -ne $status.Caught -and $status.Caught.IsTyped) 'Target validation did not preserve a native diagnostic.'
    if ($Strict) {
        Assert-ReportFixture (
            $status.Caught.Id -match '^PropertyNotFoundStrict(?:,|$)' -and
            $status.Caught.Type -like '*PropertyNotFoundException'
        ) 'A strict missing target lost its native property diagnostic.'
    }
    else {
        Assert-ReportFixture (
            $status.Caught.Message -ceq 'Invalid GPO server/domain'
        ) 'Target validation did not report the established server/domain error.'
    }
}

if ($Case -eq 'Regression') {
    $failures = [Collections.Generic.List[string]]::new()
    $count = 0
    foreach ($entry in @(
            [pscustomobject]@{ Fault = 'ReadAndCleanupFailure'; Only = 'ReadFailure'; Cleanup = '*UnauthorizedAccessException' }
            [pscustomobject]@{ Fault = 'NativeReadAndCleanupFailure'; Only = 'NativeReadFailure'; Cleanup = '*UnauthorizedAccessException' }
            [pscustomobject]@{ Fault = 'BadVersionAndCleanupFailure'; Only = 'BadVersion'; Cleanup = '*UnauthorizedAccessException' }
            [pscustomobject]@{ Fault = 'WarningsStopAndCleanupFailure'; Only = 'WarningsStop'; Cleanup = '*UnauthorizedAccessException' }
            [pscustomobject]@{ Fault = 'ReadAndNativeDriveNotFound'; Only = 'ReadFailure'; Cleanup = '*DriveNotFoundException' }
        )) {
        foreach ($mode in @('Caught', 'Uncaught')) {
            $count++
            try {
                Test-CompetingFailures $entry.Fault $entry.Only $mode ($entry.Fault -eq 'ReadAndCleanupFailure') $entry.Cleanup
            }
            catch {
                $failures.Add(('{0}/{1}: {2}' -f $entry.Fault, $mode, $_.Exception.Message))
            }
        }
    }
}
elseif ($Case -eq 'Targets') {
    $owned = 'Mount|Read|Unmount'
    $sidEvents = 'Sid:S-1-5-21-1-2-3-1001|Sid:S-1-5-21-1-2-3-1002|Sid:S-1-5-21-1-2-3-1003'
    $successes = @(
        New-Control 'TargetMountedObject' 'Uncaught' $owned 'Object'
        New-Control 'TargetUncredentialedObject' 'Uncaught' 'ReadUNC' 'Object'
        New-Control 'TargetMountedXml' 'Uncaught' ('Mount|Read|' + $sidEvents + '|Unmount') 'Warning|Xml'
        New-Control 'TargetUncredentialedXml' 'Uncaught' ('ReadUNC|' + $sidEvents) 'Warning|Xml'
        New-Control 'TargetGuid' 'Uncaught' ('Find|' + $owned) 'Object'
    )
    $failures = [Collections.Generic.List[string]]::new()
    $count = 0
    foreach ($spec in $successes) {
        $count++
        try {
            Test-ReportTargetSuccess $spec
        }
        catch {
            $failures.Add(('{0}: {1}' -f $spec.Name, $_.Exception.Message))
        }
    }
    foreach ($field in @('Server', 'Domain')) {
        $shapes = @('Null', 'Missing', 'Single', 'Multiple', 'Newline', 'Number')
        if ($field -eq 'Server') {
            $shapes += 'Syntax'
        }
        foreach ($shape in $shapes) {
            $name = 'TargetBad' + $field + $shape
            $count++
            try {
                Test-ReportTargetRejection $name $field
            }
            catch {
                $failures.Add(('{0}: {1}' -f $name, $_.Exception.Message))
            }
        }

        $name = 'TargetBad' + $field + 'Missing'
        $count++
        try {
            Test-ReportTargetRejection $name $field -Strict $true
        }
        catch {
            $failures.Add(('{0}/Strict: {1}' -f $name, $_.Exception.Message))
        }
    }
}
else {
    $owned = 'Mount|Read|Unmount'
    $controls = @(
        New-Control 'OwnedSuccess' 'Caught' $owned 'Object'
        New-Control 'OwnedSuccess' 'Uncaught' $owned 'Object' -Preferences $true
        New-Control 'MountFailure' 'Caught' 'Mount' 'Error' '*IOException'
        New-Control 'MountFailure' 'Uncaught' 'Mount' '' '*IOException'
        New-Control 'ReadFailure' 'Caught' $owned 'Error' '*InvalidDataException'
        New-Control 'ReadFailure' 'Uncaught' $owned '' '*InvalidDataException'
        New-Control 'NativeReadFailure' 'Uncaught' $owned '' '*InvalidDataException'
        New-Control 'BadVersion' 'Caught' $owned 'Error' '*FormatException'
        New-Control 'WarningsStop' 'Caught' $owned 'Warning|Error' '*ActionPreferenceStopException'
        New-Control 'CleanupFailure' 'Caught' $owned 'Object|Error' '*UnauthorizedAccessException' -ActionStop $true
        New-Control 'CleanupFailure' 'Uncaught' $owned 'Object' '*UnauthorizedAccessException'
        New-Control 'NativeCleanupFailure' 'Uncaught' $owned 'Object' '*WriteErrorException'
        New-Control 'ReadNonterminating' 'Caught' $owned 'Error|Object'
        New-Control 'ReadNonterminatingAndCleanupFailure' 'Caught' $owned 'Error|Object|Error' '*UnauthorizedAccessException'
        New-Control 'ReadNonterminatingAndCleanupFailure' 'Uncaught' $owned 'Error|Object' '*UnauthorizedAccessException'
        New-Control 'ReadNonterminatingAndCleanupFailure' 'Uncaught' $owned 'Error' -TakeFirst $true
        New-Control 'CleanupFailure' 'Uncaught' $owned 'Object' -TakeFirst $true
        New-Control 'MismatchedVersion' 'Uncaught' $owned 'Warning' -TakeFirst $true
        New-Control 'DefaultCredential' 'Uncaught' 'ReadUNC' 'Object'
        New-Control 'EmptyCredential' 'Caught' 'ReadUNC' 'Object'
        New-Control 'GuidPinned' 'Caught' ('Find|' + $owned) 'Object'
        New-Control 'GuidAmbiguous' 'Caught' 'Find' 'Error' '*RuntimeException'
        New-Control 'XmlWithSidOutcomes' 'Caught' 'Mount|Read|Sid:S-1-5-21-1-2-3-1001|Sid:S-1-5-21-1-2-3-1002|Sid:S-1-5-21-1-2-3-1003|Unmount' 'Warning|Warning|Xml'
        New-Control 'UnsignedVersion' 'Caught' $owned 'Object'
        New-Control 'AbsentStoredVersion' 'Caught' $owned 'Object'
        New-Control 'InvalidMetadata' 'Caught' '' 'Error' '*RuntimeException'
        New-Control 'NativeDriveNotFound' 'Caught' $owned 'Object|Error' '*DriveNotFoundException'
    )
    $failures = [Collections.Generic.List[string]]::new()
    $count = $controls.Count
    foreach ($control in $controls) {
        try {
            Test-ReportControl $control
        }
        catch {
            $failures.Add(('{0}/{1}: {2}' -f $control.Name, $control.Mode, $_.Exception.Message))
        }
    }
}
if ($failures.Count) {
    throw ('{0} of {1} GPO report drive cases failed. {2}' -f $failures.Count, $count, ($failures -join ' | '))
}
Write-Output ("PASS GPO report drive failure {0} {1}" -f $Case, $count)
