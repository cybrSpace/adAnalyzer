[CmdletBinding()]
param(
    [ValidateSet(
        'Utf8NoBom', 'Utf8Bom', 'Utf16LE', 'Utf16BE', 'Utf32LE', 'Utf32BE', 'SimulatedAnsi', 'Malformed', 'SharedWriter',
        'InvalidUtf8NoBom', 'InvalidUtf8Bom', 'InvalidUtf16LE', 'InvalidUtf16BE', 'InvalidUtf32LE', 'InvalidUtf32BE',
        'StandaloneProfile', 'Empty', 'BomOnly', 'ProviderDrive', 'AmbientEncoding'
    )]
    [string]$Case = 'SimulatedAnsi'
)

$ErrorActionPreference = 'Stop'
$script:Checks = 0
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$global:JsonEncodingFixture_ModelAnsi = $Case -eq 'SimulatedAnsi'
$global:JsonEncodingFixture_SamlCalls = [Collections.Generic.List[object]]::new()

function Assert-Encoding($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Content {
    [CmdletBinding()]
    param(
        [string]$LiteralPath,
        [switch]$Raw,
        $Encoding,
        [switch]$AsByteStream
    )

    if ($global:JsonEncodingFixture_ModelAnsi -and
        -not $PSBoundParameters.ContainsKey('Encoding') -and -not $AsByteStream) {
        return [IO.File]::ReadAllText($LiteralPath, [Text.Encoding]::GetEncoding(1252))
    }
    Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
}

function Invoke-CapturedSamlConfiguration {
    [CmdletBinding()]
    param($Url, $Config, $Credential, $OutputPath)

    $captured = [pscustomobject]@{
        Url = $Url
        Config = $Config
    }
    $global:JsonEncodingFixture_SamlCalls.Add($captured)
    return $captured
}

function Get-Credential {
    throw 'JSON decoding must not prompt for credentials.'
}

function Invoke-RestMethod {
    throw 'JSON decoding must not issue HTTP requests.'
}

function Invoke-WebRequest {
    throw 'JSON decoding must not issue HTTP requests.'
}

Set-Alias Invoke-SAMLResponseTimeTest Invoke-CapturedSamlConfiguration -Scope Script
if ($Case -eq 'StandaloneProfile') {
    . (Join-Path $repositoryRoot 'bin/ADProfile.ps1')
}
else {
    . (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
}

$replacement = [string][char]0xFFFD
$supplementary = [char]::ConvertFromUtf32(0x1F642)
$label = 'Caf' + [char]0x00E9 + ' ' + [char]0x6771 + [char]0x4EAC + ' ' + [char]0x03A9 + ' ' + $replacement + $supplementary
$invalidEncoding = $Case.StartsWith('Invalid', [StringComparison]::Ordinal)
$emptyDocument = $Case -in 'Empty', 'BomOnly'
$drive = $null
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-json-' + [guid]::NewGuid().ToString('N') + ' [' + $label + ']')
$null = [IO.Directory]::CreateDirectory($temporary)
$profilePath = Join-Path $temporary 'profile.json'
$documentPath = Join-Path $temporary 'assessment.json'
$configPath = Join-Path $temporary 'saml.json'

$profile = @{
    Name = $label
    RegistryRules = @(@{
            Hive = 'HKLM'
            Key = 'Software\Fixture'
            ValueName = 'Label'
            Type = 1
            Expected = $label
        })
}
$document = [pscustomobject]@{
    SchemaVersion = 1
    Target = 'example.invalid'
    Context = [pscustomobject]@{
        SearchBase = ('OU=' + $label + ',DC=example,DC=invalid')
    }
    Checks = @([pscustomobject]@{
            RuleId = 'FIXTURE.UNICODE'
            Target = ('CN=' + $label + ',DC=example,DC=invalid')
            Status = 'Pass'
            Severity = 'Information'
            Observed = $label
            Expected = $label
            Evidence = [pscustomobject]@{
                Label = $label
            }
            Applicability = 'Configured'
        })
}
$config = @{
    Url = @{
        auth = ('https://fixture.invalid/' + $label + '/auth')
        logn = 'https://fixture.invalid/login'
        saml = 'https://fixture.invalid/saml'
        appl = 'https://fixture.invalid/acs'
        data = ('https://fixture.invalid/data?label=' + $label)
    }
    Config = @{
        limit = 1
        wait = 0
    }
}

$encodingCase = if ($invalidEncoding) {
    $Case.Substring(7)
}
elseif ($Case -eq 'BomOnly') {
    'Utf32LE'
}
else {
    $Case
}
$encoding = switch ($encodingCase) {
    'Utf8Bom' {
        [Text.UTF8Encoding]::new($true)
    }
    'Utf16LE' {
        [Text.UnicodeEncoding]::new($false, $true)
    }
    'Utf16BE' {
        [Text.UnicodeEncoding]::new($true, $true)
    }
    'Utf32LE' {
        [Text.UTF32Encoding]::new($false, $true)
    }
    'Utf32BE' {
        [Text.UTF32Encoding]::new($true, $true)
    }
    default {
        [Text.UTF8Encoding]::new($false)
    }
}

$badBytes = switch ($encodingCase) {
    'Utf16LE' {
        [byte[]]@(0x00, 0xD8)
    }
    'Utf16BE' {
        [byte[]]@(0xD8, 0x00)
    }
    'Utf32LE' {
        [byte[]]@(0x00, 0x00, 0x11, 0x00)
    }
    'Utf32BE' {
        [byte[]]@(0x00, 0x11, 0x00, 0x00)
    }
    default {
        [byte[]]@(0xC3)
    }
}
$readers = [ordered]@{
    Profile = {
        Import-ADAnalyzerProfile -Path $profilePath
    }
    DirectProfile = {
        ([ADAnalyzerProfile]::Load($profilePath)).ToHashtable()
    }
    Document = {
        Read-ADAnalyzerOperationDocument -InputObject $documentPath
    }
    Compare = {
        Compare-ADAnalyzerAssessment -Reference $document -Difference $documentPath
    }
    Saml = {
        & (Join-Path $repositoryRoot 'etc/Test-SAMLProtectedResponseTimes.ps1') -ConfigPath $configPath
    }
}

function Invoke-EncodingReader {
    [CmdletBinding()]
    param([scriptblock]$Reader)
    & $Reader
}

try {
    $fingerprints = @{}
    foreach ($pair in @(
            @($profilePath, $profile),
            @($documentPath, $document),
            @($configPath, $config)
        )) {
        $json = if ($Case -eq 'Malformed') {
            '{'
        }
        elseif ($emptyDocument) {
            ''
        }
        else {
            $serialized = ConvertTo-Json -InputObject $pair[1] -Depth 30 -Compress
            $serialized = $serialized -replace '\ufffd', $replacement -replace '\ud83d\ude42', $supplementary
            Assert-Encoding ($serialized.Contains($replacement) -and $serialized.Contains($supplementary)) 'The JSON fixture must contain both literal Unicode values.'
            $serialized
        }
        if ($Case -eq 'SharedWriter') {
            $null = Write-ADAnalyzerFile -Path $pair[0] -Content $json
        }
        else {
            if ($invalidEncoding) {
                # Keep surrounding JSON valid and alter only a harmless string value.
                $field = if ($pair[0] -eq $documentPath) {
                    '"Label":"' + $label + '"'
                }
                else {
                    $label
                }
                $offset = $json.IndexOf($field, [StringComparison]::Ordinal)
                Assert-Encoding ($offset -ge 0) 'The inert malformed-byte location is missing.'
                $offset += $field.IndexOf($label, [StringComparison]::Ordinal)
                $before = $encoding.GetBytes($json.Substring(0, $offset))
                $after = $encoding.GetBytes($json.Substring($offset + $label.Length))
                [byte[]]$bytes = @($encoding.GetPreamble()) + @($before) + @($badBytes) + @($after)
            }
            else {
                [byte[]]$bytes = @($encoding.GetPreamble()) + @($encoding.GetBytes($json))
            }
            [IO.File]::WriteAllBytes($pair[0], $bytes)
        }
        $fingerprints[$pair[0]] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pair[0]))
    }
    if ($Case -eq 'ProviderDrive') {
        $drive = 'json' + [guid]::NewGuid().ToString('N').Substring(0, 12)
        $null = New-PSDrive -Name $drive -PSProvider FileSystem -Root $temporary -Scope Script -ErrorAction Stop
        $profilePath = $drive + ':/profile.json'
        $documentPath = $drive + ':/assessment.json'
        $configPath = $drive + ':/saml.json'
    }

    Write-Output ('Runtime JSON encoding: ' + $PSVersionTable.PSVersion +
        '; edition=' + $PSVersionTable.PSEdition +
        '; defaultCodePage=' + [Text.Encoding]::Default.CodePage)

    if ($Case -eq 'Utf8NoBom') {
        $oldText = Microsoft.PowerShell.Management\Get-Content -LiteralPath $profilePath -Raw -ErrorAction Stop
        $oldName = ($oldText | ConvertFrom-Json).Name
        if ($PSVersionTable.PSVersion.Major -le 5 -and [Text.Encoding]::Default.CodePage -ne 65001) {
            Assert-Encoding ($oldName -cne $label) 'Native old-default control did not demonstrate the documented ANSI decoding difference.'
            Write-Output 'PASS native old-default decoding control differs from required UTF8 Unicode'
        }
        else {
            Assert-Encoding ($oldName -ceq $label) 'Native default decoding control unexpectedly changed UTF8 text.'
        }
    }

    if ($invalidEncoding -or $Case -eq 'Malformed') {
        $unexpected = [Collections.Generic.List[string]]::new()
        foreach ($reader in $readers.Keys) {
            $rows = [Collections.Generic.List[object]]::new()
            $captured = @()
            $failure = $null
            $Error.Clear()
            try {
                Invoke-EncodingReader -Reader $readers[$reader] -ErrorVariable +captured | ForEach-Object {
                    $rows.Add($_)
                }
            }
            catch {
                $failure = $_
            }
            if ($null -eq $failure -or $rows.Count -ne 0) {
                $unexpected.Add(('{0} returned {1} result(s)' -f $reader, $rows.Count))
                continue
            }
            if ($invalidEncoding) {
                $cause = $failure.Exception.GetBaseException()
                Assert-Encoding ($cause -is [IO.InvalidDataException]) ('Expected an encoding error before parsing for ' + $reader)
                foreach ($diagnostic in @($captured) + @($Error)) {
                    Assert-Encoding ([string]$diagnostic -notmatch 'DecoderFallbackException|\[[0-9a-fA-F]{2}\]') ('An encoding diagnostic exposed raw bytes for ' + $reader)
                }
            }
            else {
                Assert-Encoding ($failure.FullyQualifiedErrorId -like '*ConvertFromJsonCommand*') ('Malformed JSON lost its native parser diagnostic for ' + $reader)
            }
            $script:Checks++
        }
    }
    elseif ($emptyDocument) {
        $expectedName = (Get-ADAnalyzerDefaultProfile).Name
        foreach ($reader in @('Profile', 'DirectProfile')) {
            $loaded = Invoke-EncodingReader -Reader $readers[$reader]
            Assert-Encoding ($loaded.Name -ceq $expectedName) ('Empty input changed default profile behavior for ' + $reader)
            $script:Checks++
        }
        foreach ($reader in @('Document', 'Compare')) {
            $failure = $null
            try {
                $null = Invoke-EncodingReader -Reader $readers[$reader]
            }
            catch {
                $failure = $_
            }
            Assert-Encoding ($null -ne $failure -and $failure.Exception.Message -ceq 'Assessment must be a structured object or JSON file') ('Empty input changed the native document failure for ' + $reader)
            $script:Checks++
        }
        $samlResult = @(Invoke-EncodingReader -Reader $readers.Saml)
        Assert-Encoding ($samlResult.Count -eq 1 -and $global:JsonEncodingFixture_SamlCalls.Count -eq 1 -and
            $samlResult[0].Url.Count -eq 0 -and $samlResult[0].Config.Count -eq 0) 'Empty input changed SAML configuration dispatch.'
        $script:Checks++
    }
    else {
        $warnings = @()
        $savedDefaults = $PSDefaultParameterValues
        $savedWarningPreference = $WarningPreference
        if ($Case -eq 'AmbientEncoding') {
            $PSDefaultParameterValues = @{
                'Get-*:Enc*' = 'ascii'
            }
            $WarningPreference = 'Stop'
        }
        try {
            $loadedProfile = Invoke-EncodingReader -Reader $readers.Profile -WarningVariable +warnings
            Assert-Encoding ($loadedProfile.Name -ceq $label) 'Profile JSON Unicode name was corrupted.'
            Assert-Encoding ($loadedProfile.RegistryRules[0].Expected -ceq $label) 'Profile JSON custom expected value was corrupted.'
            $script:Checks++
            $directProfile = Invoke-EncodingReader -Reader $readers.DirectProfile -WarningVariable +warnings
            Assert-Encoding ($directProfile.Name -ceq $label -and $directProfile.RegistryRules[0].Expected -ceq $label) 'Direct profile JSON output changed.'
            $script:Checks++

            if ($Case -ne 'StandaloneProfile') {
                $loadedDocument = Invoke-EncodingReader -Reader $readers.Document -WarningVariable +warnings
                Assert-Encoding ($loadedDocument.Checks[0].Target -ceq $document.Checks[0].Target) 'Document JSON target was corrupted.'
                Assert-Encoding ($loadedDocument.Checks[0].Evidence.Label -ceq $label) 'Document JSON evidence was corrupted.'
                $script:Checks++
                $comparison = Invoke-EncodingReader -Reader $readers.Compare -WarningVariable +warnings
                Assert-Encoding ($comparison.Changes.Count -eq 1 -and $comparison.Summary.Unchanged -eq 1 -and
                    $comparison.Summary.New -eq 0 -and $comparison.Summary.Changed -eq 0 -and
                    $comparison.Summary.Resolved -eq 0) 'JSON file decoding produced false snapshot drift.'
                $script:Checks++

                $samlResult = @(Invoke-EncodingReader -Reader $readers.Saml -WarningVariable +warnings)
                Assert-Encoding ($samlResult.Count -eq 1 -and $global:JsonEncodingFixture_SamlCalls.Count -eq 1) 'Complete SAML CLI did not dispatch exactly one decoded configuration.'
                Assert-Encoding ($samlResult[0].Url.auth -ceq $config.Url.auth -and
                    $samlResult[0].Url.data -ceq $config.Url.data) 'SAML JSON URL Unicode was corrupted.'
                $script:Checks++
            }
            if ($Case -eq 'AmbientEncoding') {
                Assert-Encoding ($warnings.Count -eq 0 -and $PSDefaultParameterValues['Get-*:Enc*'] -ceq 'ascii') 'Reading bytes emitted a warning or changed the caller defaults.'
            }
        }
        finally {
            $PSDefaultParameterValues = $savedDefaults
            $WarningPreference = $savedWarningPreference
        }

        if ($Case -eq 'SharedWriter') {
            $written = [IO.File]::ReadAllBytes($documentPath)
            Assert-Encoding ($written.Length -ge 3 -and $written[0] -eq 0xEF -and $written[1] -eq 0xBB -and $written[2] -eq 0xBF) 'Shared writer BOM safeguard changed.'
            $native = Microsoft.PowerShell.Management\Get-Content -LiteralPath $documentPath -Raw -ErrorAction Stop | ConvertFrom-Json
            Assert-Encoding ($native.Checks[0].Evidence.Label -ceq $label) 'Shared-writer default-reader control lost Unicode.'
        }
    }

    foreach ($path in $fingerprints.Keys) {
        Assert-Encoding ($fingerprints[$path] -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) 'Reading JSON modified source bytes.'
    }
    if ($invalidEncoding -or $Case -eq 'Malformed') {
        Assert-Encoding ($unexpected.Count -eq 0 -and $global:JsonEncodingFixture_SamlCalls.Count -eq 0) ('Invalid input escaped a reader or reached SAML dispatch: ' + ($unexpected -join ', '))
    }
}
finally {
    if ($drive) {
        Remove-PSDrive -Name $drive -Scope Script -Force -ErrorAction Stop
    }
    if ([IO.Directory]::Exists($temporary)) {
        [IO.Directory]::Delete($temporary, $true)
    }
}

Write-Output ('PASS JSON input encoding {0} {1}' -f $Case, $script:Checks)
