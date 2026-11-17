[CmdletBinding()]
param(
    [ValidateSet('Utf8NoBom', 'Utf8Bom', 'Utf16LE', 'Utf16BE', 'Utf32LE', 'Utf32BE', 'SimulatedAnsi', 'Malformed', 'SharedWriter')]
    [string]$Case = 'SimulatedAnsi'
)

$ErrorActionPreference = 'Stop'
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
        $Encoding
    )

    if ($global:JsonEncodingFixture_ModelAnsi -and
        -not $PSBoundParameters.ContainsKey('Encoding')) {
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
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')

$label = 'Caf' + [char]0x00E9 + ' ' + [char]0x6771 + [char]0x4EAC + ' ' + [char]0x03A9
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

$encoding = switch ($Case) {
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
        else {
            ConvertTo-Json -InputObject $pair[1] -Depth 30 -Compress
        }
        if ($Case -eq 'SharedWriter') {
            $null = Write-ADAnalyzerFile -Path $pair[0] -Content $json
        }
        else {
            [byte[]]$bytes = @($encoding.GetPreamble()) + @($encoding.GetBytes($json))
            [IO.File]::WriteAllBytes($pair[0], $bytes)
        }
        $fingerprints[$pair[0]] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pair[0]))
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

    if ($Case -eq 'Malformed') {
        $failures = 0
        foreach ($reader in @('Profile', 'Document', 'Saml')) {
            $rows = [Collections.Generic.List[object]]::new()
            try {
                & {
                    switch ($reader) {
                    'Profile' {
                        Import-ADAnalyzerProfile -Path $profilePath
                    }
                    'Document' {
                        Read-ADAnalyzerOperationDocument -InputObject $documentPath
                    }
                    'Saml' {
                        & (Join-Path $repositoryRoot 'etc/Test-SAMLProtectedResponseTimes.ps1') -ConfigPath $configPath
                    }
                    }
                } | ForEach-Object {
                    $rows.Add($_)
                }
            }
            catch {
                $failures++
            }
            Assert-Encoding ($rows.Count -eq 0) 'Malformed JSON emitted a partial result.'
        }
        Assert-Encoding ($failures -eq 3 -and $global:JsonEncodingFixture_SamlCalls.Count -eq 0) 'Malformed JSON escaped a loader or reached SAML dispatch.'
    }
    else {
        $loadedProfile = Import-ADAnalyzerProfile -Path $profilePath
        Assert-Encoding ($loadedProfile.Name -ceq $label) 'Profile JSON Unicode name was corrupted.'
        Assert-Encoding ($loadedProfile.RegistryRules[0].Expected -ceq $label) 'Profile JSON custom expected value was corrupted.'

        $loadedDocument = Read-ADAnalyzerOperationDocument -InputObject $documentPath
        Assert-Encoding ($loadedDocument.Checks[0].Target -ceq $document.Checks[0].Target) 'Document JSON target was corrupted.'
        Assert-Encoding ($loadedDocument.Checks[0].Evidence.Label -ceq $label) 'Document JSON evidence was corrupted.'
        $comparison = Compare-ADAnalyzerAssessment -Reference $document -Difference $documentPath
        Assert-Encoding ($comparison.Changes.Count -eq 1 -and $comparison.Summary.Unchanged -eq 1 -and
            $comparison.Summary.New -eq 0 -and $comparison.Summary.Changed -eq 0 -and
            $comparison.Summary.Resolved -eq 0) 'JSON file decoding produced false snapshot drift.'

        $samlResult = @(& (Join-Path $repositoryRoot 'etc/Test-SAMLProtectedResponseTimes.ps1') -ConfigPath $configPath)
        Assert-Encoding ($samlResult.Count -eq 1 -and $global:JsonEncodingFixture_SamlCalls.Count -eq 1) 'Complete SAML CLI did not dispatch exactly one decoded configuration.'
        Assert-Encoding ($samlResult[0].Url.auth -ceq $config.Url.auth -and
            $samlResult[0].Url.data -ceq $config.Url.data) 'SAML JSON URL Unicode was corrupted.'

        if ($Case -eq 'SharedWriter') {
            $written = [IO.File]::ReadAllBytes($documentPath)
            Assert-Encoding ($written.Length -ge 3 -and $written[0] -eq 0xEF -and
                $written[1] -eq 0xBB -and $written[2] -eq 0xBF) 'Shared writer BOM safeguard changed.'
            $native = Microsoft.PowerShell.Management\Get-Content -LiteralPath $documentPath -Raw -ErrorAction Stop | ConvertFrom-Json
            Assert-Encoding ($native.Checks[0].Evidence.Label -ceq $label) 'Shared-writer default-reader control lost Unicode.'
        }
    }

    foreach ($path in $fingerprints.Keys) {
        Assert-Encoding ($fingerprints[$path] -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) 'Reading JSON modified source bytes.'
    }
}
finally {
    if ([IO.Directory]::Exists($temporary)) {
        [IO.Directory]::Delete($temporary, $true)
    }
}

Write-Output ('PASS JSON input encoding ' + $Case)
