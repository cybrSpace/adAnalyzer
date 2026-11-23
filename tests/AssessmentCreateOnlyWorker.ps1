[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$Coordination,
    [Parameter(Mandatory)][ValidateSet('Native', 'Direct')][string]$Role
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
$stageDirectory = [IO.Path]::GetDirectoryName($Destination)
$readyPath = [IO.Path]::Combine($Coordination, $Role + '.ready')
$releasePath = [IO.Path]::Combine($Coordination, $Role + '.release')

# Pause the real writer at its staging-path selection, after any destination preflight.
function Join-Path {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string[]]$Path,
        [Parameter(Mandatory, Position = 1)][string]$ChildPath
    )

    $resolved = Microsoft.PowerShell.Management\Join-Path @PSBoundParameters
    if ($Path.Count -eq 1 -and $Path[0] -eq $stageDirectory -and $ChildPath -like '.ad-analyzer-*.tmp') {
        if ([IO.File]::Exists($Destination) -or [IO.File]::Exists($readyPath)) {
            throw 'The fixture did not reach staging exactly once with an initially absent destination.'
        }
        [IO.File]::WriteAllText($readyPath, $resolved)
        $watch = [Diagnostics.Stopwatch]::StartNew()
        while (-not [IO.File]::Exists($releasePath)) {
            if ($watch.Elapsed.TotalSeconds -gt 45) {
                throw 'Timed out waiting for the create-only fixture release.'
            }
            Start-Sleep -Milliseconds 25
        }
    }
    return $resolved
}

$document = [pscustomobject]@{
    SchemaVersion = 1
    Target = "$Role.example.invalid"
    Checks = @()
    Findings = @()
    Payload = "$Role|" * 1024
}
try {
    $output = if ($Role -eq 'Native') {
        $parameters = @{
            Assessment = $document
            Path = $Destination
            Format = 'Json'
            CreateOnly = $true
            Confirm = $false
            ErrorAction = 'Stop'
        }
        Export-ADAnalyzerAssessment @parameters
    }
    else {
        [ADAnalyzerAssessmentReport]::new().WriteNew($document, $Destination)
    }
    if (@($output).Count -ne 1 -or [string]$output -cne $Destination) {
        throw 'The create-only writer returned an unexpected publication receipt.'
    }
    Write-Output 'Published'
}
catch {
    for ($cause = $_.Exception; $null -ne $cause; $cause = $cause.InnerException) {
        if ($cause.Message -ceq 'The report destination already exists.') {
            Write-Output $cause.Message
            exit 4
        }
    }
    throw
}
