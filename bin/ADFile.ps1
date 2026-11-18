# Private package file I/O. Callers serialize and approve writes before invoking it.
function Get-ADAnalyzerJsonReadParameters {
    param([string]$Path)

    $parameters = @{
        LiteralPath = $Path
        Raw = $true
        ErrorAction = 'Stop'
    }
    if ($PSVersionTable.PSVersion.Major -le 5) {
        $parameters.Encoding = 'Byte'
    }
    else {
        $parameters.AsByteStream = $true
    }
    return $parameters
}

function Get-ADAnalyzerJsonReadDefaults {
    $defaults = $PSDefaultParameterValues
    if ($PSVersionTable.PSVersion.Major -le 5 -or $null -eq $defaults) {
        return $defaults
    }

    # The previous explicit UTF-8 parameter overrode ambient encoding defaults.
    # Keep Core's byte reader independent of them while preserving other defaults.
    $readDefaults = $null
    foreach ($key in $defaults.Keys) {
        $parts = $key -split ':', 2
        if ($parts.Count -eq 2 -and 'Encoding' -like $parts[1].Trim()) {
            if ($null -eq $readDefaults) {
                $readDefaults = [Management.Automation.DefaultParameterDictionary]::new($defaults)
            }
            $readDefaults.Remove($key)
        }
    }
    if ($null -ne $readDefaults) {
        return $readDefaults
    }
    return $defaults
}

function ConvertTo-ADAnalyzerJsonText {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][byte[]]$Bytes)

    process {
        if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
            return
        }
        # A CLR decoder remains valid when another Windows PowerShell runspace
        # dot-sources these file helpers and is later disposed.
        if (-not ('ADAnalyzer.JsonTextDecoder' -as [type])) {
            $null = Microsoft.PowerShell.Utility\Add-Type -Path (
                Join-Path $PSScriptRoot 'ADJsonTextDecoder.cs'
            ) -ErrorAction Stop
        }
        $text = [ADAnalyzer.JsonTextDecoder]::Decode($Bytes)
        if ($text.Length -gt 0) {
            return $text
        }
    }
}

function Resolve-ADAnalyzerFilePath {
    param([Parameter(Mandatory)][string]$Path)
    $provider = $null
    $drive = $null
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') {
        throw 'Report paths must use the FileSystem provider'
    }
    return $full
}

function Write-ADAnalyzerFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content

    )
    $full = Resolve-ADAnalyzerFilePath $Path
    $directory = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($directory)) {
        $null = [IO.Directory]::CreateDirectory($directory)
    }
    $temporary = Join-Path $directory ('.ad-analyzer-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = $null
    $writer = $null
    $failed = $false
    try {
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        # A BOM keeps non-ASCII snapshots readable with Windows PowerShell 5.1 defaults.
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($true))
        $writer.Write($Content)
        $writer.Flush()
        $stream.Flush($true)
        $writer.Dispose()
        $writer = $null
        $stream.Dispose()
        $stream = $null
        # NullString passes an actual null backup path through PowerShell's method binder.
        if ([IO.File]::Exists($full)) {
            [IO.File]::Replace($temporary, $full, [Management.Automation.Language.NullString]::Value)
        }
        else {
            [IO.File]::Move($temporary, $full)
        }
    }
    catch {
        $failed = $true
        throw
    }
    finally {
        foreach ($resource in @($writer, $stream)) {
            if ($null -ne $resource) {
                try {
                    $resource.Dispose()
                }
                catch {
                    if (-not $failed) {
                        throw
                    }
                }
            }
        }
        if ([IO.File]::Exists($temporary)) {
            try {
                [IO.File]::Delete($temporary)
            }
            catch {
                if (-not $failed) {
                    throw
                }
                Write-Warning 'Unable to remove a staged report file after a failed write.' -WarningAction Continue
            }
        }
    }
    return $full
}
