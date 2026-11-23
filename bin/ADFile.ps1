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
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [switch]$RequireExisting,
        [switch]$CreateOnly

    )
    if ($RequireExisting -and $CreateOnly) {
        throw [ArgumentException]::new('CreateOnly requires a new destination.')
    }
    $full = Resolve-ADAnalyzerFilePath $Path
    if ($CreateOnly -and [IO.File]::Exists($full)) {
        throw [IO.IOException]::new('The report destination already exists.')
    }
    $directory = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($directory)) {
        if ($RequireExisting) {
            throw 'Journal file does not exist'
        }
        $null = [IO.Directory]::CreateDirectory($directory)
    }
    $temporary = Join-Path $directory ('.ad-analyzer-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = $null
    $writer = $null
    $ownsTemporary = $false
    $failed = $false
    try {
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $ownsTemporary = $true
        # A BOM keeps non-ASCII snapshots readable with Windows PowerShell 5.1 defaults.
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($true))
        $writer.Write($Content)
        $writer.Flush()
        $stream.Flush($true)
        $writer.Dispose()
        $writer = $null
        $stream.Dispose()
        $stream = $null
        if ($CreateOnly) {
            try {
                [IO.File]::Move($temporary, $full)
            }
            catch [IO.IOException] {
                $cause = $_.Exception.GetBaseException()
                # Windows reports file-exists HRESULTs. Unix .NET can expose EEXIST directly.
                $exists = $cause.HResult -in 0x80070050, 0x800700B7 -or
                    ([IO.Path]::DirectorySeparatorChar -eq '/' -and $cause.HResult -eq 17)
                if ($exists) {
                    throw [IO.IOException]::new('The report destination already exists.', $cause)
                }
                throw
            }
        }
        elseif ($RequireExisting -or [IO.File]::Exists($full)) {
            # NullString passes an actual null backup path through PowerShell's method binder.
            [IO.File]::Replace($temporary, $full, [Management.Automation.Language.NullString]::Value)
        }
        else {
            [IO.File]::Move($temporary, $full)
        }
        $ownsTemporary = $false
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
        if ($ownsTemporary -and [IO.File]::Exists($temporary)) {
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
