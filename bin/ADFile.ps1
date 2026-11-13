# Private package file I/O. Callers serialize and approve writes before invoking it.
function Resolve-ADAnalyzerFilePath {
    param([Parameter(Mandatory)][string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if($provider.Name -ne 'FileSystem'){throw 'Report paths must use the FileSystem provider'}
    return $full
}
function Write-ADAnalyzerFile {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $full=Resolve-ADAnalyzerFilePath $Path;$directory=[IO.Path]::GetDirectoryName($full)
    if(-not [IO.Directory]::Exists($directory)){$null=[IO.Directory]::CreateDirectory($directory)}
    $temporary=Join-Path $directory ('.ad-analyzer-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $stream=$null;$writer=$null;$failed=$false
    try{
        $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        # A BOM keeps non-ASCII snapshots readable with Windows PowerShell 5.1 defaults.
        $writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($true))
        $writer.Write($Content);$writer.Flush();$stream.Flush($true)
        $writer.Dispose();$writer=$null;$stream.Dispose();$stream=$null
        # NullString passes an actual null backup path through PowerShell's method binder.
        if([IO.File]::Exists($full)){[IO.File]::Replace($temporary,$full,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($temporary,$full)}
    }catch{$failed=$true;throw}
    finally{
        foreach($resource in @($writer,$stream)){
            if($null -ne $resource){try{$resource.Dispose()}catch{if(-not $failed){throw}}}
        }
        if([IO.File]::Exists($temporary)){
            try{[IO.File]::Delete($temporary)}catch{if(-not $failed){throw};Write-Warning 'Unable to remove a staged report file after a failed write.' -WarningAction Continue}
        }
    }
    return $full
}
