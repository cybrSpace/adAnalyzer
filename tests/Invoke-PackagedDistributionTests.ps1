[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [ValidatePattern('^[0-9a-f]{40}$')][string]$SourceTree
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).ProviderPath
$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$engine = (Get-Process -Id $PID).Path
$fixture = Join-Path $PSScriptRoot 'PackageSmokeFixture.ps1'
$packageRoots = @('ADEnvironment.psd1', 'README.md', 'bin', 'lib', 'profiles')

function Invoke-PackageGit {
    param([string[]]$Arguments)

    # Package bytes must be independent of the host checkout line-ending setting.
    $result = & $git -c core.autocrlf=false -C $RepositoryRoot @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ('Package Git command failed (' + $Arguments[0] + '), exit code ' + $LASTEXITCODE)
    }
    $result
}

if (-not $SourceTree) {
    $SourceTree = Invoke-PackageGit @('rev-parse', 'HEAD^{tree}')
}
$expectedBlobs = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($line in (Invoke-PackageGit (@('ls-tree', '-r', '--full-tree', $SourceTree, '--') + $packageRoots))) {
    if ($line -cnotmatch '^100(?:644|755) blob ([0-9a-f]{40})\t([^"\\\t]+)$') {
        throw 'The package must contain ordinary, unambiguous tracked file paths.'
    }
    $expectedBlobs.Add($Matches[2], $Matches[1])
}
[string[]]$expectedPaths = @($expectedBlobs.Keys)
[Array]::Sort($expectedPaths, [StringComparer]::Ordinal)

function Get-VerifiedPackageInventory {
    param([string]$PackageRoot)

    $files = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    foreach ($file in (Get-ChildItem -LiteralPath $PackageRoot -File -Recurse -Force)) {
        $relativePath = $file.FullName.Substring($PackageRoot.Length + 1).Replace('\', '/')
        $files.Add($relativePath, $file.FullName)
    }
    if ($files.Count -ne $expectedPaths.Count) {
        throw 'The package file count differs from the selected Git tree.'
    }

    $records = foreach ($path in $expectedPaths) {
        if (-not $files.ContainsKey($path)) {
            throw ('Missing package file: ' + $path)
        }
        $file = $files[$path]
        $blob = Invoke-PackageGit @('hash-object', '--no-filters', '--', $file)
        if ($blob -cne $expectedBlobs[$path]) {
            throw ('Package bytes differ from Git: ' + $path)
        }
        $digest = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        $path + [char]9 + $digest
    }
    $records -join [char]10
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('ad package ' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryRoot)
$windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$cases = @('Class')
if ($windows) {
    $cases += 'Command'
}
$encoding = [Text.UTF8Encoding]::new($false)
try {
    $inventoryHashes = foreach ($case in @('Class', 'Command')) {
        $zip = Join-Path $temporaryRoot ($case + '.zip')
        $package = Join-Path $temporaryRoot ($case + ' distribution')
        $inventoryFile = Join-Path $temporaryRoot ($case + '.sha256')
        $null = Invoke-PackageGit (@('archive', '--format=zip', ('--output=' + $zip), $SourceTree, '--') + $packageRoots)
        Expand-Archive -LiteralPath $zip -DestinationPath $package

        $inventory = Get-VerifiedPackageInventory -PackageRoot $package
        [IO.File]::WriteAllText($inventoryFile, $inventory + [char]10, $encoding)
        (Get-FileHash -LiteralPath $inventoryFile -Algorithm SHA256).Hash

        if ($case -in $cases) {
            $output = Join-Path $temporaryRoot ($case + ' output')
            [void][IO.Directory]::CreateDirectory($output)
            $childArguments = @(
                '-NoLogo'
                '-NoProfile'
                '-NonInteractive'
                '-File'
                $fixture
                '-PackageRoot'
                $package
                '-OutputRoot'
                $output
                '-Case'
                $case
            )
            Push-Location -LiteralPath $temporaryRoot
            try {
                $childOutput = @(& $engine @childArguments)
                $childExit = $LASTEXITCODE
            }
            finally {
                Pop-Location
            }

            $childOutput | Write-Host
            $marker = 'PASS unpacked package offline report and plan via ' + $case
            if ($childExit -ne 0 -or @($childOutput | Where-Object { $_ -ceq $marker }).Count -ne 1) {
                throw ('The unpacked ' + $case + ' smoke process did not pass.')
            }
            if ((Get-VerifiedPackageInventory -PackageRoot $package) -cne $inventory) {
                throw ('The unpacked ' + $case + ' smoke process changed package bytes.')
            }
        }
    }

    if ($inventoryHashes.Count -ne 2 -or $inventoryHashes[0] -cne $inventoryHashes[1]) {
        throw 'Independent archives did not produce identical file inventories.'
    }
    Write-Host ('PACKAGE_TREE=' + $SourceTree)
    Write-Host ('PACKAGE_FILES=' + $expectedPaths.Count)
    Write-Host ('PACKAGE_INVENTORY_SHA256=' + $inventoryHashes[0])
    Write-Host 'PASS unpacked package inventory matches tracked Git bytes'
    if (-not $windows) {
        Write-Host 'The native manifest smoke case requires Windows.'
    }
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
}
