[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [string]$WorkingDirectory,
    [ValidateSet('Success', 'Refused', 'Throw', 'Nonterminating', 'Malformed', 'Selection',
        'Inert', 'Validation', 'Class', 'Csv', 'ExportFailures', 'WhatIf', 'Cli')]
    [string]$Mode = 'Nonterminating'
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
if (-not $WorkingDirectory) {
    $WorkingDirectory = Join-Path ([IO.Path]::GetTempPath()) ('ad-connection-fixture-' + [guid]::NewGuid().ToString('N'))
}
$null = [IO.Directory]::CreateDirectory($WorkingDirectory)
$path = Join-Path $RepositoryRoot 'etc/Test-ServerConnection.ps1'
$global:ConnectionCsvFixture = @{
    Calls = [Collections.Generic.List[object]]::new()
    Outcome = 'Success'
    ConversionFault = ''
}
$columns = 'ComputerName,RemoteAddress,RemotePort,tcpTest,result'

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw "Expected [$Expected], got [$Actual]"
    }
}

function Assert-Fails([scriptblock]$Body) {
    $received = [Collections.Generic.List[object]]::new()
    $caught = $false
    try {
        & $Body | ForEach-Object { $received.Add($_) }
    }
    catch {
        $caught = $true
    }
    Assert-Equal $true $caught
    Assert-Equal 0 $received.Count
}

function Test-NetConnection {
    [CmdletBinding()]
    param(
        $ComputerName,
        $Port,
        $InformationLevel

    )
    $call = @{}
    foreach ($key in $PSBoundParameters.Keys) {
        $call[$key] = $PSBoundParameters[$key]
    }
    $global:ConnectionCsvFixture.Calls.Add($call)
    if ($global:ConnectionCsvFixture.Calls.Count -gt 100) {
        throw 'Fixture probe bound exceeded'
    }
    switch ($global:ConnectionCsvFixture.Outcome) {
        'Throw' {
            throw 'Fixture probe failure'
        }
        'Nonterminating' {
            Write-Error 'Fixture nonterminating probe failure'
        }
        'Empty' {
            return
        }
        'Malformed' {
            return [pscustomobject]@{
                TcpTestSucceeded = 'False'
            }
        }
        'Multiple' {
            [pscustomobject]@{
                TcpTestSucceeded = $true
            }
        }
    }
    [pscustomobject]@{
        ComputerName = $ComputerName
        RemoteAddress = '192.0.2.10'
        RemotePort = $Port
        TcpTestSucceeded = $global:ConnectionCsvFixture.Outcome -ne 'Refused'
    }
}

function Assert-Row($Row, [string]$Computer = 'srv1', [int]$Port = 445, [string]$Outcome = 'Success') {
    Assert-Equal $columns ($Row.PSObject.Properties.Name -join ',')
    Assert-Equal $Computer $Row.ComputerName
    Assert-Equal $Port $Row.RemotePort
    if ($Outcome -in @('Success', 'Refused')) {
        Assert-Equal '192.0.2.10' $Row.RemoteAddress
        Assert-Equal $true $Row.result
        Assert-Equal ($Outcome -eq 'Success') $Row.tcpTest
    }
    else {
        Assert-Equal $null $Row.RemoteAddress
        Assert-Equal $null $Row.tcpTest
        Assert-Equal $false $Row.result
    }
}

try {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-Equal 0 $errors.Count
    $function = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Test-ServerConnection'
        }, $true)
    if ($null -eq $function) {
        # Safely exercise the original script with only the counted synthetic probe.
        $global:ConnectionCsvFixture.Outcome = 'Nonterminating'
        $ErrorActionPreference = 'Continue'
        $null = [IO.Directory]::CreateDirectory((Join-Path $WorkingDirectory 'tmp/expport'))
        $location = Get-Location
        try {
            Set-Location -LiteralPath $WorkingDirectory
            & $path | Out-Null
        }
        finally {
            Set-Location -LiteralPath $location.Path
        }
        $files = @(Get-ChildItem -LiteralPath (Join-Path $WorkingDirectory 'tmp/expport') -Filter '*.csv')
        Assert-Equal 1 $files.Count
        $rows = @(Import-Csv -LiteralPath $files[0].FullName)
        Assert-Equal 'False' $rows[0].result
        throw 'The explicit connection interface is missing'
    }

    . $path
    Assert-Equal 0 $global:ConnectionCsvFixture.Calls.Count
    $outputPath = Join-Path $WorkingDirectory 'connection.csv'

    switch ($Mode) {
        { $_ -in @('Success', 'Refused', 'Throw', 'Nonterminating') } {
            foreach ($preference in @('Continue', 'Stop')) {
                $ErrorActionPreference = $preference
                $global:ConnectionCsvFixture.Outcome = $Mode
                $rows = @(Test-ServerConnection -ComputerName 'srv1' -OutputPath $outputPath)
                Assert-Equal 1 $rows.Count
                Assert-Row $rows[0] -Outcome $Mode
                $csv = @(Import-Csv -LiteralPath $outputPath)
                Assert-Equal 1 $csv.Count
                Assert-Equal $columns ($csv[0].PSObject.Properties.Name -join ',')
                foreach ($column in $rows[0].PSObject.Properties.Name) {
                    Assert-Equal ([string]$rows[0].$column) ([string]$csv[0].$column)
                }
            }
            Assert-Equal 2 $global:ConnectionCsvFixture.Calls.Count
            foreach ($call in $global:ConnectionCsvFixture.Calls) {
                Assert-Equal 'Detailed' $call.InformationLevel
                Assert-Equal 'Stop' ([string]$call.ErrorAction)
                Assert-Equal 'SilentlyContinue' ([string]$call.WarningAction)
            }
        }
        'Malformed' {
            foreach ($outcome in @('Empty', 'Malformed', 'Multiple')) {
                $global:ConnectionCsvFixture.Outcome = $outcome
                $rows = @(Test-ServerConnection -ComputerName 'srv1')
                Assert-Equal 1 $rows.Count
                Assert-Row $rows[0] -Outcome $outcome
            }
        }
        'Selection' {
            $computers = @('first', 'second', 'first')
            $ports = @(1, 65535, 445)
            $rows = @(Test-ServerConnection -ComputerName $computers -Port $ports)
            Assert-Equal 9 $rows.Count
            Assert-Equal 9 $global:ConnectionCsvFixture.Calls.Count
            $index = 0
            foreach ($computer in $computers) {
                foreach ($port in $ports) {
                    Assert-Row $rows[$index] -Computer $computer -Port $port
                    Assert-Equal $computer $global:ConnectionCsvFixture.Calls[$index].ComputerName
                    Assert-Equal $port $global:ConnectionCsvFixture.Calls[$index].Port
                    $index++
                }
            }
            Assert-Equal 0 @(Get-ChildItem -LiteralPath $WorkingDirectory -Recurse -File).Count
        }
        'Inert' {
            Assert-Equal 0 $global:ConnectionCsvFixture.Calls.Count
            Assert-Equal 0 @(Get-ChildItem -LiteralPath $WorkingDirectory -Recurse -File).Count
        }
        'Validation' {
            foreach ($computers in @(@(), @(''), @('first', ' '))) {
                Assert-Fails { Test-ServerConnection -ComputerName $computers -OutputPath $outputPath }
            }
            foreach ($ports in @(@(), @(0), @(65536), @(445, -1))) {
                Assert-Fails { Test-ServerConnection -ComputerName 'first' -Port $ports -OutputPath $outputPath }
            }
            Assert-Equal 0 $global:ConnectionCsvFixture.Calls.Count
            Assert-Equal $false (Test-Path -LiteralPath $outputPath)
        }
        'Class' {
            $type = 'ADAnalyzerConnectionScan' -as [type]
            Assert-Equal $false ($null -eq $type)
            Assert-Fails { $type::new(@(''), @(445)) }
            Assert-Fails { $type::new(@('first'), @(0)) }
            $computers = @('first')
            $ports = @(445)
            $first = $type::new($computers, $ports)
            $second = $type::new(@('second'), @(443))
            $computers[0] = 'changed'
            $ports[0] = 999
            Assert-Equal 0 $global:ConnectionCsvFixture.Calls.Count
            $probe = Get-Command Test-NetConnection
            foreach ($repeat in 1..2) {
                $rows = @($first.Collect($probe))
                Assert-Equal 1 $rows.Count
                Assert-Row $rows[0] -Computer 'first'
                $rows[0].ComputerName = 'mutated-output'
            }
            Assert-Row ($second.Collect($probe))[0] -Computer 'second' -Port 443
            Assert-Fails { $first.Collect($null) }
            Assert-Equal 3 $global:ConnectionCsvFixture.Calls.Count
            $serialized = ConvertTo-Json -InputObject $first -Compress
            $snapshot = $serialized | ConvertFrom-Json
            Assert-Equal 2 @($snapshot.PSObject.Properties).Count
            Assert-Equal 'first' ([string]$snapshot.ComputerIdentities)
            Assert-Equal 445 ([int]$snapshot.PortNumbers[0])
            Assert-Equal $false ($serialized -match 'CommandInfo|SessionState|Credential')
            $csv = @($first.ToCsv(@()) | ConvertFrom-Csv)
            Assert-Equal 0 $csv.Count
            Assert-Equal ('"' + ($columns -replace ',', '","') + '"') $first.ToCsv(@())
        }
        'Csv' {
            $computer = 'host,"' + [char]0x00E9
            $rows = @(Test-ServerConnection -ComputerName $computer -OutputPath $outputPath)
            Assert-Row $rows[0] -Computer $computer
            $csv = @(Import-Csv -LiteralPath $outputPath)
            Assert-Equal $computer $csv[0].ComputerName
            $bytes = [IO.File]::ReadAllBytes($outputPath)
            Assert-Equal '239,187,191' ($bytes[0..2] -join ',')
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $WorkingDirectory -Recurse -File).Count
        }
        'ExportFailures' {
            [IO.File]::WriteAllText($outputPath, 'previous-report')

            function ConvertTo-Csv {
                [CmdletBinding()]
                param(
                    [Parameter(ValueFromPipeline = $true)]$InputObject,
                    [switch]$NoTypeInformation

                )
                process {
                    if ($global:ConnectionCsvFixture.ConversionFault -eq 'Throw') {
                        throw 'Fixture conversion failure'
                    }
                    Write-Error 'Fixture nonterminating conversion failure'
                    'invalid-content'
                }
            }
            try {
                foreach ($fault in @('Throw', 'Error')) {
                    $global:ConnectionCsvFixture.ConversionFault = $fault
                    Assert-Fails { Test-ServerConnection -ComputerName 'srv1' -OutputPath $outputPath }
                    Assert-Equal 'previous-report' ([IO.File]::ReadAllText($outputPath))
                }
            }
            finally {
                Remove-Item Function:ConvertTo-Csv
            }
            $directoryPath = Join-Path $WorkingDirectory 'destination-directory'
            $null = [IO.Directory]::CreateDirectory($directoryPath)
            Assert-Fails { Test-ServerConnection -ComputerName 'srv1' -OutputPath $directoryPath }
            if ($env:OS -eq 'Windows_NT') {
                $held = [IO.File]::Open($outputPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
                try {
                    Assert-Fails { Test-ServerConnection -ComputerName 'srv1' -OutputPath $outputPath }
                }
                finally {
                    $held.Dispose()
                }
            }
            Assert-Equal 'previous-report' ([IO.File]::ReadAllText($outputPath))
            Assert-Equal 0 @(Get-ChildItem -LiteralPath $WorkingDirectory -Filter '.ad-analyzer-*.tmp').Count
            Assert-Equal 1 @(Get-ChildItem -LiteralPath $WorkingDirectory -Recurse -File).Count
        }
        'WhatIf' {
            $uncreated = Join-Path $WorkingDirectory 'not-created/report.csv'
            $rows = @(Test-ServerConnection -ComputerName 'srv1' -OutputPath $uncreated -WhatIf)
            Assert-Equal 1 $rows.Count
            Assert-Row $rows[0]
            Assert-Equal 1 $global:ConnectionCsvFixture.Calls.Count
            Assert-Equal $false (Test-Path -LiteralPath (Split-Path -Parent $uncreated))
            Assert-Equal 0 @(& $path -ComputerName 'srv1' -OutputPath $uncreated -WhatIf | Where-Object { $_.result -ne $true }).Count
            Assert-Equal $false (Test-Path -LiteralPath (Split-Path -Parent $uncreated))
        }
        'Cli' {
            Assert-Fails { & $path }
            Assert-Equal 0 $global:ConnectionCsvFixture.Calls.Count
            $rows = @(& $path -ComputerName 'srv1' -Port 443 -OutputPath $outputPath)
            Assert-Equal 1 $rows.Count
            Assert-Row $rows[0] -Port 443
            Assert-Equal 1 @(Import-Csv -LiteralPath $outputPath).Count
        }
    }
    Write-Output ('PASS connection CSV ' + $Mode)
}
finally {
    Remove-Item -LiteralPath $WorkingDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
