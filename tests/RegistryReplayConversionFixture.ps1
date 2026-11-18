[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Continue', 'Compatibility', 'ChildContinue', 'ChildStop')]
    [string]$Case = 'Continue',
    [ValidateSet('MissingKey',
        'MissingValueName',
        'MissingBoth',
        'MissingDeleteValuesPayload',
        'MissingDeleteKeysPayload',
        'ExplicitNull',
        'Replacement',
        'DeleteValuesNoOp',
        'DeleteKeysNoOp')]
    [string]$Sample = 'MissingKey'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'bin/ADAnalyzer.ps1')

function Assert-ReplayConversion($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-ReplayConversionRow([string]$Key, [string]$ValueName, [string]$Source, $Value) {
    [pscustomobject][ordered]@{
        Hive = 'HKLM'
        Key = $Key
        ValueName = $ValueName
        Scope = 'Computer'
        Source = $Source
        Value = $Value
        SecretPresent = $ValueName -eq 'DefaultPassword'
        Type = 4
        KeyOnly = $false
    }
}

function New-ReplayConversionInput([string]$Name) {
    $tail = New-ReplayConversionRow 'Fixture\Tail' tail tail.pol 9
    if ($Name -eq 'Replacement') {
        New-ReplayConversionRow 'Fixture\Base\' Setting base.pol 6
        New-ReplayConversionRow 'fixture\base' setting replacement.pol 8
        return
    }
    if ($Name -eq 'ExplicitNull') {
        ConvertFrom-Json '{"Hive":"HKLM","Key":null,"ValueName":null,"Scope":"Computer","Source":"null.pol","Value":12,"SecretPresent":false,"Type":4,"KeyOnly":false}'
        $tail
        return
    }
    if ($Name -in @('DeleteValuesNoOp', 'DeleteKeysNoOp')) {
        New-ReplayConversionRow 'Fixture\Base' child base.pol 6
        New-ReplayConversionRow 'Fixture\Base\child' Setting descendant.pol 8
        $directive = '**' + $Name.Replace('NoOp', '')
        New-ReplayConversionRow 'Fixture\Base' $directive null-directive.pol $null
        New-ReplayConversionRow 'Fixture\Base' $directive empty-text.pol ''
        New-ReplayConversionRow 'Fixture\Base' $directive empty-bytes.pol ([byte[]]@())
        $tail
        return
    }
    if ($Name -eq 'MissingDeleteValuesPayload') {
        New-ReplayConversionRow 'Fixture\Base' child base.pol 6
        New-ReplayConversionRow 'Fixture\Other\child' Setting other.pol 7
        New-ReplayConversionRow 'Fixture\Other' '**DeleteKeys' directive.pol child
        ConvertFrom-Json '{"Hive":"HKLM","Key":"Fixture\\Base","ValueName":"**DeleteValues","Scope":"Computer","Source":"malformed.pol","SecretPresent":false,"Type":4,"KeyOnly":false}'
        $tail
        return
    }
    if ($Name -eq 'MissingDeleteKeysPayload') {
        New-ReplayConversionRow 'Fixture\Base\child' Setting base.pol 6
        New-ReplayConversionRow 'Fixture\Other' child other.pol 7
        New-ReplayConversionRow 'Fixture\Other' '**DeleteValues' directive.pol child
        ConvertFrom-Json '{"Hive":"HKLM","Key":"Fixture\\Base","ValueName":"**DeleteKeys","Scope":"Computer","Source":"malformed.pol","SecretPresent":false,"Type":4,"KeyOnly":false}'
        $tail
        return
    }
    New-ReplayConversionRow 'Fixture\Other' Setting other.pol 7
    New-ReplayConversionRow 'Fixture\Other' '**DelVals' directive.pol $null
    if ($Name -eq 'MissingValueName') {
        New-ReplayConversionRow 'Fixture\Base' DefaultPassword base.pol $null
        New-ReplayConversionRow 'Fixture\Other' '**DelVals' second-directive.pol $null
        ConvertFrom-Json '{"Hive":"HKLM","Key":"Fixture\\Base","Scope":"Computer","Source":"malformed.pol","Value":99,"SecretPresent":false,"Type":4,"KeyOnly":false}'
    }
    else {
        New-ReplayConversionRow 'Fixture\Base' Setting base.pol 6
        if ($Name -eq 'MissingKey') {
            ConvertFrom-Json '{"Hive":"HKLM","ValueName":"Setting","Scope":"Computer","Source":"malformed.pol","Value":99,"SecretPresent":false,"Type":4,"KeyOnly":false}'
        }
        else {
            ConvertFrom-Json '{"Hive":"HKLM","Scope":"Computer","Source":"malformed.pol","Value":99,"SecretPresent":false,"Type":4,"KeyOnly":false}'
        }
    }
    $tail
}

function Get-ReplayConversionError($Record) {
    [pscustomobject][ordered]@{
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Cause = $Record.Exception.GetBaseException().Message
    }
}

function Get-ReplayConversionObservation([object[]]$Items, [object[]]$Global) {
    [pscustomobject][ordered]@{
        Errors = @(
            foreach ($item in $Items) {
                if ($item -is [Management.Automation.ErrorRecord]) {
                    Get-ReplayConversionError $item
                }
            }
        )
        Rows = @(
            foreach ($item in $Items) {
                if ($item -isnot [Management.Automation.ErrorRecord]) {
                    [pscustomobject][ordered]@{
                        Fields = $item.PSObject.Properties.Name -join ','
                        Key = $item.Key
                        Name = $item.ValueName
                        Source = $item.Source
                        Value = $item.Value
                        ValueType = if ($null -ne $item.Value) {
                            $item.Value.GetType().FullName
                        }
                        Deleted = $item.Deleted
                        Present = $item.SecretPresent
                    }
                }
            }
        )
        Order = @(
            foreach ($item in $Items) {
                if ($item -is [Management.Automation.ErrorRecord]) {
                    'Error'
                }
                else {
                    'Row'
                }
            }
        )
        Global = @($Global | ForEach-Object { Get-ReplayConversionError $_ })
    }
}

function Invoke-ReplayConversionChild([string]$Mode, [string]$Name) {
    $engine = (Get-Process -Id $PID).Path
    $parameters = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', $Mode, '-Sample', $Name
    )
    $ErrorActionPreference = 'Continue'
    $lines = @(& $engine @parameters 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{
        Exit = $LASTEXITCODE
        Lines = @($lines | Where-Object { $_ -match '\S' })
    }
}

function Assert-ReplayConversionError($Record, [string]$Field, [string]$Label) {
    Assert-ReplayConversion ($Record.Id -like 'PropertyNotFoundStrict*' -and
        -not [string]::IsNullOrWhiteSpace($Record.Category) -and
        $Record.Cause.Contains("'" + $Field + "'")) "Expected native missing $Field error in $Label."
}

function Assert-ReplayConversionRows($Observation, [string]$Name) {
    $rows = $Observation.Rows
    $base = @($rows | Where-Object Source -ceq 'base.pol')
    $tail = @($rows | Where-Object Source -ceq 'tail.pol')
    Assert-ReplayConversion ($rows.Count -eq 3 -and $base.Count -eq 1 -and
        @($rows | Where-Object Source -ceq 'malformed.pol').Count -eq 0) "${Name}: the failed row replaced a prior tuple or entered replay."
    $deletionSource = 'other.pol'
    if ($Name -eq 'MissingDeleteKeysPayload') {
        # Named deletion reports the directive's provenance.
        $deletionSource = 'directive.pol'
    }
    $other = @($rows | Where-Object Source -ceq $deletionSource)
    Assert-ReplayConversion ($other.Count -eq 1 -and
        $other[0].Deleted -eq $true -and
        $null -eq $other[0].Value) "${Name}: the legitimate deletion changed."
    Assert-ReplayConversion ($tail.Count -eq 1 -and -not $tail[0].Deleted -and
        $tail[0].Value -eq 9 -and $tail[0].ValueType -ceq 'System.Int32') "${Name}: the valid tail row changed."
    if ($Name -eq 'MissingValueName') {
        Assert-ReplayConversion (-not $base[0].Deleted -and $base[0].Present -eq $true -and
            $null -eq $base[0].Value) 'MissingValueName: the failed row replayed the prior directive against the unrelated live row.'
    }
    else {
        $baseKey = 'Fixture\Base'
        if ($Name -eq 'MissingDeleteKeysPayload') {
            $baseKey += '\child'
        }
        Assert-ReplayConversion (-not $base[0].Deleted -and $base[0].Key -ceq $baseKey -and
            $base[0].Value -eq 6 -and $base[0].ValueType -ceq 'System.Int32') "${Name}: the failed row changed the prior valid write."
    }
}

if ($Case -in @('ChildContinue', 'ChildStop')) {
    # These processes have no enclosing try or trap around replay.
    $inputRows = @(New-ReplayConversionInput $Sample)
    $Error.Clear()
    Set-StrictMode -Version Latest
    if ($Case -eq 'ChildStop') {
        $ErrorActionPreference = 'Stop'
        $ErrorView = 'NormalView'
        Write-Output "START $Sample"
        Get-ADAnalyzerEffectiveRegistryRecords $inputRows | ForEach-Object { Write-Output 'REPLAY-ROW' }
        Write-Output 'RETURNED'
        exit 0
    }
    $ErrorActionPreference = 'Continue'
    $items = @(Get-ADAnalyzerEffectiveRegistryRecords $inputRows 2>&1)
    $globalErrors = @($Error)
    Set-StrictMode -Off
    $observation = Get-ReplayConversionObservation $items $globalErrors
    $json = ConvertTo-Json -InputObject $observation -Depth 12 -Compress
    Write-Output ('RESULT ' + $json)
    exit 0
}

$executed = 0
switch ($Case) {
    'VerifyOriginal' {
        $path = Join-Path $root 'bin/ADPolicyAnalysis.ps1'
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        Assert-ReplayConversion ($hash -ieq '917d099e283eeae97052eee94712ac0cc048e8bae03b9155fd6efb4025e37f4e') 'Accepted policy source fingerprint changed.'
        $executed++
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        $replay = @($ast.EndBlock.Statements | Where-Object Name -ceq 'Get-ADAnalyzerEffectiveRegistryRecords')
        Assert-ReplayConversion ($errors.Count -eq 0 -and $replay.Count -eq 1) 'Could not isolate the accepted replay function.'
        $source = $replay[0].Extent.Text.Replace([string][char]13 + [char]10, [string][char]10)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source))).Replace('-', '')
        }
        finally {
            $sha.Dispose()
        }
        Assert-ReplayConversion ($hash -ieq 'c755420d6f8ae8e436f8d42a1ba672118d86df937c78327a28233a500f06fe03') 'Accepted replay function fingerprint changed.'
        $executed++
    }
    'Continue' {
        $failures = [Collections.Generic.List[string]]::new()
        $samples = [ordered]@{
            MissingKey = @('Key')
            MissingValueName = @('ValueName')
            MissingBoth = @('Key', 'ValueName')
            MissingDeleteValuesPayload = @('Value')
            MissingDeleteKeysPayload = @('Value')
        }
        foreach ($name in $samples.Keys) {
            try {
                $run = Invoke-ReplayConversionChild 'ChildContinue' $name
                $json = @($run.Lines | Where-Object { $_ -like 'RESULT *' })
                Assert-ReplayConversion ($run.Exit -eq 0 -and $json.Count -eq 1 -and
                    $run.Lines.Count -eq 1) "Fresh Continue process did not capture the native replay stream for $name."
                $observed = ConvertFrom-Json $json[0].Substring(7)
                $fields = $samples[$name]
                Assert-ReplayConversion ($observed.Errors.Count -ge $fields.Count -and
                    $observed.Rows.Count -gt 0) "Missing native errors or replay output for $name."
                for ($i = 0; $i -lt $fields.Count; $i++) {
                    Assert-ReplayConversionError $observed.Errors[$i] $fields[$i] $name
                }
                Write-Host "Observed $($observed.Errors.Count) native error(s), including $($fields -join ', '), and $($observed.Rows.Count) output row(s) for $name."
                Assert-ReplayConversion ($observed.Errors.Count -eq $fields.Count -and
                    $observed.Global.Count -eq $fields.Count) "Unexpected additional replay errors for $name."
                for ($i = 0; $i -lt $fields.Count; $i++) {
                    Assert-ReplayConversionError $observed.Global[$i] $fields[$fields.Count - 1 - $i] $name
                }
                $order = @(
                    foreach ($field in $fields) {
                        'Error'
                    }
                    foreach ($row in $observed.Rows) {
                        'Row'
                    }
                )
                Assert-ReplayConversion (($observed.Order -join ',') -ceq ($order -join ',')) "Native errors were not emitted before final replay rows for $name."
                Assert-ReplayConversionRows $observed $name
                $executed++
            }
            catch {
                $failures.Add($_.Exception.Message)
            }
        }
        if ($failures.Count) {
            throw ($failures -join [Environment]::NewLine)
        }
    }
    'Compatibility' {
        foreach ($name in @('MissingKey', 'MissingValueName')) {
            $field = $name.Substring(7)
            foreach ($action in @('Continue', 'Stop')) {
                $inputRows = @(New-ReplayConversionInput $name)
                $stream = [Collections.Generic.List[object]]::new()
                $fault = $null
                try {
                    & {
                        Set-StrictMode -Version Latest
                        $ErrorActionPreference = $action
                        Get-ADAnalyzerEffectiveRegistryRecords $inputRows
                    } 2>&1 | ForEach-Object { $stream.Add($_) }
                }
                catch {
                    $fault = Get-ReplayConversionError $_
                }
                Assert-ReplayConversion ($null -ne $fault -and
                    $stream.Count -eq 0) "Caught $action did not stop replay before output for $name."
                Assert-ReplayConversionError $fault $field "$name/$action"
                $executed++
            }
            $run = Invoke-ReplayConversionChild 'ChildStop' $name
            $diagnostic = ($run.Lines | Select-Object -Skip 1) -join ' '
            Assert-ReplayConversion ($run.Exit -ne 0 -and $run.Lines[0] -ceq "START $name" -and
                $diagnostic -match 'PropertyNotFoundStrict' -and
                $diagnostic.Contains("'" + $field + "'") -and
                $diagnostic -notmatch 'RETURNED|REPLAY-ROW') "Fresh Stop process dropped the native failure or emitted a row for $name."
            $executed++
        }
        foreach ($name in @('MissingKey', 'MissingValueName')) {
            $inputRows = @(New-ReplayConversionInput $name)
            $rows = @(& {
                    Set-StrictMode -Off
                    Get-ADAnalyzerEffectiveRegistryRecords $inputRows
                })
            $converted = @($rows | Where-Object Source -ceq 'malformed.pol')
            $field = $name.Substring(7)
            Assert-ReplayConversion ($rows.Count -eq 4 -and $converted.Count -eq 1 -and
                $null -eq $converted[0].PSObject.Properties[$field] -and
                $converted[0].Value -eq 99 -and -not $converted[0].Deleted) "Permissive empty-string coercion changed for $name."
            $executed++
        }
        foreach ($strict in @($true, $false)) {
            $inputRows = @(New-ReplayConversionInput 'ExplicitNull')
            $rows = @(& {
                    if ($strict) {
                        Set-StrictMode -Version Latest
                    }
                    else {
                        Set-StrictMode -Off
                    }
                    Get-ADAnalyzerEffectiveRegistryRecords $inputRows
                })
            $converted = @($rows | Where-Object Source -ceq 'null.pol')
            Assert-ReplayConversion ($rows.Count -eq 2 -and $converted.Count -eq 1 -and
                $null -eq $converted[0].Key -and $null -eq $converted[0].ValueName -and
                -not $converted[0].Deleted) "Explicit-null permissive replay changed with StrictMode=$strict."
            $executed++
        }
        foreach ($name in @('DeleteValuesNoOp', 'DeleteKeysNoOp')) {
            $inputRows = @(New-ReplayConversionInput $name)
            $rows = @(& {
                    Set-StrictMode -Off
                    Get-ADAnalyzerEffectiveRegistryRecords $inputRows
                })
            Assert-ReplayConversion ($rows.Count -eq 3 -and @($rows | Where-Object Deleted).Count -eq 0 -and
                ($rows | Where-Object Source -ceq 'base.pol').Value -eq 6 -and
                ($rows | Where-Object Source -ceq 'descendant.pol').Value -eq 8 -and
                ($rows | Where-Object Source `
                    -ceq 'tail.pol').Value -eq 9) "Explicit-null, empty text or empty byte payload changed the no-op behavior for $name."
            $executed++
        }
        $rows = @(Get-ADAnalyzerEffectiveRegistryRecords @(New-ReplayConversionInput 'Replacement'))
        Assert-ReplayConversion ($rows.Count -eq 1 -and $rows[0].Source -ceq 'replacement.pol' -and
            $rows[0].Key -ceq 'fixture\base' -and $rows[0].ValueName -ceq 'setting' -and
            $rows[0].Value -eq 8 -and -not $rows[0].Deleted) 'A valid case-insensitive normalized replacement changed.'
        $executed++
    }
}
Write-Host "PASS registry replay conversion $Case $executed"
