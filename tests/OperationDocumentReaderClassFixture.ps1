[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

function Import-Module {
    throw 'Unexpected module acquisition in the operation reader fixture.'
}

function Invoke-Command {
    throw 'Unexpected remoting in the operation reader fixture.'
}

function Get-ADObject {
    throw 'Unexpected directory access in the operation reader fixture.'
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

$script:passed = 0

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$TestName, [scriptblock]$Body) {
    try {
        & $Body
        $script:passed++
    }
    catch {
        Write-Host ('FAIL operation document reader ' + $TestName)
        throw
    }
}

function Get-FixtureDiagnostic([object]$Value) {
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [Collections.IList]) {
        return [ordered]@{
            Type = $Value.GetType().FullName
            Entries = @(
                foreach ($entry in $Value) {
                    Get-FixtureDiagnostic $entry
                }
            )
        }
    }

    $record = $Value
    if ($Value -isnot [Management.Automation.ErrorRecord] -and
        $Value -is [Management.Automation.IContainsErrorRecord]) {
        $record = $Value.ErrorRecord
    }
    $output = [ordered]@{
        Type = $Value.GetType().FullName
        Id = $null
        Category = $null
        Command = $null
        Cause = $null
        Message = $null
    }
    if ($record -is [Management.Automation.ErrorRecord]) {
        $output.Id = $record.FullyQualifiedErrorId
        $output.Category = [string]$record.CategoryInfo.Category
        if ($null -ne $record.InvocationInfo -and $null -ne $record.InvocationInfo.MyCommand) {
            $output.Command = $record.InvocationInfo.MyCommand.Name
        }
        if ($null -ne $record.Exception) {
            $cause = $record.Exception.GetBaseException()
            $output.Cause = $cause.GetType().FullName
            $output.Message = $cause.Message
        }
    }
    elseif ($Value -is [Exception]) {
        $cause = $Value.GetBaseException()
        $output.Cause = $cause.GetType().FullName
        $output.Message = $cause.Message
    }
    return $output
}

function Write-FixtureJson([string]$Path, [string]$Text, [Text.Encoding]$Encoding) {
    $bytes = [byte[]]($Encoding.GetPreamble() + $Encoding.GetBytes($Text))
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Get-FixtureFailure([scriptblock]$Operation) {
    try {
        $null = & $Operation
    }
    catch {
        return $_
    }
    throw 'The operation reader unexpectedly accepted invalid input.'
}

if ($Case -eq 'Native') {
    # Exact accepted command body. Use the original command name for native error parity.
    # 3d4703b body SHA-256: fdafcf4a6e4c837d063e890caf15069d4b256d8d05e26df780b49143f94a41f9
    $script:AcceptedReader = @'
    param(
        [Parameter(Mandatory)]$InputObject,
        [string]$Kind = 'Assessment'

    )
    if ($InputObject -is [string]) {
        if (-not (Test-Path -LiteralPath $InputObject -PathType Leaf)) {
            throw "$Kind file does not exist"
        }
        $jsonParameters = @{
            ErrorAction = 'Stop'
        }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # Windows PowerShell already passes a decoded array as one object.
            $jsonParameters.NoEnumerate = $true
        }
        $readParameters = Get-ADAnalyzerJsonReadParameters $InputObject
        $PSDefaultParameterValues = Get-ADAnalyzerJsonReadDefaults
        $InputObject = Microsoft.PowerShell.Management\Get-Content @readParameters |
            ConvertTo-ADAnalyzerJsonText |
            ConvertFrom-Json @jsonParameters
    }
    if ($InputObject -is [array] -and $InputObject.Rank -eq 1 -and $InputObject.Length -eq 1) {
        $InputObject = $InputObject.GetValue($InputObject.GetLowerBound(0))
    }
    if ($null -eq $InputObject -or
        $InputObject -is [ValueType] -or
        $InputObject -is [string] -or
        ($InputObject -is [Collections.IEnumerable] -and $InputObject -isnot [Collections.IDictionary])) {
        throw "$Kind must be a structured object or JSON file"
    }
    $version = Get-ADAnalyzerOperationValue $InputObject @('SchemaVersion')
    if ($null -ne $version -and [string]$version -notmatch '^1(?:\.|$)') {
        throw "Unsupported $Kind SchemaVersion"
    }
    return $InputObject
'@
}

function New-FixtureReadCase([string]$Name, [string]$Path) {
    $record = [pscustomobject][ordered]@{
        SchemaVersion = 1
        Label = 'known fixture'
    }
    $fixture = @{
        Name = $Name
        Path = $Path
        Input = $Path
        Record = $record
        Kind = 'Assessment'
    }
    $script:fixtureGetterReads = 0
    $utf8 = [Text.UTF8Encoding]::new($false)
    switch ($Name) {
        'Dto' {
            $fixture.Input = $record
        }
        'Hash' {
            $fixture.Input = @{
                SchemaVersion = $null
                Label = 'dictionary'
            }
        }
        'Ordered' {
            $fixture.Input = [ordered]@{
                Label = 'legacy dictionary'
            }
        }
        'ArraySingleton' {
            $fixture.Input = @($record)
        }
        'LowerBoundSingleton' {
            $array = [array]::CreateInstance([object], [int[]]@(1), [int[]]@(7))
            $array.SetValue($record, 7)
            $fixture.Input = $array
        }
        'EmptyArray' {
            $fixture.Input = @()
        }
        'NestedArray' {
            $fixture.Input = , (, $record)
        }
        'VersionArrayEmpty' {
            $record.SchemaVersion = @()
            $fixture.Input = $record
        }
        'VersionArrayDot' {
            $record.SchemaVersion = @('1.7', 2)
            $fixture.Input = $record
        }
        'VersionArrayBare' {
            $record.SchemaVersion = @(1, 2)
            $fixture.Input = $record
        }
        'NullInput' {
            $fixture.Input = $null
        }
        'EmptyPath' {
            $fixture.Input = ''
        }
        'EmptyFile' {
            [IO.File]::WriteAllBytes($Path, [byte[]]@())
        }
        'BomOnly' {
            [IO.File]::WriteAllBytes($Path, [Text.UTF8Encoding]::new($true).GetPreamble())
        }
        'JsonNull' {
            Write-FixtureJson $Path 'null' $utf8
        }
        'JsonString' {
            Write-FixtureJson $Path '"fixture"' $utf8
        }
        'JsonSingleton' {
            Write-FixtureJson $Path '[{"SchemaVersion":1,"Label":"single JSON"}]' $utf8
        }
        'JsonMultiple' {
            Write-FixtureJson $Path '[{"SchemaVersion":1},{}]' $utf8
        }
        'StructuredGetter' {
            $record.PSObject.Properties.Remove('SchemaVersion')
            $record | Add-Member -MemberType ScriptProperty -Name SchemaVersion -Value {
                $script:fixtureGetterReads++
                '1.2'
            }
            $fixture.Input = $record
        }
        'UnknownDrive' {
            $fixture.Input = 'OperationFixtureMissingDrive:\record.json'
        }
        'Decoder' {
            [IO.File]::WriteAllBytes($Path, [byte[]]@(0xC3))
        }
        'Parser' {
            Write-FixtureJson $Path '{"Label":' $utf8
        }
        'MissingPath' {
            $fixture.Kind = 'Journal'
            if ([IO.File]::Exists($Path)) {
                [IO.File]::Delete($Path)
            }
        }
        'RawRead' {
            Write-FixtureJson $Path '{"SchemaVersion":1}' $utf8
        }
        'ProviderLeaf' {
            $fixture.Input = 'Env:' + $script:fixtureEnvironmentName
        }
        default {
            throw ('Unrecognized fixture case ' + $Name)
        }
    }
    return $fixture
}

function Invoke-FixtureNativeObservation {
    [CmdletBinding()]
    param([hashtable]$Fixture)

    if ($Fixture.Name -eq 'RawRead') {
        function Test-Path {
            [CmdletBinding()]
            param([string]$LiteralPath, [string]$PathType)

            Assert-Fixture ($LiteralPath -ceq $Fixture.Path -and $PathType -ceq 'Leaf') 'Unexpected raw-read path check.'
            [IO.File]::Delete($LiteralPath)
            return $true
        }
    }
    $seen = [Collections.ArrayList]::new()
    $caught = $null
    $continued = $false
    $items = [Collections.Generic.List[object]]::new()
    $bytesBefore = $null
    if ([IO.File]::Exists($Fixture.Path)) {
        $bytesBefore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Fixture.Path))
    }
    $Error.Clear()
    try {
        Read-ADAnalyzerOperationDocument -InputObject $Fixture.Input -Kind $Fixture.Kind -ErrorVariable +seen *>&1 |
            ForEach-Object {
                $items.Add($_)
            }
        $continued = $true
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    $getterReads = $script:fixtureGetterReads
    $bytesAfter = $null
    if ([IO.File]::Exists($Fixture.Path)) {
        $bytesAfter = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Fixture.Path))
    }
    $observation = [ordered]@{
        Continued = $continued
        Caught = Get-FixtureDiagnostic $caught
        ErrorVariable = Get-FixtureDiagnostic $seen
        History = Get-FixtureDiagnostic $history
        GetterReads = $getterReads
        BytesChanged = $bytesBefore -cne $bytesAfter
        Stream = @(
            foreach ($item in $items) {
                if ($null -eq $item) {
                    [ordered]@{
                        Type = 'Null'
                    }
                }
                elseif ($item -is [Management.Automation.ErrorRecord]) {
                    Get-FixtureDiagnostic $item
                }
                elseif ($item -is [Management.Automation.InformationalRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = $item.Message
                    }
                }
                elseif ($item -is [Management.Automation.InformationRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = $item.MessageData
                    }
                }
                else {
                    $row = [ordered]@{
                        Type = $item.GetType().FullName
                        SameInput = [object]::ReferenceEquals($Fixture.Input, $item)
                        SameRecord = [object]::ReferenceEquals($Fixture.Record, $item)
                        Label = $null
                        Schema = $null
                    }
                    if ($item -is [Collections.IDictionary]) {
                        $row.Label = $item['Label']
                        $row.Schema = $item['SchemaVersion']
                    }
                    else {
                        $label = $item.PSObject.Properties['Label']
                        if ($null -ne $label) {
                            $row.Label = $label.Value
                        }
                        $schema = $item.PSObject.Properties['SchemaVersion']
                        if ($null -ne $schema -and $Fixture.Name -ne 'StructuredGetter') {
                            $row.Schema = $schema.Value
                        }
                    }
                    $row
                }
            }
        )
    }
    return (ConvertTo-Json -InputObject $observation -Depth 24 -Compress)
}

function Assert-FixtureNativeParity([string]$Name, [string]$Action, [string]$Path) {
    $functionPath = 'Function:script:Read-ADAnalyzerOperationDocument'
    $candidate = (Get-Command Read-ADAnalyzerOperationDocument -CommandType Function).ScriptBlock
    $expectedInput = New-FixtureReadCase $Name $Path
    try {
        Set-Item -LiteralPath $functionPath -Value $script:acceptedReaderBlock
        $active = (Get-Command Read-ADAnalyzerOperationDocument -CommandType Function).ScriptBlock
        Assert-Fixture ($active.ToString() -ceq $script:acceptedReaderBlock.ToString()) 'The exact accepted reader was not installed.'
        $expected = Invoke-FixtureNativeObservation -Fixture $expectedInput -ErrorAction $Action
    }
    finally {
        Set-Item -LiteralPath $functionPath -Value $candidate
    }
    $restored = (Get-Command Read-ADAnalyzerOperationDocument -CommandType Function).ScriptBlock
    Assert-Fixture ($restored.ToString() -ceq $candidate.ToString()) 'The candidate reader was not restored.'
    $actualInput = New-FixtureReadCase $Name $Path
    $actual = Invoke-FixtureNativeObservation -Fixture $actualInput -ErrorAction $Action

    Assert-Fixture ($actual -ceq $expected) (
        "Native reader changed for $Name with inherited $Action." + [Environment]::NewLine +
        'Accepted: ' + $expected + [Environment]::NewLine + 'Current: ' + $actual
    )
}


$fixtureDirectory = $null
if ($Case -ne 'Construction') {
    $fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ('operation-reader-fixture-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($fixtureDirectory)
}
try {
    switch ($Case) {
        'Construction' {
            Test-Fixture 'literal constructor after the documented loader' {
                function Test-Path {
                    throw 'Object construction must not inspect a file.'
                }

                $first = [ADAnalyzerOperationDocumentReader]::new()
                $second = [ADAnalyzerOperationDocumentReader]::new()
                Assert-Fixture (
                    $first.GetType().Name -ceq 'ADAnalyzerOperationDocumentReader' -and
                    -not [object]::ReferenceEquals($first, $second)
                ) 'The documented loader did not expose an inert instance constructor.'
            }
            Test-Fixture 'both public overloads' {
                $type = [ADAnalyzerOperationDocumentReader]
                Assert-Fixture (
                    $null -ne $type.GetMethod('Read', [type[]]@([object])) -and
                    $null -ne $type.GetMethod('Read', [type[]]@([object], [string]))
                ) 'A public read overload is missing.'
            }
        }

        'Standalone' {
            Test-Fixture 'operations file loads the reader and local decoder independently' {
                $reader = [ADAnalyzerOperationDocumentReader]::new()
                $record = [pscustomobject]@{
                    SchemaVersion = 1
                    Label = 'standalone'
                }
                Assert-Fixture ([object]::ReferenceEquals($record, $reader.Read($record))) 'Standalone object identity changed.'
                $path = Join-Path $fixtureDirectory 'standalone [literal].json'
                Write-FixtureJson $path '{"SchemaVersion":1,"Label":"standalone file"}' ([Text.UTF8Encoding]::new($false))
                Assert-Fixture ($reader.Read($path, 'Journal').Label -ceq 'standalone file') 'Standalone file reading depends on the full loader.'
            }
        }

        'Native' {
            $script:acceptedReaderBlock = [scriptblock]::Create($script:AcceptedReader)
            $script:fixtureEnvironmentName = 'ADANALYZER_READER_FIXTURE_' + [guid]::NewGuid().ToString('N')
            [Environment]::SetEnvironmentVariable($script:fixtureEnvironmentName, '{"SchemaVersion":1}', 'Process')
            try {
                foreach ($name in @(
                        'Dto', 'Hash', 'Ordered', 'ArraySingleton', 'LowerBoundSingleton',
                        'EmptyArray', 'NestedArray', 'VersionArrayEmpty', 'VersionArrayDot', 'VersionArrayBare',
                        'NullInput', 'EmptyPath', 'EmptyFile', 'BomOnly', 'JsonNull', 'JsonString',
                        'JsonSingleton', 'JsonMultiple', 'StructuredGetter', 'UnknownDrive'
                    )) {
                    Test-Fixture $name {
                        $path = Join-Path $fixtureDirectory ($name + ' [literal].json')
                        Assert-FixtureNativeParity $name 'Stop' $path
                    }
                }
                foreach ($name in 'MissingPath', 'RawRead', 'Parser', 'Decoder', 'ProviderLeaf') {
                    foreach ($action in 'Continue', 'Stop', 'SilentlyContinue', 'Ignore') {
                        Test-Fixture ($name + ' inherited ' + $action) {
                            $path = Join-Path $fixtureDirectory ($name + ' [literal].json')
                            Assert-FixtureNativeParity $name $action $path
                        }
                    }
                }
            }
            finally {
                [Environment]::SetEnvironmentVariable($script:fixtureEnvironmentName, $null, 'Process')
            }
        }

        'Direct' {
            function Read-ADAnalyzerOperationDocument {
                throw 'The direct reader called the compatibility command.'
            }

            $reader = [ADAnalyzerOperationDocumentReader]::new()
            Test-Fixture 'structured records and singleton lower bounds retain reference identity' {
                $dto = [pscustomobject]@{
                    SchemaVersion = 1
                }
                $dictionary = @{
                    SchemaVersion = '1.0'
                }
                $ordered = [ordered]@{
                    Label = 'legacy'
                }
                $nonzero = [array]::CreateInstance([object], [int[]]@(1), [int[]]@(7))
                $nonzero.SetValue($dto, 7)
                foreach ($record in @($dto, $dictionary, $ordered)) {
                    Assert-Fixture ([object]::ReferenceEquals($record, $reader.Read($record))) 'A valid structured record was copied or changed.'
                }
                Assert-Fixture (
                    [object]::ReferenceEquals($dto, $reader.Read([object[]]@($dto))) -and
                    [object]::ReferenceEquals($dto, $reader.Read($nonzero))
                ) 'A shallow singleton did not return its original record.'
            }

            Test-Fixture 'legacy schema and one native schema getter' {
                foreach ($version in @($null, 1, '1.2', @(), @('1.7', 2))) {
                    $record = @{
                        SchemaVersion = $version
                    }
                    Assert-Fixture ([object]::ReferenceEquals($record, $reader.Read($record, 'Plan'))) 'A supported schema representation was rejected.'
                }
                $fixture = New-FixtureReadCase StructuredGetter ''
                $read = $reader.Read($fixture.Input)
                Assert-Fixture (
                    [object]::ReferenceEquals($fixture.Record, $read) -and $script:fixtureGetterReads -eq 1
                ) 'Schema validation repeated the native property getter.'
            }

            Test-Fixture 'invalid object shapes terminate before schema validation' {
                $record = [pscustomobject]@{
                    SchemaVersion = 1
                }
                $inner = , $record
                $matrix = [array]::CreateInstance([object], 1, 1)
                $matrix.SetValue($record, 0, 0)
                $invalid = [ordered]@{
                    Null = $null
                    Number = 42
                    Empty = @()
                    Multiple = @($record, $record)
                    Nested = , $inner
                    Rectangular = $matrix
                    ScalarSingleton = @(42)
                    NullSingleton = , $null
                }
                foreach ($name in $invalid.Keys) {
                    $failure = Get-FixtureFailure { $reader.Read($invalid[$name]) }
                    Assert-Fixture (
                        $failure.Exception.GetBaseException().Message -ceq 'Assessment must be a structured object or JSON file'
                    ) ('Unexpected failure for invalid input shape ' + $name + '.')
                }
            }

            Test-Fixture 'explicit document kind survives schema rejection' {
                foreach ($kind in 'Assessment', 'Plan', 'Journal') {
                    foreach ($version in @(2, @(1, 2))) {
                        $failure = Get-FixtureFailure {
                            $reader.Read(@{ SchemaVersion = $version }, $kind)
                        }
                        Assert-Fixture (
                            $failure.Exception.GetBaseException().Message -ceq ("Unsupported $kind SchemaVersion")
                        ) 'An unsupported schema lost its explicit document kind.'
                    }
                }
            }

            $encodings = [ordered]@{
                Utf8 = [Text.UTF8Encoding]::new($false)
                Utf8Bom = [Text.UTF8Encoding]::new($true)
                Utf16LE = [Text.UnicodeEncoding]::new($false, $true)
                Utf16BE = [Text.UnicodeEncoding]::new($true, $true)
                Utf32LE = [Text.UTF32Encoding]::new($false, $true)
                Utf32BE = [Text.UTF32Encoding]::new($true, $true)
            }
            foreach ($name in $encodings.Keys) {
                Test-Fixture ('literal path and singleton file ' + $name) {
                    $path = Join-Path $fixtureDirectory ($name + ' [literal].json')
                    $label = 'caf' + [char]0x00e9
                    $text = '[{"SchemaVersion":"1.1","Label":"' + $label + '"}]'
                    Write-FixtureJson $path $text $encodings[$name]
                    $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
                    $read = $reader.Read($path, 'Journal')
                    Assert-Fixture (
                        $read.Label -ceq $label -and $read.SchemaVersion -ceq '1.1' -and
                        [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -ceq $before
                    ) 'The reader changed Unicode, root cardinality, or file bytes.'
                }
            }

            Test-Fixture 'empty, BOM-only and nonrecord JSON still fail shape validation' {
                foreach ($name in 'EmptyFile', 'BomOnly', 'JsonNull', 'JsonString', 'JsonMultiple') {
                    $path = Join-Path $fixtureDirectory ($name + '.json')
                    $fixture = New-FixtureReadCase $name $path
                    $failure = Get-FixtureFailure { $reader.Read($fixture.Input) }
                    Assert-Fixture (
                        $failure.Exception.GetBaseException().Message -ceq 'Assessment must be a structured object or JSON file'
                    ) ('Unexpected failure for decoded shape ' + $name + '.')
                }
            }

            Test-Fixture 'raw decoder and native JSON parser preserve distinct causes' {
                $path = Join-Path $fixtureDirectory 'malformed [literal].json'
                $fixture = New-FixtureReadCase Decoder $path
                $failure = Get-FixtureFailure { $reader.Read($fixture.Input, 'Plan') }
                Assert-Fixture (
                    $failure.Exception.GetBaseException() -is [IO.InvalidDataException] -and
                    $failure.Exception.GetBaseException().Message -like '*invalid encoded text*'
                ) 'Malformed bytes did not retain the strict decoder cause.'
                $fixture = New-FixtureReadCase Parser $path
                $failure = Get-FixtureFailure { $reader.Read($fixture.Input, 'Journal') }
                Assert-Fixture (
                    ($failure.FullyQualifiedErrorId -like '*ConvertFromJson*' -or
                        $failure.Exception.GetBaseException().GetType().FullName -like '*Json*') -and
                    $failure.Exception.GetBaseException().Message -notlike '*must be a structured object*'
                ) 'Malformed syntax did not retain the native JSON parser cause.'
            }

            Test-Fixture 'missing and unsupported provider paths reach the expected failure' {
                foreach ($path in @((Join-Path $fixtureDirectory 'missing [literal].json'), $fixtureDirectory)) {
                    $failure = Get-FixtureFailure { $reader.Read($path, 'Journal') }
                    Assert-Fixture (
                        $failure.Exception.GetBaseException().Message -ceq 'Journal file does not exist'
                    ) 'A missing literal leaf lost its document kind.'
                }
                $name = 'ADANALYZER_READER_FIXTURE_' + [guid]::NewGuid().ToString('N')
                [Environment]::SetEnvironmentVariable($name, '{"SchemaVersion":1}', 'Process')
                try {
                    $failure = Get-FixtureFailure { $reader.Read(('Env:' + $name)) }
                    Assert-Fixture (
                        $failure.Exception.GetBaseException() -is [Management.Automation.ParameterBindingException] -or
                        $failure.Exception.GetBaseException() -is [NotSupportedException]
                    ) 'A non-FileSystem leaf lost its native provider diagnostic.'
                }
                finally {
                    [Environment]::SetEnvironmentVariable($name, $null, 'Process')
                }
            }
        }

        'Isolation' {
            Test-Fixture 'reused readers do not retain file results or failure state' {
                $firstReader = [ADAnalyzerOperationDocumentReader]::new()
                $secondReader = [ADAnalyzerOperationDocumentReader]::new()
                $path = Join-Path $fixtureDirectory 'reused [literal].json'
                Write-FixtureJson $path '{"SchemaVersion":1,"Label":"before"}' ([Text.UTF8Encoding]::new($false))
                $before = $firstReader.Read($path)
                $before.Label = 'changed projection'
                $separate = $secondReader.Read($path)
                Assert-Fixture ($separate.Label -ceq 'before') 'Separate readers shared parsed state.'

                Write-FixtureJson $path '[]' ([Text.UTF8Encoding]::new($false))
                $failure = Get-FixtureFailure { $firstReader.Read($path) }
                Assert-Fixture ($failure.Exception.GetBaseException().Message -ceq 'Assessment must be a structured object or JSON file') 'Invalid shape did not fail.'
                Write-FixtureJson $path '{"SchemaVersion":1,"Label":"after"}' ([Text.UTF8Encoding]::new($false))
                Assert-Fixture (
                    $firstReader.Read($path).Label -ceq 'after' -and $before.Label -ceq 'changed projection'
                ) 'A reused reader cached a prior result or failure.'
            }

            Test-Fixture 'same-source secondary runspace disposal preserves both read routes' {
                $reader = [ADAnalyzerOperationDocumentReader]::new()
                $path = Join-Path $fixtureDirectory 'runspace [literal].json'
                Write-FixtureJson $path '{"SchemaVersion":1,"Label":"journal"}' ([Text.UTF8Encoding]::new($true))
                Assert-Fixture ($reader.Read($path, 'Journal').Label -ceq 'journal') 'The original reader failed.'
                $worker = [powershell]::Create()
                try {
                    $snippet = @'
param($Fixture, $Root)
$ErrorActionPreference = 'Stop'
& $Fixture -Case Standalone -RepositoryRoot $Root
'@
                    $inside = @($worker.AddScript($snippet).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
                    Assert-Fixture (
                        $inside.Count -eq 1 -and [string]$inside[0] -ceq 'PASS operation document reader Standalone 1' -and
                        $worker.Streams.Error.Count -eq 0
                    ) ('Secondary reader failed: ' + ($worker.Streams.Error -join [Environment]::NewLine))
                }
                finally {
                    $worker.Dispose()
                }
                Assert-Fixture (
                    $reader.Read($path, 'Journal').Label -ceq 'journal' -and
                    (Read-ADAnalyzerOperationDocument -InputObject $path -Kind Journal).Label -ceq 'journal'
                ) 'Disposing the secondary runspace changed a read route.'
            }
        }
    }
}
finally {
    if ($null -ne $fixtureDirectory) {
        [IO.Directory]::Delete($fixtureDirectory, $true)
    }
}
'PASS operation document reader ' + $Case + ' ' + $script:passed
