[CmdletBinding()]
param(
    [ValidateSet('Contracts', 'Direct', 'Uncaught')][string]$Case = 'Contracts',
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('BadBinary', 'MissingXml')][string]$Fault = 'BadBinary',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')

# Exact accepted U-100 command before the class migration.
$script:OriginalNormalizer = @'
function ConvertTo-ADAnalyzerProvidedGpoPolicy {
    # Prefetched input uses the package DTO contract, including safe XML and
    # typed registry values. Copy before projecting so caller data stays intact.
    param([Parameter(Mandatory)]$Policy)
    foreach ($field in @('SecuritySettings', 'RegistrySettings', 'IniSettings', 'XmlFiles', 'Files', 'UnparsedFiles')) {
        foreach ($record in @($Policy.$field)) {
            if ($null -ne $record -and
                ($record -is [Collections.IDictionary] -or
                $record -is [string] -or
                $record -is [ValueType] -or
                $record -isnot [pscustomobject])) {
                throw 'InputObject policy records must use package report objects or JSON objects.'
            }
        }
    }
    $xmlFiles = @(foreach ($record in @($Policy.XmlFiles)) {
            if ($null -eq $record) {
                continue
            }
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $text = [IO.StringReader]::new([string]$record.Xml)
            $reader = $null
            try {
                $reader = [Xml.XmlReader]::Create($text, $settings)
                $document = [xml]::new()
                $document.XmlResolver = $null
                $document.Load($reader)
                $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $document
            }
            catch {
                throw 'Provided policy XML is unreadable.'
            }
            finally {
                if ($null -ne $reader) {
                    $reader.Dispose()
                }
                $text.Dispose()
            }
            [pscustomobject]@{
                Scope = $record.Scope
                Kind = $record.Kind
                Path = $record.Path
                Xml = $safe.PSBase.OuterXml
            }
        })
    [pscustomobject]@{
        Path = $Policy.Path
        SysvolVersion = $Policy.SysvolVersion
        Files = @($Policy.Files)
        UnparsedFiles = @($Policy.UnparsedFiles)
        SecuritySettings = @($Policy.SecuritySettings | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-ADAnalyzerSecretRecord $_ })
        RegistrySettings = @($Policy.RegistrySettings | Where-Object { $null -ne $_ } | ForEach-Object {
                $record = ConvertTo-ADAnalyzerSecretRecord $_.PSObject.Copy()
                if ($record.Type -notin @(1, 2, 4, 5, 7, 11) -and
                    ($null -ne $record.PSObject.Properties['Value'] -or
                        $null -eq $record.PSObject.Properties['SecretPresent']) -and
                    $record.Value -is [array]) {
                    $record.Value = [byte[]]$record.Value
                }
                $record
            })
        IniSettings = @($Policy.IniSettings | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-ADAnalyzerSecretRecord $_ })
        XmlFiles = $xmlFiles
    }
}
'@
$script:OriginalHash = 'fc3fcd372f51093ad6b5effce09b421b4dc725e5db28db1910dcaa6a224fca01'
$script:Records = @('Native', 'Json', 'Typed', 'Trace', 'References')
$script:Faults = @('BadXml', 'Dtd', 'InvalidBeforeXml', 'MissingXml', 'MissingXmlScope', 'MissingFiles', 'OrdinaryMissingValue')

function Assert-Normalizer($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-NormalizerHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Assert-NormalizerBinding {
    Assert-Normalizer ((Get-NormalizerHash $script:OriginalNormalizer) -ieq $script:OriginalHash) 'Frozen provided-policy normalizer changed.'
    $tokens = $null
    $errors = $null
    $oracle = [Management.Automation.Language.Parser]::ParseInput($script:OriginalNormalizer, [ref]$tokens, [ref]$errors)
    $command = Get-Command ConvertTo-ADAnalyzerProvidedGpoPolicy -CommandType Function
    $actual = $command.ScriptBlock.Ast
    if ($actual -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $actual = $actual.Body
    }
    Assert-Normalizer ($command.CmdletBinding -and $errors.Count -eq 0 -and
        (Get-NormalizerHash $actual.ParamBlock.Extent.Text) -ceq
        (Get-NormalizerHash $oracle.EndBlock.Statements[0].Body.ParamBlock.Extent.Text)) 'The advanced command parameter contract changed.'
    foreach ($name in @('Policy', 'ErrorAction', 'ErrorVariable', 'OutVariable')) {
        Assert-Normalizer ($command.Parameters.ContainsKey($name)) "Missing normalizer parameter $name."
    }
    $mandatory = @($command.Parameters.Policy.Attributes | Where-Object { $_ -is [Management.Automation.ParameterAttribute] -and
            $_.Mandatory })
    Assert-Normalizer ($mandatory.Count -eq 1) 'Policy must remain mandatory.'
}

function Assert-NormalizerSame($Expected, $Actual, [string]$Context) {
    $before = ConvertTo-Json -InputObject $Expected -Depth 24 -Compress
    $after = ConvertTo-Json -InputObject $Actual -Depth 24 -Compress
    Assert-Normalizer ($before -ceq $after) "$Context differs from the frozen same-engine normalizer."
}

function New-NormalizerPolicy {
    [pscustomobject][ordered]@{
        Path = 'fixture'
        SysvolVersion = 1
        Files = @()
        UnparsedFiles = @()
        SecuritySettings = @()
        RegistrySettings = @()
        IniSettings = @()
        XmlFiles = @()
    }
}

function New-NormalizerRegistry([string]$Name, [int]$Type, $Value) {
    [pscustomobject][ordered]@{
        Scope = 'Computer'
        Hive = 'HKLM'
        Key = 'Software\Fixture'
        ValueName = $Name
        Type = $Type
        Value = $Value
        RawData = [byte[]]@(4, 6)
        Source = 'Machine/Registry.pol'
    }
}

function New-NormalizerXml([string]$Text) {
    [pscustomobject][ordered]@{
        Scope = 'Computer'
        Kind = 'Preferences'
        Path = 'Machine/Preferences/Groups/Groups.xml'
        Xml = $Text
    }
}

function New-NormalizerReaderPolicy([string]$Path) {
    $null = [IO.Directory]::CreateDirectory((Join-Path $Path Machine))
    [IO.File]::WriteAllLines((Join-Path $Path 'GPT.INI'), @('[General]', 'Version=1'))
    $writer = [IO.BinaryWriter]::new([IO.File]::Create((Join-Path $Path 'Machine/Registry.pol')))
    try {
        $writer.Write([Text.Encoding]::ASCII.GetBytes('PReg'))
        $writer.Write([uint32]1)
        foreach ($name in @('DefaultPassword', 'Password', 'FixtureBytes')) {
            $bytes = [byte[]]@(4, 6)
            if ($name -eq 'Password') {
                $bytes = [byte[]]@()
            }
            $writer.Write([uint16]91)
            $writer.Write([Text.Encoding]::Unicode.GetBytes('Software\Fixture' + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([Text.Encoding]::Unicode.GetBytes($name + [char]0))
            $writer.Write([uint16]59)
            $writer.Write([uint32]3)
            $writer.Write([uint16]59)
            $writer.Write([uint32]$bytes.Length)
            $writer.Write([uint16]59)
            $writer.Write($bytes)
            $writer.Write([uint16]93)
        }
    }
    finally {
        $writer.Dispose()
    }
    [ADAnalyzerGpoReader]::new().Read($Path)
}

function Copy-NormalizerTraced($Record, [string]$Prefix) {
    $traced = [pscustomobject]@{}
    foreach ($property in $Record.PSObject.Properties) {
        $label = $Prefix + '.' + $property.Name
        $held = $property.Value
        $getter = {
            $global:NormalizerFixtureTrace.Add($label)
            return , $held
        }.GetNewClosure()
        $traced.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new($property.Name, $getter))
    }
    $traced
}

function Get-NormalizerInput([string]$Name) {
    $global:NormalizerFixtureTrace = [Collections.Generic.List[string]]::new()
    if ($Name -eq 'Native') {
        return $script:ReaderPolicy
    }
    if ($Name -eq 'Json') {
        return (ConvertFrom-Json -InputObject $script:ReaderJson)
    }
    $policy = New-NormalizerPolicy
    $policy.XmlFiles = @(New-NormalizerXml '<Groups><Item name="fixture" /></Groups>')
    switch ($Name) {
        'Typed' {
            $policy.XmlFiles[0].Xml = '<Groups><User><Properties cpassword="fixture-xml-presence-marker" /></User></Groups>'
            $policy.RegistrySettings = @(
                New-NormalizerRegistry Text 1 'fixture text'
                New-NormalizerRegistry Expandable 2 '%FIXTURE%'
                New-NormalizerRegistry DWord 4 ([uint32]9)
                New-NormalizerRegistry BigEndian 5 ([uint32]24)
                New-NormalizerRegistry Multi 7 ([string[]]@('a', 'b'))
                New-NormalizerRegistry QWord 11 ([uint64]4294967296)
                New-NormalizerRegistry Bytes 3 ([object[]]@(4, 6))
                New-NormalizerRegistry ExplicitNull 3 $null
                $null
            )
        }
        'Trace' {
            $policy.XmlFiles[0] = Copy-NormalizerTraced $policy.XmlFiles[0] 'Xml'
            $policy = Copy-NormalizerTraced $policy 'Policy'
        }
        'References' {
            $policy.Files = @([pscustomobject]@{
                    Path = 'Machine/Registry.pol'
                })
            $policy.UnparsedFiles = @([pscustomobject]@{
                    Path = 'Machine/fixture'
                })
            $policy.SecuritySettings = @([pscustomobject]@{
                    Name = 'Fixture'
                    Value = $true
                })
            $policy.IniSettings = @([pscustomobject]@{
                    Name = 'Other'
                    Value = 'fixture'
                })
            $policy.RegistrySettings = @(New-NormalizerRegistry Multi 7 ([string[]]@('a', 'b')))
        }
        'BadXml' {
            $policy.XmlFiles[0].Xml = '<Groups>'
        }
        'Dtd' {
            $policy.XmlFiles[0].Xml = '<!DOCTYPE Groups [<!ELEMENT Groups EMPTY>]><Groups />'
        }
        'InvalidBeforeXml' {
            $policy.IniSettings = @(@{
                    Name = 'Fixture invalid dictionary'
                })
            $policy.XmlFiles[0].Xml = '<Groups>'
        }
        'MissingXml' {
            $policy.XmlFiles[0].PSObject.Properties.Remove('Xml')
        }
        'MissingXmlScope' {
            $policy.XmlFiles[0].PSObject.Properties.Remove('Scope')
        }
        'MissingFiles' {
            $policy.PSObject.Properties.Remove('Files')
        }
        'OrdinaryMissingValue' {
            $policy.RegistrySettings = @(New-NormalizerRegistry Ordinary 3 $null)
            $policy.RegistrySettings[0].PSObject.Properties.Remove('Value')
        }
        'BadBinary' {
            $policy.RegistrySettings = @(
                New-NormalizerRegistry Malformed 3 ([object[]]@(0, [pscustomobject]@{}))
                New-NormalizerRegistry Following 3 ([object[]]@(4, 6))
            )
        }
    }
    $policy
}

function Get-NormalizerShape($Policy) {
    [pscustomobject]@{
        Names = @($Policy.PSObject.Properties.Name)
        Policy = $Policy
        ValueTypes = @(foreach ($row in $Policy.RegistrySettings) {
                if ($null -eq $row.PSObject.Properties['Value']) {
                    '<absent>'
                }
                elseif ($null -eq $row.Value) {
                    '<null>'
                }
                else {
                    $row.Value.GetType().FullName
                }
            })
    }
}

function Invoke-NormalizerRecord([string]$Name, [string]$Route, $Service) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalNormalizer))
    }
    $policy = Get-NormalizerInput $Name
    $tracked = $Name -eq 'Trace'
    $before = ''
    if (-not $tracked) {
        $before = ConvertTo-Json -InputObject $policy -Depth 24 -Compress
    }
    Set-StrictMode -Version Latest
    $actual = @(if ($Route -eq 'Direct') {
            $Service.Normalize($policy)
        }
        else {
            $captured = @()
            ConvertTo-ADAnalyzerProvidedGpoPolicy -Policy $policy -OutVariable captured
            Assert-Normalizer ($captured.Count -eq 1) 'OutVariable did not capture a single DTO.'
        })
    Assert-Normalizer ($actual.Count -eq 1) "$Route/$Name did not return one policy DTO."
    $trace = $global:NormalizerFixtureTrace.ToArray()
    if (-not $tracked) {
        Assert-Normalizer ((ConvertTo-Json `
                    -InputObject $policy `
                    -Depth 24 `
                    -Compress) -ceq $before) "$Route/$Name mutated the supplied policy."
    }
    if ($Name -in 'Native', 'Json') {
        $settings = $actual[0].RegistrySettings
        Assert-Normalizer ($settings.Count -eq 3 -and $settings[0].SecretPresent -is [bool] -and
            $settings[0].SecretPresent -and $settings[1].SecretPresent -is [bool] -and -not $settings[1].SecretPresent -and
            $null -eq $settings[0].PSObject.Properties['Value'] -and $null -eq $settings[1].PSObject.Properties['Value'] -and
            $settings[2].Value -is [byte[]]) 'Reader presence or JSON binary restoration changed.'
    }
    if ($Name -eq 'Typed') {
        $text = $actual[0].XmlFiles[0].Xml
        Assert-Normalizer ($text -match 'cpasswordPresent="true"' -and
            $text -notmatch 'fixture-xml-presence-marker') 'The XML projection did not preserve Boolean presence alone.'
    }
    if ($Name -eq 'References') {
        foreach ($field in @('Files', 'UnparsedFiles', 'SecuritySettings', 'IniSettings')) {
            Assert-Normalizer ([object]::ReferenceEquals($actual[0].$field[0],
                    $policy.$field[0])) "Ordinary $field rows stopped borrowing their references."
        }
        Assert-Normalizer (-not [object]::ReferenceEquals($actual[0].RegistrySettings[0], $policy.RegistrySettings[0]) -and
            [object]::ReferenceEquals($actual[0].RegistrySettings[0].Value, $policy.RegistrySettings[0].Value) -and
            -not [object]::ReferenceEquals($actual[0].XmlFiles[0], $policy.XmlFiles[0])) 'Registry/Xml rows lost their required copy depth.'
        $actual[0].RegistrySettings[0].ValueName = 'Caller change'
        Assert-Normalizer ($policy.RegistrySettings[0].ValueName -ceq 'Multi') 'An output row mutation changed the input row.'
        if ($Route -eq 'Direct') {
            $again = $Service.Normalize($policy)
            $independent = [ADAnalyzerGpoSourceNormalizer]::new().Normalize($policy)
            Assert-Normalizer ($again.RegistrySettings[0].ValueName -ceq 'Multi' -and
                -not [object]::ReferenceEquals($again.RegistrySettings[0],
                    $independent.RegistrySettings[0])) 'Direct reuse shared result state with another normalization.'
            Assert-NormalizerSame (Get-NormalizerShape $again) (Get-NormalizerShape $independent) 'Independent direct instance'
        }
    }
    [pscustomobject]@{
        Shape = Get-NormalizerShape $actual[0]
        Trace = $trace
    }
}

function Get-NormalizerError([Management.Automation.ErrorRecord]$Item) {
    $cause = $Item.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Invoke-NormalizerFault([string]$Name, [string]$Route, [string]$Action, $Service) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalNormalizer))
    }
    Set-StrictMode -Version Latest
    $policy = Get-NormalizerInput $Name
    $global:Error.Clear()
    $savedErrors = @('fixture sentinel')
    $captured = @()
    $caught = $null
    try {
        if ($Route -eq 'Direct') {
            $captured = @($Service.Normalize($policy))
        }
        else {
            $null = ConvertTo-ADAnalyzerProvidedGpoPolicy `
                -Policy $policy `
                -ErrorAction $Action `
                -ErrorVariable '+savedErrors' `
                -OutVariable captured
        }
    }
    catch {
        $caught = Get-NormalizerError $_
    }
    [pscustomobject]@{
        Caught = $caught
        Count = $captured.Count
        VariableSeed = $savedErrors[0] -is [string]
        Variable = @($savedErrors | Where-Object { $_ -is [Management.Automation.ErrorRecord] } | ForEach-Object { Get-NormalizerError $_ })
        Global = @($global:Error | ForEach-Object { Get-NormalizerError $_ })
    }
}

function Invoke-NormalizerChild([string]$Name, [bool]$Frozen) {
    $exe = (Get-Process -Id $PID).Path
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-RepositoryRoot', $RepositoryRoot, '-Case', 'Uncaught', '-Fault', $Name)
    if ($Frozen) {
        $arguments += '-Original'
    }
    $ErrorActionPreference = 'Continue'
    $lines = @(& $exe @arguments 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{
        Exit = $LASTEXITCODE
        Lines = @($lines | Where-Object { $_ -match '\S' })
    }
}

if ($Case -eq 'Uncaught') {
    if ($Original) {
        . ([scriptblock]::Create($script:OriginalNormalizer))
    }
    Set-StrictMode -Version Latest
    $policy = Get-NormalizerInput $Fault
    $ErrorActionPreference = 'Continue'
    $ErrorView = 'CategoryView'
    Write-Output "START $Fault"
    $items = @(ConvertTo-ADAnalyzerProvidedGpoPolicy -Policy $policy 2>&1)
    foreach ($item in $items) {
        if ($item -is [Management.Automation.ErrorRecord]) {
            Write-Output ('ERROR ' + $item.FullyQualifiedErrorId)
        }
        else {
            $shape = Get-NormalizerShape $item
            Write-Output ('TYPES ' + ($shape.ValueTypes -join ','))
        }
    }
    Write-Output 'RETURNED'
    exit
}

Assert-NormalizerBinding
$count = 1
$route = 'Command'
$service = $null
if ($Case -eq 'Direct') {

    function ConvertTo-ADAnalyzerProvidedGpoPolicy {
        throw 'Direct normalization delegated to the old command.'
    }
    $service = & {

        function Read-ADAnalyzerGpo {
            throw 'The normalizer constructor tried to read policy.'
        }
        [ADAnalyzerGpoSourceNormalizer]::new()
    }
    Assert-Normalizer ($service.GetType().Name -ceq 'ADAnalyzerGpoSourceNormalizer') 'Literal construction did not produce the inert normalizer.'
    $route = 'Direct'
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('gpo-source-normalizer-' + [guid]::NewGuid().ToString('N'))
try {
    $script:ReaderPolicy = New-NormalizerReaderPolicy $temporary
    $script:ReaderJson = ConvertTo-Json -InputObject $script:ReaderPolicy -Depth 20 -Compress
    foreach ($name in $script:Records) {
        $expected = Invoke-NormalizerRecord $name 'Original' $null
        $actual = Invoke-NormalizerRecord $name $route $service
        if ($name -eq 'Trace') {
            $trace = 'Policy.SecuritySettings,Policy.RegistrySettings,Policy.IniSettings,Policy.XmlFiles,Policy.Files,Policy.UnparsedFiles,Policy.XmlFiles,Xml.Xml,Xml.Scope,Xml.Kind,Xml.Path,Policy.Path,Policy.SysvolVersion,Policy.Files,Policy.UnparsedFiles,Policy.SecuritySettings,Policy.RegistrySettings,Policy.IniSettings'
            Assert-Normalizer (($expected.Trace -join ',') -ceq $trace) 'Frozen native getter trace did not exercise the original order.'
        }
        Assert-NormalizerSame $expected $actual "$Case/$name"
        $count++
    }
}
finally {
    if ([IO.Directory]::Exists($temporary)) {
        [IO.Directory]::Delete($temporary, $true)
    }
}

foreach ($name in $script:Faults) {
    if ($Case -eq 'Contracts') {
        foreach ($action in @('Continue', 'Stop')) {
            $expected = Invoke-NormalizerFault $name Original $action $null
            $actual = Invoke-NormalizerFault $name Command $action $null
            Assert-Normalizer ($null -ne $expected.Caught -and
                $expected.VariableSeed) "Frozen $name/$action did not exercise native error binding."
            if ($name -in 'BadXml', 'Dtd') {
                Assert-Normalizer ($expected.Caught.Message -ceq 'Provided policy XML is unreadable.' -and
                    @($expected.Global | Where-Object Cause `
                            -eq 'System.Xml.XmlException').Count -gt 0) 'Frozen XML did not retain both outward and parser diagnostics.'
            }
            if ($name -eq 'InvalidBeforeXml') {
                Assert-Normalizer ($expected.Caught.Message -like 'InputObject policy records must*' -and
                    @($expected.Global | Where-Object Cause `
                            -eq 'System.Xml.XmlException').Count -eq 0) 'Frozen normalizer did not validate records before reading XML.'
            }
            Assert-NormalizerSame $expected $actual "$name/$action"
        }
    }
    else {
        $expected = Invoke-NormalizerFault $name Original Stop $null
        $actual = Invoke-NormalizerFault $name Direct Stop $service
        Assert-Normalizer ($null -ne $actual.Caught -and $actual.Caught.Message -ceq $expected.Caught.Message -and
            $actual.Count -eq 0) "Direct $name dropped its diagnostic or returned a partial policy."
    }
    $count++
}

if ($Case -eq 'Contracts') {
    foreach ($name in @('BadBinary', 'MissingXml')) {
        $expected = Invoke-NormalizerChild $name $true
        $actual = Invoke-NormalizerChild $name $false
        Assert-Normalizer ($expected.Lines[0] -ceq "START $name") "The frozen $name child did not run."
        if ($name -eq 'BadBinary') {
            Assert-Normalizer ($expected.Exit -eq 0 -and $expected.Lines[1] -like 'ERROR *InvalidCast*' -and
                $expected.Lines[2] -ceq 'TYPES System.Object[],System.Byte[]' -and
                $expected.Lines[3] -ceq 'RETURNED') 'The native Continue child did not preserve its error and both binary rows.'
        }
        else {
            Assert-Normalizer ($expected.Exit -ne 0 -and
                'RETURNED' -cnotin $expected.Lines) 'The missing XML child did not stop as expected.'
        }
        Assert-NormalizerSame $expected $actual "Uncaught $name"
        $count++
    }
}
else {
    $expected = Invoke-NormalizerFault BadBinary Original Stop $null
    $actual = Invoke-NormalizerFault BadBinary Direct Stop $service
    Assert-Normalizer ($null -ne $actual.Caught -and $actual.Caught.Message -ceq $expected.Caught.Message -and
        $actual.Count -eq 0) 'Direct malformed binary did not report the cause before returning results.'
    $count++
}

Write-Host "PASS GPO source normalizer $Case $count"
