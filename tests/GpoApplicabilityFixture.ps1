[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Records', 'Faults', 'Direct', 'Uncaught')]
    [string]$Case = 'Records',
    [ValidateSet('InvalidFlags', 'OverflowFlags', 'EnabledGetter')]
    [string]$Fault = 'InvalidFlags',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'bin/ADAnalyzer.ps1')

# Exact accepted U-089 function. Normalize only platform line endings for the hash.
$script:OriginalApplicability = @'
function Get-ADAnalyzerPolicyApplicability {
    param(
        $Gpo,
        [string]$Scope,
        [hashtable]$Profile,
        [switch]$Targeted,
        [switch]$Disabled

    )
    $flags = Get-ADAnalyzerPolicyValue $Gpo Flags 0
    $bit = if ($Scope -eq 'User') {
        1
    }
    else {
        2
    }
    if ($Disabled -or ([int]$flags -band $bit)) {
        return 'NotApplicable'
    }
    $links = @(Get-ADAnalyzerPolicyValue $Gpo Links @())
    if ($links.Count -gt 0 -and @($links | Where-Object Enabled).Count -eq 0) {
        return 'NotApplicable'
    }
    if ($Targeted) {
        return 'Unknown'
    }
    if (Get-ADAnalyzerPolicyValue $Gpo WmiFilter '') {
        return 'Unknown'
    }
    $analysis = Get-ADAnalyzerPolicyValue $Profile Analysis @{}
    if (Get-ADAnalyzerPolicyValue $analysis AssumeGpoApplicable $false) {
        return 'Applicable'
    }
    return 'Unknown'
}
'@
$script:ApplicabilityHash = '5d100aa8ccdb93fea8aac74f0027be2efb12ae27588de926a53823799c26a279'

function Assert-Applicability($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-ApplicabilityHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

Assert-Applicability ((Get-ApplicabilityHash $script:OriginalApplicability) -ieq $script:ApplicabilityHash) 'Frozen applicability source changed.'

function Get-ApplicabilityDefinition([string]$Text) {
    $tokens = $null
    $errors = $null
    $program = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $definitions = @($program.EndBlock.Statements | Where-Object Name -ceq 'Get-ADAnalyzerPolicyApplicability')
    Assert-Applicability ($errors.Count -eq 0 -and $definitions.Count -eq 1) 'Could not isolate the exact applicability AST.'
    $definitions[0]
}

function Assert-ApplicabilityBinding {
    $frozen = Get-ApplicabilityDefinition $script:OriginalApplicability
    $ast = (Get-Command Get-ADAnalyzerPolicyApplicability -CommandType Function).ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    Assert-Applicability ((Get-ApplicabilityHash $ast.ParamBlock.Extent.Text) -ceq
        (Get-ApplicabilityHash $frozen.Body.ParamBlock.Extent.Text)) 'Applicability parameter contract changed.'
}

function Assert-ApplicabilitySame($Expected, $Actual, [string]$Label) {
    $before = ConvertTo-Json -InputObject $Expected -Depth 8 -Compress
    $after = ConvertTo-Json -InputObject $Actual -Depth 8 -Compress
    Assert-Applicability ($before -ceq $after) "$Label differs. Expected $before; actual $after"
}

function Add-ApplicabilityObservation($Object, [string]$Property, [string]$Label, $Value, [switch]$Throw) {
    $getter = {
        $global:GpoApplicabilityFixtureTrace.Add($Label)
        if ($Throw) {
            throw [InvalidOperationException]::new('fixture Enabled getter')
        }
        return $Value
    }.GetNewClosure()
    $Object.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new($Property, $getter))
}

$script:Records = @(
    'Omitted', 'ExplicitNull', 'Absent', 'NullFlags', 'UserBit', 'ComputerBit', 'OppositeBit', 'BothBits',
    'UnknownScope', 'Targeted', 'DisabledDominates', 'ExplicitFalse', 'NullLinks', 'EmptyLinks', 'OneNullLink',
    'MissingEnabled', 'DisabledLinks', 'MixedLinks', 'TruthyLink', 'NullWmi', 'EmptyWmi', 'SingletonBlankWmi',
    'MultiBlankWmi', 'Wmi', 'AssumptionFalse', 'AssumptionTruthy', 'TraceAll', 'TraceTargeted',
    'TraceWmi', 'TraceDisabled', 'TraceLinksDisabled'
)
$script:Faults = @('InvalidFlags', 'OverflowFlags', 'EnabledGetter')

function New-ApplicabilitySample([string]$Name) {
    $gpo = @{}
    $profile = @{
        Analysis = @{
            AssumeGpoApplicable = $true
        }
    }
    $parameters = @{
        Gpo = $gpo
        Scope = 'Computer'
        Profile = $profile
    }
    $value = 'Applicable'
    $trace = @()
    switch ($Name) {
        'Omitted' {
            $parameters = @{}
            $value = 'Unknown'
        }
        'ExplicitNull' {
            $parameters = @{
                Gpo = $null
                Scope = $null
                Profile = $null
            }
            $value = 'Unknown'
        }
        'Absent' {
        }
        'NullFlags' {
            $gpo.Flags = $null
        }
        'UserBit' {
            $gpo.Flags = '1'
            $parameters.Scope = 'user'
            $value = 'NotApplicable'
        }
        'ComputerBit' {
            $gpo.Flags = 2L
            $value = 'NotApplicable'
        }
        'OppositeBit' {
            $gpo.Flags = 1
        }
        'BothBits' {
            $gpo.Flags = 3
            $parameters.Scope = 'User'
            $value = 'NotApplicable'
        }
        'UnknownScope' {
            $gpo.Flags = 2
            $parameters.Scope = 'FixtureScope'
            $value = 'NotApplicable'
        }
        'Targeted' {
            $parameters.Targeted = $true
            $value = 'Unknown'
        }
        'DisabledDominates' {
            $gpo.Flags = 'fixture invalid flags skipped'
            $parameters.Targeted = $true
            $parameters.Disabled = $true
            $value = 'NotApplicable'
        }
        'ExplicitFalse' {
            $parameters.Targeted = $false
            $parameters.Disabled = $false
        }
        'NullLinks' {
            $gpo.Links = $null
            $value = $null
        }
        'EmptyLinks' {
            $gpo.Links = @()
            $value = $null
        }
        'OneNullLink' {
            $gpo.Links = [object[]]::new(1)
            $value = $null
        }
        'MissingEnabled' {
            $gpo.Links = [pscustomobject]@{
                LinkName = 'fixture'
            }
            $value = 'NotApplicable'
        }
        'DisabledLinks' {
            $gpo.Links = @([pscustomobject]@{
                    Enabled = $false
                }, [pscustomobject]@{
                    Enabled = 0
                })
            $parameters.Targeted = $true
            $value = 'NotApplicable'
        }
        'MixedLinks' {
            $gpo.Links = @([pscustomobject]@{
                    Enabled = $false
                }, [pscustomobject]@{
                    Enabled = $true
                })
        }
        'TruthyLink' {
            $gpo.Links = [pscustomobject]@{
                Enabled = 'false'
            }
        }
        'NullWmi' {
            $gpo.WmiFilter = $null
            $value = $null
        }
        'EmptyWmi' {
            $gpo.WmiFilter = @()
            $value = $null
        }
        'SingletonBlankWmi' {
            $gpo.WmiFilter = @('')
            $value = $null
        }
        'MultiBlankWmi' {
            $gpo.WmiFilter = @('', '')
            $value = 'Unknown'
        }
        'Wmi' {
            $gpo.WmiFilter = 'fixture-filter'
            $value = 'Unknown'
        }
        'AssumptionFalse' {
            $profile.Analysis.AssumeGpoApplicable = $false
            $value = 'Unknown'
        }
        'AssumptionTruthy' {
            $profile.Analysis.AssumeGpoApplicable = 'false'
        }
        { $_ -like 'Trace*' -or $_ -eq 'EnabledGetter' } {
            $first = [pscustomobject]@{}
            $second = [pscustomobject]@{}
            $analysis = [pscustomobject]@{}
            $observedGpo = [pscustomobject]@{}
            $enabled = $Name -ne 'TraceLinksDisabled'
            $filter = ''
            if ($Name -eq 'TraceWmi') {
                $filter = 'fixture-filter'
            }
            Add-ApplicabilityObservation $first Enabled 'Enabled:first' $enabled -Throw:($Name -eq 'EnabledGetter')
            Add-ApplicabilityObservation $second Enabled 'Enabled:second' $false
            Add-ApplicabilityObservation $analysis AssumeGpoApplicable Assume $true
            Add-ApplicabilityObservation $observedGpo Flags Flags 0
            Add-ApplicabilityObservation $observedGpo Links Links @($first, $second)
            Add-ApplicabilityObservation $observedGpo WmiFilter WmiFilter $filter
            $parameters.Gpo = $observedGpo
            $profile.Analysis = $analysis
            $trace = @('Flags', 'Links', 'Enabled:first', 'Enabled:second')
            if ($Name -eq 'TraceDisabled') {
                $parameters.Disabled = $true
                $trace = @('Flags')
                $value = 'NotApplicable'
            }
            elseif ($Name -eq 'TraceLinksDisabled') {
                $value = 'NotApplicable'
            }
            elseif ($Name -eq 'TraceTargeted') {
                $parameters.Targeted = $true
                $value = 'Unknown'
            }
            elseif ($Name -eq 'TraceWmi') {
                $trace += 'WmiFilter'
                $value = 'Unknown'
            }
            elseif ($Name -eq 'TraceAll') {
                $trace += @('WmiFilter', 'Assume')
            }
        }
        'InvalidFlags' {
            $gpo.Flags = 'fixture bad flags'
        }
        'OverflowFlags' {
            $gpo.Flags = [long]2147483648
        }
        default {
            throw "Unknown applicability fixture input $Name."
        }
    }
    @{
        Parameters = $parameters
        Value = $value
        Trace = $trace
    }
}

function Get-ApplicabilityDiagnostic([Management.Automation.ErrorRecord]$Item) {
    $cause = $Item.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Type = $Item.Exception.GetType().FullName
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Invoke-ApplicabilityCapture([string]$Name, [string]$Route, [string]$Action, [bool]$Catch, $Evaluator) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalApplicability))
    }
    $sample = New-ApplicabilitySample $Name
    $parameters = $sample.Parameters
    $ErrorActionPreference = $Action
    $global:GpoApplicabilityFixtureTrace = [Collections.Generic.List[string]]::new()
    $global:Error.Clear()
    $operation = {
        if ($Route -eq 'Direct') {
            if ($parameters.ContainsKey('Targeted') -or $parameters.ContainsKey('Disabled')) {
                $Evaluator.GetApplicability($parameters['Gpo'], $parameters['Scope'], $parameters['Profile'],
                    [bool]$parameters['Targeted'], [bool]$parameters['Disabled'])
            }
            else {
                $Evaluator.GetApplicability($parameters['Gpo'], $parameters['Scope'], $parameters['Profile'])
            }
        }
        else {
            Get-ADAnalyzerPolicyApplicability @parameters
        }
    }
    $caughtError = $null
    $output = @()
    if ($Catch) {
        try {
            $output = @(& $operation 2>&1)
        }
        catch {
            $caughtError = Get-ApplicabilityDiagnostic $_
        }
    }
    else {
        $output = @(& $operation 2>&1)
    }
    $globalErrors = @($global:Error | ForEach-Object { Get-ApplicabilityDiagnostic $_ })
    $stream = @($output | ForEach-Object {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                Get-ApplicabilityDiagnostic $_
            }
            else {
                [pscustomobject]@{
                    Type = $_.GetType().FullName
                    Value = $_
                }
            }
        })
    [pscustomobject]@{
        Stream = $stream
        Caught = $caughtError
        GlobalErrors = $globalErrors
        Trace = $global:GpoApplicabilityFixtureTrace.ToArray()
    }
}

function Invoke-ApplicabilityChild([string]$Name, [bool]$Frozen) {
    $engine = (Get-Process -Id $PID).Path
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Uncaught', '-Fault', $Name)
    if ($Frozen) {
        $arguments += '-Original'
    }
    $ErrorActionPreference = 'Continue'
    $lines = @(& $engine @arguments 2>&1 | ForEach-Object { [string]$_ })
    [pscustomobject]@{
        Exit = $LASTEXITCODE
        Lines = @($lines | Where-Object { $_ -match '\S' })
    }
}

$count = 0
switch ($Case) {
    'VerifyOriginal' {
        $path = Join-Path $root 'bin/ADPolicyAnalysis.ps1'
        Assert-Applicability ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ieq
            '3a9e01d80f8619a8460ef383507508aa2d217c56fca24e5223ad63bbc6673c47') 'Accepted U-089 policy file changed.'
        $body = Get-ApplicabilityDefinition ([IO.File]::ReadAllText($path))
        Assert-Applicability ((Get-ApplicabilityHash $body.Extent.Text) -ieq $script:ApplicabilityHash) 'Accepted applicability function changed.'
        $count = 2
    }
    { $_ -in 'Records', 'Direct' } {
        Assert-ApplicabilityBinding
        $route = 'Command'
        $evaluator = $null
        if ($Case -eq 'Direct') {

            function Get-ADAnalyzerPolicyApplicability {
                throw 'Direct applicability delegated to the compatibility command.'
            }
            $evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
            $route = 'Direct'
        }
        foreach ($name in $script:Records) {
            $sample = New-ApplicabilitySample $name
            $expected = Invoke-ApplicabilityCapture $name 'Original' 'Stop' $true $null
            $actual = Invoke-ApplicabilityCapture $name $route 'Stop' $true $evaluator
            Assert-Applicability ($null -eq $expected.Caught -and $expected.Stream.Count -eq 1 -and
                $expected.Stream[0].Type -ceq 'System.String') "Frozen $name did not return one string."
            if ($null -ne $sample.Value) {
                Assert-Applicability ($expected.Stream[0].Value -ceq $sample.Value) "Frozen $name returned the wrong status."
            }
            Assert-ApplicabilitySame $sample.Trace $expected.Trace "Frozen $name getter order"
            Assert-ApplicabilitySame $expected $actual "$Case/$name"
            $count++
        }
        if ($Case -eq 'Direct') {
            $fresh = [ADAnalyzerGpoPolicyEvaluator]::new()
            $profile = @{
                Analysis = @{
                    AssumeGpoApplicable = $true
                }
            }
            Assert-Applicability ($evaluator.GetApplicability(@{}, 'Computer', $profile, $true, $true) -ceq 'NotApplicable' -and
                $evaluator.GetApplicability(@{}, 'Computer', $profile) -ceq 'Applicable' -and
                $fresh.GetApplicability(@{}, 'Computer', $profile) -ceq 'Applicable' -and
                $profile.Analysis.AssumeGpoApplicable -eq $true) 'Reused applicability evaluator retained state or changed its profile.'
            $count++

            $expected = Invoke-ApplicabilityCapture 'InvalidFlags' 'Original' 'Stop' $true $null
            $failed = Invoke-ApplicabilityCapture 'InvalidFlags' 'Direct' 'Stop' $true $evaluator
            Assert-Applicability ($null -ne $expected.Caught -and $null -ne $failed.Caught -and
                $failed.Caught.Message -ceq $expected.Caught.Message -and
                $failed.Stream.Count -eq 0) 'Direct applicability did not surface the native invalid flag cause.'
            $count++
        }
    }
    'Faults' {
        foreach ($name in $script:Faults) {
            foreach ($action in @('Continue', 'Stop')) {
                $expected = Invoke-ApplicabilityCapture $name 'Original' $action $true $null
                $actual = Invoke-ApplicabilityCapture $name 'Command' $action $true $null
                if ($name -ne 'EnabledGetter') {
                    Assert-Applicability ($null -ne $expected.Caught -and $expected.Caught.Id -like 'InvalidCast*' -and
                        $expected.Stream.Count -eq 0) "Frozen caught $name/$action did not reach the native cast failure."
                }
                else {
                    Assert-Applicability (@($expected.GlobalErrors | Where-Object Message `
                                -eq 'fixture Enabled getter').Count -gt 0) 'Frozen Enabled getter did not exercise the synthetic failure.'
                }
                Assert-ApplicabilitySame $expected $actual "Caught $name/$action"
                $count++

                if ($action -eq 'Continue') {
                    $expected = Invoke-ApplicabilityCapture $name 'Original' $action $false $null
                    $actual = Invoke-ApplicabilityCapture $name 'Command' $action $false $null
                    if ($name -ne 'EnabledGetter') {
                        Assert-Applicability ($expected.Stream.Count -eq 2 -and $expected.Stream[0].Id -like 'InvalidCast*' -and
                            $expected.Stream[1].Value -ceq 'Applicable') "Frozen uncaught $name did not emit its error and result in order."
                    }
                }
                else {
                    $expected = Invoke-ApplicabilityChild $name $true
                    $actual = Invoke-ApplicabilityChild $name $false
                    Assert-Applicability ($expected.Lines[0] -ceq "START $name") "Frozen process did not begin $name."
                    if ($name -ne 'EnabledGetter') {
                        Assert-Applicability ($expected.Exit -ne 0 -and
                            ($expected.Lines -join ' ') -notmatch 'RETURNED|APPLICABILITY ') "Frozen uncaught $name/Stop returned a status."
                    }
                }
                Assert-ApplicabilitySame $expected $actual "Uncaught $name/$action"
                $count++
            }
        }
    }
    'Uncaught' {
        if ($Original) {
            . ([scriptblock]::Create($script:OriginalApplicability))
        }
        $global:GpoApplicabilityFixtureTrace = [Collections.Generic.List[string]]::new()
        $parameters = (New-ApplicabilitySample $Fault).Parameters
        $ErrorView = 'CategoryView'
        Write-Output "START $Fault"
        Get-ADAnalyzerPolicyApplicability @parameters | ForEach-Object { Write-Output "APPLICABILITY $_" }
        Write-Output 'RETURNED'
    }
}
Write-Host "PASS GPO applicability $Case $count"
