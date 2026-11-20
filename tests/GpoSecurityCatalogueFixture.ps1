[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Records', 'Stream', 'Faults', 'Direct', 'Uncaught')]
    [string]$Case = 'Records',
    [ValidateSet('Server', 'Client')]
    [string]$Fault = 'Server',
    [switch]$Original
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'bin/ADAnalyzer.ps1')

# Exact accepted U-092 catalogue. Normalize only platform line endings for its hash.
$script:OriginalCatalogue = @'
function Get-ADAnalyzerSecuritySpecifications {
    param([hashtable]$Profile)
    $definitions = @(
        ,
        @('RequireSecuritySignature',
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
            'Microsoft network server: Digitally sign communications (always)',
            $true)
        ,
        @('EnableSecuritySignature',
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
            'Microsoft network server: Digitally sign communications (if client agrees)',
            $true)
        ,
        @('RequireSecuritySignature',
            'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
            'Microsoft network client: Digitally sign communications (always)',
            $true)
        ,
        @('EnableSecuritySignature',
            'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
            'Microsoft network client: Digitally sign communications (if server agrees)',
            $true)
        ,
        @('EnablePlainTextPassword',
            'SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters',
            'Microsoft network client: Send unencrypted password to third-party SMB servers',
            $false)
        ,
        @('RequireSignOrSeal',
            'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters',
            'Domain member: Digitally encrypt or sign secure channel data (always)',
            $true)
        ,
        @('SealSecureChannel',
            'SYSTEM\CurrentControlSet\Services\NetLogon\Parameters',
            'Domain member: Digitally encrypt secure channel data (when possible)',
            $true)
        ,
        @('EveryoneIncludesAnonymous',
            'SYSTEM\CurrentControlSet\Control\Lsa',
            'Network access: Let Everyone permissions apply to anonymous users',
            $false)
        ,
        @('RestrictAnonymousSAM',
            'SYSTEM\CurrentControlSet\Control\Lsa',
            'Network access: Do not allow anonymous enumeration of SAM accounts',
            $true)
        ,
        @('RestrictAnonymous',
            'SYSTEM\CurrentControlSet\Control\Lsa',
            'Network access: Do not allow anonymous enumeration of SAM accounts and shares',
            $true)
        ,
        @('RestrictNullSessAccess',
            'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters',
            'Network access: Restrict anonymous access to Named Pipes and Shares',
            $true)
        ,
        @('FilterAdministratorToken',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
            'User Account Control: Admin Approval Mode for the Built-in Administrator account',
            $true)
        ,
        @('EnableUIADesktopToggle',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
            'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop',
            $false)
        ,
        @('EnableInstallerDetection',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
            'User Account Control: Detect application installations and prompt for elevation',
            $true)
        ,
        @('EnableLUA',
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
            'User Account Control: Run all administrators in Admin Approval Mode',
            $true)
    )
    foreach ($definition in $definitions) {
        [pscustomobject]@{
            Id = $definition[1] + '\' + $definition[0]
            Key = $definition[1]
            ValueName = $definition[0]
            Name = $definition[2]
            Kind = 'Boolean'
            Type = 4
            Expected = $definition[3]
        }
    }
    @(
        [pscustomobject]@{
            Id = 'Lsa.LmCompatibilityLevel'
            Key = 'SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'LmCompatibilityLevel'
            Name = 'Network security: LAN Manager authentication level'
            Kind = 'Lm'
            Type = 4
            Expected = (Get-ADAnalyzerPolicyProfileValue $Profile MinimumLmCompatibilityLevel 5)
        }
        [pscustomobject]@{
            Id = 'NTDS.LDAPServerIntegrity'
            Key = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            ValueName = 'LDAPServerIntegrity'
            Name = 'Domain controller: LDAP server signing requirements'
            Kind = 'LdapServer'
            Type = 4
            Expected = $(if (Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapServerSigning $true) {
                    2
                }
                else {
                    'Any valid value'
                })
        }
        [pscustomobject]@{
            Id = 'LDAP.LDAPClientIntegrity'
            Key = 'SYSTEM\CurrentControlSet\Services\LDAP'
            ValueName = 'LDAPClientIntegrity'
            Name = 'Network security: LDAP client signing requirements'
            Kind = 'LdapClient'
            Type = 4
            Expected = $(if (Get-ADAnalyzerPolicyProfileValue $Profile RequireLdapClientSigning $true) {
                    2
                }
                else {
                    'Any valid value'
                })
        }
        [pscustomobject]@{
            Id = 'UAC.ConsentPromptBehaviorAdmin'
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName = 'ConsentPromptBehaviorAdmin'
            Name = 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
            Kind = 'UacPrompt'
            Type = 4
            Expected = 'Prompt (1-5)'
        }
        [pscustomobject]@{
            Id = 'Server.NullSessionPipes'
            Key = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'NullSessionPipes'
            Name = 'Network access: Named Pipes that can be accessed anonymously'
            Kind = 'Pipes'
            Type = 7
            Expected = @(Get-ADAnalyzerPolicyProfileValue $Profile AllowedAnonymousPipes @('LSARPC', 'NETLOGON', 'SAMR'))
        }
        [pscustomobject]@{
            Id = 'Server.NullSessionShares'
            Key = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName = 'NullSessionShares'
            Name = 'Network access: Shares that can be access anonymously'
            Kind = 'Shares'
            Type = 7
            Expected = @()
        }
        [pscustomobject]@{
            Id = 'LSAAnonymousNameLookup'
            Key = $null
            ValueName = $null
            Name = 'Network access: Allow anonymous SID/Name translation'
            Kind = 'Boolean'
            Type = $null
            Expected = $false
        }
    )
}
'@
$script:CatalogueHash = 'a28a668f2e17baa930f7d56fbea76417468361a3e27a2c98425b495ea2147800'
$script:Fields = 'Id', 'Key', 'ValueName', 'Name', 'Kind', 'Type', 'Expected'
$script:Observations = 'MinimumLmCompatibilityLevel', 'RequireLdapServerSigning', 'RequireLdapClientSigning', 'AllowedAnonymousPipes'
$script:Records = 'Omitted', 'Null', 'Empty', 'Default', 'NullPolicy', 'Typed', 'NullOptions', 'EmptyPipes', 'Borrowed'

function Assert-Catalogue($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Get-CatalogueHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
        [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

Assert-Catalogue ((Get-CatalogueHash $script:OriginalCatalogue) -ieq $script:CatalogueHash) 'Frozen security catalogue source changed.'

function Get-CatalogueDefinition([string]$Text) {
    $tokens = $null
    $errors = $null
    $program = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    $definitions = @($program.EndBlock.Statements | Where-Object Name -ceq 'Get-ADAnalyzerSecuritySpecifications')
    Assert-Catalogue ($errors.Count -eq 0 -and $definitions.Count -eq 1) 'Could not isolate the exact security catalogue AST.'
    $definitions[0]
}

function Assert-CatalogueBinding {
    $frozen = Get-CatalogueDefinition $script:OriginalCatalogue
    $ast = (Get-Command Get-ADAnalyzerSecuritySpecifications -CommandType Function).ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    Assert-Catalogue ((Get-CatalogueHash $ast.ParamBlock.Extent.Text) -ceq
        (Get-CatalogueHash $frozen.Body.ParamBlock.Extent.Text)) 'Security catalogue parameter contract changed.'
}

function Assert-CatalogueSame($Expected, $Actual, [string]$Label) {
    $before = ConvertTo-Json -InputObject $Expected -Depth 14 -Compress
    $after = ConvertTo-Json -InputObject $Actual -Depth 14 -Compress
    Assert-Catalogue ($before -ceq $after) "$Label differs. Expected $before; actual $after"
}

function Get-CatalogueTyped($Value) {
    if ($null -eq $Value) {
        return [pscustomobject]@{
            Type = '<null>'
            Content = $null
        }
    }
    $type = $Value.GetType().FullName
    $content = $Value
    if ($Value -is [array]) {
        $content = @(foreach ($item in $Value) {
                Get-CatalogueTyped $item
            })
    }
    elseif ($type -ceq 'System.Management.Automation.PSCustomObject') {
        $content = @(foreach ($property in $Value.PSObject.Properties) {
                [pscustomobject]@{
                    Name = $property.Name
                    Value = (Get-CatalogueTyped $property.Value)
                }
            })
    }
    [pscustomobject]@{
        Type = $type
        Content = $content
    }
}

function New-CatalogueRecordSample([string]$Name) {
    $policy = @{}
    $profile = @{
        Policy = $policy
    }
    $borrowed = $null
    switch ($Name) {
        { $_ -in 'Omitted', 'Null' } {
            $profile = $null
        }
        'Empty' {
            $profile = @{}
        }
        'Default' {
            $profile = Get-ADAnalyzerDefaultProfile
        }
        'NullPolicy' {
            $profile.Policy = $null
        }
        'Typed' {
            $policy.MinimumLmCompatibilityLevel = [long]17
            $policy.RequireLdapServerSigning = $false
            $policy.RequireLdapClientSigning = 'false'
            $policy.AllowedAnonymousPipes = [string[]]@('fixture-first', 'fixture-last')
        }
        'NullOptions' {
            foreach ($property in $script:Observations) {
                $policy[$property] = $null
            }
        }
        'EmptyPipes' {
            $policy.AllowedAnonymousPipes = @()
        }
        'Borrowed' {
            $borrowed = [pscustomobject]@{
                FixtureMarker = 'raw catalogue value'
            }
            $policy.MinimumLmCompatibilityLevel = $borrowed
            $policy.AllowedAnonymousPipes = @($borrowed, 'fixture-pipe')
        }
        default {
            throw "Unknown catalogue record case $Name."
        }
    }
    @{
        Profile = $profile
        Borrowed = $borrowed
    }
}

function Invoke-CatalogueRecords([string]$Name, [string]$Route, $Evaluator) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalCatalogue))
    }
    $sample = New-CatalogueRecordSample $Name
    $rows = @(if ($Route -eq 'Direct') {
            $Evaluator.GetSecuritySpecifications($sample.Profile)
        }
        elseif ($Name -eq 'Omitted') {
            Get-ADAnalyzerSecuritySpecifications
        }
        else {
            Get-ADAnalyzerSecuritySpecifications -Profile $sample.Profile
        })
    Assert-Catalogue ($rows.Count -eq 22) "$Route/$Name did not return 22 catalogue records."
    Assert-Catalogue (@($rows[0..14] | Where-Object { $_.Kind -cne 'Boolean' -or
                $_.Expected -isnot [bool] }).Count -eq 0) 'Fixed prefix changed its Boolean contract.'
    Assert-Catalogue (($rows[15..21].Kind -join ',') -ceq 'Lm,LdapServer,LdapClient,UacPrompt,Pipes,Shares,Boolean') 'Configured catalogue order changed.'
    Assert-Catalogue (@($rows | Where-Object { ($_.PSObject.Properties.Name -join ',') -cne ($script:Fields -join ',') }).Count -eq 0) 'Catalogue fields changed order or shape.'
    if ($null -ne $sample.Borrowed) {
        Assert-Catalogue ([object]::ReferenceEquals($sample.Borrowed, $rows[15].Expected) -and
            [object]::ReferenceEquals($sample.Borrowed, $rows[19].Expected[0])) "$Route stripped a borrowed profile reference."
    }
    $rows
}

function New-CatalogueObservedProfile([string]$FaultSite) {
    $global:GpoCatalogueFixtureTrace = [Collections.Generic.List[string]]::new()
    $global:GpoCatalogueFixtureOptions = @{
        MinimumLmCompatibilityLevel = 5
        RequireLdapServerSigning = $true
        RequireLdapClientSigning = $true
        AllowedAnonymousPipes = @('fixture-old')
    }
    if ($FaultSite) {
        if ($null -eq ('GpoCatalogueFixtureFaultList' -as [type])) {
            Add-Type @'
using System;
using System.Collections;

public sealed class GpoCatalogueFixtureFaultList : ArrayList {
    public GpoCatalogueFixtureFaultList() {
        Add("placeholder");
    }

    public override int Count {
        get { throw new InvalidOperationException("fixture LDAP truthiness"); }
    }
}
'@
        }
        $faultValue = [object[]]::new(1)
        $faultValue[0] = [object[]]::new(1)
        $faultValue[0][0] = [GpoCatalogueFixtureFaultList]::new()
        $global:GpoCatalogueFixtureOptions['RequireLdap' + $FaultSite + 'Signing'] = $faultValue
    }
    $policy = [pscustomobject]@{}
    foreach ($property in $script:Observations) {
        $getter = {
            $global:GpoCatalogueFixtureTrace.Add($property)
            return , $global:GpoCatalogueFixtureOptions[$property]
        }.GetNewClosure()
        $policy.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new($property, $getter))
    }
    @{
        Policy = $policy
    }
}

function Invoke-CatalogueStream([int]$Take, [bool]$Frozen) {
    if ($Frozen) {
        . ([scriptblock]::Create($script:OriginalCatalogue))
    }
    $profile = New-CatalogueObservedProfile ''
    if ($Take) {
        $rows = @(Get-ADAnalyzerSecuritySpecifications $profile | Select-Object -First $Take)
    }
    else {
        $progress = @{
            Emitted = 0
        }
        $rows = @(Get-ADAnalyzerSecuritySpecifications $profile | ForEach-Object {
                $progress.Emitted++
                $global:GpoCatalogueFixtureTrace.Add('row:' + $progress.Emitted)
                if ($progress.Emitted -eq 1) {
                    $global:GpoCatalogueFixtureOptions.MinimumLmCompatibilityLevel = [long]23
                    $global:GpoCatalogueFixtureOptions.RequireLdapClientSigning = $false
                    $global:GpoCatalogueFixtureOptions.AllowedAnonymousPipes = @('fixture-prefix')
                }
                elseif ($progress.Emitted -eq 16) {
                    $global:GpoCatalogueFixtureOptions.MinimumLmCompatibilityLevel = 99
                    $global:GpoCatalogueFixtureOptions.RequireLdapClientSigning = $true
                    $global:GpoCatalogueFixtureOptions.AllowedAnonymousPipes = @('fixture-tail')
                }
                $_
            })
    }
    [pscustomobject]@{
        Rows = $rows
        Trace = $global:GpoCatalogueFixtureTrace.ToArray()
    }
}

function Get-CatalogueDiagnostic([Management.Automation.ErrorRecord]$Item) {
    $cause = $Item.Exception.GetBaseException()
    [pscustomobject]@{
        Id = $Item.FullyQualifiedErrorId
        Category = [string]$Item.CategoryInfo.Category
        Cause = $cause.GetType().FullName
        Message = $cause.Message
    }
}

function Invoke-CatalogueFault([string]$FaultSite, [string]$Route, [string]$Action, [bool]$Catch, $Evaluator) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalCatalogue))
    }
    $profile = New-CatalogueObservedProfile $FaultSite
    $ErrorActionPreference = $Action
    $global:Error.Clear()
    $stream = [Collections.Generic.List[object]]::new()
    $invoke = {
        if ($Route -eq 'Direct') {
            $Evaluator.GetSecuritySpecifications($profile)
        }
        else {
            Get-ADAnalyzerSecuritySpecifications $profile
        }
    }
    $observe = {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            $stream.Add((Get-CatalogueDiagnostic $_))
        }
        else {
            $stream.Add((Get-CatalogueTyped $_))
        }
    }
    $caught = $null
    if ($Catch) {
        try {
            & $invoke 2>&1 | ForEach-Object $observe
        }
        catch {
            $caught = Get-CatalogueDiagnostic $_
        }
    }
    else {
        & $invoke 2>&1 | ForEach-Object $observe
    }
    [pscustomobject]@{
        Stream = $stream.ToArray()
        Caught = $caught
        Trace = $global:GpoCatalogueFixtureTrace.ToArray()
        GlobalErrors = @($global:Error | ForEach-Object { Get-CatalogueDiagnostic $_ })
    }
}

function Invoke-CatalogueChild([string]$FaultSite, [bool]$Frozen) {
    $engine = (Get-Process -Id $PID).Path
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath,
        '-Case', 'Uncaught', '-Fault', $FaultSite)
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
        Assert-Catalogue ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ieq
            'd8312d0bd53231b68d03f8423038386bd953ad06f928e99b1eafbc79e08d48bd') 'Accepted U-092 policy file changed.'
        $body = Get-CatalogueDefinition ([IO.File]::ReadAllText($path))
        Assert-Catalogue ((Get-CatalogueHash $body.Extent.Text) -ieq $script:CatalogueHash) 'Accepted security catalogue function changed.'
        $count = 2
    }
    { $_ -in 'Records', 'Direct' } {
        Assert-CatalogueBinding
        $route = 'Command'
        $evaluator = $null
        if ($Case -eq 'Direct') {

            function Get-ADAnalyzerSecuritySpecifications {
                throw 'Direct catalogue delegated to the compatibility command.'
            }
            $evaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
            $route = 'Direct'
        }
        foreach ($name in $script:Records) {
            $expected = @(Invoke-CatalogueRecords $name 'Original' $null)
            $actual = @(Invoke-CatalogueRecords $name $route $evaluator)
            Assert-CatalogueSame (Get-CatalogueTyped $expected) (Get-CatalogueTyped $actual) "$Case/$name"
            $count++
        }
        if ($Case -eq 'Direct') {
            $first = $evaluator.GetSecuritySpecifications(@{})
            $first[0].Expected = $false
            $first[19].Expected[0] = 'fixture changed result'
            $next = $evaluator.GetSecuritySpecifications(@{})
            $independent = [ADAnalyzerGpoPolicyEvaluator]::new().GetSecuritySpecifications(@{})
            Assert-Catalogue ($next[0].Expected -eq $true -and $next[19].Expected[0] -ceq 'LSARPC' -and
                -not [object]::ReferenceEquals($next[0], $independent[0])) 'Reused catalogue shared a result or retained its changes.'
            Assert-CatalogueSame (Get-CatalogueTyped $next) (Get-CatalogueTyped $independent) 'Independent catalogue'
            $count++
            $expected = Invoke-CatalogueFault Server Original Stop $true $null
            $actual = Invoke-CatalogueFault Server Direct Stop $true $evaluator
            Assert-Catalogue ($null -ne $actual.Caught -and $actual.Caught.Message -ceq $expected.Caught.Message -and
                $actual.Stream.Count -eq 0) 'Direct catalogue did not surface the LDAP cause before returning its result.'
            $count++
        }
    }
    'Stream' {
        foreach ($take in @(0, 1, 15, 16)) {
            $expected = Invoke-CatalogueStream $take $true
            $actual = Invoke-CatalogueStream $take $false
            if ($take -eq 0) {
                $trace = @(1..15 | ForEach-Object { 'row:' + $_ }) + $script:Observations + @(16..22 | ForEach-Object { 'row:' + $_ })
                Assert-CatalogueSame $trace $expected.Trace 'Frozen mutation observations'
                Assert-Catalogue ($expected.Rows.Count -eq 22 -and $expected.Rows[15].Expected -is [long] -and
                    $expected.Rows[15].Expected -eq 23 -and $expected.Rows[17].Expected -ceq 'Any valid value' -and
                    $expected.Rows[19].Expected[0] -ceq 'fixture-prefix') 'Frozen catalogue did not observe prefix mutations only.'
            }
            else {
                Assert-Catalogue ($expected.Rows.Count -eq $take) "Frozen Select -First $take did not stop at its limit."
                $trace = @()
                if ($take -eq 16) {
                    $trace = $script:Observations
                }
                Assert-CatalogueSame $trace $expected.Trace "Frozen Select -First $take observations"
            }
            Assert-CatalogueSame $expected.Trace $actual.Trace "Stream $take observations"
            Assert-CatalogueSame (Get-CatalogueTyped $expected.Rows) (Get-CatalogueTyped $actual.Rows) "Stream $take rows"
            $count++
        }
    }
    'Faults' {
        foreach ($site in @('Server', 'Client')) {
            foreach ($action in @('Continue', 'Stop')) {
                $expected = Invoke-CatalogueFault $site Original $action $true $null
                $actual = Invoke-CatalogueFault $site Command $action $true $null
                Assert-Catalogue ($expected.Stream.Count -eq 15 -and $null -ne $expected.Caught -and
                    $expected.Caught.Cause -ceq 'System.InvalidOperationException' -and
                    $expected.Caught.Message -ceq 'fixture LDAP truthiness') "Frozen $site/$action did not emit its prefix and catch the LDAP error."
                Assert-CatalogueSame $expected $actual "Caught $site/$action"
                $count++
                if ($action -eq 'Continue') {
                    $expected = Invoke-CatalogueFault $site Original $action $false $null
                    $actual = Invoke-CatalogueFault $site Command $action $false $null
                    $position = 17
                    if ($site -eq 'Client') {
                        $position = 18
                    }
                    $field = $expected.Stream[$position].Content | Where-Object Name -ceq 'Expected'
                    Assert-Catalogue ($expected.Stream.Count -eq 23 -and $expected.Stream[15].Message -ceq 'fixture LDAP truthiness' -and
                        $field.Value.Type -ceq '<null>') "Frozen $site did not continue with a null LDAP expectation after the error."
                    Assert-CatalogueSame $script:Observations $expected.Trace "Frozen uncaught $site observations"
                }
                else {
                    $expected = Invoke-CatalogueChild $site $true
                    $actual = Invoke-CatalogueChild $site $false
                    Assert-Catalogue ($expected.Exit -ne 0 -and $expected.Lines[0] -ceq "START $site" -and
                        @($expected.Lines | Where-Object { $_ -ceq 'CATALOGUE-ROW' }).Count -eq 15 -and
                        'RETURNED' -cnotin $expected.Lines) "Frozen $site Stop omitted its prefix or returned after the error."
                }
                Assert-CatalogueSame $expected $actual "Uncaught $site/$action"
                $count++
            }
        }
    }
    'Uncaught' {
        if ($Original) {
            . ([scriptblock]::Create($script:OriginalCatalogue))
        }
        $profile = New-CatalogueObservedProfile $Fault
        $ErrorView = 'CategoryView'
        Write-Output "START $Fault"
        Get-ADAnalyzerSecuritySpecifications $profile | ForEach-Object { Write-Output 'CATALOGUE-ROW' }
        Write-Output 'RETURNED'
    }
}
Write-Host "PASS GPO security catalogue $Case $count"
