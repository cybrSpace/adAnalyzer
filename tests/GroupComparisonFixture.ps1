[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [ValidateSet('Comparison', 'Inert', 'Sets', 'Connections', 'Validation', 'Failures', 'Class', 'Cli')]
    [string]$Mode = 'Comparison'
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$path = Join-Path $RepositoryRoot 'etc/Start-GroupCompare.ps1'
$global:GroupComparisonFixture = @{
    Calls = [Collections.Generic.List[object]]::new()
    Groups = @{}
    Names = @{}
    Fault = ''
    FaultIdentity = ''
}

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

function Reset-Fixture {
    $global:GroupComparisonFixture.Calls.Clear()
    $global:GroupComparisonFixture.Groups = @{
        'DL-Desktop-Support-Z' = @(0..99 | ForEach-Object { "CN=Member$_,DC=example,DC=invalid" })
        'GL-Desktop-Support-Z' = @(0..49 | ForEach-Object { "CN=Member$_,DC=example,DC=invalid" })
    }
    $global:GroupComparisonFixture.Names = @{}
    foreach ($number in 0..99) {
        $global:GroupComparisonFixture.Names["CN=Member$number,DC=example,DC=invalid"] = "sam$number"
    }
    $global:GroupComparisonFixture.Fault = ''
    $global:GroupComparisonFixture.FaultIdentity = ''
}

function Import-Module {
    [CmdletBinding()]
    param(
        $Name,
        $Scope

    )
    Assert-Equal (Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll') $Name
    Assert-Equal 'Local' $Scope
    Assert-Equal 'Stop' ([string]$PSBoundParameters.ErrorAction)
    $global:GroupComparisonFixture.Calls.Add(@{
            Kind = 'Import'
        })
}

function Invoke-FixtureFault([string]$Identity) {
    if ($Identity -ne $global:GroupComparisonFixture.FaultIdentity) {
        return $false
    }
    switch ($global:GroupComparisonFixture.Fault) {
        'Throw' {
            throw 'Fixture lookup failed'
        }
        'Error' {
            Write-Error 'Fixture nonterminating lookup error'
        }
        'Missing' {
            return $true
        }
        'Multiple' {
            return $true
        }
        'Unnamed' {
            return $true
        }
    }
    return $false
}

function Get-ADGroup {
    [CmdletBinding()]
    param(
        $Identity,
        [Alias('pr')]$Properties,
        $Server,
        [pscredential]$Credential

    )
    if ($global:GroupComparisonFixture.Calls.Count -gt 250) {
        throw 'Fixture query bound exceeded'
    }
    $call = @{
        Kind = 'Group'
    }
    foreach ($key in $PSBoundParameters.Keys) {
        $call[$key] = $PSBoundParameters[$key]
    }
    $global:GroupComparisonFixture.Calls.Add($call)
    if (Invoke-FixtureFault $Identity) {
        if ($global:GroupComparisonFixture.Fault -eq 'Multiple') {
            [pscustomobject]@{
                Member = @()
            }
            [pscustomobject]@{
                Member = @()
            }
        }
        return
    }
    if (-not $global:GroupComparisonFixture.Groups.ContainsKey($Identity)) {
        throw 'Unexpected group identity'
    }
    [pscustomobject]@{
        Member = $global:GroupComparisonFixture.Groups[$Identity]
    }
}

function Get-ADObject {
    [CmdletBinding()]
    param(
        $Identity,
        $Properties,
        $Server,
        [pscredential]$Credential

    )
    $call = @{
        Kind = 'Object'
    }
    foreach ($key in $PSBoundParameters.Keys) {
        $call[$key] = $PSBoundParameters[$key]
    }
    $global:GroupComparisonFixture.Calls.Add($call)
    if (Invoke-FixtureFault $Identity) {
        if ($global:GroupComparisonFixture.Fault -eq 'Multiple') {
            [pscustomobject]@{
                SamAccountName = 'ambiguous-a'
            }
            [pscustomobject]@{
                SamAccountName = 'ambiguous-b'
            }
        }
        elseif ($global:GroupComparisonFixture.Fault -eq 'Unnamed') {
            [pscustomobject]@{
                SamAccountName = ''
            }
        }
        return
    }
    if (-not $global:GroupComparisonFixture.Names.ContainsKey($Identity)) {
        throw 'Unexpected member identity'
    }
    [pscustomobject]@{
        SamAccountName = $global:GroupComparisonFixture.Names[$Identity]
    }
}

Reset-Fixture
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
Assert-Equal 0 $errors.Count
$function = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-ADAnalyzerGroupMemberDifference'
    }, $true)

if ($null -eq $function) {
    # Reproduce the original implementation only under the synthetic readers above.
    $rows = @(& $path)
    Assert-Equal 50 $rows.Count
    Assert-Equal ((50..99 | ForEach-Object { "sam$_" }) -join '|') ($rows -join '|')
    Assert-Equal 2 @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -eq 'Group' }).Count
    throw 'The explicit comparison interface is missing'
}

. $path
Assert-Equal 0 $global:GroupComparisonFixture.Calls.Count
$arguments = @{
    SourceGroup = 'DL-Desktop-Support-Z'
    ReferenceGroup = 'GL-Desktop-Support-Z'
}

switch ($Mode) {
    'Inert' {
        Assert-Equal 0 $global:GroupComparisonFixture.Calls.Count
    }
    'Comparison' {
        $rows = @(Get-ADAnalyzerGroupMemberDifference @arguments)
        Assert-Equal 50 $rows.Count
        Assert-Equal ((50..99 | ForEach-Object { "sam$_" }) -join '|') ($rows -join '|')
        Assert-Equal 2 @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -eq 'Group' }).Count
        Assert-Equal 50 @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -eq 'Object' }).Count
        foreach ($call in @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -ne 'Import' })) {
            Assert-Equal 'Stop' ([string]$call.ErrorAction)
            $expectedProperty = if ($call.Kind -eq 'Group') {
                'Member'
            }
            else {
                'SamAccountName'
            }
            Assert-Equal $expectedProperty ([string]$call.Properties)
        }
    }
    'Sets' {
        foreach ($members in @(@(), @('CN=Member0,DC=example,DC=invalid'))) {
            $global:GroupComparisonFixture.Groups[$arguments.SourceGroup] = $members
            $global:GroupComparisonFixture.Groups[$arguments.ReferenceGroup] = $members
            Assert-Equal 0 @(Get-ADAnalyzerGroupMemberDifference @arguments).Count
        }
        $global:GroupComparisonFixture.Groups[$arguments.SourceGroup] = @(
            'CN=MEMBER0,DC=example,DC=invalid'
            'CN=Member1,DC=example,DC=invalid'
            'CN=Member1,DC=example,DC=invalid'
        )
        $global:GroupComparisonFixture.Groups[$arguments.ReferenceGroup] = 'cn=member0,dc=example,dc=invalid'
        $global:GroupComparisonFixture.Names['CN=Member1,DC=example,DC=invalid'] = 'membre-' + [char]0x00E9
        Assert-Equal (('membre-' + [char]0x00E9 + '|') + 'membre-' + [char]0x00E9) ((Get-ADAnalyzerGroupMemberDifference @arguments) -join '|')
        $global:GroupComparisonFixture.Groups[$arguments.SourceGroup] = 'CN=Member2,DC=example,DC=invalid'
        $global:GroupComparisonFixture.Groups[$arguments.ReferenceGroup] = $null
        Assert-Equal 'sam2' (Get-ADAnalyzerGroupMemberDifference @arguments)
    }
    'Connections' {
        $credential = [pscredential]::new('fixture', (ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
        foreach ($selected in @($null, [pscredential]::Empty, $credential)) {
            Reset-Fixture
            $null = Get-ADAnalyzerGroupMemberDifference @arguments -Server 'dc.example.invalid' -Credential $selected
            foreach ($call in @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -ne 'Import' })) {
                Assert-Equal 'dc.example.invalid' $call.Server
                Assert-Equal ($null -ne $selected -and $selected -ne [pscredential]::Empty) $call.ContainsKey('Credential')
                if ($call.ContainsKey('Credential')) {
                    Assert-Equal $true ([object]::ReferenceEquals($credential, $call.Credential))
                }
            }
        }
        Reset-Fixture
        $source = "CN=Source'*)(,DC=example,DC=invalid"
        $reference = 'CN=Reference[1],DC=example,DC=invalid'
        $global:GroupComparisonFixture.Groups[$source] = 'CN=Member1,DC=example,DC=invalid'
        $global:GroupComparisonFixture.Groups[$reference] = @()
        Assert-Equal 'sam1' (Get-ADAnalyzerGroupMemberDifference -SourceGroup $source -ReferenceGroup $reference)
        $calls = @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -ne 'Import' })
        Assert-Equal $source $calls[0].Identity
        Assert-Equal $reference $calls[1].Identity
        foreach ($call in $calls) {
            Assert-Equal $false $call.ContainsKey('Server')
            Assert-Equal $false $call.ContainsKey('Credential')
        }
    }
    'Validation' {
        foreach ($invalid in @($null, '', ' ')) {
            Assert-Fails { Get-ADAnalyzerGroupMemberDifference -SourceGroup $invalid -ReferenceGroup 'reference' }
            Assert-Fails { Get-ADAnalyzerGroupMemberDifference -SourceGroup 'source' -ReferenceGroup $invalid }
        }
        Assert-Equal 0 $global:GroupComparisonFixture.Calls.Count
        $global:GroupComparisonFixture.Groups[$arguments.SourceGroup] = @('CN=Member0,DC=example,DC=invalid', ' ')
        Assert-Fails { Get-ADAnalyzerGroupMemberDifference @arguments }
        Assert-Equal 0 @($global:GroupComparisonFixture.Calls | Where-Object { $_.Kind -eq 'Object' }).Count
    }
    'Failures' {
        foreach ($preference in @('Continue', 'Stop')) {
            $ErrorActionPreference = $preference
            foreach ($identity in @($arguments.SourceGroup, $arguments.ReferenceGroup, 'CN=Member99,DC=example,DC=invalid')) {
                foreach ($fault in @('Missing', 'Multiple', 'Throw', 'Error', 'Unnamed')) {
                    if ($fault -eq 'Unnamed' -and $identity -notlike 'CN=*') {
                        continue
                    }
                    Reset-Fixture
                    $global:GroupComparisonFixture.Fault = $fault
                    $global:GroupComparisonFixture.FaultIdentity = $identity
                    Assert-Fails { Get-ADAnalyzerGroupMemberDifference @arguments }
                }
            }
        }
    }
    'Class' {
        $type = 'ADAnalyzerGroupComparison' -as [type]
        Assert-Equal $false ($null -eq $type)
        Assert-Fails { $type::new($null, 'reference') }
        Assert-Fails { $type::new('source', '') }
        $first = $type::new($arguments.SourceGroup, $arguments.ReferenceGroup)
        $second = $type::new($arguments.SourceGroup, $arguments.ReferenceGroup)
        $connection = @{
            Server = 'dc.example.invalid'
        }
        $groupReader = Get-Command Get-ADGroup
        $objectReader = Get-Command Get-ADObject
        Assert-Equal 50 @($first.Compare($groupReader, $objectReader, $connection)).Count
        Assert-Equal 1 $connection.Count
        $global:GroupComparisonFixture.Groups[$arguments.SourceGroup] = @()
        Assert-Equal 0 @($second.Compare($groupReader, $objectReader, @{})).Count
        Assert-Fails { $first.Compare($null, $objectReader, @{}) }
        Assert-Fails { $first.Compare($groupReader, $null, @{}) }
        Assert-Fails { $first.Compare($groupReader, $objectReader, $null) }
        $serialized = ConvertTo-Json -InputObject $first -Compress
        Assert-Equal $false ($serialized -match 'Credential|fixture-only|CommandInfo|SessionState')
        Assert-Equal 0 @($first.PSObject.Properties).Count
        Assert-Equal 0 @($first.Compare($groupReader, $objectReader, @{})).Count
    }
    'Cli' {
        Assert-Fails { & $path }
        Assert-Equal 0 $global:GroupComparisonFixture.Calls.Count
        Assert-Equal 50 @(& $path @arguments).Count
    }
}

Write-Output ('PASS group comparison ' + $Mode)
