[CmdletBinding()]
param(
    [ValidateSet('Probe', 'Ordinary', 'Shadows', 'Records', 'SafeData', 'Export',
        'Disposed', 'GetterIsolation', 'ExplicitCollection')]
    [string]$Case = 'Ordinary'
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
$script:Marker = 'NATIVE_VALUE_PAYLOAD_077'
$script:Owned = [Collections.Generic.List[IDisposable]]::new()
$script:Sink = [Collections.Generic.List[object]]::new()
$script:Scenarios = 0
$script:GetterCalls = 0
$script:OwnedTypeData = [Collections.Generic.List[string]]::new()

function Assert-NativeValue($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-NativeSecure([bool]$Present) {
    $value = [Security.SecureString]::new()
    if ($Present) {
        $value.AppendChar('x')
    }
    $script:Owned.Add($value)
    return $value
}

function Add-NativeShadow(
    $Value,
    [string]$Name,
    $Shadow,
    [Management.Automation.PSMemberTypes]$MemberType = 'NoteProperty'
) {
    # A private type name avoids overriding Windows PowerShell's protected
    # System.Array Count alias. Only this disposable test value is affected.
    $wrapped = [Management.Automation.PSObject]::AsPSObject($Value)
    $typeName = 'ADAnalyzer.NativePresenceFixture.' + [guid]::NewGuid().ToString('N')
    $wrapped.PSTypeNames.Insert(0, $typeName)
    Update-TypeData -TypeName $typeName -MemberType $MemberType -MemberName $Name -Value $Shadow
    $script:OwnedTypeData.Add($typeName)
    return , $wrapped
}

function New-NativeCase([string]$Name, $Value, [bool]$Expected) {
    [pscustomobject]@{
        Name = $Name
        Value = $Value
        Expected = $Expected
    }
}

function Get-NativeOrdinaryCases {
    New-NativeCase Null $null $false
    New-NativeCase EmptyString '' $false
    New-NativeCase Whitespace ' ' $true
    New-NativeCase Text 'ordinary' $true
    New-NativeCase False $false $true
    New-NativeCase Zero 0 $true
    New-NativeCase EmptyArray @() $false
    New-NativeCase Array @(1) $true
    New-NativeCase EmptyMap @{} $false
    New-NativeCase Map @{
        Item = 1
    } $true
    New-NativeCase EmptyOrdered ([ordered]@{}) $false
    New-NativeCase Ordered ([ordered]@{
            Item = 1
        }) $true
    New-NativeCase EmptyList ([Collections.ArrayList]::new()) $false
    $list = [Collections.ArrayList]::new()
    $null = $list.Add(1)
    New-NativeCase List $list $true
    New-NativeCase EmptyGeneric ([Collections.Generic.Dictionary[string, object]]::new()) $false
    $map = [Collections.Generic.Dictionary[string, object]]::new()
    $map.Add('Item', 1)
    New-NativeCase Generic $map $true
    New-NativeCase EmptySecure (New-NativeSecure $false) $false
    New-NativeCase Secure (New-NativeSecure $true) $true
    New-NativeCase EmptyCredential ([pscredential]::new('fixture', (New-NativeSecure $false))) $false
    New-NativeCase Credential ([pscredential]::new('fixture', (New-NativeSecure $true))) $true
}

function Get-NativeShadowCases {
    New-NativeCase MapCount @{
        Count = 0
        Item = $script:Marker
    } $true
    New-NativeCase OrderedCount ([ordered]@{
            Count = 0
            Item = $script:Marker
        }) $true
    $map = [Collections.Generic.Dictionary[string, object]]::new()
    $map.Add('Count', 0)
    $map.Add('Item', $script:Marker)
    New-NativeCase GenericCount $map $true
    New-NativeCase ArrayCountZero (Add-NativeShadow ([object[]]@(1, 2)) Count 0) $true
    New-NativeCase EmptyArrayCountPositive (Add-NativeShadow ([object[]]@()) Count 5) $false
    $list = [Collections.ArrayList]::new()
    $null = $list.Add(1)
    New-NativeCase ListCountZero (Add-NativeShadow $list Count 0) $true
    New-NativeCase EmptyListCountPositive (Add-NativeShadow ([Collections.ArrayList]::new()) Count 5) $false
    New-NativeCase SecureLengthZero (Add-NativeShadow (New-NativeSecure $true) Length 0) $true
    New-NativeCase EmptySecureLengthPositive (Add-NativeShadow (New-NativeSecure $false) Length 5) $false
    New-NativeCase StringLengthZero (Add-NativeShadow $script:Marker Length 0) $true
    New-NativeCase EmptyStringLengthPositive (Add-NativeShadow '' Length 5) $false
    $credential = [pscredential]::new('fixture', (New-NativeSecure $true))
    New-NativeCase CredentialEmptyShadow (Add-NativeShadow $credential Password (New-NativeSecure $false)) $true
    $credential = [pscredential]::new('fixture', (New-NativeSecure $false))
    New-NativeCase EmptyCredentialFilledShadow (Add-NativeShadow $credential Password (New-NativeSecure $true)) $false
    $password = New-NativeSecure $true
    $null = Add-NativeShadow $password Length 0
    New-NativeCase CredentialPasswordLengthZero ([pscredential]::new('fixture', $password)) $true
    $password = New-NativeSecure $false
    $null = Add-NativeShadow $password Length 5
    New-NativeCase EmptyCredentialPasswordLengthPositive ([pscredential]::new('fixture', $password)) $false
}

function Get-NativeState($Value) {
    if ($null -eq $Value) {
        return 'null'
    }
    $native = if ($Value -is [pscredential]) {
        $Value.PSBase.Password.PSBase.Length
    }
    elseif ($Value -is [Security.SecureString] -or $Value -is [string]) {
        $Value.PSBase.Length
    }
    elseif ($Value -is [Collections.ICollection]) {
        [Collections.ICollection].GetProperty('Count').GetValue($Value, $null)
    }
    else {
        '<scalar>'
    }
    $members = @(
        foreach ($property in $Value.PSObject.Properties) {
            [pscustomobject]@{
                Name = $property.Name
                MemberType = [string]$property.MemberType
            }
        }
    )
    ConvertTo-Json -InputObject ([pscustomobject]@{
            Type = $Value.GetType().FullName
            Native = $native
            Members = $members
            TypeNames = @($Value.PSTypeNames)
        }) -Depth 10 -Compress
}

function Write-ADAnalyzerFile {
    param(
        $Path,
        [AllowEmptyString()][string]$Content

    )
    $script:Sink.Add([pscustomobject]@{
            Path = $Path
            Content = $Content
            HasPayload = $Content.Contains($script:Marker)
        })
    $Path
}

function Invoke-NativeExport($Value, [string]$Format = 'All') {
    $assessment = @{
        Findings = @(
            @{
                RuleId = 'FIXTURE'
                Evidence = @{
                    Name = 'Password'
                    Value = $Value
                }
            }
        )
    }
    $path = 'memory-only-native-value'
    if ($Format -ne 'All') {
        $path += '.' + $Format.ToLowerInvariant()
    }
    $parameters = @{
        Assessment = $assessment
        Path = $path
        Format = $Format
        Confirm = $false
    }
    Export-ADAnalyzerAssessment @parameters
}

try {
    if ($Case -eq 'Probe') {
        $body = (Get-Command Test-ADAnalyzerSecretPresence).ScriptBlock.ToString()
        Assert-NativeValue ($body.Contains('$Value.Count -gt 0')) 'Capture native-presence defects before correction.'
        foreach ($sample in @(Get-NativeShadowCases)) {
            $actual = Test-ADAnalyzerSecretPresence $sample.Value
            $record = ConvertTo-ADAnalyzerSecretRecord ([pscustomobject]@{
                    Name = 'Password'
                    Value = $sample.Value
                })
            $safe = ConvertTo-ADAnalyzerSafeData -InputObject @{
                Name = 'Password'
                Value = $sample.Value
            }
            $script:Sink.Clear()
            $rows = @(Invoke-NativeExport $sample.Value)
            $json = @($script:Sink | Where-Object { $_.Path -like '*.json' })[0].Content | ConvertFrom-Json
            Write-Host ('PROBE native presence {0}; Expected={1}; Predicate={2}; Record={3}; Deep={4}; Json={5}; Writes={6}; PayloadWrites={7}' -f
                $sample.Name, $sample.Expected, $actual, $record.SecretPresent, $safe.SecretPresent,
                $json.Findings[0].Evidence.SecretPresent, $script:Sink.Count,
                @($script:Sink | Where-Object HasPayload).Count)
        }
        return
    }
    switch ($Case) {
        { $_ -in @('Ordinary', 'Shadows') } {
            $samples = if ($Case -eq 'Ordinary') {
                @(Get-NativeOrdinaryCases)
            }
            else {
                @(Get-NativeShadowCases)
            }
            foreach ($sample in $samples) {
                $before = Get-NativeState $sample.Value
                foreach ($repeat in 1..2) {
                    $rows = @(Test-ADAnalyzerSecretPresence $sample.Value)
                    Assert-NativeValue ($rows.Count -eq 1 -and
                        $rows[0] -is [bool] -and
                        $rows[0] -eq $sample.Expected) ('Native presence is incorrect: ' + $sample.Name)
                }
                Assert-NativeValue ($before -ceq (Get-NativeState $sample.Value)) 'Presence changed native input state or extended member metadata.'
                $script:Scenarios++
            }
        }
        { $_ -in @('Records', 'SafeData', 'Export') } {
            foreach ($sample in @(Get-NativeShadowCases)) {
                $before = Get-NativeState $sample.Value
                $record = [pscustomobject]@{
                    Name = 'Password'
                    Value = $sample.Value
                }
                $safe = if ($Case -eq 'Records') {
                    ConvertTo-ADAnalyzerSecretRecord $record
                }
                else {
                    ConvertTo-ADAnalyzerSafeData -InputObject $record
                }
                Assert-NativeValue ($safe.SecretPresent -is [bool] -and
                    $safe.SecretPresent -eq $sample.Expected) ('Native presence was lost at projection: ' + $sample.Name)
                Assert-NativeValue ($null -eq $safe.PSObject.Properties['Value']) 'Projected record retained a secret Value.'
                Assert-NativeValue (-not (ConvertTo-Json `
                            -InputObject $safe `
                            -Compress).Contains($script:Marker)) 'Projected record retained a payload.'
                if ($Case -eq 'Export') {
                    foreach ($format in @('Json', 'Html', 'Csv', 'All')) {
                        $script:Sink.Clear()
                        $rows = @(Invoke-NativeExport $sample.Value $format)
                        $expectedWrites = if ($format -eq 'All') {
                            3
                        }
                        else {
                            1
                        }
                        Assert-NativeValue ($rows.Count -eq $expectedWrites -and
                            $script:Sink.Count -eq $expectedWrites) 'Native presence export changed writer cardinality.'
                        Assert-NativeValue (@($script:Sink | Where-Object HasPayload).Count -eq 0) 'Native presence export retained a payload.'
                        if ($format -in @('Json', 'All')) {
                            $json = @($script:Sink | Where-Object { $_.Path -like '*.json' })[0].Content | ConvertFrom-Json
                            $present = $json.Findings[0].Evidence.SecretPresent
                            Assert-NativeValue ($present -is [bool] -and
                                $present -eq $sample.Expected) 'Export changed native Boolean presence.'
                        }
                    }
                }
                Assert-NativeValue ($before -ceq (Get-NativeState $sample.Value)) 'Projection changed native input state or extended member metadata.'
                Assert-NativeValue ([object]::ReferenceEquals($record.Value, $sample.Value)) 'Projection replaced caller data.'
                $script:Scenarios++
            }
        }

        'Disposed' {
            foreach ($preference in @('Continue', 'Stop')) {
                $password = New-NativeSecure $true
                $credential = [pscredential]::new('fixture', $password)
                $password.Dispose()
                foreach ($value in @($password, $credential)) {
                    $ErrorActionPreference = $preference
                    $beforeErrors = $Error.Count
                    $rows = @(Test-ADAnalyzerSecretPresence $value 2>&1)
                    Assert-NativeValue ($rows.Count -eq 1 -and
                        $rows[0] -is [bool] -and
                        -not $rows[0]) 'Disposed values changed their zero-length contract.'
                    Assert-NativeValue ($Error.Count -eq $beforeErrors) 'Disposed presence emitted an unexpected error.'
                    $script:Scenarios++
                }
            }
            $ErrorActionPreference = 'Stop'
        }
        'GetterIsolation' {
            $credential = [pscredential]::new('fixture', (New-NativeSecure $true))
            $secure = New-NativeSecure $true
            $values = @(
                @{
                    Value = $credential
                    Member = 'Password'
                }
                @{
                    Value = $secure
                    Member = 'Length'
                }
                @{
                    Value = $script:Marker
                    Member = 'Length'
                }
                @{
                    Value = [object[]]@(1)
                    Member = 'Count'
                }
            )
            foreach ($sample in $values) {
                $value = Add-NativeShadow $sample.Value $sample.Member {
                    $script:GetterCalls++
                    throw 'Adapted secret metadata getter must not run.'
                } ScriptProperty
                $before = Get-NativeState $value
                $beforeCalls = $script:GetterCalls
                $rows = @(Test-ADAnalyzerSecretPresence $value)
                Assert-NativeValue ($rows.Count -eq 1 -and
                    $rows[0] -is [bool] -and
                    $rows[0]) 'Native presence depended on an adapted getter.'
                Assert-NativeValue ($script:GetterCalls -eq $beforeCalls) 'Native presence invoked an adapted payload getter.'
                Assert-NativeValue ($before -ceq (Get-NativeState $value)) 'Native presence changed getter metadata.'
                $script:Scenarios++
            }
        }
        'ExplicitCollection' {
            Add-Type -TypeDefinition @'
using System;
using System.Collections;

public sealed class NativePresenceCollection : ICollection
{
    private readonly int nativeCount;
    private readonly int publicCount;

    public NativePresenceCollection(int nativeCount, int publicCount)
    {
        this.nativeCount = nativeCount;
        this.publicCount = publicCount;
    }

    public int Reads { get; private set; }

    public int Count
    {
        get
        {
            return publicCount;
        }
    }

    int ICollection.Count
    {
        get
        {
            Reads++;
            return nativeCount;
        }
    }

    public bool IsSynchronized
    {
        get
        {
            return false;
        }
    }

    public object SyncRoot
    {
        get
        {
            return this;
        }
    }

    public void CopyTo(Array array, int index)
    {
        throw new InvalidOperationException("Collection must not be copied.");
    }

    public IEnumerator GetEnumerator()
    {
        throw new InvalidOperationException("Collection must not be enumerated.");
    }
}
'@
            foreach ($sample in @(
                    @{
                        Native = 0
                        Public = 0
                        Expected = $false
                    }
                    @{
                        Native = 2
                        Public = 2
                        Expected = $true
                    }
                    @{
                        Native = 2
                        Public = 0
                        Expected = $true
                    }
                    @{
                        Native = 0
                        Public = 5
                        Expected = $false
                    }
                )) {
                $value = [NativePresenceCollection]::new($sample.Native, $sample.Public)
                $rows = @(Test-ADAnalyzerSecretPresence $value)
                Assert-NativeValue ($rows.Count -eq 1 -and
                    $rows[0] -is [bool] -and
                    $rows[0] -eq $sample.Expected) 'Presence did not honor ICollection cardinality.'
                Assert-NativeValue ($value.Reads -eq 1) 'Native interface count was not read exactly once.'
                $script:Scenarios++
            }
        }
    }
    $expectedCases = @{
        Ordinary = 20
        Shadows = 15
        Records = 15
        SafeData = 15
        Export = 15
        Disposed = 4
        GetterIsolation = 4
        ExplicitCollection = 4
    }
    Assert-NativeValue ($script:Scenarios -eq $expectedCases[$Case]) 'Required native presence scenarios were not all executed.'
    Write-Host ('PASS native secret presence ' + $Case + ' ' + $script:Scenarios)
}
catch {
    $message = $_.Exception.Message.Replace($script:Marker, '[fixture]')
    Write-Host ('FAIL native secret presence ' + $Case + ': ' + $message)
    Write-Host ('Fixture stack: ' + $_.ScriptStackTrace)
    exit 1
}
finally {
    foreach ($value in $script:Owned) {
        $value.Dispose()
    }
    foreach ($typeName in $script:OwnedTypeData) {
        Remove-TypeData -TypeName $typeName -ErrorAction Stop
    }
}
