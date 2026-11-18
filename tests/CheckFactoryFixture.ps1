[CmdletBinding()]
param(
    [ValidateSet('VerifyOriginal', 'Creation', 'Suppression', 'Failures', 'Direct')]
    [string]$Case = 'Creation'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')

# Exact accepted function text from c1e68c0. Only line endings are normalized.
$script:OriginalCreation = @'
function New-ADAnalyzerCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][ValidateSet('Pass',
            'Fail',
            'Unknown',
            'Unreadable',
            'NotApplicable',
            'NotConfigured',
            'Invalid')][string]$Status,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Information')][string]$Severity = 'Information',
        [string]$Category = 'General',
        [Parameter(Mandatory)][string]$Target,
        [AllowNull()]$Observed,
        [AllowNull()]$Expected,
        [AllowNull()]$Evidence,
        [string]$Message = '',
        [ValidateSet('Configured', 'Applicable', 'Unknown', 'NotApplicable')][string]$Applicability = 'Unknown',
        [AllowNull()]$Object

    )
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $id = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($RuleId.ToUpperInvariant() + [char]0 + $Target.ToUpperInvariant()))).Replace('-',
            '').ToLowerInvariant()
    }
    finally {
        $hash.Dispose()
    }
    [pscustomobject][ordered]@{
        CheckId = $id
        RuleId = $RuleId
        Status = $Status
        Severity = $Severity
        Category = $Category
        Target = $Target
        Observed = $Observed
        Expected = $Expected
        Evidence = $Evidence
        Message = $Message
        Applicability = $Applicability
        ObjectGuid = $(if ($Object) {
                [string]$Object.ObjectGuid
            }
            else {
                $null
            })
        SID = $(if ($Object) {
                [string]$Object.SID
            }
            else {
                $null
            })
        DistinguishedName = $(if ($Object) {
                [string]$Object.DistinguishedName
            }
            else {
                $null
            })
        Suppressed = $false
        Exception = $null
    }
}
'@

$script:OriginalSuppression = @'
function Set-ADAnalyzerCheckException {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Check,
        [hashtable]$Profile

    )
    process {
        foreach ($exception in @($Profile.Exceptions)) {
            if ($Check.RuleId -eq $exception.RuleId -and
                $Check.Target -like $exception.Target -and
                [datetimeoffset]$exception.Expires -gt [datetimeoffset]::UtcNow) {
                $Check.Suppressed = $true
                $Check.Exception = [pscustomobject]@{
                    Owner = $exception.Owner
                    Reason = $exception.Reason
                    Expires = $exception.Expires
                }
                break
            }
        }
        $Check
    }
}
'@

$script:CreationHash = 'd4dc325ebc1cfae59d45706f30f7fee88c83b0c0374f507b4b6cc916bef190cd'
$script:SuppressionHash = 'bff0d73aa576598e666245a4f1a842e7c67da587eb78b5b0203915e9bbe1871c'
$script:CreationFields = 'CheckId,RuleId,Status,Severity,Category,Target,Observed,Expected,Evidence,Message,Applicability,ObjectGuid,SID,DistinguishedName,Suppressed,Exception'
$script:Statuses = @('Pass', 'Fail', 'Unknown', 'Unreadable', 'NotApplicable', 'NotConfigured', 'Invalid')

function Assert-Factory($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function ConvertTo-FactoryJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 15 -Compress
}

function Assert-FactorySame($Expected, $Actual, [string]$Label) {
    $expectedJson = ConvertTo-FactoryJson $Expected
    $actualJson = ConvertTo-FactoryJson $Actual
    if ($expectedJson -cne $actualJson) {
        throw "$Label differs. Expected $expectedJson; actual $actualJson"
    }
}

function Get-FactoryHash([string]$Text) {
    $normalized = $Text.Replace([string][char]13 + [char]10, [string][char]10)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hash.Dispose()
    }
}

Assert-Factory ((Get-FactoryHash $script:OriginalCreation) -ceq $script:CreationHash) 'Frozen creation source hash changed.'
Assert-Factory ((Get-FactoryHash $script:OriginalSuppression) -ceq $script:SuppressionHash) 'Frozen suppression source hash changed.'

Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Management.Automation;

public static class CheckFactoryInspection
{
    public static bool SameField(PSObject row, string field, Hashtable source)
    {
        return Object.ReferenceEquals(row.Properties[field].Value, source[field]);
    }

    public static string FieldShape(PSObject row, string field)
    {
        object value = row.Properties[field].Value;
        if (value == null)
        {
            return "<null>";
        }
        PSObject wrapped = value as PSObject;
        if (wrapped == null)
        {
            return value.GetType().FullName;
        }
        return value.GetType().FullName + "/" + wrapped.BaseObject.GetType().FullName +
            "/" + (wrapped.Properties["FixtureMarker"] != null);
    }
}

public sealed class CheckFactoryUnstringable
{
    public override string ToString()
    {
        throw new InvalidOperationException("fixture string conversion failure");
    }
}
'@

function Get-FactoryParamText([System.Management.Automation.CommandInfo]$Command) {
    $ast = $Command.ScriptBlock.Ast
    if ($ast -is [Management.Automation.Language.FunctionDefinitionAst]) {
        $ast = $ast.Body
    }
    $ast.ParamBlock.Extent.Text.Replace([string][char]13 + [char]10, [string][char]10)
}

function Assert-FactoryParameterContract {
    $creation = Get-FactoryParamText (Get-Command New-ADAnalyzerCheck)
    $suppression = Get-FactoryParamText (Get-Command Set-ADAnalyzerCheckException)
    . ([scriptblock]::Create($script:OriginalCreation))
    . ([scriptblock]::Create($script:OriginalSuppression))
    Assert-Factory ($creation -ceq (Get-FactoryParamText (Get-Command New-ADAnalyzerCheck))) 'Creation command parameter contract changed.'
    Assert-Factory ($suppression -ceq (Get-FactoryParamText (Get-Command Set-ADAnalyzerCheckException))) 'Suppression command parameter contract changed.'
}

function New-FactoryWrappedValue($Value) {
    $wrapped = [psobject]::AsPSObject($Value)
    foreach ($field in @('FixtureMarker', 'ObjectGuid', 'SID', 'DistinguishedName')) {
        $wrapped.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new($field, ('wrapped-' + $field)))
    }
    return , $wrapped
}

function New-FactoryCreationArguments([string]$Name) {
    $specification = @{
        RuleId = 'FIXTURE.Rule'
        Target = 'Fixture target'
        Status = 'Pass'
    }
    if ($Name -eq 'Defaults') {
        return $specification
    }
    if ($Name -eq 'Unicode') {
        $specification.RuleId = ' a '
        $specification.Target = ' ø '
        $specification.Status = 'fAiL'
    }
    $specification.Severity = 'hIgH'
    $specification.Category = 'fixture-category'
    $specification.Message = 'fixture-message'
    $specification.Applicability = 'aPpLiCaBlE'
    $value = $null
    switch ($Name) {
        'Unicode' {
            $value = [ordered]@{
                ObjectGuid = [guid]'a2debd7a-4988-4ec6-b39a-111111111111'
                SID = 'fixture-sid'
                DistinguishedName = 'CN=Fixture,DC=example,DC=invalid'
            }
        }
        'Null' {
            $value = $null
        }
        'False' {
            $value = $false
        }
        'Zero' {
            $value = 0
        }
        'EmptyString' {
            $value = ''
        }
        'EmptyArray' {
            $value = [object[]]@()
        }
        'SingleZero' {
            $value = [object[]]@(0)
        }
        'WrappedScalar' {
            $value = New-FactoryWrappedValue 123
        }
        'WrappedArray' {
            $value = New-FactoryWrappedValue ([object[]]@(7, 8))
        }
        'WrappedList' {
            $value = New-FactoryWrappedValue ([Collections.ArrayList]@(7, 8))
        }
        'MetadataChangesTruthiness' {
            $value = New-FactoryWrappedValue ([Collections.ArrayList]@(7, 8))
            $value.PSObject.Properties.Remove('ObjectGuid')
            $value.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('ObjectGuid', {
                        $this.PSObject.BaseObject.Clear()
                        'guid-cleared-list'
                    }))
        }
        'WrappedMap' {
            $value = New-FactoryWrappedValue @{
                Entry = 7
            }
        }
        'NakedScalar' {
            $value = 12345
        }
        'NakedArray' {
            $value = [object[]]@(0, 0)
        }
        'Custom' {
            $value = [pscustomobject]@{
                ObjectGuid = 'fixture-guid'
                SID = 'fixture-sid'
                DistinguishedName = 'fixture-dn'
            }
        }
        'EmptyMap' {
            $value = @{}
        }
        default {
            throw "Unknown creation sample $Name"
        }
    }
    $specification.Observed = $value
    $specification.Expected = $value
    $specification.Evidence = $value
    $specification.Object = $value
    return $specification
}

function Get-FactoryCreationSnapshot($Row, [hashtable]$Specification, [string]$Name) {
    Assert-Factory ($Row -is [pscustomobject]) "Creation did not produce a custom object for $Name."
    $fields = $Row.PSObject.Properties.Name -join ','
    Assert-Factory ($fields -ceq $script:CreationFields) "Creation reordered DTO fields for $Name."
    foreach ($field in @('Observed', 'Expected', 'Evidence')) {
        Assert-Factory ([CheckFactoryInspection]::SameField($Row,
                $field,
                $Specification)) "Creation changed the raw $field reference for $Name."
    }
    Assert-Factory ($Row.Suppressed -is [bool] -and
        -not $Row.Suppressed -and
        $null -eq $Row.Exception) "Creation did not initialize suppression for $Name."
    Assert-Factory ($Row.CheckId -cmatch '^[a-f0-9]{64}$') "Creation returned an invalid hash for $Name."
    if ($Name -eq 'MetadataChangesTruthiness') {
        Assert-Factory ($Row.ObjectGuid -ceq 'guid-cleared-list' -and $null -eq $Row.SID -and
            $null -eq $Row.DistinguishedName) "Creation did not recheck Object truthiness after its first metadata getter. Guid='$($Row.ObjectGuid)', SID='$($Row.SID)', DN='$($Row.DistinguishedName)'."
    }
    [pscustomobject][ordered]@{
        Fields = $fields
        CheckId = $Row.CheckId
        RuleId = $Row.RuleId
        Status = $Row.Status
        Severity = $Row.Severity
        Category = $Row.Category
        Target = $Row.Target
        Observed = [CheckFactoryInspection]::FieldShape($Row, 'Observed')
        Expected = [CheckFactoryInspection]::FieldShape($Row, 'Expected')
        Evidence = [CheckFactoryInspection]::FieldShape($Row, 'Evidence')
        Message = $Row.Message
        Applicability = $Row.Applicability
        ObjectGuid = $Row.ObjectGuid
        SID = $Row.SID
        DistinguishedName = $Row.DistinguishedName
    }
}

function Invoke-FactoryCreation([string]$Name, [string]$Route) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalCreation))
    }
    $specification = New-FactoryCreationArguments $Name
    $rows = if ($Route -eq 'Direct') {
        $factory = [ADAnalyzerCheckFactory]::new()
        if ($Name -eq 'Defaults') {
            $factory.Create($specification.RuleId, $specification.Status, $specification.Target)
        }
        else {
            $factory.Create($specification)
        }
    }
    else {
        New-ADAnalyzerCheck @specification
    }
    Assert-Factory (@($rows).Count -eq 1) "Creation returned other than one DTO for $Name."
    Get-FactoryCreationSnapshot $rows $specification $Name
}

function New-FactoryException($Expiry, [string]$RuleId = 'fixture.rule', [string]$Target = 'fixture*', [string]$Owner = 'first') {
    @{
        RuleId = $RuleId
        Target = $Target
        Expires = $Expiry
        Owner = $Owner
        Reason = 'fixture-reason'
    }
}

function New-FactoryCheck([string]$Target = 'Fixture target', [string]$Status = 'Fail') {
    [pscustomobject][ordered]@{
        RuleId = 'FIXTURE.Rule'
        Target = $Target
        Status = $Status
        CheckId = 'fixture-original-check-id'
        Suppressed = $false
        Exception = $null
    }
}

function New-FactorySuppressionState([string]$Name) {
    $row = New-FactoryCheck
    $future = '2099-03-03T12:00:00+00:00'
    $originalException = $null
    $profile = @{}
    $owner = $null
    $expiry = $null
    switch ($Name) {
        'NullProfile' {
            $profile = $null
        }
        'MissingExceptions' {
            $profile = @{}
        }
        'EmptyExceptions' {
            $profile.Exceptions = @()
        }
        'NoMatch' {
            $row.Suppressed = $true
            $row.Exception = [pscustomobject]@{
                Owner = 'prior'
                Reason = 'existing'
                Expires = [datetimeoffset]'2099-01-01T00:00:00+00:00'
            }
            $originalException = $row.Exception
            $owner = 'prior'
            $expiry = $row.Exception.Expires
            $profile.Exceptions = @((New-FactoryException $future 'other.rule'))
        }
        'RuleShortCircuit' {
            $profile.Exceptions = @(
                (New-FactoryException 'invalid' 'other.rule' '[')
                (New-FactoryException $future)
            )
            $owner = 'first'
            $expiry = $future
        }
        'TargetShortCircuit' {
            $profile.Exceptions = @(
                (New-FactoryException 'invalid' 'fixture.rule' 'Does not match')
                (New-FactoryException $future)
            )
            $owner = 'first'
            $expiry = $future
        }
        'ExpiredThenLive' {
            $profile.Exceptions = @(
                (New-FactoryException '2000-01-01T00:00:00+00:00' 'fixture.rule' 'fixture*' 'expired')
                (New-FactoryException $future)
            )
            $owner = 'first'
            $expiry = $future
        }
        'FirstLive' {
            $profile.Exceptions = @(
                (New-FactoryException $future 'fixture.rule' 'FIXTURE t?rget')
                (New-FactoryException 'invalid')
            )
            $owner = 'first'
            $expiry = $future
        }
        'RawDateTime' {
            $expiry = [datetime]::new(2099, 3, 3, 12, 0, 0, [DateTimeKind]::Utc)
            $profile.Exceptions = @((New-FactoryException $expiry))
            $owner = 'first'
        }
        'RawOffset' {
            $expiry = [datetimeoffset]'2099-03-03T12:00:00+03:00'
            $profile.Exceptions = @((New-FactoryException $expiry))
            $owner = 'first'
        }
        'NativeEnumerator' {
            $candidate = [pscustomobject]@{
                RuleId = 'fixture.rule'
                Target = 'fixture*'
                Expires = $future
                Reason = 'fixture-reason'
            }
            $candidate.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('Owner', {
                        if ($null -eq $foreach) {
                            'no-enumerator'
                        }
                        else {
                            'has-enumerator'
                        }
                    }))
            $profile.Exceptions = @($candidate)
            $owner = 'has-enumerator'
            $expiry = $future
        }
        default {
            Assert-Factory ($Name.StartsWith('Status:')) "Unknown suppression sample $Name."
            $row.Status = $Name.Substring(7)
            $profile.Exceptions = @((New-FactoryException $future))
            $owner = 'first'
            $expiry = $future
        }
    }
    @{
        Row = $row
        Profile = $profile
        Owner = $owner
        Expiry = $expiry
        OriginalException = $originalException
    }
}

function Invoke-FactorySuppression([string]$Name, [string]$Route) {
    if ($Route -eq 'Original') {
        . ([scriptblock]::Create($script:OriginalSuppression))
    }
    # Hide the test driver's iterator. Only the suppression loop should supply one.
    $foreach = $null
    $state = New-FactorySuppressionState $Name
    $row = $state.Row
    $beforeProfile = ConvertTo-FactoryJson $state.Profile
    $beforeStatus = $row.Status
    $profile = $state.Profile
    $result = if ($Route -eq 'Direct') {
        [ADAnalyzerCheckFactory]::new().ApplyException($row, $profile)
    }
    else {
        $row | Set-ADAnalyzerCheckException -Profile $profile
    }
    Assert-Factory (@($result).Count -eq 1 -and
        [object]::ReferenceEquals($row,
            $result)) "Suppression did not return its check by reference for $Name."
    Assert-Factory ($row.CheckId -ceq 'fixture-original-check-id' -and
        $row.Status -ceq $beforeStatus) "Suppression changed identity or status for $Name."
    Assert-Factory ((ConvertTo-FactoryJson $profile) -ceq $beforeProfile) "Suppression mutated its profile for $Name."
    Assert-Factory ($row.Suppressed -eq ($null -ne $state.Owner) -and
        $row.Exception.Owner -ceq $state.Owner) "Suppression expected owner '$($state.Owner)' but recorded '$($row.Exception.Owner)' for $Name."
    if ($null -ne $state.Expiry) {
        Assert-Factory ($null -ne $row.Exception.Expires -and
            $row.Exception.Expires.GetType() -eq $state.Expiry.GetType() -and
            $row.Exception.Expires -ceq $state.Expiry) "Suppression changed raw expiry for $Name."
        Assert-Factory (($row.Exception.PSObject.Properties.Name -join ',') -ceq 'Owner,Reason,Expires') "Suppression changed exception DTO schema for $Name."
    }
    if ($null -ne $state.OriginalException) {
        Assert-Factory ([object]::ReferenceEquals($row.Exception,
                $state.OriginalException)) "Suppression reset prior exception state for $Name."
    }
    [pscustomobject][ordered]@{
        RuleId = $row.RuleId
        Target = $row.Target
        Status = $row.Status
        CheckId = $row.CheckId
        Suppressed = $row.Suppressed
        Exception = $row.Exception
        ExpiryType = if ($null -ne $row.Exception.Expires) {
            $row.Exception.Expires.GetType().FullName
        }
    }
}

function Get-FactoryErrorShape([Management.Automation.ErrorRecord]$Record) {
    [pscustomobject][ordered]@{
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Type = $Record.Exception.GetType().FullName
        BaseType = $Record.Exception.GetBaseException().GetType().FullName
        Message = $Record.Exception.Message
        BaseMessage = $Record.Exception.GetBaseException().Message
    }
}

function New-FactoryMetadataTarget([string]$Name) {
    $object = [pscustomobject]@{}
    switch ($Name) {
        'CreateTrace' {
            $object.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('ObjectGuid', {
                        $script:FactoryTrace.Add('Guid')
                        'fixture-guid'
                    }))
        }
        'CreateGetter' {
            $object.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('ObjectGuid', {
                        $script:FactoryTrace.Add('Guid')
                        throw 'fixture getter failure'
                    }))
        }
        'CreateCast' {
            $object.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new('ObjectGuid', [CheckFactoryUnstringable]::new()))
        }
        'CreateOFS' {
            $object.PSObject.Properties.Add([Management.Automation.PSNoteProperty]::new('ObjectGuid', @('alpha', 'beta')))
        }
    }
    $object.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('SID', {
                $script:FactoryTrace.Add('SID')
                'fixture-sid'
            }))
    $object.PSObject.Properties.Add([Management.Automation.PSScriptProperty]::new('DistinguishedName', {
                $script:FactoryTrace.Add('DN')
                'fixture-dn'
            }))
    $object
}

function Get-FactoryStreamShape($Item) {
    if ($Item -is [Management.Automation.ErrorRecord]) {
        return Get-FactoryErrorShape $Item
    }
    if ($Item -is [string]) {
        return $Item
    }
    if ($Item -is [Exception]) {
        return [pscustomobject]@{
            Exception = $Item.GetType().FullName
            Message = $Item.Message
        }
    }
    [pscustomobject][ordered]@{
        Target = $Item.Target
        ObjectGuid = $Item.ObjectGuid
        SID = $Item.SID
        DistinguishedName = $Item.DistinguishedName
        CheckId = $Item.CheckId
        Status = $Item.Status
        Suppressed = $Item.Suppressed
        Exception = $Item.Exception
    }
}

function Invoke-FactoryFailure([string]$Name, [string]$Preference, [bool]$Caught, [bool]$Original) {
    $creation = $Name.StartsWith('Create')
    if ($Original) {
        if ($creation) {
            . ([scriptblock]::Create($script:OriginalCreation))
        }
        else {
            . ([scriptblock]::Create($script:OriginalSuppression))
        }
    }
    $script:FactoryTrace = [Collections.Generic.List[string]]::new()
    $checks = @()
    $factoryErrors = [Collections.ArrayList]@('error-seed')
    $factoryOut = [Collections.ArrayList]@('output-seed')
    $options = @{
        ErrorAction = $Preference
        ErrorVariable = '+factoryErrors'
        OutVariable = '+factoryOut'
    }
    if ($creation) {
        $options.RuleId = 'fixture.rule'
        $options.Status = 'Pass'
        $options.Target = 'fixture target'
        $options.Object = New-FactoryMetadataTarget $Name
        $invoke = { New-ADAnalyzerCheck @options }
    }
    else {
        $checks = @(
            (New-FactoryCheck 'prefix')
            (New-FactoryCheck 'candidate')
            (New-FactoryCheck 'suffix')
        )
        $future = '2099-03-03T12:00:00+00:00'
        $exceptions = @()
        switch ($Name) {
            'ExpiryInvalid' {
                $exceptions = @((New-FactoryException 'not-a-date' 'fixture.rule' 'candidate'))
            }
            'ExpiryNull' {
                $exceptions = @((New-FactoryException $null 'fixture.rule' 'candidate'))
            }
            'Wildcard' {
                $exceptions = @((New-FactoryException $future 'fixture.rule' '['))
            }
            'SetterSuppressed' {
                $checks[1].PSObject.Properties.Remove('Suppressed')
            }
            'SetterException' {
                $checks[1].PSObject.Properties.Remove('Exception')
            }
        }
        $options.Profile = @{
            Exceptions = @(
                (New-FactoryException 'invalid' 'other.rule' '[')
            ) + $exceptions + @(
                (New-FactoryException $future 'fixture.rule' '*' 'fallback')
            )
        }
        $invoke = { $checks | Set-ADAnalyzerCheckException @options }
    }
    $OFS = '|'
    $ErrorActionPreference = 'Continue'
    $Error.Clear()
    $observed = [Collections.Generic.List[object]]::new()
    $collect = {
        process {
            $observed.Add((Get-FactoryStreamShape $_))
        }
    }
    $fault = $null
    if ($Caught) {
        try {
            . $invoke 2>&1 | . $collect
        }
        catch {
            $fault = Get-FactoryErrorShape $_
        }
    }
    else {
        . $invoke 2>&1 | . $collect
    }

    $globalErrors = @($Error | ForEach-Object { Get-FactoryErrorShape $_ })
    [pscustomobject][ordered]@{
        Case = $Name
        Preference = $Preference
        Caught = $fault
        Stream = $observed.ToArray()
        ErrorVariable = @($factoryErrors | ForEach-Object { Get-FactoryStreamShape $_ })
        OutVariable = @($factoryOut | ForEach-Object { Get-FactoryStreamShape $_ })
        GlobalErrors = $globalErrors
        Trace = $script:FactoryTrace.ToArray()
        CheckState = @($checks | ForEach-Object { Get-FactoryStreamShape $_ })
    }
}

function Assert-FactoryFailureWasExercised($Observation, [string]$Name, [string]$Preference, [bool]$Caught) {
    Assert-Factory ($Observation.ErrorVariable[0] -ceq 'error-seed' -and
        $Observation.OutVariable[0] -ceq 'output-seed') "Native common-parameter seeds were lost for $Name."
    if ($Name -in @('CreateTrace', 'CreateGetter', 'CreateOFS')) {
        $expectedTrace = 'Guid,SID,DN'
        if ($Name -eq 'CreateOFS') {
            $expectedTrace = 'SID,DN'
        }
        Assert-Factory (($Observation.Trace -join ',') -ceq $expectedTrace -and
            $Observation.Stream.Count -eq 1 -and
            $Observation.Stream[0].Target -ceq 'fixture target') "Metadata reads were not exercised for $Name."
        if ($Name -eq 'CreateOFS') {
            Assert-Factory ($Observation.Stream[0].ObjectGuid -ceq 'alpha|beta') 'Metadata did not exercise caller OFS.'
        }
        if ($Name -eq 'CreateGetter') {
            Assert-Factory ($Observation.Stream[0].ObjectGuid -ceq '') 'Throwing script getter did not take the native empty string path.'
        }
        return
    }
    if ($Caught) {
        Assert-Factory ($null -ne $Observation.Caught -and
            $Observation.ErrorVariable.Count -gt 1) "Expected a caught native fault for $Name."
    }
    if (-not $Caught -and $Preference -eq 'Continue') {
        Assert-Factory (@($Observation.Stream | Where-Object { $null -ne $_.Id }).Count -gt 0) "Expected an outward native error for $Name."
        if ($Name -eq 'CreateCast') {
            Assert-Factory (($Observation.Trace -join ',') -ceq 'SID,DN' -and
                $Observation.Stream[-1].Target -ceq 'fixture target' -and
                $null -eq $Observation.Stream[-1].ObjectGuid) 'Creation did not continue with remaining metadata after a native cast failure.'
        }
        else {
            Assert-Factory (($Observation.CheckState.Target -join ',') -ceq 'prefix,candidate,suffix' -and
                $Observation.CheckState[2].Exception.Owner -ceq 'fallback') "Suppression did not exercise pipeline continuation for $Name."
            if ($Name -eq 'SetterSuppressed') {
                Assert-Factory ($Observation.CheckState[1].Exception.Owner -ceq 'fallback') 'The second suppression write did not follow the failed first write.'
            }
            elseif ($Name -eq 'SetterException') {
                Assert-Factory ($Observation.CheckState[1].Suppressed -eq $true) 'The first suppression write was lost after the failed second write.'
            }
        }
    }
    if ($Name -eq 'CreateCast' -and ($Caught -or $Preference -eq 'Stop')) {
        Assert-Factory ($Observation.Trace.Count -eq 0 -and
            $Observation.OutVariable.Count -eq 1) 'A terminating cast did not prevent the later getters and row.'
    }
}

$creationCases = @(
    'Defaults', 'Unicode', 'Null', 'False', 'Zero', 'EmptyString', 'EmptyArray', 'SingleZero',
    'WrappedScalar',
    'WrappedArray',
    'WrappedList',
    'MetadataChangesTruthiness',
    'WrappedMap',
    'NakedScalar',
    'NakedArray',
    'Custom',
    'EmptyMap'
)
$suppressionCases = @(
    'NullProfile', 'MissingExceptions', 'EmptyExceptions', 'NoMatch', 'RuleShortCircuit',
    'TargetShortCircuit', 'ExpiredThenLive', 'FirstLive', 'RawDateTime', 'RawOffset', 'NativeEnumerator'
) + @($script:Statuses | ForEach-Object { 'Status:' + $_ })
$failureCases = @(
    'CreateTrace', 'CreateGetter', 'CreateCast', 'CreateOFS',
    'ExpiryInvalid', 'ExpiryNull', 'Wildcard', 'SetterSuppressed', 'SetterException'
)
$executed = 0

switch ($Case) {
    'VerifyOriginal' {
        $tokens = $null
        $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $repositoryRoot 'bin/ADProfile.ps1'), [ref]$tokens, [ref]$parseErrors
        )
        Assert-Factory (@($parseErrors).Count -eq 0) 'Original source contains parser errors.'
        $functionAsts = $ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst]
            }, $false)
        foreach ($pair in @(
                @{
                    Name = 'New-ADAnalyzerCheck'
                    Hash = $script:CreationHash
                },
                @{
                    Name = 'Set-ADAnalyzerCheckException'
                    Hash = $script:SuppressionHash
                }
            )) {
            $matched = @($functionAsts | Where-Object { $_.Name -ceq $pair.Name })
            Assert-Factory ($matched.Count -eq 1 -and
                (Get-FactoryHash $matched[0].Extent.Text) -ceq $pair.Hash) "Active source does not match accepted function $($pair.Name)."
            $executed++
        }
    }
    'Creation' {
        Assert-FactoryParameterContract
        foreach ($name in $creationCases) {
            $expected = Invoke-FactoryCreation $name 'Original'
            $actual = Invoke-FactoryCreation $name 'Command'
            Assert-FactorySame $expected $actual "Creation $name"
            if ($name -eq 'Defaults') {
                Assert-Factory ($actual.Category -ceq 'General' -and $actual.Severity -ceq 'Information' -and
                    $actual.Applicability -ceq 'Unknown' -and $actual.Message -ceq '' -and
                    $null -eq $actual.ObjectGuid) 'Default creation shape changed.'
            }
            if ($name -eq 'Unicode') {
                Assert-Factory ($actual.CheckId -ceq 'f2aa3077c854cd3e3d44b30b414093bda2b0f7cab75b52dacb4b3c04eaa8fdf8' -and
                    $actual.RuleId -ceq ' a ' -and $actual.Target -ceq ' ø ' -and
                    $actual.Status -ceq 'fAiL' -and
                    $actual.ObjectGuid -ceq 'a2debd7a-4988-4ec6-b39a-111111111111') 'Historical Unicode/case/metadata check changed.'
            }
            $executed++
        }
    }
    'Suppression' {
        Assert-FactoryParameterContract
        foreach ($name in $suppressionCases) {
            $expected = Invoke-FactorySuppression $name 'Original'
            $actual = Invoke-FactorySuppression $name 'Command'
            Assert-FactorySame $expected $actual "Suppression $name"
            $executed++
        }
    }
    'Failures' {
        foreach ($name in $failureCases) {
            foreach ($preference in @('Continue', 'Stop', 'SilentlyContinue', 'Ignore')) {
                foreach ($caught in @($true, $false)) {
                    $expected = Invoke-FactoryFailure $name $preference $caught $true
                    $actual = Invoke-FactoryFailure $name $preference $caught $false
                    Assert-FactoryFailureWasExercised $expected $name $preference $caught
                    Assert-FactorySame $expected $actual "Failure $name $preference caught=$caught"
                    $executed++
                }
            }
        }
    }
    'Direct' {

        function New-ADAnalyzerCheck {
            throw 'The direct factory must not use the creation command.'
        }

        function Set-ADAnalyzerCheckException {
            throw 'The direct factory must not use the suppression command.'
        }
        foreach ($name in $creationCases) {
            $expected = Invoke-FactoryCreation $name 'Original'
            $actual = Invoke-FactoryCreation $name 'Direct'
            Assert-FactorySame $expected $actual "Direct creation $name"
            $executed++
        }
        foreach ($name in $suppressionCases) {
            $expected = Invoke-FactorySuppression $name 'Original'
            $actual = Invoke-FactorySuppression $name 'Direct'
            Assert-FactorySame $expected $actual "Direct suppression $name"
            $executed++
        }

        $factory = [ADAnalyzerCheckFactory]::new()
        Assert-Factory (@($factory.PSObject.Properties).Count -eq 0) 'Factory retains public instance state.'
        $executed++

        foreach ($invalid in @(
                @{
                    RuleId = ''
                    Status = 'Pass'
                    Target = 'fixture'
                },
                @{
                    RuleId = 'fixture'
                    Status = 'InvalidStatus'
                    Target = 'fixture'
                },
                @{
                    RuleId = 'fixture'
                    Status = 'Pass'
                    Target = ''
                }
            )) {
            $creationRejected = $false
            try {
                $null = $factory.Create($invalid.RuleId, $invalid.Status, $invalid.Target)
            }
            catch {
                $creationRejected = $true
            }
            Assert-Factory $creationRejected 'Direct creation accepted an invalid identity or status.'
        }
        $executed++

        $row = New-FactoryCheck 'Fixture candidate'
        $profile = @{
            Exceptions = @(
                (New-FactoryException 'not-a-date')
                (New-FactoryException '2099-03-03T12:00:00+00:00')
            )
        }
        $failure = $null
        try {
            $null = $factory.ApplyException($row, $profile)
        }
        catch {
            $failure = $_.Exception.GetBaseException()
        }
        Assert-Factory ($failure -is [FormatException] -and
            -not $row.Suppressed -and
            $null -eq $row.Exception) 'Direct suppression lost the expiry cause or applied partial suppression.'
        $executed++
    }
}
Write-Host "PASS check factory $Case $executed"
