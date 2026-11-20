[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('FullLoader', 'Standalone', 'Objects', 'Aces', 'Native', 'Windows')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
$script:Checks = 0
$script:UnexpectedCalls = 0
function Stop-ProjectionIntegration {
    $script:UnexpectedCalls++
    throw 'The directory projector attempted an integration call.'
}
function Import-Module {
    Stop-ProjectionIntegration
}
function Get-ADObject {
    Stop-ProjectionIntegration
}
function Get-ADRootDSE {
    Stop-ProjectionIntegration
}
function Get-Acl {
    Stop-ProjectionIntegration
}
function New-PSDrive {
    Stop-ProjectionIntegration
}
function Read-Host {
    Stop-ProjectionIntegration
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADDirectoryAnalysis.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}
$projector = [ADAnalyzerDirectoryObjectProjector]::new()

function Assert-Projection($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-ProjectionJson($Expected, $Actual, [string]$Message) {
    $expectedJson = ConvertTo-Json -InputObject $Expected -Depth 15 -Compress
    $actualJson = ConvertTo-Json -InputObject $Actual -Depth 15 -Compress
    Assert-Projection ($expectedJson -ceq $actualJson) $Message
}

function Assert-ProjectionFailure([scriptblock]$Operation, [string]$Message) {
    $failure = $null
    try {
        $null = & $Operation
    }
    catch {
        $failure = $_
    }
    Assert-Projection ($null -ne $failure) $Message
}

function Test-Projection([scriptblock]$Body) {
    & $Body
    $script:Checks++
}

function New-ProjectionAce([string]$Sid, [string]$Rights) {
    [pscustomobject][ordered]@{
        IdentitySid = $Sid
        Rights = $Rights
        AccessControlType = 'Allow'
        ObjectType = [guid]'b79187d0-553a-4d25-b622-9d42da661cb4'
        InheritedObjectType = [guid]::Empty
        IsInherited = $false
        PropagationFlags = 'None'
        InheritanceType = 'None'
    }
}

$target = 'CN=Fixture,DC=example,DC=invalid'
$sid = 'S-1-5-21-1-2-3-1001'
$otherSid = 'S-1-5-21-1-2-3-1002'
$utc = [datetime]::new(2030, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)

if ($Case -in 'FullLoader', 'Standalone') {
    Test-Projection {
        $record = [pscustomobject]@{
            Name = 'Fixture'
            ObjectClass = 'user'
            SID = $sid
        }
        $direct = $projector.Project($record, 'User')
        Assert-Projection ($direct.ObjectClass -ceq 'User' -and $direct.DirectoryObjectClass -ceq 'user') 'Constructor could not project a record.'
        Assert-ProjectionJson (ConvertTo-ADAnalyzerDirectoryObject $record 'User') $direct 'Loading route changed projector output.'
    }
    Test-Projection {
        $rows = $projector.ProjectAces(@{ Access = @(New-ProjectionAce $sid 'ReadProperty') }, $target, 'OU')
        Assert-Projection ($rows -is [object[]] -and $rows.Count -eq 1 -and $rows[0].IdentitySid -ceq $sid) 'Loading route changed ACE array shape.'
        $empty = $projector.ProjectAces($null, $target, 'OU')
        Assert-Projection ($empty -is [object[]] -and $empty.Count -eq 0) 'Null descriptor did not return an empty array.'
    }
}

if ($Case -eq 'Objects') {
    $reference = [pscustomobject]@{ Name = 'description evidence' }
    $source = [pscustomobject]@{
        ObjectClass = 'computer'
        ObjectGuid = [guid]'7f907f2a-78e8-44f0-b319-113ec5f2eede'
        SID = [pscustomobject]@{ Value = $sid }
        DistinguishedName = $target
        Name = 'Fixture Source'
        Description = $reference
        Department = 'Fixture Department'
        PrimaryGroupID = 516
        UserAccountControl = 8192
        ProtectedFromAccidentalDeletion = $false
        WhenCreated = $utc
        SIDHistory = @($otherSid, $sid)
        'msDS-ResultantPSO' = @('CN=Fixture Policy,DC=example,DC=invalid')
        'msDS-AllowedToDelegateTo' = @('fixture/service')
        'msDS-SupportedEncryptionTypes' = 24
        'msLAPS-PasswordExpirationTime' = $utc.ToFileTimeUtc()
        'ms-Mcs-AdmPwdExpirationTime' = 0L
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = @{
            Access = @(New-ProjectionAce $otherSid 'ReadProperty')
        }
    }
    Test-Projection {
        $native = ConvertTo-ADAnalyzerDirectoryObject $source 'Computer'
        $direct = $projector.Project($source, 'Computer')
        Assert-ProjectionJson $native $direct 'Ordinary object and command signatures differ.'
        Assert-Projection ($direct.SID -is [string] -and $direct.SID -ceq $sid) 'Canonical SID lost its text shape.'
        Assert-Projection ($direct.ObjectGuid -is [string] -and $direct.ObjectGuid -ceq [string]$source.ObjectGuid) 'GUID lost its text shape.'
        Assert-Projection ($direct.WhenCreated.Kind -eq 'Utc' -and $direct.WhenCreated -eq $utc -and $direct.LapsExpiration -eq $utc) 'UTC conversion changed.'
        Assert-Projection ($direct.Protected -eq $false -and $direct.IsDomainController -and $null -eq $direct.LegacyLapsExpiration) 'Directory flags or unset file time changed.'
        Assert-Projection ($direct.ResourceBasedDelegation.Count -eq 1 -and $direct.ResourceBasedDelegation[0].IdentitySid -ceq $otherSid) 'Nested RBCD projection changed.'
    }
    Test-Projection {
        $extras = @('Department', 'objectCLASS', 'sId', 'Password')
        $projection = $projector.Project($source, 'Computer', $extras)
        $native = ConvertTo-ADAnalyzerDirectoryObject $source 'Computer' $extras
        Assert-ProjectionJson $native $projection 'Configured fields changed object and command parity.'
        Assert-Projection ($projection.Department -ceq $source.Department -and $projection.ObjectClass -ceq 'Computer' -and $projection.SID -ceq $sid) 'Configured fields replaced canonical identity.'
        Assert-Projection ($null -eq $projection.PSObject.Properties['Password'] -and
            $null -eq $projection.PSObject.Properties['_ClassificationAttributes']) 'The public projection exposed an excluded or transient property.'
    }
    Test-Projection {
        $one = $projector.Project($null, 'User')
        $two = $projector.Project([pscustomobject]@{}, 'User')
        Assert-ProjectionJson $one $two 'Null and empty records changed relative projection.'
        Assert-Projection ($one.ObjectClass -ceq 'User' -and $null -eq $one.Protected -and $one.ResourceBasedDelegation.Count -eq 0) 'Empty record defaults changed.'
    }
    Test-Projection {
        $ordinal = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
        $ordinal.Add('name', 'lower case fixture')
        $ordinal.Add('Department', $null)
        $ordinary = $projector.Project($ordinal, 'User', @('Department', 'Location'))
        Assert-ProjectionJson (ConvertTo-ADAnalyzerDirectoryObject $ordinal 'User' @('Department', 'Location')) $ordinary 'Ordinal dictionary changed.'
        Assert-Projection ($null -eq $ordinary.Name -and $null -eq $ordinary.Department -and
            $null -ne $ordinary.PSObject.Properties['Location']) 'Dictionary spelling, present null, or requested missing field changed.'
    }
    Test-Projection {
        $first = $projector.Project($source, 'Computer')
        $second = $projector.Project($source, 'Computer')
        $native = ConvertTo-ADAnalyzerDirectoryObject $source 'Computer'
        $first.Name = 'Changed result'
        Assert-Projection (-not [object]::ReferenceEquals($first, $second) -and
            -not [object]::ReferenceEquals($source, $first) -and $source.Name -ceq $second.Name) 'Results are not independent projections.'
        Assert-Projection ([object]::ReferenceEquals($reference, $native.Description)) 'The compatibility command stopped returning an untouched selected reference.'
    }
    Test-Projection {
        $source.'msDS-ResultantPSO' = @('CN=First', 'CN=Second')
        $projected = $projector.Project($source, 'Computer')
        Assert-Projection ($null -eq $projected.ResultantPasswordPolicyDN -and
            ($projected.SIDHistory -join '|') -ceq "$otherSid|$sid" -and
            $projected.AllowedToDelegateTo.Count -eq 1) 'Resultant policy or list cardinality changed.'
    }
}

if ($Case -eq 'Aces') {
    Test-Projection {
        foreach ($descriptor in @($null, @{}, @{ Access = $null }, @{ Access = @() })) {
            $direct = $projector.ProjectAces($descriptor, $target, 'Domain')
            $native = @(Get-ADAnalyzerSecurityAces $descriptor $target 'Domain')
            Assert-Projection ($direct -is [object[]] -and $direct.Count -eq 0 -and $native.Count -eq 0) 'Empty ACL cardinality changed.'
        }
    }
    Test-Projection {
        $acl = @{ Access = @((New-ProjectionAce $sid 'ReadProperty'), (New-ProjectionAce $otherSid 'WriteProperty')) }
        $direct = $projector.ProjectAces($acl, $target, 'OU')
        Assert-ProjectionJson @(Get-ADAnalyzerSecurityAces $acl $target 'OU') $direct 'Mixed ACE records changed order or properties.'
        Assert-Projection (($direct.IdentitySid -join '|') -ceq "$sid|$otherSid" -and
            $direct[0].Target -ceq $target -and $direct[0].TargetType -ceq 'OU') 'ACE targets or identity order changed.'
        $direct[0].Rights = 'mutated result'
        Assert-Projection (($projector.ProjectAces($acl, $target, 'OU'))[0].Rights -ceq 'ReadProperty') 'Repeated ACE operations shared result state.'
    }
    Test-Projection {
        $script:Reads = [Collections.Generic.List[string]]::new()
        $ace = [pscustomobject]@{}
        $ace | Add-Member ScriptProperty IdentitySid {
            $script:Reads.Add('IdentitySid')
            'S-1-5-21-1-2-3-1001'
        }
        $ace | Add-Member ScriptProperty IdentityReference {
            $script:Reads.Add('IdentityReference')
            $null
        }
        $ace | Add-Member ScriptProperty Rights {
            $script:Reads.Add('Rights')
            'ReadProperty'
        }
        $ace | Add-Member ScriptProperty ActiveDirectoryRights {
            $script:Reads.Add('ActiveDirectoryRights')
            $null
        }
        $native = @(Get-ADAnalyzerSecurityAces @{ Access = $ace } $target 'OU')
        $expected = 'IdentitySid|IdentityReference|Rights|ActiveDirectoryRights'
        Assert-Projection (($script:Reads -join '|') -ceq $expected) 'Native fallback getter order changed.'
        $script:Reads.Clear()
        $direct = $projector.ProjectAces(@{ Access = $ace }, $target, 'OU')
        Assert-Projection (($script:Reads -join '|') -ceq $expected -and
            $null -eq $direct[0].IdentitySid -and $direct[0].Rights -ceq '') 'Present-null precedence or direct getter order changed.'
        Assert-ProjectionJson $native $direct 'Present-null object and command results differ.'
    }
    Test-Projection {
        $script:Requests = [Collections.Generic.List[object]]::new()
        $descriptor = [pscustomobject]@{ Stored = New-ProjectionAce $sid 'ReadProperty' }
        $descriptor | Add-Member ScriptProperty Access {
            $script:Requests.Add('Access')
            @()
        }
        $descriptor | Add-Member ScriptMethod GetAccessRules {
            param($Explicit, $Inherited, $IdentityType)
            $script:Requests.Add(@($Explicit, $Inherited, $IdentityType.FullName) -join '|')
            $this.Stored
        }
        $direct = $projector.ProjectAces($descriptor, $target, 'OU')
        $native = @(Get-ADAnalyzerSecurityAces $descriptor $target 'OU')
        Assert-ProjectionJson $native $direct 'Script-method descriptor object and command results differ.'
        $request = 'True|True|System.Security.Principal.SecurityIdentifier'
        Assert-Projection ($direct.Count -eq 1 -and ($script:Requests -join ',') -ceq "$request,$request") 'Descriptor method or fallback selection changed.'
    }
    Test-Projection {
        $descriptor = [pscustomobject]@{}
        $descriptor | Add-Member ScriptMethod GetAccessRules {
            throw [InvalidOperationException]::new('Fixture descriptor could not enumerate entries.')
        }
        Assert-ProjectionFailure { $projector.ProjectAces($descriptor, $target, 'OU') } 'A failing descriptor silently returned direct ACEs.'
        Assert-ProjectionFailure { $projector.Project(@{ UserAccountControl = 'fixture invalid flag' }, 'Computer') } 'A malformed UAC value returned a direct projection.'
    }
}

if ($Case -eq 'Native') {
    Add-Type -TypeDefinition @'
using System;
public sealed class DirectoryProjectionFixtureBrokenText
{
    public override string ToString()
    {
        throw new InvalidOperationException("Fixture malformed rights.");
    }
}
'@
    $script:TailReads = 0
    $source = [pscustomobject]@{
        Name = 'Fixture Computer'
        PrimaryGroupID = 516
        UserAccountControl = 'fixture invalid flag'
        FixtureTime = $utc.ToFileTimeUtc()
    }
    $source | Add-Member ScriptProperty 'msLAPS-PasswordExpirationTime' {
        $script:TailReads++
        $this.FixtureTime
    }
    $first = New-ProjectionAce $sid 'ReadProperty'
    $third = New-ProjectionAce $otherSid 'WriteProperty'
    $script:LateAceReads = 0
    $second = [pscustomobject]@{}
    $second | Add-Member ScriptProperty Rights {
        $script:LateAceReads++
        [DirectoryProjectionFixtureBrokenText]::new()
    }
    $descriptor = @{ Access = @($first, $second, $third) }

    function Invoke-FixtureProjection {
        [CmdletBinding()]
        param([switch]$Aces)

        if ($Aces) {
            Get-ADAnalyzerSecurityAces $descriptor $target 'OU'
        }
        else {
            ConvertTo-ADAnalyzerDirectoryObject $source 'Computer'
        }
    }

    $observed = @()
    $ErrorActionPreference = 'Continue'
    $projected = @(Invoke-FixtureProjection -ErrorVariable +observed 2>&1)
    $ErrorActionPreference = 'Stop'
    Assert-Projection ($projected.Count -eq 2 -and
        $projected[0].FullyQualifiedErrorId -like 'InvalidCastFromStringToInteger*' -and
        $projected[1].IsDomainController -and $projected[1].LapsExpiration -eq $utc -and
        $observed.Count -eq 1 -and $script:TailReads -eq 1) 'Native UAC Continue lost the error, error variable, or valid tail.'
    $script:Checks++

    $observed = @()
    $caught = $null
    try {
        $null = Invoke-FixtureProjection -ErrorVariable +observed -ErrorAction Stop
    }
    catch {
        $caught = $_
    }
    Assert-Projection ($null -ne $caught -and
        $caught.FullyQualifiedErrorId -like 'InvalidCastFromStringToInteger*' -and
        $observed.Count -gt 0 -and $script:TailReads -eq 1) 'Native UAC Stop evaluated the tail or changed the error.'
    $script:Checks++

    $prefix = @(Invoke-FixtureProjection -Aces | Select-Object -First 1)
    Assert-Projection ($prefix.Count -eq 1 -and $prefix[0].IdentitySid -ceq $sid -and $script:LateAceReads -eq 0) 'Select-First observed a later malformed ACE.'
    $script:Checks++

    $observed = @()
    $ErrorActionPreference = 'Continue'
    $all = @(Invoke-FixtureProjection -Aces -ErrorVariable +observed 2>&1)
    $ErrorActionPreference = 'Stop'
    Assert-Projection ($all.Count -eq 3 -and $all[0].IdentitySid -ceq $sid -and
        $all[1].FullyQualifiedErrorId -like 'InvalidCastFromAnyTypeToString*' -and
        $all[2].IdentitySid -ceq $otherSid -and $observed.Count -eq 1 -and $script:LateAceReads -eq 1) 'Native ACE Continue changed row or error order.'
    $script:Checks++
}

if ($Case -eq 'Windows') {
    Assert-Projection ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) 'This fixture requires Windows.'
    $objectId = 'b79187d0-553a-4d25-b622-9d42da661cb4'
    $inheritedId = '51e673dc-2b49-4a4a-880d-1d6c6d702f8b'
    $thirdSid = 'S-1-5-21-1-2-3-1003'
    $sddl = 'O:SYG:SYD:(OD;;WP;{0};;{1})(OA;;RP;{0};;{2})(OA;CIID;RP;{0};{3};{4})' -f (
        $objectId, $sid, $otherSid, $inheritedId, $thirdSid
    )
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $bytes = [byte[]]::new($raw.BinaryLength)
    $raw.GetBinaryForm($bytes, 0)
    $descriptor = [DirectoryServices.ActiveDirectorySecurity]::new()
    $descriptor.SetSecurityDescriptorBinaryForm($bytes)
    $reference = @(
        foreach ($ace in $descriptor.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            [pscustomobject][ordered]@{
                Target = $target
                TargetType = 'OU'
                IdentitySid = $ace.IdentityReference.Value
                Rights = [string]$ace.ActiveDirectoryRights
                AccessControlType = [string]$ace.AccessControlType
                ObjectType = [string]$ace.ObjectType
                InheritedObjectType = [string]$ace.InheritedObjectType
                IsInherited = [bool]$ace.IsInherited
                PropagationFlags = [string]$ace.PropagationFlags
                InheritanceType = [string]$ace.InheritanceType
            }
        }
    )
    Test-Projection {
        $binary = $projector.ProjectAces($bytes, $target, 'OU')
        $native = @(Get-ADAnalyzerSecurityAces $bytes $target 'OU')
        Assert-ProjectionJson $reference $binary 'Binary ACL projection diverged from .NET rule order or values.'
        Assert-ProjectionJson $reference $native 'Compatibility binary ACL projection diverged from .NET.'
        Assert-Projection ($binary.Count -eq 3 -and
            @($binary | Where-Object { $_.IdentitySid -ceq $sid -and $_.AccessControlType -ceq 'Deny' -and $_.Rights -ceq 'WriteProperty' }).Count -eq 1 -and
            @($binary | Where-Object { $_.IdentitySid -ceq $otherSid -and $_.AccessControlType -ceq 'Allow' -and $_.Rights -ceq 'ReadProperty' }).Count -eq 1) 'Native fixture lost explicit allow, deny, or SID evidence.'
    }
    Test-Projection {
        $direct = $projector.ProjectAces($descriptor, $target, 'OU')
        Assert-ProjectionJson $reference $direct 'Managed ACL projection changed native order or fields.'
        Assert-ProjectionJson $reference @(Get-ADAnalyzerSecurityAces $descriptor $target 'OU') 'Compatibility managed ACL projection changed native order or fields.'
        $inherited = @($direct | Where-Object IsInherited)
        Assert-Projection ($inherited.Count -eq 1 -and $inherited[0].IdentitySid -ceq $thirdSid -and
            $inherited[0].IdentitySid -is [string] -and $inherited[0].ObjectType -ceq $objectId -and
            $inherited[0].InheritedObjectType -ceq $inheritedId) 'Inherited native ACE lost its SID or object GUIDs.'
    }
    Test-Projection {
        $invalid = [byte[]]@(0, 1, 2, 3, 4, 5, 6, 7)
        Assert-ProjectionFailure { $projector.ProjectAces($invalid, $target, 'OU') } 'The direct API accepted a malformed binary descriptor.'
        Assert-ProjectionFailure { Get-ADAnalyzerSecurityAces $invalid $target 'OU' } 'The compatibility command accepted a malformed binary descriptor under Stop.'
    }
}

Assert-Projection ($script:UnexpectedCalls -eq 0) 'Projection invoked a guarded external operation.'
Write-Host ('PASS directory object projector {0} {1}' -f $Case, $script:Checks)
