[CmdletBinding()]
param(
    [ValidateSet('Construction', 'Ordered', 'Cycles', 'Aliases', 'Duplicates', 'Snapshot', 'Serialization', 'Isolation', 'LongChain', 'DirectoryRoute', 'RecordBaseline')]
    [string]$Case = 'Construction'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ($Case -eq 'DirectoryRoute') {
    . (Join-Path $repositoryRoot 'bin/ADProfile.ps1')
    . (Join-Path $repositoryRoot 'bin/ADDirectoryAnalysis.ps1')
}
else {
    . (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
}

function Assert-Graph($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-GraphGroups {
    @(
        [pscustomobject]@{
            DistinguishedName = 'CN=Child'
            SID = 'S-1-5-21-1-2-3-1100'
            MemberOf = @('CN=Parent')
        },
        [pscustomobject]@{
            DistinguishedName = 'CN=Parent'
            SID = 'S-1-5-21-1-2-3-512'
            MemberOf = @('CN=Child')
        },
        [pscustomobject]@{
            DistinguishedName = 'CN=Primary'
            objectSid = [pscustomobject]@{
                Value = 'S-1-5-21-1-2-3-513'
            }
            MemberOf = @()
        }
    )
}

function New-GraphObject {
    [pscustomobject]@{
        objectSid = 'S-1-5-21-1-2-3-9000'
        PrimaryGroupID = 513
        MemberOf = @('cn=child', 'CN=Foreign', 'S-1-5-99-7')
    }
}

function New-DuplicateGroups {
    @(
        [pscustomobject]@{
            DistinguishedName = 'CN=Dup'
            SID = 'S-1-5-21-1-2-3-3100'
            MemberOf = @('CN=MissingOld')
        },
        [pscustomobject]@{
            DistinguishedName = 'CN=Dup'
            SID = 'S-1-5-21-1-2-3-3200'
            MemberOf = @()
        },
        [pscustomobject]@{
            DistinguishedName = 'CN=Other'
            SID = 'S-1-5-21-1-2-3-3200'
            MemberOf = @('CN=MissingNew')
        }
    )
}

if ($Case -eq 'RecordBaseline') {
    Assert-Graph (-not ('ADAnalyzerMembershipGraph' -as [type])) 'Record the baseline only before the class conversion.'
    $arguments = @{
        Object = (New-GraphObject)
        Groups = @(New-GraphGroups)
        DomainSid = 'S-1-5-21-1-2-3'
        PrivilegedSids = @('S-1-5-21-1-2-3-512')
    }
    $ordered = Resolve-ADAnalyzerMembership @arguments
    'Ordered=' + (ConvertTo-Json -InputObject $ordered -Depth 10 -Compress)
    foreach ($roots in @(
            @('CN=Dup', 'S-1-5-21-1-2-3-3200', 'CN=Other', 'S-1-5-21-1-2-3-3100'),
            @('S-1-5-21-1-2-3-3200', 'CN=Dup')
        )) {
        $value = Resolve-ADAnalyzerMembership -Object ([pscustomobject]@{
                MemberOf = $roots
            }) -Groups @(New-DuplicateGroups)
        'Duplicate=' + (ConvertTo-Json -InputObject $value -Depth 10 -Compress)
    }
    return
}

Assert-Graph ([bool]('ADAnalyzerMembershipGraph' -as [type])) 'The constructor-based membership graph is missing.'


function Assert-GraphResult($Expected, $Actual) {
    Assert-Graph ($null -ne $Actual) 'Membership result is missing.'
    Assert-Graph (@($Actual.PSObject.Properties).Count -eq 7) 'Membership DTO field count changed.'
    foreach ($name in @('DirectSids', 'EffectiveSids', 'PrivilegedSids', 'Unresolved', 'Cycles')) {
        $expectedValues = @($Expected.$name)
        $actualValues = @($Actual.$name)
        Assert-Graph ($expectedValues.Count -eq $actualValues.Count) ($name + ' count changed.')
        for ($i = 0; $i -lt $expectedValues.Count; $i++) {
            Assert-Graph ($expectedValues[$i] -ceq $actualValues[$i]) ($name + ' ordering or value changed.')
        }
        Assert-Graph ($Actual.$name -is [array]) ($name + ' is no longer an array.')
    }
    Assert-Graph ($Actual.EffectiveSids -is [string[]]) 'Effective SID array type changed.'
    Assert-Graph ($Actual.IsPrivileged -is [bool]) 'Privilege flag type changed.'
    Assert-Graph ($Expected.IsPrivileged -eq $Actual.IsPrivileged) 'Privilege decision changed.'
    Assert-Graph ($Expected.ResolutionStatus -ceq $Actual.ResolutionStatus) 'Resolution status changed.'
}

# Captured from the original function at a45a77df7448312d263ac429155260b0d2ac603c.
$orderedExpected = ConvertFrom-Json @'
{"DirectSids":["S-1-5-21-1-2-3-1100","CN=Foreign","S-1-5-99-7","S-1-5-21-1-2-3-513"],"EffectiveSids":["S-1-5-21-1-2-3-1100","S-1-5-21-1-2-3-512","S-1-5-99-7","S-1-5-21-1-2-3-513"],"PrivilegedSids":["S-1-5-21-1-2-3-512"],"IsPrivileged":true,"Unresolved":["CN=Foreign","S-1-5-99-7"],"Cycles":["S-1-5-21-1-2-3-1100"],"ResolutionStatus":"Unknown"}
'@
$duplicateExpected = @(
    (ConvertFrom-Json @'
{"DirectSids":["S-1-5-21-1-2-3-3200","S-1-5-21-1-2-3-3100"],"EffectiveSids":["S-1-5-21-1-2-3-3200","S-1-5-21-1-2-3-3100"],"PrivilegedSids":[],"IsPrivileged":false,"Unresolved":["CN=MissingOld"],"Cycles":[],"ResolutionStatus":"Unknown"}
'@),
    (ConvertFrom-Json @'
{"DirectSids":["S-1-5-21-1-2-3-3200"],"EffectiveSids":["S-1-5-21-1-2-3-3200"],"PrivilegedSids":[],"IsPrivileged":false,"Unresolved":["CN=MissingNew"],"Cycles":[],"ResolutionStatus":"Unknown"}
'@)
)

switch ($Case) {
    'Construction' {
        $graph = [ADAnalyzerMembershipGraph]::new()
        $result = $graph.Resolve($null)
        Assert-Graph (-not $result.IsPrivileged) 'Null object gained privilege.'
        Assert-Graph ($result.ResolutionStatus -eq 'Complete') 'Null object gained unresolved evidence.'
        foreach ($name in @('DirectSids', 'EffectiveSids', 'PrivilegedSids', 'Unresolved', 'Cycles')) {
            Assert-Graph ($result.$name.Count -eq 0) 'Null object result is not empty.'
        }
        Assert-Graph (@(Get-Module ActiveDirectory, GroupPolicy).Count -eq 0) 'Construction imported a native directory module.'
        Assert-Graph ($graph.State.GetType().GetProperties().Count -eq 0) 'Internal state exposes serialized properties.'
        $nullGraph = [ADAnalyzerMembershipGraph]::new([object[]]$null)
        Assert-Graph ($nullGraph.Resolve($null).ResolutionStatus -eq 'Complete') 'Null groups no longer construct an empty graph.'
    }

    'Ordered' {
        $groups = @(New-GraphGroups)
        $object = New-GraphObject
        $before = ConvertTo-Json -InputObject @($object, $groups) -Depth 12 -Compress
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $actual = $graph.Resolve($object, 'S-1-5-21-1-2-3', @('S-1-5-21-1-2-3-512'))
        Assert-GraphResult $orderedExpected $actual
        $arguments = @{
            Object = $object
            Groups = $groups
            DomainSid = 'S-1-5-21-1-2-3'
            PrivilegedSids = @('S-1-5-21-1-2-3-512')
        }
        Assert-GraphResult $orderedExpected (Resolve-ADAnalyzerMembership @arguments)
        Assert-Graph ($before -ceq (ConvertTo-Json -InputObject @($object, $groups) -Depth 12 -Compress)) 'Resolution mutated caller inputs.'

        # A present null SID suppresses the fallback; an absent SID uses objectSid.
        $groups = @(
            [pscustomobject]@{
                DistinguishedName = 'CN=NullSid'
                SID = $null
                objectSid = 'S-1-5-21-1-2-3-1500'
                MemberOf = @('CN=Primary')
            },
            (New-GraphGroups)[2]
        )
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $result = $graph.Resolve([pscustomobject]@{
                MemberOf = @('CN=NullSid')
            })
        Assert-Graph ($result.DirectSids.Count -eq 0) 'Present null SID incorrectly used objectSid fallback.'
        Assert-Graph (($result.EffectiveSids -join ',') -ceq 'S-1-5-21-1-2-3-513') 'Raw objectSid fallback was lost.'
        Assert-Graph (($result.Unresolved -join ',') -ceq 'CN=NullSid:SID') 'Missing SID evidence changed.'
        Assert-Graph ($result.ResolutionStatus -eq 'Unknown') 'Missing SID was treated as complete.'
    }

    'Cycles' {
        $groups = @(
            [pscustomobject]@{
                DistinguishedName = 'CN=A'
                SID = 'S-1-5-21-1-2-3-1100'
                MemberOf = @('CN=C')
            },
            [pscustomobject]@{
                DistinguishedName = 'CN=B'
                SID = 'S-1-5-21-1-2-3-1200'
                MemberOf = @('CN=C')
            },
            [pscustomobject]@{
                DistinguishedName = 'CN=C'
                SID = 'S-1-5-21-1-2-3-1300'
                MemberOf = @()
            }
        )
        $object = [pscustomobject]@{
            MemberOf = @('CN=A', 'CN=B', 'CN=C')
        }
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $result = $graph.Resolve($object)
        Assert-Graph ($result.Cycles.Count -eq 0) 'Shared ancestor became a cycle.'
        Assert-Graph (($result.EffectiveSids -join ',') -ceq 'S-1-5-21-1-2-3-1100,S-1-5-21-1-2-3-1300,S-1-5-21-1-2-3-1200') 'Diamond traversal order changed.'
        $groups[2].MemberOf = @('CN=A')
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $result = $graph.Resolve($object)
        Assert-Graph (($result.Cycles -join ',') -ceq 'S-1-5-21-1-2-3-1100') 'Back-edge witness changed.'
    }

    'Aliases' {
        $group = [pscustomobject]@{
            DistinguishedName = 'CN=Real'
            SID = 'S-1-5-21-1-2-3-2000'
            MemberOf = @()
        }
        $index = New-ADAnalyzerMembershipIndex -Groups @($group)
        Assert-Graph ([object]::ReferenceEquals($group, $index.ByDn['CN=Real'])) 'Legacy DN index copied the group.'
        Assert-Graph ([object]::ReferenceEquals($group, $index.BySid[$group.SID])) 'Legacy SID index copied the group.'
        $index.ByDn['CustomAlias'] = $group
        $index.BySid['S-1-5-99-42'] = $group
        $object = [pscustomobject]@{
            MemberOf = @('customalias', 'S-1-5-99-42')
        }
        $result = Resolve-ADAnalyzerMembership -Object $object -GroupIndex $index
        Assert-Graph (($result.EffectiveSids -join ',') -ceq $group.SID) 'Custom map aliases were discarded.'
        $group.SID = 'S-1-5-21-1-2-3-2001'
        $group.MemberOf = @('CN=Missing')
        $result = Resolve-ADAnalyzerMembership -Object $object -GroupIndex $index -Groups @(New-GraphGroups)
        Assert-Graph (($result.EffectiveSids -join ',') -ceq $group.SID) 'Borrowed index stopped reflecting the original group reference.'
        Assert-Graph (($result.Unresolved -join ',') -ceq 'CN=Missing') 'Borrowed parent update was ignored.'
    }

    'Duplicates' {
        $groups = @(New-DuplicateGroups)
        $index = New-ADAnalyzerMembershipIndex -Groups $groups
        Assert-Graph ([object]::ReferenceEquals($groups[1], $index.ByDn['cn=dup'])) 'DN duplicate last-write changed.'
        Assert-Graph ([object]::ReferenceEquals($groups[0], $index.BySid['S-1-5-21-1-2-3-3100'])) 'Older SID alias was removed.'
        Assert-Graph ([object]::ReferenceEquals($groups[2], $index.BySid['S-1-5-21-1-2-3-3200'])) 'SID duplicate last-write changed.'
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $roots = @(
            @('CN=Dup', 'S-1-5-21-1-2-3-3200', 'CN=Other', 'S-1-5-21-1-2-3-3100'),
            @('S-1-5-21-1-2-3-3200', 'CN=Dup')
        )
        for ($i = 0; $i -lt $roots.Count; $i++) {
            $object = [pscustomobject]@{
                MemberOf = $roots[$i]
            }
            Assert-GraphResult $duplicateExpected[$i] ($graph.Resolve($object))
            Assert-GraphResult $duplicateExpected[$i] (Resolve-ADAnalyzerMembership -Object $object -GroupIndex $index)
        }
    }

    'Snapshot' {
        $parent = [pscustomobject]@{
            DistinguishedName = 'CN=Parent'
            SID = [pscustomobject]@{
                Value = 'S-1-5-21-1-2-3-512'
            }
            MemberOf = @()
        }
        $parents = [object[]]@('CN=Parent', $null, 0, $false, '')
        $child = [pscustomobject]@{
            DistinguishedName = 'CN=Child'
            objectSid = [pscustomobject]@{
                Value = 'S-1-5-21-1-2-3-1100'
            }
            MemberOf = $parents
        }
        $groups = [object[]]@($child, $parent)
        $object = [pscustomobject]@{
            MemberOf = @('CN=Child')
        }
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $before = $graph.Resolve($object)
        Assert-Graph ($before.ResolutionStatus -eq 'Complete') 'Falsy parent values became memberships.'
        $parents[0] = 'CN=Missing'
        $child.objectSid.Value = 'S-1-5-21-1-2-3-1101'
        $parent.SID.Value = 'S-1-5-21-1-2-3-9999'
        $groups[1] = $null
        Assert-GraphResult $before ($graph.Resolve($object))
        $newGraph = [ADAnalyzerMembershipGraph]::new($groups)
        $after = $newGraph.Resolve($object)
        Assert-Graph (($after.EffectiveSids -join ',') -ceq 'S-1-5-21-1-2-3-1101') 'New graph did not capture current source.'
        Assert-Graph (($after.Unresolved -join ',') -ceq 'CN=Missing') 'New graph did not capture parent changes.'
    }

    'Serialization' {
        $marker = 'graph-fixture-sensitive-value'
        $groups = @(New-GraphGroups)
        $groups[0] | Add-Member NoteProperty Password $marker
        $groups[0] | Add-Member NoteProperty Credential ([pscredential]::new(
                'fixture-user',
                (ConvertTo-SecureString $marker -AsPlainText -Force)
            ))
        $graph = [ADAnalyzerMembershipGraph]::new($groups)
        $json = ConvertTo-Json -InputObject $graph -Depth 20 -Compress
        $xml = [Management.Automation.PSSerializer]::Serialize($graph)
        Assert-Graph (-not $json.Contains($marker) -and -not $xml.Contains($marker)) 'Graph serialization exposed input secret values.'
        Assert-Graph (-not $json.Contains('CN=Child') -and -not $xml.Contains('CN=Child')) 'Graph serialization exposed its internal group snapshot.'
        Assert-Graph ($graph.State.GetType().GetProperties().Count -eq 0) 'Private capsule exposes public properties.'
        $stored = $graph.State.GetValue().ByDn['CN=Child']
        Assert-Graph (@($stored.PSObject.Properties).Count -eq 3) 'Graph retained unrelated native group fields.'
    }

    'Isolation' {
        $groups = @(New-GraphGroups)
        $first = [ADAnalyzerMembershipGraph]::new($groups)
        $second = [ADAnalyzerMembershipGraph]::new()
        $object = New-GraphObject
        $original = $first.Resolve($object, 'S-1-5-21-1-2-3', @('S-1-5-21-1-2-3-512'))
        $original.EffectiveSids[0] = 'mutated-output'
        $original.Unresolved[0] = 'mutated-output'
        $original.IsPrivileged = $false
        for ($i = 0; $i -lt 3; $i++) {
            Assert-GraphResult $orderedExpected ($first.Resolve($object, 'S-1-5-21-1-2-3', @('S-1-5-21-1-2-3-512')))
        }
        $empty = $second.Resolve($object, 'S-1-5-21-1-2-3')
        Assert-Graph (-not $empty.IsPrivileged) 'A second graph inherited privilege state.'
        Assert-Graph ($empty.Cycles.Count -eq 0) 'A second graph inherited cycle state.'
        $foreign = $second.Resolve([pscustomobject]@{
                MemberOf = @('S-1-5-21-1-2-3-8888')
            }, '', @('S-1-5-21-1-2-3-8888'))
        Assert-Graph ($foreign.IsPrivileged -and $foreign.ResolutionStatus -eq 'Unknown') 'Unresolved privileged SID lost fail-closed evidence.'
    }

    'LongChain' {
        $groups = [Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt 2048; $i++) {
            $groups.Add([pscustomobject]@{
                    DistinguishedName = ('CN=Chain' + $i)
                    SID = ('S-1-5-21-1-2-3-' + (6000 + $i))
                    MemberOf = if ($i -lt 2047) {
                        @('CN=Chain' + ($i + 1))
                    }
                    else {
                        @('CN=Chain1024', 'CN=Unavailable')
                    }
                })
        }
        $graph = [ADAnalyzerMembershipGraph]::new($groups.ToArray())
        $result = $graph.Resolve([pscustomobject]@{
                MemberOf = @('CN=Chain0')
            })
        Assert-Graph ($result.EffectiveSids.Count -eq 2048) 'Deep traversal lost groups.'
        Assert-Graph ($result.Cycles.Count -eq 1) 'Deep traversal lost the back-edge witness.'
        Assert-Graph (($result.Unresolved -join ',') -ceq 'CN=Unavailable') 'Deep traversal lost unresolved evidence.'
    }

    'DirectoryRoute' {
        Assert-Graph (-not ('ADAnalyzerAssessmentEngine' -as [type])) 'Directory-only route loaded an unrelated assessment engine.'
        $graph = [ADAnalyzerMembershipGraph]::new(@(New-GraphGroups))
        Assert-GraphResult $orderedExpected ($graph.Resolve(
                (New-GraphObject),
                'S-1-5-21-1-2-3',
                @('S-1-5-21-1-2-3-512')
            ))
    }
}

Write-Output ('PASS membership graph ' + $Case)
