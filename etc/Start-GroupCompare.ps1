[CmdletBinding()]
param(
    [Alias('SourceGroup')][string]$CliSourceGroup,
    [Alias('ReferenceGroup')][string]$CliReferenceGroup,
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty
)

class ADAnalyzerGroupComparison {
    hidden [string]$SourceIdentity
    hidden [string]$ReferenceIdentity

    ADAnalyzerGroupComparison([string]$SourceGroup, [string]$ReferenceGroup) {
        if ([string]::IsNullOrWhiteSpace($SourceGroup) -or
            [string]::IsNullOrWhiteSpace($ReferenceGroup)) {
            throw 'Specify nonempty source and reference group identities.'
        }
        $this.SourceIdentity = $SourceGroup
        $this.ReferenceIdentity = $ReferenceGroup
    }

    [string[]] Compare(
        [Management.Automation.CommandInfo]$GroupReader,
        [Management.Automation.CommandInfo]$ObjectReader,
        [hashtable]$Connection
    ) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $GroupReader -or $null -eq $ObjectReader -or $null -eq $Connection) {
            throw 'Group and object readers and connection parameters are required.'
        }
        if ([string]::IsNullOrWhiteSpace($this.SourceIdentity) -or
            [string]::IsNullOrWhiteSpace($this.ReferenceIdentity)) {
            throw 'Specify nonempty source and reference group identities.'
        }

        $groupArguments = $Connection.Clone()
        $groupArguments.Properties = @('Member')
        $groupArguments.ErrorAction = 'Stop'
        $groupArguments.Identity = $this.SourceIdentity
        $source = @(& $GroupReader @groupArguments)
        $groupArguments.Identity = $this.ReferenceIdentity
        $reference = @(& $GroupReader @groupArguments)
        if ($source.Count -ne 1 -or $reference.Count -ne 1 -or
            $null -eq $source[0] -or $null -eq $reference[0]) {
            throw 'Each group identity must resolve to exactly one record.'
        }

        $referenceMembers = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($member in @($reference[0].Member)) {
            if ($null -eq $member) {
                continue
            }
            if ($member -isnot [string] -or [string]::IsNullOrWhiteSpace($member)) {
                throw 'Group membership must contain nonempty distinguished names.'
            }
            $null = $referenceMembers.Add($member)
        }
        $missingMembers = [Collections.Generic.List[string]]::new()
        foreach ($member in @($source[0].Member)) {
            if ($null -eq $member) {
                continue
            }
            if ($member -isnot [string] -or [string]::IsNullOrWhiteSpace($member)) {
                throw 'Group membership must contain nonempty distinguished names.'
            }
            if (-not $referenceMembers.Contains($member)) {
                $missingMembers.Add($member)
            }
        }

        $objectArguments = $Connection.Clone()
        $objectArguments.Properties = @('SamAccountName')
        $objectArguments.ErrorAction = 'Stop'
        $collectedNames = [Collections.Generic.List[string]]::new()
        foreach ($member in $missingMembers) {
            $objectArguments.Identity = $member
            $found = @(& $ObjectReader @objectArguments)
            if ($found.Count -ne 1 -or
                [string]::IsNullOrWhiteSpace([string]$found[0].SamAccountName)) {
                throw 'A differing member must resolve to exactly one named object.'
            }
            $collectedNames.Add([string]$found[0].SamAccountName)
        }
        return $collectedNames.ToArray()
    }
}

function Get-ADAnalyzerGroupMemberDifference {
    <# .SYNOPSIS Returns direct source-group members absent from a reference group as SAM names. #>
    [CmdletBinding()]
    param(
        [string]$SourceGroup,
        [string]$ReferenceGroup,
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty
    )

    $ErrorActionPreference = 'Stop'
    $comparison = [ADAnalyzerGroupComparison]::new($SourceGroup, $ReferenceGroup)
    $repository = Split-Path -Parent $PSScriptRoot
    $moduleArguments = @{
        Name = Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll'
        Scope = 'Local'
        ErrorAction = 'Stop'
    }
    Import-Module @moduleArguments
    $connection = @{}
    if ($Server) {
        $connection.Server = $Server
    }
    if ($null -ne $Credential -and $Credential -ne [pscredential]::Empty) {
        $connection.Credential = $Credential
    }
    $groupReader = Get-Command Get-ADGroup -ErrorAction Stop
    $objectReader = Get-Command Get-ADObject -ErrorAction Stop
    return $comparison.Compare($groupReader, $objectReader, $connection)
}

if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{
        SourceGroup = $CliSourceGroup
        ReferenceGroup = $CliReferenceGroup
        Credential = $CliCredential
    }
    if ($CliServer) {
        $arguments.Server = $CliServer
    }
    Get-ADAnalyzerGroupMemberDifference @arguments
}
