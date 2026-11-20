[CmdletBinding()]
param(
    [ValidateSet('Parity', 'Collision')]
    [string]$Case
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$null = [Reflection.Assembly]::LoadFrom((Join-Path $root 'lib/Microsoft.ActiveDirectory.Management.dll'))
$module = Import-Module (Join-Path $root 'bin/ADEnvironment.psm1') -PassThru

# The eight method bodies below are the originals on 11dc0db, executed in their
# PowerShell class and module context. They intentionally retain adapted access.
$reference = @'
using namespace System.Collections

using namespace System.Collections.Specialized

class LegacyValuesReferenceTable : Table {
    [void]FormatData() {

        $table = @{}

        $key = $this.Properties.Key

        $list = $this.Values | ForEach-Object {
            ([Collections.IDictionary].GetProperty('Keys')).GetValue($_, $null)
        } | Sort-Object -Unique | Where-Object {
            $_ -notin $this.Properties.Exclude
        }

        $this.Values | ForEach-Object {

            $object = [Format]::OrderedProperties($_, $list)

            $table[$object.($key)] = $object
        }

        $this.Properties.SetPropertyNames($list)

        $table.GetEnumerator() | ForEach-Object { $this[$_.Name] = $_.Value }
    }
    [void]ExportCSV([String]$value) {

        [Export]::CSV($this.Values, $value)
    }
}

class LegacyValuesReferenceUser : UserData {
    [void]GetReport() {

        $table = [UserTable]::SetDefault()

        $this.Data.Values | ForEach-Object { $table[$_.($table.Properties.Key)] = [UserObject]::Initialize($_) }

        $this.Report = $table
    }
    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Report.Values | ForEach-Object { $array.AddItem([UserObject]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()
    }
}

class LegacyValuesReferenceGroup : GroupData {
    [void]GetReport() {

        $table = [GroupTable]::SetDefault()

        $this.Data.Values | ForEach-Object { $table[$_.($table.Properties.Key)] = [GroupObject]::Initialize($_) }

        $this.Report = $table
    }
    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Report.Values | ForEach-Object { $array.AddItem([GroupObject]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()
    }
}

class LegacyValuesReferenceComputer : ComputerData {
    [void]GetReport() {

        $table = [ComputerTable]::SetDefault()

        $this.Data.Values | ForEach-Object { $table[$_.($table.Properties.Key)] = [ComputerObject]::Initialize($_) }

        $this.Report = $table
    }
    [void]GetFinding() {

        $array = [Finding]::New()

        $this.Report.Values | ForEach-Object { $array.AddItem([ComputerObject]::Analyze($_)) }

        $this.Finding = $array

        $this.SyncFindings()
    }
}
'@

& $module {
    param(
        $Case,
        $Reference

    )

    function Assert-LegacyValues($Condition, [string]$Message) {
        if (-not $Condition) {
            throw $Message
        }
    }

    function New-LegacyValuesRow([string]$Id, [string]$Kind) {
        [ordered]@{
            samaccountname = $Id
            name = $Id
            distinguishedName = ('CN=' + $Id + ',OU=Fixture,DC=example,DC=invalid')
            userPrincipalName = ($Id + '@example.invalid')
            objectGUID = [guid]'02600000-0000-0000-0000-000000000001'
            SID = [pscustomobject]@{
                Value = 'S-1-5-21-1-2-3-1101'
            }
            enabled = $true
            adminCount = 0
            primaryGroupID = 513
            userAccountControl = 512
            memberOf = @()
            members = @()
            managedBy = ''
            acctType = 'unknown'
            AllowedReversiblePasswordEncryption = ($Kind -eq 'User')
            OperatingSystem = 'Fixture OS'
            'orgUnit.L0' = 'Fixture'
            passwordlastset = $null
            lastlogondate = $null
            whenChanged = $null
            whenCreated = $null
            'days.whenChanged' = $null
            'days.whenCreated' = $null
            'days.pwdLastSet' = $null
            'days.lastlogon' = $null
        }
    }

    function Get-LegacyValuesData([Table]$Table) {
        if ($null -eq $Table) {
            return $null
        }

        [pscustomobject]@{
            Type = if ($Table -is [LegacyValuesReferenceTable]) {
                'Table'
            }
            else {
                $Table.GetType().Name
            }
            Columns = @($Table.Properties.GetNames())
            Rows = @(
                foreach ($entry in $Table.GetEnumerator()) {
                    [pscustomobject]@{
                        Key = $entry.Key
                        Value = $entry.Value
                    }
                }
            )
        }
    }

    function Get-LegacyValuesError($Record) {
        $cause = $Record.Exception.GetBaseException()
        [pscustomobject]@{
            Cause = $cause.GetType().FullName
            Message = $cause.Message
            Category = [string]$Record.CategoryInfo.Category
            Id = $Record.FullyQualifiedErrorId
        }
    }

    function Invoke-LegacyValuesCase($Type, [string]$Kind, [string]$Method, [string]$State) {
        [FindingData]::Instance = [FindingData]::new()
        $script:LegacyValuesSink.Clear()
        $subject = $Type::new()
        $table = switch ($Kind) {
            User {
                [UserTable]::SetDefault()
            }
            Group {
                [GroupTable]::SetDefault()
            }
            Computer {
                [ComputerTable]::SetDefault()
            }
            Table {
                $subject
            }
        }
        $ids = switch ($State) {
            Single {
                'ordinary-a'
            }
            Multiple {
                'ordinary-a'
                'ordinary-b'
            }
            Collision {
                'Values'
                'ordinary-b'
            }
            Reserved {
                'vAlUeS'
                'PSBase'
                'ordinary-b'
            }
            NullRow {
                'ordinary-a'
            }
        }

        if ($Kind -eq 'Table') {
            $table.Properties.SetKey('Name')
        }
        foreach ($id in $ids) {
            if ($State -eq 'NullRow') {
                $table[$id] = $null
            }
            elseif ($Kind -eq 'Table') {
                $row = [ordered]@{
                    Name = $id
                }
                $row['Field-' + $id] = $id
                $table[$id] = $row
            }
            else {
                $table[$id] = New-LegacyValuesRow $id $Kind
            }
        }

        if ($Kind -ne 'Table' -and $State -ne 'Uninitialized') {
            if ($State -eq 'Null') {
                $table = $null
            }
            if ($Method -eq 'GetReport') {
                $subject.Data = $table
            }
            else {
                $subject.Report = $table
            }
        }

        $before = ConvertTo-Json -InputObject (Get-LegacyValuesData $table) -Depth 20 -Compress
        $caught = $null
        $success = [Collections.Generic.List[object]]::new()
        $stream = [Collections.Generic.List[object]]::new()
        try {
            & {
                switch ($Method) {
                    GetReport {
                        $subject.GetReport()
                    }
                    GetFinding {
                        $subject.GetFinding()
                    }
                    FormatData {
                        $subject.FormatData()
                    }
                    ExportCSV {
                        $subject.ExportCSV('legacy-values-memory.csv')
                    }
                }
            } 2>&1 | ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    $stream.Add((Get-LegacyValuesError $_))
                }
                else {
                    $success.Add($_)
                }
            }
        }
        catch {
            $caught = Get-LegacyValuesError $_
        }

        $sameInput = $true
        if ($Kind -ne 'Table') {
            $inputTable = if ($Method -eq 'GetReport') {
                $subject.Data
            }
            else {
                $subject.Report
            }
            $expectedInput = if ($State -eq 'Uninitialized') {
                $null
            }
            else {
                $table
            }
            $sameInput = [object]::ReferenceEquals($inputTable, $expectedInput)
        }

        $report = if ($Kind -ne 'Table') {
            Get-LegacyValuesData $subject.Report
        }
        else {
            $null
        }
        $findings = if ($Kind -ne 'Table' -and $null -ne $subject.Finding) {
            @($subject.Finding)
        }
        else {
            @()
        }
        $after = Get-LegacyValuesData $table
        [pscustomobject]@{
            Before = $before
            After = $after
            SameInput = $sameInput
            Report = $report
            Findings = @($findings)
            FindingAssigned = ($Kind -ne 'Table' -and $null -ne $subject.Finding)
            Synced = @([FindingData]::Instance | ForEach-Object { $_ })
            Writes = @($script:LegacyValuesSink.ToArray())
            Success = @($success.ToArray())
            Stream = @($stream.ToArray())
            Caught = $caught
        }
    }

    . ([scriptblock]::Create($Reference))
    $pairs = [ordered]@{
        User = @([UserData], [LegacyValuesReferenceUser])
        Group = @([GroupData], [LegacyValuesReferenceGroup])
        Computer = @([ComputerData], [LegacyValuesReferenceComputer])
        Table = @([Table], [LegacyValuesReferenceTable])
    }
    $previousDomain = [DomainData]::Instance
    $previousObject = [ObjectData]::Instance
    $previousFinding = [FindingData]::Instance
    $previousWriter = (Get-Command Write-ADAnalyzerFile -CommandType Function).ScriptBlock
    $previousProfile = Get-Variable ADAnalyzerLegacyProfile -Scope Script -ErrorAction SilentlyContinue
    $hadProfile = $null -ne $previousProfile
    $profileSnapshot = if ($hadProfile) {
        $previousProfile.Value
    }
    else {
        $null
    }
    $script:LegacyValuesSink = [Collections.Generic.List[object]]::new()
    $passed = 0

    try {

        function script:Write-ADAnalyzerFile {
            param(
                $Path,
                $Content

            )

            Assert-LegacyValues ($Path -eq 'legacy-values-memory.csv') 'A legacy test attempted a real file write.'
            $script:LegacyValuesSink.Add([pscustomobject]@{
                    Path = $Path
                    Content = $Content
                })
            return $Path
        }
        $script:ADAnalyzerLegacyProfile = Get-ADAnalyzerDefaultProfile
        [DomainData]::Instance = [DomainData]::new()
        [DomainData]::Instance.DomainSID = 'S-1-5-21-1-2-3'
        [DomainData]::Instance.RootDomainSID = 'S-1-5-21-1-2-3'
        [DomainData]::Instance.WellKnownSID = @{}
        [ObjectData]::Instance = [ObjectData]::new()
        [ObjectData]::Instance.MembershipIndex = New-ADAnalyzerMembershipIndex -Groups @()

        foreach ($kind in $pairs.Keys) {
            $actualType, $referenceType = $pairs[$kind]
            if ($kind -eq 'Table') {
                $methods = @('FormatData', 'ExportCSV')
                $ordinaryStates = @('Empty', 'Single', 'Multiple', 'NullRow')
            }
            else {
                $methods = @('GetReport', 'GetFinding')
                $ordinaryStates = @('Uninitialized', 'Null', 'Empty', 'Single', 'Multiple', 'NullRow')
            }

            foreach ($method in $methods) {
                Assert-LegacyValues ($referenceType.GetMethod($method).DeclaringType -eq $referenceType) "Missing original $kind $method."
                if ($Case -eq 'Parity') {
                    foreach ($state in $ordinaryStates) {
                        $expected = Invoke-LegacyValuesCase $referenceType $kind $method $state
                        $actual = Invoke-LegacyValuesCase $actualType $kind $method $state
                        $expectedJson = ConvertTo-Json -InputObject $expected -Depth 25 -Compress
                        $actualJson = ConvertTo-Json -InputObject $actual -Depth 25 -Compress
                        Assert-LegacyValues ($actualJson -ceq $expectedJson) "Legacy $kind $method changed its $state behavior."
                        if ($method -eq 'GetReport' -and $state -eq 'Multiple') {
                            Assert-LegacyValues ($actual.Report.Rows.Count -eq 2) 'Expected the actual report method to execute.'
                        }
                        if ($method -eq 'GetFinding' -and $kind -eq 'Group' -and $state -eq 'Null') {
                            Assert-LegacyValues ($actual.Findings.Count -eq 2) 'Expected the original null Group finding path.'
                        }
                        $passed++
                    }
                    continue
                }

                foreach ($state in @('Collision', 'Reserved')) {
                    $actual = Invoke-LegacyValuesCase $actualType $kind $method $state
                    $ids = if ($state -eq 'Collision') {
                        @('ordinary-b', 'Values')
                    }
                    else {
                        @('ordinary-b', 'PSBase', 'vAlUeS')
                    }
                    Assert-LegacyValues ($null -eq $actual.Caught -and
                        $actual.Stream.Count -eq 0 -and
                        $actual.Success.Count -eq 0) "Legacy $kind $method did not complete cleanly."
                    Assert-LegacyValues $actual.SameInput "Legacy $kind $method replaced its input."
                    if ($method -ne 'FormatData') {
                        $after = ConvertTo-Json -InputObject $actual.After -Depth 20 -Compress
                        Assert-LegacyValues ($after -ceq $actual.Before) "Legacy $kind $method changed its input."
                    }
                    switch ($method) {
                        FormatData {
                            Assert-LegacyValues ($actual.After.Rows.Count -eq $ids.Count) 'FormatData changed the number of rows.'
                            foreach ($row in $actual.After.Rows) {
                                foreach ($id in $ids) {
                                    Assert-LegacyValues ($row.Value.Contains('Field-' + $id)) 'FormatData dropped a sibling column.'
                                }
                                Assert-LegacyValues ($row.Value['Field-' + $row.Key] -ceq $row.Key) 'FormatData changed a row value.'
                            }
                        }
                        ExportCSV {
                            Assert-LegacyValues ($actual.Writes.Count -eq 1) 'Expected one legacy CSV write.'
                            $rows = @($actual.Writes[0].Content | ConvertFrom-Csv)
                            Assert-LegacyValues ($rows.Count -eq $ids.Count) 'Legacy CSV dropped sibling rows.'
                            $inputOrder = (ConvertFrom-Json $actual.Before).Rows.Key -join '|'
                            Assert-LegacyValues (($rows.Name -join '|') -ceq $inputOrder) 'Legacy CSV changed native row order.'
                            foreach ($id in $ids) {
                                $row = @($rows | Where-Object Name -CEQ $id)
                                Assert-LegacyValues ($row.Count -eq 1 -and
                                    $row[0].('Field-' + $id) -ceq $id) 'Legacy CSV lost a row identity or value.'
                            }
                        }
                        GetReport {
                            Assert-LegacyValues ($actual.Report.Rows.Count -eq $ids.Count) "Legacy $kind report dropped sibling rows in $state. Actual: $($actual.Report.Rows.Count)."
                            foreach ($id in $ids) {
                                $row = @($actual.Report.Rows | Where-Object Key -CEQ $id)
                                Assert-LegacyValues ($row.Count -eq 1 -and
                                    $row[0].Value['samaccountname'] -ceq $id) "Legacy $kind report lost a row identity."
                            }
                        }
                        GetFinding {
                            $perRow = if ($kind -eq 'Group') {
                                2
                            }
                            else {
                                1
                            }
                            $count = $ids.Count * $perRow
                            Assert-LegacyValues ($actual.Findings.Count -eq $count -and
                                $actual.Synced.Count -eq $count) "Legacy $kind omitted sibling findings."
                            $expectedOrder = foreach ($entry in (ConvertFrom-Json $actual.Before).Rows) {
                                for ($index = 0; $index -lt $perRow; $index++) {
                                    $entry.Key
                                }
                            }
                            Assert-LegacyValues (($actual.Findings.samaccountname -join '|') -ceq ($expectedOrder -join '|')) "Legacy $kind changed native finding order."
                            foreach ($id in $ids) {
                                $rows = @($actual.Findings | Where-Object samaccountname -CEQ $id)
                                $synced = @($actual.Synced | Where-Object {
                                        $_.class -ceq $kind -and (ConvertFrom-Json $_.object).samaccountname -ceq $id
                                    })
                                Assert-LegacyValues ($rows.Count -eq $perRow -and
                                    $synced.Count -eq $perRow) "Legacy $kind did not synchronize all findings for its row."
                            }
                        }
                    }
                    $passed++
                }
            }
        }

        $expectedCount = if ($Case -eq 'Parity') {
            44
        }
        else {
            16
        }
        Assert-LegacyValues ($passed -eq $expectedCount) "Expected $expectedCount legacy cases and ran $passed."
        "PASS legacy table values $Case $passed"
    }
    finally {
        [DomainData]::Instance = $previousDomain
        [ObjectData]::Instance = $previousObject
        [FindingData]::Instance = $previousFinding
        if ($hadProfile) {
            $script:ADAnalyzerLegacyProfile = $profileSnapshot
        }
        else {
            Remove-Variable ADAnalyzerLegacyProfile -Scope Script -ErrorAction SilentlyContinue
        }
        Set-Item Function:script:Write-ADAnalyzerFile -Value $previousWriter
        Remove-Variable LegacyValuesSink -Scope Script -ErrorAction SilentlyContinue
    }
} $Case $reference
