[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('Domain', 'FQDN')][string]$CliDomain,
    [Alias('Server')][string]$CliServer,
    [Alias('Name')][string]$CliName,
    [Alias('Guid')][guid]$CliGuid,
    [Alias('All')][switch]$CliAll,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty,
    [Alias('InputObject')][object[]]$CliInputObject,
    [Alias('ProfilePath')][string]$CliProfilePath,
    [Alias('OutputPath')][string]$CliOutputPath,
    [Alias('Format')][ValidateSet('Json', 'Html', 'Csv', 'All')][string]$CliFormat = 'Csv'
)

class ADAnalyzerLocalAdminPolicyInventory {
    ADAnalyzerLocalAdminPolicyInventory() {
    }

    [object[]] AnalyzeProvided([object[]]$Reports) {
        return $this.AnalyzeProvided($Reports, '')
    }

    [object[]] AnalyzeProvided([object[]]$Reports, [string]$ProfilePath) {
        if ($null -eq $Reports) {
            throw 'InputObject requires package Gpo and Policy reports.'
        }
        return $this.ReadInventory($Reports, $null, $ProfilePath)
    }

    [object[]] Collect([hashtable]$Selection) {
        return $this.Collect($Selection, [pscredential]::Empty, '')
    }

    [object[]] Collect([hashtable]$Selection, [pscredential]$Credential) {
        return $this.Collect($Selection, $Credential, '')
    }

    [object[]] Collect([hashtable]$Selection, [pscredential]$Credential, [string]$ProfilePath) {
        if ($null -eq $Selection) {
            throw 'An explicit Domain is required.'
        }
        foreach ($key in $Selection.PSBase.Keys) {
            if ($key -notin 'Domain', 'Server', 'Name', 'Guid', 'All') {
                throw 'Unsupported GPO selection field.'
            }
        }
        $domain = [string]$Selection['Domain']
        $server = [string]$Selection['Server']
        $name = [string]$Selection['Name']
        $hasName = $Selection.ContainsKey('Name')
        $hasGuid = $Selection.ContainsKey('Guid')
        $allSelection = $Selection['All']
        if ($null -ne $allSelection -and $allSelection -isnot [bool] -and $allSelection -isnot [switch]) {
            throw 'All must be a Boolean or switch.'
        }
        $all = [bool]$allSelection
        if ($this.MissingDomain($domain)) {
            throw 'An explicit Domain is required.'
        }
        if (-not $this.SelectsOneTarget($hasName, $hasGuid, $all)) {
            throw 'Select exactly one Name, Guid or All.'
        }
        if ($hasName -and $this.MissingName($name)) {
            throw 'Name cannot be empty.'
        }
        $id = [guid]::Empty
        if ($hasGuid -and -not $this.ReadGpoId([string]$Selection['Guid'], [ref]$id)) {
            throw 'GPO GUID must be supplied.'
        }
        $arguments = $this.CollectionArguments($domain, $server, $name, $id, $hasGuid, $all, $Credential)
        return $this.ReadInventory($null, $arguments, $ProfilePath)
    }

    [string[]] Export([object[]]$Rows, [string]$Target, [string]$Path, [string]$Format) {
        return $this.Export($Rows, $Target, $Path, $Format, $false)
    }

    [string[]] Export([object[]]$Rows, [string]$Target, [string]$Path, [string]$Format, [bool]$DryRun) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Rows) {
            throw 'Supply inventory rows to export.'
        }
        if ($this.HasUnreadable($Rows)) {
            throw 'GPO inventory is incomplete; the previous report was preserved.'
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADOperations.ps1')
        $writerType = [type]'ADAnalyzerAssessmentReport'
        return $writerType::new().Write($this.Assessment($Rows, $Target), $Path, $Format, $DryRun)
    }

    hidden [object[]] ReadInventory([object[]]$Reports, [hashtable]$Arguments, [string]$ProfilePath) {
        $ErrorActionPreference = 'Stop'
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADGpo.ps1')
        $offline = $null -eq $Arguments
        if (-not $offline) {
            $catalogType = [type]'ADAnalyzerGpoCatalog'
            $readerType = [type]'ADAnalyzerGpoReportService'
            $catalog = $catalogType::new()
            $reader = $readerType::new()
            $domain = $Arguments.Domain
            $server = $Arguments['Server']
            if (-not $server) {
                $server = $domain
            }
            $credential = $Arguments.Credential
            $all = [bool]$Arguments['All']
            if ($all) {
                $selected = $catalog.GetAll($domain, $server, $credential)
            }
            elseif ($Arguments.ContainsKey('Guid')) {
                $selected = $catalog.FindById($Arguments.Guid, $domain, $server, $credential)
            }
            else {
                $selected = $catalog.FindByName($Arguments.Name, $domain, $server, $credential)
            }
            if ($this.IsAmbiguousSelection($all, $selected.Count)) {
                throw 'GPO was not found or the selector was ambiguous.'
            }
            $Reports = @(foreach ($gpo in $selected) {
                    try {
                        $reader.Read($gpo, $credential)
                    }
                    catch {
                        $this.ReadFailure($gpo, $_.Exception.GetType().FullName)
                    }
                })
        }

        foreach ($file in 'ADPolicyAnalysis', 'ADProfile', 'ADOperations') {
            . (Join-Path $repository ('bin/' + $file + '.ps1'))
        }
        $profileType = [type]'ADAnalyzerProfile'
        $profile = if ($ProfilePath) {
            $profileType::Load($ProfilePath).ToHashtable()
        }
        else {
            $profileType::new().ToHashtable()
        }
        $normalizerType = [type]'ADAnalyzerGpoSourceNormalizer'
        $evaluatorType = [type]'ADAnalyzerGpoPolicyEvaluator'
        $checkType = [type]'ADAnalyzerCheckFactory'
        $projectorType = [type]'ADAnalyzerEvidenceProjector'
        $normalizer = $normalizerType::new()
        $evaluator = $evaluatorType::new()
        $factory = $checkType::new()
        $projector = $projectorType::new()
        $rows = [Collections.Generic.List[object]]::new()

        foreach ($report in $Reports) {
            $id = [guid]::Empty
            if ($null -eq $report.Gpo -or -not $this.ReadGpoId([string]$report.Gpo.Id, [ref]$id)) {
                throw 'Each report requires a valid GPO identity.'
            }
            if ($offline -and -not $this.HasValidFlags([string]$report.Gpo.Flags)) {
                throw 'Offline inventory requires supplied GPO Flags (0..3).'
            }
            $metadata = [ordered]@{}
            foreach ($field in $this.MetadataFields()) {
                $metadata[$field] = $report.Gpo.$field
            }
            $reportFrame = @{
                Record = $report
            }
            if (((Test-ADAnalyzerOptionalSecretRecordMember $reportFrame 'ReadError') -and $report.ReadError) -or
                $null -eq $report.Policy) {
                $errorType = $null
                if (Test-ADAnalyzerOptionalSecretRecordMember $reportFrame 'ErrorType') {
                    $errorType = $report.ErrorType
                }
                $checks = @($factory.Create($this.UnreadableCheck($id, $errorType)))
            }
            else {
                $policy = if ($offline) {
                    $normalizer.Normalize($report.Policy)
                }
                else {
                    $report.Policy
                }
                $checks = $evaluator.Evaluate($report.Gpo, $policy, $profile)
            }
            foreach ($check in $checks) {
                if ($this.IncludesRule($check.RuleId) -or $this.IncludesCategory($check.Category)) {
                    $this.PopulateRow($check, $metadata, $id, ([string]$report.Gpo.DisplayName), $offline)
                    $rows.Add($projector.Project($check))
                }
            }
        }
        return $rows.ToArray()
    }

    hidden [string[]] LiveInputFields() {
        return @('Domain', 'Server', 'Name', 'Guid', 'All', 'Credential')
    }

    hidden [bool] MissingDomain([string]$Domain) {
        return [string]::IsNullOrWhiteSpace($Domain)
    }

    hidden [bool] MissingName([string]$Name) {
        return [string]::IsNullOrWhiteSpace($Name)
    }

    hidden [bool] SelectsOneTarget([bool]$HasName, [bool]$HasGuid, [bool]$All) {
        return ([int]$HasName + [int]$HasGuid + [int]$All) -eq 1
    }

    hidden [hashtable] CollectionArguments(
        [string]$Domain, [string]$Server, [string]$Name, [object]$Id,
        [bool]$HasGuid, [bool]$All, [pscredential]$Credential
    ) {
        $arguments = @{
            Domain = $Domain
            Credential = $Credential
        }
        if ($Server) {
            $arguments.Server = $Server
        }
        if ($All) {
            $arguments.All = $true
        }
        elseif ($HasGuid) {
            $arguments.Guid = $Id
        }
        else {
            $arguments.Name = $Name
        }
        return $arguments
    }

    hidden [bool] IsAmbiguousSelection([bool]$All, [int]$Count) {
        return -not $All -and $Count -ne 1
    }

    hidden [object] ReadFailure([object]$Gpo, [string]$ErrorType) {
        return [pscustomobject]@{
            Gpo = $Gpo
            Policy = $null
            ReadError = $true
            ErrorType = $ErrorType
        }
    }

    hidden [bool] ReadGpoId([string]$Value, [ref]$Id) {
        return [guid]::TryParse($Value, $Id)
    }

    hidden [bool] HasValidFlags([string]$Value) {
        $flags = 0
        return [int]::TryParse($Value, [ref]$flags) -and $flags -ge 0 -and $flags -le 3
    }

    hidden [string[]] MetadataFields() {
        return @('Id', 'DisplayName', 'Domain', 'Server', 'Flags', 'Version', 'Links', 'WmiFilter')
    }

    hidden [hashtable] UnreadableCheck([guid]$Id, [object]$ErrorType) {
        return @{
            RuleId = 'GPO.READ'
            Status = 'Unreadable'
            Severity = 'High'
            Category = 'PolicyCoverage'
            Target = $Id.ToString('D')
            Message = 'The selected GPO could not be read; configuration was not assessed.'
            Evidence = @{
                ErrorType = $ErrorType
            }
        }
    }

    hidden [bool] IncludesRule([object]$RuleId) {
        return $RuleId -in 'GPO.RestrictedGroups.LocalAdministrators', 'GPO.Preferences.LocalUsersGroups'
    }

    hidden [bool] IncludesCategory([object]$Category) {
        return $Category -in 'CredentialExposure', 'PolicyCoverage'
    }

    hidden [void] PopulateRow(
        [object]$Check, [Collections.Specialized.OrderedDictionary]$Metadata,
        [guid]$Id, [string]$Name, [bool]$Offline
    ) {
        $Check.Evidence = [pscustomobject]@{
            Gpo = [pscustomobject]$Metadata
            ConfiguredSetting = $Check.Observed
            RuleEvidence = $Check.Evidence
        }
        $Check | Add-Member -NotePropertyName GpoId -NotePropertyValue $Id.ToString('D')
        $Check | Add-Member -NotePropertyName GpoName -NotePropertyValue $Name
        $metadataStatus = if ($Offline) {
            'Provided'
        }
        else {
            'Collected'
        }
        $Check | Add-Member -NotePropertyName MetadataStatus -NotePropertyValue $metadataStatus
    }

    hidden [bool] HasUnreadable([object[]]$Rows) {
        return @($Rows | Where-Object Status -eq Unreadable).Count -ne 0
    }

    hidden [object] Assessment([object[]]$Rows, [string]$Target) {
        $state = if (@($Rows | Where-Object Status -in 'Unknown', 'Invalid').Count) {
            'Partial'
        }
        else {
            'Complete'
        }
        return [pscustomobject]@{
            SchemaVersion = 1
            Target = $Target
            State = $state
            Checks = $Rows
            Findings = $Rows
            Errors = @()
            Coverage = @{
                Total = $Rows.Count
            }
        }
    }
}

function Get-ADAnalyzerLocalAdminGpo {
    <# Inventory stored local-group configuration and exposure; effective membership is not calculated. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Alias('FQDN')][string]$Domain,
        [string]$Server,
        [string]$Name,
        [guid]$Guid,
        [switch]$All,
        [pscredential]$Credential = [pscredential]::Empty,
        [object[]]$InputObject,
        [string]$ProfilePath,
        [string]$OutputPath,
        [ValidateSet('Json', 'Html', 'Csv', 'All')][string]$Format = 'Csv'

    )
    $inventory = [ADAnalyzerLocalAdminPolicyInventory]::new()
    $repository = Split-Path -Parent $PSScriptRoot
    $offline = $PSBoundParameters.ContainsKey('InputObject')
    if ($offline) {
        foreach ($field in $inventory.LiveInputFields()) {
            if ($PSBoundParameters.ContainsKey($field)) {
                throw 'Choose InputObject or explicit live target inputs.'
            }
        }
        if ($null -eq $InputObject) {
            throw 'InputObject requires package Gpo and Policy reports.'
        }
        foreach ($file in @('ADGpo', 'ADPolicyAnalysis')) {
            . (Join-Path $repository ('bin/' + $file + '.ps1'))
        }
        $reports = @($InputObject)
    }
    else {
        if ($inventory.MissingDomain($Domain)) {
            throw 'An explicit Domain is required.'
        }
        $hasName = $PSBoundParameters.ContainsKey('Name')
        $hasGuid = $PSBoundParameters.ContainsKey('Guid')
        if (-not $inventory.SelectsOneTarget($hasName, $hasGuid, [bool]$All)) {
            throw 'Select exactly one Name, Guid or All.'
        }
        if ($hasName -and $inventory.MissingName($Name)) {
            throw 'Name cannot be empty.'
        }
        Import-Module (Join-Path $repository 'ADEnvironment.psd1') -ErrorAction Stop
        $arguments = $inventory.CollectionArguments(
            $Domain, $Server, $Name, $Guid, $hasGuid, [bool]$All, $Credential
        )
        $selected = @(Get-ADAnalyzerGpo @arguments)
        if ($inventory.IsAmbiguousSelection([bool]$All, $selected.Count)) {
            throw 'GPO was not found or the selector was ambiguous.'
        }
        $reports = @(foreach ($gpo in $selected) {
                try {
                    Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $Credential -AsObject
                }
                catch {
                    $inventory.ReadFailure($gpo, $_.Exception.GetType().FullName)
                }
            })
    }
    # The manifest intentionally exports public APIs only. These transport-free
    # helpers stay local to the adapter, including when a live module is loaded.
    foreach ($file in @('ADProfile', 'ADOperations')) {
        . (Join-Path $repository ('bin/' + $file + '.ps1'))
    }
    $profile = if ($ProfilePath) {
        Import-ADAnalyzerProfile -Path $ProfilePath
    }
    else {
        Import-ADAnalyzerProfile
    }
    $rows = @(foreach ($report in $reports) {
            $id = [guid]::Empty
            if ($null -eq $report.Gpo -or -not $inventory.ReadGpoId([string]$report.Gpo.Id, [ref]$id)) {
                throw 'Each report requires a valid GPO identity.'
            }
            if ($offline -and -not $inventory.HasValidFlags([string]$report.Gpo.Flags)) {
                throw 'Offline inventory requires supplied GPO Flags (0..3).'
            }
            $metadata = [ordered]@{}
            foreach ($field in $inventory.MetadataFields()) {
                $metadata[$field] = $report.Gpo.$field
            }
            $reportFrame = @{
                Record = $report
            }
            if (((Test-ADAnalyzerOptionalSecretRecordMember $reportFrame 'ReadError') -and $report.ReadError) -or
                $null -eq $report.Policy) {
                $errorType = $null
                if (Test-ADAnalyzerOptionalSecretRecordMember $reportFrame 'ErrorType') {
                    $errorType = $report.ErrorType
                }
                $unreadableCheck = $inventory.UnreadableCheck($id, $errorType)
                $checks = @(New-ADAnalyzerCheck @unreadableCheck)
            }
            else {
                $policy = if ($offline) {
                    ConvertTo-ADAnalyzerProvidedGpoPolicy -Policy $report.Policy
                }
                else {
                    $report.Policy
                }
                $checks = @(Test-ADAnalyzerGpoPolicy -Gpo $report.Gpo -Policy $policy -Profile $profile | Where-Object {
                        $inventory.IncludesRule($_.RuleId) -or $inventory.IncludesCategory($_.Category)
                    })
            }
            foreach ($check in $checks) {
                $inventory.PopulateRow($check, $metadata, $id, ([string]$report.Gpo.DisplayName), $offline)
                ConvertTo-ADAnalyzerSafeData $check
            }
        })
    $unreadable = $inventory.HasUnreadable($rows)
    if ($OutputPath) {
        if ($unreadable) {
            throw 'GPO inventory is incomplete; the previous report was preserved.'
        }
        $target = if ($offline) {
            'provided GPO reports'
        }
        else {
            $Domain
        }
        $assessment = $inventory.Assessment($rows, $target)
        $null = Export-ADAnalyzerAssessment `
            -Assessment $assessment `
            -Path $OutputPath `
            -Format $Format `
            -WhatIf:$WhatIfPreference `
            -Confirm:$false
    }
    return $rows
}
if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{
        Format = $CliFormat
    }
    foreach ($name in @('Domain', 'Server', 'Name', 'Guid', 'All', 'Credential', 'InputObject', 'ProfilePath', 'OutputPath')) {
        if ($PSBoundParameters.ContainsKey('Cli' + $name)) {
            $arguments[$name] = Get-Variable -Name ('Cli' + $name) -ValueOnly
        }
    }
    $arguments.WhatIf = [bool]$WhatIfPreference
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $arguments.Confirm = $PSBoundParameters.Confirm
    }
    Get-ADAnalyzerLocalAdminGpo @arguments
}
