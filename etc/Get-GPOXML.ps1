[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('Domain', 'FQDN')][string]$CliDomain,
    [Alias('Server')][string]$CliServer,
    [Alias('Name')][string]$CliName,
    [Alias('Guid')][guid]$CliGuid,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty,
    [Alias('InputObject')]$CliInputObject,
    [Alias('OutputPath')][string]$CliOutputPath
)

class ADAnalyzerGpoXmlInventory {
    ADAnalyzerGpoXmlInventory() {
    }

    [string] RenderProvided([object]$Report) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Report -or $null -eq $Report.Gpo -or $null -eq $Report.Policy) {
            throw 'InputObject requires a package Gpo and Policy report.'
        }
        $id = [guid]::Empty
        if (-not $this.ReadIdentity([string]$Report.Gpo.Id, [ref]$id) -or
            -not $this.ValidFlags([string]$Report.Gpo.Flags)) {
            throw 'Offline XML requires a valid GPO Id and supplied Flags (0..3).'
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADGpo.ps1')
        $normalizerType = [type]'ADAnalyzerGpoSourceNormalizer'
        $writerType = [type]'ADAnalyzerGpoXmlWriter'
        $policy = $normalizerType::new().Normalize($Report.Policy)
        $text = $writerType::new().Render($Report.Gpo, $policy)
        return $this.Canonicalize($text, $Report.Gpo)
    }

    [string] Collect([hashtable]$Selection) {
        return $this.Collect($Selection, [pscredential]::Empty)
    }

    [string] Collect([hashtable]$Selection, [pscredential]$Credential) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $Selection) {
            throw 'An explicit Domain is required.'
        }
        foreach ($key in $Selection.PSBase.Keys) {
            if ($key -notin 'Domain', 'Server', 'Name', 'Guid') {
                throw 'Unsupported GPO selection field.'
            }
        }
        $domain = [string]$Selection['Domain']
        $server = [string]$Selection['Server']
        $name = [string]$Selection['Name']
        $hasName = $Selection.ContainsKey('Name')
        $hasGuid = $Selection.ContainsKey('Guid')
        if ($this.MissingText($domain)) {
            throw 'An explicit Domain is required.'
        }
        if (-not $this.SelectsOneTarget($hasName, $hasGuid)) {
            throw 'Select exactly one Name or Guid.'
        }
        if ($hasName -and $this.MissingText($name)) {
            throw 'Name cannot be empty.'
        }
        $guid = [guid]::Empty
        if ($hasGuid -and -not $this.ReadIdentity([string]$Selection['Guid'], [ref]$guid)) {
            throw 'GPO GUID must be supplied.'
        }
        if (-not $server) {
            $server = $domain
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADGpo.ps1')
        $catalogType = [type]'ADAnalyzerGpoCatalog'
        $catalog = $catalogType::new()
        if ($hasGuid) {
            $policies = $catalog.FindById($guid, $domain, $server, $Credential)
        }
        else {
            $policies = $catalog.FindByName($name, $domain, $server, $Credential)
        }
        if ($this.IsAmbiguousSelection($policies.Count)) {
            throw 'GPO was not found or the selector was ambiguous.'
        }
        $metadata = $policies[0]
        $reportType = [type]'ADAnalyzerGpoReportService'
        $text = $reportType::new().RenderXml($metadata, $Credential)
        return $this.Canonicalize($text, $metadata)
    }

    [string] ExportProvided([object]$Report, [string]$Path) {
        return $this.ExportProvided($Report, $Path, $false)
    }

    [string] ExportProvided([object]$Report, [string]$Path, [bool]$DryRun) {
        return $this.ExportReport($Report, $null, [pscredential]::Empty, $Path, $DryRun, $false)
    }

    [string] ExportSelected([hashtable]$Selection, [string]$Path) {
        return $this.ExportSelected($Selection, $Path, [pscredential]::Empty, $false)
    }

    [string] ExportSelected([hashtable]$Selection, [string]$Path, [pscredential]$Credential) {
        return $this.ExportSelected($Selection, $Path, $Credential, $false)
    }

    [string] ExportSelected([hashtable]$Selection, [string]$Path, [pscredential]$Credential, [bool]$DryRun) {
        return $this.ExportReport($null, $Selection, $Credential, $Path, $DryRun, $true)
    }

    hidden [string] ExportReport(
        [object]$Report,
        [hashtable]$Selection,
        [pscredential]$Credential,
        [string]$Path,
        [bool]$DryRun,
        [bool]$Live
    ) {
        $ErrorActionPreference = 'Stop'
        if ([string]::IsNullOrEmpty($Path)) {
            throw 'An XML output path is required.'
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADFile.ps1')
        $destination = Resolve-ADAnalyzerFilePath $Path
        $xml = if ($Live) {
            $this.Collect($Selection, $Credential)
        }
        else {
            $this.RenderProvided($Report)
        }
        if (-not $DryRun) {
            $null = Write-ADAnalyzerFile -Path $destination -Content $xml
        }
        return $xml
    }

    hidden [string] Canonicalize([string]$Text, [object]$Metadata) {
        $ErrorActionPreference = 'Stop'
        if ($this.MissingText($Text)) {
            throw 'The GPO report is empty.'
        }
        $readerSettings = $this.ReaderSettings()
        $stringReader = [IO.StringReader]::new($Text)
        $reader = $null
        try {
            $reader = [Xml.XmlReader]::Create($stringReader, $readerSettings)
            $document = $this.NewDocument()
            $document.Load($reader)
        }
        finally {
            if ($null -ne $reader) {
                $reader.Dispose()
            }
            $stringReader.Dispose()
        }
        if (-not $this.IsPackageRoot($document.PSBase.DocumentElement.PSBase.LocalName)) {
            throw 'The report is not package GPO XML.'
        }
        $identity = [guid]::Empty
        if (-not $this.ReadIdentity([string]$Metadata.Id, [ref]$identity)) {
            throw 'The selected GPO identity is invalid.'
        }
        foreach ($field in $this.MetadataFields()) {
            $value = if ($field -eq 'Id') {
                $identity.ToString('D')
            }
            else {
                $Metadata.$field
            }
            $this.SetMetadata($document, $field, $value)
        }
        $repository = Split-Path -Parent $PSScriptRoot
        . (Join-Path $repository 'bin/ADSecret.ps1')
        $projectorType = [type]'ADAnalyzerSecretIndicator'
        $safe = $projectorType::new().ProjectXml($document)
        return $this.FormatDocument($safe)
    }

    hidden [string[]] LiveInputFields() {
        return @('Domain', 'Server', 'Name', 'Guid', 'Credential')
    }

    hidden [bool] SelectsOneTarget([bool]$HasName, [bool]$HasGuid) {
        return ([int]$HasName + [int]$HasGuid) -eq 1
    }

    hidden [bool] MissingText([string]$Value) {
        return [string]::IsNullOrWhiteSpace($Value)
    }

    hidden [hashtable] CollectionArguments(
        [string]$Domain,
        [string]$Server,
        [string]$Name,
        [object]$Guid,
        [bool]$HasGuid,
        [pscredential]$Credential
    ) {
        $arguments = @{
            Domain = $Domain
            Credential = $Credential
        }
        if ($Server) {
            $arguments.Server = $Server
        }
        if ($HasGuid) {
            $arguments.Guid = $Guid
        }
        else {
            $arguments.Name = $Name
        }
        return $arguments
    }

    hidden [bool] IsAmbiguousSelection([int]$Count) {
        return $Count -ne 1
    }

    hidden [bool] ReadIdentity([string]$Value, [ref]$Identity) {
        return [guid]::TryParse($Value, $Identity)
    }

    hidden [bool] ValidFlags([string]$Value) {
        $flags = 0
        return [int]::TryParse($Value, [ref]$flags) -and $flags -ge 0 -and $flags -le 3
    }

    hidden [Xml.XmlReaderSettings] ReaderSettings() {
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        return $settings
    }

    hidden [xml] NewDocument() {
        $document = [xml]::new()
        $document.XmlResolver = $null
        return $document
    }

    hidden [bool] IsPackageRoot([object]$Name) {
        return ($Name -eq 'GPO')
    }

    hidden [string[]] MetadataFields() {
        return @('Id', 'DisplayName', 'Domain', 'Server', 'Flags')
    }

    hidden [void] SetMetadata([xml]$Document, [string]$Field, [object]$Value) {
        if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) {
            return
        }
        $root = $Document.PSBase.DocumentElement
        $node = $root.SelectSingleNode('./' + $Field)
        if ($null -eq $node) {
            $node = $Document.CreateElement($Field)
            $null = $root.AppendChild($node)
        }
        $node.PSBase.InnerText = [string]$Value
    }

    hidden [string] FormatDocument([Xml.XmlNode]$Safe) {
        if ($Safe.PSBase.FirstChild -is [Xml.XmlDeclaration]) {
            $Safe.PSBase.FirstChild.PSBase.Encoding = 'utf-8'
        }
        else {
            $null = $Safe.PrependChild($Safe.CreateXmlDeclaration('1.0', 'utf-8', $null))
        }
        return $Safe.PSBase.OuterXml
    }
}

function Get-ADAnalyzerGpoXml {
    <# Retrieve package canonical XML, optionally saving it. Stored policy is not RSoP. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Alias('FQDN')][string]$Domain,
        [string]$Server,
        [string]$Name,
        [guid]$Guid,
        [pscredential]$Credential = [pscredential]::Empty,
        $InputObject,
        [string]$OutputPath

    )
    $inventory = [ADAnalyzerGpoXmlInventory]::new()
    $repository = Split-Path -Parent $PSScriptRoot
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        foreach ($field in $inventory.LiveInputFields()) {
            if ($PSBoundParameters.ContainsKey($field)) {
                throw 'Choose InputObject or explicit live target inputs.'
            }
        }
        if ($null -eq $InputObject.Gpo -or $null -eq $InputObject.Policy) {
            throw 'InputObject requires a package Gpo and Policy report.'
        }
        $id = [guid]::Empty
        if (-not $inventory.ReadIdentity([string]$InputObject.Gpo.Id, [ref]$id) -or
            -not $inventory.ValidFlags([string]$InputObject.Gpo.Flags)) {
            throw 'Offline XML requires a valid GPO Id and supplied Flags (0..3).'
        }
        $metadata = $InputObject.Gpo
        . (Join-Path $repository 'bin/ADGpo.ps1')
        $policy = ConvertTo-ADAnalyzerProvidedGpoPolicy -Policy $InputObject.Policy
        $text = ConvertTo-AnalyzerGpoXml -Gpo $InputObject.Gpo -Parsed $policy
    }
    else {
        if ($inventory.MissingText($Domain)) {
            throw 'An explicit Domain is required.'
        }
        $hasName = $PSBoundParameters.ContainsKey('Name')
        $hasGuid = $PSBoundParameters.ContainsKey('Guid')
        if (-not $inventory.SelectsOneTarget($hasName, $hasGuid)) {
            throw 'Select exactly one Name or Guid.'
        }
        if ($hasName -and $inventory.MissingText($Name)) {
            throw 'Name cannot be empty.'
        }
        Import-Module (Join-Path $repository 'ADEnvironment.psd1') -ErrorAction Stop
        $arguments = $inventory.CollectionArguments($Domain, $Server, $Name, $Guid, $hasGuid, $Credential)
        $selected = @(Get-ADAnalyzerGpo @arguments)
        if ($inventory.IsAmbiguousSelection($selected.Count)) {
            throw 'GPO was not found or the selector was ambiguous.'
        }
        $metadata = $selected[0]
        $text = Get-ADAnalyzerGpoReport -Gpo $selected[0] -Credential $Credential
    }
    if ($inventory.MissingText([string]$text)) {
        throw 'The GPO report is empty.'
    }
    . (Join-Path $repository 'bin/ADSecret.ps1')
    . (Join-Path $repository 'bin/ADFile.ps1')
    $settings = $inventory.ReaderSettings()
    $stringReader = [IO.StringReader]::new([string]$text)
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create($stringReader, $settings)
        $document = $inventory.NewDocument()
        $document.Load($reader)
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        $stringReader.Dispose()
    }
    if (-not $inventory.IsPackageRoot($document.PSBase.DocumentElement.PSBase.LocalName)) {
        throw 'The report is not package GPO XML.'
    }
    $identity = [guid]::Empty
    if (-not $inventory.ReadIdentity([string]$metadata.Id, [ref]$identity)) {
        throw 'The selected GPO identity is invalid.'
    }
    foreach ($field in $inventory.MetadataFields()) {
        $value = if ($field -eq 'Id') {
            $identity.ToString('D')
        }
        else {
            $metadata.$field
        }
        $inventory.SetMetadata($document, $field, $value)
    }
    $safe = ConvertTo-ADAnalyzerSecretIndicatorXml $document
    $xml = $inventory.FormatDocument($safe)
    if ($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath, 'Save package GPO XML')) {
        $null = Write-ADAnalyzerFile -Path $OutputPath -Content $xml
    }
    return $xml
}
if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{}
    foreach ($name in @('Domain', 'Server', 'Name', 'Guid', 'Credential', 'InputObject', 'OutputPath')) {
        if ($PSBoundParameters.ContainsKey('Cli' + $name)) {
            $arguments[$name] = Get-Variable -Name ('Cli' + $name) -ValueOnly
        }
    }
    $arguments.WhatIf = [bool]$WhatIfPreference
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $arguments.Confirm = $PSBoundParameters.Confirm
    }
    Get-ADAnalyzerGpoXml @arguments
}
