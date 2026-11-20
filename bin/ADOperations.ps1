# Assessment projections and explicit, reversible remediation. No AD query is
# performed by the exporter, comparer, or planner.
. (Join-Path $PSScriptRoot 'ADSecret.ps1')
. (Join-Path $PSScriptRoot 'ADFile.ps1')

class ADAnalyzerEvidenceProjector {
    ADAnalyzerEvidenceProjector() {
    }

    [object] Project([object]$Value) {
        $result = $this.Project($Value, 0)
        if ($null -eq $result) {
            return $null
        }
        return $result
    }

    [object] Project([object]$Value, [int]$Depth) {
        $result = $this.ProjectBoundFrame(@{
                Value = $Value
                Depth = $Depth
            })
        if ($null -eq $result) {
            return $null
        }
        return $result
    }

    [object] ProjectPowerShellObject([psobject]$Value) {
        $result = $this.ProjectPowerShellObject($Value, 0)
        if ($null -eq $result) {
            return $null
        }
        return $result
    }

    [object] ProjectPowerShellObject([psobject]$Value, [int]$Depth) {
        $result = $this.ProjectBoundFrame(@{
                Value = $Value
                Depth = $Depth
            })
        if ($null -eq $result) {
            return $null
        }
        return $result
    }

    [object] ProjectIdentityMetadata([object]$Value) {
        return $this.ProjectBoundFrame(@{
                Value = $Value
                Depth = 0
                PreserveIdentityTypes = $true
            })
    }

    hidden [object] ProjectBoundFrame([hashtable]$Frame) {
        $ErrorActionPreference = 'Stop'
        $state = $this.CreateState($Frame)
        try {
            while (-not $state.Done) {
                $request = $this.Advance($state)
                if ($state.Done) {
                    break
                }
                switch ($request.Kind) {
                    Child {
                        $child = $this.ChildFrame($request.Arguments, $state.PreserveIdentityTypes)
                        $result = $this.ProjectBoundFrame($child)
                        $this.Accept($state, @{
                                Value = $result
                            })
                    }
                    Presence {
                        $result = $state.SecretService.IsPresent($request.Value)
                        $this.Accept($state, @{
                                Value = $result
                            })
                    }
                    Enumeration {
                        foreach ($item in $request.Value) {
                            $arguments = $this.CreateItemRequest($state, @{
                                    Value = $item
                                })
                            $child = $this.ChildFrame($arguments, $state.PreserveIdentityTypes)
                            $result = $this.ProjectBoundFrame($child)
                            $this.AcceptItem($state, @{
                                    Value = $result
                                })
                        }
                        $this.AcceptEnumeration($state)
                    }
                    default {
                        throw 'Invalid projection request.'
                    }
                }
            }
            $result = $state.Result
            if ($null -eq $result) {
                return $null
            }
            return $result
        }
        catch {
            throw
        }
    }

    hidden [hashtable] CreateState([hashtable]$Frame) {
        $secretType = 'ADAnalyzerSecretIndicator' -as [type]
        return @{
            Input = $Frame.Value
            Depth = [int]$Frame.Depth
            PreserveIdentityTypes = [bool]$Frame['PreserveIdentityTypes']
            Stage = 'Start'
            Pending = $null
            Done = $false
            Result = $null
            SecretService = $secretType::new()
        }
    }

    hidden [hashtable] ChildFrame([hashtable]$Arguments, [bool]$PreserveIdentityTypes) {
        return @{
            Value = $Arguments.InputObject
            Depth = $Arguments.Depth
            PreserveIdentityTypes = $PreserveIdentityTypes
        }
    }

    hidden [hashtable] CreateItemRequest([hashtable]$State, [hashtable]$Frame) {
        return @{
            InputObject = $Frame.Value
            Depth = ($State.Depth + 1)
        }
    }

    hidden [void] Complete([hashtable]$State, [hashtable]$Frame) {
        $State.Result = $Frame.Value
        $State.Pending = $null
        $State.Done = $true
    }

    hidden [void] RequestChild([hashtable]$State, [hashtable]$Frame, [string]$Stage) {
        $State.Stage = $Stage
        $State.Pending = @{
            Kind = 'Child'
            Arguments = $this.CreateItemRequest($State, $Frame)
        }
    }

    hidden [void] RequestPresence([hashtable]$State, [hashtable]$Frame, [string]$Stage) {
        $State.Stage = $Stage
        $State.Pending = @{
            Kind = 'Presence'
            Value = $Frame.Value
        }
    }

    hidden [void] Accept([hashtable]$State, [hashtable]$Frame) {
        if ($null -eq $State.Pending -or $State.Pending.Kind -notin @('Child', 'Presence')) {
            throw 'No projection response is pending.'
        }
        $State.Response = $Frame.Value
        $State.Pending = $null
    }

    hidden [void] AcceptItem([hashtable]$State, [hashtable]$Frame) {
        if ($null -eq $State.Pending -or $State.Pending.Kind -ne 'Enumeration') {
            throw 'No enumeration is pending.'
        }
        $null = $State.Items.Add($Frame.Value)
    }

    hidden [void] AcceptEnumeration([hashtable]$State) {
        if ($null -eq $State.Pending -or $State.Pending.Kind -ne 'Enumeration') {
            throw 'No enumeration is pending.'
        }
        $this.Complete($State, @{
                Value = $State.Items.ToArray()
            })
    }

    hidden [void] MergeFieldPresence([hashtable]$State, [string]$Name, [hashtable]$Frame) {
        if ($null -eq $State.Presence) {
            $State.Presence = [ordered]@{}
        }
        if (-not $State.Presence.Contains($Name)) {
            $State.Presence[$Name] = @{
                HasSource = $false
                Present = $false
                Name = $Name
            }
        }
        $indicator = $State.Presence[$Name]
        $indicator.HasSource = $true
        $indicator.Present = $indicator.Present -or $Frame.Value
        $indicator.Name = $Name
        $State.Output[$Name] = $Frame.Value
    }

    hidden [void] FinishOrdinaryProperty([hashtable]$State) {
        $propertyName = [string]$State.Name
        $State.Output[$propertyName] = $State.Response
        if ($propertyName.EndsWith('Present', [StringComparison]::OrdinalIgnoreCase)) {
            if ($null -eq $State.Presence) {
                $State.Presence = [ordered]@{}
            }
            if (-not $State.Presence.Contains($propertyName)) {
                $State.Presence[$propertyName] = @{
                    HasSource = $false
                    Present = $false
                    Name = $propertyName
                }
            }
            $indicator = $State.Presence[$propertyName]
            if ($State.Value -is [bool] -and $State.Value) {
                $indicator.Present = $true
            }
            $indicator.Name = $propertyName
        }
    }

    hidden [void] FinishRecord([hashtable]$State) {
        $result = $State.Output
        $presence = $State.Presence
        if ($State.TaggedSecret -and $null -ne $presence -and
            $presence.Contains('SecretPresent') -and $presence['SecretPresent'].HasSource) {
            $result.Remove('SecretPresent')
            $presence['SecretPresent'].Name = 'SecretPresent'
        }
        if ($State.TaggedSecret -and $State.HasPresence) {
            $result['SecretPresent'] = $State.Present
            if ($null -ne $presence -and $presence.Contains('SecretPresent')) {
                $presence['SecretPresent'].Name = 'SecretPresent'
            }
        }
        if ($null -ne $presence) {
            foreach ($indicator in $presence.Values) {
                if (-not $indicator.HasSource) {
                    continue
                }
                $fieldPresent = $indicator.Present
                if ($result[$indicator.Name] -is [bool]) {
                    $fieldPresent = $fieldPresent -or $result[$indicator.Name]
                }
                $result[$indicator.Name] = [bool]$fieldPresent
            }
        }
        $this.Complete($State, @{
                Value = [pscustomobject]$result
            })
    }

    hidden [object] Advance([hashtable]$State) {
        while (-not $State.Done -and $null -eq $State.Pending) {
            $InputObject = $State.Input
            $secretService = $State.SecretService
            switch ($State.Stage) {
                Start {
                    if ($null -eq $InputObject) {
                        $this.Complete($State, @{
                                Value = $null
                            })
                    }
                    elseif ($State.Depth -gt 40) {
                        $this.Complete($State, @{
                                Value = '[Depth limit]'
                            })
                    }
                    elseif ($InputObject -is [pscredential] -or $InputObject -is [Security.SecureString]) {
                        $this.RequestPresence($State, @{
                                Value = $InputObject
                            }, 'Credential')
                    }
                    elseif ($InputObject -is [string]) {
                        $this.Complete($State, @{
                                Value = $secretService.ProjectText($InputObject)
                            })
                    }
                    elseif ($State.PreserveIdentityTypes -and
                        ($InputObject -is [datetime] -or $InputObject -is [datetimeoffset] -or $InputObject -is [guid])) {
                        $this.Complete($State, @{
                                Value = $InputObject.PSObject.BaseObject
                            })
                    }
                    elseif ($InputObject -is [datetime] -or $InputObject -is [datetimeoffset]) {
                        $this.Complete($State, @{
                                Value = $InputObject.ToUniversalTime().ToString('o')
                            })
                    }
                    elseif ($InputObject -is [guid]) {
                        $this.Complete($State, @{
                                Value = $InputObject.ToString('D')
                            })
                    }
                    else {
                        $inputType = $InputObject.GetType()
                        if ($inputType.IsPrimitive -or $inputType.IsEnum -or
                            $inputType.FullName -in @('System.Decimal', 'System.TimeSpan',
                                'System.Numerics.BigInteger', 'System.Half', 'System.Int128', 'System.UInt128')) {
                            $this.Complete($State, @{
                                    Value = $InputObject
                                })
                        }
                        elseif ($InputObject -is [Collections.DictionaryEntry] -or
                            ($inputType.IsGenericType -and
                            $inputType.GetGenericTypeDefinition().FullName -eq 'System.Collections.Generic.KeyValuePair`2')) {
                            $State.Output = [ordered]@{}
                            $this.RequestChild($State, @{
                                    Value = $InputObject.Key
                                }, 'PairKey')
                        }
                        elseif ($InputObject -is [Xml.XmlNode]) {
                            $safeXml = $secretService.ProjectXml($InputObject)
                            $this.Complete($State, @{
                                    Value = $secretService.ProjectText($safeXml.PSBase.OuterXml)
                                })
                        }
                        elseif ($InputObject -is [Collections.IEnumerable] -and
                            $InputObject -isnot [Collections.IDictionary] -and
                            $InputObject -isnot [pscustomobject]) {
                            $State.Items = [Collections.ArrayList]::new()
                            $State.Pending = @{
                                Kind = 'Enumeration'
                                Value = $InputObject
                            }
                        }
                        else {
                            $State.Output = [ordered]@{}
                            $State.Presence = $null
                            $State.Properties = [Collections.ArrayList]::new()
                            $State.TaggedSecret = $false
                            $State.Present = $false
                            $State.HasPresence = $false
                            $State.Index = 0
                            $State.LabelIndex = 0
                            $State.Stage = 'Labels'
                            $properties = if ($InputObject -is [Collections.IDictionary]) {
                                @(([Collections.IDictionary].GetProperty('Keys')).GetValue($InputObject, $null))
                            }
                            else {
                                foreach ($property in $InputObject.PSObject.Properties) {
                                    $property.Name
                                }
                            }
                            foreach ($name in $properties) {
                                $null = $State.Properties.Add(@{
                                        Name = $name
                                    })
                            }
                        }
                    }
                }
                Credential {
                    $this.Complete($State, @{
                            Value = [pscustomobject]@{
                                SecretPresent = $State.Response
                            }
                        })
                }
                PairKey {
                    $State.Output.Key = $State.Response
                    if ($secretService.IsSecretName(([string]$InputObject.Key))) {
                        $this.RequestPresence($State, @{
                                Value = $InputObject.Value
                            }, 'PairPresence')
                    }
                    else {
                        $this.RequestChild($State, @{
                                Value = $InputObject.Value
                            }, 'PairValue')
                    }
                }
                PairPresence {
                    $State.Output.SecretPresent = $State.Response
                    $this.Complete($State, @{
                            Value = [pscustomobject]$State.Output
                        })
                }
                PairValue {
                    $State.Output.Value = $State.Response
                    $this.Complete($State, @{
                            Value = [pscustomobject]$State.Output
                        })
                }
                Labels {
                    $labels = @('Name', 'Attribute', 'AttributeName', 'Property',
                        'PropertyName', 'SettingName', 'ValueName')
                    if ($State.LabelIndex -ge $labels.Count) {
                        $State.Stage = 'Properties'
                        continue
                    }
                    $labelName = $labels[$State.LabelIndex]
                    $State.LabelIndex++
                    if ($secretService.IsSecretName(([string]($this.GetValueFrame(@{
                                            Object = $InputObject
                                            Names = @($labelName)
                                            Default = $null
                                        }))))) {
                        $State.TaggedSecret = $true
                    }
                }
                Properties {
                    if ($State.Index -ge $State.Properties.Count) {
                        $this.FinishRecord($State)
                        continue
                    }
                    $State.Name = $State.Properties[$State.Index].Name
                    $State.Index++
                    if ($InputObject -is [Collections.IDictionary]) {
                        $State.Value = $InputObject[$State.Name]
                    }
                    else {
                        $State.Value = $InputObject.PSObject.Properties[$State.Name].Value
                    }
                    if ($secretService.IsSecretName(([string]$State.Name))) {
                        $State.Flag = [string]$State.Name + 'Present'
                        $this.RequestPresence($State, @{
                                Value = $State.Value
                            }, 'NamedPresence')
                    }
                    elseif ($State.TaggedSecret -and
                        [string]$State.Name -in @('Value', 'Observed', 'Expected', 'Data', 'Bytes', 'RawData')) {
                        if ($State.Name -ne 'Expected') {
                            if ($State.Name -eq 'Observed' -and $State.Value -is [bool]) {
                                $State.Present = $State.Present -or $State.Value
                                $State.HasPresence = $true
                            }
                            else {
                                $this.RequestPresence($State, @{
                                        Value = $State.Value
                                    }, 'TaggedPresence')
                            }
                        }
                    }
                    elseif ($State.TaggedSecret -and $State.Name -eq 'SecretPresent') {
                        if ($State.Value -is [bool]) {
                            $State.Present = $State.Present -or $State.Value
                            $State.HasPresence = $true
                        }
                    }
                    else {
                        $this.RequestChild($State, @{
                                Value = $State.Value
                            }, 'OrdinaryProperty')
                    }
                }
                NamedPresence {
                    $this.MergeFieldPresence($State, $State.Flag, @{
                            Value = $State.Response
                        })
                    $State.Stage = 'Properties'
                }
                TaggedPresence {
                    $State.Present = $State.Present -or $State.Response
                    $State.HasPresence = $true
                    $State.Stage = 'Properties'
                }
                OrdinaryProperty {
                    $this.FinishOrdinaryProperty($State)
                    $State.Stage = 'Properties'
                }
                default {
                    throw 'Invalid projection continuation.'
                }
            }
        }
        if ($State.Done) {
            return $null
        }
        return $State.Pending
    }

    [object] GetValue([object]$Object, [string[]]$Names) {
        $result = $this.GetValue($Object, $Names, $null)
        if ($null -eq $result) {
            return $null
        }
        return $result
    }

    [object] GetValue([object]$Object, [string[]]$Names, [object]$Default) {
        $result = $this.GetValueFrame(@{
                Object = $Object
                Names = $Names
                Default = $Default
            })
        if ($null -eq $result) {
            return $null
        }
        return $result
    }

    hidden [hashtable] GetValueForCommand([hashtable]$Frame) {
        return $this.ReadValueFrame($Frame)
    }

    hidden [object] GetValueFrame([hashtable]$Frame) {
        $result = $this.ReadValueFrame($Frame)
        $value = $result.Value
        if ($null -eq $value) {
            return $null
        }
        return $value
    }

    hidden [hashtable] ReadValueFrame([hashtable]$Frame) {
        $Object = $Frame.Object
        [string[]]$Names = $Frame.Names
        $Default = $Frame.Default
        if ($null -eq $Object) {
            return @{
                Value = $Default
            }
        }
        foreach ($name in $Names) {
            if ($Object -is [Collections.IDictionary]) {
                if (([Collections.IDictionary]$Object).Contains($name)) {
                    return @{
                        Value = $Object[$name]
                    }
                }
            }
            else {
                $property = $Object.PSObject.Properties[$name]
                if ($null -ne $property) {
                    return @{
                        Value = $property.Value
                    }
                }
            }
        }
        return @{
            Value = $Default
        }
    }
}

function Invoke-ADAnalyzerPresenceObservation {
    param([AllowNull()]$Value)
    return [ADAnalyzerSecretIndicator]::new().IsPresent($Value)
}

function Get-ADAnalyzerOperationValue {
    param(
        [AllowNull()]$Object,
        [string[]]$Names,
        [AllowNull()]$Default = $null

    )
    $result = [ADAnalyzerEvidenceProjector]::new().GetValueForCommand(@{
            Object = $Object
            Names = $Names
            Default = $Default
        })
    return $result.Value
}

function Get-ADAnalyzerOperationSecretNames {
    Get-ADAnalyzerSecretNames
}

function Protect-ADAnalyzerSecretText {
    param([string]$Text)
    ConvertTo-ADAnalyzerSecretIndicatorText $Text
}

function ConvertTo-ADAnalyzerSafeData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][AllowNull()]$InputObject,
        [int]$Depth = 0

    )
    process {
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $state = $projector.CreateState(@{
                Value = $InputObject
                Depth = $Depth
            })
        while (-not $state.Done) {
            $request = $projector.Advance($state)
            if ($state.Done) {
                break
            }
            switch ($request.Kind) {
                Child {
                    $arguments = $request.Arguments
                    $result = ConvertTo-ADAnalyzerSafeData @arguments
                    $projector.Accept($state, @{
                            Value = $result
                        })
                }
                Presence {
                    $result = Invoke-ADAnalyzerPresenceObservation $request.Value
                    $projector.Accept($state, @{
                            Value = $result
                        })
                }
                Enumeration {
                    foreach ($item in $request.Value) {
                        $arguments = $projector.CreateItemRequest($state, @{
                                Value = $item
                            })
                        $result = ConvertTo-ADAnalyzerSafeData @arguments
                        $projector.AcceptItem($state, @{
                                Value = $result
                            })
                    }
                    $projector.AcceptEnumeration($state)
                }
                default {
                    throw 'Invalid projection request.'
                }
            }
        }
        return , $state.Result
    }
}

class ADAnalyzerOperationDocumentReader {
    ADAnalyzerOperationDocumentReader() {
    }

    [object] Read([object]$InputObject) {
        return $this.Read($InputObject, 'Assessment')
    }

    [object] Read([object]$InputObject, [string]$Kind) {
        $ErrorActionPreference = 'Stop'
        if ($InputObject -is [string]) {
            if (-not (Test-Path -LiteralPath $InputObject -PathType Leaf)) {
                throw "$Kind file does not exist"
            }

            $jsonParameters = @{
                ErrorAction = 'Stop'
            }
            $runtime = Get-Variable -Name PSVersionTable -ValueOnly -ErrorAction Stop
            if ($runtime.PSVersion.Major -ge 7) {
                $jsonParameters.NoEnumerate = $true
            }
            $readParameters = Get-ADAnalyzerJsonReadParameters $InputObject
            $PSDefaultParameterValues = Get-ADAnalyzerJsonReadDefaults
            $InputObject = Microsoft.PowerShell.Management\Get-Content @readParameters |
                ConvertTo-ADAnalyzerJsonText |
                ConvertFrom-Json @jsonParameters
        }

        $document = @{
            Value = $InputObject
        }
        if (-not $this.PrepareRecord($document)) {
            throw "$Kind must be a structured object or JSON file"
        }
        $version = Get-ADAnalyzerOperationValue $document.Value @('SchemaVersion')
        if ($null -ne $version -and -not $this.IsSupportedVersion([string]$version)) {
            throw "Unsupported $Kind SchemaVersion"
        }
        return $document.Value
    }

    hidden [bool] PrepareRecord([hashtable]$Document) {
        $value = $Document.Value
        if ($value -is [array] -and $value.Rank -eq 1 -and $value.Length -eq 1) {
            $value = $value.GetValue($value.GetLowerBound(0))
            $Document.Value = $value
        }
        return -not ($null -eq $value -or
            $value -is [ValueType] -or
            $value -is [string] -or
            ($value -is [Collections.IEnumerable] -and $value -isnot [Collections.IDictionary]))
    }

    hidden [bool] IsSupportedVersion([string]$Version) {
        return ($Version -match '^1(?:\.|$)')
    }
}

function Read-ADAnalyzerOperationDocument {
    param(
        [Parameter(Mandatory)]$InputObject,
        [string]$Kind = 'Assessment'

    )
    if ($InputObject -is [string]) {
        if (-not (Test-Path -LiteralPath $InputObject -PathType Leaf)) {
            throw "$Kind file does not exist"
        }
        $jsonParameters = @{
            ErrorAction = 'Stop'
        }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # Windows PowerShell already passes a decoded array as one object.
            $jsonParameters.NoEnumerate = $true
        }
        $readParameters = Get-ADAnalyzerJsonReadParameters $InputObject
        $PSDefaultParameterValues = Get-ADAnalyzerJsonReadDefaults
        $InputObject = Microsoft.PowerShell.Management\Get-Content @readParameters |
            ConvertTo-ADAnalyzerJsonText |
            ConvertFrom-Json @jsonParameters
    }
    $reader = [ADAnalyzerOperationDocumentReader]::new()
    $document = @{
        Value = $InputObject
    }
    if (-not $reader.PrepareRecord($document)) {
        throw "$Kind must be a structured object or JSON file"
    }
    $InputObject = $document.Value
    $version = Get-ADAnalyzerOperationValue $InputObject @('SchemaVersion')
    if ($null -ne $version -and -not $reader.IsSupportedVersion([string]$version)) {
        throw "Unsupported $Kind SchemaVersion"
    }
    return $InputObject
}

function Resolve-ADAnalyzerOperationFilePath {
    param([Parameter(Mandatory)][string]$Path)
    Resolve-ADAnalyzerFilePath $Path
}

function Write-ADAnalyzerOperationFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [switch]$RequireExisting

    )
    if ($RequireExisting) {
        Write-ADAnalyzerFile -Path $Path -Content $Content -RequireExisting
        return
    }
    Write-ADAnalyzerFile -Path $Path -Content $Content
}

class ADAnalyzerAssessmentReport {
    ADAnalyzerAssessmentReport() {
    }

    [string] Render([object]$Assessment, [string]$Format) {
        $outputs = $this.RenderReports($Assessment, $Format, '', $false)
        return $outputs[0]
    }

    [string[]] Write([object]$Assessment, [string]$Path, [string]$Format) {
        return $this.Write($Assessment, $Path, $Format, $false)
    }

    [string[]] Write([object]$Assessment, [string]$Path, [string]$Format, [bool]$DryRun) {
        if ([string]::IsNullOrEmpty($Path)) {
            throw [ArgumentException]::new('An assessment report output path is required.', 'Path')
        }
        return $this.RenderReports($Assessment, $Format, $Path, $DryRun)
    }

    hidden [hashtable] Prepare([object]$Assessment) {
        $document = [ADAnalyzerOperationDocumentReader]::new().Read($Assessment)
        $safe = [ADAnalyzerEvidenceProjector]::new().Project($document)
        $findings = @(Get-ADAnalyzerOperationValue $safe ($this.FindingNames()) @())
        return @{
            Safe = $safe
            Findings = $findings
        }
    }

    hidden [string[]] GetFormats([string]$Format, [bool]$AllowAll) {
        if ($Format -in 'Json', 'Html', 'Csv') {
            return @($Format)
        }
        if ($AllowAll -and $Format -eq 'All') {
            return @('Json', 'Html', 'Csv')
        }
        if ($AllowAll) {
            throw [ArgumentException]::new('Use Json, Html, Csv, or All.', 'Format')
        }
        throw [ArgumentException]::new('Use Json, Html, or Csv.', 'Format')
    }

    hidden [string] GetOutputPath([string]$Path, [string]$Format, [string]$Item) {
        if ($Format -eq 'All') {
            return $Path.TrimEnd('.') + '.' + $Item.ToLowerInvariant()
        }
        return $Path
    }

    hidden [string[]] FindingNames() {
        return @('Findings', 'Checks')
    }

    hidden [string[]] StatusNames() {
        return @('Pass', 'Fail', 'Unknown', 'Unreadable', 'Invalid', 'NotConfigured', 'NotApplicable')
    }

    hidden [string] GetReviewState([int]$CheckCount, [int]$ErrorCount, [hashtable]$Counts) {
        if (-not $CheckCount) {
            return 'No checks collected'
        }
        if ($ErrorCount -or $Counts.Unknown -or $Counts.Unreadable -or $Counts.Invalid) {
            return 'Incomplete evidence: review unknowns and collection errors'
        }
        if ($Counts.Fail) {
            return 'Failed checks require review'
        }
        return 'No failed checks recorded'
    }

    hidden [Text.StringBuilder] BeginHtml([hashtable]$Fields, [hashtable]$Counts, [string]$State) {
        $builder = [Text.StringBuilder]::new()
        $null = $builder.Append('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AD Analyzer assessment</title><style>body{font:15px system-ui,sans-serif;color:#1e293b;background:#f8fafc;max-width:1450px;margin:2rem auto;padding:0 1.2rem}h1{font-size:2rem;margin-bottom:.3rem}h2{margin-top:2rem}p{line-height:1.5}.meta{color:#475569}.state{border-left:4px solid #2563eb;padding:.8rem 1rem;background:white}.cards{display:flex;flex-wrap:wrap;gap:.6rem;margin:1.2rem 0}.card{background:white;border:1px solid #cbd5e1;border-radius:.4rem;padding:.6rem 1rem}.card b{font-size:1.4rem;display:block}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;background:white;font-size:.9rem}th,td{border:1px solid #cbd5e1;text-align:left;vertical-align:top;padding:.6rem;overflow-wrap:anywhere}th{background:#e2e8f0}.fail{color:#9f1239;font-weight:700}.pass{color:#166534}.unknown{color:#92400e}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:1rem}details{margin:.4rem 0}summary{cursor:pointer;color:#1d4ed8}.muted{color:#64748b}</style></head><body>')
        $null = $builder.Append(
            '<h1>Active Directory assessment</h1><p class="meta">Target: <strong>' +
            $Fields.Target + '</strong><br>Profile: ' + $Fields.ProfileName + ' ' + $Fields.ProfileVersion +
            '<br>State: ' + $Fields.RecordedState + '<br>Run: ' + $Fields.RunId +
            '<br>Collected: ' + $Fields.Timestamp + '</p>'
        )
        $null = $builder.Append(
            '<p class="state">' + [Net.WebUtility]::HtmlEncode($State) +
            '. Findings are evidence for review, not authorization to change directory objects.</p><div class="cards">'
        )
        foreach ($status in $this.StatusNames()) {
            $null = $builder.Append(
                '<div class="card"><b>' + [string]$Counts[$status] + '</b>' +
                [Net.WebUtility]::HtmlEncode($status) + '</div>'
            )
        }
        $null = $builder.Append(
            '</div><h2>Collection coverage</h2><div class="table"><table><thead><tr>' +
            '<th>Source or capability</th><th>Collection state / evidence</th></tr></thead><tbody>'
        )
        return $builder
    }

    hidden [object[]] GetCoverageNames([object]$Coverage) {
        $names = @(
            if ($Coverage -is [Collections.IDictionary]) {
                ([Collections.IDictionary].GetProperty('Keys')).GetValue($Coverage, $null)
            }
            elseif ($Coverage) {
                foreach ($property in $Coverage.PSObject.Properties) {
                    $property.Name
                }
            }
        )
        return $names
    }

    hidden [void] AddCoverageRow([Text.StringBuilder]$Builder, [string]$Name, [object]$Value) {
        $null = $Builder.Append('<tr><td>' + $Name + '</td><td>' + $Value + '</td></tr>')
    }

    hidden [void] BeginChecks([Text.StringBuilder]$Builder, [int]$CoverageCount) {
        if (-not $CoverageCount) {
            $null = $Builder.Append('<tr><td colspan="2" class="muted">Coverage was not recorded.</td></tr>')
        }
        $null = $Builder.Append(
            '</tbody></table></div><h2>Checks and findings</h2><div class="table"><table><thead><tr>' +
            '<th>Rule</th><th>Target</th><th>Status</th><th>Severity</th><th>Expected</th>' +
            '<th>Observed</th><th>Evidence</th></tr></thead><tbody>'
        )
    }

    hidden [void] AddCheckRow([Text.StringBuilder]$Builder, [hashtable]$Fields) {
        $statusClass = if ($Fields.Status -eq 'Fail') {
            'fail'
        }
        elseif ($Fields.Status -eq 'Pass') {
            'pass'
        }
        else {
            'unknown'
        }
        $statusLabel = $Fields.Status
        if ($Fields.Suppressed) {
            $statusLabel += ' (suppressed)'
        }

        $null = $Builder.Append(
            '<tr><td>' + $Fields.Rule + '</td><td>' + $Fields.Target + '</td><td class="' +
            $statusClass + '">' + [Net.WebUtility]::HtmlEncode($statusLabel) + '</td><td>' +
            $Fields.Severity + '</td><td>' + $Fields.Expected + '</td><td>' + $Fields.Observed +
            '</td><td>' + $Fields.Message + '<details><summary>View evidence</summary><pre>' +
            $Fields.Evidence + '</pre></details></td></tr>'
        )
    }

    hidden [void] EndChecks([Text.StringBuilder]$Builder, [int]$CheckCount) {
        if (-not $CheckCount) {
            $null = $Builder.Append('<tr><td colspan="7" class="muted">No check results are present in this snapshot.</td></tr>')
        }
        $null = $Builder.Append('</tbody></table></div>')
    }

    hidden [void] AddCollectionErrors([Text.StringBuilder]$Builder, [object]$EncodedErrors) {
        $null = $Builder.Append('<h2>Collection errors</h2><pre>' + $EncodedErrors + '</pre>')
    }

    hidden [void] AddComparison([Text.StringBuilder]$Builder, [object]$Assessment) {
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $comparison = $projector.GetValue($Assessment, @('Comparison'))
        $kind = $projector.GetValue($comparison, @('ComparisonType'))
        $version = $projector.GetValue($comparison, @('SchemaVersion'))
        if ($kind -isnot [string] -or $kind -cne 'ADAnalyzerAssessmentComparison' -or
            ($version -isnot [int] -and $version -isnot [long]) -or $version -ne 1) {
            return
        }

        $reference = $projector.GetValue($comparison, @('ReferenceRunId'))
        $difference = $projector.GetValue($comparison, @('DifferenceRunId'))
        $null = $Builder.Append(
            '<section aria-labelledby="assessment-comparison"><h2 id="assessment-comparison">' +
            'Assessment comparison</h2><dl><dt>Reference run</dt><dd>' +
            $this.ComparisonText($reference, 'Unavailable') + '</dd><dt>Difference run</dt><dd>' +
            $this.ComparisonText($difference, 'Unavailable') + '</dd></dl><dl>'
        )

        $summary = $projector.GetValue($comparison, @('Summary'))
        foreach ($change in @('New', 'Resolved', 'Changed', 'Unchanged')) {
            $count = $projector.GetValue($summary, @($change))
            $display = 'Unavailable'
            if (($count -is [int] -or $count -is [long]) -and $count -ge 0) {
                $display = $count.ToString([Globalization.CultureInfo]::InvariantCulture)
            }
            $null = $Builder.Append('<dt>' + $change + '</dt><dd>' + $display + '</dd>')
        }
        $null = $Builder.Append('</dl>')

        $changes = $projector.GetValue($comparison, @('Changes'))
        if ($changes -is [array]) {
            $this.AddComparisonRows($Builder, $changes, $projector)
        }
        else {
            $null = $Builder.Append('<p>Recorded comparison rows are unavailable.</p>')
        }
        $null = $Builder.Append('</section>')
    }

    hidden [void] AddComparisonRows(
        [Text.StringBuilder]$Builder,
        [object[]]$Changes,
        [ADAnalyzerEvidenceProjector]$Projector
    ) {
        $null = $Builder.Append(
            '<div class="table"><table><thead><tr><th>Rule</th><th>Target</th>' +
            '<th>Change</th><th>Reason</th></tr></thead><tbody>'
        )
        $hasRows = $false
        foreach ($row in $Changes) {
            $change = $Projector.GetValue($row, @('Change'))
            if ($change -isnot [string] -or $change -cnotin 'New', 'Resolved', 'Changed') {
                continue
            }

            $rule = $Projector.GetValue($row, @('RuleId'))
            $target = $Projector.GetValue($row, @('Target'))
            $reason = $Projector.GetValue($row, @('Reason'))
            $explanation = ''
            if ($reason -is [string]) {
                switch -CaseSensitive ($reason) {
                    'NotObservedInDifference' {
                        $explanation = ' Check coverage and collect fresh evidence for this rule and target.'
                    }
                    'RulePredicateChanged' {
                        $explanation = ' Review the recorded rule requirements before interpreting the status change.'
                    }
                }
            }
            $null = $Builder.Append(
                '<tr><td>' + $this.ComparisonText($rule, 'Unavailable') +
                '</td><td>' + $this.ComparisonText($target, 'Unavailable') +
                '</td><td>' + $change +
                '</td><td>' + $this.ComparisonText($reason, '') + $explanation + '</td></tr>'
            )
            $hasRows = $true
        }
        if (-not $hasRows) {
            $null = $Builder.Append('<tr><td colspan="4" class="muted">No changed rows available.</td></tr>')
        }
        $null = $Builder.Append('</tbody></table></div>')
    }

    hidden [string] ComparisonText([object]$Value, [string]$Fallback) {
        if (($Value -is [string] -and $Value.Length -gt 0) -or $Value -is [guid]) {
            return [Net.WebUtility]::HtmlEncode([string]$Value)
        }
        return $Fallback
    }

    hidden [string] FinishHtml([Text.StringBuilder]$Builder, [object]$EncodedSnapshot) {
        $null = $Builder.Append(
            '<details><summary>Full assessment snapshot (secret presence only)</summary><pre>' +
            $EncodedSnapshot + '</pre></details><p class="muted">' +
            'Standalone report. No external scripts, fonts, or resources are loaded.</p></body></html>'
        )
        return $Builder.ToString()
    }

    hidden [object] BuildCsvRow([hashtable]$Fields) {
        return [pscustomobject][ordered]@{
            RuleId = $Fields.RuleId
            Target = $Fields.Target
            Status = $Fields.Status
            Severity = $Fields.Severity
            Evidence = $Fields.Evidence
        }
    }

    hidden [string] EmptyCsv() {
        return '"RuleId","Target","Status","Severity","Evidence"'
    }

    hidden [string[]] RenderReports([object]$Assessment, [string]$Format, [string]$Path, [bool]$DryRun) {
        $ErrorActionPreference = 'Stop'
        $writeFiles = -not [string]::IsNullOrEmpty($Path)
        $formats = $this.GetFormats($Format, $writeFiles)
        if (-not $writeFiles -and $Assessment -is [string]) {
            throw [ArgumentException]::new('Render requires an in-memory assessment.', 'Assessment')
        }

        $report = $this.Prepare($Assessment)
        if ($DryRun) {
            return [string[]]@()
        }

        $outputs = @(
            foreach ($item in $formats) {
                $content = switch ($item) {
                    'Json' {
                        ConvertTo-Json -InputObject $report.Safe -Depth 100
                    }
                    'Html' {
                        $checks = @(Get-ADAnalyzerOperationValue $report.Safe @('Checks', 'Findings') @() | Where-Object { $null -ne $_ })
                        $errors = @(Get-ADAnalyzerOperationValue $report.Safe @('Errors') @() | Where-Object { $null -ne $_ })
                        $counts = @{}
                        foreach ($status in $this.StatusNames()) {
                            $counts[$status] = @($checks | Where-Object Status -eq $status).Count
                        }
                        $state = $this.GetReviewState($checks.Count, $errors.Count, $counts)
                        $target = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $report.Safe @('Target'))
                        $profile = Get-ADAnalyzerOperationValue $report.Safe @('Profile')
                        $fields = @{
                            Target = $target
                            ProfileName = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Name') 'Unspecified')
                            ProfileVersion = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Version') '')
                            RunId = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $report.Safe @('RunId'))
                            Timestamp = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $report.Safe @('Timestamp'))
                            RecordedState = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $report.Safe @('State') 'Unspecified')
                        }
                        $html = $this.BeginHtml($fields, $counts, $state)

                        $data = Get-ADAnalyzerOperationValue $report.Safe @('Data')
                        $directory = Get-ADAnalyzerOperationValue $data @('Directory')
                        $coverage = Get-ADAnalyzerOperationValue $directory @('Coverage') (Get-ADAnalyzerOperationValue $report.Safe @('Coverage'))
                        $names = $this.GetCoverageNames($coverage)
                        foreach ($name in @($names | Sort-Object)) {
                            $label = [Net.WebUtility]::HtmlEncode([string]$name)
                            $value = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $coverage @([string]$name))
                            $this.AddCoverageRow($html, $label, $value)
                        }

                        $this.BeginChecks($html, $names.Count)
                        foreach ($check in $checks) {
                            $status = [string](Get-ADAnalyzerOperationValue $check @('Status'))
                            $suppressed = [bool](Get-ADAnalyzerOperationValue $check @('Suppressed') $false)
                            $evidence = Get-ADAnalyzerOperationValue $check @('Evidence')
                            $encodedEvidence = [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $evidence -Depth 100))
                            $fields = @{
                                Status = $status
                                Suppressed = $suppressed
                                Evidence = $encodedEvidence
                                Message = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Message'))
                                Rule = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('RuleId', 'Finding'))
                                Target = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Target', 'DistinguishedName', 'SID'))
                                Severity = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Severity'))
                                Expected = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Expected'))
                                Observed = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Observed', 'Actual'))
                            }
                            $this.AddCheckRow($html, $fields)
                        }
                        $this.EndChecks($html, $checks.Count)

                        if ($errors.Count) {
                            $encodedErrors = [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $errors -Depth 100))
                            $this.AddCollectionErrors($html, $encodedErrors)
                        }
                        $this.AddComparison($html, $report.Safe)
                        $encodedSnapshot = [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $report.Safe -Depth 100))
                        $this.FinishHtml($html, $encodedSnapshot)
                    }
                    'Csv' {
                        $rows = @(
                            foreach ($finding in $Report.Findings) {
                                $fields = @{
                                    RuleId = Get-ADAnalyzerOperationValue $finding @('RuleId', 'Finding')
                                    Target = Get-ADAnalyzerOperationValue $finding @('Target', 'DistinguishedName', 'SID')
                                    Status = Get-ADAnalyzerOperationValue $finding @('Status')
                                    Severity = Get-ADAnalyzerOperationValue $finding @('Severity')
                                    Evidence = ConvertTo-Json -InputObject (Get-ADAnalyzerOperationValue $finding @('Evidence', 'Observed')) -Depth 100 -Compress
                                }
                                $this.BuildCsvRow($fields)
                            }
                        )
                        if ($rows.Count) {
                            ($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
                        }
                        else {
                            $this.EmptyCsv()
                        }
                    }
                }
                if ($writeFiles) {
                    $outputPath = $this.GetOutputPath($Path, $Format, $item)
                    Write-ADAnalyzerOperationFile -Path $outputPath -Content $content
                }
                else {
                    $content
                }
            }
        )
        return $outputs
    }
}

function ConvertTo-ADAnalyzerOperationHtmlValue {
    param([AllowNull()]$Value)
    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return [Net.WebUtility]::HtmlEncode([string]$Value)
    }
    return [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $Value -Depth 100 -Compress))
}

function ConvertTo-ADAnalyzerAssessmentHtml {
    param([Parameter(Mandatory)]$Assessment)

    # Observe and serialize in the original native scope for native stream and error capture.
    $report = [ADAnalyzerAssessmentReport]::new()
    $checks = @(Get-ADAnalyzerOperationValue $Assessment @('Checks', 'Findings') @() | Where-Object { $null -ne $_ })
    $errors = @(Get-ADAnalyzerOperationValue $Assessment @('Errors') @() | Where-Object { $null -ne $_ })
    $counts = @{}
    foreach ($status in $report.StatusNames()) {
        $counts[$status] = @($checks | Where-Object Status -eq $status).Count
    }
    $state = $report.GetReviewState($checks.Count, $errors.Count, $counts)

    $target = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('Target'))
    $profile = Get-ADAnalyzerOperationValue $Assessment @('Profile')
    $fields = @{
        Target = $target
        ProfileName = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Name') 'Unspecified')
        ProfileVersion = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Version') '')
        RunId = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('RunId'))
        Timestamp = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('Timestamp'))
        RecordedState = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('State') 'Unspecified')
    }
    $html = $report.BeginHtml($fields, $counts, $state)

    $data = Get-ADAnalyzerOperationValue $Assessment @('Data')
    $directory = Get-ADAnalyzerOperationValue $data @('Directory')
    $coverage = Get-ADAnalyzerOperationValue $directory @('Coverage') (Get-ADAnalyzerOperationValue $Assessment @('Coverage'))
    $names = $report.GetCoverageNames($coverage)
    foreach ($name in @($names | Sort-Object)) {
        $label = [Net.WebUtility]::HtmlEncode([string]$name)
        $value = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $coverage @([string]$name))
        $report.AddCoverageRow($html, $label, $value)
    }

    $report.BeginChecks($html, $names.Count)
    foreach ($check in $checks) {
        $status = [string](Get-ADAnalyzerOperationValue $check @('Status'))
        $suppressed = [bool](Get-ADAnalyzerOperationValue $check @('Suppressed') $false)
        $evidence = [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject (Get-ADAnalyzerOperationValue $check @('Evidence')) -Depth 100))
        $fields = @{
            Status = $status
            Suppressed = $suppressed
            Evidence = $evidence
            Message = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Message'))
            Rule = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('RuleId', 'Finding'))
            Target = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Target', 'DistinguishedName', 'SID'))
            Severity = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Severity'))
            Expected = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Expected'))
            Observed = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Observed', 'Actual'))
        }
        $report.AddCheckRow($html, $fields)
    }
    $report.EndChecks($html, $checks.Count)

    if ($errors.Count) {
        $encodedErrors = [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $errors -Depth 100))
        $report.AddCollectionErrors($html, $encodedErrors)
    }
    $report.AddComparison($html, $Assessment)
    $encodedSnapshot = [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $Assessment -Depth 100))
    return $report.FinishHtml($html, $encodedSnapshot)
}

function Export-ADAnalyzerAssessment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]$Assessment,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Json', 'Html', 'Csv', 'All')][string]$Format = 'Json'

    )

    $document = Read-ADAnalyzerOperationDocument $Assessment
    $safe = ConvertTo-ADAnalyzerSafeData -InputObject $document
    $report = [ADAnalyzerAssessmentReport]::new()
    $findings = @(Get-ADAnalyzerOperationValue $safe ($report.FindingNames()) @())
    $formats = $report.GetFormats($Format, $true)
    foreach ($item in $formats) {
        $outputPath = $report.GetOutputPath($Path, $Format, $item)
        if (-not $PSCmdlet.ShouldProcess($outputPath, 'Export assessment projection')) {
            continue
        }

        switch ($item) {
            'Json' {
                $content = ConvertTo-Json -InputObject $safe -Depth 100
            }
            'Html' {
                $content = ConvertTo-ADAnalyzerAssessmentHtml $safe
            }
            'Csv' {
                $rows = @(
                    foreach ($finding in $findings) {
                        $fields = @{
                            RuleId = Get-ADAnalyzerOperationValue $finding @('RuleId', 'Finding')
                            Target = Get-ADAnalyzerOperationValue $finding @('Target', 'DistinguishedName', 'SID')
                            Status = Get-ADAnalyzerOperationValue $finding @('Status')
                            Severity = Get-ADAnalyzerOperationValue $finding @('Severity')
                            Evidence = ConvertTo-Json -InputObject (Get-ADAnalyzerOperationValue $finding @('Evidence', 'Observed')) -Depth 100 -Compress
                        }
                        $report.BuildCsvRow($fields)
                    }
                )
                $content = if ($rows.Count) {
                    ($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
                }
                else {
                    $report.EmptyCsv()
                }
            }
        }
        Write-ADAnalyzerOperationFile -Path $outputPath -Content $content
    }
}

class ADAnalyzerAssessmentComparer {
    ADAnalyzerAssessmentComparer() {
    }

    [object] Compare([object]$Reference, [object]$Difference) {
        $ErrorActionPreference = 'Stop'
        $reader = [ADAnalyzerOperationDocumentReader]::new()
        $before = $reader.Read($Reference)
        $after = $reader.Read($Difference)

        $oldTarget = [string](Get-ADAnalyzerOperationValue $before @('Target'))
        $newTarget = [string](Get-ADAnalyzerOperationValue $after @('Target'))
        if (-not $this.TargetsMatch($oldTarget, $newTarget)) {
            throw 'Cannot compare different directory targets as configuration drift'
        }

        $oldScope = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $before @('Context')) @('SearchBase'))
        $newScope = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $after @('Context')) @('SearchBase'))
        if (-not $this.SearchBasesMatch($oldScope, $newScope)) {
            throw 'Cannot compare different search-base scopes as configuration drift'
        }

        $projector = [ADAnalyzerEvidenceProjector]::new()
        $oldMap = $this.IndexSnapshot($before, $projector)
        $newMap = $this.IndexSnapshot($after, $projector)
        $changes = @(
            foreach ($key in @(@($oldMap.Keys) + @($newMap.Keys) | Sort-Object -Unique)) {
                $hasOld = $oldMap.ContainsKey($key)
                $hasNew = $newMap.ContainsKey($key)
                $old = @(
                    if ($hasOld) {
                        $oldMap[$key]
                    }
                )
                $new = @(
                    if ($hasNew) {
                        $newMap[$key]
                    }
                )
                $observation = $this.ClassifyPresence($hasOld, $hasNew)
                if ($observation.CompareContents) {
                    $oldJson = ConvertTo-Json -InputObject ($this.NormalizeValue($old, '')) -Depth 100 -Compress
                    $newJson = ConvertTo-Json -InputObject ($this.NormalizeValue($new, '')) -Depth 100 -Compress
                    $oldFail = @($old | Where-Object Status -in 'Fail', 'Invalid').Count -gt 0
                    $newFail = @($new | Where-Object Status -in 'Fail', 'Invalid').Count -gt 0
                    $oldGood = @($old | Where-Object Status -notin 'Pass', 'NotApplicable').Count -eq 0
                    $newGood = @($new | Where-Object Status -notin 'Pass', 'NotApplicable').Count -eq 0
                    $observation.Change = $this.ClassifyStatus(($oldJson -cne $newJson), $oldFail, $newFail, $oldGood, $newGood)
                    $this.QualifyGpoRuleTransition($key, $old, $new, $observation)
                }

                $sample = $this.SelectSample($old, $new)
                $target = Get-ADAnalyzerOperationValue $sample ($this.TargetNames())
                $this.BuildChange($key, $target, $old, $new, $observation)
            }
        )

        $referenceRunId = Get-ADAnalyzerOperationValue $before @('RunId')
        $differenceRunId = Get-ADAnalyzerOperationValue $after @('RunId')
        $referenceRunId = $projector.ProjectIdentityMetadata($referenceRunId)
        $differenceRunId = $projector.ProjectIdentityMetadata($differenceRunId)
        $timestamp = $this.CreateTimestamp()
        return $this.BuildResult($referenceRunId, $differenceRunId, $timestamp, $changes, $this.CountChanges($changes))
    }

    hidden [hashtable] IndexSnapshot([object]$Snapshot, [ADAnalyzerEvidenceProjector]$Projector) {
        $map = @{}
        $rows = @(Get-ADAnalyzerOperationValue $Snapshot ($this.CheckNames()) @())
        foreach ($row in $rows) {
            if ($null -eq $row) {
                continue
            }

            $rule = [string](Get-ADAnalyzerOperationValue $row @('RuleId'))
            if (-not $rule) {
                $legacy = [string](Get-ADAnalyzerOperationValue $row @('Finding'))
                $rule = $this.TranslateLegacyRule($legacy)
                if (-not $rule) {
                    throw 'A snapshot finding is missing RuleId'
                }
            }

            $target = [string](Get-ADAnalyzerOperationValue $row ($this.TargetNames()))
            if (-not $target) {
                throw 'A snapshot finding is missing its stable target'
            }
            if ($this.UsesNamedHostIdentity($rule)) {
                $evidence = Get-ADAnalyzerOperationValue $row @('Evidence')
                $profileRuleId = Get-ADAnalyzerOperationValue $evidence @('ProfileRuleId')
                if ($null -ne $profileRuleId) {
                    $parts = @()
                    if ($this.RequiresRegistryIdentity($rule)) {
                        $path = Get-ADAnalyzerOperationValue $evidence @('RegistryPath')
                        $valueName = Get-ADAnalyzerOperationValue $evidence @('ValueName')
                        if (-not $this.HasLiteralRegistryIdentity($path, $valueName)) {
                            throw 'A named host registry snapshot is missing its literal path/value identity'
                        }
                        $parts = @($path, $valueName)
                    }
                    $target = Get-ADAnalyzerHostRuleIdentity -Rule @{
                        Id = $profileRuleId
                    } -Target $target -Parts $parts
                }
            }

            $bucket = $this.GetOrCreateBucket($map, $rule, $target)
            $null = $bucket.Add($Projector.Project($row))
        }
        return $map
    }

    hidden [bool] TargetsMatch([string]$Before, [string]$After) {
        return -not ($Before -and $After -and $Before -ine $After)
    }

    hidden [bool] SearchBasesMatch([string]$Before, [string]$After) {
        return $Before -ieq $After
    }

    hidden [string[]] CheckNames() {
        return @('Checks', 'Findings')
    }

    hidden [string[]] TargetNames() {
        return @('Target', 'DistinguishedName', 'ObjectGuid', 'SID')
    }

    hidden [string] TranslateLegacyRule([string]$Legacy) {
        switch ($Legacy) {
            'Defect - User Inactivity' {
                return 'ACCOUNT.INACTIVE'
            }
            'Defect - Computer Inactivity' {
                return 'COMPUTER.INACTIVE'
            }
        }
        if ($Legacy) {
            return 'LEGACY.' + $Legacy
        }
        return ''
    }

    hidden [bool] UsesNamedHostIdentity([string]$Rule) {
        return $Rule -in 'HOST.SERVICE', 'HOST.REGISTRY'
    }

    hidden [bool] RequiresRegistryIdentity([string]$Rule) {
        return $Rule -eq 'HOST.REGISTRY'
    }

    hidden [bool] HasLiteralRegistryIdentity([object]$Path, [object]$ValueName) {
        return $Path -is [string] -and $ValueName -is [string]
    }

    hidden [Collections.ArrayList] GetOrCreateBucket([hashtable]$Map, [string]$Rule, [string]$Target) {
        $key = $Rule.ToUpperInvariant() + [char]0 + $Target.ToUpperInvariant()
        if (-not $Map.ContainsKey($key)) {
            $Map[$key] = [Collections.ArrayList]::new()
        }
        return $Map[$key]
    }

    hidden [hashtable] ClassifyPresence([bool]$HasBefore, [bool]$HasAfter) {
        if (-not $HasBefore) {
            return @{
                CompareContents = $false
                Change = 'New'
                Reason = $null
            }
        }
        if (-not $HasAfter) {
            return @{
                CompareContents = $false
                Change = 'Changed'
                Reason = 'NotObservedInDifference'
            }
        }
        return @{
            CompareContents = $true
            Change = 'Unchanged'
            Reason = $null
        }
    }

    hidden [string] ClassifyStatus([bool]$Changed, [bool]$OldFail, [bool]$NewFail, [bool]$OldGood, [bool]$NewGood) {
        if ($OldFail -and $NewGood) {
            return 'Resolved'
        }
        if ($OldGood -and $NewFail) {
            return 'New'
        }
        if ($Changed) {
            return 'Changed'
        }
        return 'Unchanged'
    }

    hidden [void] QualifyGpoRuleTransition(
        [string]$Key,
        [object[]]$Before,
        [object[]]$After,
        [hashtable]$Observation
    ) {
        if ($Observation.Change -notin 'Resolved', 'New' -or
            -not $Key.StartsWith('GPO.EXPECTED.', [StringComparison]::Ordinal) -or
            $Before.Count -ne 1 -or $After.Count -ne 1) {
            return
        }

        $projector = [ADAnalyzerEvidenceProjector]::new()
        $oldEvidence = $projector.GetValue($Before[0], @('Evidence'))
        $newEvidence = $projector.GetValue($After[0], @('Evidence'))
        $oldOperator = $projector.GetValue($oldEvidence, @('Operator'))
        $newOperator = $projector.GetValue($newEvidence, @('Operator'))
        $operators = @('Equals', 'NotEquals', 'In', 'NotIn', 'Minimum', 'Maximum')
        if ($oldOperator -isnot [string] -or $newOperator -isnot [string] -or
            $oldOperator -notin $operators -or $newOperator -notin $operators) {
            return
        }

        # Read projected fields without flattening arrays or conflating null with absence.
        $missing = [object]::new()
        $oldExpected = $projector.GetValue($Before[0], @('Expected'), $missing)
        $newExpected = $projector.GetValue($After[0], @('Expected'), $missing)
        if ([object]::ReferenceEquals($oldExpected, $missing) -or
            [object]::ReferenceEquals($newExpected, $missing)) {
            return
        }

        $predicateChanged = $oldOperator -ine $newOperator
        if (-not $predicateChanged -and
            $oldOperator -in 'Minimum', 'Maximum', 'Equals', 'NotEquals' -and
            $this.IsRecordedInteger($oldExpected) -and
            $this.IsRecordedInteger($newExpected) -and
            [decimal]$oldExpected -ne [decimal]$newExpected) {
            $predicateChanged = $oldOperator -in 'Minimum', 'Maximum'
            if ($oldOperator -in 'Equals', 'NotEquals' -and
                $projector.GetValue($oldEvidence, @('Aggregate')) -ne $true -and
                $projector.GetValue($newEvidence, @('Aggregate')) -ne $true) {
                # Numeric equality is comparable here only for recorded scalar observations.
                $oldObserved = $projector.GetValue($Before[0], @('Observed'))
                $newObserved = $projector.GetValue($After[0], @('Observed'))
                $predicateChanged = $this.IsRecordedInteger($oldObserved) -and $this.IsRecordedInteger($newObserved)
            }
        }
        if ($predicateChanged -or $this.RegistryTypePredicateChanged($oldEvidence, $newEvidence, $projector, $missing)) {
            $Observation.Change = 'Changed'
            $Observation.Reason = 'RulePredicateChanged'
        }
    }

    hidden [bool] RegistryTypePredicateChanged(
        [object]$Before,
        [object]$After,
        [ADAnalyzerEvidenceProjector]$Projector,
        [object]$Missing
    ) {
        $oldType = $this.NormalizeExpectedRegistryType($Projector.GetValue($Before, @('ExpectedRegistryType'), $Missing), $Missing)
        $newType = $this.NormalizeExpectedRegistryType($Projector.GetValue($After, @('ExpectedRegistryType'), $Missing), $Missing)
        if ([object]::ReferenceEquals($oldType, $Missing) -or
            [object]::ReferenceEquals($newType, $Missing) -or
            [object]::Equals($oldType, $newType)) {
            return $false
        }

        foreach ($evidence in @($Before, $After)) {
            if ($Projector.GetValue($evidence, @('Aggregate')) -eq $true -or
                -not $this.IsRecordedRegistryType($Projector.GetValue($evidence, @('RegistryType')))) {
                return $false
            }

            # A scalar Registry.pol observation identifies where the expected type was applied.
            $path = $Projector.GetValue($evidence, @('Path'))
            $scope = $Projector.GetValue($evidence, @('Scope'))
            if ($path -isnot [string] -or $scope -isnot [string] -or
                -not (($scope -eq 'Computer' -and $path -eq 'Machine/Registry.pol') -or
                    ($scope -eq 'User' -and $path -eq 'User/Registry.pol'))) {
                return $false
            }
        }
        return $true
    }

    hidden [object] NormalizeExpectedRegistryType([object]$Value, [object]$Missing) {
        if ($null -eq $Value) {
            return $null
        }

        # The evaluator accepts invariant integer text and may preserve that spelling in evidence.
        if ($Value -is [string]) {
            $numericType = 0L
            if (-not [long]::TryParse(
                $Value,
                [Globalization.NumberStyles]::Integer,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$numericType
            )) {
                return $Missing
            }
            $Value = $numericType
        }
        if ($this.IsRecordedRegistryType($Value)) {
            return [uint32]$Value
        }
        return $Missing
    }

    hidden [bool] IsRecordedRegistryType([object]$Value) {
        return $this.IsRecordedInteger($Value) -and
            [decimal]$Value -ge 0 -and [decimal]$Value -le [uint32]::MaxValue
    }

    hidden [bool] IsRecordedInteger([object]$Value) {
        if ($null -eq $Value -or $Value -is [Enum]) {
            return $false
        }
        $code = [Type]::GetTypeCode($Value.GetType())
        if ($code -notin @(
                [TypeCode]::SByte,
                [TypeCode]::Byte,
                [TypeCode]::Int16,
                [TypeCode]::UInt16,
                [TypeCode]::Int32,
                [TypeCode]::UInt32,
                [TypeCode]::Int64,
                [TypeCode]::UInt64
            )) {
            return $false
        }
        return [decimal]$Value -le [long]::MaxValue
    }

    hidden [object] SelectSample([object[]]$Before, [object[]]$After) {
        if ($After.Count -and $null -ne $After[0]) {
            return $After[0]
        }
        return $Before[0]
    }

    hidden [object] BuildChange([string]$Key, [object]$Target, [object[]]$Before, [object[]]$After, [hashtable]$Observation) {
        return [pscustomobject]@{
            RuleId = $Key.Split([char]0)[0]
            Target = $Target
            Change = $Observation.Change
            Reason = $Observation.Reason
            Reference = $Before
            Difference = $After
        }
    }

    hidden [string] CreateTimestamp() {
        return [datetimeoffset]::UtcNow.ToString('o')
    }

    hidden [hashtable] CountChanges([object[]]$Changes) {
        return @{
            New = @($Changes | Where-Object Change -eq 'New').Count
            Resolved = @($Changes | Where-Object Change -eq 'Resolved').Count
            Changed = @($Changes | Where-Object Change -eq 'Changed').Count
            Unchanged = @($Changes | Where-Object Change -eq 'Unchanged').Count
        }
    }

    hidden [object] BuildResult(
        [object]$ReferenceRunId,
        [object]$DifferenceRunId,
        [string]$Timestamp,
        [object[]]$Changes,
        [hashtable]$Counts
    ) {
        return [pscustomobject][ordered]@{
            SchemaVersion = 1
            ComparisonType = 'ADAnalyzerAssessmentComparison'
            ReferenceRunId = $ReferenceRunId
            DifferenceRunId = $DifferenceRunId
            Timestamp = $Timestamp
            Changes = $Changes
            Summary = [pscustomobject]@{
                New = $Counts.New
                Resolved = $Counts.Resolved
                Changed = $Counts.Changed
                Unchanged = $Counts.Unchanged
            }
        }
    }

    hidden [string] GetValueKind([object]$Value) {
        if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
            return 'Scalar'
        }
        if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary] -and $Value -isnot [pscustomobject]) {
            return 'Collection'
        }
        return 'Record'
    }

    hidden [bool] IsMultiset([string]$Field) {
        return ($Field -eq '' -or
            $Field -in @(
                'Members'
                'MemberOf'
                'TransitiveGroups'
                'EffectiveSids'
                'DirectSids'
                'PrivilegedSids'
                'Unresolved'
                'Cycles'
                'SIDHistory'
                'ServicePrincipalNames'
            ))
    }

    hidden [bool] IncludeField([object]$Name) {
        return $Name -notin @(
            'Timestamp'
            'CollectedAt'
            'ObservedAt'
            'RunId'
            'ScanId'
            'StartedAt'
            'CompletedAt'
            'Duration'
            'Elapsed'
            'CheckId'
        )
    }

    hidden [object] NormalizeValue([object]$Value, [string]$Field) {
        $kind = $this.GetValueKind($Value)
        if ($kind -eq 'Scalar') {
            return $Value
        }
        if ($kind -eq 'Collection') {
            $items = @(
                foreach ($item in $Value) {
                    , $this.NormalizeValue($item, $Field)
                }
            )
            if ($this.IsMultiset($Field)) {
                return @(
                    $items | ForEach-Object {
                        ConvertTo-Json -InputObject $_ -Depth 100 -Compress
                    } | Sort-Object
                )
            }
            return $items
        }

        $output = [ordered]@{}
        $names = if ($Value -is [Collections.IDictionary]) {
            @(([Collections.IDictionary].GetProperty('Keys')).GetValue($Value, $null))
        }
        else {
            foreach ($property in $Value.PSObject.Properties) {
                $property.Name
            }
        }
        foreach ($name in @($names | Sort-Object)) {
            if (-not $this.IncludeField($name)) {
                continue
            }
            $child = if ($Value -is [Collections.IDictionary]) {
                , $Value[$name]
            }
            else {
                , $Value.PSObject.Properties[$name].Value
            }
            $output[[string]$name] = $this.NormalizeValue($child, [string]$name)
        }
        return [pscustomobject]$output
    }
}

function ConvertTo-ADAnalyzerComparableValue {
    param(
        [AllowNull()]$Value,
        [string]$Field = ''

    )

    # Keep the recursive native observations and output cardinality in this command's scope.
    $comparer = [ADAnalyzerAssessmentComparer]::new()
    $kind = $comparer.GetValueKind($Value)
    if ($kind -eq 'Scalar') {
        return $Value
    }
    if ($kind -eq 'Collection') {
        $items = @(
            foreach ($item in $Value) {
                ConvertTo-ADAnalyzerComparableValue $item $Field
            }
        )
        if ($comparer.IsMultiset($Field)) {
            return , @(
                foreach ($serialized in @($items | ForEach-Object {
                            ConvertTo-Json -InputObject $_ -Depth 100 -Compress
                        } | Sort-Object)) {
                    $serialized
                }
            )
        }
        return , $items
    }

    $output = [ordered]@{}
    $names = if ($Value -is [Collections.IDictionary]) {
        @(([Collections.IDictionary].GetProperty('Keys')).GetValue($Value, $null))
    }
    else {
        foreach ($property in $Value.PSObject.Properties) {
            $property.Name
        }
    }
    foreach ($name in @($names | Sort-Object)) {
        if (-not $comparer.IncludeField($name)) {
            continue
        }
        if ($Value -is [Collections.IDictionary]) {
            $child = $Value[$name]
        }
        else {
            $child = $Value.PSObject.Properties[$name].Value
        }
        $output[[string]$name] = ConvertTo-ADAnalyzerComparableValue -Value $child -Field ([string]$name)
    }
    return [pscustomobject]$output
}

function Compare-ADAnalyzerAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Reference,
        [Parameter(Mandatory)]$Difference

    )

    $before = Read-ADAnalyzerOperationDocument $Reference
    $after = Read-ADAnalyzerOperationDocument $Difference
    $comparer = [ADAnalyzerAssessmentComparer]::new()
    $oldTarget = [string](Get-ADAnalyzerOperationValue $before @('Target'))
    $newTarget = [string](Get-ADAnalyzerOperationValue $after @('Target'))
    if (-not $comparer.TargetsMatch($oldTarget, $newTarget)) {
        throw 'Cannot compare different directory targets as configuration drift'
    }

    $oldScope = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $before @('Context')) @('SearchBase'))
    $newScope = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $after @('Context')) @('SearchBase'))
    if (-not $comparer.SearchBasesMatch($oldScope, $newScope)) {
        throw 'Cannot compare different search-base scopes as configuration drift'
    }

    $maps = @(@{}, @{})
    foreach ($pair in @(@($before, 0), @($after, 1))) {
        $rows = @(Get-ADAnalyzerOperationValue $pair[0] ($comparer.CheckNames()) @())
        foreach ($row in $rows) {
            if ($null -eq $row) {
                continue
            }

            $rule = [string](Get-ADAnalyzerOperationValue $row @('RuleId'))
            if (-not $rule) {
                $legacy = [string](Get-ADAnalyzerOperationValue $row @('Finding'))
                $rule = switch ($legacy) {
                    default {
                        $translated = $comparer.TranslateLegacyRule($legacy)
                        if ($translated) {
                            $translated
                        }
                        else {
                            throw 'A snapshot finding is missing RuleId'
                        }
                    }
                }
            }

            $target = [string](Get-ADAnalyzerOperationValue $row ($comparer.TargetNames()))
            if (-not $target) {
                throw 'A snapshot finding is missing its stable target'
            }
            if ($comparer.UsesNamedHostIdentity($rule)) {
                $evidence = Get-ADAnalyzerOperationValue $row @('Evidence')
                $profileRuleId = Get-ADAnalyzerOperationValue $evidence @('ProfileRuleId')
                if ($null -ne $profileRuleId) {
                    $parts = @()
                    if ($comparer.RequiresRegistryIdentity($rule)) {
                        $path = Get-ADAnalyzerOperationValue $evidence @('RegistryPath')
                        $valueName = Get-ADAnalyzerOperationValue $evidence @('ValueName')
                        if (-not $comparer.HasLiteralRegistryIdentity($path, $valueName)) {
                            throw 'A named host registry snapshot is missing its literal path/value identity'
                        }
                        $parts = @($path, $valueName)
                    }
                    $target = Get-ADAnalyzerHostRuleIdentity -Rule @{
                        Id = $profileRuleId
                    } -Target $target -Parts $parts
                }
            }

            $bucket = $comparer.GetOrCreateBucket($maps[$pair[1]], $rule, $target)
            $null = $bucket.Add((ConvertTo-ADAnalyzerSafeData -InputObject $row))
        }
    }

    $changes = @(
        foreach ($key in @(@($maps[0].Keys) + @($maps[1].Keys) | Sort-Object -Unique)) {
            $old = @(
                if ($maps[0].ContainsKey($key)) {
                    $maps[0][$key]
                }
            )
            $new = @(
                if ($maps[1].ContainsKey($key)) {
                    $maps[1][$key]
                }
            )
            $observation = $comparer.ClassifyPresence($maps[0].ContainsKey($key), $maps[1].ContainsKey($key))
            if ($observation.CompareContents) {
                $oldJson = ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $old) -Depth 100 -Compress
                $newJson = ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerComparableValue $new) -Depth 100 -Compress
                $oldFail = @($old | Where-Object Status -in 'Fail', 'Invalid').Count -gt 0
                $newFail = @($new | Where-Object Status -in 'Fail', 'Invalid').Count -gt 0
                $oldGood = @($old | Where-Object Status -notin 'Pass', 'NotApplicable').Count -eq 0
                $newGood = @($new | Where-Object Status -notin 'Pass', 'NotApplicable').Count -eq 0
                $observation.Change = $comparer.ClassifyStatus(($oldJson -cne $newJson), $oldFail, $newFail, $oldGood, $newGood)
                $comparer.QualifyGpoRuleTransition($key, $old, $new, $observation)
            }

            $sample = $comparer.SelectSample($old, $new)
            $target = Get-ADAnalyzerOperationValue $sample ($comparer.TargetNames())
            $comparer.BuildChange($key, $target, $old, $new, $observation)
        }
    )

    $referenceRunId = Get-ADAnalyzerOperationValue $before @('RunId')
    $differenceRunId = Get-ADAnalyzerOperationValue $after @('RunId')
    $projector = [ADAnalyzerEvidenceProjector]::new()
    $referenceRunId = $projector.ProjectIdentityMetadata($referenceRunId)
    $differenceRunId = $projector.ProjectIdentityMetadata($differenceRunId)
    $timestamp = $comparer.CreateTimestamp()
    $counts = @{
        New = @($changes | Where-Object Change -eq 'New').Count
        Resolved = @($changes | Where-Object Change -eq 'Resolved').Count
        Changed = @($changes | Where-Object Change -eq 'Changed').Count
        Unchanged = @($changes | Where-Object Change -eq 'Unchanged').Count
    }
    return $comparer.BuildResult($referenceRunId, $differenceRunId, $timestamp, $changes, $counts)
}

function ConvertTo-ADAnalyzerOperationGuid {
    param($Value)
    $guid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Value, [ref]$guid) -or $guid -eq [guid]::Empty) {
        return $null
    }
    return $guid.ToString('D')
}

function ConvertTo-ADAnalyzerOperationTime {
    param($Value)
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime.ToString('o')
    }
    $time = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse([string]$Value, [ref]$time)) {
        return $null
    }
    return $time.UtcDateTime.ToString('o')
}

function Get-ADAnalyzerOperationSid {
    param($Object)
    $sid = Get-ADAnalyzerOperationValue $Object @('SID', 'ObjectSid')
    if ($sid -and $sid -isnot [string]) {
        $sid = Get-ADAnalyzerOperationValue $sid @('Value') ([string]$sid)
    }
    return [string]$sid
}

class ADAnalyzerRemediationGuard {
    ADAnalyzerRemediationGuard() {
    }

    [object] ReadState([object]$Object) {
        $ErrorActionPreference = 'Stop'
        $enabled = Get-ADAnalyzerOperationValue $Object @('Enabled')
        if ($null -eq $enabled) {
            $uac = Get-ADAnalyzerOperationValue $Object @('UserAccountControl')
            if ($null -ne $uac) {
                $enabled = ([long]$uac -band $this.DisabledAccountFlag()) -eq 0
            }
        }
        $fields = @{
            ObjectGuid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $Object @('ObjectGuid'))
            SID = Get-ADAnalyzerOperationSid $Object
            DistinguishedName = [string](Get-ADAnalyzerOperationValue $Object @('DistinguishedName', 'DN'))
            Enabled = $enabled
            WhenChanged = ConvertTo-ADAnalyzerOperationTime (Get-ADAnalyzerOperationValue $Object @('WhenChanged'))
        }
        return $this.BuildState($fields)
    }

    [string] GetObjectKind([object]$Object) {
        $ErrorActionPreference = 'Stop'
        $classes = @(Get-ADAnalyzerOperationValue $Object @('ObjectClass', 'Class'))
        return $this.ClassifyKind($classes)
    }

    [object] GetExclusion([object]$Object, [object]$Settings) {
        $ErrorActionPreference = 'Stop'
        $reader = [ADAnalyzerEvidenceProjector]::new()
        $includePrivileged = $reader.GetValue($Settings, @('IncludePrivilegedAccounts'), $null)
        $includeService = $reader.GetValue($Settings, @('IncludeServiceAccounts'), $null)
        if ($includePrivileged -isnot [bool] -or $includeService -isnot [bool]) {
            throw 'Remediation exclusion options must be Boolean'
        }

        $state = $this.ReadState($Object)
        $stateReason = $this.GetStateExclusion($state)
        if ($stateReason) {
            return $stateReason
        }
        $kind = $this.GetObjectKind($Object)
        if (-not $this.SupportsObjectKind($kind)) {
            return 'UnsupportedObjectClass'
        }
        $metadata = [string](Get-ADAnalyzerOperationValue $Object @('SafetyMetadataStatus'))
        if (-not $this.HasCollectedSafetyMetadata($metadata)) {
            return 'MissingSafetyEvidence'
        }
        foreach ($name in $this.RequiredSafetyFlags()) {
            if ((Get-ADAnalyzerOperationValue $Object @($name)) -isnot [bool]) {
                return 'MissingSafetyEvidence'
            }
        }
        $critical = Get-ADAnalyzerOperationValue $Object @('IsCriticalSystemObject')
        if ($null -ne $critical -and $critical -isnot [bool]) {
            return 'MissingSafetyEvidence'
        }
        if ($null -eq (Get-ADAnalyzerOperationValue $Object @('UserAccountControl')) -or
            $null -eq (Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID'))) {
            return 'MissingSafetyEvidence'
        }
        if ($this.IsWellKnownAccountSid($state.SID) -or
            [bool](Get-ADAnalyzerOperationValue $Object @('WellKnownSID') $false)) {
            return 'WellKnownAccount'
        }
        $uac = Get-ADAnalyzerOperationValue $Object @('UserAccountControl') 0
        $primary = Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID') 0
        if ([bool](Get-ADAnalyzerOperationValue $Object @('IsDomainController') $false) -or
            ([long]$uac -band $this.DomainControllerFlag()) -ne 0 -or
            [int]$primary -in $this.DomainControllerPrimaryGroups()) {
            return 'DomainController'
        }
        if ([int](Get-ADAnalyzerOperationValue $Object @('AdminCount') 0) -ne 0) {
            return 'AdminCountProtected'
        }
        if (@(Get-ADAnalyzerOperationValue $Object @('SIDHistory') @() | Where-Object { $null -ne $_ -and
                    -not [string]::IsNullOrWhiteSpace([string]$_) }).Count) {
            return 'SidHistoryRequiresReview'
        }
        foreach ($name in $this.ProtectionFlags()) {
            if ([bool](Get-ADAnalyzerOperationValue $Object @($name) $false)) {
                return 'ProtectedOrCriticalObject'
            }
        }
        $membership = Get-ADAnalyzerOperationValue $Object @('Membership')
        $effective = @(Get-ADAnalyzerOperationValue $Object @('TransitiveGroups',
                'EffectiveSids') @()) + @(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
        if (@($effective | Where-Object { $this.IsProtectedGroupSid($_) }).Count) {
            return 'ProtectedOrCriticalObject'
        }
        $resolution = [string](Get-ADAnalyzerOperationValue $Object @('PrivilegeResolutionStatus', 'MembershipResolutionStatus'))
        if (-not $this.IsPrivilegeResolutionComplete($resolution)) {
            return 'PrivilegeResolutionIncomplete'
        }
        $privileged = Get-ADAnalyzerOperationValue $Object @('Privileged', 'IsPrivileged')
        if ($privileged -isnot [bool]) {
            return 'PrivilegeResolutionIncomplete'
        }
        if ($privileged -and -not $includePrivileged) {
            return 'PrivilegedAccount'
        }
        if ($kind -eq 'User') {
            $accountType = [string](Get-ADAnalyzerOperationValue $Object @('AccountType'))
            if (-not $this.HasKnownAccountClassification($accountType)) {
                return 'UnknownAccountClassification'
            }
            if ($this.IsServiceAccount($accountType) -and -not $includeService) {
                return 'ServiceAccount'
            }
        }
        foreach ($excluded in @($Settings.ExcludedObjectGuids)) {
            if ((ConvertTo-ADAnalyzerOperationGuid $excluded) -eq $state.ObjectGuid) {
                return 'ExplicitObjectExclusion'
            }
        }
        foreach ($ou in @($Settings.ExcludedOUs)) {
            if ($ou -and
                ($this.MatchesExcludedOrganizationalUnit($state.DistinguishedName, [string]$ou) -or
                    $this.IsWithinExcludedOrganizationalUnit($state.DistinguishedName, [string]$ou))) {
                return 'ExcludedOrganizationalUnit'
            }
        }
        return $null
    }

    [object] AssertPreconditions([object]$Expected, [object]$Actual, [bool]$Enabled) {
        $ErrorActionPreference = 'Stop'
        $current = $this.ReadState($Actual)
        foreach ($name in $this.PreconditionNames()) {
            $wanted = Get-ADAnalyzerOperationValue $Expected @($name)
            if ($name -eq 'WhenChanged') {
                $wanted = ConvertTo-ADAnalyzerOperationTime $wanted
            }
            if ($name -eq 'ObjectGuid') {
                $wanted = ConvertTo-ADAnalyzerOperationGuid $wanted
            }
            if (-not $wanted -or -not $this.IdentityMatches([string]$wanted, [string]$current.$name)) {
                throw "Remediation precondition failed: $name changed or is missing"
            }
        }
        if ($Expected.Enabled -isnot [bool] -or
            $Expected.Enabled -ne $Enabled -or
            $current.Enabled -isnot [bool] -or
            $current.Enabled -ne $Enabled) {
            throw 'Remediation precondition failed: Enabled changed or is missing'
        }
        return $current
    }

    [void] AssertPlan([object]$Plan) {
        $ErrorActionPreference = 'Stop'
        if (-not $this.IsReviewPlanType($Plan.PlanType) -or -not (ConvertTo-ADAnalyzerOperationGuid $Plan.PlanId)) {
            throw 'Only an explicit ADAnalyzer remediation plan may be executed'
        }
        if ($Plan.Remediation.AllowDisable -isnot [bool] -or -not $Plan.Remediation.AllowDisable) {
            throw 'The plan does not enable account disabling'
        }
        foreach ($name in $this.PlanBooleanNames()) {
            if ($Plan.Remediation.$name -isnot [bool]) {
                throw "Invalid plan boolean setting: $name"
            }
        }
        $limit = 0
        if (-not [int]::TryParse([string]$Plan.Remediation.MaximumActions,
                [ref]$limit) -or
            -not $this.IsActionLimitInRange($limit) -or
            @($Plan.Actions).Count -gt $limit) {
            throw 'Invalid remediation action limit'
        }
        $approved = @(foreach ($value in @($Plan.Remediation.ApprovedObjectGuids)) {
                ConvertTo-ADAnalyzerOperationGuid $value
            })
        $seen = @{}
        $seenActionIds = @{}
        foreach ($action in @($Plan.Actions)) {
            if ($null -eq $action) {
                continue
            }
            $guid = ConvertTo-ADAnalyzerOperationGuid $action.ObjectGuid
            $actionId = $null
            if (-not $this.IsSupportedAction($action.Action) -or
                -not $guid -or
                $guid -notin $approved -or
                $action.Preconditions.ObjectGuid -ne $guid -or
                -not ($actionId = ConvertTo-ADAnalyzerOperationGuid $action.ActionId)) {
                throw 'Plan includes an unsupported, unapproved, or unbound action'
            }
            if (($this.IsUserInactivityRule($action.RuleId) -and -not $this.ClassMatches($action.ObjectClass, 'User')) -or
                ($this.IsComputerInactivityRule($action.RuleId) -and -not $this.ClassMatches($action.ObjectClass, 'Computer')) -or
                -not $this.IsSupportedInactivityRule($action.RuleId)) {
                throw 'Plan rule and object class do not match'
            }
            $days = 0L
            if (-not [long]::TryParse([string]$action.InactivityDays, [ref]$days) -or -not $this.IsInactivityThresholdValid($days)) {
                throw 'Plan action is missing its reviewed inactivity threshold'
            }
            $duplicate = $this.RegisterActionIdentity($seen, $seenActionIds, $guid, $actionId)
            if ($duplicate) {
                throw $duplicate
            }
        }
    }

    [void] AssertPrivilege([object]$Object, [object]$Action, [object]$Plan, [string]$Server) {
        $this.AssertPrivilege($Object, $Action, $Plan, $Server, [pscredential]::Empty)
    }

    [void] AssertPrivilege(
        [object]$Object,
        [object]$Action,
        [object]$Plan,
        [string]$Server,
        [pscredential]$Credential
    ) {
        $ErrorActionPreference = 'Stop'
        $connection = Get-ADAnalyzerOperationConnection $Server $Credential
        $context = Get-ADAnalyzerOperationValue $Plan @('Context')
        $reviewedServer = [string](Get-ADAnalyzerOperationValue $context @('Server'))
        if ($reviewedServer -and $reviewedServer -ine $Server) {
            throw 'Server differs from the DC recorded in the reviewed assessment'
        }
        if (-not (Get-Command Resolve-ADAnalyzerMembership -ErrorAction SilentlyContinue)) {
            throw 'Fresh privilege resolver is unavailable; remediation is blocked'
        }
        if (-not $this.FreshClassMatches($this.GetObjectKind($Object), $Action.ObjectClass)) {
            throw 'Current object class differs from the approved action'
        }

        $providerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        $groupCommand = $provider.ExportedCmdlets['Get-ADGroup']
        if ($groupCommand -isnot [Management.Automation.CommandInfo]) {
            throw 'Bundled AD assembly does not provide the required Get-ADGroup command'
        }
        $groups = @(& $groupCommand -Filter * -Properties members, memberOf, primaryGroupToken, SID @connection)
        $domainSid = $this.GetFreshDomainSid((Get-ADAnalyzerOperationSid $Object))
        if (-not $domainSid) {
            throw 'A domain SID is required for fresh privilege resolution'
        }
        $privileged = $this.StartFreshPrivilegedSids(@($Plan.PrivilegedSids))
        foreach ($group in $groups) {
            $this.AddFreshPrivilegedGroup($privileged, (Get-ADAnalyzerOperationSid $group))
        }
        $resolution = @{
            Object = $Object
            Groups = $groups
            DomainSid = $domainSid
            PrivilegedSids = @($privileged | Select-Object -Unique)
        }
        $membership = Resolve-ADAnalyzerMembership @resolution
        if ($null -eq $membership -or
            $this.HasUnresolvedFreshMembership(@(Get-ADAnalyzerOperationValue $membership @('Unresolved') @()))) {
            throw 'Fresh privilege resolution is incomplete; remediation is blocked'
        }
        $isPrivileged = Get-ADAnalyzerOperationValue $membership @('IsPrivileged')
        if ($isPrivileged -isnot [bool]) {
            throw 'Fresh privilege resolution did not return a definite result'
        }
        $state = $this.ReadState($Object)
        $safe = $this.CreateFreshSafetyRecord($state, $isPrivileged, $Action.AccountType, $Action.ObjectClass)
        foreach ($name in $this.FreshSafetyPropertyNames()) {
            $safe[$name] = Get-ADAnalyzerOperationValue $Object @($name)
        }
        $this.NormalizeFreshSafetyRecord($safe)
        $safe.TransitiveGroups = @(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
        $safe.IsDomainController = ([long]$safe.UserAccountControl -band $this.DomainControllerFlag()) -ne 0 -or
            [int]$safe.PrimaryGroupID -in $this.DomainControllerPrimaryGroups()

        if ($this.NeedsFreshClassification($Action.ObjectClass)) {
            if (-not (Get-Command Get-ADAnalyzerAccountType -ErrorAction SilentlyContinue)) {
                throw 'Fresh account classification is unavailable; remediation is blocked'
            }
            $classificationObject = $this.BuildFreshClassificationRecord(
                $state,
                (Get-ADAnalyzerOperationValue $Object @('MemberOf') @()),
                [string](Get-ADAnalyzerOperationValue $Object @('ObjectClass'))
            )
            foreach ($rule in @($Plan.AccountClassification.AttributeRules)) {
                if ($null -eq $rule) {
                    continue
                }
                $attribute = [string](Get-ADAnalyzerOperationValue $rule @('Attribute'))
                if (-not (Test-ADAnalyzerClassificationAttribute $attribute)) {
                    throw 'Classification attribute cannot be safely re-queried'
                }
                $classificationObject[$attribute] = Get-ADAnalyzerOperationValue $Object @($attribute)
            }
            $classificationInput = @{
                Object = [pscustomobject]$classificationObject
                Profile = @{
                    AccountClassification = ConvertTo-ADAnalyzerHashtable $Plan.AccountClassification
                }
                Membership = $membership
            }
            $classification = Get-ADAnalyzerAccountType @classificationInput
            $safe.AccountType = [string](Get-ADAnalyzerOperationValue $classification @('Type') 'Unknown')
            if (-not $this.HasFreshClassification($safe.AccountType)) {
                throw 'Fresh account classification is unknown or conflicting'
            }
        }
        $reason = $this.GetExclusion($safe, $Plan.Remediation)
        if ($reason) {
            throw "Fresh object safety check failed: $reason"
        }
    }

    [void] AssertInactivity([object]$Object, [object]$Action) {
        $ErrorActionPreference = 'Stop'
        $days = 0L
        if (-not [long]::TryParse([string]$Action.InactivityDays, [ref]$days) -or
            -not $this.IsInactivityThresholdValid($days)) {
            throw 'The reviewed action is missing its inactivity threshold'
        }
        $dates = [Collections.Generic.List[datetime]]::new()
        foreach ($name in $this.FreshActivityPropertyNames()) {
            $value = Get-ADAnalyzerOperationValue $Object @($name)
            if ($null -eq $value -or [string]$value -eq '0') {
                continue
            }
            try {
                $fileTime = 0L
                if ([long]::TryParse([string]$value, [ref]$fileTime)) {
                    $dates.Add([datetime]::FromFileTimeUtc($fileTime))
                }
                else {
                    $dates.Add($this.ParseFreshDate($value))
                }
            }
            catch {
                throw 'Fresh activity metadata could not be interpreted'
            }
        }
        if ($dates.Count) {
            $latest = $this.LatestFreshActivity($dates)
        }
        else {
            $created = Get-ADAnalyzerOperationValue $Object @('WhenCreated')
            if ($null -eq $created) {
                throw 'Fresh inactivity evidence is unavailable'
            }
            try {
                $latest = $this.ParseFreshDate($created)
            }
            catch {
                throw 'Fresh creation metadata could not be interpreted'
            }
        }
        if (-not $this.MeetsFreshInactivityThreshold($latest, $days)) {
            throw 'Fresh activity no longer satisfies the reviewed inactivity rule'
        }
    }

    hidden [bool] FreshClassMatches([string]$Observed, [object]$Approved) {
        return -not ($Observed -ne $Approved)
    }

    hidden [string] GetFreshDomainSid([string]$Sid) {
        if ($Sid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
            return $Matches[1]
        }
        return ''
    }

    hidden [Collections.Generic.List[object]] StartFreshPrivilegedSids([object[]]$Configured) {
        $privileged = [Collections.Generic.List[object]]::new()
        $privileged.AddRange($Configured)
        $privileged.AddRange(@(
            'S-1-5-32-544'
            'S-1-5-32-548'
            'S-1-5-32-549'
            'S-1-5-32-550'
            'S-1-5-32-551'
            'S-1-5-32-552'
        ))
        return $privileged
    }

    hidden [void] AddFreshPrivilegedGroup([Collections.Generic.List[object]]$Privileged, [string]$GroupSid) {
        if ($GroupSid -match '^S-1-5-21-(?:\d+-){3}(512|516|518|519|520|521|526|527)$') {
            $Privileged.Add($GroupSid)
        }
    }

    hidden [bool] HasUnresolvedFreshMembership([object[]]$Unresolved) {
        foreach ($entry in $Unresolved) {
            if ($this.IsFreshUnresolvedEntry($entry)) {
                return $true
            }
        }
        return $false
    }

    hidden [bool] IsFreshUnresolvedEntry([object]$Entry) {
        return $null -ne $Entry
    }

    hidden [hashtable] CreateFreshSafetyRecord(
        [object]$State,
        [bool]$IsPrivileged,
        [object]$AccountType,
        [object]$ObjectClass
    ) {
        return @{
            ObjectGuid = $State.ObjectGuid
            SID = $State.SID
            DistinguishedName = $State.DistinguishedName
            WhenChanged = $State.WhenChanged
            Enabled = $true
            Privileged = $IsPrivileged
            PrivilegeResolutionStatus = 'Complete'
            AccountType = $AccountType
            ObjectClass = $ObjectClass
        }
    }

    hidden [string[]] FreshSafetyPropertyNames() {
        return @(
            'AdminCount'
            'ProtectedFromAccidentalDeletion'
            'ProtectedUser'
            'Protected'
            'IsCriticalSystemObject'
            'IsDomainController'
            'UserAccountControl'
            'PrimaryGroupID'
            'WellKnownSID'
            'SIDHistory'
        )
    }

    hidden [void] NormalizeFreshSafetyRecord([hashtable]$Record) {
        # A successfully requested optional schema attribute can be unset.
        if ($null -eq $Record.AdminCount) {
            $Record.AdminCount = 0
        }
        if ($null -eq $Record.IsCriticalSystemObject) {
            $Record.IsCriticalSystemObject = $false
        }
        $Record.SafetyMetadataStatus = 'Collected'
    }

    hidden [bool] NeedsFreshClassification([object]$ObjectClass) {
        return [bool]($ObjectClass -eq 'User')
    }

    hidden [hashtable] BuildFreshClassificationRecord(
        [object]$State,
        [object]$MemberOf,
        [string]$DirectoryObjectClass
    ) {
        return @{
            DistinguishedName = $State.DistinguishedName
            MemberOf = $MemberOf
            DirectoryObjectClass = $DirectoryObjectClass
        }
    }

    hidden [bool] HasFreshClassification([string]$AccountType) {
        return $AccountType -in 'User', 'Service'
    }

    hidden [string[]] FreshActivityPropertyNames() {
        return @('lastLogonTimestamp', 'lastLogon', 'LastLogonDate')
    }

    hidden [datetime] ParseFreshDate([object]$Value) {
        return [datetime]::Parse(
            (ConvertTo-ADAnalyzerOperationTime $Value),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }

    hidden [datetime] LatestFreshActivity([Collections.Generic.List[datetime]]$Dates) {
        $latest = $Dates[0]
        foreach ($date in $Dates) {
            if ($date -gt $latest) {
                $latest = $date
            }
        }
        return $latest
    }

    hidden [bool] MeetsFreshInactivityThreshold([datetime]$Activity, [long]$Days) {
        return ([datetime]::UtcNow - $Activity).TotalDays -ge $Days
    }

    hidden [object] BuildState([hashtable]$Fields) {
        return [pscustomobject][ordered]@{
            ObjectGuid = $Fields.ObjectGuid
            SID = $Fields.SID
            DistinguishedName = $Fields.DistinguishedName
            Enabled = $Fields.Enabled
            WhenChanged = $Fields.WhenChanged
        }
    }

    hidden [int] DisabledAccountFlag() {
        return 2
    }

    hidden [string] ClassifyKind([object[]]$Classes) {
        if ($Classes -contains 'computer') {
            return 'Computer'
        }
        if ($Classes -contains 'group') {
            return 'Group'
        }
        if ($Classes -contains 'user') {
            return 'User'
        }
        return 'Unknown'
    }

    hidden [string] GetStateExclusion([object]$State) {
        if (-not $State.ObjectGuid -or
            $State.SID -notmatch '^S-\d+(?:-\d+)+$' -or
            -not $State.DistinguishedName -or
            -not $State.WhenChanged) {
            return 'MissingIdentityOrPreconditions'
        }
        if ($State.Enabled -isnot [bool] -or -not $State.Enabled) {
            return 'AccountNotEnabled'
        }
        return ''
    }

    hidden [bool] SupportsObjectKind([string]$Kind) {
        return $Kind -in 'User', 'Computer'
    }

    hidden [bool] HasCollectedSafetyMetadata([string]$Status) {
        return $Status -eq 'Collected'
    }

    hidden [string[]] RequiredSafetyFlags() {
        return @('ProtectedFromAccidentalDeletion', 'IsDomainController')
    }

    hidden [bool] IsWellKnownAccountSid([string]$Sid) {
        return ($Sid -match '^S-1-5-32-' -or $Sid -match '^S-1-5-21-(?:\d+-){3}(500|501|502)$')
    }

    hidden [int] DomainControllerFlag() {
        return 8192
    }

    hidden [int[]] DomainControllerPrimaryGroups() {
        return @(516, 521)
    }

    hidden [string[]] ProtectionFlags() {
        return @('ProtectedFromAccidentalDeletion', 'ProtectedUser', 'Protected', 'IsCriticalSystemObject')
    }

    hidden [bool] IsProtectedGroupSid([object]$Sid) {
        return [bool]($Sid -match '^S-1-5-21-(?:\d+-){3}525$')
    }

    hidden [bool] IsPrivilegeResolutionComplete([string]$Status) {
        return $Status -eq 'Complete'
    }

    hidden [bool] HasKnownAccountClassification([string]$AccountType) {
        return ($AccountType -in 'User', 'Personal', 'Human' -or $this.IsServiceAccount($AccountType))
    }

    hidden [bool] IsServiceAccount([string]$AccountType) {
        return $AccountType -in 'Service', 'Non-Personal', 'gMSA', 'ManagedServiceAccount'
    }

    hidden [bool] MatchesExcludedOrganizationalUnit([string]$ObjectDn, [string]$ExcludedOu) {
        return $ObjectDn.Equals($ExcludedOu, [StringComparison]::OrdinalIgnoreCase)
    }

    hidden [bool] IsWithinExcludedOrganizationalUnit([string]$ObjectDn, [string]$ExcludedOu) {
        return $ObjectDn.EndsWith(',' + $ExcludedOu, [StringComparison]::OrdinalIgnoreCase)
    }

    hidden [string[]] PreconditionNames() {
        return @('ObjectGuid', 'SID', 'DistinguishedName', 'WhenChanged')
    }

    hidden [bool] IdentityMatches([string]$Expected, [string]$Actual) {
        return $Expected -ieq $Actual
    }

    hidden [bool] IsReviewPlanType([object]$Type) {
        return -not ($Type -ne 'ADAnalyzerRemediationPlan')
    }

    hidden [string[]] PlanBooleanNames() {
        return @('IncludeServiceAccounts', 'IncludePrivilegedAccounts')
    }

    hidden [bool] IsActionLimitInRange([int]$Limit) {
        return $Limit -ge 1 -and $Limit -le 1000
    }

    hidden [bool] IsSupportedAction([object]$Action) {
        return -not ($Action -ne 'DisableAccount')
    }

    hidden [bool] IsUserInactivityRule([object]$Rule) {
        return [bool]($Rule -eq 'ACCOUNT.INACTIVE')
    }

    hidden [bool] IsComputerInactivityRule([object]$Rule) {
        return [bool]($Rule -eq 'COMPUTER.INACTIVE')
    }

    hidden [bool] IsSupportedInactivityRule([object]$Rule) {
        return $Rule -in 'ACCOUNT.INACTIVE', 'COMPUTER.INACTIVE'
    }

    hidden [bool] ClassMatches([object]$Actual, [string]$Expected) {
        return -not ($Actual -ne $Expected)
    }

    hidden [bool] IsInactivityThresholdValid([long]$Days) {
        return $Days -ge 0
    }

    hidden [string] RegisterActionIdentity(
        [hashtable]$SeenObjects,
        [hashtable]$SeenActionIds,
        [string]$ObjectGuid,
        [string]$ActionId
    ) {
        if ($SeenObjects.ContainsKey($ObjectGuid)) {
            return 'Plan contains duplicate object actions'
        }
        if ($SeenActionIds.ContainsKey($ActionId)) {
            return 'Plan contains duplicate action IDs'
        }
        $SeenObjects[$ObjectGuid] = $true
        $SeenActionIds[$ActionId] = $true
        return ''
    }
}

function Get-ADAnalyzerOperationState {
    param([Parameter(Mandatory)]$Object)
    $guard = [ADAnalyzerRemediationGuard]::new()
    $enabled = Get-ADAnalyzerOperationValue $Object @('Enabled')
    if ($null -eq $enabled) {
        $uac = Get-ADAnalyzerOperationValue $Object @('UserAccountControl')
        if ($null -ne $uac) {
            $enabled = ([long]$uac -band $guard.DisabledAccountFlag()) -eq 0
        }
    }
    $fields = @{
        ObjectGuid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $Object @('ObjectGuid'))
        SID = Get-ADAnalyzerOperationSid $Object
        DistinguishedName = [string](Get-ADAnalyzerOperationValue $Object @('DistinguishedName', 'DN'))
        Enabled = $enabled
        WhenChanged = ConvertTo-ADAnalyzerOperationTime (Get-ADAnalyzerOperationValue $Object @('WhenChanged'))
    }
    return $guard.BuildState($fields)
}

function Get-ADAnalyzerOperationKind {
    param($Object)
    $classes = @(Get-ADAnalyzerOperationValue $Object @('ObjectClass', 'Class'))
    return [ADAnalyzerRemediationGuard]::new().ClassifyKind($classes)
}

function Get-ADAnalyzerOperationExclusion {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)]$Settings

    )
    $guard = [ADAnalyzerRemediationGuard]::new()
    $state = Get-ADAnalyzerOperationState $Object
    $stateReason = $guard.GetStateExclusion($state)
    if ($stateReason) {
        return $stateReason
    }
    $kind = Get-ADAnalyzerOperationKind $Object
    if (-not $guard.SupportsObjectKind($kind)) {
        return 'UnsupportedObjectClass'
    }
    $metadata = [string](Get-ADAnalyzerOperationValue $Object @('SafetyMetadataStatus'))
    if (-not $guard.HasCollectedSafetyMetadata($metadata)) {
        return 'MissingSafetyEvidence'
    }
    foreach ($name in $guard.RequiredSafetyFlags()) {
        if ((Get-ADAnalyzerOperationValue $Object @($name)) -isnot [bool]) {
            return 'MissingSafetyEvidence'
        }
    }
    $critical = Get-ADAnalyzerOperationValue $Object @('IsCriticalSystemObject')
    if ($null -ne $critical -and $critical -isnot [bool]) {
        return 'MissingSafetyEvidence'
    }
    if ($null -eq (Get-ADAnalyzerOperationValue $Object @('UserAccountControl')) -or
        $null -eq (Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID'))) {
        return 'MissingSafetyEvidence'
    }
    if ($guard.IsWellKnownAccountSid($state.SID) -or
        [bool](Get-ADAnalyzerOperationValue $Object @('WellKnownSID') $false)) {
        return 'WellKnownAccount'
    }
    $uac = Get-ADAnalyzerOperationValue $Object @('UserAccountControl') 0
    $primary = Get-ADAnalyzerOperationValue $Object @('PrimaryGroupID') 0
    if ([bool](Get-ADAnalyzerOperationValue $Object @('IsDomainController') $false) -or
        ([long]$uac -band $guard.DomainControllerFlag()) -ne 0 -or
        [int]$primary -in $guard.DomainControllerPrimaryGroups()) {
        return 'DomainController'
    }
    if ([int](Get-ADAnalyzerOperationValue $Object @('AdminCount') 0) -ne 0) {
        return 'AdminCountProtected'
    }
    if (@(Get-ADAnalyzerOperationValue $Object @('SIDHistory') @() | Where-Object { $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace([string]$_) }).Count) {
        return 'SidHistoryRequiresReview'
    }
    foreach ($name in $guard.ProtectionFlags()) {
        if ([bool](Get-ADAnalyzerOperationValue $Object @($name) $false)) {
            return 'ProtectedOrCriticalObject'
        }
    }
    $membership = Get-ADAnalyzerOperationValue $Object @('Membership')
    $effective = @(Get-ADAnalyzerOperationValue $Object @('TransitiveGroups',
            'EffectiveSids') @()) + @(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
    if (@($effective | Where-Object { $guard.IsProtectedGroupSid($_) }).Count) {
        return 'ProtectedOrCriticalObject'
    }
    $resolution = [string](Get-ADAnalyzerOperationValue $Object @('PrivilegeResolutionStatus', 'MembershipResolutionStatus'))
    if (-not $guard.IsPrivilegeResolutionComplete($resolution)) {
        return 'PrivilegeResolutionIncomplete'
    }
    $privileged = Get-ADAnalyzerOperationValue $Object @('Privileged', 'IsPrivileged')
    if ($privileged -isnot [bool]) {
        return 'PrivilegeResolutionIncomplete'
    }
    if ($privileged -and -not $Settings.IncludePrivilegedAccounts) {
        return 'PrivilegedAccount'
    }
    if ($kind -eq 'User') {
        $accountType = [string](Get-ADAnalyzerOperationValue $Object @('AccountType'))
        if (-not $guard.HasKnownAccountClassification($accountType)) {
            return 'UnknownAccountClassification'
        }
        if ($guard.IsServiceAccount($accountType) -and -not $Settings.IncludeServiceAccounts) {
            return 'ServiceAccount'
        }
    }
    foreach ($excluded in @($Settings.ExcludedObjectGuids)) {
        if ((ConvertTo-ADAnalyzerOperationGuid $excluded) -eq $state.ObjectGuid) {
            return 'ExplicitObjectExclusion'
        }
    }
    foreach ($ou in @($Settings.ExcludedOUs)) {
        if ($ou -and
            ($guard.MatchesExcludedOrganizationalUnit($state.DistinguishedName, [string]$ou) -or
                $guard.IsWithinExcludedOrganizationalUnit($state.DistinguishedName, [string]$ou))) {
            return 'ExcludedOrganizationalUnit'
        }
    }
    return $null
}

class ADAnalyzerRemediationPlanner {
    ADAnalyzerRemediationPlanner() {
    }

    [object] CreatePlan([object]$Assessment) {
        return $this.CreatePlan($Assessment, $null)
    }

    [object] CreatePlan([object]$Assessment, [object]$Profile) {
        $ErrorActionPreference = 'Stop'
        $reader = [ADAnalyzerOperationDocumentReader]::new()
        $assessmentObject = $reader.Read($Assessment)
        $profileType = 'ADAnalyzerProfile' -as [type]
        if ($null -eq $profileType) {
            throw 'Load bin/ADAnalyzer.ps1 before creating a remediation plan'
        }
        $configuration = $profileType::new($Profile).ToHashtable()
        $settings = $configuration.Remediation
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $guard = [ADAnalyzerRemediationGuard]::new()

        $data = Get-ADAnalyzerOperationValue $assessmentObject @('Data')
        $directory = Get-ADAnalyzerOperationValue $data @('Directory')
        $domain = Get-ADAnalyzerOperationValue $directory @('Domain')
        $domainSid = [string](Get-ADAnalyzerOperationValue $domain @('SID', 'DomainSID'))
        $rootDomainSid = [string](Get-ADAnalyzerOperationValue $domain @('RootDomainSID'))
        $snapshotSids = @(Get-ADAnalyzerOperationValue $domain @('PrivilegedSids') @() | Where-Object { $null -ne $_ })
        $privilege = $this.NewPrivilegePolicy()
        foreach ($entry in $snapshotSids) {
            if (-not $this.AddSnapshotSid($privilege, $entry)) {
                throw 'Assessment privilege policy contains an unsupported SID value type'
            }
        }
        foreach ($sid in @($configuration.Policy.PrivilegedSids)) {
            $this.AddConfiguredSid($privilege, $sid, $domainSid, $rootDomainSid)
        }

        $work = $this.NewPlanState()
        foreach ($record in @(Get-ADAnalyzerOperationValue $assessmentObject @('Objects') @())) {
            if ($null -eq $record) {
                continue
            }
            $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $record @('ObjectGuid'))
            $this.IndexObject($work, $guid, $record)
        }
        $work.Approved = @(foreach ($value in @($settings.ApprovedObjectGuids)) {
                ConvertTo-ADAnalyzerOperationGuid $value
            })
        foreach ($finding in @(Get-ADAnalyzerOperationValue $assessmentObject @('Findings') @())) {
            if ($null -eq $finding) {
                continue
            }
            $rule = [string](Get-ADAnalyzerOperationValue $finding @('RuleId'))
            if (-not $guard.IsSupportedInactivityRule($rule) -or
                [string](Get-ADAnalyzerOperationValue $finding @('Status')) -ne 'Fail') {
                continue
            }
            $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $finding @('ObjectGuid'))
            $reason = $this.GetScopeExclusion($settings.AllowDisable, $privilege.ContextMissing)
            if (-not $reason) {
                $suppressed = [bool](Get-ADAnalyzerOperationValue $finding @('Suppressed') $false)
                $reason = $this.GetIdentityExclusion($work, $guid, $suppressed)
            }
            if (-not $reason) {
                $record = $work.Objects[$guid]
                $reason = $this.GetKindExclusion($rule, $guard.GetObjectKind($record))
                if (-not $reason) {
                    $reason = $guard.GetExclusion($record, $settings)
                }
            }
            if (-not $reason) {
                $reason = $this.GetLimitExclusion($work, $settings.MaximumActions)
            }
            if ($reason) {
                $target = Get-ADAnalyzerOperationValue $finding @('Target')
                $this.AddExclusion($work, $rule, $guid, $target, $reason)
                continue
            }
            if (-not $this.RegisterAction($work, $guid)) {
                continue
            }

            $record = $work.Objects[$guid]
            $state = $guard.ReadState($record)
            $action = $this.NewActionRecord($rule, $state)
            $kind = $guard.GetObjectKind($record)
            $accountType = Get-ADAnalyzerOperationValue $record @('AccountType')
            $inactivityDays = $this.GetInactivityDays($guard.GetObjectKind($record), $configuration.Policy)
            $this.AddAction($work, $action, $kind, $accountType, $inactivityDays, $state)
        }

        $header = $this.NewPlanRecord()
        $metadata = @{
            AssessmentRunId = Get-ADAnalyzerOperationValue $assessmentObject @('RunId')
            Target = Get-ADAnalyzerOperationValue $assessmentObject @('Target')
            Context = $projector.Project((Get-ADAnalyzerOperationValue $assessmentObject @('Context')))
            Remediation = $projector.Project($settings)
            AccountClassification = $projector.Project($configuration.AccountClassification)
            PrivilegedSids = @($privilege.Sids | Select-Object -Unique)
        }
        $plan = $this.BuildPlan($header, $metadata, $work)
        $this.ProjectPlanMetadata($plan, $projector)
        return $plan
    }

    hidden [hashtable] NewPrivilegePolicy() {
        return @{
            Sids = [Collections.Generic.List[object]]::new()
            ContextMissing = $false
        }
    }

    hidden [bool] AddSnapshotSid([hashtable]$Privilege, [object]$Entry) {
        if ($Entry -is [string]) {
            $Privilege.Sids.Add([string]$Entry)
            return $true
        }
        if ($Entry -is [System.Security.Principal.SecurityIdentifier]) {
            $Privilege.Sids.Add([string]$Entry.PSBase.Value)
            return $true
        }
        return $false
    }

    hidden [void] AddConfiguredSid(
        [hashtable]$Privilege,
        [object]$Sid,
        [string]$DomainSid,
        [string]$RootDomainSid
    ) {
        if (([string]$Sid).Contains('{DomainSid}') -and -not $DomainSid) {
            $Privilege.ContextMissing = $true
        }
        if (([string]$Sid).Contains('{RootDomainSid}') -and -not $RootDomainSid) {
            $Privilege.ContextMissing = $true
        }
        $expanded = ([string]$Sid).Replace('{DomainSid}', $DomainSid).Replace('{RootDomainSid}', $RootDomainSid)
        if ($expanded -and $expanded -match '^S-\d-') {
            $Privilege.Sids.Add($expanded)
        }
    }

    hidden [hashtable] NewPlanState() {
        return @{
            Objects = @{}
            Approved = @()
            Seen = @{}
            Actions = [Collections.Generic.List[object]]::new()
            Excluded = [Collections.Generic.List[object]]::new()
        }
    }

    hidden [void] IndexObject([hashtable]$Work, [object]$Guid, [object]$Record) {
        if ($Guid) {
            $Work.Objects[$Guid] = $Record
        }
    }

    hidden [string] GetScopeExclusion([bool]$AllowDisable, [bool]$PrivilegeContextMissing) {
        if (-not $AllowDisable) {
            return 'RemediationDisabled'
        }
        if ($PrivilegeContextMissing) {
            return 'PrivilegedPolicyContextMissing'
        }
        return ''
    }

    hidden [string] GetIdentityExclusion([hashtable]$Work, [object]$Guid, [bool]$Suppressed) {
        if ($Suppressed) {
            return 'SuppressedFinding'
        }
        if (-not $Guid -or -not $Work.Objects.ContainsKey($Guid)) {
            return 'MissingObjectEvidence'
        }
        if ($Guid -notin $Work.Approved) {
            return 'ObjectNotExplicitlyApproved'
        }
        return ''
    }

    hidden [string] GetKindExclusion([string]$Rule, [string]$Kind) {
        if (($Rule -eq 'ACCOUNT.INACTIVE' -and $Kind -ne 'User') -or
            ($Rule -eq 'COMPUTER.INACTIVE' -and $Kind -ne 'Computer')) {
            return 'RuleObjectClassMismatch'
        }
        return ''
    }

    hidden [string] GetLimitExclusion([hashtable]$Work, [int]$MaximumActions) {
        if ($Work.Actions.Count -ge $MaximumActions) {
            return 'MaximumActionsReached'
        }
        return ''
    }

    hidden [bool] RegisterAction([hashtable]$Work, [object]$Guid) {
        if ($Work.Seen.ContainsKey($Guid)) {
            return $false
        }
        $Work.Seen[$Guid] = $true
        return $true
    }

    hidden [void] AddExclusion(
        [hashtable]$Work, [string]$Rule, [object]$Guid, [object]$Target, [string]$Reason
    ) {
        $Work.Excluded.Add([pscustomobject]@{
                RuleId = $Rule
                ObjectGuid = $Guid
                Target = $Target
                Reason = $Reason
            })
    }

    hidden [object] GetInactivityDays([string]$Kind, [hashtable]$Policy) {
        if ($Kind -eq 'Computer') {
            return $Policy.ComputerInactivityDays
        }
        return $Policy.UserInactivityDays
    }

    hidden [System.Collections.Specialized.OrderedDictionary] NewActionRecord([string]$Rule, [object]$State) {
        return [ordered]@{
            ActionId = [guid]::NewGuid().ToString('D')
            Action = 'DisableAccount'
            RuleId = $Rule
            ObjectGuid = $State.ObjectGuid
            SID = $State.SID
            DistinguishedName = $State.DistinguishedName
        }
    }

    hidden [void] AddAction(
        [hashtable]$Work,
        [System.Collections.Specialized.OrderedDictionary]$Action,
        [string]$Kind,
        [object]$AccountType,
        [object]$InactivityDays,
        [object]$State
    ) {
        $Action.ObjectClass = $Kind
        $Action.AccountType = $AccountType
        $Action.InactivityDays = $InactivityDays
        $Action.Preconditions = $State
        $Work.Actions.Add([pscustomobject]$Action)
    }

    hidden [System.Collections.Specialized.OrderedDictionary] NewPlanRecord() {
        return [ordered]@{
            SchemaVersion = 1
            PlanType = 'ADAnalyzerRemediationPlan'
            PlanId = [guid]::NewGuid().ToString('D')
            CreatedAt = [datetimeoffset]::UtcNow.ToString('o')
        }
    }

    hidden [object] BuildPlan(
        [System.Collections.Specialized.OrderedDictionary]$Header,
        [hashtable]$Metadata,
        [hashtable]$Work
    ) {
        $Header.AssessmentRunId = $Metadata.AssessmentRunId
        $Header.Target = $Metadata.Target
        $Header.Context = $Metadata.Context
        $Header.Remediation = $Metadata.Remediation
        $Header.AccountClassification = $Metadata.AccountClassification
        $Header.PrivilegedSids = $Metadata.PrivilegedSids
        $Header.Actions = $Work.Actions.ToArray()
        $Header.Excluded = $Work.Excluded.ToArray()
        return [pscustomobject]$Header
    }

    hidden [void] ProjectPlanMetadata([object]$Plan, [ADAnalyzerEvidenceProjector]$Projector) {
        $Plan.AssessmentRunId = $Projector.ProjectIdentityMetadata($Plan.AssessmentRunId)
        $Plan.Target = $Projector.ProjectIdentityMetadata($Plan.Target)
        foreach ($item in $Plan.Excluded) {
            $item.Target = $Projector.ProjectIdentityMetadata($item.Target)
        }
        foreach ($action in $Plan.Actions) {
            $action.AccountType = $Projector.ProjectIdentityMetadata($action.AccountType)
        }
    }
}

function New-ADAnalyzerRemediationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Assessment,
        [AllowNull()]$Profile

    )
    $assessmentObject = Read-ADAnalyzerOperationDocument $Assessment
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $settings = $configuration.Remediation
    $planner = [ADAnalyzerRemediationPlanner]::new()
    $guard = [ADAnalyzerRemediationGuard]::new()
    $data = Get-ADAnalyzerOperationValue $assessmentObject @('Data')
    $directory = Get-ADAnalyzerOperationValue $data @('Directory')
    $domain = Get-ADAnalyzerOperationValue $directory @('Domain')
    $domainSid = [string](Get-ADAnalyzerOperationValue $domain @('SID', 'DomainSID'))
    $rootDomainSid = [string](Get-ADAnalyzerOperationValue $domain @('RootDomainSID'))
    $snapshotSids = @(Get-ADAnalyzerOperationValue $domain @('PrivilegedSids') @() | Where-Object { $null -ne $_ })
    $privilege = $planner.NewPrivilegePolicy()
    for ($index = 0; $index -lt $snapshotSids.Count; $index++) {
        $entry = $snapshotSids[$index]
        if (-not $planner.AddSnapshotSid($privilege, $entry)) {
            throw 'Assessment privilege policy contains an unsupported SID value type'
        }
    }
    foreach ($sid in @($configuration.Policy.PrivilegedSids)) {
        $planner.AddConfiguredSid($privilege, $sid, $domainSid, $rootDomainSid)
    }

    $work = $planner.NewPlanState()
    foreach ($object in @(Get-ADAnalyzerOperationValue $assessmentObject @('Objects') @())) {
        if ($null -eq $object) {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $object @('ObjectGuid'))
        $planner.IndexObject($work, $guid, $object)
    }
    $work.Approved = @(foreach ($value in @($settings.ApprovedObjectGuids)) {
            ConvertTo-ADAnalyzerOperationGuid $value
        })
    foreach ($finding in @(Get-ADAnalyzerOperationValue $assessmentObject @('Findings') @())) {
        if ($null -eq $finding) {
            continue
        }
        $rule = [string](Get-ADAnalyzerOperationValue $finding @('RuleId'))
        if (-not $guard.IsSupportedInactivityRule($rule) -or
            [string](Get-ADAnalyzerOperationValue $finding @('Status')) -ne 'Fail') {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $finding @('ObjectGuid'))
        $reason = $planner.GetScopeExclusion($settings.AllowDisable, $privilege.ContextMissing)
        if (-not $reason -and [bool](Get-ADAnalyzerOperationValue $finding @('Suppressed') $false)) {
            $reason = $planner.GetIdentityExclusion($work, $guid, $true)
        }
        elseif (-not $reason) {
            $reason = $planner.GetIdentityExclusion($work, $guid, $false)
        }
        # Keep the kind read in the native condition and the exclusion read at this scope.
        if (-not $reason -and
            -not ($reason = $planner.GetKindExclusion($rule, (Get-ADAnalyzerOperationKind $work.Objects[$guid])))) {
            $reason = Get-ADAnalyzerOperationExclusion $work.Objects[$guid] $settings
        }
        if (-not $reason) {
            $reason = $planner.GetLimitExclusion($work, $settings.MaximumActions)
        }
        if ($reason) {
            $target = Get-ADAnalyzerOperationValue $finding @('Target')
            $planner.AddExclusion($work, $rule, $guid, $target, $reason)
            continue
        }
        if (-not $planner.RegisterAction($work, $guid)) {
            continue
        }

        $object = $work.Objects[$guid]
        $state = Get-ADAnalyzerOperationState $object
        $action = $planner.NewActionRecord($rule, $state)
        $kind = Get-ADAnalyzerOperationKind $object
        $accountType = Get-ADAnalyzerOperationValue $object @('AccountType')
        $inactivityDays = $(
            $thresholdKind = Get-ADAnalyzerOperationKind $object
            $planner.GetInactivityDays($thresholdKind, $configuration.Policy)
        )
        $planner.AddAction($work, $action, $kind, $accountType, $inactivityDays, $state)
    }

    $header = $planner.NewPlanRecord()
    $metadata = @{
        AssessmentRunId = Get-ADAnalyzerOperationValue $assessmentObject @('RunId')
        Target = Get-ADAnalyzerOperationValue $assessmentObject @('Target')
        Context = ConvertTo-ADAnalyzerSafeData (Get-ADAnalyzerOperationValue $assessmentObject @('Context'))
        Remediation = ConvertTo-ADAnalyzerSafeData $settings
        AccountClassification = ConvertTo-ADAnalyzerSafeData $configuration.AccountClassification
        PrivilegedSids = @($privilege.Sids | Select-Object -Unique)
    }
    $projector = [ADAnalyzerEvidenceProjector]::new()
    $plan = $planner.BuildPlan($header, $metadata, $work)
    $planner.ProjectPlanMetadata($plan, $projector)
    return $plan
}

function Get-ADAnalyzerOperationConnection {
    param(
        [string]$Server,
        [pscredential]$Credential

    )
    if ($Server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'A DNS or NetBIOS Server is required'
    }
    $connection = @{
        Server = $Server
        ErrorAction = 'Stop'
    }
    if ($Credential -and $Credential -ne [pscredential]::Empty) {
        $connection.Credential = $Credential
    }
    return $connection
}

function Get-ADAnalyzerOperationCurrentObject {
    param(
        [string]$ObjectGuid,
        [hashtable]$Connection,
        $Plan,
        [Management.Automation.CommandInfo]$DirectoryCommand

    )
    $properties = @('objectGUID',
        'objectSid',
        'distinguishedName',
        'userAccountControl',
        'whenChanged',
        'whenCreated',
        'lastLogonTimestamp',
        'lastLogon',
        'sIDHistory',
        'adminCount',
        'isCriticalSystemObject',
        'ProtectedFromAccidentalDeletion',
        'memberOf',
        'primaryGroupID',
        'sAMAccountName')
    foreach ($rule in @($Plan.AccountClassification.AttributeRules)) {
        if ($null -eq $rule) {
            continue
        }
        $attribute = [string](Get-ADAnalyzerOperationValue $rule @('Attribute'))
        if (-not (Get-Command Test-ADAnalyzerClassificationAttribute `
                    -ErrorAction SilentlyContinue) -or
            -not (Test-ADAnalyzerClassificationAttribute $attribute)) {
            throw 'Classification attribute cannot be safely re-queried'
        }
        $properties += , $attribute
    }
    if ($null -ne $DirectoryCommand) {
        return & $DirectoryCommand -Identity ([guid]$ObjectGuid) -Properties $properties @Connection
    }
    return Get-ADObject -Identity ([guid]$ObjectGuid) -Properties $properties @Connection
}

function Assert-ADAnalyzerOperationPreconditions {
    param(
        $Expected,
        $Actual,
        [bool]$Enabled

    )
    $guard = [ADAnalyzerRemediationGuard]::new()
    $current = Get-ADAnalyzerOperationState $Actual
    foreach ($name in $guard.PreconditionNames()) {
        $wanted = Get-ADAnalyzerOperationValue $Expected @($name)
        if ($name -eq 'WhenChanged') {
            $wanted = ConvertTo-ADAnalyzerOperationTime $wanted
        }
        if ($name -eq 'ObjectGuid') {
            $wanted = ConvertTo-ADAnalyzerOperationGuid $wanted
        }
        if (-not $wanted -or -not $guard.IdentityMatches([string]$wanted, [string]$current.$name)) {
            throw "Remediation precondition failed: $name changed or is missing"
        }
    }
    if ($Expected.Enabled -isnot [bool] -or
        $Expected.Enabled -ne $Enabled -or
        $current.Enabled -isnot [bool] -or
        $current.Enabled -ne $Enabled) {
        throw 'Remediation precondition failed: Enabled changed or is missing'
    }
    return $current
}

function Assert-ADAnalyzerOperationPrivilege {
    param(
        $Object,
        $Action,
        $Plan,
        [hashtable]$Connection

    )
    if (-not (Get-Command Resolve-ADAnalyzerMembership -ErrorAction SilentlyContinue)) {
        throw 'Fresh privilege resolver is unavailable; remediation is blocked'
    }
    $guard = [ADAnalyzerRemediationGuard]::new()
    if (-not $guard.FreshClassMatches((Get-ADAnalyzerOperationKind $Object), $Action.ObjectClass)) {
        throw 'Current object class differs from the approved action'
    }
    $groups = @(Get-ADGroup -Filter * -Properties members, memberOf, primaryGroupToken, SID @Connection)
    $sid = Get-ADAnalyzerOperationSid $Object
    $domainSid = $guard.GetFreshDomainSid($sid)
    if (-not $domainSid) {
        throw 'A domain SID is required for fresh privilege resolution'
    }
    $privileged = $guard.StartFreshPrivilegedSids(@($Plan.PrivilegedSids))
    foreach ($group in $groups) {
        $groupSid = Get-ADAnalyzerOperationSid $group
        $guard.AddFreshPrivilegedGroup($privileged, $groupSid)
    }
    $membership = Resolve-ADAnalyzerMembership `
        -Object $Object `
        -Groups $groups `
        -DomainSid $domainSid `
        -PrivilegedSids @($privileged | Select-Object `
            -Unique)
    # Keep the native pipeline so getter errors retain the caller's capture.
    if ($null -eq $membership -or
        @(Get-ADAnalyzerOperationValue $membership @('Unresolved') @() |
            Where-Object { $guard.IsFreshUnresolvedEntry($_) }).Count -gt 0) {
        throw 'Fresh privilege resolution is incomplete; remediation is blocked'
    }
    $isPrivileged = Get-ADAnalyzerOperationValue $membership @('IsPrivileged')
    if ($isPrivileged -isnot [bool]) {
        throw 'Fresh privilege resolution did not return a definite result'
    }
    $state = Get-ADAnalyzerOperationState $Object
    $safe = $guard.CreateFreshSafetyRecord($state, $isPrivileged, $Action.AccountType, $Action.ObjectClass)
    foreach ($name in $guard.FreshSafetyPropertyNames()) {
        $safe[$name] = Get-ADAnalyzerOperationValue $Object @($name)
    }
    $guard.NormalizeFreshSafetyRecord($safe)
    $safe.TransitiveGroups = @(Get-ADAnalyzerOperationValue $membership @('EffectiveSids') @())
    $safe.IsDomainController = ([long]$safe.UserAccountControl -band $guard.DomainControllerFlag()) -ne 0 -or
        [int]$safe.PrimaryGroupID -in $guard.DomainControllerPrimaryGroups()
    if ($guard.NeedsFreshClassification($Action.ObjectClass)) {
        if (-not (Get-Command Get-ADAnalyzerAccountType -ErrorAction SilentlyContinue)) {
            throw 'Fresh account classification is unavailable; remediation is blocked'
        }
        $classificationObject = $guard.BuildFreshClassificationRecord(
            $state,
            (Get-ADAnalyzerOperationValue $Object @('MemberOf') @()),
            [string](Get-ADAnalyzerOperationValue $Object @('ObjectClass'))
        )
        foreach ($rule in @($Plan.AccountClassification.AttributeRules)) {
            if ($null -ne $rule) {
                $attribute = [string](Get-ADAnalyzerOperationValue $rule @('Attribute'))
                $classificationObject[$attribute] = Get-ADAnalyzerOperationValue $Object @($attribute)
            }
        }
        $classificationProfile = @{
            AccountClassification = ConvertTo-ADAnalyzerHashtable $Plan.AccountClassification
        }
        $classification = Get-ADAnalyzerAccountType `
            -Object ([pscustomobject]$classificationObject) `
            -Profile $classificationProfile `
            -Membership $membership
        $safe.AccountType = [string](Get-ADAnalyzerOperationValue $classification @('Type') 'Unknown')
        if (-not $guard.HasFreshClassification($safe.AccountType)) {
            throw 'Fresh account classification is unknown or conflicting'
        }
    }
    $reason = Get-ADAnalyzerOperationExclusion $safe $Plan.Remediation
    if ($reason) {
        throw "Fresh object safety check failed: $reason"
    }
}

function Assert-ADAnalyzerOperationInactivity {
    param(
        $Object,
        $Action

    )
    $guard = [ADAnalyzerRemediationGuard]::new()
    $days = 0L
    if (-not [long]::TryParse([string]$Action.InactivityDays, [ref]$days) -or
        -not $guard.IsInactivityThresholdValid($days)) {
        throw 'The reviewed action is missing its inactivity threshold'
    }
    $dates = [Collections.Generic.List[datetime]]::new()
    foreach ($name in $guard.FreshActivityPropertyNames()) {
        $value = Get-ADAnalyzerOperationValue $Object @($name)
        if ($null -eq $value -or [string]$value -eq '0') {
            continue
        }
        $fileTime = 0L
        try {
            if ([long]::TryParse([string]$value, [ref]$fileTime)) {
                $dates.Add([datetime]::FromFileTimeUtc($fileTime))
            }
            else {
                $dates.Add([datetime]::Parse((ConvertTo-ADAnalyzerOperationTime $value),
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime())
            }
        }
        catch {
            throw 'Fresh activity metadata could not be interpreted'
        }
    }
    if ($dates.Count) {
        $latest = $guard.LatestFreshActivity($dates)
    }
    else {
        $created = Get-ADAnalyzerOperationValue $Object @('WhenCreated')
        if ($null -eq $created) {
            throw 'Fresh inactivity evidence is unavailable'
        }
        try {
            $latest = [datetime]::Parse((ConvertTo-ADAnalyzerOperationTime $created),
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        }
        catch {
            throw 'Fresh creation metadata could not be interpreted'
        }
    }
    if (-not $guard.MeetsFreshInactivityThreshold($latest, $days)) {
        throw 'Fresh activity no longer satisfies the reviewed inactivity rule'
    }
    # This checks known activity on the pinned DC and its replicated timestamp;
    # it is not an authoritative all-DC lastLogon sweep.
}

function Initialize-ADAnalyzerJournalTypes {
    if ('ADAnalyzer.JournalLease' -as [type]) {
        return
    }
    try {
        Add-Type -Path (Join-Path $PSScriptRoot 'ADJournalLease.cs') -ErrorAction Stop
    }
    catch {
        # A concurrent runspace may have loaded the same package types.
        if (-not ('ADAnalyzer.JournalLease' -as [type]) -or
            -not ('ADAnalyzer.AccountEffectReservation' -as [type])) {
            throw
        }
    }
}

class ADAnalyzerRemediationJournal : System.IDisposable {
    hidden [object] $Lease
    hidden [object] $OwnershipGate

    ADAnalyzerRemediationJournal() {
        $this.OwnershipGate = [object]::new()
    }

    [void] Open([object]$Plan, [string]$Server, [string]$Path) {
        $ErrorActionPreference = 'Stop'
        if ([Threading.Monitor]::IsEntered($this.OwnershipGate)) {
            throw 'A remediation journal operation is active.'
        }
        [Threading.Monitor]::Enter($this.OwnershipGate)
        try {
            if ($null -ne $this.Lease) {
                throw 'A remediation journal is already open'
            }
            $projector = [ADAnalyzerEvidenceProjector]::new()
            $reviewedPlan = $projector.Project($Plan)
            $guard = [ADAnalyzerRemediationGuard]::new()
            $guard.AssertPlan($reviewedPlan)
            $null = Get-ADAnalyzerOperationConnection $Server ([pscredential]::Empty)
            $context = Get-ADAnalyzerOperationValue $reviewedPlan @('Context')
            $reviewedServer = [string](Get-ADAnalyzerOperationValue $context @('Server'))
            if ($reviewedServer -and $reviewedServer -ine $Server) {
                throw 'Server differs from the DC recorded in the reviewed assessment'
            }

            $full = Resolve-ADAnalyzerOperationFilePath $Path
            if ([IO.Directory]::Exists($full)) {
                throw 'JournalPath must name a file'
            }
            $directory = [IO.Path]::GetDirectoryName($full)
            if (-not [IO.Directory]::Exists($directory)) {
                $null = [IO.Directory]::CreateDirectory($directory)
            }
            $owner = $this.AcquireLease($full, [string]$reviewedPlan.PlanId, $Server)

            $opened = $false
            try {
                $fileExists = [IO.File]::Exists($full)
                if ($fileExists) {
                    $reader = [ADAnalyzerOperationDocumentReader]::new()
                    $journal = $reader.Read($full, 'Journal')
                    if (-not $this.IsJournalType($journal.JournalType) -or
                        -not $this.MatchesPlanId($journal.PlanId, $reviewedPlan.PlanId) -or
                        -not $this.MatchesServer($journal.Server, $Server)) {
                        throw 'Existing journal belongs to a different plan or server'
                    }
                }
                else {
                    $journal = $this.CreateJournal($reviewedPlan, $Server)
                }
                if ($journal.JournalId -isnot [string] -or [string]::IsNullOrEmpty($journal.JournalId)) {
                    throw 'The remediation journal is missing its identity'
                }
                $owner.BindInitialRecord($journal.JournalId, $this.SerializeJournal($journal), $fileExists)
                $this.Lease = $owner
                $opened = $true
            }
            finally {
                if (-not $opened) {
                    $owner.Dispose()
                }
            }
        }
        finally {
            [Threading.Monitor]::Exit($this.OwnershipGate)
        }
    }

    hidden [object] OpenExisting(
        [string]$Path,
        [string]$Server,
        [string]$PlanId,
        [string]$JournalId
    ) {
        $ErrorActionPreference = 'Stop'
        if ([Threading.Monitor]::IsEntered($this.OwnershipGate)) {
            throw 'A remediation journal operation is active.'
        }
        [Threading.Monitor]::Enter($this.OwnershipGate)
        try {
            if ($null -ne $this.Lease) {
                throw 'A remediation journal is already open'
            }
            if (-not [IO.File]::Exists($Path)) {
                throw 'Journal file does not exist'
            }
            $owner = $this.AcquireLease($Path, $PlanId, $Server)
            $opened = $false
            try {
                $reader = [ADAnalyzerOperationDocumentReader]::new()
                $journal = $reader.Read($owner.GetPath(), 'Journal')
                if (-not $this.IsUndoJournal($journal.JournalType, $journal.Server, $Server)) {
                    throw 'Journal type/server does not match this undo request'
                }
                if ($journal.PlanId -isnot [string] -or $journal.PlanId -ine $PlanId -or
                    $journal.JournalId -isnot [string] -or $journal.JournalId -ine $JournalId) {
                    throw 'Journal identity changed after undo review'
                }
                $record = [ADAnalyzerEvidenceProjector]::new().Project($journal)
                $owner.BindInitialRecord($journal.JournalId, $this.SerializeJournal($journal), $true)
                $this.Lease = $owner
                $opened = $true
                return $record
            }
            finally {
                if (-not $opened) {
                    $owner.Dispose()
                }
            }
        }
        finally {
            [Threading.Monitor]::Exit($this.OwnershipGate)
        }
    }

    [object] Read() {
        $ErrorActionPreference = 'Stop'
        $owner = $this.RequireLease()
        $operation = $owner.EnterOperation()
        try {
            $journal = $this.ReadOwnedJournal($owner)
            return [ADAnalyzerEvidenceProjector]::new().Project($journal)
        }
        finally {
            $operation.Dispose()
        }
    }

    [void] Write([object]$Journal) {
        $this.WriteOwned($Journal, $false)
    }

    hidden [void] WriteExisting([object]$Journal) {
        $this.WriteOwned($Journal, $true)
    }

    hidden [void] WriteOwned([object]$Journal, [bool]$RequireExisting) {
        $ErrorActionPreference = 'Stop'
        $owner = $this.RequireLease()
        $operation = $owner.EnterOperation()
        try {
            if ($null -eq $Journal -or $Journal -is [string]) {
                throw 'Supply an in-memory remediation journal'
            }
            $reader = [ADAnalyzerOperationDocumentReader]::new()
            $submitted = $reader.Read($Journal, 'Journal')
            $this.AssertOwnedIdentity($owner, $submitted)
            $null = $this.ReadOwnedJournal($owner)

            $initialJson = $owner.GetInitialJson()
            $record = ConvertFrom-Json -InputObject $initialJson -ErrorAction Stop
            $record.Entries = @(Get-ADAnalyzerOperationValue $submitted @('Entries') @())
            $record.UpdatedAt = $this.Timestamp()
            $path = $owner.GetPath()
            $content = $this.SerializeJournal($record)
            if ($RequireExisting) {
                $null = Write-ADAnalyzerOperationFile -Path $path -Content $content -RequireExisting
            }
            else {
                $null = Write-ADAnalyzerOperationFile -Path $path -Content $content
            }
            $owner.MarkWritten()
        }
        finally {
            $operation.Dispose()
        }
    }

    [void] Dispose() {
        $owner = $this.Lease
        if (-not $this.IsOwnedLease($owner)) {
            return
        }
        $owner.Dispose()
        [Threading.Monitor]::Enter($this.OwnershipGate)
        try {
            if ([object]::ReferenceEquals($owner, $this.Lease)) {
                $this.Lease = $null
            }
        }
        finally {
            [Threading.Monitor]::Exit($this.OwnershipGate)
        }
    }

    hidden [object] RequireLease() {
        $owner = $this.Lease
        if (-not $this.IsOwnedLease($owner)) {
            throw 'No remediation journal is open'
        }
        return $owner
    }

    hidden [object] AcquireLease([string]$Path, [string]$PlanId, [string]$Server) {
        Initialize-ADAnalyzerJournalTypes
        $leaseType = [type]'ADAnalyzer.JournalLease'
        try {
            return $leaseType::Open($Path, $PlanId, $Server, $this)
        }
        catch {
            throw $this.LeaseOpenFailure($Path, $_.Exception)
        }
    }

    hidden [bool] IsOwnedLease([object]$Owner) {
        $leaseType = 'ADAnalyzer.JournalLease' -as [type]
        return $null -ne $leaseType -and
            $Owner -is $leaseType -and
            $Owner.IsOwnedBy($this)
    }

    hidden [object] ReadOwnedJournal([object]$Owner) {
        $path = $Owner.GetPath()
        if ($Owner.ExpectsFile() -or [IO.File]::Exists($path)) {
            $reader = [ADAnalyzerOperationDocumentReader]::new()
            $journal = $reader.Read($path, 'Journal')
            $this.AssertOwnedIdentity($Owner, $journal)
            return $journal
        }
        $initialJson = $Owner.GetInitialJson()
        return ConvertFrom-Json -InputObject $initialJson -ErrorAction Stop
    }

    hidden [void] AssertOwnedIdentity([object]$Owner, [object]$Journal) {
        if (-not $this.IsJournalType($Journal.JournalType) -or
            $Journal.PlanId -isnot [string] -or
            $Journal.Server -isnot [string] -or
            $Journal.JournalId -isnot [string] -or
            -not $Owner.MatchesIdentity($Journal.PlanId, $Journal.Server, $Journal.JournalId)) {
            throw 'Journal identity does not match the owned remediation journal'
        }
    }

    hidden [object] CreateJournal([object]$Plan, [string]$Server) {
        $header = $this.NewJournalHeader()
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $fields = @{
            PlanId = $Plan.PlanId
            Server = $Server
            CreatedAt = $this.Timestamp()
            Remediation = $projector.Project($Plan.Remediation)
            PrivilegedSids = @($Plan.PrivilegedSids)
            AccountClassification = $projector.Project($Plan.AccountClassification)
        }
        return $this.BuildJournal($header, $fields)
    }

    hidden [string] SerializeJournal([object]$Journal) {
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $stored = $projector.Project($Journal)
        return ConvertTo-Json -InputObject $stored -Depth 100
    }

    hidden [string] LockPath([string]$Path) {
        return $Path + '.lock'
    }

    hidden [IO.IOException] LeaseOpenFailure([string]$Path, [Exception]$Cause) {
        $message = 'Unable to acquire journal lock for ' + $Path +
            '. Another run may be active or the filesystem may be unavailable.'
        return [IO.IOException]::new($message, $Cause)
    }

    hidden [bool] IsJournalType([object]$Type) {
        return -not ($Type -ne 'ADAnalyzerRemediationJournal')
    }

    hidden [bool] IsUndoJournal([object]$Type, [object]$ActualServer, [string]$ExpectedServer) {
        return $Type -is [string] -and $this.IsJournalType($Type) -and
            $ActualServer -is [string] -and $this.MatchesServer($ActualServer, $ExpectedServer)
    }

    hidden [bool] MatchesPlanId([object]$Actual, [object]$Expected) {
        return -not ($Actual -ne $Expected)
    }

    hidden [bool] MatchesServer([object]$Actual, [string]$Expected) {
        return -not ($Actual -ine $Expected)
    }

    hidden [string] Timestamp() {
        return [datetimeoffset]::UtcNow.ToString('o')
    }

    hidden [Collections.Specialized.OrderedDictionary] NewJournalHeader() {
        return [ordered]@{
            SchemaVersion = 1
            JournalType = 'ADAnalyzerRemediationJournal'
            JournalId = [guid]::NewGuid().ToString('D')
        }
    }

    hidden [object] BuildJournal(
        [Collections.Specialized.OrderedDictionary]$Header,
        [hashtable]$Fields
    ) {
        $Header.PlanId = $Fields.PlanId
        $Header.Server = $Fields.Server
        $Header.CreatedAt = $Fields.CreatedAt
        $Header.UpdatedAt = $null
        $Header.Remediation = $Fields.Remediation
        $Header.PrivilegedSids = $Fields.PrivilegedSids
        $Header.AccountClassification = $Fields.AccountClassification
        $Header.Entries = @()
        return [pscustomobject]$Header
    }
}

function Enter-ADAnalyzerJournalLease {
    param([Parameter(Mandatory)][string]$Path)
    $storage = [ADAnalyzerRemediationJournal]::new()
    $full = Resolve-ADAnalyzerOperationFilePath $Path
    if (Test-Path -LiteralPath $full -PathType Container) {
        throw 'JournalPath must name a file'
    }
    $directory = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($directory)) {
        $null = [IO.Directory]::CreateDirectory($directory)
    }
    try {
        # Keep the marker: unlinking after close can race the next owner.
        return [IO.File]::Open(
            $storage.LockPath($full), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None
        )
    }
    catch {
        throw $storage.LeaseOpenFailure($full, $_.Exception)
    }
}

function Get-ADAnalyzerOperationJournal {
    param(
        $Plan,
        [string]$Server,
        [string]$Path

    )
    $storage = [ADAnalyzerRemediationJournal]::new()
    if (Test-Path -LiteralPath $Path) {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            throw 'JournalPath must name a file'
        }
        $journal = Read-ADAnalyzerOperationDocument $Path 'Journal'
        if (-not $storage.IsJournalType($journal.JournalType) -or
            -not $storage.MatchesPlanId($journal.PlanId, $Plan.PlanId) -or
            -not $storage.MatchesServer($journal.Server, $Server)) {
            throw 'Existing journal belongs to a different plan or server'
        }
        return $journal
    }
    $header = $storage.NewJournalHeader()
    $fields = @{
        PlanId = $Plan.PlanId
        Server = $Server
        CreatedAt = $storage.Timestamp()
        Remediation = ConvertTo-ADAnalyzerSafeData $Plan.Remediation
        PrivilegedSids = @($Plan.PrivilegedSids)
        AccountClassification = ConvertTo-ADAnalyzerSafeData $Plan.AccountClassification
    }
    return $storage.BuildJournal($header, $fields)
}

function Save-ADAnalyzerOperationJournal {
    param(
        $Journal,
        [string]$Path

    )
    $storage = [ADAnalyzerRemediationJournal]::new()
    $Journal.UpdatedAt = $storage.Timestamp()
    $json = ConvertTo-Json -InputObject (ConvertTo-ADAnalyzerSafeData $Journal) -Depth 100
    $null = Write-ADAnalyzerOperationFile -Path $Path -Content $json
}

function Assert-ADAnalyzerOperationPlan {
    param($Plan)

    $guard = [ADAnalyzerRemediationGuard]::new()
    if (-not $guard.IsReviewPlanType($Plan.PlanType) -or -not (ConvertTo-ADAnalyzerOperationGuid $Plan.PlanId)) {
        throw 'Only an explicit ADAnalyzer remediation plan may be executed'
    }
    if ($Plan.Remediation.AllowDisable -isnot [bool] -or -not $Plan.Remediation.AllowDisable) {
        throw 'The plan does not enable account disabling'
    }
    foreach ($name in $guard.PlanBooleanNames()) {
        if ($Plan.Remediation.$name -isnot [bool]) {
            throw "Invalid plan boolean setting: $name"
        }
    }
    $limit = 0
    if (-not [int]::TryParse([string]$Plan.Remediation.MaximumActions,
            [ref]$limit) -or
        -not $guard.IsActionLimitInRange($limit) -or
        @($Plan.Actions).Count -gt $limit) {
        throw 'Invalid remediation action limit'
    }
    $approved = @(foreach ($value in @($Plan.Remediation.ApprovedObjectGuids)) {
            ConvertTo-ADAnalyzerOperationGuid $value
        })
    $seen = @{}
    $seenActionIds = @{}
    foreach ($action in @($Plan.Actions)) {
        if ($null -eq $action) {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid $action.ObjectGuid
        if (-not $guard.IsSupportedAction($action.Action) -or
            -not $guid -or
            $guid -notin $approved -or
            $action.Preconditions.ObjectGuid -ne $guid -or
            -not ($actionId = ConvertTo-ADAnalyzerOperationGuid $action.ActionId)) {
            throw 'Plan includes an unsupported, unapproved, or unbound action'
        }
        if (($guard.IsUserInactivityRule($action.RuleId) -and -not $guard.ClassMatches($action.ObjectClass, 'User')) -or
            ($guard.IsComputerInactivityRule($action.RuleId) -and -not $guard.ClassMatches($action.ObjectClass, 'Computer')) -or
            -not $guard.IsSupportedInactivityRule($action.RuleId)) {
            throw 'Plan rule and object class do not match'
        }
        $days = 0L
        if (-not [long]::TryParse([string]$action.InactivityDays, [ref]$days) -or -not $guard.IsInactivityThresholdValid($days)) {
            throw 'Plan action is missing its reviewed inactivity threshold'
        }
        $duplicate = $guard.RegisterActionIdentity($seen, $seenActionIds, $guid, $actionId)
        if ($duplicate) {
            throw $duplicate
        }
    }
}

function Get-ADAnalyzerRemediationAuthorityDirectory {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'The remediation account reservation requires a designated Windows host.'
    }

    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ($programData -notmatch '^[A-Za-z]:\\') {
        throw 'The remediation account reservation requires a local ProgramData directory.'
    }
    $path = [IO.Path]::Combine($programData, 'ADAnalyzer.Remediation')
    $directory = [IO.DirectoryInfo]::new($path)
    if (-not $directory.Exists -or
        [IO.DriveInfo]::new($directory.Root.FullName).DriveType -ne [IO.DriveType]::Fixed) {
        throw 'The protected ADAnalyzer.Remediation directory must be provisioned on the designated Windows host.'
    }

    $component = $directory
    while ($null -ne $component) {
        if (($component.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The remediation account reservation directory cannot use a reparse point.'
        }
        $component = $component.Parent
    }
    return $directory.FullName
}

class ADAnalyzerRemediationReservationInspector {
    ADAnalyzerRemediationReservationInspector() {
    }

    [pscustomobject] Inspect([guid]$ObjectGuid) {
        if ($ObjectGuid -eq [guid]::Empty) {
            throw 'A canonical account GUID is required.'
        }

        $directory = Get-ADAnalyzerRemediationAuthorityDirectory
        Initialize-ADAnalyzerJournalTypes
        $reservationType = 'ADAnalyzer.AccountEffectReservation' -as [type]
        if ($null -eq $reservationType -or $null -eq $reservationType.GetMethod('Inspect')) {
            throw 'Start a fresh PowerShell process to load the remediation account inspection support.'
        }
        $observation = $reservationType::Inspect($directory, $ObjectGuid)

        return [pscustomobject][ordered]@{
            ObjectGuid = $ObjectGuid
            Status = $observation['Status']
            AttemptId = $observation['AttemptId']
            Operation = $observation['Operation']
            CreatedUtc = $observation['CreatedUtc']
            LastConfirmedStep = $observation['LastConfirmedStep']
        }
    }
}

function Get-ADAnalyzerRemediationReservation {
    <#
    .SYNOPSIS
    Reads one account reservation from the local remediation authority.
    .DESCRIPTION
    Reports a point-in-time observation for the specified account GUID.
    Use the result to locate evidence for manual reconciliation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$ObjectGuid
    )

    $inspector = [ADAnalyzerRemediationReservationInspector]::new()
    $inspector.Inspect($ObjectGuid)
}

class ADAnalyzerRemediationExecutor {
    ADAnalyzerRemediationExecutor() {
    }

    hidden [object] ReserveAccount([guid]$ObjectGuid, [bool]$Undo) {
        $directory = Get-ADAnalyzerRemediationAuthorityDirectory
        Initialize-ADAnalyzerJournalTypes
        $reservationType = 'ADAnalyzer.AccountEffectReservation' -as [type]
        if ($null -eq $reservationType) {
            throw 'Start a fresh PowerShell process to load the remediation account reservation support.'
        }
        return $reservationType::Acquire($directory, $ObjectGuid, $Undo)
    }

    hidden [void] ReleaseIfNotDispatched([object]$Reservation, [Management.Automation.ErrorRecord]$Failure) {
        if ($null -ne $Reservation) {
            try {
                $Reservation.ReleaseBeforeDispatch()
            }
            catch {
                $message = 'The account reservation could not be released after the remediation failure. ' +
                    $_.Exception.Message
                throw [InvalidOperationException]::new($message, $Failure.Exception)
            }

            $this.AddReservationFailureContext($Reservation, $Failure.Exception)
        }
    }

    hidden [void] AddReservationFailureContext([object]$Reservation, [Exception]$Failure) {
        # A previously loaded helper type can still preserve its original
        # failure contract until the process is restarted.
        if ($null -ne $Reservation -and $null -ne $Reservation.GetType().GetMethod('TryAttachFailureContext')) {
            $Reservation.TryAttachFailureContext($Failure)
        }
    }

    hidden [object] NewReservationPersistenceFailure([object]$Reservation, [string]$Message) {
        $failure = [Management.Automation.RuntimeException]::new($Message, $null)
        $this.AddReservationFailureContext($Reservation, $failure)
        if ($failure.Data.Count -eq 0) {
            return $Message
        }

        # Match the original string throw's message, error ID, category and target.
        return [Management.Automation.ErrorRecord]::new(
            $failure, $Message, [Management.Automation.ErrorCategory]::OperationStopped, $Message
        )
    }

    [object[]] PreviewUndo([string]$JournalPath, [string]$Server) {
        $ErrorActionPreference = 'Stop'
        $target = $this.ReadUndoTarget($JournalPath, $Server, [pscredential]::Empty)
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($entry in @($target.Journal.Entries)) {
            if ($this.IsReviewedUndoEntry($entry)) {
                $rows.Add($this.SkippedUndo($entry.EntryId, $entry.ObjectGuid))
            }
        }
        return $rows.ToArray()
    }

    [object[]] Undo([string]$JournalPath, [string]$Server, [object[]]$ApprovedEntryIds) {
        return $this.Undo($JournalPath, $Server, $ApprovedEntryIds, [pscredential]::Empty)
    }

    [object[]] Undo(
        [string]$JournalPath,
        [string]$Server,
        [object[]]$ApprovedEntryIds,
        [pscredential]$Credential
    ) {
        $ErrorActionPreference = 'Stop'
        $target = $this.ReadUndoTarget($JournalPath, $Server, $Credential)
        $approvals = $this.ApprovedUndoSet($target.Journal, $ApprovedEntryIds)
        $rows = [Collections.Generic.List[object]]::new()
        $owner = [ADAnalyzerRemediationJournal]::new()
        $guard = [ADAnalyzerRemediationGuard]::new()
        $journal = $null
        $ownedEntries = $null
        $plan = $null
        $commands = $null
        $connection = $target.Connection
        try {
            foreach ($candidate in @($target.Journal.Entries)) {
                if (-not $this.IsReviewedUndoEntry($candidate)) {
                    continue
                }
                $id = $this.UndoEntryId($candidate.EntryId)
                if (-not $id -or -not $approvals.ContainsKey($id)) {
                    $rows.Add($this.SkippedUndo($candidate.EntryId, $candidate.ObjectGuid))
                    continue
                }

                if ($null -eq $journal) {
                    $journal = $owner.OpenExisting(
                        $target.Path, $Server, $target.Journal.PlanId, $target.Journal.JournalId
                    )
                    $ownedEntries = $this.IndexUndoEntries($journal)
                    $plan = $this.UndoPolicy(
                        $journal.Remediation, $journal.PrivilegedSids, $journal.AccountClassification
                    )
                }
                if (-not $ownedEntries.ContainsKey($id) -or $ownedEntries[$id].Count -ne 1) {
                    throw 'Journal entry identity is missing or ambiguous'
                }
                $entry = $ownedEntries[$id][0]
                if (-not $this.IsReviewedUndoEntry($entry)) {
                    continue
                }
                foreach ($name in $this.UndoIdentityFields()) {
                    $reviewedValue = [string](Get-ADAnalyzerOperationValue $candidate @($name))
                    $ownedValue = [string](Get-ADAnalyzerOperationValue $entry @($name))
                    if (-not $this.IsSameUndoIdentity($reviewedValue, $ownedValue)) {
                        throw 'Journal entry identity changed after undo review'
                    }
                }
                $reservation = $null
                $admitting = $false
                try {
                    if ($entry.Before.Enabled -isnot [bool] -or $entry.After.Enabled -isnot [bool] -or
                        -not $this.IsReversibleDisable($entry)) {
                        throw 'Journal does not contain a reversible enabled-to-disabled transition'
                    }
                    $approved = @(foreach ($value in @($journal.Remediation.ApprovedObjectGuids)) {
                            ConvertTo-ADAnalyzerOperationGuid $value
                        })
                    if (-not $this.IsApprovedUndoEntry($entry, $approved)) {
                        throw 'Journal entry identity is not bound to an approved reversible action'
                    }
                    $account = [guid]$entry.ObjectGuid
                    $admitting = $true
                    $reservation = $this.ReserveAccount($account, $true)
                    $admitting = $false
                    if ($null -eq $commands) {
                        $commands = $this.GetUndoDirectoryCommands()
                    }
                    $current = Get-ADAnalyzerOperationCurrentObject $account $connection $plan $commands.Read
                    $state = $guard.AssertPreconditions($entry.After, $current, $false)
                    $guard.AssertPrivilege($current, $entry, $plan, $Server, $Credential)
                    $this.PrepareUndoEntry($entry, $state)
                    $owner.WriteExisting($journal)

                    $mutation = @{
                        Identity = $account
                        WhatIf = $false
                        Confirm = $false
                    }
                    $enable = $commands.Enable
                    $reservation.BeginDispatch()
                    $null = & $enable @mutation @connection
                    $after = Get-ADAnalyzerOperationCurrentObject $account $connection $plan $commands.Read
                    $entry.Undo.After = $guard.ReadState($after)
                    if (-not $this.IsVerifiedEnabled($entry.Before, $entry.Undo.After)) {
                        throw 'Unable to verify the account enable result'
                    }
                    $this.CompleteUndoEntry($entry)
                    $owner.WriteExisting($journal)
                }
                catch {
                    if ($admitting) {
                        throw
                    }
                    $failure = $_
                    $this.RecordUndoFailure($entry, $failure.Exception.Message)
                    try {
                        $owner.WriteExisting($journal)
                    }
                    catch {
                        $message = $this.UndoPersistenceFailure($failure.Exception.Message, $_.Exception.Message)
                        throw $this.NewReservationPersistenceFailure($reservation, $message)
                    }
                    $this.ReleaseIfNotDispatched($reservation, $failure)
                    throw $failure
                }
                $reservation.ReleaseAfterRecordedCompletion()
                $rows.Add([ADAnalyzerEvidenceProjector]::new().Project($entry))
            }
        }
        finally {
            $owner.Dispose()
        }
        return $rows.ToArray()
    }

    hidden [hashtable] ReadUndoTarget([string]$Path, [string]$Server, [pscredential]$Credential) {
        $full = Resolve-ADAnalyzerOperationFilePath $Path
        $reader = [ADAnalyzerOperationDocumentReader]::new()
        $journal = $reader.Read($full, 'Journal')
        $storage = [ADAnalyzerRemediationJournal]::new()
        if (-not $storage.IsUndoJournal($journal.JournalType, $journal.Server, $Server)) {
            throw 'Journal type/server does not match this undo request'
        }
        if ($journal.PlanId -isnot [string] -or [string]::IsNullOrWhiteSpace($journal.PlanId) -or
            $journal.JournalId -isnot [string] -or [string]::IsNullOrWhiteSpace($journal.JournalId)) {
            throw 'The remediation journal is missing its identity'
        }
        return @{
            Path = $full
            Journal = [ADAnalyzerEvidenceProjector]::new().Project($journal)
            Connection = Get-ADAnalyzerOperationConnection $Server $Credential
        }
    }

    hidden [object] UndoEntryId([object]$Value) {
        if ($Value -isnot [string] -and $Value -isnot [guid]) {
            return $null
        }
        return ConvertTo-ADAnalyzerOperationGuid $Value
    }

    hidden [hashtable] IndexUndoEntries([object]$Journal) {
        $index = @{}
        foreach ($entry in @($Journal.Entries)) {
            if ($null -eq $entry) {
                continue
            }
            $property = $entry.PSObject.Properties['EntryId']
            if ($null -eq $property) {
                continue
            }
            $id = $this.UndoEntryId($property.Value)
            if ($id) {
                if (-not $index.ContainsKey($id)) {
                    $index[$id] = [Collections.Generic.List[object]]::new()
                }
                $index[$id].Add($entry)
            }
        }
        return $index
    }

    hidden [hashtable] ApprovedUndoSet([object]$Journal, [object[]]$Requested) {
        if ($null -eq $Requested) {
            throw 'Supply explicit approved undo entry IDs'
        }
        $reviewed = $this.IndexUndoEntries($Journal)
        $approved = @{}
        foreach ($value in $Requested) {
            $id = $this.UndoEntryId($value)
            if (-not $id -or -not $reviewed.ContainsKey($id)) {
                throw 'Approved undo entry ID does not belong to the reviewed journal'
            }
            if ($reviewed[$id].Count -ne 1) {
                throw 'Journal entry identity is missing or ambiguous'
            }
            $entry = $reviewed[$id][0]
            if (-not $this.IsReviewedUndoEntry($entry)) {
                throw 'Approved undo entry ID does not belong to the reviewed journal'
            }
            if ($approved.ContainsKey($id)) {
                throw 'Approved undo entry IDs must be unique'
            }
            $approved[$id] = $true
        }
        return $approved
    }

    hidden [hashtable] GetUndoDirectoryCommands() {
        $providerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        $exports = $provider.ExportedCmdlets
        if ($null -eq $exports -or
            $exports['Get-ADObject'] -isnot [Management.Automation.CommandInfo] -or
            $exports['Enable-ADAccount'] -isnot [Management.Automation.CommandInfo]) {
            throw 'Bundled AD assembly does not provide the required Undo commands'
        }
        return @{
            Read = $exports['Get-ADObject']
            Enable = $exports['Enable-ADAccount']
        }
    }

    hidden [bool] IsUndoAction([object]$Action) {
        return ($Action -eq 'DisableAccount')
    }

    hidden [bool] IsUndoStatus([object]$Status) {
        return ($Status -eq 'Succeeded')
    }

    hidden [bool] IsReviewedUndoEntry([object]$Entry) {
        if ($null -eq $Entry) {
            return $false
        }
        $action = $Entry.PSObject.Properties['Action']
        if ($null -eq $action -or $action.Value -isnot [string] -or -not $this.IsUndoAction($action.Value)) {
            return $false
        }
        $status = $Entry.PSObject.Properties['Status']
        return $null -ne $status -and $status.Value -is [string] -and $this.IsUndoStatus($status.Value)
    }

    hidden [object] SkippedUndo([object]$EntryId, [object]$ObjectGuid) {
        return [pscustomobject]@{
            EntryId = $EntryId
            ObjectGuid = $ObjectGuid
            Status = 'Skipped'
        }
    }

    hidden [object] UndoPolicy([object]$Remediation, [object]$PrivilegedSids, [object]$AccountClassification) {
        return [pscustomobject]@{
            Remediation = $Remediation
            PrivilegedSids = $PrivilegedSids
            AccountClassification = $AccountClassification
        }
    }

    hidden [string[]] UndoIdentityFields() {
        return @('ActionId', 'ObjectGuid', 'SID', 'DistinguishedName')
    }

    hidden [bool] IsSameUndoIdentity([string]$Reviewed, [string]$Owned) {
        return ($Owned -ieq $Reviewed)
    }

    hidden [bool] IsReversibleDisable([object]$Entry) {
        return -not ($Entry.Before.Enabled -ne $true -or $Entry.After.Enabled -ne $false)
    }

    hidden [bool] IsApprovedUndoEntry([object]$Entry, [object[]]$ApprovedObjectGuids) {
        return -not ($Entry.ObjectGuid -notin $ApprovedObjectGuids -or
            $Entry.ObjectGuid -ne $Entry.Before.ObjectGuid -or
            $Entry.ObjectGuid -ne $Entry.After.ObjectGuid -or
            $Entry.SID -ne $Entry.Before.SID -or
            $Entry.SID -ne $Entry.After.SID)
    }

    hidden [void] PrepareUndoEntry([object]$Entry, [object]$State) {
        $Entry.Undo = [pscustomobject]@{
            Timestamp = [datetimeoffset]::UtcNow.ToString('o')
            Status = 'Prepared'
            Before = $State
            After = $null
            Message = $null
        }
    }

    hidden [bool] IsVerifiedEnabled([object]$Before, [object]$After) {
        return -not ($After.ObjectGuid -ne $Before.ObjectGuid -or
            $After.SID -ne $Before.SID -or
            $After.DistinguishedName -ine $Before.DistinguishedName -or
            $After.Enabled -isnot [bool] -or -not $After.Enabled)
    }

    hidden [void] CompleteUndoEntry([object]$Entry) {
        $Entry.Undo.Status = 'Succeeded'
        $Entry.Status = 'Undone'
    }

    hidden [void] RecordUndoFailure([object]$Entry, [string]$Message) {
        if ($Entry.Undo) {
            $Entry.Undo.Status = 'Failed'
            $Entry.Undo.Message = $Message
        }
        else {
            $Entry.Undo = [pscustomobject]@{
                Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                Status = 'Rejected'
                Before = $null
                After = $null
                Message = $Message
            }
        }
    }

    hidden [string] UndoPersistenceFailure([string]$Original, [string]$Persistence) {
        return 'Undo journal persistence failed; no further changes were attempted. ' + $Original + '; ' + $Persistence
    }

    [object[]] Preview([object]$Plan, [string]$Server, [string]$JournalPath) {
        $ErrorActionPreference = 'Stop'
        $target = $this.PrepareApply($Plan, $Server, $JournalPath, [pscredential]::Empty)
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($action in @($target.Plan.Actions)) {
            if ($null -ne $action) {
                $rows.Add($this.SkippedAction($action.ActionId, $action.ObjectGuid))
            }
        }
        return $rows.ToArray()
    }

    [object[]] Apply([object]$Plan, [string]$Server, [string]$JournalPath, [object[]]$ApprovedActionIds) {
        return $this.Apply($Plan, $Server, $JournalPath, $ApprovedActionIds, [pscredential]::Empty)
    }

    [object[]] Apply(
        [object]$Plan,
        [string]$Server,
        [string]$JournalPath,
        [object[]]$ApprovedActionIds,
        [pscredential]$Credential
    ) {
        $ErrorActionPreference = 'Stop'
        $target = $this.PrepareApply($Plan, $Server, $JournalPath, $Credential)
        $approvals = $this.ApprovedActionSet($target.Plan, $ApprovedActionIds)
        $rows = [Collections.Generic.List[object]]::new()
        $owner = [ADAnalyzerRemediationJournal]::new()
        $journal = $null
        $commands = $null
        try {
            foreach ($action in @($target.Plan.Actions)) {
                if ($null -eq $action) {
                    continue
                }
                $id = ConvertTo-ADAnalyzerOperationGuid $action.ActionId
                if (-not $approvals.ContainsKey($id)) {
                    $rows.Add($this.SkippedAction($action.ActionId, $action.ObjectGuid))
                    continue
                }

                if ($null -eq $journal) {
                    $owner.Open($target.Plan, $Server, $target.Path)
                    $journal = $owner.Read()
                }
                if (@($journal.Entries | Where-Object {
                            $_.ActionId -eq $action.ActionId -and $this.IsCompletedAction($_.Status)
                        }).Count) {
                    throw 'This plan action has already been applied; create a fresh assessment and plan'
                }
                $objectGuid = $action.ObjectGuid
                $account = [guid]$objectGuid
                $reservation = $this.ReserveAccount($account, $false)
                try {
                    if ($null -eq $commands) {
                        $commands = $this.GetApplyDirectoryCommands()
                    }
                }
                catch {
                    $this.ReleaseIfNotDispatched($reservation, $_)
                    throw
                }

                $header = $this.NewEntryHeader()
                $fields = @{
                    ActionId = $action.ActionId
                    ObjectGuid = $objectGuid
                    SID = $action.SID
                    DistinguishedName = $action.DistinguishedName
                    ObjectClass = $action.ObjectClass
                    AccountType = $action.AccountType
                    InactivityDays = $action.InactivityDays
                }
                $entry = $this.BuildEntry($header, $fields)
                $guard = [ADAnalyzerRemediationGuard]::new()
                $connection = $target.Connection
                $added = $false
                try {
                    $current = Get-ADAnalyzerOperationCurrentObject $account $connection $target.Plan $commands.Read
                    $entry.Before = $guard.AssertPreconditions($action.Preconditions, $current, $true)
                    $guard.AssertPrivilege($current, $action, $target.Plan, $target.Server, $target.Credential)
                    $guard.AssertInactivity($current, $action)
                    $this.PrepareEntry($journal, $entry)
                    $added = $true
                    $owner.Write($journal)

                    $mutation = @{
                        Identity = $account
                        WhatIf = $false
                        Confirm = $false
                    }
                    $disable = $commands.Disable
                    $reservation.BeginDispatch()
                    $null = & $disable @mutation @connection
                    $after = Get-ADAnalyzerOperationCurrentObject $account $connection $target.Plan $commands.Read
                    $entry.After = $guard.ReadState($after)
                    if (-not $this.IsVerifiedDisabled($entry.Before, $entry.After)) {
                        throw 'Unable to verify the account disable result'
                    }
                    $this.CompleteEntry($entry)
                    $owner.Write($journal)
                }
                catch {
                    $failure = $_
                    $this.RecordApplyFailure($journal, $entry, $failure.Exception.Message, $added)
                    try {
                        $owner.Write($journal)
                    }
                    catch {
                        $message = $this.ApplyPersistenceFailure($failure.Exception.Message, $_.Exception.Message)
                        throw $this.NewReservationPersistenceFailure($reservation, $message)
                    }
                    $this.ReleaseIfNotDispatched($reservation, $failure)
                    throw $failure
                }
                $reservation.ReleaseAfterRecordedCompletion()
                $rows.Add([ADAnalyzerEvidenceProjector]::new().Project($entry))
            }
        }
        finally {
            $owner.Dispose()
        }
        return $rows.ToArray()
    }

    hidden [hashtable] PrepareApply(
        [object]$Plan,
        [string]$Server,
        [string]$JournalPath,
        [pscredential]$Credential
    ) {
        $reader = [ADAnalyzerOperationDocumentReader]::new()
        $projector = [ADAnalyzerEvidenceProjector]::new()
        $planObject = $projector.Project($reader.Read($Plan, 'Plan'))
        $guard = [ADAnalyzerRemediationGuard]::new()
        $guard.AssertPlan($planObject)
        $path = Resolve-ADAnalyzerOperationFilePath $JournalPath
        $connection = Get-ADAnalyzerOperationConnection $Server $Credential
        $context = Get-ADAnalyzerOperationValue $planObject @('Context')
        $reviewedServer = [string](Get-ADAnalyzerOperationValue $context @('Server'))
        if (-not $this.IsReviewedServer($reviewedServer, $Server)) {
            throw 'Server differs from the DC recorded in the reviewed assessment'
        }
        return @{
            Plan = $planObject
            Path = $path
            Connection = $connection
            Server = $Server
            Credential = $Credential
        }
    }

    hidden [hashtable] ApprovedActionSet([object]$Plan, [object[]]$Requested) {
        $reviewed = @{}
        foreach ($action in @($Plan.Actions)) {
            if ($null -ne $action) {
                $id = ConvertTo-ADAnalyzerOperationGuid $action.ActionId
                $reviewed[$id] = $true
            }
        }
        $approved = @{}
        foreach ($value in $Requested) {
            if ($value -isnot [string] -and $value -isnot [guid]) {
                throw 'Approved action ID does not belong to the reviewed plan'
            }
            $id = ConvertTo-ADAnalyzerOperationGuid $value
            if (-not $id -or -not $reviewed.ContainsKey($id)) {
                throw 'Approved action ID does not belong to the reviewed plan'
            }
            if ($approved.ContainsKey($id)) {
                throw 'Approved action IDs must be unique'
            }
            $approved[$id] = $true
        }
        return $approved
    }

    hidden [hashtable] GetApplyDirectoryCommands() {
        $providerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib/Microsoft.ActiveDirectory.Management.dll'
        $provider = Import-Module -Name $providerPath -Scope Local -PassThru -ErrorAction Stop
        $exports = $provider.ExportedCmdlets
        if ($null -eq $exports -or
            $exports['Get-ADObject'] -isnot [Management.Automation.CommandInfo] -or
            $exports['Disable-ADAccount'] -isnot [Management.Automation.CommandInfo]) {
            throw 'Bundled AD assembly does not provide the required Apply commands'
        }
        return @{
            Read = $exports['Get-ADObject']
            Disable = $exports['Disable-ADAccount']
        }
    }

    hidden [bool] IsReviewedServer([string]$ReviewedServer, [string]$Server) {
        return -not ($ReviewedServer -and $ReviewedServer -ine $Server)
    }

    hidden [object] SkippedAction([object]$ActionId, [object]$ObjectGuid) {
        return [pscustomobject]@{
            ActionId = $ActionId
            ObjectGuid = $ObjectGuid
            Status = 'Skipped'
            JournalPath = $null
        }
    }

    hidden [bool] IsCompletedAction([object]$Status) {
        return $Status -in 'Succeeded', 'Undone'
    }

    hidden [Collections.Specialized.OrderedDictionary] NewEntryHeader() {
        return [ordered]@{
            EntryId = [guid]::NewGuid().ToString('D')
        }
    }

    hidden [object] BuildEntry([Collections.Specialized.OrderedDictionary]$Header, [hashtable]$Fields) {
        $Header.ActionId = $Fields.ActionId
        $Header.Action = 'DisableAccount'
        $Header.ObjectGuid = $Fields.ObjectGuid
        $Header.SID = $Fields.SID
        $Header.DistinguishedName = $Fields.DistinguishedName
        $Header.ObjectClass = $Fields.ObjectClass
        $Header.AccountType = $Fields.AccountType
        $Header.InactivityDays = $Fields.InactivityDays
        $Header.Timestamp = [datetimeoffset]::UtcNow.ToString('o')
        $Header.Status = 'Rejected'
        $Header.Before = $null
        $Header.After = $null
        $Header.Message = $null
        $Header.Undo = $null
        return [pscustomobject]$Header
    }

    hidden [void] PrepareEntry([object]$Journal, [object]$Entry) {
        $Entry.Status = 'Prepared'
        $Journal.Entries = @($Journal.Entries) + @($Entry)
    }

    hidden [bool] IsVerifiedDisabled([object]$Before, [object]$After) {
        return -not (
            $After.ObjectGuid -ne $Before.ObjectGuid -or
            $After.SID -ne $Before.SID -or
            $After.DistinguishedName -ine $Before.DistinguishedName -or
            $After.Enabled -isnot [bool] -or
            $After.Enabled -or
            -not $After.WhenChanged
        )
    }

    hidden [void] CompleteEntry([object]$Entry) {
        $Entry.Status = 'Succeeded'
    }

    hidden [void] RecordApplyFailure([object]$Journal, [object]$Entry, [string]$Message, [bool]$Added) {
        if ($Entry.Status -ne 'Rejected') {
            $Entry.Status = 'Failed'
        }
        $Entry.Message = $Message
        if (-not $Added) {
            $Journal.Entries = @($Journal.Entries) + @($Entry)
        }
    }

    hidden [string] ApplyPersistenceFailure([string]$Original, [string]$Persistence) {
        return 'Journal persistence failed; no further changes were attempted. ' +
            'Inspect the durable journal before retrying. ' + $Original + '; ' + $Persistence
    }
}

function Invoke-ADAnalyzerRemediationPlan {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [Parameter(Mandatory)][string]$JournalPath

    )
    $planObject = Read-ADAnalyzerOperationDocument $Plan 'Plan'
    Assert-ADAnalyzerOperationPlan $planObject
    $JournalPath = Resolve-ADAnalyzerOperationFilePath $JournalPath
    $connection = Get-ADAnalyzerOperationConnection $Server $Credential
    $executor = [ADAnalyzerRemediationExecutor]::new()
    $reviewedServer = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $planObject @('Context')) @('Server'))
    if (-not $executor.IsReviewedServer($reviewedServer, $Server)) {
        throw 'Server differs from the DC recorded in the reviewed assessment'
    }
    $journal = $null
    $lease = $null
    try {
        foreach ($action in @($planObject.Actions)) {
            if ($null -eq $action) {
                continue
            }
            $objectGuid = $action.ObjectGuid
            $distinguishedName = $action.DistinguishedName
            if (-not $PSCmdlet.ShouldProcess($distinguishedName, 'Disable account from explicit reviewed plan')) {
                $skipped = @{
                    ActionId = $action.ActionId
                    ObjectGuid = $objectGuid
                }
                $executor.SkippedAction($skipped.ActionId, $skipped.ObjectGuid)
                continue
            }
            if ($null -eq $journal) {
                $lease = Enter-ADAnalyzerJournalLease $JournalPath
                $journal = Get-ADAnalyzerOperationJournal $planObject $Server $JournalPath
            }
            if (@($journal.Entries | Where-Object {
                        $_.ActionId -eq $action.ActionId -and $executor.IsCompletedAction($_.Status)
                    }).Count) {
                throw 'This plan action has already been applied; create a fresh assessment and plan'
            }
            $header = $executor.NewEntryHeader()
            $fields = @{
                ActionId = $action.ActionId
                ObjectGuid = $objectGuid
                SID = $action.SID
                DistinguishedName = $distinguishedName
                ObjectClass = $action.ObjectClass
                AccountType = $action.AccountType
                InactivityDays = $action.InactivityDays
            }
            $entry = $executor.BuildEntry($header, $fields)
            $account = [guid]$objectGuid
            $reservation = $executor.ReserveAccount($account, $false)
            $added = $false
            try {
                $current = Get-ADAnalyzerOperationCurrentObject $account $connection $planObject
                $entry.Before = Assert-ADAnalyzerOperationPreconditions $action.Preconditions $current $true
                Assert-ADAnalyzerOperationPrivilege $current $action $planObject $connection
                Assert-ADAnalyzerOperationInactivity $current $action
                $executor.PrepareEntry($journal, $entry)
                $added = $true
                # Durable intent precedes the mutation. A failed journal write aborts.
                Save-ADAnalyzerOperationJournal $journal $JournalPath
                $reservation.BeginDispatch()
                Disable-ADAccount -Identity $account @connection -WhatIf:$false -Confirm:$false
                $after = Get-ADAnalyzerOperationCurrentObject $account $connection $planObject
                $entry.After = Get-ADAnalyzerOperationState $after
                if (-not $executor.IsVerifiedDisabled($entry.Before, $entry.After)) {
                    throw 'Unable to verify the account disable result'
                }
                $executor.CompleteEntry($entry)
                Save-ADAnalyzerOperationJournal $journal $JournalPath
            }
            catch {
                $failure = $_
                $executor.RecordApplyFailure($journal, $entry, $failure.Exception.Message, $added)
                try {
                    Save-ADAnalyzerOperationJournal $journal $JournalPath
                }
                catch {
                    $message = $executor.ApplyPersistenceFailure($failure.Exception.Message, $_.Exception.Message)
                    throw $executor.NewReservationPersistenceFailure($reservation, $message)
                }
                $executor.ReleaseIfNotDispatched($reservation, $failure)
                throw $failure
            }
            $reservation.ReleaseAfterRecordedCompletion()
            ConvertTo-ADAnalyzerSafeData $entry
        }
    }
    finally {
        if ($null -ne $lease) {
            $lease.Dispose()
        }
    }
}

function Undo-ADAnalyzerRemediation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][string]$Server,
        [pscredential]$Credential = [pscredential]::Empty

    )
    $JournalPath = Resolve-ADAnalyzerOperationFilePath $JournalPath
    $journal = Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
    if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server) {
        throw 'Journal type/server does not match this undo request'
    }
    $connection = Get-ADAnalyzerOperationConnection $Server $Credential
    $executor = [ADAnalyzerRemediationExecutor]::new()
    $lease = $null
    try {
        foreach ($candidate in @($journal.Entries | Where-Object {
                    $executor.IsUndoAction($_.Action) -and $executor.IsUndoStatus($_.Status)
                })) {
            if (-not $PSCmdlet.ShouldProcess($candidate.DistinguishedName, 'Undo a journaled account disable')) {
                $executor.SkippedUndo($candidate.EntryId, $candidate.ObjectGuid)
                continue
            }
            if ($null -eq $lease) {
                $reviewedJournalId = [string](Get-ADAnalyzerOperationValue $journal @('JournalId'))
                $reviewedPlanId = [string](Get-ADAnalyzerOperationValue $journal @('PlanId'))
                $lease = Enter-ADAnalyzerJournalLease $JournalPath
                $journal = Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
                if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server) {
                    throw 'Journal type/server does not match this undo request'
                }
                $ownedJournalId = [string](Get-ADAnalyzerOperationValue $journal @('JournalId'))
                $ownedPlanId = [string](Get-ADAnalyzerOperationValue $journal @('PlanId'))
                if (-not $executor.IsSameUndoIdentity($reviewedJournalId, $ownedJournalId) -or
                    -not $executor.IsSameUndoIdentity($reviewedPlanId, $ownedPlanId)) {
                    throw 'Journal identity changed after undo review'
                }
                $plan = $executor.UndoPolicy(
                    $journal.Remediation, $journal.PrivilegedSids, $journal.AccountClassification
                )
            }
            $matching = @($journal.Entries | Where-Object { $_.EntryId -eq $candidate.EntryId })
            if (-not $candidate.EntryId -or $matching.Count -ne 1) {
                throw 'Journal entry identity is missing or ambiguous'
            }
            $entry = $matching[0]
            if ($entry.Action -ne 'DisableAccount' -or $entry.Status -ne 'Succeeded') {
                continue
            }
            foreach ($name in $executor.UndoIdentityFields()) {
                $reviewedValue = [string](Get-ADAnalyzerOperationValue $candidate @($name))
                $ownedValue = [string](Get-ADAnalyzerOperationValue $entry @($name))
                if (-not $executor.IsSameUndoIdentity($reviewedValue, $ownedValue)) {
                    throw 'Journal entry identity changed after undo review'
                }
            }
            $reservation = $null
            $admitting = $false
            try {
                if (-not $executor.IsReversibleDisable($entry)) {
                    throw 'Journal does not contain a reversible enabled-to-disabled transition'
                }
                $approved = @(foreach ($value in @($journal.Remediation.ApprovedObjectGuids)) {
                        ConvertTo-ADAnalyzerOperationGuid $value
                    })
                if (-not $executor.IsApprovedUndoEntry($entry, $approved)) {
                    throw 'Journal entry identity is not bound to an approved reversible action'
                }
                $account = [guid]$entry.ObjectGuid
                $admitting = $true
                $reservation = $executor.ReserveAccount($account, $true)
                $admitting = $false
                $current = Get-ADAnalyzerOperationCurrentObject $account $connection $plan
                $state = Assert-ADAnalyzerOperationPreconditions $entry.After $current $false
                Assert-ADAnalyzerOperationPrivilege $current $entry $plan $connection
                $executor.PrepareUndoEntry($entry, $state)
                Save-ADAnalyzerOperationJournal $journal $JournalPath
                $reservation.BeginDispatch()
                Enable-ADAccount -Identity $account @connection -WhatIf:$false -Confirm:$false
                $after = Get-ADAnalyzerOperationCurrentObject $account $connection $plan
                $entry.Undo.After = Get-ADAnalyzerOperationState $after
                if (-not $executor.IsVerifiedEnabled($entry.Before, $entry.Undo.After)) {
                    throw 'Unable to verify the account enable result'
                }
                $executor.CompleteUndoEntry($entry)
                Save-ADAnalyzerOperationJournal $journal $JournalPath
            }
            catch {
                if ($admitting) {
                    throw
                }
                $failure = $_
                $executor.RecordUndoFailure($entry, $failure.Exception.Message)
                try {
                    Save-ADAnalyzerOperationJournal $journal $JournalPath
                }
                catch {
                    $message = $executor.UndoPersistenceFailure($failure.Exception.Message, $_.Exception.Message)
                    throw $executor.NewReservationPersistenceFailure($reservation, $message)
                }
                $executor.ReleaseIfNotDispatched($reservation, $failure)
                throw $failure
            }
            $reservation.ReleaseAfterRecordedCompletion()
            ConvertTo-ADAnalyzerSafeData $entry
        }
    }
    finally {
        if ($null -ne $lease) {
            $lease.Dispose()
        }
    }
}
