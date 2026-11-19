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
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content

    )
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

function New-ADAnalyzerRemediationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Assessment,
        [AllowNull()]$Profile

    )
    $assessmentObject = Read-ADAnalyzerOperationDocument $Assessment
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $settings = $configuration.Remediation
    $data = Get-ADAnalyzerOperationValue $assessmentObject @('Data')
    $directory = Get-ADAnalyzerOperationValue $data @('Directory')
    $domain = Get-ADAnalyzerOperationValue $directory @('Domain')
    $domainSid = [string](Get-ADAnalyzerOperationValue $domain @('SID', 'DomainSID'))
    $rootDomainSid = [string](Get-ADAnalyzerOperationValue $domain @('RootDomainSID'))
    $privilegeContextMissing = $false
    $privileged = @(Get-ADAnalyzerOperationValue $domain @('PrivilegedSids') @() | Where-Object { $null -ne $_ })
    foreach ($sid in @($configuration.Policy.PrivilegedSids)) {
        if (([string]$sid).Contains('{DomainSid}') -and -not $domainSid) {
            $privilegeContextMissing = $true
        }
        if (([string]$sid).Contains('{RootDomainSid}') -and -not $rootDomainSid) {
            $privilegeContextMissing = $true
        }
        $expanded = ([string]$sid).Replace('{DomainSid}', $domainSid).Replace('{RootDomainSid}', $rootDomainSid)
        if ($expanded -and $expanded -match '^S-\d-') {
            $privileged += , $expanded
        }
    }
    $objects = @{}
    foreach ($object in @(Get-ADAnalyzerOperationValue $assessmentObject @('Objects') @())) {
        if ($null -eq $object) {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $object @('ObjectGuid'))
        if ($guid) {
            $objects[$guid] = $object
        }
    }
    $approved = @(foreach ($value in @($settings.ApprovedObjectGuids)) {
            ConvertTo-ADAnalyzerOperationGuid $value
        })
    $actions = [Collections.ArrayList]::new()
    $excluded = [Collections.ArrayList]::new()
    $seen = @{}
    foreach ($finding in @(Get-ADAnalyzerOperationValue $assessmentObject @('Findings') @())) {
        if ($null -eq $finding) {
            continue
        }
        $rule = [string](Get-ADAnalyzerOperationValue $finding @('RuleId'))
        if ($rule -notin @('ACCOUNT.INACTIVE',
                'COMPUTER.INACTIVE') -or
            [string](Get-ADAnalyzerOperationValue $finding @('Status')) -ne 'Fail') {
            continue
        }
        $guid = ConvertTo-ADAnalyzerOperationGuid (Get-ADAnalyzerOperationValue $finding @('ObjectGuid'))
        $reason = $null
        if (-not $settings.AllowDisable) {
            $reason = 'RemediationDisabled'
        }
        elseif ($privilegeContextMissing) {
            $reason = 'PrivilegedPolicyContextMissing'
        }
        elseif ([bool](Get-ADAnalyzerOperationValue $finding @('Suppressed') $false)) {
            $reason = 'SuppressedFinding'
        }
        elseif (-not $guid -or -not $objects.ContainsKey($guid)) {
            $reason = 'MissingObjectEvidence'
        }
        elseif ($guid -notin $approved) {
            $reason = 'ObjectNotExplicitlyApproved'
        }
        elseif (($rule -eq 'ACCOUNT.INACTIVE' -and
                (Get-ADAnalyzerOperationKind $objects[$guid]) -ne 'User') -or
            ($rule -eq 'COMPUTER.INACTIVE' -and
            (Get-ADAnalyzerOperationKind $objects[$guid]) -ne 'Computer')) {
            $reason = 'RuleObjectClassMismatch'
        }
        else {
            $reason = Get-ADAnalyzerOperationExclusion $objects[$guid] $settings
        }
        if (-not $reason -and $actions.Count -ge $settings.MaximumActions) {
            $reason = 'MaximumActionsReached'
        }
        if ($reason) {
            $null = $excluded.Add([pscustomobject]@{
                    RuleId = $rule
                    ObjectGuid = $guid
                    Target = Get-ADAnalyzerOperationValue $finding @('Target')
                    Reason = $reason
                })
            continue
        }
        if ($seen.ContainsKey($guid)) {
            continue
        }
        $seen[$guid] = $true
        $object = $objects[$guid]
        $state = Get-ADAnalyzerOperationState $object
        $null = $actions.Add([pscustomobject][ordered]@{
                ActionId = [guid]::NewGuid().ToString('D')
                Action = 'DisableAccount'
                RuleId = $rule
                ObjectGuid = $state.ObjectGuid
                SID = $state.SID
                DistinguishedName = $state.DistinguishedName
                ObjectClass = Get-ADAnalyzerOperationKind $object
                AccountType = Get-ADAnalyzerOperationValue $object @('AccountType')
                InactivityDays = $(if ((Get-ADAnalyzerOperationKind $object) -eq 'Computer') {
                        $configuration.Policy.ComputerInactivityDays
                    }
                    else {
                        $configuration.Policy.UserInactivityDays
                    })
                Preconditions = $state
            })
    }
    $plan = [pscustomobject][ordered]@{
        SchemaVersion = 1
        PlanType = 'ADAnalyzerRemediationPlan'
        PlanId = [guid]::NewGuid().ToString('D')
        CreatedAt = [datetimeoffset]::UtcNow.ToString('o')
        AssessmentRunId = Get-ADAnalyzerOperationValue $assessmentObject @('RunId')
        Target = Get-ADAnalyzerOperationValue $assessmentObject @('Target')
        Context = ConvertTo-ADAnalyzerSafeData (Get-ADAnalyzerOperationValue $assessmentObject @('Context'))
        Remediation = ConvertTo-ADAnalyzerSafeData $settings
        AccountClassification = ConvertTo-ADAnalyzerSafeData $configuration.AccountClassification
        PrivilegedSids = @($privileged | Select-Object -Unique)
        Actions = $actions.ToArray()
        Excluded = $excluded.ToArray()
    }
    $projector = [ADAnalyzerEvidenceProjector]::new()
    $plan.AssessmentRunId = $projector.ProjectIdentityMetadata($plan.AssessmentRunId)
    $plan.Target = $projector.ProjectIdentityMetadata($plan.Target)
    foreach ($item in $plan.Excluded) {
        $item.Target = $projector.ProjectIdentityMetadata($item.Target)
    }
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
        $Plan

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

function Enter-ADAnalyzerJournalLease {
    param([Parameter(Mandatory)][string]$Path)
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
        return [IO.File]::Open(($full + '.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch {
        throw [IO.IOException]::new(('Unable to acquire journal lock for ' + $full + '. Another run may be active or the filesystem may be unavailable.'),
            $_.Exception)
    }
}

function Get-ADAnalyzerOperationJournal {
    param(
        $Plan,
        [string]$Server,
        [string]$Path

    )
    if (Test-Path -LiteralPath $Path) {
        if (Test-Path -LiteralPath $Path -PathType Container) {
            throw 'JournalPath must name a file'
        }
        $journal = Read-ADAnalyzerOperationDocument $Path 'Journal'
        if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.PlanId -ne $Plan.PlanId -or $journal.Server -ine $Server) {
            throw 'Existing journal belongs to a different plan or server'
        }
        return $journal
    }
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        JournalType = 'ADAnalyzerRemediationJournal'
        JournalId = [guid]::NewGuid().ToString('D')
        PlanId = $Plan.PlanId
        Server = $Server
        CreatedAt = [datetimeoffset]::UtcNow.ToString('o')
        UpdatedAt = $null
        Remediation = ConvertTo-ADAnalyzerSafeData $Plan.Remediation
        PrivilegedSids = @($Plan.PrivilegedSids)
        AccountClassification = ConvertTo-ADAnalyzerSafeData $Plan.AccountClassification
        Entries = @()
    }
}

function Save-ADAnalyzerOperationJournal {
    param(
        $Journal,
        [string]$Path

    )
    $Journal.UpdatedAt = [datetimeoffset]::UtcNow.ToString('o')
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
    $reviewedServer = [string](Get-ADAnalyzerOperationValue (Get-ADAnalyzerOperationValue $planObject @('Context')) @('Server'))
    if ($reviewedServer -and $reviewedServer -ine $Server) {
        throw 'Server differs from the DC recorded in the reviewed assessment'
    }
    $journal = $null
    $lease = $null
    try {
        foreach ($action in @($planObject.Actions)) {
            if ($null -eq $action) {
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($action.DistinguishedName, 'Disable account from explicit reviewed plan')) {
                [pscustomobject]@{
                    ActionId = $action.ActionId
                    ObjectGuid = $action.ObjectGuid
                    Status = 'Skipped'
                    JournalPath = $null
                }
                continue
            }
            if ($null -eq $journal) {
                $lease = Enter-ADAnalyzerJournalLease $JournalPath
                $journal = Get-ADAnalyzerOperationJournal $planObject $Server $JournalPath
            }
            if (@($journal.Entries | Where-Object { $_.ActionId -eq $action.ActionId -and $_.Status -in @('Succeeded', 'Undone') }).Count) {
                throw 'This plan action has already been applied; create a fresh assessment and plan'
            }
            $entry = [pscustomobject][ordered]@{
                EntryId = [guid]::NewGuid().ToString('D')
                ActionId = $action.ActionId
                Action = 'DisableAccount'
                ObjectGuid = $action.ObjectGuid
                SID = $action.SID
                DistinguishedName = $action.DistinguishedName
                ObjectClass = $action.ObjectClass
                AccountType = $action.AccountType
                InactivityDays = $action.InactivityDays
                Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                Status = 'Rejected'
                Before = $null
                After = $null
                Message = $null
                Undo = $null
            }
            $added = $false
            try {
                $current = Get-ADAnalyzerOperationCurrentObject $action.ObjectGuid $connection $planObject
                $entry.Before = Assert-ADAnalyzerOperationPreconditions $action.Preconditions $current $true
                Assert-ADAnalyzerOperationPrivilege $current $action $planObject $connection
                Assert-ADAnalyzerOperationInactivity $current $action
                $entry.Status = 'Prepared'
                $journal.Entries = @($journal.Entries) + @($entry)
                $added = $true
                # Durable intent precedes the mutation. A failed journal write aborts.
                Save-ADAnalyzerOperationJournal $journal $JournalPath
                Disable-ADAccount -Identity ([guid]$action.ObjectGuid) @connection -WhatIf:$false -Confirm:$false
                $after = Get-ADAnalyzerOperationCurrentObject $action.ObjectGuid $connection $planObject
                $entry.After = Get-ADAnalyzerOperationState $after
                if ($entry.After.ObjectGuid -ne $entry.Before.ObjectGuid -or
                    $entry.After.SID -ne $entry.Before.SID -or
                    $entry.After.DistinguishedName -ine $entry.Before.DistinguishedName -or
                    $entry.After.Enabled -isnot [bool] -or
                    $entry.After.Enabled -or
                    -not $entry.After.WhenChanged) {
                    throw 'Unable to verify the account disable result'
                }
                $entry.Status = 'Succeeded'
                Save-ADAnalyzerOperationJournal $journal $JournalPath
            }
            catch {
                $failure = $_
                $entry.Status = if ($entry.Status -eq 'Rejected') {
                    'Rejected'
                }
                else {
                    'Failed'
                }
                $entry.Message = $failure.Exception.Message
                if (-not $added) {
                    $journal.Entries = @($journal.Entries) + @($entry)
                }
                try {
                    Save-ADAnalyzerOperationJournal $journal $JournalPath
                }
                catch {
                    throw ('Journal persistence failed; no further changes were attempted. Inspect the durable journal before retrying. ' + $failure.Exception.Message + '; ' + $_.Exception.Message)
                }
                throw $failure
            }
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
    $lease = $null
    try {
        foreach ($candidate in @($journal.Entries | Where-Object { $_.Action -eq 'DisableAccount' -and $_.Status -eq 'Succeeded' })) {
            if (-not $PSCmdlet.ShouldProcess($candidate.DistinguishedName, 'Undo a journaled account disable')) {
                [pscustomobject]@{
                    EntryId = $candidate.EntryId
                    ObjectGuid = $candidate.ObjectGuid
                    Status = 'Skipped'
                }
                continue
            }
            if ($null -eq $lease) {
                $lease = Enter-ADAnalyzerJournalLease $JournalPath
                $journal = Read-ADAnalyzerOperationDocument $JournalPath 'Journal'
                if ($journal.JournalType -ne 'ADAnalyzerRemediationJournal' -or $journal.Server -ine $Server) {
                    throw 'Journal type/server does not match this undo request'
                }
                $plan = [pscustomobject]@{
                    Remediation = $journal.Remediation
                    PrivilegedSids = $journal.PrivilegedSids
                    AccountClassification = $journal.AccountClassification
                }
            }
            $matching = @($journal.Entries | Where-Object { $_.EntryId -eq $candidate.EntryId })
            if (-not $candidate.EntryId -or $matching.Count -ne 1) {
                throw 'Journal entry identity is missing or ambiguous'
            }
            $entry = $matching[0]
            if ($entry.Action -ne 'DisableAccount' -or $entry.Status -ne 'Succeeded') {
                continue
            }
            try {
                if ($entry.Before.Enabled -ne $true -or $entry.After.Enabled -ne $false) {
                    throw 'Journal does not contain a reversible enabled-to-disabled transition'
                }
                $approved = @(foreach ($value in @($journal.Remediation.ApprovedObjectGuids)) {
                        ConvertTo-ADAnalyzerOperationGuid $value
                    })
                if ($entry.ObjectGuid -notin $approved -or
                    $entry.ObjectGuid -ne $entry.Before.ObjectGuid -or
                    $entry.ObjectGuid -ne $entry.After.ObjectGuid -or
                    $entry.SID -ne $entry.Before.SID -or
                    $entry.SID -ne $entry.After.SID) {
                    throw 'Journal entry identity is not bound to an approved reversible action'
                }
                $current = Get-ADAnalyzerOperationCurrentObject $entry.ObjectGuid $connection $plan
                $state = Assert-ADAnalyzerOperationPreconditions $entry.After $current $false
                Assert-ADAnalyzerOperationPrivilege $current $entry $plan $connection
                $entry.Undo = [pscustomobject]@{
                    Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                    Status = 'Prepared'
                    Before = $state
                    After = $null
                    Message = $null
                }
                Save-ADAnalyzerOperationJournal $journal $JournalPath
                Enable-ADAccount -Identity ([guid]$entry.ObjectGuid) @connection -WhatIf:$false -Confirm:$false
                $after = Get-ADAnalyzerOperationCurrentObject $entry.ObjectGuid $connection $plan
                $entry.Undo.After = Get-ADAnalyzerOperationState $after
                if ($entry.Undo.After.ObjectGuid -ne $entry.Before.ObjectGuid -or
                    $entry.Undo.After.SID -ne $entry.Before.SID -or
                    $entry.Undo.After.DistinguishedName -ine $entry.Before.DistinguishedName -or
                    $entry.Undo.After.Enabled -isnot [bool] -or
                    -not $entry.Undo.After.Enabled) {
                    throw 'Unable to verify the account enable result'
                }
                $entry.Undo.Status = 'Succeeded'
                $entry.Status = 'Undone'
                Save-ADAnalyzerOperationJournal $journal $JournalPath
            }
            catch {
                $failure = $_
                if ($entry.Undo) {
                    $entry.Undo.Status = 'Failed'
                    $entry.Undo.Message = $failure.Exception.Message
                }
                else {
                    $entry.Undo = [pscustomobject]@{
                        Timestamp = [datetimeoffset]::UtcNow.ToString('o')
                        Status = 'Rejected'
                        Before = $null
                        After = $null
                        Message = $failure.Exception.Message
                    }
                }
                try {
                    Save-ADAnalyzerOperationJournal $journal $JournalPath
                }
                catch {
                    throw ('Undo journal persistence failed; no further changes were attempted. ' + $failure.Exception.Message + '; ' + $_.Exception.Message)
                }
                throw $failure
            }
            ConvertTo-ADAnalyzerSafeData $entry
        }
    }
    finally {
        if ($null -ne $lease) {
            $lease.Dispose()
        }
    }
}
