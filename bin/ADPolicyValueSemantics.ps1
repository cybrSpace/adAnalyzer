# Shared read-only policy value semantics.
function Get-ADAnalyzerPolicyValue {
    param(
        $Object,
        [string]$Name,
        $Default = $null

    )
    if ($null -eq $Object) {
        return $Default
    }
    if ($Object -is [Collections.IDictionary]) {
        if (([Collections.IDictionary]$Object).Contains($Name)) {
            return $Object[$Name]
        }
    }
    elseif ($null -ne $Object.PSObject.Properties[$Name]) {
        return $Object.$Name
    }
    return $Default
}

class ADAnalyzerPolicyValueSemantics {
    ADAnalyzerPolicyValueSemantics() {
    }

    [bool] IsValueValid([object]$Record) {
        $marker = Get-ADAnalyzerPolicyValue $Record ValueValid $null
        return $this.AcceptValidityMarker($marker)
    }

    hidden [bool] AcceptValidityMarker([object]$Marker) {
        return $null -eq $Marker -or ($Marker -is [bool] -and $Marker)
    }

    [pscustomobject] ParseNumber([object]$Value) {
        if (-not $this.CanParseNumber($Value)) {
            return $this.MakeResult(@{
                Valid = $false
                Value = $null
            })
        }

        $number = 0L
        $valid = $this.ParseNumberText([string]$Value, [ref]$number)
        return $this.MakeResult(@{
            Valid = $valid
            Value = $number
        })
    }

    hidden [bool] CanParseNumber([object]$Value) {
        return $Value -isnot [bool] -and $Value -isnot [array] -and $null -ne $Value
    }

    hidden [bool] ParseNumberText([string]$Text, [ref]$Number) {
        return [long]::TryParse($Text,
            [Globalization.NumberStyles]::Integer,
            [Globalization.CultureInfo]::InvariantCulture,
            $Number)
    }

    [pscustomobject] ParseBoolean([object]$Value) {
        if ($this.IsBoolean($Value)) {
            return $this.MakeResult(@{
                Valid = $true
                Value = $Value
            })
        }
        if ($this.CanParseBooleanText($Value)) {
            return $this.ParseBooleanText([string]$Value)
        }
        return $this.MakeResult(@{
            Valid = $false
            Value = $null
        })
    }

    hidden [bool] IsBoolean([object]$Value) {
        return $Value -is [bool]
    }

    hidden [bool] CanParseBooleanText([object]$Value) {
        return $null -ne $Value -and $Value -isnot [array]
    }

    hidden [pscustomobject] ParseBooleanText([string]$Text) {
        switch -Regex ($Text) {
            '^(?i:true|1)$' {
                return $this.MakeResult(@{
                    Valid = $true
                    Value = $true
                })
            }
            '^(?i:false|0)$' {
                return $this.MakeResult(@{
                    Valid = $true
                    Value = $false
                })
            }
        }
        return $this.MakeResult(@{
            Valid = $false
            Value = $null
        })
    }

    hidden [pscustomobject] MakeResult([hashtable]$Observation) {
        return [pscustomobject]@{
            Valid = $Observation.Valid
            Value = $Observation.Value
        }
    }

    [bool] IsSid([object]$Value) {
        # MS-DTYP 2.4.2.1: decimal authority below 2^32, otherwise 12 hex digits.
        if ($Value -isnot [string] -or $Value -notmatch '^S-1-(?:0|[1-9][0-9]{0,9}|0x[0-9a-f]{12})(?:-(?:0|[1-9][0-9]{0,9})){1,15}$') {
            return $false
        }
        $parts = $Value.Split('-')
        [uint64]$authority = 0
        if ($parts[2].StartsWith('0x', [StringComparison]::OrdinalIgnoreCase)) {
            if (-not [uint64]::TryParse($parts[2].Substring(2),
                    [Globalization.NumberStyles]::AllowHexSpecifier,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [ref]$authority) -or
                $authority -lt 4294967296) {
                return $false
            }
        }
        elseif (-not [uint64]::TryParse($parts[2], [ref]$authority) -or $authority -gt 4294967295) {
            return $false
        }
        for ($index = 3; $index -lt $parts.Count; $index++) {
            [uint32]$part = 0
            if (-not [uint32]::TryParse($parts[$index], [ref]$part)) {
                return $false
            }
        }
        return $true
    }

    [bool] IsSidList([object]$Value) {
        if (-not $this.CanValidateSidList($Value)) {
            return $false
        }
        foreach ($sid in $Value) {
            if (-not $this.IsSid($sid)) {
                return $false
            }
        }
        return $true
    }

    hidden [bool] CanValidateSidList([object]$Value) {
        return $null -ne $Value -and ($Value -is [string] -or $Value -is [Collections.IList])
    }

    [pscustomobject] ParsePrincipal([string]$Value) {
        if ($null -eq $Value) {
            $Value = ''
        }
        $token = $Value.Trim()
        $marked = $token.StartsWith('*')
        if ($marked) {
            $token = $token.Substring(1)
        }
        $sid = $null
        $valid = -not [string]::IsNullOrWhiteSpace($token)
        if ($this.IsSid($token)) {
            $sid = $token
        }
        elseif ($marked -or $token -match '^S-\d') {
            $valid = $false
        }
        return [pscustomobject]@{
            Sid = $sid
            Name = $(if (-not $sid) {
                    $token
                }
                else {
                    $null
                })
            Valid = $valid
        }
    }

    [bool] Compare([object]$Observed, [object]$Expected) {
        return $this.Compare($Observed, $Expected, 'Equals')
    }

    [bool] Compare([object]$Observed, [object]$Expected, [string]$Operator) {
        $ErrorActionPreference = 'Stop'
        $kind = $this.ResolveOperator($Operator)
        switch ($kind) {
            { $_ -in 'Equals', 'NotEquals' } {
                $left = @($Observed)
                $right = @($Expected)
                $comparison = $this.PrepareEquality($left, $right)
                $differences = 0
                if ($comparison.CompareMembers) {
                    $differences = @(Compare-Object -ReferenceObject $left -DifferenceObject $right).Count
                }
                return $this.FinishEquality($kind, $comparison.CountsMatch, $differences)
            }
            { $_ -in 'In', 'NotIn' } {
                return $this.CompareMembership($kind, @{
                    Observed = $Observed
                    Expected = $Expected
                })
            }
            { $_ -in 'Minimum', 'Maximum' } {
                $number = $this.ParseNumber($Observed)
                if (-not $this.HasNumericValue($number)) {
                    throw 'A numeric value is required'
                }
                return $this.CompareBound($kind, $number.Value, [long]$Expected)
            }
            default {
                throw 'Unsupported comparison operator'
            }
        }
        return $false
    }

    hidden [string] ResolveOperator([string]$Operator) {
        switch ($Operator) {
            { $_ -in 'Equals', 'Equal', 'eq' } {
                return 'Equals'
            }
            { $_ -in 'NotEquals', 'ne' } {
                return 'NotEquals'
            }
            'In' {
                return 'In'
            }
            'NotIn' {
                return 'NotIn'
            }
            { $_ -in 'Minimum', 'AtLeast', 'ge' } {
                return 'Minimum'
            }
            { $_ -in 'Maximum', 'AtMost', 'le' } {
                return 'Maximum'
            }
            default {
                return 'Unsupported'
            }
        }
        return 'Unsupported'
    }

    hidden [hashtable] PrepareEquality([object[]]$Left, [object[]]$Right) {
        $countsMatch = $Left.Count -eq $Right.Count
        return @{
            CountsMatch = $countsMatch
            CompareMembers = $countsMatch -and $Left.Count
        }
    }

    hidden [bool] FinishEquality([string]$Kind, [bool]$CountsMatch, [int]$Differences) {
        $equal = $CountsMatch -and $Differences -eq 0
        if ($Kind -eq 'NotEquals') {
            return -not $equal
        }
        return $equal
    }

    hidden [bool] CompareMembership([string]$Kind, [hashtable]$Inputs) {
        if ($Kind -eq 'NotIn') {
            return @($Inputs.Expected) -notcontains $Inputs.Observed
        }
        return @($Inputs.Expected) -contains $Inputs.Observed
    }

    hidden [bool] HasNumericValue([pscustomobject]$Number) {
        return [bool]$Number.Valid
    }

    hidden [bool] CompareBound([string]$Kind, [long]$Observed, [long]$Expected) {
        if ($Kind -eq 'Minimum') {
            return $Observed -ge $Expected
        }
        return $Observed -le $Expected
    }
}

# A factory keeps the shared type available to dot-sourced class methods at runtime.
function New-ADAnalyzerPolicyValueSemantics {
    return [ADAnalyzerPolicyValueSemantics]::new()
}
