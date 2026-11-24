function Get-ADAnalyzerAccountControlObservation {
    param(
        [object]$Value,
        [object]$Enabled,
        [object]$ExpirationFlag
    )

    if ($Value -isnot [ValueType] -or $Value -is [Enum] -or [type]::GetTypeCode($Value.GetType()) -notin @(
            [TypeCode]::SByte,
            [TypeCode]::Byte,
            [TypeCode]::Int16,
            [TypeCode]::UInt16,
            [TypeCode]::Int32,
            [TypeCode]::UInt32,
            [TypeCode]::Int64,
            [TypeCode]::UInt64
        ) -or [decimal]$Value -lt 0 -or [decimal]$Value -gt [uint32]::MaxValue) {
        return $null
    }

    $flags = [uint32]$Value
    $observedEnabled = ($flags -band 0x0002) -eq 0
    $observedNeverExpires = ($flags -band 0x10000) -ne 0
    return [pscustomobject]@{
        Flags = $Value
        Enabled = $observedEnabled
        PasswordNeverExpires = $observedNeverExpires
        Consistent = (-not ($Enabled -is [bool] -and $Enabled -ne $observedEnabled) -and
            -not ($ExpirationFlag -is [bool] -and $ExpirationFlag -ne $observedNeverExpires))
    }
}

function ConvertTo-ADAnalyzerDirectorySubjectGuid {
    param([object]$Value)

    if ($Value -is [guid]) {
        return $Value
    }
    $identity = [guid]::Empty
    if ($Value -is [string] -and [guid]::TryParseExact($Value, 'D', [ref]$identity)) {
        return $identity
    }
    return [guid]::Empty
}

function Test-ADAnalyzerDirectorySubjectInScope {
    param([string]$Dn, [string]$Scope)

    if ($Dn.Equals($Scope, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $suffix = ',' + $Scope
    if (-not $Dn.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    # The boundary comma must not be part of an escaped RDN value.
    $escapes = 0
    $index = $Dn.Length - $suffix.Length - 1
    while ($index -ge 0 -and $Dn[$index] -eq [char]92) {
        $escapes++
        $index--
    }
    return ($escapes % 2 -eq 0)
}
