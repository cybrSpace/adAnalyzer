class ADAnalyzerHostScanState {
    ADAnalyzerHostScanState() {
    }

    [string] Format(
        [object]$Value,
        [Collections.IDictionary]$Rules,
        [object]$Limit,
        [Collections.IDictionary]$State
    ) {
        $message = $null
        $limits = @{
            limit = $Limit
        }
        $categories = [Collections.IDictionary].GetProperty('Keys').GetValue($Rules, $null)
        foreach ($category in $categories) {
            $rule = $Rules[$category]
            if ($this.Matches($Value, $rule['value'])) {
                if ($this.IsAttemptCategory($category) -and $this.RecordAttempt($State, $limits)) {
                    throw 'exceeded invalid attempt limit'
                }
                $message = $rule['msg']
            }
        }
        return $this.Render($Value, $message)
    }

    hidden [bool] Matches([object]$Value, [object]$Patterns) {
        $pattern = '({0})' -f ($Patterns -join '|')
        return [bool]($Value -match $pattern)
    }

    hidden [bool] IsAttemptCategory([string]$Category) {
        return $Category -in 'bad.user', 'locked'
    }

    hidden [bool] RecordAttempt([Collections.IDictionary]$State, [Collections.IDictionary]$Limits) {
        $syncRoot = [Collections.ICollection].GetProperty('SyncRoot').GetValue($State, $null)
        [Threading.Monitor]::Enter($syncRoot)
        try {
            $State['attempt']++
            return $State['attempt'] -ge $Limits['limit']
        }
        finally {
            [Threading.Monitor]::Exit($syncRoot)
        }
    }

    hidden [string] Render([object]$Value, [object]$Message) {
        if ([string]::IsNullOrEmpty($Message)) {
            $Message = '{0} ({1})' -f 'unknown exception', $Value
        }
        return '{0}({1})' -f 'server_exception', $Message
    }
}
