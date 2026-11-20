class ADAnalyzerPrincipalGroupReader {
    ADAnalyzerPrincipalGroupReader() {
    }

    [object] Read([string]$Computer, [string]$Target) {
        return $this.Read($Computer, $Target, [pscredential]::Empty)
    }

    [object] Read([string]$Computer, [string]$Target, [pscredential]$Credential) {
        $ErrorActionPreference = 'Stop'
        if ($this.MissingTarget($Computer, $Target)) {
            throw 'Specify a computer and group target.'
        }

        $context = $null
        $principal = $null
        $snapshot = $null
        $failure = $null
        $cleanupErrors = [Collections.Generic.List[object]]::new()
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
            $principalContext = [type]'System.DirectoryServices.AccountManagement.PrincipalContext'
            $contextType = [type]'System.DirectoryServices.AccountManagement.ContextType'
            $groupPrincipal = [type]'System.DirectoryServices.AccountManagement.GroupPrincipal'
            $identityType = [type]'System.DirectoryServices.AccountManagement.IdentityType'
            if ($this.UsesCredential($Credential)) {
                $context = $principalContext::new(
                    $contextType::Machine, $Computer, $Credential.UserName, $Credential.GetNetworkCredential().Password
                )
            }
            else {
                $context = $principalContext::new($contextType::Machine, $Computer)
            }
            $principal = $groupPrincipal::FindByIdentity($context, $identityType::SamAccountName, $Target)
            if ($null -eq $principal) {
                throw 'The requested host group was not found.'
            }
            $metadata = @{}
            $principalType = $principal.GetType()
            foreach ($name in $this.MetadataFields()) {
                $property = $principalType.GetProperty($name)
                if ($null -eq $property) {
                    throw 'A required host group metadata getter is unavailable.'
                }
                $metadata[$name] = $property.GetValue($principal, $null)
            }
            $sid = $metadata.Sid
            $sidValue = if ($null -ne $sid) {
                [string]$sid.Value
            }
            else {
                $null
            }
            $snapshot = $this.Snapshot($Computer, $metadata, $sidValue)
        }
        catch {
            $failure = $_
        }
        finally {
            if ($null -ne $principal) {
                try {
                    $principal.Dispose()
                }
                catch {
                    $cleanupErrors.Add($_)
                }
            }
            if ($null -ne $context) {
                try {
                    $context.Dispose()
                }
                catch {
                    $cleanupErrors.Add($_)
                }
            }
        }
        if ($null -ne $failure) {
            if ($cleanupErrors.Count) {
                $this.RecordCleanup($failure.Exception, @($cleanupErrors | ForEach-Object { $_.Exception.Message }))
            }
            throw $failure
        }
        if ($cleanupErrors.Count) {
            $errorRecord = $cleanupErrors[0]
            if ($cleanupErrors.Count -gt 1) {
                $this.RecordCleanup(
                    $errorRecord.Exception,
                    @($cleanupErrors | Select-Object -Skip 1 | ForEach-Object { $_.Exception.Message })
                )
            }
            throw $errorRecord
        }
        return $snapshot
    }

    hidden [bool] MissingTarget([string]$Computer, [string]$Target) {
        return [string]::IsNullOrWhiteSpace($Computer) -or [string]::IsNullOrWhiteSpace($Target)
    }

    hidden [bool] UsesCredential([pscredential]$Credential) {
        return $null -ne $Credential -and $Credential -ne [pscredential]::Empty
    }

    hidden [string[]] MetadataFields() {
        return @('Name', 'SamAccountName', 'Sid', 'Description')
    }

    hidden [object] Snapshot([string]$Computer, [hashtable]$Metadata, [object]$Sid) {
        return [pscustomobject][ordered]@{
            Computer = $Computer
            Name = $Metadata.Name
            SamAccountName = $Metadata.SamAccountName
            SID = $Sid
            Description = $Metadata.Description
        }
    }

    hidden [void] RecordCleanup([Exception]$Primary, [object[]]$Messages) {
        $Primary.Data['ADAnalyzerCleanupErrors'] = $Messages
    }
}
