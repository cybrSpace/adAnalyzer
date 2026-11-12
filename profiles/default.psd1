@{
    SchemaVersion = 1
    Name = 'AD Tactical Hardening'
    Version = '1.0.0'
    # Omitted keys inherit validated defaults from Get-ADAnalyzerDefaultProfile.
    # Default collection has no mutations; ACL and host inventory are opt-in.
    Remediation = @{
        AllowDisable = $false
        ApprovedObjectGuids = @()
    }
}
