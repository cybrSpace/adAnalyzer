@{
    SchemaVersion = 1
    Name = 'Example environment - customize before use'
    Version = '1.0.0'
    Targets = @{Domain='example.invalid';Server='dc01.example.invalid';SearchBase='DC=example,DC=invalid'}
    AccountClassification = @{
        UserOUs = @('OU=People,DC=example,DC=invalid')
        ServiceOUs = @('OU=Services,DC=example,DC=invalid')
        # SIDs, OUs and explicit attributes identify roles; username spelling does not.
        UserGroups = @()
        ServiceGroups = @()
        AttributeRules = @()
    }
    Policy = @{
        MinimumPasswordLength=14
        LockoutThreshold=6
        LockoutDurationMinutes=30
        ResetLockoutMinutes=30
        PrivilegedSids=@()
        ApprovedLocalAdminSids=@('S-1-5-32-544')
        AllowedUserRightSids=@{}
        SupportedOperatingSystems=@()
    }
    RegistryRules = @(
        @{Id='EXAMPLE.SMB1';Hive='HKLM';Key='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';ValueName='SMB1';Operator='Equals';Expected=0;Type=4;Severity='High'}
    )
    Exceptions=@()
    Host=@{
        Services=@(@{Name='Spooler';State='Stopped';StartMode='Disabled'})
        RegistryRules=@()
        AuditRules=@(@{SubcategoryGuid='0cce9215-69ae-11d9-bed3-505054503030';Flags=3})
        CertificateEndpoints=@(@{HostName='dc01.example.invalid';Port=636;ServerName='dc01.example.invalid';MinimumRemainingDays=30})
    }
    Remediation=@{AllowDisable=$false;ApprovedObjectGuids=@();MaximumActions=10}
}
