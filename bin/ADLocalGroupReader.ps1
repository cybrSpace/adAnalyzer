class ADAnalyzerLocalGroupReader {
    ADAnalyzerLocalGroupReader() {
    }

    [object[]] Read([string[]]$ComputerName) {
        return $this.Read($ComputerName, [pscredential]::Empty, $false)
    }

    [object[]] Read([string[]]$ComputerName, [pscredential]$Credential) {
        return $this.Read($ComputerName, $Credential, $false)
    }

    [object[]] Read([string[]]$ComputerName, [pscredential]$Credential, [bool]$IncludeName) {
        $ErrorActionPreference = 'Stop'
        if ($null -eq $ComputerName -or -not $ComputerName.Count) {
            throw 'Specify at least one computer.'
        }

        $computers = [string[]]$ComputerName.Clone()
        foreach ($computer in $computers) {
            if ($this.IsBlankComputer($computer)) {
                throw 'Computer names must be nonempty strings.'
            }
        }

        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $principalContext = [type]'System.DirectoryServices.AccountManagement.PrincipalContext'
        $contextType = [type]'System.DirectoryServices.AccountManagement.ContextType'
        $groupPrincipal = [type]'System.DirectoryServices.AccountManagement.GroupPrincipal'
        $identityType = [type]'System.DirectoryServices.AccountManagement.IdentityType'
        $framework = @{
            PrincipalContext = $principalContext
            Machine = $contextType::Machine
            GroupPrincipal = $groupPrincipal
            Sid = $identityType::Sid
            GetEnumerator = [Collections.IEnumerable].GetMethod('GetEnumerator')
            MoveNext = [Collections.IEnumerator].GetMethod('MoveNext')
            Current = [Collections.IEnumerator].GetProperty('Current')
            Dispose = [IDisposable].GetMethod('Dispose')
        }

        $rows = [Collections.Generic.List[object]]::new()
        foreach ($computer in $computers) {
            $rows.AddRange($this.ReadHost($computer, $Credential, $IncludeName, $framework))
        }
        return $rows.ToArray()
    }

    hidden [object[]] ReadHost(
        [string]$Computer,
        [pscredential]$Credential,
        [bool]$IncludeName,
        [hashtable]$Framework
    ) {
        $context = $null
        $group = $null
        $result = $null
        $enumerator = $null
        $failure = $null
        $rows = [Collections.Generic.List[object]]::new()
        $cleanupErrors = [Collections.Generic.List[object]]::new()
        try {
            $principalContext = $Framework.PrincipalContext
            if ($this.UsesCredential($Credential)) {
                $context = $principalContext::new(
                    $Framework.Machine,
                    $Computer,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
            }
            else {
                $context = $principalContext::new($Framework.Machine, $Computer)
            }

            $groupPrincipal = $Framework.GroupPrincipal
            $group = $groupPrincipal::FindByIdentity($context, $Framework.Sid, 'S-1-5-32-544')
            if ($null -eq $group) {
                throw 'The local Administrators group was not found.'
            }

            $result = $group.GetMembers($false)
            if ($null -eq $result) {
                throw 'The group membership result is unavailable.'
            }

            $enumerator = $Framework.GetEnumerator.Invoke($result, $null)
            if ($null -eq $enumerator) {
                throw 'The group membership enumerator is unavailable.'
            }

            while ([bool]$Framework.MoveNext.Invoke($enumerator, $null)) {
                $member = $null
                try {
                    $member = $Framework.Current.GetValue($enumerator, $null)
                    if ($null -eq $member) {
                        throw 'A group membership record is unavailable.'
                    }
                    $rows.Add($this.ProjectMember($Computer, $member, $IncludeName))
                }
                finally {
                    if ($null -ne $member) {
                        $this.DisposeResource($Framework.Dispose, $member, $cleanupErrors)
                    }
                }
                if ($cleanupErrors.Count) {
                    break
                }
            }
        }
        catch {
            $failure = $_
        }
        finally {
            if ($enumerator -is [IDisposable]) {
                $this.DisposeResource($Framework.Dispose, $enumerator, $cleanupErrors)
            }
            foreach ($resource in @($result, $group, $context)) {
                if ($null -ne $resource) {
                    $this.DisposeResource($Framework.Dispose, $resource, $cleanupErrors)
                }
            }
        }

        if ($null -ne $failure) {
            $this.RecordCleanup($failure, $cleanupErrors, 0)
            throw $failure
        }
        if ($cleanupErrors.Count) {
            $failure = $cleanupErrors[0]
            $this.RecordCleanup($failure, $cleanupErrors, 1)
            throw $failure
        }
        return $rows.ToArray()
    }

    hidden [object] ProjectMember([string]$Computer, [object]$Member, [bool]$IncludeName) {
        $memberType = $Member.GetType()
        $contextProperty = $memberType.GetProperty('Context')
        $samProperty = $memberType.GetProperty('SamAccountName')
        if ($null -eq $contextProperty -or $null -eq $samProperty) {
            throw 'A required member metadata getter is unavailable.'
        }

        $memberContext = $contextProperty.GetValue($Member, $null)
        $domain = $null
        if ($null -ne $memberContext) {
            $nameProperty = $memberContext.GetType().GetProperty('Name')
            if ($null -eq $nameProperty) {
                throw 'The member context name getter is unavailable.'
            }
            $domain = $nameProperty.GetValue($memberContext, $null)
        }

        $sam = $samProperty.GetValue($Member, $null)
        $row = $this.NewRow($Computer, $domain, $sam)
        if ($IncludeName) {
            $memberNameProperty = $memberType.GetProperty('Name')
            if ($null -eq $memberNameProperty) {
                throw 'The member name getter is unavailable.'
            }
            $memberName = $memberNameProperty.GetValue($Member, $null)
            if ($this.IsMissingMemberName($memberName)) {
                throw 'The member name is unavailable.'
            }
            $row.Name = $memberName
        }
        return [pscustomobject]$row
    }

    hidden [void] DisposeResource(
        [Reflection.MethodInfo]$Dispose,
        [object]$Resource,
        [Collections.Generic.List[object]]$Errors
    ) {
        try {
            $null = $Dispose.Invoke($Resource, $null)
        }
        catch {
            $Errors.Add($_)
        }
    }

    hidden [void] RecordCleanup(
        [Management.Automation.ErrorRecord]$Primary,
        [Collections.Generic.List[object]]$Errors,
        [int]$Start
    ) {
        if ($Start -lt $Errors.Count) {
            $messages = [Collections.Generic.List[object]]::new()
            for ($index = $Start; $index -lt $Errors.Count; $index++) {
                $messages.Add($Errors[$index].Exception.Message)
            }
            $Primary.Exception.Data['ADAnalyzerCleanupErrors'] = $messages.ToArray()
        }
    }

    hidden [bool] IsBlankComputer([string]$Computer) {
        return [string]::IsNullOrWhiteSpace($Computer)
    }

    hidden [bool] UsesCredential([pscredential]$Credential) {
        return $null -ne $Credential -and $Credential -ne [pscredential]::Empty
    }

    hidden [bool] IsMissingMemberName([object]$Name) {
        return [string]::IsNullOrEmpty([string]$Name)
    }

    hidden [Collections.Specialized.OrderedDictionary] NewRow(
        [string]$Computer,
        [object]$Domain,
        [object]$Sam
    ) {
        return [ordered]@{
            Computer = $Computer
            Domain = $Domain
            samaccountname = $Sam
        }
    }
}
