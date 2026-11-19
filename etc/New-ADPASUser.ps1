[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Alias('CsvPath')][string]$CliCsvPath,
    [Alias('Server')][string]$CliServer,
    [Alias('Credential')][pscredential]$CliCredential = [pscredential]::Empty
)

class ADAnalyzerPasUserImporter {
    ADAnalyzerPasUserImporter() {
    }

    [object] Preview([string]$CsvPath) {
        return $this.Preview($CsvPath, @{})
    }

    [object] Preview([string]$CsvPath, [hashtable]$Options) {
        $ErrorActionPreference = 'Stop'
        $connection = $this.ReadOptions($Options)
        $server = [string]$connection['Server']
        $path = $this.ResolveCsv($CsvPath)
        $rows = @(Import-Csv -LiteralPath $path -ErrorAction Stop)
        $this.ValidateUsernames($rows)
        if (-not $rows.Count) {
            return $this.SealPlan($path, $server, '', @())
        }

        $repository = Split-Path -Parent $PSScriptRoot
        $modulePath = Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll'
        $modules = @(Import-Module -Name $modulePath -Scope Local -PassThru -ErrorAction Stop)
        if ($modules.Count -ne 1) {
            throw 'The bundled Active Directory provider did not load once.'
        }
        $rootCommand = $modules[0].ExportedCmdlets['Get-ADRootDSE']
        $userCommand = $modules[0].ExportedCmdlets['Get-ADUser']
        if ($rootCommand -isnot [Management.Automation.CommandInfo] -or
            $userCommand -isnot [Management.Automation.CommandInfo]) {
            throw 'The bundled Active Directory query commands are unavailable.'
        }

        $roots = @(& $rootCommand @connection)
        $context = $this.NamingContext($roots)
        $actions = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $rows.Count; $index++) {
            $row = $rows[$index]
            $username = $this.RowValue($row, 'username')
            $filter = $this.LiteralAccountFilter($username)
            $existing = @(& $userCommand -LDAPFilter $filter -SearchBase $context -Properties SamAccountName @connection)
            $status = 'Existing'
            if (-not $existing.Count) {
                $this.ValidateAbsent($row)
                $status = 'Pending'
            }
            $actions.Add($this.DescribeAction($row, ($index + 1), $path, $server, $context, $status))
        }
        return $this.SealPlan($path, $server, $context, $actions.ToArray())
    }

    [object[]] Apply([string]$CsvPath, [object]$ReviewedPlan, [string[]]$ApprovedActionIds) {
        return $this.Apply($CsvPath, $ReviewedPlan, $ApprovedActionIds, @{})
    }

    [object[]] Apply(
        [string]$CsvPath,
        [object]$ReviewedPlan,
        [string[]]$ApprovedActionIds,
        [hashtable]$Options
    ) {
        $ErrorActionPreference = 'Stop'
        if (Get-Variable -Name WhatIfPreference -ValueOnly -ErrorAction Stop) {
            throw 'Use Preview for a PAS importer dry run.'
        }
        $review = $this.CopyReviewedPlan($ReviewedPlan)
        $approved = $this.ReadApprovals($review, $ApprovedActionIds)
        $connection = $this.ReadOptions($Options)
        $server = [string]$connection['Server']
        $path = $this.ResolveCsv($CsvPath)
        if ($review.CsvPath -cne $path -or $review.Server -cne $server) {
            throw 'The reviewed CSV or directory server has changed.'
        }
        $rows = @(Import-Csv -LiteralPath $path -ErrorAction Stop)
        $this.ValidateUsernames($rows)
        if ($rows.Count -ne $review.Actions.Count) {
            throw 'The reviewed CSV actions have changed.'
        }

        $repository = Split-Path -Parent $PSScriptRoot
        $modulePath = Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll'
        $modules = @(Import-Module -Name $modulePath -Scope Local -PassThru -ErrorAction Stop)
        if ($modules.Count -ne 1) {
            throw 'The bundled Active Directory provider did not load once.'
        }
        $rootCommand = $modules[0].ExportedCmdlets['Get-ADRootDSE']
        $userCommand = $modules[0].ExportedCmdlets['Get-ADUser']
        $createCommand = $modules[0].ExportedCmdlets['New-ADUser']
        if ($rootCommand -isnot [Management.Automation.CommandInfo] -or
            $userCommand -isnot [Management.Automation.CommandInfo] -or
            $createCommand -isnot [Management.Automation.CommandInfo]) {
            throw 'The bundled Active Directory provisioning commands are unavailable.'
        }

        $roots = @(& $rootCommand @connection)
        $context = $this.NamingContext($roots)
        if ($review.NamingContext -cne $context) {
            throw 'The reviewed directory naming context has changed.'
        }
        $current = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $rows.Count; $index++) {
            $current.Add($this.DescribeAction(
                $rows[$index], ($index + 1), $path, $server, $context, $review.Actions[$index].Status
            ))
        }
        $candidate = $this.SealPlan($path, $server, $context, $current.ToArray())
        if ($candidate.Fingerprint -cne $review.Fingerprint) {
            throw 'The reviewed CSV actions have changed.'
        }

        $results = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $rows.Count; $index++) {
            $action = $candidate.Actions[$index]
            if (-not $approved.Contains($action.ActionId)) {
                continue
            }

            $status = 'Existing'
            $filter = $this.LiteralAccountFilter($action.Username)
            $existing = @(& $userCommand -LDAPFilter $filter -SearchBase $context -Properties SamAccountName @connection)
            if ($existing.Count -gt 1) {
                throw 'The approved account lookup returned multiple users.'
            }
            if (-not $existing.Count) {
                $row = $rows[$index]
                $this.ValidateAbsent($row)
                $parameters = $this.UserParameters($connection, $action.Username, $action.Name, $action.Path)
                foreach ($field in $action.Fields.PSObject.Properties) {
                    $parameters[$field.Name] = $field.Value
                }
                $password = $null
                try {
                    $password = ConvertTo-SecureString ([string]$row.password) -AsPlainText -Force -ErrorAction Stop
                    $parameters.AccountPassword = $password
                    $null = & $createCommand @parameters -Confirm:$false
                }
                finally {
                    if ($null -ne $password) {
                        $password.Dispose()
                    }
                }
                $status = 'Created'
            }

            $results.Add([pscustomobject][ordered]@{
                ActionId = $action.ActionId
                Username = $action.Username
                Status = $status
            })
        }
        return $results.ToArray()
    }

    hidden [hashtable] ReadOptions([hashtable]$Options) {
        $server = ''
        $credential = [pscredential]::Empty
        if ($null -ne $Options) {
            $supplied = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($field in $Options.get_Keys()) {
                if ($field -isnot [string] -or $field -notin @('Server', 'Credential')) {
                    throw [ArgumentException]::new('Unknown PAS importer option.', 'Options')
                }
                if (-not $supplied.Add($field)) {
                    throw [ArgumentException]::new('Specify each PAS importer option once.', 'Options')
                }
                if ($field -eq 'Server') {
                    $server = [string]$Options[$field]
                    if ($this.IsBlank($server)) {
                        throw 'Server must be nonempty when specified.'
                    }
                }
                else {
                    $credential = [pscredential]$Options[$field]
                }
            }
        }
        return $this.ConnectionArguments($server, $credential)
    }

    hidden [string] ResolveCsv([string]$CsvPath) {
        if ($this.IsBlank($CsvPath)) {
            throw 'Specify an explicit CsvPath.'
        }
        $paths = @(Resolve-Path -LiteralPath $CsvPath -ErrorAction Stop)
        if ($paths.Count -ne 1 -or $paths[0].Provider.Name -ne 'FileSystem') {
            throw 'CsvPath must resolve to one file system path.'
        }
        return $paths[0].ProviderPath
    }

    hidden [void] ValidateUsernames([object[]]$Rows) {
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        foreach ($row in $Rows) {
            $username = $this.RowValue($row, 'username')
            if ($this.IsBlank($username)) {
                throw 'Each CSV row requires username.'
            }
            $null = $utf8.GetByteCount($username)
        }
    }

    hidden [string] NamingContext([object[]]$Roots) {
        $context = ''
        if ($Roots.Count -eq 1) {
            $context = $this.RowValue($Roots[0], 'DefaultNamingContext')
        }
        if ($this.IsBlank($context)) {
            throw 'The target default naming context is unavailable.'
        }
        return $context
    }

    hidden [void] ValidateAbsent([object]$Row) {
        foreach ($field in @('name', 'path')) {
            if ($this.IsBlank($this.RowValue($Row, $field))) {
                throw ('An absent user requires CSV field: ' + $field)
            }
        }
        if (-not $this.HasPassword($this.RowValue($Row, 'password'))) {
            throw 'An absent user requires CSV field: password'
        }
    }

    hidden [string] RowValue([object]$Row, [string]$Name) {
        if ($null -ne $Row) {
            $property = $Row.PSObject.Properties[$Name]
            if ($null -ne $property) {
                return [string]$property.Value
            }
        }
        return ''
    }

    hidden [object] DescribeAction(
        [object]$Row,
        [int]$Position,
        [string]$SourceFile,
        [string]$Server,
        [string]$NamingContext,
        [string]$Status
    ) {
        $username = $this.RowValue($Row, 'username')
        $name = $this.RowValue($Row, 'name')
        $path = $this.RowValue($Row, 'path')
        $fields = [ordered]@{}
        foreach ($field in $this.OptionalFields()) {
            $value = $this.RowValue($Row, $field)
            if (-not [string]::IsNullOrEmpty($value)) {
                $fields[$field] = $value
            }
        }
        $passwordPresent = $this.HasPassword($this.RowValue($Row, 'password'))
        $identity = [ordered]@{
            CsvPath = $SourceFile
            Server = $Server
            NamingContext = $NamingContext
            RowNumber = $Position
            Username = $username
            Status = $Status
            Name = $name
            Path = $path
            Fields = [pscustomobject]$fields
            PasswordPresent = $passwordPresent
        }
        return [pscustomobject][ordered]@{
            ActionId = $this.Fingerprint($identity)
            RowNumber = $Position
            Username = $username
            Status = $Status
            Name = $name
            Path = $path
            Fields = [pscustomobject]$fields
            PasswordPresent = $passwordPresent
        }
    }

    hidden [object] SealPlan([string]$Path, [string]$Server, [string]$Context, [object[]]$Actions) {
        $plan = [ordered]@{
            SchemaVersion = 1
            CsvPath = $Path
            Server = $Server
            NamingContext = $Context
            Actions = $Actions
        }
        $plan['Fingerprint'] = $this.Fingerprint($plan)
        return [pscustomobject]$plan
    }

    hidden [string] Fingerprint([object]$Data) {
        $json = ConvertTo-Json -InputObject $Data -Depth 8 -Compress -ErrorAction Stop
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))
            return [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $hasher.Dispose()
        }
    }

    hidden [Collections.Specialized.OrderedDictionary] ReadReviewFields([object]$Value, [string]$Failure) {
        if ($Value -isnot [pscustomobject]) {
            throw $Failure
        }
        $fields = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            if ($property -isnot [Management.Automation.PSNoteProperty]) {
                throw $Failure
            }
            $fields[$property.Name] = $property.Value
        }
        return $fields
    }

    hidden [object] CopyReviewedPlan([object]$Plan) {
        $planError = 'Specify a valid reviewed PAS importer plan.'
        $planFields = $this.ReadReviewFields($Plan, $planError)
        $expectedPlan = 'SchemaVersion,CsvPath,Server,NamingContext,Actions,Fingerprint'
        if (($planFields.get_Keys() -join ',') -cne $expectedPlan -or
            ($planFields.SchemaVersion -isnot [int] -and $planFields.SchemaVersion -isnot [long]) -or
            $planFields.SchemaVersion -ne 1 -or $planFields.CsvPath -isnot [string] -or
            $planFields.Server -isnot [string] -or $planFields.NamingContext -isnot [string] -or
            $planFields.Actions -isnot [object[]] -or $planFields.Fingerprint -isnot [string] -or
            $planFields.Fingerprint -cnotmatch '^[0-9a-f]{64}$') {
            throw $planError
        }

        $actionError = 'The reviewed PAS importer plan contains an invalid action.'
        $expectedAction = 'ActionId,RowNumber,Username,Status,Name,Path,Fields,PasswordPresent'
        $actions = [Collections.Generic.List[object]]::new()
        $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($record in $planFields.Actions) {
            $action = $this.ReadReviewFields($record, $actionError)
            if (($action.get_Keys() -join ',') -cne $expectedAction -or
                $action.ActionId -isnot [string] -or $action.ActionId -cnotmatch '^[0-9a-f]{64}$' -or
                -not $ids.Add($action.ActionId) -or
                ($action.RowNumber -isnot [int] -and $action.RowNumber -isnot [long]) -or
                $action.RowNumber -ne ($actions.Count + 1) -or $action.Username -isnot [string] -or
                $action.Status -isnot [string] -or $action.Status -cnotin @('Pending', 'Existing') -or
                $action.Name -isnot [string] -or $action.Path -isnot [string] -or
                $action.PasswordPresent -isnot [bool]) {
                throw $actionError
            }
            $fieldError = 'The reviewed PAS importer plan contains an invalid field.'
            $fields = $this.ReadReviewFields($action.Fields, $fieldError)
            foreach ($field in $fields.get_Keys()) {
                if ($field -cnotin $this.OptionalFields() -or $fields[$field] -isnot [string]) {
                    throw $fieldError
                }
            }
            $actions.Add([pscustomobject][ordered]@{
                ActionId = $action.ActionId
                RowNumber = [int]$action.RowNumber
                Username = $action.Username
                Status = $action.Status
                Name = $action.Name
                Path = $action.Path
                Fields = [pscustomobject]$fields
                PasswordPresent = $action.PasswordPresent
            })
        }

        $review = $this.SealPlan($planFields.CsvPath, $planFields.Server, $planFields.NamingContext, $actions.ToArray())
        if ($review.Fingerprint -cne $planFields.Fingerprint) {
            throw 'The reviewed PAS importer plan fingerprint does not match.'
        }
        return $review
    }

    hidden [Collections.Generic.HashSet[string]] ReadApprovals([object]$Review, [string[]]$ActionIds) {
        if ($null -eq $ActionIds -or -not $ActionIds.Count) {
            throw 'Specify the reviewed pending action IDs to approve.'
        }
        $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $accounts = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $pending = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
        foreach ($action in $Review.Actions) {
            if ($action.Status -ceq 'Pending') {
                $pending.Add($action.ActionId, $action.Username)
            }
        }
        foreach ($id in $ActionIds) {
            if ([string]::IsNullOrEmpty($id) -or -not $pending.ContainsKey($id) -or -not $ids.Add($id)) {
                throw 'An approved action ID is unknown, repeated, or outside the reviewed pending actions.'
            }
            if (-not $accounts.Add($pending[$id])) {
                throw 'Approve at most one pending action per account.'
            }
        }
        return $ids
    }

    hidden [bool] IsBlank([string]$Text) {
        return [string]::IsNullOrWhiteSpace($Text)
    }

    hidden [bool] HasPassword([string]$Password) {
        return -not [string]::IsNullOrEmpty($Password)
    }

    hidden [string] LiteralAccountFilter([string]$Username) {
        $escaped = $this.EscapeAccount($Username)
        return '(sAMAccountName=' + $escaped + ')'
    }

    hidden [string] EscapeAccount([string]$Username) {
        return $Username.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
    }

    hidden [hashtable] ConnectionArguments([string]$Server, [pscredential]$Credential) {
        $connection = @{
            ErrorAction = 'Stop'
        }
        if ($Server) {
            $connection.Server = $Server
        }
        if ($null -ne $Credential -and $Credential -ne [pscredential]::Empty) {
            $connection.Credential = $Credential
        }
        return $connection
    }

    hidden [hashtable] UserParameters([hashtable]$Connection, [string]$Username, [string]$Name, [string]$Path) {
        return @{} + $Connection + @{
            Name = $Name
            SamAccountName = $Username
            Path = $Path
            Enabled = $true
            ChangePasswordAtLogon = $true
        }
    }

    hidden [string[]] OptionalFields() {
        return @('GivenName', 'Surname', 'DisplayName', 'Department', 'EmployeeID', 'UserPrincipalName')
    }
}

function New-ADPASUser {
    <# .SYNOPSIS Creates absent CSV users; failures may leave an account and are not retried. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$CsvPath,
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty

    )
    $ErrorActionPreference = 'Stop'
    $importer = [ADAnalyzerPasUserImporter]::new()
    if ($importer.IsBlank($CsvPath)) {
        throw 'Specify an explicit CsvPath.'
    }
    if ($PSBoundParameters.ContainsKey('Server') -and $importer.IsBlank($Server)) {
        throw 'Server must be nonempty when specified.'
    }
    $adUsers = @(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)
    if (-not $adUsers.Count) {
        return
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    foreach ($user in $adUsers) {
        if ($importer.IsBlank([string]$user.username)) {
            throw 'Each CSV row requires username.'
        }
        $null = $utf8.GetByteCount([string]$user.username)
    }
    $repository = Split-Path -Parent $PSScriptRoot
    Import-Module -Name (Join-Path $repository 'lib/Microsoft.ActiveDirectory.Management.dll') -Scope Local -ErrorAction Stop
    $connection = $importer.ConnectionArguments($Server, $Credential)
    $roots = @(Get-ADRootDSE @connection)
    if ($roots.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$roots[0].DefaultNamingContext)) {
        throw 'The target default naming context is unavailable.'
    }
    $searchBase = [string]$roots[0].DefaultNamingContext
    foreach ($user in $adUsers) {
        $username = [string]$user.username
        $escaped = $importer.EscapeAccount($username)
        $existing = @(Get-ADUser `
                -LDAPFilter ('(sAMAccountName=' + $escaped + ')') `
                -SearchBase $searchBase `
                -Properties SamAccountName @connection)
        if ($existing.Count) {
            Write-Warning ('User {0} already exists' -f $username)
            continue
        }
        foreach ($field in @('name', 'path')) {
            if ($importer.IsBlank([string]$user.$field)) {
                throw ('An absent user requires CSV field: ' + $field)
            }
        }
        if (-not $importer.HasPassword([string]$user.password)) {
            throw 'An absent user requires CSV field: password'
        }
        if (-not $PSCmdlet.ShouldProcess($username, 'Create enabled AD user and require password change')) {
            continue
        }
        $parameters = $importer.UserParameters($connection, $username, [string]$user.name, [string]$user.path)
        foreach ($field in $importer.OptionalFields()) {
            if (-not [string]::IsNullOrEmpty([string]$user.$field)) {
                $parameters[$field] = [string]$user.$field
            }
        }
        $password = $null
        try {
            $password = ConvertTo-SecureString ([string]$user.password) -AsPlainText -Force -ErrorAction Stop
            $parameters.AccountPassword = $password
            $null = New-ADUser @parameters
        }
        finally {
            if ($null -ne $password) {
                $password.Dispose()
            }
        }
    }
}
if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{
        CsvPath = $CliCsvPath
        Credential = $CliCredential
        WhatIf = [bool]$WhatIfPreference
    }
    if ($PSBoundParameters.ContainsKey('CliServer')) {
        $arguments.Server = $CliServer
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $arguments.Confirm = $PSBoundParameters.Confirm
    }
    New-ADPASUser @arguments
}
