[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Standalone', 'Direct', 'Isolation', 'Online')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

function Import-Module {
    throw 'The prerequisite fixture blocked an unexpected module import.'
}

if ($Case -eq 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

$script:passed = 0
$script:dllName = 'Microsoft.ActiveDirectory.Management.dll'
$script:dllRelativePath = Join-Path 'lib' $script:dllName

function Assert-Inspector($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-InspectorEqual($Expected, $Actual) {
    if ($Expected -cne $Actual) {
        throw ('Expected [{0}], observed [{1}]' -f $Expected, $Actual)
    }
}

function Test-Inspector([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        $script:passed++
    }
    catch {
        Write-Host ('FAIL prerequisite inspector ' + $Name)
        throw
    }
}

function Get-InspectorJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 15 -Compress
}

function New-InspectorPackage([string]$Parent) {
    $packageName = 'package[fixture]'
    $package = Join-Path $Parent $packageName
    $dll = Join-Path $package $script:dllRelativePath
    $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $dll))
    [IO.File]::Copy((Join-Path $RepositoryRoot $script:dllRelativePath), $dll)
    [pscustomobject]@{
        Name = $packageName
        Root = $package
        Dll = $dll
        Sha = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
    }
}

function Assert-InspectorPackage([object[]]$Checks, [string]$Root, [string]$Sha) {
    Assert-InspectorEqual 'PACKAGE.WINDOWS,PACKAGE.POWERSHELL,PACKAGE.BUNDLED_AD,PACKAGE.CHECKSUM' ($Checks.RuleId -join ',')
    Assert-InspectorEqual $Root $Checks[0].Target
    Assert-InspectorEqual $Root $Checks[1].Target
    $displayTarget = Join-Path $Root $script:dllRelativePath
    Assert-InspectorEqual $displayTarget $Checks[2].Target
    Assert-InspectorEqual $displayTarget $Checks[3].Target
    Assert-InspectorEqual 'Pass' $Checks[2].Status
    Assert-InspectorEqual $Sha $Checks[2].Observed.Sha256
    Assert-InspectorEqual $Sha $Checks[3].Observed
}

function Describe-InspectorPathError($Record) {
    if ($null -eq $Record) {
        return $null
    }
    $recordType = $Record.GetType().FullName
    if ($Record -is [Collections.IList]) {
        return [pscustomobject]@{
            RecordType = $recordType
            Entries = @(
                foreach ($entry in $Record) {
                    Describe-InspectorPathError $entry
                }
            )
        }
    }
    if ($Record -is [Management.Automation.IContainsErrorRecord]) {
        $Record = $Record.ErrorRecord
    }
    if ($Record -isnot [Management.Automation.ErrorRecord]) {
        return [pscustomobject]@{
            RecordType = $recordType
        }
    }
    $cause = $Record.Exception.GetBaseException()
    [pscustomobject]@{
        RecordType = $recordType
        Id = $Record.FullyQualifiedErrorId
        Category = [string]$Record.CategoryInfo.Category
        Message = $Record.Exception.Message
        CauseType = $cause.GetType().FullName
        Cause = $cause.Message
    }
}

function Invoke-InspectorPathFault([string]$Root, [string]$Action) {
    $script:fixtureFault = 'Path'
    $script:prerequisiteReads.Clear()
    $global:Error.Clear()
    $captured = @()
    $sequence = [Collections.Generic.List[string]]::new()
    $items = [Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        Get-ADAnalyzerPrerequisite -RepositoryRoot $Root -ErrorAction $Action -ErrorVariable +captured 2>&1 |
            ForEach-Object {
                if ($_ -is [Management.Automation.ErrorRecord]) {
                    $sequence.Add(('Error:' + $_.FullyQualifiedErrorId))
                    $items.Add((Describe-InspectorPathError $_))
                }
                else {
                    $sequence.Add(('Row:' + $_.RuleId))
                    $items.Add($_)
                }
            }
    }
    catch {
        $sequence.Add(('Caught:' + $_.FullyQualifiedErrorId))
        $failure = Describe-InspectorPathError $_
    }
    $history = @($global:Error)
    $pathErrorCount = @($captured | Where-Object FullyQualifiedErrorId -like 'FixturePrerequisitePathDenied,*').Count
    $capture = @(
        foreach ($record in $captured) {
            Describe-InspectorPathError $record
        }
    )
    [pscustomobject]@{
        Sequence = $sequence.ToArray()
        Stream = $items.ToArray()
        Caught = $failure
        Captured = $capture
        PathErrorCount = $pathErrorCount
        History = @(
            foreach ($record in $history) {
                Describe-InspectorPathError $record
            }
        )
        Reads = $script:prerequisiteReads.ToArray()
    }
}

function Assert-InspectorPathIgnore([string]$Root) {
    $functionPath = 'Function:script:Get-ADAnalyzerPrerequisite'
    $current = (Get-Command Get-ADAnalyzerPrerequisite -CommandType Function).ScriptBlock
    # The frozen 015d026 command prefix retains binding, runtime rows and the negative path branch.
    $accepted = [scriptblock]::Create(@'
    [CmdletBinding()]
    param(
        [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [switch]$Online,
        [hashtable]$Profile

    )
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    New-ADAnalyzerCheck `
        -RuleId 'PACKAGE.WINDOWS' `
        -Status $(if ($windows) {
            'Pass'
        }
        else {
            'NotApplicable'
        }) `
        -Category Prerequisite `
        -Target $RepositoryRoot `
        -Observed $windows `
        -Expected $true `
        -Message 'Live AD/SMB collection uses Windows; offline policy analysis is portable'
    New-ADAnalyzerCheck -RuleId 'PACKAGE.POWERSHELL' -Status $(if ($PSVersionTable.PSVersion -ge [version]'5.1') {
            'Pass'
        }
        else {
            'Fail'
        }) -Category Prerequisite -Target $RepositoryRoot -Observed $PSVersionTable.PSVersion.ToString() -Expected '>=5.1'
    $dll = Join-Path $RepositoryRoot 'lib/Microsoft.ActiveDirectory.Management.dll'
    $packagePath = $null
    $packageLiteralPath = $null
    if (Test-Path -LiteralPath $dll -PathType Leaf) {
        throw 'The path-fault fixture unexpectedly supplied a present package.'
    }
    else {
        New-ADAnalyzerCheck `
            -RuleId 'PACKAGE.BUNDLED_AD' `
            -Status Fail `
            -Severity High `
            -Category Prerequisite `
            -Target $dll `
            -Message 'The package AD assembly is missing'
    }
'@)
    try {
        Set-Item -LiteralPath $functionPath -Value $accepted
        $installed = (Get-Command Get-ADAnalyzerPrerequisite -CommandType Function).ScriptBlock
        Assert-InspectorEqual ($accepted.ToString()) ($installed.ToString())
        $expected = Invoke-InspectorPathFault $Root 'Ignore'
    }
    finally {
        Set-Item -LiteralPath $functionPath -Value $current
    }
    $restored = (Get-Command Get-ADAnalyzerPrerequisite -CommandType Function).ScriptBlock
    Assert-InspectorEqual ($current.ToString()) ($restored.ToString())
    $actual = Invoke-InspectorPathFault $Root 'Ignore'
    Assert-InspectorEqual 'Path' ($expected.Reads -join ',')
    Assert-InspectorEqual (Get-InspectorJson $expected) (Get-InspectorJson $actual)
}

class PrerequisiteFixtureWait {
    [int]$Port

    PrerequisiteFixtureWait([int]$Port) {
        $this.Port = $Port
    }

    [bool] WaitOne([int]$Milliseconds) {
        $script:onlineTrace.Add(('Wait|{0}|{1}' -f $this.Port, $Milliseconds))
        return -not ($script:onlineScenario -eq 'TcpFaults' -and $this.Port -eq 9389)
    }
}

class PrerequisiteFixturePending {
    [PrerequisiteFixtureWait]$AsyncWaitHandle

    PrerequisiteFixturePending([int]$Port) {
        $this.AsyncWaitHandle = [PrerequisiteFixtureWait]::new($Port)
    }
}

class PrerequisiteFixtureSocket {
    [int]$Port

    [PrerequisiteFixturePending] BeginConnect([string]$Server, [int]$Port, $Callback, $State) {
        $this.Port = $Port
        $script:onlineTrace.Add(('Begin|{0}|{1}' -f $Server, $Port))
        return [PrerequisiteFixturePending]::new($Port)
    }

    [void] EndConnect([PrerequisiteFixturePending]$Pending) {
        $script:onlineTrace.Add(('End|{0}' -f $this.Port))
        if ($script:onlineScenario -eq 'TcpFaults' -and $this.Port -eq 445) {
            throw [IO.IOException]::new('fixture connection refused')
        }
    }

    [void] Dispose() {
        $script:onlineTrace.Add(('Dispose|{0}' -f $this.Port))
    }
}

function Invoke-InspectorOnlineWitness([string]$Scenario, [string]$Route, [object]$Package) {
    if ($Scenario -eq 'StrictMissingDnsHostName') {
        Set-StrictMode -Version Latest
    }
    $script:onlineScenario = $Scenario
    $script:fixtureWindows = $Scenario -ne 'UnsupportedPlatform'
    $script:onlineTrace = [Collections.Generic.List[string]]::new()
    $server = 'caller.fixture.invalid'
    $root = Join-Path '.' $Package.Name
    $credential = [pscredential]::Empty
    $profile = $null
    switch ($Scenario) {
        ExplicitCredential {
            $credential = $script:fixtureCredential
        }
        NullCredential {
            $credential = $null
        }
        MissingPackage {
            $root = Join-Path '.' 'missing-package'
        }
        MatchingPin {
            $profile = @{
                DependencyHashes = @{ $script:dllName = $Package.Sha }
            }
        }
        WrongPin {
            $profile = @{
                DependencyHashes = @{ $script:dllName = ('0' * 64) }
            }
        }
    }

    $checks = if ($Route -eq 'Method') {
        $inspector = [ADAnalyzerPrerequisiteInspector]::new()
        $inspector.InspectOnline($root, $server, $credential, $profile)
    }
    else {
        $arguments = @{
            RepositoryRoot = $root
            Server = $server
            Credential = $credential
            Profile = $profile
            Online = $true
        }
        if ($Scenario -eq 'StopAfterFirstPort') {
            Get-ADAnalyzerPrerequisite @arguments | Select-Object -First 5
        }
        else {
            Get-ADAnalyzerPrerequisite @arguments
        }
    }
    [pscustomobject]@{
        Checks = @($checks)
        Trace = $script:onlineTrace.ToArray()
    }
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('prerequisite-class-' + [guid]::NewGuid().ToString('N'))
$originalLocation = (Get-Location).Path
$originalDirectory = [Environment]::CurrentDirectory
$ownedDrive = $null
try {
    if ($Case -eq 'Standalone') {
        Test-Inspector 'construction invokes no observation' {
            & {
                function Get-ADAnalyzerPrerequisiteObservation {
                    throw 'Constructing the inspector requested an observation.'
                }
                $inspector = [ADAnalyzerPrerequisiteInspector]::new()
                Assert-InspectorEqual '{}' (Get-InspectorJson $inspector)
            }
        }
        Test-Inspector 'literal default inspection uses the owning package' {
            $inspector = [ADAnalyzerPrerequisiteInspector]::new()
            $command = @(Get-ADAnalyzerPrerequisite)
            $checks = $inspector.Inspect()
            Assert-Inspector ($checks -is [array] -and $checks.Count -eq 4) 'Inspect() did not return its ordered check array.'
            Assert-InspectorEqual $RepositoryRoot $checks[0].Target
            Assert-InspectorEqual 'NotConfigured' $checks[3].Status
            Assert-InspectorEqual (Get-InspectorJson $command) (Get-InspectorJson $checks)
        }
    }

    if ($Case -eq 'Direct') {
        $fixture = New-InspectorPackage $temporary
        $driveName = 'Prereq' + [guid]::NewGuid().ToString('N')
        $ownedDrive = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $temporary
        $processDirectory = Join-Path $temporary 'native-cwd'
        $null = [IO.Directory]::CreateDirectory($processDirectory)
        [Environment]::CurrentDirectory = $processDirectory
        $expectedDirectory = [Environment]::CurrentDirectory
        $roots = [ordered]@{
            Absolute = $fixture.Root
            Relative = (Join-Path '.' $fixture.Name)
            Drive = ('{0}:/{1}' -f $driveName, $fixture.Name)
            Qualified = ('FileSystem::' + $fixture.Root)
        }
        $pin = @{
            DependencyHashes = @{
                $script:dllName = $fixture.Sha
            }
        }
        $profileBefore = Get-InspectorJson $pin
        $inspector = [ADAnalyzerPrerequisiteInspector]::new()
        foreach ($variant in $roots.Keys) {
            Test-Inspector ('explicit inspection path ' + $variant) {
                if ($variant -eq 'Qualified') {
                    Set-Location Env:
                }
                else {
                    Set-Location -LiteralPath $temporary
                }
                $root = $roots[$variant]
                $callerLocation = (Get-Location).Path
                $command = @(Get-ADAnalyzerPrerequisite -RepositoryRoot $root -Profile $pin)
                $checks = & {
                    function Get-ADAnalyzerPrerequisite {
                        throw 'The inspector delegated to its compatibility command.'
                    }
                    , $inspector.Inspect($root, $pin)
                }
                Assert-InspectorPackage $checks $root $fixture.Sha
                Assert-InspectorEqual 'Pass' $checks[3].Status
                Assert-InspectorEqual (Get-InspectorJson $command) (Get-InspectorJson $checks)
                Assert-InspectorEqual $callerLocation (Get-Location).Path
                Assert-InspectorEqual $expectedDirectory ([Environment]::CurrentDirectory)
                Assert-InspectorEqual $profileBefore (Get-InspectorJson $pin)
            }
        }
    }

    if ($Case -eq 'Isolation') {
        Test-Inspector 'returned data and inspector instances are independent' {
            $fixture = New-InspectorPackage $temporary
            $wrongPin = @{
                DependencyHashes = @{
                    $script:dllName = ('0' * 64)
                }
            }
            $first = [ADAnalyzerPrerequisiteInspector]::new()
            $second = [ADAnalyzerPrerequisiteInspector]::new()
            $accepted = $first.Inspect($fixture.Root, $null)
            $before = Get-InspectorJson $accepted
            $accepted[2].Observed.Sha256 = 'changed'
            $accepted[2].Target = 'changed'
            Assert-InspectorEqual 'Fail' ($second.Inspect($fixture.Root, $wrongPin))[3].Status
            Assert-InspectorEqual $before (Get-InspectorJson ($first.Inspect($fixture.Root, $null)))
            Assert-InspectorEqual '{}' (Get-InspectorJson $first)
        }
        Test-Inspector 'same-source secondary runspace disposal leaves inspector usable' {
            $inspector = [ADAnalyzerPrerequisiteInspector]::new()
            $before = Get-InspectorJson ($inspector.Inspect())
            $worker = [powershell]::Create()
            try {
                $child = @'
param($Fixture, $Root)
$ErrorActionPreference = 'Stop'
& $Fixture -Case Standalone -RepositoryRoot $Root
'@
                $output = @($worker.AddScript($child).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
                Assert-Inspector ($worker.Streams.Error.Count -eq 0 -and $output.Count -eq 1) 'Secondary prerequisite runspace failed.'
                Assert-InspectorEqual 'PASS prerequisite inspector Standalone 2' ([string]$output[0])
            }
            finally {
                $worker.Dispose()
            }
            Assert-InspectorEqual $before (Get-InspectorJson ($inspector.Inspect()))
            $independent = [ADAnalyzerPrerequisiteInspector]::new()
            Assert-InspectorEqual $before (Get-InspectorJson ($independent.Inspect()))
        }
    }

    if ($Case -eq 'Native') {
        $fixture = New-InspectorPackage $temporary
        $script:fixturePathCommand = Get-Command Microsoft.PowerShell.Management\Test-Path
        $script:fixtureHashCommand = Get-Command Microsoft.PowerShell.Utility\Get-FileHash
        $script:fixtureFault = ''
        $script:prerequisiteReads = [Collections.Generic.List[string]]::new()

        function script:Test-Path {
            [CmdletBinding()]
            param([string[]]$LiteralPath, [string]$PathType)
            $script:prerequisiteReads.Add('Path')
            if ($script:fixtureFault -eq 'Path') {
                Write-Error -Message 'fixture path access denied' -ErrorId 'FixturePrerequisitePathDenied'
                return $false
            }
            & $script:fixturePathCommand @PSBoundParameters
        }
        function script:Get-FileHash {
            [CmdletBinding()]
            param([string[]]$LiteralPath, [string]$Algorithm)
            $script:prerequisiteReads.Add('Hash')
            if ($script:fixtureFault -eq 'Hash') {
                throw [UnauthorizedAccessException]::new('fixture hash access denied')
            }
            & $script:fixtureHashCommand @PSBoundParameters
        }

        Test-Inspector 'first item cutoff neither observes paths nor hashes' {
            $script:prerequisiteReads.Clear()
            $checks = @(Get-ADAnalyzerPrerequisite -RepositoryRoot $fixture.Root | Select-Object -First 1)
            Assert-InspectorEqual 'PACKAGE.WINDOWS' ($checks.RuleId -join ',')
            Assert-InspectorEqual 0 $script:prerequisiteReads.Count
        }

        foreach ($action in 'Continue', 'SilentlyContinue', 'Ignore', 'Stop') {
            Test-Inspector ('path fault preference ' + $action) {
                if ($action -eq 'Ignore') {
                    Assert-InspectorPathIgnore $fixture.Root
                    return
                }
                $observed = Invoke-InspectorPathFault $fixture.Root $action
                $prefix = 'Row:PACKAGE.WINDOWS,Row:PACKAGE.POWERSHELL'
                $expected = switch ($action) {
                    Continue {
                        $prefix + ',Error:FixturePrerequisitePathDenied,Test-Path,Row:PACKAGE.BUNDLED_AD'
                    }
                    Stop {
                        $prefix + ',Caught:FixturePrerequisitePathDenied,Test-Path'
                    }
                    default {
                        $prefix + ',Row:PACKAGE.BUNDLED_AD'
                    }
                }
                Assert-InspectorEqual $expected ($observed.Sequence -join ',')
                Assert-InspectorEqual 'Path' ($observed.Reads -join ',')
                Assert-Inspector ($observed.PathErrorCount -gt 0) 'The native path error was lost from ErrorVariable.'
            }

            Test-Inspector ('hash fault preference ' + $action) {
                $script:fixtureFault = 'Hash'
                $script:prerequisiteReads.Clear()
                $captured = @()
                $checks = [Collections.Generic.List[object]]::new()
                $failure = $null
                try {
                    Get-ADAnalyzerPrerequisite -RepositoryRoot $fixture.Root -ErrorAction $action -ErrorVariable +captured |
                        ForEach-Object { $checks.Add($_) }
                }
                catch {
                    $failure = $_.Exception.GetBaseException()
                }
                Assert-Inspector ($failure -is [UnauthorizedAccessException]) 'The real hash cause was not preserved.'
                Assert-InspectorEqual 'fixture hash access denied' $failure.Message
                Assert-InspectorEqual 'PACKAGE.WINDOWS,PACKAGE.POWERSHELL' ($checks.RuleId -join ',')
                Assert-InspectorEqual 'Path,Hash' ($script:prerequisiteReads -join ',')
                Assert-Inspector (@($captured | Where-Object { $null -ne $_ }).Count -gt 0) 'The native hash fault was lost from ErrorVariable.'
            }
        }

        Test-Inspector 'invalid profile is terminal before any path observation' {
            $script:fixtureFault = ''
            $script:prerequisiteReads.Clear()
            $profile = @{
                DependencyHashes = @{
                    $script:dllName = 'bad-pin'
                }
            }
            $checks = [Collections.Generic.List[object]]::new()
            $failure = $null
            try {
                Get-ADAnalyzerPrerequisite -RepositoryRoot $fixture.Root -Profile $profile |
                    ForEach-Object { $checks.Add($_) }
            }
            catch {
                $failure = $_.Exception.GetBaseException().Message
            }
            Assert-InspectorEqual 'DependencyHashes values must be SHA256 hex strings' $failure
            Assert-InspectorEqual 0 $script:prerequisiteReads.Count
            Assert-InspectorEqual 0 $checks.Count
        }
    }

    if ($Case -eq 'Online') {
        $fixture = New-InspectorPackage $temporary
        Set-Location -LiteralPath $temporary
        $script:fixturePhysicalPackage = $fixture.Dll
        $script:fixtureCredential = [pscredential]::new('prerequisite-fixture-only', [Security.SecureString]::new())
        $script:fixtureObservationFactory = (Get-Command Get-ADAnalyzerPrerequisiteObservation -CommandType Function).ScriptBlock
        $script:platformAnchor = '[Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT'
        $script:socketAnchor = '[Net.Sockets.TcpClient]::new()'
        $sourcePath = Join-Path $RepositoryRoot 'bin/ADProfile.ps1'
        $source = Get-Content -LiteralPath $sourcePath -Raw
        Assert-Inspector (
            [regex]::Matches($source, [regex]::Escape($script:socketAnchor)).Count -eq 1 -and
            $script:fixtureObservationFactory.ToString().Contains($script:socketAnchor)
        ) 'The online fixture no longer controls the native socket constructor.'

        function script:Get-ADAnalyzerPrerequisiteObservation {
            param([string]$Kind)
            $observation = & $script:fixtureObservationFactory -Kind $Kind
            if ($Kind -eq 'Platform') {
                $anchor = $script:platformAnchor
                $replacement = '$script:fixtureWindows'
            }
            elseif ($Kind -eq 'Tcp') {
                $anchor = $script:socketAnchor
                $replacement = '[PrerequisiteFixtureSocket]::new()'
            }
            else {
                return $observation
            }

            $text = $observation.ToString()
            Assert-Inspector ([regex]::Matches($text, [regex]::Escape($anchor)).Count -eq 1) 'An online observer fixture anchor changed.'
            $inert = $text.Replace($anchor, $replacement)
            Assert-Inspector (-not $inert.Contains($script:socketAnchor)) 'The fixture refused a real socket.'
            return [scriptblock]::Create($inert)
        }

        function script:Import-Module {
            [CmdletBinding()]
            param([string]$Name, [string]$Scope, [switch]$PassThru)
            Assert-InspectorEqual $script:fixturePhysicalPackage $Name
            Assert-InspectorEqual 'Local' $Scope
            Assert-Inspector $PassThru.IsPresent 'The import did not request its specific module information.'
            Assert-InspectorEqual 'Stop' ([string]$PSBoundParameters['ErrorAction'])
            $script:onlineTrace.Add('Import')
            if ($script:onlineScenario -eq 'ModuleError') {
                throw 'fixture module load denied'
            }
            $exports = @{}
            if ($script:onlineScenario -ne 'MissingCapability') {
                $exports['Get-ADRootDSE'] = Get-Command Invoke-PrerequisiteFixtureRootDse
            }
            [pscustomobject]@{
                ExportedCmdlets = $exports
            }
        }
        function script:Get-ADRootDSE {
            $script:onlineTrace.Add('AmbientRootDse')
            throw 'A prerequisite used an ambient AD command.'
        }
        function script:Invoke-PrerequisiteFixtureRootDse {
            [CmdletBinding()]
            param([string]$Server, [pscredential]$Credential)
            $bound = $PSBoundParameters.ContainsKey('Credential')
            Assert-InspectorEqual 'caller.fixture.invalid' $Server
            Assert-InspectorEqual 'Stop' ([string]$PSBoundParameters['ErrorAction'])
            if ($script:onlineScenario -eq 'ExplicitCredential') {
                Assert-Inspector ($bound -and [object]::ReferenceEquals($Credential, $script:fixtureCredential)) 'Explicit credential identity changed.'
            }
            else {
                Assert-Inspector (-not $bound) 'Empty or null credentials should not be passed to RootDSE.'
            }
            $script:onlineTrace.Add(('ExactRootDse|{0}' -f $bound))
            if ($script:onlineScenario -eq 'RootError') {
                throw 'fixture RootDSE denied'
            }
            if ($script:onlineScenario -in 'MissingDnsHostName', 'StrictMissingDnsHostName') {
                return [pscustomobject]@{}
            }
            [pscustomobject]@{
                DnsHostName = 'selected.fixture.invalid'
            }
        }

        $onlineCases = [ordered]@{
            Success = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Pass'
            ExplicitCredential = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Pass'
            NullCredential = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Pass'
            MatchingPin = 'Pass,Pass,Pass,Pass,Pass,Pass,Pass'
            WrongPin = 'Pass,Pass,Pass,Fail,Pass,Pass,Unreadable'
            UnsupportedPlatform = 'NotApplicable,Pass,Pass,NotConfigured,Pass,Pass,Unreadable'
            MissingPackage = 'Pass,Pass,Fail,Pass,Pass,Unreadable'
            TcpFaults = 'Pass,Pass,Pass,NotConfigured,Unreadable,Unreadable,Pass'
            ModuleError = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Unreadable'
            MissingCapability = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Unreadable'
            RootError = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Unreadable'
            MissingDnsHostName = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Pass'
            StrictMissingDnsHostName = 'Pass,Pass,Pass,NotConfigured,Pass,Pass,Unreadable'
        }
        foreach ($scenario in $onlineCases.Keys) {
            Test-Inspector ('simulated online ' + $scenario) {
                $command = Invoke-InspectorOnlineWitness $scenario Command $fixture
                $direct = Invoke-InspectorOnlineWitness $scenario Method $fixture
                Assert-InspectorEqual (Get-InspectorJson $command) (Get-InspectorJson $direct)
                Assert-InspectorEqual $onlineCases[$scenario] ($command.Checks.Status -join ',')
                Assert-InspectorEqual 'CONNECTIVITY.TCP.9389,CONNECTIVITY.TCP.445,CONNECTIVITY.DIRECTORY' ($command.Checks[-3..-1].RuleId -join ',')
                Assert-InspectorEqual 'caller.fixture.invalid' $command.Checks[-1].Target
                $expectedTrace = [Collections.Generic.List[string]]::new()
                foreach ($port in 9389, 445) {
                    $expectedTrace.Add(('Begin|caller.fixture.invalid|{0}' -f $port))
                    $expectedTrace.Add(('Wait|{0}|3000' -f $port))
                    if ($scenario -ne 'TcpFaults' -or $port -ne 9389) {
                        $expectedTrace.Add(('End|{0}' -f $port))
                    }
                    $expectedTrace.Add(('Dispose|{0}' -f $port))
                }
                if ($scenario -notin 'WrongPin', 'UnsupportedPlatform', 'MissingPackage') {
                    $expectedTrace.Add('Import')
                    if ($scenario -notin 'ModuleError', 'MissingCapability') {
                        $expectedTrace.Add(('ExactRootDse|{0}' -f ($scenario -eq 'ExplicitCredential')))
                    }
                }
                Assert-InspectorEqual ($expectedTrace -join ',') ($command.Trace -join ',')
                switch ($scenario) {
                    TcpFaults {
                        Assert-InspectorEqual 'Connection timed out' $command.Checks[-3].Observed
                        Assert-Inspector ($command.Checks[-2].Observed -like '*fixture connection refused*') 'TCP failure lost its cause.'
                    }
                    ModuleError {
                        Assert-InspectorEqual 'fixture module load denied' $command.Checks[-1].Message
                    }
                    MissingCapability {
                        Assert-InspectorEqual 'Bundled AD assembly does not provide RootDSE queries' $command.Checks[-1].Message
                    }
                    RootError {
                        Assert-InspectorEqual 'fixture RootDSE denied' $command.Checks[-1].Message
                    }
                    StrictMissingDnsHostName {
                        Assert-Inspector ($command.Checks[-1].Message -like '*DnsHostName*') 'Strict native getter error was lost.'
                    }
                }
                Assert-Inspector ((Get-InspectorJson $direct.Checks) -notmatch 'prerequisite-fixture-only') 'The check array serialized its credential.'
            }
        }
        Test-Inspector 'first TCP output disposes the client before stopping later work' {
            $result = Invoke-InspectorOnlineWitness StopAfterFirstPort Command $fixture
            Assert-InspectorEqual 5 $result.Checks.Count
            Assert-InspectorEqual 'CONNECTIVITY.TCP.9389' $result.Checks[-1].RuleId
            Assert-InspectorEqual (
                'Begin|caller.fixture.invalid|9389,Wait|9389|3000,End|9389,Dispose|9389'
            ) ($result.Trace -join ',')
        }
    }
}
finally {
    Set-Location -LiteralPath $originalLocation
    [Environment]::CurrentDirectory = $originalDirectory
    if ($null -ne $ownedDrive) {
        Remove-PSDrive -Name $ownedDrive.Name
    }
    if ([IO.Directory]::Exists($temporary)) {
        [IO.Directory]::Delete($temporary, $true)
    }
}

Write-Output ('PASS prerequisite inspector {0} {1}' -f $Case, $script:passed)
