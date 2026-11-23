[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageRoot,
    [Parameter(Mandatory)]
    [string]$OutputRoot,
    [Parameter(Mandatory)]
    [ValidateSet('Command', 'Class')]
    [string]$Case
)

$ErrorActionPreference = 'Stop'
$windows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
$comparison = if ($windows) {
    [StringComparison]::OrdinalIgnoreCase
}
else {
    [StringComparison]::Ordinal
}
$package = (Resolve-Path -LiteralPath $PackageRoot).ProviderPath
$output = (Resolve-Path -LiteralPath $OutputRoot).ProviderPath
$prefix = $package.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($output.Equals($package, $comparison) -or $output.StartsWith($prefix, $comparison) -or
    [IO.Directory]::GetFileSystemEntries($output).Length) {
    throw 'The output directory must be empty and outside the unpacked package.'
}
foreach ($directory in '.git', '.github', 'tests', 'tools') {
    if (Test-Path -LiteralPath (Join-Path $package $directory)) {
        throw ('Development files escaped into the package: ' + $directory)
    }
}
if ($windows -and (Get-Module -ListAvailable -Name ActiveDirectory, GroupPolicy)) {
    throw 'Installed RSAT modules invalidate the unpacked package test.'
}

# These are fresh-process settings. Never configure them at machine or user scope.
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$env:ADPS_LoadDefaultDrive = '0'
$commandScope = $null
$bundledDll = [IO.Path]::GetFullPath((Join-Path $package 'lib/Microsoft.ActiveDirectory.Management.dll'))
if ($Case -ceq 'Command') {
    if (-not $windows) {
        throw 'The native manifest smoke test requires Windows.'
    }
    $manifest = Join-Path $package 'ADEnvironment.psd1'
    $commandScope = Import-Module -Name $manifest -PassThru -ErrorAction Stop -WarningAction SilentlyContinue
    $export = $commandScope.ExportedFunctions['Invoke-ADAnalyzerAssessment']
    $source = [IO.Path]::GetFullPath((Join-Path $package 'bin/ADAssessment.ps1'))
    if ($export -isnot [Management.Automation.FunctionInfo] -or
        -not $source.Equals($export.ScriptBlock.File, $comparison)) {
        throw 'The public assessment command was not loaded from the package.'
    }
    $resolvedDll = & $commandScope {
        (Get-Command -Name Get-ADRootDSE -CommandType Cmdlet -ListImported -ErrorAction Stop).Module.Path
    }
    if (-not $bundledDll.Equals([IO.Path]::GetFullPath($resolvedDll), $comparison) -or
        -not (Get-PSProvider -PSProvider ActiveDirectory -ErrorAction Stop)) {
        throw 'The imported package did not resolve its bundled AD binary and provider.'
    }
    if (Get-PSDrive -Name AD -ErrorAction SilentlyContinue) {
        throw 'Manifest import created a default AD drive.'
    }
}

$forbidden = @(
    'Import-Module'
    'Get-ADRootDSE'
    'Get-ADDomain'
    'Get-ADObject'
    'Get-ADUser'
    'Get-ADAnalyzerDirectoryData'
    'Get-ADAnalyzerHostData'
    'Get-ADAnalyzerGpo'
    'Get-ADAnalyzerGpoReport'
    'Get-ADAnalyzerAuditPolicy'
    'Get-ADAnalyzerTlsCertificate'
    'New-CimSession'
    'Get-CimInstance'
    'Invoke-Command'
    'New-PSDrive'
    'Enable-ADAccount'
    'Disable-ADAccount'
    'Enter-ADAnalyzerJournalLease'
    'Get-ADAnalyzerRemediationAuthorityDirectory'
)
$installGuards = {
    param([string[]]$Names)

    $script:PackageEffectAttempts = [Collections.Generic.List[string]]::new()
    $stopEffect = {
        $script:PackageEffectAttempts.Add($MyInvocation.InvocationName)
        throw 'Unexpected provider, module, or mutation access in unpacked package test.'
    }
    Set-Item -LiteralPath 'Function:script:Stop-PackageFixtureEffect' -Value $stopEffect
    foreach ($name in $Names) {
        Set-Alias -Name $name -Value 'Stop-PackageFixtureEffect' -Scope Script -Force
        $resolved = Get-Command -Name $name -ErrorAction Stop
        if ($resolved.CommandType -ne 'Alias' -or $resolved.Definition -cne 'Stop-PackageFixtureEffect') {
            throw ('The effect guard could not be installed for ' + $name)
        }
    }

    # Calibrate with a fixture-only name that cannot dispatch a native operation.
    Set-Alias -Name Invoke-ADAnalyzerPackageGuardProbe -Value 'Stop-PackageFixtureEffect' -Scope Script
    try {
        Invoke-ADAnalyzerPackageGuardProbe
    }
    catch {
        if ($script:PackageEffectAttempts.Count -ne 1) {
            throw
        }
    }
    if ($script:PackageEffectAttempts.Count -ne 1) {
        throw 'The package effect observer did not detect its control call.'
    }
    Remove-Item -LiteralPath 'Alias:Invoke-ADAnalyzerPackageGuardProbe'
    $script:PackageEffectAttempts.Clear()
}
if ($null -ne $commandScope) {
    & $commandScope $installGuards $forbidden
}
else {
    . $installGuards $forbidden
    . (Join-Path $package 'bin/ADAnalyzer.ps1')
}

$domain = 'package-smoke.example.invalid'
$inputDirectory = [pscustomobject]@{
    Domain = [pscustomobject]@{
        DNSRoot = $domain
        DistinguishedName = 'DC=package-smoke,DC=example,DC=invalid'
        SID = 'S-1-5-21-1-2-3'
        MachineAccountQuota = 0
    }
    Server = 'dc.' + $domain
    Users = @()
    Groups = @()
    Computers = @()
    ServiceAccounts = @()
    Objects = @()
    Trusts = @()
    Hosts = @()
    Errors = @()
    Coverage = @{
        Domain = 'Collected'
        Acl = 'NotConfigured'
        Hosts = 'NotConfigured'
    }
}
$profileFile = Join-Path $package 'profiles/default.psd1'
$reportFile = Join-Path $output 'assessment.json'
if ($Case -ceq 'Command') {
    $profile = Import-ADAnalyzerProfile -Path $profileFile
    $assessment = Invoke-ADAnalyzerAssessment -DirectoryData $inputDirectory -Target $domain -Profile $profile
    $receipt = @(Export-ADAnalyzerAssessment -Assessment $assessment -Path $reportFile -Format Json -CreateOnly)
}
else {
    $profile = [ADAnalyzerProfile]::Load($profileFile).ToHashtable()
    $assessment = [ADAnalyzerAssessmentEngine]::new($profile).Evaluate($inputDirectory, @(), $domain)
    $receipt = @([ADAnalyzerAssessmentReport]::new().WriteNew($assessment, $reportFile))
}
$loaded = Get-Content -LiteralPath $reportFile -Raw | ConvertFrom-Json
$quota = @($loaded.Checks | Where-Object RuleId -CEQ 'DOMAIN.MACHINE_ACCOUNT_QUOTA')
if ($receipt.Count -ne 1 -or -not $reportFile.Equals($receipt[0], $comparison) -or
    $quota.Count -ne 1 -or $quota[0].Status -cne 'Pass' -or
    $loaded.Target -cne $domain -or $loaded.RunId -cne $assessment.RunId) {
    throw 'The unpacked package did not generate the expected synthetic report and receipt.'
}
$snapshotHash = (Get-FileHash -LiteralPath $reportFile -Algorithm SHA256).Hash
if ($Case -ceq 'Command') {
    $plan = New-ADAnalyzerRemediationPlan -Assessment $reportFile -Profile $profile
    $effects = & $commandScope { $script:PackageEffectAttempts.Count }
}
else {
    $plan = [ADAnalyzerRemediationPlanner]::new().CreatePlan($reportFile, $profile)
    $effects = $script:PackageEffectAttempts.Count
    $binary = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.ActiveDirectory.Management' })
    if ($binary.Count) {
        throw 'The offline constructor route loaded the AD provider assembly.'
    }
}
if ($effects -ne 0 -or $plan.PlanType -cne 'ADAnalyzerRemediationPlan' -or
    $plan.Target -cne $domain -or $plan.AssessmentRunId -cne $loaded.RunId -or
    $plan.Remediation.AllowDisable -ne $false -or $plan.Actions.Count -ne 0 -or
    [IO.Directory]::GetFileSystemEntries($output).Length -ne 1 -or
    (Get-FileHash -LiteralPath $reportFile -Algorithm SHA256).Hash -cne $snapshotHash) {
    throw 'Plan generation lost evidence identity, touched persisted output, or attempted an external effect.'
}
Write-Host ('PASS unpacked package offline report and plan via ' + $Case)
