[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('Operation')][ValidateSet('assess','report','plan','remediate','apply','undo','prerequisites')][string]$CliOperation='assess',
    [Alias('Domain','FQDN')][string]$CliFQDN,[Alias('Server')][string]$CliServer,[Alias('SearchBase')][string]$CliSearchBase,[Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('ProfilePath')][string]$CliProfilePath,[Alias('OutputPath')][string]$CliOutputPath,[Alias('PlanPath')][string]$CliPlanPath,[Alias('JournalPath')][string]$CliJournalPath,[Alias('ReferencePath')][string]$CliReferencePath,
    [Alias('IncludeAcl')][switch]$CliIncludeAcl,[Alias('IncludeHostChecks')][switch]$CliIncludeHostChecks,[Alias('SkipGpo')][switch]$CliSkipGpo,[Alias('Online')][switch]$CliOnline,[Alias('PassThru')][switch]$CliPassThru,[Alias('FailOnFindings')][switch]$CliFailOnFindings
)

function Start-ADAnalyzer {
    <#
    .SYNOPSIS
    Collects and evaluates AD hardening evidence, or executes a reviewed plan.
    .DESCRIPTION
    No interactive credential prompt or caller-state cleanup is performed.
    Assess/report collect read-only snapshots. Plan/remediate produce an inert
    plan; only apply executes approved DisableAccount actions from a plan file.
    The function throws on collection/export errors and never exits its caller.
    #>
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    param(
        [ValidateSet('assess','report','plan','remediate','apply','undo','prerequisites')][string]$Operation='assess',
        [Alias('Domain')][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')][string]$FQDN,
        [string]$Server,[string]$SearchBase,[pscredential]$Credential=[pscredential]::Empty,
        [string]$ProfilePath,[string]$OutputPath,[string]$PlanPath,[string]$JournalPath,[string]$ReferencePath,
        [switch]$IncludeAcl,[switch]$IncludeHostChecks,[switch]$SkipGpo,[switch]$Online
    )
    $repository=Split-Path -Parent $PSScriptRoot
    if($Operation -eq 'prerequisites') {
        if(-not (Get-Command Get-ADAnalyzerPrerequisite -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'ADProfile.ps1')}
        $configuration=if($ProfilePath){Import-ADAnalyzerProfile -Path $ProfilePath}else{Import-ADAnalyzerProfile}
        if(-not $Server){$Server=$FQDN};if(-not $Server){$Server=$configuration.Targets.Server};if(-not $Server){$Server=$configuration.Targets.Domain}
        return @(Get-ADAnalyzerPrerequisite -RepositoryRoot $repository -Server $Server -Credential $Credential -Online:$Online -Profile $configuration)
    }
    if(-not (Get-Command Get-ADAnalyzerAssessment -ErrorAction SilentlyContinue)) {
        Import-Module (Join-Path $repository 'ADEnvironment.psd1') -ErrorAction Stop
    }
    $profile=if($ProfilePath){Import-ADAnalyzerProfile -Path $ProfilePath}else{Import-ADAnalyzerProfile}
    if($Operation -eq 'apply') {
        if(-not $PlanPath -or -not $JournalPath){throw 'Apply requires PlanPath and JournalPath'}
        if(-not $Server){$Server=$profile.Targets.Server};if(-not $Server){$Server=$FQDN}
        $arguments=@{Plan=$PlanPath;Server=$Server;Credential=$Credential;JournalPath=$JournalPath;WhatIf=[bool]$WhatIfPreference}
        if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
        return Invoke-ADAnalyzerRemediationPlan @arguments
    }
    if($Operation -eq 'undo') {
        if(-not $JournalPath){throw 'Undo requires JournalPath'}
        if(-not $Server){$Server=$profile.Targets.Server};if(-not $Server){$Server=$FQDN}
        $arguments=@{JournalPath=$JournalPath;Server=$Server;Credential=$Credential;WhatIf=[bool]$WhatIfPreference}
        if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
        return Undo-ADAnalyzerRemediation @arguments
    }
    $arguments=@{Credential=$Credential;Profile=$profile;IncludeAcl=$IncludeAcl;IncludeHostChecks=$IncludeHostChecks;SkipGpo=$SkipGpo}
    if($FQDN){$arguments.Domain=$FQDN};if($Server){$arguments.Server=$Server};if($SearchBase){$arguments.SearchBase=$SearchBase}
    $assessment=Get-ADAnalyzerAssessment @arguments
    if($Operation -in 'plan','remediate') {
        $result=New-ADAnalyzerRemediationPlan -Assessment $assessment -Profile $profile
        if($OutputPath) {
            if($PSCmdlet.ShouldProcess($OutputPath,'Export reviewed remediation plan')) {
                $safe=ConvertTo-ADAnalyzerSafeData -InputObject $result
                $null=Write-ADAnalyzerOperationFile -Path $OutputPath -Content (ConvertTo-Json -InputObject $safe -Depth 100)
            }
        }
        return $result
    }
    if($ReferencePath){$assessment | Add-Member -NotePropertyName Comparison -NotePropertyValue (Compare-ADAnalyzerAssessment -Reference $ReferencePath -Difference $assessment)}
    if($OutputPath){$null=Export-ADAnalyzerAssessment -Assessment $assessment -Path $OutputPath -Format All -WhatIf:$WhatIfPreference -Confirm:$false}
    return $assessment
}

# Dot sourcing exposes the function only. Running the script is an unattended
# CLI with explicit exit semantics; it does not clear modules or change location.
if($MyInvocation.InvocationName -ne '.') {
    try {
        $arguments=@{Operation=$CliOperation;Credential=$CliCredential;IncludeAcl=$CliIncludeAcl;IncludeHostChecks=$CliIncludeHostChecks;SkipGpo=$CliSkipGpo;Online=$CliOnline;WhatIf=[bool]$WhatIfPreference}
        foreach($name in @('FQDN','Server','SearchBase','ProfilePath','OutputPath','PlanPath','JournalPath','ReferencePath')){if(Get-Variable -Name ('Cli'+$name) -ValueOnly){$arguments[$name]=Get-Variable -Name ('Cli'+$name) -ValueOnly}}
        if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
        $result=Start-ADAnalyzer @arguments
        if($CliPassThru){$result}else{$result | Select-Object RunId,Target,State,Coverage,Summary | Format-List | Out-Host}
        if($result.State -eq 'Failed'){exit 1}
        if($result.State -eq 'Partial'){exit 2}
        if($CliOperation -eq 'prerequisites' -and @($result | Where-Object { $_.Status -in 'Fail','Unreadable' }).Count){exit 2}
        if($CliFailOnFindings -and @($result.Findings | Where-Object { $_.Status -in 'Fail','Invalid' -and -not $_.Suppressed }).Count){exit 3}
    } catch {
        Write-Error -ErrorRecord $_ -ErrorAction Continue
        exit 1
    }
}
