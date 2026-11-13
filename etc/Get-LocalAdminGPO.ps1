[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('Domain','FQDN')][string]$CliDomain,[Alias('Server')][string]$CliServer,
    [Alias('Name')][string]$CliName,[Alias('Guid')][guid]$CliGuid,[Alias('All')][switch]$CliAll,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('InputObject')][object[]]$CliInputObject,[Alias('ProfilePath')][string]$CliProfilePath,
    [Alias('OutputPath')][string]$CliOutputPath,[Alias('Format')][ValidateSet('Json','Html','Csv','All')][string]$CliFormat='Csv'
)
function Get-ADAnalyzerLocalAdminGpo {
    <# Inventory stored local-group configuration and exposure; effective membership is not calculated. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Alias('FQDN')][string]$Domain,[string]$Server,[string]$Name,[guid]$Guid,[switch]$All,
        [pscredential]$Credential=[pscredential]::Empty,[object[]]$InputObject,[string]$ProfilePath,
        [string]$OutputPath,[ValidateSet('Json','Html','Csv','All')][string]$Format='Csv')
    $repository=Split-Path -Parent $PSScriptRoot
    $offline=$PSBoundParameters.ContainsKey('InputObject')
    if($offline){
        foreach($field in @('Domain','Server','Name','Guid','All','Credential')){if($PSBoundParameters.ContainsKey($field)){throw 'Choose InputObject or explicit live target inputs.'}}
        if($null -eq $InputObject){throw 'InputObject requires package Gpo and Policy reports.'}
        foreach($file in @('ADGpo','ADPolicyAnalysis')){. (Join-Path $repository ('bin/'+$file+'.ps1'))}
        $reports=@($InputObject)
    }else{
        if([string]::IsNullOrWhiteSpace($Domain)){throw 'An explicit Domain is required.'}
        if([int]$PSBoundParameters.ContainsKey('Name')+[int]$PSBoundParameters.ContainsKey('Guid')+[int][bool]$All -ne 1){throw 'Select exactly one Name, Guid or All.'}
        if($PSBoundParameters.ContainsKey('Name') -and [string]::IsNullOrWhiteSpace($Name)){throw 'Name cannot be empty.'}
        Import-Module (Join-Path $repository 'ADEnvironment.psd1') -ErrorAction Stop
        $arguments=@{Domain=$Domain;Credential=$Credential}
        if($Server){$arguments.Server=$Server}
        if($All){$arguments.All=$true}elseif($PSBoundParameters.ContainsKey('Guid')){$arguments.Guid=$Guid}else{$arguments.Name=$Name}
        $selected=@(Get-ADAnalyzerGpo @arguments)
        if(-not $All -and $selected.Count -ne 1){throw 'GPO was not found or the selector was ambiguous.'}
        $reports=@(foreach($gpo in $selected){
            try{Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $Credential -AsObject}
            catch{[pscustomobject]@{Gpo=$gpo;Policy=$null;ReadError=$true;ErrorType=$_.Exception.GetType().FullName}}
        })
    }
    # The manifest intentionally exports public APIs only. These transport-free
    # helpers stay local to the adapter, including when a live module is loaded.
    foreach($file in @('ADProfile','ADOperations')){. (Join-Path $repository ('bin/'+$file+'.ps1'))}
    $profile=if($ProfilePath){Import-ADAnalyzerProfile -Path $ProfilePath}else{Import-ADAnalyzerProfile}
    $rows=@(foreach($report in $reports){
        $id=[guid]::Empty
        if($null -eq $report.Gpo -or -not [guid]::TryParse([string]$report.Gpo.Id,[ref]$id)){throw 'Each report requires a valid GPO identity.'}
        if($offline){
            $flags=0
            if(-not [int]::TryParse([string]$report.Gpo.Flags,[ref]$flags) -or $flags -lt 0 -or $flags -gt 3){throw 'Offline inventory requires supplied GPO Flags (0..3).'}
        }
        $metadata=[ordered]@{}
        foreach($field in @('Id','DisplayName','Domain','Server','Flags','Version','Links','WmiFilter')){$metadata[$field]=$report.Gpo.$field}
        if($report.ReadError -or $null -eq $report.Policy){
            $checks=@(New-ADAnalyzerCheck -RuleId GPO.READ -Status Unreadable -Severity High -Category PolicyCoverage -Target $id.ToString('D') -Message 'The selected GPO could not be read; configuration was not assessed.' -Evidence @{ErrorType=$report.ErrorType})
        }else{
            $policy=if($offline){ConvertTo-ADAnalyzerProvidedGpoPolicy -Policy $report.Policy}else{$report.Policy}
            $checks=@(Test-ADAnalyzerGpoPolicy -Gpo $report.Gpo -Policy $policy -Profile $profile | Where-Object {
                $_.RuleId -in @('GPO.RestrictedGroups.LocalAdministrators','GPO.Preferences.LocalUsersGroups') -or $_.Category -in @('CredentialExposure','PolicyCoverage')
            })
        }
        foreach($check in $checks){
            $check.Evidence=[pscustomobject]@{Gpo=[pscustomobject]$metadata;ConfiguredSetting=$check.Observed;RuleEvidence=$check.Evidence}
            $check | Add-Member -NotePropertyName GpoId -NotePropertyValue $id.ToString('D')
            $check | Add-Member -NotePropertyName GpoName -NotePropertyValue ([string]$report.Gpo.DisplayName)
            $check | Add-Member -NotePropertyName MetadataStatus -NotePropertyValue $(if($offline){'Provided'}else{'Collected'})
            ConvertTo-ADAnalyzerSafeData $check
        }
    })
    $unreadable=@($rows | Where-Object Status -eq Unreadable)
    if($OutputPath){
        if($unreadable.Count){throw 'GPO inventory is incomplete; the previous report was preserved.'}
        $state=if(@($rows | Where-Object Status -in 'Unknown','Invalid').Count){'Partial'}else{'Complete'}
        $assessment=[pscustomobject]@{SchemaVersion=1;Target=$(if($offline){'provided GPO reports'}else{$Domain});State=$state;Checks=$rows;Findings=$rows;Errors=@();Coverage=@{Total=$rows.Count}}
        $null=Export-ADAnalyzerAssessment -Assessment $assessment -Path $OutputPath -Format $Format -WhatIf:$WhatIfPreference -Confirm:$false
    }
    return $rows
}
if($MyInvocation.InvocationName -ne '.'){
    $arguments=@{Format=$CliFormat}
    foreach($name in @('Domain','Server','Name','Guid','All','Credential','InputObject','ProfilePath','OutputPath')){
        if($PSBoundParameters.ContainsKey('Cli'+$name)){$arguments[$name]=Get-Variable -Name ('Cli'+$name) -ValueOnly}
    }
    $arguments.WhatIf=[bool]$WhatIfPreference
    if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
    Get-ADAnalyzerLocalAdminGpo @arguments
}
