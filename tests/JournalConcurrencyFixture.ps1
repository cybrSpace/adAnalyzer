[CmdletBinding()]
param([string]$RepositoryRoot,[string]$Coordination,[string]$JournalPath,[string]$Role,[ValidateSet('Apply','Undo')][string]$Operation)
$ErrorActionPreference='Stop'
. (Join-Path $RepositoryRoot 'bin/ADProfile.ps1')
. (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
$script:Reads=0
function Wait-FixtureFile([string]$Name){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath (Join-Path $Coordination $Name))){
        if($watch.Elapsed.TotalSeconds -gt 15){throw 'Fixture coordination timed out'}
        Start-Sleep -Milliseconds 25
    }
}
function Read-FixtureState {Get-Content -LiteralPath (Join-Path $Coordination 'state.json') -Raw | ConvertFrom-Json}
function Get-ADObject {
    param($Identity,$Properties,$Server,$Credential,$ErrorAction)
    $script:Reads++
    [IO.File]::AppendAllText((Join-Path $Coordination ($Role+'-reads.txt')),"read"+[Environment]::NewLine)
    if($script:Reads -eq 1){
        [IO.File]::WriteAllText((Join-Path $Coordination ($Role+'-ready')),'ready')
        Wait-FixtureFile ($Role+'-release')
    }
    $state=Read-FixtureState
    if([string]$Identity -ne $state.ObjectGuid -or $Server -ne 'dc.example.invalid'){throw 'Unexpected fixture query'}
    $state
}
function Get-ADGroup {
    param($Filter,$Properties,$Server,$Credential,$ErrorAction)
    [pscustomobject]@{SID='S-1-5-21-10-20-30-512';Members=@();MemberOf=@()}
}
function Resolve-ADAnalyzerMembership {
    param($Object,$Groups,$DomainSid,$PrivilegedSids)
    [pscustomobject]@{IsPrivileged=$false;Unresolved=@();EffectiveSids=@();DirectSids=@();Cycles=@()}
}
function Get-ADAnalyzerAccountType {param($Object,$Profile,$Membership) [pscustomobject]@{Type='User'}}
function Set-FixtureEnabled([bool]$Enabled){
    $state=Read-FixtureState
    $state.Enabled=$Enabled;$state.UserAccountControl=if($Enabled){512}else{514}
    $state.WhenChanged=([datetime]$state.WhenChanged).AddSeconds(1).ToString('o')
    [IO.File]::WriteAllText((Join-Path $Coordination 'state.json'),(ConvertTo-Json -InputObject $state -Depth 30))
    [IO.File]::AppendAllText((Join-Path $Coordination 'mutations.txt'),([string]$Enabled)+[Environment]::NewLine)
}
function Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess=$true)]param($Identity,$Server,$Credential)
    $journal=Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
    if($journal.Entries[-1].Status -ne 'Prepared'){throw 'No durable apply intent'}
    Set-FixtureEnabled $false
}
function Enable-ADAccount {
    [CmdletBinding(SupportsShouldProcess=$true)]param($Identity,$Server,$Credential)
    $journal=Get-Content -LiteralPath $JournalPath -Raw | ConvertFrom-Json
    if($journal.Entries[0].Undo.Status -ne 'Prepared'){throw 'No durable undo intent'}
    Set-FixtureEnabled $true
}
try{
    if($Operation -eq 'Apply'){
        $null=Invoke-ADAnalyzerRemediationPlan -Plan (Join-Path $Coordination 'plan.json') -Server dc.example.invalid -JournalPath $JournalPath -Confirm:$false
    }else{
        $null=Undo-ADAnalyzerRemediation -JournalPath $JournalPath -Server dc.example.invalid -Confirm:$false
    }
}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}
