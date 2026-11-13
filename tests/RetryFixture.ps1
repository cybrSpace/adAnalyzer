param([string]$RepositoryRoot,[string]$Mode)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Cmdlet'},$true)
. ([scriptblock]::Create($function.Extent.Text))
function Assert-Retry($Value,[string]$Message){if(-not $Value){throw $Message}}
$global:RetryCalls=0;$global:RetrySleeps=[Collections.Generic.List[int]]::new()
$global:RetryFailure=[InvalidOperationException]::new('original fixture failure')
function Start-Sleep {
    param([int]$Seconds=-1)
    $global:RetrySleeps.Add($Seconds)
    # Safely bound the old max=0/negative loop; never perform a real wait.
    if($global:RetrySleeps.Count -gt 4){throw 'fixture retry attempt budget exceeded'}
}
if($Mode -eq 'First'){
    $output=@(Invoke-Cmdlet -sb {$global:RetryCalls++;'success'} -retry -max 3)
    Assert-Retry ($global:RetryCalls -eq 1 -and $output.Count -eq 1 -and $output[0] -ceq 'success' -and $global:RetrySleeps.Count -eq 0) 'First success retried or changed output'
}elseif($Mode -eq 'Final'){
    $output=@(Invoke-Cmdlet -sb {$global:RetryCalls++;if($global:RetryCalls -lt 3){throw $global:RetryFailure};'final'} -retry -max 3)
    Assert-Retry ($global:RetryCalls -eq 3 -and $output.Count -eq 1 -and $output[0] -ceq 'final' -and ($global:RetrySleeps -join ',') -eq '1,1') 'Final success was rejected or sleep contract changed'
}elseif($Mode -eq 'Exhausted'){
    $caught=$null;try{Invoke-Cmdlet -sb {$global:RetryCalls++;throw $global:RetryFailure} -retry -max 3 | Out-Null}catch{$caught=$_}
    Assert-Retry ($null -ne $caught -and $global:RetryCalls -eq 3 -and ($global:RetrySleeps -join ',') -eq '1,1') 'Exhaustion count or sleep placement changed'
    Assert-Retry ([object]::ReferenceEquals($caught.Exception.GetBaseException(),$global:RetryFailure)) 'Original terminal exception was replaced'
}elseif($Mode -eq 'NoRetry'){
    $caught=$null;try{Invoke-Cmdlet -sb {$global:RetryCalls++;throw $global:RetryFailure} -max 3 | Out-Null}catch{$caught=$_}
    Assert-Retry ($null -ne $caught -and $global:RetryCalls -eq 1 -and $global:RetrySleeps.Count -eq 0 -and [object]::ReferenceEquals($caught.Exception.GetBaseException(),$global:RetryFailure)) 'Nonretry error swallowed/replaced or block retried'
}elseif($Mode -eq 'Values'){
    foreach($block in @({$false},{0},{},{'one';'two'})){
        $expected=@(& $block);$actual=@(Invoke-Cmdlet -sb $block)
        Assert-Retry ($actual.Count -eq $expected.Count -and ($actual | ConvertTo-Json -Compress) -ceq ($expected | ConvertTo-Json -Compress)) 'False/zero/empty/multiple output changed'
    }
}elseif($Mode -eq 'Invalid'){
    foreach($extra in @(@{max=0},@{max=-1},@{DelaySeconds=-1},@{DelaySeconds=301})){
        $global:RetryCalls=0;$global:RetrySleeps.Clear();$caught=$false
        try{$null=Invoke-Cmdlet -sb {$global:RetryCalls++;throw $global:RetryFailure} -retry @extra}catch{$caught=$true}
        Assert-Retry ($caught -and $global:RetryCalls -eq 0 -and $global:RetrySleeps.Count -eq 0) 'Invalid retry configuration reached block/sleep'
    }
}elseif($Mode -eq 'Partial'){
    $output=@(Invoke-Cmdlet -sb {$global:RetryCalls++;if($global:RetryCalls -lt 2){'discarded';throw $global:RetryFailure};'complete'} -retry -max 3)
    Assert-Retry ($global:RetryCalls -eq 2 -and $output.Count -eq 1 -and $output[0] -ceq 'complete') 'Failed-attempt output leaked'
}elseif($Mode -eq 'NonTerminating'){
    $caught=$null;$preference=$ErrorActionPreference
    try{$ErrorActionPreference='Continue';try{Invoke-Cmdlet -sb {$global:RetryCalls++;Write-Error 'fixture nonterminating error'} | Out-Null}catch{$caught=$_}}finally{$ErrorActionPreference=$preference}
    Assert-Retry ($null -ne $caught -and $global:RetryCalls -eq 1 -and $caught.Exception.Message -match 'fixture nonterminating error') 'Nonterminating failure was swallowed'
}elseif($Mode -eq 'Delay'){
    $output=@(Invoke-Cmdlet -sb {$global:RetryCalls++;if($global:RetryCalls -eq 1){throw $global:RetryFailure};'complete'} -retry -max 3 -DelaySeconds 2)
    Assert-Retry ($global:RetryCalls -eq 2 -and $output.Count -eq 1 -and $output[0] -ceq 'complete' -and ($global:RetrySleeps -join ',') -eq '2') 'Explicit delay contract changed'
}elseif($Mode -eq 'Defaults'){
    $caught=$null;try{Invoke-Cmdlet -sb {$global:RetryCalls++;throw $global:RetryFailure} -retry -DelaySeconds 0 | Out-Null}catch{$caught=$_}
    Assert-Retry ($null -ne $caught -and $global:RetryCalls -eq 3 -and $global:RetrySleeps.Count -eq 0) 'Default attempts or zero delay changed'
}else{throw 'Unknown fixture mode'}
'PASS retry contract '+$Mode
