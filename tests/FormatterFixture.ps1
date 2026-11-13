param([string]$RepositoryRoot,[string]$Mode)
$ErrorActionPreference='Stop'
function Assert-Formatter($Value,[string]$Message){if(-not $Value){throw $Message}}
. (Join-Path $RepositoryRoot 'etc/Test-Runspace.ps1')
$var['attempt']=0
if($Mode -eq 'Known'){
    $constant.property.limit=[int]::MaxValue
    foreach($key in $constant.error.Keys){foreach($value in $constant.error[$key].value){
        $actual=Format-WindowsServerException -value $value
        Assert-Formatter ($actual -ceq ('server_exception('+$constant.error[$key].msg+')')) ('Known classification failed '+$key)
    }}
    Assert-Formatter ($var['attempt'] -eq 3) 'Non-auth error incremented budget or auth error missed'
}elseif($Mode -eq 'Unknown'){
    $message='caller-poison';$value='fixture unknown diagnostic'
    $actual=Format-WindowsServerException -value $value
    Assert-Formatter ($actual -ceq ('server_exception(unknown exception ('+$value+'))') -and $message -ceq 'caller-poison' -and $var['attempt'] -eq 0) 'Unknown input inherited caller state or changed budget'
    $null=Format-WindowsServerException -value $constant.error.denied.value[0]
    $again=Format-WindowsServerException -value $value
    Assert-Formatter ($again -ceq $actual) 'Previous classification leaked'
}elseif($Mode -eq 'Limits'){
    $constant.property.limit=3
    $null=Format-WindowsServerException -value $constant.error['bad.user'].value[0]
    $null=Format-WindowsServerException -value $constant.error.locked.value[0]
    Assert-Formatter ($var['attempt'] -eq 2) 'Shared category counter changed'
    foreach($expected in @(3,4)){
        $caught=$null;try{$null=Format-WindowsServerException -value $constant.error.locked.value[0]}catch{$caught=$_}
        Assert-Formatter ($null -ne $caught -and $caught.Exception.Message -match 'exceeded invalid attempt limit' -and $var['attempt'] -eq $expected) 'Budget boundary/over-limit behavior changed'
    }
    $denied=Format-WindowsServerException -value $constant.error.denied.value[0]
    Assert-Formatter ($denied -ceq 'server_exception(access denied)' -and $var['attempt'] -eq 4) 'Unrelated diagnostic consumed auth budget'
}elseif($Mode -in @('Concurrent','ConcurrentLimit')){
    $constant.property.limit=if($Mode -eq 'Concurrent'){[int]::MaxValue}else{3}
    $definition=(Get-Command Format-WindowsServerException -CommandType Function).Definition
    $definition='function Format-WindowsServerException {'+[Environment]::NewLine+$definition+[Environment]::NewLine+'}'
    $workers=4;$callsPerWorker=if($Mode -eq 'Concurrent'){1000}else{25}
    $referenceId=[Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($var)
    $worker={
        param($definition,$constant,$var,$barrier,[int]$callsPerWorker,[int]$referenceId)
        $ErrorActionPreference='Stop'
        if([Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($var) -ne $referenceId){throw 'Shared table was copied'}
        . ([scriptblock]::Create($definition))
        if(-not $barrier.SignalAndWait(30000)){throw 'Worker start barrier timed out'}
        $allowed=0;$rejected=0
        for($i=0;$i -lt $callsPerWorker;$i++){
            $key=if($i % 2){'bad.user'}else{'locked'}
            try{
                $formatted=Format-WindowsServerException -value $constant.error[$key].value[0]
                if($formatted -cne ('server_exception('+$constant.error[$key].msg+')')){throw 'Worker classification failed'}
                $allowed++
            }catch{
                if($constant.property.limit -ne 3 -or $_.Exception.Message -notmatch 'exceeded invalid attempt limit'){throw}
                $rejected++
            }
        }
        [pscustomobject]@{Completed=($allowed+$rejected);Allowed=$allowed;Rejected=$rejected;SharedReference=$true}
    }
    $pool=$null;$barrier=$null;$jobs=[Collections.Generic.List[object]]::new();$cleanupErrors=[Collections.Generic.List[string]]::new()
    try{
        $barrier=[Threading.Barrier]::new($workers)
        $pool=[Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($workers,$workers)
        $pool.ThreadOptions=[Management.Automation.Runspaces.PSThreadOptions]::UseNewThread
        $pool.Open()
        for($i=0;$i -lt $workers;$i++){
            $shell=[powershell]::Create()
            try{
                $shell.RunspacePool=$pool
                $null=$shell.AddScript($worker.ToString()).AddArgument($definition).AddArgument($constant).AddArgument($var).AddArgument($barrier).AddArgument($callsPerWorker).AddArgument($referenceId)
                $handle=$shell.BeginInvoke()
                $jobs.Add([pscustomobject]@{Shell=$shell;Handle=$handle;Wait=$handle.AsyncWaitHandle})
            }catch{$shell.Dispose();throw}
        }
        $completed=0;$errors=0;$allowed=0;$rejected=0
        foreach($job in $jobs){
            if(-not $job.Wait.WaitOne(30000)){$job.Shell.Stop();throw 'Bounded worker wait timed out'}
            $rows=@($job.Shell.EndInvoke($job.Handle));$errors+=$job.Shell.Streams.Error.Count
            Assert-Formatter ($rows.Count -eq 1 -and $rows[0].SharedReference) 'Worker result was incomplete'
            $completed+=$rows[0].Completed
            $allowed+=$rows[0].Allowed;$rejected+=$rows[0].Rejected
        }
        $expected=$workers*$callsPerWorker
        Assert-Formatter ($errors -eq 0 -and $completed -eq $expected -and $var['attempt'] -eq $expected) ('Concurrent counter mismatch: '+$var['attempt']+' / '+$completed)
        Assert-Formatter ($allowed -eq $(if($Mode -eq 'Concurrent'){4000}else{2}) -and $rejected -eq $(if($Mode -eq 'Concurrent'){0}else{98})) 'Concurrent budget decisions changed'
    }finally{
        foreach($job in $jobs){
            try{if(-not $job.Handle.IsCompleted){$job.Shell.Stop()}}catch{$cleanupErrors.Add('Stop')}
            try{$job.Wait.Dispose()}catch{$cleanupErrors.Add('Wait')}
            try{$job.Shell.Dispose()}catch{$cleanupErrors.Add('PowerShell')}
        }
        if($null -ne $pool){try{$pool.Close()}catch{$cleanupErrors.Add('PoolClose')};try{$pool.Dispose()}catch{$cleanupErrors.Add('PoolDispose')}}
        if($null -ne $barrier){try{$barrier.Dispose()}catch{$cleanupErrors.Add('Barrier')}}
    }
    Assert-Formatter ($cleanupErrors.Count -eq 0) 'Concurrent fixture cleanup failed'
}else{throw 'Unknown fixture mode'}
'PASS formatter contract '+$Mode
