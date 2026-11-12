BeforeAll {
    $repository=Split-Path -Parent $PSScriptRoot
    foreach($name in @('ADProfile','ADGpo','ADPolicyAnalysis','ADDirectoryAnalysis','ADHostAnalysis','ADOperations','ADAssessment')){. (Join-Path $repository ('bin/'+$name+'.ps1'))}
}
Describe 'RSAT-free assessment invariants' {
    It 'returns independent nested profile graphs' {
        $a=Get-ADAnalyzerDefaultProfile;$b=Get-ADAnalyzerDefaultProfile;$a.Policy.MinimumPasswordLength=99
        $b.Policy.MinimumPasswordLength | Should -Be 12
    }
    It 'rejects executable profiles' {
        {Import-ADAnalyzerProfile -Path 'untrusted.ps1'} | Should -Throw
    }
    It 'rejects misspelled configuration rather than ignoring it' {
        {Import-ADAnalyzerProfile -Profile @{Policy=@{LockoutThreshhold=10}}} | Should -Throw
    }
    It 'keeps source evidence unchanged while projecting exported XML to boolean presence' {
        $source=[pscustomobject]@{Value='<Item cpassword="fixture-secret" />';Members=@('one','two')}
        $safe=ConvertTo-ADAnalyzerSafeData -InputObject $source
        $safe.Value | Should -Not -Match 'fixture-secret'
        $source.Value | Should -Match 'fixture-secret'
        $source.Members.Count | Should -Be 2
    }
    It 'uses stable identities across status changes' {
        $a=New-ADAnalyzerCheck -RuleId 'One' -Target 'Fixture' -Status Pass
        $b=New-ADAnalyzerCheck -RuleId 'one' -Target 'fixture' -Status Fail
        $a.CheckId | Should -Be $b.CheckId
    }
    It 'leaves account roles unknown without explicit classification evidence' {
        $object=[pscustomobject]@{SamAccountName='adoe';GivenName='Alice';Surname='Doe';DistinguishedName='CN=Alice,DC=example,DC=invalid'}
        (Get-ADAnalyzerAccountType -Object $object -Profile (Get-ADAnalyzerDefaultProfile)).Type | Should -Be 'Unknown'
    }
    It 'defaults remediation to an inert plan' {
        $assessment=[pscustomobject]@{SchemaVersion=1;Target='example.invalid';Findings=@();Objects=@()}
        $plan=New-ADAnalyzerRemediationPlan -Assessment $assessment -Profile (Get-ADAnalyzerDefaultProfile)
        @($plan.Actions).Count | Should -Be 0
    }
    It 'does not import installed RSAT or invoke GPMC in production reader extensions' {
        $text=@('ADProfile','ADGpo','ADPolicyAnalysis','ADDirectoryAnalysis','ADOperations','ADAssessment') | ForEach-Object {Get-Content -LiteralPath (Join-Path $repository ('bin/'+$_.ToString()+'.ps1')) -Raw}
        ($text -join "`n") | Should -Not -Match '(?i)Import-Module\s+(?:ActiveDirectory|GroupPolicy)\b|\bGet-GPOReport\b|New-Object\s+-ComObject'
    }
}
