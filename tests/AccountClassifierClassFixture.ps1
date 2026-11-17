[CmdletBinding()]
param(
    [ValidateSet('Construction',
        'Parity',
        'Types',
        'Isolation',
        'Secrets',
        'Ownership',
        'Serialization',
        'Command',
        'DirectoryRoute',
        'Errors',
        'RecordBaseline')]
    [string]$Case = 'Construction'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$script:UnexpectedCalls = 0

function Stop-ClassifierEffect {
    $script:UnexpectedCalls++
    throw 'Unexpected classifier integration call.'
}

function Get-ADUser {
    Stop-ClassifierEffect
}

function Get-ADGroup {
    Stop-ClassifierEffect
}

function Get-GPO {
    Stop-ClassifierEffect
}

function Get-CimInstance {
    Stop-ClassifierEffect
}

function Get-Credential {
    Stop-ClassifierEffect
}

function Read-Host {
    Stop-ClassifierEffect
}

if ($Case -eq 'DirectoryRoute') {
    . (Join-Path $repositoryRoot 'bin/ADProfile.ps1')
    . (Join-Path $repositoryRoot 'bin/ADDirectoryAnalysis.ps1')
}
else {
    . (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
}

function Assert-Classifier($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function New-ClassifierScenario($Name, $Object, $Profile, $Membership = $null) {
    [pscustomobject]@{
        Name = $Name
        Object = $Object
        Profile = $Profile
        Membership = $Membership
    }
}

function Get-ClassifierScenarios {
    New-ClassifierScenario 'Null' $null $null
    New-ClassifierScenario 'Empty' ([pscustomobject]@{}) @{}
    foreach ($schema in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) {
        New-ClassifierScenario $schema ([pscustomobject]@{
                DirectoryObjectClass = $schema
            }) $null
    }
    New-ClassifierScenario 'OrdinaryObjectClass' ([pscustomobject]@{
            ObjectClass = 'msDS-GroupManagedServiceAccount'
        }) $null
    foreach ($dn in @('OU=People,DC=example', 'CN=Alice,ou=people,dc=example', 'CN=Alice,OU=NotPeople,DC=example')) {
        New-ClassifierScenario ('OU:' + $dn) ([pscustomobject]@{
                DistinguishedName = $dn
            }) @{
            AccountClassification = @{
                UserOUs = @($null, '', 'OU=People,DC=example')
            }
        }
    }
    New-ClassifierScenario 'Groups' ([pscustomobject]@{
            MemberOf = @('cn=tag', $null, '')
        }) @{
        AccountClassification = @{
            UserGroups = @($null, '', 'CN=Tag', 'CN=Tag')
            ServiceGroups = @('S-1-5-21-1-2-3-512')
        }
    } ([pscustomobject]@{
            EffectiveSids = @('S-1-5-21-1-2-3-512')
        })
    New-ClassifierScenario 'AbsentGroups' ([pscustomobject]@{
            MemberOf = $null
        }) @{
        AccountClassification = @{
            UserGroups = $null
            ServiceGroups = @('', $null)
        }
    } ([pscustomobject]@{
            EffectiveSids = @($null, '')
        })
    New-ClassifierScenario 'Coercion' ([pscustomobject]@{
            Zero = 0
            False = $false
            Values = @('a', 'b')
        }) @{
        AccountClassification = @{
            AttributeRules = @(
                @{
                    Attribute = 'Zero'
                    Type = 'service'
                    Value = '0'
                },
                @{
                    Attribute = 'False'
                    Type = 'Service'
                    Value = 'false'
                    Match = 'Unknown'
                },
                @{
                    Attribute = 'Values'
                    Type = 'Service'
                    Value = 'a b'
                    Match = 'Equals'
                }
            )
        }
    }
    New-ClassifierScenario 'Regex' ([pscustomobject]@{
            Role = 'ops'
        }) @{
        AccountClassification = @{
            AttributeRules = @(
                @{
                    Attribute = 'Role'
                    Type = 'Service'
                    Value = '^op'
                    Match = 'Regex'
                },
                @{
                    Attribute = 'Role'
                    Type = 'User'
                    Value = '^admin$'
                    Match = 'Regex'
                },
                @{
                    Attribute = 'Role'
                    Type = 'User'
                    Value = '['
                    Match = 'Regex'
                }
            )
        }
    }
    New-ClassifierScenario 'NullRegex' $null @{
        AccountClassification = @{
            AttributeRules = @(
                @{
                    Attribute = 'Role'
                    Type = 'Service'
                    Value = '^$'
                    Match = 'Regex'
                }
            )
        }
    }
    New-ClassifierScenario 'SkippedAndForbidden' ([pscustomobject]@{
            Password = 'fixture-value-not-read'
        }) @{
        AccountClassification = @{
            AttributeRules = @(
                @{
                    Type = 'User'
                },
                @{
                    Attribute = 'Role'
                    Type = 'Other'
                },
                @{
                    Attribute = 'Password'
                    Type = 'User'
                    Value = 'unused'
                },
                @{
                    Attribute = 'Invalid.Name'
                    Type = 'User'
                    Value = 'unused'
                }
            )
        }
    }
    New-ClassifierScenario 'OrderedConflict' ([pscustomobject]@{
            DirectoryObjectClass = 'msDS-GroupManagedServiceAccount'
            DistinguishedName = 'CN=App,OU=Svc,DC=example'
            MemberOf = @('CN=Tag')
            Role = 'ops'
        }) @{
        AccountClassification = @{
            UserGroups = @('CN=Tag')
            ServiceOUs = @('OU=Svc,DC=example')
            ServiceGroups = @('S-1-5-21-1-2-3-512')
            AttributeRules = @(
                @{
                    Attribute = 'Role'
                    Type = 'Service'
                    Value = 'ops'
                },
                @{
                    Attribute = 'Role'
                    Type = 'User'
                    Match = 'Regex'
                    Value = '['
                },
                @{
                    Attribute = 'Password'
                    Type = 'User'
                    Value = 'unused'
                }
            )
        }
    } ([pscustomobject]@{
            EffectiveSids = @('S-1-5-21-1-2-3-512')
        })
    New-ClassifierScenario 'RawObjectExpected' ([pscustomobject]@{
            Label = [pscustomobject]@{
                Code = 'svc'
            }
        }) @{
        AccountClassification = @{
            AttributeRules = @(
                @{
                    Attribute = 'Label'
                    Type = 'Service'
                    Value = [pscustomobject]@{
                        Code = 'svc'
                    }
                }
            )
        }
    }
}

function ConvertTo-ClassifierJson($Value) {
    ConvertTo-Json -InputObject $Value -Depth 30 -Compress
}

function New-ClassifierBrokenObject {
    if (-not ('ADAnalyzer.ClassifierFixture.BrokenText' -as [type])) {
        Add-Type `
            -TypeDefinition 'namespace ADAnalyzer.ClassifierFixture { public sealed class BrokenText { public override string ToString() { throw new System.InvalidOperationException("fixture conversion failure"); } } }'
    }
    [pscustomobject]@{
        DirectoryObjectClass = [ADAnalyzer.ClassifierFixture.BrokenText]::new()
    }
}

function Get-ClassifierErrorContract([string]$Preference) {
    $diagnostics = @()
    $rows = @()
    $caught = $null
    try {
        $parameters = @{
            Object = New-ClassifierBrokenObject
            Profile = @{}
            ErrorAction = $Preference
            ErrorVariable = 'diagnostics'
        }
        $rows = @(Get-ADAnalyzerAccountType @parameters 2>$null)
    }
    catch {
        $caught = $_
    }
    [pscustomobject]@{
        Preference = $Preference
        Terminated = $null -ne $caught
        Rows = $rows.Count
        Diagnostics = $diagnostics.Count
        Category = [string]$caught.CategoryInfo.Category
        Reason = [string]$caught.CategoryInfo.Reason
        MessageIdentifiesString = $caught.Exception.Message -like '*System.String*'
    }
}

if ($Case -eq 'RecordBaseline') {
    Assert-Classifier (-not ('ADAnalyzerAccountClassifier' -as [type])) 'Capture goldens only from the original corrected function.'
    $results = @(
        foreach ($scenario in @(Get-ClassifierScenarios)) {
            $result = Get-ADAnalyzerAccountType -Object $scenario.Object -Profile $scenario.Profile -Membership $scenario.Membership
            [pscustomobject]@{
                Name = $scenario.Name
                Result = $result
            }
        }
    )
    $baseline = [pscustomobject]@{
        Source = '3a8e8aa3bc0bb5c9e050bc22114554ecc9b75ca1'
        Results = $results
        Errors = @(
            Get-ClassifierErrorContract 'Continue'
            Get-ClassifierErrorContract 'Stop'
        )
    }
    $json = ConvertTo-Json -InputObject $baseline -Depth 30
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'AccountClassifierClassBaseline.json'), $json, [Text.UTF8Encoding]::new($true))
    Write-Host ('PASS classifier baseline captured ' + $results.Count)
    return
}

Assert-Classifier ([bool]('ADAnalyzerAccountClassifier' -as [type])) 'Constructor-based classifier is missing.'
$classifier = [ADAnalyzerAccountClassifier]::new()

switch ($Case) {
    'Construction' {
        Assert-Classifier ($classifier.Classify($null).Type -eq 'Unknown') 'Default invocation changed.'
        Assert-Classifier ($classifier.Classify($null, $null).Type -eq 'Unknown') 'Explicit null profile changed.'
        Assert-Classifier ($classifier.Classify([pscustomobject]@{
                    DirectoryObjectClass = 'msDS-ManagedServiceAccount'
                }).Type -eq 'Service') 'Default schema classification changed.'
        Assert-Classifier (@($classifier.PSObject.Properties).Count -eq 0) 'Classifier retains state.'
        Assert-Classifier (@(Get-Module ActiveDirectory, GroupPolicy).Count -eq 0) 'Loading imported an RSAT module.'
    }

    'DirectoryRoute' {
        $result = $classifier.Classify([pscustomobject]@{
                MemberOf = @('CN=Tag')
            }, @{
                AccountClassification = @{
                    UserGroups = @('cn=tag')
                }
            })
        Assert-Classifier ($result.Type -eq 'User') 'Directory-only literal type loading failed.'
        Assert-Classifier (@(Get-Module ActiveDirectory, GroupPolicy).Count -eq 0) 'Directory-only route imported RSAT.'
    }

    'Parity' {
        $baseline = Get-Content `
            -LiteralPath (Join-Path $PSScriptRoot 'AccountClassifierClassBaseline.json') `
            -Raw `
            -Encoding UTF8 | ConvertFrom-Json
        $scenarios = @(Get-ClassifierScenarios)
        Assert-Classifier ($scenarios.Count -eq 16 -and $baseline.Results.Count -eq 16) 'Original scenario count changed.'
        for ($i = 0; $i -lt $scenarios.Count; $i++) {
            $scenario = $scenarios[$i]
            Assert-Classifier ($baseline.Results[$i].Name -ceq $scenario.Name) 'Scenario ordering changed.'
            $before = ConvertTo-ClassifierJson @($scenario.Object, $scenario.Profile, $scenario.Membership)
            $expected = ConvertTo-ClassifierJson $baseline.Results[$i].Result
            $direct = $classifier.Classify($scenario.Object, $scenario.Profile, $scenario.Membership)
            $compatibility = Get-ADAnalyzerAccountType -Object $scenario.Object -Profile $scenario.Profile -Membership $scenario.Membership
            Assert-Classifier ($expected -ceq (ConvertTo-ClassifierJson $direct)) ('Direct golden mismatch: ' + $scenario.Name)
            Assert-Classifier ($expected -ceq (ConvertTo-ClassifierJson $compatibility)) ('Command golden mismatch: ' + $scenario.Name)
            Assert-Classifier ($before -ceq (ConvertTo-ClassifierJson @($scenario.Object,
                        $scenario.Profile,
                        $scenario.Membership))) 'Classification mutated inputs.'
        }
    }

    'Types' {
        foreach ($scenario in @(Get-ClassifierScenarios)) {
            $result = $classifier.Classify($scenario.Object, $scenario.Profile, $scenario.Membership)
            Assert-Classifier (($result.PSObject.Properties.Name -join ',') -ceq 'Type,Evidence,Conflicting,InvalidRules') 'Result schema changed.'
            Assert-Classifier ($result.Type -is [string] -and
                $result.Evidence -is [object[]] -and
                $result.Conflicting -is [bool] -and
                $result.InvalidRules -is [string[]]) 'Result field types changed.'
            foreach ($row in $result.Evidence) {
                Assert-Classifier (($row.PSObject.Properties.Name -join ',') -ceq 'Type,Source,Value') 'Evidence schema changed.'
                Assert-Classifier ($row.Type -is [string] -and $row.Source -is [string]) 'Evidence labels changed type.'
            }
            if ($scenario.Name -eq 'Coercion') {
                Assert-Classifier ($result.Type -ceq 'Unknown' -and $result.Conflicting) 'Case-distinct type conflict changed.'
                Assert-Classifier ($result.Evidence[0].Type -ceq 'service' -and
                    $result.Evidence[1].Type -ceq 'Service') 'Configured evidence type spelling changed.'
                Assert-Classifier ($result.Evidence.Count -eq 3) 'Coercion evidence changed.'
                Assert-Classifier ($result.Evidence[0].Value -is [int] -and $result.Evidence[0].Value -eq 0) 'Numeric zero lost.'
                Assert-Classifier ($result.Evidence[1].Value -is [bool] -and -not $result.Evidence[1].Value) 'Boolean false lost.'
                Assert-Classifier ($result.Evidence[2].Value -is [object[]]) 'Multi-value type changed.'
            }
            if ($scenario.Name -eq 'RawObjectExpected') {
                Assert-Classifier ($result.Type -eq 'Service') 'Raw PSCustomObject expected value was normalized.'
                Assert-Classifier ([object]::ReferenceEquals($result.Evidence[0].Value,
                        $scenario.Object.Label)) 'Accepted raw evidence reference contract changed.'
            }
            if ($scenario.Name -eq 'NullRegex') {
                Assert-Classifier ($result.Type -eq 'Service' -and
                    $null -eq $result.Evidence[0].Value) 'Null-object Regex contract changed.'
            }
        }
    }

    'Isolation' {
        $other = [ADAnalyzerAccountClassifier]::new()
        $profile = @{
            AccountClassification = @{
                UserGroups = @('CN=Tag')
            }
        }
        $object = [pscustomobject]@{
            MemberOf = @('CN=Tag')
        }
        $before = ConvertTo-ClassifierJson @($object, $profile)
        $first = $classifier.Classify($object, $profile)
        $second = $other.Classify($object, $profile)
        Assert-Classifier (-not [object]::ReferenceEquals($first, $second)) 'Instances share results.'
        Assert-Classifier (-not [object]::ReferenceEquals($first.Evidence, $second.Evidence)) 'Instances share evidence containers.'
        $first.Type = 'Changed'
        $first.Evidence[0].Type = 'Changed'
        Assert-Classifier ($second.Type -eq 'User' -and $second.Evidence[0].Type -eq 'User') 'Result edits leaked across instances.'
        Assert-Classifier ($before -ceq (ConvertTo-ClassifierJson @($object, $profile))) 'Result mutation altered inputs.'
        $profile.AccountClassification.UserGroups = @('CN=Other')
        Assert-Classifier ($classifier.Classify($object, $profile).Type -eq 'Unknown') 'Reused instance retained stale rules.'
        $object.MemberOf = @('CN=Other')
        for ($i = 0; $i -lt 3; $i++) {
            $result = $classifier.Classify($object, $profile)
            Assert-Classifier ($result.Type -eq 'User' -and $result.Evidence.Count -eq 1) 'Repeated invocation accumulated evidence.'
        }
        Assert-Classifier ($classifier.Classify($null, @{}).Evidence.Count -eq 0) 'Prior results survived an empty call.'
    }

    'Secrets' {
        $script:SecretReads = 0
        $object = [pscustomobject]@{}
        $object | Add-Member ScriptProperty Password {
            $script:SecretReads++
            throw 'Forbidden secret getter was read.'
        }
        $profile = @{
            AccountClassification = @{
                AttributeRules = @(
                    @{
                        Attribute = 'Password'
                        Type = 'User'
                        Value = 'fixture-not-read'
                    }
                )
            }
        }
        $result = $classifier.Classify($object, $profile)
        Assert-Classifier ($result.Type -eq 'Unknown' -and
            $result.InvalidRules.Count -eq 1 -and
            $result.InvalidRules[0] -eq 'Password') 'Forbidden attribute was not rejected.'
        Assert-Classifier ($script:SecretReads -eq 0) 'Classification accessed a forbidden attribute.'
    }

    'Ownership' {

        function Get-ADAnalyzerAccountType {
            Stop-ClassifierEffect
        }

        function Import-ADAnalyzerProfile {
            Stop-ClassifierEffect
        }

        function Get-Content {
            Stop-ClassifierEffect
        }

        function Import-Module {
            Stop-ClassifierEffect
        }

        function Export-Clixml {
            Stop-ClassifierEffect
        }

        function Set-Content {
            Stop-ClassifierEffect
        }

        function New-PSDrive {
            Stop-ClassifierEffect
        }
        $owned = [ADAnalyzerAccountClassifier]::new()
        $result = $owned.Classify([pscustomobject]@{
                Role = 'ops'
            }, @{
                AccountClassification = @{
                    AttributeRules = @(
                        @{
                            Attribute = 'Role'
                            Type = 'Service'
                            Value = 'ops'
                        }
                    )
                }
            })
        Assert-Classifier ($result.Type -eq 'Service') 'Class delegates processing to an old engine.'
        Assert-Classifier ($owned.Classify($null).Type -eq 'Unknown') 'Default method delegates to old engine.'
    }

    'Serialization' {
        $marker = 'CLASSIFIER_STATE_MUST_NOT_RETAIN_INPUT'
        $profile = @{
            Ignored = $marker
            AccountClassification = @{
                AttributeRules = @(
                    @{
                        Attribute = 'Password'
                        Type = 'User'
                        Value = $marker
                    }
                )
            }
        }
        $beforeJson = ConvertTo-ClassifierJson $classifier
        $beforeXml = [Management.Automation.PSSerializer]::Serialize($classifier)
        $null = $classifier.Classify([pscustomobject]@{
                Password = $marker
            }, $profile)
        $broken = New-ClassifierBrokenObject
        $thrown = $false
        try {
            $null = $classifier.Classify($broken, $profile)
        }
        catch {
            $thrown = $true
            Assert-Classifier ($_.ToString() -notlike ('*' + $marker + '*')) 'Error exposed raw configuration.'
        }
        Assert-Classifier $thrown 'Conversion failure did not propagate.'
        $afterJson = ConvertTo-ClassifierJson $classifier
        $afterXml = [Management.Automation.PSSerializer]::Serialize($classifier)
        Assert-Classifier ($beforeJson -ceq '{}' -and $beforeJson -ceq $afterJson) 'Classifier JSON retains input state.'
        Assert-Classifier ($beforeXml -ceq $afterXml -and -not $afterXml.Contains($marker)) 'Classifier CLIXML retains input state.'
    }

    'Errors' {
        $baseline = Get-Content `
            -LiteralPath (Join-Path $PSScriptRoot 'AccountClassifierClassBaseline.json') `
            -Raw `
            -Encoding UTF8 | ConvertFrom-Json
        Assert-Classifier ($baseline.Errors.Count -eq 2) 'Original error contracts missing.'
        foreach ($expected in $baseline.Errors) {
            $actual = Get-ClassifierErrorContract $expected.Preference
            Assert-Classifier ((ConvertTo-ClassifierJson $expected) -ceq (ConvertTo-ClassifierJson $actual)) ('Command error contract changed: ' + $expected.Preference)
            Assert-Classifier ($actual.Terminated -and
                $actual.Rows -eq 0 -and
                $actual.Diagnostics -eq 1 -and
                $actual.MessageIdentifiesString) 'Conversion failure contract is not meaningful.'
        }
        $failed = $false
        try {
            $null = $classifier.Classify((New-ClassifierBrokenObject), @{})
        }
        catch {
            $failed = $true
            Assert-Classifier ($_.Exception.Message -like '*System.String*') 'Direct failure lost its conversion cause.'
        }
        Assert-Classifier $failed 'Direct conversion failure did not propagate.'
    }

    'Command' {
        $command = Get-Command Get-ADAnalyzerAccountType
        Assert-Classifier ($command.Parameters['Profile'].ParameterType -eq [hashtable]) 'Profile binding type changed.'
        foreach ($name in @('Object', 'Profile', 'Membership', 'ErrorAction', 'ErrorVariable', 'OutVariable', 'Verbose', 'Debug')) {
            Assert-Classifier ($command.Parameters.ContainsKey($name)) ('Command parameter missing: ' + $name)
        }
        Assert-Classifier ($command.ParameterSets.Count -eq 1) 'Parameter sets changed.'
        foreach ($parameter in $command.ParameterSets[0].Parameters) {
            if ($parameter.Name -in @('Object', 'Profile', 'Membership')) {
                Assert-Classifier (-not $parameter.IsMandatory -and
                    -not $parameter.ValueFromPipeline -and
                    -not $parameter.ValueFromPipelineByPropertyName) 'Command binding attributes changed.'
            }
        }
        $arguments = @{
            Object = [pscustomobject]@{
                DirectoryObjectClass = 'msDS-ManagedServiceAccount'
            }
            Profile = $null
            Membership = $null
            ErrorAction = 'Stop'
            OutVariable = 'captured'
        }
        $rows = @(Get-ADAnalyzerAccountType @arguments)
        Assert-Classifier ($rows.Count -eq 1 -and
            $captured.Count -eq 1 -and
            $rows[0].Type -eq 'Service') 'Common-parameter/cardinality contract changed.'
        Assert-Classifier ((Get-ADAnalyzerAccountType).Type -eq $classifier.Classify($null).Type) 'Optional command defaults changed.'
    }
}

Assert-Classifier ($script:UnexpectedCalls -eq 0) 'Classifier performed integration work.'
Write-Host ('PASS account classifier class ' + $Case)
