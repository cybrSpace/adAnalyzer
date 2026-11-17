[CmdletBinding()]
param(
    [ValidateSet('RecordBaseline',
        'Construction',
        'Parity',
        'Types',
        'Merge',
        'Files',
        'Validation',
        'Isolation',
        'Serialization',
        'Ownership',
        'ProfileOnly')]
    [string]$Case = 'Construction'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ($Case -eq 'ProfileOnly') {
    . (Join-Path $repositoryRoot 'bin/ADProfile.ps1')
}
else {
    . (Join-Path $repositoryRoot 'bin/ADAnalyzer.ps1')
}

function Assert-Profile($Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Add-TypeRows($Value, [string]$Path, [Collections.Generic.List[object]]$Rows) {
    if ($null -eq $Value) {
        $Rows.Add([pscustomobject]@{
                Path = $Path
                Type = '<null>'
                Value = ''
            })
        return
    }

    $type = $Value.GetType().FullName
    if ($Value -is [Collections.IDictionary]) {
        $Rows.Add([pscustomobject]@{
                Path = $Path
                Type = $type
                Value = ''
            })
        [string[]]$keys = @($Value.Keys)
        if ($null -ne $keys) {
            [Array]::Sort($keys, [StringComparer]::Ordinal)
        }
        foreach ($key in $keys) {
            $part = $key.Replace('~', '~0').Replace('/', '~1')
            Add-TypeRows $Value[$key] ($Path + '/' + $part) $Rows
        }
        return
    }
    if ($Value -is [array] -or $Value -is [Collections.IList]) {
        $Rows.Add([pscustomobject]@{
                Path = $Path
                Type = $type
                Value = [string]$Value.Count
            })
        for ($i = 0; $i -lt $Value.Count; $i++) {
            Add-TypeRows $Value[$i] ($Path + '/' + $i) $Rows
        }
        return
    }
    $text = if ($Value -is [IFormattable]) {
        $Value.ToString($null, [Globalization.CultureInfo]::InvariantCulture)
    }
    else {
        [string]$Value
    }
    $Rows.Add([pscustomobject]@{
            Path = $Path
            Type = $type
            Value = $text
        })
}

function Get-TypeRowsJson($Value) {
    $rows = [Collections.Generic.List[object]]::new()
    Add-TypeRows $Value '$' $rows
    ConvertTo-Json -InputObject $rows.ToArray() -Depth 8 -Compress
}

function New-ProfileOverrides {
    @{
        Name = 'profile fixture'
        Analysis = @{
            DirectoryConnection = 'direct'
            HostTimeoutSeconds = '45'
        }
        Policy = @{
            MinimumPasswordLength = '14'
            MaximumPasswordAgeDays = 0
            PasswordComplexity = $false
            AllowPasswordNeverExpires = $true
            AllowedUserRightSids = @{
                SeBackupPrivilege = @('S-1-5-32-544')
            }
        }
        RegistryRules = @(@{
                Hive = 'HKLM'
                Key = 'Software\Fixture'
                ValueName = 'Labels'
                Type = '7'
                Expected = @('first', 'second')
            })
        Exceptions = @(@{
                RuleId = 'FIXTURE.EXCEPTION'
                Target = '*'
                Owner = 'fixture owner'
                Reason = 'fixture reason'
                Expires = '2099-03-01T12:00:00+03:00'
            })
    }
}

if ($Case -eq 'RecordBaseline') {
    Assert-Profile (-not ('ADAnalyzerProfile' -as [type])) 'Record profile goldens only before the class migration.'
    $overrides = New-ProfileOverrides
    $jsonObject = ConvertTo-Json -InputObject $overrides -Depth 30 | ConvertFrom-Json
    [ordered]@{
        SourceRevision = '6215221fa84c6206d286dd73197914f1b80a7e74'
        Raw = Get-TypeRowsJson (Get-ADAnalyzerDefaultProfile)
        NormalizedNull = Get-TypeRowsJson (Import-ADAnalyzerProfile -Profile $null)
        PartialMemory = Get-TypeRowsJson (Import-ADAnalyzerProfile -Profile $overrides)
        PartialJson = Get-TypeRowsJson (Import-ADAnalyzerProfile -Profile $jsonObject)
    } | ConvertTo-Json -Depth 10
    return
}

Assert-Profile ([bool]('ADAnalyzerProfile' -as [type])) 'The constructor-based profile implementation is missing.'
$baseline = Microsoft.PowerShell.Management\Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'ProfileClassBaseline.json'
) -Raw -Encoding UTF8 | ConvertFrom-Json

switch ($Case) {
    'Construction' {
        $configuration = [ADAnalyzerProfile]::new()
        Assert-Profile ((Get-TypeRowsJson ($configuration.ToHashtable())) -ceq $baseline.NormalizedNull) 'Default constructor changed normalized values or types.'
        $explicitNull = [ADAnalyzerProfile]::new($null)
        Assert-Profile ((Get-TypeRowsJson ($explicitNull.ToHashtable())) -ceq $baseline.NormalizedNull) 'Explicit null constructor changed default behavior.'
        Assert-Profile (@(Get-Module ActiveDirectory, GroupPolicy).Count -eq 0) 'Construction imported native modules.'
        Assert-Profile ($configuration.Settings.GetType().GetProperties().Count -eq 0) 'Private configuration capsule exposes serialized properties.'
    }

    'Parity' {
        Assert-Profile ((Get-TypeRowsJson ([ADAnalyzerProfile]::DefaultSnapshot())) -ceq $baseline.Raw) 'Class raw defaults differ from the original.'
        Assert-Profile ((Get-TypeRowsJson (Get-ADAnalyzerDefaultProfile)) -ceq $baseline.Raw) 'Compatibility raw defaults differ from the original.'
        Assert-Profile ((Get-TypeRowsJson (Import-ADAnalyzerProfile `
                        -Profile $null)) -ceq $baseline.NormalizedNull) 'Compatibility null import changed.'
        foreach ($kind in @('PartialMemory', 'PartialJson')) {
            $inputProfile = New-ProfileOverrides
            if ($kind -eq 'PartialJson') {
                $inputProfile = ConvertTo-Json -InputObject $inputProfile -Depth 30 | ConvertFrom-Json
            }
            $before = Get-TypeRowsJson (ConvertTo-ADAnalyzerHashtable $inputProfile)
            $direct = [ADAnalyzerProfile]::new($inputProfile).ToHashtable()
            $command = Import-ADAnalyzerProfile -Profile $inputProfile
            Assert-Profile ((Get-TypeRowsJson $direct) -ceq $baseline.$kind) ($kind + ' direct typed values differ from the original.')
            Assert-Profile ((Get-TypeRowsJson $command) -ceq $baseline.$kind) ($kind + ' command typed values differ from the original.')
            Assert-Profile ((Get-TypeRowsJson (ConvertTo-ADAnalyzerHashtable $inputProfile)) -ceq $before) 'Construction modified caller data.'
        }
    }

    'Types' {
        $raw = [ADAnalyzerProfile]::DefaultSnapshot()
        $normalized = [ADAnalyzerProfile]::new().ToHashtable()
        Assert-Profile ($raw.Policy.MinimumPasswordLength -is [int]) 'Raw default threshold is no longer Int32.'
        Assert-Profile ($normalized.Policy.MinimumPasswordLength -is [long]) 'Normalized threshold is no longer Int64.'
        Assert-Profile ($normalized.Analysis.HostTimeoutSeconds -is [int]) 'Normalized timeout is no longer Int32.'
        Assert-Profile ($normalized.Remediation.MaximumActions -is [int]) 'Default action cap type changed.'
        $typed = [ADAnalyzerProfile]::new(@{
                Remediation = @{
                    MaximumActions = 7L
                }
                Policy = @{
                    MaximumPasswordAgeDays = 0
                    PasswordComplexity = $false
                }
                RegistryRules = @(@{
                        Hive = 'HKLM'
                        Key = 'Software\Fixture'
                        ValueName = 'Duration'
                        Expected = [timespan]::FromMinutes(15)
                    })
            }).ToHashtable()
        Assert-Profile ($typed.Remediation.MaximumActions -is [long]) 'Caller Int64 action cap changed type.'
        Assert-Profile ($typed.Policy.MaximumPasswordAgeDays -is [long] -and
            $typed.Policy.MaximumPasswordAgeDays -eq 0) 'Normalized integer zero changed.'
        Assert-Profile ($typed.Policy.PasswordComplexity -is [bool] -and
            -not $typed.Policy.PasswordComplexity) 'Boolean false changed.'
        Assert-Profile ($typed.RegistryRules -is [array] -and
            $typed.RegistryRules[0].Expected -is [timespan] -and
            $typed.RegistryRules[0].Expected.TotalMinutes -eq 15) 'Snapshot round-tripped or changed a supported value type.'
    }

    'Merge' {
        $defaults = [ADAnalyzerProfile]::DefaultSnapshot()
        $rights = @{
            SeBackupPrivilege = @('S-1-5-32-544')
        }
        $hashes = @{
            'fixture.dll' = ('a' * 64)
        }
        $overrides = @{
            Policy = @{
                AllowedUserRightSids = $rights
                MinimumPasswordLength = 17
            }
            DependencyHashes = $hashes
        }
        $output = @(Merge-ADAnalyzerProfile -Defaults $defaults -Overrides $overrides)
        Assert-Profile ($output.Count -eq 0) 'Legacy merge emitted output.'
        Assert-Profile ($defaults.Policy.MinimumPasswordLength -is [int] -and
            $defaults.Policy.MinimumPasswordLength -eq 17) 'Merge unexpectedly normalized its in-place target.'
        Assert-Profile ([object]::ReferenceEquals($defaults.Policy.AllowedUserRightSids, $rights) -and
            [object]::ReferenceEquals($defaults.DependencyHashes, $hashes)) 'Legacy dictionary replacement/reference contract changed.'
        $failed = $false
        try {
            Merge-ADAnalyzerProfile -Defaults @{
                Policy = @{
                    Known = 1
                }
            } -Overrides @{
                Policy = @{
                    Unknown = 2
                }
            } -Prefix 'Root.'
        }
        catch {
            $failed = $_.Exception.ToString().Contains('Unknown profile setting: Root.Policy.Unknown')
        }
        Assert-Profile $failed 'Nested merge prefix or failure information changed.'
    }

    'Files' {
        $label = 'profile ' + [char]0x03A9 + ' ' + [char]0x6771
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ('ad-profile-' + [guid]::NewGuid().ToString('N') + ' [' + $label + ']')
        $null = [IO.Directory]::CreateDirectory($temporary)
        try {
            $jsonPath = Join-Path $temporary 'profile.json'
            $psdPath = Join-Path $temporary 'profile.psd1'
            $text = ConvertTo-Json -InputObject @{
                Name = $label
                Policy = @{
                    MinimumPasswordLength = 17
                }
            } -Depth 10
            [IO.File]::WriteAllText($jsonPath, $text, [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($psdPath,
                ("@{Name='" + $label + "';Policy=@{MinimumPasswordLength=17}}"),
                [Text.UTF8Encoding]::new($true))
            foreach ($path in @($jsonPath, $psdPath)) {
                $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
                $direct = [ADAnalyzerProfile]::Load($path).ToHashtable()
                $command = Import-ADAnalyzerProfile -Path $path
                Assert-Profile ($direct.Name -ceq $label -and
                    $direct.Policy.MinimumPasswordLength -is [long] -and
                    $direct.Policy.MinimumPasswordLength -eq 17) 'Explicit file load lost Unicode or normalized values.'
                Assert-Profile ((Get-TypeRowsJson $direct) -ceq (Get-TypeRowsJson $command)) 'File command/direct business outcomes differ.'
                Assert-Profile ($before -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))) 'File load modified its source.'
            }
            foreach ($spec in @(
                    @('invalid.json', '{'),
                    @('invalid.psd1', "@{ Name = (Write-Output 'forbidden command') }"),
                    @('unsupported.txt', '{}'),
                    @('scalar.json', '"profile string"')
                )) {
                $path = Join-Path $temporary $spec[0]
                [IO.File]::WriteAllText($path, $spec[1], [Text.UTF8Encoding]::new($true))
                $failed = $false
                try {
                    $null = [ADAnalyzerProfile]::Load($path)
                }
                catch {
                    $failed = $true
                }
                Assert-Profile $failed ('Invalid profile file accepted: ' + $spec[0])
            }
            $failed = $false
            try {
                $null = [ADAnalyzerProfile]::Load((Join-Path $temporary 'missing.json'))
            }
            catch {
                $failed = $true
            }
            Assert-Profile $failed 'Missing profile file was accepted.'
        }
        finally {
            [IO.Directory]::Delete($temporary, $true)
        }
    }

    'Validation' {
        $invalid = @(
            @{
                Unknown = 1
            },
            @{
                Policy = @{
                    Unknown = 1
                }
            },
            @{
                SchemaVersion = 2
            },
            @{
                SchemaVersion = $true
            },
            @{
                Name = ''
            },
            @{
                Version = ''
            },
            @{
                Policy = @{
                    MinimumPasswordLength = -1
                }
            },
            @{
                Policy = @{
                    PasswordComplexity = 'false'
                }
            },
            @{
                Policy = @{
                    MinimumLmCompatibilityLevel = 6
                }
            },
            @{
                Policy = @{
                    LockoutThreshold = 3
                    LockoutDurationMinutes = 15
                    ResetLockoutMinutes = 30
                }
            },
            @{
                Analysis = @{
                    HostTimeoutSeconds = 0
                }
            },
            @{
                Analysis = @{
                    HostTimeoutSeconds = 301
                }
            },
            @{
                Analysis = @{
                    DirectoryConnection = 'LDAP'
                }
            },
            @{
                Remediation = @{
                    MaximumActions = '5'
                }
            },
            @{
                Remediation = @{
                    MaximumActions = 0
                }
            },
            @{
                Remediation = @{
                    MaximumActions = 1001
                }
            },
            @{
                Remediation = @{
                    ApprovedObjectGuids = @('invalid')
                }
            },
            @{
                Exceptions = @(@{
                        RuleId = 'X'
                        Target = '*'
                        Owner = 'fixture'
                        Reason = 'fixture'
                        Expires = 'invalid'
                    })
            },
            @{
                RegistryRules = @(@{
                        Key = 'Software\Fixture'
                        ValueName = 'DefaultPassword'
                        Expected = 'forbidden'
                    })
            },
            @{
                RegistryRules = @(@{
                        Operator = 'Unsupported'
                    })
            },
            @{
                RegistryRules = @(@{
                        Scope = 'Both'
                    })
            },
            @{
                RegistryRules = @(@{
                        Severity = 'Huge'
                    })
            },
            @{
                RegistryRules = @(@{
                        Aggregate = 'no'
                    })
            },
            @{
                AccountClassification = @{
                    AttributeRules = @(@{
                            Attribute = 'Label'
                            Type = 'Computer'
                        })
                }
            },
            @{
                Host = @{
                    Services = @(@{
                            Name = 'Spooler'
                            State = 'Stopped'
                        }, @{
                            Name = 'Spooler'
                            State = 'Running'
                        })
                }
            },
            @{
                Host = @{
                    RegistryRules = @(@{
                            Key = 'Software\Fixture'
                            ValueName = 'Label'
                            Type = 5
                        })
                }
            },
            @{
                Host = @{
                    AuditRules = @(@{
                            SubcategoryGuid = 'invalid'
                            Flags = 1
                        })
                }
            },
            @{
                Host = @{
                    CertificateEndpoints = @(@{
                            HostName = 'https://invalid'
                        })
                }
            },
            @{
                Host = @{
                    CertificateEndpoints = @(@{
                            HostName = 'fixture.invalid'
                            Port = 0
                        })
                }
            },
            @{
                DependencyHashes = @{
                    'fixture.dll' = 'invalid'
                }
            }
        )
        foreach ($inputProfile in @($invalid) + @('not a dictionary', 1)) {
            $directFailed = $false
            $commandFailed = $false
            try {
                $null = [ADAnalyzerProfile]::new($inputProfile)
            }
            catch {
                $directFailed = $true
            }
            try {
                $null = Import-ADAnalyzerProfile -Profile $inputProfile
            }
            catch {
                $commandFailed = $true
            }
            Assert-Profile ($directFailed -and $commandFailed) 'Invalid profile was accepted by an object or command.'
        }
        $normalized = [ADAnalyzerProfile]::new((New-ProfileOverrides)).ToHashtable()
        Assert-Profile ($normalized.Exceptions[0].Expires -ceq '2099-03-01T09:00:00.0000000+00:00') 'Exception UTC normalization changed.'
    }

    'Isolation' {
        $inputProfile = New-ProfileOverrides
        $configuration = [ADAnalyzerProfile]::new($inputProfile)
        $first = $configuration.ToHashtable()
        $first.Policy.MinimumPasswordLength = 1
        $first.RegistryRules[0].Expected[0] = 'mutated result'
        $inputProfile.Name = 'mutated input'
        $inputProfile.RegistryRules[0].Expected[0] = 'mutated source'
        for ($i = 0; $i -lt 3; $i++) {
            Assert-Profile ((Get-TypeRowsJson ($configuration.ToHashtable())) -ceq $baseline.PartialMemory) 'Input/result mutation or repeated snapshots changed stored profile.'
        }
        $other = [ADAnalyzerProfile]::new()
        Assert-Profile ((Get-TypeRowsJson ($other.ToHashtable())) -ceq $baseline.NormalizedNull) 'Independent profile inherited configuration.'
        $raw = [ADAnalyzerProfile]::DefaultSnapshot()
        $raw.Policy.MinimumPasswordLength = 1
        Assert-Profile (([ADAnalyzerProfile]::DefaultSnapshot()).Policy.MinimumPasswordLength -eq 12) 'Raw default factory shares mutable state.'
    }

    'Serialization' {
        $marker = 'profile-class-fixture-sensitive-value'
        $configuration = [ADAnalyzerProfile]::new(@{
                AccountClassification = @{
                    AttributeRules = @(@{
                            Attribute = 'Password'
                            Type = 'Service'
                            Value = $marker
                        })
                }
            })
        $json = ConvertTo-Json -InputObject $configuration -Depth 30 -Compress
        $xml = [Management.Automation.PSSerializer]::Serialize($configuration)
        Assert-Profile (-not $json.Contains($marker) -and
            -not $xml.Contains($marker)) 'Native profile serialization exposed captured configuration.'
        Assert-Profile ($configuration.Settings.GetType().GetProperties().Count -eq 0) 'Configuration capsule gained public serialized properties.'
        Assert-Profile ($configuration.ToHashtable().AccountClassification.AttributeRules[0].Value -ceq $marker) 'Explicit configuration snapshot changed a caller value.'
    }

    'Ownership' {

        function Get-ADAnalyzerDefaultProfile {
            throw 'Old default function must not own constructor processing.'
        }

        function Import-ADAnalyzerProfile {
            throw 'Old import function must not own constructor processing.'
        }

        function Merge-ADAnalyzerProfile {
            throw 'Old merge function must not own constructor processing.'
        }

        function Get-Content {
            throw 'Constructor must not read files.'
        }

        function Import-PowerShellDataFile {
            throw 'Constructor must not read data files.'
        }

        function Import-Module {
            throw 'Constructor must not import native modules.'
        }
        $configuration = [ADAnalyzerProfile]::new((New-ProfileOverrides))
        Assert-Profile ((Get-TypeRowsJson ($configuration.ToHashtable())) -ceq $baseline.PartialMemory) 'Constructor delegates to old processors or performs I/O.'
        Assert-Profile ((Get-TypeRowsJson ([ADAnalyzerProfile]::DefaultSnapshot())) -ceq $baseline.Raw) 'Class defaults delegate to the old processor.'
    }

    'ProfileOnly' {
        Assert-Profile (-not ('ADAnalyzerAssessmentEngine' -as [type])) 'Profile-only route loaded an unrelated engine.'
        $configuration = [ADAnalyzerProfile]::new()
        Assert-Profile ((Get-TypeRowsJson ($configuration.ToHashtable())) -ceq $baseline.NormalizedNull) 'Profile-only bootstrap cannot construct valid profiles.'
    }
}

Write-Output ('PASS profile class ' + $Case)
