[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Native', 'Approval', 'Construction', 'Standalone', 'Direct', 'Isolation')]
    [string]$Case,
    [Parameter(Mandatory)][string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

function Import-Module {
    throw 'The assessment report fixture cannot acquire a module.'
}

function Get-ADObject {
    throw 'The assessment report fixture cannot contact a directory provider.'
}

if ($Case -in 'Native', 'Approval', 'Standalone') {
    . (Join-Path $RepositoryRoot 'bin/ADOperations.ps1')
}
else {
    . (Join-Path $RepositoryRoot 'bin/ADAnalyzer.ps1')
}

$script:passed = 0

function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-Fixture([string]$TestName, [scriptblock]$Body) {
    try {
        & $Body
        $script:passed++
    }
    catch {
        Write-Host ('FAIL assessment report ' + $TestName)
        throw
    }
}

function Get-FixtureFailure([scriptblock]$Operation) {
    try {
        $null = & $Operation
    }
    catch {
        return $_
    }
    throw 'The assessment report unexpectedly accepted invalid input.'
}

function Get-FixtureDiagnostic([object]$Entry) {
    if ($null -eq $Entry) {
        return $null
    }
    if ($Entry -is [Collections.IList]) {
        return [ordered]@{
            Type = $Entry.GetType().FullName
            Entries = @(
                foreach ($item in $Entry) {
                    Get-FixtureDiagnostic $item
                }
            )
        }
    }

    $record = $Entry
    if ($Entry -isnot [Management.Automation.ErrorRecord] -and
        $Entry -is [Management.Automation.IContainsErrorRecord]) {
        $record = $Entry.ErrorRecord
    }
    $diagnostic = [ordered]@{
        Type = $Entry.GetType().FullName
        Id = $null
        Category = $null
        Command = $null
        Cause = $null
        Message = $null
    }
    if ($record -is [Management.Automation.ErrorRecord]) {
        $diagnostic.Id = $record.FullyQualifiedErrorId
        $diagnostic.Category = [string]$record.CategoryInfo.Category
        if ($null -ne $record.InvocationInfo -and $null -ne $record.InvocationInfo.MyCommand) {
            $diagnostic.Command = $record.InvocationInfo.MyCommand.Name
        }
        if ($null -ne $record.Exception) {
            $cause = $record.Exception.GetBaseException()
            $diagnostic.Cause = $cause.GetType().FullName
            $diagnostic.Message = $cause.Message.Replace($fixtureDirectory, '<fixture>')
        }
    }
    elseif ($Entry -is [Exception]) {
        $cause = $Entry.GetBaseException()
        $diagnostic.Cause = $cause.GetType().FullName
        $diagnostic.Message = $cause.Message.Replace($fixtureDirectory, '<fixture>')
    }
    return $diagnostic
}

function New-FixtureAssessment {
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        Target = 'fixture <north> & south'
        Timestamp = '2026-01-02T03:04:05Z'
        State = 'Complete'
        Profile = [pscustomobject][ordered]@{
            Name = 'assessment fixture'
            Version = '1.0'
        }
        Coverage = [ordered]@{
            Zeta = 'unknown'
            Alpha = 'collected'
        }
        Checks = @(
            [pscustomobject][ordered]@{
                RuleId = 'CHECK.HTML.FIRST'
                Status = 'Fail'
                Suppressed = $true
                Evidence = [pscustomobject]@{
                    ReportFixtureRole = 'HtmlEvidence'
                    Shape = 'first <evidence>'
                }
            }
            [pscustomobject][ordered]@{
                RuleId = 'CHECK.HTML.NEXT'
                Status = 'Pass'
                Evidence = [pscustomobject]@{
                    ReportFixtureRole = 'ExtraEvidence'
                    Shape = 'second & extra'
                }
            }
        )
        Findings = @(
            [pscustomobject][ordered]@{
                Finding = 'FINDING.CSV'
                SID = 'fixture account'
                Status = 'Fail'
                Evidence = [pscustomobject]@{
                    ReportFixtureRole = 'CsvEvidence'
                    Password = 'ASSESSMENT_FIXTURE_VALUE'
                }
            }
            [pscustomobject][ordered]@{
                Finding = 'FINDING.CSV.NEXT'
                DistinguishedName = 'fixture sibling'
                Status = 'Pass'
                Observed = [pscustomobject]@{
                    ReportFixtureRole = 'CsvTail'
                }
            }
        )
    }
}

# Exact native bodies from accepted 992efa6. Pair using their original scoped names.
if ($Case -eq 'Native') {
    $script:acceptedReportBodies = [ordered]@{
        # 24f0ad66fff01f4f3c99c9d0c812990fb3ea01ccb45b9ce1606e2ed2a0b0c3e1
        'ConvertTo-ADAnalyzerOperationHtmlValue' = @'
    param([AllowNull()]$Value)
    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [string] -or $Value -is [ValueType]) {
        return [Net.WebUtility]::HtmlEncode([string]$Value)
    }
    return [Net.WebUtility]::HtmlEncode((ConvertTo-Json -InputObject $Value -Depth 100 -Compress))
'@
        # 5a4bfd45bb58f1d70715c65d38f9d0e79162564032681e02a2a63d6172e370a2
        'ConvertTo-ADAnalyzerAssessmentHtml' = @'
    param([Parameter(Mandatory)]$Assessment)
    $checks = @(Get-ADAnalyzerOperationValue $Assessment @('Checks', 'Findings') @() | Where-Object { $null -ne $_ })
    $errors = @(Get-ADAnalyzerOperationValue $Assessment @('Errors') @() | Where-Object { $null -ne $_ })
    $counts = @{}
    foreach ($status in @('Pass', 'Fail', 'Unknown', 'Unreadable', 'Invalid', 'NotConfigured', 'NotApplicable')) {
        $counts[$status] = @($checks | Where-Object Status -eq $status).Count
    }
    $state = if (-not $checks.Count) {
        'No checks collected'
    }
    elseif ($errors.Count -or $counts.Unknown -or $counts.Unreadable -or $counts.Invalid) {
        'Incomplete evidence: review unknowns and collection errors'
    }
    elseif ($counts.Fail) {
        'Failed checks require review'
    }
    else {
        'No failed checks recorded'
    }
    $target = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('Target'))
    $profile = Get-ADAnalyzerOperationValue $Assessment @('Profile')
    $profileName = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Name') 'Unspecified')
    $profileVersion = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $profile @('Version') '')
    $runId = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('RunId'))
    $timestamp = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('Timestamp'))
    $recordedState = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $Assessment @('State') 'Unspecified')
    $html = [Text.StringBuilder]::new()
    $null = $html.Append('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AD Analyzer assessment</title><style>body{font:15px system-ui,sans-serif;color:#1e293b;background:#f8fafc;max-width:1450px;margin:2rem auto;padding:0 1.2rem}h1{font-size:2rem;margin-bottom:.3rem}h2{margin-top:2rem}p{line-height:1.5}.meta{color:#475569}.state{border-left:4px solid #2563eb;padding:.8rem 1rem;background:white}.cards{display:flex;flex-wrap:wrap;gap:.6rem;margin:1.2rem 0}.card{background:white;border:1px solid #cbd5e1;border-radius:.4rem;padding:.6rem 1rem}.card b{font-size:1.4rem;display:block}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;background:white;font-size:.9rem}th,td{border:1px solid #cbd5e1;text-align:left;vertical-align:top;padding:.6rem;overflow-wrap:anywhere}th{background:#e2e8f0}.fail{color:#9f1239;font-weight:700}.pass{color:#166534}.unknown{color:#92400e}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f9;padding:1rem}details{margin:.4rem 0}summary{cursor:pointer;color:#1d4ed8}.muted{color:#64748b}</style></head><body>')
    $null = $html.Append('<h1>Active Directory assessment</h1><p class="meta">Target: <strong>' + $target + '</strong><br>Profile: ' + $profileName + ' ' + $profileVersion + '<br>State: ' + $recordedState + '<br>Run: ' + $runId + '<br>Collected: ' + $timestamp + '</p>')
    $null = $html.Append('<p class="state">' + [Net.WebUtility]::HtmlEncode($state) + '. Findings are evidence for review, not authorization to change directory objects.</p><div class="cards">')
    foreach ($status in @('Pass', 'Fail', 'Unknown', 'Unreadable', 'Invalid', 'NotConfigured', 'NotApplicable')) {
        $null = $html.Append('<div class="card"><b>' + [string]$counts[$status] + '</b>' + [Net.WebUtility]::HtmlEncode($status) + '</div>')
    }
    $null = $html.Append('</div><h2>Collection coverage</h2><div class="table"><table><thead><tr><th>Source or capability</th><th>Collection state / evidence</th></tr></thead><tbody>')
    $data = Get-ADAnalyzerOperationValue $Assessment @('Data')
    $directory = Get-ADAnalyzerOperationValue $data @('Directory')
    $coverage = Get-ADAnalyzerOperationValue $directory @('Coverage') (Get-ADAnalyzerOperationValue $Assessment @('Coverage'))
    $names = @(
        if ($coverage -is [Collections.IDictionary]) {
            ([Collections.IDictionary].GetProperty('Keys')).GetValue($coverage, $null)
        }
        elseif ($coverage) {
            foreach ($property in $coverage.PSObject.Properties) {
                $property.Name
            }
        }
    )
    foreach ($name in @($names | Sort-Object)) {
        $null = $html.Append('<tr><td>' + [Net.WebUtility]::HtmlEncode([string]$name) + '</td><td>' + (ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $coverage @([string]$name))) + '</td></tr>')
    }
    if (-not $names.Count) {
        $null = $html.Append('<tr><td colspan="2" class="muted">Coverage was not recorded.</td></tr>')
    }
    $null = $html.Append('</tbody></table></div><h2>Checks and findings</h2><div class="table"><table><thead><tr><th>Rule</th><th>Target</th><th>Status</th><th>Severity</th><th>Expected</th><th>Observed</th><th>Evidence</th></tr></thead><tbody>')
    foreach ($check in $checks) {
        $status = [string](Get-ADAnalyzerOperationValue $check @('Status'))
        $statusClass = if ($status -eq 'Fail') {
            'fail'
        }
        elseif ($status -eq 'Pass') {
            'pass'
        }
        else {
            'unknown'
        }
        $statusLabel = $status + $(if ([bool](Get-ADAnalyzerOperationValue $check @('Suppressed') $false)) {
                ' (suppressed)'
            }
            else {
                ''
            })
        $evidence = [Net.WebUtility]::HtmlEncode((ConvertTo-Json `
                    -InputObject (Get-ADAnalyzerOperationValue $check @('Evidence')) `
                    -Depth 100))
        $message = ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Message'))
        $null = $html.Append('<tr><td>' + (ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('RuleId',
                        'Finding'))) + '</td><td>' + (ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Target',
                        'DistinguishedName',
                        'SID'))) + '</td><td class="' + $statusClass + '">' + [Net.WebUtility]::HtmlEncode($statusLabel) + '</td><td>' + (ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Severity'))) + '</td><td>' + (ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Expected'))) + '</td><td>' + (ConvertTo-ADAnalyzerOperationHtmlValue (Get-ADAnalyzerOperationValue $check @('Observed',
                        'Actual'))) + '</td><td>' + $message + '<details><summary>View evidence</summary><pre>' + $evidence + '</pre></details></td></tr>')
    }
    if (-not $checks.Count) {
        $null = $html.Append('<tr><td colspan="7" class="muted">No check results are present in this snapshot.</td></tr>')
    }
    $null = $html.Append('</tbody></table></div>')
    if ($errors.Count) {
        $null = $html.Append('<h2>Collection errors</h2><pre>' + [Net.WebUtility]::HtmlEncode((ConvertTo-Json `
                        -InputObject $errors `
                        -Depth 100)) + '</pre>')
    }
    $null = $html.Append('<details><summary>Full assessment snapshot (secret presence only)</summary><pre>' + [Net.WebUtility]::HtmlEncode((ConvertTo-Json `
                    -InputObject $Assessment `
                    -Depth 100)) + '</pre></details><p class="muted">Standalone report. No external scripts, fonts, or resources are loaded.</p></body></html>')
    return $html.ToString()
'@
        # 424218a04ca528986dc9d09598fe7e98592907a9fed22ea40e93294a6e75f80f
        'Export-ADAnalyzerAssessment' = @'
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]$Assessment,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Json', 'Html', 'Csv', 'All')][string]$Format = 'Json'

    )
    $document = Read-ADAnalyzerOperationDocument $Assessment
    $safe = ConvertTo-ADAnalyzerSafeData -InputObject $document
    $findings = @(Get-ADAnalyzerOperationValue $safe @('Findings', 'Checks') @())
    $formats = if ($Format -eq 'All') {
        @('Json', 'Html', 'Csv')
    }
    else {
        @($Format)
    }
    foreach ($item in $formats) {
        $outputPath = if ($Format -eq 'All') {
            $Path.TrimEnd('.') + '.' + $item.ToLowerInvariant()
        }
        else {
            $Path
        }
        if (-not $PSCmdlet.ShouldProcess($outputPath, 'Export assessment projection')) {
            continue
        }
        switch ($item) {
            'Json' {
                $content = ConvertTo-Json -InputObject $safe -Depth 100
            }
            'Html' {
                $content = ConvertTo-ADAnalyzerAssessmentHtml $safe
            }
            'Csv' {
                $rows = @(foreach ($finding in $findings) {
                        [pscustomobject][ordered]@{
                            RuleId = Get-ADAnalyzerOperationValue $finding @('RuleId', 'Finding')
                            Target = Get-ADAnalyzerOperationValue $finding @('Target', 'DistinguishedName', 'SID')
                            Status = Get-ADAnalyzerOperationValue $finding @('Status')
                            Severity = Get-ADAnalyzerOperationValue $finding @('Severity')
                            Evidence = ConvertTo-Json `
                                -InputObject (Get-ADAnalyzerOperationValue $finding @('Evidence',
                                    'Observed')) `
                                -Depth 100 `
                                -Compress
                        }
                    })
                $content = if ($rows.Count) {
                    ($rows | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
                }
                else {
                    '"RuleId","Target","Status","Severity","Evidence"'
                }
            }
        }
        Write-ADAnalyzerOperationFile -Path $outputPath -Content $content
    }
'@
    }
}

function Invoke-FixtureNativeReport([string]$Scenario, [string]$Action, [string]$Inherited) {
    $script:reportTrace = [Collections.Generic.List[string]]::new()
    $script:reportSink = [Collections.Generic.List[object]]::new()
    function ConvertTo-Json {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][AllowNull()]$InputObject,
            [int]$Depth,
            [switch]$Compress
        )

        $role = 'Other'
        if ($null -ne $InputObject -and $InputObject.PSObject.Properties['ReportFixtureRole']) {
            $role = [string]$InputObject.ReportFixtureRole
        }
        elseif ($null -ne $InputObject -and $InputObject.PSObject.Properties['SchemaVersion']) {
            $role = 'Snapshot'
        }
        $script:reportTrace.Add(('Json|{0}|Compress={1}' -f $role, $Compress.IsPresent))
        if (($Scenario -in 'HtmlEvidence', 'StandaloneHtml' -and $role -eq 'HtmlEvidence') -or
            ($Scenario -eq 'CsvEvidence' -and $role -eq 'CsvEvidence')) {
            Write-Warning 'Fixture evidence serializer warning.'
            Write-Error -Message 'Fixture evidence serializer failure.' -ErrorId 'Fixture.ReportEvidence'
            return
        }
        Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
    }

    function ConvertTo-Csv {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]$InputObject,
            [switch]$NoTypeInformation
        )

        begin {
            $csvRows = [Collections.Generic.List[object]]::new()
        }
        process {
            $csvRows.Add($InputObject)
        }
        end {
            $script:reportTrace.Add(('Csv|{0}|NoTypeInformation={1}' -f $csvRows.Count, $NoTypeInformation.IsPresent))
            if ($Scenario -eq 'CsvSerializer') {
                Write-Warning 'Fixture CSV serializer warning.'
                Write-Error -Message 'Fixture CSV serializer failure.' -ErrorId 'Fixture.ReportCsv'
                return
            }
            $csvRows.ToArray() | Microsoft.PowerShell.Utility\ConvertTo-Csv -NoTypeInformation:$NoTypeInformation
        }
    }

    function Write-ADAnalyzerOperationFile {
        param(
            [Parameter(Mandatory)][string]$Path,
            [Parameter(Mandatory)][AllowEmptyString()][string]$Content
        )

        $extension = [IO.Path]::GetExtension($Path)
        $script:reportTrace.Add('Write|' + $extension)
        if ($Scenario -eq 'Writer' -and $extension -ceq '.html') {
            Write-Warning 'Fixture writer warning.'
            Write-Error -Message 'Fixture writer failure.' -ErrorId 'Fixture.ReportWrite'
            return
        }
        $script:reportSink.Add([ordered]@{
                Extension = $extension
                Content = $Content
            })
        return $Path
    }

    $document = New-FixtureAssessment
    $document | Add-Member -MemberType ScriptProperty -Name ProbeProjection -Value {
        $script:reportTrace.Add('Project')
        'profile observation'
    }
    $paths = Join-Path $fixtureDirectory 'report [literal]...'
    $parameters = @{
        Assessment = $document
        Path = $paths
        Format = 'All'
        Confirm = $false
        ErrorAction = $Action
        ErrorVariable = '+seen'
    }
    $seen = [Collections.ArrayList]::new()
    $items = [Collections.Generic.List[object]]::new()
    $caught = $null
    $continued = $false
    $ErrorActionPreference = $Inherited
    $Error.Clear()
    try {
        if ($Scenario -eq 'StandaloneHtml') {
            ConvertTo-ADAnalyzerAssessmentHtml -Assessment $document -ErrorAction $Action -ErrorVariable +seen *>&1 |
                ForEach-Object {
                    $items.Add($_)
                }
        }
        else {
            Export-ADAnalyzerAssessment @parameters *>&1 | ForEach-Object {
                $items.Add($_)
            }
        }
        $continued = $true
    }
    catch {
        $caught = $_
    }
    $history = @($Error)
    $observation = [ordered]@{
        Completed = $continued
        Caught = Get-FixtureDiagnostic $caught
        Capture = Get-FixtureDiagnostic $seen
        History = Get-FixtureDiagnostic $history
        Trace = $script:reportTrace.ToArray()
        Written = $script:reportSink.ToArray()
        Stream = @(
            foreach ($item in $items) {
                if ($null -eq $item) {
                    [ordered]@{
                        Type = 'Null'
                    }
                }
                elseif ($item -is [Management.Automation.ErrorRecord]) {
                    Get-FixtureDiagnostic $item
                }
                elseif ($item -is [Management.Automation.InformationalRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = ([string]$item.Message).Replace($fixtureDirectory, '<fixture>')
                    }
                }
                elseif ($item -is [Management.Automation.InformationRecord]) {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = ([string]$item.MessageData).Replace($fixtureDirectory, '<fixture>')
                    }
                }
                else {
                    [ordered]@{
                        Type = $item.GetType().FullName
                        Value = ([string]$item).Replace($fixtureDirectory, '<fixture>')
                    }
                }
            }
        )
    }
    return (Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $observation -Depth 24 -Compress)
}

function Assert-FixtureNativeReport([string]$Scenario, [string]$Action, [string]$Inherited) {
    $originals = [ordered]@{}
    try {
        foreach ($name in $script:acceptedReportBodies.Keys) {
            $path = 'Function:script:' + $name
            $originals[$name] = (Get-Command $name -CommandType Function).ScriptBlock
            $accepted = [scriptblock]::Create($script:acceptedReportBodies[$name])
            Set-Item -LiteralPath $path -Value $accepted
            $active = (Get-Command $name -CommandType Function).ScriptBlock
            Assert-Fixture ($active.ToString() -ceq $accepted.ToString()) ('Failed to install archived ' + $name + '.')
        }
        $expected = Invoke-FixtureNativeReport $Scenario $Action $Inherited
    }
    finally {
        foreach ($name in $originals.Keys) {
            $path = 'Function:script:' + $name
            Set-Item -LiteralPath $path -Value $originals[$name]
        }
    }
    foreach ($name in $originals.Keys) {
        $active = (Get-Command $name -CommandType Function).ScriptBlock
        Assert-Fixture ($active.ToString() -ceq $originals[$name].ToString()) ('Failed to restore candidate ' + $name + '.')
    }
    $actual = Invoke-FixtureNativeReport $Scenario $Action $Inherited
    if ($Action -ne 'Ignore') {
        $faultId = switch ($Scenario) {
            'CsvSerializer' {
                'Fixture.ReportCsv'
            }
            'Writer' {
                'Fixture.ReportWrite'
            }
            default {
                'Fixture.ReportEvidence'
            }
        }
        Assert-Fixture ($expected.Contains($faultId)) ('The archived renderer did not exercise the configured fault ' + $faultId + '.')
    }
    Assert-Fixture ($actual -ceq $expected) (
        "Native report changed for $Scenario with ErrorAction=$Action and caller preference $Inherited." + [Environment]::NewLine +
        'Accepted: ' + $expected + [Environment]::NewLine + 'Current: ' + $actual
    )
}


function Invoke-FixtureMixedApproval([string]$TargetPrefix) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Security;

public sealed class AssessmentReportApprovalHost : PSHost
{
    private readonly Guid instanceId = Guid.NewGuid();
    public readonly AssessmentReportApprovalUI Content;
    public AssessmentReportApprovalHost(string prefix) { Content = new AssessmentReportApprovalUI(prefix); }
    public override Guid InstanceId { get { return instanceId; } }
    public override string Name { get { return "Report approval fixture"; } }
    public override Version Version { get { return new Version(1, 0); } }
    public override CultureInfo CurrentCulture { get { return CultureInfo.InvariantCulture; } }
    public override CultureInfo CurrentUICulture { get { return CultureInfo.InvariantCulture; } }
    public override PSHostUserInterface UI { get { return Content; } }
    public override void EnterNestedPrompt() { throw new InvalidOperationException(); }
    public override void ExitNestedPrompt() { throw new InvalidOperationException(); }
    public override void NotifyBeginApplication() { throw new InvalidOperationException(); }
    public override void NotifyEndApplication() { throw new InvalidOperationException(); }
    public override void SetShouldExit(int exitCode) { throw new InvalidOperationException(); }
}

public sealed class AssessmentReportApprovalUI : PSHostUserInterface
{
    private readonly string prefix;
    public readonly List<string> Decisions = new List<string>();
    public AssessmentReportApprovalUI(string prefix) { this.prefix = prefix; }

    public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices, int defaultChoice)
    {
        string ext;
        if (message.Contains(prefix + ".json")) { ext = ".json"; }
        else if (message.Contains(prefix + ".html")) { ext = ".html"; }
        else if (message.Contains(prefix + ".csv")) { ext = ".csv"; }
        else { throw new InvalidOperationException("Unexpected approval target"); }

        string answer = ext == ".html" ? "No" : "Yes";
        Decisions.Add(ext + "|" + answer + "|json=" + File.Exists(prefix + ".json")
            + "|html=" + File.Exists(prefix + ".html") + "|csv=" + File.Exists(prefix + ".csv"));
        for (int i = 0; i < choices.Count; i++)
        {
            if (choices[i].Label.Replace("&", "") == answer) { return i; }
        }
        throw new InvalidOperationException("Unexpected approval choices");
    }

    public override PSHostRawUserInterface RawUI { get { return null; } }
    public override string ReadLine() { throw new InvalidOperationException(); }
    public override SecureString ReadLineAsSecureString() { throw new InvalidOperationException(); }
    public override void Write(string value) { }
    public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value) { }
    public override void WriteLine(string value) { }
    public override void WriteErrorLine(string value) { }
    public override void WriteDebugLine(string message) { }
    public override void WriteProgress(long sourceId, ProgressRecord record) { }
    public override void WriteVerboseLine(string message) { }
    public override void WriteWarningLine(string message) { }
    public override Dictionary<string, PSObject> Prompt(string caption, string message, Collection<FieldDescription> descriptions) { throw new InvalidOperationException(); }
    public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName) { throw new InvalidOperationException(); }
    public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes types, PSCredentialUIOptions options) { throw new InvalidOperationException(); }
}
'@
    $fixtureHost = [AssessmentReportApprovalHost]::new($TargetPrefix)
    $runspace = [runspacefactory]::CreateRunspace($fixtureHost)
    $worker = [powershell]::Create()
    try {
        $runspace.Open()
        $worker.Runspace = $runspace
        $scriptText = @'
param($Root, $Path)
$ErrorActionPreference = 'Stop'
. (Join-Path $Root 'bin/ADOperations.ps1')

function Import-Module {
    throw 'The report approval fixture is offline.'
}

function ConvertTo-Json {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$InputObject, [int]$Depth, [switch]$Compress)

    if ($null -ne $InputObject -and $InputObject.PSObject.Properties['ApprovalFixtureHtml']) {
        throw 'The declined HTML target reached serialization.'
    }
    Microsoft.PowerShell.Utility\ConvertTo-Json @PSBoundParameters
}

$document = @{
    SchemaVersion = 1
    Target = 'local approval fixture'
    Checks = @(
        @{
            RuleId = 'FIXTURE.HTML'
            Status = 'Pass'
            Evidence = @{
                ApprovalFixtureHtml = $true
            }
        }
    )
    Findings = @()
}
Export-ADAnalyzerAssessment -Assessment $document -Path $Path -Format All -Confirm
'@
        $rows = @($worker.AddScript($scriptText).AddArgument($RepositoryRoot).AddArgument($TargetPrefix).Invoke())
        Assert-Fixture (-not $worker.HadErrors) ('Hosted Confirm failed: ' + ($worker.Streams.Error -join [Environment]::NewLine))
        $expected = @(
            '.json|Yes|json=False|html=False|csv=False'
            '.html|No|json=True|html=False|csv=False'
            '.csv|Yes|json=True|html=False|csv=False'
        )
        Assert-Fixture (
            ($fixtureHost.Content.Decisions -join ',') -ceq ($expected -join ',') -and
            $rows.Count -eq 2 -and [string]$rows[0] -ceq ($TargetPrefix + '.json') -and
            [string]$rows[1] -ceq ($TargetPrefix + '.csv') -and
            [IO.File]::Exists($TargetPrefix + '.json') -and [IO.File]::Exists($TargetPrefix + '.csv') -and
            -not [IO.File]::Exists($TargetPrefix + '.html')
        ) 'Mixed confirmation changed approval scope, writer ordering, or completed paths.'
    }
    finally {
        $worker.Dispose()
        $runspace.Dispose()
    }
}

function Invoke-ApprovalFixtures {
    Test-Fixture 'actual native Confirm accepts JSON, declines HTML, accepts CSV' {
        Invoke-FixtureMixedApproval (Join-Path $fixtureDirectory 'confirm [fixture]')
    }

    Test-Fixture 'WhatIf validates input and never creates destination paths' {
        $root = Join-Path $fixtureDirectory 'whatif output'
        $path = Join-Path $root 'assessment'
        $current = @(Export-ADAnalyzerAssessment (New-FixtureAssessment) $path -Format All -WhatIf)
        Assert-Fixture (
            $current.Count -eq 0 -and -not [IO.Directory]::Exists($root)
        ) 'A WhatIf preview returned a completed path or changed the destination.'
        $failure = Get-FixtureFailure {
            Export-ADAnalyzerAssessment @{ SchemaVersion = 2 } $path -Format All -WhatIf
        }
        Assert-Fixture (
            $failure.Exception.GetBaseException().Message -ceq 'Unsupported Assessment SchemaVersion' -and
            -not [IO.Directory]::Exists($root)
        ) 'WhatIf did not retain preapproval input validation.'
    }

    Test-Fixture 'first native pipeline output leaves later formats untouched' {
        $path = Join-Path $fixtureDirectory 'first [fixture]...'
        $expected = $path.TrimEnd('.') + '.json'
        $rows = @(Export-ADAnalyzerAssessment (New-FixtureAssessment) $path -Format All -Confirm:$false |
                Select-Object -First 1)
        Assert-Fixture (
            $rows.Count -eq 1 -and $rows[0] -ceq $expected -and [IO.File]::Exists($expected) -and
            -not [IO.File]::Exists($path.TrimEnd('.') + '.html') -and
            -not [IO.File]::Exists($path.TrimEnd('.') + '.csv')
        ) 'Selecting the first completed export changed later formats.'
    }

    Test-Fixture 'later real file failure preserves the first output and staged cleanup' {
        $root = Join-Path $fixtureDirectory 'conflict'
        $path = Join-Path $root 'assessment [literal]'
        $destination = $path + '.html'
        $null = [IO.Directory]::CreateDirectory($destination)
        $existing = Join-Path $destination 'sentinel.txt'
        [IO.File]::WriteAllText($existing, 'original fixture')
        $paths = [Collections.Generic.List[string]]::new()
        $caught = $null
        try {
            Export-ADAnalyzerAssessment (New-FixtureAssessment) $path -Format All -Confirm:$false |
                ForEach-Object {
                    $paths.Add($_)
                }
        }
        catch {
            $caught = $_
        }
        Assert-Fixture (
            $null -ne $caught -and $paths.Count -eq 1 -and $paths[0] -ceq ($path + '.json') -and
            [IO.File]::Exists($path + '.json') -and -not [IO.File]::Exists($path + '.csv') -and
            [IO.File]::ReadAllText($existing) -ceq 'original fixture' -and
            @([IO.Directory]::GetFiles($root, '.ad-analyzer-*.tmp')).Count -eq 0
        ) 'A failed later write lost its native prefix, preserved destination, or cleanup.'
    }
}


function Invoke-DirectReportFixtures {
    $baseExporter = (Get-Command Export-ADAnalyzerAssessment -CommandType Function).ScriptBlock
    function script:Export-ADAnalyzerAssessment {
        throw 'A direct assessment report called the compatibility command.'
    }
    $report = [ADAnalyzerAssessmentReport]::new()

    Test-Fixture 'render and write retain same-engine format bytes and order' {
        $inputDocument = New-FixtureAssessment
        $baselinePrefix = Join-Path $fixtureDirectory 'baseline report...'
        $nativePaths = @(& $baseExporter -Assessment $inputDocument -Path $baselinePrefix -Format All -Confirm:$false)
        $before = ConvertTo-Json -InputObject $inputDocument -Depth 30 -Compress
        $beforeFiles = [IO.Directory]::GetFiles($fixtureDirectory).Count
        $formatOrder = @('Json', 'Html', 'Csv')
        for ($index = 0; $index -lt $formatOrder.Count; $index++) {
            $nativeContent = [IO.File]::ReadAllText($nativePaths[$index])
            $rendered = $report.Render($inputDocument, $formatOrder[$index])
            Assert-Fixture ($rendered -ceq $nativeContent) ('Render changed ' + $formatOrder[$index] + ' content.')
        }
        Assert-Fixture (
            [IO.Directory]::GetFiles($fixtureDirectory).Count -eq $beforeFiles
        ) 'In-memory rendering created a file.'

        $target = Join-Path $fixtureDirectory 'direct report [literal]...'
        $paths = $report.Write($inputDocument, $target, 'All')
        Assert-Fixture (
            $paths -is [string[]] -and $paths.Count -eq 3
        ) 'The direct writer returned the wrong result shape.'
        for ($index = 0; $index -lt $formatOrder.Count; $index++) {
            $format = $formatOrder[$index].ToLowerInvariant()
            Assert-Fixture (
                $paths[$index] -ceq ($target.TrimEnd('.') + '.' + $format) -and
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($paths[$index])) -ceq
                    [Convert]::ToBase64String([IO.File]::ReadAllBytes($nativePaths[$index]))
            ) ('Write changed the completed path or bytes for ' + $format + '.')
        }
        Assert-Fixture (
            (ConvertTo-Json -InputObject $inputDocument -Depth 30 -Compress) -ceq $before -and
            [IO.File]::ReadAllText($paths[0]) -notlike '*ASSESSMENT_FIXTURE_VALUE*'
        ) 'The direct report changed the caller assessment or retained a fixture secret value.'
    }

    Test-Fixture 'literal JSON input retains runtime date conversion and UTF-8 BOM' {
        $source = Join-Path $fixtureDirectory 'assessment [source].json'
        $document = New-FixtureAssessment
        $document.Target = 'caf' + [char]0x00e9
        [IO.File]::WriteAllText(
            $source,
            (ConvertTo-Json -InputObject $document -Depth 30 -Compress),
            [Text.UTF8Encoding]::new($true)
        )
        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($source))
        $expected = Join-Path $fixtureDirectory 'native file report.json'
        $null = & $baseExporter -Assessment $source -Path $expected -Format Json -Confirm:$false
        $outputPath = Join-Path $fixtureDirectory 'from path [literal].json'
        $actual = $report.Write($source, $outputPath, 'Json', $false)
        $bytes = [IO.File]::ReadAllBytes($outputPath)
        Assert-Fixture (
            $actual -is [string[]] -and $actual.Count -eq 1 -and $actual[0] -ceq $outputPath -and
            [BitConverter]::ToString($bytes[0..2]) -ceq 'EF-BB-BF' -and
            [Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($expected)) -and
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($source)) -ceq $before
        ) 'The file route changed input bytes or same-engine timestamp and BOM semantics.'
    }

    Test-Fixture 'CSV and HTML use their own report shape and retain recorded state' {
        $document = New-FixtureAssessment
        $html = $report.Render($document, 'Html')
        Assert-Fixture (
            $html.Contains('State: Complete') -and $html.Contains('Failed checks require review') -and
            $html.Contains('Fail (suppressed)') -and $html.Contains('&lt;north&gt; &amp; south') -and
            $html.Contains('CHECK.HTML.FIRST') -and $html.IndexOf('Alpha') -lt $html.IndexOf('Zeta')
        ) 'HTML changed recorded state, guidance, stable column order, or escaping.'
        $csv = $report.Render($document, 'Csv')
        Assert-Fixture (
            $csv.Contains('FINDING.CSV') -and $csv.Contains('fixture account') -and
            $csv.Contains('fixture sibling') -and -not $csv.Contains('CHECK.HTML.FIRST')
        ) 'CSV did not prioritize Findings and field aliases.'
        $document.Findings = @()
        Assert-Fixture (
            $report.Render($document, 'Csv') -ceq '"RuleId","Target","Status","Severity","Evidence"'
        ) 'An explicitly empty Findings list changed its CSV header or fell back to Checks.'
        $document.PSObject.Properties.Remove('Findings')
        Assert-Fixture (
            $report.Render($document, 'Csv').Contains('CHECK.HTML.FIRST')
        ) 'Absent Findings did not fall back to Checks.'
        $document.Checks = @()
        $document.Coverage = [ordered]@{}
        Set-StrictMode -Version Latest
        $html = $report.Render($document, 'Html')
        Assert-Fixture (
            $html.Contains('No checks collected') -and $html.Contains('Coverage was not recorded.')
        ) 'Empty report evidence changed under StrictMode.'
    }

    Test-Fixture 'direct paths follow the PowerShell location and reject another provider' {
        $location = Get-Location
        $processDirectory = [Environment]::CurrentDirectory
        $physical = Join-Path $fixtureDirectory 'process location'
        $shell = Join-Path $fixtureDirectory 'shell location'
        $null = [IO.Directory]::CreateDirectory($physical)
        $null = [IO.Directory]::CreateDirectory($shell)
        try {
            [Environment]::CurrentDirectory = $physical
            Set-Location -LiteralPath $shell
            $paths = $report.Write((New-FixtureAssessment), 'relative [literal].json', 'Json')
            $expected = Join-Path $shell 'relative [literal].json'
            Assert-Fixture (
                $paths.Count -eq 1 -and $paths[0] -ceq $expected -and [IO.File]::Exists($expected) -and
                -not [IO.File]::Exists((Join-Path $physical 'relative [literal].json'))
            ) 'The direct report resolved relative output in the process directory.'
        }
        finally {
            Set-Location -LiteralPath $location.Path
            [Environment]::CurrentDirectory = $processDirectory
        }
        $failure = Get-FixtureFailure {
            $report.Write((New-FixtureAssessment), 'Env:ADANALYZER_REPORT_FIXTURE_INVALID_PROVIDER', 'Json')
        }
        Assert-Fixture (
            $failure.Exception.GetBaseException().Message -like '*FileSystem provider*'
        ) 'The direct destination lost its native provider rejection.'
    }

    Test-Fixture 'invalid inputs fail before output effects' {
        $document = New-FixtureAssessment
        $root = Join-Path $fixtureDirectory 'invalid output'
        $path = Join-Path $root 'assessment'
        $null = Get-FixtureFailure {
            $report.Write($document, $path, 'Unsupported')
        }
        $unsupported = Get-FixtureFailure {
            $report.Write(@{ SchemaVersion = 2 }, $path, 'All')
        }
        Assert-Fixture (
            $unsupported.Exception.GetBaseException().Message -like '*Unsupported Assessment SchemaVersion*'
        ) 'The direct report did not retain the operation reader cause.'
        $null = Get-FixtureFailure {
            $report.Render($document, 'All')
        }
        $source = Join-Path $fixtureDirectory 'render-source.json'
        [IO.File]::WriteAllText($source, '{"SchemaVersion":1,"Target":"fixture"}', [Text.UTF8Encoding]::new($false))
        $null = Get-FixtureFailure {
            $report.Render($source, 'Json')
        }
        Assert-Fixture (-not [IO.Directory]::Exists($root)) 'An invalid direct operation created an output directory.'
    }

    Test-Fixture 'dry run validates and projects without resolution, serialization or writes' {
        $script:dryRunReads = 0
        $document = New-FixtureAssessment
        $document | Add-Member -MemberType ScriptProperty -Name ProjectionProbe -Value {
            $script:dryRunReads++
            'fixture projection'
        }
        function script:ConvertTo-Json {
            throw 'Dry run reached the JSON serializer.'
        }
        function script:ConvertTo-Csv {
            throw 'Dry run reached the CSV serializer.'
        }
        function script:Resolve-ADAnalyzerFilePath {
            throw 'Dry run attempted to resolve the destination.'
        }
        function script:Write-ADAnalyzerOperationFile {
            throw 'Dry run reached the operation writer.'
        }
        function script:Write-ADAnalyzerFile {
            throw 'Dry run reached the atomic file writer.'
        }
        $paths = @($report.Write($document, 'Env:ADANALYZER_REPORT_FIXTURE_DRY_RUN', 'All', $true))
        Assert-Fixture (
            $paths.Count -eq 0 -and $script:dryRunReads -eq 1
        ) 'Dry run returned paths or skipped the local assessment projection.'
        $failure = Get-FixtureFailure {
            $report.Write(@{ SchemaVersion = 2 }, 'Env:ADANALYZER_REPORT_FIXTURE_DRY_RUN', 'All', $true)
        }
        Assert-Fixture (
            $failure.Exception.GetBaseException().Message -like '*Unsupported Assessment SchemaVersion*'
        ) 'Dry run skipped input validation.'
    }
}

$fixtureDirectory = $null
if ($Case -ne 'Construction') {
    $fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ('report-fixture-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($fixtureDirectory)
}
try {
    switch ($Case) {
        'Native' {
            foreach ($scenario in 'HtmlEvidence', 'CsvEvidence', 'CsvSerializer', 'Writer') {
                foreach ($action in 'Continue', 'Stop', 'SilentlyContinue', 'Ignore') {
                    Test-Fixture ($scenario + ' ' + $action) {
                        Assert-FixtureNativeReport $scenario $action 'Stop'
                    }
                }
            }
            foreach ($scenario in 'HtmlEvidence', 'Writer') {
                Test-Fixture ($scenario + ' Ignore with inherited Continue') {
                    Assert-FixtureNativeReport $scenario 'Ignore' 'Continue'
                }
            }
            foreach ($action in 'Continue', 'Stop') {
                Test-Fixture ('standalone HTML ' + $action) {
                    Assert-FixtureNativeReport 'StandaloneHtml' $action 'Stop'
                }
            }
        }

        'Approval' {
            Invoke-ApprovalFixtures
        }

        'Construction' {
            Test-Fixture 'documented construction is literal and inert' {
                function script:Test-Path {
                    throw 'The report constructor touched a path.'
                }
                function script:Write-ADAnalyzerFile {
                    throw 'The report constructor attempted to write.'
                }
                $first = [ADAnalyzerAssessmentReport]::new()
                $second = [ADAnalyzerAssessmentReport]::new()
                Assert-Fixture (
                    $first.GetType().Name -ceq 'ADAnalyzerAssessmentReport' -and
                    -not [object]::ReferenceEquals($first, $second)
                ) 'The documented loader did not expose an inert report constructor.'
            }
            Test-Fixture 'documented render and write overloads' {
                $type = [ADAnalyzerAssessmentReport]
                Assert-Fixture (
                    $null -ne $type.GetMethod('Render', [type[]]@([object], [string])) -and
                    $null -ne $type.GetMethod('Write', [type[]]@([object], [string], [string])) -and
                    $null -ne $type.GetMethod('Write', [type[]]@([object], [string], [string], [bool]))
                ) 'A public report overload is missing.'
            }
        }

        'Standalone' {
            Test-Fixture 'the operations file independently exposes the report API' {
                $report = [ADAnalyzerAssessmentReport]::new()
                $record = @{
                    SchemaVersion = 1
                    Target = 'standalone report'
                }
                $path = Join-Path $fixtureDirectory 'standalone [literal].json'
                $paths = $report.Write($record, $path, 'Json')
                Assert-Fixture (
                    $paths.Count -eq 1 -and $paths[0] -ceq $path -and
                    [IO.File]::ReadAllText($path) -ceq $report.Render($record, 'Json')
                ) 'The operations file requires the full loader to produce a report.'
            }
        }

        'Direct' {
            Invoke-DirectReportFixtures
        }

        'Isolation' {
            Test-Fixture 'separate and reused reporters retain no input or failure state' {
                $first = [ADAnalyzerAssessmentReport]::new()
                $second = [ADAnalyzerAssessmentReport]::new()
                $record = [pscustomobject]@{
                    SchemaVersion = 1
                    Target = 'first target'
                }
                $prior = $first.Render($record, 'Json')
                $record.Target = 'different target'
                Assert-Fixture ($second.Render($record, 'Json').Contains('different target')) 'A separate reporter reused earlier input.'
                $null = Get-FixtureFailure {
                    $first.Render(@{ SchemaVersion = 2 }, 'Json')
                }
                Assert-Fixture (
                    $first.Render($record, 'Json').Contains('different target') -and
                    $prior.Contains('first target') -and -not $prior.Contains('different target')
                ) 'A reused reporter cached prior data or failure state.'
            }

            Test-Fixture 'secondary runspace disposal preserves an original reporter' {
                $report = [ADAnalyzerAssessmentReport]::new()
                $record = @{
                    SchemaVersion = 1
                    Target = 'original report'
                }
                $before = $report.Render($record, 'Html')
                $worker = [powershell]::Create()
                try {
                    $snippet = @'
param($Fixture, $Root)
$ErrorActionPreference = 'Stop'
& $Fixture -Case Standalone -RepositoryRoot $Root
'@
                    $rows = @($worker.AddScript($snippet).AddArgument($PSCommandPath).AddArgument($RepositoryRoot).Invoke())
                    Assert-Fixture (
                        $rows.Count -eq 1 -and [string]$rows[0] -ceq 'PASS assessment report Standalone 1' -and
                        $worker.Streams.Error.Count -eq 0
                    ) ('Secondary report failed: ' + ($worker.Streams.Error -join [Environment]::NewLine))
                }
                finally {
                    $worker.Dispose()
                }
                Assert-Fixture (
                    $report.Render($record, 'Html') -ceq $before
                ) 'Disposal changed the original report instance.'
            }
        }
    }
}
finally {
    if ($null -ne $fixtureDirectory) {
        [IO.Directory]::Delete($fixtureDirectory, $true)
    }
}
'PASS assessment report ' + $Case + ' ' + $script:passed
