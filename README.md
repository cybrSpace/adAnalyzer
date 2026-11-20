# Active Directory Analyzer : 

+ .\bin\ADEnvironment.psm1 is a homegrown PoSh module I wrote which provides the **Get-ADEnvironment** & **Set-ADEnvironment** cmdlets to execute the corrective actions required for my **_AD Tactical Hardening Playbook_**
+ .\bin\Start-ADAnalyzer.ps1 is the helper script I wrote for the **Get-ADEnvironment** & **Set-ADEnvironment** cmdlets to simplify the ongoing analysis, reporting, remediation, & validation of AD Environment Hardening efforts via the helper's **Start-ADAnalyzer** cmdlet 
+ The manifest registers the bundled Active Directory DLL in .\lib; installed RSAT modules are not required.
+ Various other scripts loaded in .\etc 

## Running the module

Version 1.2 adds a scan-owned assessment engine, configurable rule profiles, evidence snapshots, change comparisons, and reviewed remediation plans. The main workflow is:

```powershell
Import-Module .\ADEnvironment.psd1
$credential = Get-Credential # optional; the CLI never prompts automatically
$profile = Import-ADAnalyzerProfile -Path .\profiles\example.psd1
# Customize example.invalid and the account-role rules before collecting.
$scan = Get-ADAnalyzerAssessment -Profile $profile -Credential $credential
$scan.Coverage
$scan.Findings | Select-Object RuleId, Target, Status, Severity, Applicability, Suppressed
Export-ADAnalyzerAssessment -Assessment $scan -Path .\reports\current -Format All
```

The exporter writes JSON evidence, HTML with summary/check tables and expandable evidence, and CSV projections. Secret-bearing fields and policy XML return boolean presence indicators such as `SecretPresent: true` or `cpasswordPresent="true"`; the values and masked placeholders are omitted. GPO/file/item locations remain available for remediation, and unreadable content stays Unknown. Legacy GPO reports also retain typed `property.setting.secretPresent` booleans; true indicators produce a stored-secret finding, false indicators remain inventory, and setting values are omitted. Exporting copies records without modifying the returned scan. Compare saved JSON snapshots with `Compare-ADAnalyzerAssessment -Reference .\reports\previous.json -Difference $scan`. Changes are classified as New, Resolved, Changed, or Unchanged using stable rule/target identities, including changes to passing checks. A failed check becoming Pass/NotApplicable is resolved; becoming Unknown does not prove resolution. A check absent from the new scan is Changed with `Reason: NotObservedInDifference`, including after failed or skipped collection; absence does not prove remediation. Different targets/search-base scopes are rejected as drift comparisons.

Structured assessment and raw policy inputs support generic .NET dictionaries as well as hashtables and ordered dictionaries. Lookup honors each dictionary's key comparer and key types, distinguishes a present null from a missing key, and preserves boolean-only named-secret evidence in JSON, HTML and CSV under normal or strict error handling.

Secret presence uses native password/string length and collection cardinality. A data key named `Count` or an extended `Password`, `Length` or `Count` member cannot override that metadata. Null values, empty strings/collections/passwords and disposed secure strings remain absent; scalar false and zero still count as present. Returned evidence contains only a boolean indicator, without reading credential contents.

DTD-bearing XML is unsupported in secret-presence projection and assessment export. Supplied documents, nodes owned by a DTD document, and unparseable DTD-bearing text fail with an explicit error before export writes; declarations cannot retain payloads through the text fallback. The parser continues to prohibit DTD processing and external resolution. Literal DOCTYPE examples inside safely parsed comments or CDATA remain supported, along with ordinary text and DTD-free XML. GPO readers already reject DTDs. The XML node projection helper and assessment export accept Document and Element nodes; other node kinds require an explicit supported container. Export projects the original DOM before serialization, preserving default secret presence and DTD-owner checks while rejecting contextual leaf values before any writes. Element results have a fresh, empty owner document and no parent, preserving their projected subtree, namespaces, text and default attributes. Full-document results remain independent document copies. DOM projection preserves explicit and schema-default attributes in both supported forms, so default secret fields also produce boolean presence. The projected document retains its declaration and base URI without retaining the source schema type graph.

Use Windows PowerShell 5.1 or PowerShell 7 on Windows. Import the package manifest so the bundled AD commands and provider are registered before the analyzer classes load:

```powershell
Import-Module .\ADEnvironment.psd1
Get-ADAnalyzerAssessment -Domain 'example.com'
# A domain-joined client is not required when using explicit credentials.
$credential = Get-Credential
Get-ADAnalyzerAssessment -Domain 'example.com' -Credential $credential
```

Live collection needs a reachable domain controller running AD Web Services, read access to directory objects, and SMB read access to SYSVOL. The package supplies its own GPO reader; it does not load the GroupPolicy module or use GPMC COM. Explicit credentials are forwarded to directory queries and a temporary SYSVOL drive, which is removed when the read finishes or fails. The reader pins metadata and SYSVOL reads to the same DC and warns if directory and GPT.INI versions differ.

```powershell
$gpos = Get-ADAnalyzerGpo -All -Domain 'example.com' -Credential $credential
$gpo = $gpos | Select-Object -First 1
$policy = Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $credential -AsObject
$xml = Get-ADAnalyzerGpoReport -Gpo $gpo -Credential $credential
# Parse a previously copied policy folder without a directory connection:
$offline = Read-ADAnalyzerGpo -Path 'C:\PolicyCopies\{GPO-GUID}'
```

`Read-ADAnalyzerGpo` parses Machine/User Registry.pol (including typed values and deletion directives), security-template INF, INI files, and XML such as Group Policy Preferences. It preserves raw INI settings, XML, registry bytes, and a file inventory with `UnparsedFiles` for unsupported content. Account and Kerberos keys are recognized only in their defined INF sections. Unknown or misplaced entries remain raw INI inventory, are excluded from imported baselines, and produce an explicit Unknown coverage check for the authoritative account template. Restricted Groups requires matching scope and full relative `Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf` or `User/...` provenance. Leaf-only and auxiliary INI sources remain raw inventory; they do not establish Restricted Groups configuration. The generated XML feeds the existing security/password analyzers and includes raw registry, preference, and other XML/INI records. GPO identity uses GUIDs, so policies with identical display names remain distinct. SID names are resolved where available; lookup status stays visible and a missing domain match does not prove a SID invalid.

Registry source identities from the outer GPO reader are `Machine/Registry.pol` or `User/Registry.pol`, so copying an identical policy or changing its SYSVOL root does not change its check identities. Raw writes and bytes remain inventory; assessment metadata enrichment uses final effective values, including deletion records. Comparing an older snapshot that uses absolute registry sources may report identity changes. The low-level registry parser retains its supplied file path.

Missing Machine/User folders are skipped on all supported engines, including Windows PowerShell 5.1 when its literal lookup returns no item for a bracketed path. The reader checks the returned side item as well as the missing-item exception. Access-denied and unexpected read errors remain terminating.

All relative GPO source and inventory paths use forward slashes across Windows and portable offline hosts. Physical file-read paths and the returned policy root are preserved. Older snapshots containing native backslash separators may show identity or evidence changes when compared with canonical-path snapshots.

Local Users and Groups preference checks follow their scope, source, and UID; missing UIDs use a file-local XML path. Security-option checks follow their scope, source, and setting. Unrelated file/item insertion or source removal does not renumber existing identities. Repeated identities remain separate, with occurrence suffixes confined to their duplicate family. Missing-UID sibling positions and ambiguous duplicate occurrences can still change identity when those items are reordered. Older ordinal-based snapshots may show identity changes when compared with these snapshots.

This is a file-based policy reader, not a GPMC HTML report generator or an ADMX display-name engine. Scripts and other unsupported client-side extension formats are inventoried rather than interpreted; parsed settings are not a calculation of effective policy or RSoP. Offline parsing is portable; live directory/SMB integration is supported on Windows. The older GroupPolicy DLLs in `lib` are not loaded.

`etc/Test-SAMLProtectedResponseTimes.ps1` is an explicit provider-specific timing client. Dot sourcing is inert; CLI requires `ConfigPath` JSON with `Url` (`auth`, `logn`, `saml`, `appl`, `data`) and `Config` objects, plus optional `Credential`/`OutputPath`. `appl` must be the actual ACS POST endpoint. `Target.Initialize` retains its two-argument credential-prompt API and adds an explicit-credential overload. It performs JSON authentication, reads a static HTML form, and invokes the application POST once; failed POSTs are not replayed. The strict form reader decodes one `SAMLResponse` and optional `RelayState` once, ignores comments/raw text/CDATA, rejects ambiguous fields and templates, and never executes HTML or follows its form action. It is not a general browser, MFA flow, or SAML signature validator. Config defaults are `limit=60`, `wait=30`, `RequestTimeoutSeconds=30` (1–300); waits occur only between samples. Requests terminate on errors and use native timeout/SSL capabilities. Windows PowerShell's temporary process TLS setting is serialized for cooperating requests and restored; unrelated process writers are not coordinated. Timeouts are per request/operation, not a complete-workflow deadline. Timing CSV retains its five columns and atomic export. The CLI/function wrapper disposes owned sessions; callers using `Target.Initialize` directly own returned session lifetime.

`etc/New-ADPASUser.ps1` defines `New-ADPASUser -CsvPath <file>` with optional `Server`, `Credential`, and `WhatIf`; CLI input is explicit and dot sourcing is inert. It imports the bundled AD module locally, uses the target naming context for exact SAM existence checks, warns and skips existing users, and stops after lookup errors. Creation requires `name`, `username`, `password`, and `path`; existing-user rows need only `username`. Optional given/surname/display/department/employee/UPN fields retain their CSV meaning. Absent users get one `New-ADUser` invocation with enabled/change-password-at-logon flags, without an extra enable call or returned password/account payload. `WhatIf` reads and validates but does not create users. The batch is not transactional: earlier rows and even the failing row may persist after an error. There is no automatic retry, rollback, or resumption of partially created existing users.

```powershell
. .\etc\New-ADPASUser.ps1
$importer = [ADAnalyzerPasUserImporter]::new()
$options = @{
    Server = 'dc01.example.com'
}
$plan = $importer.Preview('.\pas-users.csv', $options)
$plan.Actions | Select-Object ActionId, Username, Path, Status, PasswordPresent

$approvedId = '<reviewed pending action ID>'
$result = $importer.Apply('.\pas-users.csv', $plan, @($approvedId), $options)
```

The constructor is inert. `Preview` reads the CSV and checks account existence. Its detached plan reports password presence as a Boolean. `Apply` requires explicit IDs from the reviewed pending actions, validates the current file and target against the plan, and checks the account again before one creation attempt. Approve at most one pending action per account. Approval covers the visible account fields and password presence. The current CSV supplies the password during the approved operation. `Preview` is the class dry-run method. Use `New-ADPASUser -WhatIf` for native PowerShell confirmation and warning behavior.

`etc/Test-Runspace.ps1` now loads without opening authentication contexts. `Connect-WindowsServer -context <host> -principal <SAM-group>` delegates to `Get-ServerHPA` and accepts optional `Credential`; the legacy `domain` argument is unused and borrowed. CLI requires an explicit host and group. `Initialize-RunspacePool` returns an unopened `jobs/init/pool` dictionary, with positive `MaxRunspaces` defaulting to `Environment.ProcessorCount`; callers own opening and disposing the pool. Absolute sibling-reader configuration is copied into workers so cloned connection functions can load their dependency. `Invoke-Cmdlet` runs once unless `Retry` is set, then uses `Max` total attempts (default 3) and `DelaySeconds` between attempts (default 1). It preserves successful output and terminal errors; callers own retry safety and block completion.

The prototype's `Format-WindowsServerException` uses local classification state and synchronizes both authentication-error categories against the shared attempt counter. The configured threshold is checked atomically with each increment; unknown diagnostics retain their input evidence.

```powershell
. .\bin\ADHostScanState.ps1
$formatter = [ADAnalyzerHostScanState]::new()
$attempts = [hashtable]::Synchronized(@{
    attempt = 0
})
$rules = [ordered]@{
    denied = @{
        msg = 'access denied'
        value = @('Access is denied.')
    }
}
$formatter.Format('Access is denied.', $rules, 3, $attempts)
```

`ADAnalyzerHostScanState` borrows the caller's rules and synchronized attempt table for one call. It checks each matching authentication category under the table's existing lock and throws when the limit is reached. The formatter retains no state and performs no host access. The native command loads this class inside its original worker scope.

`etc/Get-LocalAdministrators.ps1` exposes local-only `Get-LocalAdministrators` (CLI: `-Invoke`). It resolves Administrators by its well-known SID and reads the local WinNT group, retaining the original eight fields plus canonical `memberSID`, `memberResolutionKind`, and `memberMessage`. `memberLocal` requires a valid account SID and an exact match to the actual machine's SAM authority; builtin, well-known, Entra, and other authorities have separate categories. Valid unresolved Entra SIDs are not invalid. `memberInvalid` is null when SID evidence is missing, and true only for a malformed SID. `memberLocalEnabled` is nullable: it is copied only for a local user whose exact SID is confirmed by local-account lookup. Individual metadata errors stay with their rows; enumeration and owned-entry cleanup failures terminate without partial results. Dot sourcing performs no collection. Live collection requires Windows; an unavailable local-account lookup leaves enabled state unknown.

```powershell
. .\etc\Get-LocalAdministrators.ps1
$inventory = [ADAnalyzerLocalAdministratorInventory]::new()
$members = $inventory.Read()

$evidence = @{
    Domain = 'server1'
    Name = 'LocalUser'
    Class = 'User'
    SID = 'S-1-5-21-111-222-333-1001'
    SidValid = $true
}
$row = $inventory.Project($evidence, 'server1')
```

The constructor is inert. `Read()` uses the current Windows identity, closes the local group entry before checking account state, and returns the complete detached inventory. `Project(evidence, machineName)` uses supplied normalized evidence and the local clock. It accepts string fields `Domain`, `Name`, `Class`, `SID`, and `Message`, and Boolean fields `SidValid` and `EnabledEvidence`. Omitted evidence remains unknown where applicable.

`etc/Get-MSSQLServers.ps1` exposes `Get-ADMSSQLServers` with optional `SearchBase`, `Server`, `Credential`, `OutputPath`, and `OperationTimeoutSeconds` (1–300, default 30 per CIM operation, not a global deadline). Its OS regex defaults to `Windows Server`. Discovery uses the bundled AD PSDrive by default (`DirectoryConnection=Direct` opts out), pins the resolved DC, and finishes drive cleanup before host probes. Each host owns a CIM session. The returned `Collection` retains `Export(path)` and the six existing columns: `computer.Status` means the service query succeeded; `service.Status` contains literal states such as `Running` or `Stopped`. A successful query with no SQL-named services has a blank-service row. Host failures and cleanup errors remain in `computer.Message`; cleanup-only failure preserves observed states. Discovery failures terminate, export uses atomic replacement, and `WhatIf` suppresses writes. Live AD/CIM needs Windows and reachable services. Dot sourcing is inert; CLI discovery requires explicit `SearchBase` or `Server`.

```powershell
. .\etc\Get-MSSQLServers.ps1
$inventory = [ADAnalyzerSqlServiceInventory]::new()
$services = $inventory.Read(@{
    Server = 'dc01.example.com'
    SearchBase = 'OU=Servers,DC=example,DC=com'
    OperationTimeoutSeconds = 45
})
$services.Export('.\reports\sql-services.csv')
```

The constructor is inert. `Read()` uses ambient discovery and creates an owned AD PSDrive for the search. `Read(options)` accepts `SearchBase`, `Filter`, `Server`, `Credential`, `DirectoryConnection`, and `OperationTimeoutSeconds` as case-insensitive option names. An empty `Filter` matches all operating systems. Set `DirectoryConnection` to `Direct` to query without creating a drive. Both overloads return one `Collection` after directory cleanup and all CIM cleanup attempts. Host cleanup failures are recorded in `computer.Message`. Call `Export(path)` to write the result, or use the compatibility command for PowerShell confirmation and `WhatIf`.

`etc/Get-GroupCNMember.ps1` exposes `Get-GroupCN -Array @('GroupA','GroupB')` with optional `Server`, `Credential`, and `OutputPath`. It uses the bundled library, escapes exact CN/SAM selectors, follows member DNs with a visited set per matched root, and caches repeated member reads within the call. Direct group/cycle edges and empty-group marker rows remain visible. CSV columns stay `group.DN,group.CN,member.SamAccountName,member.objectClass`: the first is the containing group's DN and the second the requested root label. Multiple matching roots are retained. Lookup/no-match/conversion/write failures prevent partial output/export; `WhatIf` suppresses writes. Dot sourcing is inert and CLI selectors are explicit.

```powershell
. .\etc\Get-GroupCNMember.ps1
$inventory = [ADAnalyzerGroupInventory]::new()
$members = $inventory.Collect(@('GroupA', 'GroupB'))
$members = $inventory.Export(@('GroupA', 'GroupB'), '.\reports\membership.csv')
```

`ADAnalyzerGroupInventory` has an inert constructor. `Collect(selectors)` accepts an optional server and credential as trailing arguments. It retains the requested group labels, breadth-first membership order, duplicate matches, and empty-group marker rows. Its member cache lasts for one call. `Export(selectors, path)` writes the complete CSV before returning rows. Pass a trailing `$true` for a dry run. To select a server and credential for export, supply both after the path and optionally add the dry-run Boolean.

`etc/Start-GroupCompare.ps1` defines `Get-ADAnalyzerGroupMemberDifference -SourceGroup <identity> -ReferenceGroup <identity>`, with optional `Server` and `Credential`. Its focused comparison class reads each group once through the bundled AD library and returns SAM names for direct source members absent from the reference. Comparison is case-insensitive and retains source order and duplicates; nested groups are not expanded. Only differing members require object lookups. Missing/ambiguous records and lookup errors terminate without partial names. The wrapper imports commands locally and preserves ambient AD-drive server/credential defaults when overrides are omitted. Dot sourcing is inert; CLI targets are explicit. Class instances retain only group selectors, not credentials or command dependencies. A mocked 100/50-member case reduces group reads from 101 to two while preserving 50 names; this is a command-count measurement, not live AD timing.

The two `etc/Get-LocalGroup*.ps1` helpers expose pipeline-capable `Get-LocalGroupMember -ComputerName <hosts>` with optional `Credential`. They use the Windows framework and the well-known Administrators SID, preserving direct nested-group rows. Returned `Computer`, `Domain`, and `samaccountname` fields are detached; `Domain` is the associated principal context's name, not a verified account-domain classification. Each retrieved member, enumerator, result, group, and owned context is cleaned up before that host's rows are emitted. Borrowed member contexts are not disposed. Earlier completed hosts may already have emitted rows when a later host fails. Dot sourcing is inert, and CLI execution requires explicit computers.

```powershell
. .\etc\Get-LocalGroup.ps1
$reader = [ADAnalyzerLocalGroupReader]::new()
$members = $reader.Read(@('server1', 'server2'))
$namedMembers = $reader.Read(@('server1'), [pscredential]::Empty, $true)
```

Either helper loads `ADAnalyzerLocalGroupReader` from the checkout. The constructor is inert. Pass an explicit computer list to `Read`. It uses the current Windows identity by default, accepts a trailing `PSCredential` for explicit authentication, and adds `Name` when the third argument is `$true`. The method returns detached rows in computer and enumeration order after all requested hosts complete and their resources close. A failure terminates the call before it returns any rows. Live reads use the built-in Windows principal framework without RSAT and require access to the selected hosts.

The two `etc/Get-ServerHPA*.ps1` helpers expose `Get-ServerHPA -Computer <host> -Target <SAM-group-name>` with optional `Credential`. They use the Windows principal framework without RSAT, return detached `Computer`, `Name`, `SamAccountName`, `SID`, and `Description` fields, and dispose their group/context before returning. Principal methods and member enumeration are not part of the returned snapshot. Credential prompts and hardcoded startup targets are removed; dot sourcing is inert. Lookup/projection/cleanup failures remain terminating, with secondary cleanup evidence attached to the primary error.

```powershell
. .\etc\Get-ServerHPA.ps1
$reader = [ADAnalyzerPrincipalGroupReader]::new()
$group = $reader.Read('server1', 'Administrators')
```

Either helper loads the same packaged class from the checkout. The constructor is inert. `Read(computer, target)` returns the detached group after closing its principal resources. Supply a trailing `PSCredential` for explicit authentication. The worker can load either helper using the existing package-relative layout.

`etc/Get-ADServers.ps1` exposes `Get-ADServers -Identity @('server1','server2')` with optional `Server`, `Credential`, and `OutputPath`. It loads the bundled AD library in the owning function scope, preserves the `name,ipv4Address` columns and input order, and buffers all requested lookups before returning/exporting. Missing or ambiguous identities and lookup/conversion/write errors preserve previous output. Dot sourcing is inert; direct execution requires explicit identities and writes only with `OutputPath`. `WhatIf` returns inventory while suppressing file writes.

```powershell
. .\etc\Get-ADServers.ps1
$inventory = [ADAnalyzerServerInventory]::new()
$servers = $inventory.Collect(@('server1', 'server2'))
$servers = $inventory.Export(@('server1', 'server2'), '.\reports\servers.csv')
```

`ADAnalyzerServerInventory` has an inert constructor. `Collect(identities)` accepts an optional server and credential as trailing arguments. It validates all identities, uses the bundled library, then returns rows in input order with duplicates and nullable IPv4 addresses intact. `Export(identities, path)` collects the same rows, writes the complete CSV, then returns the rows. Pass a trailing `$true` for a dry run. To select a server and credential for export, supply both after the path and optionally add the dry-run Boolean. The compatibility command retains native binding, confirmation and `WhatIf`.

`etc/Test-ServerConnection.ps1` defines `Test-ServerConnection -ComputerName <hosts>` with optional `Port` (default 445), `OutputPath`, and `WhatIf`. Its scan class validates and copies explicit selectors, probes each requested host/port pair once through the built-in Windows `Test-NetConnection`, and returns detached rows in input order. The five columns remain `ComputerName,RemoteAddress,RemotePort,tcpTest,result`: `tcpTest` is reachability; `result` means the probe completed with one boolean result. Refused connections retain `tcpTest=false,result=true`; thrown, nonterminating, empty, ambiguous, or malformed probe results have null address/TCP fields and `result=false`. Optional CSV export uses the shared UTF-8 atomic writer after complete serialization; failures preserve the prior report and emit no rows. There is no automatic filename or formatting-object output. `WhatIf` collects rows while suppressing file/directory writes. Dot sourcing is inert and CLI computers are explicit. This utility needs the built-in Windows networking command, not RSAT; probe timing follows that command's native behavior.

`etc/Get-NTLMEvents.ps1` now loads inertly and requires explicit hosts. Its class-owned scan reads Security event 4624 with the named `LmPackageName=NTLM V1` filter and excludes anonymous logons. The explicit workflow uses a server-side XPath query on Windows PowerShell 5.1 and PowerShell 7; it does not require RSAT. The default start time is computed once per invocation as one day before the call. Event-derived time and the existing eight CSV fields are preserved.

```powershell
. .\etc\Get-NTLMEvents.ps1
$rows = Get-ADAnalyzerNtlmEvents -ComputerName @('server1', 'server2') -Credential $credential
$rows = Get-ADAnalyzerNtlmEvents -ComputerName 'server1' -StartTime (Get-Date).AddDays(-2) -OutputPath .\reports\ntlm.csv
# Direct class method; an empty credential uses ambient authentication defaults.
$scan = [Target]::Scan([Collections.ArrayList]@('server1'), [datetime](Get-Date).AddDays(-1), [pscredential]::Empty)
$rows = $scan.Report()
```

The new scan overload copies selectors, retains no credentials, and closes owned event records after projection. Query, projection, and cleanup failures terminate before a partial report returns. Optional CSV export happens only for an explicit path after collection; `WhatIf` collects without writes, and export failure emits no report rows. The legacy `Target.Scan(ArrayList, Hashtable, string)` overload retains its explicit credential prompt. Its arbitrary named EventData filters require PowerShell 6 or later and are rejected before prompting on 5.1; use the DateTime/PSCredential overload there. This follows the documented [named-data filter support](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable). Live event collection requires Windows, event-log permissions, and reachable selected hosts; tests use synthetic events.

The standalone `etc/Get-GPOXML.ps1` and `etc/Get-LocalAdminGPO.ps1` scripts also use the package reader. They require explicit targets and selection, return XML or canonical check objects, and write only when `OutputPath` is supplied. Dot sourcing loads their interfaces without connecting, importing native modules, prompting, or opening files:

```powershell
. .\etc\Get-GPOXML.ps1
. .\etc\Get-LocalAdminGPO.ps1
$xml = Get-ADAnalyzerGpoXml -Domain example.com -Guid $gpo.Id -Credential $credential -OutputPath .\reports\policy.xml
$groups = Get-ADAnalyzerLocalAdminGpo -Domain example.com -All -Credential $credential -OutputPath .\reports\local-groups.csv
# A prefetched package report can be analyzed offline, including on macOS:
$groups = Get-ADAnalyzerLocalAdminGpo -InputObject $policy
$xml = Get-ADAnalyzerGpoXml -InputObject $policy
```

`ADAnalyzerGpoXmlInventory` is available after dot sourcing `etc/Get-GPOXML.ps1`. The constructor is inert. `RenderProvided(report)` renders a supplied package report. `Collect(selection)` reads the selected GPO using a hashtable with `Domain`, optional `Server`, and exactly one `Name` or `Guid`. A trailing credential supplies explicit authentication. Both methods return canonical XML with Boolean presence for recognized secrets.

```powershell
. .\etc\Get-GPOXML.ps1
$inventory = [ADAnalyzerGpoXmlInventory]::new()
$xml = $inventory.RenderProvided($policy)
$xml = $inventory.ExportProvided($policy, '.\reports\policy.xml')
```

`ExportProvided(report, path)` and `ExportSelected(selection, path)` return the XML after writing it. Both require a FileSystem path. Pass a trailing `$true` to `ExportProvided` for a dry run. For `ExportSelected`, pass the credential or `[PSCredential]::Empty` before the trailing dry-run argument. A dry run returns the XML without writing it. The compatibility command retains native `WhatIf` and its existing output timing.

`ADAnalyzerLocalAdminPolicyInventory` is available after dot sourcing `etc/Get-LocalAdminGPO.ps1`. Construction has no file or network effects. `AnalyzeProvided(reports)` accepts package reports or their JSON round-trip and returns detached ordered checks. A trailing profile path selects an explicit profile. `Collect(selection)` uses a hashtable with `Domain`, optional `Server`, and one of `Name`, `Guid`, or `All = $true`. It uses the bundled catalog and policy reader on the selected controller. Supply an optional credential and profile path as trailing arguments.

```powershell
. .\etc\Get-LocalAdminGPO.ps1
$inventory = [ADAnalyzerLocalAdminPolicyInventory]::new()
$checks = $inventory.AnalyzeProvided(@($policy))
$paths = $inventory.Export($checks, 'provided GPO reports', '.\reports\local-groups.csv', 'Csv')
```

`Export(rows, target, path, format)` returns the paths it writes. Pass a trailing `$true` to validate the export without writing. A dry run returns an empty path list. An unreadable policy prevents exporting the inventory. The compatibility command retains native binding, diagnostic streams, and `WhatIf`.

Offline `InputObject` uses the `{Gpo, Policy}` shape returned by `Get-ADAnalyzerGpoReport -AsObject`, with package record objects or their JSON round-trip; dictionary-backed setting rows are rejected. Supply its actual GPO ID and enabled-side Flags rather than inventing metadata for a raw folder. Raw folder parsing remains available through `Read-ADAnalyzerGpo`. The local-group inventory preserves all selected statuses, members/actions, targeting, disabled items, source locations, and boolean credential exposure; it describes stored policy rather than effective machine membership. An unreadable selected policy produces an explicit check and prevents automatic export of the incomplete inventory. Empty inventories export CSV headers. `WhatIf` allows read-only collection and suppresses writes. File replacement stages and closes UTF-8 content beside each destination before promotion; separate output formats are separate file writes. Legacy class CSV and the NTLM/SAML CSV utilities use the same writer after successful conversion. Query, conversion, and write failures propagate and preserve existing reports; no alternate filename is silently selected. A successful empty legacy class export creates an empty CSV, while empty NTLM/SAML exports contain their known headers and no records. Legacy per-class CSV exports retain the union of safely projected columns across heterogeneous finding rows, including unreadable GPOs alongside configured settings; missing fields are empty and null records are skipped. Legacy aggregate JSON keeps flat policy integers as numbers within signed/unsigned 64-bit range and exact decimal strings beyond that range, consistently across supported engines.

Credential-exposure and template-metadata check identities preserve their component boundaries. Separate XML credential locations remain separate even when UIDs repeat; a raw credential attribute and presence marker on the same element count once. Snapshots saved before this identity correction may report identity changes when compared with new scans.

Zero-byte ordinary DWORD, big-endian DWORD, and QWORD records remain in the reader inventory as `KeyOnly` records; they do not establish an effective numeric value or satisfy a value baseline. Valid numeric zero still requires 4, 4, or 8 payload bytes respectively. Empty binary values and deletion directives retain their existing behavior. This follows the documented [zero-field key-creation interpretation](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format) without discarding the original policy record.

## Constructor API

Dot source the portable object entrypoint in a fresh PowerShell process to construct the assessment engine directly:

```powershell
. .\bin\ADAnalyzer.ps1
$configuration = [ADAnalyzerProfile]::new($overrides)
$profile = $configuration.ToHashtable()
$prerequisiteInspector = [ADAnalyzerPrerequisiteInspector]::new()
$packageChecks = $prerequisiteInspector.Inspect()
$onlineChecks = $prerequisiteInspector.InspectOnline($repositoryRoot, $server, $credential, $profile)
$engine = [ADAnalyzerAssessmentEngine]::new($profile)
$scan = $engine.Evaluate($directorySnapshot, $policyReports, 'example.com')
# Defaults: an independent default profile, no policies, target 'offline'.
$offlineEngine = [ADAnalyzerAssessmentEngine]::new()
$scan = $offlineEngine.Evaluate($directorySnapshot)
$reader = [ADAnalyzerGpoReader]::new()
$policy = $reader.Read('C:\PolicyCopies\{GPO-GUID}')
$catalog = [ADAnalyzerGpoCatalog]::new()
# The explicit lookup uses the packaged Windows directory provider.
$policies = $catalog.GetAll($domain)
$gpoReports = [ADAnalyzerGpoReportService]::new()
$report = $gpoReports.Read($gpoMetadata, $credential)
$reportXml = $gpoReports.RenderXmlById($gpoId, $domain, $server, $credential, $sidNames)
$normalizer = [ADAnalyzerGpoSourceNormalizer]::new()
$normalizedPolicy = $normalizer.Normalize($providedReport.Policy)
$xmlWriter = [ADAnalyzerGpoXmlWriter]::new()
$policyXml = $xmlWriter.Render($gpoMetadata, $normalizedPolicy)
$policyEvaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
$checks = $policyEvaluator.Evaluate($gpoMetadata, $policy, $profile)
$membershipGraph = [ADAnalyzerMembershipGraph]::new($groups)
$membership = $membershipGraph.Resolve($account, $domainSid, $privilegedSids)
$accountClassifier = [ADAnalyzerAccountClassifier]::new()
$classification = $accountClassifier.Classify($account, $profile, $membership)
$directoryCollector = [ADAnalyzerDirectoryCollector]::new()
$context = @{
    Server = $server
    Domain = $domain
    Credential = $credential
}
$directorySnapshot = $directoryCollector.Collect($context, $profile)
$directoryEvaluator = [ADAnalyzerDirectoryPolicyEvaluator]::new()
$checks = $directoryEvaluator.Evaluate($directorySnapshot, $profile)
$osLifecycle = $directoryEvaluator.EvaluateOperatingSystem($computer, $profile.Policy.SupportedOperatingSystems)
$directoryProjector = [ADAnalyzerDirectoryObjectProjector]::new()
$accountProjection = $directoryProjector.Project($directoryRecord, 'User')
$accessRules = $directoryProjector.ProjectAces($directoryDescriptor, $distinguishedName, 'DomainRoot')
$hostCollector = [ADAnalyzerHostCollector]::new()
$hostInventory = $hostCollector.Collect($computerNames)
$hostInventory = $hostCollector.Collect($computerNames, $credential, 30, $profile)
$hostEvaluator = [ADAnalyzerHostPolicyEvaluator]::new()
$hostChecks = $hostEvaluator.Evaluate($hostInventory.Hosts, $credential, $profile)
$collector = [ADAnalyzerAssessmentCollector]::new()
$assessmentOptions = @{
    Domain = $domain
    Server = $server
    Profile = $profile
}
$assessment = $collector.Collect($assessmentOptions, $credential)

$secretIndicator = [ADAnalyzerSecretIndicator]::new()
$safeRecord = $secretIndicator.ProjectRecord($settingRecord)
$safeXml = $secretIndicator.ProjectXml($xmlNode)
$safeText = $secretIndicator.ProjectText($diagnosticText)

$projector = [ADAnalyzerEvidenceProjector]::new()
$safeEvidence = $projector.Project($evidence)
# Preserve PowerShell wrapper properties when they are part of the evidence.
$safeWrappedEvidence = $projector.ProjectPowerShellObject($wrappedEvidence)
# Raw lookup deliberately borrows the original value; it does not sanitize it.
$rawValue = $projector.GetValue($record, @('Primary', 'Fallback'), $null)

$documentReader = [ADAnalyzerOperationDocumentReader]::new()
$document = $documentReader.Read($assessmentPath)

$assessmentReport = [ADAnalyzerAssessmentReport]::new()
$html = $assessmentReport.Render($scan, 'Html')
$paths = $assessmentReport.Write($scan, '.\reports\current', 'All')

$assessmentComparer = [ADAnalyzerAssessmentComparer]::new()
$comparison = $assessmentComparer.Compare('.\reports\previous.json', $scan)

$remediationGuard = [ADAnalyzerRemediationGuard]::new()
$accountState = $remediationGuard.ReadState($directoryObject)
$remediationGuard.AssertPlan($reviewedPlan)
```

`ADAnalyzerAccountClassifier` owns schema, OU, group and attribute classification, including conflicting and invalid-rule evidence. Its inert constructor retains no configuration or results; pass a raw profile to `Classify(account, profile)` and optional membership to `Classify(account, profile, membership)`. `Classify(account)` uses no configured selectors. Each call creates fresh result containers; raw attribute evidence retains its existing value types and references. It does not normalize caller profiles or collect directory data. The modern collector reuses one classifier; legacy and remediation callers retain the thin `Get-ADAnalyzerAccountType` adapter.

`ADAnalyzerDirectoryObjectProjector` turns supplied directory records and access control rules into the typed records used by assessment. Its constructor is inert. `Project(record, kind)` returns a new projected account with normalized identity, dates, delegation and lifecycle fields. The overload `Project(record, kind, additionalProperties)` accepts an array of additional directory attributes. `ProjectAces(descriptor, target, targetType)` returns access control entries from a supplied descriptor. Binary directory descriptors use the Windows .NET directory security API. A failed required cast or descriptor load terminates a direct projection. Existing command adapters retain native observation order, error capture, and streamed ACEs.

`ADAnalyzerDirectoryCollector` owns the directory query plan, classification, policy and ACL coverage, and snapshot assembly. Its constructor is inert. `Collect(context, profile)` uses the packaged Windows AD provider and returns the snapshot accepted by the assessment engine. The operation uses the supplied server, with the domain as a fallback for an empty server. `Analysis.DirectoryConnection` defaults to `PSDrive`. The method closes the drive it creates and restores the caller location before returning. Set `Analysis.DirectoryConnection` to `Direct` to use direct queries. Unreadable observations remain explicit in the snapshot's coverage and errors.

`ADAnalyzerHostCollector` owns the Windows CIM inventory for services, operating systems, patches, DNS, SMB and registry values. Construction performs no collection. `Collect(computerNames)` uses the current credential, the default profile and a 30-second CIM operation timeout. The full overload accepts a credential, timeout in seconds and profile. The result contains `Hosts` and `Errors` arrays. A failed registry read stays on its registry record, and a failed class query adds a host collection error. Each call uses fresh results and closes its sessions before returning. The PowerShell compatibility helper releases each session before emitting that host and stops opening sessions when the caller stops the pipeline.

`ADAnalyzerHostPolicyEvaluator` evaluates service, registry, audit, and certificate rules. Its constructor performs no acquisition. `Evaluate(hosts)` uses the default profile, and the other overloads accept a profile or a credential and profile. Pass already collected host records. The method returns the checks in evaluation order, and configured audit and TLS probes run only during evaluation. The credential is scoped to that call. Check containers are fresh, and native CIM observations retain their original row and session metadata. The input owner retains those rows' disposal responsibility. `Test-ADAnalyzerHostPolicy` preserves native binding, diagnostics, and incremental pipeline output.

`ADAnalyzerAssessmentCollector` composes directory collection, optional host checks, GPO reading, and assessment evaluation. The constructor has no side effects. Call `Collect(options)` to use the current credential or `Collect(options, credential)` to supply one for the operation. Options accept `Domain`, `Server`, `SearchBase`, either `Profile` or `ProfilePath`, and the boolean flags `IncludeAcl`, `IncludeHostChecks`, and `SkipGpo`. The method uses profile targets and the current domain when applicable, pins the selected domain controller, and returns the assessment with separate requested and resolved domain fields. It uses the bundled Windows provider, honors the profile's `PSDrive` or `Direct` setting, and releases the directory drive before policy evaluation. Each GPO's SYSVOL access is scoped to its read. `Get-ADAnalyzerAssessment` remains available with its existing PowerShell parameters and diagnostics.

`ADAnalyzerProfile` owns fresh defaults, copying, merging, validation, and explicit JSON/PSD1 loading. `[ADAnalyzerProfile]::new()` and `::new(overrides)` construct independent normalized configuration without file reads or native-module imports. `[ADAnalyzerProfile]::Load(path)` reads a file explicitly and returns a profile instance; `ToHashtable()` returns a detached configuration snapshot for existing APIs. `DefaultSnapshot()` returns fresh raw defaults. Raw default policy thresholds retain their `Int32` contract, while normalization retains the established `Int64` policy values. Native JSON/CLIXML serialization of the profile object omits its private configuration state. Existing default/import commands delegate to these methods; the legacy merge adapter retains its in-place, no-output contract.

`ADAnalyzerPrerequisiteInspector` has an inert constructor. `Inspect()` checks the default package offline, and `Inspect(repositoryRoot, profile)` accepts an explicit root and profile. `InspectOnline(repositoryRoot, server, credential, profile)` also checks TCP reachability on ports 9389 and 445, then attempts an authenticated RootDSE read if the bundled Windows provider passes the package checks. The credential is scoped to that call. The methods return ordered checks, and `Get-ADAnalyzerPrerequisite` retains incremental output and native diagnostics.

`ADAnalyzerOperationDocumentReader` validates operation documents from a literal JSON file path or an in-memory record. Its constructor is inert. `Read(input)` uses the assessment document label, and `Read(input, kind)` accepts another label such as `Plan` or `Journal` for validation errors. A valid in-memory record is returned by reference. The reader preserves the accepted JSON encoding, singleton array, and schema-version rules.

`ADAnalyzerAssessmentReport` owns report layout and output naming. Construction performs no collection or file access. `Render(assessment, format)` accepts an in-memory assessment and returns a JSON, HTML, or CSV string. `Write(assessmentOrPath, outputPath, format)` accepts a record or literal assessment JSON path and writes to the FileSystem provider. Use `All` to write JSON, HTML, and CSV in that order. Each completed write is atomic. The method returns the resolved paths on success. If a later write fails, earlier files remain. The fourth argument, `dryRun`, validates and projects the input and returns an empty path array without writing. Reports project recognized secrets to Boolean presence indicators. The class retains no input or report state. `Export-ADAnalyzerAssessment` retains native per-target confirmation, `WhatIf`, diagnostics, and each completed path's immediate pipeline output.

`ADAnalyzerAssessmentComparer` has an inert constructor. `Compare(reference, difference)` accepts in-memory snapshots, literal assessment JSON paths, or a mix. It checks target and search-base compatibility, groups rows by stable rule and target identities, and returns one ordered comparison with a UTC timestamp and summary counts. Compared check rows and structured run identifiers are detached and project recognized secrets to Boolean presence. The operation can read explicitly supplied files and has no write or directory effects. Each call uses fresh state. `Compare-ADAnalyzerAssessment` preserves native binding, input-read order, and diagnostics for existing callers.

A matched custom GPO finding with a different recorded operator, integer minimum or maximum, or scalar integer equality expectation is reported as `Changed` with reason `RulePredicateChanged` when its status would otherwise imply resolution or a newly failing setting. Scalar `Equals` and `NotEquals` require integer observations on both records. Both recorded observations are retained. Older snapshots that lack the required predicate fields retain the historical comparison behavior.

The same distinction applies to a changed expected registry type when both records contain typed scalar observations from the matching Computer or User `Registry.pol`. Recorded numeric types and equivalent invariant integer text are compared by value. An explicitly absent type constraint and a recorded numeric type are different expectations. When you need to verify an improvement, use assessments made against the same type expectation.

`ADAnalyzerRemediationPlanner` owns offline plan selection and assembly. Dot-source the full constructor loader, then call `CreatePlan(assessment)` for the default profile or `CreatePlan(assessment, profile)` with supplied profile settings. The assessment can be an in-memory record or a literal JSON path. Construction is inert. Each call builds an independent plan from the reviewed account identities, captured safety evidence, and profile policy. It preserves approved action order and returns detached display metadata with Boolean presence for recognized secrets. The method can read the supplied snapshot path and throws when the assessment or policy is invalid. Planning has no directory, journal, or mutation effects.

```powershell
. .\bin\ADAnalyzer.ps1
$planner = [ADAnalyzerRemediationPlanner]::new()
$plan = $planner.CreatePlan($scan, $profile)
$plan.Actions
```

The `New-ADAnalyzerRemediationPlan` compatibility command preserves native parameter binding, input observation order, and diagnostics.

`ADAnalyzerRemediationGuard` has an inert constructor and retains no plan or account state. `ReadState(object)` returns the normalized identity and enabled-state record, and `GetObjectKind(object)` selects the account class. `GetExclusion(object, settings)` takes the remediation settings from a normalized profile and returns the first exclusion reason or null. The privilege and service-account options must be actual Boolean values. `AssertPreconditions(expected, actual, enabled)` returns the verified state, and `AssertPlan(plan)` checks the supplied plan structure, reviewed identities, limits, and unique action IDs. These methods evaluate supplied observations and throw when an assertion fails.

`AssertInactivity(object, action)` checks supplied directory activity against the reviewed threshold. It uses the latest known logon observation and falls back to the creation time when logon evidence is absent. A malformed observation or unavailable evidence fails the check. The method is also available when dot-sourcing `bin/ADOperations.ps1` on its own.

`AssertPrivilege(object, action, plan, server)` accepts a current object from the selected controller and reads groups from that same controller with the bundled Windows Active Directory command. A trailing `PSCredential` supplies explicit credentials. The server must match the plan's recorded controller when one is recorded. The full constructor loader, `bin/ADAnalyzer.ps1`, makes the membership resolver and account classification available. The method checks effective privilege, fresh user classification, and exclusions. Successful eligibility checks return no output. Approval, identity verification, mutation, and journal operations belong to the guarded execution workflow.

### Account remediation reservations

Apply and Undo share a persistent reservation per AD object GUID across journals and PowerShell processes on one designated Windows host. The reservation is created before the directory write. If a write may have been dispatched and the command or its verification fails, the reservation survives the failure and process restart. A later Apply or Undo for that account that reaches reservation admission reports `Uncertain` before contacting AD. A matching read alone cannot clear a reservation. Planning, previews, and declined prompts leave the authority untouched.

Before enabling writes, a Windows administrator must provision a stable local `ADAnalyzer.Remediation` directory underneath the system's Common Application Data folder, normally `C:\ProgramData\ADAnalyzer.Remediation`. Restrict its ownership and write access to the authorized remediation service or administrators. Keep journal and report output outside that directory. Use one current-build writer host and stop older writers before cutover. Reconcile unsettled attempts from older versions and other hosts before provisioning or restoring this authority. The application does not initialize or migrate the authority automatically. If it is unavailable, the write fails closed.

The account GUID identifies the `.hold` file. Its text records the attempt ID, operation, creation time, and last confirmed step. Preserve that file and its journal when escalating a timeout or interruption. The application offers no automatic retry, Undo, or clear operation for an uncertain reservation. Require independent evidence of settlement and fresh approval before any later write. Synthetic tests qualify the control flow. Native provider settlement, distributed writers, and power-loss or host-restore recovery require separate qualification.

When Apply or Undo rethrows a failure after dispatch might have started, the originating exception can carry local reservation context under `ADAnalyzer.RemediationReservation` in `Exception.Data`. Look there or in the inner exception chain for the account GUID, attempt GUID, and last confirmed step. Match both GUIDs against the retained hold before using the error details for reconciliation. If saving the failure to the journal also fails, the compound error retains both failure messages and can still identify the held attempt. Inspecting a hold still conveys no settlement or approval evidence.

Enterprise-readiness development and pull-request checks use repository-owned synthetic directory records, simulated provider failures, disposable local storage, and the RSAT-free Windows matrix. They require no directory access or operator-supplied validation data. Native deployment qualification has a separate scope.

To inspect the local authority by account object GUID through the class API, load the analyzer and call the inspector.

```powershell
. ./bin/ADAnalyzer.ps1
$inspector = [ADAnalyzerRemediationReservationInspector]::new()
$inspector.Inspect([guid]'20000000-0000-4000-8000-000000000001')
```

The packaged PowerShell command exposes the same observation.

```powershell
Import-Module ./ADEnvironment.psd1
Get-ADAnalyzerRemediationReservation -ObjectGuid '20000000-0000-4000-8000-000000000001'
```

A `Held` result shows the validated attempt ID, operation, recorded UTC time, and last confirmed step. It covers both an active reservation and a retained uncertain attempt. `NotObserved` means the record was absent from the local authority at the time of the check. `Indeterminate` means the record could not be read and validated. The operation reports an error if the local authority is unavailable. Apply and Undo still need fresh approval and their own reservation. Inspection reads only local reservation metadata.

`ADAnalyzerRemediationJournal` manages a local journal. Its constructor is inert. `Open(plan, server, path)` validates the reviewed plan, resolves one PowerShell FileSystem path, and holds that path's exclusive lock. A newly opened journal stays in memory until the first write. `Read()` returns a detached record. `Write(journal)` checks the bound journal identity, persists the supplied entries with the bound settings, and sets the update time. Call `Dispose()` in a `finally` block to release the lease. Disposal is safe to repeat, preserves the empty lock marker, and allows the instance to be opened again.

```powershell
$journal = [ADAnalyzerRemediationJournal]::new()
$journal.Open($plan, $scan.Context.Server, '.\journal.json')
try {
    $record = $journal.Read()
}
finally {
    $journal.Dispose()
}
```

`ADAnalyzerRemediationExecutor` has an inert constructor. `Preview(plan, server, journalPath)` validates the reviewed plan and path and returns ordered skipped rows. It has no directory, lease, or journal write effects. `Apply(plan, server, journalPath, approvedActionIds)` takes an explicit list of action IDs from that plan. A trailing `PSCredential` supplies optional credentials. Only listed actions proceed, in reviewed plan order. Apply uses the bundled Windows provider on the selected controller, holds one journal lease, and records the prepared action before mutation. Successful results follow a verified reread and durable journal write. `Invoke-ADAnalyzerRemediationPlan` retains its native confirmation prompts, `WhatIf`, and per-action pipeline output.

```powershell
$executor = [ADAnalyzerRemediationExecutor]::new()
$preview = $executor.Preview($plan, $scan.Context.Server, '.\journal.json')
```

Use the same executor to review and undo a previously journaled account disable. `PreviewUndo(journalPath, server)` reads the existing local journal and returns skipped rows for successful disables in journal order. It has no directory calls, lock acquisition, or file writes. `Undo(journalPath, server, approvedEntryIds)` takes the EntryIds you explicitly approve from that preview. A trailing `PSCredential` supplies optional credentials. An empty list skips every candidate. Duplicate, unknown, or ambiguous IDs fail before acquiring a lock.

```powershell
$server = $scan.Context.Server
$journalPath = '.\journal.json'
$undoPreview = $executor.PreviewUndo($journalPath, $server)

# After reviewing the preview, supply the selected EntryId values.
$undoResult = $executor.Undo($journalPath, $server, $reviewedEntryIds)
```

Undo reopens the same existing journal under its exclusive lock. It binds the selected entries to the journal snapshot read at the start of the call. It then checks the account’s current state and privileges on the selected controller and persists the prepared reversal before enabling the account. A successful entry follows a verified reread and durable journal update. Direct methods return completed results or throw on failure. `Undo-ADAnalyzerRemediation` retains native confirmation, `WhatIf`, and per-entry pipeline output.

`ADAnalyzerAssessmentEngine` validates and copies its in-memory profile at construction without importing native modules or connecting to AD. Instance methods own assessment composition, policy/version evidence, suppression, duplicate detection, coverage, state, and safe report projection. Reports retain the existing detached assessment shape; the engine stores no credentials or collected records. A bundled C# configuration holder uses a private field, so serializing an engine does not serialize its profile. The built-in `Add-Type` loads that small source component; no separate build tool or external package is required. Each instance owns its configuration, and evaluating again does not retain earlier results. Direct methods throw on evaluation errors. The existing `Invoke-ADAnalyzerAssessment` command is a thin compatibility adapter with its original parameters and a transient command context for PowerShell error-stream/common-parameter behavior. Other engine components are being converted in separate verified units.

`ADAnalyzerGpoReader` owns the actual folder reader and INI, CSV, Registry.pol, XML, INF-flag, and security-option parsers. It retains no scan data or handles. `Read(path)` returns the existing policy DTO, and `ReadRegistryPolicy(path, scope)` returns typed registry records. Raw INI/XML and scalar parsing methods are internal implementation helpers; their compatibility functions retain the original source-parser contracts. Direct registry parsing buffers records and throws on invalid content; the compatibility `Read-AnalyzerRegistryPolicy` command preserves its earlier record streaming before a late parse failure. Existing reader commands delegate to the class; their consumer boundaries remain available. Reader construction is inert, and file/reader resources are closed before a successful direct return or after failure.

`ADAnalyzerGpoCatalog` owns GPO lookup, server selection, link interpretation, and catalog record assembly. Its constructor is inert. Call `GetAll(domain)`, `FindById(guid, domain)`, or `FindByName(name, domain)`. Each method also accepts a server and an optional credential as trailing arguments. The server defaults to the domain, and ID lookups require a nonempty GUID. Explicit lookups use the bundled Windows Active Directory provider. Each call validates the requested host, pins the returned domain controller, and returns fresh catalog records with domain and site links. The compatibility command retains native PowerShell binding, streaming, and error capture.

`ADAnalyzerGpoReportService` owns policy selection, SYSVOL reading, version comparison, SID lookup and report assembly. Its constructor is inert. `Read(gpo)` accepts a catalog record and returns `Gpo`, `Policy` and `VersionMismatch`. `RenderXml(gpo)` returns the canonical XML report. Both methods accept a trailing credential, and XML rendering also accepts a SID-name hashtable after the credential. `ReadById(guid, domain)` and `RenderXmlById(guid, domain)` look up the policy first. Their optional trailing arguments are server, credential, and, for XML, the SID-name hashtable.

Each operation reconstructs the SYSVOL path from validated catalog metadata. Credentialed reads own a temporary drive for the operation. SID lookup uses the bundled Windows directory provider on the selected controller. Object reports skip SID lookup, and XML rendering from catalog metadata loads the provider only when a SID needs resolution. The service retains no credentials, lookup state, or earlier results. Direct methods return the completed result after cleanup. `Get-ADAnalyzerGpoReport` retains its native parameter binding, warning and error streams, and cleanup diagnostics.

`ADAnalyzerGpoSourceNormalizer` validates and normalizes the policy from a prefetched package report, including its JSON round-trip. Construction performs no collection or file access. `Normalize(policy)` parses XML with DTD processing prohibited, restores ordinary binary registry values, and retains Boolean presence for identified secrets. It returns a fresh root, independent XML and registry rows, and shallow references to other ordinary input rows and values. Direct normalization throws on invalid input. The compatibility command preserves native PowerShell error and continuation behavior.

`ADAnalyzerGpoXmlWriter` composes the canonical GPO report XML in memory. `Render(gpo, policy)` returns an XML string. `Render(gpo, policy, sidNames, sidStatus)` accepts optional caller-supplied lookup data through the explicit overload. Construction and rendering require no file access or directory queries. Each call creates a fresh document and retains no caller data. Direct rendering emits only Boolean presence for recognized secrets in supplied policy records and embedded XML. It parses nonempty embedded XML with DTD processing prohibited and throws before returning a report if the XML is unreadable. The compatibility writer retains PowerShell’s native error and continuation behavior.

`ADAnalyzerGpoPolicyEvaluator` owns six rule phases: credential exposure, account settings, security options, membership/user rights, custom baselines, and coverage. Its constructor is inert and retains no inputs or results. `Evaluate(gpo, policy, profile)` accepts the same raw profile contract as the compatibility command, including partial profiles, and buffers results with exception semantics. `Test-ADAnalyzerGpoPolicy` retains named/common parameters and streamed checks before a late error. Effective registry records are computed at their original phase boundary and reused only within that call.

Use the same evaluator to resolve applicability from stored GPO metadata and a profile. The overload with five arguments takes `Targeted` and `Disabled` in that order.

```powershell
$policyEvaluator = [ADAnalyzerGpoPolicyEvaluator]::new()
$applicability = $policyEvaluator.GetApplicability($gpoMetadata, 'Computer', $profile)
$targetedApplicability = $policyEvaluator.GetApplicability($gpoMetadata, 'Computer', $profile, $true, $false)
```

The method returns `Applicable`, `NotApplicable`, or `Unknown` from the policy scope, links, targeting, WMI filter and profile. The direct call surfaces a failed flag conversion as an exception. The compatibility command retains native error continuation.

The evaluator also provides the ordered security specification catalogue. The method accepts the same raw profile settings and supplies the usual defaults for missing settings.

```powershell
$securitySpecifications = $policyEvaluator.GetSecuritySpecifications($profile)
```

Each call builds 22 fresh specification records. The compatibility command streams the 15 fixed records before reading the profile for its seven configured records. The direct method returns the complete catalogue together.

`ADAnalyzerMembershipGraph` captures a minimal, independent group graph and owns iterative membership resolution. `Resolve(object, domainSid, privilegedSids)` returns the existing membership DTO, including primary groups, ordered transitive SIDs, cycle witnesses, and unresolved evidence. Repeated resolutions reuse the index without retaining earlier results. The constructor retains only copied DN/SID/parent identities in private .NET state, so input credentials and unrelated group properties are not captured or serialized. Modern collection and SIDHistory evaluation reuse one graph per call. The compatibility index builder deliberately retains its original mutable `ByDn`/`BySid` maps and group references; the compatibility resolver honors supplied aliases transiently.

`ADAnalyzerDirectoryPolicyEvaluator` owns directory rule evaluation across domain/coverage, accounts and duplicate SPNs, trusts/ACLs, resultant password policies, and host observations. Its inert constructor retains no data or configuration. `Evaluate(data, profile)` accepts the existing raw/partial profile contract and returns complete ordered checks or throws. `EvaluateOperatingSystem(computer, entries)` evaluates a collected computer against the supplied lifecycle rules using the current UTC time. A third `DateTimeOffset` argument selects a fixed reference time. The method returns status, observed and expected values, and lifecycle evidence. The expected rules and matching entries reference the supplied rules. `Test-ADAnalyzerDirectoryPolicy` remains the command interface, including streamed checks before a late error, common parameters, and the underlying diagnostic cause.

`ADAnalyzerSecretIndicator` owns secret-name recognition, native value presence, custom-baseline validation, and record, XML and text presence projection. Its no-argument constructor is inert and retains no inputs, credentials, configuration or results. The eight existing secret commands delegate to its methods with their original parameters and PowerShell binding behavior. Methods use explicit arguments; `ProjectRecord($null)` and `ProjectXml($null)` reject missing inputs. Ordinary records retain their original reference. A secret record receives a new top-level object with `Value`, `RawData`, `Data` and `Bytes` removed; its other property values retain their existing references. Use `ADAnalyzerEvidenceProjector.Project(value)` for recursive evidence sanitization. XML results are independent of their sources, and each call owns and disposes its temporary XML readers.

`ADAnalyzerEvidenceProjector` owns recursive evidence projection and related raw lookup. Its no-argument constructor is inert and keeps no input, credential, configuration or result state. `Project(value)` and `Project(value, depth)` return recursively detached mutable evidence containers with the established scalar types, ordered fields, boolean secret presence and depth limit. Null remains null, including beyond the depth limit. Direct methods throw with their meaningful underlying causes on unsupported XML, invalid input conversion or native traversal failures.

Dictionary field enumeration uses the native .NET IDictionary key collection, so a data field or adapted member named `Keys` cannot hide other fields. This also applies to profile validation, GPO INI sections, configured rights, offline directory findings, reports, comparisons and legacy dictionary tables. A failing native key getter now reports its underlying cause instead of silently producing an empty record; raw `GetValue` lookups still return the actual borrowed `Keys` data value. Every configured dependency hash is also validated through native value metadata; a legitimate `Values` key cannot hide an invalid sibling hash. Legacy table formatting, CSV exports, and user, group, and computer reports and findings read native row collections, so an account named `Values` cannot hide sibling rows.

`Project` uses normal .NET object binding: PowerShell wrappers around a CLR array are unwrapped and projected as arrays. Use `ProjectPowerShellObject(value)` or `ProjectPowerShellObject(value, depth)` when extended PowerShell properties and wrapper classification are part of the input contract. `GetValue(object, names)` and `GetValue(object, names, default)` intentionally return borrowed raw values, honor dictionary key comparison and distinguish present null from missing properties. They provide no secret projection. The retained `ConvertTo-ADAnalyzerSafeData` and `Get-ADAnalyzerOperationValue` commands preserve their existing binding, pipeline cardinality and common-parameter/error behavior through transient adapters; neither owns the processing engine.

Projection state, dispatch, property processing, child/depth requests and presence merging are owned by class methods. Direct methods recursively drive those same methods. To retain native PowerShell error continuation, the compatibility command performs only class-requested child command calls, native iteration and one-call presence observations, then passes results back. It contains no projection rules. Each node's state and dependencies are local to that operation; none are retained on the projector.

Use this explicit dot-source entrypoint for literal constructor calls. Importing `ADEnvironment.psd1` remains the supported command interface; it does not promise caller visibility of classes defined in its dot-sourced component files. The constructor entrypoint supports portable offline evaluation; live collection still uses the package manifest and its bundled AD PSDrive/provider.

For check construction and suppression, use the same dot-sourced entrypoint to load the stateless factory. The three-argument overload uses the existing defaults. The specification overload accepts the full set of check fields, including raw observed, expected, and evidence values.

```powershell
$factory = [ADAnalyzerCheckFactory]::new()
$check = $factory.Create('FIXTURE', 'Fail', 'fixture')
$check = $factory.Create(@{
    RuleId = 'FIXTURE'
    Status = 'Fail'
    Target = 'fixture'
    Severity = 'Medium'
    Observed = $observed
    Expected = $expected
    Evidence = $evidence
})
$check = $factory.ApplyException($check, $profile)
```

The factory owns check IDs, field order, validation, rule selection, expiry checks, and suppression metadata. The full specification preserves borrowed evidence values. Applying an exception changes the supplied check in place and returns that same check. The first matching live exception wins, and the metadata keeps the original expiry value. The compatibility commands retain native PowerShell binding, reads, conversions, and writes where those affect streams, continuation, or caller variables.

The stateless `ADAnalyzerPolicyValueSemantics` class interprets validity markers, numbers, booleans, SIDs, SID lists, principals, and comparisons. The same portable dot-source entrypoint loads it for direct calls.

```powershell
$values = [ADAnalyzerPolicyValueSemantics]::new()
$number = $values.ParseNumber('42')
$principal = $values.ParsePrincipal('*S-1-5-32-544')
$sameMembers = $values.Compare(@('one', 'two'), @('two', 'one'))
```

Parsing returns the established validity and typed value fields, or the SID, name, and validity fields for principals. `Compare` defaults to equality and preserves duplicate counts. The compatibility commands retain native PowerShell observation and error behavior. Direct comparison calls surface malformed inputs as errors. Direct methods use ordinary .NET argument binding. For a Boolean carrying extended PowerShell members, direct parsing produces a Boolean value and the compatibility command retains the wrapper.

The inert `ADAnalyzerGpoPolicyRecordParser` interprets stored Restricted Groups and Local Users and Groups records. It also supplies XML paths, duplicate record identities, and template source recognition. Load it through the same portable entrypoint.

```powershell
$records = [ADAnalyzerGpoPolicyRecordParser]::new()
$restricted = $records.ParseRestrictedGroups($iniSettings)
$localGroups = $records.ParseLocalUsersGroups($xmlFiles)
```

Methods return the existing ordered record fields with structured validity and member evidence. The local group method reads the provided XML records before interpreting group items. XML documents and readers are scoped to the operation. The legacy commands retain native error and output behavior through small adapters.

Use `ADAnalyzerRegistryPolicyReplay` to apply writes and deletion directives in a stored registry record sequence. Constructing it only creates the service object.

```powershell
$replay = [ADAnalyzerRegistryPolicyReplay]::new()
$effectiveRecords = $replay.Replay($registrySettings)
```

Each call returns fresh rows for the supplied sequence, including tombstones marked `Deleted`. Nested values retain their original references. A runtime error in the direct call can terminate replay before results are returned. The compatibility command retains PowerShell's native error handling and continuation.

Use `ADAnalyzerAdmxResolver` for optional offline registry metadata. The constructor is inert. `Resolve` reads template files only when given a template path. Omitting the language uses `en-US`.

```powershell
$resolver = [ADAnalyzerAdmxResolver]::new()
$unresolved = $resolver.Resolve($registrySettings)
$resolved = $resolver.Resolve($registrySettings, 'C:\PolicyDefinitions', 'en-US')
$typedValue = $resolver.ReadValue($admxValueNode)
```

Resolution returns the existing ordered raw and metadata fields, including explicit unresolved states. The command retains native per-record streaming. The direct method returns the complete result or surfaces an error.

## Profiles and assessment coverage

`Import-ADAnalyzerProfile` merges a JSON or restricted PSD1 data file with fresh defaults, validates input, and rejects unknown settings. External JSON profiles, saved assessment/plan/journal documents, and SAML configuration files use UTF-8 unless a Unicode byte order mark (BOM) identifies another encoding. Windows PowerShell 5.1 and PowerShell 7 support UTF-8 with or without a BOM and BOM-marked UTF-16 and UTF-32. The readers reject malformed byte sequences before parsing JSON. Convert legacy ANSI JSON files to UTF-8 because their code page is ambiguous. The shared writer emits a UTF-8 BOM for compatibility with 5.1 default readers.

`Get-ADAnalyzerDefaultProfile` shows every supported key. Profiles control account/password/lockout thresholds, account-role evidence, approved SIDs, custom registry expectations, OS lifecycle/build rules, and remediation approvals. `profiles/default.psd1` is inert and `profiles/example.psd1` documents customization. Profile files are data and cannot contain executable PowerShell scripts.

User/service classification uses configured OUs, group identities, explicit attributes, or managed-service-account schema classes. An unclassified account remains Unknown. Privileged membership uses SIDs, transitive membership and primary groups, with cycle and unresolved-membership evidence. Password age does not prove password strength.

Checks expose Pass, Fail, Unknown, Unreadable, NotConfigured, Invalid, and NotApplicable. Applicability is separate: GPO checks describe stored risk and normally leave target applicability Unknown. WMI filters, disabled links/sides, and preference targeting are retained; a complete inheritance/security-filter/RSoP engine is not provided. Missing settings in one GPO do not prove effective noncompliance. A retained cpassword remains a credential exposure even when its item is disabled.

When a GPO snapshot lists XML without a matching payload for the same scope and relative path, the assessment reports `GPO.Coverage.MissingXml` with a count. Credential absence stays `Unknown` until the listed XML is available and readable. Confirmed presence remains a Boolean finding even if other XML is missing.

The new analyzers cover cpassword using boolean presence only, Restricted Groups, Local Users and Groups preference actions, exact-SID user-right allowlists, password/lockout sentinel values, raw Registry.pol types/deletions, and custom baseline rules. Security-template flags use their MS-GPSB numeric domains, including documented nonzero enabled values. Invalid tokens remain raw with `ValueValid: false` and produce Invalid checks or legacy validation findings; canonical XML and flat/wide reports retain the marker. Invalid marked settings cannot be imported as baseline expectations. Optional ADMX/ADML enrichment accepts `Analysis.TemplatePath` and `Analysis.Language`; unresolved or complex definitions stay Unknown and raw registry identity remains authoritative.

Custom value baselines in `RegistryRules`, `ExpectedGpoSettings`, and `Host.RegistryRules` reject known secret-bearing settings. Use the built-in boolean secret-presence findings for those settings; their stored values are not supported baseline inputs. Identity fields (`Kind`, `Name`, `Key`, `ValueName`) identify one setting and must be strings or null; expected value collections remain supported.

Directory checks include MachineAccountQuota, Recycle Bin, default/fine-grained/resultant password policies, trusts/SID filtering, SPNs, SIDHistory, delegation including RBCD, LAPS and gMSA metadata. Managed passwords are never requested. Reader-permission and delegation checks report configured grants, not a complete effective-access calculation.

Membership traversal is iterative and includes direct, primary, and transitive group SIDs. Cycle diagnostics record representative back-edge witnesses, including when multiple direct memberships enter the same cycle; shared ancestors are not cycles. These witnesses do not enumerate every possible cycle. Unreadable memberships remain explicit unresolved evidence.

Modern bulk directory collection defaults to `Analysis.DirectoryConnection: "PSDrive"`. It creates an owned drive through the bundled ActiveDirectory provider, runs the existing typed AD queries against the pinned DC with drive-associated credentials, restores the caller location, and removes the drive before returning the snapshot. Explicit property lists and OU/domain/schema search bases are preserved. The scan records its connection mode and status. A failed drive context is reported as unreadable coverage rather than switching transports. Set `DirectoryConnection: "Direct"` for an explicit direct-query run, including comparable lab measurements. Live AD throughput was not measured by the fixture tests.

When schema discovery supports `msDS-ResultantPSO`, the collector requests this server-computed association and reuses an already collected fine-grained policy only when its DN identifies one complete record. Missing, ambiguous, incomplete, or unreadable evidence retains the individual resultant-policy lookup; an absent association never proves that the default policy applies. A bounded 100-user fixture reduced individual lookups from 100 to zero for a shared complete policy in both connection modes, with one bulk policy query. These command counts do not measure live AD response times.

Legacy `Get-ADEnvironment` reads also prefer a PSDrive: without explicit credentials, a call from outside the AD provider creates an owned drive before collection and removes it afterward. Calls already inside an AD drive keep that context, including its credentials and search base. `Analysis.DirectoryConnection: "Direct"` opts out of creating a drive for current-identity legacy reads. Explicit-credential legacy calls retain their existing credential-associated drive behavior in either mode. Constructing object graphs without credentials and requesting help remain offline.

Use `-IncludeAcl` for targeted domain-root/AdminSDHolder/OU/GPO security descriptors. Use `-IncludeHostChecks` for bounded CIM inventory of DC services, OS/build, installed hotfix records, DNS adapters, SMB and NTP/TLS registry overrides. These flags add collection; they do not configure hosts. Configured service names are added as literal, deduplicated requests. Host service and registry rules accept an optional nonempty string `Id`. Give separate expectations for the same target distinct IDs; ambiguous duplicate identities are rejected before host collection. IDs keep check identity stable when rule order or expectations change, while single rules without IDs retain their existing identity. Evidence includes the profile rule ID. Snapshot comparison tracks named host rules separately, including literal registry key/value identities; removing a failing rule does not establish resolution. Custom registry rules read named values under HKLM and discover their stored type before selecting a getter (types 1, 2, 3, 4, 7, and 11). Optional `Type` expectations require matching observed type evidence. For an unnamed default value, provide `ValueName: ""` and `Type` when StdRegProv omits default-only type metadata; unavailable or unsupported types remain Unknown. Configure `Host.Services`, `Host.RegistryRules`, `Host.AuditRules` (subcategory GUID plus numeric flags), or `Host.CertificateEndpoints` for verification. Audit reads use native Windows APIs over existing WinRM; no remoting is enabled automatically. TLS certificate checks inspect explicit direct-TLS endpoints, name/chain/time validity and modern TLS negotiation. Revocation, STARTTLS, LDAP channel binding, per-user audit policy and event delivery remain explicitly unassessed.

Account group classification requires a nonempty configured group identity that matches direct membership or an effective SID. Null and empty group selectors provide no evidence; absent membership alone leaves the account type Unknown. User and Service type comparisons ignore case, so casing alone does not create a conflict. Returned evidence keeps its configured spelling and order, and a single logical type keeps its first evidence spelling. Conflicting valid User and Service rules still leave it Unknown and block automatic remediation.

An OS lifecycle profile uses `Policy.SupportedOperatingSystems` entries such as `@{Name='Windows Server 2022*';VersionPattern='^10\.0';MinimumBuild=20348;MaximumBuild=20348;SupportedUntil='2031-10-14';RequireEsu=$false}`. Verify the lifecycle date against your organization's maintained baseline. Missing build/ESU evidence stays Unknown; an OS name alone is not a support assertion.

Exceptions use `@{RuleId='RULE.ID';Target='exact identity or wildcard';Owner='team';Reason='justification';Expires='2026-12-01T00:00:00Z'}`. A current exception attaches suppression metadata while retaining the original status and evidence. Expired exceptions do not suppress a finding.

Profiles reject duplicate audit subcategory GUIDs and equivalent certificate endpoints before observations start. Audit GUID formatting and case do not create separate rules; combine success/failure flags in one rule. Certificate identity uses host, effective port (443 by default), and effective TLS server name (host by default).

`etc/Get-ComputerADSI.ps1` now defines `Get-ComputerAdministratorName -ComputerName <hosts>` with optional `Credential`. It returns direct member names through the same SID 544 reader as `Get-LocalGroupMember`, with owned resources disposed before names are emitted. Dot sourcing is inert; CLI requires explicit computers. `Get-LocalGroupMember -IncludeName` adds a detached `Name` column; its default columns stay unchanged. Name lookup failures are terminating.

## Baseline imports

Extract a matching Microsoft Security Compliance Toolkit GPO backup and pass its `DomainSysvol/GPO` root (containing Machine/User) to `Import-ADAnalyzerBaseline -GpoPath <root> -Name <name> -Version <version>`. The importer replays Registry.pol directives, retains types, aggregates multi-value security settings and rejects conflicting inputs. Its returned profile can be saved as JSON. Policy Analyzer/LGPO remain optional reference tools; neither is required by the runtime. Download baselines from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319).

Dot-source the portable object entrypoint to construct an importer. The constructor is inert. Each `Import` call reads the supplied backups and builds an independent profile.

```powershell
. ./bin/ADAnalyzer.ps1
$importer = [ADAnalyzerBaselineImporter]::new()
$paths = [string[]]@('C:\PolicyCopies\Baseline\DomainSysvol\GPO')
$profile = $importer.Import($paths, '2026.11')
$namedProfile = $importer.Import($paths, 'Workstation baseline', '2026.11')
```

The two-argument overload names the profile `Imported GPO baseline`. Both overloads throw if the backup contents conflict or the resulting profile is invalid. The compatibility command retains native parameter binding and error streams.

New imports use unambiguous registry identities when keys or value names contain a literal pipe. IDs for those rules can differ from IDs in older imported profiles.

## Reviewed remediation

Automatic finding-label disable/delete is retired. `Set-ADEnvironment` now creates an inert plan by default; `Start-ADAnalyzer -Operation remediate` is a plan alias. Legacy direct mutation methods reject execution. Existing `Get-ADEnvironment` class reports remain available, but independent new scans should use `Get-ADAnalyzerAssessment`; a stale legacy class instance cannot analyze another instance's target. Legacy `Get-ADEnvironment -Help` and no-class help calls return normally to the caller without directory collection. Owned AD drives are removed even if restoring the caller location fails. A failed removal retains ownership for retry; cleanup errors propagate with the original restoration cause and any secondary removal diagnostic.

Legacy user/group `.Data` contains analysis-required/default metadata and approved nonsecret classification attributes, rather than a wildcard LDAP inventory. Unexpected returned secret-bearing fields are reduced to boolean presence before retention. Native SID/date values remain intact for legacy consumers; secret-valued classification attributes are rejected or reported as invalid instead of queried. Legacy inactivity and password length/history checks honor the profile. Personal password warnings use 1/2/7/21 days remaining; service warnings use 30-day windows with labels showing their configured lower elapsed-age boundary. Zero user/service password-age limits disable legacy age warnings and age findings; zero inactivity remains an immediate threshold with known creation age. Positive legacy password-age findings keep their existing at-limit boundary and creation grace. Legacy user-right rows retain canonical right/SID identities and distinguish an empty assignment from a malformed member. Within the existing Domain Controllers link heuristic, approval uses exact `Policy.AllowedUserRightSids` entries; missing identity or an unspecified/invalid allowlist requires validation. Friendly-name text and SID-name resolution do not establish approval. This stored-link heuristic does not calculate effective policy.

```powershell
$profile.Remediation.AllowDisable = $true
$profile.Remediation.ApprovedObjectGuids = @('<explicit approved object GUID>')
$plan = New-ADAnalyzerRemediationPlan -Assessment $scan -Profile $profile
$plan.Actions
$plan | ConvertTo-Json -Depth 100 | Set-Content .\reviewed-plan.json -Encoding UTF8
Invoke-ADAnalyzerRemediationPlan `
    -Plan .\reviewed-plan.json `
    -Server $scan.Context.Server `
    -Credential $credential `
    -JournalPath .\journal.json `
    -WhatIf
# After reviewing the exact plan, run the same command without -WhatIf.
```

Offline planning accepts strings in the assessment's `Data.Directory.Domain.PrivilegedSids` list, including recorded domain scope templates. For in-memory Windows assessments, a native `SecurityIdentifier` is represented by its SID string in the plan. An unsupported privilege identity type stops plan generation.

Only explicit approved Fail inactivity findings can propose DisableAccount. Unknown/service/privileged/protected/critical/DC/well-known objects, SIDHistory, and incomplete safety/privilege evidence require exclusion/manual review; hard exclusions remain enforced during execution. Each action re-queries GUID/SID/DN/state/whenChanged, fresh privilege/classification, and known recent logon/creation evidence on the pinned DC, writes intent to the journal before the mutation, then records the outcome. This is not an authoritative all-DC lastLogon sweep, so inactivity remains an approximate signal requiring explicit object approval. WhatIf performs no directory reads, mutations, or journal writes in the executor. No deletion, description/adminCount rewrite, or general-purpose script execution is supported. `Undo-ADAnalyzerRemediation -JournalPath ... -Server ...` can enable a successfully journaled disable only after checking its post-state and current exclusions; it cannot undo deletion or arbitrary external changes. Preconditions and local journals are not an atomic AD transaction: a concurrent change, process crash, or failed post-read can leave an uncertain action that needs manual verification.

Apply and undo hold an exclusive `<JournalPath>.lock` file handle while reading and updating a journal. A competing writer for the same path fails explicitly before AD queries or mutations; undo re-reads entries under that ownership. The empty marker file remains after use to avoid unlink races, and its presence alone does not mean a run is active. Ownership is released on completion, failure, cancellation, or process termination. This coordinates cooperating writers to one journal path; it does not make AD changes transactional or coordinate different journal paths.

Journal paths resolve once against the caller's PowerShell FileSystem location and use that absolute path for ownership, reads, and writes. Relative report paths use the same PowerShell location. Non-FileSystem providers are rejected.

## Unattended CLI and prerequisites

`bin/Start-ADAnalyzer.ps1` accepts explicit Operation, Domain/FQDN, Server, SearchBase, Credential, ProfilePath, OutputPath, PlanPath, JournalPath, ReferencePath, and collection switches. It does not clear caller modules/variables, change location, or select a hardcoded domain. Dot sourcing defines the function without running a scan. Script operations are assess/report, plan/remediate, apply, undo, and prerequisites. Apply requires PlanPath and JournalPath; undo requires JournalPath. The function throws on scan/export failures. The script exits 1 on failure, 2 for partial/unreadable coverage, and optionally 3 with `-FailOnFindings`; findings and collection completeness are separate concepts.

`Get-ADAnalyzerPrerequisite` reports platform/runtime, bundled DLL version/hash and optional ADWS/SMB reachability/authentication. `DependencyHashes` may pin a trusted SHA256 for `Microsoft.ActiveDirectory.Management.dll`; availability is not signature verification. `Start-ADAnalyzer -Operation prerequisites -FQDN example.com -Online` accepts the same target/profile configuration. No prerequisite command installs RSAT or changes domain/host configuration.

The standalone prerequisites path uses an already-loaded prerequisite command or loads the local implementation. Cold offline startup reads package metadata. Network checks require explicit `-Online`.

Assessment state describes evidence completeness. Invalid stored values or observations produce `Partial`, as do unknown evidence and collection errors. A fully evaluated failed check can still belong to a `Complete` assessment; `Complete` does not mean compliant.

## Validation

Run `./tests/Invoke-TestSuite.ps1` for the regression suites, each in a separate fresh PowerShell process. CI pins Windows PowerShell 5.1, PowerShell 7.6 LTS at 7.6.10, and PowerShell 7.7 at 7.7.0 on Windows Server 2025. The PowerShell 7 portable downloads are SHA256-verified against the published release digests; Windows supplies and services its 5.1 build. Each job logs `$PSVersionTable`, executable path, process architecture and .NET runtime, and rejects an unexpected version/edition/architecture before running tests. All three engines run the regression suites, native DLL/provider and host-adapter checks, Pester, and selected static security rules without installed RSAT modules. Fixture tests do not contact a live domain controller or perform real AD changes; live AD/SMB/WinRM behavior still requires a representative lab.

XML presence projection and its immediate serializers read native DOM properties through `PSBase`, so XML elements or attributes named `LocalName`, `Attributes`, `OuterXml`, or other DOM members remain data. `tests/XmlNativePropertyFixture.ps1` checks collision families, boolean presence, source immutability, ordinary output/type/cardinality against the accepted-source baseline, and real JSON/HTML/CSV export through a memory writer. Reader, provided-policy, policy-analysis and standalone XML paths use isolated input boundaries without domain or file writes.

`etc/Install-DevelopmentTools.ps1` saves pinned Pester and PSScriptAnalyzer versions under ignored `tools/modules`; it does not install runtime dependencies or change trusted repositories. After saving them, use `./tests/Invoke-TestSuite.ps1 -Mode All` to include `tests/Quality.Tests.ps1` and selected static security rules in a fresh process. These tools, ADMX/ADML templates, SCT baselines and Policy Analyzer/LGPO are optional development/reference components, not RSAT prerequisites.
 
## AD Tactical Hardening Playbook 

	[ ] Establish Change Control Procedure
		a. communications
		b. organizational change management
		c. testing
		d. defect / issue tracking
		e. escalation
		f. rollback
	[ ] Enable AD Recycle Bin
 		a. Get-ADOptionalFeature -Filter * -Properties ('Name', 'DistinguishedName', 'EnabledScopes') -Server $value -ErrorAction Stop
	[ ] System state backup
		a. Create non-personal account for domain controller backups that is a member of the BUILTIN\Administrator group
			i.    Enable AES256
			ii.   Account is sensitive and cannot be delegated
			iii.  Do not use protected users
		b. Configure one domain controller to backup up to the other and vice versa
	[ ] Enforce password complexity
		a. Length, complexity, history, reuse
	[ ] Change DSRM Password
	[ ] Reset KRBTGT password
		a. https://github.com/microsoft/New-KrbtgtKeys.ps1/blob/master/New-KrbtgtKeys.ps1
	[ ] Privileged Account Separation 
		a. New OUs for HPA Users & HPA Groups (isolated and distinct from each tier)
			i.    Tier 0 : Domain Admin 
			ii.   Tier 1 : Server Admin
			iii.  Tier 2 : Workstation Admin
			iv.   Tier 3 : User Admin
		b. Tiers are meant to be isolated boundaries to minimize lateral movement & privilege escalation risks
	    		i.    T0 Domain Admin cannot access member servers or workstations
			ii.   T1 Server Admins cannot access domain controllers or workstations
			iii.  T2 Workstation Admins cannot access domain controllers or member servers
			iv.   T3 User Admins cannot access member servers, domain controllers, or workstations 
		c. Add HPA groups to the Protected Users Group
			i.    Cannot have access internet 
			ii.   Is not mail enabled
		d. Add new HPA Users & Groups to the Protected Users Group
		e. Deploy new HPA Groups to servers, workstations, & endpoints via GPO
		f. Deploy isolation restrictions via GPO using UserRightsAssignment policies (e.g. deny logon)
		g. Fine-grained password policy
  		h. Separate service accounts per application.
   			i.    any service account shared by multiple applications must be separated
   			ii.   additionally, separate application service accounts are required per application use-case
   			iii.  i.e., one application should have two different service accounts when scheduling tasks vs. running services
	[ ] Empty BUILTIN groups (replaced with new groups above)
		a. Account Operators
		b. Backup Operators
		c. Server Operators
		d. Print Operators
	[ ] Remove general purpose, daily-use (personal), accounts from the following privileged groups
		a. Administrators
		b. Domain Admins
		c. Enterprise Admins
		d. DNS Admins
	   	e. Schema Operators
		f. DHCP Admins
	[ ] Harden BUILTIN\Administrator
		a. Renamed & Disabled via GPO 
		b. User Rights Assignment (via GPO on any non-Domain Controller)
			i.    Deny access to this computer from the network
			ii.   Deny log on as a batch job
	    		iii.  Deny log on as a service
	       		iv.   Deny log on through Remote Desktop
		c. User Account Controls
			i.    Enable 'account is sensitive and cannot be delegated'
			ii.   Enforce AES 256
		d. Add as member to Protected Users Group
	[ ] Domain Controller Hardening (Test Thoroughly)
		a. Audit Logging validation and configuration enablement
		b. Enforce NTLMv2 - Refuse LM and NTLMv1 (Test thoroughly)
	 		i.    Network Security: Restrict NTLM: Audit in coming NTLM traffic	
	 		ii.   Network Security: Restrict NTLM: Audit NTLM authentication in this domain
		c. Digital Signing (Test Thoroughly)
			i.    Domain member: Digitally encrypt secure channel data (when possible) == Enabled
			ii.   Microsoft network client: Digitally sign communications (if server agrees) == Enabled
			iii.  Microsoft network server: Digitally sign communications (if client agrees) == Enabled
		d. LDAP Signing (Test Thoroughly)
			i.    Domain Controller: LDAP server channel binding token requirements = When Supported
			ii.   Network Security: LDAP client signing requirements = Negotiate Signing
			iii.  Domain Controller: LDAP server signing requirements == REquire
		e. Validate Strict User Rights Assignment (GPO)
			i.    Access this computer from the network
			ii.   Bypass traverse checking
			iii.  Deny access to this computer from the network
			iv.   Log on as a batch job
			v.    Log on as a service
			vi.   Allow log on locally
			vii.  Allow log on through remote desktop services
		f. User Account Control
			i.    User Account Control: Run all administrators in admin approval mode
			ii.   User Account Control: Admin Approval Mode for the Built in Administrator Account == True
			iii.  User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode == Prompt for consent
		g. Disable Print Spooler
		h. Disable anonymous share enumeration 
			i.    Network Access: do not allow anonymous enumeration of sam accounts
			ii.   Network Access: Shares that can be access anonymously == null
			iii.  Network Access: Allow anonymous SID/Name translation == Disabled
			iv.   Network Access: Do not allow anonymous enumeration of SAM Accounts == Enabled
			v.    Network Access: Do not allow anonymous enumeration of SAM accounts == Enabled
			vi.   Network Access: Do not allow anonymous enumeration of SAM accounts and shares == Enabled
			vii.  Network Access: Let Everyone  permissions apply to anonymous users' == Disabled
			viii. Network Access: Named Pipes that can be accessed anonymous == @('LSARPC','NETLOGON','SAMR')
			ix.   Network access: Restrict anonymous access to Named Pipes and Shares == Enabled
			x.    Network Access: Shares that can be accessed anonymously == None
		i. Prevent server operators from adding scheduled tasks 
			i.    Domain Controller: Allow server operators to schedule tasks == Disabled
		j. Prevent users from installing print drivers
	     		i.    Devices: Prevent users from installing printer drivers == Enabled
		k. Remove non all non-Directory Services roles/features from domain controller (e.g. SQL, NPS/NPAS, IIS, DHCP, etc. )
	       		i.    Get-CIMInstance -ClassName CIM_Service | Select-Object Name, StartMode, StartName
		l. Migrate any scheduled task to non-Domain Controller utility server
		m. Prevent remotely accessible registry values
		n. Rolling and expiring NTLM secrets
		o. Trusts & SID Filtering validation
	   	p. validating Patching process
	   	q. validate NTP configuration to ensure correct time
	    	r. validate pki/certificate configuration
	[ ] Hygiene, Compliance, & User Clean-up
		a. Dormant / Inactive Clean-Up (user & computer)
		b. Disabled Clean-up (user & computer)
		c. Password Age Remediation (forced password reset)
		d. Termianted User clean-up
	  	e. Invalid Password Attempt Limit (6 invalid attempts)
	    		i.    automatically unlock after 30m
		f. Group Ownership
		g. Nested Groups (de-nest)
		h. Foreign Security Principals (analyze and remove)
		i. Unconstrained Kerberos delegation
		j. Token Bloat validation (users w/ >1000 group memberships)
	[ ] Insecure Account Attribute Clean-up
		a. Password not required
	 	b. Store password using reversible encryption (digest authentication)
		c. Use only Kerberos DES encryption types for this account
		d. Do not require Kerberos pre-auth
	    	e. set MS-DS-MachineAccountQuota = 0 
		f. SID History (analyze and remediate)
	    		i.    WellKnownSIDs in SIDHistory result in privilege escalation
		g. DCSync Privileges
	   		i.    Replicating Directory Changes
	    		ii.   Replicating Directory Changes All
		h. remove AdminSDHolder (protected user) from users not in a protected group
			i.    if a user is added to a protected group (e.g. Domain Admins) then AD updates that user as a protected user
			ii.   when the user is removed from the protected group, adminCount remains 1 until manually removed
			iii.  scan users with adminCount=1 who are not a member of a protected group
		i. Pre-Windows 2000 Compatible Access Group (remove member if present)
			i.    Anonymous Logon
			ii.   Everyone
	[ ] Kerberoasting
		a. validate users with service principal names 
			i.    Ensure only service accounts have service principal names
			ii.   Remove from any others
		b. increase password complexity of valid service users w/ SPNs
			i.    25+ character password
			ii.   Ese fine-grained password policy
	[ ] GPO Configuration Validation
		a. CPassword 
		b. User Account Control (UAC)
		c. Restricted Group 
		d. Local Users and Groups
		e. User Rights Assignment
	[ ] Address legacy protocol usage 
		a. SSL
		b. TLS 1.0 & 1.1
		c. NTLMv1
	    d. SMBv1
		e. LanMan (LM)
		f. Digest Authentication
	[ ] Address weak cipher usage
		a. DES
		b. 3DES
		c. RC4
	[ ] DNS
		a. validate name servers, root hints, and forwarders
		b. validate aging / Scavenging configuration
		c. validate dynamic update configuration
