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
$scan.Findings | Select-Object RuleId,Target,Status,Severity,Applicability,Suppressed
Export-ADAnalyzerAssessment -Assessment $scan -Path .\reports\current -Format All
```

The exporter writes JSON evidence, HTML with summary/check tables and expandable evidence, and CSV projections. Secret-bearing fields and policy XML return boolean presence indicators such as `SecretPresent: true` or `cpasswordPresent="true"`; the values and masked placeholders are omitted. GPO/file/item locations remain available for remediation, and unreadable content stays Unknown. Legacy GPO reports also retain typed `property.setting.secretPresent` booleans; true indicators produce a stored-secret finding, false indicators remain inventory, and setting values are omitted. Exporting copies records without modifying the returned scan. Compare saved JSON snapshots with `Compare-ADAnalyzerAssessment -Reference .\reports\previous.json -Difference $scan`. Changes are classified as New, Resolved, Changed, or Unchanged using stable rule/target identities, including changes to passing checks. A failed check becoming Pass/NotApplicable is resolved; becoming Unknown does not prove resolution. A check absent from the new scan is Changed with `Reason: NotObservedInDifference`, including after failed or skipped collection; absence does not prove remediation. Different targets/search-base scopes are rejected as drift comparisons.

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

This is a file-based policy reader, not a GPMC HTML report generator or an ADMX display-name engine. Scripts and other unsupported client-side extension formats are inventoried rather than interpreted; parsed settings are not a calculation of effective policy or RSoP. Offline parsing is portable; live directory/SMB integration is supported on Windows. The older GroupPolicy DLLs in `lib` are not loaded.

The standalone `etc/Get-GPOXML.ps1` and `etc/Get-LocalAdminGPO.ps1` scripts also use the package reader. They require explicit targets and selection, return XML or canonical check objects, and write only when `OutputPath` is supplied. Dot sourcing defines their functions without connecting, importing native modules, prompting, or opening files:

```powershell
. .\etc\Get-GPOXML.ps1
. .\etc\Get-LocalAdminGPO.ps1
$xml = Get-ADAnalyzerGpoXml -Domain example.com -Guid $gpo.Id -Credential $credential -OutputPath .\reports\policy.xml
$groups = Get-ADAnalyzerLocalAdminGpo -Domain example.com -All -Credential $credential -OutputPath .\reports\local-groups.csv
# A prefetched package report can be analyzed offline, including on macOS:
$groups = Get-ADAnalyzerLocalAdminGpo -InputObject $policy
$xml = Get-ADAnalyzerGpoXml -InputObject $policy
```

Offline `InputObject` uses the `{Gpo, Policy}` shape returned by `Get-ADAnalyzerGpoReport -AsObject`, with package record objects or their JSON round-trip; dictionary-backed setting rows are rejected. Supply its actual GPO ID and enabled-side Flags rather than inventing metadata for a raw folder. Raw folder parsing remains available through `Read-ADAnalyzerGpo`. The local-group inventory preserves all selected statuses, members/actions, targeting, disabled items, source locations, and boolean credential exposure; it describes stored policy rather than effective machine membership. An unreadable selected policy produces an explicit check and prevents automatic export of the incomplete inventory. Empty inventories export CSV headers. `WhatIf` allows read-only collection and suppresses writes. File replacement stages and closes UTF-8 content beside each destination before promotion; separate output formats are separate file writes. Legacy class CSV and the NTLM/SAML CSV utilities use the same writer after successful conversion. Query, conversion, and write failures propagate and preserve existing reports; no alternate filename is silently selected. A successful empty legacy class export creates an empty CSV, while empty NTLM/SAML exports contain their known headers and no records. Legacy per-class CSV exports retain the union of safely projected columns across heterogeneous finding rows, including unreadable GPOs alongside configured settings; missing fields are empty and null records are skipped. Legacy aggregate JSON keeps flat policy integers as numbers within signed/unsigned 64-bit range and exact decimal strings beyond that range, consistently across supported engines.

## Profiles and assessment coverage

`Import-ADAnalyzerProfile` merges a JSON or restricted PSD1 data file with fresh defaults, validates input, and rejects unknown settings. `Get-ADAnalyzerDefaultProfile` shows every supported key. Profiles control account/password/lockout thresholds, account-role evidence, approved SIDs, custom registry expectations, OS lifecycle/build rules, and remediation approvals. `profiles/default.psd1` is inert; `profiles/example.psd1` documents customization. Profile files are data and cannot contain executable PowerShell scripts.

User/service classification uses configured OUs, group identities, explicit attributes, or managed-service-account schema classes. An unclassified account remains Unknown. Privileged membership uses SIDs, transitive membership and primary groups, with cycle and unresolved-membership evidence. Password age does not prove password strength.

Checks expose Pass, Fail, Unknown, Unreadable, NotConfigured, Invalid, and NotApplicable. Applicability is separate: GPO checks describe stored risk and normally leave target applicability Unknown. WMI filters, disabled links/sides, and preference targeting are retained; a complete inheritance/security-filter/RSoP engine is not provided. Missing settings in one GPO do not prove effective noncompliance. A retained cpassword remains a credential exposure even when its item is disabled.

The new analyzers cover cpassword using boolean presence only, Restricted Groups, Local Users and Groups preference actions, exact-SID user-right allowlists, password/lockout sentinel values, raw Registry.pol types/deletions, and custom baseline rules. Security-template flags use their MS-GPSB numeric domains, including documented nonzero enabled values. Invalid tokens remain raw with `ValueValid: false` and produce Invalid checks or legacy validation findings; canonical XML and flat/wide reports retain the marker. Invalid marked settings cannot be imported as baseline expectations. Optional ADMX/ADML enrichment accepts `Analysis.TemplatePath` and `Analysis.Language`; unresolved or complex definitions stay Unknown and raw registry identity remains authoritative.

Custom value baselines in `RegistryRules`, `ExpectedGpoSettings`, and `Host.RegistryRules` reject known secret-bearing settings. Use the built-in boolean secret-presence findings for those settings; their stored values are not supported baseline inputs. Identity fields (`Kind`, `Name`, `Key`, `ValueName`) identify one setting and must be strings or null; expected value collections remain supported.

Directory checks include MachineAccountQuota, Recycle Bin, default/fine-grained/resultant password policies, trusts/SID filtering, SPNs, SIDHistory, delegation including RBCD, LAPS and gMSA metadata. Managed passwords are never requested. Reader-permission and delegation checks report configured grants, not a complete effective-access calculation.

Modern bulk directory collection defaults to `Analysis.DirectoryConnection: "PSDrive"`. It creates an owned drive through the bundled ActiveDirectory provider, runs the existing typed AD queries against the pinned DC with drive-associated credentials, restores the caller location, and removes the drive before returning the snapshot. Explicit property lists and OU/domain/schema search bases are preserved. The scan records its connection mode and status. A failed drive context is reported as unreadable coverage rather than switching transports. Set `DirectoryConnection: "Direct"` for an explicit direct-query run, including comparable lab measurements. Live AD throughput was not measured by the fixture tests.

When schema discovery supports `msDS-ResultantPSO`, the collector requests this server-computed association and reuses an already collected fine-grained policy only when its DN identifies one complete record. Missing, ambiguous, incomplete, or unreadable evidence retains the individual resultant-policy lookup; an absent association never proves that the default policy applies. A bounded 100-user fixture reduced individual lookups from 100 to zero for a shared complete policy in both connection modes, with one bulk policy query. These command counts do not measure live AD response times.

Use `-IncludeAcl` for targeted domain-root/AdminSDHolder/OU/GPO security descriptors. Use `-IncludeHostChecks` for bounded CIM inventory of DC services, OS/build, installed hotfix records, DNS adapters, SMB and NTP/TLS registry overrides. These flags add collection; they do not configure hosts. Configured service names are added as literal, deduplicated requests. Host service and registry rules accept an optional nonempty string `Id`. Give separate expectations for the same target distinct IDs; ambiguous duplicate identities are rejected before host collection. IDs keep check identity stable when rule order or expectations change, while single rules without IDs retain their existing identity. Evidence includes the profile rule ID. Snapshot comparison tracks named host rules separately, including literal registry key/value identities; removing a failing rule does not establish resolution. Custom registry rules read named values under HKLM and discover their stored type before selecting a getter (types 1, 2, 3, 4, 7, and 11). Optional `Type` expectations require matching observed type evidence. For an unnamed default value, provide `ValueName: ""` and `Type` when StdRegProv omits default-only type metadata; unavailable or unsupported types remain Unknown. Configure `Host.Services`, `Host.RegistryRules`, `Host.AuditRules` (subcategory GUID plus numeric flags), or `Host.CertificateEndpoints` for verification. Audit reads use native Windows APIs over existing WinRM; no remoting is enabled automatically. TLS certificate checks inspect explicit direct-TLS endpoints, name/chain/time validity and modern TLS negotiation. Revocation, STARTTLS, LDAP channel binding, per-user audit policy and event delivery remain explicitly unassessed.

An OS lifecycle profile uses `Policy.SupportedOperatingSystems` entries such as `@{Name='Windows Server 2022*';VersionPattern='^10\.0';MinimumBuild=20348;MaximumBuild=20348;SupportedUntil='2031-10-14';RequireEsu=$false}`. Verify the lifecycle date against your organization's maintained baseline. Missing build/ESU evidence stays Unknown; an OS name alone is not a support assertion.

Exceptions use `@{RuleId='RULE.ID';Target='exact identity or wildcard';Owner='team';Reason='justification';Expires='2026-12-01T00:00:00Z'}`. A current exception attaches suppression metadata while retaining the original status and evidence. Expired exceptions do not suppress a finding.

## Baseline imports

Extract a matching Microsoft Security Compliance Toolkit GPO backup and pass its `DomainSysvol/GPO` root (containing Machine/User) to `Import-ADAnalyzerBaseline -GpoPath <root> -Name <name> -Version <version>`. The importer replays Registry.pol directives, retains types, aggregates multi-value security settings and rejects conflicting inputs. Its returned profile can be saved as JSON. Policy Analyzer/LGPO remain optional reference tools; neither is required by the runtime. Download baselines from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319).

## Reviewed remediation

Automatic finding-label disable/delete is retired. `Set-ADEnvironment` now creates an inert plan by default; `Start-ADAnalyzer -Operation remediate` is a plan alias. Legacy direct mutation methods reject execution. Existing `Get-ADEnvironment` class reports remain available, but independent new scans should use `Get-ADAnalyzerAssessment`; a stale legacy class instance cannot analyze another instance's target. Legacy `Get-ADEnvironment -Help` and no-class help calls return normally to the caller without directory collection. Owned AD drives are removed even if restoring the caller location fails. A failed removal retains ownership for retry; cleanup errors propagate with the original restoration cause and any secondary removal diagnostic.

Legacy user/group `.Data` contains analysis-required/default metadata and approved nonsecret classification attributes, rather than a wildcard LDAP inventory. Unexpected returned secret-bearing fields are reduced to boolean presence before retention. Native SID/date values remain intact for legacy consumers; secret-valued classification attributes are rejected or reported as invalid instead of queried. Legacy inactivity and password length/history checks honor the profile. Personal password warnings use 1/2/7/21 days remaining; service warnings use 30-day windows with labels showing their configured lower elapsed-age boundary. Zero user/service password-age limits disable legacy age warnings and age findings; zero inactivity remains an immediate threshold with known creation age. Positive legacy password-age findings keep their existing at-limit boundary and creation grace. Legacy user-right rows retain canonical right/SID identities and distinguish an empty assignment from a malformed member. Within the existing Domain Controllers link heuristic, approval uses exact `Policy.AllowedUserRightSids` entries; missing identity or an unspecified/invalid allowlist requires validation. Friendly-name text and SID-name resolution do not establish approval. This stored-link heuristic does not calculate effective policy.

```powershell
$profile.Remediation.AllowDisable = $true
$profile.Remediation.ApprovedObjectGuids = @('<explicit approved object GUID>')
$plan = New-ADAnalyzerRemediationPlan -Assessment $scan -Profile $profile
$plan.Actions
$plan | ConvertTo-Json -Depth 100 | Set-Content .\reviewed-plan.json -Encoding UTF8
Invoke-ADAnalyzerRemediationPlan -Plan .\reviewed-plan.json -Server $scan.Context.Server -Credential $credential -JournalPath .\journal.json -WhatIf
# After reviewing the exact plan, run the same command without -WhatIf.
```

Only explicit approved Fail inactivity findings can propose DisableAccount. Unknown/service/privileged/protected/critical/DC/well-known objects, SIDHistory, and incomplete safety/privilege evidence require exclusion/manual review; hard exclusions remain enforced during execution. Each action re-queries GUID/SID/DN/state/whenChanged, fresh privilege/classification, and known recent logon/creation evidence on the pinned DC, writes intent to the journal before the mutation, then records the outcome. This is not an authoritative all-DC lastLogon sweep, so inactivity remains an approximate signal requiring explicit object approval. WhatIf performs no directory reads, mutations, or journal writes in the executor. No deletion, description/adminCount rewrite, or general-purpose script execution is supported. `Undo-ADAnalyzerRemediation -JournalPath ... -Server ...` can enable a successfully journaled disable only after checking its post-state and current exclusions; it cannot undo deletion or arbitrary external changes. Preconditions and local journals are not an atomic AD transaction: a concurrent change, process crash, or failed post-read can leave an uncertain action that needs manual verification.

Apply and undo hold an exclusive `<JournalPath>.lock` file handle while reading and updating a journal. A competing writer for the same path fails explicitly before AD queries or mutations; undo re-reads entries under that ownership. The empty marker file remains after use to avoid unlink races, and its presence alone does not mean a run is active. Ownership is released on completion, failure, cancellation, or process termination. This coordinates cooperating writers to one journal path; it does not make AD changes transactional or coordinate different journal paths.

Journal paths resolve once against the caller's PowerShell FileSystem location and use that absolute path for ownership, reads, and writes. Relative report paths use the same PowerShell location. Non-FileSystem providers are rejected.

## Unattended CLI and prerequisites

`bin/Start-ADAnalyzer.ps1` accepts explicit Operation, Domain/FQDN, Server, SearchBase, Credential, ProfilePath, OutputPath, PlanPath, JournalPath, ReferencePath, and collection switches. It does not clear caller modules/variables, change location, or select a hardcoded domain. Dot sourcing defines the function without running a scan. Script operations are assess/report, plan/remediate, apply, undo, and prerequisites. Apply requires PlanPath and JournalPath; undo requires JournalPath. The function throws on scan/export failures. The script exits 1 on failure, 2 for partial/unreadable coverage, and optionally 3 with `-FailOnFindings`; findings and collection completeness are separate concepts.

`Get-ADAnalyzerPrerequisite` reports platform/runtime, bundled DLL version/hash and optional ADWS/SMB reachability/authentication. `DependencyHashes` may pin a trusted SHA256 for `Microsoft.ActiveDirectory.Management.dll`; availability is not signature verification. `Start-ADAnalyzer -Operation prerequisites -FQDN example.com -Online` accepts the same target/profile configuration. No prerequisite command installs RSAT or changes domain/host configuration.

## Validation

Run `./tests/Invoke-TestSuite.ps1` for the regression suites, each in a separate fresh PowerShell process. CI pins Windows PowerShell 5.1, PowerShell 7.6 LTS at 7.6.10, and PowerShell 7.7 at 7.7.0 on Windows Server 2025. The PowerShell 7 portable downloads are SHA256-verified against the published release digests; Windows supplies and services its 5.1 build. Each job logs `$PSVersionTable`, executable path, process architecture and .NET runtime, and rejects an unexpected version/edition/architecture before running tests. All three engines run the regression suites, native DLL/provider and host-adapter checks, Pester, and selected static security rules without installed RSAT modules. Fixture tests do not contact a live domain controller or perform real AD changes; live AD/SMB/WinRM behavior still requires a representative lab.

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
