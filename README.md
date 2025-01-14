# Active Directory Analyzer : 

+ .\bin\ADEnvironment.psm1 is a homegrown PoSh module I wrote which provides the **Get-ADEnvironment** & **Set-ADEnvironment** cmdlets to execute the corrective actions required for my **_AD Tactical Hardening Playbook_**
+ .\bin\Start-ADAnalyzer.ps1 is the helper script I wrote for the **Get-ADEnvironment** & **Set-ADEnvironment** cmdlets to simplify the ongoing analysis, reporting, remediation, & validation of AD Environment Hardening efforts via the helper's **Start-ADAnalyzer** cmdlet 
+ DLLs for AD Remote Server Administration Tools are pre-loaded in .\lib
+ Various other scripts loaded in .\etc 
 
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
