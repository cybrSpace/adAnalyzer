function Get-ADAnalyzerAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential = [pscredential]::Empty,
        [int]$TimeoutSeconds = 30

    )
    # Numeric native policy flags avoid localized auditpol output. This is a
    # read-only WinRM operation; remote configuration is never enabled here.
    $block = {
        if (-not ('ADAnalyzer.NativeAuditPolicy' -as [type])) {
            Add-Type `
                -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace ADAnalyzer {
 public static class NativeAuditPolicy {
  [StructLayout(LayoutKind.Sequential)] public struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
  [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditEnumerateSubCategories(IntPtr category,[MarshalAs(UnmanagedType.U1)] bool all,out IntPtr buffer,out uint count);
  [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy(Guid[] categories,uint count,out IntPtr buffer);
  [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
  public static Policy[] Read() {
   IntPtr ids=IntPtr.Zero, data=IntPtr.Zero; uint count=0;
   try {
    if(!AuditEnumerateSubCategories(IntPtr.Zero,true,out ids,out count)) throw new Win32Exception(Marshal.GetLastWin32Error());
    Guid[] guids=new Guid[count]; int guidSize=Marshal.SizeOf(typeof(Guid));
    for(int i=0;i<count;i++) guids[i]=(Guid)Marshal.PtrToStructure(IntPtr.Add(ids,i*guidSize),typeof(Guid));
    if(!AuditQuerySystemPolicy(guids,count,out data)) throw new Win32Exception(Marshal.GetLastWin32Error());
    Policy[] result=new Policy[count]; int size=Marshal.SizeOf(typeof(Policy));
    for(int i=0;i<count;i++) result[i]=(Policy)Marshal.PtrToStructure(IntPtr.Add(data,i*size),typeof(Policy));
    return result;
   } finally {if(ids!=IntPtr.Zero)AuditFree(ids);if(data!=IntPtr.Zero)AuditFree(data);}
  }
 }
}
'@
        }
        [ADAnalyzer.NativeAuditPolicy]::Read() | ForEach-Object { [pscustomobject]@{
                SubcategoryGuid = $_.Subcategory.ToString()
                CategoryGuid = $_.Category.ToString()
                Flags = [uint32]$_.Flags
            } }
    }
    $arguments = @{
        ComputerName = $ComputerName
        ScriptBlock = $block
        ErrorAction = 'Stop'
    }
    if ($Credential -and $Credential -ne [pscredential]::Empty) {
        $arguments.Credential = $Credential
    }
    $arguments.SessionOption = New-PSSessionOption `
        -OpenTimeout ($TimeoutSeconds * 1000) `
        -OperationTimeout ($TimeoutSeconds * 1000) `
        -ErrorAction Stop
    @(Invoke-Command @arguments)
}

function Get-ADAnalyzerTlsCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [ValidateRange(1, 65535)][int]$Port = 443,
        [string]$ServerName = $HostName,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 10

    )
    if (-not ('ADAnalyzer.TlsInspector' -as [type])) {
        Add-Type `
            -TypeDefinition @'
using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
namespace ADAnalyzer {
 public class TlsObservation { public string Subject; public string Issuer; public string Thumbprint; public DateTime NotBefore; public DateTime NotAfter; public string Protocol; public bool NameValid; public bool ChainValid; public string Errors; public bool RevocationChecked=false; }
 public static class TlsInspector {
  public static TlsObservation Read(string host,int port,string name,int timeout) {
   TlsObservation result=new TlsObservation();
   using(TcpClient client=new TcpClient()) {
    IAsyncResult connecting=client.BeginConnect(host,port,null,null);
    using(connecting.AsyncWaitHandle) {if(!connecting.AsyncWaitHandle.WaitOne(timeout))throw new TimeoutException("TCP connection timed out");client.EndConnect(connecting);}
    client.ReceiveTimeout=timeout;client.SendTimeout=timeout;
    RemoteCertificateValidationCallback inspect=delegate(object sender,X509Certificate cert,X509Chain chain,SslPolicyErrors errors) {
     result.NameValid=(errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0;
     result.ChainValid=(errors&(SslPolicyErrors.RemoteCertificateChainErrors|SslPolicyErrors.RemoteCertificateNotAvailable))==0;
     result.Errors=errors.ToString();return cert!=null;
    };
    using(SslStream stream=new SslStream(client.GetStream(),false,inspect)) {
     SslProtocols protocols=SslProtocols.Tls12;
     if(Enum.IsDefined(typeof(SslProtocols),"Tls13"))protocols|=(SslProtocols)Enum.Parse(typeof(SslProtocols),"Tls13");
     IAsyncResult auth=stream.BeginAuthenticateAsClient(name,new X509CertificateCollection(),protocols,false,null,null);
     using(auth.AsyncWaitHandle) {if(!auth.AsyncWaitHandle.WaitOne(timeout))throw new TimeoutException("TLS handshake timed out");stream.EndAuthenticateAsClient(auth);}
     using(X509Certificate2 cert=new X509Certificate2(stream.RemoteCertificate)) {
      result.Subject=cert.Subject;result.Issuer=cert.Issuer;result.Thumbprint=cert.Thumbprint;result.NotBefore=cert.NotBefore.ToUniversalTime();result.NotAfter=cert.NotAfter.ToUniversalTime();result.Protocol=stream.SslProtocol.ToString();
     }
    }
   }
   return result;
  }
 }
}
'@
    }
    [ADAnalyzer.TlsInspector]::Read($HostName, $Port, $ServerName, $TimeoutSeconds * 1000)
}

class ADAnalyzerHostPolicyEvaluator {
    ADAnalyzerHostPolicyEvaluator() {
    }

    [object[]] Evaluate([object[]]$Hosts) {
        return $this.Evaluate($Hosts, [pscredential]::Empty, $null)
    }

    [object[]] Evaluate([object[]]$Hosts, [hashtable]$Profile) {
        return $this.Evaluate($Hosts, [pscredential]::Empty, $Profile)
    }

    [object[]] Evaluate([object[]]$Hosts, [pscredential]$Credential, [hashtable]$Profile) {
        $ErrorActionPreference = 'Stop'
        $configuration = [ADAnalyzerProfile]::new($Profile).ToHashtable()
        $rules = $configuration.Host
        $evaluator = $this
        $checks = [Collections.Generic.List[object]]::new()
        $writePolicyCheck = {
            param([hashtable]$PolicyCheckArguments)

            $evaluator.CreateCheck($PolicyCheckArguments, $null)
        }
        $observeAudit = Get-ADAnalyzerHostAuditObservation
        $observeCertificate = Get-ADAnalyzerHostCertificateObservation

        foreach ($hostRecord in $Hosts) {
            $name = [string]$hostRecord.ComputerName
            if (-not $name) {
                continue
            }
            foreach ($serviceRule in @($rules.Services)) {
                $service = @($hostRecord.Services | Where-Object Name -eq $serviceRule.Name)
                $stateMatches = $false
                $startModeMatches = $true
                if ($service.Count -eq 1) {
                    $stateMatches = $evaluator.ServiceStateMatches($service[0].State, $serviceRule)
                    if ($stateMatches -and $evaluator.ServiceStartModeRequired($serviceRule)) {
                        $startModeMatches = $evaluator.ServiceStartModeMatches($service[0].StartMode, $serviceRule)
                    }
                }
                $status = $evaluator.ServiceStatus($service.Count, $stateMatches, $startModeMatches)
                $specification = $evaluator.ServiceSpecification($name, $serviceRule, $service, $status)
                $checks.Add($evaluator.CreateCheck($specification.Arguments, $specification.Target))
            }
            foreach ($rule in @($rules.RegistryRules)) {
                $record = @($hostRecord.Registry | Where-Object {
                        $_.Path -ieq $rule.Key -and $_.Name -ieq $rule.ValueName
                    })
                $specification = $evaluator.EvaluateRegistry($name, $rule, $record)
                $checks.Add($evaluator.CreateCheck($specification.Arguments, $specification.Target))
            }
            if ($evaluator.HasAuditRules($rules)) {
                foreach ($check in @(. $observeAudit)) {
                    $checks.Add($check)
                }
            }
            else {
                $checks.Add($evaluator.CreateCheck($evaluator.AuditNotConfiguredSpecification($name), $null))
            }
        }

        foreach ($endpoint in @($rules.CertificateEndpoints)) {
            $endpointParameters = $evaluator.TlsEndpoint($endpoint)
            foreach ($check in @(. $observeCertificate)) {
                $checks.Add($check)
            }
        }
        return $checks.ToArray()
    }

    hidden [bool] HasAuditRules([hashtable]$Rules) {
        return @($Rules.AuditRules).Count -ne 0
    }

    hidden [hashtable] EvaluateRegistry([string]$Name, [object]$Rule, [object[]]$Rows) {
        $observed = $null
        $status = $this.RegistryStatus($false, $false, $false)
        $typeFrame = $null
        if ($Rows.Count -eq 1) {
            $typeFrame = @{
                Record = $Rows[0]
            }
        }
        if ($Rows.Count -eq 1 -and $Rows[0].Status -eq 'Observed') {
            $observed = $Rows[0].Value
            $typeKnown = $true
            $typeMatches = $true
            if ($Rule.Contains('Type')) {
                $typeKnown = (Test-ADAnalyzerOptionalSecretRecordMember $typeFrame 'Type') -and $null -ne $Rows[0].Type
                if ($typeKnown) {
                    $observedType = $(if (Test-ADAnalyzerOptionalSecretRecordMember $typeFrame 'Type') {
                            , $Rows[0].Type
                        })
                    $typeMatches = $this.RegistryTypeMatches($observedType, $Rule['Type'])
                }
            }
            $status = $this.RegistryStatus($true, $typeKnown, $typeMatches)
            if ($status -eq 'Compare') {
                try {
                    $comparison = New-ADAnalyzerPolicyValueSemantics
                    $status = $this.RegistryComparisonStatus(
                        $true,
                        $comparison.Compare($observed, $Rule.Expected, $this.RegistryOperator($Rule))
                    )
                }
                catch {
                    $status = $this.RegistryComparisonStatus($false, $false)
                }
            }
        }
        $specification = $this.RegistrySpecification($Name, $Rule, $observed, $null, $status)
        $specification.Arguments.Evidence.RegistryType = $(if ($null -ne $typeFrame -and
                (Test-ADAnalyzerOptionalSecretRecordMember $typeFrame 'Type')) {
                $Rows[0].Type
            })
        return $specification
    }

    hidden [pscustomobject] CreateCheck([hashtable]$Arguments, [string]$DisplayTarget) {
        foreach ($field in @('Observed', 'Expected', 'Evidence')) {
            if ($Arguments.ContainsKey($field)) {
                $Arguments[$field] = $this.CopyObservation($Arguments[$field])
            }
        }
        $check = [ADAnalyzerCheckFactory]::new().Create($Arguments)
        if ($DisplayTarget) {
            $check.Target = $DisplayTarget
        }
        return $check
    }

    hidden [object] CopyObservation([object]$Value) {
        if ($Value -is [array]) {
            $copy = $Value.Clone()
            if ($copy.GetType() -eq [object[]]) {
                for ($index = 0; $index -lt $copy.Length; $index++) {
                    $copy[$index] = $this.CopyObservationRecord($copy[$index])
                }
            }
            return $copy
        }
        return $this.CopyObservationRecord($Value)
    }

    hidden [object] CopyObservationRecord([object]$Value) {
        if ($Value -is [pscustomobject]) {
            return $Value.PSObject.Copy()
        }
        if ($Value -is [hashtable]) {
            return $Value.Clone()
        }
        # Preserve native records and their session metadata as borrowed observations.
        return $Value
    }

    hidden [bool] ServiceStateMatches([object]$State, [object]$Rule) {
        return ($State -eq $Rule.State)
    }

    hidden [bool] ServiceStartModeRequired([object]$Rule) {
        return $Rule['StartMode']
    }

    hidden [bool] ServiceStartModeMatches([object]$Mode, [object]$Rule) {
        return ($Mode -eq $Rule['StartMode'])
    }

    hidden [string] ServiceStatus([int]$Count, [bool]$StateMatches, [bool]$StartModeMatches) {
        if ($Count -ne 1) {
            return 'Unknown'
        }
        if ($StateMatches -and $StartModeMatches) {
            return 'Pass'
        }
        return 'Fail'
    }

    hidden [hashtable] ServiceSpecification(
        [string]$Name,
        [object]$Rule,
        [object]$Rows,
        [string]$Status
    ) {
        $target = $Name + '/Service/' + $Rule.Name
        $identity = Get-ADAnalyzerHostRuleIdentity -Rule $Rule -Target $target -Parts @($Rule.Name)
        return @{
            Target = $target
            Arguments = @{
                RuleId = 'HOST.SERVICE'
                Status = $Status
                Severity = 'Medium'
                Category = 'Host'
                Target = $identity
                Observed = $Rows
                Expected = $Rule
                Evidence = @{
                    ProfileRuleId = $Rule['Id']
                }
                Applicability = 'Applicable'
            }
        }
    }

    hidden [object] RegistryOperator([object]$Rule) {
        if ($Rule['Operator']) {
            return $Rule['Operator']
        }
        return 'Equals'
    }

    hidden [bool] RegistryTypeMatches([object]$Type, [object]$Expected) {
        return (-not ($Type -ne $Expected))
    }

    hidden [string] RegistryStatus([bool]$Observed, [bool]$TypeKnown, [bool]$TypeMatches) {
        if (-not $Observed -or -not $TypeKnown) {
            return 'Unknown'
        }
        if (-not $TypeMatches) {
            return 'Invalid'
        }
        return 'Compare'
    }

    hidden [string] RegistryComparisonStatus([bool]$ComparisonSucceeded, [bool]$Matched) {
        if (-not $ComparisonSucceeded) {
            return 'Invalid'
        }
        if ($Matched) {
            return 'Pass'
        }
        return 'Fail'
    }

    hidden [hashtable] RegistrySpecification(
        [string]$Name,
        [object]$Rule,
        [object]$Observed,
        [object]$RegistryType,
        [string]$Status
    ) {
        $target = $Name + '/Registry/' + $Rule.Key + '/' + $Rule.ValueName
        $identity = Get-ADAnalyzerHostRuleIdentity -Rule $Rule -Target $target -Parts @($Rule.Key, $Rule.ValueName)
        return @{
            Target = $target
            Arguments = @{
                RuleId = 'HOST.REGISTRY'
                Status = $Status
                Severity = 'Medium'
                Category = 'Host'
                Target = $identity
                Observed = $Observed
                Expected = $Rule.Expected
                Evidence = @{
                    ProfileRuleId = $Rule['Id']
                    RegistryPath = $Rule.Key
                    ValueName = $Rule.ValueName
                    RegistryOperator = $this.RegistryOperator($Rule)
                    RegistryType = $RegistryType
                    ExpectedRegistryType = $Rule['Type']
                }
                Message = 'An absent registry override does not establish the operating-system default or effective protocol behavior'
                Applicability = 'Configured'
            }
        }
    }

    hidden [string] AuditStatus([int]$Count, [object]$ObservedFlags, [object]$RequiredFlags) {
        if ($Count -ne 1) {
            return 'Unknown'
        }
        if (([uint32]$ObservedFlags -band [uint32]$RequiredFlags) -eq [uint32]$RequiredFlags) {
            return 'Pass'
        }
        return 'Fail'
    }

    hidden [hashtable] AuditSpecification([string]$Name, [string]$Id, [object]$Rule, [object[]]$Rows, [string]$Status) {
        return @{
            RuleId = 'HOST.AUDIT_POLICY'
            Status = $Status
            Severity = 'Medium'
            Category = 'Audit'
            Target = $Name + '/Audit/' + $Id
            Observed = $Rows
            Expected = $Rule.Flags
            Message = 'Native system audit policy flags: success=1, failure=2. Per-user policy and event delivery are separate controls.'
            Applicability = 'Applicable'
        }
    }

    hidden [hashtable] AuditFailureSpecification([string]$Name, [string]$Message) {
        return @{
            RuleId = 'HOST.AUDIT_POLICY'
            Status = 'Unreadable'
            Severity = 'Medium'
            Category = 'Audit'
            Target = $Name + '/Audit'
            Message = $Message
        }
    }

    hidden [hashtable] AuditNotConfiguredSpecification([string]$Name) {
        return @{
            RuleId = 'HOST.AUDIT_POLICY'
            Status = 'NotConfigured'
            Category = 'Audit'
            Target = $Name + '/Audit'
            Message = 'Configure subcategory GUID and required flag masks to collect native system audit policy'
        }
    }

    hidden [hashtable] TlsEndpoint([hashtable]$Endpoint) {
        $hostName = [string]$Endpoint.HostName
        $port = if ($Endpoint['Port']) {
            [int]$Endpoint['Port']
        }
        else {
            443
        }
        $serverName = if ($Endpoint['ServerName']) {
            [string]$Endpoint['ServerName']
        }
        else {
            $hostName
        }
        return @{
            HostName = $hostName
            Port = $port
            ServerName = $serverName
            Target = '{0}:{1}/{2}' -f $hostName, $port, $serverName
        }
    }

    hidden [int] TlsMinimum([hashtable]$Endpoint) {
        if ($null -ne $Endpoint['MinimumRemainingDays']) {
            return [int]$Endpoint['MinimumRemainingDays']
        }
        return 30
    }

    hidden [string] TlsStatus([bool]$Trusted, [object]$NotBefore, [double]$Remaining, [int]$Minimum) {
        if ($Trusted -and [datetime]$NotBefore -le [datetime]::UtcNow -and $Remaining -ge $Minimum) {
            return 'Pass'
        }
        return 'Fail'
    }

    hidden [hashtable] TlsSpecification([string]$Target, [object]$Certificate, [int]$Minimum, [string]$Status) {
        return @{
            RuleId = 'HOST.TLS_CERTIFICATE'
            Status = $Status
            Severity = 'High'
            Category = 'Certificate'
            Target = $Target
            Observed = $Certificate
            Expected = @{
                MinimumRemainingDays = $Minimum
                NameValid = $true
                ChainValid = $true
                Protocol = 'TLS1.2 or TLS1.3'
            }
            Message = 'Direct TLS endpoint inspection. Certificate revocation was not checked; STARTTLS and LDAP channel binding are not assessed.'
            Applicability = 'Applicable'
        }
    }

    hidden [hashtable] TlsRevocationSpecification([string]$Target) {
        return @{
            RuleId = 'HOST.CERTIFICATE_REVOCATION'
            Status = 'Unknown'
            Category = 'Certificate'
            Target = $Target
            Observed = $false
            Expected = 'Revocation validation'
            Message = 'This bounded offline-chain inspection does not query revocation services'
        }
    }

    hidden [hashtable] TlsFailureSpecification([string]$Target, [string]$Message) {
        return @{
            RuleId = 'HOST.TLS_CERTIFICATE'
            Status = 'Unreadable'
            Severity = 'High'
            Category = 'Certificate'
            Target = $Target
            Message = $Message
        }
    }
}

function Get-ADAnalyzerHostAuditObservation {
    {
        try {
            $auditArguments = @{
                ComputerName = $name
                Credential = $Credential
                TimeoutSeconds = $configuration.Analysis.HostTimeoutSeconds
            }
            $audit = @(Get-ADAnalyzerAuditPolicy @auditArguments)
            foreach ($rule in $rules.AuditRules) {
                $id = ([guid]$rule.SubcategoryGuid).ToString()
                $record = @($audit | Where-Object SubcategoryGuid -eq $id)
                $status = if ($record.Count -ne 1) {
                    $evaluator.AuditStatus($record.Count, $null, $null)
                }
                elseif ($evaluator.AuditStatus($record.Count, [uint32]$record[0].Flags, [uint32]$rule.Flags) -eq 'Pass') {
                    'Pass'
                }
                else {
                    'Fail'
                }
                . $writePolicyCheck ($evaluator.AuditSpecification($name, $id, $rule, $record, $status))
            }
        }
        catch {
            . $writePolicyCheck ($evaluator.AuditFailureSpecification($name, $_.Exception.Message))
        }
    }
}

function Get-ADAnalyzerHostCertificateObservation {
    {
        $target = $endpointParameters.Target
        try {
            $tlsArguments = @{
                HostName = $endpointParameters.HostName
                Port = $endpointParameters.Port
                ServerName = $endpointParameters.ServerName
                TimeoutSeconds = $configuration.Analysis.HostTimeoutSeconds
            }
            $certificate = Get-ADAnalyzerTlsCertificate @tlsArguments
            $remaining = ([datetime]$certificate.NotAfter - [datetime]::UtcNow).TotalDays
            $minimum = $evaluator.TlsMinimum($endpoint)
            $trusted = $certificate.NameValid -and $certificate.ChainValid
            $notBefore = $null
            if ($trusted) {
                $notBefore = [datetime]$certificate.NotBefore
            }
            $status = $evaluator.TlsStatus($trusted, $notBefore, $remaining, $minimum)
            . $writePolicyCheck ($evaluator.TlsSpecification($target, $certificate, $minimum, $status))
            . $writePolicyCheck ($evaluator.TlsRevocationSpecification($target))
        }
        catch {
            . $writePolicyCheck ($evaluator.TlsFailureSpecification($target, $_.Exception.Message))
        }
    }
}

function Test-ADAnalyzerHostPolicy {
    [CmdletBinding()]
    param(
        [array]$Hosts = @(),
        [pscredential]$Credential = [pscredential]::Empty,
        [hashtable]$Profile

    )
    $configuration = Import-ADAnalyzerProfile -Profile $Profile
    $rules = $configuration.Host
    $evaluator = [ADAnalyzerHostPolicyEvaluator]::new()
    $writePolicyCheck = {
        param([hashtable]$PolicyCheckArguments)

        New-ADAnalyzerCheck @PolicyCheckArguments
    }
    $observeAudit = Get-ADAnalyzerHostAuditObservation
    $observeCertificate = Get-ADAnalyzerHostCertificateObservation

    # Observe properties in the advanced command scope so native errors remain visible.
    foreach ($hostRecord in $Hosts) {
        $name = [string]$hostRecord.ComputerName
        if (-not $name) {
            continue
        }
        foreach ($serviceRule in @($rules.Services)) {
            $service = @($hostRecord.Services | Where-Object Name -eq $serviceRule.Name)
            $expectedStartMode = $serviceRule['StartMode']
            $status = if ($service.Count -ne 1) {
                $evaluator.ServiceStatus($service.Count, $false, $false)
            }
            elseif ($evaluator.ServiceStateMatches($service[0].State, $serviceRule) -and
                (-not $expectedStartMode -or
                $evaluator.ServiceStartModeMatches($service[0].StartMode, $serviceRule))) {
                $evaluator.ServiceStatus($service.Count, $true, $true)
            }
            else {
                $evaluator.ServiceStatus($service.Count, $false, $false)
            }
            $specification = $evaluator.ServiceSpecification($name, $serviceRule, $service, $status)
            $arguments = $specification.Arguments
            $check = New-ADAnalyzerCheck @arguments
            $check.Target = $specification.Target
            $check
        }
        foreach ($rule in @($rules.RegistryRules)) {
            $record = @($hostRecord.Registry | Where-Object {
                    $_.Path -ieq $rule.Key -and $_.Name -ieq $rule.ValueName
                })
            $observed = $null
            $status = $evaluator.RegistryStatus($false, $false, $false)
            $typeFrame = $null
            if ($record.Count -eq 1) {
                $typeFrame = @{
                    Record = $record[0]
                }
            }
            if ($record.Count -eq 1 -and $record[0].Status -eq 'Observed') {
                $observed = $record[0].Value
                $operator = $evaluator.RegistryOperator($rule)
                $typeKnown = $true
                $typeMatches = $true
                if ($rule.Contains('Type')) {
                    $typeKnown = (Test-ADAnalyzerOptionalSecretRecordMember $typeFrame 'Type') -and $null -ne $record[0].Type
                    if ($typeKnown) {
                        $observedType = $(if (Test-ADAnalyzerOptionalSecretRecordMember $typeFrame 'Type') {
                                , $record[0].Type
                            })
                        $typeMatches = $evaluator.RegistryTypeMatches($observedType, $rule['Type'])
                    }
                }
                $status = $evaluator.RegistryStatus($true, $typeKnown, $typeMatches)
                if ($status -eq 'Compare') {
                    try {
                        $status = $evaluator.RegistryComparisonStatus($true, (
                                Test-ADAnalyzerPolicyComparison $observed $rule.Expected $operator
                            ))
                    }
                    catch {
                        $status = $evaluator.RegistryComparisonStatus($false, $false)
                    }
                }
            }
            $specification = $evaluator.RegistrySpecification($name, $rule, $observed, $null, $status)
            $arguments = $specification.Arguments
            $arguments.Evidence.RegistryType = $(if ($null -ne $typeFrame -and
                    (Test-ADAnalyzerOptionalSecretRecordMember $typeFrame 'Type')) {
                    $record[0].Type
                })
            $check = New-ADAnalyzerCheck @arguments
            $check.Target = $specification.Target
            $check
        }

        if ($evaluator.HasAuditRules($rules)) {
            . $observeAudit
        }
        else {
            $arguments = $evaluator.AuditNotConfiguredSpecification($name)
            New-ADAnalyzerCheck @arguments
        }
    }

    foreach ($endpoint in @($rules.CertificateEndpoints)) {
        $endpointParameters = $evaluator.TlsEndpoint($endpoint)
        . $observeCertificate
    }
}
