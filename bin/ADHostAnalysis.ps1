function Get-ADAnalyzerAuditPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName,[pscredential]$Credential=[pscredential]::Empty,[int]$TimeoutSeconds=30)
    # Numeric native policy flags avoid localized auditpol output. This is a
    # read-only WinRM operation; remote configuration is never enabled here.
    $block={
        if(-not ('ADAnalyzer.NativeAuditPolicy' -as [type])) {
            Add-Type -TypeDefinition @'
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
        [ADAnalyzer.NativeAuditPolicy]::Read() | ForEach-Object {[pscustomobject]@{SubcategoryGuid=$_.Subcategory.ToString();CategoryGuid=$_.Category.ToString();Flags=[uint32]$_.Flags}}
    }
    $arguments=@{ComputerName=$ComputerName;ScriptBlock=$block;ErrorAction='Stop'}
    if($Credential -and $Credential -ne [pscredential]::Empty){$arguments.Credential=$Credential}
    $arguments.SessionOption=New-PSSessionOption -OpenTimeout ($TimeoutSeconds*1000) -OperationTimeout ($TimeoutSeconds*1000) -ErrorAction Stop
    @(Invoke-Command @arguments)
}

function Get-ADAnalyzerTlsCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostName,[ValidateRange(1,65535)][int]$Port=443,[string]$ServerName=$HostName,[ValidateRange(1,300)][int]$TimeoutSeconds=10)
    if(-not ('ADAnalyzer.TlsInspector' -as [type])) {
        Add-Type -TypeDefinition @'
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
    [ADAnalyzer.TlsInspector]::Read($HostName,$Port,$ServerName,$TimeoutSeconds*1000)
}

function Test-ADAnalyzerHostPolicy {
    [CmdletBinding()]
    param([array]$Hosts=@(),[pscredential]$Credential=[pscredential]::Empty,[hashtable]$Profile)
    $configuration=Import-ADAnalyzerProfile -Profile $Profile
    $rules=$configuration.Host
    foreach($hostRecord in $Hosts) {
        $name=[string]$hostRecord.ComputerName
        if(-not $name){continue}
        foreach($serviceRule in @($rules.Services)) {
            $service=@($hostRecord.Services | Where-Object Name -eq $serviceRule.Name)
            $status=if($service.Count -ne 1){'Unknown'}elseif($service[0].State -eq $serviceRule.State -and (!$serviceRule.StartMode -or $service[0].StartMode -eq $serviceRule.StartMode)){'Pass'}else{'Fail'}
            New-ADAnalyzerCheck -RuleId 'HOST.SERVICE' -Status $status -Severity Medium -Category Host -Target ($name+'/Service/'+$serviceRule.Name) -Observed $service -Expected $serviceRule -Applicability Applicable
        }
        foreach($rule in @($rules.RegistryRules)) {
            $record=@($hostRecord.Registry | Where-Object { $_.Path -ieq $rule.Key -and $_.Name -ieq $rule.ValueName })
            $status='Unknown';$observed=$null
            if($record.Count -eq 1 -and $record[0].Status -eq 'Observed'){
                $observed=$record[0].Value;$operator=if($rule.Operator){$rule.Operator}else{'Equals'}
                if($rule.Contains('Type') -and $null -eq $record[0].Type){$status='Unknown'}
                elseif($rule.Contains('Type') -and $record[0].Type -ne $rule.Type){$status='Invalid'}
                else{try{$status=if(Test-ADAnalyzerPolicyComparison $observed $rule.Expected $operator){'Pass'}else{'Fail'}}catch{$status='Invalid'}}
            }
            New-ADAnalyzerCheck -RuleId 'HOST.REGISTRY' -Status $status -Severity Medium -Category Host -Target ($name+'/Registry/'+$rule.Key+'/'+$rule.ValueName) -Observed $observed -Expected $rule.Expected -Message 'An absent registry override does not establish the operating-system default or effective protocol behavior' -Applicability Configured
        }
        if(@($rules.AuditRules).Count) {
            try {
                $audit=@(Get-ADAnalyzerAuditPolicy -ComputerName $name -Credential $Credential -TimeoutSeconds $configuration.Analysis.HostTimeoutSeconds)
                foreach($rule in $rules.AuditRules) {
                    $id=([guid]$rule.SubcategoryGuid).ToString();$record=@($audit | Where-Object SubcategoryGuid -eq $id)
                    $status=if($record.Count -ne 1){'Unknown'}elseif(([uint32]$record[0].Flags -band [uint32]$rule.Flags) -eq [uint32]$rule.Flags){'Pass'}else{'Fail'}
                    New-ADAnalyzerCheck -RuleId 'HOST.AUDIT_POLICY' -Status $status -Severity Medium -Category Audit -Target ($name+'/Audit/'+$id) -Observed $record -Expected $rule.Flags -Message 'Native system audit policy flags: success=1, failure=2. Per-user policy and event delivery are separate controls.' -Applicability Applicable
                }
            } catch {New-ADAnalyzerCheck -RuleId 'HOST.AUDIT_POLICY' -Status Unreadable -Severity Medium -Category Audit -Target ($name+'/Audit') -Message $_.Exception.Message}
        } else {New-ADAnalyzerCheck -RuleId 'HOST.AUDIT_POLICY' -Status NotConfigured -Category Audit -Target ($name+'/Audit') -Message 'Configure subcategory GUID and required flag masks to collect native system audit policy'}
    }
    foreach($endpoint in @($rules.CertificateEndpoints)) {
        $hostName=[string]$endpoint.HostName;$port=if($endpoint.Port){[int]$endpoint.Port}else{443};$serverName=if($endpoint.ServerName){[string]$endpoint.ServerName}else{$hostName}
        $target=('{0}:{1}/{2}' -f $hostName,$port,$serverName)
        try {
            $certificate=Get-ADAnalyzerTlsCertificate -HostName $hostName -Port $port -ServerName $serverName -TimeoutSeconds $configuration.Analysis.HostTimeoutSeconds
            $remaining=([datetime]$certificate.NotAfter-[datetime]::UtcNow).TotalDays
            $minimum=if($null -ne $endpoint.MinimumRemainingDays){[int]$endpoint.MinimumRemainingDays}else{30}
            $valid=$certificate.NameValid -and $certificate.ChainValid -and [datetime]$certificate.NotBefore -le [datetime]::UtcNow -and $remaining -ge $minimum
            New-ADAnalyzerCheck -RuleId 'HOST.TLS_CERTIFICATE' -Status $(if($valid){'Pass'}else{'Fail'}) -Severity High -Category Certificate -Target $target -Observed $certificate -Expected @{MinimumRemainingDays=$minimum;NameValid=$true;ChainValid=$true;Protocol='TLS1.2 or TLS1.3'} -Message 'Direct TLS endpoint inspection. Certificate revocation was not checked; STARTTLS and LDAP channel binding are not assessed.' -Applicability Applicable
            New-ADAnalyzerCheck -RuleId 'HOST.CERTIFICATE_REVOCATION' -Status Unknown -Category Certificate -Target $target -Observed $false -Expected 'Revocation validation' -Message 'This bounded offline-chain inspection does not query revocation services'
        } catch {New-ADAnalyzerCheck -RuleId 'HOST.TLS_CERTIFICATE' -Status Unreadable -Severity High -Category Certificate -Target $target -Message $_.Exception.Message}
    }
}
