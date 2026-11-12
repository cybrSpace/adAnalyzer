[CmdletBinding()]
param([string]$RepositoryRoot)
$ErrorActionPreference='Stop'
if(-not $RepositoryRoot){$RepositoryRoot=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)}
foreach($name in @('ADProfile','ADGpo','ADPolicyAnalysis','ADHostAnalysis')){. (Join-Path $RepositoryRoot ('bin/'+$name+'.ps1'))}
$script:Passed=0;$script:Failed=0
function Assert-Equal($Expected,$Actual){if($Expected -ne $Actual){throw "Expected [$Expected], got [$Actual]"}}
function Assert-True($Actual,[string]$Message){if(-not $Actual){throw $Message}}
function Test-HostPolicy([string]$Name,[scriptblock]$Body){try{& $Body;$script:Passed++;Write-Host "PASS $Name"}catch{$script:Failed++;Write-Host "FAIL $Name : $_";Write-Host $_.ScriptStackTrace}}
$script:AuditFlags=3;$script:AuditFails=$false
$script:Credential=[pscredential]::new('fixture',(ConvertTo-SecureString 'fixture-only' -AsPlainText -Force))
function Get-ADAnalyzerAuditPolicy {param($ComputerName,$Credential,$TimeoutSeconds)
    $script:AuditCredential=$Credential
    if($script:AuditFails){throw 'fixture WinRM denied'}
    [pscustomobject]@{SubcategoryGuid='0cce9215-69ae-11d9-bed3-505054503030';Flags=$script:AuditFlags}
}
$script:CertificateValid=$true;$script:CertificateFails=$false
function Get-ADAnalyzerTlsCertificate {param($HostName,$Port,$ServerName,$TimeoutSeconds)
    if($script:CertificateFails){throw 'fixture TLS failed'}
    [pscustomobject]@{Subject='CN=fixture';Thumbprint='fixture';NameValid=$script:CertificateValid;ChainValid=$script:CertificateValid;NotBefore=[datetime]::UtcNow.AddDays(-1);NotAfter=[datetime]::UtcNow.AddDays(90);Protocol='Tls12';RevocationChecked=$false}
}
$hostRecord=[pscustomobject]@{ComputerName='dc.example.invalid';Services=@([pscustomobject]@{Name='Spooler';State='Stopped';StartMode='Disabled'});Registry=@([pscustomobject]@{Path='SYSTEM\Fixture';Name='Enabled';Status='Observed';Value=0})}
$profile=Get-ADAnalyzerDefaultProfile
$profile.Host.Services=@(@{Name='Spooler';State='Stopped';StartMode='Disabled'})
$profile.Host.RegistryRules=@(@{Key='SYSTEM\Fixture';ValueName='Enabled';Expected=0})
$profile.Host.AuditRules=@(@{SubcategoryGuid='0cce9215-69ae-11d9-bed3-505054503030';Flags=3})
$profile.Host.CertificateEndpoints=@(@{HostName='dc.example.invalid';Port=636;ServerName='dc.example.invalid';MinimumRemainingDays=30})
Test-HostPolicy 'host services and explicit registry overrides are evaluated from observations' {
    $checks=@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile -Credential $script:Credential)
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.SERVICE).Status
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.REGISTRY).Status
}
Test-HostPolicy 'numeric audit masks verify success and failure without localized text' {
    $checks=@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile -Credential $script:Credential)
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.AUDIT_POLICY).Status
    Assert-True ([object]::ReferenceEquals($script:Credential,$script:AuditCredential)) 'Audit credential lost'
    $script:AuditFlags=1
    try{Assert-Equal Fail (@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile) | Where-Object RuleId -eq HOST.AUDIT_POLICY).Status}finally{$script:AuditFlags=3}
}
Test-HostPolicy 'unavailable audit permissions become unreadable instead of compliant' {
    $script:AuditFails=$true
    try{Assert-Equal Unreadable (@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile) | Where-Object RuleId -eq HOST.AUDIT_POLICY).Status}finally{$script:AuditFails=$false}
}
Test-HostPolicy 'TLS name chain validity and expiry are checked with revocation explicit' {
    $checks=@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile)
    Assert-Equal Pass ($checks | Where-Object RuleId -eq HOST.TLS_CERTIFICATE).Status
    Assert-Equal Unknown ($checks | Where-Object RuleId -eq HOST.CERTIFICATE_REVOCATION).Status
    $script:CertificateValid=$false
    try{Assert-Equal Fail (@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile) | Where-Object RuleId -eq HOST.TLS_CERTIFICATE).Status}finally{$script:CertificateValid=$true}
}
Test-HostPolicy 'TLS handshake errors are visible and never produce a passing certificate' {
    $script:CertificateFails=$true
    try{Assert-Equal Unreadable (@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $profile) | Where-Object RuleId -eq HOST.TLS_CERTIFICATE).Status}finally{$script:CertificateFails=$false}
}
Test-HostPolicy 'missing registry overrides remain unknown and unconfigured audit causes no read' {
    $copy=Get-ADAnalyzerDefaultProfile;$copy.Host.RegistryRules=@(@{Key='Missing';ValueName='Enabled';Expected=0})
    $checks=@(Test-ADAnalyzerHostPolicy -Hosts @($hostRecord) -Profile $copy)
    Assert-Equal Unknown ($checks | Where-Object RuleId -eq HOST.REGISTRY).Status
    Assert-Equal NotConfigured ($checks | Where-Object RuleId -eq HOST.AUDIT_POLICY).Status
}
Test-HostPolicy 'native audit and TLS adapter source compiles without third party assemblies' {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot 'bin/ADHostAnalysis.ps1'),[ref]$tokens,[ref]$errors)
    $sources=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*namespace ADAnalyzer*'},$true))
    Assert-Equal 2 $sources.Count
    foreach($source in $sources){if($source.Value -like '*class TlsInspector*' -and -not ('ADAnalyzer.TlsInspector' -as [type])){Add-Type -TypeDefinition $source.Value};if($source.Value -like '*class NativeAuditPolicy*' -and -not ('ADAnalyzer.NativeAuditPolicy' -as [type])){Add-Type -TypeDefinition $source.Value}}
    Assert-True ([bool]('ADAnalyzer.TlsInspector' -as [type])) 'TLS inspector not compiled'
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $records=@([ADAnalyzer.NativeAuditPolicy]::Read())
        Assert-True ($records.Count -gt 0) 'No native audit subcategories returned'
        foreach($record in $records){Assert-True ($record.Flags -le 7) 'Invalid native audit flags'}
    }
}
if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Test-HostPolicy 'native TLS inspector observes a loopback server without trusting its self-signed certificate' {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
namespace ADAnalyzer {
 public sealed class TestTlsServer : IDisposable {
  TcpListener listener; X509Certificate2 cert; RSA key; Task server;
  public int Port;
  public TestTlsServer() {
   key=RSA.Create(2048);
   CertificateRequest request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
   listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;
   server=Task.Run(delegate {
    using(TcpClient client=listener.AcceptTcpClient()) using(SslStream stream=new SslStream(client.GetStream(),false)) {
     stream.AuthenticateAsServer(cert,false,SslProtocols.Tls12,false);
    }
   });
  }
  public void Dispose() {listener.Stop();try{server.Wait(5000);}catch{}cert.Dispose();key.Dispose();}
 }
}
'@
        $server=[ADAnalyzer.TestTlsServer]::new()
        try {
            $record=[ADAnalyzer.TlsInspector]::Read('127.0.0.1',$server.Port,'wrong.example.invalid',5000)
            Assert-Equal $false $record.NameValid;Assert-Equal $false $record.ChainValid
            Assert-Equal Tls12 $record.Protocol
            Assert-True (-not [string]::IsNullOrWhiteSpace($record.Thumbprint)) 'Missing inspected certificate'
        } finally {$server.Dispose()}
    }
}
Write-Host ("{0} host-analysis tests passed; {1} failed" -f $script:Passed,$script:Failed)
if($script:Failed){exit 1}
