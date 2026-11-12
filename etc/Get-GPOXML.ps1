[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Alias('Domain','FQDN')][string]$CliDomain,[Alias('Server')][string]$CliServer,
    [Alias('Name')][string]$CliName,[Alias('Guid')][guid]$CliGuid,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('InputObject')]$CliInputObject,[Alias('OutputPath')][string]$CliOutputPath
)
function Get-ADAnalyzerGpoXml {
    <# Retrieve package canonical XML, optionally saving it. Stored policy is not RSoP. #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Alias('FQDN')][string]$Domain,[string]$Server,[string]$Name,[guid]$Guid,
        [pscredential]$Credential=[pscredential]::Empty,$InputObject,[string]$OutputPath)
    $repository=Split-Path -Parent $PSScriptRoot
    if($PSBoundParameters.ContainsKey('InputObject')){
        foreach($field in @('Domain','Server','Name','Guid','Credential')){if($PSBoundParameters.ContainsKey($field)){throw 'Choose InputObject or explicit live target inputs.'}}
        if($null -eq $InputObject.Gpo -or $null -eq $InputObject.Policy){throw 'InputObject requires a package Gpo and Policy report.'}
        $id=[guid]::Empty;$flags=0
        if(-not [guid]::TryParse([string]$InputObject.Gpo.Id,[ref]$id) -or
           -not [int]::TryParse([string]$InputObject.Gpo.Flags,[ref]$flags) -or $flags -lt 0 -or $flags -gt 3){throw 'Offline XML requires a valid GPO Id and supplied Flags (0..3).'}
        $metadata=$InputObject.Gpo
        . (Join-Path $repository 'bin/ADGpo.ps1')
        $policy=ConvertTo-ADAnalyzerProvidedGpoPolicy -Policy $InputObject.Policy
        $text=ConvertTo-AnalyzerGpoXml -Gpo $InputObject.Gpo -Parsed $policy
    }else{
        if([string]::IsNullOrWhiteSpace($Domain)){throw 'An explicit Domain is required.'}
        if([int]$PSBoundParameters.ContainsKey('Name')+[int]$PSBoundParameters.ContainsKey('Guid') -ne 1){throw 'Select exactly one Name or Guid.'}
        if($PSBoundParameters.ContainsKey('Name') -and [string]::IsNullOrWhiteSpace($Name)){throw 'Name cannot be empty.'}
        Import-Module (Join-Path $repository 'ADEnvironment.psd1') -ErrorAction Stop
        $arguments=@{Domain=$Domain;Credential=$Credential}
        if($Server){$arguments.Server=$Server}
        if($PSBoundParameters.ContainsKey('Guid')){$arguments.Guid=$Guid}else{$arguments.Name=$Name}
        $selected=@(Get-ADAnalyzerGpo @arguments)
        if($selected.Count -ne 1){throw 'GPO was not found or the selector was ambiguous.'}
        $metadata=$selected[0]
        $text=Get-ADAnalyzerGpoReport -Gpo $selected[0] -Credential $Credential
    }
    if([string]::IsNullOrWhiteSpace([string]$text)){throw 'The GPO report is empty.'}
    . (Join-Path $repository 'bin/ADSecret.ps1')
    . (Join-Path $repository 'bin/ADFile.ps1')
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $stringReader=[IO.StringReader]::new([string]$text);$reader=$null
    try{
        $reader=[Xml.XmlReader]::Create($stringReader,$settings)
        $document=[xml]::new();$document.XmlResolver=$null;$document.Load($reader)
    }finally{if($null -ne $reader){$reader.Dispose()};$stringReader.Dispose()}
    if($document.DocumentElement.LocalName -ne 'GPO'){throw 'The report is not package GPO XML.'}
    $identity=[guid]::Empty
    if(-not [guid]::TryParse([string]$metadata.Id,[ref]$identity)){throw 'The selected GPO identity is invalid.'}
    foreach($field in @('Id','DisplayName','Domain','Server','Flags')){
        $value=if($field -eq 'Id'){$identity.ToString('D')}else{$metadata.$field}
        if($null -eq $value -or [string]::IsNullOrEmpty([string]$value)){continue}
        $node=$document.DocumentElement.SelectSingleNode('./'+$field)
        if($null -eq $node){$node=$document.CreateElement($field);$null=$document.DocumentElement.AppendChild($node)}
        $node.InnerText=[string]$value
    }
    $safe=ConvertTo-ADAnalyzerSecretIndicatorXml $document
    if($safe.FirstChild -is [Xml.XmlDeclaration]){$safe.FirstChild.Encoding='utf-8'}
    else{$null=$safe.PrependChild($safe.CreateXmlDeclaration('1.0','utf-8',$null))}
    $xml=$safe.OuterXml
    if($OutputPath -and $PSCmdlet.ShouldProcess($OutputPath,'Save package GPO XML')){$null=Write-ADAnalyzerFile -Path $OutputPath -Content $xml}
    return $xml
}
if($MyInvocation.InvocationName -ne '.'){
    $arguments=@{}
    foreach($name in @('Domain','Server','Name','Guid','Credential','InputObject','OutputPath')){
        if($PSBoundParameters.ContainsKey('Cli'+$name)){$arguments[$name]=Get-Variable -Name ('Cli'+$name) -ValueOnly}
    }
    $arguments.WhatIf=[bool]$WhatIfPreference
    if($PSBoundParameters.ContainsKey('Confirm')){$arguments.Confirm=$PSBoundParameters.Confirm}
    Get-ADAnalyzerGpoXml @arguments
}
