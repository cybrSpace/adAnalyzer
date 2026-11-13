using module Microsoft.PowerShell.Utility
using namespace System.Collections
using namespace System.Collections.Specialized
[CmdletBinding()]
param(
    [Alias('ConfigPath')][string]$CliConfigPath,
    [Alias('Credential')][pscredential]$CliCredential=[pscredential]::Empty,
    [Alias('OutputPath')][string]$CliOutputPath
)
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin/ADFile.ps1')

class Target {
    $URL
    $Config
    $Agent
    $Protocol
    $Session
    $Collection
    hidden static [object]$TlsGate=[object]::new()

    Target([hashtable]$value,[hashtable]$item) {
        $this.URL=@{};if($null -ne $value){foreach($key in $value.Keys){$this.URL[$key]=$value[$key]}}
        $this.Config=@{limit=60;wait=30;RequestTimeoutSeconds=30}
        if($null -ne $item){foreach($key in $item.Keys){$this.Config[$key]=$item[$key]}}
        $this.Config.limit=[Target]::ReadInteger($this.Config.limit,'limit',1,[int]::MaxValue)
        $this.Config.wait=[Target]::ReadInteger($this.Config.wait,'wait',0,[int]::MaxValue)
        $this.Config.RequestTimeoutSeconds=[Target]::ReadInteger($this.Config.RequestTimeoutSeconds,'RequestTimeoutSeconds',1,300)
        $this.Agent=[Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
        $this.Protocol=[Net.SecurityProtocolType]::Tls12
        $this.Session=[Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $this.Collection=[Collection]::new()
    }
    static [int]ReadInteger($value,[string]$name,[int]$minimum,[int]$maximum) {
        $number=0
        if(-not [int]::TryParse([string]$value,[Globalization.NumberStyles]::Integer,[Globalization.CultureInfo]::InvariantCulture,[ref]$number) -or $number -lt $minimum -or $number -gt $maximum){throw ('Invalid SAML configuration field: '+$name)}
        return $number
    }
    static [string]HttpsUrl($value) {
        $uri=$null
        if($value -is [Uri]){$uri=$value}
        elseif($value -isnot [string] -or -not [Uri]::TryCreate($value,[UriKind]::Absolute,[ref]$uri)){throw 'SAML endpoints require absolute HTTPS URLs without user information.'}
        if(-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo){throw 'SAML endpoints require absolute HTTPS URLs without user information.'}
        return $uri.AbsoluteUri
    }
    [object]Request([string]$command,[hashtable]$arguments) {
        if($command -notin @('Invoke-RestMethod','Invoke-WebRequest')){throw 'Unsupported SAML request command.'}
        $parameters=@{}+$arguments
        $parameters.WebSession=$this.Session;$parameters.UserAgent=$this.Agent;$parameters.UseBasicParsing=$true
        $parameters.ErrorAction='Stop';$parameters.TimeoutSec=$this.Config.RequestTimeoutSeconds
        $native=Get-Command -Name $command -CommandType Cmdlet -Module Microsoft.PowerShell.Utility -ErrorAction Stop
        if($native.Parameters.ContainsKey('OperationTimeoutSeconds')){$parameters.OperationTimeoutSeconds=$this.Config.RequestTimeoutSeconds}
        if($native.Parameters.ContainsKey('SslProtocol')){
            $parameters.SslProtocol='Tls12'
            return (& $command @parameters)
        }
        # Windows PowerShell lacks per-request SslProtocol. Cooperating requests serialize this temporary process setting.
        $taken=$false;$changed=$false;$previous=$null;$failure=$null;$result=$null
        try {
            [Threading.Monitor]::Enter([Target]::TlsGate,[ref]$taken)
            $previous=[Net.ServicePointManager]::SecurityProtocol
            [Net.ServicePointManager]::SecurityProtocol=$this.Protocol;$changed=$true
            $result=& $command @parameters
        } catch {$failure=$_}
        finally {
            if($changed){
                try{[Net.ServicePointManager]::SecurityProtocol=$previous}
                catch{if($null -ne $failure){$failure.Exception.Data['ADAnalyzerCleanupErrors']=@($_.Exception.Message)}else{$failure=$_}}
            }
            if($taken){[Threading.Monitor]::Exit([Target]::TlsGate)}
        }
        if($null -ne $failure){throw $failure}
        return $result
    }
    static [hashtable]ReadSamlForm([string]$html) {
        if([string]::IsNullOrEmpty($html)){throw 'SAML response form is missing.'}
        $options=[Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
        $tagPattern='<!--(?:[\s\S]*?-->|[\s\S]*$)|<!\[CDATA\[(?:[\s\S]*?\]\]>|[\s\S]*$)|<[!?](?:[^''"<>]|"[^"]*"|''[^'']*'')*>|<(?<close>/)?(?<tag>[A-Za-z][A-Za-z0-9:-]*)(?=[ \t\r\n\f/>])(?<attrs>(?:[^''"<>]|"[^"]*"|''[^'']*'')*)>'
        $attributePattern='\G[ \t\r\n\f]*(?<key>[^ \t\r\n\f=/"''<>]+)(?:[ \t\r\n\f]*=[ \t\r\n\f]*(?:"(?<dq>[^"]*)"|''(?<sq>[^'']*)''|(?<uq>[^ \t\r\n\f"''<>]+)))?'
        $tags=[regex]::new('\G(?:'+$tagPattern+')',$options,[timespan]::FromSeconds(2))
        $attributes=[regex]::new($attributePattern,$options,[timespan]::FromSeconds(2))
        $raw='';$rawClosing=$null;$fields=@{};$cursor=0
        while($cursor -lt $html.Length){
            if($raw){
                if($raw -eq 'plaintext'){break}
                $end=$rawClosing.Match($html,$cursor)
                if(-not $end.Success){break}
                if($raw -eq 'script' -and $html.Substring($cursor,$end.Index-$cursor).Contains('<!--')){throw 'Unsupported escaped script markup in SAML form.'}
                $closingTag=$tags.Match($html,$end.Index)
                if(-not $closingTag.Success -or $closingTag.Index -ne $end.Index){throw 'Malformed raw-text closing tag in SAML form.'}
                $cursor=$closingTag.Index+$closingTag.Length;$raw='';continue
            }
            $opening=$html.IndexOf('<',$cursor)
            if($opening -lt 0){break}
            $tag=$tags.Match($html,$opening)
            if(-not $tag.Success -or $tag.Index -ne $opening){
                if(-not $raw -and $opening+1 -lt $html.Length -and [string]$html[$opening+1] -match '[A-Za-z!/?]'){throw 'Malformed markup in SAML form.'}
                $cursor=$opening+1;continue
            }
            $cursor=$tag.Index+$tag.Length
            if(-not $tag.Groups['tag'].Success){continue}
            $name=$tag.Groups['tag'].Value.ToLowerInvariant();$closing=$tag.Groups['close'].Success
            if($closing){continue}
            if($name -eq 'template'){throw 'Unsupported template markup in SAML form.'}
            if($name -in @('script','style','textarea','title','xmp','iframe','noembed','noframes','plaintext')){
                $raw=$name;$rawClosing=[regex]::new('</'+[regex]::Escape($raw)+'(?=[ \t\r\n\f/>])',$options,[timespan]::FromSeconds(2));continue
            }
            if($name -ne 'input'){continue}
            $text=$tag.Groups['attrs'].Value;$position=0;$values=@{}
            while($position -lt $text.Length){
                if($text.Substring($position).Trim([char[]]@(32,9,13,10,12)) -in @('','/')){break}
                $attribute=$attributes.Match($text,$position)
                if(-not $attribute.Success -or $attribute.Index -ne $position){throw 'Malformed SAML form attributes.'}
                $position=$attribute.Index+$attribute.Length
                $key=$attribute.Groups['key'].Value.ToLowerInvariant()
                $content=if($attribute.Groups['dq'].Success){$attribute.Groups['dq'].Value}elseif($attribute.Groups['sq'].Success){$attribute.Groups['sq'].Value}else{$attribute.Groups['uq'].Value}
                if([string]::Equals($key,'name',[StringComparison]::Ordinal) -or [string]::Equals($key,'value',[StringComparison]::Ordinal)){
                    if($values.ContainsKey($key)){throw 'Duplicate name/value attribute in SAML form.'}
                    $values[$key]=[Net.WebUtility]::HtmlDecode($content)
                }
            }
            $field=[string]$values['name']
            if(-not [string]::Equals($field,'SAMLResponse',[StringComparison]::Ordinal) -and -not [string]::Equals($field,'RelayState',[StringComparison]::Ordinal)){continue}
            if($fields.ContainsKey($field)){throw 'Duplicate SAML form field.'}
            if(-not $values.ContainsKey('value')){throw 'Missing SAML form field value.'}
            $fields[$field]=[string]$values['value']
        }
        if(-not $fields.ContainsKey('SAMLResponse') -or [string]::IsNullOrWhiteSpace($fields.SAMLResponse)){throw 'Exactly one nonempty SAMLResponse field is required.'}
        return $fields
    }
    static [Target]Initialize([hashtable]$url,[hashtable]$config) {
        return [Target]::Initialize($url,$config,[pscredential]::Empty)
    }
    static [Target]Initialize([hashtable]$url,[hashtable]$config,[pscredential]$credential) {
        $target=[Target]::new($url,$config)
        try {
            foreach($key in @('auth','logn','saml','appl')){$target.URL[$key]=[Target]::HttpsUrl($target.URL[$key])}
            $c=$credential
            if($null -eq $c -or $c -eq [pscredential]::Empty){
                if($target.Config.ContainsKey('user') -and -not [string]::IsNullOrWhiteSpace([string]$target.Config.user)){$c=Get-Credential -Message 'Enter your SSO credentials' -UserName $target.Config.user}
                else{$c=Get-Credential -Message 'Enter your SSO credentials'}
            }
            if($null -eq $c -or $c -eq [pscredential]::Empty){throw 'SSO credentials are required.'}
            $body=@{username=$c.UserName;password=$c.GetNetworkCredential().Password} | ConvertTo-Json -Compress
            $auth=$target.Request('Invoke-RestMethod',@{Uri=$target.URL.auth;Method='POST';ContentType='application/json';Body=$body})
            if($auth.Status -isnot [string] -or $auth.Status -ne 'SUCCESS' -or $auth.SessionToken -isnot [string] -or [string]::IsNullOrWhiteSpace($auth.SessionToken)){throw 'Authentication did not return a successful scalar session token.'}
            $page=$target.Request('Invoke-WebRequest',@{Uri=$target.URL.logn;Method='POST';ContentType='application/x-www-form-urlencoded';Body=@{token=$auth.SessionToken;redirectUrl=$target.URL.saml}})
            $form=[Target]::ReadSamlForm([string]$page.Content)
            $null=$target.Request('Invoke-WebRequest',@{Uri=$target.URL.appl;Method='POST';ContentType='application/x-www-form-urlencoded';Body=$form})
            return $target
        } catch {
            $failure=$_
            if($target.Session -is [IDisposable]){try{$target.Session.Dispose()}catch{$failure.Exception.Data['ADAnalyzerCleanupErrors']=@($_.Exception.Message)}}
            throw $failure
        }
    }
    [void]Analyze([string]$string) {
        $endpoint=[Target]::HttpsUrl($string)
        for($count=1;$count -le $this.Config.limit;$count++){
            $watch=[Diagnostics.Stopwatch]::StartNew()
            $response=$null
            try{$response=$this.Request('Invoke-RestMethod',@{Uri=$endpoint;Method='GET'})}
            finally{$watch.Stop()}
            $row=[ordered]@{iteration=$count;url=$string;status=$response.status;seconds=$watch.Elapsed.TotalSeconds;timestamp=(Get-Date -Format u)}
            $null=$this.Collection.Add([pscustomobject]$row)
            if($count -lt $this.Config.limit -and $this.Config.wait){Start-Sleep -Seconds $this.Config.wait}
        }
    }
    [void]Export([string]$value) {$this.Collection.Export($value)}
    [Collection]Report() {if($this.Collection.Count){return $this.Collection};return $null}
}
class Collection : ArrayList {
    Collection() : base() {}
    [void]Export([string]$value) {
        try {
            $content=if($this.Count){($this | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop) -join [Environment]::NewLine}else{'"iteration","url","status","seconds","timestamp"'}
            $null=Write-ADAnalyzerFile -Path $value -Content $content
        } catch {throw ('export({0})' -f $_.Exception.Message)}
    }
}
function Invoke-SAMLResponseTimeTest {
    [CmdletBinding()]
    param([hashtable]$Url,[hashtable]$Config,[pscredential]$Credential=[pscredential]::Empty,[string]$OutputPath)
    $ErrorActionPreference='Stop'
    $endpoint=[Target]::HttpsUrl($Url.data)
    $target=$null;$failure=$null;$rows=@()
    try{
        $target=[Target]::Initialize($Url,$Config,$Credential)
        $target.Analyze($endpoint)
        if($OutputPath){$target.Export($OutputPath)}
        $rows=@($target.Report())
    }catch{$failure=$_}
    finally{
        if($null -ne $target -and $target.Session -is [IDisposable]){
            try{$target.Session.Dispose()}catch{if($null -ne $failure){$failure.Exception.Data['ADAnalyzerCleanupErrors']=@($_.Exception.Message)}else{$failure=$_}}
        }
    }
    if($null -ne $failure){throw $failure}
    return $rows
}
if($MyInvocation.InvocationName -ne '.'){
    if([string]::IsNullOrWhiteSpace($CliConfigPath)){throw 'Specify ConfigPath containing Url and Config objects.'}
    $document=Get-Content -LiteralPath $CliConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $url=@{};$config=@{}
    foreach($property in $document.Url.PSObject.Properties){$url[$property.Name]=$property.Value}
    foreach($property in $document.Config.PSObject.Properties){$config[$property.Name]=$property.Value}
    Invoke-SAMLResponseTimeTest -Url $url -Config $config -Credential $CliCredential -OutputPath $CliOutputPath
}
