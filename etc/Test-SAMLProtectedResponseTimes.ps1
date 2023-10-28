using namespace System.Collections
using namespace System.Collections.Specialized

$var = @{

    'config' = @{
        'limit'  = 60
        'wait'   = 30

        'user'   = 'sa-alipa'

        'export' = ('{0}\{1}{2}.{3}.csv' -f $env:USERPROFILE, '.\tmp', 'SAML.ResponseTimes', (Get-Date -Format 'yyyyMMdd.HHmm'))
    }

    'url'    = @{

        'auth' = 'https://sso.cybr.pro/api/v1/authn'
        'appl' = 'https://application.cybr.pro/'
        'logn' = 'https://sso.cybr.pro/login/sessionCookieRedirect'
        'saml' = 'https://sso.cybr.pro/home/cybrPro_application/Q9MbXIkB7fwS1l8JptYC/S7vox6BFDqMsfmyEueZ0'

        'data' = 'https://application.cybr.pro/rest/requestAccess/'

    }

}

class Target {

    $URL
    $Config
    $Agent
    $Protocol
    $Session
    $Collection

    Target([Hashtable]$value, [Hashtable]$item) {

        $this.URL = $value
        $this.Config = $item
        $this.Agent = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
        $this.Protocol = [System.Net.SecurityProtocolType]::Tls12
        $this.Session = [Microsoft.PowerShell.Commands.WebRequestSession]::New()
        $this.Collection = [Collection]::New

    }

    static [Target]Initialize([HashTable]$url, [HashTable]$config) {

        $target = [Target]::New($url, $config)

        try {

            [Net.ServicePointManager]::SecurityProtocol = $target.Protocol

            if (-not $target.Config.ContainsKey('user')) {

                $c = Get-Credential -Message 'Enter your SSO credentials' 

            }
            else {

                $c = Get-Credential -Message 'Enter your SSO credentials' -UserName $target.Config['user'] 

            }

            $param = @{

                username = $c.UserName
                password = $c.GetNetworkCredential().Password

            } | ConvertTo-Json

            $r = Invoke-RestMethod -Uri $target.URL['auth'] -Method POST -ContentType 'application/json' -WebSession $target.Session -Body $param -UseBasicParsing -UserAgent $target.Agent -ErrorAction Stop
            
            if ($r.Status -eq 'SUCCESS') {

                $param = @{

                    'token'       = $r.SessionToken
                    'redirectUrl' = $target.URL['saml']

                }
                
                $r = Invoke-RestMethod -Uri $target.URL['logn'] -Method POST -WebSession $target.Session -Body $param -UseBasicParsing -UserAgent $target.Agent 

                $string = $r.InputFields | Where-Object { Name -EQ 'SAMLResponse' } | Select-Object -ExpandProperty Value

                $param = @{

                    'SAMLResponse' = $string.Replace('&#x2b;', '+').Replace('&#x3d;', '=')

                }

                try {

                    $r = Invoke-WebRequest -Uri $target.URL['appl'] -Method POST -WebSession $target.Session -Body $param -UseBasicParsing -UserAgent $target.Agent

                }
                catch { <# TODO: resolve issue where webrequest throws 405 error on initial post #> }

                $r = Invoke-WebRequest -Uri $target.URL['appl'] -Method POST -WebSession $target.Session -Body $param -UseBasicParsing -UserAgent $target.Agent

            }
            else {

                throw 'invalid authn api status'

            }

        }
        catch {

            throw 'authenticate_failed({0})' -f $_.Exception.Message

        }

        return $target

    }
    [void]Analyze([String]$string) {

        $count = 1

        do {

            $r = $null

            $time = Measure-Command -Expression {

                $r = Invoke-RestMethod -Uri $string -Method GET -WebSession $this.Session -UseBasicParsing -UserAgent $this.Agent

            }

            $object = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

            $object['iteration'] = $count
            $object['url'] = $string
            $object['status'] = $r.status
            $object['seconds'] = $time.TotalSeconds
            $object['timestamp'] = Get-Date -Format u

            [void]$this.Collection.Add([PSCustomObject]$object)

            $count++

            Start-Sleep -Seconds $this.Config['wait']

        } while ($count -le $this.Config['limit'])

    }
    [void]Export([String]$value) {

        if ($this.Collection.Count -gt 0) {

            $this.Collection.Export($value)

        }

    }
    [Collection]Report() {

        if ($this.Collection.Count -gt 0) {

            return $this.Collection

        }
        else {

            return $null

        }

    }

}
class Collection : ArrayList {

    Collection() : base () { }

    [void]Export([String]$value) {

        try {

            if (Test-Path $value) {
                
                Remove-Item $value -Force -ErrorAction Stop

            }

        }
        catch {

            $value = $value -replace '.csv', ('.{0}.csv' -f (Get-Date -Format 'ss'))

        }

        try {

            if ($this.Count -gt 0) {

                $this | Export-Csv -Path $value -NoTypeInformation

            }

        }
        catch {

            throw ('{0}({1})' -f 'export', $_.Exception.Message)

        }

    }

}

try {

    Write-Host ''
    Write-Host '[ + ] Start' -ForegroundColor Yellow -NoNewline; Write-Host ': ' `t (Get-Date -f 'MM.dd @ HH:mm')

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $target = [Target]::Initialize($var['url'], $var['config'])

    $target.Analyze($target.URL['data'])

    try {

        $target.Report() | Format-Table -AutoSize

        $target.Export($target.Config['export'])

    }
    catch {

        $_.Exception.Message

    }

}
catch {

    throw ('{0}({1})' -f 'error', $_.Exception.Message) 

    Write-Host ''
    Write-Host ('{0} {1}' -f '[ ! ]', 'Uncaught Exception') -ForegroundColor Yellow -NoNewline
    Write-Host $_.Exception.Message
    Write-Host ''

}
finally {

    $sw.Stop()
    Write-Host '[ + ] Runtime' -ForegroundColor Yellow -NoNewline
    Write-Host ':  ' $([String]::Format('{0:d2}:{1:d2}:{2:d2}', $sw.Elapsed.Hours, $sw.Elapsed.Minutes, $sw.Elapsed.Seconds))
    Write-Host ''

}
