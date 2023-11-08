using namespace System.Collections
using namespace System.Collections.Specialized
using namespace System.Management.Automation

######################################################################################################################################################################################################################################################
#region Enumeration
######################################################################################################################################################################################################################################################

Enum Module {

    DLL = 1 # 'Windows AD Management DLLs (RSAT not required)
    PSM1 = 2 # 'ADEnvironment Management Modules

}

Enum Classes {

    User
    Group
    Computer
    GroupPolicy

}

Enum Finding {

    User
    Computer

}

Enum Tables{

    Data
    Report
    Finding

}

######################################################################################################################################################################################################################################################
#endregion Enumeration
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Classes
######################################################################################################################################################################################################################################################

class Config : Hashtable {

    Config() : base([StringComparer]::OrdinalIgnoreCase) { }

    #TODO : Update Config/Option logic to enable runtime input & commandline execution w/ prompting for parameterization

    static [Hashtable]$Parameters = @{

        'Operation' = 'report'
        #'Operation' = 'remediate'

        'whatIf'    = $false
        'confirm'   = $false

        #stop, inquire, continue, silentlycontinue
        'debug'     = 'continue'
        'info'      = 'continue'
        'warning'   = 'silentlycontinue'
        'verbose'   = 'silentlycontinue'
        'error'     = 'stop'

        'fqdn'      = 'ad.cybr.pro'
        'path'      = 'C:\Users\allen\OneDrive\Documents\dev\repos\adAnalyzer'

        'import'    = [Module].GetEnumNames()
        'report'    = [Classes].GetEnumNames()
        'remediate' = [Finding].GetEnumNames()

    }

    static [Config]$Options

    static [Hashtable]$Diagnostic = [Hashtable]@{

        'StopWatch' = [System.Diagnostics.StopWatch]::New()

    }
    static [ArrayList]$PSModules = [ArrayList]@(

        'Microsoft.Powershell.Management', 'Microsoft.Powershell.Security', 'Microsoft.Powershell.Utility', 
        'PowershellEditorServices.Commands', 'PowerShellEditorServices.VSCode', 'PSReadLine'

    )

    static [ArrayList]$PSVariables = [ArrayList]@(

        '$', '?', '^', 'args', 'ConfirmPreference', 'ConsoleFileName', 'DebugPreference', 'Error', 'ErrorActionPreference', 
        'ErrorView', 'ExecutionContext', 'FALSE', 'FormatEnumerationLimit', 'HOME', 'Host', 'InformationPreference', 
        'input', 'MaximumAliasCount', 'MaximumDriveCount', 'MaximumErrorCount', 'MaximumFunctionCount', 'MaximumHistoryCound', 
        'MaximumVariableCound', 'MyInvocation', 'NestedPromptedLevel', 'null', 'OutputEncoding', 'PID', 'profile', 
        'ProgressPreference', 'PSBoundParameters', 'PSCommandPath', 'PSCulture', 'PSDefaultParameterValues', 'PSEdition', 'psEditor', 
        'PSEmailServer', 'PSHOME', 'PSScriptRoot', 'PSSessionApplicationName', 'PSSessionConfigurationName', 
        'PSSessionOption', 'PSUICulture', 'PSVersionTable', 'PWD', 'ShellId', 'StackTrace', 'true', 'VerbosePreference',
        'WarningPreference', 'WhatIfPreference'

    )
    
    static [void]Clear() {

        Get-Module | Where-Object { $_.name -notin [Config]::PSModules } | Remove-Module -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false
        Get-Variable | Where-Object { $_.name -notin [Config]::PSVariables } | Remove-Variable -Force -ErrorAction SilentlyContinue -WhatIf:$false -Confirm:$false

        [System.GC]::Collect()

        $error.Clear()

    }

    static [void]Close() {

        [Config]::Diagnostic['StopWatch'].Stop()

        Write-Information -MessageData ''
        Write-Information -MessageData ('[ {0} ] {1} : {2}' -f '+', 'Runtime', ([string]::Format('{0:d2}:{1:d2}:{2:d2}', [Config]::Diagnostic['StopWatch'].Elapsed.Hours, [Config]::Diagnostic['StopWatch'].Elapsed.Minutes, [Config]::Diagnostic['StopWatch'].Elapsed.Seconds)))
        Write-Information -MessageData ''
        Write-Information -MessageData '###########################################################################################################################################################'
        Write-Information -MessageData ''

        [Config]::Diagnostic['StopWatch'] = $null
        [Config]::Options = $null

        Set-Location -Path ($env:USERPROFILE)

    }

    static [void]Banner() {

        Write-Information -MessageData ''
        Write-Information -MessageData '###########################################################################################################################################################'

        Set-Location -Path ($env:USERPROFILE)
        
        Get-Content -Path ('{0}\{1}\{2}' -f [Config]::Parameters['path'], 'etc', 'banner.txt') -Encoding 'bigendianunicode' | Out-String | Out-Host
        
        Write-Information -MessageData '###########################################################################################################################################################'
        Write-Information -MessageData ''        

    }

    static [void]Telemetry() {

        $Script:DebugPreference = [Config]::Parameters['Debug']
        $Script:VerbosePreference = [Config]::Parameters['Verbose']
        $Script:WarningPreference = [Config]::Parameters['Warning']
        $Script:InformationPreference = [Config]::Parameters['Info']
        $Script:ErrorActionPreference = [Config]::Parameters['Error']

    }

    static [void]Initialize() {

        [Config]::Diagnostic['StopWatch'] = [System.Diagnostics.Stopwatch]::StartNew()

        [Config]::Banner()

        $config = [Config]::New()

        $config.Path([Config]::Parameters['path'])
        $config.Library([Config]::Parameters['import'])

        [Config]::Parameters.Keys | Where-Object { $_ -notin $config.Keys } | ForEach-Object { $config[$_] = [Config]::Parameters[$_] }

        [Config]::Options = $config
        
        Write-Information -MessageData ('[ {0} ] {1} : {2}' -f '+', 'Start', (Get-Date -f 'MM.dd @ HH:mm.ss')) | Out-Host

    }

    [void]Path([String]$value) {

        $this['path'] = @{'root' = $value }

        If (Test-Path $value) {

            Get-ChildItem -Path $value -Directory | ForEach-Object { $this['path'][$_.Name] = $_.FullName }

        }
        else {

            throw ('error({0})' -f 'Invalid folder path')

        }

    }

    [void]Import([String]$value, [String]$item) {

        $list = Get-ChildItem -Path $value -File -ErrorAction Stop | Where-Object { $_.Extension -match ('({0})$' -f $item) }

        $list | ForEach-Object {

            try {

                Import-Module -Name $_.FullName -Force -ErrorAction Stop

            }
            catch { throw ('error({0}[{1}])' -f 'importingModule', $_.Exception.Message) }

        }

    }

    [void]Library([ArrayList]$value) {

        if ($this.ContainsKey('path') -and $this['path'].ContainsKey('lib')) {
            $value | ForEach-Object { $this.Import($this['path']['lib'], $_) }
        }
        if ($this.ContainsKey('path') -and $this['path'].ContainsKey('bin')) {
            $value | ForEach-Object { $this.Import($this['path']['bin'], $_) }
        }
        else { throw ('error({0})' -f 'path to module library undefined') }

    }

}
Class Target : Hashtable {

    Target() : base([StringComparer]::OrdinalIgnoreCase) { }

    static [Target]Report([ArrayList]$list) {

        $target = [Target]::New()

        $target['FQDN'] = [Config]::Options['FQDN']
        $target['Class'] = $list
        $target['Export'] = [Config]::Options['path']['tmp']

        $splat = @{          
            'analyze' = $list        
        }

        $target['Environment'] = Get-ADEnvironment @splat

        return $target

    }
    static [Target]Report([PSCredential]$item, [ArrayList]$list) {
        
        $target = [Target]::New()

        $target['FQDN'] = [Config]::Options['FQDN']
        $target['Class'] = $list
        $target['Export'] = [Config]::Options['path']['tmp']

        $splat = @{           
            'analyze'    = $list 
            'credential' = $item
        }

        $target['Environment'] = Get-ADEnvironment @splat
        
        return $target
        
    }
    static [Target]Report([String]$value, [PSCredential]$item, [ArrayList]$list) {
        
        $target = [Target]::New()

        $target['FQDN'] = [Config]::Options['FQDN']
        $target['Class'] = $list
        $target['Export'] = [Config]::Options['path']['tmp']

        $splat = @{ 
            'fqdn'       = $value
            'analyze'    = $list 
            'credential' = $item
        }

        $target['Environment'] = Get-ADEnvironment @splat
        
        return $target
        
    }

    static [Target]Remediate([ArrayList]$list) {

        $target = [Target]::New()

        $target['FQDN'] = [Config]::Options['FQDN']
        $target['Class'] = $list
        $target['Export'] = [Config]::Options['path']['tmp']

        $splat = @{  
            'remediate' = $list
            'whatif'    = [Config]::Options['whatIf']
            'confirm'   = [Config]::Options['confirm']        
        }

        $target['Environment'] = Set-ADEnvironment @splat
        
        return $target

    }
    static [Target]Remediate([PSCredential]$item, [ArrayList]$list) {

        $target = [Target]::New()

        $target['FQDN'] = [Config]::Options['FQDN']
        $target['Class'] = $list
        $target['Export'] = [Config]::Options['path']['tmp']

        $splat = @{           
            'remediate'  = $list
            'credential' = $item
            'whatif'     = [Config]::Options['whatIf']
            'confirm'    = [Config]::Options['confirm']    
        }

        $target['Environment'] = Set-ADEnvironment @splat
        
        return $target

    }
    static [Target]Remediate([String]$value, [PSCredential]$item, [ArrayList]$list) {

        $target = [Target]::New()

        $target['FQDN'] = [Config]::Options['FQDN']
        $target['Class'] = $list
        $target['Export'] = [Config]::Options['path']['tmp']

        $splat = @{ 
            'fqdn'       = $value
            'remediate'  = $list
            'credential' = $item
            'whatif'     = [Config]::Options['whatIf']
            'confirm'    = [Config]::Options['confirm']
        }

        $target['Environment'] = Set-ADEnvironment @splat
        
        return $target

    }

    [void]Export() {

        foreach ($obj in $this['Class']) {

            foreach ($item in [Tables].GetEnumNames()) {
            
                try {

                    $this.Environment.($obj).($item).ExportCSV(('{0}\{1}.{2}.{3}.csv' -f $this['export'], $this['FQDN'], $obj, $item))

                }
                catch { }
            
            }

        }

        $this.Environment.Finding.ExportCSV(('{0}\{1}.all.csv' -f $this['export'], $this['FQDN']))

    }

    [void]Summary() {

        Write-Information -MessageData ''

        foreach ($item in $this['Class']) {

            try {

                Write-Information -MessageData ('[ - ] {0}' -f $item.ToUpper()) -Tags 'ConsoleReport'

                $this['Environment'].($item).Finding | Group-Object -Property Finding -NoElement | Sort-Object Name | Format-Table -AutoSize | Out-Host

            }
            catch { }

        }

    }

}
######################################################################################################################################################################################################################################################
#endregion Classes
######################################################################################################################################################################################################################################################

######################################################################################################################################################################################################################################################
#region Execution
######################################################################################################################################################################################################################################################

function Start-ADAnalyzer () {

    [cmdletbinding(DefaultParameterSetName = 'Help', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (

        [Parameter(ParameterSetName = 'Help')]
        [Switch]$help,

        [Parameter(Mandatory = $true, ParameterSetName = 'Target')]
        [ValidateSet('report', 'remediate')]
        [String]$Operation,

        [Parameter(ParameterSetName = 'Target')]
        [ValidateScript(
            {
                if (Test-ComputerSecureChannel -Server $PSItem -WhatIf:$false -Confirm:$false) {
                    return $true
                }
                else {
                    return $false
                }
            }
        )]
        [String]$FQDN,

        [Parameter(ParameterSetName = 'Target')]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        [PSCredential]$Credential = [PSCredential]::Empty,

        [Alias('Analyze', 'Remediate', 'Report')]
        [Parameter(ParameterSetName = 'Target')]
        [ValidateSet('user', 'group', 'computer', 'groupPolicy')]
        [ArrayList]$Class = @('user', 'group', 'computer', 'groupPolicy')

    )

    try {

        $target = $null

        if ($Credential -ne [PSCredential]::Empty -and [String]::IsNullOrEmpty($FQDN)) {

            # NOTE : Get-GPO does not work with credential object
            # NOTE : credential is not a switch for the AD Management cmdlet

            if ($Class -contains 'groupPolicy') {

                $Class = $Class | Where-Object { $_ -notmatch 'groupPolicy' }

            }

            switch ($Operation) {

                'report' { $target = [Target]::Report($Credential, $Class) }
                'remediate' { $target = [Target]::Remediate($Credential, $Class) }

            }

        }
        elseif ($Credential -ne [PSCredential]::Empty -and -not [String]::IsNullOrEmpty($FQDN)) {

            # NOTE : Get-GPO does not work with credential object
            # NOTE : credential is not a switch for the AD Management cmdlet
            
            if ($Class -contains 'groupPolicy') {

                $Class = $Class | Where-Object { $_ -notmatch 'groupPolicy' }

            }

            switch ($Operation) {

                'report' { $target = [Target]::Report($FQDN, $Credential, $Class) }
                'remediate' { $target = [Target]::Remediate($FQDN, $Credential, $Class) }

            }

        }
        else {

            switch ($Operation) {

                'report' { $target = [Target]::Report($Class) }
                'remediate' { $target = [Target]::Remediate($Class) }

            }

        }

        return $target

    }
    catch {

        Write-Debug -Message ('{0} {1}({2})' -f '[ ! ]', 'exception', $_.Exception.Message)

    }
    finally {

        try {

            if ($null -ne $target) {

                $target.Export()
                $target.Summary()

            }

        }
        catch { }

    }

}

try {

    [Config]::Clear()
    [Config]::Telemetry()
    [Config]::Initialize()

    $splat = @{

        'FQDN'       = ([Config]::Options['FQDN'])
        'Operation'  = ([Config]::Options['Operation'])
        'Class'      = ([Classes].GetEnumNames())
        'Credential' = (Get-Credential)
    }

    $target = Start-ADAnalyzer @splat -WhatIf:([Config]::Options['whatIf']) -Confirm:([Config]::Options['confirm'])

}
catch {

    Write-Debug -Message ('{0} {1}({2})' -f '[ ! ]', 'uncaughtException', $_.Exception.Message)

}
finally {

    [Config]::Close()

}

######################################################################################################################################################################################################################################################
#endregion Execution
######################################################################################################################################################################################################################################################