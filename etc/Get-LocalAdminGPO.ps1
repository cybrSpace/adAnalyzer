
using namespace System.Collections
using namespace System.Collections.Specialized

$var = @{

    'table'  = [ArrayList]::New()

    'gpo'    = @{

        'target'    = 'all'
        #'target' = 'TEST ADMIN GPO
        'config'    = @('computer', 'user')
        'filter'    = @('FilterBattery', 'FilterCollection', 'FilterComputer', 'FilterFile', 'FilterGroup', 'FilterOrgUnit', 'FilterRunOnce', 'FilterUser', 'FilterWMI')
        'extension' = @('Local Users and Groups', 'Security', 'Registry') # , 'Scripts', 'Software Installation', 'Folder Redirection', 'Internet Explorer Maintenance'

    }

    'export' = [String]('{0}\{1}.{2}.csv' -f '\\srv1.ad.cybr.pro\users$\allen\dev\repos\adeAnalyzer\etc\LocalAdminGPO', (Get-WmiObject -Class Win32_ComputerSystem).Domain, (Get-Date -f 'yyyy.MM.dd.HHmm'))

}

if ($var['gpo']['target'] -eq 'all') {

    $var['objects'] = Get-GPO -All

}
else {

    $var['objects'] = Get-GPO -Name $var['gpo']['target']

}
function Get-GPOConfig () {
    param ( $gpo, $xml, $config)

    function Get-GPOLink () {
        param ( $link, $domain )

        $r = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

        if (-not [String]::IsNullOrEmpty($link)) {

            foreach ($i in $link) {

                $r[($i.SOMPath.Replace($domain, ''))] = $i.Enabled

            }
            else {

                $r['nolink'] = $true

            }

        }

    }
    function Get-GPOLocalUsersAndGroupsConfig () {
        param ( [Alias('data')]$p )

        function Get-LocalUsersandGroupsFilter () {
            param ( $filter, $type )
            
            if ($type -eq 'FilterCollection') {

                $collection = [ArrayList]::New()

                switch ($filter.($type).PSObject.Properties.Name | Where-Object { $_ -in $var['gpo']['filter'] }) {

                    default {

                        $fCollection = Get-LocalUsersandGroupsFilter -filter $filter.($type) -type $_
                        $collection.Add($fCollection) > $null

                    }

                }

                $r = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

                return $r[$type] = $collection

            }
            elseif ($filter.($type).Count -gt 1) {

                $collection = [ArrayList]::New()

                foreach ($f in $filter.($type).GetEnumerator()) {

                    $fObject = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

                    $f.Attributes.GetEnumerator() | Where-Object { -not [String]::IsNullOrEmpty($_.Value) -and $_.Name -notin ('userContext', 'directMember', 'primaryGroup', 'localGroup', 'sid') } | ForEach-Object { $fObject[$_.Name] = $_.Value }

                    $collection.Add($fObject) > $null

                }

                $r = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

                $r[$type] = $collection

            }
            else {

                $fObject = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

                $f = $filter.($type)

                $f.Attributes.GetEnumerator() | Where-Object { -not [String]::IsNullOrEmpty($_.Value) -and $_.Name -notin ('userContext', 'directMember', 'primaryGroup', 'localGroup', 'sid') } | ForEach-Object { $fObject[$_.Name] = $_.Value }

                $r = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

                return $r[$type] = $fObject

            }

        }
        function Get-GPOLocalGroupsConfig () {

            $obj = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

            $object.GetEnumerator() | ForEach-Object { $obj[$_.Name] = $_.Value }

            $obj['ext.property.class'] = $pClass
            $obj['ext.property.type'] = ('Order: {0}' -f $o.GPOSettingOrder)

            if (-not [String]::IsNullOrEmpty($o.Disabled)) {

                switch ($o.Disabled) {

                    0 { $obj['ext.property.enabled'] = $true }
                    1 { $obj['ext.property.enabled'] = $false }
                    Default { $obj['ext.property.enabled'] = $true }

                }

            }
            else {

                $obj['ext.property.enabled'] = $true

            }

            $pArgs = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)
            
            $o.Properties.Attributes.GetEnumerator() | Where-Object { -not [String]::IsNullOrEmpty($_.Value) -and $_.Name -notin ('groupsid') } | ForEach-Object { $pArgs[$_.Name] = $_.Value }

            $obj['ext.property.arg'] = $pArgs | ConvertTo-Json

            $obj['ext.parameter.name'] = $o.Name
            $obj['ext.parameter.value'] = $null
            $obj['ext.parameter.arg'] = $null

            if (-not [String]::IsNullOrEmpty($o.Filters)) {

                $filters = [ArrayList]::New()

                switch ($o.Filters.PSObject.Properties.Name | Where-Object { $_ -in $var['gpo']['filter'] }) {

                    default {

                        $fCollection = Get-LocalUsersandGroupsFilter -filter $o.Filters -type $_
                        $filters.Add($fCollection) > $null

                    }

                } 

                $obj['ext.property.filter'] = $filters | ConvertTo-Json -Depth 25

            }

            if ([String]::IsNullOrEmpty($o.Properties.Members)) {

                $r = New-Object -TypeName PSCustomObject -Property $obj

                $var['table'].Add($r) > $null

            }
            else {

                foreach ($v in $o.Properties.Members.GetEnumerator()) {

                    $r = New-Object -TypeName PSCustomObject -Property $obj

                    $r.'ext.parameter.value' = $v.Name

                    $vArgs = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

                    $v.Attributes.GetEnumerator() | Where-Object { -not [String]::IsNullOrEmpty($_.Value) -and $_.Name -notin ('name', 'sid') } | ForEach-Object { $vArgs[$_.Name] = $_.Value }

                    $r.'ext.parameter.arg' = $vArgs | ConvertTo-Json

                    $var['table'].Add($r) > $null

                }

            }

        }
        function get-GPOLocalUserConfig () {

            $obj = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

            $object.GetEnumerator() | ForEach-Object { $obj[$_.Name] = $_.Value }

            $obj['ext.property.class'] = $pClass
            $obj['ext.property.type'] = ('Order: {0}' -f $o.GPOSettingOrder)

            if (-not [String]::IsNullOrEmpty($o.Disabled)) {

                switch ($o.Disabled) {

                    0 { $obj['ext.property.enabled'] = $true }
                    1 { $obj['ext.property.enabled'] = $false }
                    Default { $obj['ext.property.enabled'] = $true }

                }

            }
            else {

                $obj['ext.property.enabled'] = $true

            }

            $obj.'ext.parameter.name' = 'LocalUser'
            $obj.'ext.parameter.value' = $o.Properties.UserName

            $pArgs = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

            $o.Properties.Attributes.GetEnumerator() | Where-Object { -not [String]::IsNullOrEmpty($_.Value) } | ForEach-Object { $pArgs[$_.Name] = $_.Value }
            $obj['ext.property.arg'] = $pArgs | ConvertTo-Json

            if (-not [String]::IsNullOrEmpty($o.Filters)) {

                $filters = [ArrayList]::New()

                switch ($o.Filters.PSObject.Properties.Name | Where-Object { $_ -in $var['gpo']['filter'] }) {

                    default {

                        $fCollection = Get-LocalUsersandGroupsFilter -filter $o.Filters -type $_
                        $filters.Add($fCollection) > $null

                    }

                }

                $obj['ext.property.filter'] = $filters | ConvertTo-Json -Depth 25

            }

            $r = New-Object -TypeName PSCustomObject -Property $obj
            $var['table'].Add($r) > $null

        }

        switch ($p.PSObject.Properties.Name | Where-Object { $_ -in @('User', 'Group') }) {

            Default {

                $pClass = $_

                if ($p.($_).Count -gt 1) {

                    foreach ($o in $p.($_).GetEnumerator()) {

                        switch ($pClass) {

                            'User' { Get-GPOLocalUserConfig }
                            'Group' { Get-GPOLocalGroupsConfig }

                        }

                    }

                }
                else {

                    $o = $p.($_)

                    switch ($pClass) {

                        'User' { Get-GPOLocalUserConfig }
                        'Group' { Get-GPOLocalGroupsConfig }

                    }

                }

            }

        }
    }
    function Get-GPORestrictedGroupsConfig () {
        param ( [Alias('data')]$p )

        function Get-GPORestrictedGroupMember () {
            param ($type)

            $obj = [OrderedDictionary]::New([StringComparer]::OrdinalIgnoreCase)

            $object.GetEnumerator() | ForEach-Object { $obj[$_.Name] = $_.Value }

            $obj['ext.property.name'] = $pValue.LocalName
            $obj['ext.property.class'] = $m.LocalName
            $obj['ext.parameter.name'] = $pValue.GroupName.name.'#text'
            $obj['ext.parameter.value'] = $m.Name.'#text'

            $r = New-Object -TypeName PSCustomObject -Property $obj

            $var['table'].Add($r) > $null

        }

        foreach ($pValue in $p.GetEnumerator()) {

            switch ($pValue.PSObject.Properties.Name | Where-Object { $_ -in @('Member', 'MemberOf') }) {

                Default {

                    if ($pValue.($_).Count -gt 1) {

                        foreach ($m in $pValue.($_).GetEnumerator()) {

                            Get-GPORestrictedGroupMember -type $_

                        }

                    }
                    else {

                        $m = $pValue.($_)

                        Get-GPORestrictedGroupMember -type $_


                    }

                }

            }

        }

    }
    
    function Get-GPOLoopBackConfig () {
        param ( [Alias('config')]$v )

        $return = $null 

        if ($xml.GPO.($v).ExtensionData.Name -contains 'Registry' -and $xml.GPO.($v).ExtensionData.Extension.Policy.Name -contains 'Configure user Group Policy Loopback processing mode') {

            $lbPolicy = $xml.GPO.($v).ExtensionData.Extension.Policy | Where-Object { $_.Name -eq 'Configure user Group Policy Loopback processing mode' }

            $return = ('{0} ({1})' - $lbPolicy.DropDownList.State, $lbPolicy.DrownDownList.Value.Name)

        }

        return $return

    }
    function Get-GPORegistryPolicyConfig () {
        param ( [Alias('data')]$p)

        foreach ($pValue in $p.GetEnumerator()) {

            if ($pValue.Name -eq '') {


            }

        }

    }

    $object = [ordered]@{

        'gpo.name'             = $gpo.DisplayName
        'gpo.created'          = (Get-Date $gpo.CreationTime -f 'yyyy/MM/dd HH:mm')
        'gpo.modified'         = (Get-Date $gpo.ModificationTime -f 'yyyy/MM/dd HH:mm')
        'gpo.read'             = (Get-Date $xml.GPO.ReadTime -f 'yyyy/MM/dd HH:mm')
        'gpo.status'           = $gpo.Gpostatus
        'gpo.linked'           = $null
        'gpo.linked.ou'        = $null

        'cfg.class'            = $null
        'cfg.enabeld'          = $null
        'cfg.loopback'         = $null
        'cfg.extension'        = $null

        'ext.property.name'    = $null
        'ext.property.enabled' = $null
        'ext.property.class'   = $null

        'ext.parameter.name'   = $null
        'ext.parameter.value'  = $null
        'ext.parameter.arg'    = $null

        'ext.property.arg'     = $null
        'ext.property.filter'  = $null

    }

    $linkData = Get-GPOLink -link $xml.GPO.LinksTo -domain $gpo.DomainNamingMaster

    if ($linkData.nolink) {

        $object.'gpo.linked' = $false

    }
    else {

        $object.'gpo.linked' = $true
        $object.'gpo.linked.ou' = $linkData | ConvertTo-Json

    }

    $object['cfg.loopback'] = Get-GPOLoopBackConfig -config $config

    foreach ($eData in $xml.GPO.($config).ExtensionData) {

        $object['cfg.class'] = $config
        $object['cfg.enabled'] = $xml.GPO.($config).Enabled
        $object['cfg.extension'] = $eData.Name

        switch ($object['cfg.extension'] | Where-Object { $_ -in $var['gpo']['extension'] }) {

            'Local Users and Groups' { Get-GPOLocalUsersAndGroupsConfig -data $eData.Extension.LocalUsersAndGroups }
            'Registry' { 
                
                switch ($eData.Extension.PSObject.Properties.Name) {

                    'Policy' { Get-GPORegistryPolicyConfig -data $eData.Extension.Policy }

                }
            
            }
            'Security' { 
                
                switch ($eData.Extension.PSObject.Properties.Name) {

                    'RestrictedGroups' { Get-GPORestrictedGroupsConfig -data $eData.Extension.RestrictedGroups }

                }
            
            }

        }

    }

}

foreach ($gpObject in $var['objects']) {

    [xml]$xGPObj = Get-GPOReport -Name $gpObject.Id -ReportType Xml

    foreach ($cfg in $var['gpo']['config']) {

        Get-GPOConfig -gpo $gpObject -xml $xGPObj -config $cfg

    }

}

$var['table'] | Format-Table -Property * -AutoSize

if (Test-Path -Path $var['export']) {

    $var['export'] = $var['export'].Replace('.csv', ('.{0}.csv' -f (Get-Date -f 'ss')))

}

try {

    $var['table'] | Export-Csv -Path $var['export'] -NoTypeInformation -ErrorAction Stop
}
catch {

    throw ('{0}({1})' -f 'export', $_.Exception.Message)

}