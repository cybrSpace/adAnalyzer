$server = 'dc2.ad.cybr.pro'
$target = [adsi]('WinNT://{0},computer' -f $server)
$member = ($target.psbase.children.find('Administrators', 'Group')).psbase.invoke('Members') | ForEach-Object {

    $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)

}
$member