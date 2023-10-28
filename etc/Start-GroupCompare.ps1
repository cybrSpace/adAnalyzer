$group = @{
    0 = 'DL-Desktop-Support-Z' # domain local
    1 = 'GL-Desktop-Support-Z' # global
}
@(
    (Get-ADGroup $group[0] -pr member | Select-Object -ExpandProperty member) | Where-Object {
        $_ -notin (Get-ADGroup $group[1] -pr member | Select-Object -ExpandProperty member)
    } | ForEach-Object {

        (Get-ADObject $_ -Properties samaccountname).samaccountname
        
    }
) 