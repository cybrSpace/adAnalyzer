[System.Reflection.Assembly]::LoadFrom('.\lib\Microsoft.ActiveDirectory.Management.dll') | Out-Null

$adUsers = Import-Csv -Path '.\tmp\import\createUserList.csv'

foreach ($user in $adUsers) {
    if (Get-ADUser -f { SamAccountName -eq $user.username }) {
        
        Write-Warning ('User {0} already exists' -f $user.username) -ForegroundColor Yellow
        continue
    }
    else {
        New-ADUser `
            -Name $user.name `
            -SamAccountName $user.username `
            -GivenName $user.givenName `
            -Surname $user.surname `
            -DisplayName $user.displayName `
            -Department $user.department `
            -EmployeeID $user.employeeID `
            -UserPrincipalName $user.userPrincipalName `
            -AccountPassword (ConvertTo-SecureString $user.password -AsPlainText -Force) `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -Path $user.path `
            -PassThru | Enable-ADAccount
    }
}