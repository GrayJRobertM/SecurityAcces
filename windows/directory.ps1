# Runs under the delegated Windows service identity; passwords arrive only on stdin.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    Import-Module ActiveDirectory
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $server = [string]$request.server
    $ou = [string]$request.ou
    $base = Get-ADOrganizationalUnit -Identity $ou -Server $server
    $common = @{ Server = $server; ErrorAction = 'Stop' }
    switch ($request.action) {
        'list' {
            $items = @(Get-ADUser -Filter * -SearchBase $base.DistinguishedName -SearchScope Subtree -Properties DisplayName,Department,Enabled,LockedOut @common | ForEach-Object {
                @{ id=$_.ObjectGUID.ToString(); name=$(if ($_.DisplayName) {$_.DisplayName} else {$_.Name}); username=$_.SamAccountName; department=$_.Department; upn=$_.UserPrincipalName; enabled=$_.Enabled; locked=$_.LockedOut }
            })
            $data = $items
        }
        'create' {
            if ([string]$request.username -notmatch '^[a-zA-Z0-9._-]{1,20}$' -or -not $request.upnSuffix) { throw 'Invalid configuration' }
            $secure = ConvertTo-SecureString -String $request.password -AsPlainText -Force
            $user = New-ADUser -Name $request.name -DisplayName $request.name -SamAccountName $request.username -UserPrincipalName "$($request.username)@$($request.upnSuffix)" -Department $request.department -Path $base.DistinguishedName -AccountPassword $secure -ChangePasswordAtLogon $true -Enabled $true -PassThru @common
            $data = @{ id=$user.ObjectGUID.ToString() }
        }
        { $_ -in 'reset','enable','disable','unlock' } {
            $user = Get-ADUser -Identity ([Guid]$request.identifier) -Properties adminCount @common
            # Resolve GUID first, then restrict actions to the configured OU subtree.
            if (-not $user.DistinguishedName.EndsWith(','+$base.DistinguishedName,[StringComparison]::OrdinalIgnoreCase) -or $user.adminCount -eq 1) { throw 'Outside delegated scope' }
            switch ($request.action) {
                'reset' {
                    $secure = ConvertTo-SecureString -String $request.password -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user -Reset -NewPassword $secure @common
                    Set-ADUser -Identity $user -ChangePasswordAtLogon $true @common
                }
                'enable' { Enable-ADAccount -Identity $user @common }
                'disable' { Disable-ADAccount -Identity $user @common }
                'unlock' { Unlock-ADAccount -Identity $user @common }
            }
            $data = @{ id=$user.ObjectGUID.ToString() }
        }
        default { throw 'Unsupported action' }
    }
    @{ ok=$true; data=$data } | ConvertTo-Json -Depth 6 -Compress
} catch {
    # Avoid transmitting raw exceptions that may contain submitted credentials.
    @{ ok=$false; error='AD_OPERATION_FAILED' } | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($secure) { $secure.Dispose() }
    $request = $null
}
