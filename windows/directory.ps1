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
    function Get-ScopedUser($identifier) {
        $found=Get-ADUser -Identity ([Guid]$identifier) -Properties adminCount,AccountExpirationDate @common
        if (-not $found.DistinguishedName.EndsWith(','+$base.DistinguishedName,[StringComparison]::OrdinalIgnoreCase) -or $found.adminCount -eq 1) { throw 'Outside delegated scope' }
        return $found
    }
    function Expiry-Result($user) {
        $expires=$null
        if($user.AccountExpirationDate){$expires=[DateTimeOffset]::new($user.AccountExpirationDate.ToUniversalTime()).ToUnixTimeSeconds()}
        return @{id=$user.ObjectGUID.ToString();username=$user.SamAccountName;enabled=[bool]$user.Enabled;expires_at=$expires}
    }
    function Read-PasswordStamp($user) {
        try {
            $meta=Get-ADReplicationAttributeMetadata -Object $user.DistinguishedName -Server $server -Properties pwdLastSet -ErrorAction Stop | Select-Object -First 1
            if (-not $meta.Version -or -not $meta.LastOriginatingChangeUsn -or -not $meta.LastOriginatingChangeDirectoryServerInvocationId) { return '' }
            return "$($meta.Version):$($meta.LastOriginatingChangeUsn):$($meta.LastOriginatingChangeDirectoryServerInvocationId)"
        } catch { return '' }
    }
    function Password-Result($user) {
        $domainGuid=''
        try {$domainGuid=(Get-ADDomain @common).ObjectGUID.ToString()} catch {}
        return @{id=$user.ObjectGUID.ToString();username=$user.SamAccountName;domain_guid=$domainGuid;stamp=(Read-PasswordStamp $user)}
    }
    . ([IO.Path]::Combine($PSScriptRoot,'department-groups.ps1'))
    switch ($request.action) {
        'list' {
            $items = @(Get-ADUser -Filter * -SearchBase $base.DistinguishedName -SearchScope Subtree -Properties DisplayName,Department,Enabled,LockedOut,adminCount,AccountExpirationDate @common | ForEach-Object {
                @{ id=$_.ObjectGUID.ToString(); name=$(if ($_.DisplayName) {$_.DisplayName} else {$_.Name}); username=$_.SamAccountName; department=$_.Department; upn=$_.UserPrincipalName; enabled=$_.Enabled; locked=$_.LockedOut; protected=($_.adminCount -eq 1);windows_expires_at=$(if($_.AccountExpirationDate){[DateTimeOffset]::new($_.AccountExpirationDate.ToUniversalTime()).ToUnixTimeSeconds()}else{$null}) }
            })
            $data = $items
        }
        'create' {
            if ([string]$request.username -notmatch '^[a-zA-Z0-9._-]{1,20}$' -or -not $request.upnSuffix) { throw 'Invalid configuration' }
            $secure = ConvertTo-SecureString -String $request.password -AsPlainText -Force
            $enabled=if ($request.PSObject.Properties.Name -contains 'enabled') {[bool]$request.enabled} else {$true}
            $attributes=@{Name=$request.name;DisplayName=$request.name;SamAccountName=$request.username;UserPrincipalName="$($request.username)@$($request.upnSuffix)";Path=$base.DistinguishedName;AccountPassword=$secure;ChangePasswordAtLogon=$true;Enabled=$enabled;PassThru=$true}
            if ($request.department) {$attributes.Department=$request.department}
            $null=Department-Group ([string]$request.department)
            $user=New-ADUser @attributes @common
            $data=Password-Result $user
            try {$data.department_group=Set-DepartmentMembership $user '' ([string]$request.department)} catch {$data.warning='La cuenta se creó, pero no se pudo asignar el grupo del departamento. Conserva la contraseña y vuelve a guardar el departamento.'}
        }
        {$_ -in 'expiry-info','expiry-set','expiry-disable'} {
            $user=Get-ScopedUser $request.identifier
            if($request.action -eq 'expiry-set') {
                if($null -eq $request.expires_at) {Clear-ADAccountExpiration -Identity $user @common}
                else {
                    $deadline=[DateTimeOffset]::Parse([string]$request.expires_at,[Globalization.CultureInfo]::InvariantCulture)
                    Set-ADAccountExpiration -Identity $user -DateTime $deadline.UtcDateTime @common
                }
                $user=Get-ScopedUser $request.identifier
            }
            $data=Expiry-Result $user
            if($request.action -eq 'expiry-disable') {
                if($null -eq $data.expires_at -or $data.expires_at -ne [long]$request.expected_at) {$data.conflict=$true}
                else {
                    if([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $data.expires_at){throw 'Deadline not reached'}
                    $changed=[bool]$user.Enabled
                    if($changed){Disable-ADAccount -Identity $user @common}
                    $data=Expiry-Result (Get-ScopedUser $request.identifier)
                    $data.changed=$changed
                }
            }
        }
        'stamps' {
            $domain=Get-ADDomain @common
            $items=@()
            foreach ($identifier in @($request.identifiers)) {
                try {$user=Get-ScopedUser $identifier;$items+=@{id=$user.ObjectGUID.ToString();stamp=(Read-PasswordStamp $user)}}
                catch {$items+=@{id=[string]$identifier;stamp=''}}
            }
            $data=@{domain_guid=$domain.ObjectGUID.ToString();users=@($items)}
        }
        { $_ -in 'reset','enable','disable','unlock','update','department' } {
            $user = Get-ADUser -Identity ([Guid]$request.identifier) -Properties adminCount,Department @common
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
                'department' {
                    $group=Set-DepartmentMembership $user ([string]$user.Department) ([string]$request.department)
                    if ($request.department) {Set-ADUser -Identity $user -Department $request.department @common}
                    else {Set-ADUser -Identity $user -Clear Department @common}
                }
                'update' {
                    $group=Set-DepartmentMembership $user ([string]$user.Department) ([string]$request.department)
                    Set-ADUser -Identity $user -DisplayName $request.name @common
                    if ($request.department) {Set-ADUser -Identity $user -Department $request.department @common}
                    else {Set-ADUser -Identity $user -Clear Department @common}
                    if ($request.enabled) {Enable-ADAccount -Identity $user @common} else {Disable-ADAccount -Identity $user @common}
                }
            }
            $data=if ($request.action -eq 'reset') {Password-Result $user} else {@{id=$user.ObjectGUID.ToString()}}
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
