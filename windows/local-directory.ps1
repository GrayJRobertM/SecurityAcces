# Local SAM only; secrets arrive over stdin and never appear in process arguments.
# No remote host, group elevation, deletion or domain-controller SAM operations are supported.
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
    # Windows PowerShell Utility/Management are built-in snap-ins, not module manifests.
    # Search standard modules first without changing machine/user environment settings.
    $env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')+';'+$env:PSModulePath
    Import-Module CimCmdlets -ErrorAction Stop
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $os=Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -ne 3) { throw 'Requires member or standalone Windows Server' }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $elevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $reading=$request.action -in 'list','inventory'
    if (-not $elevated -and -not $reading) { throw 'Elevation required' }
    $machineGuid=[string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    $scope='local:'+$machineGuid.ToLowerInvariant()
    # Listing is independent of group-name resolution. Unverifiable rights stay read-only.
    $admins=@();$adminsVerified=$false
    try {
        $admins=@(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544') -ErrorAction Stop | ForEach-Object {$_.SID.Value})
        $adminsVerified=$true
    } catch {
        if (-not $reading) {throw 'Administrator membership unavailable'}
    }
    function SecurePassword($plain) {
        $value=[Security.SecureString]::new()
        foreach ($character in ([string]$plain).ToCharArray()) {$value.AppendChar($character)}
        $value.MakeReadOnly()
        return $value
    }
    function Protected($user) {
        $rid=[long]($user.SID.Value.Split('-')[-1])
        return (-not $elevated -or -not $adminsVerified -or $rid -lt 1000 -or $user.SID.Value -eq $identity.User.Value -or $admins -contains $user.SID.Value -or [string]$user.PrincipalSource -ne 'Local')
    }
    function Scoped($identifier) {
        if ([string]$identifier -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid local identifier' }
        $user=Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]$identifier) -ErrorAction Stop
        if (Protected $user) { throw 'Protected account' }
        return $user
    }
    function Stamp($user) {
        if (-not $user.PasswordLastSet) {return ''}
        return [string]$user.PasswordLastSet.ToFileTimeUtc()
    }
    function PasswordResult($user) {
        $user=Get-LocalUser -SID $user.SID
        return @{id=$user.SID.Value;username=$user.Name;domain_guid=$scope;stamp=(Stamp $user)}
    }
    function UserObject($user) { return [ADSI]("WinNT://"+$env:COMPUTERNAME+'/'+$user.Name+',user') }
    $stage='dispatch'
    switch ($request.action) {
        'check' { $data=@{local=$true;computer=$env:COMPUTERNAME;scope=$scope} }
        {$_ -in 'list','inventory'} {
            $items=@(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                # Keep the account reference stable if an optional ADSI lookup throws.
                $localUser=$_
                $locked=$false
                try {$locked=[bool](UserObject $localUser).InvokeGet('IsAccountLocked')} catch {}
                @{id=$localUser.SID.Value;name=$(if ($localUser.FullName) {$localUser.FullName} else {$localUser.Name});username=$localUser.Name;department=[string]$localUser.Description;upn=($env:COMPUTERNAME+'\'+$localUser.Name);enabled=$localUser.Enabled;locked=$locked;protected=(Protected $localUser)}
            })
            if ($request.action -eq 'inventory') {
                $warnings=@()
                if (-not $elevated) {$warnings+='Abre Metakampo como administrador para realizar cambios. La lectura de cuentas sigue disponible.'}
                if (-not $adminsVerified) {$warnings+='Windows no pudo verificar el grupo Administradores. Se muestran todas las cuentas en modo de solo lectura.'}
                $data=@{users=@($items);source='windows-local';computer=$env:COMPUTERNAME;read_only=(-not $elevated -or -not $adminsVerified);warnings=@($warnings)}
            } else {$data=@($items)}
        }
        'stamps' {
            $items=@()
            foreach ($identifier in @($request.identifiers)) {
                try {$user=Scoped $identifier;$items+=@{id=$user.SID.Value;stamp=(Stamp $user)}}
                catch {$items+=@{id=[string]$identifier;stamp=''}}
            }
            $data=@{domain_guid=$scope;users=@($items)}
        }
        'create' {
            if ([string]$request.username -notmatch '^[a-zA-Z0-9._-]{1,20}$' -or [string]$request.username -match '\.$' -or [string]$request.username -in '.','..') {throw 'Invalid username'}
            $secure=SecurePassword $request.password
            $enabled=if ($request.PSObject.Properties.Name -contains 'enabled') {[bool]$request.enabled} else {$true}
            $stage='create'
            $user=New-LocalUser -Name $request.username -FullName $request.name -Description ([string]$request.department) -Password $secure -Disabled:(-not $enabled) -ErrorAction Stop
            # Standard Users membership only; RDP rights remain controlled by Windows policy.
            $stage='group'
            Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-545') -Member $user -ErrorAction Stop
            $stage='password-stamp'
            $data=PasswordResult $user
        }
        {$_ -in 'reset','enable','disable','unlock','update'} {
            $user=Scoped $request.identifier
            $stage='modify'
            switch ($request.action) {
                'reset' {$secure=SecurePassword $request.password;Set-LocalUser -SID $user.SID -Password $secure -ErrorAction Stop}
                'enable' {Enable-LocalUser -SID $user.SID -ErrorAction Stop}
                'disable' {Disable-LocalUser -SID $user.SID -ErrorAction Stop}
                'unlock' {$entry=UserObject $user;$entry.InvokeSet('IsAccountLocked',$false);$entry.CommitChanges()}
                'update' {
                    Set-LocalUser -SID $user.SID -FullName $request.name -Description ([string]$request.department) -ErrorAction Stop
                    if ($request.enabled) {Enable-LocalUser -SID $user.SID} else {Disable-LocalUser -SID $user.SID}
                }
            }
            $data=if ($request.action -eq 'reset') {PasswordResult $user} else {@{id=$user.SID.Value}}
        }
        default {throw 'Unsupported action'}
    }
    @{ok=$true;data=$data} | ConvertTo-Json -Depth 6 -Compress
} catch {
    @{ok=$false;error='LOCAL_OPERATION_FAILED';stage=$stage;category=[string]$_.CategoryInfo.Category;exception=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber} | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($secure) {$secure.Dispose()}
    $request=$null
}
