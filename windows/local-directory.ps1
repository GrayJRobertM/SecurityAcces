# Local SAM only; secrets arrive over stdin and never appear in process arguments.
# No remote host, group elevation, deletion or domain-controller SAM operations are supported.
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
try {
    $request=[Console]::In.ReadToEnd() | ConvertFrom-Json
    $os=Get-CimInstance Win32_OperatingSystem
    if ($os.ProductType -ne 3) { throw 'Requires member or standalone Windows Server' }
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $elevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $elevated) { throw 'Elevation required' }
    $machineGuid=[string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    $scope='local:'+$machineGuid.ToLowerInvariant()
    # Membership lookup must succeed; unresolved group members cause a fail-closed response.
    $admins=@(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544') -ErrorAction Stop | ForEach-Object {$_.SID.Value})
    function Protected($user) {
        $rid=[long]($user.SID.Value.Split('-')[-1])
        return ($rid -lt 1000 -or $user.SID.Value -eq $identity.User.Value -or $admins -contains $user.SID.Value -or [string]$user.PrincipalSource -ne 'Local')
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
    switch ($request.action) {
        'check' { $data=@{local=$true;computer=$env:COMPUTERNAME;scope=$scope} }
        'list' {
            $data=@(Get-LocalUser | ForEach-Object {
                $locked=$false
                try {$locked=[bool](UserObject $_).InvokeGet('IsAccountLocked')} catch {}
                @{id=$_.SID.Value;name=$(if ($_.FullName) {$_.FullName} else {$_.Name});username=$_.Name;department=[string]$_.Description;upn=($env:COMPUTERNAME+'\'+$_.Name);enabled=$_.Enabled;locked=$locked;protected=(Protected $_)}
            })
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
            $secure=ConvertTo-SecureString -String $request.password -AsPlainText -Force
            $enabled=if ($request.PSObject.Properties.Name -contains 'enabled') {[bool]$request.enabled} else {$true}
            $user=New-LocalUser -Name $request.username -FullName $request.name -Description ([string]$request.department) -Password $secure -Disabled:(-not $enabled) -ErrorAction Stop
            # Standard Users membership only; RDP rights remain controlled by Windows policy.
            Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-545') -Member $user -ErrorAction Stop
            $data=PasswordResult $user
        }
        {$_ -in 'reset','enable','disable','unlock','update'} {
            $user=Scoped $request.identifier
            switch ($request.action) {
                'reset' {$secure=ConvertTo-SecureString -String $request.password -AsPlainText -Force;Set-LocalUser -SID $user.SID -Password $secure -ErrorAction Stop}
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
    @{ok=$false;error='LOCAL_OPERATION_FAILED'} | ConvertTo-Json -Compress
    exit 1
} finally {
    if ($secure) {$secure.Dispose()}
    $request=$null
}
