#Requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Plan)
# Executes only an installer whose bytes match a pinned, signed release manifest.
$ErrorActionPreference='Stop'
$publicXml='@@PUBLIC_XML@@'
$packageStream=$null;$lease=$null;$owned=$false;$resultFile=$null;$interactive=$false;$success=$false;$root=$null;$installerCode=0
function Write-Result($status,$message,$code=0) {
    if($resultFile){@{status=$status;message=$message;code=$code;version=[string]$manifest.version;at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();restarted_pid=$script:restartedPid}|ConvertTo-Json -Compress|Set-Content -LiteralPath $resultFile -Encoding UTF8}
}
try {
    $stage=[IO.Path]::GetFullPath($PSScriptRoot)
    $cache=Split-Path -Parent $stage
    if((Split-Path -Leaf $cache) -ne '.metakampo-updates' -or (Split-Path -Leaf $stage) -notmatch '^[a-f0-9]{32}$'){throw 'Invalid staging directory'}
    $root=Split-Path -Parent $cache;$resultFile=Join-Path $cache 'result.json'
    if([IO.Path]::GetFullPath($Plan) -ne (Join-Path $stage 'plan.json')){throw 'Invalid plan path'}
    foreach($path in @($root,$cache,$stage,$Plan,(Join-Path $stage 'Metakampo-Access-Setup-x64.exe'),(Join-Path $stage 'metakampo-update.json'))){
        if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse path rejected'}
    }
    $planData=Get-Content -LiteralPath $Plan -Raw|ConvertFrom-Json
    $interactive=($planData.interactive -eq $true)
    if($planData.schema -ne 1 -or [string]$planData.version -notmatch '^\d{1,4}\.\d{1,4}\.\d{1,4}$' -or [long]$planData.owner_pid -le 0){throw 'Invalid plan'}
    $manifestPath=Join-Path $stage 'metakampo-update.json'
    if((Get-Item -LiteralPath $manifestPath).Length -gt 32768){throw 'Manifest too large'}
    $envelope=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    $payload=[Convert]::FromBase64String([string]$envelope.payload);$signature=[Convert]::FromBase64String([string]$envelope.signature)
    if($payload.Length -gt 8192 -or $signature.Length -ne 384){throw 'Invalid signature envelope'}
    $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new()
    try {$rsa.FromXmlString($publicXml);if(-not $rsa.VerifyData($payload,'SHA256',$signature)){throw 'Signature rejected'}} finally {$rsa.Dispose()}
    $manifest=[Text.Encoding]::UTF8.GetString($payload)|ConvertFrom-Json
    if($manifest.schema -ne 1 -or $manifest.platform -ne 'windows-x64' -or $manifest.asset -ne 'Metakampo-Access-Setup-x64.exe' -or $manifest.version -ne $planData.version -or $manifest.tag -ne ('metakampo-v'+$manifest.version) -or [string]$manifest.sha256 -notmatch '^[a-f0-9]{64}$' -or [long]$manifest.size -le 0 -or [long]$manifest.size -gt 1GB){throw 'Manifest rejected'}
    $ownerExe=Join-Path $root 'MetakampoAccess.exe'
    $installed=[Diagnostics.FileVersionInfo]::GetVersionInfo($ownerExe).ProductVersion
    if([Version]$manifest.version -le [Version]$installed){throw 'Version rollback rejected'}
    $owner=Get-Process -Id ([int]$planData.owner_pid) -ErrorAction Stop
    if(-not [string]::Equals([IO.Path]::GetFullPath($owner.Path),$ownerExe,[StringComparison]::OrdinalIgnoreCase)){throw 'Wrong owner process'}
    $package=Join-Path $stage 'Metakampo-Access-Setup-x64.exe'
    # Deny replacement/write/delete from verification through installer completion (TOCTOU).
    $packageStream=[IO.File]::Open($package,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    if($packageStream.Length -ne [long]$manifest.size -or $packageStream.ReadByte() -ne 77 -or $packageStream.ReadByte() -ne 90){throw 'Invalid installer'}
    $packageStream.Position=0;$sha=[Security.Cryptography.SHA256]::Create()
    try {$hash=([BitConverter]::ToString($sha.ComputeHash($packageStream))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    if($hash -ne $manifest.sha256){throw 'Installer hash rejected'}
    $lease=[Threading.Mutex]::new($false,'Global\Metakampo.Access.Update.v1')
    try {$owned=$lease.WaitOne(0)} catch [Threading.AbandonedMutexException] {$owned=$true}
    if(-not $owned){throw 'Another updater is active'}
    @{ready=$true;version=$manifest.version}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $stage 'ready.json') -Encoding UTF8
    # Never terminate another user's work. The owner drains and exits voluntarily.
    if(-not $owner.WaitForExit(90000)){throw 'Owner did not close'}
    $until=[DateTime]::UtcNow.AddSeconds(45)
    do {
        $busy=$false
        foreach($process in @(Get-Process -Name MetakampoAccess,MetakampoClient -ErrorAction SilentlyContinue)){
            try {$path=[IO.Path]::GetFullPath($process.Path)} catch {throw 'Could not verify running application'}
            if([string]::Equals((Split-Path -Parent $path),$root,[StringComparison]::OrdinalIgnoreCase)){$busy=$true}
        }
        if($busy){Start-Sleep -Milliseconds 500}
    } while($busy -and [DateTime]::UtcNow -lt $until)
    if($busy){throw 'Other application windows remain open'}
    $arguments='/VERYSILENT /SUPPRESSMSGBOXES /SP- /NORESTART /RESTARTEXITCODE=3010 /NOCLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /DIR="'+$root+'" /LOG="'+(Join-Path $stage 'install.log')+'"'
    $setup=Start-Process -FilePath $package -ArgumentList $arguments -PassThru -Wait
    $installerCode=$setup.ExitCode
    if($setup.ExitCode -ne 0){Write-Result 'error' 'El instalador no completó la actualización. Revisa el registro; no se reinició Windows.' $setup.ExitCode;throw 'Installer did not complete'}
    if([Version]([Diagnostics.FileVersionInfo]::GetVersionInfo($ownerExe).ProductVersion) -ne [Version]$manifest.version){throw 'Installed version mismatch'}
    $smoke=Start-Process -FilePath $ownerExe -ArgumentList '--self-test' -PassThru
    if(-not $smoke.WaitForExit(90000)){throw 'Installed self-test timed out'}
    if($smoke.ExitCode -ne 0){throw 'Installed self-test failed'}
    $success=$true
    Write-Result 'success' 'Actualización instalada y comprobada.'
} catch {
    # Do not expose URL query strings, credentials or arbitrary exception bodies.
    Write-Result 'error' 'No se completó la actualización. Conserva la copia de seguridad y revisa install.log. Puede requerir cerrar otras ventanas o revisar políticas Windows.' $installerCode
    if($interactive){Add-Type -AssemblyName System.Windows.Forms;[void][Windows.Forms.MessageBox]::Show('No se completó la actualización de Metakampo. No se reinició Windows. Revisa el resultado en .metakampo-updates y vuelve a abrir Administrar servidor Metakampo.','Metakampo Access',0,16)}
} finally {
    if($packageStream){$packageStream.Dispose()}
    if($owned -and $lease){$lease.ReleaseMutex()}
    if($lease){$lease.Dispose()}
}
if($success){
    $launch=Start-Process -FilePath (Join-Path $root 'MetakampoAccess.exe') -ArgumentList '--shared-host' -PassThru
    $script:restartedPid=$launch.Id
    Write-Result 'success' 'Actualización instalada y comprobada; servidor reabierto con la misma cuenta Windows.'
    exit 0
}
exit 1
