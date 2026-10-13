#Requires -Version 5.1
# This template is populated and signed by Freshkampo Access before distribution.
$ErrorActionPreference = 'Stop'
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG_BASE64__')) | ConvertFrom-Json
if (-not $PSCommandPath) { throw 'Ejecuta el archivo firmado desde Windows PowerShell.' }
$signature = Get-AuthenticodeSignature -FilePath $PSCommandPath
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw 'La firma del lanzador no es válida o su editor no es de confianza.' }
$digest = [Security.Cryptography.SHA256]::Create()
try { $signer = ([BitConverter]::ToString($digest.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() }
finally { $digest.Dispose() }
if ($signer -ne $config.signerSha256.ToLowerInvariant()) { throw 'El editor no coincide con el certificado configurado.' }
$profile = Join-Path $PSScriptRoot 'Conexion.rdp'
if ((Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $config.rdpSha256.ToLowerInvariant()) { throw 'El archivo RDP ha sido modificado.' }
$machine=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($machine -ne $config.identity.machine -or $sid -ne $config.identity.sid) { throw 'Este cliente pertenece a otro servidor o cuenta Windows.' }
# Use the Windows Credential API, not cmdkey /pass: (which exposes the secret in process arguments).
if (-not ('FreshkampoRdpCredential' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class FreshkampoRdpCredential {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct Credential {
        public uint Flags, Type;
        public string TargetName, Comment;
        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias, UserName;
    }
    [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CredWrite(ref Credential credential, uint flags);
    [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr credential);
    public static bool Exists(string target, string user, string marker) {
        IntPtr ptr;
        if (!CredRead(target, 1, 0, out ptr)) return false;
        try {
            var c=(Credential)Marshal.PtrToStructure(ptr, typeof(Credential));
            return String.Equals(c.UserName,user,StringComparison.OrdinalIgnoreCase) && c.Comment==marker;
        } finally { CredFree(ptr); }
    }
    public static void Store(string target, string user, string password, string marker) {
        IntPtr secret=Marshal.StringToCoTaskMemUni(password);
        try {
            Credential c=new Credential();
            c.Type=1; c.TargetName=target; c.UserName=user; c.Comment=marker;
            c.CredentialBlob=secret; c.CredentialBlobSize=(uint)(password.Length*2); c.Persist=2;
            if (!CredWrite(ref c,0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.ZeroFreeCoTaskMemUnicode(secret); }
    }
}
'@
}
Add-Type -AssemblyName System.Security
$encrypted=[Convert]::FromBase64String($config.credential)
$entropy=[Text.Encoding]::UTF8.GetBytes('Freshkampo.Access.Desktop.v1')
$clear=$null
try {
    $clear=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $credentials=[Text.Encoding]::UTF8.GetString($clear) | ConvertFrom-Json
    if ($credentials.host -ne $config.host -or $credentials.username -ne $config.username -or -not $credentials.password) { throw 'Credencial incompatible.' }
    [FreshkampoRdpCredential]::Store(('TERMSRV/'+$config.host),$credentials.username,$credentials.password,('Freshkampo Access: '+$config.id))
} finally {
    if ($clear) { [Array]::Clear($clear,0,$clear.Length) }
    $credentials=$null
}
& (Join-Path $env:SystemRoot 'System32\mstsc.exe') $profile
