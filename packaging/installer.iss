#define AppVersion "1.2.0"
[Setup]
AppId={{72FBC267-2574-4268-AB77-36B8374BCA7D}
AppName=Freshkampo Access
AppVersion={#AppVersion}
AppPublisher=Freshkampo
DefaultDirName={autopf}\Freshkampo\Access
DefaultGroupName=Freshkampo Access
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=Freshkampo-Access-Setup-x64
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile=FreshkampoAccess.ico
UninstallDisplayIcon={app}\FreshkampoAccess.exe
CloseApplications=yes
SetupLogging=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\dist\FreshkampoAccess\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\build-tools\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "..\DESKTOP.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Freshkampo Access"; Filename: "{app}\FreshkampoAccess.exe"
Name: "{group}\Configurar Freshkampo Access"; Filename: "{app}\FreshkampoAccess.exe"; Parameters: "--configure"
Name: "{commondesktop}\Freshkampo Access"; Filename: "{app}\FreshkampoAccess.exe"

[Run]
Filename: "{tmp}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; Parameters: "/silent /install"; StatusMsg: "Instalando el motor de escritorio Microsoft WebView2..."; Flags: waituntilterminated
Filename: "{app}\FreshkampoAccess.exe"; Description: "Abrir Freshkampo Access"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
function IsServerCore(): Boolean;
var InstallationType: String;
begin
  Result := False;
  if RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'InstallationType', InstallationType) then
    Result := InstallationType <> 'Server';
end;

function InitializeSetup(): Boolean;
begin
  Result := IsWin64;
  if Result then Result := not IsServerCore;
  if not Result then MsgBox('Se requiere Windows Server x64 con experiencia de escritorio.', mbError, MB_OK);
end;

