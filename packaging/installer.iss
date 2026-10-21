#define AppVersion "1.10.1"
[Setup]
AppId={{72FBC267-2574-4268-AB77-36B8374BCA7D}
AppName=Metakampo Access
AppVersion={#AppVersion}
AppPublisher=Metakampo
; Keep the original directory and AppId for compatible upgrades.
DefaultDirName={autopf}\Freshkampo\Access
DefaultGroupName=Metakampo Access
UsePreviousGroup=no
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=Metakampo-Access-Setup-x64
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile=MetakampoAccess.ico
UninstallDisplayIcon={app}\MetakampoAccess.exe
CloseApplications=yes
SetupLogging=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "..\dist\MetakampoAccess\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\build-tools\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "..\DESKTOP.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Metakampo Access"; Filename: "{app}\MetakampoClient.exe"
Name: "{group}\Administrar servidor Metakampo"; Filename: "{app}\MetakampoClient.exe"
Name: "{group}\Configurar Metakampo Access"; Filename: "{app}\MetakampoAccess.exe"; Parameters: "--configure"
Name: "{commondesktop}\Metakampo Access"; Filename: "{app}\MetakampoClient.exe"

[InstallDelete]
Type: files; Name: "{app}\FreshkampoAccess.exe"
Type: files; Name: "{commonprograms}\Freshkampo Access\Freshkampo Access.lnk"
Type: files; Name: "{commonprograms}\Freshkampo Access\Configurar Freshkampo Access.lnk"
Type: files; Name: "{commondesktop}\Freshkampo Access.lnk"

[Run]
Filename: "{tmp}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; Parameters: "/silent /install"; StatusMsg: "Instalando el motor de escritorio Microsoft WebView2..."; Flags: waituntilterminated
Filename: "{app}\MetakampoClient.exe"; Description: "Abrir Metakampo Access"; Flags: shellexec nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\MetakampoAccess.exe"; Parameters: "--remove-service"; Flags: runhidden waituntilterminated
Filename: "{app}\MetakampoAccess.exe"; Parameters: "--remove-protection"; Flags: runhidden waituntilterminated

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer;
begin
  if CurStep = ssPostInstall then
    if (not Exec(ExpandConstant('{app}\MetakampoAccess.exe'), '--install-protection', '', SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
      RaiseException('Windows no registró o inició la protección en segundo plano. Revisa el registro y repara la instalación.');
  if CurStep = ssPostInstall then
    if (not Exec(ExpandConstant('{app}\MetakampoAccess.exe'), '--repair-service', '', SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
      RaiseException('Windows no pudo reiniciar el servicio Metakampo. Revisa sus credenciales y el registro.');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  Result := '';
  if RegKeyExists(HKLM64, 'SOFTWARE\Metakampo\AccessService') and FileExists(ExpandConstant('{app}\MetakampoAccess.exe')) then
    if (not Exec(ExpandConstant('{app}\MetakampoAccess.exe'), '--stop-service', '', SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
    begin
      Result := 'No se detuvo el servicio Metakampo. Espera a que terminen sus operaciones antes de actualizar.';
      Exit;
    end;
  if FileExists(ExpandConstant('{commonappdata}\Metakampo\Access\Protection\worker.lock')) and FileExists(ExpandConstant('{app}\MetakampoAccess.exe')) then
    if (not Exec(ExpandConstant('{app}\MetakampoAccess.exe'), '--stop-protection', '', SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
      Result := 'No se detuvo la protección de Metakampo. Cierra sus tareas pendientes antes de actualizar.';
end;

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

