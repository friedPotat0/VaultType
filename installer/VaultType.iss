; Inno Setup script - machine-wide installer for the self-contained VaultType.exe.
; The version is passed in by the release workflow:
;   ISCC.exe /DMyAppVersion=1.0.1 installer\VaultType.iss

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#define MyAppName "VaultType"
#define MyAppPublisher "Christian Zaenker"
#define MyAppURL "https://github.com/friedPotat0/VaultType"
#define MyAppExeName "VaultType.exe"

[Setup]
AppId={{5E9C3B71-2F4A-4D8E-9A6B-7C1D0E2F3A4B}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
; Installs into Program Files, where only an administrator can replace VaultType.exe; in the user
; profile anything running under the user's account could swap it for a tampered build.
; /CURRENTUSER on the command line still installs per user, for machines without admin rights.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
; Held by the running app, so setup and uninstall ask for it to be closed wherever it was installed.
AppMutex=VaultType_SingleInstance_9F2A
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\src\VaultType\Assets\vaulttype.ico
OutputDir=..
OutputBaseFilename=VaultType-{#MyAppVersion}-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\publish\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; The app must not inherit setup's elevation.
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';

// Up to 1.2.x the installer only installed per user. Left in place, that copy would keep its own
// Start-menu entry and uninstaller next to the new one, so it is removed before the new files go in.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Uninstaller: String;
  ResultCode: Integer;
begin
  Result := '';
  if not IsAdminInstallMode then Exit;
  // The key name setup itself derives from AppId.
  if not RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\'
      + ExpandConstant('{#SetupSetting("AppId")}') + '_is1', 'UninstallString', Uninstaller) then Exit;
  Uninstaller := RemoveQuotes(Uninstaller);
  if FileExists(Uninstaller) then
    Exec(Uninstaller, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// The app keeps its autostart entry pointed at wherever it runs from, but only once it is started
// again. Until then an entry left by a per-user install would point at the removed copy.
procedure CurStepChanged(CurStep: TSetupStep);
var
  Command: String;
begin
  if CurStep <> ssPostInstall then Exit;
  if RegQueryStringValue(HKCU, RunKey, '{#MyAppName}', Command) then
    RegWriteStringValue(HKCU, RunKey, '{#MyAppName}', '"' + ExpandConstant('{app}\{#MyAppExeName}') + '"');
end;
