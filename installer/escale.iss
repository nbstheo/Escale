; Installateur Windows d'Escale (Inno Setup 6). Généré via installer\build.ps1.

#define AppName "Escale"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{6B0E5C1A-4F2D-4E8B-9A57-3C1E2D7F8A90}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppName}
AppComments=Client SSH, RDP et VNC léger, chiffré, avec rebonds
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Installation pour l'utilisateur courant sans droits admin, ou pour tous (au choix)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=Escale-Setup-{#AppVersion}
SetupIconFile=escale.ico
UninstallDisplayIcon={app}\escale.exe
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\target\release\escale.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\escale.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\escale.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\escale.exe"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; Le coffre chiffré (%APPDATA%\Escale) est volontairement conservé à la désinstallation.
