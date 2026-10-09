; ==============================================================================
; Inno Setup Script for Scout Malware Scanner
; ==============================================================================
; To compile this installer:
; 1. Download and install Inno Setup 6 (free from https://jrsoftware.org/isdl.php)
; 2. Right-click this file and choose "Compile", or run from CLI:
;    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
; 3. Output installer ScoutSetup.exe will be created in the Output\ folder.
; ==============================================================================

#define MyAppName "Scout"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "Security Team"
#define MyAppURL "http://localhost:8000"
#define MyAppExeName "ScannerApp.exe"

[Setup]
AppId={{9F5F042C-821A-4C2E-A1D8-726D8E42F992}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=ScoutSetup
OutputDir=Output
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
ChangesEnvironment=yes
UsedUserAreasWarning=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\ScannerApp\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{app}"; Permissions: users-full
Name: "{app}\data"; Permissions: users-full
Name: "{app}\data\logs"; Permissions: users-full
Name: "{app}\inbox"; Permissions: users-full
Name: "{app}\processing"; Permissions: users-full
Name: "{app}\clean"; Permissions: users-full
Name: "{app}\review"; Permissions: users-full
Name: "{app}\quarantine"; Permissions: users-full
Name: "{app}\tools\clamav\database"; Permissions: users-full
Name: "{app}\tools\clamav\certs"; Permissions: users-full

[Registry]
; Re-enable Windows automatic root cert updates if disabled by stripped OS
Root: HKLM; Subkey: "SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot"; ValueType: dword; ValueName: "DisableRootAutoUpdate"; ValueData: "0"; Flags: uninsdeletevalue

; Set system-wide and user-wide OpenSSL / libcurl environment variables pointing to bundled CA bundle
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: string; ValueName: "CURL_CA_BUNDLE"; ValueData: "{app}\tools\clamav\curl-ca-bundle.crt"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: string; ValueName: "SSL_CERT_FILE"; ValueData: "{app}\tools\clamav\curl-ca-bundle.crt"; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Environment"; ValueType: string; ValueName: "CURL_CA_BUNDLE"; ValueData: "{app}\tools\clamav\curl-ca-bundle.crt"; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Environment"; ValueType: string; ValueName: "SSL_CERT_FILE"; ValueData: "{app}\tools\clamav\curl-ca-bundle.crt"; Flags: uninsdeletevalue

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Populate Windows Root Certificate stores with official Microsoft root catalog
Filename: "certutil.exe"; Parameters: "-addstore -f Root ""{app}\tools\clamav\roots.sst"""; Flags: runhidden; StatusMsg: "Configuring system root security certificates..."
Filename: "certutil.exe"; Parameters: "-addstore -f AuthRoot ""{app}\tools\clamav\roots.sst"""; Flags: runhidden; StatusMsg: "Configuring system root security certificates..."
Filename: "certutil.exe"; Parameters: "-user -addstore -f CA ""{app}\tools\clamav\roots.sst"""; Flags: runhidden; StatusMsg: "Configuring user root security certificates..."
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
