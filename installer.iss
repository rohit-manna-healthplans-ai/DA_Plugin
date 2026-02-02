#define AppId "{{D1F4A9E2-8C62-4E4F-A9B5-91B5E6E8A101}}"
#define AppName "Discovery Agent"
#define AppVersion "1.0"
#define AppPublisher "Rohit Manna"
;#define DashboardURL "https://powershell-frontend.vercel.app/"

; Your exact PyInstaller ONEFILE output folder (must contain: "Discovery Agent.exe")
#define SourceDir "C:\Rohit Files\IntelliH\plugin\dist"
#define ExeName "Discovery Agent.exe"

#define PluginIco "C:\Rohit Files\IntelliH\plugin\plugin.ico"
;#define PowerShellIco "C:\Rohit Files\IntelliH\plugin\powershell.ico"
[Registry]
; --- Auto-start at login using HKCU Run (FAST & RELIABLE) ---
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
ValueType: string; ValueName: "{#AppName}"; \
ValueData: """{app}\{#ExeName}"""; Flags: uninsdeletevalue

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
;AppSupportURL={#DashboardURL}
;AppPublisherURL={#DashboardURL}

; Per-user install (no admin needed)
DefaultDirName={localappdata}\DiscoveryAgent
DefaultGroupName={#AppName}

OutputDir=Output
OutputBaseFilename=DiscoveryAgent_Setup
Compression=lzma
SolidCompression=yes

; IMPORTANT: keep as lowest so employees can install without admin
PrivilegesRequired=lowest
WizardStyle=modern
DisableProgramGroupPage=yes

SetupIconFile={#PluginIco}
UninstallDisplayIcon={app}\plugin.ico
UninstallDisplayName={#AppName}
SetupLogging=yes

[Files]
; --- Copy ONEFILE exe ---
Source: "{#SourceDir}\{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion

; --- Copy icon used by shortcuts ---
Source: "{#PluginIco}"; DestDir: "{app}"; DestName: "plugin.ico"; Flags: ignoreversion
;Source: "{#PowerShellIco}"; DestDir: "{app}"; DestName: "powershell.ico"; Flags: ignoreversion

[INI]
; --- Dashboard URL file (KEEP COMMENTED) ---
;FileName: "{app}\Powershell Dashboard.url"; Section: "InternetShortcut"; Key: "URL"; String: "{#DashboardURL}"

[Icons]
; --- Start Menu shortcut ---
Name: "{group}\{#AppName}"; Filename: "{app}\{#ExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\plugin.ico"

; --- Auto-start at login (NO ADMIN REQUIRED) ---
; This is the most reliable way for per-user startup.
;Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#ExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\plugin.ico"

; --- Dashboard shortcut (KEEP COMMENTED) ---
;Name: "{group}\Powershell Dashboard"; Filename: "{app}\Powershell Dashboard.url"; WorkingDir: "{app}"; IconFilename: "{app}\powershell.ico"

[Run]
; Intentionally EMPTY: you said you don't want the installer to show "Run automatically" / quick-start checkbox.
; (App will start automatically next time the user logs in because of the Startup shortcut above.)

[Code]
// Start the app automatically right after installation (without showing any checkbox).
// Runs under the current logged-in user (same as PrivilegesRequired=lowest).
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Don't auto-launch during silent installs
    if not WizardSilent then
    begin
      Exec(ExpandConstant('{app}\\{#ExeName}'), '', ExpandConstant('{app}'), SW_SHOWNORMAL, ewNoWait, ResultCode);
    end;
  end;
end;


[UninstallRun]
; --------------------------------------------------------
; 1. KILL PROCESS (Must run BEFORE deleting files)
; --------------------------------------------------------
Filename: "{sys}\taskkill.exe"; \
    Parameters: "/F /IM ""{#ExeName}"""; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "KillDiscoveryAgent"


[UninstallDelete]
Type: filesandordirs; Name: "{app}"