; LaTeXStruct 安装器（Inno Setup 6）
; 每用户安装（无需管理员）；静默更新参数：/SILENT /CLOSEAPPLICATIONS /NORESTART
#ifndef AppVersion
  #error AppVersion must be supplied by scripts/build.ps1 or CI
#endif

[Setup]
AppId={{6B4E9D3C-2F1A-4C6E-9A5B-7D8C3F2E1A09}
AppName=LaTeXStruct
AppVersion={#AppVersion}
AppPublisher=LaTeXStruct
DefaultDirName={localappdata}\Programs\LaTeXStruct
DefaultGroupName=LaTeXStruct
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
; v1.1.1 updater starts Setup before its PyInstaller process tree has exited.
; Restart Manager therefore needs force as a compatibility fallback. Newer
; updaters exit first and wait for LaTeXStruct.exe to become exclusively writable.
CloseApplications=force
RestartApplications=no
OutputDir=..\dist
OutputBaseFilename=LaTeXStruct-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\LaTeXStruct.exe
SetupIconFile=..\packaging\icon.ico

[Languages]
; 简体中文为默认安装界面语言（官方翻译文件随仓库提供，避免 CI 上 Inno 未带语言包）
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："

[Files]
Source: "..\dist\LaTeXStruct.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\LaTeXStruct"; Filename: "{app}\LaTeXStruct.exe"
Name: "{autodesktop}\LaTeXStruct"; Filename: "{app}\LaTeXStruct.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\LaTeXStruct.exe"; Description: "启动 LaTeXStruct"; Parameters: "{code:UpdateLaunchParameters}"; Flags: nowait postinstall skipifsilent
; Silent initial installs stay silent. A silent upgrade (including the old v1.1.1
; updater command line) starts the newly installed version after replacement.
Filename: "{app}\LaTeXStruct.exe"; Parameters: "{code:UpdateLaunchParameters}"; Flags: nowait skipifnotsilent; Check: RestartAfterSilentUpdate

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  WasInstalledBefore: Boolean;
  PreviousVersion: String;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then begin
    WasInstalledBefore := FileExists(ExpandConstant('{app}\LaTeXStruct.exe'));
    PreviousVersion := '';
    if WasInstalledBefore then
      GetVersionNumbersString(ExpandConstant('{app}\LaTeXStruct.exe'), PreviousVersion);
  end;
end;

function UpdateLaunchParameters(Param: String): String;
begin
  if WasInstalledBefore and (PreviousVersion <> '') then
    Result := '--updated-from "' + PreviousVersion + '"'
  else
    Result := '';
end;

function RestartAfterSilentUpdate: Boolean;
begin
  Result := WasInstalledBefore or
    (CompareText(ExpandConstant('{param:LATEXSTRUCTUPDATE|0}'), '1') = 0);
end;
