[Setup]
AppId={{9B5C7A5D-2E7B-4C85-8D0D-4A2B7B8E19C4}
AppName=Summerlinc CyberSentinel AI
AppVersion=0.3.2
AppPublisher=SUMMERLINC TECHNOLOGY Ltd
DefaultDirName={autopf}\Summerlinc\CyberSentinel
DefaultGroupName=Summerlinc CyberSentinel AI
OutputDir=installer_output
OutputBaseFilename=Summerlinc_CyberSentinel_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest

[Files]
Source: "dist\CyberSentinel\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Summerlinc CyberSentinel AI"; Filename: "{app}\CyberSentinel.exe"
Name: "{autodesktop}\Summerlinc CyberSentinel AI"; Filename: "{app}\CyberSentinel.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\CyberSentinel.exe"; Description: "Launch Summerlinc CyberSentinel AI"; Flags: postinstall nowait skipifsilent
