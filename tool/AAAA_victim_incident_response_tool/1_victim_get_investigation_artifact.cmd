ping "DEBUT_COLLECTE"
mkdir "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact"
set DFIR_OUTPUT_PATH="C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
echo %date% %time% > "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"

EvtxExplorer\EvtxECmd.exe -d %systemroot%\System32\winevt\logs --csv C:\Windows\AAAA_victim_incident_response_tool\parsing_out\logs --csvf evtxecmd_out.csv

mkdir "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\logs"
copy "%systemroot%\System32\winevt\logs" "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\logs"
mkdir "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\prefetch"
copy "%systemroot%\Prefetch" "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\prefetch"
mkdir "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config"
reg save HKLM\SYSTEM "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config\SYSTEM.hiv"
reg save HKLM\SAM "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config\SAM.hiv"
reg save HKU\DEFAULT "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config\DEFAULT.hiv"
reg save HKLM\SECURITY "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config\SECURITY.hiv"
reg save HKLM\SOFTWARE "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config\SOFTWARE.hiv"
reg save HKU\S-1-5-21-321011808-3761883066-353627080-1000 "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\config\HKU.DAT"

mkdir "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\rdp_cache"
copy "C:\Users\%username%\AppData\Local\Microsoft\Terminal Server Client\Cache" "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\rdp_cache"

SrumECmd\SrumECmd.exe -f %systemroot%\System32\sru\SRUDB.dat -r C:\Users\Lucas\Desktop\victim_incident_response_tool\2_raw_artifact\config\SOFTWARE.hiv --csv "C:\Windows\AAAA_victim_incident_response_tool\parsing_out\sru"
AmcacheParser\AmcacheParser.exe -f C:\Windows\appcompat\Programs\Amcache.hve --csv "C:\Windows\AAAA_victim_incident_response_tool\parsing_out\amcache"

reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /f TimeZoneKeyName>> %DFIR_OUTPUT_PATH%
reg query "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName">> %DFIR_OUTPUT_PATH%
reg query "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces" /s /f *IPAddress>> %DFIR_OUTPUT_PATH%

echo "# Pour investigation hive SYSTEM a froid sur ControlSetXXX (remplacement du CurentControlSet)">> %DFIR_OUTPUT_PATH%
reg query "HKEY_LOCAL_MACHINE\SYSTEM\Select" /f current >> %DFIR_OUTPUT_PATH%

echo "# Liste des hive sur le PC">> %DFIR_OUTPUT_PATH%
reg query "HKLM\SYSTEM\CurrentControlSet\Control\hivelist">> %DFIR_OUTPUT_PATH%

echo "# SafeDllSearchMode est désactivé si 0. Permet de load les DLL depuis de répertoire courant">> %DFIR_OUTPUT_PATH%
reg query "HKLM\System\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode>> %DFIR_OUTPUT_PATH%

echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%

echo "##########"
echo "Persistance IOC"
echo "##########"
set DFIR_OUTPUT_PATH_PERSISTANCE="C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd_persistance.txt"
echo %date% %time% > %DFIR_OUTPUT_PATH_PERSISTANCE%
echo "^(HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\)[a-zA-z0-9\-\.\_]+\r[a-zA-z\s\_]+(0x3|0x4)$" >> %DFIR_OUTPUT_PATH_PERSISTANCE%
echo "^\r\n" >> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "startup" >> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "startup" >> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup" >> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup" >> %DFIR_OUTPUT_PATH_PERSISTANCE%

dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup">> %DFIR_OUTPUT_PATH_PERSISTANCE%
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup">> %DFIR_OUTPUT_PATH_PERSISTANCE%


reg query "HKLM\SYSTEM\ControlSet001\Control\Session Manager" /v BootExecute >> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /v start >> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce">> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify>> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v UserInit>> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell>> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell>> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot" /v Shell>> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad">> %DFIR_OUTPUT_PATH_PERSISTANCE%


reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce">> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load">> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs>> %DFIR_OUTPUT_PATH_PERSISTANCE%


reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run">> %DFIR_OUTPUT_PATH_PERSISTANCE%
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices">> %DFIR_OUTPUT_PATH_PERSISTANCE%

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s /v MonitorProcess>> %DFIR_OUTPUT_PATH_PERSISTANCE%

echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%
echo "Action utilisateur IOC">> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%

echo "# Recherche utilisateur dans barre de recherche de l'explorateur (seulement ajoute apres restart de la machine dans le registry)">> "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths">> %DFIR_OUTPUT_PATH%

echo "# Si 0x1 veut dire que le pagefile.sys (windows swap) est supprime a l'arret de windows">> "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown>> %DFIR_OUTPUT_PATH%

echo "# Programmes installes">> "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall">> %DFIR_OUTPUT_PATH%

reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall">> %DFIR_OUTPUT_PATH%

echo "# Historique Liste carte réseau">> "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /s /f Description>> %DFIR_OUTPUT_PATH%

echo "# Historique liste SSID Wifi">> "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s /f ProfileName>> %DFIR_OUTPUT_PATH%

echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%
echo "USB IOC">> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%

echo "# Historique branchement usb pour storage">> "C:\Windows\AAAA_victim_incident_response_tool\2_raw_artifact\dfir_cmd.txt"
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s /f FriendlyName>> %DFIR_OUTPUT_PATH%

echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%
echo "SHARE IOC">> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%

reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares">> %DFIR_OUTPUT_PATH%


echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo. >> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%
echo "SRUM temporaire dans hive avant ajout dans C:\Windows\System32\sru\SRUDB.dat IOC">> %DFIR_OUTPUT_PATH%
echo "##########">> %DFIR_OUTPUT_PATH%

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions" /s >> %DFIR_OUTPUT_PATH%