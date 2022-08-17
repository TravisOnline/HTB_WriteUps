# Legacy

This was way too easy, even for me. It's probably not even worth doing a write-up on, but anyway...

## Recon
I start with the usual nmap command `nmap -sV -sC -Pn 10.10.10.4`, so we're running default script, service version, treating the host as up and targeting 10.10.10.4.

Nmap returns with:
```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m40s, deviation: 2h07m15s, median: 4d22h57m41s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:5c:6c (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2022-08-22T13:00:33+03:00
```

Nothing too unusual here, SMB is a good place to start though. Before I even try to browse to it, I ran this nmap command: `nmap -Pn -p 445 --script smb-vuln-* 10.10.10.4`. So this time, we're looking at only port 445, and specifically running SMB vulnerability scripts at our host address.

The following is the interesting part:
```
nmap -Pn -p 445 --script smb-vuln-* 10.10.10.4 
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx

Nmap done: 1 IP address (1 host up) scanned in 9.32 seconds
```

Checking out [the MITRE link](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2008-4250) lets us understand how the exploit works. Essentially we're sending a buffer overflow to the service. I had a look on exploit DB and found [an example of the attack written in C](https://www.exploit-db.com/exploits/7104) but decided to be lazy once again and boot up Metasploit

## Exploitation
With Metasploit open, I just searched the CVE number: 2008-4350, loaded up the only result: `0  exploit/windows/smb/ms08_067_netapi  2008-10-28       great  Yes    MS08-067 Microsoft` set RHOSTS to `10.10.10.4` LHOSTS to my IP address and ran the command.

*Note: the machine kept booting me due to network/msf issues. Not sure why, but I ended up finding out that the Windows version we're targeting is Selected Target: Windows XP SP3 English (AlwaysOn NX). To speed up the process I also set target to 6 (this Windows version) when reconnecting.*

Just like that, we have a meterpreter shell on the machine. We can grab the flags from John's Desktop, and Administrator's Desktop.
