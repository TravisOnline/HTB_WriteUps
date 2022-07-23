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
