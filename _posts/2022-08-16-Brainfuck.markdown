---
layout: post
title:  "HTB Writeup [Linux - Insane] - Brainfuck"
published: false
---

![Sniper](Brainfuck.png)

### Summary
- A Linux box where find email ports (SMTP/POP/IMAP) open as well as two https websites (we discovered them from the SSL certificate Subject Alternative Name field)
- One website had a Wordpress blog which happened to have a vulnerable component that enabled us to impersonate the `admin` user.
- After failing to get code execution using traditional ways (Editing Wordpress themes and Uploading malicious plugins), we search more to find email credentials for the `orestis` user in the SMTP plugin installed in Wordpress.
- We configure a mail client with IMAP and retrieve the mailbox contents for the `orestis` user to a set of credentials for the other website which was a forum.
- After logging in, we find a discussion between the `administrator` and `orestis` about him losing SSH access and wanting his key.
- The `administrator` says he won't provide the SSH key in the discussion thread because it would be visible to all forum members. So they switch over to an encrypted one.
- We do some research on recognizing the Cipher in use to find out it's a Keyed Vigenere Cipher and are able to figure out the key.
- After decrypting the messages on the thread, we get a passphrase-protected SSH key. Which we crack using john.
- We finally login as the `orestis` user and find out he's a member of the `lxd` group which enables us to escalate our privileges to `root`.

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
Looking at the nmap scan results, we notice:
1. SSH version < 7.7 which allows for user enumeration (we might need that to confirm some users' existence on the box)
2. Mail ports: 25, 110 & 143 for SMTP, POP and IMAP (SMTP = we can send malicious emails and launch client-side attacks while IMAP and POP3 can give us access to user mailboxes if we have credentials)
3. HTTPs on port 443 is a web-based attack surface for us to explore

But we notice that the nmap default script gave us a couple of host names in the commonName and Subject Alternative Name fields:
- brainfuck.htb
- www.brainfuck.htb
- sup3rs3cr3t.brainfuck.htb

Adding those to our `/etc/hosts` shouldn't take much time:

![setting-etc-hosts](setting-etc-hosts.jpg)

### Taking a look at the websites
We take a look at www.brainfuck.htb to find a Wordpress Blog

![wordpress-first-look](wordpress-first-look.jpg)

It's rich with information:
1. we find two usernames: `admin` and `orestis`
2. we find a note about integration with SMTP. which could be a hint
3. we notice a link to "open a ticket" which could be a Wordpress plugin and maybe more functionality to be exploited

### Enumerating Wordpress
At this point, it's both a quick and easy check to run `wpscan`. It's specialized for scanning Wordpress and would give us tons of information on it.

we run it the below command:
```bash
wpscan --url https://brainfuck.htb/ -e ap,at,tt,cb,dbe,u --disable-tls-checks
```

this would enable us to enumerate `-e`:
- All plugins `ap`
- All themes `at`
- Timthumbs `tt`
- Config backups `cb`
- Database exports `dbe`
- And, Wordpress users `u`

Looking at the results, we find something interesting:

![wp-plugin-discovered](wp-plugin-discovered.jpg)

We do a search on [Exploit-DB](https://www.exploit-db.com/) to find that there is couple of verified exploits that match the version we have:

![exploit-db-plugin](exploit-db-plugin.jpg)

At first, we check out the SQL injection one. But we find out that it requires at least one valid user:

![vuln1-user-access-required](vuln1-user-access-required.jpg)

Luckily however, the second one doesn't require authentication:

![](vuln2-user-access-not-required.jpg)

And the PoC seems straightforward. Just a form we have to submit:

![](vuln2-poc.jpg)

