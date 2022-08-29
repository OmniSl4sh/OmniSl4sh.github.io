---
layout: post
title:  "HTB Writeup [Linux - Medium] - TartarSauce"
published: false
---

![](/assets/TartarSauce/TartarSauce.png)

## Summary
- **TartarSauce** is a **Linux** machine where *only port 80 was open.*
- *On the webroot*, the `robots.txt` file had entries for a **CMS** called **"Monstra"** where we could log on using **weak credentials.**
- *Even though the* ***CMS had plenty of exploitable functionalities***, we **couldn't exploit** any **due to the restrictions in place**. so we looked elsewhere.
- *After we do some* ***web directory brute forcing***, we discover a **WordPress instance** that had a **plugin vulnerable to RFI**.
- We **successfully exploit the vulnerability** and get **Remote Code Execution**.
- *With* `www-data`, we find that we have a `sudo` **privilege** to **run** the `tar` command as the `onuma` user. We **exploit that** for a shell as him/her/it.
- Running `linpeas.sh` for **privilege escalation** shows us a **system timer** that **runs a script** (`backuperer`) every 5 minutes.
- *Since that script ran as* `root`, we analyzed it to find that it **extracts an archive that we can control** *during execution.*
- *By inserting an* **SUID shell** *into a* **tar archive** *of our own*, and then ***replacing the initial archive with it***. We take advantage of the script **extracting our SUID shell** and ***becoming its owner in the process***. Thus **giving us a root shell ;]**

***That last part unclear? it will get its fair share of breakdown [below](#detecting-system-operations) :)***

---

## NMAP
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-title: Landing Page
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

*Starting with* **nmap**, it gave it to us straight... only **port 80** here :D

The home page shows *nothing special*. Just a bottle of **Tartar Sauce.**

![](/assets/TartarSauce/home-page-tartar-sauce.jpg)

`robots.txt` shows us **a few urls to try**. So we whip up a ***quick and fancy*** **bash script** to check all 5 of them.

```bash
for url in `curl -s http://tartarsauce/robots.txt | tail -n 6 | sed 's/Disallow: /http:\/\/tartarsauce/g'`; do echo Curling $url; curl -I $url; done
```

![](/assets/TartarSauce/curling-robots-txt.jpg)

Only `http://tartarsauce/webservices/monstra-3.0.4/` was valid. So we check it out.

## The Monstra CMS

Here's what the home page looked like:

![](/assets/TartarSauce/monstra-homepage.jpg)

most links on it led to a `404 - Not Found` *except for the* **login form**:

![](/assets/TartarSauce/monstra-login-page.jpg)

we could log in with `admin:admin`

![](/assets/TartarSauce/monstra-logged-in.jpg)

*however,* we **couldn't abuse any functionalities** to get **RCE**.

**Check #1:** **Uploading a reverse shell** failed.

![](/assets/TartarSauce/monstra-file-upload-fail.jpg)

**Check #2:** **Installing a malicious plugin..** the same.

![](/assets/TartarSauce/monstra-install-plugin-fail.jpg)

**Check #3:** **Editing themes to insert PHP...** no dice :/

![](/assets/TartarSauce/monstra-editing-themese.jpg)

![](/assets/TartarSauce/monstra-editing-themes-2.jpg)

*After* ***all the exploits on ExploitDB failed,*** we decided **"Monstra was relatively secure"** and it was ***time to look elsewhere :D***

![](/assets/TartarSauce/monstra-exploit-db-fail.jpg)

## Finding a Wordpress Instance

*After running a quick* `gobuster`, we found ***another web directory:*** `wp`

![](/assets/TartarSauce/finding-wordpress.jpg)

it contained a **Wordpress** blog

![](/assets/TartarSauce/wordpress-homepage.jpg)

*Naturally,* we run `wpscan` to enumerate `-e`:
- All **plugins** `ap`
- All **themes** `at`
- **Timthumbs** `tt`
- **Config backups** `cb`
- **Database exports** `dbe`
- And **Users** `u`

**Important to note:** adding the `--plugins-detection` flag with the `aggressive` mode is **key** in this step.

That's because the recent versions of `wpscan` -*by default*- use the -*too polite and gentle*- `passive` mode which **won't detect any plugins** and thus **block the main exploitation path**.

That part took me a while to figure out \****smiles in pain***\*.

Here's the command:

```bash
wpscan --url http://tartarsauce/webservices/wp/ -e ap,at,tt,cb,dbe,u --plugins-detection aggressive -t 50
```

The output shows **a total of 3 plugins:**

![](/assets/TartarSauce/wordpress-plugins.jpg)

the `Gwolle Guestbook` plugin turned out to have **a Remote File Inclusion vulnerability**

![](/assets/TartarSauce/wordpress-vuln-plugin.jpg)

*Following the exploit steps,* we:
1. **Copy our favourite PHP reverse shell** `/usr/share/webshells/php/php-reverse-shell.php` to `rev.txt`
2. **Modify** the `ip` and `port` variables
3. **Serve it** on a `python` webserver
4. Start a `netcat` listener to **catch the connect back**
5. `curl` the **vulnerable endpoint** placing a question mark `?` at the end. (This is because the plugin appends `wp-load.php` to the request. So we use the `?` to break the url off)

![](/assets/TartarSauce/RFI-2-shell.jpg)

Sweet :D

## Pivoting to Onuma
*After* ***optimizing our shell,*** we get to work.

![](/assets/TartarSauce/shell-pimping.jpg)

*when we type* `sudo -l` *to check our* **sudo privileges**, we find that we can run the `tar` command as the `onuma` user.

![](/assets/TartarSauce/sudo-tar.jpg)

A quick look on [GTFOBins](https://gtfobins.github.io/gtfobins/tar/) tells us that **we can get a shell** with that:

![](/assets/TartarSauce/gtfobins-tar.jpg)

Legit. we're now interacting as `onuma`

![](/assets/TartarSauce/shell-as-onuma.jpg)

## Detecting system operations
*When running a quick* [linpeas.sh](https://github.com/carlospolop/PEASS-ng), we spot a **unique system timer:**

![](/assets/TartarSauce/system-timers.jpg)

and **other files** that stick out

![](/assets/TartarSauce/backup-files-modified.jpg)

We do a quick *case-insensitive* `find` to search for **everything that has the word "backup" in it.**

```bash
find / -type f -iname '*backup*' 2>/dev/null
```

to find a `bash` script in `/usr/bin/backuperer`

![](/assets/TartarSauce/finding-backuperer-script.jpg)

the contents:

```bash
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```
*removing the excess lines and comments,* it's around **30 lines of code**. not too bad I guess :)

## Breaking down "Backuperer"
Let's first tear down all the variables for **absolute paths**
```bash
# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp

testmsg=/var/backups/onuma_backup_test.txt
errormsg=/var/backups/onuma_backup_error.txt

tmpfile=/var/tmp/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=/var/tmp/check
```

all self-explanatory except for the `tmpfile` variable, which is just a `SHA1` value

![](/assets/TartarSauce/sha1sum.jpg)

next, the `printbdr` function

```bash
# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)
```

it just **creates a border** for **nice formatting**

![](/assets/TartarSauce/bdr-function.jpg)

then, the script:
- **does some cleanup from older runs**
- **tars up** the `basedir` (`/var/www/html`) into `tmpfile` (`/var/tmp/.<SHA1SUM>`)
- then **sleeps for 30 seconds.** *(This is in case the backup process takes longer than expected.)*

```bash
# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30
```

The following is a **function** that does a ***recursive*** `diff` between `basedir` (`var/www/html`) and `check+basedir` (`/var/tmp/check/var/www/html`)

```bash
# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}
```

here's a quick **example** of how a recurse diff works:

![](/assets/TartarSauce/recursive-diff-example.jpg)

This function would make much more sense with the lines that follow:
- creating the `check` directory (`/var/tmp/check`)
```bash
/bin/mkdir $check
```
- extracting the `tmpfile` (`/var/tmp/.<SHA1SUM>`) into it
```bash
/bin/tar -zxvf $tmpfile -C $check
```

The **integrity check** is **validation** that **the backup** *exactly matches* the **backed up data.**

```bash
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

## Exploiting tar to root the box

There's **a way to escalate our privileges** to `root`

Because:
1. The script **backs up the website** into `/var/tmp/.<SHA1SUM>` as `onuma` (*we own this user and this makes that archive writable*)
2. It then **sleeps for 30 seconds**. which is **enough time** for us to ***swap the archive with a malicious one***
3. **creates** a `check` directory, **extracting** the contents of the -***then manipulated***- `/var/tmp/.<SHA1SUM>` into it before doing the integrity check

**The key here** is that: **everything the script extracts would be owned by root!**

So we just need to:
1. **Create an SUID shell** and **embed it within a tar archive**
2. **Wait for the first backup to complete** (`/var/www/html` to `/var/tmp/.<SHA1SUM>`)
3. **Replace** the `/var/tmp/.<SHA1SUM>` with **the one we created**
4. **Wait for the extraction** to be done by `root` into the `check` directory
5. **Go within the extracted contents** and **run the root shell :)**

*But before executing this evil plan,* let's first observe the script in action:

We'll go to `/var/tmp` and do a `watch` command to **keep an eye** on **the timer** (`systemctl list-timers`) as well as **the directory contents** (`ls -la`)

```bash
cd /var/tmp
watch -n 1 'systemctl list-timers; ls -la'
```

here, the `/var/tmp` directory is empty before any execution

![](/assets/TartarSauce/watching-timers-and-contents.jpg)

*26 seconds after the code ran,* notice the `SHA1` (`$tmpfile`) got created.

it's owned by `onuma` (*since it's the output of* **line 35**)
```bash
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &
```

![](/assets/TartarSauce/tmp-file-creation.jpg)

*After the 30-second sleep interval has passed,* the `check` directory (`$check`) is now there with the contents of the `$tmpfile` inside.

it's owned by `root` (*as it's the output of* **line 47**)
```bash
/bin/tar -zxvf $tmpfile -C $check
```

![](/assets/TartarSauce/check-directory-created.jpg)

*Having seen everything up close,* let's prepare the **SUID shell**

![](/assets/TartarSauce/killershell-c.jpg)

We compile it using `gcc` with the `-m32` flag to **match the victim's architecture**

![](/assets/TartarSauce/victim-arch.jpg)

*Even though we got a warning,* it's been successfully compiled

![](/assets/TartarSauce/compiling-killer-shell.jpg)

We make sure to **add the SUID bit** and **create the same directory structure** (`/var/www/html`) within the archive.

![](/assets/TartarSauce/crafting-killer-tar.jpg)

we then **transfer it over** and **overwrite** the `SHA1` file ***as soon as the file length stabilizes.*** (*to avoid interrupting the first backup*)

we **wait 30 seconds for the extraction** to be done in the `check` directory.

*going into the extract,* a sweet **SUID shell** is there waiting for us :D

it's all in the image below:

![](/assets/TartarSauce/tar-ownage-for-root.jpg)

**Wicked!**