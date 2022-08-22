---
layout: post
title:  "HTB Writeup [Linux - Medium] - TartarSauce"
published: false
---

![](/assets/TartarSauce/TartarSauce.png)

### Summary
- TartarSauce is a linux machine where only port 80 was open.
- The `robots.txt` file had entries for a CMS called Monstra which we could log on to using weak credentials.
- Even though the CMS version was vulnerable, we couldn't exploit any of the file upload CVEs due to restricted write access. so we looked elsewhere.
- After we did some web directory brute forcing, we discover a WordPress instance which happened to have a plugin vulnerable to RFI.
- We successfully exploit the vulnerability and get Remote Code Execution.
- With `www-data`, we find that we can run the `tar` command as the `onuma` user. We exploit that and get ourselves a shell as that account.
- Running `linpeas.sh` for privilege escalation shows us a system timer that runs a script (`backuperer`) every 5 minutes.
- Since that script ran as root, we analyzed it to find that it `untar`s an archive that we can control during its execution.
- By inserting an SUID shell into a tar archive of our own, and then replacing the initial archive with it. we take advantage of the `backuperer` script to extract our SUID shell and becoming its owner in the process. Thus giving us a root shell ;]

---

### NMAP
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

Nmap gave it to us straight. It's only port 80 on this box :D

The home page shows nothing special. Just a bottle of Tartar Sauce.

![](/assets/TartarSauce/home-page-tartar-sauce.jpg)

`robots.txt` gives a few urls to try. So we whip up a quick and fancy bash script to check all 5 of them.

```bash
for url in `curl -s http://tartarsauce/robots.txt | tail -n 6 | sed 's/Disallow: /http:\/\/tartarsauce/g'`; do echo Curling $url; curl -I $url; done
```

![](/assets/TartarSauce/curling-robots-txt.jpg)

Only `http://tartarsauce/webservices/monstra-3.0.4/` was valid. So we check it out.

### Checking out the Monstra CMS

![](/assets/TartarSauce/monstra-homepage.jpg)

Most links on the web page led to `404 - Not Found` except for the login form:

![](/assets/TartarSauce/monstra-login-page.jpg)

we could log in with `admin:admin`

![](/assets/TartarSauce/monstra-logged-in.jpg)

However, we couldn't abuse any functionalities to get RCE.

Uploading a reverse shell failed.

![](/assets/TartarSauce/monstra-file-upload-fail.jpg)

Installing a malicious plugin. The same.

![](/assets/TartarSauce/monstra-install-plugin-fail.jpg)

Editing themes to insert PHP. No dice :/

![](/assets/TartarSauce/monstra-editing-themese.jpg)

![](/assets/TartarSauce/monstra-editing-themes-2.jpg)

After testing the exploits on ExploitDB and still failing, we decided it's time to look elsewhere :D

![](/assets/TartarSauce/monstra-exploit-db-fail.jpg)

### Finding a Wordpress Instance

After running a quick `gobuster`, we found another directory: `wp`

![](/assets/TartarSauce/finding-wordpress.jpg)

![](/assets/TartarSauce/wordpress-homepage.jpg)

We launch an aggressive `wpscan` on the blog to enumerate `-e`:
- All plugins `ap`
- All themes `at`
- Timthumbs `tt`
- Config backups `cb`
- Database exports `dbe`
- And, Users `u`

Using the `--plugins-detection` flag with the `aggressive` mode is key here. `wpscan` uses the too gentle `passive` mode by default which won't detect anything.

That part took me a while to figure out \*smiles in pain\*. Here's the command:

```bash
wpscan --url http://tartarsauce/webservices/wp/ -e ap,at,tt,cb,dbe,u --plugins-detection aggressive -t 50
```

![](/assets/TartarSauce/wordpress-plugins.jpg)

The `Gwolle Guestbook` plugin turned out to have a RFI vulnerability

![](/assets/TartarSauce/wordpress-vuln-plugin.jpg)

Following the exploit steps, we:
1. Copy the PHP reverse shell `/usr/share/webshells/php/php-reverse-shell.php` to `rev.txt`
2. Modify the `ip` and `port` variables
3. Serve them on a `python` webserver
4. Start a `netcat` listener to catch the reverse shell
5. `curl` the vulnerable endpoint making sure to place a question mark `?` at the end. (That's because the plugin appended `wp-load.php` to the request. So we use the `?` to break off the url from the query string.)

![](/assets/TartarSauce/RFI-2-shell.jpg)

Sweet :D

### Pivoting to Onuma
After optimizing our shell, we get to work.

![](/assets/TartarSauce/shell-pimping.jpg)

when we type `sudo -l` to check our sudo privileges, we find that we can run the `tar` command as the `onuma` user.

![](/assets/TartarSauce/sudo-tar.jpg)

This can get us a shell :D

A quick look on [GTFOBins](https://gtfobins.github.io/gtfobins/tar/) can confirm that:

![](/assets/TartarSauce/gtfobins-tar.jpg)

![](/assets/TartarSauce/shell-as-onuma.jpg)

### Detecting system operations
When running a quick [linpeas.sh](https://github.com/carlospolop/PEASS-ng), we spot a unique system timer:

![](/assets/TartarSauce/system-timers.jpg)

And notice other files that stick out

![](/assets/TartarSauce/backup-files-modified.jpg)

We do a quick `find` to search for everything that has the word "backup" in it.

```bash
find / -type f -iname '*backup*' 2>/dev/null
```

We find a `bash` script doing the backup

![](/assets/TartarSauce/finding-backuperer-script.jpg)

Here were its contents:

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

### Breaking down "Backuperer"
Let's first tear down all the variables for absolute paths
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

the `tmpfile` variable is just a sha1 value

![](/assets/TartarSauce/sha1sum.jpg)

Next, the `printbdr` function

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

it just creates a border for nice formatting

![](/assets/TartarSauce/bdr-function.jpg)

There, the script does some cleanup from old runs, tars up the `basedir` (`/var/www/html`) into `tmpfile` (`/var/tmp/.<SHA1SUM>`) then sleeps for 30 seconds.

This is in case the backup process takes longer than expected.

```bash
# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30
```

The following is a function that does a recursive `diff` between `basedir` (`var/www/html`) and `check+basedir` (`/var/tmp/check/var/www/html`)

```bash
# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}
```

here's an exampe of how it works:

![](/assets/TartarSauce/recursive-diff-example.jpg)

but that function makes more sense with the two actions below.
- creating the `check` directory (`/var/tmp/check`)
- extracting the `tmpfile` (`/var/tmp/.<SHA1SUM>`) into it

```bash
/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
```

### Exploiting tar to root the box

without continuing on with what the rest of the script does, we now have an exploitable situation :D

That's because:
1. the script backs up the website into `/var/tmp/.<SHA1SUM>`
2. waits for 30 seconds --> which is enough time for us to change the archive
3. creates a `check` directory, extracts the contents of the `/var/tmp/.<SHA1SUM>` into it and starts doing the integrity checks

The key here is that: everything the `/usr/bin/backuperer` script extracts would be owned by root!

So we just need to:
1. Create an SUID shell and embed it within a tar archive
2. Wait for the first backup to complete (`/var/www/html` to `/var/tmp/.<SHA1SUM>`)
3. Replace the `/var/tmp/.<SHA1SUM>` with the one we created
4. Wait for the extraction to be done by root into the `check` directory
5. Go within the extracted contents and run the root shell :)

Let's see it in action.

We'll first change to `/var/tmp` and do a `watch` command to keep an eye on the timers (`systemctl list-timers`) and observe the directory contents (`ls -la`)

```bash
cd /var/tmp
watch -n 1 'systemctl list-timers; ls -la'
```

The `/var/tmp` directory is empty before script execution

![](/assets/TartarSauce/watching-timers-and-contents.jpg)

less than 30 seconds after the code ran. Notice the `SHA1` (`$tmpfile`) created.

it's owned by `onuma` since it's the output of line 35:
```bash
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &
```

![](/assets/TartarSauce/tmp-file-creation.jpg)

After 30 seconds have passed, the `check` directory (`$check`) is now there and the contents of the `$tmpfile` are within.

it's owned by `root` as it's the output of line 47:
```bash
/bin/tar -zxvf $tmpfile -C $check
```

![](/assets/TartarSauce/check-directory-created.jpg)

Having seen everything up close, let's prepare an SUID shell:

![](/assets/TartarSauce/killershell-c.jpg)

And compile it using the `-m32` flag to match the victim's architecture:

![](/assets/TartarSauce/victim-arch.jpg)

Even though we got a warning, it's been compiled successfully.

![](/assets/TartarSauce/compiling-killer-shell.jpg)

We make sure to add the SUID bit and create the same directory structure.

![](/assets/TartarSauce/crafting-killer-tar.jpg)

We then transfer the archive over, copy it over the `SHA1` file as soon as the file length stabilizes.

Then wait for the extraction to be done in the `check` directory.

Going into the extract, SUID shell is waiting for us to root the box :D

![](/assets/TartarSauce/tar-ownage-for-root.jpg)

Wicked!