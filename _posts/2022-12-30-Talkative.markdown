---
layout: post
title:  "HTB Writeup [Linux - Hard] - Talkative"
published: false
---

![](/Assets/Box/Box.png)

## Summary
- Talkative is an extremely fun Linux box where we exploit 3 different web applications to gain RCE on 3 different containers to finally gain root on the host.
- The intial exploitation is on an analytics web app called Jamovi that was on port 8080. It had a module called "RJ Editor" which gave us access to run system commands using the R language.
- After using an R reverse shell, we get on a container as root.
- In `/root`, find an archive that container passwords for 3 users: `matt`, `janit` and `saul`.
- Reusing the passwords on the Bolt CMS instance on port 80, we login as `admin` but with `saul`'s password.
- Because Bolt CMS used thed Twig PHP template engine, we were able to create a template and execute an SSTI payload for another RCE as `www-date` on the second container.
- On the second container, we transferred a binary for `nmap` so we can scan our subnet. we found many hosts with port 80 open, but two ones stuck out with ports 22 for SSH and 27017 for MongoDB.
- We could gain access to the first host through SSH when we used `saul`'s credentials from before. Note: access to SSH was only available from within that container as the port was filtered from the outside.
- And to reach Mongo, we set up chisel to forward any connections from our Kali to that port. We could log in to that database without authentication.
- That DB instance belonged to the Rocket Chat application that was on port 3000. After registering our own user, we modified our privileges by altering the users collection on Mongo.
- With the administrator privilege, we accessed the admin interface and were able to get a third RCE as `root` on the rocket chat application container.
- To finally root the box, we exploit the capabilities granted to our container to get privileged read and write access on the host.
- We could exploit the `cap_dac_read_search` capability to read `/etc/shadow` and `root.txt`.
- But, to fully own the box, we abuse the `cap_dac_override` capability to write our SSH public key into `/root/.ssh/authorized_keys` and get a `root` shell (this is using the 2nd container since it had the SSH client).

---

## NMAP