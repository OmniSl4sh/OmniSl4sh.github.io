---
layout: post
title:  "HTB Writeup [Linux - Hard] - Unobtainium"
published: false
---

![](/Assets/Box/Box.png)

## Summary
- Unobtainium is a Linux box which hosted a kubernetes cluster and served both a static website on port 80 and a Node JS web app on port 31337.
- We find a debian package on the main page of the port 80 website. We extract it to know that it was an Electron JS application.
- After reversing it, we found that would chain a prototype pollution vulnerability with a command injection one to gain RCE.
- We get on a container as `root` and start to check our privileges on the cluster using `kubectl` which we upload.
- We had the privileges to list all namespaces in the cluster. Which we used to discover another namespace called `dev` where other pods existed.
- When we scan the other pods, we find one of them having same vulnerable web app hosted. So we exploit the same chain and pivto to it.
- One the second container, we had the privilege of viewing the cluster's secrets. Among which was a special admin token that could perform all actions on the cluster.
- To finally exploit the host, we use a kubernets-specific tool called Peirates to write a Cron job for a reverse shell as `root` and catch it to own the box.

---

## NMAP