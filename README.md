# CEH Notes

Thes are my notes for CEH.

# Module 3 : 

## TCP Flags :

- Syn :  notify a nw sequence number. (etablish connection)
- ACK : confirme la reception et identify the next expected sequence
- PSH : Start and end of data transmission.
- URG : Process the data asap.
- FIN : No more transmission will be send 
- RST : When there is an error. It abort the transmission

## Initialisation TCP
SYN -> SYN ACK -> ACK 

## Fin TCP 

FIN -> 
<- ACK
<- FIN
ACK ->

## Scanning Tools

- nmap
nmap /options/  /Target IP/

- Hping2/Hping3 
hping /options/ /target ip/

- Metasploit

- NetScanToolspro



### icmp scanning 
see of host are up by sending ping or icmp
hping3 -1 10.0.0.25 

### ACK scan on port 80
checking if there is a firewall that block the connections.
hping3 –A 10.0.0.25 –p 80

### UDP scan on port 80 

hping3 -2 10.0.0.25 –p 8

### Intercept all traffic containing HTTP signature

Ex. hping3 -9 HTTP –I eth0

### SYN flooding a victim 

hping3 -S 192.168.1.1 -a 192.168.1.254 -p 22 --flood 
The attacker employs TCP SYN flooding techniques using spoofed IP addresses to perform a DoS attack.

## Scanning for mobile

- IP Scanner

- Fing 

- Network Scanner

## Host discovery 

- ARP Ping Scan 

netmap -rp 

- UDP Ping scan

netmap -PU

## ICMP ECHO Ping Scan

Does icmp pass thgrough firewall ? ICMP ECHO -> ICMP ECHO

nemap -PE

## ICMP ECHO Ping Sweep

Slow method. 

### Tools for ping sweep 

- Angry IP Scanner

## Ping sweep contermeasure

- Configure well the firewall 
- use IDS 
- Carefully evaluate ICMP traffic
- Terminate connection with host that make more than 10 Echo requests
- Use DMZ with basic commands allowed 
- Use ACL's

## TCP SYN Ping Scan

- Machine can be scanned parallely 
- Determine if host is up without connection, so not recorded in logs.

## TCP ACK Ping Scan

Same as SYN but less firewall are configured to counter it.

## IP Protocol Ping Sca

Send a lot if different packets for ICMP.

nmap -PO

## Port Scanning Technique

### TCP Connect/Full Open Sca

Most reliable. Full tcp 3 way handshake. 
nmap -sT

### Stealth Scan

Abort before the end of the Handshake, it bypasses firewall and logging system.
nmap -sS

### Inverse TCP Flag Sca

Send FIN,URG or PSH flag, if port is open = no answer. If port closed = RST from host.

### SSDP and List Scanning
Simple Service Discovery Protocol (SSDP) is a network protocol that generally communicates with machines when querying them with routable IPv4 or IPv6 multicast addresses. 

## Os discorvery / Banner grabbing

### Active Banner Grabbing

Sending bad ICMP packets and comparing the response to a os base response database. 

### Passive Banner Grabbing

Instead of sendind packets and scanning, it sniff to study telltale that can reveal OS.

Avec le TTL et le WIndows Size on peut determiner l'OS

----------------

- Nmap
- Unicornscan
- Nmap NSE
- Wireshark

## Countermeasures 

- fisplay false banner
- only necessary service
- use ServerMask
- Hide file extension 

## Scanning Beyond IDS and Firewall

- **Packet Fragmentation**: The attacker sends fragmented probe packets to the intended target, which reassembles the fragments after receiving all of them.
- **Source Routing**: The attacker specifies the routing path for the malformed packet to reach the intended target.
-  **Source Port Manipulation**: The attacker manipulates the actual source port with the common source port to evade the IDS/firewall.
- **IP Address Decoy**: The attacker generates or manually specifies IP addresses of decoys so that the IDS/firewall cannot determine the actual IP address.
- **IP Address Spoofing**: The attacker changes the source IP addresses so that the attack appears to be coming from someone else.
- **Randomizing Host Order**: The attacker scans the number of hosts in the target network in a random order to scan the intended target that lies beyond the firewall.
- **Creating Custom Packets**: The attacker sends custom packets to scan the intended target beyond the firewalls.
- **Sending Bad Checksums**: The attacker sends packets with bad or bogus TCP/UPD checksums to the intended target
- **Proxy Servers**: The attacker uses a chain of proxy servers to hide the actual source of a scan and evade certain IDS/firewall restrictions.
- **Anonymizers**: The attacker uses anonymizers, which allows them to bypass Internet censors and evade certain IDS and firewall rules.




# Module 4 

*In the enumeration phase, attackers enumerate usernames and other information on the groups, network shares, and services of networked computers.*


## Techniques for Enumeration

- **Extract usernames using email ID** : username@domain
- **Extract information using default password**
- **Brute force Active Directory**
- **Extract information using DNS Zone Transfer** : Si on fais une zone transfert on peut avoir les info en clair
- **Extract user groups from Windows** : interface windows simple 
- **Extract usernames using SNMP** :  utiliser l'API SNMP.



## NetBios 

- The list of computers that belong to a domai
- The list of shares on the individual hosts in a network
- Policies and password

**NbstatUtility** : troubleshooting NETBIOS name resolution problems. Attackers use Nbtstat to enumerate information such as NetBIOS over TCP/IP (NetBT) protocol statistics NetBIOS name tables for both local and remote computers, and the NetBIOS name cache.

**Netbios Enumerator**  : API to enumerate infos 

**Nmap NSE**: tmtc nbstat.nse

## SNMP Enumeration 

SNMP enumeration tools are used to scan a single IP address or a range of IP addresses of SNMP-enabled network devices to monitor, diagnose, and troubleshoot security threats. 

**Management Information Base (MIB)** : MIB is a virtual database containing a formal description of all the network objects that SNMP manages.

**Communication process**

Host x request for active session -> host Y check if host x in MIB. if not send error to known host Z

## SNNMP Enumeration tools

**Snmpcheck** : contact, description, write access, devices, domain, hardware and storage information, hostname, Internet Information Services (IIS) statistics, IP forwarding, listening UDP ports, location, mountpoints, network interfaces, network services, routing information, software components, system uptime, TCP connections, total memory, uptime, and user accounts.

**SoftPerfect Network Scanner** : SoftPerfect Network Scanner can ping computers, scan ports, discover shared folders, and retrieve practically any information about network devices


## LDAP Enumeration

lighweight directory access procotol

**Softerra LDAP Administraton** : tools to enumerate every info in a ldap server

## NTP and NFS Enumeration 

### NTP 

Network time protocol

- List of connected hosts
- Client IP, Os and names
- Internal IP if NTP is in DMZ

| Command | Description |
| ----------- | ----------- |
| ntpdate | collects the number of time samples from several time sources. |
| ntptrace | This command determines where the NTP server obtains the time from and follows the chain of NTP servers back to its primary time source. Attackers use this command to trace the list of NTP servers connected to the network.  |
| ntpdc | This command queries the ntpd daemon about its current state and requests changes in that state. Attackers use this command to retrieve the state and statistics of each NTP server  |
| ntpq | This command monitors the operations of the NTP daemon ntpd and determines performance.   |

**PRTG Network Monitor** : PRTG monitors all systems, devices, traffic, and applications of IT infrastructure by using various technologies such as SNMP, WMI, and SSH.


### NFS 

Network file system
NFS is a type of file system that enables users to access, view, store, and update files over a remote server. 

| Command | Description |
| ----------- | ----------- |
| rpcinfo -p 10.10.10. | scan the target IP address for an open NFS port (port 2049) and the NFS services running on it |
| showmount -e 10.10.10.1 | view the list of shared files and directories  |

**RPCScan** : RPCScan communicates with RPC services and checks misconfigurations on NFS share.
Python3 rpc-scan.py 10.10.10.19 --rpc

**SuperEnum** : SuperEnum includes a script that performs the basic enumeration of any open port. 

## SMTP and DNS Enumeration

### SMTP Enumeration Too

**NetScanTools Pr** : NetScanTools Pro’s SMTP Email Generator tool tests the process of sending an email message through an SMTP server. Attackers use NetScanTools Pro for SMTP enumeration and extract all the email header parameters, including confirm/urgent flags. 

**smtp-user-enum** : smtp-user-enum is a tool for enumerating OS-level user accounts on Solaris via the SMTP service (sendmail). 

### DNS Enumeration Using Zone Transfer

DNS zone transfer is the process of transferring a copy of the DNS zone file from the primary DNS server to a secondary DNS server.
An attacker performs DNS zone transfer enumeration to locate the DNS server and access records of the target organization.

#### dig Command 

Attackers use the dig command on Linux-based systems to query the DNS name server.

| Command | Description |
| ----------- | ----------- |
| dig ns <target domain |retrieves all the DNS name servers of the target domain. Next, attackers use one of the name servers from the output of the above command to test whether the target DNS allows zone transfers. |
| dig @ axfr|  Next, attackers use one of the name servers from the output of the above command to test whether the target DNS allows zone transfers. |

**nslookup Command** : Attackers use the nslookup command on Windows-based systems to query the DNS name servers and retrieve information about the target .

**DNSRecon** :: Attackers use DNSRecon to check all NS records of the target domain for zone transfers.
dnsrecon -t axfr -d "target domain"

### DNS Cache Snooping

DNS cache snooping is a type of DNS enumeration technique in which an attacker queries the DNS server for a specific cached DNS record. By using this cached record, the attacker can determine the sites recently visited by the user.

### DNSSEC Zone Walking

Domain Name System Security Extensions (DNSSEC) zone walking is a type of DNS enumeration technique in which an attacker attempts to obtain internal records if the DNS zone is not properly configured.

**LDNS** : LDNS-walk enumerates the DNSSEC zone and obtains results on the DNS record files. 

**DNSRecon** : DNSRecon is a zone enumeration tool that assists users in enumerating DNS records such as A, AAAA, and CNAME. It also performs NSEC zone enumeration to obtain DNS record files of a target domain.

## IPsec Enumeration

IPsec is the most commonly implemented technology for both gateway-to-gateway (LAN-to-LAN) and host-to-gateway (remote access) enterprise VPN solutions. 

Attackers can perform simple direct scanning for ISAKMP at UDP port 500 with tools such as Nmap to acquire information related to the presence of a VPN gateway

nmap –sU –p 500 /target IP address/

Attackers can probe further using fingerprinting tools such as ike-scan to enumerate sensitive information, including the encryption and hashing algorithm, authentication type, key distribution algorithm, and SA LifeDuration. 

**ike-scan –M target gateway IP address**
- Discovery of host
- Fingerprinting -> IKe version, soft versions etc..
- Transform enumeration -> supported by the vpn
- User Enumertion
- Pre-shared key craking

## VoIP Enumeration

VoIP is an advanced technology that has replaced the conventional public switched telephone network (PSTN) in both corporate and home environments. 

Attackers use Svmap and Metasploit tools to perform VoIP enumeration. 

**Svmap** is an open-source scanner that identifies SIP devices and PBX servers on a target network.
**svmap (target network range)**

## RPC Enumeration

The remote procedure call (RPC) is a technology used for creating distributed client/server programs.

Attackers use the following Nmap scan commands to identify the RPC service running on the network : 

nmap -sR <target IP/network>
nmap -T4 –A <target IP/network>

Additionally, attackers use tools such as NetScanTools Pro to capture the RPC information of the target network. 

## Unix/Linux User Enumeratio

| Command | Description |
| ----------- | ----------- |
| rusers | rusers displays a list of users who are logged in to remote machines or machines on the local network. |
| rwho | rwho displays a list of users who are logged in to hosts on the local network. |
| finger | finger displays information about system users such as the user’s login name, real name, terminal name, idle time, login time, office location, and office phone numbers. |

							

## Telnet Enumeration 

As shown in the screenshot, the following Nmap command is used by attackers to enumerate the Telnet service running on the target system:
nmap -p 23 target domain

Attackers can further use the following script to enumerate information from remote Microsoft Telnet services with New Technology LAN Manager (NTLM) authentication enabled:

**nmap -p 23 --script telnet-ntlm-info **
 
Once the information about the target server is obtained, the attackers can use the following script to perform a brute-force attack against the Telnet server:

**nmap -p 23 –script telnet-brute.nse –script-args userdb=/root/Desktop/user.txt,passdb=/root/Desktop/pass.txt**

## SMB Enumeration

Server Message Block (SMB) is a transport protocol that is generally used by Windows systems for providing shared access to files, printers, and serial ports as well as remote access to Windows services.

As shown in the screenshot, attackers use the following Nmap command to enumerate the SMB service running on the target IP address: 
**nmap -p 445 -A target IP**

The STATE of PORT 445/tcp is OPEN, which indicates that port 445 is open and that the SMB service is running. By using this command, attackers can also obtain details on the OS and traceroute of the specified targe

## FTP Enumeration

The File Transfer Protocol (FTP) is used to transfer files over TCP, and its default port is 21. In FTP, data are transferred between a sender and receiver in plaintext, exposing critical information such as usernames and passwords to attackers. 

As shown in the screenshot, the following Nmap command is used by the attackers to enumerate the FTP service running on the target domain: 
**nmap -p 21 target domain**

## IPv6 Enumeratio

### Enyx 
Enyx is an enumeration tool that fetches the IPv6 address of a machine through SNMP.
As shown in the screenshot, attackers use the following command to enumerate the IPv6 address of a target machine (10.10.10.20) by setting the SNMP version to 2c and community string to public: 

**Python enyx.py 2c public target **


### IPv6 Hackit

Hackit is a scanning tool that provides a list of active IPv6 hosts. It can perform TCP port scanning and identify AAAA IPv6 host records.

###  BGP Enumeration

Attackers perform BGP enumeration on the target using tools such as Nmap and BGP Toolkit to discover the IPv4 prefixes indicated by the AS number and the routing path followed by the target.

 **nmap -p 179 target IP**
 
 



