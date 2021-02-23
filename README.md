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

**Softerra LDAP Administrato**

## NTP and NFS Enumeration 

### NTP 

- List of connected hosts
- Client IP, Os and names
- Internal IP if NTP is in DMZ

| Command | Description |
| ----------- | ----------- |
| ntpdate | collects the number of time samples from several time sources. |
| ntptrace | This command determines where the NTP server obtains the time from and follows the chain of NTP servers back to its primary time source. Attackers use this command to trace the list of NTP servers connected to the network.  |
| ntpdc | This command queries the ntpd daemon about its current state and requests changes in that state. Attackers use this command to retrieve the state and statistics of each NTP server  |
| ntpq | This command monitors the operations of the NTP daemon ntpd and determines performance.   |



















