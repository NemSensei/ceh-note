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


