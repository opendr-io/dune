
# Common Well-Known TCP Ports (0 – 1023)

port	service	description	event
20 / 21	FTP	File Transfer Protocol (Data / Control)	true
22	SSH	Secure Shell (remote command-line access)	true
23	Telnet	Unencrypted text communications	true
25	SMTP	Simple Mail Transfer Protocol (email routing)	false
43	WHOIS	WHOIS directory lookups (domain / IP registration)	true
53	DNS	Domain Name System (also uses UDP)	false
67 / 68	DHCP	Dynamic Host Configuration Protocol	false
69	TFTP	Trivial File Transfer Protocol	true
80	HTTP	Hypertext Transfer Protocol (unencrypted web traffic)	false
88	Kerberos	Network authentication protocol	false
110	POP3	Post Office Protocol version 3 (retrieving email)	false
119	NNTP	Network News Transfer Protocol	false
123	NTP	Network Time Protocol	false
135	RPC	Microsoft Remote Procedure Call	true
139	NetBIOS	NetBIOS Session Service	true
143	IMAP	Internet Message Access Protocol	false
161 / 162	SNMP	Simple Network Management Protocol	false
179	BGP	Border Gateway Protocol	false
389	LDAP	Lightweight Directory Access Protocol	false
443	HTTPS	HTTP Secure (encrypted web traffic)	false
445	SMB	Server Message Block (file sharing)	true
514	Syslog	Computer message logging	false
636	LDAPS	LDAP over TLS/SSL	false

#Common Registered TCP Ports (1024 – 49151)

port	service	description	event
873	rsync	Remote file synchronization	true
989 / 990	FTPS	FTP over TLS/SSL	true
993	IMAPS	IMAP over TLS/SSL	false
995	POP3S	POP3 over TLS/SSL	false
3306	MySQL	MySQL database server	false
3389	RDP	Remote Desktop Protocol	true
5432	PostgreSQL	PostgreSQL database server	false
5900	VNC	-	true
8080	HTTP-Proxy	Alternative HTTP web traffic / proxy port	false


