
Background
==========
based on:
* [FreeBSD 10: IPv4 VPN Relay (IPsec entry/OpenVPN middle/OpenVPN exit node) mit Jails für Roadwarrior](https://blog.plitc.eu/2014/freebsd-10-ipv4-vpn-relay-ipsec-entryopenvpn-middleopenvpn-exit-node-mit-jails/)

WARNING
=======
* if you use more than 1 roadwarrior clients in the same subnet -> they need different "public" transport gateway ips (if possible)
* for example:
   * laptop 1 with mac os:
     * local network ip AAA.AAA.AAA.101 - default routing over ISP1 gateway YYY.YYY.YYY.1
   * laptop 2 with debian linux:
     * local network ip BBB.BBB.BBB.102 - default routing over ISP2 gateway ZZZ.ZZZ.ZZZ.2
* this limitation comes from the ipsec "main mode" function and the "my_identifier" is address based
```
   2015-07-02 12:31:18: ERROR: Expecting IP address type in main mode, but User_FQDN.
```
* IKE main mode with PSK allow id type = IP address only.

Dependencies
============
* MacOS
   * [brew](http://brew.sh/)
   * [dialog](http://brewformulas.org/Dialog)
   * [tunnelblick](http://sourceforge.net/projects/tunnelblick/)

* FreeBSD
   * [racoon/ipsec-tools](https://www.freshports.org/security/ipsec-tools/)
   * [openvpn](https://www.freshports.org/security/openvpn/)

* Linux
   * [dialog](https://packages.debian.org/stretch/dialog)
   * [espeak](https://packages.debian.org/stretch/espeak)
   * [mbrola](https://packages.debian.org/stretch/mbrola)
   * [iputils-ping](https://packages.debian.org/stretch/iputils-ping)
   * [strongswan (ikev1)](https://packages.debian.org/stretch/strongswan)
   * [openvpn](https://packages.debian.org/stretch/openvpn)

* Windows
   * [PowerShell](https://www.microsoft.com/en-us/download/details.aspx?id=34595)
   * [Github on Windows](https://windows.github.com/) (optional)

Features
========
easy ipsec configuration

* MacOS
  * ipsec connection
  * openvpn connection
    * (partial support)

* FreeBSD
  * ipsec connection

* Linux
  * ipsec connection
  * openvpn connection
  * restrictive firewall rules
    * (for ipsec only traffic)

|Protocol | v4   | v6   |
|---------|------|------|
|INPUT    |DROP  |DROP  |
|FORWARD  |DROP  |DROP  |
|OUTPUT   |DROP  |DROP  |
|         |      |      |
|icmp     |ACCEPT| ---- |
|icmpv6   | ---- |ACCEPT|
|dhcp     |ACCEPT| ---- |
|ssh*     |ACCEPT|ACCEPT|
|cifs*    |ACCEPT|ACCEPT|
|udp 500  |ACCEPT|ACCEPT|
|udp 4500 |ACCEPT|ACCEPT|
|esp      |ACCEPT|ACCEPT|
|broadcast|DROP  | ---- |
|multicast|DROP  |DROP  |
|         |      |      |
|openvpn**|ALL   |ALL   |

INFO: *allow only outgoing connections
INFO: **allow all openvpn traffic

* set static/permanent arp entry for the ipsecgatewayip
  * restart (local):
    * minidlna service
    * unbound service

* Windows
  * ipsec connection but NOT works!
    * (windows ipsec support is only up to dhgroup14)

Platform
========
* Mac OS X 10.8+
* FreeBSD 10+
* Linux / Debian 8+
* Windows 8+ / 10+ (Technical Preview)

Usage
=====
    # ./easy_ipsec.sh

Usage (for Windows)
===================
* run as administrator (allow the untrusted powershell scripts)
```
   Set-ExecutionPolicy Unrestricted
```

* run as administrator
```
   PS C:\github\easy_ipsec> .\easy_ipsec_win.ps1
```

Screencast
==========
* github plitc easy_ipsec [VERSION: 01.05.2015]
  * freebsd racoon server <-> linux strongswan client

[![github plitc easy_ipsec](https://img.youtube.com/vi/GX6whhD096Y/0.jpg)](https://www.youtube.com/watch?v=GX6whhD096Y)

* github plitc easy_ipsec strongswan openvpn [VERSION: 01.07.2015]
  * freebsd racoon server <-> linux strongswan client (outside) and openvpn client (inside)

[![github plitc easy_ipsec strongswan openvpn](https://img.youtube.com/vi/Kp3HIMJi3x4/0.jpg)](https://www.youtube.com/watch?v=Kp3HIMJi3x4)

Errata
======
* 14.06.2015: interruption after ~1h 15 min
```
64 bytes from 172.31.254.254: icmp_seq=4931 ttl=64 time=18 ms

64 bytes from 172.31.254.254: icmp_seq=4945 ttl=64 time=16 ms
```

* 06.06.2015: NAT issues? (tcpdump)
```
   NONESP-encap: isakmp: phase 1 I ident
   NONESP-encap: isakmp: phase 1 R ident
   NONESP-encap: isakmp: phase 1 I ident[E]
   NONESP-encap: isakmp: phase 1 R ident[E]
   NONESP-encap: isakmp: phase 1 ? oakley-quick[E]
   NONESP-encap: isakmp: phase 2/others ? inf[E]
   NONESP-encap: isakmp: phase 2/others ? oakley-quick[E]
```

* failed after delete system-logs (MacOS)

