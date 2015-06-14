
Background
==========
based on [FreeBSD 10: IPv4 VPN Relay (IPsec entry/OpenVPN middle/OpenVPN exit node) mit Jails für Roadwarrior](https://blog.plitc.eu/2014/freebsd-10-ipv4-vpn-relay-ipsec-entryopenvpn-middleopenvpn-exit-node-mit-jails/)

WARNING
=======
* if you use more than 1 roadwarrior clients in the same subnet -> they need different "public" transport gateway ips (if possible)
* for example:
   * laptop 1 with mac os:
     * local network ip AAA.AAA.AAA.101 - default routing over ISP1 gateway YYY.YYY.YYY.1
   * laptop 2 with debian linux:
     * local network ip BBB.BBB.BBB.102 - default routing over ISP2 gateway ZZZ.ZZZ.ZZZ.2
* this limitation comes from the ipsec "main mode" function and the "my_identifier" is address based

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
   * [iputils-ping](https://packages.debian.org/stretch/iputils-ping)
   * [strongswan (ikev1)](https://packages.debian.org/stretch/strongswan)
   * [openvpn](https://packages.debian.org/stretch/openvpn)

* Windows
   * [PowerShell](https://www.microsoft.com/en-us/download/details.aspx?id=34595)
   * [Github on Windows](https://windows.github.com/) (optional)

Features
========
easy ipsec configuration

Platform
========
* MacOS X 10.6+
* FreeBSD 10+
* Linux / Debian 8+
* Windows 7+

Usage
=====
    # ./easy_ipsec.sh

Usage (for Windows)
===================
```
   Set-ExecutionPolicy Unrestricted

   & "C:\github\easy_ipsec\easy_ipsec_win.ps1"
```

Screencast
==========
* github plitc easy_ipsec
  * freebsd racoon server <-> linux strongswan client

[![github plitc easy_ipsec](https://img.youtube.com/vi/GX6whhD096Y/0.jpg)](https://www.youtube.com/watch?v=GX6whhD096Y)

Errata
======
* 14.06.2015: reconnect after 1h 15 min
```
64 bytes from 172.31.254.254: icmp_seq=4931 ttl=64 time=18 ms

64 bytes from 172.31.254.254: icmp_seq=4945 ttl=64 time=16 ms
```

* 06.06.2015: NAT issues (tcpdump)
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

