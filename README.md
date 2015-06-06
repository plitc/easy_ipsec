
Background
==========
easy_ipsec for ipv4 vpn relay setup

https://blog.plitc.eu/2014/freebsd-10-ipv4-vpn-relay-ipsec-entryopenvpn-middleopenvpn-exit-node-mit-jails/

WARNING
=======
* if you use more than 1 roadwarrior clients in the same subnet -> they need different "public" transport gateway ips (if possible)
* for example:
   * laptop 1 with mac os:
     * local network ip AAA.AAA.AAA.101 - default routing over ISP1 gateway YYY.YYY.YYY.1
   * laptop 2 with debian linux:
     * local network ip BBB.BBB.BBB.102 - default routing over ISP2 gateway ZZZ.ZZZ.ZZZ.2
* this limitation comes from the ipsec "main mode"

Dependencies
============
* MacOS
   * brew
   * dialog
   * tunnelblick

* FreeBSD
   * racoon/ipsec-tools
   * openvpn

* Linux
   * dialog
   * iputils-ping
   * strongswan (ikev1)
   * openvpn

Features
========
easy ipsec configuration

Platform
========
* MacOS X 10.5+
* FreeBSD 10+
* Linux / Debian 8 (Jessie)

Usage
=====
    # ./easy_ipsec.sh

Errata
======
* failed after delete system-logs (MacOS)

