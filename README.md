
Background
==========
easy_ipsec for ipv4 vpn relay setup

https://blog.plitc.eu/2014/freebsd-10-ipv4-vpn-relay-ipsec-entryopenvpn-middleopenvpn-exit-node-mit-jails/

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

