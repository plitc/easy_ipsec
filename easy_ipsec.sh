#!/bin/sh

### LICENSE (BSD 2-Clause) // ###
#
# Copyright (c) 2014, Daniel Plominski (Plominski IT Consulting)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
### // LICENSE (BSD 2-Clause) ###

### ### ### PLITC ### ### ###


### stage0 // ###
UNAME=$(uname)
MYNAME=$(whoami)
### // stage0 ###

### stage1 // ###
case $UNAME in
Darwin)
   ### MacOS ###
BREW=$(/usr/bin/which brew)
MDIALOG=$(/usr/bin/which dialog)
LASTUSER=$(/usr/bin/last | head -n 1 | awk '{print $1}')
LASTGROUP=$(/usr/bin/id "$LASTUSER" | grep -o 'gid=[^(]*[^)]*)' | sed 's/[0-9]//g' | sed 's/gid=(//g' | sed 's/)//g')
#
### ### ### ### ### ### ### ### ###

if [ "$MYNAME" = root ]; then
   echo "" # dummy
else
   echo "<--- --- --->"
   echo ""
   echo "ERROR: You must be root to run this script"
   exit 1
fi

if [ -z "$BREW" ]; then
   echo "<--- --- --->"
   echo "need homebrew"
   echo "<--- --- --->"
        ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
   echo "<--- --- --->"
else
   echo "" # dummy
fi

if [ -z "$MDIALOG" ]; then
   echo "<--- --- --->"
   echo "need dialog"
   echo "<--- --- --->"
        /usr/sbin/chown -R "$LASTUSER:$LASTGROUP" /usr/local
        sudo -u "$LASTUSER" -s "/usr/local/bin/brew install dialog"
   echo "<--- --- --->"
else
   echo "" # dummy
fi

(
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
)

### stage2 // ###

GIF1=50
(
while test $GIF1 != 150
do
echo $GIF1
echo "XXX"
echo "create gif interface: ($GIF1 percent)"
echo "XXX"
#
### run //
/sbin/ifconfig gif0 create > /dev/null 2>&1
/sbin/ifconfig gif0 up
### // run
#
GIF1=$((GIF1 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "create gif interface" 20 70 0

EASYIPSECCLIENTIP="/tmp/easy_ipsec_client_ip.txt"
touch $EASYIPSECCLIENTIP

say "Enter your Roadwarrior Client IP: for example 10.0.0.1" &
dialog --inputbox "Enter your Roadwarrior Client IP: (for example 10.0.0.1)" 8 40 2>$EASYIPSECCLIENTIP

EASYIPSECDESTNET="/tmp/easy_ipsec_destination_net.txt"
touch $EASYIPSECDESTNET

say "Enter your VPN destination network: for example 172.31.254.0" &
dialog --inputbox "Enter your VPN destination network: (for example 172.31.254.0)" 8 40 2>$EASYIPSECDESTNET

EASYIPSECCLIENTIPVALUE=$(sed 's/#//g' $EASYIPSECCLIENTIP | sed 's/%//g')
EASYIPSECDESTNETVALUE=$(sed 's/#//g' $EASYIPSECDESTNET | sed 's/%//g')

GIF2=50
(
while test $GIF2 != 150
do
echo $GIF2
echo "XXX"
echo "set gif options: ($GIF2 percent)"
echo "XXX"
#
### run //
/sbin/ifconfig gif0 "$EASYIPSECCLIENTIPVALUE" "$EASYIPSECDESTNETVALUE"
/sbin/route add -net "$EASYIPSECDESTNETVALUE"/24 -interface gif0 > /dev/null 2>&1
### // run
#
GIF2=$((GIF2 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set gif options" 20 70 0

EASYIPSECSERVERIP="/tmp/easy_ipsec_server_ip.txt"
touch $EASYIPSECSERVERIP

say "Enter your VPN IP security Server IP:" &
dialog --inputbox "Enter your VPN IPsec Server IP:" 8 40 2>$EASYIPSECSERVERIP

EASYIPSECLOCALGATEWAY="/tmp/easy_ipsec_local_gateway.txt"
touch $EASYIPSECLOCALGATEWAY

say "Enter your local gateway IP:" &
dialog --inputbox "Enter your local gateway IP:" 8 40 2>$EASYIPSECLOCALGATEWAY

EASYIPSECSERVERIPVALUE=$(sed 's/#//g' $EASYIPSECSERVERIP | sed 's/%//g')
EASYIPSECLOCALGATEWAYVALUE=$(sed 's/#//g' $EASYIPSECLOCALGATEWAY | sed 's/%//g')

GIF3=50
(
while test $GIF3 != 150
do
echo $GIF3
echo "XXX"
echo "set direct vpn server route: ($GIF3 percent)"
echo "XXX"
#
### run //
# clean up double entries
/usr/sbin/netstat -rn -f inet | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $2}' | xargs -L1 route delete -host "$EASYIPSECSERVERIPVALUE" > /dev/null 2>&1
#
/sbin/route delete -host "$EASYIPSECSERVERIPVALUE" > /dev/null 2>&1
/sbin/route add -host "$EASYIPSECSERVERIPVALUE" "$EASYIPSECLOCALGATEWAYVALUE" > /dev/null 2>&1
### // run
#
GIF3=$((GIF3 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set direct vpn server route" 20 70 0

### check vpn server //
#
/bin/echo ""
#(
/sbin/ping -q -c5 "$EASYIPSECSERVERIPVALUE" > /dev/null
if [ $? -eq 0 ]
then
      /bin/echo ""
      say "well, server is responsive" &
      /bin/echo "server is responsive"
      sleep 3
      # exit 0
else
      /bin/echo ""
      say "excuse me if have got an error: IP security server isn't responsive" &
      /bin/echo "ERROR: IPsec server isn't responsive"
      exit 1
fi
#)
#
### // check vpn server

/bin/mkdir -p /etc/racoon
/bin/mkdir -p /etc/racoon/certs
/bin/chmod 0700 /etc/racoon/certs

### modify /etc/racoon/setkey.conf //
#
(
EASYIPSECGETIFIP=$(/usr/sbin/netstat -rn -f inet | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $6}' | xargs -L1 ifconfig | grep -w "inet" | awk '{print $2}')

/bin/cat <<SETKEY > /etc/racoon/setkey.conf
### ### ### PLITC // ### ### ###
#
flush;

spdflush;

spdadd $EASYIPSECCLIENTIPVALUE/32 $EASYIPSECDESTNETVALUE/24 any -P out ipsec
   esp/tunnel/$EASYIPSECGETIFIP-$EASYIPSECSERVERIPVALUE/require;

spdadd $EASYIPSECDESTNETVALUE/24 $EASYIPSECCLIENTIPVALUE/32 any -P in ipsec
   esp/tunnel/$EASYIPSECSERVERIPVALUE-$EASYIPSECGETIFIP/require;
#
### ### ### // PLITC ### ### ###
# EOF
SETKEY
)
#
/bin/chmod 0600 /etc/racoon/setkey.conf
#
### // modify /etc/racoon/setkey.conf

### modify /etc/racoon/psk.txt //
#
(
EASYIPSECSERVERPSK="/tmp/easy_ipsec_server_psk.txt"
touch $EASYIPSECSERVERPSK
/bin/chmod 0600 $EASYIPSECSERVERPSK

say "Enter your VPN IP security Server Pre-shared key: without spaces and pound" &
dialog --inputbox "Enter your VPN IPsec Server Pre-shared key: (without spaces and pound)" 8 85 2>$EASYIPSECSERVERPSK

EASYIPSECSERVERPSKVALUE=$(sed 's/#//g' $EASYIPSECSERVERPSK | sed 's/%//g')

/bin/cat <<PSK > /etc/racoon/psk.txt
### ### ### PLITC ### ### ###
# IPv4/v6 addresses
# 10.160.94.3	asecretkeygoeshere
# 172.16.1.133	asecretkeygoeshere
# 3ffe:501:410:ffff:200:86ff:fe05:80fa	asecretkeygoeshere
# 3ffe:501:410:ffff:210:4bff:fea2:8baa	asecretkeygoeshere
# USER_FQDN
# macuser@localhost	somethingsecret
# FQDN
# kame		hoge
### ### ### ##### ### ### ###
#
$EASYIPSECSERVERIPVALUE $EASYIPSECSERVERPSKVALUE
#
### ### ### PLITC ### ### ###
# EOF
PSK

/bin/chmod 0600 /etc/racoon/psk.txt
/bin/rm $EASYIPSECSERVERPSK
)
#
### // modify /etc/racoon/psk.txt

### modify /etc/racoon/racoon.conf //
#
EASYIPSECGETIFIPCONF=$(/usr/sbin/netstat -rn -f inet | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $6}' | xargs -L1 ifconfig | grep -w "inet" | awk '{print $2}')
#
(
/bin/cat <<CONF > /etc/racoon/racoon.conf
### ### ### PLITC ### ### ###
#
path include "/etc/racoon" ;
path pre_shared_key "/etc/racoon/psk.txt" ;
path certificate "/etc/cert" ;
log debug;
#
### ### ### ##### ### ### ###

padding # options are not to be changed
{
        maximum_length  20;
        randomize       off;
        strict_check    off;
        exclusive_tail  off;
}
 
timer   # timing options. change as needed
{
        counter         5;
        interval        20 sec;
        persend         1;
        natt_keepalive  15 sec;
        phase1          120 sec;
        phase2          60 sec;
}
 
listen  # address [port] that racoon will listening on
{
#
### CHANGEME // ###
        isakmp          $EASYIPSECGETIFIPCONF [500];
        isakmp_natt     $EASYIPSECGETIFIPCONF [4500];
### // CHANGEME ###
#
}

remote $EASYIPSECSERVERIPVALUE
{
        # ph1id 1;
        exchange_mode   main;
        doi             ipsec_doi;
        situation       identity_only;

        peers_identifier address $EASYIPSECSERVERIPVALUE;
        verify_identifier on;
        verify_cert off;
        weak_phase1_check on;

        passive         off;
        proposal_check  strict;

        ike_frag on;
        nonce_size 16;
        support_proxy on;
        generate_policy off;

        nat_traversal   force;
	dpd_delay 30;
	dpd_retry 10;
	dpd_maxfail 10;

                        proposal {
                                dh_group                16;
                                lifetime time           600 sec;
                                encryption_algorithm    aes 256;
                                hash_algorithm          sha512;
                                authentication_method   pre_shared_key;
                        }
}

sainfo (address $EASYIPSECCLIENTIPVALUE/32 any address $EASYIPSECDESTNETVALUE/24 any)
{
        # remoteid 1;
        pfs_group       16;
        lifetime        time       300 sec;
        encryption_algorithm       aes 256;
        authentication_algorithm   hmac_sha512;
        compression_algorithm      deflate;
}

#
### ### ### ### ### ### ### ### ###
# EOF
CONF
)
#
/bin/chmod 0600 /etc/racoon/racoon.conf
#
### // modify /etc/racoon/racoon.conf

### start ipsec //
#
(
say "syslog can be very slow, do you want delete all system logs before ?" &
dialog --title "Delete all System-Logs" --backtitle "Delete all System-Logs" --yesno "syslog can be very slow, do you want delete all system logs before ?" 7 60

response=$?
case $response in
   0)
      #/bin/rm -rf /private/var/log/asl/*.asl
      /usr/sbin/aslmanager -size 1
      /bin/echo ""
      /bin/echo "System-Logs deleted!"
;;
   1)
      /bin/echo ""
      /bin/echo "System-Logs not deleted."
;;
   255)
      /bin/echo ""
      /bin/echo "[ESC] key pressed."
;;
esac
#
#/ /bin/launchctl stop com.apple.syslog
#/ /bin/launchctl start com.apple.syslog
#
#/ 
#/ launchctl unload /System/Library/LaunchDaemons/com.apple.racoon.plist
#/ sleep 1
#/ launchctl load /System/Library/LaunchDaemons/com.apple.racoon.plist
#
)
#
(
/bin/echo ""
say "Starting IP security" &
/bin/echo "Starting IPsec"
/usr/sbin/setkey -f /etc/racoon/setkey.conf
sleep 1
/bin/launchctl stop com.apple.racoon
/bin/launchctl stop com.apple.ipsec
sleep 1
/bin/launchctl start com.apple.ipsec
/bin/launchctl start com.apple.racoon
sleep 1
/bin/echo ""
say "wait a minute please" &
/bin/echo "prepare racoon log ... wait a minute"
/bin/echo ""
sleep 15
)
#
/usr/bin/syslog -k Facility -k Sender racoon | tail -n 100 | grep "established" > /tmp/easy_ipsec_racoon_log.txt
#
RACOONLOG="/tmp/easy_ipsec_racoon_log.txt"
#
(
say "VPN Logfile" &
dialog --textbox "$RACOONLOG" 0 0
)
#
### // start ipsec

### ipsec test //
#
#(
EASYIPSECSERVERTEST="/tmp/easy_ipsec_server_test.txt"
touch $EASYIPSECSERVERTEST
/bin/chmod 0600 $EASYIPSECSERVERTEST

say "Enter your VPN IP security Server forwarding interface IP: for example 172.31.254.254" &
dialog --inputbox "Enter your VPN IPsec Server forwarding interface IP: (for example 172.31.254.254)" 8 85 2>$EASYIPSECSERVERTEST

EASYIPSECSERVERTESTVALUE=$(sed 's/#//g' $EASYIPSECSERVERTEST | sed 's/%//g')

/sbin/ping -q -c5 "$EASYIPSECSERVERTESTVALUE" > /dev/null
if [ $? -eq 0 ]
then
      say "It works!" &
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "It works!" 0 0
      # exit 0
else
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      say "excuse me if have got an error: IP security server isn't responsive" &
      /bin/echo "ERROR: IPsec server isn't responsive"
      exit 1
fi
#)
/bin/rm -rf "$EASYIPSECSERVERTEST"
#
### // ipsec test

### // stage2 ###

### stage3 // ###

### ipsec/openvpn relay setup // ###
#
#(
say "if you have an IP security/OpenVPN Relay Server-Setup, Go ahead" &
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --yesno "if you have an IPsec/OpenVPN Relay Server-Setup Go ahead!" 7 70

OPENVPN=$?
case $OPENVPN in
   0)
      /bin/echo ""
;;
   1)
      /bin/echo ""
      #/bin/echo "no thanks!"
      say "Have a nice day with IP security, good bye" &
      /bin/echo "Have a nice day with IPsec"
###
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
###
      exit 1
;;
   255)
      /bin/echo ""
      /bin/echo "[ESC] key pressed."
;;
esac
#)
#
(
say "its time now to establish, manually a successful connection" &
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --msgbox "its time now to establish a successful connection! ... than press OK" 8 80
)
#
### // ipsec/openvpn relay setup ###

### openvpn server // ###
#
EASYIPSECSERVEROVPNTEST="/tmp/easy_ipsec_server_openvpn_test.txt"
touch $EASYIPSECSERVEROVPNTEST
/bin/chmod 0600 $EASYIPSECSERVEROVPNTEST

say "Enter your VPN, OpenVPN Server forwarding interface IP: for example 172.31.253.1" &
dialog --inputbox "Enter your VPN OpenVPN Server forwarding interface IP: (for example 172.31.253.1)" 8 85 2>$EASYIPSECSERVEROVPNTEST

EASYIPSECSERVEROVPNTESTVALUE=$(sed 's/#//g' $EASYIPSECSERVEROVPNTEST | sed 's/%//g')
#(
/sbin/ping -q -c5 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null
if [ $? -eq 0 ]
then
      say "It works!" &
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "It works!" 0 0
      # exit 0
else
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      say "excuse me if have got an error: OpenVPN server isn't responsive" &
      /bin/echo "ERROR: OpenVPN server isn't responsive"
      exit 1
fi
#)
##/bin/rm -rf "$EASYIPSECSERVEROVPNTEST"
#
### // openvpn server ###

### new default gateway // ###
#
EASYIPSECNETSTATOVPN="/tmp/easy_ipsec_server_openvpn_netstat.txt"
touch $EASYIPSECNETSTATOVPN
/bin/chmod 0600 $EASYIPSECNETSTATOVPN
#
say "it seems to work, lets change the default gateway!" &
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --msgbox "it seems to work, lets change the default gateway!" 8 70
#
/sbin/route delete default > /dev/null 2>&1
/sbin/route delete 128.0.0.0/1 > /dev/null 2>&1
/sbin/route delete 0.0.0.0/1 > /dev/null 2>&1
#
/sbin/route add -net 128.0.0.0/1 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null 2>&1
/sbin/route add -net 0.0.0.0/1 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null 2>&1
#
###
/usr/sbin/netstat -rn -f inet > "$EASYIPSECNETSTATOVPN"
###
#
say 'your default gateway is now "$EASYIPSECSERVEROVPNTESTVALUE"'
dialog --textbox "$EASYIPSECNETSTATOVPN" 0 0
#
###
/bin/echo ""
say "Have a nice day with IP security and OpenVPN, good bye" &
/bin/echo "Have a nice day with IPsec and OpenVPN"
###
#
/bin/rm -rf "$EASYIPSECNETSTATOVPN"
#
### // new default gateway ###

### // stage3 ###

### stage4 // ###
#
(
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
)
#
### // stage4 ###

### ### ### ### ### ### ### ### ###
   ;;
FreeBSD)
   ### FreeBSD ###
#
FRACOON=$(/usr/bin/which racoon)
FOPENVPN=$(/usr/bin/which openvpn)
#
### ### ### ### ### ### ### ### ###

if [ "$MYNAME" = root ]; then
   echo "" # dummy
else
   echo "<--- --- --->"
   echo ""
   echo "ERROR: You must be root to run this script"
   exit 1
fi

if [ -z "$FRACOON" ]; then
   echo "<--- --- --->"
   echo "need racoon/ipsec-tools"
   echo "<--- --- --->"
   # (
        cd /usr/ports/security/ipsec-tools/ && make install clean
   # )
   echo "<--- --- --->"
   ### break // ###
   echo ""
   read "Press [Enter] key to continue..."
   ### // break ###
else
   echo "" # dummy
fi

if [ -z "$FOPENVPN" ]; then
   echo "<--- --- --->"
   echo "need openvpn"
   echo "<--- --- --->"
   # (
        cd /usr/ports/security/openvpn/ && make install clean
   # )
   echo "<--- --- --->"
   ### break // ###
   echo ""
   read "Press [Enter] key to continue..."
   ### // break ###
else
   echo "" # dummy
fi

(
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
)

### stage2 // ###

GIF1=50
(
while test $GIF1 != 150
do
echo $GIF1
echo "XXX"
echo "create gif interface: ($GIF1 percent)"
echo "XXX"
#
### run //
/sbin/ifconfig gif0 create > /dev/null 2>&1
/sbin/ifconfig gif0 up
### // run
#
GIF1=$((GIF1 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "create gif interface" 20 70 0

EASYIPSECCLIENTIP="/tmp/easy_ipsec_client_ip.txt"
touch $EASYIPSECCLIENTIP

dialog --inputbox "Enter your Roadwarrior Client IP: (for example 10.0.0.1)" 8 40 2>$EASYIPSECCLIENTIP

EASYIPSECDESTNET="/tmp/easy_ipsec_destination_net.txt"
touch $EASYIPSECDESTNET

dialog --inputbox "Enter your VPN destination network: (for example 172.31.254.0)" 8 40 2>$EASYIPSECDESTNET

EASYIPSECCLIENTIPVALUE=$(sed 's/#//g' $EASYIPSECCLIENTIP | sed 's/%//g')
EASYIPSECDESTNETVALUE=$(sed 's/#//g' $EASYIPSECDESTNET | sed 's/%//g')

GIF2=50
(
while test $GIF2 != 150
do
echo $GIF2
echo "XXX"
echo "set gif options: ($GIF2 percent)"
echo "XXX"
#
### run //
/sbin/ifconfig gif0 "$EASYIPSECCLIENTIPVALUE" "$EASYIPSECDESTNETVALUE"
/sbin/route add -net "$EASYIPSECDESTNETVALUE"/24 -interface gif0 > /dev/null 2>&1
### // run
#
GIF2=$((GIF2 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set gif options" 20 70 0

EASYIPSECSERVERIP="/tmp/easy_ipsec_server_ip.txt"
touch $EASYIPSECSERVERIP

dialog --inputbox "Enter your VPN IPsec Server IP:" 8 40 2>$EASYIPSECSERVERIP

EASYIPSECLOCALGATEWAY="/tmp/easy_ipsec_local_gateway.txt"
touch $EASYIPSECLOCALGATEWAY

dialog --inputbox "Enter your local gateway IP:" 8 40 2>$EASYIPSECLOCALGATEWAY

EASYIPSECSERVERIPVALUE=$(sed 's/#//g' $EASYIPSECSERVERIP | sed 's/%//g')
EASYIPSECLOCALGATEWAYVALUE=$(sed 's/#//g' $EASYIPSECLOCALGATEWAY | sed 's/%//g')

GIF3=50
(
while test $GIF3 != 150
do
echo $GIF3
echo "XXX"
echo "set direct vpn server route: ($GIF3 percent)"
echo "XXX"
#
### run //
# clean up double entries on (RADIX_MPATH) equal-cost multi-path routing (ecmp) systems
/usr/bin/netstat -rn -f inet | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $2}' | xargs -L1 route del -host "$EASYIPSECSERVERIPVALUE" > /dev/null 2>&1
#
/sbin/route del -host "$EASYIPSECSERVERIPVALUE" "$EASYIPSECLOCALGATEWAYVALUE" > /dev/null 2>&1
/sbin/route add -host "$EASYIPSECSERVERIPVALUE" "$EASYIPSECLOCALGATEWAYVALUE" > /dev/null 2>&1
### // run
#
GIF3=$((GIF3 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set direct vpn server route" 20 70 0

### check vpn server //
#
/bin/echo ""
(
/sbin/ping -q -c5 "$EASYIPSECSERVERIPVALUE" > /dev/null
if [ $? -eq 0 ]
then
      /bin/echo ""
      /bin/echo "server is responsive"
      sleep 3
      exit 0
else
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 1
fi
)
#
### // check vpn server

/bin/mkdir -p /usr/local/etc/racoon
/bin/mkdir -p /usr/local/etc/racoon/certs
/bin/chmod 0700 /usr/local/etc/racoon/certs

### modify /usr/local/etc/racoon/setkey.conf //
#
(
EASYIPSECGETIFIP=$(/usr/bin/netstat -rnW -f inet | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $7}' | xargs -L1 ifconfig | grep -w "inet" | awk '{print $2}')

/bin/cat <<SETKEY > /usr/local/etc/racoon/setkey.conf
### ### ### PLITC // ### ### ###
#
flush;

spdflush;

spdadd $EASYIPSECCLIENTIPVALUE/32 $EASYIPSECDESTNETVALUE/24 any -P out ipsec
   esp/tunnel/$EASYIPSECGETIFIP-$EASYIPSECSERVERIPVALUE/require;

spdadd $EASYIPSECDESTNETVALUE/24 $EASYIPSECCLIENTIPVALUE/32 any -P in ipsec
   esp/tunnel/$EASYIPSECSERVERIPVALUE-$EASYIPSECGETIFIP/require;
#
### ### ### // PLITC ### ### ###
# EOF
SETKEY
)
#
/bin/chmod 0600 /usr/local/etc/racoon/setkey.conf
#
### // modify /usr/local/etc/racoon/setkey.conf

### modify /usr/local/etc/racoon/psk.txt //
#
(
EASYIPSECSERVERPSK="/tmp/easy_ipsec_server_psk.txt"
touch $EASYIPSECSERVERPSK
/bin/chmod 0600 $EASYIPSECSERVERPSK

dialog --inputbox "Enter your VPN IPsec Server Pre-shared key: (without spaces and pound)" 8 85 2>$EASYIPSECSERVERPSK

EASYIPSECSERVERPSKVALUE=$(sed 's/#//g' $EASYIPSECSERVERPSK | sed 's/%//g')

/bin/cat <<PSK > /usr/local/etc/racoon/psk.txt
### ### ### PLITC ### ### ###
#
$EASYIPSECSERVERIPVALUE $EASYIPSECSERVERPSKVALUE
#
### ### ### PLITC ### ### ###
# EOF
PSK

/bin/chmod 0600 /usr/local/etc/racoon/psk.txt
/bin/rm $EASYIPSECSERVERPSK
)
#
### // modify /usr/local/etc/racoon/psk.txt

### modify /usr/local/etc/racoon/racoon.conf //
#
EASYIPSECGETIFIPCONF=$(/usr/bin/netstat -rnW -f inet | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $7}' | xargs -L1 ifconfig | grep -w "inet" | awk '{print $2}')
#
(
/bin/cat <<CONF > /usr/local/etc/racoon/racoon.conf
### ### ### PLITC ### ### ###
#
path    include "/usr/local/etc/racoon";
path    certificate "/usr/local/etc/racoon/certs";      #location of cert files
path    pre_shared_key "/usr/local/etc/racoon/psk.txt"; #location of pre-shared key file
log     debug;                                          #log verbosity setting: set to 'notify' when testing and debugging is complete
#
### ### ### ##### ### ### ###

padding # options are not to be changed
{
        maximum_length  20;
        randomize       off;
        strict_check    off;
        exclusive_tail  off;
}
 
timer   # timing options. change as needed
{
        counter         5;
        interval        20 sec;
        persend         1;
        natt_keepalive  15 sec;
        phase1          120 sec;
        phase2          60 sec;
}
 
listen  # address [port] that racoon will listening on
{
#
### CHANGEME // ###
        isakmp          $EASYIPSECGETIFIPCONF [500];
        isakmp_natt     $EASYIPSECGETIFIPCONF [4500];
### // CHANGEME ###
#
}

remote $EASYIPSECSERVERIPVALUE
{
        # ph1id 1;
        exchange_mode   main;
        doi             ipsec_doi;
        situation       identity_only;

        peers_identifier address $EASYIPSECSERVERIPVALUE;
        verify_identifier on;
        verify_cert off;
        weak_phase1_check on;

        passive         off;
        proposal_check  strict;

        ike_frag on;
        nonce_size 16;
        support_proxy on;
        generate_policy off;

        nat_traversal   force;
	dpd_delay 30;
	dpd_retry 10;
	dpd_maxfail 10;

                        proposal {
                                dh_group                16;
                                lifetime time           600 sec;
                                encryption_algorithm    aes 256;
                                hash_algorithm          sha512;
                                authentication_method   pre_shared_key;
                        }
}

sainfo (address $EASYIPSECCLIENTIPVALUE/32 any address $EASYIPSECDESTNETVALUE/24 any)
{
        # remoteid 1;
        pfs_group       16;
        lifetime        time       300 sec;
        encryption_algorithm       aes 256;
        authentication_algorithm   hmac_sha512;
        compression_algorithm      deflate;
}

#
### ### ### ### ### ### ### ### ###
# EOF
CONF
)
#
/bin/chmod 0600 /usr/local/etc/racoon/racoon.conf
#
### // modify /usr/local/etc/racoon/racoon.conf

### start ipsec //
#
(
dialog --title "Delete Racoon-Logs" --backtitle "Delete Racoon-Logs" --yesno "syslog can be very slow, do you want delete racoon logs before ?" 7 60

response=$?
case $response in
   0)
      /bin/echo "" > /var/log/racoon.log
      /bin/echo ""
      /bin/echo "System-Logs deleted!"
;;
   1)
      /bin/echo ""
      /bin/echo "System-Logs not deleted."
;;
   255)
      /bin/echo ""
      /bin/echo "[ESC] key pressed."
;;
esac
#
)
#
(
/bin/echo ""
/bin/echo "Starting IPsec"
sleep 1
/bin/echo ""
/usr/sbin/service racoon stop
/usr/sbin/service ipsec stop
sleep 1
/bin/echo ""
/usr/sbin/service ipsec start
/usr/sbin/service racoon start
sleep 1
/bin/echo ""
)
#

### ipsec test //
#
#(
EASYIPSECSERVERTEST="/tmp/easy_ipsec_server_test.txt"
touch $EASYIPSECSERVERTEST
/bin/chmod 0600 $EASYIPSECSERVERTEST

dialog --inputbox "Enter your VPN IPsec Server forwarding interface IP: (for example 172.31.254.254)" 8 85 2>$EASYIPSECSERVERTEST

EASYIPSECSERVERTESTVALUE=$(sed 's/#//g' $EASYIPSECSERVERTEST | sed 's/%//g')

/sbin/ping -q -c5 "$EASYIPSECSERVERTESTVALUE" > /dev/null
if [ $? -eq 0 ]
then
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "It works!" 0 0
      exit 0
else
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 1
fi
#)
#
### // ipsec test

/bin/echo ""
/bin/echo "prepare racoon log ... wait a minute"
/bin/echo ""
sleep 15

egrep "established|WARNING" /var/log/racoon.log | tail -n 10 > /tmp/easy_ipsec_racoon_log.txt
#
RACOONLOG="/tmp/easy_ipsec_racoon_log.txt"
#
(
dialog --textbox "$RACOONLOG" 0 0
)
#
/bin/rm -rf "$EASYIPSECSERVERTEST"
#
### // start ipsec

### // stage2 ###

### stage3 // ###

### ipsec/openvpn relay setup // ###
#
#(
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --yesno "if you have an IPsec/OpenVPN Relay Server-Setup Go ahead!" 7 70

OPENVPN=$?
case $OPENVPN in
   0)
      /bin/echo ""
;;
   1)
      /bin/echo ""
      #/bin/echo "no thanks!"
      /bin/echo "Have a nice day with IPsec"
###
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
###
      exit 1
;;
   255)
      /bin/echo ""
      /bin/echo "[ESC] key pressed."
;;
esac
#)
#
(
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --msgbox "its time now to establish a successful connection! ... than press OK" 8 80
)
#
### // ipsec/openvpn relay setup ###

### openvpn server // ###
#
EASYIPSECSERVEROVPNTEST="/tmp/easy_ipsec_server_openvpn_test.txt"
touch $EASYIPSECSERVEROVPNTEST
/bin/chmod 0600 $EASYIPSECSERVEROVPNTEST

dialog --inputbox "Enter your VPN OpenVPN Server forwarding interface IP: (for example 172.31.253.1)" 8 85 2>$EASYIPSECSERVEROVPNTEST

EASYIPSECSERVEROVPNTESTVALUE=$(sed 's/#//g' $EASYIPSECSERVEROVPNTEST | sed 's/%//g')
(
/sbin/ping -q -c5 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null
if [ $? -eq 0 ]
then
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "It works!" 0 0
      exit 0
else
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 1
fi
)
##/bin/rm -rf $EASYIPSECSERVEROVPNTEST
#
### // openvpn server ###

### new default gateway // ###
#
EASYIPSECNETSTATOVPN="/tmp/easy_ipsec_server_openvpn_netstat.txt"
touch $EASYIPSECNETSTATOVPN
/bin/chmod 0600 $EASYIPSECNETSTATOVPN
#
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --msgbox "it seems to work, lets change the default gateway!" 8 70
#
/sbin/route delete default > /dev/null 2>&1
/sbin/route delete 128.0.0.0/1 > /dev/null 2>&1
/sbin/route delete 0.0.0.0/1 > /dev/null 2>&1
#
/sbin/route add -net 128.0.0.0/1 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null 2>&1
/sbin/route add -net 0.0.0.0/1 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null 2>&1
#
###
/usr/bin/netstat -rn -f inet > "$EASYIPSECNETSTATOVPN"
###
#
dialog --textbox "$EASYIPSECNETSTATOVPN" 0 0
#
###
/bin/echo ""
/bin/echo "Have a nice day with IPsec and OpenVPN"
###
#
/bin/rm -rf $EASYIPSECNETSTATOVPN
#
### // new default gateway ###

### // stage3 ###

### stage4 // ###
#
(
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
)
#
### // stage4 ###

### ### ### ### ### ### ### ### ###
   ;;
Linux)
   ### Linux ###
#
DEBIAN=$(grep "ID" /etc/os-release | egrep -v "VERSION" | sed 's/ID=//g')
DEBVERSION=$(grep "VERSION_ID" /etc/os-release | sed 's/VERSION_ID=//g' | sed 's/"//g')
#
case $DEBIAN in
debian)
### stage2 // ###
#
DEBPING=$(/usr/bin/dpkg -l | grep "iputils-ping" | awk '{print $2}')
DEBDIALOG=$(/usr/bin/which dialog)
DEBSTRONGSWAN=$(/usr/bin/dpkg -l | grep "strongswan-ikev1" | awk '{print $2}')
DEBOPENVPN=$(/usr/bin/dpkg -l | grep "openvpn" | awk '{print $2}')
#
#/ spinner
spinner()
{
    local pid=$1
    local delay=0.01
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
          local temp=${spinstr#?}
          printf " [%c]  " "$spinstr"
          local spinstr=$temp${spinstr%"$temp"}
          sleep $delay
          printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}
#
### ### ### ### ### ### ### ### ###

if [ "$MYNAME" = root ]; then
   echo "" # dummy
else
   echo "<--- --- --->"
   echo ""
   echo "ERROR: You must be root to run this script"
   exit 1
fi

if [ "$DEBVERSION" = "8" ]; then
   : # dummy
else
   if [ "$DEBVERSION" = "9" ]; then
      : # dummy
   else
      echo "<--- --- --->"
      echo ""
      echo "ERROR: You need Debian 8 (Jessie) or 9 (Stretch) Version"
      exit 1
   fi
fi

if [ -z "$DEBPING" ]; then
    echo "<--- --- --->"
    echo "need iputils-ping"
    echo "<--- --- --->"
    # (
         apt-get update
         apt-get -y install iputils-ping
    # )
    echo "<--- --- --->"
    ### break // ###
    #/ echo ""
    #/ read "Press [Enter] key to continue..."
    ### // break ###
else
    : # dummy
fi

if [ -z "$DEBDIALOG" ]; then
   echo "<--- --- --->"
   echo "need dialog"
   echo "<--- --- --->"
   # (
        apt-get update
        apt-get -y install dialog
   # )
   echo "<--- --- --->"
   ### break // ###
   #/ echo ""
   #/ read "Press [Enter] key to continue..."
   ### // break ###
else
   : # dummy
fi

if [ -z "$DEBSTRONGSWAN" ]; then
   echo "<--- --- --->"
   echo "need strongswan-ikev1"
   echo "<--- --- --->"
   # (
        apt-get update
        apt-get -y install strongswan-ikev1
   # )
   echo "<--- --- --->"
   ### break // ###
   #/ echo ""
   #/ read "Press [Enter] key to continue..."
   ### // break ###
else
   : # dummy
fi

if [ -z "$DEBOPENVPN" ]; then
   echo "<--- --- --->"
   echo "need openvpn"
   echo "<--- --- --->"
   # (
        apt-get update
        apt-get -y install openvpn
   # )
   echo "<--- --- --->"
   ### break // ###
   #/ echo ""
   #/ read "Press [Enter] key to continue..."
   ### // break ###
else
   : # dummy
fi

(
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
)

(
### clean up - openvpn iptable rules // ##
#
CHECKIPSECIPTABLERULES0=$(iptables -S | grep -c "EASYIPSEC")
if [ "$CHECKIPSECIPTABLERULES0" = "1" ]
then
   ### ACCEPT // ###
   ###/ v4
   iptables -P INPUT ACCEPT
   iptables -P FORWARD ACCEPT
   iptables -P OUTPUT ACCEPT
   ##/ v6
   ip6tables -P INPUT ACCEPT
   ip6tables -P FORWARD ACCEPT
   ip6tables -P OUTPUT ACCEPT
   ### // ACCEPT ###


   ### flush // ###
   ##/ v4
   iptables -F INPUT
   iptables -F FORWARD
   iptables -F OUTPUT
   iptables -t nat -F PREROUTING
   iptables -t nat -F POSTROUTING
   ##/ v6
   ip6tables -F INPUT
   ip6tables -F FORWARD
   ip6tables -F OUTPUT
   ip6tables -t nat -F PREROUTING
   ip6tables -t nat -F POSTROUTING
   ### // flush ###


   ### info // ###
   iptables -X EASYIPSEC > /dev/null 2>&1
   ### // info ###
else
   : # dummy
fi
#
### // clean up - openvpn iptable rules ###
)

### stage2 // ###

EASYIPSECINTERFACE="/tmp/easy_ipsec_interface.txt"
touch $EASYIPSECINTERFACE
dialog --inputbox "choose your public transport interface: (for example wlan0)" 8 70 2>$EASYIPSECINTERFACE

EASYIPSECINTERFACEVALUE=$(sed 's/#//g' $EASYIPSECINTERFACE | sed 's/%//g')

CHECKINTERFACE=$(ip a | egrep "UP" | awk '{print $2}' | sed 's/://' | egrep -v "lo" | tr '\n' ' ' | grep -Fc "$EASYIPSECINTERFACEVALUE")
if [ "$CHECKINTERFACE" = "1" ]; then
   : # dummy
else
   echo "" # dummy
   echo "" # dummy
   echo "[ERROR] interface not usable!"
   exit 1
fi

EASYIPSECCLIENTIP="/tmp/easy_ipsec_client_ip.txt"
touch $EASYIPSECCLIENTIP
dialog --inputbox "Enter your Roadwarrior Client IP: (for example 10.0.0.1)" 8 40 2>$EASYIPSECCLIENTIP

EASYIPSECDESTNET="/tmp/easy_ipsec_destination_net.txt"
touch $EASYIPSECDESTNET
dialog --inputbox "Enter your VPN destination network: (for example 172.31.254.0)" 8 40 2>$EASYIPSECDESTNET

EASYIPSECCLIENTIPVALUE=$(sed 's/#//g' $EASYIPSECCLIENTIP | sed 's/%//g')
EASYIPSECDESTNETVALUE=$(sed 's/#//g' $EASYIPSECDESTNET | sed 's/%//g')
OLDINTERFACE=$(/bin/ip a | grep $EASYIPSECCLIENTIPVALUE | awk '{print $5}')

GIF2=50
(
while test $GIF2 != 150
do
echo $GIF2
echo "XXX"
echo "set ipsec local subnet address: ($GIF2 percent)"
echo "XXX"
#
### run //
/bin/ip addr del $EASYIPSECCLIENTIPVALUE dev $OLDINTERFACE > /dev/null 2>&1
/bin/ip addr add $EASYIPSECCLIENTIPVALUE/32 dev $EASYIPSECINTERFACEVALUE > /dev/null 2>&1
### // run
#
GIF2=$((GIF2 + 50))
sleep 1
done
) | dialog --title "set ipsec local subnet address" --gauge "set ipsec local subnet address" 20 70 0

EASYIPSECSERVERIP="/tmp/easy_ipsec_server_ip.txt"
touch $EASYIPSECSERVERIP

dialog --inputbox "Enter your VPN IPsec Server IP:" 8 40 2>$EASYIPSECSERVERIP

EASYIPSECLOCALGATEWAY="/tmp/easy_ipsec_local_gateway.txt"
touch $EASYIPSECLOCALGATEWAY

dialog --inputbox "Enter your local gateway IP:" 8 40 2>$EASYIPSECLOCALGATEWAY

EASYIPSECSERVERIPVALUE=$(sed 's/#//g' $EASYIPSECSERVERIP | sed 's/%//g')
EASYIPSECLOCALGATEWAYVALUE=$(sed 's/#//g' $EASYIPSECLOCALGATEWAY | sed 's/%//g')

GIF3=50
(
while test $GIF3 != 150
do
echo $GIF3
echo "XXX"
echo "set direct vpn server route: ($GIF3 percent)"
echo "XXX"
#
### run //
/bin/netstat -rn4 | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $2}' | xargs -L1 route del -host "$EASYIPSECSERVERIPVALUE" > /dev/null 2>&1
/sbin/route del -host "$EASYIPSECSERVERIPVALUE" > /dev/null 2>&1
/sbin/route add -host "$EASYIPSECSERVERIPVALUE" gw "$EASYIPSECLOCALGATEWAYVALUE" dev "$EASYIPSECINTERFACEVALUE" > /dev/null 2>&1
### // run
#
GIF3=$((GIF3 + 50))
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set direct vpn server route" 20 70 0

### check vpn server //
#
/bin/echo ""

### initial "routed" connection // ###
(
/bin/ping -q -c4 "$EASYIPSECSERVERIPVALUE" > /dev/null
)
### // initial "routed" connection ###

/bin/ping -q -c5 "$EASYIPSECSERVERIPVALUE" > /dev/null
if [ $? -eq 0 ]
then
      /bin/echo ""
      #/ /bin/echo "server is responsive"
      printf "\033[1;32m[OK]\033[0m server is responsive \n"
      sleep 3
else
      /bin/echo ""
      #/ /bin/echo "ERROR: server isn't responsive"
      printf "\033[1;33m[WARNING]\033[0m server isn't responsive \n"
      exit 1
fi

#
### // check vpn server

### modify /etc/ipsec.conf //
#
(
EASYIPSECGETIFIP=$(/bin/netstat -rnW4 | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $8}' | xargs -L1 ifconfig | grep -w "inet" | awk '{print $2}' | sed 's/Adresse://g')

/bin/cat <<IPSECCONF > /etc/ipsec.conf
### ### ### PLITC ### ### ###

config setup
       strictcrlpolicy=yes

conn %default
     ikelifetime=10m
     keylife=5m
     rekeymargin=2m
     keyingtries=2
     keyexchange=ikev1

conn roadwarrior
     left=%any
     leftsubnet=$EASYIPSECCLIENTIPVALUE/32
     leftauth=psk
     leftsendcert=never
     leftfirewall=yes
     type=tunnel
     right=$EASYIPSECSERVERIPVALUE
     rightsubnet=$EASYIPSECDESTNETVALUE/24
     rightauth=psk
     auto=route
     forceencaps=yes
     compress=no
     dpddelay=30
     dpdtimeout=10
     dpdaction=clear
     ike=aes256-sha512-modp4096!
     esp=aes256-sha512-modp4096!
     leftikeport=4500
     rightikeport=4500

### ### ### PLITC ### ### ###
# EOF
IPSECCONF
)
#
/bin/chmod 0600 /etc/ipsec.conf
#
### // modify /etc/ipsec.conf

### modify /etc/ipsec.secrets //
#
(
EASYIPSECSERVERPSK="/tmp/easy_ipsec_server_psk.txt"
touch $EASYIPSECSERVERPSK
/bin/chmod 0600 $EASYIPSECSERVERPSK

dialog --inputbox "Enter your VPN IPsec Server Pre-shared key: (without spaces and pound)" 8 85 2>$EASYIPSECSERVERPSK

EASYIPSECSERVERPSKVALUE=$(sed 's/#//g' $EASYIPSECSERVERPSK | sed 's/%//g')

/bin/cat <<PSK > /etc/ipsec.secrets
### ### ### PLITC ### ### ###
#
$EASYIPSECSERVERIPVALUE : PSK "$EASYIPSECSERVERPSKVALUE"
#
### ### ### PLITC ### ### ###
# EOF
PSK

/bin/chmod 0600 /etc/ipsec.secrets > /dev/null 2>&1
if [ $? -eq 0 ]
then
   : # dummy
else
   CHECKATTRIPSECSECRETS=$(lsattr /etc/ipsec.secrets | awk '{print $1}' | grep -c "i")
   if [ "$CHECKATTRIPSECSECRETS" = "1" ]; then
      echo "" # dummy
      printf "\033[1;31m[WARNING] /etc/ipsec.secrets has immutable flag!\033[0m\n"
      echo "" # dummy
      sleep 4
   fi
fi
/bin/rm $EASYIPSECSERVERPSK
)
#
### // modify /etc/ipsec.secrets

### start ipsec //
#
(
/bin/echo ""
/bin/echo "Starting IPsec"
sleep 1
/bin/echo ""
/bin/systemctl restart strongswan
sleep 1
/bin/echo ""
/bin/systemctl status strongswan
sleep 1
/bin/echo ""
/usr/sbin/ipsec statusall
sleep 5
/bin/echo ""
)
#

### ipsec test //
#
#(
EASYIPSECSERVERTEST="/tmp/easy_ipsec_server_test.txt"
touch $EASYIPSECSERVERTEST
/bin/chmod 0600 $EASYIPSECSERVERTEST

dialog --inputbox "Enter your VPN IPsec Server forwarding interface IP: (for example 172.31.254.254)" 8 85 2>$EASYIPSECSERVERTEST

EASYIPSECSERVERTESTVALUE=$(sed 's/#//g' $EASYIPSECSERVERTEST | sed 's/%//g')

/bin/ping -q -c5 "$EASYIPSECSERVERTESTVALUE" > /dev/null
if [ $? -eq 0 ]
then
      #/ dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "It works!" 0 0
      echo "" # dummy
      echo "" # dummy
      printf "\033[1;32m[OK]\033[0m server is responsive \n"
      sleep 2
else
      #/ dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      echo "" # dummy
      echo "" # dummy
      printf "\033[1;33m[WARNING]\033[0m server isn't responsive \n"
      exit 1
fi
#)
#
### // ipsec test


systemctl status strongswan > /tmp/easy_ipsec_racoon_log.txt
#
RACOONLOG="/tmp/easy_ipsec_racoon_log.txt"
#
(
dialog --textbox "$RACOONLOG" 0 0
)
#
/bin/rm -rf "$EASYIPSECSERVERTEST"
#
### // start ipsec

### // stage2 ###

### ipsec iptable rules // ###
#
#(
dialog --title "IPsec restrictive Firewall Rules" --backtitle "IPsec restrictive Firewall Rules" --yesno "do you want allow (ipv4) ipsec only traffic?" 7 70

IPSECFIREWALL=$?
case $IPSECFIREWALL in
  0)
     #/ ###
     #/ #/ clean up
     #/ /bin/rm -rf /tmp/easy_ipsec*.txt
     #/ ###
     #
     sleep 2
     #
### ACCEPT // ###
###/ v4
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
##/ v6
ip6tables -P INPUT ACCEPT
ip6tables -P FORWARD ACCEPT
ip6tables -P OUTPUT ACCEPT
### // ACCEPT ###


### flush // ###
##/ v4
iptables -F INPUT
iptables -F FORWARD
iptables -F OUTPUT
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
##/ v6
ip6tables -F INPUT
ip6tables -F FORWARD
ip6tables -F OUTPUT
ip6tables -t nat -F PREROUTING
ip6tables -t nat -F POSTROUTING
### // flush ###


### ALLOW: loopback interface // ###
##/ v4
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
##/ v6
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
### // ALLOW: loopback interface ###


### ALLOW: (all) DHCP // ###
iptables -A INPUT -i "$EASYIPSECINTERFACEVALUE" -p udp --dport 67:68 --sport 67:68 -j ACCEPT
iptables -A OUTPUT -o "$EASYIPSECINTERFACEVALUE" -p udp --dport 67:68 --sport 67:68 -j ACCEPT
### // ALLOW: (all) DHCP ###


### ALLOW: (all) SSH // ###
##/ v4
iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
##/ v6
ip6tables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
### // ALLOW: (all) SSH ###


### ALLOW: (all) icmp // ###
iptables -A INPUT -p icmp --icmp-type 0 -s 0/0 -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 0 -s 0/0 -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 8 -s 0/0 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
if [ $? -eq 0 ]
then
   : # dummy
else
    iptables -A OUTPUT -p icmp --icmp-type 8 -s 0/0 -d 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
fi
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
### // ALLOW: (all) icmp ###


### ALLOW: ipsec encapsulation // ###
##/ IKE negotiations
iptables -A INPUT  -p udp --sport 500 --dport 500 -j ACCEPT
iptables -A OUTPUT -p udp --sport 500 --dport 500 -j ACCEPT
##/ IKE negotiations over nat
iptables -A INPUT  -p udp --sport 4500 --dport 4500 -j ACCEPT
iptables -A OUTPUT -p udp --sport 4500 --dport 4500 -j ACCEPT
##/ ESP encrypton and authentication
iptables -A INPUT  -p 50 -j ACCEPT
iptables -A OUTPUT -p 50 -j ACCEPT
##/ uncomment for AH authentication header
#/ iptables -A INPUT  -p 51 -j ACCEPT
#/ iptables -A OUTPUT -p 51 -j ACCEPT
### // ALLOW: ipsec encapsulation ###


### ALLOW: ipsec policy // ###
iptables -A FORWARD -s "$EASYIPSECDESTNETVALUE"/24 -d "$EASYIPSECCLIENTIPVALUE"/32 -i "$EASYIPSECINTERFACEVALUE" -m policy --dir in --pol ipsec --reqid 1 --proto esp -j ACCEPT
iptables -A FORWARD -s "$EASYIPSECCLIENTIPVALUE"/32 -d "$EASYIPSECDESTNETVALUE"/24 -o "$EASYIPSECINTERFACEVALUE" -m policy --dir out --pol ipsec --reqid 1 --proto esp -j ACCEPT
### // ALLOW: ipsec policy ###


### ALLOW: through ipsec // ###
iptables -A INPUT -m policy --pol ipsec --dir in -j ACCEPT
iptables -A OUTPUT -m policy --pol ipsec --dir out -j ACCEPT
### // ALLOW: through ipsec ###


### info // ###
iptables -N EASYIPSEC > /dev/null 2>&1
### // info ###


### DROP: igmp // ###
##/ v4
iptables -A INPUT -p igmp -j DROP
iptables -A OUTPUT -p igmp -j DROP
##/ v6
ip6tables -A INPUT -p igmp -j DROP
ip6tables -A OUTPUT -p igmp -j DROP
### // DROP: igmp ###


### DROP: broadcast/multicast // ###
##/ v4
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -m pkttype --pkt-type multicast -j DROP
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A OUTPUT -s 224.0.0.0/4 -j DROP
iptables -A OUTPUT -d 224.0.0.0/4 -j DROP
iptables -A OUTPUT -s 240.0.0.0/5 -j DROP
iptables -A OUTPUT -m pkttype --pkt-type multicast -j DROP
iptables -A OUTPUT -m pkttype --pkt-type broadcast -j DROP
##/ v6
ip6tables -A INPUT -m pkttype --pkt-type multicast -j DROP
ip6tables -A OUTPUT -m pkttype --pkt-type multicast -j DROP
### // DROP: broadcast/multicast ###


### DROP // ###
##/ v4
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
##/ v6
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
### // DROP ###
     #
;;
  1)
     /bin/echo "" # dummy
     printf "\033[1;31mIPsec finished\033[0m\n"
     ###
     #/ clean up
     /bin/rm -rf /tmp/easy_ipsec*.txt
     ###
     exit 0
;;
255)
     /bin/echo "" # dummy
     /bin/echo "[ESC] key pressed."
;;
esac
#)
#
### // ipsec iptable rules ###

### stage3 // ###

### ipsec/openvpn relay setup // ###
#
#(
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --yesno "if you have an IPsec/OpenVPN Relay Server-Setup Go ahead!" 7 70

OPENVPN=$?
case $OPENVPN in
  0)
     /bin/echo "" # dummy
     /bin/echo "" # dummy
;;
  1)
     /bin/echo "" # dummy
     /bin/echo "" # dummy
     printf "\033[1;31mHave a nice day with IPsec\033[0m\n"
     ###
     #/ clean up
     /bin/rm -rf /tmp/easy_ipsec*.txt
     ###
     exit 0
;;
255)
     /bin/echo "" # dummy
     /bin/echo "" # dummy
     /bin/echo "[ESC] key pressed."
;;
esac
#)
#
(
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --msgbox "its time now to establish a successful connection! ... than press OK" 8 80
)
#
### // ipsec/openvpn relay setup ###

### openvpn connection // ###
#
EASYIPSECOVPNCONFIG1="/tmp/easy_ipsec_server_openvpn_config1.txt"
EASYIPSECOVPNCONFIG2="/tmp/easy_ipsec_server_openvpn_config2.txt"
EASYIPSECOVPNCONFIG3="/tmp/easy_ipsec_server_openvpn_config3.txt"
EASYIPSECOVPNCONFIG4="/tmp/easy_ipsec_server_openvpn_config4.txt"
EASYIPSECOVPNCONFIG5="/tmp/easy_ipsec_server_openvpn_config5.txt"

(
# clean up - systemctl
systemctl reset-failed
sleep 1
systemctl daemon-reload
sleep 1
)

systemctl --all | grep openvpn | awk '{print $1}' | egrep -v "system" > "$EASYIPSECOVPNCONFIG1"
nl "$EASYIPSECOVPNCONFIG1" | sed 's/ //g' > "$EASYIPSECOVPNCONFIG2"
/bin/sed 's/$/ off/' "$EASYIPSECOVPNCONFIG2" > "$EASYIPSECOVPNCONFIG3"

dialog --radiolist "Choose one OpenVPN Service:" 45 80 60 --file "$EASYIPSECOVPNCONFIG3" 2>"$EASYIPSECOVPNCONFIG4"
list1=$?
case $list1 in
    0)
       echo "" # dummy
       echo "" # dummy
       awk 'NR==FNR {h[$1] = $2; next} {print $1,$2,h[$1]}' "$EASYIPSECOVPNCONFIG3" "$EASYIPSECOVPNCONFIG4" | awk '{print $2}' | sed 's/"//g' > "$EASYIPSECOVPNCONFIG5"
       GETSERVICE=$(cat "$EASYIPSECOVPNCONFIG5")
       systemctl restart "$GETSERVICE"
       (echo "systemctl restart $GETSERVICE"; sleep 10) & spinner $!
       : # dummy
    ;;
    1)
       echo "" # dummy
       echo "" # dummy
       exit 0
    ;;
  255)
       echo "" # dummy
       echo "" # dummy
       echo "[ESC] key pressed."
       exit 0
    ;;
esac
#
### // openvpn connection ###

### openvpn server // ###
#
EASYIPSECSERVEROVPNTEST="/tmp/easy_ipsec_server_openvpn_test.txt"
touch $EASYIPSECSERVEROVPNTEST
/bin/chmod 0600 $EASYIPSECSERVEROVPNTEST

dialog --inputbox "Enter your VPN OpenVPN Server forwarding interface IP: (for example 172.31.253.1)" 8 85 2>$EASYIPSECSERVEROVPNTEST

EASYIPSECSERVEROVPNTESTVALUE=$(sed 's/#//g' $EASYIPSECSERVEROVPNTEST | sed 's/%//g')

/bin/ping -q -c5 "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null
if [ $? -eq 0 ]
then
      #/ dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "It works!" 0 0
      echo "" # dummy
      echo "" # dummy
      printf "\033[1;32m[OK]\033[0m server is responsive \n"
      sleep 2
else
      #/ dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      echo "" # dummy
      echo "" # dummy
      printf "\033[1;33m[WARNING]\033[0m server isn't responsive \n"
      exit 1
fi

##/bin/rm -rf $EASYIPSECSERVEROVPNTEST
#
### // openvpn server ###

### new default gateway // ###
#
EASYIPSECNETSTATOVPN="/tmp/easy_ipsec_server_openvpn_netstat.txt"
touch $EASYIPSECNETSTATOVPN
/bin/chmod 0600 $EASYIPSECNETSTATOVPN
#
dialog --title "IPsec/OpenVPN Relay Network" --backtitle "IPsec/OpenVPN Relay Network" --msgbox "it seems to work, lets change the default gateway!" 8 70
#
#/ /sbin/route del default > /dev/null 2>&1
/sbin/route del -net 128.0.0.0/1 > /dev/null 2>&1
/sbin/route del -net 0.0.0.0/1 > /dev/null 2>&1
#
EASYIPSECOVPNSUBNET=$(echo "$EASYIPSECSERVEROVPNTESTVALUE" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.' | sed 's/$/0/')
EASYIPSECOVPNINTERFACE=$(netstat -rn4 | grep "$EASYIPSECOVPNSUBNET" | awk '{print $8}')
/bin/ip r a "$EASYIPSECSERVEROVPNTESTVALUE"/32 dev "$EASYIPSECOVPNINTERFACE"
/bin/ip r a 0.0.0.0/1 via "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null 2>&1
/bin/ip r a 128.0.0/1 via "$EASYIPSECSERVEROVPNTESTVALUE" > /dev/null 2>&1
#

### openvpn iptable rules // ##
#
CHECKIPSECIPTABLERULES=$(iptables -S | grep -c "EASYIPSEC")
if [ "$CHECKIPSECIPTABLERULES" = "1" ]
then
    iptables -A INPUT -i "$EASYIPSECOVPNINTERFACE" -j ACCEPT
    iptables -A OUTPUT -o "$EASYIPSECOVPNINTERFACE" -j ACCEPT
    #/ check minidlna
    CHECKIPSECOVPNMINIDLNA=$(dpkg -l | grep -c "minidlna")
    if [ "$CHECKIPSECOVPNMINIDLNA" = "1" ]
    then
       CHECKIPSECOVPNMINIDLNASERVICE=$(systemctl status minidlna | grep -c "running")
       if [ "$CHECKIPSECOVPNMINIDLNASERVICE" = "1" ]
       then
          iptables -A INPUT -i "$EASYIPSECINTERFACEVALUE" -p udp --dport 1900 -j ACCEPT
          iptables -A OUTPUT -o "$EASYIPSECINTERFACEVALUE" -p udp --sport 1900 -j ACCEPT
          iptables -A INPUT -i "$EASYIPSECINTERFACEVALUE" -p tcp --dport 8200 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
          iptables -A OUTPUT -o "$EASYIPSECINTERFACEVALUE" -p tcp --sport 8200 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
          ip6tables -A INPUT -i "$EASYIPSECINTERFACEVALUE" -p udp --dport 1900 -j ACCEPT
          ip6tables -A OUTPUT -o "$EASYIPSECINTERFACEVALUE" -p udp --sport 1900 -j ACCEPT
          ip6tables -A INPUT -i "$EASYIPSECINTERFACEVALUE" -p tcp --dport 8200 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
          ip6tables -A OUTPUT -o "$EASYIPSECINTERFACEVALUE" -p tcp --sport 8200 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
          ##/ v4
          iptables -D INPUT -s 224.0.0.0/4 -j DROP
          iptables -D INPUT -d 224.0.0.0/4 -j DROP
          iptables -D INPUT -s 240.0.0.0/5 -j DROP
          iptables -D INPUT -m pkttype --pkt-type multicast -j DROP
          iptables -D INPUT -m pkttype --pkt-type broadcast -j DROP
          iptables -D OUTPUT -s 224.0.0.0/4 -j DROP
          iptables -D OUTPUT -d 224.0.0.0/4 -j DROP
          iptables -D OUTPUT -s 240.0.0.0/5 -j DROP
          iptables -D OUTPUT -m pkttype --pkt-type multicast -j DROP
          iptables -D OUTPUT -m pkttype --pkt-type broadcast -j DROP
          ##/ v6
          ip6tables -D INPUT -m pkttype --pkt-type multicast -j DROP
          ip6tables -D OUTPUT -m pkttype --pkt-type multicast -j DROP
       fi
    fi
    #/ static ARP
    GETIPSECSERVERGATEWAYFORMAT=$(echo "$EASYIPSECSERVERIPVALUE" | grep -cEo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    if [ "$GETIPSECSERVERGATEWAYFORMAT" = "0" ]
    then
       #/ fqdn
       GETIPSECGATEWAYFQDN=$(netstat -r4 | awk '{print $1,$2}' | grep "$(echo "$EASYIPSECSERVERIPVALUE" | cut -c 1,2,3,4,5,6)" | awk '{print $2}')
       GETIPSECGATEWAYFQDNMAC=$(arp -n | grep "$GETIPSECGATEWAYFQDN" | awk '{print $3}')
       arp -s "$GETIPSECGATEWAYFQDN" "$GETIPSECGATEWAYFQDNMAC"
    else
       #/ ip address
       GETIPSECGATEWAY=$(netstat -rn4 | grep "$EASYIPSECSERVERIPVALUE" | awk '{print $2}')
       GETIPSECGATEWAYMAC=$(arp -n | grep "$GETIPSECGATEWAY" | awk '{print $3}')
       arp -s "$GETIPSECGATEWAY" "$GETIPSECGATEWAYMAC"
   fi
else
    : # dummy
fi
#
### // openvpn iptable rules ###

###
/bin/netstat -rn4 > "$EASYIPSECNETSTATOVPN"
###
#
dialog --textbox "$EASYIPSECNETSTATOVPN" 0 0
#
###
/bin/echo "" # dummy
/bin/echo "" # dummy
printf "\033[1;31mHave a nice day with IPsec and OpenVPN\033[0m\n"
###
#
#HUHU /bin/rm -rf "$EASYIPSECNETSTATOVPN"
#
### // new default gateway ###

### // stage3 ###

### stage4 // ###
#
(
# clean up
/bin/rm -rf /tmp/easy_ipsec*.txt
)
#
### // stage4 ###

### ### ### ### ### ### ### ### ###
   ;;
*)
   # error 1
   echo "<--- --- --->"
   echo ""
   echo "ERROR: Plattform = unknown"
   exit 1
   ;;
esac
### ### ### ### ### ### ### ### ###
   ;;
*)
   # error 1
   echo "<--- --- --->"
   echo ""
   echo "ERROR: Plattform = unknown"
   exit 1
   ;;
esac

#
### // stage1 ###


### ### ### PLITC ### ### ###
# EOF
