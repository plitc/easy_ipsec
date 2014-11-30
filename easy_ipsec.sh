#!/bin/sh
#
### LICENSE // ###
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
### // LICENSE ###
#
### ### ### PLITC ### ### ###


### stage0 // ###
#
UNAME=$(uname)
MYNAME=$(whoami)
#
### // stage0 ###

### stage1 // ###
#
case $UNAME in
Darwin)
   ### MacOS ###
#
BREW=$(/usr/bin/which brew)
MDIALOG=$(/usr/bin/which dialog)
LASTUSER=$(/usr/bin/last | head -n 1 | awk '{print $1}')
#LASTGROUP0=$(/usr/bin/id $LASTUSER | awk '{print $2}' | sed 's/[^0-9]*//g')
LASTGROUP=$(/usr/bin/id $LASTUSER | grep -o 'gid=[^(]*[^)]*)' | sed 's/[0-9]//g' | sed 's/gid=(//g' | sed 's/)//g')
#
### ### ### ### ### ### ### ### ###

if [ $MYNAME = root ]; then
   echo "" # dummy
else
   echo "<--- --- --->"
   echo ""
   echo "ERROR: You must be root to run this script"
   exit 1
fi

if [ -z $BREW ]; then
   echo "<--- --- --->"
   echo "need homebrew"
   echo "<--- --- --->"
        ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
   echo "<--- --- --->"
else
   echo "" # dummy
fi

if [ -z $MDIALOG ]; then
   echo "<--- --- --->"
   echo "need dialog"
   echo "<--- --- --->"
        /usr/sbin/chown -R "$LASTUSER:$LASTGROUP" /usr/local
        sudo -u $LASTUSER -s "/usr/local/bin/brew install dialog"
   echo "<--- --- --->"
else
   echo "" # dummy
fi

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
/sbin/ifconfig gif0 create 2>&1 > /dev/null
/sbin/ifconfig gif0 up
### // run
#
GIF1=`expr $GIF1 + 50`
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "create gif interface" 20 70 0

EASYIPSECCLIENTIP="/tmp/easy_ipsec_client_ip.txt"
touch $EASYIPSECCLIENTIP

dialog --inputbox "Enter your Roadwarrior Client IP: (for example 10.0.0.1)" 8 40 2>$EASYIPSECCLIENTIP

EASYIPSECDESTNET="/tmp/easy_ipsec_destination_net.txt"
touch $EASYIPSECDESTNET

dialog --inputbox "Enter your VPN destination network: (for example 172.31.254.0)" 8 40 2>$EASYIPSECDESTNET

EASYIPSECCLIENTIPVALUE=$(/bin/cat $EASYIPSECCLIENTIP | sed 's/#//g' | sed 's/%//g')
EASYIPSECDESTNETVALUE=$(/bin/cat $EASYIPSECDESTNET | sed 's/#//g' | sed 's/%//g')

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
/sbin/ifconfig gif0 $EASYIPSECCLIENTIPVALUE $EASYIPSECDESTNETVALUE
/sbin/route add -net $EASYIPSECDESTNETVALUE/24 -interface gif0 2>&1 > /dev/null
### // run
#
GIF2=`expr $GIF2 + 50`
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set gif options" 20 70 0

EASYIPSECSERVERIP="/tmp/easy_ipsec_server_ip.txt"
touch $EASYIPSECSERVERIP

dialog --inputbox "Enter your VPN IPsec Server IP:" 8 40 2>$EASYIPSECSERVERIP

EASYIPSECLOCALGATEWAY="/tmp/easy_ipsec_local_gateway.txt"
touch $EASYIPSECLOCALGATEWAY

dialog --inputbox "Enter your local gateway IP:" 8 40 2>$EASYIPSECLOCALGATEWAY

EASYIPSECSERVERIPVALUE=$(/bin/cat $EASYIPSECSERVERIP | sed 's/#//g' | sed 's/%//g')
EASYIPSECLOCALGATEWAYVALUE=$(/bin/cat $EASYIPSECLOCALGATEWAY | sed 's/#//g' | sed 's/%//g')

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
/sbin/route delete -host $EASYIPSECSERVERIPVALUE 2>&1 > /dev/null
/sbin/route add -host $EASYIPSECSERVERIPVALUE $EASYIPSECLOCALGATEWAYVALUE 2>&1 > /dev/null
### // run
#
GIF3=`expr $GIF3 + 50`
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set direct vpn server route" 20 70 0

### check vpn server //
#
/bin/echo ""
(
/sbin/ping -q -c5 $EASYIPSECSERVERIPVALUE > /dev/null

if [ $? -eq 0 ]
then
      /bin/echo ""
      /bin/echo "server is responsive"
      sleep 3
      exit 0
else
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 2
fi
)
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

dialog --inputbox "Enter your VPN IPsec Server Pre-shared key: (without spaces and pound)" 8 85 2>$EASYIPSECSERVERPSK

EASYIPSECSERVERPSKVALUE=$(/bin/cat $EASYIPSECSERVERPSK | sed 's/#//g' | sed 's/%//g')

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
        phase2          100 sec;
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
                                lifetime time           1800 sec;
                                encryption_algorithm    aes 256;
                                hash_algorithm          sha512;
                                authentication_method   pre_shared_key;
                        }
}

sainfo (address $EASYIPSECCLIENTIPVALUE/32 any address $EASYIPSECDESTNETVALUE/24 any)
{
        # remoteid 1;
        pfs_group       16;
        lifetime        time       18000 sec;
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
#/bin/launchctl stop com.apple.syslog
#sleep 1
#/bin/launchctl start com.apple.syslog
#
)
#
(
/bin/echo ""
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
dialog --textbox "$RACOONLOG" 0 0
)
#
### // start ipsec

### ipsec test //
#
(
EASYIPSECSERVERTEST="/tmp/easy_ipsec_server_test.txt"
touch $EASYIPSECSERVERTEST
/bin/chmod 0600 $EASYIPSECSERVERTEST

dialog --inputbox "Enter your VPN IPsec Server forwarding interface IP: (for example 172.31.254.254)" 8 85 2>$EASYIPSECSERVERTEST

EASYIPSECSERVERTESTVALUE=$(/bin/cat $EASYIPSECSERVERTEST | sed 's/#//g' | sed 's/%//g')

/sbin/ping -q -c5 $EASYIPSECSERVERTESTVALUE > /dev/null

if [ $? -eq 0 ]
then
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "It works!" 0 0
      exit 0
else
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 3
fi
)
/bin/rm -rf $EASYIPSECSERVERTEST
#
### // ipsec test

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
      exit 4
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

EASYIPSECSERVEROVPNTESTVALUE=$(/bin/cat $EASYIPSECSERVEROVPNTEST | sed 's/#//g' | sed 's/%//g')
(
/sbin/ping -q -c5 $EASYIPSECSERVEROVPNTESTVALUE > /dev/null

if [ $? -eq 0 ]
then
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "It works!" 0 0
      exit 0
else
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 5
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
/sbin/route delete default 2>&1 > /dev/null
/sbin/route delete 128.0.0.0/1 2>&1 > /dev/null
/sbin/route delete 0.0.0.0/1 2>&1 > /dev/null
#
/sbin/route add -net 128.0.0.0/1 $EASYIPSECSERVEROVPNTESTVALUE 2>&1 > /dev/null
/sbin/route add -net 0.0.0.0/1 $EASYIPSECSERVEROVPNTESTVALUE 2>&1 > /dev/null
#
###
/usr/sbin/netstat -rn -f inet > $EASYIPSECNETSTATOVPN
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
FreeBSD)
   ### FreeBSD ###
#
FRACOON=$(/usr/bin/which racoon)
FOPENVPN=$(/usr/bin/which openvpn)
#
### ### ### ### ### ### ### ### ###

if [ $MYNAME = root ]; then
   echo "" # dummy
else
   echo "<--- --- --->"
   echo ""
   echo "ERROR: You must be root to run this script"
   exit 1
fi

if [ -z $FRACOON ]; then
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

if [ -z $FOPENVPN ]; then
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
/sbin/ifconfig gif0 create 2>&1 > /dev/null
/sbin/ifconfig gif0 up
### // run
#
GIF1=`expr $GIF1 + 50`
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "create gif interface" 20 70 0

EASYIPSECCLIENTIP="/tmp/easy_ipsec_client_ip.txt"
touch $EASYIPSECCLIENTIP

dialog --inputbox "Enter your Roadwarrior Client IP: (for example 10.0.0.1)" 8 40 2>$EASYIPSECCLIENTIP

EASYIPSECDESTNET="/tmp/easy_ipsec_destination_net.txt"
touch $EASYIPSECDESTNET

dialog --inputbox "Enter your VPN destination network: (for example 172.31.254.0)" 8 40 2>$EASYIPSECDESTNET

EASYIPSECCLIENTIPVALUE=$(/bin/cat $EASYIPSECCLIENTIP | sed 's/#//g' | sed 's/%//g')
EASYIPSECDESTNETVALUE=$(/bin/cat $EASYIPSECDESTNET | sed 's/#//g' | sed 's/%//g')

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
/sbin/ifconfig gif0 $EASYIPSECCLIENTIPVALUE $EASYIPSECDESTNETVALUE
/sbin/route add -net $EASYIPSECDESTNETVALUE/24 -interface gif0 2>&1 > /dev/null
### // run
#
GIF2=`expr $GIF2 + 50`
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set gif options" 20 70 0

EASYIPSECSERVERIP="/tmp/easy_ipsec_server_ip.txt"
touch $EASYIPSECSERVERIP

dialog --inputbox "Enter your VPN IPsec Server IP:" 8 40 2>$EASYIPSECSERVERIP

EASYIPSECLOCALGATEWAY="/tmp/easy_ipsec_local_gateway.txt"
touch $EASYIPSECLOCALGATEWAY

dialog --inputbox "Enter your local gateway IP:" 8 40 2>$EASYIPSECLOCALGATEWAY

EASYIPSECSERVERIPVALUE=$(/bin/cat $EASYIPSECSERVERIP | sed 's/#//g' | sed 's/%//g')
EASYIPSECLOCALGATEWAYVALUE=$(/bin/cat $EASYIPSECLOCALGATEWAY | sed 's/#//g' | sed 's/%//g')

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
/sbin/route del -host $EASYIPSECSERVERIPVALUE $EASYIPSECLOCALGATEWAYVALUE 2>&1 > /dev/null
/sbin/route add -host $EASYIPSECSERVERIPVALUE $EASYIPSECLOCALGATEWAYVALUE 2>&1 > /dev/null
### // run
#
GIF3=`expr $GIF3 + 50`
sleep 1
done
) | dialog --title "generic tunnel interface" --gauge "set direct vpn server route" 20 70 0

### check vpn server //
#
/bin/echo ""
(
/sbin/ping -q -c5 $EASYIPSECSERVERIPVALUE > /dev/null

if [ $? -eq 0 ]
then
      /bin/echo ""
      /bin/echo "server is responsive"
      sleep 3
      exit 0
else
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 2
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

EASYIPSECSERVERPSKVALUE=$(/bin/cat $EASYIPSECSERVERPSK | sed 's/#//g' | sed 's/%//g')

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
        phase2          100 sec;
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
                                lifetime time           1800 sec;
                                encryption_algorithm    aes 256;
                                hash_algorithm          sha512;
                                authentication_method   pre_shared_key;
                        }
}

sainfo (address $EASYIPSECCLIENTIPVALUE/32 any address $EASYIPSECDESTNETVALUE/24 any)
{
        # remoteid 1;
        pfs_group       16;
        lifetime        time       18000 sec;
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
(
EASYIPSECSERVERTEST="/tmp/easy_ipsec_server_test.txt"
touch $EASYIPSECSERVERTEST
/bin/chmod 0600 $EASYIPSECSERVERTEST
   
dialog --inputbox "Enter your VPN IPsec Server forwarding interface IP: (for example 172.31.254.254)" 8 85 2>$EASYIPSECSERVERTEST

EASYIPSECSERVERTESTVALUE=$(/bin/cat $EASYIPSECSERVERTEST | sed 's/#//g' | sed 's/%//g')

/sbin/ping -q -c5 $EASYIPSECSERVERTESTVALUE > /dev/null

if [ $? -eq 0 ]
then
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "It works!" 0 0
      exit 0
else
      dialog --title "VPN IPsec Gateway Test" --backtitle "VPN IPsec Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 3
fi        
)
#
### // ipsec test

/bin/echo ""
/bin/echo "prepare racoon log ... wait a minute"
/bin/echo ""
sleep 15

/bin/cat /var/log/racoon.log | egrep "established|WARNING" > /tmp/easy_ipsec_racoon_log.txt
#
RACOONLOG="/tmp/easy_ipsec_racoon_log.txt"
#
(
dialog --textbox "$RACOONLOG" 0 0
)
#
/bin/rm -rf $EASYIPSECSERVERTEST
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
      exit 4
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

EASYIPSECSERVEROVPNTESTVALUE=$(/bin/cat $EASYIPSECSERVEROVPNTEST | sed 's/#//g' | sed 's/%//g')
(
/sbin/ping -q -c5 $EASYIPSECSERVEROVPNTESTVALUE > /dev/null

if [ $? -eq 0 ]
then
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "It works!" 0 0
      exit 0
else
      dialog --title "VPN OpenVPN Gateway Test" --backtitle "VPN OpenVPN Gateway Test" --msgbox "ERROR: can't ping!" 0 0
      /bin/echo ""
      /bin/echo "ERROR: server isn't responsive"
      exit 5
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
/sbin/route delete default 2>&1 > /dev/null
/sbin/route delete 128.0.0.0/1 2>&1 > /dev/null
/sbin/route delete 0.0.0.0/1 2>&1 > /dev/null
#
/sbin/route add -net 128.0.0.0/1 $EASYIPSECSERVEROVPNTESTVALUE 2>&1 > /dev/null
/sbin/route add -net 0.0.0.0/1 $EASYIPSECSERVEROVPNTESTVALUE 2>&1 > /dev/null
#
###
/usr/bin/netstat -rn -f inet > $EASYIPSECNETSTATOVPN
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
*)
   # error 1
   echo "<--- --- --->"
   echo ""
   echo "ERROR: Plattform = unknown"
   exit 6
   ;;
esac

#
### // stage1 ###


### ### ### PLITC ### ### ###
# EOF
