#!/usr/bin/env bash

set -euxo pipefail

IPT="/sbin/iptables"
IPT6="/sbin/ip6tables"
# the interface which connect to the the internet, 
# the interface which connect to the the internet, 
# it differs if you use wifi or other network device
ITF=enp0s20f0u2
VTF=tun0
LIP="192.168.42.146"    # local IP, check yours IP to modify this
VPNSERVER="209.58.185.234
209.58.185.233"

# git ip via api meta
GIT="192.30.252.0/22
185.199.108.0/22
140.82.112.0/20
13.229.188.59/32
13.250.177.223/32
18.194.104.89/32
18.195.85.27/32
35.159.8.160/32
52.74.223.119/32"

# shortcut of state, we build stateful-firewall
EED="-m state --state ESTABLISHED"
NEW="-m state --state NEW"
NED="-m state --state NEW,ESTABLISHED"
RED="-m state --state RELATED,ESTABLISHED"

# allow dns 
DNS="114.114.114.114"

# bogus filter, it shouldn't appear in outside network
# and you can add yours blacklist here
BADIP="0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/16
192.0.2.0/24
192.88.99.0/24
192.88.99.2/32
192.168.0.0/16
192.0.0.0/24
198.18.0.0/15
203.0.113.0/24
224.0.0.0/3
172.104.64.0/19
5.188.0.0/17
23.252.98.104/32
118.244.0.0/16
125.252.0.0/18
46.174.0.0/16
81.17.16.0/20
222.218.0.0/16
203.208.32.0/19
178.132.0.0/21
74.82.0.0/16
178.73.192.0/18
209.92.0.0/16
209.97.222.140
203.95.213.12
209.58.185.100
203.95.213.129
85.199.214.100"

# flush all the old iptables rules 
$IPT -F
$IPT6 -F
$IPT6 -A INPUT -j DROP
$IPT6 -A FORWARD -j DROP
$IPT6 -A OUTPUT -j DROP

# allow local loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A INPUT ! -i lo -s 127.0.0.1/8 -j DROP
$IPT -A OUTPUT -o lo -j ACCEPT

# allow ping out, icmp echo-reply and fragment request, drop others to defend ICMP SMURF ATTACKS
$IPT -A INPUT -i $ITF -p icmp --icmp-type 0 -m limit --limit 2/s $RED -j ACCEPT
$IPT -A INPUT -i $ITF -p icmp --icmp-type fragmentation-needed $NEW -j ACCEPT
$IPT -A OUTPUT -o $ITF -p icmp $NED -j ACCEPT 
$IPT -A INPUT -i $VTF -p icmp --icmp-type 0 -m limit --limit 2/s $RED -j ACCEPT
$IPT -A INPUT -i $VTF -p icmp --icmp-type fragmentation-needed $NEW -j ACCEPT
$IPT -A OUTPUT -o $VTF -p icmp $NED -j ACCEPT 

# Reject bad ip
for ip in $BADIP
    do
        $IPT -A INPUT -i $ITF -s $ip -j LOG --log-prefix "INPUT BADIP" --log-level 7
        $IPT -A OUTPUT -o $ITF -d $ip -j LOG --log-prefix "OUTPUT BADIP" --log-level 7
        $IPT -A INPUT -i $ITF -s $ip -j DROP
        $IPT -A OUTPUT -o $ITF -d $ip -j DROP
        $IPT -A INPUT -i $VTF -s $ip -j LOG --log-prefix "VINPUT BADIP" --log-level 7
        $IPT -A OUTPUT -o $VTF -d $ip -j LOG --log-prefix "VOUTPUT BADIP" --log-level 7
        $IPT -A INPUT -i $VTF -s $ip -j DROP
        $IPT -A OUTPUT -o $VTF -d $ip -j DROP
    done

# check tcp syn to defend syn-flood attack
$IPT -A INPUT -i $ITF -p tcp ! --syn $NEW -j DROP
$IPT -A INPUT -i $VTF -p tcp ! --syn $NEW -j DROP


# check tcp fragments which are invalid, then drop them 
$IPT -A INPUT -i $ITF -p tcp -f -j DROP
$IPT -A INPUT -i $VTF -p tcp -f -j DROP


# DROP ALL INVALID PACKETS
$IPT -A INPUT -i $ITF -m state --state INVALID -j LOG --log-prefix "input valid" --log-level 7
$IPT -A INPUT -i $ITF -m state --state INVALID -j DROP
$IPT -A FORWARD -i $ITF -m state --state INVALID -j LOG --log-prefix "forward valid" --log-level 7
$IPT -A FORWARD -i $ITF -m state --state INVALID -j DROP 
$IPT -A OUTPUT -o $ITF -m state --state INVALID -j LOG --log-prefix "output valid" --log-level 7
$IPT -A OUTPUT -o $ITF -m state --state INVALID -j DROP

$IPT -A INPUT -i $VTF -m state --state INVALID -j DROP
$IPT -A FORWARD -i $VTF -m state --state INVALID -j DROP
$IPT -A OUTPUT -o $VTF -m state --state INVALID -j DROP

# portscan filter
$IPT -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPT -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,PSH,URG -j DROP

# string filter and log them

$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/sh" -j LOG --log-prefix "bin/sh filterd" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/sh" -j DROP
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/bash" -j LOG --log-prefix "bin/bash filterd" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "bin/bash" -j DROP
$IPT -A INPUT -i $ITF -m string --algo bm --string "tftp" -j LOG --log-prefix "tftp filterd" --log-level 7
$IPT -A INPUT -i $ITF -m string --algo bm --string "tftp" -j DROP
$IPT -A INPUT -i $VTF -m string --algo bm --string "bin/sh" -j LOG --log-prefix "bin/sh filterd" --log-level 7
$IPT -A INPUT -i $VTF -m string --algo bm --string "bin/sh" -j DROP
$IPT -A INPUT -i $VTF -m string --algo bm --string "bin/bash" -j LOG --log-prefix "bin/bash filterd" --log-level 7
$IPT -A INPUT -i $VTF -m string --algo bm --string "bin/bash" -j DROP
$IPT -A INPUT -i $VTF -m string --algo bm --string "tftp" -j LOG --log-prefix "tftp filterd" --log-level 7
$IPT -A INPUT -i $VTF -m string --algo bm --string "tftp" -j DROP

$IPT -A INPUT -i vboxnet0 $EED -j ACCEPT
$IPT -A OUTPUT -o vboxnet0 $NED -j ACCEPT

# allow dns
for ip in $DNS
    do
        $IPT -A INPUT -i $ITF -p udp -s $ip --sport 53 -d $LIP $EED -j ACCEPT
        $IPT -A OUTPUT -o $ITF -p udp -s $LIP -d $ip --dport 53 $NED -j ACCEPT
        $IPT -A INPUT -i $VTF -p udp -s $ip --sport 53  $EED -j ACCEPT
        $IPT -A OUTPUT -o $VTF -p udp -d $ip --dport 53 $NED -j ACCEPT
    done

# allow ntp
#$IPT -A INPUT -i $ITF -p udp --sport 123 -d $LIP $EED -j ACCEPT
#$IPT -A OUTPUT -o $ITF -p udp -s $LIP --dport 123 $NED -j ACCEPT
#$IPT -A INPUT -i $VTF -p udp  --sport 123 $EED -j ACCEPT
#$IPT -A OUTPUT -o $VTF -p udp --dport 123 $NED -j ACCEPT

# allow VPN
for ip in $VPNSERVER
  do
    $IPT -A INPUT -i $ITF -p udp --sport 1194 -s $ip $EED -j ACCEPT
    $IPT -A OUTPUT -o $ITF -p udp --dport 1194 -d $ip $NED -j ACCEPT
  done

# allow dnscrypt-proxy

$IPT -A INPUT -i $ITF -p udp --sport 443 -s 208.67.220.220 $EED -j ACCEPT
$IPT -A OUTPUT -o $ITF -p udp --dport 443 -d 208.67.220.220 $NED -j ACCEPT
$IPT -A INPUT -i $VTF -p udp --sport 443 -s 208.67.220.220 $EED -j ACCEPT
$IPT -A OUTPUT -o $VTF -p udp --dport 443 -d 208.67.220.220 $NED -j ACCEPT

# allow git 
for ip in $GIT
  do
    $IPT -A INPUT -i $ITF -p tcp --sport 22 -s $ip $EED -j ACCEPT
    $IPT -A OUTPUT -o $ITF -p tcp --dport 22 -d $ip $NED -j ACCEPT
  done


# if you need open others udp ports, add them above this line

# drop all else udp and log them
$IPT -A INPUT -i $ITF -p udp -j LOG --log-prefix "IN_UDP droped" --log-level 7
$IPT -A INPUT -i $ITF -p udp -j DROP
$IPT -A OUTPUT -o $ITF -p udp -j LOG --log-prefix "OUT_UDP droped" --log-level 7
$IPT -A OUTPUT -o $ITF -p udp -j DROP

$IPT -A INPUT -i $VTF -p udp -j LOG --log-prefix "IN_UDP droped" --log-level 7
$IPT -A INPUT -i $VTF -p udp -j DROP
$IPT -A OUTPUT -o $VTF -p udp -j LOG --log-prefix "OUT_UDP droped" --log-level 7
$IPT -A OUTPUT -o $VTF -p udp -j DROP

# allow ssh
$IPT -A INPUT -i $ITF -p tcp -s 23.106.135.238 --sport 26399 -d $LIP $EED -j ACCEPT
#$IPT -A OUTPUT -o $ITF -p tcp -s $LIP -d 23.106.135.238 --dport 26399 $NED -j LOG --log-prefix "gid match debug"
$IPT -A OUTPUT -o $ITF -p tcp -s $LIP -d 23.106.135.238 --dport 26399 $NED -j ACCEPT


# allow git push
$IPT -A INPUT -i $ITF -p tcp -d $LIP -s 192.30.255.0/24 --sport 22 $EED -j ACCEPT
$IPT -A OUTPUT -o $ITF -p tcp -s $LIP -d 192.30.255.0/24 --dport 22 $NED -j ACCEPT

# allow http and https
$IPT -A INPUT -i $ITF -p tcp -m multiport --sport 80,443,11371 -d $LIP $EED -j ACCEPT
$IPT -A OUTPUT -o $ITF -p tcp -s $LIP -m multiport --dport 80,443,11371 $NED -j ACCEPT
$IPT -A INPUT -i $VTF -p tcp -m multiport --sport 80,443,11371  $EED -j ACCEPT
$IPT -A OUTPUT -o $VTF -p tcp -m multiport --dport 80,443,11371 $NED -j ACCEPT


# if you need open others tcp ports, add these above this line
# drop all else and log them
$IPT -A INPUT -j LOG --log-prefix "IPT_droped" --log-level 7
$IPT -A FORWARD -j LOG --log-prefix "FWD_droped" --log-level 7
$IPT -A OUTPUT -j LOG --log-prefix "OUT_droped" --log-level 7
$IPT -A INPUT -j DROP
$IPT -A FORWARD -j DROP
$IPT -A OUTPUT -j DROP
