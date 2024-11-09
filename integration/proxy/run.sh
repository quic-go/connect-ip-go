#!/bin/bash

set -e

ethtool -K eth0 tx off
ethtool -K eth1 tx off

iptables -A FORWARD -i eth0 -o eth1 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP
ip6tables -A FORWARD -i eth0 -o eth1 -j DROP
ip6tables -A FORWARD -i eth1 -o eth0 -j DROP

tcpdump -i eth0 -w proxy_eth0.pcap -U &
tcpdump -i eth1 -w proxy_eth1.pcap -U &

./proxy
