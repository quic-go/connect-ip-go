#!/bin/bash

set -e

SERVER_INTERFACE="eth1"

if [ -n "$GATEWAY_IPV4" ] && ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | grep -q "$GATEWAY_IPV4"; then
  SERVER_INTERFACE="eth0"
fi
if [ -n "$GATEWAY_IPV6" ] && ip addr show eth0 | grep 'inet6 ' | awk '{print $2}' | cut -d/ -f1 | grep -q "$GATEWAY_IPV6"; then
  SERVER_INTERFACE="eth0"
fi

echo "eth0:"
ip addr show eth0
echo "eth1:"
ip addr show eth1

echo "Server facing interface: $SERVER_INTERFACE"
export SERVER_INTERFACE

ethtool -K eth0 tx off
ethtool -K eth1 tx off

iptables -A FORWARD -i eth0 -o eth1 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP
ip6tables -A FORWARD -i eth0 -o eth1 -j DROP
ip6tables -A FORWARD -i eth1 -o eth0 -j DROP

tcpdump -i eth0 -w proxy_eth0.pcap -U &
tcpdump -i eth1 -w proxy_eth1.pcap -U &

./proxy
