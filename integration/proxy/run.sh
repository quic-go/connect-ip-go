#!/bin/bash

set -e

# The proxy is set up with two Docker networks.
# This creates two network interfaces, eth0 and eth1.
# However, the setup is not deterministic:
# We don't know which interface will be assigned to which network.
# We therefore swap eth0 and eth1 such that eth0 is the interface facing the client,
# and eth1 is the interface facing the server.
swap_interfaces() {
  echo "swapping eth0 and eth1"
  ip link set eth0 down
  ip link set eth1 down
  ip link set eth0 name eth_temp
  ip link set eth1 name eth0
  ip link set eth_temp name eth1
  ip link set eth0 up
  ip link set eth1 up
}

echo "GATEWAY_IPV4: $GATEWAY_IPV4"
echo "GATEWAY_IPV6: $GATEWAY_IPV6"

echo "inet eth0: $(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)"
echo "inet6 eth0: $(ip addr show eth0 | grep 'inet6 ' | awk '{print $2}' | cut -d/ -f1)"

if [ -n "$GATEWAY_IPV4" ] && ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | grep -q "$GATEWAY_IPV4"; then
  swap_interfaces
fi
if [ -n "$GATEWAY_IPV6" ] && ip addr show eth0 | grep 'inet6 ' | awk '{print $2}' | cut -d/ -f1 | grep -q "$GATEWAY_IPV6"; then
    swap_interfaces
fi

echo "eth0:"
ip addr show eth0
echo "eth1:"
ip addr show eth1

ethtool -K eth0 tx off
ethtool -K eth1 tx off

iptables -A FORWARD -i eth0 -o eth1 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP
ip6tables -A FORWARD -i eth0 -o eth1 -j DROP
ip6tables -A FORWARD -i eth1 -o eth0 -j DROP

tcpdump -i eth0 -w proxy_eth0.pcap -U &
tcpdump -i eth1 -w proxy_eth1.pcap -U &

./proxy
