#!/bin/bash

set -e

ethtool -K eth0 tx off

ip route change default via $GATEWAY dev eth0

# delete all routes except default
for route in $(ip route show | grep -v default | awk '{print $1}'); do
    ip route del $route
done

./server
