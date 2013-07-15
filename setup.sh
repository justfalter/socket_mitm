#!/bin/bash
export SRC_IP=10.211.55.21
iptables -t nat -F PREROUTING
iptables -t nat -A PREROUTING -p tcp --src $SRC_IP -m tcp --syn -m mark ! --mark 0x1000000 -j QUEUE
iptables -t nat -A PREROUTING -p tcp --src $SRC_IP -m tcp --syn -m mark --mark 0x1000000 -j REDIRECT --to-ports 9999
