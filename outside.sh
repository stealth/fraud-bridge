#!/bin/sh

DEV=tun1

ip addr add 1.2.3.5 peer 1.2.3.4 dev $DEV
ip link set up dev $DEV

echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

ip -6 x p add dir out proto 58 type 129 code 0 action block

