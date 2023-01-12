#!/bin/sh

DEV=tun1

ip addr add 1.2.3.4 peer 1.2.3.5 dev $DEV
ip link set up dev $DEV

