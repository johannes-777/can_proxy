#!/bin/bash
IF="can1"

clear
ifconfig $IF down
ip link set $IF type can bitrate 125000
ifconfig $IF up

#python3 can_proxy.py $IF localhost 770
python3 can_proxy.py $IF 172.30.33.21 770