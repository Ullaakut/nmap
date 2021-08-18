#!/bin/bash

cat << EOF
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-17 19:23 CEST
************************INTERFACES************************
DEV    (SHORT)  IP/MASK                                   TYPE     UP MTU   MAC
lo     (lo)     127.0.0.1/8                               loopback up 65536
lo     (lo)     ::1/128                                   loopback up 65536 11:11:11:11:11:11

**************************ROUTES**************************
DST/MASK                                  DEV    METRIC GATEWAY
192.168.122.0/24                          virbr0 0
192.168.0.0/23                            wlp5s0 600    192.168.0.1

EOF
