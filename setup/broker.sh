#!/bin/ash
cd authenticator 
rm src/authenticator.c.bak
kodev build
kore -r -c conf/authenticator.conf
