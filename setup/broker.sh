#!/bin/ash
cd authenticator 
rm src/authenticator.c
mv src/authenticator.c.bak src/authenticator.c
kodev build
kore -r -c conf/authenticator.conf
