#!/bin/ash
cd authenticator 
rm src/authenticator.c
mv src/authenticator_new.c src/authenticator.c
kodev build
kore -r -c conf/authenticator.conf
