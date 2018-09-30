#!/bin/ash
cd authenticator 
kodev build
kore -r -c conf/authenticator.conf
