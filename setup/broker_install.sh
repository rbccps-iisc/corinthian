#!/bin/ash
cd authenticator 
rm src/authenticator.c
mv src/authenticator_new.c src/authenticator.c
kodev build > /dev/null 2>/dev/null
tmux new-session -d -s authenticator 'cd /authenticator && kodev run'
rabbitmq-server -detached > /dev/null 2>&1

