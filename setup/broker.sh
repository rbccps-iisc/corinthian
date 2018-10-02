#!/bin/ash
cd authenticator 
rm src/authenticator.c
mv src/authenticator_new.c src/authenticator.c
kodev build
tmux new-session -d -s authenticator 'cd /authenticator && kodev run'
rabbitmq-server -detached
