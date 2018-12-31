#!/bin/ash
cd authenticator 
sysctl net.core.somaxconn=4096
kodev build > /dev/null 2>/dev/null
tmux new-session -d -s authenticator 'cd /authenticator && kodev run'
rabbitmq-server -detached > /dev/null 2>&1

