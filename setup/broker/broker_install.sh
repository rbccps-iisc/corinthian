#!/bin/ash

sysctl net.core.somaxconn=4096
adduser -h /dev/null -s /sbin/nologin -D -H kore_auth

cd authenticator 
kodev build > /dev/null 2>/dev/null
tmux new-session -d -s authenticator 'cd /authenticator && kore -fc conf/authenticator.conf'

rabbitmq-server -detached > /dev/null 2>&1

