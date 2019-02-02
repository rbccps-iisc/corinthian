#!/bin/ash

sysctl net.core.somaxconn=4096

adduser -h /dev/null -s /sbin/nologin -D -H _kore_auth -u 7777 

tmux new-session -d -s authenticator 'cd /authenticator && kodev build && kore -fc conf/authenticator.conf'

rabbitmq-server -detached > /dev/null 2>&1

