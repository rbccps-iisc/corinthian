#!/bin/ash

rm -r /tmp/tmux-* > /dev/null 2>&1
tmux new-session -d -s authenticator 'cd /authenticator && kodev build && kore -fc conf/authenticator.conf'
rabbitmq-server -detached > /dev/null 2>&1
