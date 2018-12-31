#!/bin/ash
rm -r /tmp/tmux-* > /dev/null 2>&1
kodev build > /dev/null 2> /dev/null 
tmux new-session -d -s kore 'cd /kore-publisher && kodev build && kore -fc conf/kore-publisher.conf'
