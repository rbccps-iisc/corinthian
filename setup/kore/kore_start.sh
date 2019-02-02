#!/bin/ash
rm -r /tmp/tmux-* > /dev/null 2>&1
tmux new-session -d -s kore 'cd /kore-publisher && kodev build && kore -nfc conf/kore-publisher.conf'
