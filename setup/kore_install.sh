#!/bin/ash
cd kore-publisher 
kodev build > /dev/null 2> /dev/null 
tmux new-session -d -s kore 'cd /kore-publisher && kodev run'
