#!/bin/ash
cd kore-publisher 
rm src/kore-publisher.c
mv src/kore-publisher_new.c src/kore-publisher.c
kodev build > /dev/null 2> /dev/null 
tmux new-session -d -s kore 'cd /kore-publisher && kodev run'
