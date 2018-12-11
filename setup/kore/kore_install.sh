#!/bin/ash
cd kore-publisher 

rm random.data
cat /dev/urandom | head -c1024 > random.data
chmod 400 random.data

kodev build > /dev/null 2> /dev/null 
tmux new-session -d -s kore 'cd /kore-publisher && kodev run'
