#!/bin/ash
cd kore-publisher 

if [ -e "jail-keymgr/random.data" ]
then
    rm jail-keymgr/random.data
fi

head -c1024 < /dev/urandom > jail-keymgr/random.data 
chmod 1444 jail-keymgr/random.data

###### For future #####
#for p in $(seq 1 $(nproc --all))
#do
#	adduser -h /dev/null -s /sbin/nologin -D -H kore_worker_$p
#done

adduser -h /dev/null -s /sbin/nologin -D -H kore_worker
adduser -h /dev/null -s /sbin/nologin -D -H kore_keymgr

kodev build > /dev/null 2> /dev/null 
tmux new-session -d -s kore 'cd /kore-publisher && kore -fc conf/kore-publisher.conf'
