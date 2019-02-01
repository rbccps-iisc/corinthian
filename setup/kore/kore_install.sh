#!/bin/ash
cd kore-publisher 

sysctl net.core.somaxconn=4096

if [ -e "jail-keymgr/random.data" ]
then
    rm jail-keymgr/random.data
fi


###### For future #####
#for p in $(seq 1 $(nproc --all))
#do
#	adduser -h /dev/null -s /sbin/nologin -D -H kore_worker_$p -u 888$p
#done

adduser -h /dev/null -s /sbin/nologin -D -H kore_worker -u 8888
adduser -h /dev/null -s /sbin/nologin -D -H kore_keymgr -u 9999

head -c1024 < /dev/urandom > jail-keymgr/random.data 

chown kore_keymgr:kore_keymgr jail-keymgr 
chown kore_keymgr:kore_keymgr jail-keymgr/random.data

chmod 555 jail-keymgr 

# let no one write to random.data
chmod 444 jail-keymgr/random.data

tmux new-session -d -s kore 'cd /kore-publisher && kodev build && kore -fc conf/kore-publisher.conf'
