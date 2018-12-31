#!/bin/ash
cd kore-publisher 

head -c1024 < /dev/urandom > jail-keymgr/random.data 
chown kore_keymgr:kore_keymgr jail-keymgr 
chown kore_keymgr:kore_keymgr jail-keymgr/random.data
chmod u+rw jail-keymgr/random.data
