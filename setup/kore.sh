#!/bin/ash
cd kore-publisher 
rm src/kore-publisher.c
mv src/kore-publisher.c.bak src/kore-publisher.c
kodev build
kore -r -c conf/kore-publisher.conf
