#!/bin/ash
cd kore-publisher 
rm src/kore-publisher.c.bak
kodev build
kore -r -c conf/kore-publisher.conf
