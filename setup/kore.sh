#!/bin/ash
cd kore-publisher 
rm src/kore-publisher.c
mv src/kore-publisher_new.c src/kore-publisher.c
kodev build
kore -r -c conf/kore-publisher.conf
