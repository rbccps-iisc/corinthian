#!/bin/ash
cd kore-publisher 
kodev build
kore -r -c conf/kore-publisher.conf
