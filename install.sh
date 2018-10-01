#!/bin/bash

set -e 

docker-compose down 
docker-compose up -d 

docker cp config/schema.db kore-postgres:/
docker cp setup/postgres.sh kore-postgres:/
docker exec kore-postgres chmod +x postgres.sh
docker exec -d kore-postgres ./postgres.sh
docker cp kore-postgres:/postgres_pwd .

pwd=`cat postgres_pwd | cut -d ":" -f 2`

sed -i .bak 's/postgres_pwd/'$pwd'/g' authenticator/src/authenticator.c
sed -i .bak 's/postgres_pwd/'$pwd'/g' kore-publisher/src/kore-publisher.c

docker cp authenticator/ kore-broker:/
docker cp setup/broker.sh kore-broker:/
docker exec kore-broker chmod +x broker.sh
docker exec -d kore-broker ./broker.sh 

docker cp kore-publisher/ kore:/
docker cp setup/kore.sh kore:/
docker exec kore chmod +x kore.sh
docker exec -d kore ./kore.sh 

