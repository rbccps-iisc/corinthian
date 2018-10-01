#!/bin/ash

set -e 

pwd="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1)"

echo "postgres:$pwd" > postgres_pwd

psql -U postgres postgres  < schema.db >> file
psql -U postgres -c "alter user postgres with password '$pwd'" >> file

