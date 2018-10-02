#!/bin/ash

set -e 

pwd="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1)"

echo "postgres:$pwd" > postgres_pwd

psql -U postgres postgres  < schema.db >> file

psql -U postgres -c "alter user postgres with password '$pwd'" >> file

psql -U postgres -c "insert into users values('admin','8896dc08ba1e17556f336edc11a56e9244bba853a4ae9ccbe54c7e51f683ce62',NULL,'salt','f')"
