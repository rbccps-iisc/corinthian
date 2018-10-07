#!/bin/ash

set -e 

pwd="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1)"

echo "postgres:$pwd" > postgres_pwd

until su postgres -c 'pg_isready' >/dev/null 2>&1
do
:
done

psql -U postgres < schema.db
psql -U postgres -c "alter user postgres with password '$pwd'" 

psql -U postgres -c "insert into users values('admin','8896dc08ba1e17556f336edc11a56e9244bba853a4ae9ccbe54c7e51f683ce62',NULL,'salt','f')"
psql -U postgres -c "insert into users values('admin1','fa8d4b8fe10794af430f04b7af55388be9f676361c49849daff827918b6bd2f3',NULL,'salt','f')"
