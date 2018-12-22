#!/bin/ash

set -e 

postgres_pwd="$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w ${1:-32} | head -n 1)"
admin_pwd="$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w ${1:-32} | head -n 1)"
salt="$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w ${1:-32} | head -n 1)"

string=$admin_pwd$salt"admin"
hash=$(echo -n $string | sha256sum | cut -d ' ' -f 1)


echo $postgres_pwd > /vars/postgres.passwd
echo $admin_pwd > /vars/admin.passwd

su postgres -c "postgres -D /var/lib/postgresql > /var/lib/postgresql/logfile 2>&1 &"

until su postgres -c 'pg_isready' >/dev/null 2>&1
do
sleep 0.1
done

psql -U postgres -c "alter user postgres with password '$postgres_pwd'" > /dev/null 2>&1 
psql -U postgres -c "insert into users values('admin','$hash',NULL,'$salt','f', 't')" > /dev/null 2>&1
