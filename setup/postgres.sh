#!/bin/ash

#pwd="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1)"

#echo "postgres:$pwd" > postgres_pwd

psql -U postgres -c "create database db" >> file
psql -U postgres db < db.schema >> file
psql -U postgres -c "alter user postgres with password 'password'" >> file

