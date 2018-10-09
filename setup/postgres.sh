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

# psql -U postgres -c "SET statement_timeout = 0"
# psql -U postgres -c "SET lock_timeout = 0"
# psql -U postgres -c "SET idle_in_transaction_session_timeout = 0"
# psql -U postgres -c "SET client_encoding = 'UTF8'"
# psql -U postgres -c "SET standard_conforming_strings = on"
# psql -U postgres -c "SELECT pg_catalog.set_config('search_path', '', false)"
# psql -U postgres -c "SET check_function_bodies = false"
# psql -U postgres -c "SET client_min_messages = warning"
# psql -U postgres -c "SET row_security = off"
# psql -U postgres -c "COMMENT ON DATABASE postgres IS 'default administrative connection database'"
# psql -U postgres -c "CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog"
# psql -U postgres -c "COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language'"
# psql -U postgres -c "SET default_tablespace = ''"
# psql -U postgres -c "SET default_with_oids = false"
# psql -U postgres -c "CREATE TABLE public.acl (
# 		    	from_id character varying NOT NULL,
#     			exchange character varying NOT NULL,
#     			permission character varying,
#     			valid_till timestamp without time zone,
#     			follow_id character varying,
#     			topic character varying,
#     			acl_id integer NOT NULL
# 			)"
# 
# psql -U postgres -c "ALTER TABLE public.acl OWNER TO postgres"
# psql -U postgres -c "CREATE SEQUENCE public.acl_acl_id_seq
# 			AS integer
#     			START WITH 1
#     			INCREMENT BY 1
#     			NO MINVALUE
#     			NO MAXVALUE
#     			CACHE 1"
# 
# psql -U postgres -c "ALTER TABLE public.acl_acl_id_seq OWNER TO postgres"
# psql -U postgres -c "ALTER SEQUENCE public.acl_acl_id_seq OWNED BY public.acl.acl_id"
# psql -U postgres -c "CREATE TABLE IF NOT EXISTS public.follow (
# 			follow_id integer NOT NULL,
#     			requested_by character varying,
#     			exchange character varying,
#     			'time' timestamp without time zone,
#     			permission character varying,
#     			topic character varying,
#     			validity character varying,
#     			status character varying,
#     			from_id character varying
# 			)"
# 
# 
# psql -U postgres -c "ALTER TABLE public.follow OWNER TO postgres"
# psql -U postgres -c "CREATE SEQUENCE public.follow_follow_id_seq
# 			AS integer
#     			START WITH 1
#     			INCREMENT BY 1
#     			NO MINVALUE
#     			NO MAXVALUE
#     			CACHE 1"
# 
# psql -U postgres -c "ALTER TABLE public.follow_follow_id_seq OWNER TO postgres"
# psql -U postgres -c "ALTER SEQUENCE public.follow_follow_id_seq OWNED BY public.follow.follow_id"
# 
# psql -U postgres -c "CREATE TABLE public.users (
# 			id character varying NOT NULL,
#     			password_hash character varying,
#     			schema jsonb,
#     			salt character varying,
#     			blocked boolean,
#     			is_autonomous boolean
# 			)"
# 
# psql -U postgres -c "ALTER TABLE public.users OWNER TO postgres"
# psql -U postgres -c "ALTER TABLE ONLY public.acl ALTER COLUMN acl_id SET DEFAULT nextval('public.acl_acl_id_seq'::regclass)"
# psql -U postgres -c "ALTER TABLE ONLY public.follow ALTER COLUMN follow_id SET DEFAULT nextval('public.follow_follow_id_seq'::regclass)"
# psql -U postgres -c "ALTER TABLE ONLY public.acl ADD CONSTRAINT acl_pkey PRIMARY KEY (from_id, exchange)"
# psql -U postgres -c "ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id)"
# psql -U postgres -c "ALTER TABLE ONLY public.acl ADD CONSTRAINT acl_id_fkey FOREIGN KEY (from_id) REFERENCES public.users(id)"
# 
