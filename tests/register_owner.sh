#!/bin/bash
docker exec -it kore apk add curl 
owner_name=$1
admin_passwd="$(cat ../vars/admin.passwd)"
reg_owner="https://localhost:8888/admin/register-owner -H 'owner:"$owner_name"' -H 'id:"$2"' -H 'apikey:"$admin_passwd"' -d '{"CREATED_FOR":"TESTING_MW"}'"
_curl="curl -k -XPOST "$reg_owner
sudo -- sh -c -e "docker exec -it kore $_curl > ../vars/owner_register.response"
