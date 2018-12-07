#!/bin/bash
docker exec -it kore apk add curl 
owner_name=$1
admin_passwd="$(cat ../vars/admin.passwd)"
reg_owner="https://localhost:8888/admin/register-owner -H 'owner:"$owner_name"' -H 'id:admin' -H 'apikey:"$admin_passwd"' -d '{test:test}'"
_curl="curl -ik -XPOST "$reg_owner
echo $_curl
docker exec -it kore $_curl
echo "done"
#sudo -- sh -c -e "docker exec -it kore $_curl > ../vars/owner.credentials";