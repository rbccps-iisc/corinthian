id=$1
apikey=$2
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: audi" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: bmw" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: landrover" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: jaguar" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: autobot" -H "apikey: ${apikey}" -d "{}" -H "is-autonomous:true"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: optimus" -H "apikey: ${apikey}" -d "{}"  -H "is-autonomous:true"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: bumblebee" -H "apikey: ${apikey}" -d "{}"  -H "is-autonomous:true"


