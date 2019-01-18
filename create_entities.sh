id=$1
apikey=$2
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: ent1" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: ent2" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: ent3" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: ent3" -H "apikey: ${apikey}" -d "{}"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: autoent1" -H "apikey: ${apikey}" -d "{}" -H "is-autonomous:true"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: autoent2" -H "apikey: ${apikey}" -d "{}"  -H "is-autonomous:true"
curl -k -XPOST https://localhost/owner/register-entity -H "id: ${id}" -H "entity: autoent3" -H "apikey: ${apikey}" -d "{}"  -H "is-autonomous:true"


