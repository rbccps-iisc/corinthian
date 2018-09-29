import sys
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get(api, headers, data = "dummy"):
	url = "https://127.0.0.1:8888"
	return requests.get(url + "/" + api, headers=headers, data=data, verify = False)

def post(api, headers, data = "dummy"):
	url = "https://127.0.0.1:8888"
	return requests.post(url + "/" + api, headers=headers, data=data, verify = False)

def check(r,c):
	if (r.status_code != c):
		print "Failed : ",r.url
		print r.text
		sys.exit(0)

# delete owners
r = get("deregister-owner", { "id":"admin", "apikey":"x", "entity":"owner-a" })
check(r, 200)

r = get("deregister-owner", { "id":"admin", "apikey":"x", "entity":"owner-b" })
check(r, 200)

# add them
r = get("register-owner", { "id":"admin", "apikey":"x", "entity":"owner-a" })
check(r, 200)
owner_a_apikey = r.json()['apikey']

r = get("register-owner", { "id":"admin", "apikey":"x", "entity":"owner-b" })
check(r, 200)
owner_b_apikey = r.json()['apikey']

r = post("register", {"id":"owner-a", "apikey":owner_a_apikey, "entity":"device"},'{"x":"y"}')
check(r, 200)
device 		= r.json()['id']
device_apikey 	= r.json()['apikey']

r = post("register", {"id":"owner-b", "apikey":owner_b_apikey, "entity":"app"},'{"x":"y"}')
check(r, 200)
app = r.json()['id']
app_apikey = r.json()['apikey']

print device, app

r = get("follow", {"id":"owner-b", "apikey":owner_b_apikey, "from": app, "to":device, "validity":"2", "permission" :"read", "topic":"hello"})
check(r,202)
follow_id = r.json()['follow-id-read']

r = get("share", {"id":"owner-a", "apikey":owner_a_apikey, "follow-id":follow_id})
check(r,200)

r = get("deregister", {"id":"owner-a", "apikey":owner_a_apikey, "entity":"device"})
print "Got ",r.status_code
print "And ",r.text
