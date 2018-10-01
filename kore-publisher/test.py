import random
import sys
import requests

admin_api = "x"

num_devices = 10

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
		print "Failed : expected ",c,"got ",r.status_code, "url = ",r.url
		print r.text
		sys.exit(0)
	else:
		print "---> Ok ",r.url, r.text

# delete owners
r = get("deregister-owner", { "id":"admin", "apikey":admin_api, "entity":"owner-a" })
check(r, 200)

r = get("deregister-owner", { "id":"admin", "apikey":admin_api, "entity":"owner-b" })
check(r, 200)

# add them
r = get("register-owner", { "id":"admin", "apikey":admin_api, "entity":"owner-a" })
check(r, 200)
owner_a_apikey = r.json()['apikey']

r = get("register-owner", { "id":"admin", "apikey":admin_api, "entity":"owner-b" })
check(r, 200)
owner_b_apikey = r.json()['apikey']

a = {}
b = {} 

for i in xrange(0,num_devices):

	r = post("register", {"id":"owner-a", "apikey":owner_a_apikey, "entity":"device-"+str(i)},'{"x":"y"}')
	check(r, 200)
	device 		= r.json()['id']
	device_apikey 	= r.json()['apikey']

	r = post("register", {"id":"owner-b", "apikey":owner_b_apikey, "entity":"app-"+str(i)},'{"x":"y"}')
	check(r, 200)
	app = r.json()['id']
	app_apikey = r.json()['apikey']

	print "Registered device",device
	print "Registered app", app
	
	a[i] = {}
	b[i] = {}
	
	a[i]['name'] = device 
	a[i]['apikey'] = device_apikey

	b[i]['name'] = app 
	b[i]['apikey'] = app_apikey	
	

for i in xrange(0,num_devices):

	a_info = a[i]
	b_info = b[i]

	device = a_info['name']	
	app = b_info['name']	

	device_apikey =	a_info['apikey']
	app_apikey = 	b_info['apikey']

	perm = random.choice(["read","write"])

	r = get("follow", {"id":"owner-b", "apikey":owner_b_apikey,
		"from": app, "to":device, "validity":"2", "permission":perm,
		"topic":"hello"})
	check(r,202)

	follow_id = r.json()["follow-id-"+perm]
	print "Follow id for following ",device, "from ", app , "is ",follow_id

	r = get("share", {"id":"owner-a", "apikey":owner_a_apikey, "follow-id":follow_id})
	check(r,200)

	print "Follow id ",follow_id,"approved"

	"""
	# publish
	print "publishing {"+device+"} with {"+device_apikey+"}"
	r = post("publish",{"id":device,"apikey":device_apikey,"message":"hello", "to":device+".protected", "topic":"hello"})
	check(r,202)
	
	# subscribe
	"""

for i in xrange(0,num_devices):
	r = get("deregister", {"id":"owner-a", "apikey":owner_a_apikey, "entity":"device-"+str(i)})
	check(r,200)

	r = get("deregister", {"id":"owner-b", "apikey":owner_b_apikey, "entity":"app-"+str(i)})
	check(r,200)

# delete owners
r = get("deregister-owner", { "id":"admin", "apikey":admin_api, "entity":"owner-a" })
check(r, 200)

r = get("deregister-owner", { "id":"admin", "apikey":admin_api, "entity":"owner-b" })
check(r, 200)



print "Done"
