import time
import random
import sys
import requests

admin_api = "x"
num_devices = 10

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get(api, headers, data = "dummy"):
	headers["Connection"] = "close"
	url = "https://127.0.0.1:8888"
	return requests.get(url + "/" + api, headers=headers, data=data, verify = False)

def post(api, headers, data = "dummy"):
	headers["Connection"] = "close"
	url = "https://127.0.0.1:8888"
	return requests.post(url + "/" + api, headers=headers, data=data, verify = False)

def check(r,c):
	if (r.status_code != c):
		print "Failed : expected ",c,"got ",r.status_code, "url = ",r.url
		print r._content
		sys.exit(0)
	else:
		print "---> Ok [",r.status_code,"]",r.url, r._content.strip()


print "De registering owners"
# delete owners
r = get("deregister-owner", { "id":"admin", "apikey":admin_api, "owner":"owner-a"})
check(r, 200)

r =get("deregister-owner", { "id":"admin", "apikey":admin_api, "owner":"owner-b" })
check(r, 200)


print "\nRegistering owners"

# add them
r =get("register-owner", { "id":"admin", "apikey":admin_api, "owner":"owner-a" })
owner_a_apikey = r.json()['apikey']
check(r, 200)

r =get("register-owner", { "id":"admin", "apikey":admin_api, "owner":"owner-b" })
owner_b_apikey = r.json()['apikey']
check(r, 200)

a = {}
b = {} 

t_register = time.time()
print "\nRegistering devices"

for i in xrange(0,num_devices):

	r =post("register", {"id":"owner-a", "apikey":owner_a_apikey, "entity":"device-"+str(i)},'{"x":"y"}')
	device 		= r.json()['id']
	device_apikey 	= r.json()['apikey']
	check(r, 200)

	r =post("register", {"id":"owner-b", "apikey":owner_b_apikey, "entity":"app-"+str(i)},'{"x":"y"}')
	app = r.json()['id']
	app_apikey = r.json()['apikey']
	check(r, 200)

	a[i] = {}
	b[i] = {}
	
	a[i]['name'] = device 
	a[i]['apikey'] = device_apikey

	b[i]['name'] = app 
	b[i]['apikey'] = app_apikey	
	
t_register =time.time() - t_register

print "\nFollow-Share"
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
	follow_id = r.json()["follow-id-"+perm]
	check(r,202)


	r._content = ""
	r =get("share", {"id":"owner-a", "apikey":owner_a_apikey, "follow-id":follow_id})
	check(r,200)

	"""
	# publish
	print "publishing {"+device+"} with {"+device_apikey+"}"
	r =post("publish",{"id":device,"apikey":device_apikey,"message":"hello", "to":device+".protected", "topic":"hello"})
	check(r,202)
	
	# subscribe
	"""

t_dregister = time.time()
print "\nDeleting entities"
for i in xrange(0,num_devices):
	a_info = a[i]
	b_info = b[i]

	device = a_info['name']	
	app = b_info['name']	

	r =get("deregister", {"id":"owner-a", "apikey":owner_a_apikey, "entity":device})
	check(r,200)

	r =get("deregister", {"id":"owner-b", "apikey":owner_b_apikey, "entity":app})
	check(r,200)

t_dregister =time.time() - t_dregister


print "\nDeleting owners"
# delete owners
r =get("deregister-owner", { "id":"admin", "apikey":admin_api, "owner":"owner-a" })
check(r, 200)

r =get("deregister-owner", { "id":"admin", "apikey":admin_api, "owner":"owner-b" })
check(r, 200)

print 

print "===>",t_register,"seconds to register   ",2*num_devices,"entities", " >> avg = ", (t_register)/(2*num_devices),"seconds"
print "===>",t_dregister,"seconds to de-register",2*num_devices,"entities", " >> avg = ", (t_dregister)/(2*num_devices),"seconds"

print "\nDone"
