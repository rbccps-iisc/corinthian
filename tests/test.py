import json
import argparse
import random
import string
import argparse
import logging
import time
import warnings
import subprocess
import requests 
import urllib3
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl

class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)

s = requests.Session()
s.mount('https://', MyAdapter())
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

base_url = "https://localhost:8888"

parser = argparse.ArgumentParser(description='Test cases for Corinthian')
parser.add_argument('-d', action="store", dest="devices", type=int)
parser.add_argument('-a', action="store", dest="apps", type=int)

results = parser.parse_args()

devices = results.devices
apps = results.apps

device_keys = {}
app_keys = {}

class colour:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def check(response, code):
	
    if response.status_code == code:
        return True
    else:
        return False


def register(owner_id, apikey, entity_id):
	
	url = base_url + "/register"
	headers = {"id": owner_id, "apikey":apikey, "entity": entity_id, "content-type":"application/json"}
	r = s.post(url=url, headers=headers, data="{\"test\":\"schema\"}", verify=False)
	return r

def deregister(owner_id, apikey, entity_id):
    url = base_url + "/deregister"
    headers = {"id": owner_id, "apikey": apikey, "entity": entity_id}
    r = requests.get(url=url, headers=headers, verify=False)
    return r


def publish(entity_id, apikey, to, topic, message_type, data):
    url = base_url + "/publish"
    headers = {"id": entity_id, "apikey": apikey, "to": to, "topic": topic, "message-type": message_type}
    r = requests.post(url=url, headers=headers, data=data, verify=False)
    return r


def follow(user_id, apikey, to_id, permission, from_id=""):
    headers = {}

    if from_id:
        headers['from'] = from_id

    headers['id'] = user_id
    headers['apikey'] = apikey
    headers['to'] = to_id
    headers['validity'] = "24"
    headers['topic'] = "#"
    headers['permission'] = permission

    url = base_url + "/follow"
    r = requests.get(url=url, headers=headers, verify=False)
    return r


def unfollow(ID, apikey, to, topic, permission, from_id=""):
    headers = {}

    if from_id:
        headers['from'] = from_id

    headers['id'] = ID
    headers['apikey'] = apikey
    headers['to'] = to
    headers['topic'] = topic
    headers['permission'] = permission

    url = base_url + "/unfollow"
    r = requests.get(url=url, headers=headers, verify=False)
    return r


def share(ID, apikey, follow_id):
    url = base_url + "/share"
    headers = {"id": ID, "apikey": apikey, "follow-id": follow_id}
    r = requests.get(url=url, headers=headers, verify=False)
    return r


def bind_unbind(ID, apikey, to, topic, req_type, from_id="", message_type=""):
    headers = {}

    if from_id:
        headers['from'] = from_id
    if message_type:
        headers['message_type'] = message_type

    headers['id'] = ID
    headers['apikey'] = apikey
    headers['to'] = to
    headers['topic'] = topic

    if req_type == "bind":
        url = base_url + "/bind"
    elif req_type == "unbind":
        url = base_url + "/unbind"

    r = requests.get(url=url, headers=headers, verify=False)
    return r


def subscribe(ID, apikey, message_type="", num_messages=""):
    headers = {}

    if message_type:
        headers['message-type'] = message_type
    if num_messages:
        headers['num-messages'] = num_messages

    headers['id'] = ID
    headers['apikey'] = apikey

    url = base_url + "/subscribe"
    r = requests.get(url=url, headers=headers, verify=False)
    return r


def follow_requests(ID, apikey, request_type):
    url = base_url

    if request_type == "requests":
        url = url + "/follow-requests"
    elif request_type == "status":
        url = url + "/follow-status"

    r = requests.get(url=url, headers={"id": ID, "apikey": apikey}, verify=False)
    return r


def dev_publish():
    for device, apikey in device_keys.items():
        logger.info("PUBLISHING MESSAGE FROM " + device)
        pub_req = publish(device, apikey, device, "#", "protected", "test message from " + device)
        pub_status = check(pub_req, 202)
        assert (pub_status)


def bind_unbind_dev(as_admin="", req_type="", expected=devices):

    if as_admin == False:
        approved = 0
        for app, apikey in app_keys.items():
            logger.info("APP " + app + " CHECKING APPROVAL STATUS OF FOLLOW REQUESTS BEFORE BINDING")
            follow_status = follow_requests(app, apikey, "status")
            flag = check(follow_status, 200)

            for entry in follow_status.json():
                if entry['status'] == "approved":
                    approved = approved + 1

            assert (approved == expected)
            logger.info("APP " + app + " HAS RECEIVED " + str(approved) + " APPROVALS")
            approved = 0
        for app, apikey in app_keys.items():
            for device in device_keys:
                logger.info("APP " + app + " (UN)BINDING FROM DEVICE " + device)
                bind_req = bind_unbind(app, apikey, device, "#", req_type)
                bind_status = check(bind_req, 200)
                assert (bind_status)

    elif as_admin == True:

        approved = 0

        for app in app_keys:

            logger.info("APP " + app + " CHECKING APPROVAL STATUS OF FOLLOW REQUESTS BEFORE BINDING")
            follow_status = follow_requests("admin1", "admin1", "status")
            flag = check(follow_status, 200)

            for entry in follow_status.json():
                if entry['status'] == "approved":
                    approved = approved + 1

            assert (approved == expected)
            logger.info("APP ADMIN HAS RECEIVED " + str(approved) + " APPROVALS")
            approved = 0

        for app in app_keys:
            for device in device_keys:
                logger.info("APP " + app + " BINDING TO DEVICE " + device)
                bind_req = bind_unbind("admin1", "admin1", device, "#", req_type, from_id=app)
                bind_status = check(bind_req, 200)
                assert (bind_status)


def bind_unbind_without_follow(as_admin="", req_type=""):

	if as_admin == False:
        	for app, apikey in app_keys.items():
            		for device in device_keys:
                		logger.info("APP " + app + " (UN)BINDING FROM DEVICE " + device)
                		bind_req = bind_unbind(app, apikey, device, "#", req_type)
                		bind_status = check(bind_req, 403)
                		assert (bind_status)

    	elif as_admin == True:
        	for app in app_keys:
            		for device in device_keys:
                		logger.info("APP " + app + " BINDING TO DEVICE " + device)
                		bind_req = bind_unbind("admin1", "admin1", device, "#", req_type, from_id=app)
                		bind_status = check(bind_req, 403)
                		assert (bind_status)

def app_subscribe(expected):
    count = devices % 10

    if count == 0:
        count = devices / 10

    actual = 0

    for app, apikey in app_keys.items():

        logger.info("APP " + app + " SUBSCRIBING TO ITS QUEUE")

        for i in range(0, count):
            sub_req = subscribe(app, apikey, num_messages="10")
            sub_status = check(sub_req, 200)
            response = sub_req.json()
            actual = actual + len(response)

        assert (actual == expected)
        actual = 0
        logger.info("APP " + app + " has successfully received " + str(expected) + " messages")


def follow_dev(as_admin="", permission=""):
    if as_admin == True:
        for app in app_keys:
            for device in device_keys:
                logger.info("FOLLOW REQUEST FROM APP " + app + " TO DEVICE " + device)
                r = follow("admin1", "admin1", device, permission, from_id=app)
                follow_status = check(r, 202)
                assert (follow_status)

    elif as_admin == False:
        for app, apikey in app_keys.items():
            for device in device_keys:
                logger.info("FOLLOW REQUEST FROM APP " + app + " TO DEVICE " + device)
                r = follow(app, apikey, device, permission)
                follow_status = check(r, 202)
                assert (follow_status)


def unfollow_dev(as_admin="", permission=""):
    if as_admin == True:
        for app in app_keys:
            for device in device_keys:
                logger.info("UNFOLLOW REQUEST FROM APP " + app + " TO DEVICE " + device)
                r = unfollow("admin1", "admin1", device, "#", permission, from_id=app)
                follow_status = check(r, 200)
                assert (follow_status)

    elif as_admin == False:
        for app, apikey in app_keys.items():
            for device in device_keys:
                logger.info("UNFOLLOW REQUEST FROM APP " + app + " TO DEVICE " + device)
                r = unfollow(app, apikey, device, "#", permission)
                follow_status = check(r, 200)
                assert (follow_status)

def share_dev(expected):

	r = follow_requests("admin", "admin", "requests")
    	response = r.json()
	count = 0
	
	assert(check(r,200))
	
	for follow_req in response:
		count = count + 1
        	logger.info("SHARE FROM DEVICE " + str(follow_req['to']).split(".")[0] + " TO APP " + str(follow_req['from']))
        	share_req = share("admin", "admin", str(follow_req['follow-id']))
        	share_status = check(share_req, 200)
        	assert (share_status)

	assert(count == expected)

def app_publish(expected_code):

	for app, apikey in app_keys.items():
		for device in device_keys:
			logger.info("APP "+ app +" PUBLISHING TO DEVICE "+ device +".command EXCHANGE")
			publish_req = publish(app,apikey, device, device+":#", "command", "test data")
			assert(check(publish_req, expected_code))


def dev_subscribe(expected):

    count = apps % 10

    if count == 0:
        count = apps / 10

    actual = 0

    for device, apikey in device_keys.items():

        logger.info("DEVICE " + device + " SUBSCRIBING TO ITS COMMAND QUEUE")

        for i in range(0, count):
            sub_req = subscribe(device, apikey, message_type="command", num_messages="10")
            sub_status = check(sub_req, 200)
            response = sub_req.json()
            actual = actual + len(response)

        assert (actual == expected)
        actual = 0
        logger.info("DEVICE " + device + " HAS RECEIVED " + str(expected) + " COMMAND MESSAGES")


def functional_test():

	# Device regsitration
    	logger.info(colour.HEADER + "---------------> REGISTERING DEVICES " + colour.ENDC)

    	for i in range(0, devices):
        	logger.info("REGISTERING DEVICE " + str(i))
        	dev_name = "dev" + ''.join(
            	random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
        	r = register('admin', 'admin', dev_name)
		response = r.json()
        	logger.info(json.dumps(response))
        	reg_status = check(r, 200)

        	assert (reg_status)

        	device_keys[response['id']] = response['apikey']

    	# App registration
    	logger.info(colour.HEADER + "---------------> REGISTERING APPS" + colour.ENDC)
    	for i in range(0, apps):
        	logger.info("REGISTERING APP " + str(i))
        	app_name = "app" + ''.join(
            	random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
        	r = register('admin1', 'admin1', app_name)
        	response = r.json() 
        	logger.info(json.dumps(response))
        	reg_status = check(r, 200)

        	assert (reg_status)

        	app_keys[response['id']] = response['apikey']

    	# Follow requests from apps to devices using apps' respective apikeys
    	logger.info(colour.HEADER + "---------------> FOLLOW REQUESTS WITH READ PERMISSION " + colour.ENDC)
    	follow_dev(as_admin=False, permission="read")

    	# Devices read all follow requests and share with apps
    	logger.info(colour.HEADER + "---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS" + colour.ENDC)
	share_dev(apps*devices)

    	# Apps bind to devices' queues
    	logger.info(colour.HEADER + "---------------> APPS BIND TO DEVICES" + colour.ENDC)
    	bind_unbind_dev(as_admin=False, req_type="bind")

	# Devices publish data
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps subscribe to messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(devices)

	# Apps unbind from devices
	logger.info(colour.HEADER + "---------------> APPS UNBIND FROM DEVICES" + colour.ENDC)
	bind_unbind_dev(as_admin=False, req_type="unbind")

	# Devices again publish messages
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps try to subscribe
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(0)

	# Apps bind to devices again but this time using admin apikey
	logger.info(colour.HEADER + "---------------> APPS BIND TO DEVICES USING ADMIN APIKEY" + colour.ENDC)
	bind_unbind_dev(as_admin=True, req_type="bind", expected=(devices*apps))

	# Devices publish again
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps subscribe to messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(devices)

	# Unbind from devices as admin
	logger.info(colour.HEADER + "---------------> APPS UNBIND FROM DEVICES USING ADMIN APIKEY" + colour.ENDC)
	bind_unbind_dev(as_admin=True, req_type="unbind", expected=(devices*apps))

	# Devices now publish data
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps try to subscribe but get 0 messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(0)

	# Apps unfollow all devices
	logger.info(colour.HEADER + "---------------> APPS UNFOLLOW ALL DEVICES USING THEIR RESPECTIVE APIKEYS" + colour.ENDC)
	unfollow_dev(as_admin=False, permission="read")

	# Apps try to bind to unfollowed devices
	logger.info(colour.HEADER + "---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES" + colour.ENDC)
	bind_unbind_without_follow(as_admin=False, req_type="bind")

	#Follow requests as admin	
    	logger.info(colour.HEADER + "---------------> FOLLOW REQUESTS WITH READ PERMISSION AS ADMIN" + colour.ENDC)
    	follow_dev(as_admin=True, permission="read")

	#Devices share with apps
    	logger.info(colour.HEADER + "---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS" + colour.ENDC)
	share_dev(apps*devices)

    	# Apps bind to devices' queues
    	logger.info(colour.HEADER + "---------------> APPS BIND TO DEVICES" + colour.ENDC)
    	bind_unbind_dev(as_admin=False, req_type="bind")

	# Devices publish data
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps subscribe to messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(devices)

	# Apps unfollow all devices
	logger.info(colour.HEADER + "---------------> APPS UNFOLLOW ALL DEVICES USING THEIR ADMIN APIKEYS" + colour.ENDC)
	unfollow_dev(as_admin=True, permission="read")

	# Apps try to bind to unfollowed devices
	logger.info(colour.HEADER + "---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES" + colour.ENDC)
	bind_unbind_without_follow(as_admin=False, req_type="bind")

	#Follow requests for write	
    	logger.info(colour.HEADER + "---------------> FOLLOW REQUESTS WITH WRITE PERMISSIONS" + colour.ENDC)
    	follow_dev(as_admin=False, permission="write")

	#Devices share with apps with write access
    	logger.info(colour.HEADER + "---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS" + colour.ENDC)
	share_dev(apps*devices)

	#Apps publish to command queue of devices
	logger.info(colour.HEADER+"---------------> APPS PUBLISH TO COMMAND EXCHANGE OF DEVICES"+colour.ENDC)
	app_publish(202)

	#Devices subscribe to their command queue
	logger.info(colour.HEADER+"---------------> DEVICES SUBSCRIBE TO THEIR COMMAND QUEUES"+colour.ENDC)
	dev_subscribe(apps)

	#Follow requests for write	
    	logger.info(colour.HEADER+"---------------> APPS WITH WRITE ACCESS UNFOLLOW DEVICES" + colour.ENDC)
    	unfollow_dev(as_admin=False, permission="write")

	#Apps publish to command queue of devices
	logger.info(colour.HEADER+"---------------> APPS TRY TO PUBLISH TO COMMAND EXCHANGE OF UNFOLLOWED DEVICES"+colour.ENDC)
	app_publish(202)

	#Apps request follow with read-write permissions
	logger.info(colour.HEADER+"---------------> APPS REQUEST FOLLOW WITH READ-WRITE PERMISSIONS"+colour.ENDC)
	follow_dev(as_admin=False, permission="read-write")

	#Devices approve issue share to apps
	logger.info(colour.HEADER+"---------------> DEVICES APPROVE READ-WRITE FOLLOW REQUESTS WITH SHARE"+colour.ENDC)
	share_dev(devices*apps*2)

	#Apps publish to command queue of devices
	logger.info(colour.HEADER+"---------------> APPS PUBLISH TO COMMAND EXCHANGE OF DEVICES"+colour.ENDC)
	app_publish(202)

	#Devices subscribe to their command queue
	logger.info(colour.HEADER+"---------------> DEVICES SUBSCRIBE TO THEIR COMMAND QUEUES"+colour.ENDC)
	dev_subscribe(apps)
	
    	# Apps bind to devices' queues
    	logger.info(colour.HEADER + "---------------> APPS BIND TO DEVICES" + colour.ENDC)
    	bind_unbind_dev(as_admin=False, req_type="bind", expected=(devices*apps))

	# Devices publish again
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps subscribe to messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(devices)

	#Apps relinquish write permission
    	logger.info(colour.HEADER+"---------------> APPS WITH WRITE ACCESS UNFOLLOW DEVICES" + colour.ENDC)
	unfollow_dev(as_admin=False, permission="write")

	#Apps publish to command queue of devices
	logger.info(colour.HEADER+"---------------> APPS TRY TO PUBLISH TO COMMAND EXCHANGE OF UNFOLLOWED DEVICES"+colour.ENDC)
	app_publish(202)

	# Devices publish again
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA AFTER WRITE UNFOLLOW" + colour.ENDC)
	dev_publish()

	# Apps subscribe to messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA AFTER WRITE UNFOLLOW" + colour.ENDC)
	app_subscribe(devices)

	# Apps unfollow with read permissions
	logger.info(colour.HEADER + "---------------> APPS UNFOLLOW DEVICES WITH READ ACCESS" + colour.ENDC)
	unfollow_dev(as_admin=True, permission="read")

	# Apps try to bind to unfollowed devices
	logger.info(colour.HEADER + "---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES" + colour.ENDC)
	bind_unbind_without_follow(as_admin=False, req_type="bind")

	#Apps obtain read-write follow
	logger.info(colour.HEADER+"---------------> APPS FOLLOW WITH READ-WRITE PERMISSIONS"+colour.ENDC)
	follow_dev(as_admin=False, permission="read-write")

	#Devices approve issue share to apps
	logger.info(colour.HEADER+"---------------> DEVICES APPROVE READ-WRITE FOLLOW REQUESTS WITH SHARE"+colour.ENDC)
	share_dev(devices*apps*2)

    	# Apps bind to devices' queues
    	logger.info(colour.HEADER + "---------------> APPS BIND TO DEVICES WITH ADMIN APIKEY" + colour.ENDC)
    	bind_unbind_dev(as_admin=True, req_type="bind", expected=(2*devices*apps))

	# Devices publish again
	logger.info(colour.HEADER + "---------------> DEVICES PUBLISH DATA" + colour.ENDC)
	dev_publish()

	# Apps subscribe to messages
	logger.info(colour.HEADER + "---------------> APPS TRY TO READ PUBLISHED DATA" + colour.ENDC)
	app_subscribe(devices)
	

if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(levelname)-6s %(message)s', level=logging.DEBUG,
                        datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    functional_test()
