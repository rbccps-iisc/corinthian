import sys, os
# import names
import requests
import subprocess
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '..','..', 'tests'))
admin_passwd_file = os.path.join(os.path.dirname(__file__), '..','..', 'vars','admin.passwd')
import _test as test

# dummy_id = test.gen_rand(8)
# owner="owner"+str(dummy_id)#names.get_full_name().replace(" ","")

owner='testowner'

def get_owner_reg_dereg_api_response(test_script, response_file, user):
	key = subprocess.check_output("cat "+ admin_passwd_file, shell=True).decode("utf-8").replace("\n","")
	subprocess.check_output("../tests/" + test_script + " " + owner + " " + user, shell=True).decode("utf-8")
	return subprocess.check_output("cat ../vars/" + response_file, shell=True).decode("utf-8").replace("\n","")

@then('middleware uses TLS with a valid certificate')
def f(context):
	r = requests.get(context.url)
	return True

@then('middleware runs on HTTP')
def f(context):
	r = requests.get(context.url)
	return True

@then('middleware registers owner as admin')
def f(context):
	res=get_owner_reg_dereg_api_response('register_owner.sh', 'owner_register.response', context.user)
	if (res.strip()):
		assert('error' not in json.loads(res).keys())
	else:
		assert(False)

@then('middleware deregisters owner as admin')
def f(context):
	res=get_owner_reg_dereg_api_response('deregister_owner.sh', 'owner_deregister.response', context.user)
	assert(not res.strip())

@then('middleware can\'t register owner')
def f(context):
	res=get_owner_reg_dereg_api_response('register_owner.sh', 'owner_register.response', context.user)
	if (res.strip()):
		assert('error' in json.loads(res).keys())
	else:
		assert(False)

@then('middleware can\'t deregister owner')
def f(context):
	res=get_owner_reg_dereg_api_response('deregister_owner.sh', 'owner_deregister.response', context.user)
	assert(res.strip())