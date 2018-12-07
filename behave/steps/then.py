import sys, os
# import names
import requests
import subprocess
import json
import shlex

sys.path.append(os.path.join(os.path.dirname(__file__), '..','..', 'tests'))
passwd_file = os.path.join(os.path.dirname(__file__), '..','..', 'vars','admin.passwd')
import _test as test

# dummy_id = test.gen_rand(8)
# owner="owner"+str(dummy_id)#names.get_full_name().replace(" ","")

owner='testowner'

@then('middleware uses TLS with a valid certificate')
def f(context):
	r = requests.get(context.url)
	return True

@then('middleware runs on HTTP')
def f(context):
	r = requests.get(context.url)
	return True

@then('middleware registers owner')
def f(context):
	key = subprocess.check_output("cat "+ passwd_file, shell=True).decode("utf-8").replace("\n","")
	subprocess.check_output("../tests/register_owner.sh " + owner, shell=True).decode("utf-8")
	owner_cred = subprocess.check_output("cat ../vars/owner_register.response", shell=True).decode("utf-8").replace("\n","")
	if (owner_cred.strip()):
		assert('error' not in json.loads(owner_cred).keys())
	else:
		assert(False)

@then('middleware deregisters owner')
def f(context):
	key = subprocess.check_output("cat "+ passwd_file, shell=True).decode("utf-8").replace("\n","")
	subprocess.check_output("../tests/deregister_owner.sh " + owner, shell=True).decode("utf-8")
	owner_cred = subprocess.check_output("cat ../vars/owner_deregister.response", shell=True).decode("utf-8").replace("\n","")
	assert(not owner_cred.strip())