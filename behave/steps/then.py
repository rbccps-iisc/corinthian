import sys, os
# import names
import requests
import subprocess
import json
import shlex

sys.path.append(os.path.join(os.path.dirname(__file__), '..','..', 'tests'))
passwd_file = os.path.join(os.path.dirname(__file__), '..','..', 'vars','admin.passwd')
import _test as test

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
	dummy_id = test.gen_rand(8)
	key = subprocess.check_output("cat "+ passwd_file, shell=True).decode("utf-8").replace("\n","")
	owner = "owner"+str(dummy_id)
	print(subprocess.check_output("pwd", shell=True).decode("utf-8"))
	print(subprocess.check_output("../tests/register_owner.sh " + owner, shell=True).decode("utf-8"))
	owner_cred = subprocess.check_output("cat ../vars/owner.credentials", shell=True).decode("utf-8").replace("\n","")
	print(owner_cred)
