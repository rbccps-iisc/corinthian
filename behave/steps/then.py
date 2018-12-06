import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '..','..', 'tests'))

import test
import names
import requests

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
	test.register_owner(ID, apikey, owner);
	return True