import requests

@then('middleware uses TLS with a valid certificate')
def f(context):
	r = requests.get(context.url)
	return r
