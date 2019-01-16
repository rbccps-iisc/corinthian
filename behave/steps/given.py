@given('the middleware\'s address is https://{host}')
def f(context,host):
	context.url = "https://" + host
	return True
