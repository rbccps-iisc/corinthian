@given('the middleware\'s address is https://{host}')
def f(context,host):
	context.url = "https://" + host
	return True

@given('the middleware\'s address is http://{host}')
def f(context,host):
	context.url = "http://" + host
	return True

@given('the middleware allows owner registration')
def f(context):
	return True