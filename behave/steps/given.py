@given('the middleware\'s address is https://{host}')
def f(context,host):
	context.url = "https://" + host
	return True

@given('the middleware\'s address is http://{host}')
def f(context,host):
	context.url = "http://" + host
	return True

@given('the middleware allows owner registration as admin')
def f(context):
	return True

@given('the middleware doesn\'t allow owner registration without admin')
def f(context):
	return True

@given('the middleware allows owner deregistration as admin')
def f(context):
	return True

@given('the middleware doesn\'t allow owner deregistration without admin')
def f(context):
	return True