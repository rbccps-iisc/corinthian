@when('middleware is running')
def f(context):
	return True

@when('middleware is running and user is {admin}')
def f(context, admin):
	context.user = admin
	return True