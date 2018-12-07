Feature: Deregister_OWNER_as_ADMIN

	Scenario: Middleware allows owner deregistration as admin
 
	Given the middleware allows owner deregistration as admin
	When middleware is running and user is admin
	Then middleware deregisters owner as admin

