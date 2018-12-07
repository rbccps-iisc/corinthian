Feature: Deregister_OWNER_NOT_as_ADMIN

	Scenario: Middleware doesn't allow owner deregistration without admin
 
	Given the middleware doesn't allow owner deregistration without admin
	When middleware is running and user is nonadmin
	Then middleware can't deregister owner