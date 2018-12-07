Feature: Register_OWNER_NOT_as_ADMIN

	Scenario: Middleware doesn't allow owner registration without admin
 
	Given the middleware doesn't allow owner registration without admin
	When middleware is running and user is nonadmin
	Then middleware can't register owner