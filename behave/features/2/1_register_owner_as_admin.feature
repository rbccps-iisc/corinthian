Feature: Register_OWNER_as_ADMIN

	Scenario: Middleware allows owner registration as admin
 
	Given the middleware allows owner registration as admin
	When middleware is running and user is admin
	Then middleware registers owner as admin