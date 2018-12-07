Feature: Register_OWNER 

	Scenario: Middleware allows owner registration
 
	Given the middleware allows owner registration
	When middleware is running 
	Then middleware registers owner
