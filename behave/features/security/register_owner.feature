Feature: Register_OWNER 

	Scenario: Check OWNER Registration API
 
	Given the middleware allows owner registration
	When middleware is running 
	Then middleware registers owner
