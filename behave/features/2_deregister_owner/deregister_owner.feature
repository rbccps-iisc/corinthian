Feature: Deregister_OWNER 

	Scenario: Middleware allows owner deregistration
 
	Given the middleware allows owner deregistration
	When middleware is running 
	Then middleware deregisters owner
