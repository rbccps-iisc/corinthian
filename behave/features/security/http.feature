Feature: HTTP 

	Scenario: Middleware allows connections through HTTP
 
	Given the middleware's address is http://localhost 
	When middleware is running 
	Then middleware runs on HTTP 
