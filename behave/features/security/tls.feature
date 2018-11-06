Feature: TLS 

	Scenario: Middleware allows connections through TLS only
 
	Given the middleware's address is https://localhost 
	When middleware is running 
	Then middleware uses TLS with a valid certificate 
