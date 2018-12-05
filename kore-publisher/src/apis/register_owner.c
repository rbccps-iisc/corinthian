#include "../apis/api.h"

int
register_owner(struct http_request *req)
{
	const char *apikey;
	const char *owner;

	char salt		[33];
	char owner_apikey	[33];
	char password_hash	[65];

	pthread_t thread;
	bool thread_started = false;

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this api can only be called from localhost");

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "owner", &owner)
			,
		"inputs missing in headers"
	);

	str_to_lower(owner);

	// cannot create an admin, validator or database
	if (strcmp(owner,"admin") == 0 || strcmp(owner,"validator") == 0 || strcmp(owner,"database") == 0)
		FORBIDDEN("cannot create the user");

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("entity should be a valid owner");

/////////////////////////////////////////////////

	if (! login_success("admin",apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(owner);

/////////////////////////////////////////////////

	// conflict if owner already exist
	CREATE_STRING (query,
			"SELECT id FROM users WHERE id ='%s'",
				owner
	);
	RUN_QUERY (query,"could not query info about the owner");

	if(kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	if (0 == pthread_create(&thread,NULL,create_exchanges_and_queues,(const void *)owner))
		thread_started = true;
	else
		create_exchanges_and_queues((const void *)owner);

	gen_salt_password_and_apikey (owner, salt, password_hash, owner_apikey);

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked,is_autonomous) "
				"VALUES('%s','%s',NULL,'%s','f','t')",
				owner,
				password_hash,
				salt
	);

	RUN_QUERY (query, "could not create a new owner");

	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,owner,strlen(owner));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,owner_apikey,strlen(owner_apikey));
	kore_buf_append(response,"\"}\n",3);

	OK_201();

done:
	// wait for thread ...
	if (thread_started)
	{
		bool *result;
		pthread_join(thread,(void *)&result);
		if (!result || !*result)
		{
			req->status = 500;
			kore_buf_reset(response);
		}
	}

	END();
}
