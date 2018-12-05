#include "../apis/api.h"

int
deregister_owner(struct http_request *req)
{
	int i, num_rows;

	const char *id;
	const char *apikey;
	const char *owner;

	pthread_t thread;
	bool thread_started = false; 

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this api can only be called from localhost");

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "owner", &owner)
			,
		"inputs missing in headers"
	);

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this api");

	// cannot delete admin
	if (strcmp(owner,"admin") == 0 || strcmp(owner,"DATABASE") == 0 || strcmp(owner,"database") == 0)
		FORBIDDEN("cannot delete user");

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("not a valid owner");

/////////////////////////////////////////////////

	if (! login_success("admin",apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(owner);

/////////////////////////////////////////////////

	CREATE_STRING (query,
			"SELECT id FROM users where id = '%s' or id like '%s/%%'",
				owner,
				owner
	);

	RUN_QUERY (query,"could not get app/devices associated with owner");

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *entity = kore_pgsql_getvalue(&sql,i,0);
		debug_printf("Deleting {%s}\n",entity);
		delete_exchanges_and_queues((void *)entity); 
	}

	// delete entries in to RabbitMQ
	if (0 == pthread_create(&thread,NULL,delete_exchanges_and_queues,(const void *)owner))
		thread_started = true;
	else
		delete_exchanges_and_queues((const void *)owner);

	// delete from acl
	CREATE_STRING (query,
			"DELETE FROM acl WHERE from_id LIKE '%s/%%' OR exchange LIKE '%s/%%'",
				owner,
				owner
	);

	RUN_QUERY (query,"could not delete from acl table");

	// delete all apps and devices of the owner
	CREATE_STRING (query,
		"DELETE FROM users WHERE id LIKE '%s/%%'",
			owner
	);
	RUN_QUERY (query,"could not delete apps/devices of the owner");

	// finally delete the owner 
	CREATE_STRING (query,
			"DELETE FROM users WHERE id = '%s'",
				owner
	);
	RUN_QUERY (query,"could not delete the owner");

	OK();

done:
	// wait for thread ...
	if (thread_started)
		pthread_join(thread,NULL);

	END();
}
