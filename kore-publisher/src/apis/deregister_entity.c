#include "../apis/api.h"

int
deregister_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	pthread_t thread;
	bool thread_started = false; 

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "entity", &entity)
			,
		"inputs missing in headers"
	);

	// deny if the id does not look like an owner
	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not an owner");

	if (! looks_like_a_valid_entity(entity))
		FORBIDDEN("entity is not valid");

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

/////////////////////////////////////////////////

	if (! is_owner(id,entity))
		FORBIDDEN("you are not the owner of the entity");

	// check if the entity exists
	CREATE_STRING (
		query,
		"SELECT 1 FROM users WHERE id = '%s'",
		entity
	);
	RUN_QUERY(query,"could no query entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid entity");

	// delete entries in to RabbitMQ
	if (0 == pthread_create(&thread,NULL,delete_exchanges_and_queues,(const void *)entity))
		thread_started = true;
	else
		delete_exchanges_and_queues((const void *)entity);

	CREATE_STRING (query,
		"DELETE FROM acl WHERE from_id = '%s' OR exchange LIKE '%s.%%'",
		entity,
		entity
	);

	RUN_QUERY(query,"could not delete from acl table");

	CREATE_STRING (
		query,
		"DELETE FROM follow WHERE requested_by = '%s' OR exchange LIKE '%s.%%'",
		entity,
		entity
	);

	RUN_QUERY(query,"could not delete from follow table");

	CREATE_STRING (query,
			"DELETE FROM users WHERE id = '%s'",
				entity
	);
	RUN_QUERY (query,"could not delete the entity");

	OK();

done:
	// wait for thread ...
	if (thread_started)
		pthread_join(thread,NULL);

	END();
}

