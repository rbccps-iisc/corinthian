#include "../apis/api.h"

int
register_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;
	const char *char_is_autonomous;

	char entity_name[66];

	char salt		[33];
	char entity_apikey	[33];
	char password_hash	[65];

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

	// deny if the user is not a owner
	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not valid");

	if (! is_alpha_numeric(entity))
		BAD_REQUEST("entity is not valid");

	char *body = (char *)req->http_body->data;

	bool is_autonomous = false;
	if (http_request_header(req, "is-autonomous", &char_is_autonomous) == KORE_RESULT_OK)
	{
		if (strcmp(char_is_autonomous,"true") == 0)
			is_autonomous = true;
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	str_to_lower(entity);

	sanitize(entity);

	// TODO maybe body needs a different sanitizer
	if (body)
		sanitize(body);

/////////////////////////////////////////////////

	snprintf(entity_name,66,"%s/%s",id,entity);

	// create entries in to RabbitMQ

	if (0 == pthread_create(&thread,NULL,create_exchanges_and_queues,(const void *)entity_name)) 
		thread_started = true;
	else
		create_exchanges_and_queues((const void *)entity_name);

	// conflict if entity_name already exist

	CREATE_STRING(query,
		 	"SELECT id FROM users WHERE id='%s'",
				entity_name
	);

	RUN_QUERY (query,"could not get info about entity");

	if (kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity_name, salt, password_hash, entity_apikey);

	if (body)
	{
		// use parameterized query for inserting json

		CREATE_STRING (query,
			"INSERT INTO users(id,password_hash,schema,salt,blocked,is_autonomous) "
			"VALUES('%s','%s',$1,'%s','f','%s')",	// $1 is the schema (in body) 
			entity_name,
			password_hash,
			salt,
			is_autonomous ? "t" : "f"
		);

		kore_pgsql_cleanup(&sql);
		kore_pgsql_init(&sql);
		if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
		{
			kore_pgsql_logerror(&sql);
			ERROR("DB error while setup");
		}
		if (! kore_pgsql_query_params (&sql,query->data,0,1,body,req->http_body_length,0))
		{
			kore_pgsql_logerror(&sql);
			ERROR("failed to create the entity with schema");
		}
	}
	else
	{
		CREATE_STRING (query,
			"INSERT INTO users(id,password_hash,schema,salt,blocked,is_autonomous) "
			"VALUES('%s','%s','%s',NULL,'f','%s')",
			entity_name,
			password_hash,
			salt,
			is_autonomous ? "t" : "f"
		);

		RUN_QUERY (query,"failed to create the entity");
	}

	// generate response
	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity_name,strlen(entity_name));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
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
