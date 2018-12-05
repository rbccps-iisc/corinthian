#include "../apis/api.h"

int
queue_unbind (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *to;
	const char *from;

        const char *topic;
	const char *message_type;
	const char *is_priority;

 	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "topic", &topic)
				||
		KORE_RESULT_OK != http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	if (looks_like_a_valid_owner(id))
	{
		if (KORE_RESULT_OK != http_request_header(req, "from", &from))
			FORBIDDEN("'from' value missing in header");

		if (! looks_like_a_valid_entity(from))
			FORBIDDEN("'from' is not a valid entity");

		// check if the he is the owner of from 
		if (! is_owner(id,from))
			FORBIDDEN("you are not the owner of 'from' entity");
	}
	else
	{
		// entity must bind itself -> 'to'
		from = id;
	}

	if (! looks_like_a_valid_entity(to))
		FORBIDDEN("'to' is not a valid entity");

	if (
		(strcmp(message_type,"public") != 0) &&
		(strcmp(message_type,"private") != 0) &&
		(strcmp(message_type,"protected") != 0) &&
		(strcmp(message_type,"diagnostics") != 0)
	)
	{
		BAD_REQUEST("message-type is invalid");
	}

	if(strcmp(message_type,"private") == 0)
	{
		if (! is_owner(id,to))
		{
			FORBIDDEN("you are not the owner of 'to'");
		}
	}

	snprintf (exchange,128,"%s.%s", to,message_type); 

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey, &is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

	sanitize(from);
	sanitize(to);
	sanitize(topic);

/////////////////////////////////////////////////

	strlcpy(queue,from,128);
	if (KORE_RESULT_OK == http_request_header(req, "is-priority", &is_priority))
	{
		if (strcmp(is_priority,"true") == 0)
		{
			strlcat(queue,".priority",128);
		}
	}

	debug_printf("queue = %s",queue);
	debug_printf("exchange = %s", exchange);

	// if he is not the owner, he needs an entry in acl
	if(! is_owner(id,to))
	{
		CREATE_STRING (
			query,
			"SELECT 1 FROM acl WHERE "
			"from_id = '%s' "
			"AND exchange = '%s' "
			"AND permission = 'read' "
			"AND valid_till > now() "
			"AND topic = '%s'",
			from,
			exchange,
			topic
		);

		RUN_QUERY(query,"failed to query for permission");

		if (kore_pgsql_ntuples(&sql) != 1)
			FORBIDDEN("unauthorized");
	}

	amqp_queue_unbind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(queue),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		amqp_empty_table
	);

	amqp_rpc_reply_t r = amqp_get_rpc_reply(cached_admin_conn);

	if (r.reply_type != AMQP_RESPONSE_NORMAL)
	{
		snprintf(error_string,1024,"unbind failed %d e={%s} q={%s} t={%s}\n",r.reply_type,exchange,queue,topic);
		ERROR(error_string);
	}

	OK();

done:
	if (req->status == 500)
	{
		init_admin_conn();
	}

	END();
}
