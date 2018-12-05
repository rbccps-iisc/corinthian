#include "../apis/api.h"

int
unfollow (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *from;
	const char *to;
	const char *topic;
	const char *permission;
	const char *message_type;

	char *acl_id;
	char *follow_id;

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
		KORE_RESULT_OK != http_request_header(req, "permission", &permission)
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
		// entity must unfollow itself -> 'to'
		from = id;
	}

	if(
		(strcmp(permission,"read") !=0)
			&&
		(strcmp(permission,"write") !=0)
			&&
		(strcmp(permission,"read-write") !=0)
	)
	{
		BAD_REQUEST("Invalid permission string");
	}

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

	sanitize(from);
	sanitize(to);
	sanitize(topic);

/////////////////////////////////////////////////

	if (strcmp(permission,"write") == 0 || strcmp(permission,"read-write") == 0)
	{
		CREATE_STRING ( query,
			"SELECT follow_id FROM follow "
				"WHERE "
				"requested_by = '%s' "
					"AND "
				"exchange = '%s.command' "
					"AND "
				"topic = '%s' "
					"AND "
				"permission = 'write'",

					from,
					to,
					topic
		);

		RUN_QUERY(query,"failed to query follow table for permission");

		if (kore_pgsql_ntuples(&sql) == 0)
			FORBIDDEN("unauthorized");

		follow_id	= kore_pgsql_getvalue(&sql,0,0);
		
		char write_exchange 	[129];
		char command_queue	[129];
		char write_topic	[129];

		snprintf(write_exchange,129,"%s.publish",from);
		snprintf(command_queue,129,"%s.command",to);
		snprintf(write_topic,129,"%s.command.%s",to,topic);

		amqp_queue_unbind (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(command_queue),
			amqp_cstring_bytes(write_exchange),
			amqp_cstring_bytes(write_topic),
			amqp_empty_table
		);

		amqp_rpc_reply_t r = amqp_get_rpc_reply(cached_admin_conn);

		if (r.reply_type != AMQP_RESPONSE_NORMAL)
		{
			snprintf(error_string,1024,"unbind failed %d e={%s} q={%s} t={%s}\n",r.reply_type,write_exchange,command_queue,write_topic);
			ERROR(error_string);
		}

		CREATE_STRING 	(query, "DELETE FROM follow WHERE follow_id='%s'", follow_id);
		RUN_QUERY	(query, "failed to delete from follow table");

		CREATE_STRING 	(query, "DELETE FROM acl WHERE follow_id='%s'", follow_id);
		RUN_QUERY	(query, "failed to delete from acl table");
		
		// if its just write then stop 
		if (strcmp(permission,"write") == 0)
			OK();
	}

//// for read permissions /////
	snprintf(exchange,128,"%s.%s",to,message_type);

	CREATE_STRING ( query,
		"SELECT acl_id,follow_id FROM acl "
			"WHERE "
			"from_id = '%s' "
				"AND "
			"exchange = '%s' "
				"AND "
			"topic = '%s' "
				"AND "
			"permission = 'read'",

				from,
				exchange,
				topic
	);

	RUN_QUERY(query,"failed to query acl table for permission");

	if (kore_pgsql_ntuples(&sql) != 1)
		FORBIDDEN("unauthorized");

	char priority_queue[129];

	strlcpy(priority_queue, from, 128);
	strlcat(priority_queue, ".priority", 128);

	acl_id		= kore_pgsql_getvalue(&sql,0,0);
	follow_id	= kore_pgsql_getvalue(&sql,0,1);

	CREATE_STRING 	(query, "DELETE FROM acl WHERE acl_id='%s'", acl_id);
	RUN_QUERY	(query, "failed to delete from acl table");

	CREATE_STRING 	(query, "DELETE FROM follow WHERE follow_id='%s'", follow_id);
	RUN_QUERY	(query, "failed to delete from follow table");

	amqp_rpc_reply_t r;


	amqp_queue_unbind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(from),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		amqp_empty_table
	);

	r = amqp_get_rpc_reply(cached_admin_conn);

	if (r.reply_type != AMQP_RESPONSE_NORMAL)
	{
		snprintf(error_string,1024,"unbind failed %d e={%s} q={%s} t={%s}\n",r.reply_type,exchange,from,topic);
		ERROR(error_string);
	}

	amqp_queue_unbind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(priority_queue),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		amqp_empty_table
	);

	r = amqp_get_rpc_reply(cached_admin_conn);

	if (r.reply_type != AMQP_RESPONSE_NORMAL)
	{
		snprintf(error_string,1024,"unbind priority failed %d e={%s} q={%s} t={%s}\n",r.reply_type,exchange,priority_queue,topic);
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
