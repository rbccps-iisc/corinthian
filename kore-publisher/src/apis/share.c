#include "../apis/api.h"

int
share (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *follow_id;

	req->status = 403;
	kore_buf_reset(response);

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "follow-id", &follow_id)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

	sanitize(follow_id);

/////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query, 
			"SELECT from_id,exchange,permission,validity,topic FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' and status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id,exchange,permission,validity,topic FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s.%%' and status='pending'",
				follow_id,
				id
		);
	}

	RUN_QUERY (query,"could not run select query on follow");

	int num_rows = kore_pgsql_ntuples(&sql);

	if (num_rows != 1)
		BAD_REQUEST("follow-id is not valid");

	char *from_id		= kore_pgsql_getvalue(&sql,0,0);
	char *my_exchange 	= kore_pgsql_getvalue(&sql,0,1);
	char *permission 	= kore_pgsql_getvalue(&sql,0,2); 
	char *validity_hours 	= kore_pgsql_getvalue(&sql,0,3); 
	char *topic 	 	= kore_pgsql_getvalue(&sql,0,4); 

	// NOTE: follow_id is primary key 
	CREATE_STRING (query,
			"UPDATE follow SET status='approved' WHERE follow_id = '%s'",
				follow_id
	);
	RUN_QUERY (query,"could not run update query on follow");

	// add entry in acl
	CREATE_STRING (query,
		"INSERT INTO acl (acl_id,from_id,exchange,follow_id,permission,topic,valid_till) "
		"VALUES(DEFAULT,'%s','%s','%s','%s','%s',now() + interval '%s hours')",
	        	from_id,
			my_exchange,
			follow_id,
			permission,
			topic,
			validity_hours
	);

	RUN_QUERY (query,"could not run insert query on acl");

	if (strcmp(permission,"write") == 0)
	{
		char write_exchange 	[129];
		char command_queue	[129];
		char write_topic	[129];

		snprintf(write_exchange,129,"%s.publish",from_id);
		snprintf(command_queue,129,"%s",my_exchange);	// exchange in follow is device.command
		snprintf(write_topic,129,"%s.%s",my_exchange,topic); // routing key will be dev.command.topic

		debug_printf("\n--->binding {%s} with {%s} {%s}\n",command_queue,write_exchange,write_topic);

		if (! amqp_queue_bind (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(command_queue),
			amqp_cstring_bytes(write_exchange),
			amqp_cstring_bytes(write_topic),
			amqp_empty_table
		))
		{
			ERROR("bind failed for app.publish with device.command");
		}
	}

	OK();

done:
	if (req->status == 500)
	{
		init_admin_conn();
	}

	END();
}
