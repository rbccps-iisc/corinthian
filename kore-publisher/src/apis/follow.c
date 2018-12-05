#include "../apis/api.h"

int
follow (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *from;
	const char *to;

	const char *permission; // read, write, or, read-write

	const char *topic; // topics the subscriber is interested in

	const char *validity; // in hours 

	const char *message_type;

	char *status = "pending";

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "permission", &permission)
				||
		KORE_RESULT_OK != http_request_header(req, "validity", &validity)
				||
		KORE_RESULT_OK != http_request_header(req, "topic", &topic)
			,
		"inputs missing in headers"
	);

	if (http_request_header(req, "message-type", &message_type) == KORE_RESULT_OK)
	{
		if (strcmp(message_type,"protected") != 0 && strcmp(message_type,"diagnostics") != 0)
		{
			BAD_REQUEST("invalid message-type");	
		}
	}
	else
	{
		message_type = "protected";
	}

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
		// from is itself 
		from = id;
	}

	if (! looks_like_a_valid_entity(to))
		FORBIDDEN("'to' is not a valid entity");

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

	sanitize (from);
	sanitize (to);
	sanitize (validity);
	sanitize (topic);

/////////////////////////////////////////////////

	// if both from and to are owned by id
	if (is_owner(id,to))
		status = "approved";

	char read_follow_id  [10];
	char write_follow_id [10];

	read_follow_id[0] = '\0';
	write_follow_id[0] = '\0';

	bool valid_permission = false;

	int int_validity = strtonum(validity,1,10000,NULL);
	if (int_validity <= 0)
		BAD_REQUEST("validity must be in number of hours");

	if (strcmp(permission,"read") == 0 || strcmp(permission,"read-write") == 0)
	{
		valid_permission = true;

		CREATE_STRING (query, 
			"INSERT INTO follow "
			"(follow_id,requested_by,from_id,exchange,time,permission,topic,validity,status) "
			"VALUES(DEFAULT,'%s','%s','%s.%s',now(),'read','%s','%d','%s')",
				id,
				from,
				to,	// .message_type is appended to it
				message_type,
				topic,
				int_validity,
				status
		);
		RUN_QUERY (query, "failed to insert follow - read");

		CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
		RUN_QUERY 	(query,"failed pg_get_serial read");

		strlcpy(read_follow_id,kore_pgsql_getvalue(&sql,0,0),10);
	}

	if (strcmp(permission,"write") == 0 || strcmp(permission,"read-write") == 0)
	{
		valid_permission = true;

		CREATE_STRING (query,
			"INSERT INTO follow "
			"(follow_id,requested_by,from_id,exchange,time,permission,topic,validity,status) "
			"VALUES(DEFAULT,'%s','%s','%s.command',now(),'write','%s','%d','%s')",
				id,
				from,
				to,	// .command is appended to it
				topic,
				int_validity,
				status
		);
		RUN_QUERY (query, "failed to insert follow - write");

		CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
		RUN_QUERY 	(query,"failed pg_get_serial write");

		strlcpy(write_follow_id,kore_pgsql_getvalue(&sql,0,0),10);
	}

	if (! valid_permission)
		BAD_REQUEST("invalid permission");

	if (strcmp(status,"approved") == 0)
	{
		// add entry in acl
		if (strcmp(permission,"read") == 0 || strcmp(permission,"read-write") == 0)
		{
			CREATE_STRING (query,
			"INSERT INTO acl "
			"(acl_id,from_id,exchange,follow_id,permission,topic,valid_till) "
			"VALUES(DEFAULT,'%s','%s.%s','%s','%s', '%s', now() + interval '%d hours')",
			        	from,
					to,		// .message_type is appended to it
					message_type,
					read_follow_id,
					"read",
					topic,
					int_validity
			);

			RUN_QUERY (query,"could not run insert query on acl - read ");
		}

		if (strcmp(permission,"write") == 0 || strcmp(permission,"read-write") == 0)
		{
			char write_exchange 	[129];
			char command_queue	[129];
			char write_topic	[129];

			snprintf(write_exchange,129,"%s.publish",from);
			snprintf(command_queue,129,"%s.command",to);
			snprintf(write_topic,129,"%s.command.%s",to,topic);

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

			CREATE_STRING (query,
			"INSERT INTO acl "
			"(acl_id,from_id,exchange,follow_id,permission,topic,valid_till) "
			"VALUES(DEFAULT,'%s','%s.command','%s','%s', '%s', now() + interval '%d hours')",
			        	from,
					to,		// .command is appended to it
					read_follow_id,
					"write",
					topic,
					int_validity
			);

			RUN_QUERY (query,"could not run insert query on acl - read ");
		}

		req->status = 200;
	}
	else
	{
		// we have sent the request,
		// but the owner of the "to" device must approve
		req->status = 202;
	}

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	if (strlen(read_follow_id) > 0)
		kore_buf_appendf(response,"\"follow-id-read\":\"%s\"",read_follow_id);

	if (strlen(write_follow_id) > 0)
	{
		// put a comma
		if (strlen(read_follow_id) > 0)
			kore_buf_append(response,",",1);

		kore_buf_appendf(response,"\"follow-id-write\":\"%s\"",write_follow_id);
	}

	kore_buf_append(response,"}\n",2);

done:
	if (req->status == 500)
	{
		init_admin_conn();
	}

	END();
}
