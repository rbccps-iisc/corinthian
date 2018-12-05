#include "apis/api.h"

int
subscribe (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *message_type;
	const char *num_messages;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_entity(id))
		BAD_REQUEST("id is not a valid entity");

	strlcpy(queue,id,128);

	if (KORE_RESULT_OK == http_request_header(req, "message-type", &message_type))
	{
		if (strcmp(message_type,"priority") == 0)
		{
			strlcat(queue,".priority",128);
		}
		else if (strcmp(message_type,"command") == 0)
		{
			strlcat(queue,".command",128);
		}
		else if (strcmp(message_type,"notification") == 0)
		{
			strlcat(queue,".notification",128);
		}
		else
		{
			BAD_REQUEST("invalid message-type");
		}
	}

	int int_num_messages = 10;
	if (KORE_RESULT_OK == http_request_header(req, "num-messages", &num_messages))
	{
		int_num_messages = strtonum(num_messages,1,100,NULL);

		if (int_num_messages <= 0)
			BAD_REQUEST("num-messages is not valid");
	}

	node *n = NULL;
	amqp_connection_state_t	*cached_conn = NULL;

	char key[65];
	strlcpy(key,id,32);
	strlcat(key,apikey,64);

	if ((n = ht_search(&connection_ht,key)) != NULL)
	{
		cached_conn = n->value;
	}
	else
	{

/////////////////////////////////////////////////

		if (! looks_like_a_valid_entity(id))
			BAD_REQUEST("id is not a valid entity");

		if (! login_success(id,apikey,NULL))
			FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////
		
		cached_conn = malloc(sizeof(amqp_connection_state_t));

		if (cached_conn == NULL)
			ERROR("out of memory");

		*cached_conn = amqp_new_connection();
		amqp_socket_t *socket = amqp_tcp_socket_new(*cached_conn);

		if (socket == NULL)
			ERROR("could not create a new socket");

		if (amqp_socket_open(socket, broker_ip , 5672))
			ERROR("could not open a socket");

		login_reply = amqp_login(
				*cached_conn, 
				"/",
				0,
				131072,
				HEART_BEAT,
				AMQP_SASL_METHOD_PLAIN,
				id,
				apikey
		);

		if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
			FORBIDDEN("broker: invalid id or apkey");

		if(! amqp_channel_open(*cached_conn, 1))
			ERROR("could not open an AMQP connection");

		rpc_reply = amqp_get_rpc_reply(*cached_conn);
		if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
			ERROR("error from broker");

		ht_insert (&connection_ht, key, cached_conn);
	}

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);

	for (i = 0; i < int_num_messages; ++i)
	{
		amqp_rpc_reply_t res;
		amqp_message_t 	 message;

		time_t t;
		t = time(NULL);
		int time_spent = 0;

		do
		{
			res = amqp_basic_get(
					*cached_conn,
					1,
					amqp_cstring_bytes((const char *)queue),
					/*no ack*/ 1
			);

		} while (
			(res.reply_type == AMQP_RESPONSE_NORMAL) 	&&
           		(res.reply.id 	== AMQP_BASIC_GET_EMPTY_METHOD) &&
           		((time_spent = (time(NULL) - t)) < 1)
		);

		if (AMQP_RESPONSE_NORMAL != res.reply_type)
			break;

		if (res.reply.id != AMQP_BASIC_GET_OK_METHOD)
			break;

		if (res.reply_type != AMQP_RESPONSE_NORMAL)
			break;

		amqp_basic_get_ok_t *header = (amqp_basic_get_ok_t *) res.reply.decoded;
         
		amqp_read_message(*cached_conn, 1, &message, 0);

		/* construct the response */
		kore_buf_append(response,"{\"sent-by\":\"",12);

		if (message.properties._flags & AMQP_BASIC_USER_ID_FLAG)
			kore_buf_append (response,message.properties.user_id.bytes,
				message.properties.user_id.len);

		kore_buf_append(response,"\",\"from\":\"",10);
		if(header->exchange.len > 0)
			kore_buf_append(response,header->exchange.bytes, header->exchange.len);

		kore_buf_append(response,"\",\"topic\":\"",11);
		if (header->routing_key.len > 0)
			kore_buf_append(response,header->routing_key.bytes, header->routing_key.len);


		bool is_json = false;

		kore_buf_append(response,"\",\"content-type\":\"",18);
		if (message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG)
		{
			kore_buf_append(response,message.properties.content_type.bytes,
				message.properties.content_type.len);

			if (
				strncmp (
					message.properties.content_type.bytes,
					"application/json",
					message.properties.content_type.len
				) == 0
			)
			{
				is_json = true;
			}

		}

		kore_buf_append(response,"\",\"body\":",9);
		
		if (is_json)
		{
			kore_buf_append (
				response,
				message.body.bytes,
				message.body.len
			);
		}
		else
		{
			kore_buf_append(response,"\"",1);

			char *p = message.body.bytes;

			for (size_t j = 0; j < message.body.len; ++j)
			{
				// escape any double quotes
				if (*p == '\"')
					kore_buf_append(response,"\\",1);
			
				kore_buf_append(response,p,1);

				++p;
			}

			kore_buf_append(response,"\"",1);
		}

		kore_buf_append(response,"},",2);

		// we waited for messages for at least a second
		if (time_spent >= 1)
			break;
	}


	// remove the last comma
	if (i > 0)
		--(response->offset);

	kore_buf_append(response,"]",1);

	OK();

done:
	if (req->status == 500)
	{
		if (cached_conn)
		{
			amqp_channel_close	(*cached_conn, 1, AMQP_REPLY_SUCCESS);
			amqp_connection_close	(*cached_conn,    AMQP_REPLY_SUCCESS);
			amqp_destroy_connection	(*cached_conn);
	
			ht_delete(&connection_ht,key);
		}
	}

	END();
}


