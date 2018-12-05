#include "api.h"

int
publish (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *to;
	const char *subject;
	const char *message;
	const char *message_type;

	const char *content_type;

	char topic_to_publish[129];

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "subject", &subject)
				||
		KORE_RESULT_OK != http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_entity(to))
		BAD_REQUEST("'to' is not a valid entity");

	// ok to publish to himself
	if (strcmp(id,to) == 0)
	{
		if (
			(strcmp(message_type,"public") 		!= 0)	&&
			(strcmp(message_type,"private") 	!= 0)	&&
			(strcmp(message_type,"protected") 	!= 0)	&&
			(strcmp(message_type,"diagnostics") 	!= 0)	
		)
		{
			BAD_REQUEST("message-type is not valid");
		}

		snprintf(exchange,129,"%s.%s",id,message_type);
		strlcpy(topic_to_publish,subject,129);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",topic_to_publish);
	}
	else
	{
		if (strcmp(message_type,"command") != 0)
		{
			BAD_REQUEST("message-type can only be command");		
		}

		snprintf(topic_to_publish,129,"%s.%s.%s",to,message_type,subject);
		snprintf(exchange,129,"%s.publish",id);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",topic_to_publish);
	}

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if ((message = (char *)req->http_body->data) == NULL)
			BAD_REQUEST("no body found in request");
	}

	// get content-type and set in props
	if (http_request_header(req,"content-type",&content_type) != KORE_RESULT_OK)
	{
		content_type = "";
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
			ERROR("did not receive expected response from the broker");

		ht_insert (&connection_ht, key, cached_conn);
	}

	props.user_id 		= amqp_cstring_bytes(id);
	props.content_type 	= amqp_cstring_bytes(content_type);

	debug_printf("Got content-type {%s} : {%s}\n",content_type,id);

	FORBIDDEN_if
	(
		AMQP_STATUS_OK != amqp_basic_publish (
			*cached_conn,
			1,
			amqp_cstring_bytes(exchange),
        		amqp_cstring_bytes(topic_to_publish),
			0,
			0,
			&props,
			amqp_cstring_bytes(message)
		),

		"broker refused to publish message"
	);

	OK_202();

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
