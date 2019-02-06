#include "kore-publisher.h"
#include "async.h"

#define MAX_ASYNC_THREADS (2)

static int queue_index = 0;

static pthread_t 	thread	[MAX_ASYNC_THREADS];
static Q 		thread_q[MAX_ASYNC_THREADS];

static
void*
async_publish_function (void *v)
{
	Q *q = (Q *)v;

	publish_async_data_t *data = NULL; 

	node *n = NULL;
	char key [MAX_LEN_HASH_KEY + 1];

	const char *id;
	const char *to;
	const char *apikey;
	const char *subject;
	const char *message;
	const char *message_type;
	const char *content_type;

	char exchange [MAX_LEN_RESOURCE_ID + 1];

	char subject_to_publish[MAX_LEN_TOPIC + 1];

	amqp_connection_state_t	*cached_conn = NULL;
	
	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;
	amqp_basic_properties_t	props;

	memset(&props, 0, sizeof props);
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_USER_ID_FLAG;

	ht connection_ht;
	ht_init (&connection_ht);

	while (1)
	{
		while ((data = q_delete(q)))
		{
			id		= data->id;
			to		= data->to;
			apikey		= data->apikey;
			subject		= data->subject;
			message		= data->message;
			message_type	= data->message_type;
			content_type	= data->content_type;

			if (! looks_like_a_valid_entity(to))
				goto done;	
			
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
					goto done;	
				}

				snprintf(exchange,MAX_LEN_RESOURCE_ID + 1,"%s.%s",id,message_type);
				strlcpy(subject_to_publish,subject,MAX_LEN_TOPIC);
			}
			else
			{
				if (strcmp(message_type,"command") != 0)
					goto done;	

				snprintf(subject_to_publish,MAX_LEN_TOPIC + 1,"%s.%s.%s",to,message_type,subject);
				snprintf(exchange,MAX_LEN_RESOURCE_ID + 1,"%s.publish",id);

				debug_printf("==> exchange = %s\n",exchange);
				debug_printf("==> topic = %s\n",subject_to_publish);
			}

			snprintf (key, MAX_LEN_HASH_KEY + 1, "%s%s", id, apikey);

			if ((n = ht_search(&connection_ht,key)) != NULL)
			{
				cached_conn = n->value;
			}
			else
			{

/////////////////////////////////////////////////

				if (! looks_like_a_valid_entity(id))
					goto done;	

/////////////////////////////////////////////////

				cached_conn = malloc(sizeof(amqp_connection_state_t));

				if (cached_conn == NULL)
					goto done;	

				*cached_conn = amqp_new_connection();
				amqp_socket_t *socket = amqp_tcp_socket_new(*cached_conn);

				if (socket == NULL)
					goto done;	

				if (amqp_socket_open(socket, "broker", 5672))
					goto done;	
	
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
					goto done;	

				if(! amqp_channel_open(*cached_conn, 1))
					goto done;	

				rpc_reply = amqp_get_rpc_reply(*cached_conn);

				if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
					goto done;	

				ht_insert (&connection_ht, key, cached_conn);
			}

			props.user_id 		= amqp_cstring_bytes(id);
			props.content_type 	= amqp_cstring_bytes(content_type);

			if ( AMQP_STATUS_OK != amqp_basic_publish (
					*cached_conn,
					1,
					amqp_cstring_bytes(exchange),
        				amqp_cstring_bytes(subject_to_publish),
					0,
					0,
					&props,
					amqp_cstring_bytes(message)
				)
			)
			{
				goto done;
			}
done:
				
			free (data);
		}

		sleep (1);
	}
}

int
publish_async (struct http_request *req)
{
	const char *id;
	const char *to;
	const char *apikey;
	const char *subject;
	const char *message;
	const char *message_type;
	const char *content_type;

	struct kore_buf *response = kore_buf_alloc(128);

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

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if (req->http_body == NULL)
			BAD_REQUEST("no message found in request");

		if (req->http_body_length > MAX_LEN_SAFE_JSON)
			BAD_REQUEST("message too long");

		if ((message = (char *)req->http_body->data) == NULL)
			BAD_REQUEST("no message found in request");
	}

	if (http_request_header(req, "content-type", &content_type) != KORE_RESULT_OK)
		content_type = "";

	publish_async_data_t *data = malloc (sizeof(publish_async_data_t));

	if (data == NULL)
		ERROR("out of memory");

	data->id 		=
	data->apikey 		=
	data->message		=
	data->message_type	=
	data->subject		=
	data->content_type	= NULL;

	if (!(data->id 			= strdup(id)))			ERROR("out of memmory");
	if (!(data->to 			= strdup(to)))			ERROR("out of memmory");
	if (!(data->apikey		= strdup(apikey)))		ERROR("out of memmory");
	if (!(data->subject		= strdup(subject)))		ERROR("out of memmory");
	if (!(data->message		= strdup(message)))		ERROR("out of memmory");
	if (!(data->message_type	= strdup(message_type)))	ERROR("out of memmory");
	if (!(data->content_type	= strdup(content_type)))	ERROR("out of memmory");

	if (q_insert (&thread_q[queue_index], data) < 0)
		ERROR("inserting into queue failed");

	queue_index = (queue_index + 1) % MAX_ASYNC_THREADS;

	OK_202();

done:
	if (req->status == 500)
	{
		if (data)
		{
			if (data->id)		free (data->id);
			if (data->apikey)	free (data->apikey);
			if (data->message)	free (data->message);
			if (data->subject)	free (data->subject);
			if (data->content_type)	free (data->content_type);

			free (data);
		}
	}

	http_response_header(		
		req,			
		"content-type",		
		"application/json"	
	);				

	http_response (			
		req,			
		req->status, 		
		response->data,		
		response->offset	
	);				

	kore_buf_reset(response);	

	return (KORE_RESULT_OK);	
}

int async_init (char *connection_str)
{
	int i;

	for (i = 0; i < MAX_ASYNC_THREADS; ++i)
	{
		q_init(&thread_q[i]);

		if (
			pthread_create(
				&thread[i],
				NULL,
				async_publish_function,
				(void *)&thread_q[i]
			) != 0
		)
		{
			perror("could not create async thread");
			return KORE_RESULT_ERROR;
		}
	}
	
	return KORE_RESULT_OK;
}
