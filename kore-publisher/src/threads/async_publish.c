#include "../apis/api.h"

void*
async_publish_thread (const void *v)
{
	Q *q = (Q *)v;

	publish_async_data_t *data = NULL; 

	node *n = NULL;
	char key[65];

	const char *id;
	const char *apikey;
	const char *subject;
	const char *message;
	const char *content_type;

	char *async_exchange;

	// TODO : yet to be tested !

	amqp_connection_state_t	*async_cached_conn = NULL;
	
	amqp_rpc_reply_t 	async_login_reply;
	amqp_rpc_reply_t 	async_rpc_reply;
	amqp_basic_properties_t	async_props;

	memset(&async_props, 0, sizeof props);
	async_props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_USER_ID_FLAG;

	ht_init (&async_connection_ht);

	while (1)
	{
		while ((data = q_delete(q)))
		{
			id		= data->id;
			apikey		= data->apikey;
			subject		= data->subject;
			message		= data->message;
			content_type	= data->content_type;
			async_exchange	= data->exchange;

			strlcpy(key,id,32);
			strlcat(key,apikey,64);

			if ((n = ht_search(&async_connection_ht,key)) != NULL)
			{
				async_cached_conn = n->value;
			}
			else
			{

/////////////////////////////////////////////////

				if (! looks_like_a_valid_entity(id))
					goto done;	

				if (! login_success(id,apikey,NULL))
					goto done;	

/////////////////////////////////////////////////

				async_cached_conn = malloc(sizeof(amqp_connection_state_t));

				if (async_cached_conn == NULL)
					goto done;	

				*async_cached_conn = amqp_new_connection();
				amqp_socket_t *socket = amqp_tcp_socket_new(*async_cached_conn);

				if (socket == NULL)
					goto done;	

				if (amqp_socket_open(socket, broker_ip , 5672))
					goto done;	
	
				async_login_reply = amqp_login(
					*async_cached_conn, 
					"/",
					0,
					131072,
					HEART_BEAT,
					AMQP_SASL_METHOD_PLAIN,
					id,
					apikey
				);

				if (async_login_reply.reply_type != AMQP_RESPONSE_NORMAL)
					goto done;	

				if(! amqp_channel_open(*async_cached_conn, 1))
					goto done;	

				async_rpc_reply = amqp_get_rpc_reply(*async_cached_conn);
				if (async_rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
					goto done;	

				ht_insert (&async_connection_ht, key, async_cached_conn);
			}

			async_props.user_id 		= amqp_cstring_bytes(id);
			async_props.content_type 	= amqp_cstring_bytes(content_type);

			amqp_basic_publish (
				*async_cached_conn,
				1,
				amqp_cstring_bytes(async_exchange),
        			amqp_cstring_bytes(subject),
				0,
				0,
				&async_props,
				amqp_cstring_bytes(message)
			);

done:
			free (data);
		}

		sleep (1);
	}

	return NULL;
}


