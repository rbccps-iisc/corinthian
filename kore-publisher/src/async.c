#include "kore-publisher.h"
#include "async.h"

static struct kore_pgsql sql;

//static char queue	[MAX_LEN_RESOURCE_ID + 1];
static char exchange	[MAX_LEN_RESOURCE_ID + 1];

static struct kore_buf *query 		= NULL;
static struct kore_buf *response 	= NULL;

static char 	string_to_be_hashed 	[MAX_LEN_APIKEY + MAX_LEN_SALT + MAX_LEN_ENTITY_ID + 1];
static uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
static char 	hash_string		[2*SHA256_DIGEST_LENGTH + 1];

static ht connection_ht;

#define MAX_ASYNC_THREADS (2)

static int queue_index = 0;

static pthread_t 	thread	[MAX_ASYNC_THREADS];
static Q 		thread_q[MAX_ASYNC_THREADS];

static
bool
async_login_success (const char *id, const char *apikey, bool *is_autonomous)
{
	char *salt;
	char *password_hash;
	char *str_is_autonomous;

	bool login_success = false;

	if (id == NULL || apikey == NULL || *id == '\0' || *apikey == '\0')
		goto done;

	if (id[0] < 'a' || id[0] > 'z')
		goto done;	

	if (! is_string_safe(id))
		goto done;

	CREATE_STRING (query,
		"SELECT salt,password_hash,is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				id
	);

	debug_printf("async login query = {%s}\n",query->data);

	kore_pgsql_cleanup(&sql);
	kore_pgsql_init(&sql);
	if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
	{
		kore_pgsql_logerror(&sql);
		goto done;
	}
	if (! kore_pgsql_query(&sql,(const char *)query->data))
	{
		kore_pgsql_logerror(&sql);
		goto done;
	}

	if (kore_pgsql_ntuples(&sql) == 0)
		goto done;

	salt 	 		= kore_pgsql_getvalue(&sql,0,0);
	password_hash		= kore_pgsql_getvalue(&sql,0,1);
	str_is_autonomous 	= kore_pgsql_getvalue(&sql,0,2);

	if (is_autonomous)
		*is_autonomous = false; 

	// there is no salt or password hash in db ?
	if (salt[0] == '\0' || password_hash[0] == '\0')
		goto done;

	if (is_autonomous)
		*is_autonomous = str_is_autonomous[0] == 't'; 

	snprintf (string_to_be_hashed, 
			MAX_LEN_HASH_INPUT + 1,
				"%s%s%s",
					apikey, salt, id);

	SHA256 (
		(const uint8_t*)string_to_be_hashed,
		strnlen (string_to_be_hashed,MAX_LEN_HASH_INPUT),
		binary_hash
	);

	debug_printf("login success STRING TO BE HASHED = {%s}\n",
			string_to_be_hashed);
	snprintf
	(
		hash_string,
		1 + 2*SHA256_DIGEST_LENGTH,
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x",
		binary_hash[ 0],binary_hash[ 1],binary_hash[ 2],binary_hash[ 3],
		binary_hash[ 4],binary_hash[ 5],binary_hash[ 6],binary_hash[ 7],
		binary_hash[ 8],binary_hash[ 9],binary_hash[10],binary_hash[11],
		binary_hash[12],binary_hash[13],binary_hash[14],binary_hash[15],
		binary_hash[16],binary_hash[17],binary_hash[18],binary_hash[19],
		binary_hash[20],binary_hash[21],binary_hash[22],binary_hash[23],
		binary_hash[24],binary_hash[25],binary_hash[26],binary_hash[27],
		binary_hash[28],binary_hash[29],binary_hash[30],binary_hash[31]
	);

	hash_string[2*SHA256_DIGEST_LENGTH] = '\0';

	debug_printf("Expecting it to be {%s} got {%s}\n",
			password_hash,
				hash_string
	);

	if (strncmp(hash_string,password_hash,64) == 0) {
		login_success = true;
		debug_printf("Login OK\n");
	}

done:
	kore_buf_reset(query);
	kore_pgsql_cleanup(&sql);

	return login_success;
}

static
void*
async_publish_function (void *v)
{
	Q *q = (Q *)v;

	publish_async_data_t *data = NULL; 

	node *n = NULL;
	char key [MAX_LEN_HASH_KEY + 1];

	const char *id;
	const char *apikey;
	const char *subject;
	const char *message;
	const char *content_type;

	char *my_exchange;

	amqp_connection_state_t	*cached_conn = NULL;
	
	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;
	amqp_basic_properties_t	props;

	memset(&props, 0, sizeof props);
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_USER_ID_FLAG;

	ht_init (&connection_ht);

	while (1)
	{
		while ((data = q_delete(q)))
		{
			id		= data->id;
			apikey		= data->apikey;
			subject		= data->subject;
			message		= data->message;
			content_type	= data->content_type;
			my_exchange	= data->exchange;

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

				if (! async_login_success(id,apikey,NULL))
					goto done;	

/////////////////////////////////////////////////

				cached_conn = malloc(sizeof(amqp_connection_state_t));

				if (cached_conn == NULL)
					goto done;	

				*cached_conn = amqp_new_connection();
				amqp_socket_t *socket = amqp_tcp_socket_new(*cached_conn);

				if (socket == NULL)
					goto done;	

				if (amqp_socket_open(socket, "broker" , 5672))
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
					amqp_cstring_bytes(my_exchange),
        				amqp_cstring_bytes(subject),
					0,
					0,
					&props,
					amqp_cstring_bytes(message)
				)
			)
				goto done;

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
	const char *apikey;
	const char *to;
	const char *subject;
	const char *message;
	const char *message_type;

	const char *content_type;

	char topic_to_publish[MAX_LEN_TOPIC + 1];

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

		snprintf(exchange,MAX_LEN_RESOURCE_ID + 1,"%s.%s",id,message_type);
		strlcpy(topic_to_publish,subject,MAX_LEN_TOPIC);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",topic_to_publish);
	}
	else
	{
		if (strcmp(message_type,"command") != 0)
		{
			BAD_REQUEST("message-type can only be command");		
		}

		snprintf(topic_to_publish,MAX_LEN_TOPIC + 1,"%s.%s.%s",to,message_type,subject);
		snprintf(exchange,MAX_LEN_RESOURCE_ID + 1,"%s.publish",id);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",topic_to_publish);
	}

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if (req->http_body == NULL)
			BAD_REQUEST("no message found in request");

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
	data->exchange		=
	data->subject		=
	data->content_type	= NULL;

	if (!(data->id 			= strdup(id)))			ERROR("out of memmory");
	if (!(data->apikey		= strdup(apikey)))		ERROR("out of memmory");
	if (!(data->message		= strdup(message)))		ERROR("out of memmory");
	if (!(data->exchange 		= strdup(exchange)))		ERROR("out of memmory");
	if (!(data->subject		= strdup(topic_to_publish)))	ERROR("out of memmory");
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
			if (data->exchange)	free (data->exchange);
			if (data->subject)	free (data->subject);
			if (data->content_type)	free (data->content_type);

			free (data);
		}
	}

	END();
}

int async_init ()
{
	int i;

	// XXX: do everything a normal init does

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


