#include "kore-publisher.h"
#include "assets.h"

#define MAX_LEN_SALT		(32)
#define MAX_LEN_APIKEY	 	(32)

#define MIN_LEN_OWNER_ID	(3)
#define MAX_LEN_OWNER_ID	(32)

/* min = abc/efg */
#define MIN_LEN_ENTITY_ID 	(7)
#define MAX_LEN_ENTITY_ID 	(65)

// for queues and exchanges
#define MIN_LEN_RESOURCE_ID	(MIN_LEN_ENTITY_ID)
#define MAX_LEN_RESOURCE_ID	(128)

#define MAX_LEN_HASH_KEY 	(MAX_LEN_ENTITY_ID + MAX_LEN_APIKEY)
#define MAX_LEN_HASH_INPUT	(MAX_LEN_APIKEY + MAX_LEN_SALT + MAX_LEN_ENTITY_ID)

#define MAX_LEN_FOLLOW_ID	(10)

#define MAX_LEN_TOPIC		(128)

#define MAX_AMQP_RETRIES	(3)

char password_chars[] = "abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"0123456789"
			"-";

// variables for exchanges and queues
char *_e[] = {
		".public",
		".private",
		".protected",
		".notification",
		".publish",
		".diagnostics",
		// ".public.validated",
		// ".protected.validated",
		NULL
};

char *_q[] = {
		"\0",
		".private",
		".priority",
		".command",
		".notification",
		NULL
};

char *_invalid_owner_names [] = {
		"admin",
		"amq",
		"amqp",
		"mqtt",
		"database",
		"validator",
		NULL
};

struct kore_pgsql sql;

char queue	[MAX_LEN_RESOURCE_ID + 1];
char exchange	[MAX_LEN_RESOURCE_ID + 1];

struct kore_buf *query 		= NULL;
struct kore_buf *response 	= NULL;

char 	string_to_be_hashed 	[MAX_LEN_APIKEY + MAX_LEN_SALT + MAX_LEN_ENTITY_ID + 1];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[2*SHA256_DIGEST_LENGTH + 1];

ht connection_ht;
ht async_connection_ht;

bool is_success				= false;
bool allow_admin_apis_from_other_hosts	= false;

char *admin_apikey;
char *postgres_pwd;

char error_string [1025];

int tries;

amqp_connection_state_t	admin_connection;
amqp_table_t 		lazy_queue_table;
amqp_rpc_reply_t 	login_reply;
amqp_rpc_reply_t 	rpc_reply;
amqp_table_entry_t 	*entry;
amqp_basic_properties_t	props;

amqp_rpc_reply_t r;

#define MAX_ASYNC_THREADS (2)

int async_queue_index = 0;

Q 		async_q		[MAX_ASYNC_THREADS];
pthread_t 	async_thread	[MAX_ASYNC_THREADS];

bool admin_connection_open = false;

void
init_admin_connection (void)
{
	if (admin_connection_open)
	{
		amqp_channel_close	(admin_connection,1, AMQP_REPLY_SUCCESS);
		amqp_connection_close	(admin_connection,   AMQP_REPLY_SUCCESS);
		amqp_destroy_connection	(admin_connection);

		admin_connection_open = false;
	}

	admin_connection = amqp_new_connection();
	amqp_socket_t *socket = amqp_tcp_socket_new(admin_connection);

	if (socket == NULL)
	{
		fprintf(stderr,"Could not open socket for admin\n");
		exit(-1);
	}

	while (amqp_socket_open(socket, "broker", 5672))
	{
		fprintf(stderr,"Could not connect to broker for admin\n");
		sleep(1);
	}

	login_reply = amqp_login(
			admin_connection,
			"/",
			0,
			131072,
			HEART_BEAT,
			AMQP_SASL_METHOD_PLAIN,
			"admin",
			admin_apikey
	);

	if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"[%s:%d] invalid id or apikey\n",__FUNCTION__,__LINE__);
		exit (-1);
	}

	if(! amqp_channel_open(admin_connection, 1))
	{
		fprintf(stderr,"could not open an AMQP connection\n");
		exit (-1);
	}

	rpc_reply = amqp_get_rpc_reply(admin_connection);
	if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"broker did not send AMQP_RESPONSE_NORMAL\n");
		exit (-1);
	}

	admin_connection_open = true;
}

int
init (int state)
{
	int i;

	// mask server name 
	http_server_version("");

//////////////
// lazy queues
//////////////

	lazy_queue_table.num_entries = 3;
	lazy_queue_table.entries = malloc (
		lazy_queue_table.num_entries * sizeof(amqp_table_entry_t)
	);

	if (! lazy_queue_table.entries)
		exit(-1);

	entry = &lazy_queue_table.entries[0];
	entry->key = amqp_cstring_bytes("x-queue-mode");
	entry->value.kind = AMQP_FIELD_KIND_UTF8;
	entry->value.value.bytes = amqp_cstring_bytes("lazy");

	entry = &lazy_queue_table.entries[1];
	entry->key = amqp_cstring_bytes("x-max-length");
	entry->value.kind = AMQP_FIELD_KIND_I64;
	entry->value.value.i64 = 50000;

	entry = &lazy_queue_table.entries[2];
	entry->key = amqp_cstring_bytes("x-message-ttl");
	entry->value.kind = AMQP_FIELD_KIND_I64;
	entry->value.value.i64 = 43200000; // half day

//////////////

	if (! (admin_apikey = getenv("ADMIN_PWD")))
	{
		fprintf(stderr,"admin apikey not set\n");
		return KORE_RESULT_ERROR;
	}
	unsetenv("ADMIN_PWD");

	if (! (postgres_pwd = getenv("POSTGRES_PWD")))
	{
		fprintf(stderr,"postgres password not set\n");
		return KORE_RESULT_ERROR;
	}
	unsetenv("POSTGRES_PWD");

	/* By default we allow admin APIs to be called from any hosts.
	   Admin must unset the ALLOW_ADMIN_APIS_FROM_OTHER_HOSTS 
	   environment variable to only allow it from localhost. */

	if (getenv("ALLOW_ADMIN_APIS_FROM_OTHER_HOSTS"))
	{
		allow_admin_apis_from_other_hosts = true;
	}

	admin_connection_open = false;
	init_admin_connection();
	admin_connection_open = true;

	// declare the "DATABASE" queue if it does not exist
	amqp_queue_declare (
		admin_connection,
		1,
		amqp_cstring_bytes("DATABASE"),
		0,
		1, /* durable */
		0,
		0,
		lazy_queue_table
	);

	r = amqp_get_rpc_reply (admin_connection);

	if (r.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"amqp_queue_declare failed for {DATABASE}\n");
		return KORE_RESULT_ERROR;
	}

	ht_init (&connection_ht);

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(1024*1024);

	char connection_str[129];
        snprintf (
			connection_str,
			129,
			"host = %s user = postgres password = %s",
			"postgres",
			postgres_pwd
	);
	kore_pgsql_register("db",connection_str);

	memset(&props, 0, sizeof props);
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_USER_ID_FLAG;

////////////// For async publish ///////////////////

	for (i = 0; i < MAX_ASYNC_THREADS; ++i)
	{
		q_init(&async_q[i]);

		if (
			pthread_create(
				&async_thread[i],
				NULL,
				async_publish_function,
				(void *)&async_q[i]
			) != 0
		)
		{
			perror("could not create async thread");
			return KORE_RESULT_ERROR;
		}
	}

////////////////////////////////////////////////////

	return KORE_RESULT_OK;
}

bool
is_alpha_numeric (const char *str)
{
	size_t len = 0;

	const char *p = str;

	while (*p)
	{
		if (! isalnum(*p))
		{
			switch (*p)
			{
				case '-':
						break;
				default:
						return false;
			}
		}

		++p;
		++len;

		if (len > MAX_LEN_OWNER_ID)
			return false;
	}

	if (len < MIN_LEN_OWNER_ID)
		return false;
	else
		return true;
}

bool
looks_like_a_valid_owner (const char *str)
{
	return (str[0] >= 'a' && str[0] <= 'z' && is_alpha_numeric(str));
}

bool
is_owner(const char *id, const char *entity)
{
	int strlen_id = strnlen(id,MAX_LEN_OWNER_ID);

	if (strncmp(id,entity,strlen_id) != 0)
		return false;

	// '/' for owner and '.' for entity
	if (entity[strlen_id] != '/' && entity[strlen_id] != '.')
		return false;

	return true;
}

bool
looks_like_a_valid_entity (const char *str)
{
	size_t	len = 0;

	uint8_t front_slash_count = 0;

	const char *p = str;

	while (*p)
	{
		if (! isalnum(*p))
		{
			// support some extra chars
			switch (*p)
			{
				case '/':
						++front_slash_count;
						break;
				case '-':
						break;
				default:
						return false;
			}
		}

		++p;
		++len;

		if (len > MAX_LEN_ENTITY_ID || front_slash_count > 1)
			return false;
	}

	// there should be one front slash
	if (len < MIN_LEN_ENTITY_ID || front_slash_count != 1)
		return false;
	else
		return true;
}

bool
looks_like_a_valid_resource (const char *str)
{
	size_t 	len = 0;

	uint8_t dot_count 		= 0;
	uint8_t front_slash_count 	= 0;

	const char *p = str;

	while (*p)
	{
		if (! isalnum(*p))
		{
			// support some extra chars
			switch (*p)
			{
				case '/':
						++front_slash_count;
						break;
				case '-':
						break;

				case '.':
						++dot_count;
						break;
				default:
						return false;
			}
		}

		++p;
		++len;

		if (len > MAX_LEN_RESOURCE_ID)
			return false;
	}

	if (len < MIN_LEN_RESOURCE_ID)
		return false;

	// there should be only one front slash. Dot may or may not exist
	if ( (front_slash_count != 1) || (dot_count > 1) ) {
		return false;
	}

	return true;
}

void
gen_salt_password_and_apikey (
	const 	char *entity,
		char *salt,
		char *password_hash,
		char *apikey
)
{
	int i;

	int n_passwd_chars = sizeof(password_chars) - 1;

	for (i = 0; i < MAX_LEN_APIKEY; ++i)
	{
		salt  [i] = password_chars[arc4random_uniform(n_passwd_chars)]; 
		apikey[i] = password_chars[arc4random_uniform(n_passwd_chars)]; 
	}

	salt	[MAX_LEN_APIKEY] = '\0';
	apikey	[MAX_LEN_APIKEY] = '\0';

	snprintf (string_to_be_hashed, 
			MAX_LEN_HASH_INPUT + 1,
				"%s%s%s",
					apikey, salt, entity);

	SHA256 (
		(const uint8_t*)string_to_be_hashed,
		strnlen (string_to_be_hashed,MAX_LEN_HASH_INPUT),
		binary_hash
	);

	debug_printf("gen STRING TO BE HASHED = {%s}\n",string_to_be_hashed);

	snprintf
	(
		password_hash,
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

	password_hash [2*SHA256_DIGEST_LENGTH] = '\0';
}

bool
login_success (const char *id, const char *apikey, bool *is_autonomous)
{
	char *salt;
	char *password_hash;
	char *str_is_autonomous;

	bool login_result = false;

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

	debug_printf("login query = {%s}\n",query->data);

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
		login_result = true;
		debug_printf("Login OK\n");
	}

done:
	kore_buf_reset(query);
	kore_pgsql_cleanup(&sql);

	return login_result;
}

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

	// get content-type and set in props
	if (http_request_header(req,"content-type",&content_type) != KORE_RESULT_OK)
	{
		content_type = "";
	}

	node *n = NULL;
	amqp_connection_state_t	*cached_conn = NULL;

	char key [MAX_LEN_HASH_KEY + 1];
	snprintf (key, MAX_LEN_HASH_KEY + 1, "%s%s", id, apikey);

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

		if (amqp_socket_open(socket, "broker" , 5672))
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
	debug_printf("Got message : {%s}\n",message);

	FORBIDDEN_if ( 

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

		"[publish] broker refused to publish message"
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

	char key [MAX_LEN_HASH_KEY + 1];
	snprintf (key, MAX_LEN_HASH_KEY + 1, "%s%s", id, apikey);

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

		if (amqp_socket_open(socket, "broker" , 5672))
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

	time_t start_time = time(NULL);

	for (i = 0; i < int_num_messages; ++i)
	{
		amqp_rpc_reply_t res;
		amqp_message_t 	 message;

		do
		{
			res = amqp_basic_get(
					*cached_conn,
					1,
					amqp_cstring_bytes((const char *)queue),
					/*no ack*/ 1
			);
		
		} while	(
			(res.reply_type == AMQP_RESPONSE_NORMAL) 	&&
			(res.reply.id 	== AMQP_BASIC_GET_EMPTY_METHOD) &&
			((time(NULL) - start_time) < 1)
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

		kore_buf_append(response,"\",\"subject\":\"",13);
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
		if ((time(NULL) - start_time) > 1)
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

int
reset_apikey (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;
	const char *owner;

	char salt		[MAX_LEN_APIKEY + 1];
	char new_apikey		[MAX_LEN_APIKEY + 1];
	char password_hash	[2*SHA256_DIGEST_LENGTH + 1];

	const char *reset_api_key_for = NULL;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not valid");


	// either "id" should be owner of the "entity", or an "admin" 
	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");

		if (KORE_RESULT_OK != http_request_header(req, "owner", &owner))
			FORBIDDEN("owner field missing in header");

		if (! is_string_safe(owner))
			FORBIDDEN("invalid owner");

		if (! looks_like_a_valid_owner(owner))
			FORBIDDEN("owner is not valid");

		reset_api_key_for = owner;
	}
	else
	{
		if (KORE_RESULT_OK != http_request_header(req, "entity", &entity))
			FORBIDDEN("entity field missing in header");

		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");

		if (! is_string_safe(entity))
			FORBIDDEN("invalid entity");

		if (! looks_like_a_valid_entity(entity))
			FORBIDDEN("entity is not valid");

		reset_api_key_for = entity;
	}

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	gen_salt_password_and_apikey (
		reset_api_key_for,
		salt,
		password_hash,
		new_apikey	
	);

	CREATE_STRING (query,
		"UPDATE users SET password_hash='%s', salt='%s' WHERE id='%s'",
			password_hash,
			salt,
			reset_api_key_for	
	);

	// generate response
	kore_buf_reset(response);
	kore_buf_appendf (response,
		"{\"id\":\"%s\",\"apikey\":\"%s\"}\n",
			reset_api_key_for,
			new_apikey	
	);

	RUN_QUERY (query,"failed to reset the apikey");

	OK();

done:
	END();
}

int
set_autonomous(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;
	const char *str_is_autonomous;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "entity", &entity)
				||
		KORE_RESULT_OK != http_request_header(req, "is-autonomous", &str_is_autonomous)
			,
		"inputs missing in headers"
	);

	char char_is_autonomous = 'f';
 
	if (strcmp(str_is_autonomous,"true") == 0)
	{
		char_is_autonomous = 't';
	}
	else if (strcmp(str_is_autonomous,"false") == 0)
	{
		char_is_autonomous = 'f';
	}
	else {
		BAD_REQUEST("is-autonomous value is invalid");	
	}

/////////////////////////////////////////////////

	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not valid");

	if (! is_string_safe(entity))
		FORBIDDEN("invalid entity");

	if (! looks_like_a_valid_entity(entity))
		FORBIDDEN("entity is not valid");

	// either "id" should be owner of the "entity", or an "admin" 
	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");
	}
	else
	{
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING (query,
		"UPDATE users SET is_autonomous = '%c' WHERE id = '%s'",
			char_is_autonomous,
			entity
	);

	RUN_QUERY(query,"failed to set is-autonomous state");

	OK();

done:
	END();
}

int
register_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;
	const char *char_is_autonomous;

	char entity_name 	[MAX_LEN_ENTITY_ID + 1];

	char salt		[MAX_LEN_APIKEY + 1];
	char entity_apikey	[MAX_LEN_APIKEY + 1];
	char password_hash	[2*SHA256_DIGEST_LENGTH + 1];

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

	// entity at the time of registration has the same criteria as the owner's id
	// later on we will add owner/ in front of it
	if (! is_alpha_numeric(entity))
		BAD_REQUEST("entity is not valid");

	char *body = req->http_body ? (char *)req->http_body->data : NULL;
	
	bool is_autonomous = false;
	if (http_request_header(req, "is-autonomous", &char_is_autonomous) == KORE_RESULT_OK)
	{
		is_autonomous = (0 == strcmp(char_is_autonomous,"true"));
	}

/////////////////////////////////////////////////

	string_to_lower(entity);

	if (! is_string_safe(entity))
		FORBIDDEN("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	if (body)
		json_sanitize(body);
	else
		body = "{}";

/////////////////////////////////////////////////

	snprintf(entity_name,MAX_LEN_ENTITY_ID + 1,"%s/%s",id,entity);

	// create entries in to RabbitMQ

	if (0 == pthread_create(&thread,NULL,create_exchanges_and_queues,(void *)entity_name))
		thread_started = true;
	else
	{
		create_exchanges_and_queues((void *)entity_name);

		if (! is_success)
			ERROR("could not create exchanges and queues");
	}

	// conflict if entity_name already exist

	CREATE_STRING(query,
		 	"SELECT id FROM users WHERE id='%s'",
				entity_name
	);

	RUN_QUERY (query,"could not get info about entity");

	if (kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity_name, salt, password_hash, entity_apikey);

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

	if ( 
		! kore_pgsql_query_params (
			&sql,
			(char *)query->data,
			0,
			1,
			body,
			req->http_body_length,
			0
		)
	)
	{
		kore_pgsql_logerror(&sql);
		ERROR("failed to create the entity with schema");
	}
	
	// generate response
	kore_buf_reset(response);
	kore_buf_appendf (response,
		"{\"id\":\"%s\",\"apikey\":\"%s\"}\n",
			entity_name,
			entity_apikey
	);

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

int
get_entities (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	// deny if the user is not a owner
	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not valid");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
		 	"SELECT id,blocked,is_autonomous FROM users WHERE id LIKE '%s/%%' ORDER BY id",
				id
	);

	RUN_QUERY (query,"could not get info about entity");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);

	for (i = 0; i < num_rows; ++i)
	{
		char *entity 		= kore_pgsql_getvalue(&sql,i,0);
		char *is_blocked	= kore_pgsql_getvalue(&sql,i,1);
		char *is_autonomous 	= kore_pgsql_getvalue(&sql,i,2);

		kore_buf_appendf (
				response,
					"{\"%s\":[%s,%s]},",
						entity,
						is_blocked	[0] == 't' ? "1" : "0",
						is_autonomous	[0] == 't' ? "1" : "0"
		);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"]",1);

	OK();

done:
	END();	
}

int
deregister_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

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

/////////////////////////////////////////////////

	// deny if the id does not look like an owner
	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not an owner");

	if (! is_string_safe(entity))
		FORBIDDEN("invalid entity");

	if (! looks_like_a_valid_entity(entity))
		FORBIDDEN("entity is not valid");

	if (! is_owner(id,entity))
		FORBIDDEN("you are not the owner of the entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	// check if the entity exists
	CREATE_STRING (query,
			"SELECT 1 FROM users WHERE id = '%s'",
				entity
	);
	RUN_QUERY(query,"could no query entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid entity");

	// delete entries in to RabbitMQ
	if (0 == pthread_create(&thread,NULL,delete_exchanges_and_queues,(void *)entity))
		thread_started = true;
	else
	{
		delete_exchanges_and_queues((void *)entity);

		if (! is_success)
			ERROR("could not delete exchanges and queues");
	}


	CREATE_STRING (query,
		"DELETE FROM acl WHERE from_id = '%s' OR exchange LIKE '%s.%%'",
		entity,
		entity
	);

	RUN_QUERY(query,"could not delete from acl table");

	CREATE_STRING (query,
		"DELETE FROM follow WHERE requested_by = '%s' OR exchange LIKE '%s.%%'",
		entity,
		entity
	);

	RUN_QUERY(query,"could not delete from follow table");

	CREATE_STRING (query,
			"DELETE FROM users WHERE id = '%s'",
				entity
	);
	RUN_QUERY (query,"could not delete the entity");

	OK();

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

int
catalog (struct http_request *req)
{
	int i, num_rows;

	const char *entity;

	req->status = 403;

	http_populate_get(req);
	if (http_argument_get_string(req,"id",(void *)&entity))
	{
		// if not a valid entity
		if (! looks_like_a_valid_entity(entity))
			FORBIDDEN("id is not a valid entity");

		if (! is_string_safe(entity))
			FORBIDDEN("invalid entity");

		CREATE_STRING (query,
				"SELECT schema FROM users WHERE id='%s'",
					entity
		);
	}
	else
	{
		entity = NULL;
		CREATE_STRING (query,"SELECT id,schema FROM users LIMIT 50");
	}

	RUN_QUERY (query,"unable to query catalog data");

	num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	if (entity == NULL) // get top 50 data 
	{
		kore_buf_append(response,"{",1);

		for (i = 0; i < num_rows; ++i)
		{
			char *id	= kore_pgsql_getvalue(&sql,i,0);
			char *schema 	= kore_pgsql_getvalue(&sql,i,1);

			kore_buf_appendf(response,"\"%s\":%s,",id,schema);
		} 
		if (num_rows > 0)
		{
			// remove the last COMMA 
			--(response->offset);
		}

		kore_buf_append(response,"}",1);
	}
	else
	{
		// if this entity has no schema or the entity does't exist
		if (num_rows == 0)
			BAD_REQUEST("not a valid id");

		char *schema = kore_pgsql_getvalue(&sql,0,0);

		// max 3MB
		kore_buf_append(response,schema,strnlen(schema,3*1024*1024));
	}

	OK();

done:
	END();
}

int
register_owner(struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *owner;

	char salt		[MAX_LEN_APIKEY + 1];
	char owner_apikey	[MAX_LEN_APIKEY + 1];
	char password_hash	[2*SHA256_DIGEST_LENGTH + 1];

	pthread_t thread;
	bool thread_started = false;

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this API can only be called from localhost");

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "owner", &owner)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this API");

	string_to_lower(owner);

	for (i = 0; _invalid_owner_names [i]; ++i)
	{
		if (strcmp(owner,_invalid_owner_names[i]) == 0)
			FORBIDDEN("cannot create owner");
	}


	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("invalid owner");

	if (! is_string_safe(owner))
		FORBIDDEN("invalid owner");

	if (! login_success("admin",apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	// conflict if owner already exist
	CREATE_STRING (query,
			"SELECT id FROM users WHERE id ='%s'",
				owner
	);
	RUN_QUERY (query,"could not query info about the owner");

	if(kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	if (0 == pthread_create(&thread,NULL,create_exchanges_and_queues,(void *)owner))
		thread_started = true;
	else
	{
		create_exchanges_and_queues((void *)owner);

		if (! is_success)
			ERROR("could not create exchanges and queues");
	}

	gen_salt_password_and_apikey (owner, salt, password_hash, owner_apikey);

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked,is_autonomous) "
				"VALUES('%s','%s',NULL,'%s','f','t')",
				owner,
				password_hash,
				salt
	);

	RUN_QUERY (query, "could not create a new owner");

	kore_buf_reset(response);
	kore_buf_appendf(response,
			"{\"id\":\"%s\",\"apikey\":\"%s\"}\n",
				owner,
				owner_apikey
	);

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

int
get_owners(struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this API can only be called from localhost");

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("unauthorized");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING (query, "SELECT id,blocked FROM users WHERE id NOT LIKE '%%/%%' ORDER BY id");
	RUN_QUERY(query,"failed to query user table");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	for (i = 0; i < num_rows; ++i)
	{
		char *owner		= kore_pgsql_getvalue(&sql,i,0);
		char *is_blocked	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf (
			response,
				"\"%s\":%s,",
					owner,	
					is_blocked [0] == 't' ? "1" : "0"
		);
	}

	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"}",1);

	OK();

done:
	END();
}

int
deregister_owner(struct http_request *req)
{
	int i, num_rows;

	const char *id;
	const char *apikey;
	const char *owner;

	pthread_t thread;
	bool thread_started = false; 

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this API can only be called from localhost");

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "owner", &owner)
			,
		"inputs missing in headers"
	);

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this API");

	for (i = 0; _invalid_owner_names[i]; ++i)
	{
		if (strcmp(owner,_invalid_owner_names[i]) == 0)
			FORBIDDEN("cannot delete owner");
	}

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("invalid owner");

/////////////////////////////////////////////////

	if (! is_string_safe(owner))
		FORBIDDEN("invalid owner");

	if (! login_success("admin",apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING (query,
			"SELECT id FROM users where id = '%s' or id like '%s/%%'",
				owner,
				owner
	);

	RUN_QUERY (query,"could not get app/devices associated with owner");

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *entity = kore_pgsql_getvalue(&sql,i,0);
		debug_printf("Deleting {%s}\n",entity);
		delete_exchanges_and_queues((void *)entity); 
	}

	// delete entries in to RabbitMQ
	if (0 == pthread_create(&thread,NULL,delete_exchanges_and_queues,(void *)owner))
		thread_started = true;
	else
	{
		delete_exchanges_and_queues((void *)owner);

		if (! is_success)
			ERROR("could not delete exchanges and queues");
	}

	// delete from acl
	CREATE_STRING (query,
			"DELETE FROM acl WHERE from_id LIKE '%s/%%' OR exchange LIKE '%s/%%'",
				owner,
				owner
	);

	RUN_QUERY (query,"could not delete from acl table");

	// delete all apps and devices of the owner
	CREATE_STRING (query,
		"DELETE FROM users WHERE id LIKE '%s/%%'",
			owner
	);
	RUN_QUERY (query,"could not delete apps/devices of the owner");

	// finally delete the owner 
	CREATE_STRING (query,
			"DELETE FROM users WHERE id = '%s'",
				owner
	);
	RUN_QUERY (query,"could not delete the owner");

	OK();

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

int
queue_bind (struct http_request *req)
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

	debug_printf("id = %s\n, apikey = %s\n, to =%s\n, topic = %s\n, message-type = %s\n", id, apikey, to, topic, message_type);


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
		(strcmp(message_type,"public") 		!= 0) &&
		(strcmp(message_type,"private") 	!= 0) &&
		(strcmp(message_type,"protected") 	!= 0) &&
		(strcmp(message_type,"diagnostics") 	!= 0)
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

	snprintf (exchange,MAX_LEN_RESOURCE_ID + 1,"%s.%s", to,message_type); 

/////////////////////////////////////////////////

	if (! is_string_safe(from))
		FORBIDDEN("invalid from");

	if (! is_string_safe(to))
		FORBIDDEN("invalid to");

	if (! is_string_safe(topic))
		FORBIDDEN("invalid topic");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	strlcpy(queue,from,128);
	if (KORE_RESULT_OK == http_request_header(req, "is-priority", &is_priority))
	{
		if (strcmp(is_priority,"true") == 0)
		{
			strlcat(queue,".priority",128);
		}
	}

	debug_printf("queue = %s\n",queue);
	debug_printf("exchange = %s\n", exchange);

	// For all non public messages
	// if he is not the owner, he needs an entry in acl
	if(strcmp(message_type,"public") != 0)
	{
		if (! is_owner(id,to))
		{ 
			CREATE_STRING (
				query,
				"SELECT 1 FROM acl WHERE "
				"from_id = '%s' "
				"AND exchange = '%s' "
				"AND permission = 'read' "
				"AND valid_till > now() AND topic = '%s'",
				from,
				exchange,
				topic
			);

			RUN_QUERY(query,"failed to query for permission");

			if (kore_pgsql_ntuples(&sql) != 1)
				FORBIDDEN("unauthorized");
		}
	}

	for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
	{
		amqp_queue_bind (
			admin_connection,
			1,
			amqp_cstring_bytes(queue),
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(topic),
			amqp_empty_table
		);

		r = amqp_get_rpc_reply(admin_connection);

		if (r.reply_type == AMQP_RESPONSE_NORMAL)
			break;
		else
		{
			printf("%s Retrying ....\n",__FUNCTION__);
			init_admin_connection ();
		}
	}

	if (tries > MAX_AMQP_RETRIES)
	{
		snprintf(error_string,1025,"bind failed e={%s} q={%s} t={%s}\n", exchange,queue,topic);
		ERROR(error_string);
	}

	OK();

done:
	if (req->status == 500)
		init_admin_connection(); // try once more

	END();
}

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

/////////////////////////////////////////////////

	if (! is_string_safe(from))
		FORBIDDEN("invalid from");

	if (! is_string_safe(to))
		FORBIDDEN("invalid to");

	if (! is_string_safe(topic))
		FORBIDDEN("invalid topic");

	bool is_autonomous = false;

	if (! login_success(id,apikey, &is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	snprintf	(exchange,MAX_LEN_RESOURCE_ID + 1,"%s.%s", to,message_type); 
	strlcpy		(queue,from,MAX_LEN_RESOURCE_ID);

	if (KORE_RESULT_OK == http_request_header(req, "is-priority", &is_priority))
	{
		if (strcmp(is_priority,"true") == 0)
		{
			strlcat(queue,".priority",128);
		}
	}

	debug_printf("queue = %s",queue);
	debug_printf("exchange = %s", exchange);

	if(strcmp(message_type,"public") != 0)
	{
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
	}

	for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
	{
		amqp_queue_unbind (
			admin_connection,
			1,
			amqp_cstring_bytes(queue),
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(topic),
			amqp_empty_table
		);

		r = amqp_get_rpc_reply(admin_connection);

		if (r.reply_type == AMQP_RESPONSE_NORMAL)
			break;
		else
		{
			printf("[%d] %s Retrying ....\n",tries,__FUNCTION__);
			init_admin_connection();
		}
	}

	if (tries > MAX_AMQP_RETRIES)
	{
		snprintf(error_string,1025,"unbind failed e={%s} q={%s} t={%s}\n",exchange,queue,topic);
		ERROR(error_string);
	}

	OK();

done:
	if (req->status == 500)
		init_admin_connection(); // try once more

	END();
}

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

/////////////////////////////////////////////////

	if (! looks_like_a_valid_entity(to))
		FORBIDDEN("'to' is not a valid entity");

	if (! is_string_safe(from))
		FORBIDDEN("invalid from");

	if (! is_string_safe(to))
		FORBIDDEN("invalid to");

	if (! is_string_safe(validity))
		FORBIDDEN("invalid validity");

	if (! is_string_safe(topic))
		FORBIDDEN("invalid topic");

	BAD_REQUEST_if (
		(strcmp(permission,"read") 		!= 0) &&
		(strcmp(permission,"write") 		!= 0) &&
		(strcmp(permission,"read-write") 	!= 0)
		,
		"invalid permission"
	);

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////


	// if both from and to are owned by id
	if (is_owner(id,to))
		status = "approved";

	char read_follow_id  [10];
	char write_follow_id [10];

	read_follow_id[0] = '\0';
	write_follow_id[0] = '\0';

	int int_validity = strtonum(validity,1,10000,NULL);
	if (int_validity <= 0)
		BAD_REQUEST("validity must be in number of hours");

	CREATE_STRING (query,
		"SELECT is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				to	
	);

	RUN_QUERY (query,"could not get info about 'to'");

	if (kore_pgsql_ntuples(&sql) != 1)
		FORBIDDEN("'to' does not exist OR has been blocked");

	char *char_is_to_autonomous	= kore_pgsql_getvalue(&sql,0,0);
	bool is_to_autonomous		= char_is_to_autonomous[0] == 't';

	if (strcmp(permission,"read") == 0 || strcmp(permission,"read-write") == 0)
	{
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
			char write_exchange 	[MAX_LEN_RESOURCE_ID + 1];
			char command_queue	[MAX_LEN_RESOURCE_ID + 1];
			char write_topic	[MAX_LEN_TOPIC + 1];

			snprintf(write_exchange,MAX_LEN_RESOURCE_ID + 1,"%s.publish",from);
			snprintf(command_queue, MAX_LEN_RESOURCE_ID + 1,"%s.command",to);
			snprintf(write_topic,MAX_LEN_TOPIC + 1,"%s.command.%s",to,topic);

			for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
			{
				amqp_queue_bind (
					admin_connection,
					1,
					amqp_cstring_bytes(command_queue),
					amqp_cstring_bytes(write_exchange),
					amqp_cstring_bytes(write_topic),
					amqp_empty_table
				);

				r = amqp_get_rpc_reply(admin_connection);

				if (r.reply_type == AMQP_RESPONSE_NORMAL)
					break;
				else
				{
					printf("%s Retrying ....\n",__FUNCTION__);
					init_admin_connection();
				}
			}

			if (tries > MAX_AMQP_RETRIES)
			{
				snprintf(error_string,1025,"bind failed e={%s} q={%s} t={%s}\n",write_exchange, command_queue, write_topic);
				ERROR(error_string);
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
		if (is_to_autonomous)
			snprintf (exchange, MAX_LEN_RESOURCE_ID + 1, "%s.notification",to);
		else
		{
			int index = 0;

			while (
				to[index]
					&&
				to[index] != '/'
					&&
				index < MAX_LEN_OWNER_ID 
			)
			{
				exchange[index] = to[index];
				++index;
			}

			strlcpy (exchange + index,".notification", 32);
		}

		char *subject = "Request for follow";

		char message[1025];
		snprintf(message,  1025, "'%s' has requested '%s' access on '%s'",id,permission,to);

		props.user_id 		= amqp_cstring_bytes("admin");
		props.content_type 	= amqp_cstring_bytes("text/plain");

		ERROR_if
		(
			AMQP_STATUS_OK != amqp_basic_publish (
				admin_connection,
				1,
				amqp_cstring_bytes(exchange),
				amqp_cstring_bytes(subject),
				0,
				0,
				&props,
				amqp_cstring_bytes(message)
			),

			"[follow] broker refused to publish message"
		);

		/* we have sent the request,
		   but the owner of the "to" device/app must approve */
		req->status = 202;
	}

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	if (read_follow_id[0])
		kore_buf_appendf(response,"\"follow-id-read\":\"%s\"",read_follow_id);

	if (write_follow_id[0])
	{
		// put a comma if follow-id-read was written in response
		if (read_follow_id[0])
			kore_buf_append(response,",",1);

		kore_buf_appendf(response,"\"follow-id-write\":\"%s\"",write_follow_id);
	}

	kore_buf_append(response,"}\n",2);

done:
	if (req->status == 500)
		init_admin_connection(); // try once more

	END();
}

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

	if (! is_string_safe(from))
		FORBIDDEN("invalid from");

	if (! is_string_safe(to))
		FORBIDDEN("invalid to");

	if (! is_string_safe(topic))
		FORBIDDEN("invalid topic");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

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
		
		char write_exchange 	[MAX_LEN_RESOURCE_ID + 1];
		char command_queue	[MAX_LEN_RESOURCE_ID + 1];
		char write_topic	[MAX_LEN_TOPIC + 1];

		snprintf(write_exchange,MAX_LEN_RESOURCE_ID + 1,"%s.publish",from);
		snprintf(command_queue, MAX_LEN_RESOURCE_ID + 1,"%s.command",to);
		snprintf(write_topic,MAX_LEN_TOPIC + 1,"%s.command.%s",to,topic);

		for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
		{
			amqp_queue_unbind (
				admin_connection,
				1,
				amqp_cstring_bytes(command_queue),
				amqp_cstring_bytes(write_exchange),
				amqp_cstring_bytes(write_topic),
				amqp_empty_table
			);

			r = amqp_get_rpc_reply(admin_connection);

			if (r.reply_type == AMQP_RESPONSE_NORMAL)
				break;
			else
			{
				printf("%s Retrying ....\n",__FUNCTION__);
				init_admin_connection();
			}
		}

		if (tries > MAX_AMQP_RETRIES)
		{
			snprintf(error_string,1025,"unbind failed e={%s} q={%s} t={%s}\n",write_exchange,command_queue,write_topic);
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
	snprintf(exchange,MAX_LEN_RESOURCE_ID + 1,"%s.%s",to,message_type);

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

	char priority_queue[MAX_LEN_RESOURCE_ID + 1];

	snprintf(priority_queue,MAX_LEN_RESOURCE_ID + 1,"%s.priority", from);

	acl_id		= kore_pgsql_getvalue(&sql,0,0);
	follow_id	= kore_pgsql_getvalue(&sql,0,1);

	CREATE_STRING 	(query, "DELETE FROM acl WHERE acl_id='%s'", acl_id);
	RUN_QUERY	(query, "failed to delete from acl table");

	CREATE_STRING 	(query, "DELETE FROM follow WHERE follow_id='%s'", follow_id);
	RUN_QUERY	(query, "failed to delete from follow table");

	for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
	{
		amqp_queue_unbind (
			admin_connection,
			1,
			amqp_cstring_bytes(from),
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(topic),
			amqp_empty_table
		);

		r = amqp_get_rpc_reply(admin_connection);

		if (r.reply_type == AMQP_RESPONSE_NORMAL)
			break;
		else
		{
			printf("%s Retrying ....\n",__FUNCTION__);
			init_admin_connection();
		}
	}

	if (tries > MAX_AMQP_RETRIES)
	{
		snprintf(error_string,1025,"unbind failed e={%s} q={%s} t={%s}\n",exchange,from,topic);
		ERROR(error_string);
	}

	for (tries = 1; tries <= MAX_AMQP_RETRIES ; ++tries)
	{
		amqp_queue_unbind (
			admin_connection,
			1,
			amqp_cstring_bytes(priority_queue),
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(topic),
			amqp_empty_table
		);

		r = amqp_get_rpc_reply(admin_connection);

		if (r.reply_type == AMQP_RESPONSE_NORMAL)
			break;
		else
		{
			printf("%s Retrying ....\n",__FUNCTION__);
			init_admin_connection();
		}
	}

	if (tries > 3)
	{
		snprintf(error_string,1025,"unbind priority failed e={%s} q={%s} t={%s}\n",exchange,priority_queue,topic);
		ERROR(error_string);
	}

	OK();

done:
	if (req->status == 500)
		init_admin_connection(); // try once more

	END();
}

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

	if (! is_string_safe(follow_id))
		FORBIDDEN("invalid follow-id");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

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

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("follow-id is not valid");

	char *from_id		= kore_pgsql_getvalue(&sql,0,0);
	char *my_exchange 	= kore_pgsql_getvalue(&sql,0,1);
	char *permission 	= kore_pgsql_getvalue(&sql,0,2); 
	char *validity_hours 	= kore_pgsql_getvalue(&sql,0,3); 
	char *topic 	 	= kore_pgsql_getvalue(&sql,0,4); 

	CREATE_STRING (query,
		"SELECT is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				from_id	
	);

	RUN_QUERY (query,"could not get info about 'from'");

	if (kore_pgsql_ntuples(&sql) != 1)
		FORBIDDEN("'from' does not exist OR has been blocked");

	char *char_is_from_autonomous	= kore_pgsql_getvalue(&sql,0,0);
	bool is_from_autonomous		= char_is_from_autonomous[0] == 't';

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

	char bind_exchange	[MAX_LEN_RESOURCE_ID + 1];
	char bind_queue		[MAX_LEN_RESOURCE_ID + 1];
	char bind_topic		[MAX_LEN_TOPIC + 1];

	if (strcmp(permission,"read") == 0)
	{
		/*
		snprintf(bind_exchange,	MAX_LEN_RESOURCE_ID + 1,"%s",		my_exchange);
		snprintf(bind_queue,	MAX_LEN_RESOURCE_ID + 1,"%s",		from_id); 		// TODO: what about priority queue
		snprintf(bind_topic,	MAX_LEN_TOPIC + 1,      "%s",		topic);
		*/
	}
	else if (strcmp(permission,"write") == 0)
	{
		snprintf(bind_exchange,	MAX_LEN_RESOURCE_ID + 1,"%s.publish",	from_id);
		snprintf(bind_queue,	MAX_LEN_RESOURCE_ID + 1,"%s",		my_exchange);		// exchange in follow is "device.command"
		snprintf(bind_topic,	MAX_LEN_TOPIC + 1,      "%s.%s",	my_exchange,topic); 	// binding routing is "dev.command.topic"

		for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
		{
			amqp_queue_bind (
				admin_connection,
				1,
				amqp_cstring_bytes(bind_queue),
				amqp_cstring_bytes(bind_exchange),
				amqp_cstring_bytes(bind_topic),
				amqp_empty_table
			);

			r = amqp_get_rpc_reply(admin_connection);

			if (r.reply_type == AMQP_RESPONSE_NORMAL)
				break;
			else
			{
				printf("%s Retrying ....\n",__FUNCTION__);
				init_admin_connection();
			}
		}

		if (tries > MAX_AMQP_RETRIES)
		{
			snprintf(error_string,1025,"bind failed e={%s} q={%s} t={%s}\n",bind_exchange, bind_queue, bind_topic);
			ERROR(error_string);
		}

		debug_printf("\n--->binding {%s} with {%s} {%s}\n",bind_queue,bind_exchange,bind_topic);
	}
	else
	{
		ERROR ("wrong value of permission in db");
	}

	if (is_from_autonomous)
		snprintf (exchange, MAX_LEN_RESOURCE_ID + 1, "%s.notification",from_id);
	else
	{
		int index = 0;

		while (
			from_id[index]
					&&
			from_id[index] != '/'
					&&
			index < MAX_LEN_OWNER_ID 
		)
		{
			exchange[index] = from_id[index];
			++index;
		}

		strlcpy (exchange + index,".notification", 32);
	}

	char *subject = "Approved follow request";

	char message[1025];
	snprintf(message, 1025, "'%s' has approved follow request for '%s' access on '%s'",id,permission,bind_exchange);

	props.user_id 		= amqp_cstring_bytes("admin");
	props.content_type 	= amqp_cstring_bytes("text/plain");

	ERROR_if
	(
		AMQP_STATUS_OK != amqp_basic_publish (
			admin_connection,
			1,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(subject),
			0,
			0,
			&props,
			amqp_cstring_bytes(message)
		),

		"[share] broker refused to publish message"
	);

	OK();

done:
	if (req->status == 500)
		init_admin_connection(); // try once more

	END();
}

int
reject_follow (struct http_request *req)
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

	if (! is_string_safe(follow_id))
		FORBIDDEN("invalid follow-id");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' AND status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s.%%' AND status='pending'",
				follow_id,
				id
		);

	}

	RUN_QUERY (query,"could not run select query on follow");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("follow-id is not valid");

	// NOTE: follow_id is primary key 
	CREATE_STRING (query,
			"UPDATE follow SET status='rejected' WHERE follow_id = '%s'",
				follow_id
	);
	RUN_QUERY (query,"could not run update query on follow");

	OK();

done:
	END();
}

int
get_follow_status (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

//////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,permission,topic,validity,status "
			"FROM follow "
			"WHERE from_id LIKE '%s/%%' "
			"ORDER BY time DESC",
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,permission,topic,validity,status "
			"FROM follow "
			"WHERE from_id = '%s' "
			"ORDER BY time DESC",
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);
	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
			response,
			"{\"follow-id\":\"%s\","
			"\"from\":\"%s\","
			"\"to\":\"%s\","
			"\"time\":\"%s\","
			"\"permission\":\"%s\","
			"\"topic\":\"%s\","
			"\"validity\":\"%s\","
			"\"status\":\"%s\"},"
			,
			kore_pgsql_getvalue(&sql,i,0),
			kore_pgsql_getvalue(&sql,i,1),
			kore_pgsql_getvalue(&sql,i,2),
			kore_pgsql_getvalue(&sql,i,3),
			kore_pgsql_getvalue(&sql,i,4),
			kore_pgsql_getvalue(&sql,i,5),
			kore_pgsql_getvalue(&sql,i,6),
			kore_pgsql_getvalue(&sql,i,7)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]",1);

	OK();

done:
	END();
}

int
get_follow_requests (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,permission,topic,validity "
			"FROM follow "
			"WHERE exchange LIKE '%s/%%.%%' AND status='pending' "
			"ORDER BY time",
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,permission,topic,validity "
			"FROM follow "
			"WHERE exchange LIKE '%s.%%' AND status='pending' "
			"ORDER BY time",
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);
	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
			response,
			"{\"follow-id\":\"%s\","
			"\"from\":\"%s\","
			"\"to\":\"%s\","
			"\"time\":\"%s\","
			"\"permission\":\"%s\","
			"\"topic\":\"%s\","
			"\"validity\":\"%s\"},"
			,
			kore_pgsql_getvalue(&sql,i,0),
			kore_pgsql_getvalue(&sql,i,1),
			kore_pgsql_getvalue(&sql,i,2),
			kore_pgsql_getvalue(&sql,i,3),
			kore_pgsql_getvalue(&sql,i,4),
			kore_pgsql_getvalue(&sql,i,5),
			kore_pgsql_getvalue(&sql,i,6)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]",1);

	OK();

done:
	END();
}

int
block (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

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

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");

	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");
	}
	else
	{
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (! is_string_safe(entity))
		FORBIDDEN("invalid entity");

	if (strcmp(id,entity) == 0)
		FORBIDDEN("cannot block yourself");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"UPDATE users set blocked='t' WHERE id='%s'",
				entity
	);

	RUN_QUERY(query, "could not block the entity");

	OK();

done:
	END();
}

int
unblock (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

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

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");

	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");
	}
	else
	{
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (! is_string_safe(entity))
		FORBIDDEN("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"UPDATE users set blocked='f' WHERE id='%s'",
				entity
	);

	RUN_QUERY(query, "could not block the entity");

	OK();

done:
	END();
}

int
permissions (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *entity;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	)

	if (looks_like_a_valid_owner(id))
	{
		if (KORE_RESULT_OK != http_request_header(req, "entity", &entity))
			BAD_REQUEST("entity value not specified in header");
			
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of entity");
	}
	else
	{
		entity = id;
	}

/////////////////////////////////////////////////

	if (! is_string_safe(entity))
		FORBIDDEN("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT exchange,permission FROM acl WHERE from_id='%s' "
			"AND valid_till > now()",entity
	);
	RUN_QUERY (query,"could not query acl table");

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);

	int num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *my_exchange 	= kore_pgsql_getvalue(&sql,i,0);
		char *perm 		= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf(response,
				"{\"entity\":\"%s\",\"permission\":\"%s\"},",
					my_exchange,
					perm
		);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"]",1);

	OK();

done:
	END();

}

void *
create_exchanges_and_queues (void *v)
{
	int i;

	const char *id = (const char *)v;

	// local variables
	// int my_tries;
	char my_queue	[MAX_LEN_RESOURCE_ID + 1];
	char my_exchange[MAX_LEN_RESOURCE_ID + 1];

	amqp_rpc_reply_t my_r;

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// create notification exchange 
		snprintf(my_exchange,MAX_LEN_RESOURCE_ID + 1,"%s.notification",id);

		debug_printf("[owner] creating exchange {%s}\n",my_exchange);

		amqp_exchange_declare (
				admin_connection,
				1,
				amqp_cstring_bytes(my_exchange),
				amqp_cstring_bytes("topic"),
				0,
				1, /* durable */
				0,
				0,
				amqp_empty_table
		);

		my_r = amqp_get_rpc_reply (admin_connection);

		if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
		{
			fprintf(stderr,"[owner] amqp_exchange_declare failed {%s}\n",my_exchange);
			goto done;
		}

		debug_printf("[owner] done creating exchange {%s}\n",my_exchange);

		// create notification queue
		snprintf(my_queue,MAX_LEN_RESOURCE_ID + 1,"%s.notification",id);
		debug_printf("[owner] creating queue {%s}\n",my_queue);

		amqp_queue_declare (
				admin_connection,
				1,
				amqp_cstring_bytes(my_queue),
				0,
				1, /* durable */
				0,
				0,
				lazy_queue_table
		);

		my_r = amqp_get_rpc_reply (admin_connection);

		if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
		{
			fprintf(stderr,"[owner] amqp_queue_declare failed {%s}\n",my_queue);
			goto done;
		}

		debug_printf("done creating queue {%s}\n",my_queue);

		amqp_queue_bind (
			admin_connection,
			1,
			amqp_cstring_bytes(my_queue),
			amqp_cstring_bytes(my_exchange),
			amqp_cstring_bytes("#"),
			amqp_empty_table
		);

		my_r = amqp_get_rpc_reply (admin_connection);

		if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
		{
			fprintf(stderr,"bind failed for {%s} -> {%s}\n",my_queue,my_exchange);
			goto done;
		}

		debug_printf("bound queue {%s} to exchange {%s}\n",my_queue,my_exchange);

		amqp_queue_bind (
			admin_connection,
			1,
			amqp_cstring_bytes("DATABASE"),
			amqp_cstring_bytes(my_exchange),
			amqp_cstring_bytes("#"),
			amqp_empty_table
		);

		my_r = amqp_get_rpc_reply (admin_connection);

		if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
		{
			fprintf(stderr,"failed to bind {%s} to DATABASE queue for\n",my_exchange);
			goto done;
		}
		debug_printf("bound queue {%s} to exchange {%s}\n",my_queue,"DATABASE");
	}
	else
	{
		for (i = 0; _e[i]; ++i)
		{
			snprintf(my_exchange,MAX_LEN_RESOURCE_ID + 1,"%s%s",id,_e[i]);

			debug_printf("[entity] creating exchange {%s}\n",my_exchange);

			amqp_exchange_declare (
					admin_connection,
					1,
					amqp_cstring_bytes(my_exchange),
					amqp_cstring_bytes("topic"),
					0,
					1, /* durable */
					0,
					0,
					amqp_empty_table
			);

			my_r = amqp_get_rpc_reply (admin_connection);

			if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
			{
				fprintf(stderr,"something went wrong with exchange creation {%s}\n",my_exchange);
				goto done;
			}
			debug_printf("[entity] DONE creating exchange {%s}\n",my_exchange);

			amqp_queue_bind (
				admin_connection,
				1,
				amqp_cstring_bytes("DATABASE"),
				amqp_cstring_bytes(my_exchange),
				amqp_cstring_bytes("#"),
				amqp_empty_table
			);

			my_r = amqp_get_rpc_reply (admin_connection);

			if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
			{
				fprintf(stderr,"failed to bind {%s} to DATABASE queue for\n",my_exchange);
				goto done;
			}
		}

		for (i = 0; _q[i]; ++i)
		{
			snprintf(my_queue,MAX_LEN_RESOURCE_ID + 1,"%s%s",id,_q[i]);

			debug_printf("[entity] creating queue {%s}\n",my_queue);

			amqp_queue_declare (
				admin_connection,
				1,
				amqp_cstring_bytes(my_queue),
				0,
				1, /* durable */
				0,
				0,
				lazy_queue_table
			);

			my_r = amqp_get_rpc_reply (admin_connection);

			if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
			{
				fprintf(stderr,"[entity] amqp_queue_declare failed {%s}\n",my_queue);
				goto done;
			}
			debug_printf("[entity] DONE creating queue {%s}\n",my_queue);

			// bind .private and .notification 
			if (strcmp(_q[i],".private") == 0 || strcmp(_q[i],".notification") == 0)
			{
				snprintf(my_exchange,MAX_LEN_RESOURCE_ID + 1,"%s%s",id,_q[i]);
				debug_printf("[entity] binding {%s} -> {%s}\n",my_queue,my_exchange);

				amqp_queue_bind (
					admin_connection,
					1,
					amqp_cstring_bytes(my_queue),
					amqp_cstring_bytes(my_exchange),
					amqp_cstring_bytes("#"),
					amqp_empty_table
				);

				my_r = amqp_get_rpc_reply (admin_connection);

				if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
				{
					fprintf(stderr,"failed to bind {%s} to {%s}\n",my_queue,my_exchange);
					goto done;
				}
			}
		}
	}

	is_success = true;

done:
	if (! is_success)
		init_admin_connection(); 

	return &is_success;
}

void *
delete_exchanges_and_queues (void *v)
{
	int i;

	const char *id = (const char *)v;

	// local variables
	char my_queue	[MAX_LEN_RESOURCE_ID + 1];
	char my_exchange[MAX_LEN_RESOURCE_ID + 1];

	amqp_rpc_reply_t my_r;

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// delete notification exchange 
		snprintf(my_exchange,MAX_LEN_RESOURCE_ID + 1,"%s.notification",id);

		debug_printf("[owner] deleting exchange {%s}\n",my_exchange);

		if (! amqp_exchange_delete (
			admin_connection,
			1,
			amqp_cstring_bytes(my_exchange),
			0
		))
		{
			my_r = amqp_get_rpc_reply (admin_connection);

			if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
			{
				fprintf(stderr,"amqp_exchange_delete failed {%s}\n",my_exchange);
				goto done;
			}
		}

		debug_printf("[owner] done deleting exchange {%s}\n",my_exchange);

		// delete notification queue
		snprintf(my_queue,MAX_LEN_RESOURCE_ID + 1,"%s.notification",id);
		debug_printf("[owner] deleting queue {%s}\n",my_queue);

		if (! amqp_queue_delete (
			admin_connection,
			1,
			amqp_cstring_bytes(my_queue),
			0,
			0
		))
		{
			my_r = amqp_get_rpc_reply (admin_connection);

			if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
			{
				fprintf(stderr,"amqp_queue_delete failed {%s}\n",my_queue);
				goto done;
			}
		}

		debug_printf("[owner] DONE deleting queue {%s}\n",my_queue);
	}
	else
	{
		for (i = 0; _e[i]; ++i)
		{
			snprintf(my_exchange,MAX_LEN_RESOURCE_ID + 1,"%s%s",id,_e[i]);

			debug_printf("[entity] deleting exchange {%s}\n",my_exchange);

			if (! amqp_exchange_delete (
					admin_connection,
					1,
					amqp_cstring_bytes(my_exchange),
					0
			))
			{
				my_r = amqp_get_rpc_reply (admin_connection);

				if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
				{
					fprintf(stderr,"something went wrong with exchange deletion {%s}\n",my_exchange);
					goto done;
				}
			}

			debug_printf("[entity] DONE deleting exchange {%s}\n",my_exchange);
		}

		for (i = 0; _q[i]; ++i)
		{
			snprintf(my_queue,MAX_LEN_RESOURCE_ID + 1,"%s%s",id,_q[i]);

			debug_printf("[entity] deleting queue {%s}\n",my_queue);

			if (! amqp_queue_delete (
				admin_connection,
				1,
				amqp_cstring_bytes(my_queue),
				0,
				0
			))
			{
				my_r = amqp_get_rpc_reply (admin_connection);

				if (my_r.reply_type != AMQP_RESPONSE_NORMAL)
				{
					fprintf(stderr,"amqp_queue_delete failed {%s}\n",my_queue);
					goto done;
				}
			}

			debug_printf("[entity] DONE deleting queue {%s}\n",my_queue);
		}
	}

	is_success = true;

done:
	if (! is_success)
		init_admin_connection(); 

	return &is_success;
}

bool
is_string_safe (const char *string)
{
	size_t len = 0;

	// string should not be NULL. let it crash if it is 
	const char *p = string;

	// assumption is that 'string' is in single quotes

	while (*p)
	{
		if (! isalnum (*p))
		{
			switch (*p)
			{
				/* allow these chars */
				case '-':
				case '/':
				case '.':
				case '*':
				case '#':
					break;

				default:
					return false;	
			}
		}

		++p;
		++len;

		// string is too long
		if (len > 256)
			return false;
	}

	return true;
}

void
json_sanitize (const char *string)
{
	char *p = (char *)string;

	while (*p)
	{
		if (*p == '\'' || *p == '\\')
		{
			*p = '\0';
			return;
		}

		++p;
	}

	return;
}

bool
is_request_from_localhost (struct http_request *req)
{
	if (allow_admin_apis_from_other_hosts)
		return true;

	switch (req->owner->family)
	{
		case AF_INET:
			if (req->owner->addr.ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
				return true;
			break;

		case AF_INET6:
			return false;
			break;
	}

	return false;
}

void
string_to_lower (const char *str)
{
	char *p = (char *)str;

	while (*p)
	{
		if (*p >= 'A' && *p <= 'Z')
			*p += 32; 

		++p;
	}
}

/////////////////////////////////////////////////////////////////////////////
//////////////////////////// ASYNC RELATED FUNCTIONS ////////////////////////
//////////////////////////// ... not yet tested ... /////////////////////////
/////////////////////////////////////////////////////////////////////////////

bool
async_login_success (const char *id, const char *apikey, bool *is_autonomous)
{
#if 0
	char *salt;
	char *password_hash;
	char *str_is_autonomous;

	bool login_result = false;

	if (id == NULL || apikey == NULL || *id == '\0' || *apikey == '\0')
		goto done;

	if (id[0] < 'a' || id[0] > 'z')
		goto done;	

	if (! is_string_safe(id))
		goto done;

	CREATE_STRING (async_query,
		"SELECT salt,password_hash,is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				id
	);

	debug_printf("async login query = {%s}\n",async_query->data);

	kore_pgsql_cleanup(&async_sql);
	kore_pgsql_init(&async_sql);
	if (! kore_pgsql_setup(&async_sql,"db",KORE_PGSQL_SYNC))
	{
		kore_pgsql_logerror(&async_sql);
		goto done;
	}
	if (! kore_pgsql_query(&async_sql,(const char *)async_query->data))
	{
		kore_pgsql_logerror(&async_sql);
		goto done;
	}

	if (kore_pgsql_ntuples(&async_sql) == 0)
		goto done;

	salt 	 		= kore_pgsql_getvalue(&async_sql,0,0);
	password_hash		= kore_pgsql_getvalue(&async_sql,0,1);
	str_is_autonomous 	= kore_pgsql_getvalue(&async_sql,0,2);

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
		login_result = true;
		debug_printf("Login OK\n");
	}

done:
	kore_buf_reset(async_query);
	kore_pgsql_cleanup(&async_sql);

	return login_result;
#endif

	return false;
}

void*
async_publish_function (void *v)
{
	// XXX: this api is not tested and must not be used

	return NULL;
#if 0

	Q *q = (Q *)v;

	publish_async_data_t *data = NULL; 

	node *n = NULL;
	char key [MAX_LEN_HASH_KEY + 1];

	const char *id;
	const char *apikey;
	const char *subject;
	const char *message;
	const char *content_type;

	char *async_exchange;

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

			snprintf (key, MAX_LEN_HASH_KEY + 1, "%s%s", id, apikey);

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

				if (amqp_socket_open(socket, "broker" , 5672))
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

			if ( AMQP_STATUS_OK != amqp_basic_publish (
					*async_cached_conn,
					1,
					amqp_cstring_bytes(async_exchange),
        				amqp_cstring_bytes(subject),
					0,
					0,
					&async_props,
					amqp_cstring_bytes(message)
				)
			)
				goto done;

done:
			free (data);
		}

		sleep (1);
	}
#endif
}

int
publish_async (struct http_request *req)
{
#if 0
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

	if (q_insert (&async_q[async_queue_index], data) < 0)
		ERROR("inserting into queue failed");

	async_queue_index = (async_queue_index + 1) % MAX_ASYNC_THREADS;

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

#endif

	OK();
done:
	END();
}
