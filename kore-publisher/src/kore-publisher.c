#include "kore-publisher.h"
#include "assets.h"

static const char password_chars[] = 
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789"
	"-";

// variables for exchanges and queues
static const char *_e[] = {
	".public",
	".private",
	".publish",
	".protected",
	".diagnostics",
	".notification",
	NULL
};

static const char *_q[] = {
	"\0",
	".private",
	".priority",
	".command",
	".notification",
	NULL
};

static const char *_invalid_owner_names [] = {
	"admin",
	"guest",
	"amq",
	"amqp",
	"mqtt",
	"database",
	"validator",
	NULL
};

struct kore_pgsql sql;

char queue	[1 + MAX_LEN_RESOURCE_ID];
char exchange	[1 + MAX_LEN_RESOURCE_ID];

struct kore_buf *query 		= NULL;
struct kore_buf *response 	= NULL;

char 	string_to_be_hashed	[1 + MAX_LEN_HASH_INPUT];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[1 + 2*SHA256_DIGEST_LENGTH];

ht connection_ht;

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
		fprintf(stderr,"broker:login_reply -> invalid id or apikey\n");
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

//////////////////// Async initialization //////////

	async_init (connection_str);

////////////////////////////////////////////////////

	printf("===> Worker [%d]'s initialization OK\n",worker->id);

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
			1 + MAX_LEN_HASH_INPUT,
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
		printf("[%d] Error in query {%s}\n",__LINE__,query->data);
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
			1 + MAX_LEN_HASH_INPUT,
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

	char subject_to_publish [1 + MAX_LEN_TOPIC];

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "to", &to)
				||
		! http_request_header(req, "subject", &subject)
				||
		! http_request_header(req, "message-type", &message_type)
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

		snprintf (
			exchange,
			1 + MAX_LEN_RESOURCE_ID,
			"%s.%s",
				id,
				message_type
		);

		strlcpy(subject_to_publish,subject,MAX_LEN_TOPIC);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",subject_to_publish);
	}
	else
	{
		if (strcmp(message_type,"command") != 0)
			BAD_REQUEST("message-type can only be command");

		snprintf (
			subject_to_publish,
			1 + MAX_LEN_TOPIC,
			"%s.%s.%s",
				to,
				message_type,
				subject
		);

		snprintf(exchange, 1 + MAX_LEN_RESOURCE_ID,"%s.publish",id);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",subject_to_publish);
	}

	if (! http_request_header(req, "message", &message))
	{
		if (req->http_body == NULL)
			BAD_REQUEST("no message found in request");

		if (req->http_body_length > MAX_LEN_SAFE_JSON)
			BAD_REQUEST("message too long");
			
		if ((message = (char *)req->http_body->data) == NULL)
			BAD_REQUEST("no message found in request");
	}

	// get content-type and set in props
	if (! http_request_header(req,"content-type",&content_type))
	{
		content_type = "";
	}

	node *n = NULL;
	amqp_connection_state_t	*cached_conn = NULL;

	char key [1 + MAX_LEN_HASH_KEY];
	snprintf (key, 1 + MAX_LEN_HASH_KEY, "%s%s", id, apikey);

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
			ERROR("did not receive expected response from broker");

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
			amqp_cstring_bytes(subject_to_publish),
			1, /* mandatory */
			0,
			&props,
			amqp_cstring_bytes(message)
		),

		"[publish] broker refused to publish message"
	);

	OK_202();

done:
	if (req->status == 500 && cached_conn)
	{
		amqp_channel_close	(*cached_conn, 1, AMQP_REPLY_SUCCESS);
		amqp_connection_close	(*cached_conn,    AMQP_REPLY_SUCCESS);
		amqp_destroy_connection	(*cached_conn);
	
		ht_delete(&connection_ht,key);
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

	http_populate_get(req);

	BAD_REQUEST_if
	(
		(
			! http_request_header		(req, "id", &id)
				&&
			! http_argument_get_string 	(req, "id", &id)
		)
				||
		(
			! http_request_header		(req, "apikey", &apikey)
				&&
			! http_argument_get_string 	(req, "apikey", &apikey)
		)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_entity(id))
		BAD_REQUEST("id is not a valid entity");

	strlcpy(queue,id,128);

	if (http_request_header(req, "message-type", &message_type))
	{
		if (strcmp(message_type,"private") == 0)
		{
			strlcat(queue,".private",128);
		}
		else if (strcmp(message_type,"priority") == 0)
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
	if (http_request_header(req, "num-messages", &num_messages))
	{
		int_num_messages = strtonum(num_messages,1,100,NULL);

		if (int_num_messages <= 0)
			BAD_REQUEST("num-messages is not valid");
	}

	node *n = NULL;
	amqp_connection_state_t	*cached_conn = NULL;

	char key [1 + MAX_LEN_HASH_KEY];
	snprintf (key, 1 + MAX_LEN_HASH_KEY, "%s%s", id, apikey);

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
			kore_buf_append (
				response,
				message.properties.user_id.bytes,
				message.properties.user_id.len
			);

		kore_buf_append(response,"\",\"from\":\"",10);
		if(header->exchange.len > 0)
			kore_buf_append (
				response,header->exchange.bytes,
				header->exchange.len
			);

		kore_buf_append(response,"\",\"subject\":\"",13);
		if (header->routing_key.len > 0)
			kore_buf_append (
				response,
				header->routing_key.bytes,
				header->routing_key.len
			);

		bool is_json = false;

		kore_buf_append(response,"\",\"content-type\":\"",18);
		if (message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG)
		{
			kore_buf_append (
				response,
				message.properties.content_type.bytes,
				message.properties.content_type.len
			);

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

	kore_buf_append(response,"]\n",2);

	OK();

done:
	if (req->status == 500 && cached_conn)
	{
		amqp_channel_close	(*cached_conn, 1, AMQP_REPLY_SUCCESS);
		amqp_connection_close	(*cached_conn,    AMQP_REPLY_SUCCESS);
		amqp_destroy_connection	(*cached_conn);

		ht_delete(&connection_ht,key);
	}

	END();
}

int
reset_apikey (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *reset_api_key_for;

	char salt		[1 + MAX_LEN_APIKEY];
	char new_apikey		[1 + MAX_LEN_APIKEY];
	char password_hash	[1 + 2*SHA256_DIGEST_LENGTH];

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid");

	// either "id" should be owner of the "entity", or an "admin" 
	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");

		if (! http_request_header(req, "owner", &reset_api_key_for))
			BAD_REQUEST("owner field missing in header");

		if (! is_string_safe(reset_api_key_for))
			BAD_REQUEST("invalid owner");

		if (! looks_like_a_valid_owner(reset_api_key_for))
			BAD_REQUEST("owner is not valid");
	}
	else
	{
		if (! http_request_header(req, "entity", &reset_api_key_for))
			BAD_REQUEST("entity field missing in header");

		if (! is_owner(id,reset_api_key_for))
			FORBIDDEN("you are not the owner of the entity");

		if (! is_string_safe(reset_api_key_for))
			BAD_REQUEST("invalid entity");

		if (! looks_like_a_valid_entity(reset_api_key_for))
			BAD_REQUEST("entity is not valid");
	}

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT 1 FROM users WHERE id='%s'",
				reset_api_key_for	
	);

	RUN_QUERY(query, "could not query the owner/entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid owner/entity");

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "entity", &entity)
				||
		! http_request_header(req, "is-autonomous", &str_is_autonomous)
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
		BAD_REQUEST("id is not valid");

	if (! is_string_safe(entity))
		BAD_REQUEST("invalid entity");

	if (! looks_like_a_valid_entity(entity))
		BAD_REQUEST("entity is not valid");

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

	CREATE_STRING(query,
			"SELECT 1 FROM users WHERE id='%s'",
				entity	
	);

	RUN_QUERY(query, "could not query the entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid entity");

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

	char entity_name 	[1 + MAX_LEN_ENTITY_ID];

	char salt		[1 + MAX_LEN_APIKEY];
	char entity_apikey	[1 + MAX_LEN_APIKEY];
	char password_hash	[1 + 2*SHA256_DIGEST_LENGTH];

	pthread_t thread;
	bool thread_started = false; 

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "entity", &entity)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	// deny if the user is not a owner
	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid");

	// deny if the user is admin 
	if (strcmp(id,"admin") == 0)
		FORBIDDEN("admin cannot create entities");

	// entity at the time of registration is simple alapha numeric
	if (! is_alpha_numeric(entity))
		BAD_REQUEST("entity is not valid");

	char *body = req->http_body ? (char *)req->http_body->data : NULL;

	if (req->http_body_length > MAX_LEN_SAFE_JSON)
		BAD_REQUEST("schema too long");
	
	bool is_autonomous = false;
	if (http_request_header(req, "is-autonomous", &char_is_autonomous))
	{
		is_autonomous = (0 == strcmp(char_is_autonomous,"true"));
	}

/////////////////////////////////////////////////

	string_to_lower(entity);

	if (! is_string_safe(entity))
		BAD_REQUEST("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	if (body)
	{
		if (! is_json_safe(body))
			BAD_REQUEST("bad json input");
	}
	else
		body = "{}";

/////////////////////////////////////////////////

	snprintf(entity_name, 1 + MAX_LEN_ENTITY_ID,"%s/%s",id,entity);

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
		printf("[%d] Error in query {%s}\n",__LINE__,query->data);
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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	// deny if the user is not a owner
	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid");

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
	kore_buf_append(response,"{",1);

	for (i = 0; i < num_rows; ++i)
	{
		char *entity 		= kore_pgsql_getvalue(&sql,i,0);
		char *is_blocked	= kore_pgsql_getvalue(&sql,i,1);
		char *is_autonomous 	= kore_pgsql_getvalue(&sql,i,2);

		kore_buf_appendf (
				response,
				"\"%s\":[%s,%s],",
					entity,
					is_blocked	[0] == 't' ? "1" : "0",
					is_autonomous	[0] == 't' ? "1" : "0"
		);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"}\n",2);

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "entity", &entity)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	// deny if the id does not look like an owner
	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not an owner");

	// deny if the user is admin 
	if (strcmp(id,"admin") == 0)
		FORBIDDEN("admin cannot create entities");

	if (! is_string_safe(entity))
		BAD_REQUEST("invalid entity");

	if (! looks_like_a_valid_entity(entity))
		BAD_REQUEST("entity is not valid");

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

	int num_rows = kore_pgsql_ntuples(&sql);

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

	/* if the entity did NOT exist, return BAD_REQUEST after we have
		deleted all of its resources  */

	if (num_rows != 1)
		BAD_REQUEST("invalid entity");

	END();
}

int
catalog (struct http_request *req)
{
	int i, num_rows;

	const char *id;
	const char *apikey;

	req->status = 403;

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	if (
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! login_success (id,apikey,NULL)
	)
	{
		CREATE_STRING (query,
			"SELECT id,schema FROM users WHERE id LIKE '%%/%%' ORDER BY id "
			"LIMIT 50"
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT id,schema FROM users WHERE id LIKE '%%/%%' ORDER BY id"
		);
	}

	RUN_QUERY (query,"unable to query catalog data");

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *entity_id	= kore_pgsql_getvalue(&sql,i,0);
		char *schema 	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf(response,"\"%s\":%s,",entity_id,schema);
	} 

	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"}\n",2);

	OK();

done:
	END();
}

int
search_catalog (struct http_request *req)
{
	int i, num_rows;

	const char *tag;
	const char *entity;

	const char *key;
	const char *value;

	const char *body = req->http_body ? (char *)req->http_body->data : NULL;

	req->status = 403;

	http_populate_get(req);

	if (req->http_body_length > MAX_LEN_SAFE_JSON)
		BAD_REQUEST("body too long");

	if (http_argument_get_string(req,"id",(void *)&entity))
	{
		if (! looks_like_a_valid_entity(entity))
			BAD_REQUEST("id is not a valid entity");

		if (! is_string_safe(entity))
			BAD_REQUEST("invalid entity");

		CREATE_STRING (query,
				"SELECT id,schema FROM users WHERE id='%s'",
					entity
		);

		RUN_QUERY (query,"unable to query catalog data");
	}
	else if (http_argument_get_string(req,"tag",(void *)&tag))
	{
		if (! is_string_safe(tag))	
			BAD_REQUEST("invalid tag");

		CREATE_STRING (query,
				"SELECT id,schema FROM users WHERE id LIKE '%%/%%' "
				"AND jsonb_typeof(schema->'tags') = 'array' " 
				"AND ("
					"(schema->'tags' ? LOWER('%s'))"
						" OR "
					"(schema->'tags' ? '%s')"
				") "
				"ORDER BY id",
					tag, 
					tag 
		);

		RUN_QUERY (query,"unable to query catalog data");
	}
	else if (http_argument_get_string(req,"key",(void *)&key))
	{
		if (! http_argument_get_string(req,"value",(void *)&value))
			BAD_REQUEST("value field missing");
			
		if (! is_string_safe(key))	
			BAD_REQUEST("invalid key");

		if (! is_string_safe(value))	
			BAD_REQUEST("invalid value");

		// convert . to ,
		char *p = key;
		while (*p)
		{
			if (*p == '.')
				*p = ',';
			++p;
		}

		// remove all starting and trailing double quotes and remove spaces
		CREATE_STRING (query,
				"SELECT id,schema FROM users WHERE id LIKE '%%/%%' "
				"AND TRIM(RTRIM(LTRIM((schema #> '{%s}')::TEXT,'\"'),'\"')) = '%s' " 
				"ORDER BY id",
					key,
					value
		);

		RUN_QUERY (query,"unable to query catalog data");
	}
	else if (body)
	{
		if (! is_json_safe(body))
			BAD_REQUEST("bad json input");

		CREATE_STRING (query,
			"SELECT id,schema FROM users WHERE schema @> '$1'::jsonb"
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
			printf("[%d] Error in query {%s}\n",__LINE__,query->data);
			kore_pgsql_logerror(&sql);
			ERROR("failed to query catalog schema using body");
		}
	}
	else
	{
		BAD_REQUEST("inputs for the API are missing");
	}

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	num_rows = kore_pgsql_ntuples(&sql);

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

	kore_buf_append(response,"}\n",2);

	OK();

done:
	END();
}

int
catalog_tags (struct http_request *req)
{
	int i, num_rows;

	req->status = 403;

	kore_buf_reset(response);
	kore_buf_append(response,"{",1);

	CREATE_STRING (query,

		// 1. remove () from (tag),
		// 2. remove front and end spaces
		// 3. limit tag length to 30
		// 4. ignore the ones with double quotes in tags 

		"SELECT RTRIM(LTRIM(tag::TEXT,'('),')') as final_tag,"
		"COUNT(tag) as tag_count FROM ("
			"SELECT SUBSTRING(TRIM(LOWER(jsonb_array_elements_text(schema->'tags')::TEXT)) for 30) "
			"FROM users WHERE jsonb_typeof(schema->'tags') = 'array'"
		") AS tag WHERE tag::TEXT NOT LIKE '%%\"%%' group by final_tag order by tag_count DESC"
	);

	RUN_QUERY (query,"could not query catalog");

	num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *tag 	= kore_pgsql_getvalue(&sql,i,0);
		char *count 	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_appendf(response,"\"%s\":%s,",tag,count);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"}\n",2);

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

	char salt		[1 + MAX_LEN_APIKEY];
	char owner_apikey	[1 + MAX_LEN_APIKEY];
	char password_hash	[1 + 2*SHA256_DIGEST_LENGTH];

	pthread_t thread;
	bool thread_started = false;

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this API can only be called from localhost");

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "owner", &owner)
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
			BAD_REQUEST("cannot create owner");
	}


	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("invalid owner");

	if (! is_string_safe(owner))
		BAD_REQUEST("invalid owner");

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
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

	kore_buf_append(response,"}\n",2);

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "owner", &owner)
			,
		"inputs missing in headers"
	);

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this API");

	for (i = 0; _invalid_owner_names[i]; ++i)
	{
		if (strcmp(owner,_invalid_owner_names[i]) == 0)
			BAD_REQUEST("cannot delete owner");
	}

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("invalid owner");

/////////////////////////////////////////////////

	if (! is_string_safe(owner))
		BAD_REQUEST("invalid owner");

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "to", &to)
				||
		! http_request_header(req, "topic", &topic)
				||
		! http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	debug_printf("id = %s\n, apikey = %s\n, to =%s\n, topic = %s\n, "
			"message-type = %s\n",
				id, apikey, to, topic, message_type);

	if (looks_like_a_valid_owner(id))
	{
		if (! http_request_header(req, "from", &from))
			BAD_REQUEST("'from' value missing in header");

		if (! looks_like_a_valid_entity(from))
			BAD_REQUEST("'from' is not a valid entity");

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
		BAD_REQUEST("'to' is not a valid entity");

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

	snprintf (exchange, 1 + MAX_LEN_RESOURCE_ID,"%s.%s", to,message_type); 

/////////////////////////////////////////////////

	if (! is_string_safe(from))
		BAD_REQUEST("invalid from");

	if (! is_string_safe(to))
		BAD_REQUEST("invalid to");

	if (! is_string_safe(topic))
		BAD_REQUEST("invalid topic");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	strlcpy(queue,from,128);
	if (http_request_header(req, "is-priority", &is_priority))
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
				"AND valid_till > NOW() AND topic = '%s'",
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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "to", &to)
				||
		! http_request_header(req, "topic", &topic)
				||
		! http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	if (looks_like_a_valid_owner(id))
	{
		if (! http_request_header(req, "from", &from))
			BAD_REQUEST("'from' value missing in header");

		if (! looks_like_a_valid_entity(from))
			BAD_REQUEST("'from' is not a valid entity");

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
		BAD_REQUEST("'to' is not a valid entity");

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

/////////////////////////////////////////////////

	if (! is_string_safe(from))
		BAD_REQUEST("invalid from");

	if (! is_string_safe(to))
		BAD_REQUEST("invalid to");

	if (! is_string_safe(topic))
		BAD_REQUEST("invalid topic");

	bool is_autonomous = false;

	if (! login_success(id,apikey, &is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	snprintf(exchange, 1 + MAX_LEN_RESOURCE_ID,"%s.%s", to,message_type); 
	strlcpy	(queue,from,MAX_LEN_RESOURCE_ID);

	if (http_request_header(req, "is-priority", &is_priority))
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
			    "AND valid_till > NOW() "
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

	const char *topic; // topics the subscriber is interested in

	const char *validity; // in hours 

	const char *message_type;

	char *status = "pending";

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "to", &to)
				||
		! http_request_header(req, "validity", &validity)
				||
		! http_request_header(req, "topic", &topic)
				||
		! http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	BAD_REQUEST_if (
		(strcmp(message_type,"command") 	!= 0) &&
		(strcmp(message_type,"protected") 	!= 0) &&
		(strcmp(message_type,"diagnostics") 	!= 0)
		,
		"invalid message-type"
	);

	if (looks_like_a_valid_owner(id))
	{
		if (! http_request_header(req, "from", &from))
			BAD_REQUEST("'from' value missing in header");

		if (! looks_like_a_valid_entity(from))
			BAD_REQUEST("'from' is not a valid entity");

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
		BAD_REQUEST("'to' is not a valid entity");

	if (! is_string_safe(from))
		BAD_REQUEST("invalid from");

	if (! is_string_safe(to))
		BAD_REQUEST("invalid to");

	if (! is_string_safe(validity))
		BAD_REQUEST("invalid validity");

	if (! is_string_safe(topic))
		BAD_REQUEST("invalid topic");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	// if both from and to are owned by id
	if (is_owner(id,to))
		status = "approved";

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
		BAD_REQUEST("'to' does not exist OR has been blocked");

	char *char_is_to_autonomous	= kore_pgsql_getvalue(&sql,0,0);
	bool is_to_autonomous		= char_is_to_autonomous[0] == 't';

	CREATE_STRING (query, 
		"INSERT INTO follow "
		"(follow_id,requested_by,from_id,exchange,time,topic,validity,status) "
		"VALUES(DEFAULT,'%s','%s','%s.%s',NOW(),'%s','%d','%s')",
			id,
			from,
			to,
			message_type,
			topic,
			int_validity,
			status
	);

	RUN_QUERY (query, "failed to insert follow");

	CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
	RUN_QUERY 	(query,"failed pg_get_serial");

	const char *follow_id = kore_pgsql_getvalue(&sql,0,0);

	if (strcmp(status,"approved") == 0)
	{
		// add entry in acl
		CREATE_STRING (query,
			"INSERT INTO acl "
			"(acl_id,from_id,exchange,follow_id,topic,valid_till) "
			"VALUES(DEFAULT,'%s','%s.%s','%s','%s',NOW() + interval '%d hours')",
		        	from,
				to,
				message_type,
				follow_id,
				topic,
				int_validity
		);

		RUN_QUERY (query,"could not run insert query on acl");

		if (strcmp(message_type,"command") == 0)
		{
			char write_exchange 	[1 + MAX_LEN_RESOURCE_ID];
			char write_queue	[1 + MAX_LEN_RESOURCE_ID];
			char write_topic	[1 + MAX_LEN_TOPIC];

			snprintf(write_exchange,1 + MAX_LEN_RESOURCE_ID,"%s.publish",from);
			snprintf(write_queue, 	1 + MAX_LEN_RESOURCE_ID,"%s.%s",to,message_type);
			snprintf(write_topic,   1 + MAX_LEN_TOPIC,	"%s.%s.%s",to,message_type,topic);

			for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
			{
				amqp_queue_bind (
					admin_connection,
					1,
					amqp_cstring_bytes(write_queue),
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
				snprintf(error_string,1025,"bind failed e={%s} q={%s} t={%s}\n",write_exchange, write_queue, write_topic);
				ERROR(error_string);
			}

		}

		req->status = 200;
	}
	else
	{
		if (is_to_autonomous)
			snprintf (exchange, 1 + MAX_LEN_RESOURCE_ID, "%s.notification",to);
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
		snprintf(message,  1025, "'%s' has requested access to '%s'",id,to);

		props.user_id 		= amqp_cstring_bytes("admin");
		props.content_type 	= amqp_cstring_bytes("text/plain");

		ERROR_if
		(
			AMQP_STATUS_OK != amqp_basic_publish (
				admin_connection,
				1,
				amqp_cstring_bytes(exchange),
				amqp_cstring_bytes(subject),
				1, /* mandatory */
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
	kore_buf_appendf(response,"{\"follow-id\":\"%s\"}\n",follow_id);

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

	const char *follow_id;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "follow-id", &follow_id)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (! is_string_safe(follow_id))
		BAD_REQUEST("invalid follow-id");

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
			"from_id,exchange,topic "
			"FROM follow "
			"WHERE follow_id = '%s' AND from_id LIKE '%s/%%' "
			"ORDER BY time DESC",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"from_id,exchange,topic "
			"FROM follow "
			"WHERE follow_id = '%s' AND from_id = '%s' "
			"ORDER BY time DESC",
				follow_id,
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	if (num_rows != 1)
		FORBIDDEN("unauthorized");

	char *from_id 		= kore_pgsql_getvalue(&sql,0,0);
	char *my_exchange	= kore_pgsql_getvalue(&sql,0,1);
	char *topic		= kore_pgsql_getvalue(&sql,0,2);

	CREATE_STRING (query,
				"SELECT 1 FROM acl "
				"WHERE follow_id = '%s' ",
					follow_id
	);

	RUN_QUERY(query,"failed to query acl table for permission");

	if (kore_pgsql_ntuples(&sql) != 1)
		FORBIDDEN("unauthorized");

	if (
		str_ends_with(my_exchange,".protected") == 0 	|| 
		str_ends_with(my_exchange,".diagnostics") == 0	||
		str_ends_with(my_exchange,".notification") == 0
	)
	{
		for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
		{
			amqp_queue_unbind (
				admin_connection,
				1,
				amqp_cstring_bytes(from_id),
				amqp_cstring_bytes(my_exchange),
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
			snprintf(error_string,1025,"unbind failed e={%s} q={%s} t={%s}\n",my_exchange,from_id,topic);
			ERROR(error_string);
		}

		char priority_queue [1 + MAX_LEN_RESOURCE_ID];
		snprintf(priority_queue,1 + MAX_LEN_RESOURCE_ID,"%s.priority", from_id);

		for (tries = 1; tries <= MAX_AMQP_RETRIES ; ++tries)
		{
			amqp_queue_unbind (
				admin_connection,
				1,
				amqp_cstring_bytes(priority_queue),
				amqp_cstring_bytes(my_exchange),
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
			snprintf(error_string,1025,"unbind priority failed e={%s} q={%s} t={%s}\n",my_exchange,priority_queue,topic);
			ERROR(error_string);
		}
	}
	else // command
	{
		char write_exchange 	[1 + MAX_LEN_RESOURCE_ID];
		char *write_queue 	= my_exchange;
		char write_topic	[1 + MAX_LEN_TOPIC];

		snprintf(write_exchange,1 + MAX_LEN_RESOURCE_ID,"%s.publish",from_id);
		snprintf(write_topic,	1 + MAX_LEN_TOPIC,	"%s.%s",my_exchange,topic);

		for (tries = 1; tries <= MAX_AMQP_RETRIES; ++tries)
		{
			amqp_queue_unbind (
				admin_connection,
				1,
				amqp_cstring_bytes(write_queue),
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
			snprintf(error_string,1025,"unbind failed e={%s} q={%s} t={%s}\n",write_exchange,write_queue,write_topic);
			ERROR(error_string);
		}
	}

	CREATE_STRING 	(query, "DELETE FROM follow WHERE follow_id='%s'", follow_id);
	RUN_QUERY	(query, "failed to delete from follow table");
		
	CREATE_STRING 	(query, "DELETE FROM acl WHERE follow_id='%s'", follow_id);
	RUN_QUERY	(query, "failed to delete from acl table");

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "follow-id", &follow_id)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	if (! is_string_safe(follow_id))
		BAD_REQUEST("invalid follow-id");

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query, 
			"SELECT from_id,exchange,validity,topic FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' and status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id,exchange,validity,topic FROM follow "
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
	char *validity_hours 	= kore_pgsql_getvalue(&sql,0,2);
	char *topic 	 	= kore_pgsql_getvalue(&sql,0,3); 

	CREATE_STRING (query,
		"SELECT is_autonomous FROM users "
			"WHERE id='%s' AND blocked='f'",
				from_id	
	);

	RUN_QUERY (query,"could not get info about 'from'");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("'from' does not exist OR has been blocked");

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
		"INSERT INTO acl (acl_id,from_id,exchange,follow_id,topic,valid_till) "
		"VALUES(DEFAULT,'%s','%s','%s','%s',NOW() + interval '%s hours')",
			from_id,
			my_exchange,
			follow_id,
			topic,
			validity_hours
	);

	RUN_QUERY (query,"could not run insert query on acl");

	char bind_exchange	[1 + MAX_LEN_RESOURCE_ID];
	char bind_queue		[1 + MAX_LEN_RESOURCE_ID];
	char bind_topic		[1 + MAX_LEN_TOPIC];

	if (
		str_ends_with(my_exchange,".protected") == 0 	|| 
		str_ends_with(my_exchange,".diagnostics") == 0	||
		str_ends_with(my_exchange,".notification") == 0
	)
	{
		snprintf(bind_exchange,	1 + MAX_LEN_RESOURCE_ID,"%s",	my_exchange);
		/*
		snprintf(bind_queue,	1 + MAX_LEN_RESOURCE_ID,"%s",	from_id); 		// TODO: what about priority queue
		snprintf(bind_topic,	1 + MAX_LEN_TOPIC,      "%s",	topic);
		*/
	}
	else
	{
		snprintf(bind_exchange,	1 + MAX_LEN_RESOURCE_ID,"%s.publish",	from_id);
		snprintf(bind_queue,	1 + MAX_LEN_RESOURCE_ID,"%s",		my_exchange);
		snprintf(bind_topic,	1 + MAX_LEN_TOPIC,      "%s.%s",	my_exchange,topic);

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

	if (is_from_autonomous)
		snprintf (exchange, 1 + MAX_LEN_RESOURCE_ID, "%s.notification",from_id);
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
	snprintf(message, 1025, "'%s' has approved follow request for access on '%s'",id,bind_exchange);

	props.user_id 		= amqp_cstring_bytes("admin");
	props.content_type 	= amqp_cstring_bytes("text/plain");

	ERROR_if
	(
		AMQP_STATUS_OK != amqp_basic_publish (
			admin_connection,
			1,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(subject),
			1, /* mandatory */
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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "follow-id", &follow_id)
		,

		"inputs missing in headers"
	);


/////////////////////////////////////////////////

	if (! is_string_safe(follow_id))
		BAD_REQUEST("invalid follow-id");

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
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
			"follow_id,requested_by,exchange,time,topic,validity,status "
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
			"follow_id,requested_by,exchange,time,topic,validity,status "
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
			kore_pgsql_getvalue(&sql,i,6)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]\n",2);

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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
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
			"follow_id,requested_by,exchange,time,topic,validity "
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
			"follow_id,requested_by,exchange,time,topic,validity "
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
			"\"topic\":\"%s\","
			"\"validity\":\"%s\"},"
			,
			kore_pgsql_getvalue(&sql,i,0),
			kore_pgsql_getvalue(&sql,i,1),
			kore_pgsql_getvalue(&sql,i,2),
			kore_pgsql_getvalue(&sql,i,3),
			kore_pgsql_getvalue(&sql,i,4),
			kore_pgsql_getvalue(&sql,i,5)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]\n",2);

	OK();

done:
	END();
}

int
block (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity_to_be_blocked;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");

	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");

		if (! http_request_header(req, "owner", &entity_to_be_blocked))
		{
			if (! http_request_header(req, "entity", &entity_to_be_blocked))
				BAD_REQUEST("owner/entity field missing in header");
		}
	}
	else
	{
		if (! http_request_header(req, "entity", &entity_to_be_blocked))
			BAD_REQUEST("entity field missing in header");

		if (! looks_like_a_valid_entity(entity_to_be_blocked))
			BAD_REQUEST("entity is not valid");

		if (! is_owner(id,entity_to_be_blocked))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (strcmp(id,entity_to_be_blocked) == 0)
		BAD_REQUEST("cannot block yourself");

	if (! is_string_safe(entity_to_be_blocked))
		BAD_REQUEST("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT 1 FROM users WHERE id='%s'",
				entity_to_be_blocked
	);

	RUN_QUERY(query, "could not query the owner/entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid owner/entity");

	CREATE_STRING(query,
			"UPDATE users set blocked='t' WHERE id='%s'",
				entity_to_be_blocked	
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
	const char *entity_to_be_unblocked;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");

	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only call APIs from localhost");

		if (! http_request_header(req, "owner", &entity_to_be_unblocked))
		{
			if (! http_request_header(req, "entity", &entity_to_be_unblocked))
				BAD_REQUEST("owner/entity field missing in header");
		}
	}
	else
	{
		if (! http_request_header(req, "entity", &entity_to_be_unblocked))
			BAD_REQUEST("entity field missing in header");

		if (! looks_like_a_valid_entity(entity_to_be_unblocked))
			BAD_REQUEST("invalid entity");

		if (! is_owner(id,entity_to_be_unblocked))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (! is_string_safe(entity_to_be_unblocked))
		BAD_REQUEST("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT 1 FROM users WHERE id='%s'",
				entity_to_be_unblocked
	);

	RUN_QUERY(query, "could not query the owner/entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid owner/entity");

	CREATE_STRING(query,
			"UPDATE users set blocked='f' WHERE id='%s'",
				entity_to_be_unblocked
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
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	)

	if (looks_like_a_valid_owner(id))
	{
		if (! http_request_header(req, "entity", &entity))
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
		BAD_REQUEST("invalid entity");

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT exchange FROM acl WHERE from_id='%s' "
			"AND valid_till > NOW()",entity
	);
	RUN_QUERY (query,"could not query acl table");

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);

	int num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
				response,
					"\"%s\",",
						kore_pgsql_getvalue(&sql,i,0)
		);
	}

	// remove the last comma
	if (num_rows > 0)
		--(response->offset);

	kore_buf_append(response,"]\n",2);

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
	char my_queue	 [1 + MAX_LEN_RESOURCE_ID];
	char my_exchange [1 + MAX_LEN_RESOURCE_ID];

	amqp_rpc_reply_t my_r;

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// create notification exchange 
		snprintf(my_exchange, 1 + MAX_LEN_RESOURCE_ID,"%s.notification",id);

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
		snprintf(my_queue, 1 + MAX_LEN_RESOURCE_ID,"%s.notification",id);
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
			snprintf(my_exchange, 1 + MAX_LEN_RESOURCE_ID,"%s%s",id,_e[i]);

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
			snprintf(my_queue, 1 + MAX_LEN_RESOURCE_ID,"%s%s",id,_q[i]);

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
			if (
				(strcmp(_q[i],".private") == 0)
					||
				(strcmp(_q[i],".notification") == 0)
			)
			{
				snprintf(my_exchange, 1 + MAX_LEN_RESOURCE_ID,"%s%s",id,_q[i]);
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
	char my_queue	 [1 + MAX_LEN_RESOURCE_ID];
	char my_exchange [1 + MAX_LEN_RESOURCE_ID];

	amqp_rpc_reply_t my_r;

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// delete notification exchange 
		snprintf(my_exchange, 1 + MAX_LEN_RESOURCE_ID,"%s.notification",id);

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
		snprintf(my_queue, 1 + MAX_LEN_RESOURCE_ID,"%s.notification",id);
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
			snprintf(my_exchange, 1 + MAX_LEN_RESOURCE_ID,"%s%s",id,_e[i]);

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
			snprintf(my_queue, 1 + MAX_LEN_RESOURCE_ID,"%s%s",id,_q[i]);

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
