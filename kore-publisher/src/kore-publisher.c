#include "kore-publisher.h"

char password_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

// variables for exchanges and queues
char *_e[] = {".public",".private",".protected",".notification",".publish",".diagnostics",NULL};
char *_q[] = {"\0", ".private", ".priority", ".command", ".notification", NULL};

struct kore_pgsql sql;

struct kore_buf *Q = NULL;
struct kore_buf *query = NULL;
struct kore_buf *response = NULL;

char 	string_to_be_hashed 	[256];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

ht connection_ht;

bool is_success = false;
char admin_apikey[33];
char postgres_pwd[33];

char broker_ip	[100];
char pgsql_ip	[100];

char error_string [100];

amqp_connection_state_t	cached_admin_conn;
amqp_table_t 		lazy_queue_table;
amqp_rpc_reply_t 	login_reply;
amqp_rpc_reply_t 	rpc_reply;
amqp_table_entry_t 	*entry;
amqp_basic_properties_t	props;

static int
hostname_to_ip(char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
     
    return 1;
}

int
init (int state)
{
	int i;

	// mask server name 
	http_server_version("");

	hostname_to_ip("broker", broker_ip);
	hostname_to_ip("postgres", pgsql_ip);

//////////////
// lazy queues
//////////////

	lazy_queue_table.num_entries = 3;
	lazy_queue_table.entries = malloc(lazy_queue_table.num_entries * sizeof(amqp_table_entry_t));

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

	int fd = open("/vars/admin.passwd",O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr,"could not open admin.passwd file\n");
		exit(-1);
	}

	if (! read(fd,admin_apikey,32))
	{
		fprintf(stderr,"could not read from admin.passwd file\n");
		exit(-1);
	}

	admin_apikey[32] = '\0';
	int strlen_admin_apikey = strlen(admin_apikey);

	for (i = 0; i < strlen_admin_apikey; ++i)
	{
		if (isspace(admin_apikey[i]))
		{
			admin_apikey[i] = '\0';
			break;
		}
	}

	(void) close (fd);

	fd = open("/vars/postgres.passwd",O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr,"could not open postgres.passwd\n");
		exit(-1);
	}

	if (! read(fd,postgres_pwd,32))
	{
		fprintf(stderr,"could not read from postgres.passwd\n");
		exit(-1);
	}

	postgres_pwd[32] = '\0';
	int strlen_postgres_pwd = strlen(postgres_pwd);

	for (i = 0; i < strlen_postgres_pwd; ++i)
	{
		if (isspace(postgres_pwd[i]))
		{
			postgres_pwd[i] = '\0';
			break;
		}
	}

	(void) close (fd);

	cached_admin_conn = amqp_new_connection();
	amqp_socket_t *socket = amqp_tcp_socket_new(cached_admin_conn);

	if (socket == NULL)
	{
		fprintf(stderr,"Could not open a socket ");
		return KORE_RESULT_ERROR;
	}

retry:
	if (amqp_socket_open(socket, broker_ip, 5672))
	{
		fprintf(stderr,"Could not connect to broker\n");
		sleep(1);
		goto retry;
	}

	login_reply = amqp_login
#ifdef TEST
		(cached_admin_conn, "/", 0, 131072, HEART_BEAT, AMQP_SASL_METHOD_PLAIN, "guest", "guest");
#else
		(cached_admin_conn, "/", 0, 131072, HEART_BEAT, AMQP_SASL_METHOD_PLAIN, "admin", admin_apikey);
#endif
	if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"invalid id or apikey\n");
		return KORE_RESULT_ERROR;
	}

	if(! amqp_channel_open(cached_admin_conn, 1))
	{
		fprintf(stderr,"could not open an AMQP connection\n");
		return KORE_RESULT_ERROR;
	}

	rpc_reply = amqp_get_rpc_reply(cached_admin_conn);
	if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"did not receive expected response from the broker\n");
		return KORE_RESULT_ERROR;
	}

	// declare the "DATABASE" queue if it does not exist
	if (! amqp_queue_declare (
		cached_admin_conn,
		1,
		amqp_cstring_bytes("DATABASE"),
		0,
		1, /* durable */
		0,
		0,
		lazy_queue_table
	))
	{
		fprintf(stderr,"amqp_queue_declare failed for {DATABASE}\n");
		return KORE_RESULT_ERROR;
	}

	ht_init (&connection_ht);

	if (Q == NULL)
		Q = kore_buf_alloc(256);

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(1024*1024);

#ifdef TEST
	kore_pgsql_register("db","user=postgres password=password");
#else
	char conn_str[129];
        snprintf(conn_str,129,"host = %s user = postgres password = %s", pgsql_ip, postgres_pwd);
	kore_pgsql_register("db",conn_str);
#endif

	memset(&props, 0, sizeof props);
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_USER_ID_FLAG ;

///// chroot and drop priv /////

	if (chroot("./jail") < 0)
		perror("chroot ");
	
	if (setgid(65534) < 0)
		perror("setgid ");

	if (setuid(65534) < 0)
		perror("setuid ");

/////////////////////////////////

	return KORE_RESULT_OK;
}

bool
is_alpha_numeric (const char *str)
{
	int i;
	uint8_t strlen_str = strlen(str);

	if (strlen_str < 3 || strlen_str > 32)
		return false;

	for (i = 0; i < strlen_str; ++i)
	{
		if (! isalnum(str[i]))
		{
			switch (str[i])
			{
				case '-':
						break;
				default:
						return false;
			}
		}
	}

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
	int strlen_id = strlen(id);

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
	int i;

	uint8_t strlen_str = strlen(str);

	uint8_t front_slash_count = 0;

	// format is owner/entity
	if (strlen_str < 3 || strlen_str > 65)
		return false;

	for (i = 0; i < strlen_str; ++i)
	{
		if (! isalnum(str[i]))
		{
			// support some extra chars
			switch (str[i])
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

		if (front_slash_count > 1)
			return false;
	}

	// there should be one front slash
	if (front_slash_count != 1)
		return false;

	return true;
}

bool
looks_like_a_valid_resource (const char *str)
{
	int i;

	uint8_t strlen_str = strlen(str);

	uint8_t front_slash_count = 0;
 
        uint8_t dot_count = 0;

	// format is owner/entity.public
	if (strlen_str < 10 || strlen_str > 128)
		return false;

	for (i = 0; i < strlen_str; ++i)
	{
		if (! isalnum(str[i]))
		{
			// support some extra chars
			switch (str[i])
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
	}

	// there should be only one front slash. Dot may or may not exist
	if ( (front_slash_count != 1) || (dot_count > 1) )
		return false;
  	   
	return true;
}

void
gen_salt_password_and_apikey (const char *entity, char *salt, char *password_hash, char *apikey)
{
	int i;

	for (i = 0; i < 32; ++i)
	{
		salt	[i] 	= password_chars[arc4random_uniform(sizeof(password_chars) - 1)]; 
		apikey	[i]  	= password_chars[arc4random_uniform(sizeof(password_chars) - 1)]; 
	}
	salt	[32] = '\0';
	apikey	[32] = '\0';

	strlcpy(string_to_be_hashed, apikey, 33);
	strlcat(string_to_be_hashed, salt,   65);
	strlcat(string_to_be_hashed, entity, 250);

	SHA256((const uint8_t*)string_to_be_hashed,strlen(string_to_be_hashed),binary_hash);

	debug_printf("gen STRING TO BE HASHED = {%s}\n",string_to_be_hashed);

	snprintf
	(
		password_hash,
		65,
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x",
		binary_hash[ 0], binary_hash[ 1], binary_hash[ 2], binary_hash[ 3],
		binary_hash[ 4], binary_hash[ 5], binary_hash[ 6], binary_hash[ 7],
		binary_hash[ 8], binary_hash[ 9], binary_hash[10], binary_hash[11],
		binary_hash[12], binary_hash[13], binary_hash[14], binary_hash[15],
		binary_hash[16], binary_hash[17], binary_hash[18], binary_hash[19],
		binary_hash[20], binary_hash[21], binary_hash[22], binary_hash[23],
		binary_hash[24], binary_hash[25], binary_hash[26], binary_hash[27],
		binary_hash[28], binary_hash[29], binary_hash[30], binary_hash[31]
	);

	password_hash [64] = '\0';
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

	sanitize(id);

	CREATE_STRING (query,
			"SELECT salt,password_hash,is_autonomous FROM users WHERE id='%s' and blocked='f'",
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

	debug_printf("strlen of salt = %d (%s)\n",strlen(salt),salt);
	debug_printf("strlen of apikey = %d (%s)\n",strlen(apikey),apikey);

	strlcpy(string_to_be_hashed, apikey, 33);
	strlcat(string_to_be_hashed, salt,   65);
	strlcat(string_to_be_hashed, id,    250);

	SHA256((const uint8_t*)string_to_be_hashed,strlen(string_to_be_hashed),binary_hash);

	debug_printf("login success STRING TO BE HASHED = {%s}\n",string_to_be_hashed);

	snprintf
	(
		hash_string,
		65,
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x"
		"%02x%02x%02x%02x",
		binary_hash[ 0], binary_hash[ 1], binary_hash[ 2], binary_hash[ 3],
		binary_hash[ 4], binary_hash[ 5], binary_hash[ 6], binary_hash[ 7],
		binary_hash[ 8], binary_hash[ 9], binary_hash[10], binary_hash[11],
		binary_hash[12], binary_hash[13], binary_hash[14], binary_hash[15],
		binary_hash[16], binary_hash[17], binary_hash[18], binary_hash[19],
		binary_hash[20], binary_hash[21], binary_hash[22], binary_hash[23],
		binary_hash[24], binary_hash[25], binary_hash[26], binary_hash[27],
		binary_hash[28], binary_hash[29], binary_hash[30], binary_hash[31]
	);

	hash_string[64] = '\0';

	debug_printf("Expecting it to be {%s} got {%s}\n",password_hash, hash_string);

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

	char exchange[129];
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

		snprintf(exchange,129,"%s.%s",to,message_type);
		strlcpy(topic_to_publish,subject,129);

		debug_printf("------------------> exchange = %s\n",exchange);
		debug_printf("------------------> topic = %s\n",topic_to_publish);
	}
	else
	{
		if (strcmp(message_type,"command") != 0)
		{
			BAD_REQUEST("message-type can only be command");		
		}

		snprintf(topic_to_publish,129,"%s.%s.%s",to,message_type,subject);
		snprintf(exchange,129,"%s.publish",id);

		debug_printf("------------------> exchange = %s\n",exchange);
		debug_printf("------------------> topic = %s\n",topic_to_publish);
	}

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if ((message = (char *)req->http_body->data) == NULL)
			BAD_REQUEST("no body found in request");
	}

	// get content-type and set in props
	if (http_request_header(req, "content-type", &content_type) != KORE_RESULT_OK)
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

		login_reply = amqp_login(*cached_conn, 
			"/", 0, 131072, HEART_BEAT, AMQP_SASL_METHOD_PLAIN, id, apikey);

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

int
subscribe (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *message_type;
	const char *num_messages;

	amqp_socket_t 			*socket = NULL;
	amqp_connection_state_t		connection;

	bool connection_opened = false;

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

	kore_buf_reset(Q);
	kore_buf_append(Q,id,strlen(id));

	if (KORE_RESULT_OK == http_request_header(req, "message-type", &message_type))
	{
		if (strcmp(message_type,"priority") == 0)
		{
			kore_buf_append (Q,".priority",sizeof(".priority") - 1);
		}
		else if (strcmp(message_type,"command") == 0)
		{
			kore_buf_append (Q,".command",sizeof(".command") - 1);
		}
		else if (strcmp(message_type,"notification") == 0)
		{
			kore_buf_append (Q,".notification",sizeof(".notification") - 1);
		}
		else
		{
			BAD_REQUEST("invalid message-type");
		}
	}

	kore_buf_append(Q,"\0",1);

	int int_num_messages = 10;
	if (KORE_RESULT_OK == http_request_header(req, "num-messages", &num_messages))
	{
		int_num_messages = strtonum(num_messages,1,100,NULL);

		if (int_num_messages <= 0)
			BAD_REQUEST("num-messages is not valid");
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////////////////

	connection 	= amqp_new_connection();
	socket		= amqp_tcp_socket_new(connection);

	connection_opened = true;

	if (socket == NULL)
		ERROR("could not create a new socket");

	if (amqp_socket_open(socket, broker_ip, 5672))
		ERROR("could not open a socket");

	login_reply = amqp_login(connection, 
			"/",
			0,
			131072,
			HEART_BEAT,
			AMQP_SASL_METHOD_PLAIN,
			id,
			apikey
	);

	if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
		FORBIDDEN("invalid id or apikey");

	if (! amqp_channel_open(connection, 1))
		ERROR("could not open an AMQP connection");

	rpc_reply = amqp_get_rpc_reply(connection);
	if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
		FORBIDDEN("did not receive expected response from the broker");

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
					connection,
					1,
					amqp_cstring_bytes((const char *)Q->data),
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
         
		amqp_read_message(connection, 1, &message, 0);

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

			if (strncmp(message.properties.content_type.bytes,"application/json", message.properties.content_type.len) == 0)
				is_json = true;
		}

		kore_buf_append(response,"\",\"body\":",9);

		if (is_json)
		{
			kore_buf_append(response,message.body.bytes, message.body.len);
		}
		else
		{
			kore_buf_append(response,"\"",1);

			char *p = message.body.bytes;

			for (int j = 0; j < message.body.len; ++j)
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
	if (connection_opened)
	{
		amqp_channel_close	(connection, 1, AMQP_REPLY_SUCCESS);
		amqp_connection_close	(connection,    AMQP_REPLY_SUCCESS);
		amqp_destroy_connection	(connection);
	}

	END();
}

int
register_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;
	const char *char_is_autonomous;

	char entity_name[66];

	char salt		[33];
	char entity_apikey	[33];
	char password_hash	[65];

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

	if (! is_alpha_numeric(entity))
		BAD_REQUEST("entity is not valid");

	char *body = (char *)req->http_body->data;

	bool is_autonomous = false;
	if (http_request_header(req, "is-autonomous", &char_is_autonomous) == KORE_RESULT_OK)
	{
		if (strcmp(char_is_autonomous,"true") == 0)
			is_autonomous = true;
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

	// TODO maybe body needs a different sanitizer
	if (body)
		sanitize(body);

/////////////////////////////////////////////////

	str_to_lower(entity);

	snprintf(entity_name,66,"%s/%s",id,entity);

	// create entries in to RabbitMQ

	if (0 == pthread_create(&thread,NULL,create_exchanges_and_queues,(const void *)entity_name)) 
		thread_started = true;
	else
		create_exchanges_and_queues((const void *)entity_name);

	// conflict if entity_name already exist

	CREATE_STRING(query,
		 	"SELECT id from users WHERE id='%s'",
				entity_name
	);

	RUN_QUERY (query,"could not get info about entity");

	if (kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity_name, salt, password_hash, entity_apikey);

	if (body)
	{
		// use parameterized query for inserting json

		CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked,is_autonomous) "
			"values('%s','%s',$1,'%s','f','%s')",	// $1 is the schema (in body) 
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
		if (! kore_pgsql_query_params (&sql,query->data,0,1,body,req->http_body_length,0))
		{
			kore_pgsql_logerror(&sql);
			ERROR("failed to create the entity with schema");
		}
	}
	else
	{
		CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked,is_autonomous) "
			"values('%s','%s','%s',NULL,'f','%s')",
			entity_name,
			password_hash,
			salt,
			is_autonomous ? "t" : "f"
		);

		RUN_QUERY (query,"failed to create the entity");
	}

	// generate response
	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity_name,strlen(entity_name));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
	kore_buf_append(response,"\"}\n",3);

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

	// deny if the id does not look like an owner
	if (! looks_like_a_valid_owner(id))
		FORBIDDEN("id is not an owner");

	if (! looks_like_a_valid_entity(entity))
		FORBIDDEN("entity is not valid");

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

/////////////////////////////////////////////////

	if (! is_owner(id,entity))
		FORBIDDEN("you are not the owner of the entity");

	// check if the entity exists
	CREATE_STRING (
		query,
		"SELECT 1 FROM users WHERE id = '%s'",
		entity
	);
	RUN_QUERY(query,"could no query entity");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("invalid entity");

	// delete entries in to RabbitMQ
	if (0 == pthread_create(&thread,NULL,delete_exchanges_and_queues,(const void *)entity))
		thread_started = true;
	else
		delete_exchanges_and_queues((const void *)entity);

	CREATE_STRING (query,
		"DELETE FROM acl WHERE from_id = '%s' or exchange LIKE '%s.%%'",
		entity,
		entity
	);

	RUN_QUERY(query,"could not delete from acl table");

	CREATE_STRING (
		query,
		"DELETE FROM follow WHERE requested_by = '%s' or exchange LIKE '%s.%%'",
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
		pthread_join(thread,NULL);

	END();
}

int
cat (struct http_request *req)
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

		sanitize(entity);

		CREATE_STRING (query,
				"SELECT schema FROM users WHERE schema is NOT NULL AND id='%s'",
					entity
		);
	}
	else
	{
		entity = NULL;
		CREATE_STRING (query,"SELECT id,schema FROM users WHERE schema is NOT NULL LIMIT 50");
	}

	RUN_QUERY (query,"unable to query catalog data");

	num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	if (entity == NULL) // get top 50 data 
	{
		kore_buf_append(response,"[",1);

		for (i = 0; i < num_rows; ++i)
		{
			char *user 	= kore_pgsql_getvalue(&sql,i,0);
			char *schema 	= kore_pgsql_getvalue(&sql,i,1);

			kore_buf_append(response,"{\"",2);
			kore_buf_append(response,user,strlen(user));
			kore_buf_append(response,"\":",2);
			kore_buf_append(response,schema,strlen(schema));

			kore_buf_append(response,"},",2);
		} 
		if (num_rows > 0)
		{
			// remove the last COMMA 
			--(response->offset);
		}

		kore_buf_append(response,"]",1);
	}
	else
	{
		// if this entity has no schema or the entity does't exist
		if (num_rows == 0)
			BAD_REQUEST("not a valid id");

		char *schema = kore_pgsql_getvalue(&sql,0,0);

		kore_buf_append(response,schema,strlen(schema));
	}

	OK();

done:
	END();
}

int
register_owner(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *owner;

	char salt		[33];
	char owner_apikey	[33];
	char password_hash	[65];

	pthread_t thread;
	bool thread_started = false;

	req->status = 403;

	if (! is_request_from_localhost(req))
		FORBIDDEN("this api can only be called from localhost");

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
		FORBIDDEN("only admin can call this api");

	// cannot create an admin
	if (strcmp(owner,"admin") == 0 || strcmp(owner,"DATABASE") == 0 || strcmp(owner,"database") == 0)
		FORBIDDEN("cannot create the user");

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("entity should be a valid owner");

/////////////////////////////////////////////////

	if (! login_success("admin",apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(owner);

/////////////////////////////////////////////////

	str_to_lower(owner);

	// conflict if owner already exist
	CREATE_STRING (query,
			"SELECT id FROM users WHERE id ='%s'",
				owner
	);
	RUN_QUERY (query,"could not query info about the owner");

	if(kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	if (0 == pthread_create(&thread,NULL,create_exchanges_and_queues,(const void *)owner))
		thread_started = true;
	else
		create_exchanges_and_queues((const void *)owner);

	gen_salt_password_and_apikey (owner, salt, password_hash, owner_apikey);

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked,is_autonomous) "
				"values('%s','%s',NULL,'%s','f','t')",
				owner,
				password_hash,
				salt
	);

	RUN_QUERY (query, "could not create a new owner");

	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,owner,strlen(owner));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,owner_apikey,strlen(owner_apikey));
	kore_buf_append(response,"\"}\n",3);

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
		FORBIDDEN("this api can only be called from localhost");

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
		FORBIDDEN("only admin can call this api");

	// cannot delete admin
	if (strcmp(owner,"admin") == 0 || strcmp(owner,"DATABASE") == 0 || strcmp(owner,"database") == 0)
		FORBIDDEN("cannot delete user");

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("not a valid owner");

/////////////////////////////////////////////////

	if (! login_success("admin",apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(owner);

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
	if (0 == pthread_create(&thread,NULL,delete_exchanges_and_queues,(const void *)owner))
		thread_started = true;
	else
		delete_exchanges_and_queues((const void *)owner);

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
		pthread_join(thread,NULL);

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

	char queue 	[129];
	char exchange	[129];

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

	snprintf (exchange,128,"%s.%s", to,message_type); 

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

	if(strcmp(message_type,"public") != 0)
	{
		// if he is not the owner, he needs an entry in acl
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

	if (! amqp_queue_bind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(queue),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		amqp_empty_table
	))
	{
		ERROR("bind failed");
	}

	OK();

done:
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

	char queue 	[129];
	char exchange	[129];

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

	snprintf (exchange,128,"%s.%s", to,message_type); 

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey, &is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

	sanitize(from);
	sanitize(to);
	sanitize(topic);

/////////////////////////////////////////////////

	strlcpy(queue,from,128);
	if (KORE_RESULT_OK == http_request_header(req, "is-priority", &is_priority))
	{
		if (strcmp(is_priority,"true") == 0)
		{
			strlcat(queue,".priority",128);
		}
	}

	debug_printf("queue = %s",queue);
	debug_printf("exchange = %s", exchange);

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

	amqp_queue_unbind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(queue),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		amqp_empty_table
	);

	amqp_rpc_reply_t r = amqp_get_rpc_reply(cached_admin_conn);

	if (r.reply_type != AMQP_RESPONSE_NORMAL)
	{
		snprintf(error_string,100,"unbind failed %d\n",r.reply_type);
		ERROR(error_string);
	}

	OK();

done:
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
			"values(DEFAULT,'%s','%s','%s.%s',now(),'read','%s','%d','%s')",
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
			"values(DEFAULT,'%s','%s','%s.command',now(),'write','%s','%d','%s')",
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
			"values(DEFAULT,'%s','%s.%s','%s','%s', '%s', now() + interval '%d hours')",
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
			"values(DEFAULT,'%s','%s.command','%s','%s', '%s', now() + interval '%d hours')",
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
	char *exchange;

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
		snprintf(write_topic,129,"%s.command.%s",to,topic); // XXX use message_type instead of command

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
			ERROR("unbind failed for app.publish with device.command");

		CREATE_STRING 	(query, "DELETE FROM follow WHERE follow_id='%s'", follow_id);
		RUN_QUERY	(query, "failed to delete from follow table");
		
		// if its just write then stop 
		if (strcmp(permission,"write") == 0)
		{
			CREATE_STRING 	(query, "DELETE FROM acl WHERE follow_id='%s'", follow_id);
			RUN_QUERY	(query, "failed to delete from acl table");
			OK();
		}
			
	}

//// for read permissions /////

	CREATE_STRING ( query,
		"SELECT acl_id,follow_id,exchange FROM acl "
			"WHERE "
			"from_id = '%s' "
				"AND "
			"exchange = '%s.%s' "
				"AND "
			"topic = '%s' "
				"AND "
			"permission = 'read'",

				from,
				to,
				message_type,
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
	exchange 	= kore_pgsql_getvalue(&sql,0,2);

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
		snprintf(error_string,100,"unbind failed %d\n",r.reply_type);
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
		snprintf(error_string,100,"unbind to priority failed %d\n",r.reply_type);
		ERROR(error_string);
	}

	OK();

done:
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
	char *exchange 	 	= kore_pgsql_getvalue(&sql,0,1);
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
		"values(DEFAULT,'%s','%s','%s','%s','%s',now() + interval '%s hours')",
	        	from_id,
			exchange,
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
		snprintf(command_queue,129,"%s",exchange);	// exchange in follow is device.command
		snprintf(write_topic,129,"%s.%s",exchange,topic); // routing key will be dev.command.topic

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
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' and status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s.%%' and status='pending'",
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
			"WHERE exchange LIKE '%s/%%.%%' and status='pending' "
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
			"WHERE exchange LIKE '%s.%%' and status='pending' "
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
			FORBIDDEN("admin can only use from localhost");
	}
	else
	{
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize (entity);

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
			FORBIDDEN("admin can only use from localhost");
	}
	else
	{
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

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

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

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
		char *exchange 	= kore_pgsql_getvalue(&sql,i,0);
		char *perm 	= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_append(response,"{\"entity\":\"",11);
		kore_buf_append(response,exchange,strlen(exchange));
		kore_buf_append(response,"\",\"permission\":\"",16);
		kore_buf_append(response,perm,strlen(perm));
		kore_buf_append(response,"\"},",3);
	}

	// remove the last comma
	if (i > 0)
		--(response->offset);

	kore_buf_append(response,"]",1);

	OK();

done:
	END();

}

void *
create_exchanges_and_queues (const void *v)
{
	int i;

	const char *id = (const char *)v;

	char queue	[129];
	char exchange	[129];

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// create notification exchange 
		snprintf(exchange,129,"%s.notification",id);

		debug_printf("[owner] creating exchange {%s}\n",exchange);

		if (! amqp_exchange_declare (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes("topic"),
			0,
			1, /* durable */
			0,
			0,
			amqp_empty_table
		))
		{
			fprintf(stderr,"amqp_exchange_declare failed {%s}\n",exchange);
			goto done;
		}
		debug_printf("[owner] done creating exchange {%s}\n",exchange);

		// create notification queue
		snprintf(queue,129,"%s.notification",id);
		debug_printf("[owner] creating queue {%s}\n",queue);
		if (! amqp_queue_declare (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(queue),
			0,
			1, /* durable */
			0,
			0,
			lazy_queue_table
		))
		{
			fprintf(stderr,"amqp_queue_declare failed {%s}\n",queue);
			goto done;
		}

		debug_printf("done creating queue {%s}\n",queue);

		if (! amqp_queue_bind (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(queue),
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes("#"),
			amqp_empty_table
		))
		{
			fprintf(stderr,"bind failed for {%s} -> {%s}\n",queue,exchange);
			goto done;
		}

		debug_printf("bound queue {%s} to exchange {%s}\n",queue,exchange);

		if (! amqp_queue_bind (
			cached_admin_conn,
			1,
			amqp_cstring_bytes("DATABASE"),
			amqp_cstring_bytes(exchange),
			amqp_cstring_bytes("#"),
			amqp_empty_table
		))
		{
			fprintf(stderr,"failed to bind {%s} to DATABASE queue for\n",exchange);
			goto done;
		}
		debug_printf("bound queue {%s} to exchange {%s}\n",queue,"DATABASE");
	}
	else
	{
		for (i = 0; _e[i]; ++i)
		{
			snprintf(exchange,129,"%s%s",id,_e[i]);

			debug_printf("[entity] creating exchange {%s}\n",exchange);

			if (! amqp_exchange_declare (
					cached_admin_conn,
					1,
					amqp_cstring_bytes(exchange),
					amqp_cstring_bytes("topic"),
					0,
					1, /* durable */
					0,
					0,
					amqp_empty_table
				)
			)
			{
				fprintf(stderr,"something went wrong with exchange creation {%s}\n",exchange);
				goto done;
			}
			debug_printf("[entity] DONE creating exchange {%s}\n",exchange);

			if (! amqp_queue_bind (
				cached_admin_conn,
				1,
				amqp_cstring_bytes("DATABASE"),
				amqp_cstring_bytes(exchange),
				amqp_cstring_bytes("#"),
				amqp_empty_table
			))
			{
				fprintf(stderr,"failed to bind {%s} to DATABASE queue for\n",exchange);
				goto done;
			}
		}

		for (i = 0; _q[i]; ++i)
		{
			snprintf(queue,129,"%s%s",id,_q[i]);

			debug_printf("[entity] creating queue {%s}\n",queue);

			if (! amqp_queue_declare (
				cached_admin_conn,
				1,
				amqp_cstring_bytes(queue),
				0,
				1, /* durable */
				0,
				0,
				lazy_queue_table
			))
			{
				fprintf(stderr,"amqp_queue_declare failed {%s}\n",queue);
				goto done;
			}
			debug_printf("[entity] DONE creating queue {%s}\n",queue);

			// bind .private and .notification 
			if (strcmp(_q[i],".private") == 0 || strcmp(_q[i],".notification") == 0)
			{
				snprintf(exchange,129,"%s%s",id,_q[i]);
				debug_printf("[entity] binding {%s} -> {%s}\n",queue,exchange);

				if (! amqp_queue_bind (
					cached_admin_conn,
					1,
					amqp_cstring_bytes(queue),
					amqp_cstring_bytes(exchange),
					amqp_cstring_bytes("#"),
					amqp_empty_table
				))
				{
					fprintf(stderr,"failed to bind {%s} to {%s}\n",queue,exchange);
					goto done;
				}
			}
		}
	}

	is_success = true;

done:
	return &is_success;
}

void *
delete_exchanges_and_queues (const void *v)
{
	int i;

	const char *id = (const char *)v;

	char queue[129];
	char exchange[129];

	if (looks_like_a_valid_owner(id))
	{
		// delete notification exchange 
		snprintf(exchange,129,"%s.notification",id);

		debug_printf("[owner] deleting exchange {%s}\n",exchange);

		if (! amqp_exchange_delete (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(exchange),
			0
		))
		{
			fprintf(stderr,"amqp_exchange_delete failed {%s}\n",exchange);
			goto done;
		}
		debug_printf("[owner] done deleting exchange {%s}\n",exchange);

		// delete notification queue
		snprintf(queue,129,"%s.notification",id);
		debug_printf("[owner] deleting queue {%s}\n",queue);
		if (! amqp_queue_delete (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(queue),
			0,
			0
		))
		{
			fprintf(stderr,"amqp_queue_delete failed {%s}\n",queue);
			goto done;
		}
		debug_printf("[owner] DONE deleting queue {%s}\n",queue);
	}
	else
	{
		for (i = 0; _e[i]; ++i)
		{
			snprintf(exchange,129,"%s%s",id,_e[i]);

			debug_printf("[entity] deleting exchange {%s}\n",exchange);

			if (! amqp_exchange_delete (
					cached_admin_conn,
					1,
					amqp_cstring_bytes(exchange),
					0
				)
			)
			{
				fprintf(stderr,"something went wrong with exchange deletion {%s}\n",exchange);
				goto done;
			}
			debug_printf("[entity] DONE deleting exchange {%s}\n",exchange);
		}

		for (i = 0; _q[i]; ++i)
		{
			snprintf(queue,129,"%s%s",id,_q[i]);

			debug_printf("[entity] deleting queue {%s}\n",queue);

			if (! amqp_queue_delete (
				cached_admin_conn,
				1,
				amqp_cstring_bytes(queue),
				0,
				0
			))
			{
				fprintf(stderr,"amqp_queue_delete failed {%s}\n",queue);
				goto done;
			}
			debug_printf("[entity] DONE deleting queue {%s}\n",queue);
		}
	}

done:

	return NULL;
}

void
sanitize (const char *string)
{
	// string should not be NULL. let it crash if it is 
	char *p = (char *)string;

	// assumption is that 'string' is in single quotes

	while (*p)
	{
		/* wipe out anything that looks suspicious */
	
		if (! isprint(*p))
		{
			*p = '\0';
			return;
		}
		
		switch(*p)
		{
			case '\'':
			case '\\':
			case '_' :
			case '%' :
			case '(' :
			case ')' :
			case '|' :
			case ';' :
			case '&' :
				*p = '\0';
				return;
		}

		++p;
	}
}

bool
is_request_from_localhost (struct http_request *req)
{
	switch (req->owner->addrtype)
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
str_to_lower (const char *str)
{
	char *p = (char *)str;

	while (*p)
	{
		if (*p >= 'A' && *p <= 'Z')
			*p += 32; 

		++p;
	}
}
