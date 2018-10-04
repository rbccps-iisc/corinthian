#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_framing.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <openssl/sha.h>

#include <ctype.h>
#include <pthread.h>

#include "ht.h"

//#define TEST (1)

#if 1
	#define debug_printf(...)
#else
	#define debug_printf(...) printf(__VA_ARGS__)
#endif

char password_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$^&*-+=.?/";

int cat			(struct http_request *);

int publish		(struct http_request *);
int subscribe		(struct http_request *);

int register_entity	(struct http_request *);
int deregister_entity	(struct http_request *);

int register_owner 	(struct http_request *);
int deregister_owner 	(struct http_request *);

int follow		(struct http_request *);
int unfollow		(struct http_request *);

int get_follow_requests (struct http_request *);

int share		(struct http_request *);
int unshare		(struct http_request *);
int reject_follow	(struct http_request *);

int queue_bind          (struct http_request *);
int queue_unbind        (struct http_request *);


int block		(struct http_request *);
int unblock		(struct http_request *);

int init (int);

void gen_salt_password_and_apikey (const char *, char *, char *, char *);

bool login_success (const char *, const char *);
bool check_acl(const char *id, const char *exchange, const char *permission);

bool looks_like_a_valid_owner	(const char *str);
bool looks_like_a_valid_entity 	(const char *str);
bool looks_like_a_valid_resource(const char *str);

bool is_alpha_numeric 	(const char *str);
bool is_owner		(const char *, const char *);

void *create_exchanges_and_queues (void *);
void *delete_exchanges_and_queues (void *);

char *sanitize (char *string);

#define OK()    {req->status=200; goto done;}
#define OK202() {req->status=202; goto done;}

#define BAD_REQUEST(x) { 				\
	req->status = 400;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define FORBIDDEN(x) {					\
	req->status = 403;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define CONFLICT(x) { 					\
	req->status = 409;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define ERROR(x) { 					\
	req->status = 500;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define OK_if(x) {if(x) { OK(); }}
#define FORBIDDEN_if(x,msg) {if(x) { FORBIDDEN(msg); }}
#define ERROR_if(x,msg) {if(x) { ERROR(msg); }}
#define BAD_REQUEST_if(x,msg) {if(x) { BAD_REQUEST(msg); }}

#define RUN_QUERY(query,err) {					\
	debug_printf("RUN_QUERY ==> {%s}\n",query->data);	\
	kore_pgsql_cleanup(&sql);				\
	kore_pgsql_init(&sql);					\
	if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))	\
	{							\
		kore_pgsql_logerror(&sql);			\
		ERROR("DB error while setup");			\
	}							\
	if (! kore_pgsql_query(&sql, (char *)query->data))	\
	{							\
		kore_pgsql_logerror(&sql);			\
		ERROR(err);					\
	}							\
}

#define END() 	{			\
	http_response_header(		\
		req,			\
		"content-type",		\
		"application/json"	\
	);				\
	http_response (			\
		req,			\
		req->status, 		\
		response->data,		\
		response->offset	\
	);				\
	kore_pgsql_cleanup(&sql);	\
	kore_buf_reset(response);	\
	kore_buf_reset(Q);		\
	return (KORE_RESULT_OK);	\
} 

struct kore_buf *Q = NULL;
struct kore_buf *query = NULL;
struct kore_buf *response = NULL;

char 	string_to_be_hashed 	[256];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

struct kore_pgsql sql;

#define CREATE_STRING(buf,...)	{			\
	kore_buf_reset(buf);				\
	kore_buf_appendf(buf,__VA_ARGS__);		\
	kore_buf_stringify(buf,NULL);			\
	debug_printf("BUF => {%s}\n",buf->data);	\
}

ht connection_ht;


amqp_table_entry_t *entry;
amqp_table_t lazy_queue_table;
amqp_table_t durable_binding_table;

char admin_apikey[33];
amqp_connection_state_t	cached_admin_conn;

int
init (int state)
{
	int i;

	// ignore the https worker
	if (worker->id == 0)
		return KORE_RESULT_OK;

	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;

//////////////
// lazy queues
//////////////
	lazy_queue_table.num_entries = 1;
	lazy_queue_table.entries = malloc(lazy_queue_table.num_entries * sizeof(amqp_table_entry_t));

	if (! lazy_queue_table.entries)
		exit(-1);

	entry = &lazy_queue_table.entries[0];
	entry->key = amqp_cstring_bytes("x-queue-mode");
	entry->value.kind = AMQP_FIELD_KIND_UTF8;
	entry->value.value.bytes = amqp_cstring_bytes("lazy");

//////////////
// durable bindings 
//////////////
	durable_binding_table.num_entries = 1;
	durable_binding_table.entries = malloc(durable_binding_table.num_entries * sizeof(amqp_table_entry_t));

	if (! durable_binding_table.entries)
		exit(-1);

	entry = &durable_binding_table.entries[0];
	entry->key = amqp_cstring_bytes("durable");
	entry->value.kind = AMQP_FIELD_KIND_UTF8;
	entry->value.value.bytes = amqp_cstring_bytes("true");

//////////////

	int fd = open("admin.apikey",O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr,"could not open admin.apikey\n");
		exit(-1);
	}

	if (! read(fd,admin_apikey,32))
	{
		fprintf(stderr,"could not read from admin.apikey\n");
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

	close (fd);

	amqp_socket_t *socket = NULL;

	cached_admin_conn = amqp_new_connection();
	socket = amqp_tcp_socket_new(cached_admin_conn);

	if (socket == NULL)
	{
		fprintf(stderr,"Could not open a socket ");
		return KORE_RESULT_ERROR;
	}

	if (amqp_socket_open(socket, "kore-broker", 5672))
	{
		fprintf(stderr,"Could not connect to kore-broker");
		return KORE_RESULT_ERROR;	
	}

	login_reply = amqp_login
#ifdef TEST
		(cached_admin_conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "guest", "guest");
#else	
		(cached_admin_conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, "admin", admin_apikey);
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


	// TODO drop privilages to read admin.apikey file

	ht_init (&connection_ht);

	if (Q == NULL)
		Q = kore_buf_alloc(256);

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(65536);

#ifdef TEST
	kore_pgsql_register("db","user=postgres password=password");
#else
	kore_pgsql_register("db","host=kore-postgres user=postgres password=postgres_pwd");
#endif

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
	return is_alpha_numeric(str);
}

bool
is_owner(const char *id, const char *entity)
{
	int strlen_id = strlen(id);

	if (strncmp(id,entity,strlen_id) != 0)
		return false;	

	if (entity[strlen_id] != '/')
		return false;	

	return true;
}

bool
looks_like_a_valid_entity (const char *str)
{
	int i;

	uint8_t strlen_str = strlen(str);

	uint8_t front_slash_count = 0;

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

				case '.':
						++dot_count;
						break;
				default:
						return false;	
			}
		}

		if (
			(front_slash_count > 1)
				  ||
		            (dot_count > 1)
		   )
		   {	
			return false;
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

	// TODO security level
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

	sprintf	
	(
		password_hash,
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
login_success (const char *id, const char *apikey)
{
	char *salt;
	char *password_hash;

	bool login_result = false;

	if (id == NULL || apikey == NULL || *id == '\0' || *apikey == '\0')
		goto done;

	if (strchr(id,'\'') != NULL)
		goto done;

	CREATE_STRING (query,
			"SELECT salt,password_hash FROM users WHERE id='%s' and blocked='f'",
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

	salt 	 	= kore_pgsql_getvalue(&sql,0,0);
	password_hash	= kore_pgsql_getvalue(&sql,0,1);

	// there is no salt or password hash in db ?
	if (salt[0] == '\0' || password_hash[0] == '\0')
		goto done;

	debug_printf("strlen of salt = %d (%s)\n",strlen(salt),salt);
	debug_printf("strlen of apikey = %d (%s)\n",strlen(apikey),apikey);

	strlcpy(string_to_be_hashed, apikey, 33);
	strlcat(string_to_be_hashed, salt,   65);
	strlcat(string_to_be_hashed, id,    250);

	SHA256((const uint8_t*)string_to_be_hashed,strlen(string_to_be_hashed),binary_hash);

	debug_printf("login_success STRING TO BE HASHED = {%s}\n",string_to_be_hashed);

	sprintf	
	(
		hash_string,
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
	return login_result;
}

int
publish (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *exchange;
	const char *topic;
	const char *message;

	const char *content_type;

	amqp_basic_properties_t props;

	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &exchange)
				||
		KORE_RESULT_OK != http_request_header(req, "topic", &topic)
			,
		"inputs missing in headers"
	);

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if (!(message = (char *)req->http_body->data))
			BAD_REQUEST("no body found in request");
	}

	// get content-type and set in props
	if (http_request_header(req, "content-type", &content_type) != KORE_RESULT_OK)
	{
		content_type = "";
	}

	if (! looks_like_a_valid_entity(id))
		BAD_REQUEST("id is not a valid entity");

	// let it not go to the broker
	if (! login_success(id,apikey))
		BAD_REQUEST("invalid id or apikey");

	amqp_socket_t *socket = NULL;

	node *n = NULL;

	amqp_connection_state_t	*cached_conn = NULL;

	if ((n = ht_search(&connection_ht,id)) != NULL)
	{
		cached_conn = n->value;

		if (cached_conn == NULL)
		{
			goto reconnect;
		}

		// TODO also check if connection is still open 
	}
	else
	{
reconnect:
		cached_conn = malloc(sizeof(amqp_connection_state_t));

		if (cached_conn == NULL)
			ERROR("out of memory");

		*cached_conn = amqp_new_connection();
		socket = amqp_tcp_socket_new(*cached_conn);
		
		if (socket == NULL)
			ERROR("could not create a new socket");

		if (amqp_socket_open(socket, "broker", 5672))
			ERROR("could not open a socket");

		login_reply = amqp_login(*cached_conn, 
			"/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, id, apikey);

		if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
			FORBIDDEN("invalid id or apiey ...");

		if(! amqp_channel_open(*cached_conn, 1))
			ERROR("could not open an AMQP connection");

		rpc_reply = amqp_get_rpc_reply(*cached_conn);
		if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
			ERROR("did not receive expected response from the broker");

		ht_insert (&connection_ht, id, cached_conn);
	}

	memset(&props, 0, sizeof props);
	props.user_id 		= amqp_cstring_bytes(id);
	props.content_type 	= amqp_cstring_bytes(content_type);

	debug_printf("Got content-type {%s}\n",content_type);

	FORBIDDEN_if
	(
		AMQP_STATUS_OK != amqp_basic_publish (	
			*cached_conn,
			1,
			amqp_cstring_bytes(exchange),
        		amqp_cstring_bytes(topic),
			0,
			0,
			&props,
			amqp_cstring_bytes(message)
		),

		"broker refused to publish message"
	);

	OK202();

done:
	if (req->status == 500)
	{
		if (cached_conn)
		{
			amqp_channel_close	(*cached_conn, 1, AMQP_REPLY_SUCCESS);
			amqp_connection_close	(*cached_conn,    AMQP_REPLY_SUCCESS);
			amqp_destroy_connection	(*cached_conn);

			ht_delete(&connection_ht,id);
		}
	}

	END();
}

int
subscribe(struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *message_type;
	const char *num_messages;

	uint8_t int_num_messages = 1;

	amqp_socket_t 			*socket = NULL;
	amqp_connection_state_t		connection;

	bool connection_opened = false;

	amqp_rpc_reply_t 	login_reply;
	amqp_rpc_reply_t 	rpc_reply;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

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

	if (KORE_RESULT_OK == http_request_header(req, "num-messages", &num_messages))
	{
		int_num_messages = atoi(num_messages);

		if (int_num_messages > 10 || int_num_messages < 1)
			int_num_messages = 10;
	}

	if (! looks_like_a_valid_entity(id))
		BAD_REQUEST("id is not a valid entity");

	// let it not go to the broker
	if (! login_success(id,apikey))
		BAD_REQUEST("invalid id or apikey");

	connection 	= amqp_new_connection();
	socket		= amqp_tcp_socket_new(connection);

	connection_opened = true;

	if (socket == NULL)
		ERROR("could not create a new socket");

	if (amqp_socket_open(socket, "broker", 5672))
		ERROR("could not open a socket");

	login_reply = amqp_login(connection, 
			"/",
			0,
			131072,
			0,
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

		if (message.properties.user_id.len == 0)
			kore_buf_append (response,"\"\"",2);
		else
			kore_buf_append (response,message.properties.user_id.bytes,
				message.properties.user_id.len);


		kore_buf_append(response,"\",\"from\":\"",10);
		if(header->exchange.len > 0)
			kore_buf_append(response,header->exchange.bytes, header->exchange.len);

		kore_buf_append(response,"\",\"topic\":\"",11);
		if (header->routing_key.len > 0)
			kore_buf_append(response,header->routing_key.bytes, header->routing_key.len);

		kore_buf_append(response,"\",\"content-type\":\"",18);
		if (message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG)
		{
			kore_buf_append(response,message.properties.content_type.bytes,
				message.properties.content_type.len);
		}

		kore_buf_append(response,"\",\"body\":\"",10);
		kore_buf_append(response,message.body.bytes, message.body.len);
		kore_buf_append(response,"\"},",3);

		// we waited for messages for atleast a second
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

// one with register-bulk

int
register_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	char *body;

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

	BAD_REQUEST_if	
	(
		req->http_body == NULL
			||
		(body = (char *)req->http_body->data) == NULL
			,
		"no body found in request"	
	);	

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

///////////////////////////////////
	id 	= sanitize(id);
	entity	= sanitize(entity);
	body	= sanitize(body);
///////////////////////////////////

	strlcpy(entity_name,id,32);
	strcat(entity_name,"/");
	strlcat(entity_name,entity,66);

	// create entries in to RabbitMQ
	pthread_create(&thread,NULL,create_exchanges_and_queues,(void *)&entity_name); 
	thread_started = true;

	// conflict if entity_name already exist

	CREATE_STRING(query,
		 	"SELECT id from users WHERE id='%s'",
				entity_name
	);

	RUN_QUERY (query,"could not get info about entity");

	if (kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity_name, salt, password_hash, entity_apikey);

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked) values('%s','%s','%s','%s','f')",
			entity_name,
			password_hash,
			body,		// schema
			salt
	);
	RUN_QUERY (query,"failed to create the entity");

	// generate response
	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity_name,strlen(entity_name));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
	kore_buf_append(response,"\"}\n",3);

	OK();

done:
	// wait for thread ...
	if (thread_started)
	{
		bool *result;
		pthread_join(thread,(void *)&result);

		if (! *result) {
			req->status = 500;
			kore_buf_reset(response);
		}

		free(result);
	}

	END();
}

int
delete_owner_from_rabbitmq (char *owner)
{
	if (! looks_like_a_valid_owner(owner))
		return -1;
/*
	CREATE_STRING (query,
				"SELECT * from users where id='%s'",
					sanitize(owner)
	); 
	RUN_QUERY (query, "can't search entity in DB");

	// login as admin in amqp

	uint32_t num_rows = kore_pgsql_ntuples(&sql);
	for (i = 0; i < num_rows; ++i)
	{
		entity = kore_pgsql_getvalue(&sql,i,0);
		// delete_entity_from_rabbitmq (entity);
	}
*/

done:
	return 0;
}

int
deregister_entity (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	char entity_name [66];

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

	if (! is_alpha_numeric(entity))
		FORBIDDEN("entity is not valid");

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

///////////////////////////////////
	id 	= sanitize(id);
	entity 	= sanitize(entity);
///////////////////////////////////

	strlcpy(entity_name,id,33); 
	strlcat(entity_name,"/",34); 
	strlcat(entity_name,entity,66); 

	// TODO delete from follow where from_entity = entity_name or to_entity = entity_name
	// delete entries in to RabbitMQ

	pthread_create(&thread,NULL,delete_exchanges_and_queues,(void *)&entity_name); 
	thread_started = true;

	// TODO run select query and delete all exchanges and queues of entity_name 

	CREATE_STRING (
		query,
		"DELETE FROM acl WHERE id = '%s' or exchange LIKE '%s.%%'",
		entity_name,
		entity_name
	);

	RUN_QUERY(query,"could not delete from acl table");

	CREATE_STRING (
		query,
		"DELETE FROM follow WHERE id_from = '%s' or id_to LIKE '%s.%%'",
		entity_name,
		entity_name
	);

	RUN_QUERY(query,"could not delete from follow table");

	CREATE_STRING (query,
			"DELETE FROM users WHERE id = '%s'",
				entity_name
	);
	RUN_QUERY (query,"could not delete the entity");

	OK();

done:
	// wait for thread ...
	if (thread_started)
	{
		bool *result;
		pthread_join(thread,(void *)&result);

		if (! *result) {
			req->status = 500;
			kore_buf_reset(response);
		}

		free(result);
	}

	END();
}

int
cat(struct http_request *req)
{
	int i;

	const char *entity;
	uint32_t num_rows = 0;

	req->status = 403;

	http_populate_get(req);
	if (http_argument_get_string(req,"id",&entity))
	{
		// if not a valid entity
		if (! looks_like_a_valid_entity(entity))
			FORBIDDEN("id is not a valid entity");
	
		CREATE_STRING (query,
				"SELECT schema FROM users WHERE schema is NOT NULL AND id='%s'",
					sanitize(entity)
		);
	}
	else
	{
		entity = NULL;
		CREATE_STRING (query,"SELECT id,schema FROM users WHERE schema is NOT NULL");
	}

	RUN_QUERY (query,"unable to query catalog data");
	
	num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	if (entity == NULL) // get all data
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
db_cleanup (struct http_request *req)
{
	const char *id;
	const char *apikey;

	req->status = 403;

	if (req->owner->addrtype == AF_INET)
	{
		if (req->owner->addr.ipv4.sin_addr.s_addr != htonl(INADDR_LOOPBACK))	
		{
			FORBIDDEN("this api can only be called from localhost");
		}
	}

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this api");

	if (! login_success("admin",apikey))
		FORBIDDEN("wrong apikey");

	CREATE_STRING 	(query,"DELETE FROM acl WHERE now() > valid_till");
	RUN_QUERY 	(query,"could not delete old entiries from acl table");
	
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

	if (req->owner->addrtype == AF_INET)
	{
		if (req->owner->addr.ipv4.sin_addr.s_addr != htonl(INADDR_LOOPBACK))	
		{
			FORBIDDEN("this api can only be called from localhost");
		}
	}

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

	// cannot create an admin
	if (strcmp(owner,"admin") == 0)
		FORBIDDEN("cannot create admin");

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this api");

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("entity should be an owner");	
		
	if (! login_success("admin",apikey))
		FORBIDDEN("wrong apikey");

////////////////////////////////////////
	owner = sanitize(owner);
////////////////////////////////////////

	// conflict if entity_name already exist
	CREATE_STRING (query,
			"SELECT id FROM users WHERE id ='%s'",
				owner
	);
	RUN_QUERY (query,"could not query info about the owner");

	if(kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	pthread_create(&thread,NULL,create_exchanges_and_queues,(void *)owner); 
	thread_started = true;

	gen_salt_password_and_apikey (owner, salt, password_hash, owner_apikey);

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked) values('%s','%s',NULL,'%s','f')",
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

	OK();

done:
	// wait for thread ...
	if (thread_started)
	{
		bool *result;
		pthread_join(thread,&result);

		if (! *result) {
			req->status = 500;
			kore_buf_reset(response);
		}

		free(result);
	}

	END();
}

int
deregister_owner(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *owner;

	pthread_t thread;
	bool thread_started = false; 

	req->status = 403;

	if (req->owner->addrtype == AF_INET)
	{
		if (req->owner->addr.ipv4.sin_addr.s_addr != htonl(INADDR_LOOPBACK))	
		{
			FORBIDDEN("this api can only be called from localhost");
		}
	}

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
	if (strcmp(owner,"admin") == 0)
		FORBIDDEN("cannot delete admin");

	// it should look like an owner
	if (! looks_like_a_valid_owner(owner))
		BAD_REQUEST("not a valid owner");	

	if (! login_success("admin",apikey))
		FORBIDDEN("wrong apikey");

////////////////////////////////////////////////
	owner 	= sanitize(owner);
////////////////////////////////////////////////

	// delete entries in to RabbitMQ
	pthread_create(&thread,NULL,delete_exchanges_and_queues,(void *)owner); 
	thread_started = true;
	// XXX TODO delete all entities of the owner

	// delete all acls
	CREATE_STRING (query,
			"DELETE FROM acl WHERE id LIKE '%s/%%' OR exchange LIKE '%s/%%'",
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
		pthread_join(thread,&result);

		if (! *result) {
			req->status = 500;
			kore_buf_reset(response);
		}

		free(result);
	}

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

	char *status = "pending";

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "from", &from)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "permission", &permission)
				||
		KORE_RESULT_OK != http_request_header(req, "validity", &validity)
			,
		"inputs missing in headers"
	);

	if (strcmp(permission,"read") == 0 || strcmp(permission,"read-write") == 0)
	{
		if (KORE_RESULT_OK != http_request_header(req, "topic", &topic))
		{
			BAD_REQUEST ("topic is missing in headers");
		}
	}

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");	

	if (! looks_like_a_valid_entity(from))
		FORBIDDEN("from is not a valid entity");
	
	if (! looks_like_a_valid_entity(to))
		FORBIDDEN("to is not a valid entity");

	// check if the he is the owner of from 
	if (! is_owner(id,from))
		FORBIDDEN("you are not the owner of from entity");

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

///////////////////////////////////

	sanitize (from);
	sanitize (to);
	sanitize (permission);
	sanitize (validity);
	sanitize (topic);

///////////////////////////////////

	// if both from and to are owned by id
	if (is_owner(id,to))
	{
		status = "approved";	
	}

	char read_follow_id  [10];
	char write_follow_id [10];

	read_follow_id[0] = '\0';
	write_follow_id[0] = '\0';

	if (strcmp(permission,"read") == 0)
	{
		CREATE_STRING (query, 
			"INSERT INTO follow "
			"(follow_id,id_from,id_to,time,permission,topic,validity,status) "
			"values(DEFAULT,'%s','%s.protected',now(),'read','%s','%s','%s')",
				from,
				to,
				topic,
				validity,
				status
		);
		RUN_QUERY (query, "failed to insert follow - read");

		CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
		RUN_QUERY 	(query,"failed pg_get_serial read");

		strlcpy(read_follow_id,kore_pgsql_getvalue(&sql,0,0),10);
	}
	else if (strcmp(permission,"write") == 0) 
	{
		CREATE_STRING (query,
			"INSERT INTO follow (follow_id,id_from,id_to,time,permission,topic,validity,status) "
			"values(DEFAULT,'%s','%s.command',now(),'write','%s','%s','%s')",
				from,
				to,
				"#",
				validity,
				status
		);
		RUN_QUERY (query, "failed to insert follow - write");

		CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
		RUN_QUERY 	(query,"failed pg_get_serial write");
		strlcpy(write_follow_id,kore_pgsql_getvalue(&sql,0,0),10);
	}
	else if (strcmp(permission,"read-write") == 0) 
	{
		CREATE_STRING (query,
			"INSERT INTO follow (follow_id,id_from,id_to,time,permission,topic,validity,status) "
			"values(DEFAULT,'%s','%s.protected',now(),'read','%s','%s','%s')",
				from,
				to,
				topic,
				validity,
				status
		);
		RUN_QUERY (query, "failed to insert follow - read");

		CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
		RUN_QUERY 	(query,"failed pg_get_serial read in read-write");

		strlcpy(read_follow_id,kore_pgsql_getvalue(&sql,0,0),10);

		CREATE_STRING (query,
			"INSERT INTO follow (follow_id,id_from,id_to,time,permission,topic,validity,status) "
			"values(DEFAULT,'%s','%s.command',now(),'write','%s','%s','%s')",
				from,
				to,
				"#",
				validity,
				status
		);
		RUN_QUERY (query, "failed to insert follow - write");

		CREATE_STRING 	(query,"SELECT currval(pg_get_serial_sequence('follow','follow_id'))");
		RUN_QUERY 	(query,"failed pg_get_serial write in read-write");

		strlcpy(write_follow_id,kore_pgsql_getvalue(&sql,0,0),10);
	}
	else
	{
		BAD_REQUEST("invalid permission type");
	}

	if (strcmp(status,"approved") == 0)
	{
		// add entry in acl
		if (strcmp(permission,"read") == 0)
		{
			CREATE_STRING (query,
				"INSERT into acl (acl_id,id,exchange,follow_id,permission,topic,valid_till) "
				"values(DEFAULT,'%s','%s.protected','%s','%s', '%s', now() + interval '%s  hours')",
			        	from,
					to,
					read_follow_id,
					"read",
					topic,
					validity
			);

			RUN_QUERY (query,"could not run insert query on acl - read ");
		}
		else if (strcmp(permission,"write") == 0)
		{
			CREATE_STRING (query,
				"INSERT into acl (acl_id,id,exchange,follow_id,permission,topic,valid_till) "
				"values(DEFAULT,'%s','%s.command','%s','%s', '%s', now() + interval '%s  hours')",
			        	from,
					to,
					write_follow_id,
					"write",
					topic,
					validity
			);

			RUN_QUERY (query,"could not run insert query on acl - write");
		}
		else if (strcmp(permission,"read-write") == 0)
		{
			CREATE_STRING (query,
				"INSERT into acl (acl_id,id,exchange,follow_id,permission,topic,valid_till) "
				"values(DEFAULT,'%s','%s.protected','%s','%s', '%s', now() + interval '%s  hours')",
			        	from,
					to,
					read_follow_id,
					"read",
					topic,
					validity
			);

			RUN_QUERY(query,"could not run insert query on acl - read/write -1 ");

			CREATE_STRING (query,
				"INSERT into acl (acl_id,id,exchange,follow_id,permission,topic,valid_till) "
				"values(DEFAULT,'%s','%s.command','%s','%s', '%s', now() + interval '%s  hours')",
			        	from,
					to,
					write_follow_id,
					"write",
					topic,
					validity
			);

			RUN_QUERY (query,"could not run insert query on acl - read/write - 2");
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

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");	

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

///////////////////////////////////

	sanitize(id);
	sanitize(follow_id);

///////////////////////////////////

	CREATE_STRING (query, 
		"SELECT id_from,id_to,permission,validity,topic FROM follow "
		"WHERE follow_id = '%s' AND id_to LIKE '%s/%%.%%' and status='pending'",
			follow_id,
			id
	);

	RUN_QUERY (query,"could not run select query on follow");

	uint32_t num_rows = kore_pgsql_ntuples(&sql);

	if (num_rows != 1)
		BAD_REQUEST("follow-id is not valid");

	char *id_from 	 	= kore_pgsql_getvalue(&sql,0,0);
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
	CREATE_STRING 	(query,
				"INSERT into acl (acl_id,id,exchange,follow_id,permission,topic,valid_till) "
				"values(DEFAULT,'%s','%s','%s','%s', '%s', now() + interval '%s  hours')",
			        	id_from,
					exchange,
					follow_id,
					permission,
					topic,
					validity_hours
	);

	RUN_QUERY (query,"could not run insert query on acl");

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

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");	

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

///////////////////////////////////

	sanitize(id);
	sanitize(follow_id);

///////////////////////////////////

	CREATE_STRING (query, 
		"SELECT follow_id FROM follow "
		"WHERE follow_id = '%s' AND id_to LIKE '%s/%%.%%' and status='pending'",
			follow_id,
			id
	);

	RUN_QUERY (query,"could not run select query on follow");

	uint32_t num_rows = kore_pgsql_ntuples(&sql);

	if (num_rows != 1)
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
unfollow (struct http_request *req)
{
	return (KORE_RESULT_OK);
}

int
queue_bind (struct http_request *req)
{
	/*XXX XXX XXX not tested XXX XXX XXX */

	const char *id;
	const char *apikey;

	// source and destination instead ?
	const char *from;
	const char *to;

	char *message_type;

	char queue	[128];
	char exchange	[128];

        const char *topic;

	bool is_priority = false;

 	req->status = 403;
	
	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "from", &from)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "topic", &topic)
			,
		"inputs missing in headers"
	);

	if (KORE_RESULT_OK == http_request_header(req, "message-type", &topic))
	{
		if (strcmp(message_type,"priority") == 0);
		{
			is_priority = true;
		}
	}

      	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");	

	if (! looks_like_a_valid_resource(from))
		FORBIDDEN("queue is not a valid resource name");
	
	if (! looks_like_a_valid_resource(to))
		FORBIDDEN("exchange is not a valid resource name");

	// check if the he is the owner of queue 
	if (! is_owner(id,from))
		FORBIDDEN("you are not the owner of the queue");

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////

	sanitize(id);
	sanitize(from);
	sanitize(to);
	sanitize(topic);

/////////////////////////////////////

	// if he is not the owner of exchange, he should have an entry in acl
	if (! is_owner(id,from))
	{
		CREATE_STRING (
			query,
				"SELECT topic FROM acl WHERE id = '%s' "
				"AND exchange = '%s' AND permission = 'read' "
				"AND valid_till > now() AND topic = '%s'",
				id,
				from,
				topic
		);

		RUN_QUERY(query,"failed to query for permission");
		
		if (kore_pgsql_ntuples(&sql) != 1)
			FORBIDDEN("unauthorized");
	}

	snprintf (queue,"%s%s", id, is_priority ? ".priority" : "");
	snprintf (exchange,"%s.protected",from); 
	
	if (! amqp_queue_bind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(queue),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		durable_binding_table
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

	/*XXX XXX XXX not tested XXX XXX XXX */

	const char *id;
	const char *apikey;

	// source and destination instead ?
	const char *from;
	const char *to;

	char *message_type;

	char queue	[128];
	char exchange	[128];

        const char *topic;

	bool is_priority = false;

 	req->status = 403;
	
	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "from", &from)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "topic", &topic)
			,
		"inputs missing in headers"
	);

	if (KORE_RESULT_OK == http_request_header(req, "message-type", &topic))
	{
		if (strcmp(message_type,"priority") == 0);
		{
			is_priority = true;
		}
	}

      	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");	

	if (! looks_like_a_valid_resource(from))
		FORBIDDEN("queue is not a valid resource name");
	
	if (! looks_like_a_valid_resource(to))
		FORBIDDEN("exchange is not a valid resource name");

	// check if the he is the owner of queue 
	if (! is_owner(id,from))
		FORBIDDEN("you are not the owner of the queue");

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

/////////////////////////////////////

	sanitize(id);
	sanitize(from);
	sanitize(to);
	sanitize(topic);

/////////////////////////////////////

	// if he is not the owner of exchange, he should have an entry in acl
	if (! is_owner(id,to))
	{
		CREATE_STRING (
			query,
				"SELECT topic FROM acl WHERE id = '%s' "
				"AND exchange = '%s' AND permission = 'read' "
				"AND valid_till > now() AND topic = '%s'",
				id,
				to,
				topic
		);

		RUN_QUERY(query,"failed to query for permission");
		
		if (kore_pgsql_ntuples(&sql) != 1)
			FORBIDDEN("unauthorized");
	}

	snprintf (queue,127,"%s%s", from, is_priority ? ".priority" : "");
	snprintf (exchange,127,"%s.protected",to); 
	
	if (! amqp_queue_unbind (
		cached_admin_conn,
		1,
		amqp_cstring_bytes(queue),
		amqp_cstring_bytes(exchange),
		amqp_cstring_bytes(topic),
		durable_binding_table	
	))
	{
		ERROR("bind failed");
	}

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
	const char *status;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
		,
		
		"inputs missing in headers"
	);

	if (KORE_RESULT_OK != http_request_header(req, "status", &status))
		status = "all";

	if (	
		strcmp(status,"pending")  != 0 && 
		strcmp(status,"approved") != 0 &&
		strcmp(status,"rejected") != 0 &&
		strcmp(status,"all") 	  != 0
	)
		BAD_REQUEST("status can be pending, approved, rejected, or all");

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");	

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

	if (strcmp(status,"all") == 0)
	{
		CREATE_STRING(query,
				"SELECT * FROM follow WHERE id_to LIKE '%s/%%.%%' "
				"ORDER BY time",
					sanitize(id)
		);
	}
	else
	{
		CREATE_STRING (query,
				"SELECT * FROM follow WHERE id_to LIKE '%s/%%.%%' and status='%s' "
				"ORDER BY time",
					sanitize(id),
					sanitize(status)
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	uint32_t num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);
	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
			response,
			"{\"id\":\"%s\","
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
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

	CREATE_STRING(query,
			"UPDATE users set blocked='t' WHERE id='%s'",
				sanitize(entity)
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
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");

		if (! login_success(id,apikey))
			FORBIDDEN("invalid id or apikey");
	}

	CREATE_STRING(query,
			"UPDATE users set blocked='f' WHERE id='%s'",
				sanitize(entity)
	);
	
	RUN_QUERY(query, "could not block the entity");

	OK();

done:
	END();
}

void *
create_exchanges_and_queues (void *v)
{
	const char *id = (const char *)v;

	bool *is_success;

	char exchange[128];
	char q[128];

	is_success = malloc (sizeof(bool));

	*is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		snprintf(exchange,128,"%s.notification",id);

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

		snprintf(q,128,"%s.notification",id);
		debug_printf("[owner] creating queue {%s}\n",q);
		if (! amqp_queue_declare (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(q),
			0,
			1, /* durable */
			0,
			0,
			lazy_queue_table	
		))
		{
			fprintf(stderr,"amqp_queue_declare failed {%s}\n",q);
			goto done;
		}
	}
	else
	{
		char *_e[] = {".public", ".private", ".protected", ".command"};

		for (int i = 0; i < 4; ++i)
		{
			snprintf(exchange,128,"%s%s",id,_e[i]);

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
		}

		char *_q[] = {"\0", ".priority", ".command"};
		for (int i = 0; i < 3; ++i)
		{
			snprintf(q,128,"%s%s",id,_q[i]);

		debug_printf("[entity] creating queue {%s}\n",q);
			if (! amqp_queue_declare (
				cached_admin_conn,
				1,
				amqp_cstring_bytes(q),
				0,
				1, /* durable */
				0,
				0,
				lazy_queue_table	
			))
			{
				fprintf(stderr,"amqp_queue_declare failed {%s}\n",q);
				goto done;
			}
		debug_printf("[entity] DONE creating queue {%s}\n",q);
		}
	}

	*is_success = true;

done:
	return is_success;
}

void *
delete_exchanges_and_queues (void *v)
{
	int i;

	const char *id = (const char *)v;
	
	char exchange[128];
	char q[128];

	bool *is_success;

	is_success = malloc(sizeof(bool));
	*is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		snprintf(exchange,128,"%s.notification",id);

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
		debug_printf("[owner] done creating exchange {%s}\n",exchange);

		snprintf(q,128,"%s.notification",id);
		debug_printf("[owner] deleting queue {%s}\n",q);
		if (! amqp_queue_delete (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(q),
			0,
			0
		))
		{
			fprintf(stderr,"amqp_queue_delete failed {%s}\n",q);
			goto done;
		}
		debug_printf("[owner] DONE deleting queue {%s}\n",q);
	}
	else
	{
		char *_e[] = {".public", ".private", ".protected", ".command"};

		for (i = 0; i < 4; ++i)
		{
			snprintf(exchange,128,"%s%s",id,_e[i]);

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

		char *_q[] = {"\0", ".priority", ".command"};
		for (i = 0; i < 3; ++i)
		{
			snprintf(q,128,"%s%s",id,_q[i]);

			debug_printf("[entity] deleting queue {%s}\n",q);

			if (! amqp_queue_delete (
				cached_admin_conn,
				1,
				amqp_cstring_bytes(q),
				0,
				0
			))
			{
				fprintf(stderr,"amqp_queue_delete failed {%s}\n",q);
				goto done;
			}
			debug_printf("[entity] DONE deleting queue {%s}\n",q);
		}
	}

	*is_success = true;

done:
	return is_success;
}

char*
sanitize (char *string)
{
	char *p = string;

	while (*p)
	{
		/* replace single quotes with double quotes.

		   underscores and % with spaces. ok ?

		  we will have problem with read only strings */

			if (*p == '\'') *p = '\"';
		else 	if (*p == '_' ) *p = ' ';
		else 	if (*p == '%' ) *p = ' ';

		++p;
	}
	
	return string;
}
