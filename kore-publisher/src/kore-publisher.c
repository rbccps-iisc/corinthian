#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <openssl/sha.h>

#include <ctype.h>

#if 0
	#define debug_printf(...)
#else
	#define debug_printf(...) printf(__VA_ARGS__)
#endif

char password_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*_-+=.?/";


int cat			(struct http_request *);

int publish		(struct http_request *);
int subscribe		(struct http_request *);

int register_entity	(struct http_request *);
int deregister_entity	(struct http_request *);

int register_owner 	(struct http_request *);
int deregister_owner 	(struct http_request *);

int follow		(struct http_request *);
int unfollow		(struct http_request *);

int share		(struct http_request *);
int unshare		(struct http_request *);

int init (int);
void gen_salt_password_and_apikey (const char *, char *, char *, char *);
bool login_success (const char *, const char *);


bool looks_like_a_valid_owner(const char *str);
bool looks_like_a_valid_entity (const char *str);

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

struct kore_buf *Q = NULL;
struct kore_buf *query = NULL;
struct kore_buf *response = NULL;

char 	string_to_be_hashed 	[256];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

struct kore_pgsql sql;

size_t i;

#define CREATE_STRING(buf,...)	{		\
	kore_buf_reset(buf);			\
	kore_buf_appendf(buf,__VA_ARGS__);	\
	kore_buf_stringify(buf,NULL);		\
	printf("Got buf = {%s}\n",buf->data);	\
}

int
init (int state)
{
	if (Q == NULL)
		Q = kore_buf_alloc(256);

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(65536);

	kore_pgsql_register("db","user=postgres password=password");

	return KORE_RESULT_OK;
}

bool
is_alpha_numeric (const char *str)
{
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
looks_like_a_valid_entity (const char *str)
{
	uint8_t strlen_str = strlen(str);

	uint8_t back_slash_count = 0;

	if (strlen_str < 3 || strlen_str > 65)
		return false;

	for (i = 0; i < strlen_str; ++i)
	{
		if (! isalnum(str[i]))
		{
			// support some extra chars but maximum 1 back slash
			switch (str[i])
			{
				case '/':
						++back_slash_count;
						break;
				case '-':
						break;
				default:
						return false;	
			}
		}

		if (back_slash_count > 1)
			return false;
	}

	// there should be one back slash
	if (back_slash_count != 1)
		return false;

	return true;
}

void
gen_salt_password_and_apikey (const char *entity, char *salt, char *password_hash, char *apikey)
{
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

	if (strchr(id,'\\') != NULL)
		goto done;

	CREATE_STRING (query,"SELECT salt,password_hash FROM users WHERE id='%s' and blocked='f'",id);

	kore_pgsql_cleanup(&sql);
	kore_pgsql_init(&sql);
	if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
	{
		kore_pgsql_logerror(&sql);
		goto done;	
	}
	if (! kore_pgsql_query(&sql, (char *)query->data))
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

	printf("Expecting it to be {%s} got {%s}\n",password_hash, hash_string);

	if (strncmp(hash_string,password_hash,64) == 0)
		login_result = true;

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
	const char *exchange;
	const char *topic;
	const char *message;

	amqp_basic_properties_t props;

	amqp_socket_t 			*socket = NULL;
	amqp_connection_state_t		connection;

	// TODO set connection.state = uninitalized

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

	connection 	= amqp_new_connection();
	socket		= amqp_tcp_socket_new(connection);

	if (socket == NULL)
		ERROR("could not create a new socket");

	if (amqp_socket_open(socket, "broker", 5672))
		ERROR("could not open a socket");

	login_reply = amqp_login(connection, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, id, apikey);
	if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
		FORBIDDEN("invalid id or apikey");

	if(! amqp_channel_open(connection, 1))
		ERROR("could not open an AMQP connection");

	rpc_reply = amqp_get_rpc_reply(connection);
	if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
		FORBIDDEN("did not receive expected response from the broker");

	memset(&props, 0, sizeof props);
	props.user_id = amqp_cstring_bytes(id);

	FORBIDDEN_if
	(
		AMQP_STATUS_OK != amqp_basic_publish (	
			connection,
			1,
			amqp_cstring_bytes(exchange),
        		amqp_cstring_bytes(topic),
			0,
			0,
			&props,
               		amqp_cstring_bytes(message)
		),

		"broker refused publish message"
	);

	OK202();

done:
	// TODO if connection.state != uninitalized

	amqp_channel_close	(connection, 1, AMQP_REPLY_SUCCESS);
	amqp_connection_close	(connection, AMQP_REPLY_SUCCESS);
	amqp_destroy_connection	(connection);

	if (socket)
		free(socket);

	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_buf_reset(Q);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
subscribe(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *message_type;
	const char *num_messages;
	const char *time_out;

	uint8_t int_time_out;

	uint8_t int_num_messages;
	uint8_t num_messages_read;

	amqp_socket_t 			*socket = NULL;
	amqp_connection_state_t		connection;

	// TODO set connection.state = uninitalized

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

	kore_buf_append(Q,id,strlen(id));
	if (KORE_RESULT_OK == http_request_header(req, "message-type", &message_type))
	{
		if (strcmp(message_type,"priority") == 0)
		{
			kore_buf_append (Q,".priority",9);
		}
	}
	kore_buf_append(Q,"\0",1);

	/* XXX TO BE DONE */
	int_num_messages = 10;
	if (KORE_RESULT_OK == http_request_header(req, "num-messages", &num_messages))
	{
		int_num_messages = atoi(num_messages);

		if (int_num_messages > 10 || int_time_out < 0)
			int_time_out = 10;
	}

	int_time_out = 3;
	if (KORE_RESULT_OK != http_request_header(req, "time-out", &message_type))
	{
		int_time_out = atoi(time_out);

		if (int_time_out > 3 || int_time_out < 0)
			int_time_out = 3;
	}

	/* XXX TO BE DONE */

	connection 	= amqp_new_connection();
	socket		= amqp_tcp_socket_new(connection);

	if (socket == NULL)
		ERROR("could not create a new socket");

	if (amqp_socket_open(socket, "broker", 5672))
		ERROR("could not open a socket");

	login_reply = amqp_login(connection, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, id, apikey);
	if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
		FORBIDDEN("invalid id or apikey");

	if (! amqp_channel_open(connection, 1))
		ERROR("could not open an AMQP connection");

	rpc_reply = amqp_get_rpc_reply(connection);
	if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
		FORBIDDEN("did not receive expected response from the broker");

	amqp_basic_consume(connection, 1, amqp_cstring_bytes((char const *)Q->data), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);

	kore_buf_append(response,"[",1);

	for (num_messages_read = 0; num_messages_read <= int_num_messages; ++num_messages_read)
	{
		amqp_rpc_reply_t res;
		amqp_envelope_t envelope;
		amqp_maybe_release_buffers(connection);

		// TODO check for timeout
		// TODO check for message size 

		res = amqp_consume_message(connection, &envelope, NULL, 0);
		if (AMQP_RESPONSE_NORMAL != res.reply_type) {
			break;
		}

		kore_buf_append(response,"{\"from\":\"",9);
		if (envelope.message.properties.user_id.len == 0)
			kore_buf_append (response,"<unknown>",9);
		else
			kore_buf_append (response,envelope.message.properties.user_id.bytes,
				envelope.message.properties.user_id.len);

		kore_buf_append(response,"\",\"to\":\"",8);
		kore_buf_append(response,envelope.exchange.bytes, envelope.exchange.len);
		kore_buf_append(response,"\",\"message-type\":\"",18);
		kore_buf_append(response,envelope.routing_key.bytes, envelope.routing_key.len);
		kore_buf_append(response,"\",\"content-type\":\"",18);
		kore_buf_append(response,envelope.routing_key.bytes, envelope.routing_key.len);

		if (envelope.message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG)
		{
			kore_buf_append(response,envelope.message.properties.content_type.bytes,
				envelope.message.properties.content_type.len);
		}
		else
		{
			kore_buf_append(response,"<unspecified>",13);
		}

		kore_buf_append(response,"\",\"body\":\"",10);
		kore_buf_append(response,envelope.message.body.bytes, envelope.message.body.len);
		kore_buf_append(response,"\"},",3);
	}

	kore_buf_append(response,"]",1);

	OK();

done:
	// TODO if connection.state != uninitalized

	amqp_channel_close	(connection, 1, AMQP_REPLY_SUCCESS);
	amqp_connection_close	(connection, AMQP_REPLY_SUCCESS);
	amqp_destroy_connection	(connection);

	if (socket)
		free(socket);

	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_buf_reset(Q);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
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

	strlcpy(entity_name,id,128);
	strcat(entity_name,"/");
	strlcat(entity_name,entity,256);

	// conflict if entity_name already exist
	CREATE_STRING	(query,"SELECT id from users WHERE id='%s'",entity_name);
	RUN_QUERY	(query,"could not get info about entity");

	if (kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity_name, salt, password_hash, entity_apikey);

	// sanitize body
	size_t s = strlen(body);
	for (i = 0; i < s; ++i)
	{
		if (body[i] == '\'')
			body[i] = '\"';
		else if (body[i] == '\\')
			body[i] = ' ';
	} 

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked) values('%s','%s','%s','%s','f')",
			entity_name,
			password_hash,
			body,		// schema
			salt
	);
	RUN_QUERY (query,"failed to create the entity");

	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity_name,strlen(entity_name));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
	kore_buf_append(response,"\"}\n",3);

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
delete_entity_from_rabbitmq (char *entity)
{
	if (! looks_like_a_valid_entity(entity))
		return -1;

/* XXX
	amqp_exchange_delete (entity.public);
	amqp_exchange_delete (entity.private);
	amqp_exchange_delete (entity.protected);

	amqp_queue_delete (entity);
	amqp_queue_delete (entity.priority);
*/
	return 0;
}

int
delete_owner_from_rabbitmq (char *owner)
{
	if (! looks_like_a_valid_owner(owner))
		return -1;
/*
	CREATE_STRING 	(query, "SELECT * from users where id='%s'",owner); 
	RUN_QUERY 	(query, "can't search entity in DB");

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

	strlcpy(entity_name,id,33); 
	strlcat(entity_name,"/",34); 
	strlcat(entity_name,entity,66); 

	// TODO delete from follow where from_entity = entity_name or to_entity = entity_name

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

	CREATE_STRING (query,"DELETE FROM users WHERE id = '%s'",entity_name);
	printf("RAN2 ===> {%s}\n",query->data);
	RUN_QUERY	(query,"could not delete the entity");


	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
cat(struct http_request *req)
{
	const char *entity;
	uint32_t num_rows = 0;

	req->status = 403;

	http_populate_get(req);
	if (http_argument_get_string(req,"id",&entity))
	{
		// if not a valid entity
		if (! looks_like_a_valid_entity(entity))
			FORBIDDEN("id is not a valid entity");
	
		CREATE_STRING (query,"SELECT schema FROM users WHERE schema is NOT NULL AND id='%s'",entity);
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
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
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
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
register_owner(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	char salt		[33];
	char entity_apikey	[33];
	char password_hash	[65];

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
		KORE_RESULT_OK != http_request_header(req, "entity", &entity)
			,
		"inputs missing in headers"
	);

	// cannot create an admin
	if (strcmp(entity,"admin") == 0)
		FORBIDDEN("cannot create admin");

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this api");

	// it should look like an owner
	if (! looks_like_a_valid_owner(entity))
		BAD_REQUEST("entity should be an owner");	
		
	if (! login_success("admin",apikey))
		FORBIDDEN("wrong apikey");

	// conflict if entity_name already exist
	CREATE_STRING 	(query,"SELECT id FROM users WHERE id ='%s'",entity);
	RUN_QUERY	(query,"could not query info about the owner");

	if(kore_pgsql_ntuples(&sql) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity, salt, password_hash, entity_apikey);

	CREATE_STRING (query,
			"INSERT INTO users (id,password_hash,schema,salt,blocked) values('%s','%s',NULL,'%s','f')",
				entity,
				password_hash,
				salt
	);

	RUN_QUERY (query, "could not create a new owner");

	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity,strlen(entity));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
	kore_buf_append(response,"\"}\n",3);

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
deregister_owner(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

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
		KORE_RESULT_OK != http_request_header(req, "entity", &entity)
			,
		"inputs missing in headers"
	);

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("only admin can call this api");

	// cannot delete admin
	if (strcmp(entity,"admin") == 0)
		FORBIDDEN("cannot delete admin");

	// it should look like an owner
	if (! looks_like_a_valid_owner(entity))
		BAD_REQUEST("entity should be an owner");	

	if (! login_success("admin",apikey))
		FORBIDDEN("wrong apikey");

	// XXX delete from follow table

	// XXX run select query and delete each and every queue and exchange. This needs work

	// delete all acls
	CREATE_STRING 	(query,"DELETE FROM acl WHERE id LIKE '%s/%%' OR exchange LIKE '%s/%%'",entity);
	RUN_QUERY 	(query,"could not delete from acl table");

	// delete all apps and devices of the owner
	CREATE_STRING 	(query,"DELETE FROM users WHERE id LIKE '%s/%%'",entity);
	RUN_QUERY	(query,"could not delete apps/devices of the entity");

	// finally delete the owner 
	CREATE_STRING 	(query,"DELETE FROM users WHERE id = '%s'",entity);
	RUN_QUERY	(query,"could not delete the entity");

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
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

	uint8_t strlen_id = strlen(id);

	if (! looks_like_a_valid_entity(from))
		FORBIDDEN("from is not a valid entity");
	
	if (! looks_like_a_valid_entity(to))
		FORBIDDEN("to is not a valid entity");

	// check if the he is the owner of from 
	if (strncmp(id,from,strlen_id) != 0)
		FORBIDDEN("you are not the owner of from entity");

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

	// if both from and to are owned by id
	if (
		(from[strlen_id] == '/')
				&&
		(strncmp(id,to,strlen_id) == 0)
				&&
		(to[strlen_id] == '/')
	)
	{
		status = "approved";	
	}

	char read_follow_id  [10];
	char write_follow_id [10];

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
		RUN_QUERY 	(query, "failed pg_get_serial write");
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

		printf("Got read ={%s}\n",read_follow_id);

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

		printf("Got read ={%s}\n",read_follow_id);
		printf("Got write ={%s}\n",write_follow_id);

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

	kore_buf_append(response,"}",1);

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
get_follow_requests (struct http_request *req)
{
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
		CREATE_STRING(query,"SELECT * FROM follow WHERE id_to LIKE '%s/%%.%%'",id);
	}
	else
	{
		CREATE_STRING(query,"SELECT * FROM follow WHERE id_to LIKE '%s/%%.%%' and status='%s'",id, status);
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
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
share (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *follow_id;

	req->status = 403;

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
	CREATE_STRING 	(query,"UPDATE follow SET status='approved' WHERE follow_id = '%s'",follow_id);
	RUN_QUERY	(query,"could not run update query on follow");

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
	http_response_header(req, "content-type", "application/json");
	http_response(req, req->status, response->data, response->offset);

	kore_pgsql_cleanup(&sql);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
unfollow (struct http_request *req)
{
	return (KORE_RESULT_OK);
}

int
unshare (struct http_request *req)
{
	return (KORE_RESULT_OK);
}
