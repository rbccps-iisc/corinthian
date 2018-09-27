#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <libpq-fe.h>

#include <kore/kore.h>
#include <kore/http.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <openssl/sha.h>

#if 0
	#define debug_printf(...)
#else
	#define debug_printf(...) printf(__VA_ARGS__)
#endif

char password_chars[] = "-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@#./";

int init (int);
int ep_cat(struct http_request *);
int ep_publish(struct http_request *);
int ep_subscribe(struct http_request *);
int ep_register(struct http_request *);
int ep_deregister(struct http_request *);

int ep_register_owner (struct http_request *);
int ep_deregister_owner (struct http_request *);

void gen_salt_password_and_apikey (const char *, char *, char *, char *);
bool login_success (const char *, const char *);

inline bool is_owner(const char *);

#define OK()    {status=200; goto done;}
#define OK202() {status=202; goto done;}

#define BAD_REQUEST(x) { 				\
	status = 400;					\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define FORBIDDEN(x) { 					\
	status = 403;					\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define CONFLICT(x) { 					\
	status = 409;					\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define ERROR(x) { 					\
	status = 500;					\
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

PGconn *psql = NULL;
PGresult *result = NULL;

struct kore_buf *queue = NULL;
struct kore_buf *query = NULL;
struct kore_buf *response = NULL;

uint8_t string_to_be_hashed 	[256];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
uint8_t hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

size_t i;

int status = 403;

int
init (int state)
{
	if (queue == NULL)
		queue = kore_buf_alloc(256);

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(65536);

	if (psql == NULL)
	{
		psql = PQconnectdb("user=postgres password=password");
		if (PQstatus(psql) == CONNECTION_BAD)
		{
			exit(-1);
		}
	}

	return KORE_RESULT_OK;
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

	kore_buf_append(query,"SELECT blocked,salt,password_hash FROM users WHERE id ='",
		       sizeof("SELECT blocked,salt,password_hash FROM users WHERE id ='") - 1);

	kore_buf_append(query,id,strlen(id));
	kore_buf_append(query,"'\0",2);

	debug_printf("login query = {%s}\n",query->data);

    	PQclear(result); 
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
		goto done;	

	if (PQntuples(result) == 0)
		goto done;	

	if (strcmp(PQgetvalue(result,0,0),"t") == 0)
		goto done;	

	salt 	 	= PQgetvalue(result,0,1);
	password_hash	= PQgetvalue(result,0,2);

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

	if (strncmp(hash_string,password_hash,64) == 0)
		login_result = true;

done:
	kore_buf_reset(query);

	return login_result;
}

int
ep_publish (struct http_request *req)
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

	status = 403;

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

	http_response(req, status, NULL, 0);

	return (KORE_RESULT_OK);
}

inline bool
is_owner(const char *id)
{
	return (strchr(id,'/') == NULL);
}

int
ep_subscribe(struct http_request *req)
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

	status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

	kore_buf_append(queue,id,strlen(id));
	if (KORE_RESULT_OK == http_request_header(req, "message-type", &message_type))
	{
		if (strcmp(message_type,"priority") == 0)
		{
			kore_buf_append (queue,".priority",9);
		}
	}
	kore_buf_append(queue,"\0",1);

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

	amqp_basic_consume(connection, 1, amqp_cstring_bytes((char const *)queue->data), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);

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
	http_response(req, status, response->data, response->offset);

	kore_buf_reset(queue);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
ep_register(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	char *body;

	char entity_name[66];

	char salt		[33];
	char entity_apikey	[33];
	char password_hash	[65];

	status = 403;

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
	if (! is_owner(id))
		FORBIDDEN("id does not belong to a owner");

	if (! login_success(id,apikey))
		FORBIDDEN("invalid id or apikey");

	strlcpy(entity_name,id,128);
	strcat(entity_name,"/");
	strlcat(entity_name,entity,256);

	// conflict if entity_name already exist
	kore_buf_reset(query);
	kore_buf_append(query,"SELECT id from users WHERE id = '",
		       sizeof("SELECT id from users WHERE id = '") - 1);

	kore_buf_append(query,entity_name,strlen(entity_name));
	kore_buf_append(query,"'\0",2);

    	PQclear(result);    
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
		FORBIDDEN("bad query");

	if(PQntuples(result) > 0)
		CONFLICT("id already used");

	BAD_REQUEST_if	
	(
		req->http_body == NULL
			||
		(body = (char *)req->http_body->data) == NULL
			,
		"no body found in request"	
	);	

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

	kore_buf_reset(query);
	kore_buf_append(query,"INSERT INTO users values('",
		       sizeof("INSERT INTO users values('") - 1);

	kore_buf_append(query,entity_name,strlen(entity_name));
		kore_buf_append(query,"','",3);
	kore_buf_append(query,password_hash, 64);
		kore_buf_append(query,"','",3);
	kore_buf_append(query,body,strlen(body));
		kore_buf_append(query,"','",3);
	kore_buf_append(query,salt,strlen(salt));
		kore_buf_append(query,"',",2);
	kore_buf_append(query,"'f')\0",5);

    	PQclear(result); 
	result = PQexec(psql, (char *)query->data); 

	debug_printf("Query was {%s}\n",query->data);

	if (PQresultStatus(result) != PGRES_COMMAND_OK)
		FORBIDDEN("bad query");

	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity_name,strlen(entity_name));
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
	kore_buf_append(response,"\"}\n",3);

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, status, response->data, response->offset);

	PQclear(result);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
ep_deregister(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	char entity_name [66];

	status = 403;

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

	// deny if the user is not an owner
	if (strchr(id,'/') != NULL)
		FORBIDDEN("id is not an owner");

	// deny if the entity does not have '/'
	if (strchr(entity,'/') == NULL)
		FORBIDDEN("not a valid entity");

	BAD_REQUEST_if
	(
		strlen(entity) > 256
			|| 
		strchr(entity,'\'')
			||
		strchr(entity,'\\')
			,
		"invalid entity"
	)

	// TODO deny if user is blocked
	kore_buf_append(query,"SELECT blocked,salt,password_hash FROM users WHERE id ='",
		       sizeof("SELECT blocked,salt,password_hash FROM users WHERE id ='") - 1);

	kore_buf_append(query,id,strlen(id));
	kore_buf_append(query,"'\0",2);

	debug_printf("Got query = {%s}\n",query->data);

    	PQclear(result);    
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
		ERROR("bad query");

	if (PQntuples(result) == 0)
		FORBIDDEN("entity not found");

	if (strcmp(PQgetvalue(result,0,0),"t") == 0)
		FORBIDDEN("id is blocked");

	strlcpy(entity_name,id,33); 
	strlcat(entity_name,"/",34); 
	strlcat(entity_name,entity,66); 

	// TODO CHECK apikey

	// TODO deny if entity_name is not in users db deny with msg

	// TODO delete from acl where id = entity_name
	// TODO delete from follow where from_entity = entity_name or to_entity = entity_name
	// TODO delete from users where id = entity_name

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, status, response->data, response->offset);

	PQclear(result);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
ep_cat(struct http_request *req)
{
	char *id = NULL;
	uint32_t num_rows = 0;

	status = 403;

	http_populate_get(req);
	if (http_argument_get_string(req,"id",&id))
	{
		// if not a valid entity
		if (strchr(id,'/') == NULL)
			FORBIDDEN("id is not a valid entity");

		kore_buf_append (query,"SELECT schema FROM users WHERE schema is NOT NULL AND id='",
			        sizeof("SELECT schema FROM users WHERE schema is NOT NULL AND id='") - 1);
		kore_buf_append (query,id,strlen(id));
		kore_buf_append (query,"'",1);
	}
	else
	{
		id = NULL;
		kore_buf_append (query,"SELECT id,schema FROM users WHERE schema is NOT NULL",
			        sizeof("SELECT id,schema FROM users WHERE schema is NOT NULL") - 1);
	}
	
	kore_buf_append (query,"\0",1);

    	PQclear(result);
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
		FORBIDDEN("bad query"); // TODO fix

	num_rows = PQntuples(result);

	if (id == NULL) // get all data
	{
		kore_buf_append(response,"[",1);

		for (i = 0; i < num_rows; ++i)
		{
			char *user = PQgetvalue(result,i,0);
			char *schema = PQgetvalue(result,i,1);

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

		char *schema = PQgetvalue(result,0,0);

		kore_buf_append(response,schema,strlen(schema));
	}

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, status, response->data, response->offset);

	PQclear(result);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}


int
ep_register_owner(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	char salt		[33];
	char entity_apikey	[33];
	char password_hash	[65];

	status = 403;

	if (req->owner->addrtype == AF_INET)
	{
		if (req->owner->addr.ipv4.sin_addr.s_addr != htonl(INADDR_LOOPBACK))	
		{
			FORBIDDEN("unauthorized request");
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

	uint8_t strlen_entity = strlen(entity);
	if (strlen_entity == 0 || strlen_entity > 32)
		BAD_REQUEST("entity name should be 1 to 32 chars long");

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("unauthorized request");

	if (! login_success(id,apikey))
		FORBIDDEN("wrong apikey");

	// conflict if entity_name already exist
	kore_buf_reset(query);
	kore_buf_append(query,"SELECT id from users WHERE id = '",
		       sizeof("SELECT id from users WHERE id = '") - 1);

	kore_buf_append(query,entity,strlen_entity);
	kore_buf_append(query,"'\0",2);

    	PQclear(result);    
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_TUPLES_OK)
		FORBIDDEN("bad query");

	if(PQntuples(result) > 0)
		CONFLICT("id already used");

	gen_salt_password_and_apikey (entity, salt, password_hash, entity_apikey);

	kore_buf_reset(query);
	kore_buf_append(query,"INSERT INTO users values('",
		       sizeof("INSERT INTO users values('") - 1);

	kore_buf_append(query,entity,strlen_entity);
		kore_buf_append(query,"','",3);
	kore_buf_append(query,password_hash, 64);
		kore_buf_append(query,"',",2);
	kore_buf_append(query,"NULL",4);
		kore_buf_append(query,",'",2);
	kore_buf_append(query,salt,strlen(salt));
		kore_buf_append(query,"',",2);
	kore_buf_append(query,"'f')\0",5);

    	PQclear(result); 
	result = PQexec(psql, (char *)query->data); 

	debug_printf("Query was {%s}\n",query->data);

	if (PQresultStatus(result) != PGRES_COMMAND_OK)
		FORBIDDEN("bad query");

	kore_buf_reset(response);
	kore_buf_append(response,"{\"id\":\"",7);
	kore_buf_append(response,entity,strlen_entity);
	kore_buf_append(response,"\",\"apikey\":\"",12);
	kore_buf_append(response,entity_apikey,strlen(entity_apikey));
	kore_buf_append(response,"\"}\n",3);

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, status, response->data, response->offset);

	PQclear(result);

	kore_buf_reset(query);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}

int
ep_deregister_owner(struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	// XXX to be done

	status = 403;

	if (req->owner->addrtype == AF_INET)
	{
		if (req->owner->addr.ipv4.sin_addr.s_addr != htonl(INADDR_LOOPBACK))	
		{
			FORBIDDEN("unauthorized request");
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

	uint8_t strlen_entity = strlen(entity);
	if (strlen_entity == 0 || strlen_entity > 32)
		BAD_REQUEST("entity name should be 1 to 32 chars long");

	// cannot delete admin
	if (strcmp(entity,"admin") == 0)
		FORBIDDEN("cannot delete admin");

	if (strcmp(id,"admin") != 0)
		FORBIDDEN("unauthorized request");

	if (! login_success(id,apikey))
		FORBIDDEN("wrong apikey");

	// XXX delete from follow table

	// delete all acls
	kore_buf_reset(query);
	kore_buf_append(query,"DELETE from acl WHERE id LIKE ",
		       sizeof("DELETE from acl WHERE id LIKE ") - 1);

	kore_buf_append(query,entity,strlen_entity);
	kore_buf_append(query,"/%\0",3);

    	PQclear(result);    
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_COMMAND_OK)
		ERROR("could not delete from acl table");
	
	// delete all apps and devices of the owner
	kore_buf_reset(query);
	kore_buf_append(query,"DELETE from users WHERE id LIKE ",
		       sizeof("DELETE from users WHERE id LIKE ") - 1);

	kore_buf_append(query,entity,strlen_entity);
	kore_buf_append(query,"/%\0",3);

    	PQclear(result);    
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_COMMAND_OK)
		ERROR("could not delete apps/devices of the entity");

	// finally delete the owner 
	kore_buf_reset(query);
	kore_buf_append(query,"DELETE from users WHERE id = '",
		       sizeof("DELETE from users WHERE id = '") - 1);

	kore_buf_append(query,entity,strlen_entity);
	kore_buf_append(query,"'\0",2);

    	PQclear(result);    
	result = PQexec(psql, (char *)query->data); 

	if (PQresultStatus(result) != PGRES_COMMAND_OK)
		ERROR("could not delete the entity");

	OK();

done:
	http_response_header(req, "content-type", "application/json");
	http_response(req, status, response->data, response->offset);

	PQclear(result);

	kore_buf_reset(queue);
	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}
