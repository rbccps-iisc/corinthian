#include <kore/kore.h>
#include <kore/http.h>
#include <libpq-fe.h>

#include <openssl/sha.h>

#include <stdbool.h>

#include <string.h>
#include <bsd/string.h>
#include <bsd/stdlib.h>

#if 1
	#define debug_printf(...)
#else
	#define debug_printf(...) printf(__VA_ARGS__)
#endif

#define OK()    { status=200; goto done; }
#define DENY()  { status=403; goto done; }
#define ERROR() { status=500; goto done; }
#define BAD_REQUEST() {status=400; goto done;}

#define GET_MANDATORY_FIELD(x) \
	if (! http_argument_get_string(req, "" #x "", &x))		\
	{								\
		debug_printf("No GET input '%s' found\n","" #x "");	\
		BAD_REQUEST();							\
	}

int init(int);
int auth_user(struct http_request *);
int auth_topic(struct http_request *);
int auth_vhost(struct http_request *);
int auth_resource(struct http_request *);
bool login_success (const char *, const char *);

PGconn *psql = NULL;
PGresult *result = NULL;

uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
uint8_t string_to_be_hashed 	[SHA256_DIGEST_LENGTH*2 + 1];
uint8_t hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

struct kore_buf *query = NULL;

int
init (int state)
{
	if (query == NULL)
		query = kore_buf_alloc(512);

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

inline bool
is_owner(const char *id)
{
	return (strchr(id,'/') == NULL);
}

bool
login_success (const char *id, const char *apikey)
{
	char *salt;
	char *password_hash;

	printf("Got id = {%s} : pwd = {%s}\n",id,apikey);

	bool login_result = false;

	if (id == NULL || apikey == NULL || *id == '\0' || *apikey == '\0')
		return false;

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

	strlcpy((char *)string_to_be_hashed, apikey, 32);
	strlcat((char *)string_to_be_hashed, salt,   64);

	SHA256((const uint8_t*)string_to_be_hashed,64,binary_hash);

	sprintf	
	(
		(char *)hash_string,
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

	if (strncmp((char *)hash_string,password_hash,64) == 0)
		login_result = true;
done:
	kore_buf_reset(query);

	return login_result;
}

int
auth_user(struct http_request *req)
{
	char *username;
	char *password;

	int status = 403;
	
	http_populate_get(req);

	GET_MANDATORY_FIELD(username);
	GET_MANDATORY_FIELD(password);

	// Also, kore's conf file contains a regex
	if (	strlen(username) > 128
			|| 
		strchr(username,'\'')
			|| 
		strchr(username,'\\')
	)
	{
		BAD_REQUEST();
	}

	if (login_success(username,password))	
		OK();	
done:
	if (status == 200)
		http_response(req, 200, "allow", 5);
	else
		http_response(req, status, "deny", 4);

	if (result)
		PQclear(result);

	kore_buf_reset(query);

	return (KORE_RESULT_OK);
}

int
auth_vhost(struct http_request *req)
{
	// dont worry about vhost
	http_response(req, 200, "allow", 5);
	return (KORE_RESULT_OK);
}

int
auth_topic(struct http_request *req)
{
	http_response(req, 200, "allow", 5);
	return (KORE_RESULT_OK);
}

int
auth_resource(struct http_request *req)
{
	char *username;
	char *resource;
	char *name;
	char *permission;

	int status = 403;

	size_t strlen_username;
	
	http_populate_get(req);

	GET_MANDATORY_FIELD(username);
	GET_MANDATORY_FIELD(resource);
	GET_MANDATORY_FIELD(name);
	GET_MANDATORY_FIELD(permission);

	// we do not worry about topic
	if (strcmp(resource,"topic") == 0)
		OK()

	// admin can do anything ???
	if (strcmp(username,"admin") == 0)
		OK()
	
	// we do not allow users to configure
	if (strcmp(permission,"configure") == 0)
		DENY()

	// kore's conf file contains a regex
	if (strlen(username) > 128 || strlen(name) > 128)
		DENY()

	// get user info in acl, if blocked deny
	kore_buf_append(query,"SELECT blocked FROM users WHERE id ='",
		       sizeof("SELECT blocked FROM users WHERE id ='") - 1);
	kore_buf_append(query,username,strlen(username));
	kore_buf_append(query,"'\0",2);

	result = PQexec(psql, (char *)query->data); 
	if (PQresultStatus(result) != PGRES_TUPLES_OK)
		DENY();

	if (PQntuples(result) != 1 || PQnfields(result) != 1)
		DENY();

	if (strcmp(PQgetvalue(result,0,0),"t") == 0)
		DENY();

	strlen_username = strlen(username);
	if (strcmp(resource,"queue") == 0)
	{
		// don't allow writes on queue
		if (strcmp(permission,"write") == 0)
			DENY()

		// if owner then allow in username.notify, username.follow
		if (is_owner(username))
		{
			// deny if the resource does not begin with username
			if (strncmp(name,username,strlen_username) != 0)
				DENY()

			// if it ends with .notify or .follow
			if (
				(strcmp(name + strlen_username ,".notify") == 0) 
						||
 				(strcmp(name + strlen_username ,".follow") == 0)
			)
			{
				OK();
			}
		}
		else
		{
			// Deny if name does not begin with username
			if (strncmp(name,username,strlen_username) != 0)
				DENY();

			// Else allow in queues = username and username.priority 
			if (strcmp(name,username) == 0)
			{
				OK();
			}
			else if (strcmp(name + strlen_username ,".priority") == 0)
			{
				OK();
			}
			else if (strcmp(name + strlen_username ,".command") == 0)
			{
				OK();
			}
		}
	}
	else if (strcmp(resource,"exchange") == 0)
	{
		if (strcmp(permission,"read") == 0)
		{
			// ok to allow read as bind is not allowed
			OK();
		}
		else if (strcmp(permission,"write") == 0)
		{
			if (strchr(username,'/') == NULL)
			{	
				// as owners can only manage their devices
				debug_printf("You are an owner!\n");
				DENY();
			}

			if (strncmp(name,username,strlen_username) == 0 && (name[strlen_username + 1] != '.'))
			{
				// Devices/apps can write in to their 
				// 	username.public
				// 	username.private
				// 	username.protected
				// 	username.diagnostics
			printf("Came here 1\n");
				char *exchange_ends_with = name + strlen_username;

				if (
					strcmp(exchange_ends_with,".public") == 0
							||
					strcmp(exchange_ends_with,".private") == 0
							||
					strcmp(exchange_ends_with,".protected") == 0
							||
					strcmp(exchange_ends_with,".diagnostics") == 0
				)
				{
					OK();
				}
			}
			else
			{
				kore_buf_reset(query);
				kore_buf_append(query,"SELECT permissions FROM acl WHERE id ='",
		       			       sizeof("SELECT permissions FROM acl WHERE id ='") - 1);
				kore_buf_append(query,username,strlen(username));
				kore_buf_append(query,"' AND exchange = '",
		       			       sizeof("' AND exchange = '") - 1);
				kore_buf_append(query,name,strlen(name));
				kore_buf_append(query,"'\0",2);

				debug_printf("query = '%s'\n",query->data);

				result = PQexec(psql, (char *)query->data); 
				if (PQresultStatus(result) != PGRES_TUPLES_OK)
					DENY();

				if (PQntuples(result) != 1 || PQnfields(result) != 1)
					DENY();

				// has write permission
				if (strcmp(PQgetvalue(result,0,0),"w") == 0)
					OK()
				else
					DENY()
			}
		}
	}

done:

	if (status == 200)
		http_response(req, 200, "allow", 5);
	else
		http_response(req, status, "deny", 4);

	PQclear(result);

	kore_buf_reset(query);

	return (KORE_RESULT_OK);
}
