#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

#include <openssl/sha.h>

#include <stdbool.h>

#include <string.h>
#include <bsd/string.h>
#include <bsd/stdlib.h>

#include <ctype.h>

#if 1
	#define debug_printf(...)
#else
	#define debug_printf(...) printf(__VA_ARGS__)
#endif

#define OK()    { req->status=200; goto done; }
#define DENY()  { debug_printf("DENY %d\n",__LINE__);req->status=403; goto done; }
#define ERROR() { req->status=500; goto done; }
#define BAD_REQUEST() {debug_printf("BAD %d\n",__LINE__);req->status=400; goto done;}

#define GET_MANDATORY_FIELD(x) \
	if (! http_argument_get_string(req, "" #x "", &x))		\
	{								\
		debug_printf("No GET input '%s' found\n","" #x "");	\
		BAD_REQUEST();						\
	}

#define CREATE_STRING(buf,...) 	{			\
		kore_buf_reset(buf);			\
		kore_buf_appendf(buf,__VA_ARGS__);	\
		kore_buf_stringify(buf,NULL);		\
}

int init(int);
int auth_user(struct http_request *);
int auth_topic(struct http_request *);
int auth_vhost(struct http_request *);
int auth_resource(struct http_request *);

bool looks_like_a_valid_owner (const char *);
bool looks_like_a_valid_entity(const char *);

bool login_success (const char *, const char *);

char 	string_to_be_hashed 	[256];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

struct kore_buf *query = NULL;
struct kore_pgsql sql;

size_t i;

int
init (int state)
{
	if (query == NULL)
		query = kore_buf_alloc(512);

	// XXX this user must only have read permissions on DB
	kore_pgsql_register("db","user=postgres password=password");

	return KORE_RESULT_OK;
}

inline bool
is_alpha_numeric (const char *str)
{
	uint8_t strlen_str = strlen(str);

	if (strlen_str == 0 || strlen_str > 32)
		return false;

	for (i = 0; i < strlen_str; ++i)
	{
		if (! isalnum(str[i]))
		{
			// support some extra chars
			switch (str[i])
			{
				case '.':
				case '@':
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

	if (strlen_str == 0 || strlen_str > 65)
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
				case '.':
				case '@':
				case '-':
						break;
				
				default:
						return false;	
			}
		}

		if (back_slash_count > 1)
			return false;
	}

	return true;
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

	CREATE_STRING 	(query,"SELECT blocked,salt,password_hash FROM users WHERE id='%s'",id);

	debug_printf("login query = {%s}\n",query->data);

	kore_pgsql_cleanup(&sql);				\
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

	if (strcmp(kore_pgsql_getvalue(&sql,0,0),"t")  == 0)
		goto done;	

	salt 	 	= kore_pgsql_getvalue(&sql,0,1);
	password_hash	= kore_pgsql_getvalue(&sql,0,2);

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

	if (strncmp((char *)hash_string,password_hash,64) == 0)
		login_result = true;

done:
	kore_buf_reset(query);

	kore_pgsql_cleanup(&sql);

	return login_result;
}

int
auth_user(struct http_request *req)
{
	char *username;
	char *password;

	req->status = 403;
	
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
	if (req->status == 200)
		http_response(req, req->status, "allow", 5);
	else
		http_response(req, req->status, "deny", 4);

	kore_buf_reset(query);

	kore_pgsql_cleanup(&sql);				\

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

	req->status = 403;

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

	// name should not look like a owner 
	if (looks_like_a_valid_owner(name))
		DENY()

	// name should be a valid entity
	if (! looks_like_a_valid_entity(name))
		DENY()

	// get user info in acl, if blocked deny
	CREATE_STRING (query,"SELECT blocked FROM users WHERE id='%s'",username);

	debug_printf("Query = {%s}\n",query->data);

	kore_pgsql_cleanup(&sql);				\
	if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
	{
		kore_pgsql_logerror(&sql);
		DENY();
	}
	if (! kore_pgsql_query(&sql,(const char *)query->data))
	{
		kore_pgsql_logerror(&sql);
		DENY();
	}

	if (kore_pgsql_ntuples(&sql) != 1)
		DENY();

	if (strcmp(kore_pgsql_getvalue(&sql,0,0),"t")  == 0)
		DENY();

	strlen_username = strlen(username);
	if (strcmp(resource,"queue") == 0)
	{
		// don't allow writes on queue
		if (strcmp(permission,"write") == 0)
			DENY()

		// if owner then allow in username.notify, username.follow
		if (looks_like_a_valid_owner(username))
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
				CREATE_STRING (query,
						"SELECT permissions FROM acl WHERE id='%s' AND exchange='%s'",
							username,
							name
				);
				debug_printf("query = '%s'\n",query->data);

				kore_pgsql_cleanup(&sql);				\
				if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))
				{
					kore_pgsql_logerror(&sql);
					DENY();
				}
				if (! kore_pgsql_query(&sql, (const char *)query->data))
				{
					kore_pgsql_logerror(&sql);
					DENY();
				}

				if (kore_pgsql_ntuples(&sql) != 1)
					DENY();

				// has write permission
				if (strcmp(kore_pgsql_getvalue(&sql,0,0),"w")  == 0)
					OK()
				else
					DENY()
			}
		}
	}

done:

	if (req->status == 200)
		http_response(req, req->status, "allow", 5);
	else
		http_response(req, req->status, "deny", 4);

	kore_buf_reset(query);

	kore_pgsql_cleanup(&sql);				\

	return (KORE_RESULT_OK);
}
