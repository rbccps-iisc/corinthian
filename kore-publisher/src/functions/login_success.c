#include "../apis/api.h"

static char 	string_to_be_hashed 	[256];
static unsigned binary_hash 		[SHA256_DIGEST_LENGTH];
static char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

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

	debug_printf("strlen of salt = %d (%s)\n",strlen(salt),salt);
	debug_printf("strlen of apikey = %d (%s)\n",strlen(apikey),apikey);

	strlcpy(string_to_be_hashed, apikey, 33);
	strlcat(string_to_be_hashed, salt,   65);
	strlcat(string_to_be_hashed, id,    250);

	SHA256 (
		(const unsigned *)string_to_be_hashed,
		strlen(string_to_be_hashed),
		binary_hash
	);

	debug_printf("login success STRING TO BE HASHED = {%s}\n",
			string_to_be_hashed);
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
		binary_hash[ 0],binary_hash[ 1],binary_hash[ 2],binary_hash[ 3],
		binary_hash[ 4],binary_hash[ 5],binary_hash[ 6],binary_hash[ 7],
		binary_hash[ 8],binary_hash[ 9],binary_hash[10],binary_hash[11],
		binary_hash[12],binary_hash[13],binary_hash[14],binary_hash[15],
		binary_hash[16],binary_hash[17],binary_hash[18],binary_hash[19],
		binary_hash[20],binary_hash[21],binary_hash[22],binary_hash[23],
		binary_hash[24],binary_hash[25],binary_hash[26],binary_hash[27],
		binary_hash[28],binary_hash[29],binary_hash[30],binary_hash[31]
	);

	hash_string[64] = '\0';

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
