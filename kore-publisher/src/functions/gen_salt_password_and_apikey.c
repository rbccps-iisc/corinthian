#ifdef __linux__
	#include <bsd/stdlib.h>
	#include <bsd/string.h>
#else
	#include <stdlib.h>
	#include <string.h>
#endif

#include <openssl/sha.h>

#define PASSWORD_CHARS	"abcdefghijklmnopqrstuvwxyz"	\
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"	\
			"0123456789"			\
			"-"

static char 	string_to_be_hashed 	[256];
static uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
static char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

void
gen_salt_password_and_apikey (
	const 	char *entity,
		char *salt,
		char *password_hash,
		char *apikey
)
{
	int i;

	int n_passwd_chars = sizeof(PASSWORD_CHARS) - 1;

	for (i = 0; i < 32; ++i)
	{
		salt  [i] = PASSWORD_CHARS[arc4random_uniform(n_passwd_chars)]; 
		apikey[i] = PASSWORD_CHARS[arc4random_uniform(n_passwd_chars)]; 
	}
	salt	[32] = '\0';
	apikey	[32] = '\0';

	strlcpy(string_to_be_hashed, apikey, 33);
	strlcat(string_to_be_hashed, salt,   65);
	strlcat(string_to_be_hashed, entity, 250);

	SHA256 (
		(const uint8_t*)string_to_be_hashed,
		strlen(string_to_be_hashed),
		binary_hash
	);

	// debug_printf("gen STRING TO BE HASHED = {%s}\n",string_to_be_hashed);

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
		binary_hash[ 0],binary_hash[ 1],binary_hash[ 2],binary_hash[ 3],
		binary_hash[ 4],binary_hash[ 5],binary_hash[ 6],binary_hash[ 7],
		binary_hash[ 8],binary_hash[ 9],binary_hash[10],binary_hash[11],
		binary_hash[12],binary_hash[13],binary_hash[14],binary_hash[15],
		binary_hash[16],binary_hash[17],binary_hash[18],binary_hash[19],
		binary_hash[20],binary_hash[21],binary_hash[22],binary_hash[23],
		binary_hash[24],binary_hash[25],binary_hash[26],binary_hash[27],
		binary_hash[28],binary_hash[29],binary_hash[30],binary_hash[31]
	);

	password_hash [64] = '\0';
}
