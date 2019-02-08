#include "kore-publisher.h"

extern int allow_admin_apis_from_other_hosts;

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

bool
is_json_safe (const char *string)
{
	size_t len = 0;

	char *p = (char *)string;

	while (*p)
	{
		if (! isprint(*p))
			return false;

		if (*p == '\'' || *p == '\\')
			return false;	

		++p;

		if (len > MAX_LEN_SAFE_JSON)
			return false;
	}

	return true;
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
		if (len > MAX_LEN_SAFE_STRING)
			return false;
	}

	return true;
}

bool
str_ends_with (const char *s1, const char *s2)
{
	// s1 has s2 at the end ?

	size_t s1_len = strnlen(s1,MAX_LEN_SAFE_STRING);
	size_t s2_len = strnlen(s2,MAX_LEN_SAFE_STRING);

	if (s2_len > s1_len)
		return false;

	size_t i = s1_len;
	size_t j = s2_len;

	while (j >= 0) 
	{
		if (s1[i--] != s2[j--])
			return false;
	}

	return true;
}
