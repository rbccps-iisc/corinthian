#include <stdbool.h>

bool
looks_like_a_valid_owner (const char *str)
{
	return (str[0] >= 'a' && str[0] <= 'z' && is_alpha_numeric(str));
}
