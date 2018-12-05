#include <stdbool.h>
#include <string.h>
#include <ctype.h>

bool
is_alpha_numeric (const char *str)
{
	unsigned int i;
	unsigned int strlen_str = strlen(str);

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

