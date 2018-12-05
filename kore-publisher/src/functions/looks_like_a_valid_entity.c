#include <stdbool.h>
#include <string.h>

bool
looks_like_a_valid_entity (const char *str)
{
	unsigned int i;

	unsigned int strlen_str = strlen(str);

	unsigned int front_slash_count = 0;

	// format is owner/entity
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
