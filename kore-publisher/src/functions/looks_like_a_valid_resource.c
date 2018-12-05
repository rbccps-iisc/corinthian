#include <stdbool.h>
#include <string.h>

bool
looks_like_a_valid_resource (const char *str)
{
	unsigned int i;

	unsigned int strlen_str = strlen(str);

	unsigned int front_slash_count = 0;
 
	unsigned int dot_count = 0;

	// format is owner/entity.public
	if (strlen_str < 10 || strlen_str > 128)
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

				case '.':
						++dot_count;
						break;
				default:
						return false;
			}
		}
	}

	// there should be only one front slash. Dot may or may not exist
	if ( (front_slash_count != 1) || (dot_count > 1) ) {
		return false;
	}
  	   
	return true;
}
