#include <ctype.h>

void
sanitize (const char *string)
{
	// string should not be NULL. let it crash if it is 
	char *p = (char *)string;

	// assumption is that 'string' is in single quotes

	while (*p)
	{
		/* wipe out anything that looks suspicious */
	
		if (! isprint(*p))
		{
			*p = '\0';
			return;
		}
		
		switch(*p)
		{
			case '\'':
			case '\\':
			case '_' :
			case '%' :
			case '(' :
			case ')' :
			case '|' :
			case ';' :
			case '&' :
				*p = '\0';
				return;
		}

		++p;
	}
}
