void
str_to_lower (const char *str)
{
	char *p = (char *)str;

	while (*p)
	{
		if (*p >= 'A' && *p <= 'Z')
			*p += 32; 

		++p;
	}
}
