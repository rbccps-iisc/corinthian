#include <stdbool.h>
#include <string.h>

bool
is_owner(const char *id, const char *entity)
{
	int strlen_id = strlen(id);

	if (strncmp(id,entity,strlen_id) != 0)
		return false;

	// '/' for owner and '.' for entity
	if (entity[strlen_id] != '/' && entity[strlen_id] != '.')
		return false;

	return true;
}
