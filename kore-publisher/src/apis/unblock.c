#include "../apis/api.h"

int
unblock (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *entity;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "entity", &entity)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_owner(id))
		BAD_REQUEST("id is not valid owner");

	if (strcmp(id,"admin") == 0)
	{
		if (! is_request_from_localhost(req))
			FORBIDDEN("admin can only use from localhost");
	}
	else
	{
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of the entity");
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"UPDATE users set blocked='f' WHERE id='%s'",
				entity
	);

	RUN_QUERY(query, "could not block the entity");

	OK();

done:
	END();
}
