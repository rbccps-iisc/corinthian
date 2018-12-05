#include "../apis/api.h"

int
permissions (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;
	const char *entity;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	)

	if (looks_like_a_valid_owner(id))
	{
		if (KORE_RESULT_OK != http_request_header(req, "entity", &entity))
			BAD_REQUEST("entity value not specified in header");
			
		if (! is_owner(id,entity))
			FORBIDDEN("you are not the owner of entity");
	}
	else
	{
		entity = id;
	}

/////////////////////////////////////////////////

	if (! login_success(id,apikey,NULL))
		FORBIDDEN("invalid id or apikey");

	sanitize(entity);

/////////////////////////////////////////////////

	CREATE_STRING(query,
			"SELECT exchange,permission FROM acl WHERE from_id='%s' "
			"AND valid_till > now()",entity
	);
	RUN_QUERY (query,"could not query acl table");

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);

	int num_rows = kore_pgsql_ntuples(&sql);

	for (i = 0; i < num_rows; ++i)
	{
		char *my_exchange 	= kore_pgsql_getvalue(&sql,i,0);
		char *perm 		= kore_pgsql_getvalue(&sql,i,1);

		kore_buf_append(response,"{\"entity\":\"",11);
		kore_buf_append(response,my_exchange,strlen(my_exchange));
		kore_buf_append(response,"\",\"permission\":\"",16);
		kore_buf_append(response,perm,strlen(perm));
		kore_buf_append(response,"\"},",3);
	}

	// remove the last comma
	if (i > 0)
		--(response->offset);

	kore_buf_append(response,"]",1);

	OK();

done:
	END();

}


