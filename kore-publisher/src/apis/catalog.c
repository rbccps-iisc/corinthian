#include "../apis/api.h"

int
catalog (struct http_request *req)
{
	int i, num_rows;

	const char *entity;

	req->status = 403;

	http_populate_get(req);
	if (http_argument_get_string(req,"id",(void *)&entity))
	{
		// if not a valid entity
		if (! looks_like_a_valid_entity(entity))
			FORBIDDEN("id is not a valid entity");

		sanitize(entity);

		CREATE_STRING (query,
				"SELECT schema FROM users WHERE schema IS NOT NULL AND id='%s'",
					entity
		);
	}
	else
	{
		entity = NULL;
		CREATE_STRING (query,"SELECT id,schema FROM users WHERE schema IS NOT NULL LIMIT 50");
	}

	RUN_QUERY (query,"unable to query catalog data");

	num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	if (entity == NULL) // get top 50 data 
	{
		kore_buf_append(response,"[",1);

		for (i = 0; i < num_rows; ++i)
		{
			char *user 	= kore_pgsql_getvalue(&sql,i,0);
			char *schema 	= kore_pgsql_getvalue(&sql,i,1);

			kore_buf_append(response,"{\"",2);
			kore_buf_append(response,user,strlen(user));
			kore_buf_append(response,"\":",2);
			kore_buf_append(response,schema,strlen(schema));

			kore_buf_append(response,"},",2);
		} 
		if (num_rows > 0)
		{
			// remove the last COMMA 
			--(response->offset);
		}

		kore_buf_append(response,"]",1);
	}
	else
	{
		// if this entity has no schema or the entity does't exist
		if (num_rows == 0)
			BAD_REQUEST("not a valid id");

		char *schema = kore_pgsql_getvalue(&sql,0,0);

		kore_buf_append(response,schema,strlen(schema));
	}

	OK();

done:
	END();
}
