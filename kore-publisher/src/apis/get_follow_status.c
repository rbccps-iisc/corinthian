#include "../apis/api.h"

int
get_follow_status (struct http_request *req)
{
	int i;

	const char *id;
	const char *apikey;

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
		,

		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

//////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,permission,topic,validity,status "
			"FROM follow "
			"WHERE from_id LIKE '%s/%%' "
			"ORDER BY time DESC",
				id
		);
	}
	else
	{
		CREATE_STRING (query,
			"SELECT "
			"follow_id,requested_by,exchange,time,permission,topic,validity,status "
			"FROM follow "
			"WHERE from_id = '%s' "
			"ORDER BY time DESC",
				id
		);
	}

	RUN_QUERY(query, "could not get follow requests");

	int num_rows = kore_pgsql_ntuples(&sql);

	kore_buf_reset(response);
	kore_buf_append(response,"[",1);
	for (i = 0; i < num_rows; ++i)
	{
		kore_buf_appendf(
			response,
			"{\"follow-id\":\"%s\","
			"\"from\":\"%s\","
			"\"to\":\"%s\","
			"\"time\":\"%s\","
			"\"permission\":\"%s\","
			"\"topic\":\"%s\","
			"\"validity\":\"%s\","
			"\"status\":\"%s\"},"
			,
			kore_pgsql_getvalue(&sql,i,0),
			kore_pgsql_getvalue(&sql,i,1),
			kore_pgsql_getvalue(&sql,i,2),
			kore_pgsql_getvalue(&sql,i,3),
			kore_pgsql_getvalue(&sql,i,4),
			kore_pgsql_getvalue(&sql,i,5),
			kore_pgsql_getvalue(&sql,i,6),
			kore_pgsql_getvalue(&sql,i,7)
		);
	}
	if (num_rows > 0)
	{
		// remove the last COMMA 
		--(response->offset);
	}

	kore_buf_append(response,"]",1);

	OK();

done:
	END();
}
