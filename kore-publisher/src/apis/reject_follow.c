#include "../apis/api.h"

int
reject_follow (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *follow_id;

	req->status = 403;
	kore_buf_reset(response);

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "follow-id", &follow_id)
		,

		"inputs missing in headers"
	);


/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

	sanitize(follow_id);

/////////////////////////////////////////////////

	if (looks_like_a_valid_owner(id))
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s/%%.%%' AND status='pending'",
				follow_id,
				id
		);
	}
	else
	{
		CREATE_STRING (query, 
			"SELECT from_id FROM follow "
			"WHERE follow_id = '%s' AND exchange LIKE '%s.%%' AND status='pending'",
				follow_id,
				id
		);

	}

	RUN_QUERY (query,"could not run select query on follow");

	if (kore_pgsql_ntuples(&sql) != 1)
		BAD_REQUEST("follow-id is not valid");

	// NOTE: follow_id is primary key 
	CREATE_STRING (query,
			"UPDATE follow SET status='rejected' WHERE follow_id = '%s'",
				follow_id
	);
	RUN_QUERY (query,"could not run update query on follow");

	OK();

done:
	END();
}
