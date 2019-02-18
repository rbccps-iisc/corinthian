#include "kore-publisher.h"

static struct kore_pgsql sql;

static struct kore_buf *query 		= NULL;
static struct kore_buf *response 	= NULL;

int upload_file (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *file_name;
	const char *content_type;

	const char *file_content;

	struct kore_buf *response = kore_buf_alloc(128);

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "name", &file_name)
				||
		! http_request_header(req, "content-type", &content_type)
			,
		"inputs missing in headers"
	);

	if (req->http_body == NULL)
		BAD_REQUEST("no body found in request");

	if (req->http_body_length > MAX_LEN_SAFE_JSON)
		BAD_REQUEST("body too long");
			
	if ((file_content = (char *)req->http_body->data) == NULL)
		BAD_REQUEST("no body found in request");


/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_string_safe(file_name))
		BAD_REQUEST("invalid file name");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

	// get content-type and set in props
	if (! http_request_header(req,"content-type",&content_type))
		content_type = "";

	// search in DB

	CREATE_STRING (query,
			"SELECT 1 FROM file where id='%s/%s'",
				id,
				file_name
	);

	bool file_exists = false;

	if (file_exists)
	{
		// TODO: insert into catalog
		// return 201
	}
	else
	{
		// TODO: update catalog
		// return 200
	}

done:
	END();

}

int download_file (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *file_name;

	struct kore_buf *response = kore_buf_alloc(128);

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "name", &file_name)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_string_safe(file_name))
		BAD_REQUEST("invalid file name");

/////////////////////////////////////////////////

		
	// TODO: search in DB

done:
	END();
}

int delete_file (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const char *file_name;

	struct kore_buf *response = kore_buf_alloc(128);

	req->status = 403;

	BAD_REQUEST_if
	(
		! http_request_header(req, "id", &id)
				||
		! http_request_header(req, "apikey", &apikey)
				||
		! http_request_header(req, "name", &file_name)
			,
		"inputs missing in headers"
	);

/////////////////////////////////////////////////

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	if (! is_string_safe(file_name))
		BAD_REQUEST("invalid file name");

	if (! is_autonomous)
		FORBIDDEN("unauthorized");

/////////////////////////////////////////////////

		
	// TODO: delete file 

done:
	END();
}
