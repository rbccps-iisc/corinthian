#include <kore/http.h>
#include <kore/kore.h>

#include "kore-publisher.h"
#include "websocket.h"

static const char password_chars[] = 
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789"
	"-";

static const int n_passwd_chars = sizeof(password_chars) - 1;

void
websocket_connect(struct connection *c)
{
	printf("Connect\n");
}

void
websocket_message(struct connection *c, u_int8_t op, void *data, size_t len)
{
	printf("Message\n");
}

void
websocket_disconnect(struct connection *c)
{
	printf("Disconnect\n");
}

int serve_websocket (struct http_request *req)
{
	const char *id;
	const char *apikey;

	const void *sec_websocket_key;
	const void *sec_websocket_version;

	struct kore_buf *response = kore_buf_alloc(128);

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
			,
		"inputs missing in headers"
	);

	bool is_autonomous = false;

	if (! login_success(id,apikey,&is_autonomous))
		FORBIDDEN("invalid id or apikey");

	BAD_REQUEST("NOT YET IMPLEMENTED !");
		
	if (KORE_RESULT_OK != http_request_header(req,"sec-websocket-key",&sec_websocket_key))
	{
		// TODO: get it from pool 
		struct http_header *hdr = malloc(sizeof(struct http_header));

		if (hdr == NULL)
			ERROR("out of memory");

		char tmp_sec_websocket_key[32];

		for (int i = 0; i < 32; ++i)
			tmp_sec_websocket_key [i] = password_chars[arc4random_uniform(n_passwd_chars)]; 

		hdr->header	= strdup("sec-websocket-key");
		hdr->value	= strdup(tmp_sec_websocket_key);

		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);
	}

	if (KORE_RESULT_OK != http_request_header(req,"sec-websocket-version",&sec_websocket_version))
	{
		// TODO: get it from pool 
		struct http_header *hdr = malloc(sizeof(struct http_header));

		if (hdr == NULL)
			ERROR("out of memory");

		hdr->header	= strdup("sec-websocket-version");
		hdr->value	= strdup("13");

		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);
	}

	kore_websocket_handshake (
		req,
		"websocket_connect",
		"websocket_message",
		"websocket_disconnect"
	);

	return (KORE_RESULT_OK);

done:
	http_response_header(
		req,
		"content-type",
		"application/json"
	);

	http_response (
		req,
		req->status,
		response->data,
		response->offset
	);

	kore_buf_reset(response);

	return (KORE_RESULT_OK);
}
