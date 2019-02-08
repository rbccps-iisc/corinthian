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
	printf("Message {%s}\n",data);
	if (len >= 3)
	{	
		/*if (data[0] == 'p' && data[1] == ' ')
		{
		}
		else if (data[0] == 's' && data[1] == ' ')
		{
		}*/
		// error
	}
	else
	{
		// error
	}
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

	const char *sec_websocket_key;
	const char *sec_websocket_version;

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

	/// TODO put it in websocket init
	struct kore_pool http_header_pool;

	/// TODO put it in websocket init
	kore_pool_init (
		&http_header_pool,
		"my_http_request_pool",
           	sizeof(struct http_request),
		2
	);
		
	if (KORE_RESULT_OK != http_request_header(req,"sec-websocket-key",&sec_websocket_key))
	{
		struct http_header *hdr = kore_pool_get(&http_header_pool);

		char server_generated_sec_websocket_key[32];

		for (int i = 0; i < 32; ++i)
			server_generated_sec_websocket_key [i] = password_chars[arc4random_uniform(n_passwd_chars)]; 

		hdr->header	= kore_strdup("sec-websocket-key");
		hdr->value	= kore_strdup(server_generated_sec_websocket_key);

		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);

		printf("\nGenerated key {%s}\n",sec_websocket_key);
	}
	else
		printf("\nFound key {%s}\n",sec_websocket_key);

	if (KORE_RESULT_OK != http_request_header(req,"sec-websocket-version",&sec_websocket_version))
	{
		struct http_header *hdr = kore_pool_get(&http_header_pool);

		hdr->header	= kore_strdup("sec-websocket-version");
		hdr->value	= kore_strdup("13");

		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);
	}
	else
		printf("Found version {%s}\n",sec_websocket_version);

	printf("Yes\n");

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
