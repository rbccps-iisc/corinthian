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

	// todo ok ?
	req->hdlr_extra = kore_strdup("success");

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
