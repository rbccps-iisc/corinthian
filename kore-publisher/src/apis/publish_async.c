#include "../apis/api.h"

int
publish_async (struct http_request *req)
{
	const char *id;
	const char *apikey;
	const char *to;
	const char *subject;
	const char *message;
	const char *message_type;

	const char *content_type;

	char topic_to_publish[129];

	req->status = 403;

	BAD_REQUEST_if
	(
		KORE_RESULT_OK != http_request_header(req, "id", &id)
				||
		KORE_RESULT_OK != http_request_header(req, "apikey", &apikey)
				||
		KORE_RESULT_OK != http_request_header(req, "to", &to)
				||
		KORE_RESULT_OK != http_request_header(req, "subject", &subject)
				||
		KORE_RESULT_OK != http_request_header(req, "message-type", &message_type)
			,
		"inputs missing in headers"
	);

	if (! looks_like_a_valid_entity(to))
		BAD_REQUEST("'to' is not a valid entity");

	// ok to publish to himself
	if (strcmp(id,to) == 0)
	{
		if (
			(strcmp(message_type,"public") 		!= 0)	&&
			(strcmp(message_type,"private") 	!= 0)	&&
			(strcmp(message_type,"protected") 	!= 0)	&&
			(strcmp(message_type,"diagnostics") 	!= 0)	
		)
		{
			BAD_REQUEST("message-type is not valid");
		}

		snprintf(exchange,129,"%s.%s",id,message_type);
		strlcpy(topic_to_publish,subject,129);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",topic_to_publish);
	}
	else
	{
		if (strcmp(message_type,"command") != 0)
		{
			BAD_REQUEST("message-type can only be command");		
		}

		snprintf(topic_to_publish,129,"%s.%s.%s",to,message_type,subject);
		snprintf(exchange,129,"%s.publish",id);

		debug_printf("==> exchange = %s\n",exchange);
		debug_printf("==> topic = %s\n",topic_to_publish);
	}

	if (http_request_header(req, "message", &message) != KORE_RESULT_OK)
	{
		if ((message = (char *)req->http_body->data) == NULL)
			BAD_REQUEST("no body found in request");
	}

	if (http_request_header(req, "content-type", &content_type) != KORE_RESULT_OK)
		content_type = "";

	publish_async_data_t *data = malloc (sizeof(publish_async_data_t));

	if (data == NULL)
		ERROR("out of memory");

	data->id 		=
	data->apikey 		=
	data->message		=
	data->exchange		=
	data->subject		=
	data->content_type	= NULL;

	if (!(data->id 			= strdup(id)))			ERROR("out of memmory");
	if (!(data->apikey		= strdup(apikey)))		ERROR("out of memmory");
	if (!(data->message		= strdup(message)))		ERROR("out of memmory");
	if (!(data->exchange 		= strdup(exchange)))		ERROR("out of memmory");
	if (!(data->subject		= strdup(topic_to_publish)))	ERROR("out of memmory");
	if (!(data->content_type	= strdup(content_type)))	ERROR("out of memmory");

	// TODO push "data" in any of the queue 

	if (q_insert (&async_q[async_queue_index], data) < 0)
		ERROR("inserting into queue failed");

	async_queue_index = (async_queue_index + 1) % MAX_ASYNC_THREADS;

	OK_202();

done:
	if (req->status == 500)
	{
		if (data)
		{
			if (data->id)		free (data->id);
			if (data->apikey)	free (data->apikey);
			if (data->message)	free (data->message);
			if (data->exchange)	free (data->exchange);
			if (data->subject)	free (data->subject);
			if (data->content_type)	free (data->content_type);

			free (data);
		}
	}

	END();
}
