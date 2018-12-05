#include "../apis/api.h"

// variables for exchanges and queues
const char *_e[] = {
		".public",
		".private",
		".protected",
		".notification",
		".publish",
		".diagnostics",
		".public.validated",
		".protected.validated",
		NULL
};

const char *_q[] = {
		"\0",
		".private",
		".priority",
		".command",
		".notification",
		NULL
};

void *
create_exchanges_and_queues (const void *v)
{
	int i;

	const char *id = (const char *)v;

	// local variables
	char my_queue	[129];
	char my_exchange[129];

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// create notification exchange 
		snprintf(my_exchange,129,"%s.notification",id);

		debug_printf("[owner] creating exchange {%s}\n",my_exchange);

		if (! amqp_exchange_declare (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(my_exchange),
			amqp_cstring_bytes("topic"),
			0,
			1, /* durable */
			0,
			0,
			amqp_empty_table
		))
		{
			fprintf(stderr,"amqp_exchange_declare failed {%s}\n",my_exchange);
			goto done;
		}
		debug_printf("[owner] done creating exchange {%s}\n",my_exchange);

		// create notification queue
		snprintf(queue,129,"%s.notification",id);
		debug_printf("[owner] creating queue {%s}\n",my_queue);
		if (! amqp_queue_declare (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(my_queue),
			0,
			1, /* durable */
			0,
			0,
			lazy_queue_table
		))
		{
			fprintf(stderr,"amqp_queue_declare failed {%s}\n",my_queue);
			goto done;
		}

		debug_printf("done creating queue {%s}\n",my_queue);

		if (! amqp_queue_bind (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(my_queue),
			amqp_cstring_bytes(my_exchange),
			amqp_cstring_bytes("#"),
			amqp_empty_table
		))
		{
			fprintf(stderr,"bind failed for {%s} -> {%s}\n",my_queue,my_exchange);
			goto done;
		}

		debug_printf("bound queue {%s} to exchange {%s}\n",my_queue,my_exchange);

		if (! amqp_queue_bind (
			cached_admin_conn,
			1,
			amqp_cstring_bytes("DATABASE"),
			amqp_cstring_bytes(my_exchange),
			amqp_cstring_bytes("#"),
			amqp_empty_table
		))
		{
			fprintf(stderr,"failed to bind {%s} to DATABASE queue for\n",my_exchange);
			goto done;
		}
		debug_printf("bound queue {%s} to exchange {%s}\n",my_queue,"DATABASE");
	}
	else
	{
		for (i = 0; _e[i]; ++i)
		{
			snprintf(my_exchange,129,"%s%s",id,_e[i]);

			debug_printf("[entity] creating exchange {%s}\n",my_exchange);

			if (! amqp_exchange_declare (
					cached_admin_conn,
					1,
					amqp_cstring_bytes(my_exchange),
					amqp_cstring_bytes("topic"),
					0,
					1, /* durable */
					0,
					0,
					amqp_empty_table
				)
			)
			{
				fprintf(stderr,"something went wrong with exchange creation {%s}\n",my_exchange);
				goto done;
			}
			debug_printf("[entity] DONE creating exchange {%s}\n",my_exchange);

			if (! amqp_queue_bind (
				cached_admin_conn,
				1,
				amqp_cstring_bytes("DATABASE"),
				amqp_cstring_bytes(my_exchange),
				amqp_cstring_bytes("#"),
				amqp_empty_table
			))
			{
				fprintf(stderr,"failed to bind {%s} to DATABASE queue for\n",my_exchange);
				goto done;
			}
		}

		for (i = 0; _q[i]; ++i)
		{
			snprintf(my_queue,129,"%s%s",id,_q[i]);

			debug_printf("[entity] creating queue {%s}\n",my_queue);

			if (! amqp_queue_declare (
				cached_admin_conn,
				1,
				amqp_cstring_bytes(my_queue),
				0,
				1, /* durable */
				0,
				0,
				lazy_queue_table
			))
			{
				fprintf(stderr,"amqp_queue_declare failed {%s}\n",my_queue);
				goto done;
			}
			debug_printf("[entity] DONE creating queue {%s}\n",my_queue);

			// bind .private and .notification 
			if (strcmp(_q[i],".private") == 0 || strcmp(_q[i],".notification") == 0)
			{
				snprintf(exchange,129,"%s%s",id,_q[i]);
				debug_printf("[entity] binding {%s} -> {%s}\n",my_queue,my_exchange);

				if (! amqp_queue_bind (
					cached_admin_conn,
					1,
					amqp_cstring_bytes(my_queue),
					amqp_cstring_bytes(my_exchange),
					amqp_cstring_bytes("#"),
					amqp_empty_table
				))
				{
					fprintf(stderr,"failed to bind {%s} to {%s}\n",my_queue,my_exchange);
					goto done;
				}
			}
		}
	}

	is_success = true;

done:
	if (! is_success)
	{
		init_admin_conn(); 
	}

	return &is_success;
}
