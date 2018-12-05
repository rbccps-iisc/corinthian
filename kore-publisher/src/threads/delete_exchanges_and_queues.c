#include "apis/api.h"

// variables for exchanges and queues
extern const char *_e[];
extern const char *_q[];

void *
delete_exchanges_and_queues (const void *v)
{
	int i;

	const char *id = (const char *)v;

	// local variables
	char my_queue	[129];
	char my_exchange[129];

	is_success = false;

	if (looks_like_a_valid_owner(id))
	{
		// delete notification exchange 
		snprintf(my_exchange,129,"%s.notification",id);

		debug_printf("[owner] deleting exchange {%s}\n",my_exchange);

		if (! amqp_exchange_delete (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(my_exchange),
			0
		))
		{
			fprintf(stderr,"amqp_exchange_delete failed {%s}\n",my_exchange);
			goto done;
		}
		debug_printf("[owner] done deleting exchange {%s}\n",my_exchange);

		// delete notification queue
		snprintf(my_queue,129,"%s.notification",id);
		debug_printf("[owner] deleting queue {%s}\n",my_queue);
		if (! amqp_queue_delete (
			cached_admin_conn,
			1,
			amqp_cstring_bytes(my_queue),
			0,
			0
		))
		{
			fprintf(stderr,"amqp_queue_delete failed {%s}\n",my_queue);
			goto done;
		}
		debug_printf("[owner] DONE deleting queue {%s}\n",my_queue);
	}
	else
	{
		for (i = 0; _e[i]; ++i)
		{
			snprintf(my_exchange,129,"%s%s",id,_e[i]);

			debug_printf("[entity] deleting exchange {%s}\n",my_exchange);

			if (! amqp_exchange_delete (
					cached_admin_conn,
					1,
					amqp_cstring_bytes(my_exchange),
					0
				)
			)
			{
				fprintf(stderr,"something went wrong with exchange deletion {%s}\n",my_exchange);
				goto done;
			}
			debug_printf("[entity] DONE deleting exchange {%s}\n",my_exchange);
		}

		for (i = 0; _q[i]; ++i)
		{
			snprintf(my_queue,129,"%s%s",id,_q[i]);

			debug_printf("[entity] deleting queue {%s}\n",my_queue);

			if (! amqp_queue_delete (
				cached_admin_conn,
				1,
				amqp_cstring_bytes(my_queue),
				0,
				0
			))
			{
				fprintf(stderr,"amqp_queue_delete failed {%s}\n",my_queue);
				goto done;
			}
			debug_printf("[entity] DONE deleting queue {%s}\n",my_queue);
		}
	}

	is_success = true;

done:
	if (! is_success)
	{
		init_admin_conn(); 
	}

	return NULL;
}

