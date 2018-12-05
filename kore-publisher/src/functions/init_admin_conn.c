#include "../apis/api.h"

void
init_admin_conn ()
{
	cached_admin_conn = amqp_new_connection();
	amqp_socket_t *socket = amqp_tcp_socket_new(cached_admin_conn);

	if (socket == NULL)
	{
		fprintf(stderr,"Could not open a socket\n");
		exit(-1);
	}

	while (amqp_socket_open(socket, broker_ip, 5672))
	{
		fprintf(stderr,"Could not connect to broker\n");
		sleep(1);
	}

	login_reply = amqp_login(
			cached_admin_conn,
			"/",
			0,
			131072,
			HEART_BEAT,
			AMQP_SASL_METHOD_PLAIN,
			"admin",
			admin_apikey
	);

	if (login_reply.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"invalid id or apikey\n");
		exit (-1);
	}

	if(! amqp_channel_open(cached_admin_conn, 1))
	{
		fprintf(stderr,"could not open an AMQP connection\n");
		exit (-1);
	}

	rpc_reply = amqp_get_rpc_reply(cached_admin_conn);
	if (rpc_reply.reply_type != AMQP_RESPONSE_NORMAL)
	{
		fprintf(stderr,"broker did not send AMQP_RESPONSE_NORMAL\n");
		exit (-1);
	}
}
