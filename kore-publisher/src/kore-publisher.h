#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <string.h>
#include <pthread.h>

#include <kore/kore.h>
#include <kore/http.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include "ht.h"

#if 1
	#define dprintf(...) 
#else
	#define dprintf(...) printf(__VA_ARGS__)
#endif

int init (int state);

#define forbidden() {						\
	http_response(req, 403, NULL,0); 			\
	dprintf("403 LINE = %d\n",__LINE__);			\
	return (KORE_RESULT_OK);				\
}

#define bad_request() {						\
	http_response(req, 400, NULL,0); 			\
	dprintf("400 LINE = %d\n",__LINE__);			\
	return (KORE_RESULT_OK);				\
}

#define internal_error() {						\
	http_response(req, 500, NULL,0); 			\
	dprintf("500 LINE = %d\n",__LINE__);			\
	return (KORE_RESULT_OK);				\
}

#define ok() {					\
	dprintf("ok...");			\
	http_response(req, 200, NULL,0); 	\
	return (KORE_RESULT_OK);		\
}

#define ok202() {				\
	dprintf("ok 202 ...");			\
	http_response(req, 202, NULL,0); 	\
	return (KORE_RESULT_OK);		\
}

int ep_publish(struct http_request *);
