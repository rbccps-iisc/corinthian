#ifndef __KORE_PUBLISHER_H
#define __KORE_PUBLISHER_H

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_framing.h>
#include <amqp_ssl_socket.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <openssl/sha.h>

#include <ctype.h>
#include <pthread.h>

#include "ht.h"
#include<arpa/inet.h>
#include<netdb.h>
#include<sys/socket.h>
#include<errno.h>

//#define TEST (1)

#if 0
	#define debug_printf(...)
#else
	#define debug_printf(...) printf(__VA_ARGS__)
#endif

int cat			(struct http_request *);

int publish		(struct http_request *);
int subscribe		(struct http_request *);

int register_entity	(struct http_request *);
int deregister_entity	(struct http_request *);

int register_owner 	(struct http_request *);
int deregister_owner 	(struct http_request *);

int follow		(struct http_request *);
int unfollow		(struct http_request *);

int get_follow_requests (struct http_request *);

int share		(struct http_request *);
int unshare		(struct http_request *);
int reject_follow	(struct http_request *);

int queue_bind          (struct http_request *);
int queue_unbind        (struct http_request *);

int block		(struct http_request *);
int unblock		(struct http_request *);

int init (int);

void gen_salt_password_and_apikey (const char *, char *, char *, char *);

bool login_success (const char *, const char *, bool *);
bool check_acl(const char *id, const char *exchange, const char *permission);

bool looks_like_a_valid_owner	(const char *str);
bool looks_like_a_valid_entity 	(const char *str);
bool looks_like_a_valid_resource(const char *str);

bool is_alpha_numeric 	(const char *str);
bool is_owner		(const char *, const char *);

void *create_exchanges_and_queues (void *);
void *delete_exchanges_and_queues (void *);

void sanitize (char *string);

bool is_request_from_localhost (struct http_request *);

#define OK()    {req->status=200; goto done;}
#define OK202() {req->status=202; goto done;}

#define BAD_REQUEST(x) { 				\
	req->status = 400;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define FORBIDDEN(x) {					\
	req->status = 403;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define CONFLICT(x) { 					\
	req->status = 409;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define ERROR(x) { 					\
	req->status = 500;				\
	kore_buf_reset(response); 			\
	kore_buf_append(response,"{\"error\":\"",10); 	\
	kore_buf_append(response,x,strlen(x));	 	\
	kore_buf_append(response,"\"}\n",3);	 	\
	goto done;					\
}

#define OK_if(x) {if(x) { OK(); }}
#define FORBIDDEN_if(x,msg) {if(x) { FORBIDDEN(msg); }}
#define ERROR_if(x,msg) {if(x) { ERROR(msg); }}
#define BAD_REQUEST_if(x,msg) {if(x) { BAD_REQUEST(msg); }}

#define RUN_QUERY(query,err) {					\
	debug_printf("RUN_QUERY ==> {%s}\n",query->data);	\
	kore_pgsql_cleanup(&sql);				\
	kore_pgsql_init(&sql);					\
	if (! kore_pgsql_setup(&sql,"db",KORE_PGSQL_SYNC))	\
	{							\
		kore_pgsql_logerror(&sql);			\
		ERROR("DB error while setup");			\
	}							\
	if (! kore_pgsql_query(&sql, (char *)query->data))	\
	{							\
		kore_pgsql_logerror(&sql);			\
		ERROR(err);					\
	}							\
}

#define END() 	{			\
	http_response_header(		\
		req,			\
		"content-type",		\
		"application/json"	\
	);				\
	http_response (			\
		req,			\
		req->status, 		\
		response->data,		\
		response->offset	\
	);				\
	kore_pgsql_cleanup(&sql);	\
	kore_buf_reset(response);	\
	kore_buf_reset(query);		\
	return (KORE_RESULT_OK);	\
} 

#define END_HTML() 	{		\
	http_response_header(		\
		req,			\
		"content-type",		\
		"text/html"		\
	);				\
	http_response (			\
		req,			\
		req->status, 		\
		response->data,		\
		response->offset	\
	);				\
	kore_pgsql_cleanup(&sql);	\
	kore_buf_reset(response);	\
	kore_buf_reset(query);		\
	return (KORE_RESULT_OK);	\
}

#define CREATE_STRING(buf,...)	{			\
	kore_buf_reset(buf);				\
	kore_buf_appendf(buf,__VA_ARGS__);		\
	kore_buf_stringify(buf,NULL);			\
}

#endif /* __KORE_PUBLISHER_H */
