#include "apis/api.h"

#define UNPRIVILEGED_USER ("nobody")

struct kore_pgsql sql;

char queue	[129];
char exchange	[129];

struct kore_buf *query = NULL;
struct kore_buf *response = NULL;

char 	string_to_be_hashed 	[256];
uint8_t	binary_hash 		[SHA256_DIGEST_LENGTH];
char 	hash_string		[SHA256_DIGEST_LENGTH*2 + 1];

ht connection_ht;
ht async_connection_ht;

bool is_success = false;
char admin_apikey[33];
char postgres_pwd[33];

char broker_ip	[100];
char pgsql_ip	[100];

char error_string [1025];

amqp_connection_state_t	cached_admin_conn;
amqp_table_t 		lazy_queue_table;
amqp_rpc_reply_t 	login_reply;
amqp_rpc_reply_t 	rpc_reply;
amqp_table_entry_t 	*entry;
amqp_basic_properties_t	props;

#define MAX_ASYNC_THREADS (2)

int async_queue_index = 0;

Q 		async_q		[MAX_ASYNC_THREADS];
pthread_t 	async_thread	[MAX_ASYNC_THREADS];

int
init (int state)
{
	int i;

	// mask server name 
	http_server_version("");

	hostname_to_ip("broker", broker_ip);
	hostname_to_ip("postgres", pgsql_ip);

//////////////
// lazy queues
//////////////

	lazy_queue_table.num_entries = 3;
	lazy_queue_table.entries = malloc (
		lazy_queue_table.num_entries * sizeof(amqp_table_entry_t)
	);

	if (! lazy_queue_table.entries)
		exit(-1);

	entry = &lazy_queue_table.entries[0];
	entry->key = amqp_cstring_bytes("x-queue-mode");
	entry->value.kind = AMQP_FIELD_KIND_UTF8;
	entry->value.value.bytes = amqp_cstring_bytes("lazy");

	entry = &lazy_queue_table.entries[1];
	entry->key = amqp_cstring_bytes("x-max-length");
	entry->value.kind = AMQP_FIELD_KIND_I64;
	entry->value.value.i64 = 50000;

	entry = &lazy_queue_table.entries[2];
	entry->key = amqp_cstring_bytes("x-message-ttl");
	entry->value.kind = AMQP_FIELD_KIND_I64;
	entry->value.value.i64 = 43200000; // half day

//////////////

	int fd = open("/vars/admin.passwd",O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr,"could not open admin.passwd file\n");
		exit(-1);
	}

	if (! read(fd,admin_apikey,32))
	{
		fprintf(stderr,"could not read from admin.passwd file\n");
		exit(-1);
	}

	admin_apikey[32] = '\0';
	int strlen_admin_apikey = strlen(admin_apikey);

	for (i = 0; i < strlen_admin_apikey; ++i)
	{
		if (isspace(admin_apikey[i]))
		{
			admin_apikey[i] = '\0';
			break;
		}
	}

	(void) close (fd);

	fd = open("/vars/postgres.passwd",O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr,"could not open postgres.passwd\n");
		exit(-1);
	}

	if (! read(fd,postgres_pwd,32))
	{
		fprintf(stderr,"could not read from postgres.passwd\n");
		exit(-1);
	}

	postgres_pwd[32] = '\0';
	int strlen_postgres_pwd = strlen(postgres_pwd);

	for (i = 0; i < strlen_postgres_pwd; ++i)
	{
		if (isspace(postgres_pwd[i]))
		{
			postgres_pwd[i] = '\0';
			break;
		}
	}

	(void) close (fd);

	init_admin_conn();

	// declare the "DATABASE" queue if it does not exist
	if (! amqp_queue_declare (
		cached_admin_conn,
		1,
		amqp_cstring_bytes("DATABASE"),
		0,
		1, /* durable */
		0,
		0,
		lazy_queue_table
	))
	{
		fprintf(stderr,"amqp_queue_declare failed for {DATABASE}\n");
		return KORE_RESULT_ERROR;
	}

	ht_init (&connection_ht);

	if (query == NULL)
		query = kore_buf_alloc(512);

	if (response == NULL)
		response = kore_buf_alloc(1024*1024);

	char conn_str[129];
        snprintf (
			conn_str,
			129,
			"host = %s user = postgres password = %s",
			pgsql_ip,
			postgres_pwd
	);
	kore_pgsql_register("db",conn_str);

	memset(&props, 0, sizeof props);
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_USER_ID_FLAG;

///// chroot and drop priv /////

	//explicit_bzero(admin_apikey,33);
	explicit_bzero(postgres_pwd,33);

	struct passwd *p;
	if ((p = getpwnam(UNPRIVILEGED_USER)) == NULL) {
		perror("getpwnam failed ");
		return KORE_RESULT_ERROR;
	}

	if (chroot("./jail") < 0) {
		perror("chroot failed ");
		return KORE_RESULT_ERROR;
	}

	if (setgid(p->pw_gid) < 0) {
		perror("setgid failed ");
		return KORE_RESULT_ERROR;
	}

	if (setuid(p->pw_uid) < 0) {
		perror("setuid failed ");
		return KORE_RESULT_ERROR;
	}

/////////////////////////////////

	for (i = 0; i < MAX_ASYNC_THREADS; ++i)
	{
		q_init(&async_q[i]);

		if (
			pthread_create(
				&async_thread[i],
				NULL,
				async_publish_thread,
				(void *)&async_q[i]
			) != 0
		)
		{
			perror("could not create async thread");
			return KORE_RESULT_ERROR;
		}
	}

	return KORE_RESULT_OK;
}
