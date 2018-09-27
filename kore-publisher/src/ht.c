#include "ht.h"

unsigned int hash_function (const void *key)
{
	size_t i;
	unsigned int hash = 0;

	size_t strlen_key = strlen(key);

	size_t len = strlen_key > 16 ? 16 : strlen_key; 

	for (i = 0; i < len; ++i) {
		hash += *((const char *)key + i);
	}

	return (hash * hash + hash) % MAX_HASH;
}


void ht_init (ht *h)
{
	int i;
	for (i = 0; i < MAX_HASH; ++i)
	{
		h->list[i] = (ll *) malloc (sizeof(ll));	

		if (h->list[i] == NULL)
		{
			perror("Malloc failed for h->list[i] !");
			exit (-1);
		}

		h->list[i]->head = NULL;
		h->list[i]->tail = NULL;
	}
}

void ht_insert (ht *h, const char *key, void *value)
{
	unsigned int hash = hash_function (key);

	node *new_node = (node *) malloc (sizeof(node));	
	if (new_node == NULL)
	{
		perror("Malloc failed for new node !");
		exit (-1);
	}

	new_node->key = (char *)strdup(key);
	if (new_node->key == NULL)
	{
		perror("Failed to malloc key !");
		exit(-1);
	}

	new_node->value 	= value; 
	new_node->next 		= h->list[hash]->head;
	h->list[hash]->head	= new_node;
}


node* ht_search (ht *h, const char *key)
{
	node *n;
	unsigned int hash = hash_function (key);

	for (n = h->list[hash]->head; n ; n = n->next)
	{
		if (strcmp(key, n->key) == 0)
		{
			return n;
		}
	}
	return NULL;
}
