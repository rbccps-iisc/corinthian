#ifndef _HT_H
#define _HT_H

#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<assert.h>

#include "ll.h"

#define MAX_HASH (4096)

typedef struct ht
{
	ll *list [MAX_HASH];	
} ht;

unsigned int hash_function (const void *key);
void ht_init (ht *h);
void ht_insert (ht *h, const char *key, void *value);
void ht_delete(ht *h, const char *key);
node* ht_search (ht *h, const char *key);

#endif
