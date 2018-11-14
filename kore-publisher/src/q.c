#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "node.h"
#include "q.h"

void q_init (Q *q)
{
	q->head = q->tail = NULL;	
	pthread_mutex_init(&q->mutex, NULL);
}

void q_insert (Q *q)
{
	node *new_node = malloc(sizeof(node));

	if (new_node == NULL)
	{
		perror("Malloc failed ");
		exit (-1);
	}

	new_node->next = new_node->prev = NULL;

	pthread_mutex_lock(&q->mutex);

		if (q->head == NULL)
		{
			q->head		= new_node;
			q->tail 	= q->head;
		}	
		else
		{
			new_node->next 	= q->head;
			q->head->prev	= new_node;
			q->head 	= new_node;
		}

	pthread_mutex_unlock(&q->mutex);
}

void* q_delete (Q *q)
{
	void *v;

	pthread_mutex_lock(&q->mutex);

		if (q->head == NULL || q->tail == NULL)
			return NULL;		

		v = q->tail->value;

		q->tail 	= q->tail->prev;
		q->tail->next 	= NULL;

		free (q->tail);

	pthread_mutex_unlock(&q->mutex);
	
	return v;
}
