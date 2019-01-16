#ifndef _Q_H
#define _Q_H

#include <pthread.h>
#include "node.h"

typedef struct Q {

	node *head;
	node *tail;

	pthread_mutex_t mutex;

} Q; 

void 	q_init		(Q *q);
int	q_insert 	(Q *q, void *v);
void* 	q_delete 	(Q *q);

#endif
