#ifndef _NODE_H
#define _NODE_H

typedef struct node {

	char 	*key;
	void 	*value;

	struct node 	*next;
	struct node 	*prev;
} node;

#endif
