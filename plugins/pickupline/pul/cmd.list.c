#include"pul.h"

int list(struct puldb* mydb)
{
	struct puldbnode* current;

	current=mydb->head;

	int x=1;
	while(current)
	{
		printf("%d: %hi.%hi.%hi.%hi\n",
				x,current->ip[0],current->ip[1],current->ip[2],current->ip[3]);
		current=current->next;
		++x;
	}
}
