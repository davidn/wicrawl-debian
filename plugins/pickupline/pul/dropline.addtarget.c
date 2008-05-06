#include"pul.h"

int addtarget(u_char* ip,u_char* mac,struct puldb* mydb)
{
	if(!(mydb->head)) // if this is the first node in the list..
	{
		mydb->head=malloc(sizeof(struct puldbnode));
		memcpy(mydb->head->ip,ip,4);
		memcpy(mydb->head->mac,mac,6);
		mydb->head->next=0;

		fprintf(stderr,"\n++ adding new target %u.%u.%u.%u",
			ip[0],ip[1],ip[2],ip[3]);
		return 1;
	}

	struct puldbnode* current;

	current=mydb->head;
	
	while(current) // traverse the list to the end
	{
		if(!memcmp(ip,current->ip,4))return 0; // do not add duplicates
		if(current->next)current=current->next;
		else break;
	}

	current->next=malloc(sizeof(struct puldbnode)); // allocate new node
	current=current->next;       // assign new node
	memcpy(current->ip,ip,4);    // set the IP of the target
	memcpy(current->mac,mac,6);  // set the MAC of the target
	current->next=0;

	fprintf(stderr,"\n++ adding new target %u.%u.%u.%u",
			ip[0],ip[1],ip[2],ip[3]);
	
	return 1;
}
